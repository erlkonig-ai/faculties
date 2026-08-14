//! Portable exact-term-frequency BM25 over canonical Archive blocks.
//!
//! This module is one concrete V4 collection recipe, not a registry. Its
//! source is Archive's canonical `SimpleArchive` union and its target is the
//! portable BM25 carrier. Every canonical block is a document, including a
//! textless block. Content parts are occurrences, so the same content fact at
//! two ordinals contributes twice. Every selected `LongString` payload is
//! tokenized with [`hash_tokens`], and repeated documents join by pointwise
//! maximum in the portable carrier.
//!
//! Importer receipts are deliberately outside the projection. The recipe
//! validates the intrinsic block/part/fact graph it consumes; Archive's full
//! domain validator remains the publication boundary for source facts.

use std::collections::{BTreeMap, BTreeSet};

use anybytes::View;
use anyhow::{bail, Result};

use triblespace::core::blob::encodings::longstring::LongString;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::{Blob, IntoBlob, TryFromBlob};
use triblespace::core::collection::CollectionDescriptor;
use triblespace::core::id::{id_hex, Id};
use triblespace::core::inline::encodings::genid::GenId;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::encodings::iu256::U256BE;
use triblespace::core::inline::encodings::time::NsTAIInterval;
use triblespace::core::inline::encodings::UnknownInline;
use triblespace::core::inline::{Inline, InlineEncoding, IntoInline, RawInline, TryFromInline};
use triblespace::core::metadata::{self, MetaDescribe};
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStoreGet, BlobStoreMeta};
use triblespace::core::trible::{build_intrinsic_entity, IntrinsicEntityRow, Trible, TribleSet};
use triblespace_search::portable_bm25::{PortableBM25Blob, PortableBM25Index};
use triblespace_search::tokens::{hash_tokens, WordHash};

use crate::schemas::blockdag as schema;

/// Archive-block-text BM25 recipe, version 1.
///
/// Minted with `trible genid` on 2026-08-08:
/// `0DDC5AFF78EFBC00CA64CEA0F9565291`.
///
/// Changing the selected graph fields, aggregation law, tokenizer behavior,
/// document/term schemas, or scoring semantics requires a new recipe id.
pub const ARCHIVE_BLOCK_TEXT_BM25_RECIPE_V1: Id = id_hex!("0DDC5AFF78EFBC00CA64CEA0F9565291");

pub type ArchiveBM25Index = PortableBM25Index<GenId, WordHash>;

#[derive(Debug)]
enum DeriveValidation {
    Ready(Blob<PortableBM25Blob>),
    Pending,
    Rejected(String),
}

#[derive(Debug)]
struct ProjectionPlan {
    documents: BTreeMap<Id, Vec<Inline<Handle<LongString>>>>,
}

/// Exact V4 descriptor for the derived Archive BM25 collection.
pub fn descriptor() -> CollectionDescriptor {
    CollectionDescriptor::new(
        schema::DEFAULT_SCOPE_ID,
        <PortableBM25Blob as MetaDescribe>::id(),
        ARCHIVE_BLOCK_TEXT_BM25_RECIPE_V1,
    )
}

/// Build one exact portable Archive BM25 element.
///
/// A missing selected payload is an operational cache miss for an active
/// builder. A later exact ensure retries with a fresh attachment reader.
pub fn derive_element(
    reader: &PileReader,
    source: Blob<SimpleArchive>,
) -> Result<Blob<PortableBM25Blob>> {
    match derive_for_validation(reader, source)? {
        DeriveValidation::Ready(blob) => Ok(blob),
        DeriveValidation::Pending => bail!("Archive BM25 source has a nonresident text payload"),
        DeriveValidation::Rejected(reason) => bail!("invalid Archive BM25 source: {reason}"),
    }
}

fn derive_for_validation(
    reader: &PileReader,
    source: Blob<SimpleArchive>,
) -> Result<DeriveValidation> {
    let plan = match projection_plan(source) {
        Ok(plan) => plan,
        Err(reason) => return Ok(DeriveValidation::Rejected(reason)),
    };

    // Resolve each distinct payload once, while retaining its occurrence in
    // every part that names it. Scan all resident siblings before Pending so
    // malformed bytes cannot hide behind one evicted payload.
    let handles: BTreeSet<_> = plan
        .documents
        .values()
        .flat_map(|payloads| payloads.iter().copied())
        .collect();
    let mut token_cache = BTreeMap::new();
    let mut missing = false;
    for handle in handles {
        if reader.metadata(handle)?.is_none() {
            missing = true;
            continue;
        }
        let blob: Blob<LongString> = reader.get(handle)?;
        let text: View<str> = match blob.bytes.clone().view() {
            Ok(text) => text,
            Err(error) => {
                return Ok(DeriveValidation::Rejected(format!(
                    "resident LongString payload {} is not UTF-8: {error}",
                    hex::encode_upper(handle.raw),
                )))
            }
        };
        token_cache.insert(handle.raw, hash_tokens(text.as_ref()));
    }
    if missing {
        return Ok(DeriveValidation::Pending);
    }

    let documents: Vec<Inline<GenId>> = plan.documents.keys().map(IntoInline::to_inline).collect();
    let mut counts = Vec::new();
    for (document_id, payloads) in plan.documents {
        let document: Inline<GenId> = document_id.to_inline();
        let mut frequencies: BTreeMap<RawInline, u32> = BTreeMap::new();
        for payload in payloads {
            let tokens = token_cache
                .get(&payload.raw)
                .expect("all selected payloads were resolved before counting");
            for token in tokens {
                let frequency = frequencies.entry(token.raw).or_default();
                let Some(incremented) = frequency.checked_add(1) else {
                    return Ok(DeriveValidation::Rejected(format!(
                        "term frequency overflows u32 for Archive block {document_id:X}"
                    )));
                };
                *frequency = incremented;
            }
        }
        counts.extend(
            frequencies
                .into_iter()
                .map(|(term, frequency)| (document, Inline::<WordHash>::new(term), frequency)),
        );
    }

    let index = match ArchiveBM25Index::from_exact_counts(documents, counts) {
        Ok(index) => index,
        Err(error) => {
            return Ok(DeriveValidation::Rejected(format!(
                "portable BM25 construction failed: {error}"
            )))
        }
    };
    Ok(DeriveValidation::Ready(index.to_blob()))
}

fn projection_plan(source: Blob<SimpleArchive>) -> std::result::Result<ProjectionPlan, String> {
    let facts = TribleSet::try_from_blob(source)
        .map_err(|error| format!("source is not a canonical SimpleArchive: {error}"))?;
    let mut entities: BTreeMap<Id, Vec<Trible>> = BTreeMap::new();
    for fact in facts.iter() {
        entities.entry(*fact.e()).or_default().push(*fact);
    }

    let block_ids: BTreeSet<Id> = entities
        .iter()
        .filter_map(|(&entity, rows)| has_exact_tag(rows, schema::block::KIND).then_some(entity))
        .collect();
    let mut documents = BTreeMap::new();
    for block_id in block_ids {
        let block_rows = entities
            .get(&block_id)
            .expect("a discovered entity has rows");
        validate_block(block_id, block_rows)?;

        let mut parts = Vec::new();
        for raw in values(block_rows, schema::block::contains.id()) {
            let part_id = parse_id(raw, "block contains")?;
            let part_rows = entities.get(&part_id).ok_or_else(|| {
                format!("Archive block {block_id:X} references absent part {part_id:X}")
            })?;
            let (ordinal, fact_id) = validate_part(part_id, part_rows)?;
            let fact_rows = entities.get(&fact_id).ok_or_else(|| {
                format!("Archive part {part_id:X} references absent fact {fact_id:X}")
            })?;
            let payloads = validate_content_fact(fact_id, fact_rows)?;
            parts.push((ordinal, payloads));
        }
        parts.sort_unstable_by_key(|(ordinal, _)| *ordinal);
        for (expected, (actual, _)) in parts.iter().enumerate() {
            let expected = u64::try_from(expected)
                .map_err(|_| format!("Archive block {block_id:X} has more than u64::MAX parts"))?;
            if *actual != expected {
                return Err(format!(
                    "Archive block {block_id:X} part ordinals are not exactly contiguous from zero"
                ));
            }
        }
        let payloads = parts
            .into_iter()
            .flat_map(|(_, payloads)| payloads)
            .collect();
        documents.insert(block_id, payloads);
    }
    Ok(ProjectionPlan { documents })
}

fn validate_block(entity: Id, rows: &[Trible]) -> std::result::Result<(), String> {
    let identity = [
        schema::block::previous.id(),
        schema::block::timestamp.id(),
        schema::block::contains.id(),
    ];
    let nonidentity = [metadata::tag.id()];
    validate_intrinsic_entity(entity, rows, schema::block::KIND, &identity, &nonidentity)?;

    for raw in values(rows, schema::block::previous.id()) {
        parse_id(raw, "block previous")?;
    }
    let timestamps = values(rows, schema::block::timestamp.id());
    if timestamps.len() > 1 {
        return Err(format!("Archive block {entity:X} has multiple timestamps"));
    }
    if let Some(raw) = timestamps.first() {
        NsTAIInterval::validate(Inline::new(*raw))
            .map_err(|_| format!("Archive block {entity:X} has an invalid timestamp"))?;
    }
    let contained = values(rows, schema::block::contains.id());
    if contained.is_empty() {
        return Err(format!(
            "Archive block {entity:X} contains no content parts"
        ));
    }
    for raw in contained {
        parse_id(raw, "block contains")?;
    }
    Ok(())
}

fn validate_part(entity: Id, rows: &[Trible]) -> std::result::Result<(u64, Id), String> {
    let identity = [
        schema::content_part::ordinal.id(),
        schema::content_part::fact.id(),
        schema::content_part::responds_to.id(),
    ];
    let nonidentity = [metadata::tag.id()];
    validate_intrinsic_entity(
        entity,
        rows,
        schema::content_part::KIND,
        &identity,
        &nonidentity,
    )?;

    let ordinal = exactly_one(
        rows,
        schema::content_part::ordinal.id(),
        "part ordinal",
        entity,
    )?;
    let ordinal = u64::try_from_inline(&Inline::<U256BE>::new(ordinal))
        .map_err(|_| format!("Archive part {entity:X} ordinal does not fit u64"))?;
    let fact = exactly_one(rows, schema::content_part::fact.id(), "part fact", entity)?;
    let fact = parse_id(fact, "part fact")?;
    let responses = values(rows, schema::content_part::responds_to.id());
    if responses.len() > 1 {
        return Err(format!(
            "Archive part {entity:X} has multiple responds_to values"
        ));
    }
    if let Some(raw) = responses.first() {
        parse_id(*raw, "part responds_to")?;
    }
    Ok((ordinal, fact))
}

fn validate_content_fact(
    entity: Id,
    rows: &[Trible],
) -> std::result::Result<Vec<Inline<Handle<LongString>>>, String> {
    let identity = [
        schema::content_fact::modality.id(),
        schema::content_fact::direction.id(),
        schema::content_fact::payload.id(),
        schema::content_fact::blob.id(),
        schema::content_fact::asset_pointer.id(),
        schema::content_fact::asset_namespace.id(),
        schema::content_fact::media_type.id(),
        schema::content_fact::asset_size.id(),
    ];
    let nonidentity = [metadata::tag.id(), schema::content_fact::resolved_to.id()];
    validate_intrinsic_entity(
        entity,
        rows,
        schema::content_fact::KIND,
        &identity,
        &nonidentity,
    )?;

    let modality = exactly_one(
        rows,
        schema::content_fact::modality.id(),
        "content modality",
        entity,
    )?;
    parse_id(modality, "content modality")?;
    let direction = exactly_one(
        rows,
        schema::content_fact::direction.id(),
        "content direction",
        entity,
    )?;
    parse_id(direction, "content direction")?;

    let payloads = values(rows, schema::content_fact::payload.id());
    let blobs = values(rows, schema::content_fact::blob.id());
    let pointers = values(rows, schema::content_fact::asset_pointer.id());
    if payloads.len() > 1 || blobs.len() > 1 || pointers.len() > 1 {
        return Err(format!(
            "Archive content fact {entity:X} has a repeated scalar payload variant"
        ));
    }
    let variant_count = usize::from(!payloads.is_empty())
        + usize::from(!blobs.is_empty())
        + usize::from(!pointers.is_empty());
    if variant_count != 1 {
        return Err(format!(
            "Archive content fact {entity:X} must have exactly one payload variant"
        ));
    }

    let namespaces = values(rows, schema::content_fact::asset_namespace.id());
    if pointers.is_empty() != namespaces.is_empty() || namespaces.len() > 1 {
        return Err(format!(
            "Archive content fact {entity:X} must pair one external pointer with one namespace"
        ));
    }
    if let Some(raw) = namespaces.first() {
        parse_id(*raw, "asset namespace")?;
    }
    let media_types = values(rows, schema::content_fact::media_type.id());
    if media_types.len() > 1 {
        return Err(format!(
            "Archive content fact {entity:X} has multiple media types"
        ));
    }
    if let Some(raw) = media_types.first() {
        parse_id(*raw, "content media type")?;
    }
    if values(rows, schema::content_fact::asset_size.id()).len() > 1 {
        return Err(format!(
            "Archive content fact {entity:X} has multiple asset sizes"
        ));
    }

    Ok(payloads
        .into_iter()
        .map(Inline::<Handle<LongString>>::new)
        .collect())
}

fn validate_intrinsic_entity(
    entity: Id,
    rows: &[Trible],
    kind: Id,
    identity: &[Id],
    nonidentity: &[Id],
) -> std::result::Result<(), String> {
    let tags = values(rows, metadata::tag.id());
    if tags.len() != 1 || parse_id(tags[0], "kind tag")? != kind {
        return Err(format!(
            "Archive entity {entity:X} does not carry exactly its canonical kind tag"
        ));
    }

    let identity_set: BTreeSet<_> = identity.iter().copied().collect();
    let nonidentity_set: BTreeSet<_> = nonidentity.iter().copied().collect();
    let mut intrinsic_rows = Vec::new();
    for row in rows {
        if identity_set.contains(row.a()) {
            intrinsic_rows.push(IntrinsicEntityRow::new(
                *row.a(),
                row.v::<UnknownInline>().raw,
            ));
        } else if !nonidentity_set.contains(row.a()) {
            return Err(format!(
                "Archive entity {entity:X} carries unknown attribute {:X}",
                row.a()
            ));
        }
    }
    let (expected, _) = build_intrinsic_entity(intrinsic_rows);
    if expected != entity {
        return Err(format!(
            "Archive entity {entity:X} is not the intrinsic id of its canonical fields (expected {expected:X})"
        ));
    }
    Ok(())
}

fn has_exact_tag(rows: &[Trible], kind: Id) -> bool {
    let expected: Inline<GenId> = kind.to_inline();
    rows.iter()
        .any(|row| row.a() == &metadata::tag.id() && row.v::<UnknownInline>().raw == expected.raw)
}

fn values(rows: &[Trible], attribute: Id) -> Vec<RawInline> {
    rows.iter()
        .filter(|row| row.a() == &attribute)
        .map(|row| row.v::<UnknownInline>().raw)
        .collect()
}

fn exactly_one(
    rows: &[Trible],
    attribute: Id,
    field: &str,
    entity: Id,
) -> std::result::Result<RawInline, String> {
    let values = values(rows, attribute);
    if values.len() != 1 {
        return Err(format!(
            "Archive entity {entity:X} has {} values for scalar {field}",
            values.len()
        ));
    }
    Ok(values[0])
}

fn parse_id(raw: RawInline, field: &str) -> std::result::Result<Id, String> {
    Id::try_from_inline(&Inline::<GenId>::new(raw))
        .map_err(|_| format!("Archive {field} is not a canonical non-nil GenId"))
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use anybytes::Bytes;
    use tempfile::TempDir;
    use triblespace::core::blob::encodings::UnknownBlob;
    use triblespace::core::id::ExclusiveId;
    use triblespace::core::repo::{BlobStore, BlobStorePut};
    use triblespace::core::trible::Fragment;
    use triblespace::macros::entity;

    use super::*;
    use crate::blockdag as archive;

    struct StoredBlobs {
        _directory: TempDir,
        reader: PileReader,
    }

    impl StoredBlobs {
        fn new(blobs: impl IntoIterator<Item = Blob<UnknownBlob>>) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("archive-bm25-test.pile");
            File::create(&path).unwrap();
            let mut pile = crate::collection_cutover::open_pile_strict(&path).unwrap();
            for blob in blobs {
                pile.put::<UnknownBlob, _>(blob).unwrap();
            }
            pile.flush().unwrap();
            let reader = pile.reader().unwrap();
            pile.close().unwrap();
            Self {
                _directory: directory,
                reader,
            }
        }
    }

    fn source_and_attachments(fragment: Fragment) -> (Blob<SimpleArchive>, Vec<Blob<UnknownBlob>>) {
        let (facts, mut blobs) = fragment.into_facts_and_blobs();
        let source: Blob<SimpleArchive> = facts.to_blob();
        let attachments = blobs
            .reader()
            .unwrap()
            .into_iter()
            .map(|(_, blob)| blob)
            .collect();
        (source, attachments)
    }

    fn text_block(parts: &[(Id, &str)]) -> Fragment {
        let mut occurrences = Fragment::empty();
        for (ordinal, (modality, text)) in parts.iter().enumerate() {
            let fact = archive::text_fact(
                *modality,
                schema::content_fact::direction::IN,
                (*text).to_owned(),
            )
            .unwrap();
            occurrences += archive::content_part(ordinal as u64, fact, None).unwrap();
        }
        archive::block(std::iter::empty::<Id>(), None, occurrences).unwrap()
    }

    fn parse(blob: Blob<PortableBM25Blob>) -> ArchiveBM25Index {
        ArchiveBM25Index::try_from_blob(blob).unwrap()
    }

    fn derive(reader: &PileReader, source: Blob<SimpleArchive>) -> Blob<PortableBM25Blob> {
        derive_element(reader, source).unwrap()
    }

    #[test]
    fn recipe_v1_freezes_case_punctuation_and_unicode_tokenization() {
        let actual: Vec<_> = hash_tokens("Hello, WORLD — hello. 🛰️")
            .into_iter()
            .map(|token| hex::encode_upper(token.raw))
            .collect();
        assert_eq!(
            actual,
            [
                "EA8F163DB38682925E4491C5E58D4BB3506EF8C14EB78A86E908C5624A67200F",
                "D7894AE9716D38D2DFAD0EC55424CA321EE12453D51F1B3ADEB77D0475ED988C",
                "EA8F163DB38682925E4491C5E58D4BB3506EF8C14EB78A86E908C5624A67200F",
                "A7908C180BA54AD5F231D25EA710B3C5C4485B8445F0E9D95ECA460DCA3A966E",
            ]
        );
        assert_eq!(
            hex::encode_upper(hash_tokens("CAFÉ…")[0].raw),
            "9B79CF554A46C059EE5892ECB71EDAC015A8461816ABF33A5F7936087F5669E6"
        );
    }

    #[test]
    fn empty_corpus_and_textless_blocks_remain_documents() {
        let (empty_source, empty_attachments) = source_and_attachments(Fragment::empty());
        let empty_store = StoredBlobs::new(empty_attachments);
        let empty = parse(derive(&empty_store.reader, empty_source));
        assert_eq!(empty.doc_count(), 0);
        assert_eq!(empty.term_count(), 0);

        let empty_text = text_block(&[(schema::content_fact::modality::TEXT, "")]);
        let empty_text_id = empty_text.root().unwrap();
        let binary_fact = archive::blob_fact(
            schema::content_fact::modality::IMAGE,
            schema::content_fact::direction::IN,
            vec![0, 1, 2, 3],
            "application/octet-stream",
        )
        .unwrap();
        let binary_part = archive::content_part(0, binary_fact, None).unwrap();
        let binary_block = archive::block(std::iter::empty::<Id>(), None, binary_part).unwrap();
        let binary_id = binary_block.root().unwrap();
        let mut corpus = empty_text;
        corpus += binary_block;
        let (source, attachments) = source_and_attachments(corpus);
        let store = StoredBlobs::new(attachments);
        let index = parse(derive(&store.reader, source));
        let documents: BTreeSet<_> = index.document_keys().map(|doc| doc.raw).collect();
        assert_eq!(index.doc_count(), 2);
        assert_eq!(index.term_count(), 0);
        let empty_text_inline: Inline<GenId> = empty_text_id.to_inline();
        let binary_inline: Inline<GenId> = binary_id.to_inline();
        assert_eq!(
            documents,
            BTreeSet::from([empty_text_inline.raw, binary_inline.raw])
        );
    }

    #[test]
    fn repeated_part_occurrences_sum_across_modalities() {
        let block = text_block(&[
            (schema::content_fact::modality::THINKING, "echo"),
            (schema::content_fact::modality::TOOL_RESULT, "echo"),
        ]);
        let block_id = block.root().unwrap();
        let (source, attachments) = source_and_attachments(block);
        let store = StoredBlobs::new(attachments);
        let index = parse(derive(&store.reader, source));
        let document: Inline<GenId> = block_id.to_inline();
        let term = hash_tokens("echo")[0];
        assert_eq!(index.term_frequency(&document, &term), 2);
        assert_eq!(index.merged(&index).unwrap(), index);
    }

    #[test]
    fn derivation_commutes_with_union_and_carrier_join() {
        let left = text_block(&[(schema::content_fact::modality::TEXT, "alpha alpha")]);
        let right = text_block(&[(schema::content_fact::modality::TEXT, "beta")]);
        let left_source: Blob<SimpleArchive> = left.facts().clone().to_blob();
        let right_source: Blob<SimpleArchive> = right.facts().clone().to_blob();
        let mut union = left;
        union += right;
        let (union_source, attachments) = source_and_attachments(union);
        let store = StoredBlobs::new(attachments);

        let left = parse(derive(&store.reader, left_source));
        let right = parse(derive(&store.reader, right_source));
        let direct = derive(&store.reader, union_source);
        let merged: Blob<PortableBM25Blob> = left.merged(&right).unwrap().to_blob();
        let reverse: Blob<PortableBM25Blob> = right.merged(&left).unwrap().to_blob();
        assert_eq!(merged.bytes, direct.bytes);
        assert_eq!(reverse.bytes, direct.bytes);
    }

    #[test]
    fn missing_payload_and_malformed_source_fail_derivation() {
        let block = text_block(&[(schema::content_fact::modality::TEXT, "not resident")]);
        let (source, _attachments) = source_and_attachments(block);
        let missing_store = StoredBlobs::new([]);
        let error = derive_element(&missing_store.reader, source).unwrap_err();
        assert!(format!("{error:#}").contains("nonresident text payload"));

        let mut malformed_graph =
            text_block(&[(schema::content_fact::modality::TEXT, "also absent")]);
        let block_id = malformed_graph.root().unwrap();
        malformed_graph += entity! { ExclusiveId::force_ref(&block_id) @
            metadata::name: "unexpected block field",
        };
        let (malformed_graph, _attachments) = source_and_attachments(malformed_graph);
        let malformed_store = StoredBlobs::new([]);
        let error = derive_element(&malformed_store.reader, malformed_graph).unwrap_err();
        assert!(format!("{error:#}").contains("unknown attribute"));

        let malformed = Blob::<SimpleArchive>::new(Bytes::from(vec![0xFF]));
        let error = derive_element(&malformed_store.reader, malformed).unwrap_err();
        assert!(format!("{error:#}").contains("canonical SimpleArchive"));
    }
}
