//! Portable exact-term-frequency BM25 over canonical Archive blocks.
//!
//! This module is one concrete V4 collection mapping, not a registry. Its
//! source is Archive's canonical `SimpleArchive` union and its target is the
//! portable BM25 carrier. Every canonical semantic block is a document,
//! including a genuine textless block. The unique content-free canonical
//! bottom used only by raw source receipts is excluded so provenance volume
//! cannot perturb corpus statistics. Content parts are occurrences, so the
//! same content fact at two ordinals contributes twice. Every selected
//! `UTF8String` payload is tokenized with [`hash_tokens`], and repeated
//! documents join by pointwise maximum in the portable carrier.
//!
//! Importer receipts are deliberately outside the projection. The mapping is
//! an open-world typed query: unknown facts and undecodable rows are inert,
//! while a block-selected part/fact closure which is actually needed for this
//! BM25 value must be present in the same derivable source element.

use std::collections::{BTreeMap, BTreeSet};

use anybytes::View;
use anyhow::{bail, Result};

use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::utf8string::UTF8String;
use triblespace::core::blob::{Blob, IntoBlob, TryFromBlob};
use triblespace::core::collection::records::{mapping_algorithm, KIND_COLLECTION_MAPPING};
use triblespace::core::collection::{CollectionMapping, CollectionOperationError};
use triblespace::core::id::{id_hex, Id};
use triblespace::core::inline::encodings::genid::GenId;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::{Inline, IntoInline, RawInline};
use triblespace::core::metadata::{self, MetaDescribe};
use triblespace::core::repo::{BlobStoreGet, BlobStoreMeta};
use triblespace::core::trible::Fragment;
use triblespace::core::trible::TribleSet;
use triblespace::macros::entity;
use triblespace::prelude::blobencodings::RawBytes;
use triblespace::prelude::{find, pattern};
use triblespace_search::portable_bm25::{PortableBM25Blob, PortableBM25Index};
use triblespace_search::tokens::{hash_tokens, WordHash};

use crate::schemas::blockdag as schema;

/// Archive-block-text BM25 member mapping, version 1.
///
/// Minted with `trible genid` on 2026-08-30:
/// `4EC6991611EF484A37FBD95F6E108FC6`.
///
/// Changing the selected graph fields, occurrence aggregation / term-frequency
/// law, tokenizer behavior, or document/term schemas requires a new mapping id.
/// Joining mapped members belongs to [`PortableBM25Blob`], not this identity.
/// BM25 `k1` / `b` scoring policy is derived query behavior and is deliberately
/// outside the persisted collection identity.
pub const ARCHIVE_BLOCK_TEXT_BM25_MAPPING_V1: Id = id_hex!("4EC6991611EF484A37FBD95F6E108FC6");

pub type ArchiveBM25Index = PortableBM25Index<GenId, WordHash>;

#[derive(Debug)]
enum DeriveValidation {
    Ready(Blob<PortableBM25Blob>),
    Pending,
    Rejected(String),
}

#[derive(Debug)]
struct ProjectionPlan {
    documents: BTreeMap<Id, Vec<Inline<Handle<UTF8String>>>>,
}

/// The archive-block-text BM25 law, as a describable type.
///
/// A descriptor embeds this rather than only naming it, so a reader holding
/// the pile can learn what the index is without the code that built it.
pub struct ArchiveBlockTextBm25MappingV1;

impl MetaDescribe for ArchiveBlockTextBm25MappingV1 {
    fn describe() -> triblespace::core::trible::Fragment {
        let id: Id = ARCHIVE_BLOCK_TEXT_BM25_MAPPING_V1;
        entity! {
            triblespace::core::id::ExclusiveId::force_ref(&id) @
                metadata::name: "archive-block-text-bm25-v1",
                metadata::description: "Canonical mapping from one Archive SimpleArchive member to one PortableBM25Blob. Every canonical semantic block in that member is one document; Archive's content-free bottom is excluded, selected UTF8String payload occurrences are tokenized with hash_tokens, repeated terms contribute exact frequencies, and repeated documents combine by pointwise maximum. PortableBM25Blob owns target-member validation and join. The k1 and b scoring parameters are deliberately absent because they are query-time behaviour.",
                metadata::tag: metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        }
    }
}

/// Bound canonical projection from one Archive fact-set member to its
/// portable BM25 image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveBlockTextBm25Mapping;

impl CollectionMapping for ArchiveBlockTextBm25Mapping {
    type Source = SimpleArchive;
    type Target = PortableBM25Blob;

    fn fragment(&self) -> Fragment {
        mapping_fragment()
    }

    fn bind(_source: &Fragment, target: &Fragment) -> Result<Self, CollectionOperationError> {
        let actual = triblespace::core::collection::descriptor::mapping_algorithm(target.facts())
            .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?;
        if actual != Some(ARCHIVE_BLOCK_TEXT_BM25_MAPPING_V1) {
            return Err(CollectionOperationError::Fatal(format!(
                "Archive BM25 mapping algorithm {:?} does not match archive-block-text-v1 \
                 {ARCHIVE_BLOCK_TEXT_BM25_MAPPING_V1:X}",
                actual.map(|id| format!("{id:X}")),
            )));
        }
        Ok(Self)
    }

    fn map<R>(
        &self,
        source: &Blob<SimpleArchive>,
        reader: &R,
    ) -> Result<Blob<PortableBM25Blob>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        derive_element(reader, source.clone())
            .map_err(|error| CollectionOperationError::Fatal(format!("{error:#}")))
    }
}

fn mapping_fragment() -> Fragment {
    entity! {
        metadata::tag: KIND_COLLECTION_MAPPING,
        mapping_algorithm*: <ArchiveBlockTextBm25MappingV1 as MetaDescribe>::describe(),
    }
}

/// Build one exact portable Archive BM25 element.
///
/// A missing selected payload is an operational cache miss for an active
/// builder. A later exact ensure retries with a fresh attachment reader.
pub fn derive_element<R>(reader: &R, source: Blob<SimpleArchive>) -> Result<Blob<PortableBM25Blob>>
where
    R: BlobStoreGet + BlobStoreMeta,
{
    match derive_for_validation(reader, source)? {
        DeriveValidation::Ready(blob) => Ok(blob),
        DeriveValidation::Pending => bail!("Archive BM25 source has a nonresident text payload"),
        DeriveValidation::Rejected(reason) => bail!("invalid Archive BM25 source: {reason}"),
    }
}

fn derive_for_validation<R>(reader: &R, source: Blob<SimpleArchive>) -> Result<DeriveValidation>
where
    R: BlobStoreGet + BlobStoreMeta,
{
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
        let blob: Blob<UTF8String> = reader.get(handle)?;
        let text: View<str> = match blob.bytes.clone().view() {
            Ok(text) => text,
            Err(error) => {
                return Ok(DeriveValidation::Rejected(format!(
                    "resident UTF8String payload {} is not UTF-8: {error}",
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
    let block_ids: BTreeSet<Id> = find!(
        block: Id,
        pattern!(&facts, [{ ?block @ metadata::tag: &schema::block::KIND }])
    )
    .collect();
    let mut documents = BTreeMap::new();
    for block_id in block_ids {
        let part_ids: BTreeSet<Id> = find!(
            part: Id,
            pattern!(&facts, [{ block_id @ schema::block::contains: ?part }])
        )
        .collect();
        // The unique content-free bottom is not a BM25 document. Under the
        // open-world schema, other tag-only rows are simply nonmatching too;
        // neither case licenses reconstructing or validating an entity id.
        if part_ids.is_empty() {
            continue;
        }

        let mut parts = Vec::new();
        for part_id in part_ids {
            let occurrences: BTreeSet<(u64, Id)> = find!(
                (ordinal: u64, fact: Id),
                pattern!(&facts, [{
                    part_id @ metadata::tag: &schema::content_part::KIND,
                    schema::content_part::ordinal: ?ordinal,
                    schema::content_part::fact: ?fact,
                }])
            )
            .collect();
            if occurrences.is_empty() {
                return Err(format!(
                    "Archive block {block_id:X} references absent part {part_id:X} or one without typed fields"
                ));
            }
            for (ordinal, fact_id) in occurrences {
                if find!(
                    (modality: Id, direction: Id),
                    pattern!(&facts, [{
                        fact_id @ metadata::tag: &schema::content_fact::KIND,
                        schema::content_fact::modality: ?modality,
                        schema::content_fact::direction: ?direction,
                    }])
                )
                .next()
                .is_none()
                {
                    return Err(format!(
                        "Archive part {part_id:X} references absent or untyped fact {fact_id:X}"
                    ));
                }
                let payloads: Vec<Inline<Handle<UTF8String>>> = find!(
                    payload: Inline<Handle<UTF8String>>,
                    pattern!(&facts, [{ fact_id @ schema::content_fact::payload: ?payload }])
                )
                .collect();
                let has_nontext_payload = find!(
                    _blob: Inline<Handle<RawBytes>>,
                    pattern!(&facts, [{ fact_id @ schema::content_fact::blob: ?_blob }])
                )
                .next()
                .is_some()
                    || find!(
                        _pointer: Inline<Handle<UTF8String>>,
                        pattern!(&facts, [{
                            fact_id @ schema::content_fact::asset_pointer: ?_pointer
                        }])
                    )
                    .next()
                    .is_some();
                if payloads.is_empty() && !has_nontext_payload {
                    return Err(format!(
                        "Archive content fact {fact_id:X} has no typed payload variant"
                    ));
                }
                parts.push((ordinal, part_id, payloads));
            }
        }
        parts.sort_unstable_by_key(|(ordinal, part, _)| (*ordinal, *part));
        let payloads = parts
            .into_iter()
            .flat_map(|(_, _, payloads)| payloads)
            .collect();
        documents.insert(block_id, payloads);
    }
    Ok(ProjectionPlan { documents })
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use anybytes::Bytes;
    use tempfile::TempDir;
    use triblespace::core::blob::encodings::UnknownBlob;
    use triblespace::core::id::ExclusiveId;
    use triblespace::core::repo::pile::PileSnapshot;
    use triblespace::core::repo::{BlobStorePut, SnapshotSource};
    use triblespace::core::trible::Fragment;
    use triblespace::macros::entity;

    use super::*;
    use crate::blockdag as archive;

    struct StoredBlobs {
        _directory: TempDir,
        reader: PileSnapshot,
    }

    impl StoredBlobs {
        fn new(blobs: impl IntoIterator<Item = Blob<UnknownBlob>>) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("archive-bm25-test.pile");
            File::create(&path).unwrap();
            let mut pile = crate::storage::open_pile_strict(&path).unwrap();
            for blob in blobs {
                pile.put::<UnknownBlob, _>(blob).unwrap();
            }
            pile.flush().unwrap();
            let reader = pile.snapshot().unwrap();
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
            .snapshot()
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

    fn derive(reader: &PileSnapshot, source: Blob<SimpleArchive>) -> Blob<PortableBM25Blob> {
        derive_element(reader, source).unwrap()
    }

    #[test]
    fn mapping_v1_freezes_case_punctuation_and_unicode_tokenization() {
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
    fn empty_corpus_and_semantic_textless_blocks_remain_documents() {
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
        let bottom = archive::block(std::iter::empty::<Id>(), None, Fragment::empty()).unwrap();
        let mut corpus = empty_text;
        corpus += binary_block;
        corpus += bottom;
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
    fn canonical_bottom_does_not_perturb_the_bm25_carrier() {
        let semantic = text_block(&[(schema::content_fact::modality::TEXT, "stable corpus")]);
        let (semantic_source, semantic_attachments) = source_and_attachments(semantic.clone());
        let semantic_store = StoredBlobs::new(semantic_attachments);
        let semantic_index = parse(derive(&semantic_store.reader, semantic_source));

        let mut with_bottom = semantic;
        with_bottom += archive::block(std::iter::empty::<Id>(), None, Fragment::empty()).unwrap();
        let (with_bottom_source, with_bottom_attachments) = source_and_attachments(with_bottom);
        let with_bottom_store = StoredBlobs::new(with_bottom_attachments);
        let with_bottom_index = parse(derive(&with_bottom_store.reader, with_bottom_source));

        assert_eq!(semantic_index, with_bottom_index);
    }

    #[test]
    fn content_free_nonmatching_rows_are_inert() {
        let predecessor = text_block(&[(schema::content_fact::modality::TEXT, "parent")]);
        let predecessor_id = predecessor.root().unwrap();
        let mut invalid = entity! { _ @
            schema::block::previous: &predecessor_id,
        };
        let invalid_id = invalid.root().unwrap();
        invalid += entity! { ExclusiveId::force_ref(&invalid_id) @
            metadata::tag: &schema::block::KIND,
        };

        let mut corpus = predecessor;
        corpus += invalid;
        let (source, attachments) = source_and_attachments(corpus);
        let store = StoredBlobs::new(attachments);
        let index = parse(derive(&store.reader, source));
        assert_eq!(index.doc_count(), 1);
        let predecessor_inline: Inline<GenId> = predecessor_id.to_inline();
        assert_eq!(
            index
                .document_keys()
                .map(|document| document.raw)
                .collect::<Vec<_>>(),
            vec![predecessor_inline.raw],
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
    fn selected_missing_payload_and_malformed_encoding_fail_derivation() {
        let block = text_block(&[(schema::content_fact::modality::TEXT, "not resident")]);
        let (source, _attachments) = source_and_attachments(block);
        let missing_store = StoredBlobs::new([]);
        let error = derive_element(&missing_store.reader, source).unwrap_err();
        assert!(format!("{error:#}").contains("nonresident text payload"));

        let fact = archive::text_fact(
            schema::content_fact::modality::TEXT,
            schema::content_fact::direction::IN,
            "open world",
        )
        .unwrap();
        let part = archive::content_part(0, fact, None).unwrap();
        let part_id = part.root().unwrap();
        let block_id = Id::new([0xA5; 16]).unwrap();
        let mut graph_with_unknown_fact = part;
        graph_with_unknown_fact += entity! { ExclusiveId::force_ref(&block_id) @
            metadata::tag: &schema::block::KIND,
            metadata::name: "unexpected block field",
            schema::block::contains: &part_id,
        };
        let (graph_with_unknown_fact, attachments) =
            source_and_attachments(graph_with_unknown_fact);
        let open_world_store = StoredBlobs::new(attachments);
        let index = parse(derive(&open_world_store.reader, graph_with_unknown_fact));
        let block_inline: Inline<GenId> = block_id.to_inline();
        assert_eq!(
            index.doc_count(),
            1,
            "unknown facts do not close the schema"
        );
        assert_eq!(
            index
                .document_keys()
                .map(|document| document.raw)
                .collect::<Vec<_>>(),
            vec![block_inline.raw],
            "the selected entity id remains opaque",
        );

        let malformed = Blob::<SimpleArchive>::new(Bytes::from(vec![0xFF]));
        let error = derive_element(&open_world_store.reader, malformed).unwrap_err();
        assert!(format!("{error:#}").contains("canonical SimpleArchive"));
    }
}
