//! Canonical entries in the immutable episodic Memory journal.
//!
//! A memory is what was remembered in one moment. Later understanding adds a
//! later memory; it does not turn the earlier experience into a false database
//! row. Every canonical chunk in the collection is therefore visible. There
//! are no heads, tombstones, or semantic retractions in this model.
//!
//! Historical native chunks may carry `metadata::supersedes` because those
//! edges participated in their content-derived identities. The loader retains
//! them solely to verify those old ids. They have no ordering or visibility
//! semantics, and new chunks never emit them. Legacy random ids survive only
//! as additive exact aliases for old prose links.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::core::repo::{BlobStoreGet, BlobStoreMeta};
use triblespace::prelude::*;

use crate::schemas::memory::{ctx, KIND_CHUNK_ID};

pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;
pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;
pub type ImageHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkContent {
    Text(TextHandle),
    Image(ImageHandle),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkRow {
    pub id: Id,
    pub content: ChunkContent,
    pub start_at: IntervalValue,
    pub end_at: IntervalValue,
    pub lens: Option<TextHandle>,
    pub references: BTreeSet<Id>,
    pub about_exec_result: Option<Id>,
    pub about_archive_message: Option<Id>,
    /// Inert historical identity material. New journal writes never populate
    /// this set and readers never interpret it as ordering or visibility.
    pub predecessors: BTreeSet<Id>,
    /// Genuine creation/import observations, outside intrinsic state.
    pub observed_at: BTreeSet<IntervalValue>,
    /// Extrinsic historical names, outside intrinsic state.
    pub aliases: BTreeSet<Id>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct MemoryCatalog {
    pub chunks: BTreeMap<Id, ChunkRow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChunkDraftContent {
    Text(String),
    Image(Vec<u8>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkDraft {
    pub content: ChunkDraftContent,
    pub start_at: IntervalValue,
    pub end_at: IntervalValue,
    pub lens: Option<String>,
    pub references: BTreeSet<Id>,
    pub about_exec_result: Option<Id>,
    pub about_archive_message: Option<Id>,
    pub observed_at: BTreeSet<IntervalValue>,
    pub aliases: BTreeSet<Id>,
}

fn point_bounds(entity: Option<Id>, field: &str, value: IntervalValue) -> Result<i128> {
    let (lower, upper): (i128, i128) = value.try_from_inline().map_err(|error| match entity {
        Some(entity) => anyhow!("decode {field} on Memory entity {entity:x}: {error:?}"),
        None => anyhow!("decode {field}: {error:?}"),
    })?;
    if lower != upper {
        match entity {
            Some(entity) => bail!("{field} on Memory entity {entity:x} must be a point interval"),
            None => bail!("{field} must be a point interval"),
        }
    }
    Ok(lower)
}

fn one<T: Ord>(mut values: BTreeSet<T>, entity: Id, field: &str) -> Result<Option<T>> {
    match values.len() {
        0 => Ok(None),
        1 => Ok(values.pop_first()),
        count => {
            bail!("Memory entity {entity:x} has {count} values for {field}; expected at most one")
        }
    }
}

fn one_required<T: Ord>(values: BTreeSet<T>, entity: Id, field: &str) -> Result<T> {
    one(values, entity, field)?
        .ok_or_else(|| anyhow!("Memory entity {entity:x} is missing {field}"))
}

fn tagged_entities(space: &TribleSet, kind: Id) -> BTreeSet<Id> {
    find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: kind }])).collect()
}

#[allow(clippy::too_many_arguments)]
fn chunk_core(
    content: ChunkContent,
    start_at: IntervalValue,
    end_at: IntervalValue,
    lens: Option<TextHandle>,
    references: &BTreeSet<Id>,
    about_exec_result: Option<Id>,
    about_archive_message: Option<Id>,
    predecessors: &BTreeSet<Id>,
) -> Fragment {
    let summary = match content {
        ChunkContent::Text(handle) => Some(handle),
        ChunkContent::Image(_) => None,
    };
    let image = match content {
        ChunkContent::Text(_) => None,
        ChunkContent::Image(handle) => Some(handle),
    };
    entity! {
        metadata::tag: &KIND_CHUNK_ID,
        ctx::summary?: summary.as_ref(),
        ctx::image?: image.as_ref(),
        ctx::start_at: start_at,
        ctx::end_at: end_at,
        ctx::lens?: lens.as_ref(),
        ctx::reference*: references.iter(),
        ctx::about_exec_result?: about_exec_result.as_ref(),
        ctx::about_archive_message?: about_archive_message.as_ref(),
        metadata::supersedes*: predecessors.iter(),
    }
}

fn annotate_chunk(
    mut fragment: Fragment,
    observed_at: &BTreeSet<IntervalValue>,
    aliases: &BTreeSet<Id>,
) -> Fragment {
    let id = fragment
        .root()
        .expect("canonical Memory chunk core has one intrinsic root");
    for at in observed_at {
        fragment += entity! { ExclusiveId::force_ref(&id) @ metadata::created_at: at };
    }
    for alias in aliases {
        let alias = inlineencodings::GenId::inline_from(*alias);
        fragment += entity! { ExclusiveId::force_ref(&id) @ metadata::anchor: alias };
    }
    fragment
}

fn chunk_record(row: &ChunkRow) -> Fragment {
    annotate_chunk(
        chunk_core(
            row.content,
            row.start_at,
            row.end_at,
            row.lens,
            &row.references,
            row.about_exec_result,
            row.about_archive_message,
            &row.predecessors,
        ),
        &row.observed_at,
        &row.aliases,
    )
}

pub fn chunk_fragment(draft: ChunkDraft) -> Result<(Fragment, Id)> {
    let start = point_bounds(None, "chunk start", draft.start_at)?;
    let end = point_bounds(None, "chunk end", draft.end_at)?;
    if end < start {
        bail!("chunk end precedes its start");
    }
    for at in &draft.observed_at {
        point_bounds(None, "chunk observation time", *at)?;
    }
    if draft.lens.as_ref().is_some_and(|lens| lens.is_empty()) {
        bail!("memory lens must not be empty");
    }

    let mut fragment = Fragment::empty();
    let content = match draft.content {
        ChunkDraftContent::Text(summary) => {
            if summary.is_empty() {
                bail!("memory summary must not be empty");
            }
            ChunkContent::Text(fragment.put(summary))
        }
        ChunkDraftContent::Image(image) => {
            if image.is_empty() {
                bail!("memory image must not be empty");
            }
            ChunkContent::Image(fragment.put::<blobencodings::RawBytes, _>(image))
        }
    };
    let lens = draft.lens.map(|lens| fragment.put(lens));
    fragment += annotate_chunk(
        chunk_core(
            content,
            draft.start_at,
            draft.end_at,
            lens,
            &draft.references,
            draft.about_exec_result,
            draft.about_archive_message,
            &BTreeSet::new(),
        ),
        &draft.observed_at,
        &draft.aliases,
    );
    let id = fragment
        .root()
        .ok_or_else(|| anyhow!("Memory chunk fragment has no unique intrinsic root"))?;
    Ok((fragment, id))
}

fn load_chunk(space: &TribleSet, id: Id) -> Result<Option<ChunkRow>> {
    let summaries: BTreeSet<TextHandle> =
        find!(value: TextHandle, pattern!(space, [{ id @ ctx::summary: ?value }])).collect();
    let images: BTreeSet<ImageHandle> =
        find!(value: ImageHandle, pattern!(space, [{ id @ ctx::image: ?value }])).collect();
    let content = match (summaries.len(), images.len()) {
        (1, 0) => ChunkContent::Text(*summaries.first().expect("one summary")),
        (0, 1) => ChunkContent::Image(*images.first().expect("one image")),
        (summary_count, image_count) => bail!(
            "Memory chunk {id:x} has {summary_count} summaries and {image_count} images; expected exactly one content value"
        ),
    };
    let row = ChunkRow {
        id,
        content,
        start_at: one_required(
            find!(value: IntervalValue, pattern!(space, [{ id @ ctx::start_at: ?value }]))
                .collect(),
            id,
            "ctx::start_at",
        )?,
        end_at: one_required(
            find!(value: IntervalValue, pattern!(space, [{ id @ ctx::end_at: ?value }])).collect(),
            id,
            "ctx::end_at",
        )?,
        lens: one(
            find!(value: TextHandle, pattern!(space, [{ id @ ctx::lens: ?value }])).collect(),
            id,
            "ctx::lens",
        )?,
        references: find!(value: Id, pattern!(space, [{ id @ ctx::reference: ?value }])).collect(),
        about_exec_result: one(
            find!(value: Id, pattern!(space, [{ id @ ctx::about_exec_result: ?value }])).collect(),
            id,
            "ctx::about_exec_result",
        )?,
        about_archive_message: one(
            find!(value: Id, pattern!(space, [{ id @ ctx::about_archive_message: ?value }]))
                .collect(),
            id,
            "ctx::about_archive_message",
        )?,
        predecessors: find!(value: Id, pattern!(space, [{ id @ metadata::supersedes: ?value }]))
            .collect(),
        observed_at:
            find!(value: IntervalValue, pattern!(space, [{ id @ metadata::created_at: ?value }]))
                .collect(),
        aliases: find!(value: Id, pattern!(space, [{ id @ metadata::anchor: ?value }])).collect(),
    };
    let canonical = chunk_core(
        row.content,
        row.start_at,
        row.end_at,
        row.lens,
        &row.references,
        row.about_exec_result,
        row.about_archive_message,
        &row.predecessors,
    )
    .root()
    .expect("chunk core has one root");
    if canonical != id {
        // Additive cutover preserves the historical random-id record beside
        // its intrinsic shadow.  Such a row is still queryable provenance,
        // but it is not a member of the native Memory read model.
        return Ok(None);
    }
    let start = point_bounds(Some(id), "chunk start", row.start_at)?;
    let end = point_bounds(Some(id), "chunk end", row.end_at)?;
    if end < start {
        bail!("Memory chunk {id:x} ends before it starts");
    }
    for at in &row.observed_at {
        point_bounds(Some(id), "chunk observation time", *at)?;
    }
    Ok(Some(row))
}

/// Strictly project every canonical entry in the episodic Memory journal.
/// Historical retraction entities and unrelated preserved facts are inert:
/// only canonical `KIND_CHUNK_ID` records participate in this read model.
fn load_catalog(space: &TribleSet) -> Result<MemoryCatalog> {
    let chunk_ids = tagged_entities(space, KIND_CHUNK_ID);
    let mut catalog = MemoryCatalog::default();
    for id in &chunk_ids {
        if let Some(row) = load_chunk(space, *id)? {
            catalog.chunks.insert(*id, row);
        }
    }

    for row in catalog.chunks.values() {
        for reference in &row.references {
            if !catalog.chunks.contains_key(reference) {
                bail!(
                    "Memory chunk {:x} references missing chunk {reference:x}",
                    row.id
                );
            }
        }
    }
    Ok(catalog)
}

fn read_text_overlay<Overlay>(
    reader: &PileSnapshot,
    overlay: Option<&Overlay>,
    handle: TextHandle,
) -> Result<String>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    if let Some(overlay) = overlay {
        if overlay.metadata(handle)?.is_some() {
            let value: anybytes::View<str> = overlay.get(handle)?;
            return Ok(value.to_string());
        }
    }
    let value: anybytes::View<str> = reader.get(handle)?;
    Ok(value.to_string())
}

fn read_image_overlay<Overlay>(
    reader: &PileSnapshot,
    overlay: Option<&Overlay>,
    handle: ImageHandle,
) -> Result<anybytes::Bytes>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    if let Some(overlay) = overlay {
        if overlay.metadata(handle)?.is_some() {
            return overlay.get(handle).map_err(Into::into);
        }
    }
    reader.get(handle).map_err(Into::into)
}

fn validate_payloads<Overlay>(
    reader: &PileSnapshot,
    overlay: Option<&Overlay>,
    catalog: &MemoryCatalog,
) -> Result<()>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    for row in catalog.chunks.values() {
        match row.content {
            ChunkContent::Text(handle) => {
                let summary = read_text_overlay(reader, overlay, handle)
                    .with_context(|| format!("read Memory chunk {:x} summary", row.id))?;
                if summary.is_empty() {
                    bail!("Memory chunk {:x} has an empty summary", row.id);
                }
            }
            ChunkContent::Image(handle) => {
                let image = read_image_overlay(reader, overlay, handle)
                    .with_context(|| format!("read Memory chunk {:x} image", row.id))?;
                if image.is_empty() {
                    bail!("Memory chunk {:x} has an empty image", row.id);
                }
            }
        }
        if let Some(handle) = row.lens {
            let lens = read_text_overlay(reader, overlay, handle)
                .with_context(|| format!("read Memory chunk {:x} lens", row.id))?;
            if lens.is_empty() {
                bail!("Memory chunk {:x} has an empty lens", row.id);
            }
        }
    }
    Ok(())
}

pub fn validate_catalog(reader: &PileSnapshot, facts: &TribleSet) -> Result<()> {
    let catalog = load_catalog(facts)?;
    validate_payloads(reader, None::<&PileSnapshot>, &catalog)?;
    Ok(())
}

/// Validate the exact union a publication would create, including blobs still
/// staged only inside `fragment`, before a signed root is written.
pub fn validate_candidate(
    reader: &PileSnapshot,
    current: &TribleSet,
    fragment: &Fragment,
) -> Result<()> {
    let prior = load_catalog(current)?;
    let mut union = current.clone();
    union += fragment.facts().clone();
    let catalog = load_catalog(&union)?;
    for id in prior.chunks.keys() {
        if !catalog.chunks.contains_key(id) {
            bail!(
                "Memory mutation changes the intrinsic core of existing chunk {id:x}; write a distinct immutable chunk instead"
            );
        }
    }
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .snapshot()
        .context("snapshot staged Memory attachments")?;
    validate_payloads(reader, Some(&overlay), &catalog)?;
    Ok(())
}

pub fn read_text(reader: &PileSnapshot, handle: TextHandle) -> Result<String> {
    read_text_overlay(reader, None::<&PileSnapshot>, handle)
}

pub fn read_image(reader: &PileSnapshot, handle: ImageHandle) -> Result<anybytes::Bytes> {
    read_image_overlay(reader, None::<&PileSnapshot>, handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    use crate::collection_names::open_configured;
    use crate::schemas::memory::DEFAULT_SCOPE_ID;
    use crate::storage::open_pile_strict;
    use crate::test_support::initialize_open_collection_fixture;
    use ed25519_dalek::SigningKey;
    use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace::core::collection::{Collection, CollectionStoreExt};

    fn collection(
        pile: &mut triblespace::core::repo::pile::Pile,
        signer: &SigningKey,
    ) -> Collection<SimpleArchive> {
        open_configured(pile, DEFAULT_SCOPE_ID, signer.verifying_key()).unwrap()
    }

    fn point(seconds: f64) -> IntervalValue {
        let at = hifitime::Epoch::from_tai_seconds(seconds);
        (at, at).try_to_inline().unwrap()
    }

    fn draft(summary: &str) -> ChunkDraft {
        ChunkDraft {
            content: ChunkDraftContent::Text(summary.to_owned()),
            start_at: point(10.0),
            end_at: point(20.0),
            lens: None,
            references: BTreeSet::new(),
            about_exec_result: None,
            about_archive_message: None,
            observed_at: BTreeSet::from([point(30.0)]),
            aliases: BTreeSet::new(),
        }
    }

    fn historical_chunk(summary: &str, predecessors: BTreeSet<Id>) -> (Fragment, Id) {
        let mut fragment = Fragment::empty();
        let content = ChunkContent::Text(fragment.put(summary.to_owned()));
        fragment += annotate_chunk(
            chunk_core(
                content,
                point(10.0),
                point(20.0),
                None,
                &BTreeSet::new(),
                None,
                None,
                &predecessors,
            ),
            &BTreeSet::from([point(30.0)]),
            &BTreeSet::new(),
        );
        let id = fragment.root().expect("historical chunk has one root");
        (fragment, id)
    }

    fn facts(fragments: impl IntoIterator<Item = Fragment>) -> TribleSet {
        let mut facts = TribleSet::new();
        for fragment in fragments {
            facts += fragment;
        }
        facts
    }

    #[test]
    fn observation_times_and_aliases_do_not_change_revision_identity() {
        let first = chunk_fragment(draft("same")).unwrap();
        let mut replay = draft("same");
        replay.observed_at = BTreeSet::from([point(99.0)]);
        replay.aliases.insert(Id::new([0x11; 16]).unwrap());
        let replay = chunk_fragment(replay).unwrap();
        assert_eq!(first.1, replay.1);
        assert_ne!(first.0, replay.0);
    }

    #[test]
    fn new_writes_never_emit_supersedes() {
        let (fragment, id) = chunk_fragment(draft("one episode")).unwrap();
        assert!(find!(
            predecessor: Id,
            pattern!(fragment.facts(), [{ id @ metadata::supersedes: ?predecessor }])
        )
        .next()
        .is_none());
    }

    #[test]
    fn historical_edges_and_retractions_do_not_hide_episodes() {
        let (base_fragment, base) = chunk_fragment(draft("what I felt first")).unwrap();
        let (later_fragment, later) =
            historical_chunk("what I understood later", BTreeSet::from([base]));
        let retraction = entity! {
            metadata::tag: &crate::schemas::memory::KIND_RETRACTION,
            metadata::supersedes: base,
        };

        let catalog = load_catalog(&facts([base_fragment, later_fragment, retraction])).unwrap();
        let ids: Vec<Id> = catalog.chunks.keys().copied().collect();
        assert_eq!(ids, vec![base.min(later), base.max(later)]);
        assert_eq!(catalog.chunks[&later].predecessors, BTreeSet::from([base]));
    }

    #[test]
    fn dangling_contextual_references_are_rejected() {
        let missing = Id::new([0x44; 16]).unwrap();
        let mut dangling = draft("dangling");
        dangling.references.insert(missing);
        let dangling = chunk_fragment(dangling).unwrap().0;
        assert!(load_catalog(&facts([dangling]))
            .unwrap_err()
            .to_string()
            .contains("references missing"));
    }

    #[test]
    fn scalar_ambiguity_is_rejected_but_unmodelled_annotations_are_inert() {
        let (fragment, id) = chunk_fragment(draft("one")).unwrap();
        let other = "two".to_owned().to_blob().get_handle();
        let corrupt = fragment + entity! { ExclusiveId::force_ref(&id) @ ctx::summary: other };
        assert!(load_catalog(&facts([corrupt])).is_err());

        let unknown = Id::new([0x55; 16]).unwrap();
        let (fragment, id) = chunk_fragment(draft("clean")).unwrap();
        let unrelated =
            fragment.clone() + entity! { ExclusiveId::force_ref(&unknown) @ ctx::reference: id };
        assert_eq!(load_catalog(&facts([unrelated])).unwrap().chunks.len(), 1);

        // OPEN WORLD: an attribute this reader does not model is an ANNOTATION,
        // not corruption. Ignoring it is the property that lets a newer writer
        // add facts without making every older reader refuse the record --- the
        // same property that makes `cat a.pile >> b.pile` safe. A reader that
        // rejected here would have the polarity backwards.
        let annotated =
            fragment + entity! { ExclusiveId::force_ref(&id) @ metadata::description: other };
        let catalog = load_catalog(&facts([annotated])).unwrap();
        assert_eq!(catalog.chunks.len(), 1);
        assert!(catalog.chunks.contains_key(&id));
    }

    #[test]
    fn additive_legacy_rows_are_inert_in_the_native_view() {
        let legacy_chunk = Id::new([0x56; 16]).unwrap();
        let summary = "legacy".to_owned().to_blob().get_handle();
        let rows = entity! { ExclusiveId::force_ref(&legacy_chunk) @
            metadata::tag: &KIND_CHUNK_ID,
            ctx::summary: summary,
            ctx::start_at: point(10.0),
            ctx::end_at: point(20.0),
            metadata::created_at: point(30.0),
        };
        let catalog = load_catalog(rows.facts()).unwrap();
        assert!(catalog.chunks.is_empty());
    }

    #[test]
    fn additive_legacy_rows_do_not_require_resident_payloads() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("memory.pile");
        File::create(&pile).unwrap();
        let mut pile_store = open_pile_strict(&pile).unwrap();
        let reader = pile_store.snapshot().unwrap();

        // The handle is intentionally not inserted into the pile. Exact
        // historical rows are durable evidence, but only intrinsic Memory
        // entities belong to the native catalog and therefore require their
        // attachments to be resident.
        let missing = "not resident".to_owned().to_blob().get_handle();
        let legacy = Id::new([0x58; 16]).unwrap();
        let rows = entity! { ExclusiveId::force_ref(&legacy) @
            metadata::tag: &KIND_CHUNK_ID,
            ctx::summary: missing,
            ctx::start_at: point(10.0),
            ctx::end_at: point(20.0),
            metadata::created_at: point(30.0),
        };

        validate_catalog(&reader, rows.facts()).unwrap();
        assert!(load_catalog(rows.facts()).unwrap().chunks.is_empty());
        pile_store.close().unwrap();
    }

    #[test]
    fn staged_attachments_validate_before_publication() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("memory.pile");
        let key = directory.path().join("memory.key");
        File::create(&pile).unwrap();
        let signer = initialize_open_collection_fixture(&pile, Some(&key));
        let mut pile_store = open_pile_strict(&pile).unwrap();
        let collection = collection(&mut pile_store, &signer);
        let reader = pile_store.snapshot().unwrap();
        let (before, _) = crate::storage::read_fact_collection(collection, &reader).unwrap();
        let fragment = chunk_fragment(draft("resident only in fragment"))
            .unwrap()
            .0;
        validate_candidate(&reader, &before, &fragment).unwrap();
        assert_eq!(load_catalog(&before).unwrap().chunks.len(), 0);

        pile_store.commit(collection, &signer, fragment).unwrap();
        let reader = pile_store.snapshot().unwrap();
        let (after, _) = crate::storage::read_fact_collection(collection, &reader).unwrap();
        validate_catalog(&reader, &after).unwrap();
        assert_eq!(load_catalog(&after).unwrap().chunks.len(), 1);
        pile_store.close().unwrap();
    }

    #[test]
    fn candidate_cannot_turn_a_canonical_node_into_inert_legacy_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("memory.pile");
        let key = directory.path().join("memory.key");
        File::create(&pile).unwrap();
        let signer = initialize_open_collection_fixture(&pile, Some(&key));
        let mut pile_store = open_pile_strict(&pile).unwrap();
        let (left, left_id) = chunk_fragment(draft("left")).unwrap();
        let (right, right_id) = chunk_fragment(draft("right")).unwrap();
        let mut initial = left;
        initial += right;
        let collection = collection(&mut pile_store, &signer);
        pile_store.commit(collection, &signer, initial).unwrap();
        let reader = pile_store.snapshot().unwrap();
        let (current, _) = crate::storage::read_fact_collection(collection, &reader).unwrap();

        for mutation in [
            entity! { ExclusiveId::force_ref(&left_id) @ ctx::reference: right_id },
            entity! { ExclusiveId::force_ref(&left_id) @ metadata::supersedes: right_id },
        ] {
            let error = validate_candidate(&reader, &current, &mutation).unwrap_err();
            assert!(error.to_string().contains("changes the intrinsic core"));
        }
        pile_store.close().unwrap();
    }
}
