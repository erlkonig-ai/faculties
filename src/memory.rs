//! Canonical entries in the immutable episodic Memory journal.
//!
//! A memory is what was remembered in one moment. Later understanding adds a
//! later memory; it does not turn the earlier experience into a false database
//! row. Every typed chunk in the collection is therefore visible. There
//! are no heads, tombstones, or semantic retractions in this model.
//!
//! Historical native chunks may carry `metadata::supersedes` because those
//! edges participated in their content-derived identities. They have no
//! ordering or visibility semantics, and new chunks never emit them at
//! creation. Entity ids remain opaque: old random ids and newer intrinsic
//! ids are ordinary, additive members of the same journal.
//!
//! One edge is written on purpose, after the fact: `memory respan <id>
//! <from>..<to>` writes the SAME memory over corrected time coordinates -- a
//! new chunk with the identical text, superseding the old one. The cover lets
//! the old chunk stand aside from its temporal structure only when the text
//! is identical, so the one thing this can change is where a memory sits in
//! time, never what it says (JP, 2026-09-05: allow superseding, but limit the
//! interface to time-range adjustments; a journal is not a mutable fact
//! store). Both chunks remain members of the journal and answer by id.

use std::collections::BTreeSet;

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::BlobStoreGet;
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

/// The edge a respan writes: `newer` is the same memory as `older`, over
/// corrected time coordinates. The cover honours it only when the two texts
/// are identical (see [`crate::memory_cover::collect_chunk_spans`]).
pub fn respan_edge(newer: Id, older: Id) -> Fragment {
    entity! { ExclusiveId::force_ref(&newer) @ metadata::supersedes: older }
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

pub fn read_text<B: BlobStoreGet>(reader: &B, handle: TextHandle) -> Result<String> {
    let value: anybytes::View<str> = reader.get(handle)?;
    Ok(value.to_string())
}

pub fn read_image<B: BlobStoreGet>(reader: &B, handle: ImageHandle) -> Result<anybytes::Bytes> {
    reader.get(handle).map_err(Into::into)
}

/// Explicit boundary validation for the Memory values this version knows.
///
/// This is intentionally not an ordinary read path. It neither constructs a
/// shadow catalog nor validates opaque entity ids, closed-world cardinality,
/// or contextual-reference closure. Every typed value that can be projected
/// is checked independently; unknown and incomplete records remain inert.
pub fn validate_catalog<B, P>(reader: &B, facts: &P) -> Result<()>
where
    B: BlobStoreGet,
    P: TriblePattern,
{
    for (id, handle) in find!(
        (id: Id, handle: TextHandle),
        pattern!(facts, [{
            ?id @ metadata::tag: &KIND_CHUNK_ID,
            ctx::summary: ?handle,
        }])
    ) {
        let summary = read_text(reader, handle)
            .with_context(|| format!("read Memory chunk {id:x} summary"))?;
        if summary.is_empty() {
            bail!("Memory chunk {id:x} has an empty summary");
        }
    }
    for (id, handle) in find!(
        (id: Id, handle: ImageHandle),
        pattern!(facts, [{
            ?id @ metadata::tag: &KIND_CHUNK_ID,
            ctx::image: ?handle,
        }])
    ) {
        let image = read_image(reader, handle)
            .with_context(|| format!("read Memory chunk {id:x} image"))?;
        if image.is_empty() {
            bail!("Memory chunk {id:x} has an empty image");
        }
    }
    for (id, handle) in find!(
        (id: Id, handle: TextHandle),
        pattern!(facts, [{
            ?id @ metadata::tag: &KIND_CHUNK_ID,
            ctx::lens: ?handle,
        }])
    ) {
        let lens =
            read_text(reader, handle).with_context(|| format!("read Memory chunk {id:x} lens"))?;
        if lens.is_empty() {
            bail!("Memory chunk {id:x} has an empty lens");
        }
    }
    for (id, value) in find!(
        (id: Id, value: IntervalValue),
        pattern!(facts, [{
            ?id @ metadata::tag: &KIND_CHUNK_ID,
            ctx::start_at: ?value,
        }])
    ) {
        point_bounds(Some(id), "chunk start", value)?;
    }
    for (id, value) in find!(
        (id: Id, value: IntervalValue),
        pattern!(facts, [{
            ?id @ metadata::tag: &KIND_CHUNK_ID,
            ctx::end_at: ?value,
        }])
    ) {
        point_bounds(Some(id), "chunk end", value)?;
    }
    for (id, value) in find!(
        (id: Id, value: IntervalValue),
        pattern!(facts, [{
            ?id @ metadata::tag: &KIND_CHUNK_ID,
            metadata::created_at: ?value,
        }])
    ) {
        point_bounds(Some(id), "chunk observation time", value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let facts = facts([base_fragment, later_fragment, retraction]);
        let ids: BTreeSet<Id> = find!(
            id: Id,
            pattern!(&facts, [{ ?id @ metadata::tag: &KIND_CHUNK_ID }])
        )
        .collect();
        assert_eq!(ids, BTreeSet::from([base, later]));
        let predecessors: BTreeSet<Id> = find!(
            predecessor: Id,
            pattern!(&facts, [{ later @ metadata::supersedes: ?predecessor }])
        )
        .collect();
        assert_eq!(predecessors, BTreeSet::from([base]));
    }

    /// A respan -- the same text over corrected coordinates -- takes the old
    /// chunk's place in the cover's structure; a different text that claims to
    /// supersede changes nothing, because that is not a time-range adjustment.
    #[test]
    fn a_respan_stands_in_for_the_old_coordinates_and_nothing_else_does() {
        let (old_fragment, old) = chunk_fragment(draft("the same words")).unwrap();
        let mut moved = draft("the same words");
        moved.start_at = point(5.0);
        moved.end_at = point(25.0);
        let (moved_fragment, moved) = chunk_fragment(moved).unwrap();

        let (kept_fragment, kept) = chunk_fragment(draft("a second memory")).unwrap();
        let mut rewrite = draft("different words over a wider span");
        rewrite.start_at = point(0.0);
        rewrite.end_at = point(30.0);
        let (rewrite_fragment, rewrite) = chunk_fragment(rewrite).unwrap();

        let facts = facts([
            old_fragment,
            moved_fragment,
            kept_fragment,
            rewrite_fragment,
            respan_edge(moved, old),
            respan_edge(rewrite, kept),
        ]);
        let shown: BTreeSet<Id> = crate::memory_cover::collect_chunk_spans(&facts)
            .into_iter()
            .map(|(_, _, id)| id)
            .collect();
        assert!(shown.contains(&moved), "the respan stands");
        assert!(!shown.contains(&old), "the old coordinates stand aside");
        assert!(shown.contains(&kept), "a different text supersedes nothing");
        assert!(shown.contains(&rewrite));
        let all: BTreeSet<Id> = find!(
            id: Id,
            pattern!(&facts, [{ ?id @ metadata::tag: &KIND_CHUNK_ID }])
        )
        .collect();
        assert_eq!(
            all,
            BTreeSet::from([old, moved, kept, rewrite]),
            "all remain members"
        );
    }

    #[test]
    fn dangling_contextual_references_remain_additive_evidence() {
        let missing = Id::new([0x44; 16]).unwrap();
        let mut dangling = draft("dangling");
        dangling.references.insert(missing);
        let (dangling, id) = chunk_fragment(dangling).unwrap();
        let facts = facts([dangling]);
        assert!(find!(
            reference: Id,
            pattern!(&facts, [{ id @ ctx::reference: ?reference }])
        )
        .any(|reference| reference == missing));
    }

    #[test]
    fn repeated_values_and_unmodelled_annotations_do_not_poison_the_entity() {
        let (mut fragment, id) = chunk_fragment(draft("one")).unwrap();
        let other = fragment.put("two".to_owned());
        fragment += entity! { ExclusiveId::force_ref(&id) @ ctx::summary: other };
        let unknown = Id::new([0x55; 16]).unwrap();
        fragment += entity! { ExclusiveId::force_ref(&unknown) @ ctx::reference: id };
        fragment += entity! { ExclusiveId::force_ref(&id) @ metadata::description: other };
        let summaries: BTreeSet<TextHandle> = find!(
            summary: TextHandle,
            pattern!(fragment.facts(), [{ id @ ctx::summary: ?summary }])
        )
        .collect();
        assert_eq!(summaries.len(), 2);
    }

    #[test]
    fn random_ids_are_opaque_members_of_the_native_view() {
        let legacy_chunk = Id::new([0x56; 16]).unwrap();
        let summary = "legacy".to_owned().to_blob().get_handle();
        let rows = entity! { ExclusiveId::force_ref(&legacy_chunk) @
            metadata::tag: &KIND_CHUNK_ID,
            ctx::summary: summary,
            ctx::start_at: point(10.0),
            ctx::end_at: point(20.0),
            metadata::created_at: point(30.0),
        };
        let ids: BTreeSet<Id> = find!(
            id: Id,
            pattern!(rows.facts(), [{ ?id @ metadata::tag: &KIND_CHUNK_ID }])
        )
        .collect();
        assert_eq!(ids, BTreeSet::from([legacy_chunk]));
    }

    #[test]
    fn explicit_validation_checks_known_payloads_for_opaque_ids() {
        let missing = "not resident".to_owned().to_blob().get_handle();
        let legacy = Id::new([0x58; 16]).unwrap();
        let rows = entity! { ExclusiveId::force_ref(&legacy) @
            metadata::tag: &KIND_CHUNK_ID,
            ctx::summary: missing,
            ctx::start_at: point(10.0),
            ctx::end_at: point(20.0),
            metadata::created_at: point(30.0),
        };
        let mut empty = Fragment::empty();
        let reader = empty.blobs_mut().snapshot().unwrap();
        let error = validate_catalog(&reader, rows.facts()).unwrap_err();
        assert!(error.to_string().contains("summary"));
    }

    #[test]
    fn explicit_validation_accepts_repeated_resident_values() {
        let (mut fragment, id) = chunk_fragment(draft("one")).unwrap();
        let other = fragment.put("two".to_owned());
        fragment += entity! { ExclusiveId::force_ref(&id) @ ctx::summary: other };
        let reader = fragment.blobs_mut().snapshot().unwrap();
        validate_catalog(&reader, fragment.facts()).unwrap();
    }
}
