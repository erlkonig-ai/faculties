//! Canonical Memory revisions and strict collection semantics.
//!
//! A memory chunk is an immutable intrinsic state.  Its content, temporal
//! span, contextual references, lens, provenance links, and direct
//! `metadata::supersedes` predecessors determine its id.  Creation times and
//! legacy ids are additive observations on that state: replaying the same
//! state therefore converges while preserving every genuine observation.
//!
//! Retractions inhabit the same supersedes DAG but carry no replacement
//! content.  A live memory is simply a chunk that no chunk or retraction
//! directly supersedes.  Forks remain visible until a later intrinsic chunk
//! names every live predecessor it reconciles.
//!
//! There is deliberately no separately minted journal/fragment anchor.  A
//! chunk denotes remembered state, not a database row occurrence: identical
//! state and history should converge, while `supersedes` can fork and merge
//! without first deciding which arbitrary anchor owns a recollection. Legacy
//! random ids survive only as additive exact aliases for old prose links.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
use triblespace::prelude::*;

use crate::schemas::memory::{ctx, KIND_CHUNK_ID, KIND_RETRACTION};

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
    pub predecessors: BTreeSet<Id>,
    /// Genuine creation/import observations, outside intrinsic state.
    pub observed_at: BTreeSet<IntervalValue>,
    /// Extrinsic historical names, outside intrinsic state.
    pub aliases: BTreeSet<Id>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetractionRow {
    pub id: Id,
    pub reason: Option<TextHandle>,
    pub predecessors: BTreeSet<Id>,
    pub observed_at: BTreeSet<IntervalValue>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MemoryCatalog {
    pub chunks: BTreeMap<Id, ChunkRow>,
    pub retractions: BTreeMap<Id, RetractionRow>,
    /// `latest` over the loading collection view: the nodes nothing in that
    /// frame observes. Resolved by [`load_catalog`], never by a reader.
    heads: BTreeSet<Id>,
}

impl MemoryCatalog {
    pub fn node_ids(&self) -> BTreeSet<Id> {
        self.chunks
            .keys()
            .chain(self.retractions.keys())
            .copied()
            .collect()
    }

    /// The complete fork-visible frontier, including head retractions.
    pub fn head_ids(&self) -> Vec<Id> {
        self.heads.iter().copied().collect()
    }

    /// Content-bearing members of the complete frontier.
    pub fn live_chunk_ids(&self) -> Vec<Id> {
        self.chunks
            .keys()
            .filter(|id| self.heads.contains(*id))
            .copied()
            .collect()
    }

    pub fn is_live(&self, chunk: Id) -> bool {
        self.heads.contains(&chunk) && self.chunks.contains_key(&chunk)
    }

    /// Exact targets of an extrinsic historical name.
    ///
    /// A legacy chunk id named one historical state, not a moving branch.  A
    /// union may nevertheless reveal several targets for the same name; that
    /// ambiguity is returned rather than arbitrated.
    pub fn alias_targets(&self, alias: Id) -> Vec<Id> {
        self.chunks
            .values()
            .filter(|row| row.aliases.contains(&alias))
            .map(|row| row.id)
            .collect()
    }
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
    pub predecessors: BTreeSet<Id>,
    pub observed_at: BTreeSet<IntervalValue>,
    pub aliases: BTreeSet<Id>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetractionDraft {
    pub reason: Option<String>,
    pub predecessors: BTreeSet<Id>,
    pub observed_at: BTreeSet<IntervalValue>,
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

fn entity_facts(space: &TribleSet, entity: Id) -> TribleSet {
    let mut facts = TribleSet::new();
    for fact in space.iter().filter(|fact| fact.e() == &entity) {
        facts.insert(fact);
    }
    facts
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

fn retraction_core(reason: Option<TextHandle>, predecessors: &BTreeSet<Id>) -> Fragment {
    entity! {
        metadata::tag: &KIND_RETRACTION,
        ctx::summary?: reason.as_ref(),
        metadata::supersedes*: predecessors.iter(),
    }
}

fn retraction_record(row: &RetractionRow) -> Fragment {
    let mut fragment = retraction_core(row.reason, &row.predecessors);
    let id = fragment
        .root()
        .expect("canonical Memory retraction core has one intrinsic root");
    for at in &row.observed_at {
        fragment += entity! { ExclusiveId::force_ref(&id) @ metadata::created_at: at };
    }
    fragment
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
            &draft.predecessors,
        ),
        &draft.observed_at,
        &draft.aliases,
    );
    let id = fragment
        .root()
        .ok_or_else(|| anyhow!("Memory chunk fragment has no unique intrinsic root"))?;
    Ok((fragment, id))
}

pub fn retraction_fragment(draft: RetractionDraft) -> Result<(Fragment, Id)> {
    if draft.predecessors.is_empty() {
        bail!("a Memory retraction must supersede at least one prior node");
    }
    for at in &draft.observed_at {
        point_bounds(None, "retraction observation time", *at)?;
    }
    if draft
        .reason
        .as_ref()
        .is_some_and(|reason| reason.is_empty())
    {
        bail!("retraction reason must not be empty when present");
    }
    let mut fragment = Fragment::empty();
    let reason = draft.reason.map(|reason| fragment.put(reason));
    fragment += retraction_core(reason, &draft.predecessors);
    let id = fragment
        .root()
        .ok_or_else(|| anyhow!("Memory retraction fragment has no unique intrinsic root"))?;
    for at in &draft.observed_at {
        fragment += entity! { ExclusiveId::force_ref(&id) @ metadata::created_at: at };
    }
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
    if entity_facts(space, id) != *chunk_record(&row).facts() {
        bail!("Memory chunk {id:x} is not one canonical immutable record");
    }
    Ok(Some(row))
}

fn load_retraction(space: &TribleSet, id: Id) -> Result<Option<RetractionRow>> {
    let row = RetractionRow {
        id,
        reason: one(
            find!(value: TextHandle, pattern!(space, [{ id @ ctx::summary: ?value }])).collect(),
            id,
            "retraction reason",
        )?,
        predecessors: find!(value: Id, pattern!(space, [{ id @ metadata::supersedes: ?value }]))
            .collect(),
        observed_at:
            find!(value: IntervalValue, pattern!(space, [{ id @ metadata::created_at: ?value }]))
                .collect(),
    };
    let canonical = retraction_core(row.reason, &row.predecessors)
        .root()
        .expect("retraction core has one root");
    if canonical != id {
        // See `load_chunk`: exact legacy rows survive publication but remain
        // inert unless their entity is the intrinsic identity of the core.
        return Ok(None);
    }
    if row.predecessors.is_empty() {
        bail!("Memory retraction {id:x} supersedes no prior node");
    }
    for at in &row.observed_at {
        point_bounds(Some(id), "retraction observation time", *at)?;
    }
    if entity_facts(space, id) != *retraction_record(&row).facts() {
        bail!("Memory retraction {id:x} is not one canonical immutable record");
    }
    Ok(Some(row))
}

fn ancestors(graph: &BTreeMap<Id, BTreeSet<Id>>, start: Id) -> BTreeSet<Id> {
    let mut found = BTreeSet::new();
    let mut pending: Vec<Id> = graph
        .get(&start)
        .into_iter()
        .flat_map(|values| values.iter().copied())
        .collect();
    while let Some(node) = pending.pop() {
        if found.insert(node) {
            pending.extend(
                graph
                    .get(&node)
                    .into_iter()
                    .flat_map(|values| values.iter().copied()),
            );
        }
    }
    found
}

pub(crate) fn validate_predecessor_dag(
    graph: &BTreeMap<Id, BTreeSet<Id>>,
    label: &str,
) -> Result<()> {
    for (node, predecessors) in graph {
        for predecessor in predecessors {
            if !graph.contains_key(predecessor) {
                bail!("{label} node {node:x} supersedes missing node {predecessor:x}");
            }
        }
    }

    let mut remaining: BTreeMap<Id, usize> = graph
        .iter()
        .map(|(node, predecessors)| (*node, predecessors.len()))
        .collect();
    let mut successors: BTreeMap<Id, Vec<Id>> = BTreeMap::new();
    for (node, predecessors) in graph {
        for predecessor in predecessors {
            successors.entry(*predecessor).or_default().push(*node);
        }
    }
    let mut ready: Vec<Id> = remaining
        .iter()
        .filter_map(|(node, count)| (*count == 0).then_some(*node))
        .collect();
    let mut ordered = 0usize;
    while let Some(node) = ready.pop() {
        ordered += 1;
        for successor in successors.get(&node).into_iter().flatten() {
            let count = remaining
                .get_mut(successor)
                .expect("successor has dependency count");
            *count -= 1;
            if *count == 0 {
                ready.push(*successor);
            }
        }
    }
    if ordered != graph.len() {
        bail!("{label} supersedes graph contains a cycle");
    }

    for (node, predecessors) in graph {
        let predecessors: Vec<Id> = predecessors.iter().copied().collect();
        for (index, left) in predecessors.iter().enumerate() {
            let left_ancestors = ancestors(graph, *left);
            for right in &predecessors[index + 1..] {
                let right_ancestors = ancestors(graph, *right);
                if left_ancestors.contains(right) || right_ancestors.contains(left) {
                    bail!(
                        "{label} node {node:x} has non-antichain predecessors {left:x} and {right:x}"
                    );
                }
            }
        }
    }
    Ok(())
}

/// Strictly project the complete canonical Memory collection.
pub fn load_catalog(space: &TribleSet) -> Result<MemoryCatalog> {
    let chunk_ids = tagged_entities(space, KIND_CHUNK_ID);
    let retraction_ids = tagged_entities(space, KIND_RETRACTION);
    let mut catalog = MemoryCatalog::default();
    for id in &chunk_ids {
        if let Some(row) = load_chunk(space, *id)? {
            catalog.chunks.insert(*id, row);
        }
    }
    for id in &retraction_ids {
        if let Some(row) = load_retraction(space, *id)? {
            catalog.retractions.insert(*id, row);
        }
    }
    if let Some(id) = catalog
        .chunks
        .keys()
        .find(|id| catalog.retractions.contains_key(*id))
    {
        bail!("Memory entity {id:x} is both a chunk and a retraction");
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
    let graph: BTreeMap<Id, BTreeSet<Id>> = catalog
        .chunks
        .values()
        .map(|row| (row.id, row.predecessors.clone()))
        .chain(
            catalog
                .retractions
                .values()
                .map(|row| (row.id, row.predecessors.clone())),
        )
        .collect();
    validate_predecessor_dag(&graph, "Memory revision")?;

    // The frontier is resolved once, here, against the same collection view
    // every other fact came from — so a catalog can never answer "is this
    // live?" in a frame that differs from the one it was loaded in.
    catalog.heads = latest(space, metadata::supersedes.id(), catalog.node_ids());

    Ok(catalog)
}

fn read_text_overlay<Overlay>(
    reader: &PileReader,
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
    reader: &PileReader,
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
    reader: &PileReader,
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
    for row in catalog.retractions.values() {
        if let Some(handle) = row.reason {
            let reason = read_text_overlay(reader, overlay, handle)
                .with_context(|| format!("read Memory retraction {:x} reason", row.id))?;
            if reason.is_empty() {
                bail!("Memory retraction {:x} has an empty reason", row.id);
            }
        }
    }
    Ok(())
}

pub fn validate_catalog(reader: &PileReader, facts: &TribleSet) -> Result<MemoryCatalog> {
    let catalog = load_catalog(facts)?;
    validate_payloads(reader, None::<&PileReader>, &catalog)?;
    Ok(catalog)
}

/// Validate the exact union a publication would create, including blobs still
/// staged only inside `fragment`, before a signed root is written.
pub fn validate_candidate(
    reader: &PileReader,
    current: &TribleSet,
    fragment: &Fragment,
) -> Result<MemoryCatalog> {
    let prior = load_catalog(current)?;
    let mut union = current.clone();
    union += fragment.facts().clone();
    let catalog = load_catalog(&union)?;
    for id in prior.chunks.keys() {
        if !catalog.chunks.contains_key(id) {
            bail!(
                "Memory mutation changes the intrinsic core of existing chunk {id:x}; create a successor instead"
            );
        }
    }
    for id in prior.retractions.keys() {
        if !catalog.retractions.contains_key(id) {
            bail!(
                "Memory mutation changes the intrinsic core of existing retraction {id:x}; create a successor instead"
            );
        }
    }
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .reader()
        .context("snapshot staged Memory attachments")?;
    validate_payloads(reader, Some(&overlay), &catalog)?;
    Ok(catalog)
}

pub fn read_text(reader: &PileReader, handle: TextHandle) -> Result<String> {
    read_text_overlay(reader, None::<&PileReader>, handle)
}

pub fn read_image(reader: &PileReader, handle: ImageHandle) -> Result<anybytes::Bytes> {
    read_image_overlay(reader, None::<&PileReader>, handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    use crate::storage::{initialize_signer, open_pile_strict};
    use crate::schemas::memory::DEFAULT_SCOPE_ID;

    fn point(seconds: f64) -> IntervalValue {
        let at = hifitime::Epoch::from_tai_seconds(seconds);
        (at, at).try_to_inline().unwrap()
    }

    fn draft(summary: &str, predecessors: impl IntoIterator<Item = Id>) -> ChunkDraft {
        ChunkDraft {
            content: ChunkDraftContent::Text(summary.to_owned()),
            start_at: point(10.0),
            end_at: point(20.0),
            lens: None,
            references: BTreeSet::new(),
            about_exec_result: None,
            about_archive_message: None,
            predecessors: predecessors.into_iter().collect(),
            observed_at: BTreeSet::from([point(30.0)]),
            aliases: BTreeSet::new(),
        }
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
        let first = chunk_fragment(draft("same", [])).unwrap();
        let mut replay = draft("same", []);
        replay.observed_at = BTreeSet::from([point(99.0)]);
        replay.aliases.insert(Id::new([0x11; 16]).unwrap());
        let replay = chunk_fragment(replay).unwrap();
        assert_eq!(first.1, replay.1);
        assert_ne!(first.0, replay.0);
    }

    #[test]
    fn supersedes_is_identity_and_input_order_is_not() {
        let a = chunk_fragment(draft("a", [])).unwrap().1;
        let b = chunk_fragment(draft("b", [])).unwrap().1;
        let left = chunk_fragment(draft("joined", [a, b])).unwrap().1;
        let right = chunk_fragment(draft("joined", [b, a, b])).unwrap().1;
        assert_eq!(left, right);
        assert_ne!(left, chunk_fragment(draft("joined", [])).unwrap().1);
    }

    #[test]
    fn retraction_removes_content_without_becoming_content() {
        let (chunk, chunk_id) = chunk_fragment(draft("mistake", [])).unwrap();
        let (retraction, retraction_id) = retraction_fragment(RetractionDraft {
            reason: Some("not true".to_owned()),
            predecessors: BTreeSet::from([chunk_id]),
            observed_at: BTreeSet::new(),
        })
        .unwrap();
        let catalog = load_catalog(&facts([chunk, retraction])).unwrap();
        assert!(catalog.live_chunk_ids().is_empty());
        assert_eq!(catalog.head_ids(), vec![retraction_id]);
        assert!(catalog.retractions.contains_key(&retraction_id));
    }

    #[test]
    fn content_retraction_race_stays_visible_and_can_rejoin() {
        let (base_fragment, base) = chunk_fragment(draft("base", [])).unwrap();
        let (content_fragment, content) = chunk_fragment(draft("corrected", [base])).unwrap();
        let (retraction_fragment, retraction) = retraction_fragment(RetractionDraft {
            reason: None,
            predecessors: BTreeSet::from([base]),
            observed_at: BTreeSet::new(),
        })
        .unwrap();
        let fork = load_catalog(&facts([
            base_fragment.clone(),
            content_fragment.clone(),
            retraction_fragment.clone(),
        ]))
        .unwrap();
        assert_eq!(
            fork.head_ids(),
            vec![content.min(retraction), content.max(retraction)]
        );
        assert_eq!(fork.live_chunk_ids(), vec![content]);

        let (join_fragment, join) =
            chunk_fragment(draft("corrected", [content, retraction])).unwrap();
        let joined = load_catalog(&facts([
            base_fragment,
            content_fragment,
            retraction_fragment,
            join_fragment,
        ]))
        .unwrap();
        assert_eq!(joined.head_ids(), vec![join]);
        assert_eq!(joined.live_chunk_ids(), vec![join]);
    }

    #[test]
    fn dangling_reference_and_redundant_predecessor_are_rejected() {
        let missing = Id::new([0x44; 16]).unwrap();
        let mut dangling = draft("dangling", []);
        dangling.references.insert(missing);
        let dangling = chunk_fragment(dangling).unwrap().0;
        assert!(load_catalog(&facts([dangling]))
            .unwrap_err()
            .to_string()
            .contains("references missing"));

        let (a_fragment, a) = chunk_fragment(draft("a", [])).unwrap();
        let (b_fragment, b) = chunk_fragment(draft("b", [a])).unwrap();
        let c_fragment = chunk_fragment(draft("c", [a, b])).unwrap().0;
        assert!(load_catalog(&facts([a_fragment, b_fragment, c_fragment]))
            .unwrap_err()
            .to_string()
            .contains("non-antichain"));
    }

    #[test]
    fn scalar_ambiguity_and_extra_canonical_facts_are_rejected() {
        let (fragment, id) = chunk_fragment(draft("one", [])).unwrap();
        let other = "two".to_owned().to_blob().get_handle();
        let corrupt = fragment + entity! { ExclusiveId::force_ref(&id) @ ctx::summary: other };
        assert!(load_catalog(&facts([corrupt])).is_err());

        let unknown = Id::new([0x55; 16]).unwrap();
        let (fragment, id) = chunk_fragment(draft("clean", [])).unwrap();
        let unrelated =
            fragment.clone() + entity! { ExclusiveId::force_ref(&unknown) @ ctx::reference: id };
        assert_eq!(load_catalog(&facts([unrelated])).unwrap().chunks.len(), 1);

        let corrupt =
            fragment + entity! { ExclusiveId::force_ref(&id) @ metadata::description: other };
        assert!(load_catalog(&facts([corrupt])).is_err());
    }

    #[test]
    fn additive_legacy_rows_are_inert_in_the_native_view() {
        let legacy_chunk = Id::new([0x56; 16]).unwrap();
        let legacy_retraction = Id::new([0x57; 16]).unwrap();
        let summary = "legacy".to_owned().to_blob().get_handle();
        let mut rows = entity! { ExclusiveId::force_ref(&legacy_chunk) @
            metadata::tag: &KIND_CHUNK_ID,
            ctx::summary: summary,
            ctx::start_at: point(10.0),
            ctx::end_at: point(20.0),
            metadata::created_at: point(30.0),
        };
        rows += entity! { ExclusiveId::force_ref(&legacy_retraction) @
            metadata::tag: &KIND_RETRACTION,
            ctx::supersedes: legacy_chunk,
            metadata::created_at: point(31.0),
        };
        let catalog = load_catalog(rows.facts()).unwrap();
        assert!(catalog.chunks.is_empty());
        assert!(catalog.retractions.is_empty());
    }

    #[test]
    fn additive_legacy_rows_do_not_require_resident_payloads() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("memory.pile");
        File::create(&pile).unwrap();
        let mut pile_store = open_pile_strict(&pile).unwrap();
        let reader = pile_store.reader().unwrap();

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

        let catalog = validate_catalog(&reader, rows.facts()).unwrap();
        assert!(catalog.chunks.is_empty());
        assert!(catalog.retractions.is_empty());
        pile_store.close().unwrap();
    }

    #[test]
    fn dag_validator_rejects_cycles_even_for_noncanonical_inputs() {
        let a = Id::new([0x66; 16]).unwrap();
        let b = Id::new([0x77; 16]).unwrap();
        let graph = BTreeMap::from([(a, BTreeSet::from([b])), (b, BTreeSet::from([a]))]);
        assert!(validate_predecessor_dag(&graph, "test")
            .unwrap_err()
            .to_string()
            .contains("cycle"));
    }

    #[test]
    fn staged_attachments_validate_before_publication() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("memory.pile");
        let key = directory.path().join("memory.key");
        File::create(&pile).unwrap();
        let signer = initialize_signer(&pile, Some(&key)).unwrap();
        let mut pile_store = open_pile_strict(&pile).unwrap();
        let before = {
            let mut collection = crate::collection_names::open(&mut pile_store, DEFAULT_SCOPE_ID, signer.clone());
            collection.materialize().unwrap()
        };
        let reader = pile_store.reader().unwrap();
        let fragment = chunk_fragment(draft("resident only in fragment", []))
            .unwrap()
            .0;
        let catalog = validate_candidate(&reader, &before, &fragment).unwrap();
        assert_eq!(catalog.chunks.len(), 1);

        {
            let mut collection = crate::collection_names::open(&mut pile_store, DEFAULT_SCOPE_ID, signer.clone());
            collection.commit(fragment).unwrap();
        }
        let after = {
            let mut collection = crate::collection_names::open(&mut pile_store, DEFAULT_SCOPE_ID, signer);
            collection.materialize().unwrap()
        };
        let reader = pile_store.reader().unwrap();
        let catalog = validate_catalog(&reader, &after).unwrap();
        assert_eq!(catalog.chunks.len(), 1);
        pile_store.close().unwrap();
    }

    #[test]
    fn candidate_cannot_turn_a_canonical_node_into_inert_legacy_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("memory.pile");
        let key = directory.path().join("memory.key");
        File::create(&pile).unwrap();
        let signer = initialize_signer(&pile, Some(&key)).unwrap();
        let mut pile_store = open_pile_strict(&pile).unwrap();
        let (left, left_id) = chunk_fragment(draft("left", [])).unwrap();
        let (right, right_id) = chunk_fragment(draft("right", [])).unwrap();
        let mut initial = left;
        initial += right;
        {
            let mut collection = crate::collection_names::open(&mut pile_store, DEFAULT_SCOPE_ID, signer.clone());
            collection.commit(initial).unwrap();
        }
        let current = {
            let mut collection = crate::collection_names::open(&mut pile_store, DEFAULT_SCOPE_ID, signer);
            collection.materialize().unwrap()
        };
        let reader = pile_store.reader().unwrap();

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
