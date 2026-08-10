//! The shared multimodal embedding space.
//!
//! ONE space for everything the agent perceives or generates — file images,
//! photos, memory-chunk prose — so all four search directions
//! (text→text, text→image, image→text, image→image) are just cosine in one
//! HNSW. The space is nomic's *aligned* text+vision latent (768-d):
//! `nomic-embed-text-v1.5` and `nomic-embed-vision-v1.5` are deliberately
//! co-embedded into the same coordinates, so a text query and an image
//! candidate are directly comparable — `cosine(text_vec, image_vec)` is
//! meaningful with no extra alignment.
//!
//! Why one type, not three: a per-silo model (CLIP-512 for files, SigLIP-1152
//! for photos, nomic-768 for prose) is locally optimal but globally useless —
//! incomparable spaces can't be cross-searched, which is the *whole* point. So
//! the zoo collapses to one canonical [`Embedding768`] and one [`attr::embedding`]
//! attribute, reused across every faculty: "this entity's position in the
//! shared space." The dimension is part of the type, so a vector of any other
//! width fails to decode and can never slip into the index — a model swap stays
//! a clean break (new dim → new type), never a silent dimension clash.

use anybytes::View;
use itertools::Itertools;
use triblespace::core::blob::{Blob, BlobEncoding, TryFromBlob};
use triblespace::core::id::ExclusiveId;
use triblespace::core::inline::{Encodes, InlineEncoding};
use triblespace::core::metadata::{self, MetaDescribe};
use triblespace::core::patch::PATCH;
use triblespace::core::repo::index_home::{
    append_range, set_index_frontier, strip_recipe_manifest, CommitRange, IndexHome, IndexKind,
    Manifest,
};
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{
    ancestors, commits_topological, difference, BlobStore, CommitSelector, PinStore, PushResult,
    Repository, Workspace,
};
use triblespace::core::trible::Fragment;
use triblespace::core::trible::TribleSet;
use triblespace::macros::id_hex;
use triblespace::prelude::*;
use triblespace_search::hnsw::HNSWBuilder;
use triblespace_search::index_hnsw::{nearest_across, HnswRollup};
use triblespace_search::schemas::{put_embedding, Embedding};

/// Dimension of the shared space (nomic-embed-{text,vision}-v1.5).
pub const DIM: usize = 768;

// ── dimension-typed embedding encoding ────────────────────────────────────

/// Error decoding a dimension-typed embedding blob.
#[derive(Debug)]
pub enum EmbeddingDimError {
    /// The blob held a different number of floats than the type's dimension.
    WrongLen { expected: usize, got: usize },
    /// The bytes couldn't be viewed as `[f32]` (misalignment / bad length).
    View(anybytes::view::ViewError),
}

impl std::fmt::Display for EmbeddingDimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongLen { expected, got } => {
                write!(f, "embedding has {got} floats, expected {expected}")
            }
            Self::View(e) => write!(f, "embedding view: {e}"),
        }
    }
}
impl std::error::Error for EmbeddingDimError {}

/// A 768-d L2-normalized embedding in the shared nomic space, length-validated
/// on read so a foreign-dimension vector can never enter the index. Same wire
/// format as `triblespace_search::Embedding` (raw f32 LE), but reads check the
/// width — so a 512-d CLIP or 1152-d SigLIP vector simply fails to decode here,
/// at compile time (distinct `Handle<_>`) and at read time (the check below).
pub struct Embedding768;

impl BlobEncoding for Embedding768 {}

impl MetaDescribe for Embedding768 {
    fn describe() -> Fragment {
        let id = id_hex!("D135AA8404D09D112E5BD206494190C4");
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "Embedding768",
            metadata::description: "768-d [f32] LE embedding blob in the shared nomic text+vision space (nomic-embed-{text,vision}-v1.5). L2-normalized; length-validated on read so it can never be mixed with another embedding dimension in one HNSW index.",
            metadata::tag: metadata::KIND_BLOB_ENCODING,
        }
    }
}

impl TryFromBlob<Embedding768> for View<[f32]> {
    type Error = EmbeddingDimError;
    fn try_from_blob(b: Blob<Embedding768>) -> Result<Self, Self::Error> {
        let floats = b.bytes.len() / 4;
        if floats != DIM {
            return Err(EmbeddingDimError::WrongLen {
                expected: DIM,
                got: floats,
            });
        }
        b.bytes.view().map_err(EmbeddingDimError::View)
    }
}

impl Encodes<Vec<f32>> for Embedding768
where
    inlineencodings::Handle<Embedding768>: InlineEncoding,
{
    type Output = Blob<Embedding768>;
    fn encode(source: Vec<f32>) -> Blob<Embedding768> {
        let mut bytes = Vec::with_capacity(source.len() * 4);
        for v in &source {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        Blob::new(bytes.into())
    }
}

// ── the canonical embedding attribute ──────────────────────────────────────
// One attribute, reused across files, photos, and memory chunks — like
// `metadata::name`, it's a cross-cutting property, not owned by any one
// faculty. "This entity has a position in the shared multimodal space."

pub mod attr {
    use super::*;
    attributes! {
        "BCDCA79081A84E7428A2D06A7F222313" unsafe as embedding: inlineencodings::Handle<super::Embedding768>;
    }
}

// ── nomic-embed-multimodal-7b dense space (3584-d) ─────────────────────────
// A SEPARATE space from the 768-d nomic-v1.5 one above: nomic-embed-multimodal
// -7b (a Qwen2.5-VL LoRA) emits a 3584-d dense last-token embedding. It is its
// own coordinate system — text and image queries are comparable *within* it
// (one model embeds both), but NOT comparable to the 768-d space. A distinct
// type per space is the whole guard: even if two spaces ever shared a width,
// the `Handle<_>` keeps their vectors from colliding in one HNSW index.

/// Dimension of the nomic-embed-multimodal-7b dense space.
pub const DIM_3584: usize = 3584;

/// A 3584-d L2-normalized embedding in the nomic-embed-multimodal-7b space,
/// length-validated on read (a vector of any other width fails to decode here,
/// at compile time via the distinct `Handle<_>` and at read time via the check
/// below). Same wire format as [`Embedding768`] (raw f32 LE) — but a distinct
/// type, so the two spaces can never be mixed in one index.
pub struct Embedding3584;

impl BlobEncoding for Embedding3584 {}

impl MetaDescribe for Embedding3584 {
    fn describe() -> Fragment {
        let id = id_hex!("3A11703C58FD2E7DB78846565E8FEABB");
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "Embedding3584",
            metadata::description: "3584-d [f32] LE embedding blob in the nomic-embed-multimodal-7b dense space (Qwen2.5-VL LoRA; last-token pool, L2-normalized). Length-validated on read so it can never be mixed with another embedding dimension in one HNSW index.",
            metadata::tag: metadata::KIND_BLOB_ENCODING,
        }
    }
}

impl TryFromBlob<Embedding3584> for View<[f32]> {
    type Error = EmbeddingDimError;
    fn try_from_blob(b: Blob<Embedding3584>) -> Result<Self, Self::Error> {
        let floats = b.bytes.len() / 4;
        if floats != DIM_3584 {
            return Err(EmbeddingDimError::WrongLen {
                expected: DIM_3584,
                got: floats,
            });
        }
        b.bytes.view().map_err(EmbeddingDimError::View)
    }
}

impl Encodes<Vec<f32>> for Embedding3584
where
    inlineencodings::Handle<Embedding3584>: InlineEncoding,
{
    type Output = Blob<Embedding3584>;
    fn encode(source: Vec<f32>) -> Blob<Embedding3584> {
        let mut bytes = Vec::with_capacity(source.len() * 4);
        for v in &source {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        Blob::new(bytes.into())
    }
}

/// The embedding attribute for the 3584-d space — kept distinct from
/// [`attr::embedding`] so the two spaces index independently.
pub mod attr_mm7b {
    use super::*;
    attributes! {
        "1BFC43C63FE8A38BC09DB3144859F3FC" unsafe as embedding: inlineencodings::Handle<super::Embedding3584>;
    }
}

// ── the shared nearest-neighbour core ──────────────────────────────────────

/// Pure nearest-neighbour core: build a succinct HNSW over `pairs`
/// (id, L2-normalized vector) and return every entry within `floor` cosine of
/// `query`, ranked descending. cosine == dot since the vectors are unit-norm.
///
/// The query vector's *origin* is irrelevant — it's the embedding of a query
/// image, a photo, a memory summary, or a text string, all in the one shared
/// space. Self-match and any domain filtering are the caller's job. No
/// pile/workspace dependency, so it's unit-testable with synthetic vectors and
/// shared by every faculty that searches the space (files, memory, …).
pub fn nearest(
    pairs: &[(Id, Vec<f32>)],
    query: &[f32],
    floor: f32,
) -> anyhow::Result<Vec<(f32, Id)>> {
    type LocalHandle = Inline<inlineencodings::Handle<Embedding>>;
    if pairs.is_empty() {
        return Ok(Vec::new());
    }
    let dim = query.len();
    let mut store = MemoryBlobStore::new();
    let mut builder = HNSWBuilder::new(dim).with_seed(42);
    let mut by_handle: std::collections::HashMap<LocalHandle, (Id, Vec<f32>)> =
        std::collections::HashMap::new();
    for (eid, v) in pairs {
        let lh = put_embedding(&mut store, v.clone())
            .map_err(|e| anyhow::anyhow!("stage embedding: {e:?}"))?;
        builder
            .insert(lh, v.clone())
            .map_err(|e| anyhow::anyhow!("hnsw insert: {e:?}"))?;
        by_handle.insert(lh, (*eid, v.clone()));
    }
    let local_query = put_embedding(&mut store, query.to_vec())
        .map_err(|e| anyhow::anyhow!("stage query: {e:?}"))?;
    let idx = builder.build();
    let reader = store
        .reader()
        .map_err(|e| anyhow::anyhow!("blob reader: {e:?}"))?;
    let view = idx.attach(&reader);
    let candidates = view
        .candidates_above(local_query, floor)
        .map_err(|e| anyhow::anyhow!("similarity search: {e:?}"))?;
    let mut rows: Vec<(f32, Id)> = candidates
        .into_iter()
        .filter_map(|h| {
            by_handle.get(&h).map(|(eid, v)| {
                let cos: f32 = query.iter().zip(v.iter()).map(|(a, b)| a * b).sum();
                (cos, *eid)
            })
        })
        .collect();
    rows.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    Ok(rows)
}

// ── persisted HNSW index-home (fast path for `similar`) ─────────────────────
//
// The `nearest` core above rebuilds the whole graph per query. These helpers
// wrap the [`HnswRollup`] index-home so the graph is PERSISTED as a segment in
// the branch head and refreshed incrementally, turning a query into
// `attach + candidates_above` — no read-all-blobs, no rebuild.

/// The [`HnswRollup`] for the shared 768-d space: indexes the
/// `Handle<Embedding768>` values stored under [`attr::embedding`], resolving
/// them to vectors through `reader`. The stored blobs are raw `[f32]` LE, so
/// their content-addressed handles coincide with the search crate's
/// `Handle<Embedding>` — the index resolves them transparently.
pub fn embedding_rollup<R>(reader: R) -> HnswRollup<R> {
    HnswRollup::new(reader, DIM, attr::embedding.id())
}

type CommitHandle = Inline<inlineencodings::Handle<blobencodings::SimpleArchive>>;

fn commit_projection(reader: &PileReader, commit: CommitHandle) -> anyhow::Result<TribleSet> {
    let metadata: TribleSet = reader
        .get(commit)
        .map_err(|e| anyhow::anyhow!("read commit {commit:?}: {e:?}"))?;
    let content = find!(
        (content: CommitHandle),
        pattern!(&metadata, [{ triblespace::core::repo::content: ?content }])
    )
    .at_most_one()
    .map_err(|_| anyhow::anyhow!("commit {commit:?} has ambiguous content"))?
    .map(|(content,)| content);
    match content {
        Some(content) => reader
            .get(content)
            .map_err(|e| anyhow::anyhow!("read commit projection {commit:?}: {e:?}")),
        None => Ok(TribleSet::new()),
    }
}

fn advance_frontier(
    ws: &mut Workspace<Pile>,
    frontier: &mut Vec<CommitHandle>,
    commit: CommitHandle,
) -> anyhow::Result<()> {
    let metadata: TribleSet = ws
        .get(commit)
        .map_err(|e| anyhow::anyhow!("read commit metadata {commit:?}: {e:?}"))?;
    let parents: std::collections::HashSet<[u8; 32]> = find!(
        (parent: CommitHandle),
        pattern!(&metadata, [{ triblespace::core::repo::parent: ?parent }])
    )
    .map(|(parent,)| parent.raw)
    .collect();
    frontier.retain(|tip| !parents.contains(&tip.raw));
    frontier.push(commit);
    frontier.sort_unstable_by_key(|tip| tip.raw);
    frontier.dedup_by_key(|tip| tip.raw);
    Ok(())
}

fn inspect_hnsw_manifest(
    storage: &mut Pile,
    branch_meta: &TribleSet,
    reachable: &PATCH<32>,
    rollup: &HnswRollup<PileReader>,
) -> anyhow::Result<Vec<CommitHandle>> {
    let reader = storage
        .reader()
        .map_err(|e| anyhow::anyhow!("typed HNSW manifest reader: {e:?}"))?;
    let manifest = Manifest::from_tribles(branch_meta, &reader, rollup)
        .map_err(|e| anyhow::anyhow!("parse typed HNSW manifest: {e}"))?;
    if let Some(foreign) = manifest
        .frontier()
        .iter()
        .find(|tip| reachable.get(&tip.raw).is_none())
    {
        anyhow::bail!("HNSW frontier tip {foreign:?} is not an ancestor of branch HEAD");
    }
    manifest
        .audit_exact_cover(&reader)
        .map_err(|e| anyhow::anyhow!("audit typed HNSW range cover: {e}"))?;
    for range in manifest.ranges() {
        for artifact in range.artifacts() {
            rollup.attach(&reader, artifact).map_err(|e| {
                anyhow::anyhow!("attach HNSW artifact from {:?}: {e}", range.range())
            })?;
        }
    }
    Ok(manifest.frontier().to_vec())
}

/// Bring the persisted HNSW recipe for `branch` exactly to its source HEAD.
///
/// This is deliberately repository-aware rather than accepting a naked
/// trible delta: every derived artifact is certified by the actual immutable
/// source commit it came from. Missing history is replayed parents-first,
/// including artifact-free ranges for commits with no embeddings. A malformed
/// HNSW recipe is soft state, so only that recipe is stripped and rebuilt;
/// unrelated typed manifests and unknown facts are retained. Each successful
/// range/frontier checkpoint is flushed before the next commit.
pub fn refresh_index(repo: &mut Repository<Pile>, branch: Id) -> anyhow::Result<()> {
    let mut ws = repo
        .pull(branch)
        .map_err(|e| anyhow::anyhow!("pull embedding branch: {e:?}"))?;
    let target = ws
        .head()
        .ok_or_else(|| anyhow::anyhow!("embedding branch has no source commits"))?;
    let reachable = ancestors(target)
        .select(&mut ws)
        .map_err(|e| anyhow::anyhow!("walk embedding commit DAG: {e}"))?;

    let mut branch_meta_handle = repo
        .storage_mut()
        .head(branch)
        .map_err(|e| anyhow::anyhow!("read embedding branch pin: {e:?}"))?
        .ok_or_else(|| anyhow::anyhow!("embedding branch is missing"))?;
    let mut branch_meta: TribleSet = repo
        .storage_mut()
        .reader()
        .map_err(|e| anyhow::anyhow!("embedding branch reader: {e:?}"))?
        .get(branch_meta_handle)
        .map_err(|e| anyhow::anyhow!("read embedding branch metadata: {e:?}"))?;
    let pinned_source = find!(
        head: CommitHandle,
        pattern!(&branch_meta, [{ _?branch @ triblespace::core::repo::head: ?head }])
    )
    .at_most_one()
    .map_err(|_| anyhow::anyhow!("embedding branch metadata has ambiguous source HEADs"))?;
    if pinned_source != Some(target) {
        anyhow::bail!(
            "embedding branch changed during HNSW refresh: pulled {target:?}, pinned {pinned_source:?}"
        );
    }

    let source_reader = repo
        .storage_mut()
        .reader()
        .map_err(|e| anyhow::anyhow!("HNSW source reader: {e:?}"))?;
    let rollup = embedding_rollup(source_reader.clone());
    let mut frontier = match inspect_hnsw_manifest(
        repo.storage_mut(),
        &branch_meta,
        &reachable,
        &rollup,
    ) {
        Ok(frontier) => frontier,
        Err(error) => {
            let recipe = Manifest::new(&rollup)
                .map_err(|e| anyhow::anyhow!("construct HNSW recipe: {e}"))?
                .recipe();
            strip_recipe_manifest(&mut branch_meta, recipe);
            eprintln!(
                "discarding only invalid HNSW recipe {recipe:x}; rebuilding from source commits: {error:#}"
            );
            Vec::new()
        }
    };

    let commits = if frontier.is_empty() {
        commits_topological(&mut ws, reachable.clone())
    } else {
        commits_topological(
            &mut ws,
            difference(reachable.clone(), ancestors(frontier.clone())),
        )
    }
    .map_err(|e| anyhow::anyhow!("order uncovered embedding commits: {e}"))?;
    if commits.is_empty() {
        return Ok(());
    }

    for commit in commits {
        let projection = commit_projection(&source_reader, commit)?;
        append_range(
            repo.storage_mut(),
            &rollup,
            &projection,
            CommitRange::leaf(commit),
            &mut branch_meta,
        )
        .map_err(|e| anyhow::anyhow!("append typed HNSW range {commit:?}: {e}"))?;
        advance_frontier(&mut ws, &mut frontier, commit)?;
        set_index_frontier(
            repo.storage_mut(),
            &rollup,
            &mut branch_meta,
            frontier.clone(),
        )
        .map_err(|e| anyhow::anyhow!("advance typed HNSW frontier: {e}"))?;

        let next_meta: CommitHandle = repo
            .storage_mut()
            .put(branch_meta.clone())
            .map_err(|e| anyhow::anyhow!("store HNSW checkpoint: {e:?}"))?;
        match repo
            .storage_mut()
            .update(branch, Some(branch_meta_handle), Some(next_meta))
            .map_err(|e| anyhow::anyhow!("publish HNSW checkpoint: {e:?}"))?
        {
            PushResult::Success() => branch_meta_handle = next_meta,
            PushResult::Conflict(_) => {
                anyhow::bail!("embedding branch changed during HNSW refresh; rerun to resume")
            }
        }
        repo.storage_mut()
            .flush()
            .map_err(|e| anyhow::anyhow!("flush HNSW checkpoint: {e:?}"))?;
    }

    let final_frontier =
        inspect_hnsw_manifest(repo.storage_mut(), &branch_meta, &reachable, &rollup)?;
    if final_frontier.as_slice() != [target] {
        anyhow::bail!("HNSW traversal ended at frontier {final_frontier:?}, expected {target:?}");
    }
    Ok(())
}

/// Fast-path nearest neighbours via the persisted HNSW segment(s) on `branch`.
///
/// Returns `None` if no HNSW segment exists yet (the caller falls back to the
/// rebuild path or builds one on the fly). Otherwise attaches every segment
/// named by the manifest, stages the query vector, and unions the per-segment
/// candidate lists — ranked by exact cosine. Each row is `(cosine,
/// raw_handle_bytes)`; the caller maps the handle to its entity id via its own
/// id↔handle tribles. Reads only the candidate vectors (bounded by the beam
/// width), never the whole corpus.
pub fn nearest_via_index<S>(
    storage: &mut S,
    branch: Id,
    expected_head: Option<CommitHandle>,
    query: &[f32],
    floor: f32,
) -> anyhow::Result<Option<Vec<(f32, [u8; 32])>>>
where
    S: BlobStore + PinStore,
{
    if DIM == 0 {
        anyhow::bail!("embedding dimension must be greater than zero");
    }
    if query.len() != DIM {
        anyhow::bail!(
            "query embedding has dimension {}, expected {DIM}",
            query.len()
        );
    }
    if query.iter().any(|value| !value.is_finite()) {
        anyhow::bail!("query embedding contains a non-finite value");
    }
    if !floor.is_finite() {
        anyhow::bail!("query score floor must be finite");
    }
    // Interpret the source HEAD and typed manifest from one immutable branch
    // pin snapshot. A later concurrent push cannot make an older accelerator
    // look current merely because a second pin read raced ahead.
    let branch_meta_handle = storage
        .head(branch)
        .map_err(|e| anyhow::anyhow!("read embedding branch pin: {e:?}"))?;
    let branch_meta = match branch_meta_handle {
        Some(handle) => storage
            .reader()
            .map_err(|e| anyhow::anyhow!("embedding branch reader: {e:?}"))?
            .get(handle)
            .map_err(|e| anyhow::anyhow!("read embedding branch metadata: {e:?}"))?,
        None => TribleSet::new(),
    };
    let source_head = find!(
        head: Inline<inlineencodings::Handle<blobencodings::SimpleArchive>>,
        pattern!(&branch_meta, [{ _?branch @ triblespace::core::repo::head: ?head }])
    )
    .at_most_one()
    .map_err(|_| anyhow::anyhow!("embedding branch metadata has ambiguous source HEADs"))?;
    if source_head != expected_head {
        return Ok(None);
    }
    let rollup = embedding_rollup(
        storage
            .reader()
            .map_err(|e| anyhow::anyhow!("index-home reader: {e:?}"))?,
    );
    let manifest_reader = storage
        .reader()
        .map_err(|e| anyhow::anyhow!("typed HNSW manifest reader: {e:?}"))?;
    let manifest = Manifest::from_tribles(&branch_meta, &manifest_reader, &rollup)
        .map_err(|e| anyhow::anyhow!("read typed HNSW manifest: {e}"))?;
    if !manifest.claims_head(expected_head) {
        return Ok(None);
    }
    if manifest
        .ranges()
        .iter()
        .all(|range| range.artifacts().is_empty())
    {
        return Ok(Some(Vec::new()));
    }
    let segments = {
        let mut home = IndexHome::new(storage, branch, rollup);
        home.attach_manifest(&manifest)
            .map_err(|e| anyhow::anyhow!("attach hnsw segments: {e}"))?
    };
    // Stage the query vector so `candidates_above` can resolve it by handle.
    // A loose blob (never committed) — soft state, GC-able, exactly like the
    // segments themselves.
    let qh = put_embedding(storage, query.to_vec())
        .map_err(|e| anyhow::anyhow!("stage query embedding: {e:?}"))?;
    let reader = storage
        .reader()
        .map_err(|e| anyhow::anyhow!("index reader: {e:?}"))?;
    let rows = nearest_across(&segments, &reader, qh, floor)
        .map_err(|e| anyhow::anyhow!("query typed HNSW artifacts: {e}"))?
        .into_iter()
        .map(|(cos, h)| (cos, h.raw))
        .collect();
    Ok(Some(rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedding768_roundtrips_and_rejects_wrong_dim() {
        let v: Vec<f32> = (0..DIM).map(|i| i as f32 * 0.001).collect();
        let blob = <Embedding768 as Encodes<Vec<f32>>>::encode(v.clone());
        let back: View<[f32]> =
            <View<[f32]> as TryFromBlob<Embedding768>>::try_from_blob(blob).unwrap();
        assert_eq!(back.as_ref(), v.as_slice(), "768-d round-trips byte-exact");

        // A foreign-dimension vector (e.g. a 512-d CLIP leftover) must NOT
        // decode — the width is validated on read, so it can never slip into
        // the shared index.
        let wrong: Vec<f32> = vec![0.0; 512];
        let blob = <Embedding768 as Encodes<Vec<f32>>>::encode(wrong);
        let err = <View<[f32]> as TryFromBlob<Embedding768>>::try_from_blob(blob);
        assert!(
            matches!(
                err,
                Err(EmbeddingDimError::WrongLen {
                    expected: 768,
                    got: 512
                })
            ),
            "wrong dimension is rejected on read"
        );
    }

    #[test]
    fn embedding3584_roundtrips_and_rejects_wrong_dim() {
        let v: Vec<f32> = (0..DIM_3584).map(|i| i as f32 * 0.0001).collect();
        let blob = <Embedding3584 as Encodes<Vec<f32>>>::encode(v.clone());
        let back: View<[f32]> =
            <View<[f32]> as TryFromBlob<Embedding3584>>::try_from_blob(blob).unwrap();
        assert_eq!(back.as_ref(), v.as_slice(), "3584-d round-trips byte-exact");

        // A 768-d vector from the OTHER nomic space must not decode here — the
        // width guard keeps the two spaces from ever sharing an index.
        let wrong: Vec<f32> = vec![0.0; DIM];
        let blob = <Embedding3584 as Encodes<Vec<f32>>>::encode(wrong);
        let err = <View<[f32]> as TryFromBlob<Embedding3584>>::try_from_blob(blob);
        assert!(
            matches!(
                err,
                Err(EmbeddingDimError::WrongLen {
                    expected: 3584,
                    got: 768
                })
            ),
            "wrong dimension is rejected on read"
        );
    }

    /// L2-normalize (mirrors `put_embedding`'s source normalization, which is
    /// what makes dot-product == cosine downstream).
    fn unit(mut v: Vec<f32>) -> Vec<f32> {
        let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if n > 0.0 {
            for x in &mut v {
                *x /= n;
            }
        }
        v
    }

    #[test]
    fn nearest_ranks_by_cosine_and_respects_floor() {
        let a = Id::new([1u8; 16]).unwrap();
        let b = Id::new([2u8; 16]).unwrap();
        let c = Id::new([3u8; 16]).unwrap();
        let pairs = vec![
            (a, unit(vec![1.0, 0.0, 0.0])),
            (b, unit(vec![0.0, 1.0, 0.0])),
            (c, unit(vec![0.9, 0.1, 0.0])),
        ];
        let query = unit(vec![1.0, 0.0, 0.0]);
        let ranked = nearest(&pairs, &query, 0.0).unwrap();
        assert_eq!(ranked.first().unwrap().1, a, "A is the nearest");

        // floor excludes the orthogonal vector b (cosine 0) but keeps a and c.
        let high = nearest(&pairs, &query, 0.5).unwrap();
        assert!(
            high.iter().all(|(_, id)| *id != b),
            "floor drops orthogonal b"
        );
        assert!(high.iter().any(|(_, id)| *id == a), "floor keeps near a");
    }

    #[test]
    fn nearest_empty_is_empty() {
        let q = unit(vec![1.0, 0.0, 0.0]);
        assert!(nearest(&[], &q, 0.0).unwrap().is_empty());
    }
}
