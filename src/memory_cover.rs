//! The memory context-cover renderer, extracted so it can be assembled
//! IN-PROCESS by more than one caller.
//!
//! `memory context` (in `src/bin/memory.rs`) and `orient wake` (in
//! `src/bin/orient.rs`) both need the antichain cover over ALL of a persona's
//! memories — coarse → fine, fit to a character budget — rendered to a string.
//! Keeping the render (and the chunk accessors it needs) here means the two
//! callers can never drift: the cover semantics — antichain completeness, the
//! character budget, the `--about`/`--filter`/`--remove` composition — live in
//! exactly one place. Context never gets to rewrite the temporal structure:
//! `--about` may choose one recollection among entries with the exact same
//! temporal coverage, but cannot change which spans the cover refines.
//!
//! Callers hand this module maintained Memory and shared Embeddings collection
//! views frozen from one pile snapshot, plus the Memory attachment reader and
//! parsed [`CoverOpts`]. The result is the cover text.

use std::collections::{BTreeSet, HashMap};

#[cfg(feature = "local-embed")]
use anyhow::anyhow;
use anyhow::{bail, Context, Result};
use hifitime::Epoch;

use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::BlobStoreGet;
use triblespace::macros::{find, pattern};
use triblespace::prelude::blobencodings::{RawBytes, UTF8String};
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval};
use triblespace::prelude::*;
use triblespace_search::bm25::BM25Builder;
use triblespace_search::tokens::hash_tokens;

#[cfg(feature = "local-embed")]
use crate::nomic;
#[cfg(feature = "local-embed")]
use crate::schemas::embeddings::{self, Embedding768};
use crate::schemas::memory::{ctx, KIND_CHUNK_ID};

// ---------------------------------------------------------------------------
// on-demand chunk queries — moved here from memory.rs so the render is
// self-contained. memory.rs re-imports these via `use faculties::memory_cover::…`.
// ---------------------------------------------------------------------------

pub fn chunk_summary_handle<P: TriblePattern>(
    space: &P,
    id: Id,
) -> Option<Inline<Handle<UTF8String>>> {
    find!(h: Inline<Handle<UTF8String>>, pattern!(space, [{ id @ ctx::summary: ?h }])).min()
}

/// The raw image bytes handle of a WORDLESS image memory chunk, if it is one.
/// An image chunk has no `ctx::summary`; its content is the picture itself.
pub fn chunk_image_handle<P: TriblePattern>(space: &P, id: Id) -> Option<Inline<Handle<RawBytes>>> {
    find!(h: Inline<Handle<RawBytes>>, pattern!(space, [{ id @ ctx::image: ?h }])).min()
}

/// A chunk's `from..to` span as a string (or `?` if missing) — used to render
/// a wordless image memory as `[image memory @ <span>]` everywhere a summary
/// would otherwise print.
pub fn chunk_span_str<P: TriblePattern>(space: &P, id: Id) -> String {
    match (chunk_start_at(space, id), chunk_end_at(space, id)) {
        (Some(s), Some(e)) => format_time_range(epoch_from_interval(s), epoch_end_from_interval(e)),
        _ => "?".to_string(),
    }
}

/// A chunk's lens-theme handle, if it is a thematic lens (not part of the
/// chronological spine). Presence is what excludes it from the temporal cover.
pub fn chunk_lens_handle<P: TriblePattern>(
    space: &P,
    id: Id,
) -> Option<Inline<Handle<UTF8String>>> {
    find!(h: Inline<Handle<UTF8String>>, pattern!(space, [{ id @ ctx::lens: ?h }])).min()
}

pub fn chunk_start_at<P: TriblePattern>(space: &P, id: Id) -> Option<Inline<NsTAIInterval>> {
    find!(v: Inline<NsTAIInterval>, pattern!(space, [{ id @ ctx::start_at: ?v }])).min()
}

pub fn chunk_end_at<P: TriblePattern>(space: &P, id: Id) -> Option<Inline<NsTAIInterval>> {
    find!(v: Inline<NsTAIInterval>, pattern!(space, [{ id @ ctx::end_at: ?v }])).max()
}

/// What archive message this chunk is about, if any.
pub fn chunk_about_archive_message<P: TriblePattern>(space: &P, id: Id) -> Option<Id> {
    find!(v: Id, pattern!(space, [{ id @ ctx::about_archive_message: ?v }])).min()
}

/// A chunk's extrinsic historical names. Annotation, never intrinsic state.
pub fn chunk_aliases<P: TriblePattern>(space: &P, id: Id) -> Vec<Id> {
    find!(v: Id, pattern!(space, [{ id @ metadata::anchor: ?v }]))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn all_chunk_ids<P: TriblePattern>(space: &P) -> Vec<Id> {
    find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: &KIND_CHUNK_ID }]))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Outgoing contextual references of a chunk, ordered by `start_at`.
pub fn chunk_references<P: TriblePattern>(space: &P, id: Id) -> Vec<Id> {
    let mut children: Vec<Id> =
        find!(c: Id, pattern!(space, [{ id @ ctx::reference: ?c }])).collect();
    // Sort referenced chunks by their start_at time.
    children.sort_by_key(|child_id| {
        chunk_start_at(space, *child_id)
            .map(interval_key)
            .unwrap_or(i128::MAX)
    });
    children.dedup();
    children
}

/// The exec result this chunk is about, if it records one.
pub fn chunk_about_exec_result<P: TriblePattern>(space: &P, id: Id) -> Option<Id> {
    find!(v: Id, pattern!(space, [{ id @ ctx::about_exec_result: ?v }])).min()
}

/// Genuine creation/import observations for a chunk. These sit OUTSIDE
/// intrinsic state -- they are additive provenance, so several may coexist and
/// that multiplicity is returned rather than arbitrated.
pub fn chunk_observed_at<P: TriblePattern>(space: &P, id: Id) -> Vec<Inline<NsTAIInterval>> {
    find!(v: Inline<NsTAIInterval>, pattern!(space, [{ id @ metadata::created_at: ?v }]))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The stored shared-space embedding handle for a chunk, if it has been embedded.
#[cfg(feature = "local-embed")]
pub fn chunk_embedding_handle<P: TriblePattern>(
    embeddings_space: &P,
    id: Id,
) -> Result<Option<Inline<Handle<Embedding768>>>> {
    let handles: BTreeSet<_> = find!(
        h: Inline<Handle<Embedding768>>,
        pattern!(embeddings_space, [{ id @ embeddings::attr::embedding: ?h }])
    )
    .collect();
    // Embeddings are additive observations. Older callers consume one vector,
    // so arbitrate deterministically instead of imposing scalar cardinality on
    // the open-world relation. Richer scorers may inspect every observation.
    Ok(handles.first().copied())
}

// ---------------------------------------------------------------------------
// time-range helpers
// ---------------------------------------------------------------------------

pub fn format_time_range(start: Epoch, end: Epoch) -> String {
    let (y1, m1, d1, h1, mi1, s1, _) = start.to_gregorian_tai();
    let (y2, m2, d2, h2, mi2, s2, _) = end.to_gregorian_tai();
    format!(
        "{y1:04}-{m1:02}-{d1:02}T{h1:02}:{mi1:02}:{s1:02}..{y2:04}-{m2:02}-{d2:02}T{h2:02}:{mi2:02}:{s2:02}"
    )
}

pub fn fmt_epoch(e: Epoch) -> String {
    let (y, m, d, h, mi, s, _) = e.to_gregorian_tai();
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}")
}

pub fn epoch_from_interval(interval: Inline<NsTAIInterval>) -> Epoch {
    let (lower, _): (Epoch, Epoch) = interval.try_from_inline().unwrap();
    lower
}

pub fn epoch_end_from_interval(interval: Inline<NsTAIInterval>) -> Epoch {
    let (_, upper): (Epoch, Epoch) = interval.try_from_inline().unwrap();
    upper
}

pub fn interval_key(interval: Inline<NsTAIInterval>) -> i128 {
    let (lower, _): (Epoch, Epoch) = interval.try_from_inline().unwrap();
    lower.to_tai_duration().total_nanoseconds()
}

pub fn key_to_epoch(key: i128) -> Epoch {
    Epoch::from_tai_duration(hifitime::Duration::from_total_nanoseconds(key))
}

/// L2-normalize so dot-product == cosine downstream (the shared `nearest` core
/// and `put_embedding` both assume unit vectors; nomic's raw output is not
/// guaranteed normalized).
#[cfg(feature = "local-embed")]
pub fn l2_normalize(mut v: Vec<f32>) -> Vec<f32> {
    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if n > 0.0 {
        for x in &mut v {
            *x /= n;
        }
    }
    v
}

// ---------------------------------------------------------------------------
// cover helpers
// ---------------------------------------------------------------------------

/// Project every usable Memory span as `(start_key, end_key, id)`.
///
/// Start/end observations remain additive: the raw projected tuple is the
/// identity, so another typed value adds another span instead of invalidating
/// or silently rewriting an entity. Incomplete and backwards ranges simply do
/// not inhabit the view this renderer can use.
pub fn collect_chunk_spans<P: TriblePattern>(space: &P) -> Vec<(i128, i128, Id)> {
    let mut spans: Vec<_> = find!(
        (id: Id, start: Inline<NsTAIInterval>, end: Inline<NsTAIInterval>),
        pattern!(space, [{
            ?id @ metadata::tag: &KIND_CHUNK_ID,
            ctx::start_at: ?start,
            ctx::end_at: ?end,
        }])
    )
    .filter(|(id, _, _)| chunk_lens_handle(space, *id).is_none())
    .map(|(id, start, end)| (interval_key(start), interval_key(end), id))
    .filter(|(start, end, _)| start <= end)
    .collect();
    spans.sort_unstable();
    spans.dedup();

    // A respan -- `memory respan` -- is the same memory over corrected time
    // coordinates: a chunk with the IDENTICAL text that supersedes the old
    // one. The old coordinates stand aside from the temporal structure; the
    // old chunk stays in the journal and answers by id. Any other supersedes
    // edge (a different text, the old comb's history) means nothing here: the
    // one thing an edge may move is where a memory sits in time.
    let content_of = |id: Id| -> Option<[u8; 32]> {
        chunk_summary_handle(space, id)
            .map(|h| h.raw)
            .or_else(|| chunk_image_handle(space, id).map(|h| h.raw))
    };
    let respanned: BTreeSet<Id> = find!(
        (newer: Id, older: Id),
        pattern!(space, [{
            ?newer @ metadata::tag: &KIND_CHUNK_ID,
            metadata::supersedes: ?older,
        }])
    )
    .filter(|(newer, older)| {
        let newer = content_of(*newer);
        newer.is_some() && newer == content_of(*older)
    })
    .map(|(_, older)| older)
    .collect();
    if !respanned.is_empty() {
        spans.retain(|(_, _, id)| !respanned.contains(id));
    }
    spans
}

/// Budget weight charged for a wordless image memory in the context cover —
/// it renders as a one-line `[image memory @ <span>]` marker, so a small fixed
/// character cost (vs a text summary's measured length).
pub const IMAGE_CHUNK_CHAR_COST: usize = 64;

/// Character-cost of a chunk (its budget weight), loaded lazily and cached by
/// span index. Cost is the summary's exact character count, so the budget and
/// the per-chunk weights are in the same, unambiguous CHARACTER units.
pub fn context_chunk_cost<B: BlobStoreGet, P: TriblePattern>(
    ws: &B,
    space: &P,
    spans: &[(i128, i128, Id)],
    cache: &mut [Option<usize>],
    i: usize,
) -> Result<usize> {
    if let Some(c) = cache[i] {
        return Ok(c);
    }
    let c = match chunk_summary_handle(space, spans[i].2) {
        Some(handle) => {
            let summary: View<str> = ws.get(handle).context("read chunk summary")?;
            summary.chars().count()
        }
        // A wordless image memory renders as a small `[image memory @ <span>]`
        // marker in the cover — a fixed handful of characters, not zero.
        None if chunk_image_handle(space, spans[i].2).is_some() => IMAGE_CHUNK_CHAR_COST,
        None => 0,
    };
    cache[i] = Some(c);
    Ok(c)
}

/// Default cosine cutoff for `--filter`/`--remove` eligibility. Chosen from the
/// nomic score distribution observed on this pile: topically-matched chunks
/// cluster ~0.62–0.73 for their query, while unrelated chunks fall to ~0.40–0.52
/// (nomic cosines sit in a compressed high band). 0.55 lands in that natural gap
/// — high enough to spare unrelated material, low enough to catch the whole
/// matched cluster. Override per call with `--sim-threshold <f>`.
pub const DEFAULT_SIM_THRESHOLD: f32 = 0.55;

/// Rebuild the exact lexical view from the frozen maintained Memory facts.
/// BM25 is query-time machinery, not durable journal state: there is no stale
/// index entity to arbitrate and every text journal entry visible in `space`
/// participates in this one scored postings walk.
pub fn lexical_relevance_scores<B: BlobStoreGet, P: TriblePattern>(
    space: &P,
    reader: &B,
    query: &str,
) -> Result<HashMap<Id, f32>> {
    let mut builder = BM25Builder::new();
    for chunk in all_chunk_ids(space) {
        let Some(handle) = chunk_summary_handle(space, chunk) else {
            continue;
        };
        let summary: View<str> = reader
            .get(handle)
            .with_context(|| format!("read Memory chunk {chunk:x} for lexical search"))?;
        builder.insert(chunk, hash_tokens(summary.as_ref()));
    }
    Ok(builder
        .build()
        .query_multi(&hash_tokens(query))
        .into_iter()
        .filter_map(|(doc, score)| Some((doc.try_from_inline().ok()?, score)))
        .collect())
}

/// Per-chunk relevance scores for `memory context --about`: SEMANTIC (nomic
/// cosine over the stored shared-space embeddings) when they exist, else LEXICAL
/// (BM25). Both are non-negative. The scores choose between recollections with
/// identical temporal coverage; they never participate in structural refinement.
pub fn about_relevance_scores<B, P, E>(
    space: &P,
    embeddings_space: &E,
    reader: &B,
    query: &str,
) -> Result<HashMap<Id, f32>>
where
    B: BlobStoreGet,
    P: TriblePattern,
    E: TriblePattern,
{
    #[cfg(feature = "local-embed")]
    {
        if let Some(scores) = semantic_about_scores(space, embeddings_space, reader, query)? {
            return Ok(scores);
        }
    }
    #[cfg(not(feature = "local-embed"))]
    let _ = embeddings_space;
    lexical_relevance_scores(space, reader, query)
}

/// Semantic relevance via nomic: embed the query, cosine it against every stored
/// chunk embedding. `None` if no chunk is embedded yet (caller falls back to
/// BM25). Negative cosines clamp to 0 so "unrelated" is uniform (matching
/// BM25's non-negative scores).
#[cfg(feature = "local-embed")]
pub fn semantic_about_scores<B, P, E>(
    space: &P,
    embeddings_space: &E,
    reader: &B,
    query: &str,
) -> Result<Option<HashMap<Id, f32>>>
where
    B: BlobStoreGet,
    P: TriblePattern,
    E: TriblePattern,
{
    let mut handles: Vec<(Id, Inline<Handle<Embedding768>>)> = Vec::new();
    for chunk in all_chunk_ids(space) {
        if let Some(h) = chunk_embedding_handle(embeddings_space, chunk)? {
            handles.push((chunk, h));
        }
    }
    if handles.is_empty() {
        return Ok(None);
    }
    eprintln!("memory: loading nomic-embed-text for --about (once)…");
    let emb = nomic::load_text_embedder()?;
    let qv = l2_normalize(
        emb.embed_query(query)
            .map_err(|e| anyhow!("embed query: {e:?}"))?,
    );
    let mut scores = HashMap::new();
    for (chunk, h) in handles {
        let v: View<[f32]> = reader
            .get(h)
            .map_err(|e| anyhow!("read embedding: {e:?}"))?;
        let cos: f32 = qv.iter().zip(v.as_ref().iter()).map(|(a, b)| a * b).sum();
        scores.insert(chunk, cos.max(0.0));
    }
    Ok(Some(scores))
}

/// Per-chunk positive-similarity scores for `--filter`/`--remove` ELIGIBILITY,
/// using the SAME scoring as `--about`: nomic cosine (clamped ≥0) when the chunk
/// is embedded, else the lexical BM25 score (normalized to a fraction of the top
/// score so the [0,1] threshold still means something). The second return value
/// is the ids that could NOT be scored at all — no embedding AND no positive
/// lexical score — which the caller treats fail-open (kept) and warns about, so
/// the guardrail use of `--remove` never *silently* leaks an unassessable chunk.
///
/// Scores are POSITIVE similarity to the query (the reliable direction). `--remove`
/// negates in the RETRIEVAL LOGIC (drop the high-match chunks), never by embedding
/// a negated query — that is the whole point, and it sidesteps embedding-negation
/// failure.
/// `universe` is the exact set of chunks that can appear in the cover (all
/// chronological, non-lens chunks selected by `collect_chunk_spans`), so the unscorable
/// warning never lists chunks that could never surface anyway.
pub fn eligibility_scores<B, P, E>(
    space: &P,
    embeddings_space: &E,
    reader: &B,
    query: &str,
    universe: &[Id],
) -> Result<(HashMap<Id, f32>, Vec<Id>)>
where
    B: BlobStoreGet,
    P: TriblePattern,
    E: TriblePattern,
{
    #[cfg(feature = "local-embed")]
    {
        if let Some(res) =
            semantic_eligibility_scores(space, embeddings_space, reader, query, universe)?
        {
            return Ok(res);
        }
    }
    #[cfg(not(feature = "local-embed"))]
    let _ = embeddings_space;
    // Pure lexical fallback (no embeddings on the pile yet, or built without
    // `local-embed`): BM25 normalized to a fraction of the top score. Every chunk
    // gets an explicit score — those absent from the postings scored a genuine 0
    // ("no match"), so nothing here is *unscorable*.
    let raw = lexical_relevance_scores(space, reader, query)?;
    let max = raw.values().copied().fold(0.0_f32, f32::max).max(1e-6);
    let scores = universe
        .iter()
        .map(|&id| (id, raw.get(&id).copied().map(|s| s / max).unwrap_or(0.0)))
        .collect();
    Ok((scores, Vec::new()))
}

/// Semantic half of [`eligibility_scores`]: nomic cosine over stored chunk
/// embeddings. Unembedded text chunks fall back to exact lexical BM25,
/// including an explicit zero for no token match. Wordless images without an
/// embedding remain unscorable, so the caller keeps them fail-open and warns.
/// Returns `None` when no chunk is embedded at all (pure lexical fallback).
#[cfg(feature = "local-embed")]
pub fn semantic_eligibility_scores<B, P, E>(
    space: &P,
    embeddings_space: &E,
    reader: &B,
    query: &str,
    universe: &[Id],
) -> Result<Option<(HashMap<Id, f32>, Vec<Id>)>>
where
    B: BlobStoreGet,
    P: TriblePattern,
    E: TriblePattern,
{
    let mut embedded: Vec<(Id, Inline<Handle<Embedding768>>)> = Vec::new();
    let mut unembedded: Vec<Id> = Vec::new();
    for &chunk in universe {
        match chunk_embedding_handle(embeddings_space, chunk)? {
            Some(h) => embedded.push((chunk, h)),
            None => unembedded.push(chunk),
        }
    }
    if embedded.is_empty() {
        return Ok(None);
    }
    eprintln!("memory: loading nomic-embed-text for --filter/--remove (once)…");
    let emb = nomic::load_text_embedder()?;
    let qv = l2_normalize(
        emb.embed_query(query)
            .map_err(|e| anyhow!("embed query: {e:?}"))?,
    );
    let mut scores = HashMap::new();
    for (chunk, h) in embedded {
        let v: View<[f32]> = reader
            .get(h)
            .map_err(|e| anyhow!("read embedding: {e:?}"))?;
        let cos: f32 = qv.iter().zip(v.as_ref().iter()).map(|(a, b)| a * b).sum();
        scores.insert(chunk, cos.max(0.0));
    }
    // Unembedded text chunks still have an exact lexical score. Wordless
    // images have neither modality and remain honestly unscorable.
    let lexical = lexical_relevance_scores(space, reader, query)?;
    let lexical_max = lexical.values().copied().fold(0.0_f32, f32::max).max(1e-6);
    let mut unscorable = Vec::new();
    for chunk in unembedded {
        if chunk_summary_handle(space, chunk).is_some() {
            scores.insert(
                chunk,
                lexical
                    .get(&chunk)
                    .copied()
                    .map(|score| score / lexical_max)
                    .unwrap_or(0.0),
            );
        } else {
            unscorable.push(chunk);
        }
    }
    Ok(Some((scores, unscorable)))
}

/// Parsed options for [`render_cover`] — the same knobs `memory context`
/// accepts, already parsed from argv by the caller.
pub struct CoverOpts {
    /// CHARACTER budget for the cover.
    pub budget_chars: usize,
    /// Fixed CHARACTER-equivalent cost charged for each selected chunk by the
    /// consumer (framing, tokenization, or other per-chunk overhead). This is
    /// selection accounting only: stored summaries retain their intrinsic
    /// character lengths and rendered cover text is unchanged.
    pub chunk_overhead: usize,
    /// `--about <query>`: choose the most relevant recollection whenever
    /// multiple memories have identical temporal coverage.
    pub about: Option<String>,
    /// `--filter <query>`: keep ONLY chunks whose similarity exceeds the threshold.
    pub filter: Option<String>,
    /// `--remove <query>`: the anti-filter — drop chunks whose similarity exceeds it.
    pub remove: Option<String>,
    /// Cosine cutoff for `--filter`/`--remove` eligibility.
    pub sim_threshold: f32,
    /// Memories per tile, stated by the reader with its window. `None` searches
    /// for the finest detail that fits the budget; a reader that wants the same
    /// cover tomorrow states the detail that search printed.
    pub detail: Option<usize>,
}

impl CoverOpts {
    /// The plain recency-first cover: no about/filter/remove, default threshold.
    pub fn plain(budget_chars: usize) -> Self {
        CoverOpts {
            budget_chars,
            chunk_overhead: 0,
            about: None,
            filter: None,
            remove: None,
            sim_threshold: DEFAULT_SIM_THRESHOLD,
            detail: None,
        }
    }
}

/// Render the context-cover text from maintained Memory and shared Embeddings
/// views, using `reader` for their attachment blobs. The result is the
/// antichain cover over all temporal memory positions, coarse → fine, fit to
/// `opts.budget_chars` characters.
///
/// Completeness is invariant — every temporal position remains represented.
/// Exact-span recollections are interchangeable at one position, not additive
/// structural nodes. If even the coarsest cover (all roots) overflows the
/// budget, this ERRORS with instructions for raising a coarser apex rather than
/// silently losing the past.
/// Containment forest over chunk spans: each chunk's tightest strict container,
/// the children that induces, and the roots with no container at all.
///
// ---------------------------------------------------------------------------
// the field: coarseness by age
// ---------------------------------------------------------------------------
//
// Memories have a coarseness -- their width -- and the cover is coarser
// further back in time. That is the whole rule (JP, 2026-09-05). There is
// no parent and no child: two memories over the same minutes are two
// memories, and an arc over a day is a wider memory than an entry in it.
// The tree this replaced was a rendering shortcut that grew semantics: it
// walked a containment forest and never split a chunk with one child, so
// six whole-life roots nested by their tails hid every leaf before June.

/// A memory lasts at least a moment for the purpose of covering time: an
/// instant-stamped memory has no interior an instant could fall into.
const MOMENT_NS: i128 = (crate::memory::MOMENT_SECONDS * 1_000_000_000.0) as i128;

/// The grid unit: 2^14 seconds, about four and a half hours -- the order of
/// the resident's working quarter, and nothing the calendar knows.
pub const TILE_UNIT_NS: i128 = (1i128 << 14) * 1_000_000_000;

/// Tiles grow by this factor per level, and a level holds at most this many
/// complete tiles before they merge into one tile of the next level.
pub const TILE_BASE: i128 = 4;

/// The most memories per tile a reader may ask for.
pub const DETAIL_CAP: usize = 4096;

/// The details a tile can render at: eighth-doublings from one memory per
/// tile to `DETAIL_CAP`, so a tile fitting its share from below leaves at
/// most a tenth of it unused.
const DETAIL_LADDER: [usize; 79] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 17, 19, 21, 23, 25, 27, 29, 32, 35, 38, 41,
    45, 49, 54, 59, 64, 70, 76, 83, 91, 99, 108, 117, 128, 140, 152, 166, 181, 197, 215, 235, 256,
    279, 304, 332, 362, 395, 431, 470, 512, 558, 609, 664, 724, 790, 861, 939, 1024, 1117, 1218,
    1328, 1448, 1579, 1722, 1878, 2048, 2233, 2435, 2656, 2896, 3158, 3444, 3756, 4096,
];

/// One tile of the cover: a block of whole grid units on an absolute grid.
/// `open` is the tile `now` falls in, still being written; it wants leaf
/// grain. A closed tile of `units` units wants a grain of its width over the
/// detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tile {
    pub start: i128,
    pub end: i128,
    pub units: i128,
    pub open: bool,
}

impl Tile {
    /// The tile's width, humanized: hours under two days, days above.
    pub fn width(&self) -> String {
        let hours = (self.units * TILE_UNIT_NS) as f64 / 3.6e12;
        if hours < 48.0 {
            format!("{hours:.1}h")
        } else {
            format!("{:.1}d", hours / 24.0)
        }
    }
}

/// The tiling for a pile whose earliest memory starts at `earliest` and whose
/// latest ends at `now` (TAI keys): a pure function of the pile.
///
/// It is the base-`TILE_BASE` counter of the unit `now` falls in. Level 0 is
/// that unit, open. Level `l` holds the complete tiles of `TILE_BASE^l` units
/// that lie before the current block at that level and inside the current
/// block of the level above: the digit of the counter, zero to
/// `TILE_BASE - 1` tiles. So when the open unit closes it becomes a one-unit
/// tile; when a level fills, its tiles merge into one tile of the next level
/// and are re-rendered at that level's grain. Between merges the cover changes
/// only by appends in the open tile, a merge rewrites a suffix, and a merge
/// into a deep level is rare in proportion to its depth. That is what lets a
/// resident reuse the prefix of her cover across recomputes.
pub fn tiles(earliest: i128, now: i128) -> Vec<Tile> {
    let first = earliest.div_euclid(TILE_UNIT_NS);
    let current = now.div_euclid(TILE_UNIT_NS);
    let mut out = vec![Tile {
        start: current * TILE_UNIT_NS,
        end: (current + 1) * TILE_UNIT_NS,
        units: 1,
        open: true,
    }];
    let mut size = 1i128;
    loop {
        // The current block at this level already reaches the first memory:
        // nothing lies to its left.
        let block = current - current.rem_euclid(size);
        if block <= first {
            break;
        }
        let up = size * TILE_BASE;
        let block_up = current - current.rem_euclid(up);
        let left = block_up.max(first - first.rem_euclid(size));
        let mut t = left;
        while t < block {
            out.push(Tile {
                start: t * TILE_UNIT_NS,
                end: (t + size) * TILE_UNIT_NS,
                units: size,
                open: false,
            });
            t += size;
        }
        size = up;
    }
    out.sort_by_key(|t| t.start);
    out
}

/// An alternative tiling, for measuring beside the counter: every level
/// renders the `k` most recent complete blocks of its size, aligned to the
/// grid, except where a finer level already renders; the open unit renders
/// at leaf grain. Older levels appear as the life grows. The number of tiles
/// is then about `k` per level at every phase of the grid, where the
/// counter's swings between one and three, and a level's window slides by
/// one block at every boundary of its size, re-rendering from that block on.
pub fn tiles_sliding(earliest: i128, now: i128, k: i128) -> Vec<Tile> {
    let k = k.max(1);
    let first = earliest.div_euclid(TILE_UNIT_NS);
    let current = now.div_euclid(TILE_UNIT_NS);
    let mut out = vec![Tile {
        start: current * TILE_UNIT_NS,
        end: (current + 1) * TILE_UNIT_NS,
        units: 1,
        open: true,
    }];
    let mut size = 1i128;
    let mut covered_from = current;
    loop {
        let boundary = current - current.rem_euclid(size);
        let start = boundary - k * size;
        let first_aligned = first - first.rem_euclid(size);
        let from = start.max(first_aligned);
        let mut t = from;
        while t < covered_from {
            out.push(Tile {
                start: t * TILE_UNIT_NS,
                end: (t + size).min(covered_from) * TILE_UNIT_NS,
                units: size,
                open: false,
            });
            t += size;
        }
        if start <= first {
            break;
        }
        covered_from = from;
        size *= TILE_BASE;
    }
    out.sort_by_key(|t| t.start);
    out
}

/// The grain a tile wants at `detail` memories per tile. `detail == 0` wants
/// the widest memory everywhere: the completeness floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Want {
    Widest,
    Narrowest,
    Width(i128),
}

fn want(tile: &Tile, detail: usize) -> Want {
    if detail == 0 {
        Want::Widest
    } else if tile.open {
        Want::Narrowest
    } else {
        Want::Width((tile.units * TILE_UNIT_NS / detail as i128).max(MOMENT_NS))
    }
}

/// Of the active memories, keyed `(width, index)`, the one whose width is
/// closest to the want as a ratio; ties go to the narrower.
fn closest(active: &BTreeSet<(i128, usize)>, want: Want) -> usize {
    match want {
        Want::Widest => active.iter().next_back().unwrap().1,
        Want::Narrowest => active.iter().next().unwrap().1,
        Want::Width(w) => {
            let narrower = active.range(..(w + 1, 0)).next_back();
            let wider = active.range((w + 1, 0)..).next();
            match (narrower, wider) {
                (Some(&(nw, ni)), Some(&(ww, wi))) => {
                    // w / nw <= ww / w  <=>  w * w <= nw * ww
                    if w * w <= nw * ww {
                        ni
                    } else {
                        wi
                    }
                }
                (Some(&(_, i)), None) | (None, Some(&(_, i))) => i,
                (None, None) => unreachable!("closest of an empty set"),
            }
        }
    }
}

/// Sweep the tiled field left to right and report every elementary interval:
/// `(tile index, from, to, picked span index)`. At every point, of the
/// memories covering it, the one whose width is closest to the grain the
/// point's tile wants. Instants are a moment wide, so a moment inside an entry
/// is picked beside it, and overlapping memories are each picked where they
/// are closest.
fn sweep(
    spans: &[(i128, i128, Id)],
    tiles: &[Tile],
    detail: usize,
    visit: impl FnMut(usize, i128, i128, usize),
) {
    sweep_with(spans, tiles, |_| detail, visit)
}

/// `sweep` with a detail per tile (by tile index): the level-shares fit
/// renders every tile at its own grain.
fn sweep_with(
    spans: &[(i128, i128, Id)],
    tiles: &[Tile],
    detail_of: impl Fn(usize) -> usize,
    mut visit: impl FnMut(usize, i128, i128, usize),
) {
    let n = spans.len();
    if n == 0 {
        return;
    }
    let width = |i: usize| (spans[i].1 - spans[i].0).max(MOMENT_NS);
    // (coordinate, kind, index): ends leave before starts arrive at one
    // coordinate (0 sorts before 1), and a tile boundary (2) only breaks the
    // sweep so the want can change there.
    let mut events: Vec<(i128, u8, usize)> = Vec::with_capacity(2 * n + tiles.len());
    for i in 0..n {
        events.push((spans[i].0, 1, i));
        events.push((spans[i].0 + width(i), 0, i));
    }
    for (t, tile) in tiles.iter().enumerate() {
        events.push((tile.start, 2, t));
    }
    events.sort_unstable();
    let mut active: BTreeSet<(i128, usize)> = BTreeSet::new();
    let mut tile_at = 0usize;
    let mut at = 0;
    while at < events.len() {
        let coordinate = events[at].0;
        while at < events.len() && events[at].0 == coordinate {
            let (_, kind, i) = events[at];
            match kind {
                0 => {
                    active.remove(&(width(i), i));
                }
                1 => {
                    active.insert((width(i), i));
                }
                _ => tile_at = tile_at.max(i),
            }
            at += 1;
        }
        if at < events.len() && !active.is_empty() {
            let pick = closest(&active, want(&tiles[tile_at], detail_of(tile_at)));
            visit(tile_at, coordinate, events[at].0, pick);
        }
    }
}

/// One cut through the tiled field at `detail` memories per tile: a memory is
/// in the cover wherever it was the closest to what its tile wants. `detail`
/// zero is the widest memory at every point, the completeness floor.
pub fn select_tiled(spans: &[(i128, i128, Id)], tiles: &[Tile], detail: usize) -> Vec<usize> {
    let mut shown = vec![false; spans.len()];
    sweep(spans, tiles, detail, |_, _, _, pick| shown[pick] = true);
    (0..spans.len()).filter(|&i| shown[i]).collect()
}

/// One cut with a detail per tile: the cover, its cost, and each tile's
/// share of that cost. A memory shown in two tiles is charged to the older
/// one, where the sweep met it first.
fn select_with(
    spans: &[(i128, i128, Id)],
    tiles: &[Tile],
    details: &[usize],
    cost: &mut dyn FnMut(usize) -> Result<usize>,
) -> Result<(Vec<usize>, usize, Vec<usize>)> {
    let mut owner: Vec<Option<usize>> = vec![None; spans.len()];
    sweep_with(
        spans,
        tiles,
        |t| details[t],
        |t, _, _, pick| {
            if owner[pick].is_none() {
                owner[pick] = Some(t);
            }
        },
    );
    let mut cover = Vec::new();
    let mut per_tile = vec![0usize; tiles.len()];
    let mut used = 0usize;
    for i in 0..spans.len() {
        if let Some(t) = owner[i] {
            let c = cost(i)?;
            per_tile[t] = per_tile[t].saturating_add(c);
            used = used.saturating_add(c);
            cover.push(i);
        }
    }
    Ok((cover, used, per_tile))
}

/// The tiles in one line with their details, newest first, runs of equal
/// width and detail joined: `now@4096, 3x4.6h@1218, 1x3.0d@256`.
pub fn describe_details(tiles: &[Tile], details: &[usize]) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut runs: Vec<(i128, usize, String, usize)> = Vec::new();
    for (t, tile) in tiles.iter().enumerate().rev() {
        if tile.open {
            parts.push(format!("now@{}", details[t]));
            continue;
        }
        match runs.last_mut() {
            Some((units, detail, _, count)) if *units == tile.units && *detail == details[t] => {
                *count += 1
            }
            _ => runs.push((tile.units, details[t], tile.width(), 1)),
        }
    }
    for (_, detail, width, count) in runs {
        parts.push(format!("{count}x{width}@{detail}"));
    }
    parts.join(", ")
}

/// How well the pile serves one tile at a detail: what the tile wanted, how
/// many memories were picked in it, and the worst ratio between a picked
/// width and the want over the tile. A ratio far from one is a missing arc
/// (or, for today, nothing: today wants everything).
#[derive(Clone, Debug, PartialEq)]
pub struct TileReport {
    pub tile: Tile,
    pub want_ns: Option<i128>,
    pub picked: usize,
    pub worst_ratio: f64,
}

pub fn tile_report(spans: &[(i128, i128, Id)], tiles: &[Tile], detail: usize) -> Vec<TileReport> {
    let mut picked: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); tiles.len()];
    let mut worst: Vec<f64> = vec![1.0; tiles.len()];
    let width = |i: usize| (spans[i].1 - spans[i].0).max(MOMENT_NS);
    sweep(spans, tiles, detail, |t, _, _, pick| {
        picked[t].insert(pick);
        if let Want::Width(w) = want(&tiles[t], detail) {
            let ratio = (width(pick) as f64 / w as f64).max(w as f64 / width(pick) as f64);
            worst[t] = worst[t].max(ratio);
        }
    });
    tiles
        .iter()
        .enumerate()
        .map(|(t, tile)| TileReport {
            tile: *tile,
            want_ns: match want(tile, detail) {
                Want::Width(w) => Some(w),
                _ => None,
            },
            picked: picked[t].len(),
            worst_ratio: worst[t],
        })
        .collect()
}

/// A cut that fits, by level shares.
///
/// Every level of the tiling (every tile width present, the open unit with
/// the one-unit tiles) gets an equal share of the budget, and the tiles at a
/// level split their level's share. A tile renders at the finest rung of the
/// ladder whose cost fits its share, so a level with one tile shows it three
/// times as finely as a level with three. The cover is therefore always
/// about as full as the ladder allows, whatever the counter's phase; between
/// carries nothing but the open tile changes; a carry at level `l` re-shares
/// levels `l` and `l + 1`, the young end, and leaves everything older as it
/// was; and only a new level -- once per quadrupling of the life -- moves
/// every share. That is what JP asked for on 2026-09-06: a fixed token
/// count, temporal order, and recomputes that reach deeper ever more rarely.
///
/// `asked` pins one detail for every tile, for measuring. `fits` is false
/// only when even the floor (the widest memory at every point) overflows, in
/// which case `cover` is that floor and `used` its cost, so the caller can
/// name the shortfall.
pub struct TiledCut {
    /// The finest detail any tile renders at.
    pub detail: usize,
    /// The detail of each tile, by tile index.
    pub details: Vec<usize>,
    pub asked: Option<usize>,
    pub cover: Vec<usize>,
    pub used: usize,
    pub fits: bool,
}

fn rung_below(detail: usize) -> usize {
    DETAIL_LADDER
        .iter()
        .rev()
        .copied()
        .find(|&d| d < detail)
        .unwrap_or(0)
}

pub fn fit_tiled(
    spans: &[(i128, i128, Id)],
    tiles: &[Tile],
    cost: &mut dyn FnMut(usize) -> Result<usize>,
    budget: usize,
    asked: Option<usize>,
) -> Result<TiledCut> {
    let n = tiles.len();
    let (floor_cover, floor, _) = select_with(spans, tiles, &vec![0; n], cost)?;
    if floor > budget {
        return Ok(TiledCut {
            detail: 0,
            details: vec![0; n],
            asked,
            cover: floor_cover,
            used: floor,
            fits: false,
        });
    }
    let mut details: Vec<usize> = match asked {
        Some(wanted) => vec![wanted.min(DETAIL_CAP); n],
        None => {
            // Shares by level INDEX up to the top level, so the layout of the
            // shares depends only on the life's length, not on which levels
            // the counter happens to hold today. A level with no tile at this
            // phase lends its share to the nearest older level that has one:
            // that is the tile the missing levels just merged into, at the
            // young end, so re-sharing it is a suffix change.
            let level_of = |units: i128| -> usize {
                let mut l = 0;
                let mut u = units;
                while u > 1 {
                    u /= TILE_BASE;
                    l += 1;
                }
                l
            };
            let top = tiles.iter().map(|t| level_of(t.units)).max().unwrap_or(0);
            let mut present = vec![0usize; top + 1];
            for t in tiles {
                present[level_of(t.units)] += 1;
            }
            let unit_share = budget / (top + 1);
            let mut level_share = vec![0usize; top + 1];
            let mut lent = 0usize;
            for l in 0..=top {
                if present[l] > 0 {
                    level_share[l] = unit_share.saturating_mul(1 + lent);
                    lent = 0;
                } else {
                    lent += 1;
                }
            }
            let tile_share: Vec<usize> = tiles
                .iter()
                .map(|t| {
                    let l = level_of(t.units);
                    level_share[l] / present[l].max(1)
                })
                .collect();
            let mut chosen = vec![false; n];
            let mut details = vec![0usize; n];
            for &rung in DETAIL_LADDER.iter().rev() {
                let (_, _, per_tile) = select_with(spans, tiles, &vec![rung; n], cost)?;
                for t in 0..n {
                    if !chosen[t] && per_tile[t] <= tile_share[t] {
                        details[t] = rung;
                        chosen[t] = true;
                    }
                }
                if chosen.iter().all(|&c| c) {
                    break;
                }
            }
            details
        }
    };
    // The whole must fit; if the shares' sum of parts does not (a memory
    // charged to one tile and shown in another), step every tile down one
    // rung until it does. The floor fits, so this ends.
    loop {
        let (cover, used, _) = select_with(spans, tiles, &details, cost)?;
        if used <= budget {
            return Ok(TiledCut {
                detail: details.iter().copied().max().unwrap_or(0),
                details,
                asked,
                cover,
                used,
                fits: true,
            });
        }
        for d in details.iter_mut() {
            *d = rung_below(*d);
        }
    }
}

/// The tiles in one line, newest first: `now, 3x4.6h, 2x18.2h, 1x3.0d`.
pub fn describe_tiles(tiles: &[Tile]) -> String {
    let mut parts = vec!["now".to_string()];
    let mut runs: Vec<(i128, String, usize)> = Vec::new();
    for tile in tiles.iter().rev() {
        if tile.open {
            continue;
        }
        match runs.last_mut() {
            Some((units, _, count)) if *units == tile.units => *count += 1,
            _ => runs.push((tile.units, tile.width(), 1)),
        }
    }
    for (_, width, count) in runs {
        parts.push(format!("{count}x{width}"));
    }
    parts.join(", ")
}

/// Collapse memories which are interchangeable to the temporal cover into one
/// structural position.
///
/// The current cover has one axis: chronological, non-lens memories. Its forest
/// is computed solely from `(start, end)`, so exact equality of those two keys is
/// the strongest possible notion of structural equivalence: substituting one
/// member for another cannot alter containment, ancestry, recency, or width.
/// Content, intrinsic id, and rendered size deliberately do not participate.
///
/// The structural id is the least member id. It exists only as a stable final
/// tie-break for the refinement algorithm; the id of the recollection eventually
/// rendered is selected separately.
fn recollection_classes(
    raw_spans: &[(i128, i128, Id)],
) -> (Vec<(i128, i128, Id)>, Vec<Vec<usize>>) {
    let mut order: Vec<usize> = (0..raw_spans.len()).collect();
    order.sort_by(|&a, &b| {
        raw_spans[a]
            .0
            .cmp(&raw_spans[b].0)
            .then(raw_spans[a].1.cmp(&raw_spans[b].1))
            .then(raw_spans[a].2.cmp(&raw_spans[b].2))
    });

    let mut spans = Vec::new();
    let mut members: Vec<Vec<usize>> = Vec::new();
    for raw in order {
        let (start, end, id) = raw_spans[raw];
        if spans
            .last()
            .is_some_and(|&(class_start, class_end, _)| class_start == start && class_end == end)
        {
            members.last_mut().expect("class exists").push(raw);
        } else {
            spans.push((start, end, id));
            members.push(vec![raw]);
        }
    }
    (spans, members)
}

/// Conservative charge of one structural position. A contextual substitution
/// must not change whether a split fits, so the whole equivalence class is
/// charged at its largest member rather than at the currently selected prose.
fn recollection_class_cost<B: BlobStoreGet, P: TriblePattern>(
    reader: &B,
    space: &P,
    raw_spans: &[(i128, i128, Id)],
    raw_costs: &mut [Option<usize>],
    classes: &[Vec<usize>],
    class_costs: &mut [Option<usize>],
    class: usize,
) -> Result<usize> {
    if let Some(cost) = class_costs[class] {
        return Ok(cost);
    }
    let mut cost = 0;
    for &raw in &classes[class] {
        cost = cost.max(context_chunk_cost(
            reader, space, raw_spans, raw_costs, raw,
        )?);
    }
    class_costs[class] = Some(cost);
    Ok(cost)
}

/// Pick one recollection for a structural position. Eligibility is decided
/// before contextual ranking, so `--about` cannot accidentally hide a span by
/// choosing a filtered-out alternative when an eligible one exists. Scores tie
/// by intrinsic id for byte-stable output.
fn select_recollection(
    raw_spans: &[(i128, i128, Id)],
    members: &[usize],
    about_scores: Option<&HashMap<Id, f32>>,
    eligible: &[bool],
) -> usize {
    let has_eligible = members.iter().any(|&raw| eligible[raw]);
    members
        .iter()
        .copied()
        .filter(|&raw| !has_eligible || eligible[raw])
        .max_by(|&a, &b| {
            let a_score = about_scores
                .and_then(|scores| scores.get(&raw_spans[a].2))
                .copied()
                .unwrap_or(0.0);
            let b_score = about_scores
                .and_then(|scores| scores.get(&raw_spans[b].2))
                .copied()
                .unwrap_or(0.0);
            a_score
                .total_cmp(&b_score)
                // `max_by` should select the lexicographically least id on a
                // score tie, hence the deliberately reversed id comparison.
                .then_with(|| raw_spans[b].2.cmp(&raw_spans[a].2))
        })
        .expect("a recollection class is never empty")
}

/// How close the coarsest possible cover is to the budget.
///
/// `render_cover` refuses when the roots alone overflow, which is correct but
/// only observable once it has already happened — and it happens to EVERY reader
/// at once, because the roots grow silently as top-level chunks accumulate
/// without a coarser parent. On 2026-08-09 the whole wake ritual returned nothing
/// at 805,092 characters against an 800,000 budget: it had crossed by 0.6% and
/// nothing had ever reported the approach. This makes the approach readable while
/// the cover still works.
#[derive(Clone, Copy, Debug)]
pub struct CoverHeadroom {
    /// Top-level temporal positions with no coarser parent. These are the
    /// coarsest cover.
    pub roots: usize,
    /// Characters the coarsest cover needs, conservatively charging the largest
    /// recollection at each exact-span position.
    pub used: usize,
    /// Characters allowed.
    pub budget: usize,
}

impl CoverHeadroom {
    /// Characters to spare, saturating at zero once the cover is impossible.
    pub fn spare(&self) -> usize {
        self.budget.saturating_sub(self.used)
    }

    /// True once no in-budget cover exists — i.e. `render_cover` now fails.
    pub fn exhausted(&self) -> bool {
        self.used > self.budget
    }

    /// Fraction of the budget still free, 0.0 when exhausted.
    pub fn spare_fraction(&self) -> f64 {
        if self.budget == 0 {
            return 0.0;
        }
        self.spare() as f64 / self.budget as f64
    }
}

/// Compute [`CoverHeadroom`] without rendering a cover.
pub fn cover_headroom<B: BlobStoreGet, P: TriblePattern>(
    space: &P,
    ws: &B,
    budget_chars: usize,
) -> Result<CoverHeadroom> {
    let raw_spans = collect_chunk_spans(space);
    let (spans, classes) = recollection_classes(&raw_spans);
    let coarsest = match (
        spans.iter().map(|s| s.0).min(),
        spans.iter().map(|s| s.1).max(),
    ) {
        (Some(earliest), Some(latest)) => select_tiled(&spans, &tiles(earliest, latest), 0),
        _ => Vec::new(),
    };
    let mut raw_costs: Vec<Option<usize>> = vec![None; raw_spans.len()];
    let mut class_costs: Vec<Option<usize>> = vec![None; spans.len()];
    let mut used = 0usize;
    for &i in &coarsest {
        used = used.saturating_add(recollection_class_cost(
            ws,
            space,
            &raw_spans,
            &mut raw_costs,
            &classes,
            &mut class_costs,
            i,
        )?);
    }
    Ok(CoverHeadroom {
        roots: coarsest.len(),
        used,
        budget: budget_chars,
    })
}

/// One step of a replay: the cover the pile would have rendered when its
/// latest memory ended at `now`, and how much of the previous step's cover
/// survived as a byte-for-byte prefix.
#[derive(Clone, Debug)]
pub struct ReplayRow {
    /// The latest memory end at this step (TAI key): the `now` of the tiling.
    pub now: i128,
    pub tiles: usize,
    pub detail: usize,
    pub chunks: usize,
    /// Characters the cover used.
    pub used: usize,
    /// Characters of the previous step's cover that this cover begins with,
    /// unchanged and in the same order: what a cache would keep.
    pub kept: usize,
    /// Characters the previous step's cover used (0 on the first step).
    pub prev_used: usize,
    pub fits: bool,
    /// The tiling, newest first, as `describe_tiles` prints it.
    pub layout: String,
    /// The span of the first chunk in the cover: where a re-render began if
    /// nothing was kept.
    pub first: Option<(i128, i128)>,
    /// The span of the first chunk that differs from the previous cover.
    pub changed_at: Option<(i128, i128)>,
}

/// Replay the cover over the pile's own past: pretend the newest memory ends
/// at each of `steps` points, one `step_units` grid units apart, walking from
/// the oldest point to the present, and at each point render the cover the
/// pile would have rendered then (memories ending after the point are not yet
/// there). Fit the detail to the budget at every step -- or hold `asked` --
/// and report how much of each cover survives into the next.
///
/// A memory counts as present once its range has ended, not once it was
/// written, so arcs the comb wrote later over earlier days are present from
/// the start. That hides the comb's own re-renders on purpose: this measures
/// the churn of the tiling and the fit, nothing else.
pub fn replay_cover<B: BlobStoreGet, P: TriblePattern>(
    space: &P,
    ws: &B,
    budget_chars: usize,
    chunk_overhead: usize,
    steps: usize,
    step_units: i128,
    asked: Option<usize>,
    sliding: Option<i128>,
) -> Result<Vec<ReplayRow>> {
    let raw_spans = collect_chunk_spans(space);
    let (spans, classes) = recollection_classes(&raw_spans);
    let mut rows = Vec::new();
    let (Some(earliest), Some(latest)) = (
        spans.iter().map(|s| s.0).min(),
        spans.iter().map(|s| s.1).max(),
    ) else {
        return Ok(rows);
    };
    let mut raw_costs: Vec<Option<usize>> = vec![None; raw_spans.len()];
    let mut class_costs: Vec<Option<usize>> = vec![None; spans.len()];
    let mut cost_of = |i: usize| -> Result<usize> {
        Ok(recollection_class_cost(
            ws,
            space,
            &raw_spans,
            &mut raw_costs,
            &classes,
            &mut class_costs,
            i,
        )?
        .saturating_add(chunk_overhead))
    };
    let step_ns = step_units.max(1) * TILE_UNIT_NS;
    let mut previous: Vec<usize> = Vec::new();
    let mut prev_used = 0usize;
    for k in (0..=steps).rev() {
        let point = latest - (k as i128) * step_ns;
        // The pile as it stood: every memory whose range had ended by `point`.
        let mut map: Vec<usize> = Vec::new();
        let mut sub: Vec<(i128, i128, Id)> = Vec::new();
        for (i, s) in spans.iter().enumerate() {
            if s.1 <= point {
                map.push(i);
                sub.push(*s);
            }
        }
        let Some(now) = sub.iter().map(|s| s.1).max() else {
            continue;
        };
        let first = sub.iter().map(|s| s.0).min().unwrap_or(earliest);
        let tiles = match sliding {
            Some(k) => tiles_sliding(first, now, k),
            None => tiles(first, now),
        };
        let mut cost_sub = |j: usize| -> Result<usize> { cost_of(map[j]) };
        let cut = fit_tiled(&sub, &tiles, &mut cost_sub, budget_chars, asked)?;
        // The emission order: time order, wider first at a tie.
        let mut cover: Vec<usize> = cut.cover.iter().map(|&j| map[j]).collect();
        cover.sort_by(|&a, &b| {
            spans[a]
                .0
                .cmp(&spans[b].0)
                .then(spans[b].1.cmp(&spans[a].1))
        });
        let mut kept = 0usize;
        let mut changed_at = None;
        for (n, (a, b)) in cover.iter().zip(previous.iter()).enumerate() {
            if a != b {
                changed_at = Some((spans[*a].0, spans[*a].1));
                break;
            }
            kept = kept.saturating_add(cost_of(*a)?);
            if n + 1 == previous.len() && cover.len() > previous.len() {
                changed_at = Some((spans[cover[n + 1]].0, spans[cover[n + 1]].1));
            }
        }
        rows.push(ReplayRow {
            now,
            tiles: tiles.len(),
            detail: cut.detail,
            chunks: cover.len(),
            used: cut.used,
            kept,
            prev_used,
            fits: cut.fits,
            layout: describe_tiles(&tiles),
            first: cover.first().map(|&i| (spans[i].0, spans[i].1)),
            changed_at,
        });
        previous = cover;
        prev_used = cut.used;
    }
    Ok(rows)
}

// ---------------------------------------------------------------------------
// the render
// ---------------------------------------------------------------------------

pub fn render_cover<B, P, E>(
    space: &P,
    embeddings_space: &E,
    reader: &B,
    opts: &CoverOpts,
) -> Result<String>
where
    B: BlobStoreGet,
    P: TriblePattern,
    E: TriblePattern,
{
    use std::fmt::Write as _;

    let budget_chars = opts.budget_chars;
    let chunk_overhead = opts.chunk_overhead;
    let about = opts.about.as_deref();
    let filter_q = opts.filter.as_deref();
    let remove_q = opts.remove.as_deref();
    let sim_threshold = opts.sim_threshold;

    let mut out = String::new();
    let raw_spans = collect_chunk_spans(space);
    if raw_spans.is_empty() {
        writeln!(out, "no memory chunks")?;
        return Ok(out);
    }
    let (spans, classes) = recollection_classes(&raw_spans);
    if spans.is_empty() {
        eprintln!("memory context — 0 chunk(s)");
        return Ok(String::new());
    }
    let n = spans.len();

    // Only the emission needs containment, to indent a shown memory under the
    // shown memories around it. Nothing else does.
    let strict_contains = |a: usize, b: usize| -> bool {
        spans[a].0 <= spans[b].0
            && spans[a].1 >= spans[b].1
            && (spans[a].1 - spans[a].0) > (spans[b].1 - spans[b].0)
    };

    // Eligibility gates. `--filter` keeps only chunks whose positive
    // similarity to its query is ABOVE the threshold; `--remove` drops chunks
    // whose similarity is above it (an anti-filter — the negation lives in the
    // RETRIEVAL, not the query text, sidestepping embedding-negation failure).
    // These decide WHICH chunks may appear; `--about` chooses one recollection
    // inside an eligible exact-span class; the budget decides how many / how
    // coarse. A removed chunk must never be emitted at any granularity
    // (enforced by gating the selected cover below). Both compose with each
    // other and with `--about`.
    let universe: Vec<Id> = raw_spans.iter().map(|s| s.2).collect();
    let filter_elig = match filter_q {
        Some(q) => Some(eligibility_scores(
            space,
            embeddings_space,
            reader,
            q,
            &universe,
        )?),
        None => None,
    };
    let remove_elig = match remove_q {
        Some(q) => Some(eligibility_scores(
            space,
            embeddings_space,
            reader,
            q,
            &universe,
        )?),
        None => None,
    };
    // Fail-open honesty: unembedded, un-lexically-scorable chunks can't be
    // assessed, so they are KEPT — but say so loudly, because for the
    // intimate-exclusion use of `--remove` a silent keep would LEAK.
    for (label, elig) in [("--filter", &filter_elig), ("--remove", &remove_elig)] {
        if let Some((_, unscorable)) = elig {
            if !unscorable.is_empty() {
                let ids: Vec<String> = unscorable.iter().map(|id| format!("{id:x}")).collect();
                eprintln!(
                    "memory: {} unembedded chunk(s) not scorable for {label} — kept (fail-open); \
                     run `memory embed` to make them filterable: {}",
                    unscorable.len(),
                    ids.join(", ")
                );
            }
        }
    }
    let eligible_id = |id: Id| -> bool {
        if let Some((scores, _)) = &filter_elig {
            if let Some(v) = scores.get(&id) {
                if *v <= sim_threshold {
                    return false;
                }
            }
            // unscorable → fail-open KEEP (warned above)
        }
        if let Some((scores, _)) = &remove_elig {
            if let Some(v) = scores.get(&id) {
                if *v > sim_threshold {
                    return false;
                }
            }
            // unscorable (absent from map) → fail-open KEEP
        }
        true
    };

    let member_eligible: Vec<bool> = raw_spans.iter().map(|span| eligible_id(span.2)).collect();
    let class_eligible: Vec<bool> = classes
        .iter()
        .map(|members| members.iter().any(|&raw| member_eligible[raw]))
        .collect();

    // Contextual similarity is deliberately *not* a structural score. It may
    // select one member of an exact-span class, but never changes the forest or
    // split order. This is the crucial boundary between situated recollection
    // and a context-dependent autobiography.
    let about_scores = if classes.iter().any(|class| class.len() > 1) {
        about
            .map(|query| about_relevance_scores(space, embeddings_space, reader, query))
            .transpose()?
    } else {
        // With no structural alternatives there is nothing context may choose.
        // In particular, do not load an embedding model for a guaranteed no-op.
        None
    };
    let representatives: Vec<usize> = classes
        .iter()
        .map(|members| {
            select_recollection(&raw_spans, members, about_scores.as_ref(), &member_eligible)
        })
        .collect();

    // The cut. Cost is the recollection's exact character count plus the
    // consumer overhead, once per shown chunk.
    let mut raw_costs: Vec<Option<usize>> = vec![None; raw_spans.len()];
    let mut class_costs: Vec<Option<usize>> = vec![None; n];
    let mut cost_of = |i: usize| -> Result<usize> {
        Ok(recollection_class_cost(
            reader,
            space,
            &raw_spans,
            &mut raw_costs,
            &classes,
            &mut class_costs,
            i,
        )?
        .saturating_add(chunk_overhead))
    };
    let earliest = spans.iter().map(|s| s.0).min().unwrap();
    let latest = spans.iter().map(|s| s.1).max().unwrap();
    let tiles = tiles(earliest, latest);
    let cut = fit_tiled(&spans, &tiles, &mut cost_of, budget_chars, opts.detail)?;
    if !cut.fits {
        // Completeness is invariant -- never drop a temporal position to fit.
        // Even the floor, the widest memory at every point, overflows: the
        // memories at the edge have no arc over them yet. Say where.
        bail!(
            "incomplete cover: the coarsest cover of all memories needs ~{} characters, over the {budget_chars}-character budget.\n\
             {} memories are the widest thing over some stretch of time, so no in-budget cover can contain everything.\n\
             Comb the uncovered stretch into arcs BESIDE what exists -- day or week arcs over it (`memory levels` and `memory check` show where) -- never a new root from {} over the whole extent to {}: a root nested inside a root is a second rendering of the same time, and the journal keeps both.\n\
             (A well-maintained hierarchy keeps arcs over every span; the apex is the one you already have.)",
            cut.used,
            cut.cover.len(),
            fmt_epoch(key_to_epoch(earliest)),
            fmt_epoch(key_to_epoch(latest)),
        );
    }
    let detail = cut.detail;
    let details = cut.details;
    let asked = cut.asked;
    let mut cover = cut.cover;
    let mut used = cut.used;

    // Enforce eligibility at the chunk level the cover selected: a removed /
    // filtered-out chunk is not emitted at ANY granularity. V1 LIMITATION: a
    // surviving coarse ANCESTOR's summary is pre-written text and passes
    // through unchanged, so it may still *mention* removed material in its
    // prose — we drop selected nodes, we do not rewrite ancestor summaries.
    if filter_elig.is_some() || remove_elig.is_some() {
        cover.retain(|&i| class_eligible[i]);
        // Recompute the conservative character tally over what survived.
        used = 0;
        for &i in &cover {
            used = used.saturating_add(cost_of(i)?);
        }
    }

    // Emit coarse → fine: time order, indented by containment depth, each
    // chunk's span header followed by its summary content.
    cover.sort_by(|&a, &b| {
        spans[a]
            .0
            .cmp(&spans[b].0)
            .then(spans[b].1.cmp(&spans[a].1))
    });
    let mode = {
        let mut parts = vec![match about {
            Some(q) => format!("recollections about \"{q}\" within equal spans"),
            None => "coarser further back".to_string(),
        }];
        if let Some(q) = filter_q {
            parts.push(format!("filtered to \"{q}\""));
        }
        if let Some(q) = remove_q {
            parts.push(format!("excluding \"{q}\""));
        }
        format!("coarse → fine; {}", parts.join("; "))
    };
    // The status header goes to STDERR, not into the returned cover buffer: the
    // time-ranges are the drill key the wake ritual ingests, and this line's
    // volatile counts (chunk/char totals) would perturb the otherwise
    // prefix-stable cover on every call. Keep it visible to a human on stderr,
    // out of the stored/ingested cover text.
    // The pool is part of the same status line: a reader who sees a cover come
    // in under budget needs to know the shortfall is the quantized pool doing
    // its job, not a cover that failed to fill.
    for &i in &cover {
        let (s, e, _) = spans[i];
        let id = raw_spans[representatives[i]].2;
        let depth = cover
            .iter()
            .filter(|&&j| j != i && strict_contains(j, i))
            .count();
        let indent = "  ".repeat(depth);
        writeln!(out)?;
        // Ranges are the drill key (`memory <from>..<to>`); the opaque hex id is
        // boot-theatre noise in the wake, so it stays out of the cover line.
        writeln!(
            out,
            "{indent}{}",
            format_time_range(key_to_epoch(s), key_to_epoch(e)),
        )?;
        if let Some(handle) = chunk_summary_handle(space, id) {
            let summary: View<str> = reader.get(handle).context("read chunk summary")?;
            writeln!(out, "{}", summary.trim_end())?;
        } else if chunk_image_handle(space, id).is_some() {
            writeln!(out, "[image memory @ {}]", chunk_span_str(space, id))?;
        }
    }
    // Only report a completed cover. A live caller may acquire a missing
    // selected summary and retry this resident-only computation. The status
    // line goes to STDERR so its volatile counts never enter the cover text.
    eprintln!(
        "memory context — {} chunk(s), ~{} of {} characters ({mode}); {}; tiles: {}; floor {} chunk(s)",
        cover.len(),
        used,
        budget_chars,
        match asked {
            Some(wanted) if wanted != detail => format!("detail {detail} per tile (asked {wanted}, stepped down to fit)"),
            Some(_) => format!("detail {detail} per tile (asked)"),
            None => format!("equal shares per level, each tile at the finest detail that fits its share: {}", describe_details(&tiles, &details)),
        },
        describe_tiles(&tiles),
        select_tiled(&spans, &tiles, 0).len(),
    );
    Ok(out)
}

#[cfg(test)]
mod headroom_tests {
    use super::*;
    use triblespace::macros::id_hex;

    const A: Id = id_hex!("C1000000000000000000000000000001");
    const B: Id = id_hex!("C1000000000000000000000000000002");
    const C: Id = id_hex!("C1000000000000000000000000000003");

    #[test]
    fn exact_span_is_the_structural_equivalence_class() {
        let spans = vec![(10, 20, C), (10, 21, B), (10, 20, A)];
        let (structural, classes) = recollection_classes(&spans);
        assert_eq!(
            structural,
            vec![(10, 20, A), (10, 21, B)],
            "only exact endpoint equality collapses, and the structural id is stable"
        );
        let member_ids: Vec<Vec<Id>> = classes
            .iter()
            .map(|class| class.iter().map(|&raw| spans[raw].2).collect())
            .collect();
        assert_eq!(member_ids, vec![vec![A, C], vec![B]]);
    }

    #[test]
    fn span_projection_keeps_additive_typed_observations() {
        let point = |seconds: f64| {
            let epoch = Epoch::from_tai_seconds(seconds);
            (epoch, epoch).try_to_inline().unwrap()
        };
        let start_0 = point(0.0);
        let start_10 = point(10.0);
        let end_20 = point(20.0);
        let end_30 = point(30.0);
        let expected = vec![
            (interval_key(start_0), interval_key(end_20), A),
            (interval_key(start_0), interval_key(end_30), A),
            (interval_key(start_10), interval_key(end_20), A),
            (interval_key(start_10), interval_key(end_30), A),
        ];
        let facts = entity! {
            ExclusiveId::force_ref(&A) @
            metadata::tag: &KIND_CHUNK_ID,
            ctx::start_at: start_0,
            ctx::start_at: start_10,
            ctx::end_at: end_20,
            ctx::end_at: end_30,
        };

        assert_eq!(collect_chunk_spans(facts.facts()), expected);
    }

    #[test]
    fn recollection_classes_ignore_input_order() {
        let original = [(0, 100, C), (0, 100, A), (10, 20, B)];
        for permutation in [
            [0usize, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let raw: Vec<_> = permutation.into_iter().map(|i| original[i]).collect();
            let (spans, classes) = recollection_classes(&raw);
            assert_eq!(spans, vec![(0, 100, A), (10, 20, B)]);
            let ids: Vec<Vec<Id>> = classes
                .iter()
                .map(|members| members.iter().map(|&i| raw[i].2).collect())
                .collect();
            assert_eq!(ids, vec![vec![A, C], vec![B]]);
        }
    }

    #[test]
    fn contextual_selection_stays_inside_one_class_and_respects_eligibility() {
        let spans = vec![(0, 10, A), (0, 10, B), (0, 10, C)];
        let members = vec![0, 1, 2];
        let scores = HashMap::from([(A, 0.1), (B, 0.8), (C, 0.5)]);
        assert_eq!(
            select_recollection(&spans, &members, Some(&scores), &[true; 3]),
            1,
            "the most relevant equal-span recollection wins"
        );
        assert_eq!(
            select_recollection(&spans, &members, Some(&scores), &[true, false, true]),
            2,
            "context cannot select an ineligible recollection"
        );
        assert_eq!(
            select_recollection(&spans, &members, None, &[true; 3]),
            0,
            "without context the least intrinsic id is deterministic"
        );
    }

    #[test]
    fn headroom_arithmetic() {
        let ok = CoverHeadroom {
            roots: 2,
            used: 700_000,
            budget: 800_000,
        };
        assert!(!ok.exhausted());
        assert_eq!(ok.spare(), 100_000);
        assert!((ok.spare_fraction() - 0.125).abs() < 1e-9);

        // the real numbers from the 2026-08-09 outage
        let dead = CoverHeadroom {
            roots: 722,
            used: 805_092,
            budget: 800_000,
        };
        assert!(
            dead.exhausted(),
            "this is the state in which wake returns nothing"
        );
        assert_eq!(dead.spare(), 0, "spare saturates rather than underflowing");
        assert_eq!(dead.spare_fraction(), 0.0);

        // and the state that should have warned, well before it died
        let thin = CoverHeadroom {
            roots: 700,
            used: 799_000,
            budget: 800_000,
        };
        assert!(!thin.exhausted());
        assert!(
            thin.spare_fraction() < 0.15,
            "warning threshold would fire here"
        );
    }

    #[cfg(feature = "local-embed")]
    #[test]
    fn competing_shared_embedding_observations_are_arbitrated_deterministically() {
        let chunk = Id::new([0x61; 16]).unwrap();
        let mut fragment = Fragment::empty();
        let first = fragment.put::<Embedding768, _>(vec![0.0; 768]);
        let second = fragment.put::<Embedding768, _>(vec![1.0; 768]);
        fragment += entity! {
            triblespace::core::id::ExclusiveId::force_ref(&chunk) @
            embeddings::attr::embedding: first,
            embeddings::attr::embedding: second,
        };
        let selected = chunk_embedding_handle(fragment.facts(), chunk)
            .unwrap()
            .expect("one additive observation is selected");
        assert_eq!(selected, first.min(second));
    }

    fn ids(n: usize) -> Vec<Id> {
        (1..=n)
            .map(|k| {
                Id::new(u128::to_be_bytes(
                    0xC1000000000000000000000000000000 + k as u128,
                ))
                .unwrap()
            })
            .collect()
    }

    fn unit(n: i128) -> i128 {
        n * TILE_UNIT_NS
    }

    fn minutes(m: i128) -> i128 {
        m * 60_000_000_000
    }

    fn tile_units(tiles: &[Tile]) -> Vec<(i128, i128)> {
        tiles
            .iter()
            .map(|t| (t.start / TILE_UNIT_NS, t.units))
            .collect()
    }

    /// The tiling is the base-4 counter of the unit now falls in: one open
    /// unit, then the complete tiles of each level before the current block
    /// at that level.
    #[test]
    fn the_tiling_is_the_counter_of_now() {
        // 85 = 1*64 + 1*16 + 1*4 + 1: one tile at every level.
        let t = tiles(unit(0), unit(85) + minutes(30));
        assert_eq!(
            tile_units(&t),
            vec![(0, 64), (64, 16), (80, 4), (84, 1), (85, 1)]
        );
        assert!(t.last().unwrap().open);
        assert_eq!(describe_tiles(&t), "now, 1x4.6h, 1x18.2h, 1x3.0d, 1x12.1d");
        // 87 = 1*64 + 1*16 + 1*4 + 3: three unit tiles.
        let t = tiles(unit(0), unit(87));
        assert_eq!(
            tile_units(&t),
            vec![
                (0, 64),
                (64, 16),
                (80, 4),
                (84, 1),
                (85, 1),
                (86, 1),
                (87, 1)
            ]
        );
        // 88 = 1*64 + 1*16 + 2*4: the three units merged into a 4-unit tile.
        let t = tiles(unit(0), unit(88));
        assert_eq!(
            tile_units(&t),
            vec![(0, 64), (64, 16), (80, 4), (84, 4), (88, 1)]
        );
        // A life that began two units ago has no tiles left of the first memory.
        let t = tiles(unit(83), unit(85) + minutes(30));
        assert_eq!(tile_units(&t), vec![(80, 4), (84, 1), (85, 1)]);
        // A life that began in this unit is one open tile.
        assert_eq!(
            tile_units(&tiles(unit(85) + minutes(1), unit(85) + minutes(30))),
            vec![(85, 1)]
        );
    }

    /// The open tile wants leaf grain: every memory in it, nested, overlapping,
    /// and the instant beside its container.
    #[test]
    fn the_open_tile_wants_every_memory() {
        let id = ids(5);
        let spans = vec![
            (unit(85), unit(85) + minutes(60), id[0]),
            (unit(85) + minutes(10), unit(85) + minutes(25), id[1]),
            (unit(85) + minutes(20), unit(85) + minutes(20), id[2]),
            (unit(85) + minutes(50), unit(85) + minutes(90), id[3]),
            (unit(85) + minutes(90), unit(85) + minutes(91), id[4]),
        ];
        let t = tiles(unit(85), unit(85) + minutes(120));
        assert_eq!(select_tiled(&spans, &t, 1), vec![0, 1, 2, 3, 4]);
        assert_eq!(select_tiled(&spans, &t, 4096), vec![0, 1, 2, 3, 4]);
        // The floor is the widest at every point: the two arcs, and the last
        // minute that escapes them.
        assert_eq!(select_tiled(&spans, &t, 0), vec![0, 3, 4]);
    }

    /// A closed tile wants its width over the detail; at every point the
    /// memory closest to that, as a ratio.
    #[test]
    fn a_closed_tile_wants_its_grain() {
        let id = ids(14);
        let quarter = TILE_UNIT_NS / 4;
        let entry = TILE_UNIT_NS / 64;
        let mut spans = vec![(unit(84), unit(85), id[0])];
        for q in 0..4 {
            spans.push((
                unit(84) + q * quarter,
                unit(84) + (q + 1) * quarter,
                id[1 + q as usize],
            ));
        }
        for e in 0..8 {
            let s = unit(84) + e * entry;
            spans.push((s, s + entry, id[5 + e as usize]));
        }
        spans.push((unit(85) + minutes(30), unit(85) + minutes(40), id[13]));
        let t = tiles(unit(84), unit(85) + minutes(60));
        // One per tile: the unit arc, and the open tile's entry.
        assert_eq!(select_tiled(&spans, &t, 1), vec![0, 13]);
        // Four per tile: the quarter arcs.
        assert_eq!(select_tiled(&spans, &t, 4), vec![1, 2, 3, 4, 13]);
        // Sixty-four per tile: the entries where they exist, and where none
        // does, the quarter arcs (closer to a sixty-fourth than the unit).
        assert_eq!(
            select_tiled(&spans, &t, 64),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        );
    }

    /// Closest as a ratio, from either side: a point covered by an entry and a
    /// life root, wanting a unit, shows the entry; add an arc between and it
    /// shows the arc. Ties go to the narrower.
    #[test]
    fn closest_by_ratio_takes_the_entry_over_the_root() {
        let id = ids(3);
        let root = (unit(0), unit(400), id[0]);
        let entry = (unit(81) + minutes(10), unit(81) + minutes(27), id[1]);
        let t = tiles(unit(0), unit(85) + minutes(30));
        assert_eq!(select_tiled(&[root, entry], &t, 4), vec![0, 1]);
        let arc = (unit(81), unit(81) + TILE_UNIT_NS / 2, id[2]);
        assert_eq!(select_tiled(&[root, entry, arc], &t, 4), vec![0, 2]);
        let half = (unit(81), unit(81) + TILE_UNIT_NS / 2, id[1]);
        let double = (unit(80), unit(82), id[2]);
        assert_eq!(select_tiled(&[half, double], &t, 4), vec![0, 1]);
        assert_eq!(select_tiled(&[double, half], &t, 4), vec![0, 1]);
    }

    /// The floor is the widest memory at every point, and an overhang that
    /// escapes the wide memory is the widest over itself.
    #[test]
    fn the_floor_is_the_widest_at_every_point() {
        let id = ids(3);
        let t = tiles(unit(0), unit(150));
        let spans = vec![
            (unit(0), unit(100), id[0]),
            (unit(10), unit(20), id[1]),
            (unit(30), unit(40), id[2]),
        ];
        assert_eq!(select_tiled(&spans, &t, 0), vec![0]);
        let spans = vec![(unit(0), unit(100), id[0]), (unit(90), unit(150), id[1])];
        assert_eq!(select_tiled(&spans, &t, 0), vec![0, 1]);
    }

    /// An asked detail steps down the ladder until a complete cover fits;
    /// only the floor overflowing is a failure; with nothing asked, the finest
    /// rung that fits is found.
    #[test]
    fn the_cut_steps_down_and_never_strands() {
        let id = ids(34);
        let sub = TILE_UNIT_NS / 32;
        let mut spans = vec![(unit(84), unit(85), id[0])];
        for e in 0..32 {
            spans.push((
                unit(84) + e * sub,
                unit(84) + (e + 1) * sub,
                id[1 + e as usize],
            ));
        }
        spans.push((unit(85) + minutes(10), unit(85) + minutes(15), id[33]));
        let t = tiles(unit(84), unit(85) + minutes(30));
        let mut cost = |i: usize| -> Result<usize> { Ok(if i == 0 { 100 } else { 10 }) };
        // Every sub-arc costs 330: at 200 only the unit arc fits.
        let cut = fit_tiled(&spans, &t, &mut cost, 200, Some(32)).unwrap();
        assert!(cut.fits);
        assert_eq!(cut.asked, Some(32));
        assert!(cut.detail < 32);
        assert_eq!(cut.cover, vec![0, 33]);
        // With room: every sub-arc, at the detail asked.
        let cut = fit_tiled(&spans, &t, &mut cost, 400, Some(32)).unwrap();
        assert_eq!(cut.detail, 32);
        assert_eq!(cut.cover.len(), 33);
        // Below the floor: not fitting, and the floor is what comes back.
        let cut = fit_tiled(&spans, &t, &mut cost, 50, Some(32)).unwrap();
        assert!(!cut.fits);
        assert_eq!(cut.detail, 0);
        assert_eq!(cut.cover, vec![0, 33]);
        // Nothing asked: level shares. The two one-unit tiles (the closed unit
        // and the open one) split the level's share; at 400 the closed unit's
        // 200 holds only the unit arc, at 800 it holds every sub-arc at the
        // finest rung.
        let cut = fit_tiled(&spans, &t, &mut cost, 400, None).unwrap();
        assert_eq!(cut.asked, None);
        assert_eq!(cut.cover, vec![0, 33]);
        let cut = fit_tiled(&spans, &t, &mut cost, 800, None).unwrap();
        assert_eq!(cut.detail, DETAIL_CAP);
        assert_eq!(cut.cover.len(), 33);
    }

    /// Consecutive covers differ only in a suffix: a write in the open tile
    /// changes nothing before it; the unit closing changes nothing before it;
    /// a merge rewrites the merged tiles and nothing before them.
    #[test]
    fn consecutive_covers_differ_only_in_a_suffix() {
        let mut spans = Vec::new();
        let mut next = 1u128;
        let mut mint = || {
            let id = Id::new(u128::to_be_bytes(0xC1000000000000000000000000000000 + next)).unwrap();
            next += 1;
            id
        };
        let quarter = TILE_UNIT_NS / 4;
        for u in 0..86 {
            spans.push((unit(u), unit(u + 1), mint()));
            for q in 0..4 {
                spans.push((unit(u) + q * quarter, unit(u) + (q + 1) * quarter, mint()));
            }
        }
        let shown_before = |spans: &[(i128, i128, Id)], now: i128, limit: i128| -> Vec<Id> {
            let t = tiles(unit(0), now);
            select_tiled(spans, &t, 6)
                .into_iter()
                .filter(|&i| spans[i].1 <= limit)
                .map(|i| spans[i].2)
                .collect()
        };
        let a = shown_before(&spans, unit(85) + minutes(30), unit(85));
        // A write in the open tile.
        spans.push((unit(85) + minutes(40), unit(85) + minutes(55), mint()));
        assert_eq!(shown_before(&spans, unit(85) + minutes(60), unit(85)), a);
        // The unit closes: nothing before it moves.
        spans.push((unit(86) + minutes(5), unit(86) + minutes(20), mint()));
        assert_eq!(shown_before(&spans, unit(86) + minutes(30), unit(85)), a);
        // Unit 88: units 84 to 87 merge into one tile; nothing before 84 moves,
        // and the merged stretch is rendered coarser.
        let before_84 = shown_before(&spans, unit(86) + minutes(30), unit(84));
        spans.push((unit(88) + minutes(5), unit(88) + minutes(20), mint()));
        assert_eq!(
            shown_before(&spans, unit(88) + minutes(30), unit(84)),
            before_84
        );
        let merged_fine = shown_before(&spans, unit(87) + minutes(30), unit(88)).len();
        let merged_coarse = shown_before(&spans, unit(88) + minutes(30), unit(88)).len();
        assert!(
            merged_coarse < merged_fine,
            "{merged_coarse} < {merged_fine}"
        );
    }

    /// The report names a tile whose memories are far from its want.
    #[test]
    fn the_report_names_the_missing_arc() {
        let id = ids(9);
        let entry = TILE_UNIT_NS / 64;
        let mut spans = Vec::new();
        for e in 0..8 {
            let s = unit(84) + e * entry;
            spans.push((s, s + entry, id[e as usize]));
        }
        let t = tiles(unit(84), unit(85) + minutes(30));
        let report = tile_report(&spans, &t, 1);
        assert_eq!(report[0].picked, 8);
        assert!(report[0].worst_ratio > 60.0, "{}", report[0].worst_ratio);
        assert_eq!(report[1].want_ns, None, "the open tile wants leaf grain");
        spans.push((unit(84), unit(85), id[8]));
        let report = tile_report(&spans, &t, 1);
        assert_eq!(report[0].picked, 1);
        assert_eq!(report[0].worst_ratio, 1.0);
    }
}
