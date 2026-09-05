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

/// The fineness ladder. A step is a quarter of a doubling of the scalar that
/// turns age into a coarseness threshold. A cover is cut AT a step, never
/// between, so a new memory at the edge moves the cut by whole steps or not
/// at all and the text before the edge stays byte-identical between steps.
const FINENESS_STEPS: std::ops::RangeInclusive<i32> = -80..=120;

fn fineness(step: i32) -> f64 {
    2f64.powf(step as f64 / 4.0)
}

/// One cut through the field.
///
/// `now` is the latest end of any memory: a pure function of the pile, never
/// the wall clock. At every instant of the extent, the memories covering it
/// are ranked: a memory whose width clears the coarseness wanted at its age
/// (`width >= age / k`, age measured at its end) is eligible, and the
/// narrowest eligible is shown there; where none is eligible, the widest
/// there is. A memory is in the cover if it is shown at any instant it
/// covers. So arcs cover gaps and entries cover moments by arithmetic; two
/// memories over the same minutes both show, each narrowest somewhere; and
/// a moment inside an entry shows beside it rather than replacing it.
/// `k = None` is the coarsest cut: nothing eligible, the widest everywhere,
/// which is what completeness requires at the smallest budget.
pub fn select_field(spans: &[(i128, i128, Id)], k: Option<f64>) -> Vec<usize> {
    let n = spans.len();
    if n == 0 {
        return Vec::new();
    }
    let now = spans.iter().map(|s| s.1).max().unwrap();
    let width = |i: usize| (spans[i].1 - spans[i].0).max(MOMENT_NS);
    let eligible: Vec<bool> = (0..n)
        .map(|i| match k {
            Some(k) => (width(i) as f64) * k >= (now - spans[i].1).max(0) as f64,
            None => false,
        })
        .collect();
    // Sweep the endpoints. At one coordinate, ends leave before starts arrive
    // (0 sorts before 1), so a memory covers `[start, start + width)`.
    let mut events: Vec<(i128, u8, usize)> = Vec::with_capacity(2 * n);
    for i in 0..n {
        events.push((spans[i].0, 1, i));
        events.push((spans[i].0 + width(i), 0, i));
    }
    events.sort_unstable();
    let mut active: BTreeSet<(i128, usize)> = BTreeSet::new();
    let mut active_eligible: BTreeSet<(i128, usize)> = BTreeSet::new();
    let mut shown = vec![false; n];
    let mut at = 0;
    while at < events.len() {
        let coordinate = events[at].0;
        while at < events.len() && events[at].0 == coordinate {
            let (_, kind, i) = events[at];
            let key = (width(i), i);
            if kind == 0 {
                active.remove(&key);
                active_eligible.remove(&key);
            } else {
                active.insert(key);
                if eligible[i] {
                    active_eligible.insert(key);
                }
            }
            at += 1;
        }
        // The elementary interval from here to the next coordinate.
        if at < events.len() {
            let pick = active_eligible
                .iter()
                .next()
                .or_else(|| active.iter().next_back());
            if let Some(&(_, i)) = pick {
                shown[i] = true;
            }
        }
    }
    (0..n).filter(|&i| shown[i]).collect()
}

/// A cut that fits: the finest step whose cover costs no more than the
/// budget. The ladder is walked from the finest step downward and the first
/// step that fits wins, because cost is not monotone in fineness: between
/// two steps a wide memory may still pay in full for the old half of its span
/// while narrow memories already pay for the new half, so a cut can overflow
/// at a middle step and fit again at a finer one. `fits` is false only when
/// even the coarsest cut overflows, in which case `cover` is that coarsest
/// cut and `used` its cost, so the caller can name the shortfall.
pub struct FieldCut {
    pub step: Option<i32>,
    pub cover: Vec<usize>,
    pub used: usize,
    pub fits: bool,
}

pub fn fit_field(
    spans: &[(i128, i128, Id)],
    cost: &mut dyn FnMut(usize) -> Result<usize>,
    budget: usize,
) -> Result<FieldCut> {
    let total = |cover: &[usize], cost: &mut dyn FnMut(usize) -> Result<usize>| -> Result<usize> {
        let mut used = 0usize;
        for &i in cover {
            used = used.saturating_add(cost(i)?);
        }
        Ok(used)
    };
    let coarsest = select_field(spans, None);
    let floor = total(&coarsest, cost)?;
    if floor > budget {
        return Ok(FieldCut {
            step: None,
            cover: coarsest,
            used: floor,
            fits: false,
        });
    }
    for step in FINENESS_STEPS.rev() {
        let cover = select_field(spans, Some(fineness(step)));
        let used = total(&cover, cost)?;
        if used <= budget {
            return Ok(FieldCut {
                step: Some(step),
                cover,
                used,
                fits: true,
            });
        }
    }
    Ok(FieldCut {
        step: None,
        cover: coarsest,
        used: floor,
        fits: true,
    })
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
    let coarsest = select_field(&spans, None);
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
    let cut = fit_field(&spans, &mut cost_of, budget_chars)?;
    if !cut.fits {
        // Completeness is invariant -- never drop a temporal position to fit.
        // Even the coarsest cut, the widest memory at every instant, overflows:
        // the memories at the edge have no arc over them yet. Say where.
        let earliest = spans.iter().map(|s| s.0).min().unwrap();
        let latest = spans.iter().map(|s| s.1).max().unwrap();
        bail!(
            "incomplete cover: the coarsest cover of all memories needs ~{} characters, over the {budget_chars}-character budget.\n\
             {} memories are the widest thing over some stretch of time, so no in-budget cover can contain everything.\n\
             Comb the uncovered stretch into arcs BESIDE what exists -- day or week arcs over it (`memory density` and `memory check` show where) -- never a new root from {} over the whole extent to {}: a root nested inside a root is a second rendering of the same time, and the journal keeps both.\n\
             (A well-maintained hierarchy keeps arcs over every span; the apex is the one you already have.)",
            cut.used,
            cut.cover.len(),
            fmt_epoch(key_to_epoch(earliest)),
            fmt_epoch(key_to_epoch(latest)),
        );
    }
    let step = cut.step;
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
        "memory context — {} chunk(s), ~{} of {} characters ({mode}); fineness step {}; coarsest cover {} chunk(s)",
        cover.len(),
        used,
        budget_chars,
        match step {
            Some(step) => format!("{step} (age/{:.3})", fineness(step)),
            None => "coarsest".to_string(),
        },
        select_field(&spans, None).len(),
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

    fn day(d: i128) -> i128 {
        d * 86_400 * 1_000_000_000
    }

    /// The coarsest cut is the widest memory at every instant.
    #[test]
    fn the_coarsest_cut_is_the_widest_at_every_instant() {
        let id = ids(3);
        let spans = vec![
            (0, day(100), id[0]),
            (day(10), day(20), id[1]),
            (day(30), day(40), id[2]),
        ];
        assert_eq!(select_field(&spans, None), vec![0]);
        // An overlapping tail that escapes the wide memory is the widest over
        // its own overhang, so it shows too: completeness by arithmetic.
        let spans = vec![(0, day(100), id[0]), (day(90), day(150), id[1])];
        assert_eq!(select_field(&spans, None), vec![0, 1]);
    }

    /// Coarser further back: entries show only where they clear the
    /// coarseness their age asks for; the arc always covers the gaps.
    #[test]
    fn coarser_further_back() {
        let id = ids(11);
        let mut spans = vec![(0, day(100), id[0])];
        for i in 0..10 {
            spans.push((day(10 * i), day(10 * i) + day(5), id[i as usize + 1]));
        }
        // Finest: every entry, and the arc over the gaps between them.
        let fine = select_field(&spans, Some(1e9));
        assert_eq!(fine, (0..11).collect::<Vec<_>>());
        // Coarsest: the arc alone.
        assert_eq!(select_field(&spans, Some(1e-9)), vec![0]);
        // In between: an entry 5 days wide clears an age of at most 5 days
        // at k = 1 -- the last entry (age 5 days, ending at day 95) shows,
        // the one before it (age 15 days) does not.
        let mid = select_field(&spans, Some(1.0));
        assert!(mid.contains(&10), "the newest entry shows: {mid:?}");
        assert!(
            !mid.contains(&9),
            "an older entry is below the coarseness for its age: {mid:?}"
        );
        assert!(mid.contains(&0), "the arc covers the rest");
    }

    /// Two memories over the same minutes both show, each narrowest somewhere,
    /// whether they overlap or one sits inside the other.
    #[test]
    fn overlapping_memories_both_show() {
        let id = ids(3);
        let nested = vec![
            (0, day(1), id[0]),
            (day(1) / 2, day(1) / 2 + 60_000_000_000, id[1]),
        ];
        assert_eq!(select_field(&nested, Some(1e9)), vec![0, 1]);
        let overlapping = vec![(0, day(1), id[0]), (day(1) / 2, day(1) + day(1) / 2, id[1])];
        assert_eq!(select_field(&overlapping, Some(1e9)), vec![0, 1]);
    }

    /// An instant lasts a moment: it shows beside its container, not instead.
    #[test]
    fn a_moment_shows_beside_its_container() {
        let id = ids(2);
        let spans = vec![(0, day(1), id[0]), (day(1) / 2, day(1) / 2, id[1])];
        assert_eq!(select_field(&spans, Some(1e9)), vec![0, 1]);
    }

    /// The cut fits the budget at the finest step that does, and names an
    /// overflow of even the coarsest cut instead of dropping time.
    #[test]
    fn fit_picks_the_finest_step_within_budget() {
        let id = ids(11);
        let mut spans = vec![(0, day(100), id[0])];
        for i in 0..10 {
            spans.push((day(10 * i), day(10 * i) + day(5), id[i as usize + 1]));
        }
        let mut cost = |i: usize| -> Result<usize> { Ok(if i == 0 { 100 } else { 10 }) };
        let tight = fit_field(&spans, &mut cost, 120).unwrap();
        assert!(tight.fits);
        assert!(tight.cover.contains(&0));
        assert!(tight.cover.len() <= 3, "{:?}", tight.cover);
        assert!(tight.used <= 120);
        let loose = fit_field(&spans, &mut cost, 1_000).unwrap();
        assert_eq!(loose.cover, (0..11).collect::<Vec<_>>());
        assert_eq!(loose.used, 200);
        let impossible = fit_field(&spans, &mut cost, 50).unwrap();
        assert!(!impossible.fits);
        assert_eq!(impossible.cover, vec![0]);
        assert_eq!(impossible.used, 100);
    }

    /// On this shape a finer step never shows fewer memories than a coarser
    /// one. That is not true in general -- see `fit_finds_a_fit_past_a_bump`
    /// -- which is why `fit_field` walks the ladder from the fine end.
    #[test]
    fn steps_are_cut_at_the_ladder() {
        let id = ids(11);
        let mut spans = vec![(0, day(100), id[0])];
        for i in 0..10 {
            spans.push((day(10 * i), day(10 * i) + day(5), id[i as usize + 1]));
        }
        let mut last = 0usize;
        for step in FINENESS_STEPS {
            let n = select_field(&spans, Some(fineness(step))).len();
            assert!(n >= last, "step {step}: {n} < {last}");
            last = n;
        }
    }

    /// Cost is not monotone in fineness: with a root over two halves, the
    /// middle steps show the root (still paying for the old half) beside the
    /// new half, which costs more than either the root alone or both halves.
    /// The fit must not stop at that bump.
    #[test]
    fn fit_finds_a_fit_past_a_bump() {
        let id = ids(3);
        let spans = vec![
            (0, day(2), id[0]),
            (0, day(1), id[1]),
            (day(1), day(2), id[2]),
        ];
        let mut cost = |i: usize| -> Result<usize> { Ok(if i == 0 { 4 } else { 3 }) };
        let bump = select_field(&spans, Some(fineness(-4)));
        assert_eq!(
            bump,
            vec![0, 2],
            "the middle step shows the root beside the new half"
        );
        let cut = fit_field(&spans, &mut cost, 6).unwrap();
        assert!(cut.fits);
        assert_eq!(cut.cover, vec![1, 2]);
        assert_eq!(cut.used, 6);
        let coarse = fit_field(&spans, &mut cost, 5).unwrap();
        assert!(coarse.fits);
        assert_eq!(coarse.cover, vec![0]);
        assert_eq!(coarse.step, None);
    }
}
