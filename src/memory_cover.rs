//! The memory context-cover renderer, extracted so it can be assembled
//! IN-PROCESS by more than one caller.
//!
//! `memory context` (in `src/bin/memory.rs`) and `orient wake` (in
//! `src/bin/orient.rs`) both need the antichain cover over ALL of a persona's
//! memories — coarse → fine, fit to a character budget — rendered to a string.
//! Keeping the render (and the chunk accessors it needs) here means the two
//! callers can never drift: the cover semantics — antichain completeness, the
//! character budget, the `--about`/`--filter`/`--remove` composition — live in
//! exactly one place.
//!
//! Callers hand this module canonical Memory and shared Embeddings collection
//! views frozen from one pile snapshot, plus the Memory attachment reader and
//! parsed [`CoverOpts`]. The result is the cover text.

use std::collections::{BTreeSet, HashMap};

#[cfg(feature = "local-embed")]
use anyhow::anyhow;
use anyhow::{bail, Context, Result};
use hifitime::Epoch;

use triblespace::core::metadata;
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

pub fn chunk_summary_handle(space: &TribleSet, id: Id) -> Option<Inline<Handle<UTF8String>>> {
    find!(h: Inline<Handle<UTF8String>>, pattern!(space, [{ id @ ctx::summary: ?h }])).next()
}

/// The raw image bytes handle of a WORDLESS image memory chunk, if it is one.
/// An image chunk has no `ctx::summary`; its content is the picture itself.
pub fn chunk_image_handle(space: &TribleSet, id: Id) -> Option<Inline<Handle<RawBytes>>> {
    find!(h: Inline<Handle<RawBytes>>, pattern!(space, [{ id @ ctx::image: ?h }])).next()
}

/// A chunk's `from..to` span as a string (or `?` if missing) — used to render
/// a wordless image memory as `[image memory @ <span>]` everywhere a summary
/// would otherwise print.
pub fn chunk_span_str(space: &TribleSet, id: Id) -> String {
    match (chunk_start_at(space, id), chunk_end_at(space, id)) {
        (Some(s), Some(e)) => format_time_range(epoch_from_interval(s), epoch_end_from_interval(e)),
        _ => "?".to_string(),
    }
}

/// A chunk's lens-theme handle, if it is a thematic lens (not part of the
/// chronological spine). Presence is what excludes it from the temporal cover.
pub fn chunk_lens_handle(space: &TribleSet, id: Id) -> Option<Inline<Handle<UTF8String>>> {
    find!(h: Inline<Handle<UTF8String>>, pattern!(space, [{ id @ ctx::lens: ?h }])).next()
}

pub fn chunk_start_at(space: &TribleSet, id: Id) -> Option<Inline<NsTAIInterval>> {
    find!(v: Inline<NsTAIInterval>, pattern!(space, [{ id @ ctx::start_at: ?v }])).next()
}

pub fn chunk_end_at(space: &TribleSet, id: Id) -> Option<Inline<NsTAIInterval>> {
    find!(v: Inline<NsTAIInterval>, pattern!(space, [{ id @ ctx::end_at: ?v }])).next()
}

pub fn all_chunk_ids(space: &TribleSet) -> Vec<Id> {
    find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: &KIND_CHUNK_ID }])).collect()
}

/// The chunks nothing in `space` has corrected — [`latest`] over the Memory
/// supersedes DAG, restricted to chunk-tagged candidates.
///
/// Monotonic correction: the `supersedes` fact is appended, never removed;
/// covers and trees show only this frontier (read-side policy), while direct
/// id lookup still resolves superseded chunks for history inspection. A
/// retraction node observes without replacing, and it is an observer here like
/// any other — retracting a chunk removes it from the frontier and puts
/// nothing in its place, which is exactly what a retraction means.
pub fn live_chunk_ids(space: &TribleSet) -> BTreeSet<Id> {
    latest(space, metadata::supersedes.id(), all_chunk_ids(space))
}

/// [`latest`] over an arbitrary candidate set of Memory nodes — one
/// reverse-index probe per candidate, so a caller holding a handful of ids
/// never pays for a scan of the whole corpus.
pub fn live_among(space: &TribleSet, candidates: impl IntoIterator<Item = Id>) -> BTreeSet<Id> {
    latest(space, metadata::supersedes.id(), candidates)
}

/// The stored shared-space embedding handle for a chunk, if it has been embedded.
#[cfg(feature = "local-embed")]
pub fn chunk_embedding_handle(
    embeddings_space: &TribleSet,
    id: Id,
) -> Result<Option<Inline<Handle<Embedding768>>>> {
    let mut handles: BTreeSet<_> = find!(
        h: Inline<Handle<Embedding768>>,
        pattern!(embeddings_space, [{ id @ embeddings::attr::embedding: ?h }])
    )
    .collect();
    if handles.len() > 1 {
        bail!(
            "shared Embeddings collection has {} observations for Memory chunk {id:x}; expected at most one",
            handles.len()
        );
    }
    Ok(handles.pop_first())
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

/// Load the non-superseded chunks of canonical Memory as `(start_key, end_key, id)`.
/// Chunks missing a start/end interval are skipped. Shared by `list` and `check`.
pub fn collect_chunk_spans(space: &TribleSet) -> Vec<(i128, i128, Id)> {
    let mut spans = Vec::new();
    for id in live_chunk_ids(space) {
        // Thematic lenses are a parallel weave, not part of the chronological
        // spine — exclude them so a wide lens can't hijack the containment tree.
        if chunk_lens_handle(space, id).is_some() {
            continue;
        }
        let (Some(s), Some(e)) = (chunk_start_at(space, id), chunk_end_at(space, id)) else {
            continue;
        };
        spans.push((interval_key(s), interval_key(e), id));
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
pub fn context_chunk_cost<B: BlobStoreGet>(
    ws: &B,
    space: &TribleSet,
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

/// Rebuild the exact lexical view from the frozen canonical Memory facts.
/// BM25 is query-time machinery, not durable journal state: there is no stale
/// index entity to arbitrate and every live text revision visible in `space`
/// participates in this one scored postings walk.
pub fn lexical_relevance_scores<B: BlobStoreGet>(
    space: &TribleSet,
    reader: &B,
    query: &str,
) -> Result<HashMap<Id, f32>> {
    let mut builder = BM25Builder::new();
    for chunk in live_chunk_ids(space) {
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
/// (BM25). Both are non-negative; the cover propagates subtree maxima over them,
/// so a node is worth descending into iff some memory beneath it is relevant.
pub fn about_relevance_scores<B: BlobStoreGet>(
    space: &TribleSet,
    embeddings_space: &TribleSet,
    reader: &B,
    query: &str,
) -> Result<HashMap<Id, f32>> {
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
/// BM25). Negative cosines clamp to 0 so "unrelated" is uniform and subtree-max
/// stays meaningful (matching BM25's non-negative scores).
#[cfg(feature = "local-embed")]
pub fn semantic_about_scores<B: BlobStoreGet>(
    space: &TribleSet,
    embeddings_space: &TribleSet,
    reader: &B,
    query: &str,
) -> Result<Option<HashMap<Id, f32>>> {
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
/// `universe` is the exact set of chunks that can appear in the cover (non-
/// superseded, non-lens — what `collect_chunk_spans` selects), so the unscorable
/// warning never lists chunks that could never surface anyway.
pub fn eligibility_scores<B: BlobStoreGet>(
    space: &TribleSet,
    embeddings_space: &TribleSet,
    reader: &B,
    query: &str,
    universe: &[Id],
) -> Result<(HashMap<Id, f32>, Vec<Id>)> {
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
pub fn semantic_eligibility_scores<B: BlobStoreGet>(
    space: &TribleSet,
    embeddings_space: &TribleSet,
    reader: &B,
    query: &str,
    universe: &[Id],
) -> Result<Option<(HashMap<Id, f32>, Vec<Id>)>> {
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
    /// `--about <query>`: bias detail toward memories relevant to the query.
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
            about: None,
            filter: None,
            remove: None,
            sim_threshold: DEFAULT_SIM_THRESHOLD,
        }
    }
}

/// Render the context-cover text from canonical Memory and shared Embeddings
/// views, using `reader` for their attachment blobs. The result is the
/// antichain cover over all memories, coarse → fine, fit to
/// `opts.budget_chars` characters.
///
/// Completeness is invariant — a memory is never dropped to fit. If even the
/// coarsest cover (all roots) overflows the budget, this ERRORS with
/// instructions for raising a coarser apex rather than silently losing the past.
/// Containment forest over chunk spans: each chunk's tightest strict container,
/// the children that induces, and the roots with no container at all.
///
/// Shared by [`render_cover`] and [`cover_headroom`] so the two cannot disagree
/// about what a root is — the roots ARE the coarsest possible cover, so a
/// headroom figure computed from a different notion of root would report safety
/// the cover does not have.
fn containment_forest(
    spans: &[(i128, i128, Id)],
) -> (Vec<Option<usize>>, Vec<Vec<usize>>, Vec<usize>) {
    let n = spans.len();
    let strict_contains = |a: usize, b: usize| -> bool {
        spans[a].0 <= spans[b].0
            && spans[a].1 >= spans[b].1
            && (spans[a].1 - spans[a].0) > (spans[b].1 - spans[b].0)
    };
    let width = |i: usize| spans[i].1 - spans[i].0;
    let mut parent: Vec<Option<usize>> = vec![None; n];
    for (i, parent_slot) in parent.iter_mut().enumerate() {
        let mut best: Option<usize> = None;
        for j in 0..n {
            if j != i && strict_contains(j, i) {
                best = Some(match best {
                    Some(b) if width(b) <= width(j) => b,
                    _ => j,
                });
            }
        }
        *parent_slot = best;
    }
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut roots: Vec<usize> = Vec::new();
    for (i, parent) in parent.iter().copied().enumerate() {
        match parent {
            Some(p) => children[p].push(i),
            None => roots.push(i),
        }
    }
    (parent, children, roots)
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
    /// Top-level chunks with no coarser parent. These are the coarsest cover.
    pub roots: usize,
    /// Characters the coarsest cover needs.
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
pub fn cover_headroom<B: BlobStoreGet>(
    space: &TribleSet,
    ws: &B,
    budget_chars: usize,
) -> Result<CoverHeadroom> {
    let spans = collect_chunk_spans(space);
    let (_, _, roots) = containment_forest(&spans);
    let mut cost_cache: Vec<Option<usize>> = vec![None; spans.len()];
    let mut used = 0usize;
    for &i in &roots {
        used = used.saturating_add(context_chunk_cost(ws, space, &spans, &mut cost_cache, i)?);
    }
    Ok(CoverHeadroom {
        roots: roots.len(),
        used,
        budget: budget_chars,
    })
}

// ---------------------------------------------------------------------------
// prefix stability
// ---------------------------------------------------------------------------

/// Resolution of the refinement pool, as a divisor of the budget.
///
/// The cover is EMITTED oldest-first but REFINED recency-first, so the last
/// split the budget can afford is the *oldest splittable* chunk — which is the
/// FRONT of the emitted text. When every split competes for one global
/// remainder, the marginal decision is therefore a function of the TOTAL, and
/// it sits at the front: perturb the total by anything and the whole cover
/// after the first coarse chunk re-cuts.
///
/// Measured on `self.pile` (2026-08-27, plain `memory context`, 200,000-char
/// budget, 202-chunk / 204,717-byte cover, one machine, pile held FIXED so
/// only the budget number changed): raising the budget by 1,500 characters —
/// 0.75% — moved the first differing byte to 9,200 of 204,317. One
/// journal-sized memory does the same, for the same reason.
///
/// The fix is to stop letting the mandatory part fund the discretionary part.
/// The floor — the coarsest antichain, which completeness REQUIRES — is not a
/// decision, so it is subtracted once and the remainder is quantized to this
/// resolution. Between quanta the pool is a literal constant, so a new memory
/// enlarges the floor and moves nothing else, and every leading chunk survives.
///
/// The resolution is the one knob, and it is a resolution on the budget axis —
/// the natural parameter — not a duration, not a calendar unit, and not a proxy
/// for how often anyone happens to journal. It trades unspent budget against
/// re-cut frequency, and with per-chunk KV checkpoints downstream those are not
/// symmetric: a re-cut costs one re-prefill, unspent budget costs detail in
/// EVERY wake. A journal entry measures ~1,300 characters, so a sixteenth of a
/// 200,000-character budget absorbs about ten of them before the cover must be
/// re-cut. Measured over 30 such writes on a clone of the live pile: 27 of 30
/// re-cut nothing at all, against 3 of 30 unchanged, and a median of 2 of 200
/// leading chunks surviving, under one global remainder. The price is 9,186
/// characters (4.6% of the budget) left unspent, and 13 of 200 cover chunks.
const REFINE_POOL_QUANTUM_DEN: usize = 16;

/// Characters available for refinement: what the budget has left after the
/// mandatory floor, rounded DOWN to a whole number of quanta so it is a
/// constant between steps.
fn refinement_pool(budget_chars: usize, floor_chars: usize) -> usize {
    let quantum = (budget_chars / REFINE_POOL_QUANTUM_DEN).max(1);
    budget_chars.saturating_sub(floor_chars) / quantum * quantum
}

pub fn render_cover<B: BlobStoreGet>(
    space: &TribleSet,
    embeddings_space: &TribleSet,
    reader: &B,
    opts: &CoverOpts,
) -> Result<String> {
    use std::fmt::Write as _;

    let budget_chars = opts.budget_chars;
    let about = opts.about.as_deref();
    let filter_q = opts.filter.as_deref();
    let remove_q = opts.remove.as_deref();
    let sim_threshold = opts.sim_threshold;

    let mut out = String::new();
    let spans = collect_chunk_spans(space);
    if spans.is_empty() {
        writeln!(out, "no memory chunks")?;
        return Ok(out);
    }
    let n = spans.len();

    // Containment is time-range subsumption (the only hierarchy): a chunk's
    // immediate parent is the *tightest* strictly-wider chunk that spans it.
    let (parent, children, mut roots) = containment_forest(&spans);
    let strict_contains = |a: usize, b: usize| -> bool {
        spans[a].0 <= spans[b].0
            && spans[a].1 >= spans[b].1
            && (spans[a].1 - spans[a].0) > (spans[b].1 - spans[b].0)
    };
    let width = |i: usize| spans[i].1 - spans[i].0;

    // Eligibility gates. `--filter` keeps only chunks whose positive
    // similarity to its query is ABOVE the threshold; `--remove` drops chunks
    // whose similarity is above it (an anti-filter — the negation lives in the
    // RETRIEVAL, not the query text, sidestepping embedding-negation failure).
    // These decide WHICH chunks may appear; `--about` decides DETAIL WEIGHTING
    // among the eligible; the budget decides how many / how coarse. A removed
    // chunk must never be emitted at any granularity (enforced by gating the
    // selected cover below). Both compose with each other and with `--about`.
    let universe: Vec<Id> = spans.iter().map(|s| s.2).collect();
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
    let eligible = |id: Id| -> bool {
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

    // Relevance scoring for detail weighting: score every chunk against a
    // query, then propagate each node's score up to a subtree maximum (a node
    // is worth descending into if ANY memory beneath it is relevant). `--about`
    // drives this when present; with only `--filter`, reuse the filter scores
    // so the cover descends TOWARD the eligible material instead of staying
    // coarse (otherwise a filtered cover would surface little detail).
    let relevance: Vec<f32> = if about.is_some() || filter_q.is_some() {
        let scores: HashMap<Id, f32> = if let Some(query) = about {
            about_relevance_scores(space, embeddings_space, reader, query)?
        } else {
            filter_elig.as_ref().unwrap().0.clone()
        };
        let mut r: Vec<f32> = (0..n)
            .map(|i| *scores.get(&spans[i].2).unwrap_or(&0.0))
            .collect();
        // Narrow→wide so children precede parents; lift each subtree maximum up.
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by_key(|&i| spans[i].1 - spans[i].0);
        for &i in &order {
            if let Some(p) = parent[i] {
                if r[i] > r[p] {
                    r[p] = r[i];
                }
            }
        }
        r
    } else {
        vec![0.0; n]
    };

    // Floor of the cover: the coarsest antichain (all roots), oldest first.
    // Completeness is invariant — never drop a memory to fit. If even this
    // overflows, the hierarchy lacks a coarse-enough apex; tell the caller
    // how to raise one instead of silently losing the past.
    roots.sort_by(|&a, &b| {
        spans[a]
            .0
            .cmp(&spans[b].0)
            .then(spans[b].1.cmp(&spans[a].1))
    });
    let mut cost_cache: Vec<Option<usize>> = vec![None; n];
    let mut used = 0usize;
    for &i in &roots {
        used = used.saturating_add(context_chunk_cost(
            reader,
            space,
            &spans,
            &mut cost_cache,
            i,
        )?);
    }
    if used > budget_chars {
        let earliest = roots.iter().map(|&i| spans[i].0).min().unwrap();
        let latest = roots.iter().map(|&i| spans[i].1).max().unwrap();
        bail!(
            "incomplete cover: the coarsest cover of all memories needs ~{} characters, over the {budget_chars}-character budget.\n\
             Your memory hierarchy has {} top-level chunk(s) with no coarser parent spanning them, so no in-budget cover can contain everything.\n\
             Raise a coarser apex over the whole extent, then retry:\n    \
             memory create {}..{} \"<one coarse summary of this whole span>\"\n\
             (A well-maintained hierarchy keeps a coarse summary over its full extent — this is how you add the missing layer.)",
            used,
            roots.len(),
            fmt_epoch(key_to_epoch(earliest)),
            fmt_epoch(key_to_epoch(latest)),
        );
    }

    // Refine recency-first: spend the remaining budget splitting the most
    // recent splittable chunk into its immediate children, so detail
    // concentrates toward now and the deep past stays coarse. (The playground
    // gets this gradient from drop-oldest; we get it from the split order,
    // since completeness forbids dropping.)
    let mut cover: Vec<usize> = roots.clone();
    // The floor is not a decision, so it must not compete with decisions. It is
    // subtracted once, and what is left — quantized — is the pool every split
    // is judged against for the rest of this render.
    let floor_used = used;
    let pool = refinement_pool(budget_chars, floor_used) as i128;
    let mut spent: i128 = 0;
    loop {
        let remaining = pool - spent;
        if remaining <= 0 {
            break;
        }
        let mut best: Option<usize> = None; // position in `cover`
        let mut best_delta: i128 = 0;
        let mut best_key: Option<(f32, i128, i128, i128, Id)> = None;
        for (pos, &i) in cover.iter().enumerate() {
            if children[i].len() < 2 {
                continue;
            }
            let mut kids_cost = 0i128;
            for &k in &children[i] {
                kids_cost += context_chunk_cost(reader, space, &spans, &mut cost_cache, k)? as i128;
            }
            let pcost = context_chunk_cost(reader, space, &spans, &mut cost_cache, i)? as i128;
            // SIGNED. A split whose children are collectively cheaper than the
            // parent's own summary gives budget back; `saturating_sub` used to
            // round that to zero, so the pool was under-spent by however much
            // detail happened to be cheap. Correctness, independent of any
            // allocation scheme.
            let delta = kids_cost - pcost;
            if delta > remaining {
                continue;
            }
            // Priority: relevance (subtree-max, when --about) desc → recency
            // (latest end) desc → width desc → detail gained desc → id asc.
            // Without --about every relevance is 0, so recency leads exactly as
            // before; with it, the cover descends into the query-relevant
            // subtrees first and leaves the rest coarse.
            let key = (relevance[i], spans[i].1, width(i), delta, spans[i].2);
            let better = match best_key {
                None => true,
                Some((br, be, bw, bx, bid)) => {
                    if key.0 != br {
                        key.0 > br
                    } else if key.1 != be {
                        key.1 > be
                    } else if key.2 != bw {
                        key.2 > bw
                    } else if key.3 != bx {
                        key.3 > bx
                    } else {
                        key.4 < bid
                    }
                }
            };
            if better {
                best = Some(pos);
                best_delta = delta;
                best_key = Some(key);
            }
        }
        let Some(pos) = best else {
            break;
        };
        let kids = children[cover[pos]].clone();
        cover.splice(pos..=pos, kids);
        spent += best_delta;
    }
    used = (floor_used as i128 + spent).max(0) as usize;

    // Enforce eligibility at the chunk level the cover selected: a removed /
    // filtered-out chunk is not emitted at ANY granularity. V1 LIMITATION: a
    // surviving coarse ANCESTOR's summary is pre-written text and passes
    // through unchanged, so it may still *mention* removed material in its
    // prose — we drop selected nodes, we do not rewrite ancestor summaries.
    if filter_elig.is_some() || remove_elig.is_some() {
        cover.retain(|&i| eligible(spans[i].2));
        // Recompute the character tally honestly over what actually survived.
        used = 0;
        for &i in &cover {
            used = used.saturating_add(context_chunk_cost(
                reader,
                space,
                &spans,
                &mut cost_cache,
                i,
            )?);
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
            Some(q) => format!("most detail on memories about \"{q}\""),
            None => "recent in most detail".to_string(),
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
    eprintln!(
        "memory context — {} chunk(s), ~{} of {} characters ({mode}); floor {} + refinement pool {}",
        cover.len(),
        used,
        budget_chars,
        floor_used,
        refinement_pool(budget_chars, floor_used),
    );
    for &i in &cover {
        let (s, e, id) = spans[i];
        let depth = (0..n).filter(|&j| j != i && strict_contains(j, i)).count();
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
    Ok(out)
}

#[cfg(test)]
mod headroom_tests {
    use super::*;
    use triblespace::macros::id_hex;

    const A: Id = id_hex!("C1000000000000000000000000000001");
    const B: Id = id_hex!("C1000000000000000000000000000002");
    const C: Id = id_hex!("C1000000000000000000000000000003");

    /// A chunk strictly inside another is not a root; only the container is.
    #[test]
    fn nesting_yields_one_root() {
        let spans = vec![(0i128, 100i128, A), (10, 20, B), (30, 40, C)];
        let (_, _, roots) = containment_forest(&spans);
        assert_eq!(roots, vec![0]);
    }

    /// The shape that broke wake: an apex that stops short, and later chunks
    /// that OVERLAP its tail without being contained by it. Overlap is not
    /// containment, so both are roots and the coarsest cover is the sum of
    /// both — which is how the roots grew unnoticed until they overflowed.
    #[test]
    fn overlap_is_not_containment() {
        // apex 0..100; a chunk 90..150 overlaps its tail but escapes it.
        let spans = vec![(0i128, 100i128, A), (90, 150, B)];
        let (parent, _, roots) = containment_forest(&spans);
        assert_eq!(parent, vec![None, None], "neither contains the other");
        assert_eq!(roots.len(), 2, "both are top-level, so both cost budget");
    }

    /// Extending the apex over the escaping chunk re-parents it — the fix.
    #[test]
    fn a_wider_apex_adopts_the_orphan() {
        let spans = vec![(0i128, 100i128, A), (90, 150, B), (0, 200, C)];
        let (parent, _, roots) = containment_forest(&spans);
        assert_eq!(roots, vec![2], "the wide apex is the only root");
        assert_eq!(parent[0], Some(2));
        assert_eq!(parent[1], Some(2));
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
    fn competing_shared_embedding_observations_are_ambiguous() {
        let chunk = Id::new([0x61; 16]).unwrap();
        let mut fragment = Fragment::empty();
        let first = fragment.put::<Embedding768, _>(vec![0.0; 768]);
        let second = fragment.put::<Embedding768, _>(vec![1.0; 768]);
        fragment += entity! {
            triblespace::core::id::ExclusiveId::force_ref(&chunk) @
            embeddings::attr::embedding: first,
            embeddings::attr::embedding: second,
        };
        let error = chunk_embedding_handle(fragment.facts(), chunk).unwrap_err();
        assert!(error.to_string().contains("expected at most one"));
    }

    /// The pool is a whole number of quanta, so it is a CONSTANT while the
    /// floor grows — which is the only reason a new memory can leave every
    /// earlier split decision alone.
    #[test]
    fn the_refinement_pool_is_constant_between_quanta() {
        let budget = 200_000; // quantum = 12_500
        let a = refinement_pool(budget, 60_000);
        for floor in [60_001, 61_400, 62_500] {
            assert_eq!(
                refinement_pool(budget, floor),
                a,
                "floor {floor} moved the pool"
            );
        }
        assert_eq!(a, 137_500);
        // Crossing a quantum steps it, once, by exactly one quantum. At ~1,300
        // characters a journal entry that is about ten writes apart.
        assert_eq!(refinement_pool(budget, 62_501), 125_000);
        // A floor that eats the budget leaves nothing discretionary — and does
        // not underflow. (`render_cover` has already failed loud by then.)
        assert_eq!(refinement_pool(budget, 200_000), 0);
        assert_eq!(refinement_pool(budget, 999_999), 0);
        // A budget smaller than the divisor still has a usable quantum of 1.
        assert_eq!(refinement_pool(8, 3), 5);
    }
}
