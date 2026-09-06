//! The memory context-cover renderer, extracted so it can be assembled
//! IN-PROCESS by more than one caller.
//!
//! `memory context` (in `src/bin/memory.rs`) and `orient wake` (in
//! `src/bin/orient.rs`) both need the same density-shaped recollection of a
//! persona's memories, fit to a character budget and rendered to a string.
//! Keeping the render (and the chunk accessors it needs) here means the two
//! callers can never drift: the recollection semantics, character budget, and
//! `--about`/`--filter`/`--remove` composition live in exactly one place.
//! Context never gets to rewrite the temporal structure:
//! `--about` may choose one recollection among entries with the exact same
//! temporal coverage, but cannot change which spans the cover refines.
//!
//! Callers hand this module maintained Memory and shared Embeddings collection
//! views frozen from one pile snapshot, plus the Memory attachment reader and
//! parsed [`CoverOpts`]. The result is the cover text.

use std::collections::{BTreeSet, HashMap};

#[cfg(feature = "local-embed")]
use anyhow::anyhow;
use anyhow::{Context, Result};
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

/// Exact rendered character-cost of a chunk, loaded lazily and cached by span
/// index. This includes the leading blank line, range label, body, and their
/// newlines; `budget_chars` therefore bounds the returned string rather than
/// merely its summaries.
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
    let (start, end, id) = spans[i];
    let range = format_time_range(key_to_epoch(start), key_to_epoch(end));
    // Leading blank line plus the range and its newline.
    let framing = 1usize
        .saturating_add(range.chars().count())
        .saturating_add(1);
    let body = match chunk_summary_handle(space, id) {
        Some(handle) => {
            let summary: View<str> = ws.get(handle).context("read chunk summary")?;
            Some(summary.trim_end().chars().count())
        }
        None if chunk_image_handle(space, id).is_some() => {
            Some(format!("[image memory @ {range}]").chars().count())
        }
        None => None,
    };
    let c = body.map_or(framing, |chars| {
        framing.saturating_add(chars).saturating_add(1)
    });
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
    /// Plain density-shaped recollection: no semantic gating or substitution.
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

/// A point memory lasts one journal moment when its endpoints are compared
/// with an ideal slot; otherwise its temporal density would be exactly zero.
const MOMENT_NS: i128 = (crate::memory::MOMENT_SECONDS * 1_000_000_000.0) as i128;

// ---------------------------------------------------------------------------
// density-shaped recollection
// ---------------------------------------------------------------------------

/// The ideal temporal point and grain at one character position in a reader's
/// memory space. Times are offsets from the beginning of the remembered life,
/// avoiding precision loss from converting absolute TAI nanoseconds to `f64`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DensitySample {
    pub time_ns: f64,
    pub time_per_char_ns: f64,
}

/// A continuous map from a fixed character space onto an arbitrarily long
/// remembered life.
///
/// Characters are uniform in `ln(moment + age)`, where age is measured back
/// from the newest memory. Consequently the wanted temporal density grows
/// exponentially into the past. The existing three-second memory moment is
/// the only scale anchor; there is no calendar cell, tile width, level, or
/// fitted detail. Integrating [`DensityGradient::sample`] from zero to `space`
/// yields exactly `life_ns`.
#[derive(Clone, Copy, Debug)]
pub struct DensityGradient {
    life_ns: f64,
    space: usize,
    rate: f64,
}

impl DensityGradient {
    pub fn new(life_ns: i128, space: usize) -> Self {
        let life_ns = life_ns.max(MOMENT_NS) as f64;
        let space = space.max(1);
        let moment = MOMENT_NS as f64;
        let rate = (life_ns / moment).ln_1p() / space as f64;
        Self {
            life_ns,
            space,
            rate,
        }
    }

    pub fn sample(&self, cursor: usize) -> DensitySample {
        let cursor = cursor.min(self.space) as f64;
        let behind = self.space as f64 - cursor;
        let exponent = self.rate * behind;
        let moment = MOMENT_NS as f64;
        let age = moment * exponent.exp_m1();
        DensitySample {
            time_ns: (self.life_ns - age).clamp(0.0, self.life_ns),
            time_per_char_ns: moment * self.rate * exponent.exp(),
        }
    }
}

/// The lossy recollection selected for one reader. `cover` is in greedy SPACE
/// cursor order. Temporal centres may wobble when ranges overlap or support is
/// sparse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecollectionCut {
    pub cover: Vec<usize>,
    pub used: usize,
}

/// Greedily approximate the continuous density gradient with the memories the
/// journal actually contains.
///
/// A candidate's charged size turns the cursor into one ideal temporal slot:
/// `[gradient(cursor), gradient(cursor + cost)]`. The closest memory is the one
/// whose actual start and end best match those two endpoints. Centre and
/// density are therefore not separately weighted objectives: they are the
/// midpoint and width of the same interval comparison, including the
/// gradient's curvature across a long memory. Local overshoot is deliberate:
/// the cursor remains on the ideal field, so subsequent memories may fall
/// inside or leave gaps around an earlier range. This is recollection, not an
/// interval partition.
///
/// Each exact-span structural class may appear once. The first best candidate
/// which cannot fit ends the recollection, exactly as a physical
/// reader whose remaining space is smaller than the next memory. Intrinsic id
/// is the final tie-break, making the projection independent of input order.
pub fn select_recollection_cut(
    spans: &[(i128, i128, Id)],
    costs: &[usize],
    eligible: &[bool],
    budget: usize,
) -> RecollectionCut {
    assert_eq!(spans.len(), costs.len());
    assert_eq!(spans.len(), eligible.len());
    let (Some(earliest), Some(latest)) = (
        spans.iter().map(|span| span.0).min(),
        spans.iter().map(|span| span.1).max(),
    ) else {
        return RecollectionCut {
            cover: Vec::new(),
            used: 0,
        };
    };
    if budget == 0 {
        return RecollectionCut {
            cover: Vec::new(),
            used: 0,
        };
    }

    let gradient = DensityGradient::new(latest.saturating_sub(earliest), budget);
    let mut selected = vec![false; spans.len()];
    let mut cover = Vec::new();
    let mut used = 0usize;

    while used < budget {
        let ideal_start = gradient.sample(used).time_ns;
        let mut best: Option<(f64, Id, usize)> = None;
        for (i, &(start, end, id)) in spans.iter().enumerate() {
            let cost = costs[i];
            if selected[i] || !eligible[i] || cost == 0 {
                continue;
            }
            let width = end.saturating_sub(start).max(MOMENT_NS) as f64;
            let actual_start = start.saturating_sub(earliest) as f64;
            let actual_end = actual_start + width;
            let ideal_end = gradient.sample(used.saturating_add(cost)).time_ns;
            let start_error = actual_start - ideal_start;
            let end_error = actual_end - ideal_end;
            let score = start_error.mul_add(start_error, end_error * end_error);
            let candidate = (score, id, i);
            if best.as_ref().is_none_or(|current| {
                candidate
                    .0
                    .total_cmp(&current.0)
                    .then(candidate.1.cmp(&current.1))
                    .is_lt()
            }) {
                best = Some(candidate);
            }
        }
        let Some((_, _, pick)) = best else {
            break;
        };
        let next = used.saturating_add(costs[pick]);
        if next > budget {
            break;
        }
        selected[pick] = true;
        cover.push(pick);
        used = next;
    }

    RecollectionCut { cover, used }
}

/// Gaps longer than one quarter of the currently available life which no
/// selected memory overlaps.
///
/// This is an instrument, never an admission rule: recollection remains the
/// pure greedy projection above. A reported silent era points to missing
/// coarse support for the comb to improve. Overlapping selected memories are
/// unioned before gaps are measured.
pub fn silent_life_quarters(spans: &[(i128, i128, Id)], cover: &[usize]) -> Vec<(i128, i128)> {
    let (Some(earliest), Some(latest)) = (
        spans.iter().map(|span| span.0).min(),
        spans.iter().map(|span| span.1).max(),
    ) else {
        return Vec::new();
    };
    let life = latest.saturating_sub(earliest);
    if life <= 0 {
        return Vec::new();
    }

    let mut selected: Vec<(i128, i128)> = cover
        .iter()
        .map(|&i| {
            let span = spans
                .get(i)
                .unwrap_or_else(|| panic!("cover index {i} is outside {} spans", spans.len()));
            (span.0.max(earliest), span.1.min(latest))
        })
        .filter(|(start, end)| end > start)
        .collect();
    selected.sort_unstable();

    let threshold = life / 4;
    let mut silent = Vec::new();
    let mut cursor = earliest;
    for (start, end) in selected {
        if start > cursor && start.saturating_sub(cursor) > threshold {
            silent.push((cursor, start));
        }
        cursor = cursor.max(end);
        if cursor >= latest {
            break;
        }
    }
    if latest.saturating_sub(cursor) > threshold {
        silent.push((cursor, latest));
    }
    silent
}

/// Collapse memories which are interchangeable to the temporal sampler into
/// one structural position.
///
/// Recollection has one axis: chronological, non-lens memories. Exact equality
/// of `(start, end)` is therefore the strongest possible structural
/// equivalence. Every member is later assigned the class's conservative
/// maximum rendered charge, so substituting its prose cannot alter the ideal
/// slot or its contribution to a silent-stretch diagnostic. Content, intrinsic
/// id, and an individual member's rendered size deliberately do not split the
/// class.
///
/// The structural id is the least member id. It exists only as a stable final
/// tie-break for the sampler; the id of the recollection eventually
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

/// The first journal observation of each exact-span structural class.
///
/// A range says what period a memory recalls; `created_at` says when that
/// recollection became available. Historical replay must use the latter or a
/// summary written today about an old month appears before it existed. Legacy
/// memories without an observation fall back to their range end, and the count
/// is returned so the approximation remains visible.
fn recollection_class_observations<P: TriblePattern>(
    space: &P,
    raw_spans: &[(i128, i128, Id)],
    classes: &[Vec<usize>],
) -> (Vec<i128>, usize) {
    let mut first_by_id: HashMap<Id, i128> = HashMap::new();
    for (id, observed) in find!(
        (id: Id, observed: Inline<NsTAIInterval>),
        pattern!(space, [{ ?id @ metadata::created_at: ?observed }])
    ) {
        let observed = interval_key(observed);
        first_by_id
            .entry(id)
            .and_modify(|first| *first = (*first).min(observed))
            .or_insert(observed);
    }

    let mut missing = 0usize;
    let observations = classes
        .iter()
        .map(|members| {
            let mut observed = None;
            for &raw in members {
                if let Some(at) = first_by_id.get(&raw_spans[raw].2).copied() {
                    observed = Some(observed.map_or(at, |first: i128| first.min(at)));
                }
            }
            observed.unwrap_or_else(|| {
                missing += 1;
                members
                    .iter()
                    .map(|&raw| raw_spans[raw].1)
                    .min()
                    .unwrap_or(0)
            })
        })
        .collect();
    (observations, missing)
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

/// One step of a historical replay, using when memories actually joined the
/// journal rather than pretending a later-written summary always existed.
#[derive(Clone, Debug)]
pub struct ReplayRow {
    pub observed_now: i128,
    pub semantic_now: i128,
    pub chunks: usize,
    pub used: usize,
    pub silent_life_quarters: Vec<(i128, i128)>,
    pub kept: usize,
    pub prev_used: usize,
    pub first: Option<(i128, i128)>,
    pub changed_at: Option<(i128, i128)>,
    pub unobserved_classes: usize,
}

/// One replay sampling quantum: about 4.55 hours, historically the resident's
/// working-quarter cadence. This is measurement cadence only, never a boundary
/// in the recollection algorithm.
pub const REPLAY_QUANTUM_NS: i128 = (1i128 << 14) * 1_000_000_000;

/// Replay density-shaped recollection over the pile's observation history.
pub fn replay_cover<B: BlobStoreGet, P: TriblePattern>(
    space: &P,
    ws: &B,
    budget_chars: usize,
    chunk_overhead: usize,
    steps: usize,
    step_units: i128,
) -> Result<Vec<ReplayRow>> {
    let raw_spans = collect_chunk_spans(space);
    let (spans, classes) = recollection_classes(&raw_spans);
    let (observed_at, unobserved_classes) =
        recollection_class_observations(space, &raw_spans, &classes);
    let mut rows = Vec::new();
    let Some(latest_observation) = observed_at.iter().copied().max() else {
        return Ok(rows);
    };
    let mut raw_costs: Vec<Option<usize>> = vec![None; raw_spans.len()];
    let mut class_costs: Vec<Option<usize>> = vec![None; spans.len()];
    let mut costs = Vec::with_capacity(spans.len());
    for i in 0..spans.len() {
        costs.push(
            recollection_class_cost(
                ws,
                space,
                &raw_spans,
                &mut raw_costs,
                &classes,
                &mut class_costs,
                i,
            )?
            .saturating_add(chunk_overhead),
        );
    }
    let step_ns = step_units.max(1) * REPLAY_QUANTUM_NS;
    let mut previous: Vec<usize> = Vec::new();
    let mut prev_used = 0usize;
    for k in (0..=steps).rev() {
        let point = latest_observation - (k as i128) * step_ns;
        let mut map: Vec<usize> = Vec::new();
        let mut sub: Vec<(i128, i128, Id)> = Vec::new();
        let mut sub_costs = Vec::new();
        for (i, s) in spans.iter().enumerate() {
            if observed_at[i] <= point {
                map.push(i);
                sub.push(*s);
                sub_costs.push(costs[i]);
            }
        }
        let Some(semantic_now) = sub.iter().map(|s| s.1).max() else {
            continue;
        };
        let cut = select_recollection_cut(&sub, &sub_costs, &vec![true; sub.len()], budget_chars);
        let silent_life_quarters = silent_life_quarters(&sub, &cut.cover);
        let cover: Vec<usize> = cut.cover.iter().map(|&j| map[j]).collect();
        let mut kept = 0usize;
        let mut changed_at = None;
        for (n, (a, b)) in cover.iter().zip(previous.iter()).enumerate() {
            if a != b {
                changed_at = Some((spans[*a].0, spans[*a].1));
                break;
            }
            kept = kept.saturating_add(costs[*a]);
            if n + 1 == previous.len() && cover.len() > previous.len() {
                changed_at = Some((spans[cover[n + 1]].0, spans[cover[n + 1]].1));
            }
        }
        if changed_at.is_none() && previous.is_empty() {
            changed_at = cover.first().map(|&i| (spans[i].0, spans[i].1));
        }
        rows.push(ReplayRow {
            observed_now: point,
            semantic_now,
            chunks: cover.len(),
            used: cut.used,
            silent_life_quarters,
            kept,
            prev_used,
            first: cover.first().map(|&i| (spans[i].0, spans[i].1)),
            changed_at,
            unobserved_classes,
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
    // select one member of an exact-span class, but never changes the sampled
    // spans. This is the crucial boundary between situated recollection
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

    // The recollection. Cost is the exact-span class's conservative character
    // count plus consumer overhead, once per selected memory.
    let mut raw_costs: Vec<Option<usize>> = vec![None; raw_spans.len()];
    let mut class_costs: Vec<Option<usize>> = vec![None; n];
    let mut costs = Vec::with_capacity(n);
    for i in 0..n {
        costs.push(
            recollection_class_cost(
                reader,
                space,
                &raw_spans,
                &mut raw_costs,
                &classes,
                &mut class_costs,
                i,
            )?
            .saturating_add(chunk_overhead),
        );
    }
    let cut = select_recollection_cut(&spans, &costs, &class_eligible, budget_chars);
    let used = cut.used;
    let cover = cut.cover;

    // The selected SPACE order is the emitted order. Reordering by lived time
    // would move memories away from the ideal slots which chose them and hide
    // where the journal lacks appropriately dense support. Ranges may therefore
    // overlap, leave gaps, or wobble backwards in lived time.
    let mode = {
        let mut parts = vec![match about {
            Some(q) => format!("recollections about \"{q}\" within equal spans"),
            None => "density-shaped recollection".to_string(),
        }];
        if let Some(q) = filter_q {
            parts.push(format!("filtered to \"{q}\""));
        }
        if let Some(q) = remove_q {
            parts.push(format!("excluding \"{q}\""));
        }
        format!("greedy SPACE order; {}", parts.join("; "))
    };
    // The status header goes to STDERR, not into the returned cover buffer: the
    // time-ranges are the drill key the wake ritual ingests, and this line's
    // volatile counts (chunk/char totals) would perturb the otherwise
    // prefix-stable cover on every call. Keep it visible to a human on stderr,
    // out of the stored/ingested cover text.
    for &i in &cover {
        let (s, e, _) = spans[i];
        let id = raw_spans[representatives[i]].2;
        writeln!(out)?;
        // Ranges are the drill key (`memory <from>..<to>`); the opaque hex id is
        // boot-theatre noise in the wake, so it stays out of the cover line.
        writeln!(
            out,
            "{}",
            format_time_range(key_to_epoch(s), key_to_epoch(e)),
        )?;
        if let Some(handle) = chunk_summary_handle(space, id) {
            let summary: View<str> = reader.get(handle).context("read chunk summary")?;
            writeln!(out, "{}", summary.trim_end())?;
        } else if chunk_image_handle(space, id).is_some() {
            let range = format_time_range(key_to_epoch(s), key_to_epoch(e));
            writeln!(out, "[image memory @ {range}]")?;
        }
    }
    let fill = if budget_chars == 0 {
        0.0
    } else {
        100.0 * used as f64 / budget_chars as f64
    };
    eprintln!(
        "memory context — {} of {} eligible memories recalled, ~{} of {} characters ({fill:.1}% full; {mode})",
        cover.len(),
        class_eligible.iter().filter(|&&yes| yes).count(),
        used,
        budget_chars,
    );
    Ok(out)
}

#[cfg(test)]
mod recollection_tests {
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

    #[test]
    fn gradient_integrates_the_life_and_gets_finer_toward_now() {
        let life = 1023 * MOMENT_NS;
        let space = 10_000;
        let gradient = DensityGradient::new(life, space);
        let old = gradient.sample(0);
        let young = gradient.sample(space);

        assert!(old.time_ns.abs() < life as f64 * 1e-12);
        assert!((young.time_ns - life as f64).abs() < life as f64 * 1e-12);
        assert!(old.time_per_char_ns > young.time_per_char_ns);

        // Trapezoidal integration is enough to catch a density which does not
        // actually map the whole reader space onto the whole remembered life.
        let mut integral = 0.0;
        for cursor in 0..space {
            let a = gradient.sample(cursor).time_per_char_ns;
            let b = gradient.sample(cursor + 1).time_per_char_ns;
            integral += (a + b) / 2.0;
        }
        let relative_error = (integral - life as f64).abs() / life as f64;
        assert!(relative_error < 1e-6, "{relative_error}");
    }

    #[test]
    fn recollection_is_deliberately_lossy() {
        let id = ids(101);
        let life = 1000 * MOMENT_NS;
        let mut spans = vec![(0, life, id[0])];
        let mut costs = vec![10usize];
        for i in 0..100 {
            let start = i as i128 * 10 * MOMENT_NS;
            spans.push((start, start + 10 * MOMENT_NS, id[i + 1]));
            costs.push(10);
        }

        let cut = select_recollection_cut(&spans, &costs, &[true; 101], 50);
        assert_eq!(cut.used, 50);
        assert_eq!(cut.cover.len(), 5);
        assert!(
            cut.cover.len() < spans.len(),
            "the unselected memories remain losslessly journaled, not forced into active recall"
        );
    }

    #[test]
    fn greedy_projection_ignores_candidate_input_order() {
        let original = [
            (0, 100 * MOMENT_NS, A),
            (0, 50 * MOMENT_NS, B),
            (50 * MOMENT_NS, 100 * MOMENT_NS, C),
        ];
        let mut expected = None;
        for permutation in [
            [0usize, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let spans: Vec<_> = permutation.into_iter().map(|i| original[i]).collect();
            let cut = select_recollection_cut(&spans, &[5; 3], &[true; 3], 10);
            let ids: Vec<_> = cut.cover.iter().map(|&i| spans[i].2).collect();
            if let Some(expected) = &expected {
                assert_eq!(&ids, expected);
            } else {
                expected = Some(ids);
            }
        }
    }

    #[test]
    fn greedy_space_order_is_not_chronologically_repaired() {
        let spans = vec![
            (0, 80 * MOMENT_NS, A),
            (80 * MOMENT_NS, 100 * MOMENT_NS, B),
            (50 * MOMENT_NS, 60 * MOMENT_NS, C),
        ];

        let cut = select_recollection_cut(&spans, &[5; 3], &[true; 3], 15);
        let selected: Vec<_> = cut.cover.iter().map(|&i| spans[i].2).collect();

        assert_eq!(selected, vec![A, B, C]);
        assert!(
            spans[cut.cover[2]].0 < spans[cut.cover[1]].0,
            "the final fallback stays in its selected SPACE slot"
        );
    }

    #[test]
    fn candidate_length_defines_one_ideal_temporal_slot() {
        let id = ids(5);
        let life = 1000 * MOMENT_NS;
        let budget = 101;
        let cost = 10;
        let gradient = DensityGradient::new(life, budget);
        let ideal_end = gradient.sample(cost).time_ns.round() as i128;
        let shift = ideal_end / 4;
        let spans = vec![
            // Ineligible boundary observations establish LIFE without taking
            // part in the choice.
            (0, 0, id[0]),
            (life, life, id[1]),
            // Exact slot, same-width shifted slot, and same-centre narrow slot.
            (0, ideal_end, id[2]),
            (shift, ideal_end + shift, id[3]),
            (ideal_end / 4, ideal_end * 3 / 4, id[4]),
        ];
        let cut = select_recollection_cut(
            &spans,
            &[1, 1, cost, cost, cost],
            &[false, false, true, true, true],
            budget,
        );

        assert_eq!(cut.cover.first(), Some(&2));
    }

    #[test]
    fn sampled_grain_gets_finer_toward_the_present() {
        let id = ids(17);
        let life = 4096 * MOMENT_NS;
        let mut spans = vec![(0, life, id[0])];
        let mut costs = vec![1usize];

        // Abundant support at geometrically decreasing widths. Each scale has
        // an old and young representative, so the field rather than scarcity
        // determines the selected grain.
        for level in 0..8 {
            let width = (1i128 << (11 - level)) * MOMENT_NS;
            let old_start = (1i128 << level) * MOMENT_NS;
            let young_end = life - (1i128 << level) * MOMENT_NS;
            spans.push((old_start, old_start + width, id[1 + level * 2]));
            spans.push((young_end - width, young_end, id[2 + level * 2]));
            costs.extend([8, 8]);
        }

        let cut = select_recollection_cut(&spans, &costs, &[true; 17], 49);
        let selected: Vec<_> = cut.cover.iter().copied().filter(|&i| i != 0).collect();
        assert!(selected.len() >= 2, "{selected:?}");
        let oldest = selected
            .iter()
            .min_by_key(|&&i| spans[i].0 + (spans[i].1 - spans[i].0) / 2)
            .copied()
            .unwrap();
        let youngest = selected
            .iter()
            .max_by_key(|&&i| spans[i].0 + (spans[i].1 - spans[i].0) / 2)
            .copied()
            .unwrap();
        let old_width = spans[oldest].1 - spans[oldest].0;
        let young_width = spans[youngest].1 - spans[youngest].0;
        assert!(
            old_width > young_width,
            "old {oldest} width {old_width}, young {youngest} width {young_width}, selected {selected:?}"
        );
    }

    #[test]
    fn first_best_sample_that_does_not_fit_ends_the_walk() {
        let id = ids(1);
        let life = 100 * MOMENT_NS;
        let spans = vec![(0, life, id[0])];
        let cut = select_recollection_cut(&spans, &[11], &[true], 10);

        assert!(cut.cover.is_empty());
        assert_eq!(cut.used, 0);
    }

    #[test]
    fn silent_era_detection_is_observation_not_selection() {
        let id = ids(4);
        let spans = vec![
            (0, 100 * MOMENT_NS, id[0]),
            (0, 20 * MOMENT_NS, id[1]),
            (10 * MOMENT_NS, 25 * MOMENT_NS, id[2]),
            (60 * MOMENT_NS, 100 * MOMENT_NS, id[3]),
        ];
        assert_eq!(
            silent_life_quarters(&spans, &[1, 2, 3]),
            vec![(25 * MOMENT_NS, 60 * MOMENT_NS)]
        );
        assert_eq!(
            silent_life_quarters(&spans, &[]),
            vec![(0, 100 * MOMENT_NS)]
        );
        assert!(
            silent_life_quarters(&spans, &[0]).is_empty(),
            "a broad selected arc makes the instrument quiet; it is not forced into selection"
        );
    }
}
