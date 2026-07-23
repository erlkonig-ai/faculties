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
//! Everything below is the post-checkout half of what used to be
//! `build_context_cover` in `memory.rs`: the caller does the branch
//! resolution / pull / checkout, then hands us the already-checked-out `space`
//! and `&mut ws` plus the parsed [`CoverOpts`]; we return the cover TEXT.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, anyhow, bail};
use hifitime::Epoch;

use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::Workspace;
use triblespace::macros::{find, pattern};
use triblespace::prelude::blobencodings::{LongString, RawBytes};
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval};
use triblespace::prelude::*;
use triblespace_search::succinct::{SuccinctBM25Blob, SuccinctBM25Index};
use triblespace_search::tokens::hash_tokens;

#[cfg(feature = "local-embed")]
use crate::nomic;
#[cfg(feature = "local-embed")]
use crate::schemas::embeddings::{self, Embedding768};
use crate::schemas::memory::{ctx, search_index, KIND_CHUNK_ID, KIND_SEARCH_INDEX};

// ---------------------------------------------------------------------------
// on-demand chunk queries — moved here from memory.rs so the render is
// self-contained. memory.rs re-imports these via `use faculties::memory_cover::…`.
// ---------------------------------------------------------------------------

pub fn chunk_summary_handle(space: &TribleSet, id: Id) -> Option<Inline<Handle<LongString>>> {
    find!(h: Inline<Handle<LongString>>, pattern!(space, [{ id @ ctx::summary: ?h }])).next()
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
        (Some(s), Some(e)) => format_time_range(
            epoch_from_interval(s),
            epoch_end_from_interval(e),
        ),
        _ => "?".to_string(),
    }
}

/// A chunk's lens-theme handle, if it is a thematic lens (not part of the
/// chronological spine). Presence is what excludes it from the temporal cover.
pub fn chunk_lens_handle(space: &TribleSet, id: Id) -> Option<Inline<Handle<LongString>>> {
    find!(h: Inline<Handle<LongString>>, pattern!(space, [{ id @ ctx::lens: ?h }])).next()
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

/// Ids of chunks that have been superseded by a corrected chunk.
/// Monotonic correction: the `supersedes` fact is appended, never removed;
/// covers and trees exclude superseded chunks (read-side policy), while
/// direct id lookup still resolves them for history inspection.
pub fn superseded_ids(space: &TribleSet) -> HashSet<Id> {
    find!(old: Id, pattern!(space, [{ _ @ ctx::supersedes: ?old }])).collect()
}

/// The stored shared-space embedding handle for a chunk, if it has been embedded.
#[cfg(feature = "local-embed")]
pub fn chunk_embedding_handle(
    space: &TribleSet,
    id: Id,
) -> Option<Inline<Handle<Embedding768>>> {
    find!(
        h: Inline<Handle<Embedding768>>,
        pattern!(space, [{ id @ embeddings::attr::embedding: ?h }])
    )
    .next()
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

/// Latest (handle, indexed_at) search-index entity, if any.
pub fn latest_search_index(
    space: &TribleSet,
) -> Option<(Inline<Handle<SuccinctBM25Blob>>, Inline<NsTAIInterval>)> {
    find!(
        (h: Inline<Handle<SuccinctBM25Blob>>, at: Inline<NsTAIInterval>),
        pattern!(space, [{
            _?e @
            metadata::tag: &KIND_SEARCH_INDEX,
            search_index::index: ?h,
            search_index::indexed_at: ?at,
        }])
    )
    .max_by_key(|(_, at)| interval_key(*at))
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

/// Load the non-superseded chunks of the memory branch as `(start_key, end_key, id)`.
/// Chunks missing a start/end interval are skipped. Shared by `list` and `check`.
pub fn collect_chunk_spans(space: &TribleSet) -> Vec<(i128, i128, Id)> {
    let superseded = superseded_ids(space);
    let mut spans = Vec::new();
    for id in all_chunk_ids(space) {
        if superseded.contains(&id) {
            continue;
        }
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
pub fn context_chunk_cost(
    ws: &mut Workspace<Pile>,
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

/// Per-chunk relevance scores for `memory context --about`: SEMANTIC (nomic
/// cosine over the stored shared-space embeddings) when they exist, else LEXICAL
/// (BM25). Both are non-negative; the cover propagates subtree maxima over them,
/// so a node is worth descending into iff some memory beneath it is relevant.
pub fn about_relevance_scores(
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
    query: &str,
) -> Result<HashMap<Id, f32>> {
    #[cfg(feature = "local-embed")]
    {
        if let Some(scores) = semantic_about_scores(space, ws, query)? {
            return Ok(scores);
        }
    }
    // Lexical fallback (BM25) — used without `local-embed`, or before any
    // `memory embed` has populated the semantic space.
    let Some((handle, _)) = latest_search_index(space) else {
        bail!(
            "no relevance source for --about: build one with `memory embed` (semantic, preferred) \
             or `memory index` (lexical BM25)"
        );
    };
    let idx: SuccinctBM25Index = ws.get(handle).context("load search index")?;
    Ok(idx
        .query_multi(&hash_tokens(query))
        .into_iter()
        .filter_map(|(doc, score)| {
            let id: Id = doc.try_from_inline().ok()?;
            Some((id, score))
        })
        .collect())
}

/// Semantic relevance via nomic: embed the query, cosine it against every stored
/// chunk embedding. `None` if no chunk is embedded yet (caller falls back to
/// BM25). Negative cosines clamp to 0 so "unrelated" is uniform and subtree-max
/// stays meaningful (matching BM25's non-negative scores).
#[cfg(feature = "local-embed")]
pub fn semantic_about_scores(
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
    query: &str,
) -> Result<Option<HashMap<Id, f32>>> {
    let mut handles: Vec<(Id, Inline<Handle<Embedding768>>)> = Vec::new();
    for chunk in all_chunk_ids(space) {
        if let Some(h) = chunk_embedding_handle(space, chunk) {
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
        let v: View<[f32]> = ws.get(h).map_err(|e| anyhow!("read embedding: {e:?}"))?;
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
pub fn eligibility_scores(
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
    query: &str,
    universe: &[Id],
) -> Result<(HashMap<Id, f32>, Vec<Id>)> {
    #[cfg(feature = "local-embed")]
    {
        if let Some(res) = semantic_eligibility_scores(space, ws, query, universe)? {
            return Ok(res);
        }
    }
    // Pure lexical fallback (no embeddings on the pile yet, or built without
    // `local-embed`): BM25 normalized to a fraction of the top score. Every chunk
    // gets an explicit score — those absent from the postings scored a genuine 0
    // ("no match"), so nothing here is *unscorable*.
    let Some((handle, _)) = latest_search_index(space) else {
        bail!(
            "no relevance source for --filter/--remove: build one with `memory embed` \
             (semantic, preferred) or `memory index` (lexical BM25)"
        );
    };
    let idx: SuccinctBM25Index = ws.get(handle).context("load search index")?;
    let raw: HashMap<Id, f32> = idx
        .query_multi(&hash_tokens(query))
        .into_iter()
        .filter_map(|(doc, score)| Some((doc.try_from_inline().ok()?, score)))
        .collect();
    let max = raw.values().copied().fold(0.0_f32, f32::max).max(1e-6);
    let scores = universe
        .iter()
        .map(|&id| (id, raw.get(&id).copied().map(|s| s / max).unwrap_or(0.0)))
        .collect();
    Ok((scores, Vec::new()))
}

/// Semantic half of [`eligibility_scores`]: nomic cosine over stored chunk
/// embeddings. Unembedded chunks fall back to a positive lexical (BM25) score if
/// the index has one; otherwise they are reported UNSCORABLE so the caller can
/// keep them (fail-open) and warn — the honest, guardrail-safe behavior. Returns
/// `None` when no chunk is embedded at all (caller drops to pure lexical).
#[cfg(feature = "local-embed")]
pub fn semantic_eligibility_scores(
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
    query: &str,
    universe: &[Id],
) -> Result<Option<(HashMap<Id, f32>, Vec<Id>)>> {
    let mut embedded: Vec<(Id, Inline<Handle<Embedding768>>)> = Vec::new();
    let mut unembedded: Vec<Id> = Vec::new();
    for &chunk in universe {
        match chunk_embedding_handle(space, chunk) {
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
        let v: View<[f32]> = ws.get(h).map_err(|e| anyhow!("read embedding: {e:?}"))?;
        let cos: f32 = qv.iter().zip(v.as_ref().iter()).map(|(a, b)| a * b).sum();
        scores.insert(chunk, cos.max(0.0));
    }
    // Unembedded chunks: try a positive lexical score; else mark unscorable.
    let lexical: Option<(HashMap<Id, f32>, f32)> =
        if let Some((handle, _)) = latest_search_index(space) {
            let idx: SuccinctBM25Index = ws.get(handle).context("load search index")?;
            let raw: HashMap<Id, f32> = idx
                .query_multi(&hash_tokens(query))
                .into_iter()
                .filter_map(|(doc, score)| Some((doc.try_from_inline().ok()?, score)))
                .collect();
            let max = raw.values().copied().fold(0.0_f32, f32::max).max(1e-6);
            Some((raw, max))
        } else {
            None
        };
    let mut unscorable = Vec::new();
    for chunk in unembedded {
        match lexical
            .as_ref()
            .and_then(|(raw, max)| raw.get(&chunk).map(|s| s / max))
        {
            Some(s) if s > 0.0 => {
                scores.insert(chunk, s);
            }
            _ => unscorable.push(chunk),
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

/// Render the context-cover TEXT from an already-checked-out memory `space`
/// (and its `&mut ws`, needed to read summaries / embeddings / the search
/// index) — the antichain cover over ALL memories, coarse → fine, fit to
/// `opts.budget_chars` characters.
///
/// This is the post-checkout half of the old `build_context_cover`: the caller
/// resolves + pulls + checks out the memory branch, then hands the result here.
///
/// Completeness is invariant — a memory is never dropped to fit. If even the
/// coarsest cover (all roots) overflows the budget, this ERRORS with
/// instructions for raising a coarser apex rather than silently losing the past.
pub fn render_cover(
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
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
    let strict_contains = |a: usize, b: usize| -> bool {
        spans[a].0 <= spans[b].0
            && spans[a].1 >= spans[b].1
            && (spans[a].1 - spans[a].0) > (spans[b].1 - spans[b].0)
    };
    let width = |i: usize| spans[i].1 - spans[i].0;
    let mut parent: Vec<Option<usize>> = vec![None; n];
    for i in 0..n {
        let mut best: Option<usize> = None;
        for j in 0..n {
            if j != i && strict_contains(j, i) {
                best = Some(match best {
                    Some(b) if width(b) <= width(j) => b,
                    _ => j,
                });
            }
        }
        parent[i] = best;
    }
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut roots: Vec<usize> = Vec::new();
    for i in 0..n {
        match parent[i] {
            Some(p) => children[p].push(i),
            None => roots.push(i),
        }
    }

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
        Some(q) => Some(eligibility_scores(space, ws, q, &universe)?),
        None => None,
    };
    let remove_elig = match remove_q {
        Some(q) => Some(eligibility_scores(space, ws, q, &universe)?),
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
            match scores.get(&id) {
                Some(v) => {
                    if *v <= sim_threshold {
                        return false;
                    }
                }
                None => {} // unscorable → fail-open KEEP (warned above)
            }
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
            about_relevance_scores(space, ws, query)?
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
    roots.sort_by(|&a, &b| spans[a].0.cmp(&spans[b].0).then(spans[b].1.cmp(&spans[a].1)));
    let mut cost_cache: Vec<Option<usize>> = vec![None; n];
    let mut used = 0usize;
    for &i in &roots {
        used = used.saturating_add(context_chunk_cost(ws, space, &spans, &mut cost_cache, i)?);
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
    loop {
        let remaining = budget_chars.saturating_sub(used);
        if remaining == 0 {
            break;
        }
        let mut best: Option<usize> = None; // position in `cover`
        let mut best_extra = 0usize;
        let mut best_key: Option<(f32, i128, i128, usize, Id)> = None;
        for pos in 0..cover.len() {
            let i = cover[pos];
            if children[i].len() < 2 {
                continue;
            }
            let mut kids_cost = 0usize;
            for &k in &children[i] {
                kids_cost = kids_cost
                    .saturating_add(context_chunk_cost(ws, space, &spans, &mut cost_cache, k)?);
            }
            let pcost = context_chunk_cost(ws, space, &spans, &mut cost_cache, i)?;
            let extra = kids_cost.saturating_sub(pcost);
            if extra > remaining {
                continue;
            }
            // Priority: relevance (subtree-max, when --about) desc → recency
            // (latest end) desc → width desc → detail gained desc → id asc.
            // Without --about every relevance is 0, so recency leads exactly as
            // before; with it, the cover descends into the query-relevant
            // subtrees first and leaves the rest coarse.
            let key = (relevance[i], spans[i].1, width(i), extra, spans[i].2);
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
                best_extra = extra;
                best_key = Some(key);
            }
        }
        let Some(pos) = best else {
            break;
        };
        let kids = children[cover[pos]].clone();
        cover.splice(pos..=pos, kids);
        used = used.saturating_add(best_extra);
    }

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
                ws,
                space,
                &spans,
                &mut cost_cache,
                i,
            )?);
        }
    }

    // Emit coarse → fine: time order, indented by containment depth, each
    // chunk's span header followed by its summary content.
    cover.sort_by(|&a, &b| spans[a].0.cmp(&spans[b].0).then(spans[b].1.cmp(&spans[a].1)));
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
    writeln!(
        out,
        "memory context — {} chunk(s), ~{} of {} characters ({mode})",
        cover.len(),
        used,
        budget_chars,
    )?;
    for &i in &cover {
        let (s, e, id) = spans[i];
        let depth = (0..n).filter(|&j| j != i && strict_contains(j, i)).count();
        let indent = "  ".repeat(depth);
        writeln!(out)?;
        writeln!(
            out,
            "{indent}{}  ({:x})",
            format_time_range(key_to_epoch(s), key_to_epoch(e)),
            id
        )?;
        if let Some(handle) = chunk_summary_handle(space, id) {
            let summary: View<str> = ws.get(handle).context("read chunk summary")?;
            writeln!(out, "{}", summary.trim_end())?;
        } else if chunk_image_handle(space, id).is_some() {
            writeln!(out, "[image memory @ {}]", chunk_span_str(space, id))?;
        }
    }
    Ok(out)
}
