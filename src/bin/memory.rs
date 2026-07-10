
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{CommandFactory, Parser};
use ed25519_dalek::SigningKey;
use faculties::schemas::memory::{
    DEFAULT_ARCHIVE_BRANCH, DEFAULT_COGNITION_BRANCH, DEFAULT_MEMORY_BRANCH, KIND_ARCHIVE_MESSAGE,
    KIND_CHUNK_ID, KIND_EXEC_RESULT, KIND_RETRACTION, KIND_SEARCH_INDEX, archive_import_schema,
    archive_schema,
    comb, ctx, search_index,
};
use faculties::schemas::embeddings::{self, Embedding768};
use faculties::tokens::TokenEstimator;
use triblespace_search::bm25::BM25Builder;
use triblespace_search::succinct::{SuccinctBM25Blob, SuccinctBM25Index};
use triblespace_search::tokens::hash_tokens;
use hifitime::Epoch;
use rand_core::OsRng;
use triblespace::core::blob::Bytes;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::macros::{find, pattern};
use triblespace::prelude::blobencodings::{LongString, RawBytes};
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval};
use triblespace::prelude::*;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "memory",
    about = "Show compacted context chunks (drill down by narrowing the time range).\n\n\
             Subcommands:\n  \
             memory <from>..<to>              — show best summary covering a time range\n  \
             memory meta <from>..<to>         — show structural metadata for a time range\n  \
             memory context [<budget>] [--tokens N] [--chars N] [--about <query>] [--filter <query>] [--remove <query>] [--sim-threshold <f>] — antichain cover over ALL memories, coarse→fine to a budget (default tokens; bare <budget> or --tokens N budgets by TOKENS, --chars N budgets by CHARACTERS instead); --about biases detail toward memories relevant to <query> by MEANING (semantic, via `memory embed`; falls back to lexical `memory index`); --filter <query> keeps ONLY chunks whose positive similarity to <query> exceeds --sim-threshold (default 0.55); --remove <query> is the anti-filter — drops chunks whose similarity EXCEEDS the threshold (negate in the retrieval, NOT the query text; do not phrase a negation). Filter/remove decide eligibility, --about weights detail among the eligible, budget decides coarseness; they compose. NOTE: gating is chunk-level — a surviving COARSE ancestor's pre-written summary may still mention removed material. Unembedded+un-lexically-scorable chunks are kept (fail-open) with a stderr warning.\n  \
             memory density [<grain>]        — find where the hierarchy is BUSHY (many flat leaf-children under one span, no intermediate arc summary) vs balanced vs coarse; worst-first\n  \
             memory search <query>           — lexical (BM25) search over chunk summaries (build/refresh with `memory index`)\n  \
             memory similar <query>           — semantic search: nearest chunks by MEANING in the shared nomic space (build/refresh with `memory embed`) [needs --features local-embed]\n  \
             memory lens [<theme>]            — thematic lenses beside the spine: list them, or print a theme's narratives (create with `create --lens <theme>`)\n  \
             memory list [<grain>]            — show chunk time-ranges only: containment outline, or one zoom layer (no content)\n  \
             memory check <grain>             — report coverage gaps at a coarseness level (chunks of width <= grain)\n  \
             memory create [<range>] <summary> — create a memory chunk\n  \
             memory image <when> <image-path> — create a WORDLESS image memory at a time-coordinate (embed with `memory embed`; ranks in `memory similar` beside text) [needs --features local-embed to embed]\n  \
             memory respan <id> <from>..<to>  — correct a chunk's span (new chunk supersedes old; views exclude old)\n  \
             memory supersede <new> <old>     — mark an existing chunk as replacing another (old leaves all views)\n  \
             memory retract <id> [reason]      — retire a mistaken/duplicate chunk with NO replacement (invisible tombstone; target leaves all views, nothing new shows up as a memory)\n  \
             memory retractions               — audit surface: list retractions (what was retracted, and why)\n  \
             memory consolidate start <ts> | <ts> <summary> | stop — write chunks from an advancing edge ($PERSONA cursor)\n  \
             memory replay start <grain> [<from>] | [<count>] | stop — stream the memory at a zoom level ($PERSONA cursor)\n  \
             memory provenance <chunk-id>     — list cognition + archive events overlapping the chunk's time range\n\n\
             Time format: YYYY-MM-DDTHH:MM:SS..YYYY-MM-DDTHH:MM:SS (TAI)\n\
             Hex id prefixes also accepted as fallback."
)]
struct Cli {
    /// Path to the pile file to use.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Optional explicit branch id (hex) to read chunks from (defaults to cognition branch).
    #[arg(long)]
    branch_id: Option<String>,
    /// One or more time ranges / id prefixes to show, or `turn <turn-id>`, or `create [<from>..<to>] <summary>`.
    #[arg(value_name = "ID", trailing_var_arg = true, allow_hyphen_values = true)]
    ids: Vec<String>,
}

// ── on-demand chunk queries ───────────────────────────────────────────
// Chunks are queried directly from the TribleSet — no pre-materialization.

fn chunk_summary_handle(space: &TribleSet, id: Id) -> Option<Inline<Handle<LongString>>> {
    find!(h: Inline<Handle<LongString>>, pattern!(space, [{ id @ ctx::summary: ?h }])).next()
}

/// The raw image bytes handle of a WORDLESS image memory chunk, if it is one.
/// An image chunk has no `ctx::summary`; its content is the picture itself.
fn chunk_image_handle(space: &TribleSet, id: Id) -> Option<Inline<Handle<RawBytes>>> {
    find!(h: Inline<Handle<RawBytes>>, pattern!(space, [{ id @ ctx::image: ?h }])).next()
}

/// A chunk's `from..to` span as a string (or `?` if missing) — used to render
/// a wordless image memory as `[image memory @ <span>]` everywhere a summary
/// would otherwise print.
fn chunk_span_str(space: &TribleSet, id: Id) -> String {
    match (chunk_start_at(space, id), chunk_end_at(space, id)) {
        (Some(s), Some(e)) => format_time_range(
            epoch_from_interval(s),
            epoch_end_from_interval(e),
        ),
        _ => "?".to_string(),
    }
}

/// One-line render of a chunk for list/similar output: the summary's first
/// line, or a wordless-image marker, or empty.
fn chunk_oneline(ws: &mut Workspace<Pile>, space: &TribleSet, id: Id) -> String {
    if let Some(h) = chunk_summary_handle(space, id) {
        return ws
            .get::<View<str>, LongString>(h)
            .ok()
            .map(|v| v.as_ref().lines().next().unwrap_or("").to_string())
            .unwrap_or_default();
    }
    if chunk_image_handle(space, id).is_some() {
        return format!("[image memory @ {}]", chunk_span_str(space, id));
    }
    String::new()
}

/// A chunk's lens-theme handle, if it is a thematic lens (not part of the
/// chronological spine). Presence is what excludes it from the temporal cover.
fn chunk_lens_handle(space: &TribleSet, id: Id) -> Option<Inline<Handle<LongString>>> {
    find!(h: Inline<Handle<LongString>>, pattern!(space, [{ id @ ctx::lens: ?h }])).next()
}

fn chunk_start_at(space: &TribleSet, id: Id) -> Option<Inline<NsTAIInterval>> {
    find!(v: Inline<NsTAIInterval>, pattern!(space, [{ id @ ctx::start_at: ?v }])).next()
}

fn chunk_end_at(space: &TribleSet, id: Id) -> Option<Inline<NsTAIInterval>> {
    find!(v: Inline<NsTAIInterval>, pattern!(space, [{ id @ ctx::end_at: ?v }])).next()
}

/// Outgoing references of a chunk: ctx::reference facts (renamed from the
/// legacy `child` attribute — same id, so old tree edges read as references)
/// plus the ancient left/right binary-tree remnants.
fn chunk_references(space: &TribleSet, id: Id) -> Vec<Id> {
    let mut children: Vec<Id> = Vec::new();
    children.extend(find!(c: Id, pattern!(space, [{ id @ ctx::reference: ?c }])));
    children.extend(find!(c: Id, pattern!(space, [{ id @ ctx::left: ?c }])));
    children.extend(find!(c: Id, pattern!(space, [{ id @ ctx::right: ?c }])));
    // Sort referenced chunks by their start_at time.
    let superseded = superseded_ids(space);
    children.retain(|child_id| !superseded.contains(child_id));
    children.sort_by_key(|child_id| {
        chunk_start_at(space, *child_id)
            .map(interval_key)
            .unwrap_or(i128::MAX)
    });
    children.dedup();
    children
}

fn chunk_about_exec_result(space: &TribleSet, id: Id) -> Option<Id> {
    find!(v: Id, pattern!(space, [{ id @ ctx::about_exec_result: ?v }])).next()
}

fn chunk_about_archive_message(space: &TribleSet, id: Id) -> Option<Id> {
    find!(v: Id, pattern!(space, [{ id @ ctx::about_archive_message: ?v }])).next()
}

fn all_chunk_ids(space: &TribleSet) -> Vec<Id> {
    find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: &KIND_CHUNK_ID }])).collect()
}

/// Ids of chunks that have been superseded by a corrected chunk.
/// Monotonic correction: the `supersedes` fact is appended, never removed;
/// covers and trees exclude superseded chunks (read-side policy), while
/// direct id lookup still resolves them for history inspection.
fn superseded_ids(space: &TribleSet) -> std::collections::HashSet<Id> {
    find!(old: Id, pattern!(space, [{ _ @ ctx::supersedes: ?old }])).collect()
}

// ---------------------------------------------------------------------------
// time-range helpers
// ---------------------------------------------------------------------------

fn format_time_range(start: Epoch, end: Epoch) -> String {
    let (y1, m1, d1, h1, mi1, s1, _) = start.to_gregorian_tai();
    let (y2, m2, d2, h2, mi2, s2, _) = end.to_gregorian_tai();
    format!(
        "{y1:04}-{m1:02}-{d1:02}T{h1:02}:{mi1:02}:{s1:02}..{y2:04}-{m2:02}-{d2:02}T{h2:02}:{mi2:02}:{s2:02}"
    )
}

fn fmt_epoch(e: Epoch) -> String {
    let (y, m, d, h, mi, s, _) = e.to_gregorian_tai();
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}")
}

fn parse_tai_timestamp(s: &str) -> Result<Epoch> {
    // Parse "YYYY-MM-DDTHH:MM:SS"
    let parts: Vec<&str> = s.split('T').collect();
    if parts.len() != 2 {
        bail!("invalid timestamp: {s}");
    }
    let date_parts: Vec<&str> = parts[0].split('-').collect();
    let time_parts: Vec<&str> = parts[1].split(':').collect();
    if date_parts.len() != 3 || time_parts.len() != 3 {
        bail!("invalid timestamp: {s}");
    }
    let y: i32 = date_parts[0].parse().context("year")?;
    let m: u8 = date_parts[1].parse().context("month")?;
    let d: u8 = date_parts[2].parse().context("day")?;
    let hh: u8 = time_parts[0].parse().context("hour")?;
    let mm: u8 = time_parts[1].parse().context("minute")?;
    let ss: u8 = time_parts[2].parse().context("second")?;
    Ok(Epoch::from_gregorian_tai(y, m, d, hh, mm, ss, 0))
}

fn parse_time_range(s: &str) -> Result<(Epoch, Epoch)> {
    let Some((from_str, to_str)) = s.split_once("..") else {
        bail!("invalid time range (expected `from..to`): {s}");
    };
    let from = parse_tai_timestamp(from_str).context("parsing range start")?;
    let to = parse_tai_timestamp(to_str).context("parsing range end")?;
    Ok((from, to))
}

fn epoch_from_interval(interval: Inline<NsTAIInterval>) -> Epoch {
    let (lower, _): (Epoch, Epoch) = interval.try_from_inline().unwrap();
    lower
}

fn epoch_end_from_interval(interval: Inline<NsTAIInterval>) -> Epoch {
    let (_, upper): (Epoch, Epoch) = interval.try_from_inline().unwrap();
    upper
}

/// Find the best chunk covering a query time range — the most *specific*
/// summary, by overlap, at a scale matching the query.
///
/// Each overlapping chunk is scored `2*overlap - width = overlap - (width -
/// overlap)`: it rewards covering the query and penalises span wasted outside
/// it. A snug cover (width ≈ overlap ≈ query) wins; a vastly wider container
/// (e.g. a whole-life root) scores deeply negative and only wins when the
/// query itself is whole-life-scale; a sub-query moment scores below a cover
/// that matches the query's width. This replaces a "narrowest strict
/// container, else max raw overlap" rule that let an oversized root shadow
/// every finer cover (raw overlap also favours wide chunks).
fn find_chunk_by_time_range(
    space: &TribleSet,
    query_start: Epoch,
    query_end: Epoch,
) -> Option<Id> {
    let query_start_ns = query_start.to_tai_duration().total_nanoseconds();
    let query_end_ns = query_end.to_tai_duration().total_nanoseconds();

    let mut best: Option<(Id, i128)> = None; // (id, specificity score)

    let superseded = superseded_ids(space);
    for chunk_id in all_chunk_ids(space) {
        if superseded.contains(&chunk_id) {
            continue;
        }
        let start_val = chunk_start_at(space, chunk_id);
        let end_val = chunk_end_at(space, chunk_id);
        let (Some(start_v), Some(end_v)) = (start_val, end_val) else { continue };

        let chunk_start = epoch_from_interval(start_v).to_tai_duration().total_nanoseconds();
        let chunk_end = epoch_end_from_interval(end_v).to_tai_duration().total_nanoseconds();

        if chunk_start > query_end_ns || chunk_end < query_start_ns {
            continue;
        }

        let overlap_start = chunk_start.max(query_start_ns);
        let overlap_end = chunk_end.min(query_end_ns);
        let overlap = overlap_end.saturating_sub(overlap_start);
        let width = chunk_end - chunk_start;
        let score = 2 * overlap - width;
        match best {
            Some((_, prev_score)) if prev_score >= score => {}
            _ => best = Some((chunk_id, score)),
        }
    }

    best.map(|(id, _)| id)
}

// ── BM25 search over chunk summaries ─────────────────────────────────
// Index entities are rebuild-and-replace: `memory index` mints a fresh
// (KIND_SEARCH_INDEX, blob handle, indexed_at) entity; `memory search`
// reads the latest by timestamp. Superseded chunks are excluded at
// build time, and again at query time in case the index is stale.

fn now_interval() -> Result<Inline<NsTAIInterval>> {
    let now = Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0));
    (now, now)
        .try_to_inline()
        .map_err(|e| anyhow!("encode timestamp: {e:?}"))
}

/// Latest (handle, indexed_at) search-index entity, if any.
fn latest_search_index(
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

fn cmd_index(pile_path: &Path) -> Result<()> {
    with_repo(pile_path, |repo| {
        let branch_id = repo
            .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
            .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?;
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull memory branch: {e:?}"))?;
        let space = ws.checkout(..).context("checkout memory branch")?;

        let superseded = superseded_ids(&space);
        let mut builder: BM25Builder = BM25Builder::new();
        let mut indexed = 0usize;
        for chunk in find!(id: Id, pattern!(&space, [{ ?id @ metadata::tag: &KIND_CHUNK_ID }])) {
            if superseded.contains(&chunk) {
                continue;
            }
            let Some(handle) = chunk_summary_handle(&space, chunk) else {
                continue;
            };
            let summary: View<str> = ws.get(handle).context("read chunk summary")?;
            builder.insert(&chunk, hash_tokens(summary.as_ref()));
            indexed += 1;
        }
        let idx = builder.build();
        let handle = ws.put(&idx);
        let at = now_interval()?;
        let mut change = TribleSet::new();
        change += entity! { _ @
            metadata::tag: &KIND_SEARCH_INDEX,
            search_index::index: handle,
            search_index::indexed_at: at,
        };
        ws.commit(change, "memory index");
        repo.push(&mut ws)
            .map_err(|e| anyhow!("push failed: {e:?}"))?;
        println!(
            "indexed {indexed} chunk summaries ({} superseded excluded)",
            superseded.len()
        );
        Ok(())
    })
}

fn cmd_search(pile_path: &Path, args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!("usage: memory search <query words...>");
    }
    let query = args.join(" ");
    with_repo(pile_path, |repo| {
        let branch_id = repo
            .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
            .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?;
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull memory branch: {e:?}"))?;
        let space = ws.checkout(..).context("checkout memory branch")?;

        let Some((handle, _at)) = latest_search_index(&space) else {
            bail!("no search index on this pile yet — run `memory index` first");
        };
        let idx: SuccinctBM25Index = ws.get(handle).context("load search index")?;

        let superseded = superseded_ids(&space);
        // One scored postings walk over the whole index — never score
        // per-doc (that re-walks postings per match and goes quadratic
        // on common terms). The index only contains chunk docs by
        // construction; superseded is re-filtered here in case chunks
        // were superseded after the index was built.
        let mut rows: Vec<(Id, f32)> = idx
            .query_multi(&hash_tokens(&query))
            .into_iter()
            .filter_map(|(doc, score)| {
                let id: Id = doc.try_from_inline().ok()?;
                (!superseded.contains(&id)).then_some((id, score))
            })
            .collect();
        rows.sort_unstable_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Staleness hint: the index is rebuild-and-replace, so chunks
        // written since the last `memory index` aren't searchable yet.
        let live = find!(id: Id, pattern!(&space, [{ ?id @ metadata::tag: &KIND_CHUNK_ID }]))
            .filter(|id| !superseded.contains(id))
            .count();
        if live > idx.doc_count() {
            eprintln!(
                "note: {} chunk(s) newer than the index — run `memory index` to refresh",
                live - idx.doc_count()
            );
        }

        if rows.is_empty() {
            println!("no matches.");
            return Ok(());
        }
        for (chunk, score) in rows.into_iter().take(10) {
            let summary = chunk_oneline(&mut ws, &space, chunk);
            println!("{score:6.2}  {chunk:x}  {summary}");
        }
        Ok(())
    })
}

// ── semantic embedding seam (nomic + shared HNSW, behind `local-embed`) ─────
// Mirrors the BM25 index/search pair, but in the shared multimodal space:
// `memory embed` is the build step (embed each chunk summary once with
// nomic-embed-text, store the 768-d vector as exhaust under the chunk's id),
// `memory similar` is the query (embed the query, nearest over stored vectors).
// Where BM25 matches tokens, this matches MEANING — a paraphrase with no shared
// words still recalls the right memory. The vectors live in the SAME
// `embeddings::attr::embedding` space as files/photos, so this is the memory end
// of one cross-faculty semantic search: a text query here is directly
// comparable to an image candidate there (nomic text+vision are co-embedded).

#[cfg(feature = "local-embed")]
const NOMIC_TEXT_MODEL: &str = "nomic-ai/nomic-embed-text-v1.5";

/// Durable embedder piles — weights load from piles only (write them with
/// mary's `embed_persist`); env vars override so the faculty isn't pinned to
/// one machine's paths. tokenizer.json stays a small HF-cache side-file.
#[cfg(feature = "local-embed")]
const NOMIC_TEXT_PILE: &str = "/Users/jp/Desktop/chatbot/liora/models/nomic_text.pile";
#[cfg(feature = "local-embed")]
const NOMIC_VISION_PILE: &str = "/Users/jp/Desktop/chatbot/liora/models/nomic_vision.pile";

#[cfg(feature = "local-embed")]
fn load_nomic_text_embedder() -> Result<mary::embed::NomicTextEmbedder<mary::nn::backend::B>> {
    let pile = std::env::var("NOMIC_TEXT_PILE").unwrap_or_else(|_| NOMIC_TEXT_PILE.to_string());
    let tok = mary::embed::hf_cache_resolve(NOMIC_TEXT_MODEL, "tokenizer.json")
        .ok_or_else(|| anyhow!("tokenizer.json not in HF cache for {NOMIC_TEXT_MODEL}"))?;
    mary::embed::load_nomic_text_from_pile(
        std::path::Path::new(&pile),
        &tok,
        mary::embed::default_device(),
    )
    .map_err(|e| anyhow!("load nomic text embedder from pile {pile}: {e:?}"))
}

#[cfg(feature = "local-embed")]
fn load_nomic_vision_embedder() -> Result<mary::embed::NomicVisionEmbedder<mary::nn::backend::B>> {
    let pile = std::env::var("NOMIC_VISION_PILE").unwrap_or_else(|_| NOMIC_VISION_PILE.to_string());
    mary::embed::load_nomic_vision_from_pile(
        std::path::Path::new(&pile),
        mary::embed::default_device(),
    )
    .map_err(|e| anyhow!("load nomic vision embedder from pile {pile}: {e:?}"))
}

/// nomic-embed-vision-v1.5 — the image encoder co-embedded into the SAME 768-d
/// space as nomic-text, so an image memory's vector is directly comparable to a
/// text query's. Used by `memory embed` for wordless image chunks.
#[cfg(feature = "local-embed")]
const NOMIC_VISION_MODEL: &str = "nomic-ai/nomic-embed-vision-v1.5";

/// L2-normalize so dot-product == cosine downstream (the shared `nearest` core
/// and `put_embedding` both assume unit vectors; nomic's raw output is not
/// guaranteed normalized).
#[cfg(feature = "local-embed")]
fn l2_normalize(mut v: Vec<f32>) -> Vec<f32> {
    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if n > 0.0 {
        for x in &mut v {
            *x /= n;
        }
    }
    v
}

/// The stored shared-space embedding handle for a chunk, if it has been embedded.
#[cfg(feature = "local-embed")]
fn chunk_embedding_handle(
    space: &TribleSet,
    id: Id,
) -> Option<Inline<Handle<Embedding768>>> {
    find!(
        h: Inline<Handle<Embedding768>>,
        pattern!(space, [{ id @ embeddings::attr::embedding: ?h }])
    )
    .next()
}

/// `memory embed` — embed every live chunk summary that lacks a vector and
/// store it as exhaust. Idempotent (re-running only embeds chunks added since),
/// like the rebuild-and-replace BM25 index but per-chunk content-addressed.
#[cfg(feature = "local-embed")]
fn cmd_embed(pile_path: &Path) -> Result<()> {
    use mary::embed::LocalEmbedder;

    // What a chunk embeds FROM: its summary prose (nomic-text) or its raw image
    // bytes (nomic-vision). Both land on the same `embeddings::attr::embedding`
    // because nomic text+vision share one 768-d space.
    enum Src {
        Text(Inline<Handle<LongString>>),
        Image(Inline<Handle<RawBytes>>),
    }

    with_repo(pile_path, |repo| {
        let branch_id = repo
            .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
            .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?;
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull memory branch: {e:?}"))?;
        let space = ws.checkout(..).context("checkout memory branch")?;

        let superseded = superseded_ids(&space);
        let mut todo: Vec<(Id, Src)> = Vec::new();
        for chunk in all_chunk_ids(&space) {
            if superseded.contains(&chunk) {
                continue;
            }
            if chunk_embedding_handle(&space, chunk).is_some() {
                continue;
            }
            // An image chunk is wordless — route it to vision; otherwise embed
            // its summary with text. (A chunk has one or the other.)
            if let Some(h) = chunk_image_handle(&space, chunk) {
                todo.push((chunk, Src::Image(h)));
            } else if let Some(h) = chunk_summary_handle(&space, chunk) {
                todo.push((chunk, Src::Text(h)));
            }
        }
        if todo.is_empty() {
            println!("all live chunks already embedded.");
            return Ok(());
        }
        let total = todo.len();

        // Load each model once, lazily — a pile with only text memories never
        // pays for the vision weights, and vice versa.
        let mut text_emb: Option<mary::embed::NomicTextEmbedder<_>> = None;
        let mut vision_emb: Option<mary::embed::NomicVisionEmbedder<_>> = None;
        let mut n_text = 0usize;
        let mut n_image = 0usize;
        let mut change = TribleSet::new();
        for (i, (chunk, src)) in todo.into_iter().enumerate() {
            let v = match src {
                Src::Text(sh) => {
                    let summary: View<str> = ws.get(sh).context("read chunk summary")?;
                    let emb = match &text_emb {
                        Some(e) => e,
                        None => {
                            eprintln!("memory: loading nomic-embed-text (once)…");
                            text_emb = Some(load_nomic_text_embedder()?);
                            text_emb.as_ref().unwrap()
                        }
                    };
                    n_text += 1;
                    l2_normalize(
                        emb.embed_document(summary.as_ref())
                            .map_err(|e| anyhow!("embed chunk {chunk:x}: {e:?}"))?,
                    )
                }
                Src::Image(ih) => {
                    let bytes: Bytes = ws.get(ih).context("read image bytes")?;
                    let emb = match &vision_emb {
                        Some(e) => e,
                        None => {
                            eprintln!("memory: loading nomic-embed-vision (once)…");
                            vision_emb = Some(load_nomic_vision_embedder()?);
                            vision_emb.as_ref().unwrap()
                        }
                    };
                    n_image += 1;
                    l2_normalize(
                        emb.embed_image(bytes.as_ref())
                            .map_err(|e| anyhow!("embed image chunk {chunk:x}: {e:?}"))?,
                    )
                }
            };
            let handle = ws.put::<Embedding768, _>(v);
            change += entity! { triblespace::core::id::ExclusiveId::force_ref(&chunk) @ embeddings::attr::embedding: handle };
            if (i + 1) % 25 == 0 || i + 1 == total {
                eprintln!("  embedded {}/{total}", i + 1);
            }
        }
        let delta = change.clone();
        ws.commit(change, "memory embed");
        repo.push(&mut ws).map_err(|e| anyhow!("push failed: {e:?}"))?;
        // Refresh the persisted HNSW segment so `memory similar` queries the
        // graph instead of rebuilding it. Best-effort: the segment is soft
        // state (recomputable from the commit chain), so a failure here warns
        // but doesn't fail the embed.
        if let Err(e) = embeddings::update_index(repo.storage_mut(), branch_id, &delta) {
            eprintln!("memory: warning: HNSW index refresh failed (similar will fall back): {e:#}");
        }
        println!(
            "embedded {n_text} text + {n_image} image chunk(s) into the shared nomic space."
        );
        Ok(())
    })
}

#[cfg(not(feature = "local-embed"))]
fn cmd_embed(_pile_path: &Path) -> Result<()> {
    bail!("`memory embed` needs the local embedder — rebuild with `--features local-embed`");
}

/// `memory similar <query>` — nearest chunks to a free-text query in the shared
/// nomic space. Matches by meaning, not tokens (the semantic complement to
/// `memory search`). Reads stored vectors only; `memory embed` builds them.
#[cfg(feature = "local-embed")]
fn cmd_similar(pile_path: &Path, args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!("usage: memory similar <query words...>");
    }
    let query = args.join(" ");
    eprintln!("memory: loading nomic-embed-text (once)…");
    let emb = load_nomic_text_embedder()?;
    let qv = l2_normalize(
        emb.embed_query(&query)
            .map_err(|e| anyhow!("embed query: {e:?}"))?,
    );

    with_repo(pile_path, |repo| {
        let branch_id = repo
            .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
            .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?;
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull memory branch: {e:?}"))?;
        let space = ws.checkout(..).context("checkout memory branch")?;

        let superseded = superseded_ids(&space);

        // FAST PATH: attach the persisted HNSW segment(s) from the branch head
        // and query them — no read-all-blobs, no rebuild. The checkout above
        // stays only to map result handles → chunk ids (tribles, no blob
        // reads) and to render, not to gather every embedding.
        let ranked: Vec<(f32, Id)> = match embeddings::nearest_via_index(
            repo.storage_mut(),
            branch_id,
            &qv,
            0.0,
        )? {
            Some(rows) => {
                // Build handle→id over LIVE chunks (a trible query per chunk,
                // no blob fetch), then translate the ranked candidate handles.
                let mut by_handle: std::collections::HashMap<[u8; 32], Id> =
                    std::collections::HashMap::new();
                for chunk in all_chunk_ids(&space) {
                    if superseded.contains(&chunk) {
                        continue;
                    }
                    if let Some(h) = chunk_embedding_handle(&space, chunk) {
                        by_handle.insert(h.raw, chunk);
                    }
                }
                rows.into_iter()
                    .filter_map(|(cos, raw)| by_handle.get(&raw).map(|id| (cos, *id)))
                    .collect()
            }
            // FALLBACK: no HNSW segment yet (e.g. embedded before this landed).
            // Gather all pairs and rebuild once, as before.
            None => {
                let mut pairs: Vec<(Id, Vec<f32>)> = Vec::new();
                let mut live = 0usize;
                for chunk in all_chunk_ids(&space) {
                    if superseded.contains(&chunk) {
                        continue;
                    }
                    live += 1;
                    if let Some(h) = chunk_embedding_handle(&space, chunk) {
                        let v: View<[f32]> =
                            ws.get(h).map_err(|e| anyhow!("read embedding: {e:?}"))?;
                        pairs.push((chunk, v.as_ref().to_vec()));
                    }
                }
                if pairs.is_empty() {
                    bail!("no chunk embeddings on this pile yet — run `memory embed` first");
                }
                if pairs.len() < live {
                    eprintln!(
                        "note: {} live chunk(s) not yet embedded — run `memory embed` to refresh",
                        live - pairs.len()
                    );
                }
                embeddings::nearest(&pairs, &qv, 0.0).map_err(|e| anyhow!("nearest: {e:?}"))?
            }
        };
        if ranked.is_empty() {
            println!("no matches.");
            return Ok(());
        }
        for (cos, chunk) in ranked.into_iter().take(10) {
            let span = match (chunk_start_at(&space, chunk), chunk_end_at(&space, chunk)) {
                (Some(s), Some(e)) => {
                    let (s, _): (Epoch, Epoch) = s.try_from_inline().unwrap();
                    let (e, _): (Epoch, Epoch) = e.try_from_inline().unwrap();
                    format_time_range(s, e)
                }
                _ => "?".to_string(),
            };
            let summary = chunk_oneline(&mut ws, &space, chunk);
            // Image memories: export the blob to a path the caller can Read,
            // so a Claude-Code reader (no auto-injected blobs) can actually see it.
            let img_line = match chunk_image_handle(&space, chunk) {
                Some(h) => match materialize_image(&mut ws, chunk, h) {
                    Ok(path) => format!("\n        → {} (Read this path to view)", path.display()),
                    Err(e) => format!("\n        (image export failed: {e})"),
                },
                None => String::new(),
            };
            println!("{cos:6.3}  {chunk:x}  {span}\n        {summary}{img_line}");
        }
        Ok(())
    })
}

#[cfg(not(feature = "local-embed"))]
fn cmd_similar(_pile_path: &Path, _args: &[String]) -> Result<()> {
    bail!("`memory similar` needs the local embedder — rebuild with `--features local-embed`");
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.ids.is_empty() {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    }

    // Dispatch to subcommand handlers.
    if cli.ids.first().is_some_and(|value| value == "create") {
        return cmd_create(&cli.pile, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "image") {
        return cmd_image(&cli.pile, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "meta") {
        return cmd_meta(&cli.pile, cli.branch_id.as_deref(), &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "respan") {
        return cmd_respan(&cli.pile, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "supersede") {
        return cmd_supersede(&cli.pile, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "retract") {
        return cmd_retract(&cli.pile, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "retractions") {
        return cmd_retractions(&cli.pile, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "provenance") {
        return cmd_provenance(&cli.pile, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "consolidate") {
        return cmd_consolidate(&cli.pile, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "replay") {
        return cmd_replay(&cli.pile, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "index") {
        return cmd_index(&cli.pile);
    }
    if cli.ids.first().is_some_and(|value| value == "search") {
        return cmd_search(&cli.pile, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "embed") {
        return cmd_embed(&cli.pile);
    }
    if cli.ids.first().is_some_and(|value| value == "similar") {
        return cmd_similar(&cli.pile, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "context") {
        return cmd_context(&cli.pile, cli.branch_id.as_deref(), &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "lens") {
        return cmd_lens(&cli.pile, cli.branch_id.as_deref(), &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "list") {
        return cmd_list(&cli.pile, cli.branch_id.as_deref(), &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "check") {
        return cmd_check(&cli.pile, cli.branch_id.as_deref(), &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "density") {
        return cmd_density(&cli.pile, cli.branch_id.as_deref(), &cli.ids[1..]);
    }

    let explicit_branch_id = parse_optional_hex_id(cli.branch_id.as_deref())?;
    with_repo(&cli.pile, |repo| {
        let branch_id = match explicit_branch_id {
            Some(id) => id,
            None => repo
                .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
                .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?,
        };

        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull branch {branch_id:x}: {e:?}"))?;
        let space = ws.checkout(..).context("checkout branch")?;

        if cli.ids.first().is_some_and(|value| value == "turn") {
            if cli.ids.len() != 2 {
                bail!("usage: memory turn <turn-id>");
            }
            return print_turn_facets(&mut ws, &space, &cli.ids[1]);
        }

        let mut first = true;
        for raw in &cli.ids {
            let chunk_id = if raw.contains("..") {
                let (start, end) = parse_time_range(raw)?;
                find_chunk_by_time_range(&space, start, end)
                    .ok_or_else(|| anyhow!("no memory covers range {raw}"))?
            } else {
                match resolve_chunk_id(&space, raw) {
                    Ok(id) => id,
                    Err(err) => {
                        return Err(invalid_memory_id_error(raw, err));
                    }
                }
            };
            if !first {
                println!();
            }
            first = false;
            print_chunk(&mut ws, &space, chunk_id)?;
        }

        Ok(())
    })
}

// ---------------------------------------------------------------------------
// create subcommand
// ---------------------------------------------------------------------------

fn cmd_create(pile_path: &Path, args: &[String]) -> Result<()> {
    // A help flag must never be minted as memory content — print usage and stop
    // before any parsing, so `memory create --help` explains itself instead of
    // storing the literal "--help" as a chunk.
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "usage: memory create [--lens <theme>] [<from>..<to>] <summary...>\n\
             \n\
             Create a memory chunk and store it in the pile.\n\
             An optional time range as the first argument grounds the memory in\n\
             that period; without it, defaults to now. --lens <theme> files the\n\
             chunk as a thematic memory kept out of the chronological spine."
        );
        return Ok(());
    }
    if args.is_empty() {
        bail!(
            "usage: memory create [<from>..<to>] <summary...>\n\
             \n\
             Create a memory chunk and store it in the pile.\n\
             An optional time range as the first argument grounds the\n\
             memory in that period. Without it, defaults to now.\n\
             References in prose: (memory:<from>..<to>) is a soft temporal\n\
             address, resolved by range query at read time, no fact minted.\n\
             [why it matters](memory:<hex>) is a hard reference to an exact\n\
             chunk, extracted into a queryable ctx::reference fact. Neither\n\
             affects the span or the hierarchy: containment relates chunks,\n\
             and the explicit range argument always wins."
        );
    }

    // Pull an optional `--lens <theme>` out first: a lens chunk is a thematic
    // memory (e.g. "us", "becoming-self"), kept OUT of the chronological spine.
    let mut lens: Option<String> = None;
    let mut filtered: Vec<String> = Vec::new();
    {
        let mut i = 0;
        while i < args.len() {
            if args[i] == "--lens" && i + 1 < args.len() {
                lens = Some(args[i + 1].clone());
                i += 2;
            } else {
                filtered.push(args[i].clone());
                i += 1;
            }
        }
    }
    let args = &filtered[..];
    if args.is_empty() {
        bail!("summary text is required: memory create [--lens <theme>] [<from>..<to>] <summary...>");
    }

    // If the first argument looks like a time range, parse it.
    let mut explicit_range: Option<(Epoch, Epoch)> = None;
    let summary_start_idx;
    if args[0].contains("..") {
        if let Ok(range) = parse_time_range(&args[0]) {
            explicit_range = Some(range);
            summary_start_idx = 1;
        } else {
            summary_start_idx = 0;
        }
    } else {
        summary_start_idx = 0;
    }

    let summary_text: String = args[summary_start_idx..].join(" ");
    if summary_text.is_empty() {
        bail!("summary text is required: memory create [<from>..<to>] <summary...>");
    }

    with_repo(pile_path, |repo| {
        let range = match explicit_range {
            Some(range) => range,
            None => {
                let now = Epoch::now()
                    .unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0));
                (now, now)
            }
        };
        let chunk_id = create_chunk(repo, &summary_text, range, lens.as_deref())?;
        println!(
            "range: {}",
            format_time_range(range.0, range.1)
        );
        println!("id: {chunk_id:x}");
        Ok(())
    })
}

/// The chunk-creation core, shared by `create` and `consolidate`.
///
/// Hard references `[context](memory:<hex>)` in the summary become
/// ctx::reference facts (resolved against the catalog so a dangling hard ref
/// fails at write time). Soft references `(memory:<from>..<to>)` stay prose.
/// Neither affects the span: temporal containment is the only hierarchy, and
/// the given range is stored as typed. Chunks carry no persona or author —
/// the memory belongs to the one being; only cursors are session-scoped.
fn create_chunk(
    repo: &mut Repository<Pile>,
    summary_text: &str,
    range: (Epoch, Epoch),
    lens: Option<&str>,
) -> Result<Id> {
    let branch_id = repo
        .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
        .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?;

    let hard_refs = scan_hard_references(summary_text);
    let mut reference_ids: Vec<Id> = Vec::new();
    if !hard_refs.is_empty() {
        let catalog = {
            let mut ws = repo
                .pull(branch_id)
                .map_err(|e| anyhow!("pull memory branch: {e:?}"))?;
            ws.checkout(..).context("checkout memory branch")?
        };
        for hex in &hard_refs {
            let target = resolve_chunk_id(&catalog, hex)
                .map_err(|e| anyhow!("hard reference (memory:{hex}): {e}"))?;
            reference_ids.push(target);
        }
    }

    let start_at: Inline<NsTAIInterval> = (range.0, range.0).try_to_inline().unwrap();
    let end_at: Inline<NsTAIInterval> = (range.1, range.1).try_to_inline().unwrap();

    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull memory branch for write: {e:?}"))?;
    let summary_handle = ws.put(summary_text.to_owned());
    let lens_handle = lens.map(|theme| ws.put(theme.to_owned()));
    let chunk_id = ufoid();
    let now = Epoch::now()
        .unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0));
    let created_at: Inline<NsTAIInterval> = (now, now).try_to_inline().unwrap();

    let mut change = TribleSet::new();
    change += entity! { &chunk_id @
        metadata::tag: KIND_CHUNK_ID,
        ctx::summary: summary_handle,
        metadata::created_at: created_at,
        ctx::start_at: start_at,
        ctx::end_at: end_at,
        ctx::reference*: reference_ids.iter(),
    };
    if let Some(h) = lens_handle {
        change += entity! { &chunk_id @ ctx::lens: h };
    }

    ws.commit(change, "memory create");
    repo.push(&mut ws)
        .map_err(|e| anyhow!("push failed: {e:?}"))?;
    Ok(*chunk_id)
}

// ---------------------------------------------------------------------------
// image subcommand — a WORDLESS memory at a time-coordinate
// ---------------------------------------------------------------------------

/// `memory image <when> <image-path>` — create an image memory chunk. It is
/// JUST a chunk (tag KIND_CHUNK_ID) whose content is a picture instead of prose:
/// no `ctx::summary`, the image bytes live on `ctx::image`. Same time-coordinate
/// as any chunk — `<when>` is a single `YYYY-MM-DDTHH:MM:SS` point (start==end)
/// or a `from..to` range. Embed it into the shared 768-d nomic space with
/// `memory embed` (via nomic-VISION, co-embedded with nomic-text), and it ranks
/// in `memory similar` by MEANING beside text memories. Reference it from prose
/// like any chunk: `[caption](memory:<hex>)`.
fn cmd_image(pile_path: &Path, args: &[String]) -> Result<()> {
    if args.len() != 2 {
        bail!(
            "usage: memory image <when> <image-path>\n\
             \n\
             Create a WORDLESS image memory chunk and store it in the pile.\n\
             <when> is a single TAI timestamp (YYYY-MM-DDTHH:MM:SS — a point\n\
             where start==end) or a `from..to` range. The image bytes are stored\n\
             as a blob; embed it into the shared nomic space with `memory embed`\n\
             (nomic-VISION-768), and it ranks in `memory similar` by meaning\n\
             beside text memories. Reference it from prose with [caption](memory:<hex>)."
        );
    }
    let when = &args[0];
    let image_path = Path::new(&args[1]);
    let range = if when.contains("..") {
        parse_time_range(when)?
    } else {
        let p = parse_tai_timestamp(when)?;
        (p, p)
    };
    let bytes = std::fs::read(image_path)
        .with_context(|| format!("read image {}", image_path.display()))?;
    if bytes.is_empty() {
        bail!("image file is empty: {}", image_path.display());
    }

    with_repo(pile_path, |repo| {
        let chunk_id = create_image_chunk(repo, &bytes, range)?;
        println!("range: {}", format_time_range(range.0, range.1));
        println!("id: {chunk_id:x}");
        println!(
            "({} image bytes stored; run `memory embed` to place it in the shared nomic space)",
            bytes.len()
        );
        Ok(())
    })
}

/// Store image bytes as a blob and create a wordless image chunk at `range`.
/// Mirrors `create_chunk`, but the content is the picture (`ctx::image`) rather
/// than a summary — temporal containment (the only hierarchy) still relates it
/// to text chunks by time, and `[caption](memory:<hex>)` references still point
/// at it like any chunk.
fn create_image_chunk(
    repo: &mut Repository<Pile>,
    bytes: &[u8],
    range: (Epoch, Epoch),
) -> Result<Id> {
    let branch_id = repo
        .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
        .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?;

    let start_at: Inline<NsTAIInterval> = (range.0, range.0).try_to_inline().unwrap();
    let end_at: Inline<NsTAIInterval> = (range.1, range.1).try_to_inline().unwrap();

    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull memory branch for write: {e:?}"))?;
    let image_handle = ws.put::<RawBytes, _>(bytes.to_vec());
    let chunk_id = ufoid();
    let now = Epoch::now()
        .unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0));
    let created_at: Inline<NsTAIInterval> = (now, now).try_to_inline().unwrap();

    let mut change = TribleSet::new();
    change += entity! { &chunk_id @
        metadata::tag: KIND_CHUNK_ID,
        ctx::image: image_handle,
        metadata::created_at: created_at,
        ctx::start_at: start_at,
        ctx::end_at: end_at,
    };

    ws.commit(change, "memory image");
    repo.push(&mut ws)
        .map_err(|e| anyhow!("push failed: {e:?}"))?;
    Ok(*chunk_id)
}

// ---------------------------------------------------------------------------
// consolidate + replay — the comb verbs
// ---------------------------------------------------------------------------

const COMB_STATE_BRANCH: &str = "comb-state";
const CONSOLIDATE_STREAM: &str = "consolidate-edge";
const MEMORY_REPLAY_STREAM: &str = "memory-replay";

fn comb_persona() -> Result<String> {
    std::env::var("PERSONA").map_err(|_| {
        anyhow!(
            "no persona: set $PERSONA.\n\
             Cursors are session bookkeeping — no zooid is defaulted as \
             \"the\" rememberer; the memories themselves belong to the one \
             being and are never persona-scoped."
        )
    })
}

fn comb_catalog(repo: &mut Repository<Pile>) -> Result<(Id, TribleSet)> {
    let branch_id = repo
        .ensure_branch(COMB_STATE_BRANCH, None)
        .map_err(|e| anyhow!("ensure comb-state branch: {e:?}"))?;
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull comb-state branch: {e:?}"))?;
    let catalog = ws.checkout(..).context("checkout comb-state branch")?.into_facts();
    Ok((branch_id, catalog))
}

fn comb_advance(
    repo: &mut Repository<Pile>,
    branch_id: Id,
    stream: &str,
    persona: &str,
    position: Option<Epoch>,
    grain: Option<&str>,
) -> Result<()> {
    let now = Epoch::now()
        .unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0));
    let change = comb::advance_change(stream, persona, position, grain, now);
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull comb-state for write: {e:?}"))?;
    ws.commit(change, "comb cursor");
    repo.push(&mut ws)
        .map_err(|e| anyhow!("push failed: {e:?}"))?;
    Ok(())
}

fn key_to_epoch(key: i128) -> Epoch {
    Epoch::from_tai_duration(hifitime::Duration::from_total_nanoseconds(key))
}

/// `memory consolidate start <ts> | stop | <ts> <summary...>`
///
/// The consolidation edge is where the next chunk opens. `<ts> <summary>`
/// writes a chunk spanning [edge, ts] and advances the edge to ts — the
/// boundary is chosen in hindsight (you pass the timestamp where the shift
/// happened, typically copied from replay output; the shift-signaling
/// message becomes the next chunk's opening).
fn cmd_consolidate(pile_path: &Path, args: &[String]) -> Result<()> {
    let persona = comb_persona()?;
    if args.is_empty() {
        bail!(
            "usage: memory consolidate start <YYYY-MM-DDTHH:MM:SS>\n\
             \x20      memory consolidate stop\n\
             \x20      memory consolidate <YYYY-MM-DDTHH:MM:SS> <summary...>"
        );
    }
    with_repo(pile_path, |repo| {
        let (comb_branch, catalog) = comb_catalog(repo)?;
        match args[0].as_str() {
            "start" => {
                let Some(raw) = args.get(1) else {
                    bail!("usage: memory consolidate start <YYYY-MM-DDTHH:MM:SS>");
                };
                let edge = parse_tai_timestamp(raw)?;
                comb_advance(repo, comb_branch, CONSOLIDATE_STREAM, &persona, Some(edge), None)?;
                println!("consolidation edge set to {raw} (persona {persona})");
                Ok(())
            }
            "stop" => {
                comb_advance(repo, comb_branch, CONSOLIDATE_STREAM, &persona, None, None)?;
                println!("consolidation stopped (persona {persona})");
                Ok(())
            }
            _ => {
                let until = parse_tai_timestamp(&args[0])?;
                let summary = args[1..].join(" ");
                if summary.is_empty() {
                    bail!("summary required: memory consolidate <ts> <summary...>");
                }
                let Some((Some(edge_key), _)) =
                    comb::latest(&catalog, CONSOLIDATE_STREAM, &persona)
                else {
                    bail!(
                        "no open consolidation edge for persona {persona}: \
                         use `memory consolidate start <ts>`"
                    );
                };
                let edge = key_to_epoch(edge_key);
                if until.to_tai_duration().total_nanoseconds() <= edge_key {
                    bail!(
                        "consolidate target {} is not after the open edge {}",
                        args[0],
                        fmt_epoch(edge)
                    );
                }
                let chunk_id = create_chunk(repo, &summary, (edge, until), None)?;
                comb_advance(
                    repo,
                    comb_branch,
                    CONSOLIDATE_STREAM,
                    &persona,
                    Some(until),
                    None,
                )?;
                println!("range: {}", format_time_range(edge, until));
                println!("id: {chunk_id:x}");
                println!("edge → {}", args[0]);
                Ok(())
            }
        }
    })
}

/// Parse a grain like "90m", "2h", "1d", "4w" into nanoseconds.
fn parse_grain(s: &str) -> Result<i128> {
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let n: i128 = num.parse().with_context(|| format!("invalid grain: {s}"))?;
    let ns_per = match unit {
        "m" => 60_i128 * 1_000_000_000,
        "h" => 3_600_i128 * 1_000_000_000,
        "d" => 86_400_i128 * 1_000_000_000,
        "w" => 7 * 86_400_i128 * 1_000_000_000,
        _ => bail!("grain unit must be m/h/d/w: {s}"),
    };
    Ok(n * ns_per)
}

/// `memory replay start <grain> [<from>] | stop | [<count>]`
///
/// Streams the memory itself, chronologically, at a zoom level: maximal
/// non-superseded chunks whose span-width fits the grain. This is how upper
/// layers get written — replay the layer below, consolidate up. Reads ALL
/// chunks regardless of which session wrote them: one being, one memory.
fn cmd_replay(pile_path: &Path, args: &[String]) -> Result<()> {
    let persona = comb_persona()?;
    with_repo(pile_path, |repo| {
        let (comb_branch, comb_cat) = comb_catalog(repo)?;
        match args.first().map(String::as_str) {
            Some("start") => {
                let Some(grain_raw) = args.get(1) else {
                    bail!("usage: memory replay start <grain e.g. 2h/1d/4w> [<from-ts>]");
                };
                parse_grain(grain_raw)?;
                let from = match args.get(2) {
                    Some(raw) => parse_tai_timestamp(raw)?,
                    None => Epoch::from_gregorian_tai(1970, 1, 1, 0, 0, 0, 0),
                };
                let position = from - hifitime::Duration::from_total_nanoseconds(1);
                comb_advance(
                    repo,
                    comb_branch,
                    MEMORY_REPLAY_STREAM,
                    &persona,
                    Some(position),
                    Some(grain_raw),
                )?;
                println!("memory replay started at grain {grain_raw} (persona {persona})");
                Ok(())
            }
            Some("stop") => {
                comb_advance(repo, comb_branch, MEMORY_REPLAY_STREAM, &persona, None, None)?;
                println!("memory replay stopped (persona {persona})");
                Ok(())
            }
            other => {
                let count: usize = match other {
                    None => 5,
                    Some(raw) => raw
                        .parse()
                        .with_context(|| format!("expected a batch count, got `{raw}`"))?,
                };
                let Some((Some(position_key), Some(grain_raw))) =
                    comb::latest(&comb_cat, MEMORY_REPLAY_STREAM, &persona)
                else {
                    bail!(
                        "no active memory replay for persona {persona}: \
                         use `memory replay start <grain> [<from>]`"
                    );
                };
                let grain_ns = parse_grain(&grain_raw)?;

                let memory_branch = repo
                    .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
                    .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?;
                let mut ws = repo
                    .pull(memory_branch)
                    .map_err(|e| anyhow!("pull memory branch: {e:?}"))?;
                let space = ws.checkout(..).context("checkout memory branch")?;

                // Chunks at this zoom: width fits the grain, not superseded,
                // and maximal among grain-fitting chunks (not contained in a
                // wider one that also fits — that one IS this zoom's voice).
                let superseded = superseded_ids(&space);
                let mut fitting: Vec<(i128, i128, Id)> = Vec::new();
                for chunk_id in all_chunk_ids(&space) {
                    if superseded.contains(&chunk_id) {
                        continue;
                    }
                    let (Some(s), Some(e)) =
                        (chunk_start_at(&space, chunk_id), chunk_end_at(&space, chunk_id))
                    else {
                        continue;
                    };
                    let (sk, ek) = (interval_key(s), interval_key(e));
                    if ek - sk <= grain_ns {
                        fitting.push((sk, ek, chunk_id));
                    }
                }
                let maximal: Vec<(i128, i128, Id)> = fitting
                    .iter()
                    .filter(|(sk, ek, id)| {
                        !fitting.iter().any(|(osk, oek, oid)| {
                            oid != id && osk <= sk && oek >= ek && (oek - osk) > (ek - sk)
                        })
                    })
                    .copied()
                    .collect();

                let mut batch: Vec<(i128, i128, Id)> = maximal
                    .into_iter()
                    .filter(|(sk, _, _)| *sk > position_key)
                    .collect();
                batch.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
                let total = batch.len();
                if total == 0 {
                    println!("memory replay complete at grain {grain_raw}: nothing after the cursor.");
                    return Ok(());
                }
                let take = count.min(total);
                let mut last_start = position_key;
                for (sk, ek, chunk_id) in batch.iter().take(take) {
                    let summary = match chunk_summary_handle(&space, *chunk_id) {
                        Some(handle) => {
                            let view: View<str> =
                                ws.get(handle).context("read chunk summary")?;
                            view.trim_end().to_string()
                        }
                        None => String::new(),
                    };
                    println!(
                        "── {} ({:x})",
                        format_time_range(key_to_epoch(*sk), key_to_epoch(*ek)),
                        chunk_id
                    );
                    println!("{summary}");
                    println!();
                    last_start = *sk;
                }
                comb_advance(
                    repo,
                    comb_branch,
                    MEMORY_REPLAY_STREAM,
                    &persona,
                    Some(key_to_epoch(last_start)),
                    Some(&grain_raw),
                )?;
                println!(
                    "— batch: {take} chunk(s) at grain {grain_raw}; {} remaining",
                    total - take
                );
                Ok(())
            }
        }
    })
}

// ---------------------------------------------------------------------------
// supersede subcommand
// ---------------------------------------------------------------------------

/// Assert that an existing chunk replaces another. The superseded chunk
/// leaves all views (covers, trees) but stays resolvable by id.
fn cmd_supersede(pile_path: &Path, args: &[String]) -> Result<()> {
    if args.len() != 2 {
        bail!("usage: memory supersede <new-id> <old-id>");
    }
    with_repo(pile_path, |repo| {
        let branch_id = repo
            .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
            .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?;
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull memory branch: {e:?}"))?;
        let space = ws.checkout(..).context("checkout memory branch")?;

        let new = resolve_chunk_id(&space, &args[0])
            .map_err(|e| anyhow!("new chunk {}: {e}", args[0]))?;
        let old = resolve_chunk_id(&space, &args[1])
            .map_err(|e| anyhow!("old chunk {}: {e}", args[1]))?;
        if new == old {
            bail!("a chunk cannot supersede itself");
        }
        let new_entity = new
            .acquire()
            .unwrap_or_else(|| triblespace::core::id::ExclusiveId::force(new));
        let mut change = TribleSet::new();
        change += entity! { &new_entity @ ctx::supersedes: old };
        ws.commit(change, "memory supersede");
        repo.push(&mut ws)
            .map_err(|e| anyhow!("push failed: {e:?}"))?;
        println!("{new:x} supersedes {old:x}");
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// retract subcommand
// ---------------------------------------------------------------------------

/// Retire a chunk with NO replacement. Mints a *retraction* tombstone: a fresh
/// entity tagged `KIND_RETRACTION` (never `KIND_CHUNK_ID`, so it never
/// enumerates as a chunk) carrying the `supersedes` edge, plus the reason as
/// its `ctx::summary` when one is given. The target leaves every view; the
/// retraction stays invisible to covers/trees/recall yet queryable as a class
/// ("what have I walked back, and why"). Use this for mistaken/duplicate
/// ingests, where `supersede` would otherwise force a bogus replacement chunk
/// that then shows up as a memory of its own. Nothing is destroyed: the retired
/// chunk's own facts survive for direct-id / provenance lookup.
fn cmd_retract(pile_path: &Path, args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!("usage: memory retract <id> [reason...]");
    }
    let reason = args[1..].join(" ");
    with_repo(pile_path, |repo| {
        let branch_id = repo
            .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
            .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?;
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull memory branch: {e:?}"))?;
        let space = ws.checkout(..).context("checkout memory branch")?;

        let old = resolve_chunk_id(&space, &args[0])
            .map_err(|e| anyhow!("chunk {}: {e}", args[0]))?;

        let tombstone = ufoid();
        let mut change = TribleSet::new();
        // Tagged KIND_RETRACTION (not KIND_CHUNK_ID) so it never enumerates as a
        // chunk, yet retractions stay queryable as a class. The reason, if given,
        // rides along as the tombstone's summary — recoverable, never in a view.
        if reason.is_empty() {
            change += entity! { &tombstone @
                metadata::tag: KIND_RETRACTION,
                ctx::supersedes: old,
            };
        } else {
            let reason_handle = ws.put(reason.clone());
            change += entity! { &tombstone @
                metadata::tag: KIND_RETRACTION,
                ctx::supersedes: old,
                ctx::summary: reason_handle,
            };
        }

        ws.commit(change, "memory retract");
        repo.push(&mut ws)
            .map_err(|e| anyhow!("push failed: {e:?}"))?;

        if reason.is_empty() {
            println!("retracted {old:x} (retraction {:x})", tombstone.id);
        } else {
            println!(
                "retracted {old:x} — {reason} (retraction {:x})",
                tombstone.id
            );
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// retractions subcommand
// ---------------------------------------------------------------------------

/// Audit surface for `retract`: list every `KIND_RETRACTION` tombstone, the
/// chunk(s) it retracts, and the recorded reason. Retracted chunks are gone from
/// covers/trees/recall but never lost — what was walked back, and why, is always
/// answerable here.
fn cmd_retractions(pile_path: &Path, _args: &[String]) -> Result<()> {
    with_repo(pile_path, |repo| {
        let branch_id = repo
            .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
            .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?;
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull memory branch: {e:?}"))?;
        let space = ws.checkout(..).context("checkout memory branch")?;

        let retractions: Vec<Id> =
            find!(r: Id, pattern!(&space, [{ ?r @ metadata::tag: &KIND_RETRACTION }])).collect();
        if retractions.is_empty() {
            println!("no retractions.");
            return Ok(());
        }
        for r in retractions {
            let targets: Vec<Id> =
                find!(old: Id, pattern!(&space, [{ r @ ctx::supersedes: ?old }])).collect();
            let reason = match chunk_summary_handle(&space, r) {
                Some(handle) => {
                    let s: View<str> = ws.get(handle).context("read retraction reason")?;
                    s.as_ref().to_string()
                }
                None => "(no reason recorded)".to_string(),
            };
            println!("retraction {r:x} — {reason}");
            for t in &targets {
                println!("    -> retracted {t:x}");
            }
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// respan subcommand
// ---------------------------------------------------------------------------

/// Correct a chunk's time span. Appends a new chunk with the same summary
/// (content-addressed handle reused) and the corrected explicit range, plus a
/// `supersedes` fact pointing at the old chunk. Covers and trees exclude
/// superseded chunks; direct id lookup still shows them (history inspection).
/// Child edges are NOT copied: a span correction usually exists precisely
/// because link-inferred children dragged the span wrong — re-link explicitly
/// if the new chunk should keep them.
fn cmd_respan(pile_path: &Path, args: &[String]) -> Result<()> {
    if args.len() != 2 || !args[1].contains("..") {
        bail!(
            "usage: memory respan <id> <from>..<to>\n\
             \n\
             Creates a corrected chunk (same summary, new span) that\n\
             supersedes the old one. Views exclude superseded chunks."
        );
    }
    let (range_start, range_end) = parse_time_range(&args[1])?;

    with_repo(pile_path, |repo| {
        let branch_id = repo
            .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
            .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?;
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull memory branch: {e:?}"))?;
        let space = ws.checkout(..).context("checkout memory branch")?;

        let old = resolve_chunk_id(&space, &args[0])
            .map_err(|e| anyhow!("chunk {}: {e}", args[0]))?;
        let summary_handle = chunk_summary_handle(&space, old)
            .ok_or_else(|| anyhow!("chunk {old:x} has no summary"))?;

        let start_at: Inline<NsTAIInterval> =
            (range_start, range_start).try_to_inline().unwrap();
        let end_at: Inline<NsTAIInterval> = (range_end, range_end).try_to_inline().unwrap();
        let now = Epoch::now()
            .unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0));
        let created_at: Inline<NsTAIInterval> = (now, now).try_to_inline().unwrap();

        let new_chunk = ufoid();
        let mut change = TribleSet::new();
        change += entity! { &new_chunk @
            metadata::tag: KIND_CHUNK_ID,
            ctx::summary: summary_handle,
            metadata::created_at: created_at,
            ctx::start_at: start_at,
            ctx::end_at: end_at,
            ctx::supersedes: old,
        };

        ws.commit(change, "memory respan");
        repo.push(&mut ws)
            .map_err(|e| anyhow!("push failed: {e:?}"))?;

        println!(
            "range: {}",
            format_time_range(range_start, range_end)
        );
        println!("id: {:x} (supersedes {old:x})", new_chunk.id);
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// meta subcommand
// ---------------------------------------------------------------------------

/// Humanize a nanosecond duration into a coarse `d/h/m/s` string.
fn humanize_ns(ns: i128) -> String {
    let secs = ns / 1_000_000_000;
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3600;
    let mins = (secs % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else if mins > 0 {
        format!("{mins}m")
    } else {
        format!("{secs}s")
    }
}

/// Load the non-superseded chunks of the memory branch as `(start_key, end_key, id)`.
/// Chunks missing a start/end interval are skipped. Shared by `list` and `check`.
fn collect_chunk_spans(space: &TribleSet) -> Vec<(i128, i128, Id)> {
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

/// `memory lens [<theme>]` — the thematic weave that runs beside the spine.
/// With no theme: list every lens memory (theme · span · first line). With a
/// theme substring: print the full text of the matching lens narratives. Lens
/// chunks are deliberately outside the temporal cover, so they can overlap each
/// other and the spine freely.
fn cmd_lens(pile_path: &Path, branch_id_raw: Option<&str>, args: &[String]) -> Result<()> {
    let explicit_branch_id = parse_optional_hex_id(branch_id_raw)?;
    let filter = args.first().map(|s| s.to_lowercase());
    with_repo(pile_path, |repo| {
        let branch_id = match explicit_branch_id {
            Some(id) => id,
            None => repo
                .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
                .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?,
        };
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull branch {branch_id:x}: {e:?}"))?;
        let space = ws.checkout(..).context("checkout branch")?;

        let superseded = superseded_ids(&space);
        let mut lenses: Vec<(String, i128, i128, Id)> = Vec::new();
        for id in all_chunk_ids(&space) {
            if superseded.contains(&id) {
                continue;
            }
            let Some(lh) = chunk_lens_handle(&space, id) else {
                continue;
            };
            let theme: String = ws
                .get::<View<str>, LongString>(lh)
                .context("read lens theme")?
                .as_ref()
                .to_string();
            let (Some(s), Some(e)) = (chunk_start_at(&space, id), chunk_end_at(&space, id)) else {
                continue;
            };
            lenses.push((theme, interval_key(s), interval_key(e), id));
        }
        if let Some(t) = &filter {
            lenses.retain(|(theme, _, _, _)| theme.to_lowercase().contains(t.as_str()));
        }
        lenses.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

        if lenses.is_empty() {
            println!(
                "no lens memories{} — create one with `memory create --lens <theme> <from>..<to> <summary>`",
                filter.map(|t| format!(" matching \"{t}\"")).unwrap_or_default()
            );
            return Ok(());
        }

        if filter.is_some() {
            // Full narratives for the matched theme(s).
            for (theme, s, e, id) in &lenses {
                println!(
                    "\n## [{theme}] {}  ({id:x})",
                    format_time_range(key_to_epoch(*s), key_to_epoch(*e))
                );
                if let Some(h) = chunk_summary_handle(&space, *id) {
                    let summary: View<str> = ws.get(h).context("read lens summary")?;
                    println!("{}", summary.trim_end());
                }
            }
        } else {
            // One line per lens.
            println!("{} lens memor(ies):", lenses.len());
            for (theme, s, e, id) in &lenses {
                let first = chunk_summary_handle(&space, *id)
                    .and_then(|h| ws.get::<View<str>, LongString>(h).ok())
                    .map(|v| v.as_ref().lines().next().unwrap_or("").to_string())
                    .unwrap_or_default();
                println!(
                    "  [{theme}] {}  ({id:x})  {first}",
                    format_time_range(key_to_epoch(*s), key_to_epoch(*e))
                );
            }
        }
        Ok(())
    })
}

/// `memory list [<grain>]` — show the SHAPE of the memory as time-ranges only,
/// never content (coverage is by time range, not by reference). With a grain,
/// lists the maximal non-superseded chunks whose width fits that zoom — the
/// same layer `replay <grain>` would stream. Without a grain, prints every
/// non-superseded chunk as a containment outline: indentation expresses how
/// wider ranges cover narrower ones.
fn cmd_list(pile_path: &Path, branch_id_raw: Option<&str>, args: &[String]) -> Result<()> {
    let explicit_branch_id = parse_optional_hex_id(branch_id_raw)?;
    let grain: Option<(String, i128)> = match args.first() {
        Some(raw) => Some((raw.clone(), parse_grain(raw)?)),
        None => None,
    };
    with_repo(pile_path, |repo| {
        let branch_id = match explicit_branch_id {
            Some(id) => id,
            None => repo
                .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
                .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?,
        };
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull branch {branch_id:x}: {e:?}"))?;
        let space = ws.checkout(..).context("checkout branch")?;

        let mut chunks = collect_chunk_spans(&space);
        if chunks.is_empty() {
            println!("no memory chunks on branch {branch_id:x}");
            return Ok(());
        }

        match grain {
            Some((raw, grain_ns)) => {
                // The layer at this zoom: width <= grain, maximal among fitting
                // (not contained in a wider chunk that also fits) — matches `replay`.
                let fitting: Vec<(i128, i128, Id)> =
                    chunks.iter().copied().filter(|(s, e, _)| e - s <= grain_ns).collect();
                let mut layer: Vec<(i128, i128, Id)> = fitting
                    .iter()
                    .copied()
                    .filter(|(s, e, id)| {
                        !fitting.iter().any(|(os, oe, oid)| {
                            oid != id && os <= s && oe >= e && (oe - os) > (e - s)
                        })
                    })
                    .collect();
                layer.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
                println!(
                    "layer at grain {raw}: {} chunk(s) of {} total",
                    layer.len(),
                    chunks.len()
                );
                for (s, e, id) in &layer {
                    println!(
                        "  {}  [{}]  ({:x})",
                        format_time_range(key_to_epoch(*s), key_to_epoch(*e)),
                        humanize_ns(e - s),
                        id
                    );
                }
            }
            None => {
                // Containment outline: containers before contained; indent by
                // how many strictly-wider chunks contain this one.
                chunks.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
                println!(
                    "{} chunk(s) on branch {branch_id:x} (indent = containment by time range)",
                    chunks.len()
                );
                for (s, e, id) in &chunks {
                    let depth = chunks
                        .iter()
                        .filter(|(os, oe, oid)| {
                            oid != id && os <= s && oe >= e && (oe - os) > (e - s)
                        })
                        .count();
                    let indent = "  ".repeat(depth + 1);
                    println!(
                        "{indent}{}  ({:x})",
                        format_time_range(key_to_epoch(*s), key_to_epoch(*e)),
                        id
                    );
                }
            }
        }
        Ok(())
    })
}

/// `memory check <grain>` — coverage audit at a coarseness level. Coverage is
/// by TIME RANGE, not by reference: a span is covered at grain G if some
/// non-superseded chunk of width <= G overlaps it. Reports the spans of the
/// overall extent left uncovered at that zoom (e.g. `check 1d` finds holes in
/// Token-cost of a chunk (its budget weight), loaded lazily and cached by span
/// index. Cost is measured through the configured [`TokenEstimator`], so the
/// budget and the per-chunk weights are in the same token units.
/// Budget weight charged for a wordless image memory in the context cover —
/// it renders as a one-line `[image memory @ <span>]` marker, so a small fixed
/// token cost (vs a text summary's measured length).
const IMAGE_CHUNK_TOKEN_COST: usize = 16;

fn context_chunk_cost(
    ws: &mut Workspace<Pile>,
    space: &TribleSet,
    estimator: &TokenEstimator,
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
            estimator.estimate(&summary)
        }
        // A wordless image memory renders as a small `[image memory @ <span>]`
        // marker in the cover — a fixed handful of tokens, not zero.
        None if chunk_image_handle(space, spans[i].2).is_some() => IMAGE_CHUNK_TOKEN_COST,
        None => 0,
    };
    cache[i] = Some(c);
    Ok(c)
}

/// `memory context [<budget-tokens>]` — the antichain cover over ALL of my
/// memories, coarse → fine, fit to a token budget. This is the grounding cover a
/// fresh context reads first to wake into its own past: every memory is
/// represented (completeness is invariant), with detail concentrated toward the
/// recent end and the deep past held as coarse summary.
///
/// Unlike the playground — which must degrade silently because the cover
/// *bootstraps* the model and there is no model yet to repair the hierarchy — the
/// faculty is called by an already-running agent. So when even the coarsest cover
/// overflows the budget, it ERRORS with instructions for raising a coarser apex
/// rather than dropping memories: the caller is right there to fix it.
/// Per-chunk relevance scores for `memory context --about`: SEMANTIC (nomic
/// cosine over the stored shared-space embeddings) when they exist, else LEXICAL
/// (BM25). Both are non-negative; the cover propagates subtree maxima over them,
/// so a node is worth descending into iff some memory beneath it is relevant.
/// Semantic is strictly better for a briefing-cover — it biases toward memories
/// that MEAN the query, not ones that share its words — which is exactly what a
/// subagent's `--about <goal>` briefing wants.
fn about_relevance_scores(
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
    query: &str,
) -> Result<std::collections::HashMap<Id, f32>> {
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
fn semantic_about_scores(
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
    query: &str,
) -> Result<Option<std::collections::HashMap<Id, f32>>> {
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
    let emb = load_nomic_text_embedder()?;
    let qv = l2_normalize(
        emb.embed_query(query)
            .map_err(|e| anyhow!("embed query: {e:?}"))?,
    );
    let mut scores = std::collections::HashMap::new();
    for (chunk, h) in handles {
        let v: View<[f32]> = ws.get(h).map_err(|e| anyhow!("read embedding: {e:?}"))?;
        let cos: f32 = qv.iter().zip(v.as_ref().iter()).map(|(a, b)| a * b).sum();
        scores.insert(chunk, cos.max(0.0));
    }
    Ok(Some(scores))
}

/// Default cosine cutoff for `--filter`/`--remove` eligibility. Chosen from the
/// nomic score distribution observed on this pile: topically-matched chunks
/// cluster ~0.62–0.73 for their query, while unrelated chunks fall to ~0.40–0.52
/// (nomic cosines sit in a compressed high band). 0.55 lands in that natural gap
/// — high enough to spare unrelated material, low enough to catch the whole
/// matched cluster. Override per call with `--sim-threshold <f>`.
const DEFAULT_SIM_THRESHOLD: f32 = 0.55;

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
fn eligibility_scores(
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
    query: &str,
    universe: &[Id],
) -> Result<(std::collections::HashMap<Id, f32>, Vec<Id>)> {
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
    let raw: std::collections::HashMap<Id, f32> = idx
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
fn semantic_eligibility_scores(
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
    query: &str,
    universe: &[Id],
) -> Result<Option<(std::collections::HashMap<Id, f32>, Vec<Id>)>> {
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
    let emb = load_nomic_text_embedder()?;
    let qv = l2_normalize(
        emb.embed_query(query)
            .map_err(|e| anyhow!("embed query: {e:?}"))?,
    );
    let mut scores = std::collections::HashMap::new();
    for (chunk, h) in embedded {
        let v: View<[f32]> = ws.get(h).map_err(|e| anyhow!("read embedding: {e:?}"))?;
        let cos: f32 = qv.iter().zip(v.as_ref().iter()).map(|(a, b)| a * b).sum();
        scores.insert(chunk, cos.max(0.0));
    }
    // Unembedded chunks: try a positive lexical score; else mark unscorable.
    let lexical: Option<(std::collections::HashMap<Id, f32>, f32)> =
        if let Some((handle, _)) = latest_search_index(space) {
            let idx: SuccinctBM25Index = ws.get(handle).context("load search index")?;
            let raw: std::collections::HashMap<Id, f32> = idx
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

fn cmd_context(pile_path: &Path, branch_id_raw: Option<&str>, args: &[String]) -> Result<()> {
    let estimator = TokenEstimator::from_env();

    // Parse `[<budget>] [--chars N] [--about <query words...>]`. A bare number
    // sets the token budget; `--chars N` instead sets the budget as a CHARACTER
    // count (converted to the internal token budget through the estimator);
    // `--about` switches the cover from recency-first to relevance-first,
    // concentrating detail on the memories most similar to the query (so a face
    // can be cast with the slice of the past most relevant to its goal).
    let mut budget_tokens: usize = 20_000;
    let mut about: Option<String> = None;
    // `--filter <query>` (include-only) and `--remove <query>` (anti-filter) gate
    // ELIGIBILITY by positive similarity to their query; `--sim-threshold <f>` is
    // the shared cosine cutoff (default `DEFAULT_SIM_THRESHOLD`).
    let mut filter_q: Option<String> = None;
    let mut remove_q: Option<String> = None;
    let mut sim_threshold: f32 = DEFAULT_SIM_THRESHOLD;
    // `--tokens N` names the token budget explicitly; when present it wins over
    // the bare positional (which stays a backward-compatible fallback — it also
    // means tokens). `--chars N` budgets by characters instead (see below).
    let mut tokens_explicit = false;
    {
        // A value flag consumes the following args up to the NEXT recognized flag
        // (or end), so multi-word queries stay unquoted AND `--about`/`--filter`/
        // `--remove` compose in any order.
        let is_flag = |s: &str| {
            matches!(
                s,
                "--about" | "--filter" | "--remove" | "--tokens" | "--chars" | "--sim-threshold"
            )
        };
        let mut i = 0;
        while i < args.len() {
            if matches!(args[i].as_str(), "--about" | "--filter" | "--remove") {
                let mut j = i + 1;
                while j < args.len() && !is_flag(&args[j]) {
                    j += 1;
                }
                let q = args[i + 1..j].join(" ");
                let q = (!q.trim().is_empty()).then_some(q);
                match args[i].as_str() {
                    "--about" => about = q,
                    "--filter" => filter_q = q,
                    _ => remove_q = q,
                }
                i = j;
                continue;
            }
            if args[i] == "--sim-threshold" {
                let raw = args.get(i + 1).ok_or_else(|| {
                    anyhow!("--sim-threshold needs a number in [0,1], e.g. `--sim-threshold 0.55`")
                })?;
                sim_threshold = raw
                    .parse()
                    .map_err(|_| anyhow!("--sim-threshold expects a float, got `{raw}`"))?;
                i += 2;
                continue;
            }
            if args[i] == "--tokens" {
                let raw = args.get(i + 1).ok_or_else(|| {
                    anyhow!("--tokens needs a number, e.g. `memory context --tokens 60000`")
                })?;
                budget_tokens = raw.parse().map_err(|_| {
                    anyhow!("--tokens expects a positive integer, got `{raw}`")
                })?;
                tokens_explicit = true;
                i += 2;
                continue;
            }
            if args[i] == "--chars" {
                let raw = args.get(i + 1).ok_or_else(|| {
                    anyhow!("--chars needs a number, e.g. `memory context --chars 9500`")
                })?;
                let chars: usize = raw.parse().map_err(|_| {
                    anyhow!("--chars expects a positive integer, got `{raw}`")
                })?;
                // Convert a CHARACTER budget to the internal token budget. The
                // cover charges each chunk its summary's *token* estimate, but the
                // rendered output also spends characters on span headers, ids,
                // indentation and blank lines — empirically printed_chars ≈
                // 4.15–4.32 × used_tokens while the estimator runs at ~4
                // chars/token (so ~5% structural overhead). Convert through the
                // estimator (probing its ratio on a fixed sample, never allocating
                // the full N-char budget), then discount ~13% so the rendered
                // cover lands at or just under N characters (slightly under is
                // fine; over is not).
                const PROBE: usize = 4096;
                let toks_per_probe = estimator.estimate(&"x".repeat(PROBE)).max(1);
                budget_tokens = chars.saturating_mul(toks_per_probe) / PROBE * 87 / 100;
                i += 2;
                continue;
            }
            if !tokens_explicit {
                if let Ok(n) = args[i].parse::<usize>() {
                    budget_tokens = n;
                }
            }
            i += 1;
        }
    }

    let explicit_branch_id = parse_optional_hex_id(branch_id_raw)?;

    with_repo(pile_path, |repo| {
        let branch_id = match explicit_branch_id {
            Some(id) => id,
            None => repo
                .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
                .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?,
        };
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull branch {branch_id:x}: {e:?}"))?;
        let space = ws.checkout(..).context("checkout branch")?;

        let spans = collect_chunk_spans(&space);
        if spans.is_empty() {
            println!("no memory chunks on branch {branch_id:x}");
            return Ok(());
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
        let filter_elig = match &filter_q {
            Some(q) => Some(eligibility_scores(&space, &mut ws, q, &universe)?),
            None => None,
        };
        let remove_elig = match &remove_q {
            Some(q) => Some(eligibility_scores(&space, &mut ws, q, &universe)?),
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
            let scores: std::collections::HashMap<Id, f32> = if let Some(query) = &about {
                about_relevance_scores(&space, &mut ws, query)?
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
            used = used.saturating_add(context_chunk_cost(&mut ws, &space, &estimator, &spans, &mut cost_cache, i)?);
        }
        if used > budget_tokens {
            let earliest = roots.iter().map(|&i| spans[i].0).min().unwrap();
            let latest = roots.iter().map(|&i| spans[i].1).max().unwrap();
            bail!(
                "incomplete cover: the coarsest cover of all memories needs ~{} tokens, over the {budget_tokens}-token budget.\n\
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
            let remaining = budget_tokens.saturating_sub(used);
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
                        .saturating_add(context_chunk_cost(&mut ws, &space, &estimator, &spans, &mut cost_cache, k)?);
                }
                let pcost = context_chunk_cost(&mut ws, &space, &estimator, &spans, &mut cost_cache, i)?;
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
            // Recompute the token tally honestly over what actually survived.
            used = 0;
            for &i in &cover {
                used = used.saturating_add(context_chunk_cost(
                    &mut ws,
                    &space,
                    &estimator,
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
            let mut parts = vec![match &about {
                Some(q) => format!("most detail on memories about \"{q}\""),
                None => "recent in most detail".to_string(),
            }];
            if let Some(q) = &filter_q {
                parts.push(format!("filtered to \"{q}\""));
            }
            if let Some(q) = &remove_q {
                parts.push(format!("excluding \"{q}\""));
            }
            format!("coarse → fine; {}", parts.join("; "))
        };
        println!(
            "memory context — {} chunk(s), ~{} of {} tokens ({mode})",
            cover.len(),
            used,
            budget_tokens,
        );
        for &i in &cover {
            let (s, e, id) = spans[i];
            let depth = (0..n).filter(|&j| j != i && strict_contains(j, i)).count();
            let indent = "  ".repeat(depth);
            println!();
            println!(
                "{indent}{}  ({:x})",
                format_time_range(key_to_epoch(s), key_to_epoch(e)),
                id
            );
            if let Some(handle) = chunk_summary_handle(&space, id) {
                let summary: View<str> = ws.get(handle).context("read chunk summary")?;
                println!("{}", summary.trim_end());
            } else if chunk_image_handle(&space, id).is_some() {
                println!("[image memory @ {}]", chunk_span_str(&space, id));
            }
        }
        Ok(())
    })
}

/// the fine edge; `check 13w` finds regions with no coarse cover).
fn cmd_check(pile_path: &Path, branch_id_raw: Option<&str>, args: &[String]) -> Result<()> {
    let Some(grain_raw) = args.first() else {
        bail!("usage: memory check <grain e.g. 1d/4w/13w>");
    };
    let grain_ns = parse_grain(grain_raw)?;
    let explicit_branch_id = parse_optional_hex_id(branch_id_raw)?;
    with_repo(pile_path, |repo| {
        let branch_id = match explicit_branch_id {
            Some(id) => id,
            None => repo
                .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
                .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?,
        };
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull branch {branch_id:x}: {e:?}"))?;
        let space = ws.checkout(..).context("checkout branch")?;

        let all = collect_chunk_spans(&space);
        if all.is_empty() {
            println!("no memory chunks on branch {branch_id:x}");
            return Ok(());
        }
        let global_start = all.iter().map(|(s, _, _)| *s).min().unwrap();
        let global_end = all.iter().map(|(_, e, _)| *e).max().unwrap();

        // Coverage at this zoom: intervals of chunks with width <= grain.
        let mut covering: Vec<(i128, i128)> =
            all.iter().filter(|(s, e, _)| e - s <= grain_ns).map(|(s, e, _)| (*s, *e)).collect();
        covering.sort_by_key(|(s, _)| *s);

        // Sweep for holes in [global_start, global_end].
        let mut gaps: Vec<(i128, i128)> = Vec::new();
        let mut cursor = global_start;
        for (s, e) in &covering {
            if *s > cursor {
                gaps.push((cursor, *s));
            }
            if *e > cursor {
                cursor = *e;
            }
        }
        if cursor < global_end {
            gaps.push((cursor, global_end));
        }
        // A gap only matters at coarseness G if it is at least G wide; smaller
        // holes are below this zoom's resolution (you'd see them at a finer grain).
        gaps.retain(|(s, e)| e - s >= grain_ns);

        println!(
            "extent {}  ({} chunk(s) of width <= {grain_raw})",
            format_time_range(key_to_epoch(global_start), key_to_epoch(global_end)),
            covering.len()
        );
        if gaps.is_empty() {
            println!("OK no gaps >= {grain_raw} — coverage is contiguous at this zoom");
        } else {
            println!("{} gap(s) at grain {grain_raw}:", gaps.len());
            for (s, e) in &gaps {
                println!(
                    "  GAP {}  ({})",
                    format_time_range(key_to_epoch(*s), key_to_epoch(*e)),
                    humanize_ns(e - s)
                );
            }
        }
        Ok(())
    })
}

/// `memory density [<grain>]` — inspection tooling that finds where the
/// containment hierarchy is BUSHY: a span with many direct *leaf* children and
/// no intermediate arc summary combing them into mid-level groups. Bushiness is
/// exactly what makes a cover unable to drill granularly under budget — the only
/// way to add detail beneath a bushy span is to dump ALL its leaves into the
/// cover at once (the lumpy jump), because completeness forbids a partial split.
/// The fix is never to drop memories; it is to ADD intermediate summaries
/// (comb the leaves into arcs). This command only points at where to comb —
/// it writes nothing. Optional `<grain>`: restrict the report to spans of width
/// <= grain (zoom the analysis to e.g. day- vs week-level structure).
fn cmd_density(pile_path: &Path, branch_id_raw: Option<&str>, args: &[String]) -> Result<()> {
    // Threshold for the BUSHY flag: this many direct leaf-children with no
    // intermediate arc make a span expensive to expand in the cover.
    const BUSHY_LEAVES: usize = 5;
    let grain_ns: Option<i128> = match args.first() {
        Some(raw) => Some(parse_grain(raw)?),
        None => None,
    };
    let explicit_branch_id = parse_optional_hex_id(branch_id_raw)?;
    with_repo(pile_path, |repo| {
        let branch_id = match explicit_branch_id {
            Some(id) => id,
            None => repo
                .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
                .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?,
        };
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull branch {branch_id:x}: {e:?}"))?;
        let space = ws.checkout(..).context("checkout branch")?;

        let spans = collect_chunk_spans(&space);
        if spans.is_empty() {
            println!("no memory chunks on branch {branch_id:x}");
            return Ok(());
        }
        let n = spans.len();

        // Same containment hierarchy cmd_context builds: a chunk's parent is the
        // tightest strictly-wider chunk that spans it (time-range subsumption).
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
        for i in 0..n {
            if let Some(p) = parent[i] {
                children[p].push(i);
            }
        }

        // Subtree depth (leaves = 0) and size, computed narrow→wide so children
        // are finished before their parent.
        let mut depth = vec![0usize; n];
        let mut subtree = vec![1usize; n];
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by_key(|&i| width(i));
        for &i in &order {
            if let Some(p) = parent[i] {
                depth[p] = depth[p].max(depth[i] + 1);
                subtree[p] += subtree[i];
            }
        }
        let leaf_kids = |i: usize| children[i].iter().filter(|&&c| children[c].is_empty()).count();

        // Non-leaf spans (forks worth inspecting: >= 2 children), optionally
        // restricted to a coarseness zoom.
        let mut forks: Vec<usize> = (0..n)
            .filter(|&i| children[i].len() >= 2)
            .filter(|&i| grain_ns.map_or(true, |g| width(i) <= g))
            .collect();

        // Classify each fork: BUSHY (many flat leaves, no comb) / coarse (few
        // children) / balanced (the rest — already has intermediate arcs).
        let classify = |i: usize| -> &'static str {
            if leaf_kids(i) >= BUSHY_LEAVES {
                "BUSHY"
            } else if children[i].len() <= 3 {
                "coarse"
            } else {
                "balanced"
            }
        };

        let total_forks = forks.len();
        let bushy_count = forks.iter().filter(|&&i| classify(i) == "BUSHY").count();
        println!(
            "memory density — {n} chunk(s), {total_forks} fork(s) (>=2 children) on branch {branch_id:x}{}",
            grain_ns.map(|_| format!(" of width <= {}", args[0])).unwrap_or_default(),
        );
        println!(
            "  BUSHY = >= {BUSHY_LEAVES} direct leaf-children with no intermediate arc (expensive to expand → comb leaves into arcs); {bushy_count} found"
        );
        if forks.is_empty() {
            println!("  (no forks at this zoom)");
            return Ok(());
        }

        // Bushiest first: by direct leaf-children desc, then recency (end) desc.
        // Shallow subtrees with many leaves are the worst — splitting them dumps
        // every leaf into the cover at once.
        forks.sort_by(|&a, &b| {
            leaf_kids(b)
                .cmp(&leaf_kids(a))
                .then(spans[b].1.cmp(&spans[a].1))
        });
        let render = |i: usize| -> String {
            format!(
                "{:8} {}  ({:x})  children={} leaf={} depth={} subtree={}",
                classify(i),
                format_time_range(key_to_epoch(spans[i].0), key_to_epoch(spans[i].1)),
                spans[i].2,
                children[i].len(),
                leaf_kids(i),
                depth[i],
                subtree[i],
            )
        };

        println!("\nBushiest forks (worst first):");
        for &i in forks.iter().take(15) {
            println!("  {}", render(i));
        }

        // The recent edge: forks STARTING in the last 14 days, newest first —
        // local structure at the now-end (today's sessions), where chunks are
        // most likely hanging flat and uncombed. (Start-based, so the 2024-rooted
        // apex — whose own fan-out shows in the worst-first list above — doesn't
        // crowd out the genuinely recent forks here.)
        let newest_end = spans.iter().map(|(_, e, _)| *e).max().unwrap();
        let recent_cutoff = newest_end - parse_grain("2w").unwrap_or(0);
        let mut recent: Vec<usize> =
            forks.iter().copied().filter(|&i| spans[i].0 >= recent_cutoff).collect();
        recent.sort_by(|&a, &b| spans[b].1.cmp(&spans[a].1));
        println!("\nRecent edge (forks starting within 2w, newest first):");
        if recent.is_empty() {
            println!("  (none)");
        } else {
            for &i in &recent {
                println!("  {}", render(i));
            }
        }
        Ok(())
    })
}

fn cmd_meta(pile_path: &Path, branch_id_raw: Option<&str>, args: &[String]) -> Result<()> {
    if args.len() != 1 {
        bail!("usage: memory meta <id>");
    }

    let explicit_branch_id = parse_optional_hex_id(branch_id_raw)?;

    with_repo(pile_path, |repo| {
        let branch_id = match explicit_branch_id {
            Some(id) => id,
            None => repo
                .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
                .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?,
        };

        // Load memory branch.
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull branch {branch_id:x}: {e:?}"))?;
        let space = ws.checkout(..).context("checkout branch")?;

        // Resolve chunk (time range or hex fallback).
        let raw = &args[0];
        let chunk_id = if raw.contains("..") {
            let (start, end) = parse_time_range(raw)?;
            find_chunk_by_time_range(&space, start, end)
                .ok_or_else(|| anyhow!("no memory covers range {raw}"))?
        } else {
            resolve_chunk_id(&space, raw)
                .map_err(|e| invalid_memory_id_error(raw, e))?
        };

        // Print structural metadata.
        if let (Some(start_v), Some(end_v)) = (chunk_start_at(&space, chunk_id), chunk_end_at(&space, chunk_id)) {
            let range = format_time_range(
                epoch_from_interval(start_v),
                epoch_end_from_interval(end_v),
            );
            println!("range: {}", range);
        }
        println!("id: {:x}", chunk_id);

        // References, both directions. Outgoing includes legacy left/right
        // remnants and is supersede-filtered + time-sorted; shown with the
        // target's span (the address the prose would use) and id.
        let outgoing = chunk_references(&space, chunk_id);
        if !outgoing.is_empty() {
            let refs: Vec<String> = outgoing
                .iter()
                .map(|cid| {
                    match (chunk_start_at(&space, *cid), chunk_end_at(&space, *cid)) {
                        (Some(s), Some(e)) => format!(
                            "{} ({:x})",
                            format_time_range(
                                epoch_from_interval(s),
                                epoch_end_from_interval(e)
                            ),
                            cid
                        ),
                        _ => format!("{cid:x}"),
                    }
                })
                .collect();
            println!("references: {}", refs.join(", "));
        }
        let superseded_set = superseded_ids(&space);
        let incoming: Vec<Id> =
            find!(s: Id, pattern!(&space, [{ ?s @ ctx::reference: chunk_id }]))
                .filter(|s| !superseded_set.contains(s))
                .collect();
        if !incoming.is_empty() {
            let ids: Vec<String> = incoming.iter().map(|s| format!("{s:x}")).collect();
            println!("referenced_by: {}", ids.join(", "));
        }

        if let Some(exec_id) = chunk_about_exec_result(&space, chunk_id) {
            println!("about_exec_result: {exec_id:x}");
        }

        if let Some(archive_id) = chunk_about_archive_message(&space, chunk_id) {
            println!("about_archive_message: {archive_id:x}");
            print_archive_meta(repo, &mut ws, archive_id)?;
        }

        Ok(())
    })
}

fn print_archive_meta(
    repo: &mut Repository<Pile>,
    ws: &mut Workspace<Pile>,
    archive_msg_id: Id,
) -> Result<()> {
    let archive_branch_id = match repo.ensure_branch(DEFAULT_ARCHIVE_BRANCH, None) {
        Ok(id) => id,
        Err(_) => return Ok(()),
    };

    // Pull archive branch.
    let archive_catalog = match repo.pull(archive_branch_id) {
        Ok(mut archive_ws) => match archive_ws.checkout(..) {
            Ok(cat) => cat,
            Err(_) => return Ok(()),
        },
        Err(_) => return Ok(()),
    };

    // Author (as id prefix).
    if let Some((author_id,)) = find!(
        (author_id: Id),
        pattern!(&archive_catalog, [{
            archive_msg_id @
            archive_schema::author: ?author_id,
        }])
    ).next() {
        // Try to resolve author name.
        let author_name: Option<String> = find!(
            (name: Inline<Handle<LongString>>),
            pattern!(&archive_catalog, [{
                archive_msg_id @
                archive_schema::author_name: ?name,
            }])
        ).next().and_then(|(name_handle,)| {
            ws.get::<View<str>, LongString>(name_handle).ok().map(|v| v.as_ref().to_string())
        });
        match author_name {
            Some(name) => println!("  author: {} ({:x})", name, author_id),
            None => println!("  author: {:x}", author_id),
        }
    }

    // Source format.
    if let Some((fmt,)) = find!(
        (fmt: String),
        pattern!(&archive_catalog, [{
            archive_msg_id @
            archive_import_schema::source_format: ?fmt,
        }])
    ).next() {
        println!("  source_format: {}", fmt);
    }

    // Source conversation id.
    if let Some((conv_handle,)) = find!(
        (conv: Inline<Handle<LongString>>),
        pattern!(&archive_catalog, [{
            archive_msg_id @
            archive_import_schema::source_conversation_id: ?conv,
        }])
    ).next() {
        if let Ok(view) = ws.get::<View<str>, LongString>(conv_handle) {
            println!("  conversation: {}", view.as_ref());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// reference notation
// ---------------------------------------------------------------------------
//
// Two reference forms live in summary prose (settled design, restored after
// the 2026-06-12 over-steer; see the practice fragment in the wiki):
//
// - SOFT: `(memory:<from>..<to>)` — a temporal address. Human-readable,
//   machine-recognizable, resolved by range query at read time against
//   whatever the best chunk then is. Deliberately NOT parsed at write time;
//   no fact is minted. Addresses are not links.
//
// - HARD: `[why this matters here](memory:<hex>)` — a contextualised
//   cross-reference to an exact chunk. Extracted at create into a
//   ctx::reference fact: queryable in both directions, pinned forever,
//   zero span effect, zero tree role. The bracket text carries the
//   explanation; a bare reference without context is bad style.
//
// Hierarchy is temporal subsumption only. create() once minted ctx::child
// edges from references and let their union OVERRIDE the typed range; that
// conflation of reference with structure is gone for good.

/// Extract hard references `[text](memory:<hex>)` from summary prose.
/// Returns the hex values; range-form references are soft and stay unparsed.
fn scan_hard_references(text: &str) -> Vec<String> {
    let mut refs = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("](memory:") {
        let after = &rest[start + 9..];
        if let Some(end) = after.find(')') {
            let value = after[..end].trim();
            if !value.is_empty()
                && !value.contains("..")
                && value.chars().all(|c| c.is_ascii_hexdigit())
            {
                refs.push(value.to_string());
            }
        }
        rest = &rest[start + 9..];
    }
    refs
}

/// Extract `[text](faculty:<hex>)` markdown link references from text.
/// Returns (faculty, raw_value) pairs for non-memory faculties.
/// Memory links are handled by `scan_memory_links` instead.
#[allow(dead_code)]
fn extract_references(text: &str) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    let mut rest = text;
    while let Some(paren) = rest.find("](") {
        let after = &rest[paren + 2..];
        let end = after.find(')').unwrap_or(after.len());
        let link = &after[..end];
        if let Some(colon) = link.find(':') {
            let faculty = &link[..colon];
            let value = &link[colon + 1..];
            if !faculty.is_empty()
                && faculty
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                && faculty != "memory"  // memory links handled separately
                && !value.is_empty()
            {
                refs.push((faculty.to_string(), value.to_string()));
            }
        }
        rest = &after[end.min(after.len()).max(1)..];
    }
    refs.sort();
    refs.dedup();
    refs
}

/// Find all exec results whose finished_at falls within the given time range,
/// sorted chronologically.
fn find_execs_in_range(
    catalog: &TribleSet,
    query_start: Epoch,
    query_end: Epoch,
) -> Vec<(Id, Inline<NsTAIInterval>)> {
    let qs = query_start.to_tai_duration().total_nanoseconds();
    let qe = query_end.to_tai_duration().total_nanoseconds();
    let mut out: Vec<(Id, Inline<NsTAIInterval>, i128)> = find!(
        (result_id: Id, finished_at: Inline<NsTAIInterval>),
        pattern!(catalog, [{
            ?result_id @
            metadata::tag: &KIND_EXEC_RESULT,
            metadata::finished_at: ?finished_at,
        }])
    )
    .filter_map(|(id, t)| {
        let k = interval_key(t);
        (k >= qs && k <= qe).then_some((id, t, k))
    })
    .collect();
    out.sort_by_key(|(_, _, k)| *k);
    out.into_iter().map(|(id, t, _)| (id, t)).collect()
}

/// Find all archive messages whose created_at falls within the given time range,
/// sorted chronologically.
fn find_archive_in_range(
    catalog: &TribleSet,
    query_start: Epoch,
    query_end: Epoch,
) -> Vec<(Id, Inline<NsTAIInterval>)> {
    let qs = query_start.to_tai_duration().total_nanoseconds();
    let qe = query_end.to_tai_duration().total_nanoseconds();
    let mut out: Vec<(Id, Inline<NsTAIInterval>, i128)> = find!(
        (msg_id: Id, created_at: Inline<NsTAIInterval>),
        pattern!(catalog, [{
            ?msg_id @
            metadata::tag: &KIND_ARCHIVE_MESSAGE,
            metadata::created_at: ?created_at,
        }])
    )
    .filter_map(|(id, t)| {
        let k = interval_key(t);
        (k >= qs && k <= qe).then_some((id, t, k))
    })
    .collect();
    out.sort_by_key(|(_, _, k)| *k);
    out.into_iter().map(|(id, t, _)| (id, t)).collect()
}

/// Resolve provenance for a memory chunk by time-range query — find all
/// exec results (cognition branch) and archive messages (archive branch)
/// whose timestamps fall within the chunk's `[start_at, end_at]` interval.
/// This is the loose-coupling alternative to chunk-side `about_exec_result`
/// / `about_archive_message` attributes: associations emerge from temporal
/// overlap at read-time, so importing archive data after a chunk was written
/// automatically associates it with that chunk.
fn cmd_provenance(pile_path: &Path, args: &[String]) -> Result<()> {
    let Some(chunk_arg) = args.first() else {
        bail!("usage: memory provenance <chunk-id>");
    };

    with_repo(pile_path, |repo| {
        let memory_branch_id = repo
            .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
            .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?;
        let memory_catalog = {
            let mut ws = repo
                .pull(memory_branch_id)
                .map_err(|e| anyhow!("pull memory branch: {e:?}"))?;
            ws.checkout(..).context("checkout memory branch")?
        };

        let chunk_id = resolve_chunk_id(&memory_catalog, chunk_arg)
            .map_err(|e| anyhow!("resolve chunk id `{chunk_arg}`: {e}"))?;

        let start_at = chunk_start_at(&memory_catalog, chunk_id)
            .ok_or_else(|| anyhow!("chunk {chunk_id:x} has no start_at"))?;
        let end_at = chunk_end_at(&memory_catalog, chunk_id)
            .ok_or_else(|| anyhow!("chunk {chunk_id:x} has no end_at"))?;
        let (start_epoch, _): (Epoch, Epoch) = start_at.try_from_inline().unwrap();
        let (_, end_epoch): (Epoch, Epoch) = end_at.try_from_inline().unwrap();

        println!("chunk: {chunk_id:x}");
        println!(
            "range: {}..{}",
            fmt_epoch(start_epoch),
            fmt_epoch(end_epoch),
        );

        // Cognition branch.
        if let Ok(exec_bid) = repo.ensure_branch(DEFAULT_COGNITION_BRANCH, None) {
            if let Some(catalog) = repo
                .pull(exec_bid)
                .ok()
                .and_then(|mut ws| ws.checkout(..).ok())
            {
                let execs = find_execs_in_range(&catalog, start_epoch, end_epoch);
                println!("\ncognition exec results in range: {}", execs.len());
                for (id, t) in execs {
                    let (epoch, _): (Epoch, Epoch) = t.try_from_inline().unwrap();
                    println!("  {id:x}  {}", fmt_epoch(epoch));
                }
            }
        }

        // Archive branch.
        if let Ok(archive_bid) = repo.ensure_branch(DEFAULT_ARCHIVE_BRANCH, None) {
            if let Some(catalog) = repo
                .pull(archive_bid)
                .ok()
                .and_then(|mut ws| ws.checkout(..).ok())
            {
                let msgs = find_archive_in_range(&catalog, start_epoch, end_epoch);
                println!("\narchive messages in range: {}", msgs.len());
                for (id, t) in msgs {
                    let (epoch, _): (Epoch, Epoch) = t.try_from_inline().unwrap();
                    println!("  {id:x}  {}", fmt_epoch(epoch));
                }
            }
        }

        Ok(())
    })
}

// ---------------------------------------------------------------------------
// show / turn subcommands
// ---------------------------------------------------------------------------


fn print_chunk(ws: &mut Workspace<Pile>, space: &TribleSet, chunk_id: Id) -> Result<()> {
    if let Some(handle) = chunk_summary_handle(space, chunk_id) {
        let summary: View<str> = ws.get(handle).context("read chunk summary")?;
        print!("{}", summary.trim_end());
        println!();
        return Ok(());
    }
    // A wordless image memory has no summary — render a marker rather than
    // crash, and export the blob so a Claude-Code reader can Read it to see it.
    if let Some(h) = chunk_image_handle(space, chunk_id) {
        let span = chunk_span_str(space, chunk_id);
        match materialize_image(ws, chunk_id, h) {
            Ok(path) => println!(
                "[image memory @ {span}] → {} (Read this path to view)",
                path.display()
            ),
            Err(e) => println!("[image memory @ {span}] (image export failed: {e})"),
        }
        return Ok(());
    }
    bail!("chunk {:x} has no summary", chunk_id)
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn resolve_chunk_id(space: &TribleSet, raw: &str) -> Result<Id> {
    let prefix = normalize_prefix(raw)?;

    let mut chunk_matches = Vec::new();
    for chunk_id in all_chunk_ids(space) {
        if id_starts_with(chunk_id, prefix.as_str()) {
            chunk_matches.push(chunk_id);
        }
    }
    match chunk_matches.len() {
        1 => return Ok(chunk_matches[0]),
        n if n > 1 => {
            bail!("multiple chunk ids match prefix '{prefix}' (use a longer prefix)")
        }
        _ => {}
    }

    for chunk_id in all_chunk_ids(space) {
        if let Some(turn_id) = chunk_about_exec_result(space, chunk_id) {
            if id_starts_with(turn_id, prefix.as_str()) {
                bail!("turn id `{prefix}` is not a chunk id; use `memory turn {prefix}`");
            }
        }
    }

    bail!("no chunk id matches prefix '{prefix}'")
}

fn print_turn_facets(ws: &mut Workspace<Pile>, space: &TribleSet, raw: &str) -> Result<()> {
    let prefix = normalize_prefix(raw)?;
    let mut turn_matches = Vec::new();
    for chunk_id in all_chunk_ids(space) {
        if let Some(turn_id) = chunk_about_exec_result(space, chunk_id) {
            if id_starts_with(turn_id, prefix.as_str()) {
                turn_matches.push((turn_id, chunk_id));
            }
        }
    }
    match turn_matches.len() {
        0 => bail!("no turn_id matches prefix '{prefix}'"),
        _ => {}
    }

    turn_matches.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    turn_matches.dedup();

    let first_turn = turn_matches[0].0;
    if turn_matches.iter().any(|(turn_id, _)| *turn_id != first_turn) {
        bail!("multiple turn_id values match prefix '{prefix}' (use a longer prefix)");
    }

    let mut chunk_ids: Vec<Id> = turn_matches.iter().map(|(_, cid)| *cid).collect();
    chunk_ids.sort_unstable_by(|a, b| {
        let a_width = chunk_end_at(space, *a).map(|v| epoch_end_from_interval(v).to_tai_duration().total_nanoseconds()).unwrap_or(0)
            - chunk_start_at(space, *a).map(|v| epoch_from_interval(v).to_tai_duration().total_nanoseconds()).unwrap_or(0);
        let b_width = chunk_end_at(space, *b).map(|v| epoch_end_from_interval(v).to_tai_duration().total_nanoseconds()).unwrap_or(0)
            - chunk_start_at(space, *b).map(|v| epoch_from_interval(v).to_tai_duration().total_nanoseconds()).unwrap_or(0);
        a_width.cmp(&b_width).then(a.cmp(b))
    });

    println!(
        "turn {} has {} memory facet(s)",
        fmt_id(first_turn),
        chunk_ids.len()
    );
    for (i, chunk_id) in chunk_ids.iter().enumerate() {
        if i > 0 {
            println!();
        }
        print_chunk(ws, space, *chunk_id)?;
    }

    Ok(())
}

fn invalid_memory_id_error(raw: &str, cause: anyhow::Error) -> anyhow::Error {
    anyhow!(
        "memory lookup failed for id `{raw}`: {cause}\n\
         hint: that id is wrong here.\n\
         hint: only call `memory <id>` when you want to inspect an id that already appeared in prior output.\n\
         hint: do not guess memory ids or loop lookups; switch to a concrete non-memory action if no valid id is available."
    )
}

// ---------------------------------------------------------------------------
// utilities
// ---------------------------------------------------------------------------

fn normalize_prefix(raw: &str) -> Result<String> {
    let mut prefix = raw.trim().to_ascii_lowercase();
    if let Some(rest) = prefix.strip_prefix("0x") {
        prefix = rest.to_string();
    }
    if prefix.is_empty() {
        bail!("id prefix is empty");
    }
    Ok(prefix)
}

fn id_starts_with(id: Id, prefix: &str) -> bool {
    format!("{id:x}").starts_with(prefix)
}

fn parse_optional_hex_id(raw: Option<&str>) -> Result<Option<Id>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let id = Id::from_hex(trimmed).ok_or_else(|| anyhow!("invalid id {trimmed}"))?;
    Ok(Some(id))
}

fn interval_key(interval: Inline<NsTAIInterval>) -> i128 {
    let (lower, _): (Epoch, Epoch) = interval.try_from_inline().unwrap();
    lower.to_tai_duration().total_nanoseconds()
}

/// Export an image memory's blob to a temp file and return the path. The
/// Claude-Code environment can't auto-inject pile blobs — a reader has to call
/// the Read tool on a file path — so when a wordless image memory surfaces we
/// drop its bytes at `/tmp/mem_img/<hex>.<ext>` and print the path. No embedder
/// needed; this is pure blob → disk. Extension is sniffed from the magic bytes.
fn materialize_image(
    ws: &mut Workspace<Pile>,
    chunk_id: Id,
    handle: Inline<Handle<RawBytes>>,
) -> Result<PathBuf> {
    let bytes: Bytes = ws.get(handle).context("read image bytes")?;
    let b = bytes.as_ref();
    let dir = Path::new("/tmp/mem_img");
    std::fs::create_dir_all(dir).context("create /tmp/mem_img")?;
    let path = dir.join(format!("{chunk_id:x}.{}", sniff_image_ext(b)));
    std::fs::write(&path, b).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

/// Guess a file extension from an image's leading magic bytes; default `png`.
fn sniff_image_ext(b: &[u8]) -> &'static str {
    if b.starts_with(&[0x89, b'P', b'N', b'G']) {
        "png"
    } else if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        "jpg"
    } else if b.starts_with(b"GIF8") {
        "gif"
    } else if b.len() >= 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        "webp"
    } else if b.starts_with(b"BM") {
        "bmp"
    } else {
        "png"
    }
}

fn open_repo(path: &Path) -> Result<Repository<Pile>> {
    let mut pile =
        Pile::open(path).map_err(|e| anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.refresh() {
        let _ = pile.close();
        return Err(match err {
            triblespace::core::repo::pile::ReadError::CorruptPile { valid_length } => anyhow!(
                "pile corrupt at byte {valid_length}: refusing to auto-repair (a stale binary \
                 could truncate newer data). If, and only if, the tail is a genuinely torn write, truncate it explicitly (DESTRUCTIVE) with: trible pile amputate {}",
                path.display()
            ),
            other => anyhow!("refresh pile {}: {other:?}", path.display()),
        });
    }
    Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
        .map_err(|err| anyhow!("create repository: {err:?}"))
}

fn with_repo<T>(
    pile: &Path,
    f: impl FnOnce(&mut Repository<Pile>) -> Result<T>,
) -> Result<T> {
    let mut repo = open_repo(pile)?;
    let result = f(&mut repo);
    let close_res = repo.close().map_err(|e| anyhow!("close pile: {e:?}"));
    if let Err(err) = close_res {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }
    result
}
