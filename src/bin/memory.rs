
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{CommandFactory, Parser};
use ed25519_dalek::SigningKey;
use faculties::schemas::memory::{
    DEFAULT_ARCHIVE_BRANCH, DEFAULT_COGNITION_BRANCH, DEFAULT_MEMORY_BRANCH, KIND_ARCHIVE_MESSAGE,
    KIND_CHUNK_ID, KIND_EXEC_RESULT, KIND_SEARCH_INDEX, archive_import_schema, archive_schema,
    comb, ctx, search_index,
};
use triblespace_search::bm25::BM25Builder;
use triblespace_search::succinct::{SuccinctBM25Blob, SuccinctBM25Index};
use triblespace_search::tokens::hash_tokens;
use hifitime::Epoch;
use rand_core::OsRng;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::macros::{find, pattern};
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval};
use triblespace::prelude::*;

#[derive(Parser)]
#[command(
    name = "memory",
    about = "Show compacted context chunks (drill down by narrowing the time range).\n\n\
             Subcommands:\n  \
             memory <from>..<to>              — show best summary covering a time range\n  \
             memory meta <from>..<to>         — show structural metadata for a time range\n  \
             memory create [<range>] <summary> — create a memory chunk\n  \
             memory respan <id> <from>..<to>  — correct a chunk's span (new chunk supersedes old; views exclude old)\n  \
             memory supersede <new> <old>     — mark an existing chunk as replacing another (old leaves all views)\n  \
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
    #[arg(value_name = "ID")]
    ids: Vec<String>,
}

// ── on-demand chunk queries ───────────────────────────────────────────
// Chunks are queried directly from the TribleSet — no pre-materialization.

fn chunk_summary_handle(space: &TribleSet, id: Id) -> Option<Inline<Handle<LongString>>> {
    find!(h: Inline<Handle<LongString>>, pattern!(space, [{ id @ ctx::summary: ?h }])).next()
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

/// Find the best chunk covering a query time range.
/// Prefers: narrowest chunk that fully contains the query (most specific).
/// Fallback: best partial overlap.
fn find_chunk_by_time_range(
    space: &TribleSet,
    query_start: Epoch,
    query_end: Epoch,
) -> Option<Id> {
    let query_start_ns = query_start.to_tai_duration().total_nanoseconds();
    let query_end_ns = query_end.to_tai_duration().total_nanoseconds();

    let mut best_cover: Option<(Id, i128)> = None;
    let mut best_overlap: Option<(Id, i128)> = None;

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

        if chunk_start <= query_start_ns && chunk_end >= query_end_ns {
            let width = chunk_end - chunk_start;
            match best_cover {
                Some((_, prev_width)) if prev_width <= width => {}
                _ => best_cover = Some((chunk_id, width)),
            }
        }

        let overlap_start = chunk_start.max(query_start_ns);
        let overlap_end = chunk_end.min(query_end_ns);
        let overlap = overlap_end.saturating_sub(overlap_start);
        match best_overlap {
            Some((_, prev_overlap)) if prev_overlap >= overlap => {}
            _ => best_overlap = Some((chunk_id, overlap)),
        }
    }

    best_cover.map(|(id, _)| id).or(best_overlap.map(|(id, _)| id))
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
            let summary = chunk_summary_handle(&space, chunk)
                .and_then(|h| ws.get::<View<str>, LongString>(h).ok())
                .map(|v| v.as_ref().lines().next().unwrap_or("").to_string())
                .unwrap_or_default();
            println!("{score:6.2}  {chunk:x}  {summary}");
        }
        Ok(())
    })
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
    if cli.ids.first().is_some_and(|value| value == "meta") {
        return cmd_meta(&cli.pile, cli.branch_id.as_deref(), &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "respan") {
        return cmd_respan(&cli.pile, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "supersede") {
        return cmd_supersede(&cli.pile, &cli.ids[1..]);
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
        let chunk_id = create_chunk(repo, &summary_text, range)?;
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

    ws.commit(change, "memory create");
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
                let chunk_id = create_chunk(repo, &summary, (edge, until))?;
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
    let handle = chunk_summary_handle(space, chunk_id)
        .ok_or_else(|| anyhow!("chunk {:x} has no summary", chunk_id))?;
    let summary: View<str> = ws.get(handle).context("read chunk summary")?;
    print!("{}", summary.trim_end());
    println!();
    Ok(())
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

fn open_repo(path: &Path) -> Result<Repository<Pile>> {
    let mut pile =
        Pile::open(path).map_err(|e| anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.restore() {
        let _ = pile.close();
        return Err(anyhow!("restore pile {}: {err:?}", path.display()));
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
