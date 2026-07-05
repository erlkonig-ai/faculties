//! `status` — per-window "currently doing X" status.
//!
//! Each window (a relations persona / zooid) has a current status it sets
//! with `status set "<text>"`; everyone else reads `status list` (the
//! colony at a glance) or `status show <window>`. Status is append-only
//! timestamped events keyed to the window — latest-per-window is current,
//! the history is a free per-window activity timeline (coordinate-and-
//! cursor). Lives on its own `status` branch.
//!
//! The star-handle (stable address) names the window; the status names
//! what it's doing now — so the role is never pinned to the name.
//!
//! Commands:
//!   status set "<text>"          — set $PERSONA's current status
//!   status list                  — latest status of every window
//!   status show <window> [--limit N]

use anyhow::{Result, anyhow, bail};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use faculties::schemas::relations::relations as rel_attrs;
use faculties::schemas::status::{DEFAULT_BRANCH, KIND_STATUS_UPDATE, status};
use hifitime::Epoch;
use rand_core::OsRng;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use triblespace::core::metadata;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::prelude::*;

type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

#[derive(Parser)]
#[command(name = "status", about = "Per-window 'currently doing X' status")]
struct Cli {
    /// Path to the pile file
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Branch name for status data
    #[arg(long, default_value = DEFAULT_BRANCH)]
    branch: String,
    /// Branch name for relations (window labels)
    #[arg(long, default_value = "relations")]
    relations_branch: String,
    /// Acting persona (relations label or 32-char hex id)
    #[arg(long, env = "PERSONA")]
    persona: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Set the current status for your window ($PERSONA)
    Set {
        #[arg(help = "Status text, e.g. \"porting SigLIP\"")]
        text: String,
    },
    /// Show the latest status of every window
    List,
    /// Show a window's current status + recent history
    Show {
        /// Window: relations label or 32-char hex id
        window: String,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
}

// ── time + ids ──────────────────────────────────────────────────────────────

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn epoch_interval(epoch: Epoch) -> IntervalValue {
    (epoch, epoch).try_to_inline().unwrap()
}

fn interval_key(interval: IntervalValue) -> i128 {
    let (lower, _): (i128, i128) = interval.try_from_inline().unwrap();
    lower
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

/// Compact age like "3m" / "2h" / "5d" from two ns keys.
fn format_age(now_key: i128, past_key: i128) -> String {
    let secs = ((now_key - past_key) / 1_000_000_000).max(0);
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

// ── repo plumbing ─────────────────────────────────────────────────────────────

fn open_repo(path: &Path) -> Result<Repository<Pile>> {
    let mut pile = Pile::open(path).map_err(|e| anyhow!("open pile {}: {e:?}", path.display()))?;
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
    let signing_key = SigningKey::generate(&mut OsRng);
    Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|e| anyhow!("create repository: {e:?}"))
}

fn with_repo<T>(pile: &Path, f: impl FnOnce(&mut Repository<Pile>) -> Result<T>) -> Result<T> {
    let mut repo = open_repo(pile)?;
    let result = f(&mut repo);
    let close = repo.close().map_err(|e| anyhow!("close pile: {e:?}"));
    if let Err(err) = close {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }
    result
}

fn read_text(ws: &mut Workspace<Pile>, h: TextHandle) -> Option<String> {
    ws.get::<View<str>, blobencodings::LongString>(h)
        .ok()
        .map(|v| v.to_string())
}

/// Resolve a window (relations label or hex id) to its persona id.
fn resolve_window_id(repo: &mut Repository<Pile>, relations_branch_id: Id, input: &str) -> Result<Id> {
    let trimmed = input.trim();
    if let Some(id) = Id::from_hex(trimmed) {
        return Ok(id);
    }
    let mut ws = repo
        .pull(relations_branch_id)
        .map_err(|e| anyhow!("pull relations: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow!("checkout relations: {e:?}"))?;
    let key = trimmed.to_ascii_lowercase();
    let matches: Vec<Id> = find!(
        person_id: Id,
        pattern!(&space, [{ ?person_id @ metadata::tag: &faculties::schemas::relations::KIND_PERSON_ID }])
    )
    .filter(|&person_id| {
        exists!(pattern!(&space, [{ person_id @ rel_attrs::label_norm: key.as_str() }]))
            || exists!(pattern!(&space, [{ person_id @ rel_attrs::alias_norm: key.as_str() }]))
    })
    .collect();
    match matches.len() {
        0 => bail!("unknown window '{trimmed}' (no relations entry; try the hex id)"),
        1 => Ok(matches[0]),
        _ => bail!("multiple relations entries match '{trimmed}'"),
    }
}

fn window_label(ws: &mut Workspace<Pile>, space: &TribleSet, id: Id) -> String {
    find!(h: TextHandle, pattern!(space, [{ id @ metadata::name: ?h }]))
        .next()
        .and_then(|h| read_text(ws, h))
        .unwrap_or_else(|| fmt_id(id))
}

// ── status events ─────────────────────────────────────────────────────────────

struct StatusRow {
    window: Id,
    text: TextHandle,
    at: IntervalValue,
}

fn load_status_rows(space: &TribleSet) -> Vec<StatusRow> {
    find!(
        (ev: Id, window: Id, text: TextHandle, at: IntervalValue),
        pattern!(space, [{
            ?ev @
            metadata::tag: &KIND_STATUS_UPDATE,
            status::window: ?window,
            status::text: ?text,
            metadata::created_at: ?at,
        }])
    )
    .map(|(_ev, window, text, at)| StatusRow { window, text, at })
    .collect()
}

/// Latest status row per window.
fn latest_per_window(rows: Vec<StatusRow>) -> HashMap<Id, StatusRow> {
    let mut latest: HashMap<Id, StatusRow> = HashMap::new();
    for row in rows {
        match latest.get(&row.window) {
            Some(existing) if interval_key(existing.at) >= interval_key(row.at) => {}
            _ => {
                latest.insert(row.window, row);
            }
        }
    }
    latest
}

// ── commands ──────────────────────────────────────────────────────────────────

fn cmd_set(pile: &Path, branch: &str, relations_branch: &str, persona: Option<&str>, text: String) -> Result<()> {
    let text = text.trim().to_string();
    if text.is_empty() {
        bail!("status text is empty");
    }
    let persona = persona.ok_or_else(|| {
        anyhow!("no persona — set $PERSONA or pass --persona <label> (whose status is this?)")
    })?;
    with_repo(pile, |repo| {
        let branch_id = repo
            .ensure_branch(branch, None)
            .map_err(|e| anyhow!("ensure branch '{branch}': {e:?}"))?;
        let relations_branch_id = repo
            .ensure_branch(relations_branch, None)
            .map_err(|e| anyhow!("ensure relations branch: {e:?}"))?;
        let window = resolve_window_id(repo, relations_branch_id, persona)?;
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow!("pull status: {e:?}"))?;
        let now = epoch_interval(now_epoch());
        let handle = ws.put(text.clone());
        let change = entity! { ufoid() @
            metadata::tag: &KIND_STATUS_UPDATE,
            status::window: window,
            status::text: handle,
            metadata::created_at: now,
        };
        ws.commit(change, "status set");
        repo.push(&mut ws).map_err(|e| anyhow!("push status: {e:?}"))?;
        println!("{} → {text}", fmt_id(window));
        Ok(())
    })
}

fn cmd_list(pile: &Path, branch: &str, relations_branch: &str) -> Result<()> {
    with_repo(pile, |repo| {
        let branch_id = repo
            .ensure_branch(branch, None)
            .map_err(|e| anyhow!("ensure branch '{branch}': {e:?}"))?;
        let relations_branch_id = repo
            .ensure_branch(relations_branch, None)
            .map_err(|e| anyhow!("ensure relations branch: {e:?}"))?;

        let mut status_ws = repo.pull(branch_id).map_err(|e| anyhow!("pull status: {e:?}"))?;
        let status_space = status_ws.checkout(..).map_err(|e| anyhow!("checkout status: {e:?}"))?;
        let latest = latest_per_window(load_status_rows(&status_space));

        let mut rel_ws = repo
            .pull(relations_branch_id)
            .map_err(|e| anyhow!("pull relations: {e:?}"))?;
        let rel_space = rel_ws.checkout(..).map_err(|e| anyhow!("checkout relations: {e:?}"))?;

        if latest.is_empty() {
            println!("No statuses set yet.");
            return Ok(());
        }
        let now = interval_key(epoch_interval(now_epoch()));
        let mut rows: Vec<(String, String, String)> = latest
            .into_values()
            .map(|row| {
                let label = window_label(&mut rel_ws, &rel_space, row.window);
                let text = read_text(&mut status_ws, row.text).unwrap_or_default();
                let age = format_age(now, interval_key(row.at));
                (label, text, age)
            })
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        for (label, text, age) in rows {
            println!("{label}: {text}  ({age} ago)");
        }
        Ok(())
    })
}

fn cmd_show(pile: &Path, branch: &str, relations_branch: &str, window: String, limit: usize) -> Result<()> {
    with_repo(pile, |repo| {
        let branch_id = repo
            .ensure_branch(branch, None)
            .map_err(|e| anyhow!("ensure branch '{branch}': {e:?}"))?;
        let relations_branch_id = repo
            .ensure_branch(relations_branch, None)
            .map_err(|e| anyhow!("ensure relations branch: {e:?}"))?;
        let window_id = resolve_window_id(repo, relations_branch_id, &window)?;

        let mut status_ws = repo.pull(branch_id).map_err(|e| anyhow!("pull status: {e:?}"))?;
        let status_space = status_ws.checkout(..).map_err(|e| anyhow!("checkout status: {e:?}"))?;
        let mut rel_ws = repo
            .pull(relations_branch_id)
            .map_err(|e| anyhow!("pull relations: {e:?}"))?;
        let rel_space = rel_ws.checkout(..).map_err(|e| anyhow!("checkout relations: {e:?}"))?;
        let label = window_label(&mut rel_ws, &rel_space, window_id);

        let mut rows: Vec<StatusRow> = load_status_rows(&status_space)
            .into_iter()
            .filter(|r| r.window == window_id)
            .collect();
        rows.sort_by(|a, b| interval_key(b.at).cmp(&interval_key(a.at)));

        println!("status for {label} ({})", fmt_id(window_id));
        if rows.is_empty() {
            println!("- (no status set)");
            return Ok(());
        }
        let now = interval_key(epoch_interval(now_epoch()));
        for (i, row) in rows.into_iter().take(limit).enumerate() {
            let text = read_text(&mut status_ws, row.text).unwrap_or_default();
            let age = format_age(now, interval_key(row.at));
            let marker = if i == 0 { "*" } else { " " };
            println!("{marker} {text}  ({age} ago)");
        }
        Ok(())
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Set { text } => cmd_set(
            &cli.pile,
            &cli.branch,
            &cli.relations_branch,
            cli.persona.as_deref(),
            text,
        ),
        Command::List => cmd_list(&cli.pile, &cli.branch, &cli.relations_branch),
        Command::Show { window, limit } => {
            cmd_show(&cli.pile, &cli.branch, &cli.relations_branch, window, limit)
        }
    }
}
