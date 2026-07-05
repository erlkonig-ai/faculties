//! `planner` — calendar / event-tracking faculty.
//!
//! Stores events as RFC 5545 VEVENT-shaped tribles in the pile
//! (see `faculties::schemas::planner`). Manual create/edit, plus
//! `.ics` ingest so meeting invites land directly in the pile
//! without a manual data-entry round-trip.

use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use faculties::schemas::planner::{
    DEFAULT_BRANCH, KIND_EVENT_ID, KIND_NOTE_ID, event, note,
};
use hifitime::Epoch;
use rand_core::OsRng;
use rrule::{RRuleSet, Tz};
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use triblespace::core::metadata;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::prelude::*;

type IntervalValue = Inline<inlineencodings::NsTAIInterval>;
type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;

const STATUS_CONFIRMED: &str = "CONFIRMED";
const STATUS_TENTATIVE: &str = "TENTATIVE";
const STATUS_CANCELLED: &str = "CANCELLED";
const TRANSP_OPAQUE: &str = "OPAQUE";
const TRANSP_TRANSPARENT: &str = "TRANSPARENT";

// ── CLI ───────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, name = "planner", about = "Calendar / event-tracking faculty")]
struct Cli {
    /// Path to the pile file
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Branch name for the planner state
    #[arg(long, default_value = DEFAULT_BRANCH)]
    branch: String,
    /// Branch id for the planner (hex). Overrides `--branch`.
    #[arg(long)]
    branch_id: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Add an event manually. Times are ISO 8601 — date (`2026-05-15`),
    /// datetime (`2026-05-15T14:00`), or with TZ (`2026-05-15T14:00:00+02:00`).
    /// All-day events use date-only times and span midnight-to-midnight UTC.
    Add {
        /// Event title (RFC 5545 SUMMARY).
        summary: String,
        /// Start time (ISO 8601 — date or datetime).
        #[arg(long)]
        from: String,
        /// End time. Defaults to a 1-hour interval after `--from` for
        /// timed events and 24h after for date-only events.
        #[arg(long)]
        to: Option<String>,
        /// RFC 5545 recurrence rule (e.g. `FREQ=WEEKLY;BYDAY=MO`).
        #[arg(long)]
        rrule: Option<String>,
        /// Free-text location (room, video link, …).
        #[arg(long)]
        location: Option<String>,
        /// `tentative` / `confirmed` / `cancelled` (default `confirmed`).
        #[arg(long)]
        status: Option<String>,
        /// `opaque` (default — blocks the slot) or `transparent`
        /// (informational, doesn't block).
        #[arg(long)]
        transp: Option<String>,
        /// Long-form description (use `@path` for file input or `@-` for stdin).
        #[arg(long)]
        description: Option<String>,
        /// Initial note body. `@path` / `@-` like other faculties.
        #[arg(long)]
        note: Option<String>,
    },
    /// List events overlapping the given window (defaults to "all").
    List {
        /// Window start (ISO 8601). Default: epoch.
        #[arg(long)]
        from: Option<String>,
        /// Window end (ISO 8601). Default: far future.
        #[arg(long)]
        to: Option<String>,
        /// Show cancelled events too.
        #[arg(long)]
        all: bool,
    },
    /// Events overlapping today (local TZ).
    Today,
    /// Events overlapping the next 7 days (local TZ).
    Week,
    /// Next upcoming event from now.
    Next,
    /// Add a note (free-text context) to an event.
    Note {
        /// Full 32-char hex event id.
        id: String,
        /// Note body. `@path` / `@-` like other faculties.
        text: String,
    },
    /// Show an event with all properties + notes.
    Show {
        /// Full 32-char hex event id.
        id: String,
    },
    /// Cancel an event (sets STATUS=CANCELLED; history-preserving).
    Cancel {
        /// Full 32-char hex event id.
        id: String,
    },
    /// Resolve a hex prefix to a full 32-char event id.
    Resolve {
        prefix: String,
    },
    /// Ingest one or more `.ics` calendar files. Each VEVENT becomes
    /// an event entity (decomposed into tribles); the original UID is
    /// preserved so re-ingesting the same file is idempotent.
    Ingest {
        /// One or more `.ics` files.
        files: Vec<PathBuf>,
    },
}

// ── helpers ───────────────────────────────────────────────────────────────

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn epoch_to_chrono_utc(e: Epoch) -> DateTime<Utc> {
    // hifitime Epoch -> seconds since unix epoch -> chrono UTC
    let secs = e.to_unix_seconds();
    Utc.timestamp_opt(secs as i64, ((secs.fract() * 1e9) as u32).min(999_999_999))
        .single()
        .unwrap_or_else(Utc::now)
}

fn chrono_to_epoch(dt: DateTime<Utc>) -> Epoch {
    Epoch::from_unix_seconds(dt.timestamp() as f64 + dt.timestamp_subsec_nanos() as f64 * 1e-9)
}

fn make_interval(start: Epoch, end: Epoch) -> IntervalValue {
    (start, end).try_to_inline().unwrap()
}

fn unpack_interval(iv: IntervalValue) -> (Epoch, Epoch) {
    iv.try_from_inline().unwrap()
}

/// Parse an ISO 8601 string into a UTC datetime, treating date-only
/// inputs as midnight UTC and datetimes-without-tz as UTC.
fn parse_iso8601(input: &str) -> Result<DateTime<Utc>> {
    let trimmed = input.trim();
    // Datetime with explicit offset (`+02:00`, `Z`).
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Ok(dt.with_timezone(&Utc));
    }
    // Datetime without offset — assume UTC.
    if let Ok(naive) = NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S") {
        return Ok(Utc.from_utc_datetime(&naive));
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M") {
        return Ok(Utc.from_utc_datetime(&naive));
    }
    // Date-only.
    if let Ok(date) = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        let naive = date.and_hms_opt(0, 0, 0).unwrap();
        return Ok(Utc.from_utc_datetime(&naive));
    }
    bail!(
        "could not parse '{}' as ISO 8601 (date `2026-05-15`, datetime `2026-05-15T14:00`, \
         or RFC 3339 `2026-05-15T14:00:00+02:00`)",
        trimmed
    )
}

/// Returns true if the input parses as date-only (no time component).
fn is_date_only(input: &str) -> bool {
    NaiveDate::parse_from_str(input.trim(), "%Y-%m-%d").is_ok()
}

fn fmt_interval(iv: IntervalValue) -> String {
    let (start, end) = unpack_interval(iv);
    let s = epoch_to_chrono_utc(start);
    let e = epoch_to_chrono_utc(end);
    if s == e {
        s.format("%Y-%m-%d %H:%M UTC").to_string()
    } else if (e - s).num_seconds() == 86_400 && s.format("%H:%M:%S").to_string() == "00:00:00" {
        // Single all-day window, render as a date.
        s.format("%Y-%m-%d (all day)").to_string()
    } else {
        format!(
            "{} → {}",
            s.format("%Y-%m-%d %H:%M"),
            e.format("%Y-%m-%d %H:%M UTC")
        )
    }
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn parse_full_id_strict(input: &str) -> Result<Id> {
    let trimmed = input.trim();
    Id::from_hex(trimmed)
        .ok_or_else(|| anyhow::anyhow!("invalid id '{}': expected 32-char hex", trimmed))
}

fn validate_short(label: &str, value: &str) -> Result<()> {
    if value.as_bytes().len() > 32 {
        bail!("{label} exceeds 32 bytes: {value}");
    }
    if value.as_bytes().iter().any(|b| *b == 0) {
        bail!("{label} contains NUL bytes: {value}");
    }
    Ok(())
}

fn load_value_or_file(raw: &str, label: &str) -> Result<String> {
    if let Some(path) = raw.strip_prefix('@') {
        if path == "-" {
            let mut value = String::new();
            std::io::stdin()
                .read_to_string(&mut value)
                .with_context(|| format!("read {label} from stdin"))?;
            return Ok(value);
        }
        return fs::read_to_string(path).with_context(|| format!("read {label} from {path}"));
    }
    Ok(raw.to_string())
}

fn open_repo(path: &Path) -> Result<Repository<Pile>> {
    let mut pile = Pile::open(path)
        .map_err(|e| anyhow::anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.refresh() {
        let _ = pile.close();
        return Err(match err {
            triblespace::core::repo::pile::ReadError::CorruptPile { valid_length } => anyhow::anyhow!(
                "pile corrupt at byte {valid_length}: refusing to auto-repair (a stale binary \
                 could truncate newer data). If, and only if, the tail is a genuinely torn write, truncate it explicitly (DESTRUCTIVE) with: trible pile amputate {}",
                path.display()
            ),
            other => anyhow::anyhow!("refresh pile {}: {other:?}", path.display()),
        });
    }
    let signing_key = SigningKey::generate(&mut OsRng);
    Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|err| anyhow::anyhow!("create repository: {err:?}"))
}

fn with_repo<T>(
    pile: &Path,
    f: impl FnOnce(&mut Repository<Pile>) -> Result<T>,
) -> Result<T> {
    let mut repo = open_repo(pile)?;
    let result = f(&mut repo);
    let close_res = repo
        .close()
        .map_err(|e| anyhow::anyhow!("close pile: {e:?}"));
    if let Err(err) = close_res {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }
    result
}

fn resolve_branch(
    repo: &mut Repository<Pile>,
    branch_name: &str,
    branch_id_hex: Option<&str>,
) -> Result<Id> {
    if let Some(hex) = branch_id_hex {
        return parse_full_id_strict(hex);
    }
    repo.ensure_branch(branch_name, None)
        .map_err(|e| anyhow::anyhow!("ensure branch '{branch_name}': {e:?}"))
}

// ── queries ───────────────────────────────────────────────────────────────

fn all_event_ids(space: &TribleSet) -> Vec<Id> {
    let mut ids: Vec<Id> = find!(
        e: Id,
        pattern!(space, [{ ?e @ metadata::tag: KIND_EVENT_ID }])
    )
    .collect();
    ids.sort();
    ids
}

fn event_summary(_ws: &mut Workspace<Pile>, space: &TribleSet, id: Id) -> String {
    find!(s: String, pattern!(space, [{ id @ event::summary: ?s }]))
        .next()
        .unwrap_or_else(|| "(untitled)".to_string())
}

fn event_time(space: &TribleSet, id: Id) -> Option<IntervalValue> {
    find!(t: IntervalValue, pattern!(space, [{ id @ event::time: ?t }])).next()
}

fn event_status(space: &TribleSet, id: Id) -> String {
    find!(s: String, pattern!(space, [{ id @ event::status: ?s }]))
        .next()
        .unwrap_or_else(|| STATUS_CONFIRMED.to_string())
}

fn event_rrule(space: &TribleSet, id: Id) -> Option<String> {
    find!(r: String, pattern!(space, [{ id @ event::rrule: ?r }])).next()
}

fn event_location(space: &TribleSet, id: Id) -> Option<String> {
    find!(s: String, pattern!(space, [{ id @ event::location: ?s }])).next()
}

fn event_ical_uid(
    ws: &mut Workspace<Pile>,
    space: &TribleSet,
    id: Id,
) -> Option<String> {
    let h: TextHandle = find!(h: TextHandle, pattern!(space, [{ id @ event::ical_uid: ?h }])).next()?;
    read_text(ws, h)
}

fn event_description_handle(space: &TribleSet, id: Id) -> Option<TextHandle> {
    find!(h: TextHandle, pattern!(space, [{ id @ event::description: ?h }])).next()
}

fn read_text(ws: &mut Workspace<Pile>, h: TextHandle) -> Option<String> {
    ws.get::<View<str>, blobencodings::LongString>(h)
        .ok()
        .map(|view| view.to_string())
}

fn resolve_event_id(input: &str, space: &TribleSet) -> Result<Id> {
    faculties::resolve_id_prefix(input, all_event_ids(space))
}

// ── recurrence expansion ──────────────────────────────────────────────────

/// Expand an event's actual occurrences within `[window_start, window_end]`.
/// Returns the per-occurrence `(start, end)` pairs in UTC.
fn occurrences_in_window(
    base: (Epoch, Epoch),
    rrule_str: Option<&str>,
    window: (Epoch, Epoch),
) -> Vec<(Epoch, Epoch)> {
    let (base_start, base_end) = base;
    let duration = base_end - base_start;
    let (win_start, win_end) = window;

    // No RRULE: single occurrence; check overlap with window.
    let Some(rrule) = rrule_str else {
        let overlaps = !(base_end < win_start || base_start > win_end);
        return if overlaps { vec![(base_start, base_end)] } else { vec![] };
    };

    // Build an RRuleSet from `DTSTART:...` + the rule string. The rrule
    // crate parses this combined form. UTC throughout — caller normalizes.
    let dtstart_chrono = epoch_to_chrono_utc(base_start);
    let dtstart_str = dtstart_chrono.format("%Y%m%dT%H%M%SZ").to_string();
    let combined = format!("DTSTART:{dtstart_str}\nRRULE:{rrule}");
    let Ok(set) = combined.parse::<RRuleSet>() else {
        return vec![]; // malformed RRULE — silently skip
    };

    let win_start_chrono = epoch_to_chrono_utc(win_start).with_timezone(&Tz::UTC);
    let win_end_chrono = epoch_to_chrono_utc(win_end).with_timezone(&Tz::UTC);

    let set = set.after(win_start_chrono).before(win_end_chrono);
    let result = set.all(10_000);
    result
        .dates
        .into_iter()
        .map(|dt| {
            let occ_start = chrono_to_epoch(dt.with_timezone(&Utc));
            let occ_end = occ_start + duration;
            (occ_start, occ_end)
        })
        .collect()
}

// ── kind entity (planner branch) ──────────────────────────────────────────

fn ensure_kind_entities(ws: &mut Workspace<Pile>) -> Result<TribleSet> {
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let existing: HashSet<Id> = find!(
        (kind: Id),
        pattern!(&space, [{ ?kind @ metadata::name: _?handle }])
    )
    .map(|(kind,)| kind)
    .collect();
    let mut change = TribleSet::new();
    let label = |id: Id| -> &'static str {
        if id == KIND_EVENT_ID { "planner-event" } else { "planner-note" }
    };
    for kind in [KIND_EVENT_ID, KIND_NOTE_ID] {
        if !existing.contains(&kind) {
            let name = ws.put(label(kind));
            change += entity! { ExclusiveId::force_ref(&kind) @
                metadata::name: name,
            };
        }
    }
    Ok(change)
}

// ── add ───────────────────────────────────────────────────────────────────

fn cmd_add(
    pile: &Path,
    _: &str,
    branch_id: Id,
    summary: String,
    from: String,
    to: Option<String>,
    rrule: Option<String>,
    location: Option<String>,
    status: Option<String>,
    transp: Option<String>,
    description: Option<String>,
    note_text: Option<String>,
) -> Result<()> {
    if summary.as_bytes().len() > 32 {
        bail!("summary exceeds 32 bytes (use --description for long-form text)");
    }
    let from_dt = parse_iso8601(&from)?;
    let date_only = is_date_only(&from);
    let to_dt = if let Some(t) = &to {
        parse_iso8601(t)?
    } else if date_only {
        from_dt + chrono::Duration::days(1)
    } else {
        from_dt + chrono::Duration::hours(1)
    };
    if to_dt < from_dt {
        bail!("--to is before --from");
    }
    let interval = make_interval(chrono_to_epoch(from_dt), chrono_to_epoch(to_dt));

    if let Some(s) = &status {
        let upper = s.to_uppercase();
        if !matches!(upper.as_str(), STATUS_CONFIRMED | STATUS_TENTATIVE | STATUS_CANCELLED) {
            bail!("--status must be one of confirmed/tentative/cancelled");
        }
        validate_short("status", &upper)?;
    }
    if let Some(t) = &transp {
        let upper = t.to_uppercase();
        if !matches!(upper.as_str(), TRANSP_OPAQUE | TRANSP_TRANSPARENT) {
            bail!("--transp must be opaque or transparent");
        }
    }
    if let Some(loc) = &location {
        validate_short("location", loc)?;
    }

    let description_body = description
        .map(|raw| load_value_or_file(&raw, "description"))
        .transpose()?;
    let note_body = note_text
        .map(|raw| load_value_or_file(&raw, "note"))
        .transpose()?;

    let resolved_event_id = with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;

        let event_id = ufoid();
        let event_ref = event_id.id;
        let now = (now_epoch(), now_epoch()).try_to_inline().unwrap();

        let status_str = status.as_deref().map(str::to_uppercase).unwrap_or_else(|| STATUS_CONFIRMED.to_string());
        let transp_str = transp.as_deref().map(str::to_uppercase).unwrap_or_else(|| TRANSP_OPAQUE.to_string());
        let synth_uid = format!("{:x}@triblespace", event_ref);

        let description_handle: Option<TextHandle> =
            description_body.as_deref().map(|d| ws.put(d.to_string()));
        let location_str = location.clone();
        let rrule_str = rrule.clone();
        let uid_handle: TextHandle = ws.put(synth_uid);

        let mut change = TribleSet::new();
        change += ensure_kind_entities(&mut ws)?;
        change += entity! { &event_id @
            metadata::tag: &KIND_EVENT_ID,
            metadata::created_at: now,
            event::summary: summary.as_str(),
            event::time: interval,
            event::status: status_str.as_str(),
            event::transp: transp_str.as_str(),
            event::ical_uid: uid_handle,
            event::description?: description_handle.as_ref(),
            event::location?: location_str.as_deref(),
            event::rrule?: rrule_str.as_deref(),
        };

        if let Some(text) = note_body {
            let note_id = ufoid();
            let text_handle = ws.put(text);
            change += entity! { &note_id @
                metadata::tag: &KIND_NOTE_ID,
                metadata::created_at: now,
                note::note_about: &event_ref,
                note::note_text: text_handle,
            };
        }

        ws.commit(change, "add event");
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push event: {e:?}"))?;
        Ok(event_ref)
    })?;
    println!("Added event {}", fmt_id(resolved_event_id));
    Ok(())
}

// ── list / today / week / next ────────────────────────────────────────────

struct Occurrence {
    event_id: Id,
    start: Epoch,
    end: Epoch,
    summary: String,
    status: String,
    location: Option<String>,
}

fn collect_occurrences(
    ws: &mut Workspace<Pile>,
    space: &TribleSet,
    window: (Epoch, Epoch),
    show_cancelled: bool,
) -> Vec<Occurrence> {
    let mut out = Vec::new();
    for id in all_event_ids(space) {
        let Some(time_iv) = event_time(space, id) else {
            continue;
        };
        let status = event_status(space, id);
        if !show_cancelled && status == STATUS_CANCELLED {
            continue;
        }
        let summary = event_summary(ws, space, id);
        let location = event_location(space, id);
        let rrule = event_rrule(space, id);
        let base = unpack_interval(time_iv);
        let occs = occurrences_in_window(base, rrule.as_deref(), window);
        for (start, end) in occs {
            out.push(Occurrence {
                event_id: id,
                start,
                end,
                summary: summary.clone(),
                status: status.clone(),
                location: location.clone(),
            });
        }
    }
    out.sort_by_key(|o| (o.start.to_tai_seconds() as i128, fmt_id(o.event_id)));
    out
}

fn print_occurrences(occs: &[Occurrence]) {
    if occs.is_empty() {
        println!("(no events)");
        return;
    }
    for occ in occs {
        let start = epoch_to_chrono_utc(occ.start);
        let end = epoch_to_chrono_utc(occ.end);
        let timestr = if (end - start).num_seconds() == 86_400
            && start.format("%H:%M:%S").to_string() == "00:00:00"
        {
            start.format("%Y-%m-%d (all day)     ").to_string()
        } else if start.date_naive() == end.date_naive() {
            format!(
                "{} {}-{}",
                start.format("%Y-%m-%d"),
                start.format("%H:%M"),
                end.format("%H:%M UTC")
            )
        } else {
            format!(
                "{} → {}",
                start.format("%Y-%m-%d %H:%M"),
                end.format("%Y-%m-%d %H:%M UTC")
            )
        };
        let mut line = format!(
            "  {} {} {}",
            &fmt_id(occ.event_id)[..8],
            timestr,
            occ.summary,
        );
        if let Some(loc) = &occ.location {
            line.push_str(&format!("  @ {loc}"));
        }
        if occ.status != STATUS_CONFIRMED {
            line.push_str(&format!("  [{}]", occ.status));
        }
        println!("{line}");
    }
}

fn cmd_list(
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    from: Option<String>,
    to: Option<String>,
    show_cancelled: bool,
) -> Result<()> {
    let win_start = from
        .map(|s| parse_iso8601(&s))
        .transpose()?
        .map(|d| chrono_to_epoch(d))
        .unwrap_or_else(|| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0));
    let win_end = to
        .map(|s| parse_iso8601(&s))
        .transpose()?
        .map(|d| chrono_to_epoch(d))
        .unwrap_or_else(|| Epoch::from_gregorian_utc(2100, 1, 1, 0, 0, 0, 0));

    with_repo(pile, |repo| {
        
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let occs = collect_occurrences(&mut ws, &space, (win_start, win_end), show_cancelled);
        print_occurrences(&occs);
        Ok(())
    })
}

fn cmd_today(pile: &Path, _branch_name: &str, branch_id: Id) -> Result<()> {
    let now = chrono::Local::now();
    let start = now.date_naive().and_hms_opt(0, 0, 0).unwrap();
    let end = start + chrono::Duration::days(1);
    let win_start = chrono_to_epoch(now.timezone().from_local_datetime(&start).unwrap().with_timezone(&Utc));
    let win_end = chrono_to_epoch(now.timezone().from_local_datetime(&end).unwrap().with_timezone(&Utc));

    with_repo(pile, |repo| {
        
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let occs = collect_occurrences(&mut ws, &space, (win_start, win_end), false);
        print_occurrences(&occs);
        Ok(())
    })
}

fn cmd_week(pile: &Path, _branch_name: &str, branch_id: Id) -> Result<()> {
    let now = chrono::Local::now();
    let start = now.date_naive().and_hms_opt(0, 0, 0).unwrap();
    let end = start + chrono::Duration::days(7);
    let win_start = chrono_to_epoch(now.timezone().from_local_datetime(&start).unwrap().with_timezone(&Utc));
    let win_end = chrono_to_epoch(now.timezone().from_local_datetime(&end).unwrap().with_timezone(&Utc));

    with_repo(pile, |repo| {
        
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let occs = collect_occurrences(&mut ws, &space, (win_start, win_end), false);
        print_occurrences(&occs);
        Ok(())
    })
}

fn cmd_next(pile: &Path, _branch_name: &str, branch_id: Id) -> Result<()> {
    let now = now_epoch();
    let far = Epoch::from_gregorian_utc(2100, 1, 1, 0, 0, 0, 0);

    with_repo(pile, |repo| {
        
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let occs = collect_occurrences(&mut ws, &space, (now, far), false);
        let upcoming: Vec<_> = occs.into_iter().filter(|o| o.end >= now).take(1).collect();
        print_occurrences(&upcoming);
        Ok(())
    })
}

// ── note / show / cancel / resolve ────────────────────────────────────────

fn cmd_note(
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    id: String,
    text: String,
) -> Result<()> {
    let body = load_value_or_file(&text, "note")?;
    let event_ref = with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let event_ref = resolve_event_id(&id, &space)?;

        let note_id = ufoid();
        let text_handle = ws.put(body);
        let now = (now_epoch(), now_epoch()).try_to_inline().unwrap();

        let mut change = TribleSet::new();
        change += ensure_kind_entities(&mut ws)?;
        change += entity! { &note_id @
            metadata::tag: &KIND_NOTE_ID,
            metadata::created_at: now,
            note::note_about: &event_ref,
            note::note_text: text_handle,
        };
        ws.commit(change, "add note");
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push note: {e:?}"))?;
        Ok(event_ref)
    })?;
    println!("Added note to event {}", fmt_id(event_ref));
    Ok(())
}

fn cmd_show(
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    id: String,
) -> Result<()> {
    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let event_ref = resolve_event_id(&id, &space)?;

        let summary = event_summary(&mut ws, &space, event_ref);
        println!("event {}  {}", fmt_id(event_ref), summary);

        if let Some(t) = event_time(&space, event_ref) {
            println!("  time:     {}", fmt_interval(t));
        }
        if let Some(loc) = event_location(&space, event_ref) {
            println!("  location: {loc}");
        }
        let status = event_status(&space, event_ref);
        if status != STATUS_CONFIRMED {
            println!("  status:   {status}");
        }
        if let Some(rr) = event_rrule(&space, event_ref) {
            println!("  rrule:    {rr}");
        }
        if let Some(uid) = event_ical_uid(&mut ws, &space, event_ref) {
            println!("  uid:      {uid}");
        }
        if let Some(handle) = event_description_handle(&space, event_ref) {
            if let Some(body) = read_text(&mut ws, handle) {
                println!("  ----");
                for line in body.lines() {
                    println!("  {line}");
                }
            }
        }

        let mut notes: Vec<(IntervalValue, Id)> = find!(
            (created: IntervalValue, n: Id),
            pattern!(&space, [{
                ?n @
                    metadata::tag: KIND_NOTE_ID,
                    metadata::created_at: ?created,
                    note::note_about: event_ref,
            }])
        )
        .collect();
        notes.sort_by_key(|(c, _)| unpack_interval(*c).0.to_tai_seconds() as i128);

        if !notes.is_empty() {
            println!("  notes:");
            for (created, note_id) in notes {
                let when = unpack_interval(created).0;
                let when_str = epoch_to_chrono_utc(when).format("%Y-%m-%d %H:%M UTC");
                let body: Option<TextHandle> = find!(
                    h: TextHandle,
                    pattern!(&space, [{ note_id @ note::note_text: ?h }])
                )
                .next();
                let text = body
                    .and_then(|h| read_text(&mut ws, h))
                    .unwrap_or_else(|| "(missing)".into());
                println!("  - [{when_str}] {text}");
            }
        }

        Ok(())
    })
}

fn cmd_cancel(
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    id: String,
) -> Result<()> {
    let event_ref = with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let event_ref = resolve_event_id(&id, &space)?;
        let mut change = TribleSet::new();
        change += entity! { ExclusiveId::force_ref(&event_ref) @
            event::status: STATUS_CANCELLED,
        };
        ws.commit(change, "cancel event");
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push cancel: {e:?}"))?;
        Ok(event_ref)
    })?;
    println!("Cancelled event {}", fmt_id(event_ref));
    Ok(())
}

fn cmd_resolve(
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    prefix: String,
) -> Result<()> {
    with_repo(pile, |repo| {
        
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let id = resolve_event_id(&prefix, &space)?;
        println!("{}", fmt_id(id));
        Ok(())
    })
}

// ── ingest .ics ───────────────────────────────────────────────────────────

fn cmd_ingest(
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    files: Vec<PathBuf>,
) -> Result<()> {
    if files.is_empty() {
        bail!("no files supplied");
    }
    let mut total = 0usize;
    let mut imported = 0usize;
    let mut skipped_dup = 0usize;

    with_repo(pile, |repo| {
        
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;

        // Collect existing UIDs so re-ingest is idempotent. Each
        // UID lives as a Handle<LongString> so we dereference one
        // blob per known event.
        let uid_handles: Vec<(Id, TextHandle)> = find!(
            (e: Id, h: TextHandle),
            pattern!(&space, [{ ?e @ metadata::tag: KIND_EVENT_ID, event::ical_uid: ?h }])
        )
        .collect();
        let mut existing_uids: HashSet<String> = HashSet::new();
        for (_, h) in &uid_handles {
            if let Some(s) = read_text(&mut ws, *h) {
                existing_uids.insert(s);
            }
        }

        let mut change = TribleSet::new();
        change += ensure_kind_entities(&mut ws)?;

        for path in &files {
            let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
            let reader = ical::IcalParser::new(&bytes[..]);
            for cal in reader {
                let cal = cal.with_context(|| format!("parse {}", path.display()))?;
                for event in cal.events {
                    total += 1;
                    let ievt = parse_ical_event(&event)?;
                    if let Some(uid) = ievt.uid.as_ref() {
                        if existing_uids.contains(uid) {
                            skipped_dup += 1;
                            continue;
                        }
                    }
                    let event_id = ufoid();
                    let now = (now_epoch(), now_epoch()).try_to_inline().unwrap();
                    let interval = make_interval(
                        chrono_to_epoch(ievt.dtstart),
                        chrono_to_epoch(ievt.dtend),
                    );
                    let summary = ievt.summary.clone().unwrap_or_else(|| "(untitled)".into());
                    let summary_short = truncate_for_short(&summary);
                    let description_handle = ievt
                        .description
                        .as_deref()
                        .map(|d| ws.put(d.to_string()));
                    let location_short = ievt.location.as_deref().map(truncate_for_short);
                    let synth_uid = ievt
                        .uid
                        .clone()
                        .unwrap_or_else(|| format!("{:x}@triblespace", event_id.id));
                    let status = ievt.status.clone().unwrap_or_else(|| STATUS_CONFIRMED.into());
                    let transp = ievt.transp.clone().unwrap_or_else(|| TRANSP_OPAQUE.into());
                    let uid_handle: TextHandle = ws.put(synth_uid);

                    change += entity! { &event_id @
                        metadata::tag: &KIND_EVENT_ID,
                        metadata::created_at: now,
                        event::summary: summary_short.as_str(),
                        event::time: interval,
                        event::status: status.as_str(),
                        event::transp: transp.as_str(),
                        event::ical_uid: uid_handle,
                        event::description?: description_handle.as_ref(),
                        event::location?: location_short.as_deref(),
                        event::rrule?: ievt.rrule.as_deref(),
                    };
                    imported += 1;
                }
            }
        }

        ws.commit(change, "ingest .ics");
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push ingest: {e:?}"))?;
        Ok(())
    })?;

    println!(
        "ingested {imported} of {total} events ({skipped_dup} duplicates skipped by UID)"
    );
    Ok(())
}

struct IcalEvent {
    uid: Option<String>,
    summary: Option<String>,
    description: Option<String>,
    dtstart: DateTime<Utc>,
    dtend: DateTime<Utc>,
    location: Option<String>,
    rrule: Option<String>,
    status: Option<String>,
    transp: Option<String>,
}

fn parse_ical_event(event: &ical::parser::ical::component::IcalEvent) -> Result<IcalEvent> {
    let mut uid = None;
    let mut summary = None;
    let mut description = None;
    let mut dtstart_raw = None;
    let mut dtend_raw = None;
    let mut location = None;
    let mut rrule = None;
    let mut status = None;
    let mut transp = None;
    let mut dtstart_is_date = false;

    for prop in &event.properties {
        let value = prop.value.clone().unwrap_or_default();
        match prop.name.as_str() {
            "UID" => uid = Some(value),
            "SUMMARY" => summary = Some(value),
            "DESCRIPTION" => description = Some(value),
            "DTSTART" => {
                dtstart_is_date = prop
                    .params
                    .as_ref()
                    .and_then(|ps| {
                        ps.iter().find(|(k, _)| k == "VALUE").map(|(_, vs)| vs.clone())
                    })
                    .map(|vs| vs.iter().any(|v| v == "DATE"))
                    .unwrap_or(false);
                dtstart_raw = Some(value);
            }
            "DTEND" => dtend_raw = Some(value),
            "LOCATION" => location = Some(value),
            "RRULE" => rrule = Some(value),
            "STATUS" => status = Some(value),
            "TRANSP" => transp = Some(value),
            _ => {}
        }
    }

    let dtstart_str =
        dtstart_raw.ok_or_else(|| anyhow::anyhow!("VEVENT missing DTSTART"))?;
    let dtstart = parse_ical_datetime(&dtstart_str, dtstart_is_date)?;
    let dtend = if let Some(s) = dtend_raw {
        parse_ical_datetime(&s, dtstart_is_date)?
    } else if dtstart_is_date {
        dtstart + chrono::Duration::days(1)
    } else {
        dtstart + chrono::Duration::hours(1)
    };

    Ok(IcalEvent {
        uid,
        summary,
        description,
        dtstart,
        dtend,
        location,
        rrule,
        status,
        transp,
    })
}

/// Parse an RFC 5545 datetime literal: `20260515T140000Z`, `20260515T140000`
/// (floating, treated as UTC), or `20260515` (date-only, midnight UTC).
fn parse_ical_datetime(input: &str, is_date: bool) -> Result<DateTime<Utc>> {
    let input = input.trim();
    if is_date || input.len() == 8 {
        let date = NaiveDate::parse_from_str(input, "%Y%m%d")
            .with_context(|| format!("parse date '{input}'"))?;
        return Ok(Utc.from_utc_datetime(&date.and_hms_opt(0, 0, 0).unwrap()));
    }
    if let Some(stripped) = input.strip_suffix('Z') {
        let dt = NaiveDateTime::parse_from_str(stripped, "%Y%m%dT%H%M%S")
            .with_context(|| format!("parse UTC datetime '{input}'"))?;
        return Ok(Utc.from_utc_datetime(&dt));
    }
    let dt = NaiveDateTime::parse_from_str(input, "%Y%m%dT%H%M%S")
        .with_context(|| format!("parse floating datetime '{input}'"))?;
    Ok(Utc.from_utc_datetime(&dt))
}

fn truncate_for_short(s: &str) -> String {
    let mut out = s.replace('\n', " ");
    while out.as_bytes().len() > 32 {
        out.pop();
    }
    out
}

// ── main ──────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cmd = cli.command.unwrap_or(Command::Today);
    let branch_id_hex = cli.branch_id.as_deref();

    let branch_id = with_repo(&cli.pile, |repo| resolve_branch(repo, &cli.branch, branch_id_hex))?;

    match cmd {
        Command::Add { summary, from, to, rrule, location, status, transp, description, note } => {
            cmd_add(
                &cli.pile, &cli.branch, branch_id,
                summary, from, to, rrule, location, status, transp, description, note,
            )
        }
        Command::List { from, to, all } => {
            cmd_list(&cli.pile, &cli.branch, branch_id, from, to, all)
        }
        Command::Today => cmd_today(&cli.pile, &cli.branch, branch_id),
        Command::Week => cmd_week(&cli.pile, &cli.branch, branch_id),
        Command::Next => cmd_next(&cli.pile, &cli.branch, branch_id),
        Command::Note { id, text } => cmd_note(&cli.pile, &cli.branch, branch_id, id, text),
        Command::Show { id } => cmd_show(&cli.pile, &cli.branch, branch_id, id),
        Command::Cancel { id } => cmd_cancel(&cli.pile, &cli.branch, branch_id, id),
        Command::Resolve { prefix } => cmd_resolve(&cli.pile, &cli.branch, branch_id, prefix),
        Command::Ingest { files } => cmd_ingest(&cli.pile, &cli.branch, branch_id, files),
    }
}
