//! `planner` — collection-native calendar and event tracking.
//!
//! Each mutation publishes one immutable fragment into the Planner union
//! collection. Events are UID-derived records; cancellation is a separate
//! monotone assertion rather than a second value for a scalar status field.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use clap::{Parser, Subcommand};
use faculties::clock;
use faculties::legacy_hint::open_scope;
use faculties::planner::{
    self as planner_model, cancellation_fragment, event_facts, event_fragment, note_fragment,
    read_text, EventDraft, EventRow, IntervalValue, PlannerCatalog, STATUS_CANCELLED,
    STATUS_CONFIRMED, TRANSP_OPAQUE,
};
use faculties::schemas::planner::DEFAULT_SCOPE_ID;
use faculties::storage::{load_signer, open_pile_strict};
use hifitime::Epoch;
use rrule::{RRuleSet, Tz};
use triblespace::core::collection::Collection;
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::BlobStore;
use triblespace::prelude::*;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "planner",
    about = "Calendar and event-tracking faculty"
)]
struct Cli {
    /// Path to the pile file.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Add an event manually. Times are ISO 8601 dates or datetimes.
    Add {
        /// Event title (RFC 5545 SUMMARY).
        summary: String,
        /// Start time (ISO 8601 date or datetime).
        #[arg(long)]
        from: String,
        /// End time. Defaults to one hour, or one day for date-only starts.
        #[arg(long)]
        to: Option<String>,
        /// RFC 5545 recurrence rule (for example `FREQ=WEEKLY;BYDAY=MO`).
        #[arg(long)]
        rrule: Option<String>,
        /// Free-text location.
        #[arg(long)]
        location: Option<String>,
        /// `tentative`, `confirmed`, or `cancelled`.
        #[arg(long)]
        status: Option<String>,
        /// `opaque` (default) or `transparent`.
        #[arg(long)]
        transp: Option<String>,
        /// Long-form description. Use @path or @-.
        #[arg(long)]
        description: Option<String>,
        /// Initial note body. Use @path or @-.
        #[arg(long)]
        note: Option<String>,
    },
    /// List events overlapping a window (defaults to all events).
    List {
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
        /// Include cancelled events.
        #[arg(long)]
        all: bool,
    },
    /// Events overlapping today in the local timezone.
    Today,
    /// Events overlapping the next seven days in the local timezone.
    Week,
    /// Next upcoming event.
    Next,
    /// Attach an immutable note to an event.
    Note {
        /// Event id or unambiguous hex prefix.
        id: String,
        /// Note body. Use @path or @-.
        text: String,
    },
    /// Show an event and its notes.
    Show {
        /// Event id or unambiguous hex prefix.
        id: String,
    },
    /// Assert monotonically that an event is cancelled.
    Cancel {
        /// Event id or unambiguous hex prefix.
        id: String,
    },
    /// Resolve an event-id prefix.
    Resolve { prefix: String },
    /// Ingest one or more iCalendar files atomically.
    Ingest { files: Vec<PathBuf> },
}

#[derive(Clone, Copy)]
struct PlannerStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

struct LoadedPlanner {
    facts: TribleSet,
    reader: PileReader,
    catalog: PlannerCatalog,
}

impl PlannerStorage<'_> {
    fn with_collection<T>(
        &self,
        operation: impl FnOnce(&mut Collection<Pile>, &LoadedPlanner) -> Result<T>,
    ) -> Result<T> {
        let signer = load_signer(self.pile, self.key)?;
        let pile = open_pile_strict(self.pile)?;
        let mut collection = open_scope(pile, DEFAULT_SCOPE_ID, signer);
        let result = (|| {
            let facts = collection
                .materialize()
                .context("materialize Planner collection")?;
            let reader = collection
                .storage_mut()
                .reader()
                .context("open Planner blob reader")?;
            let catalog = planner_model::validate_catalog(&reader, &facts)
                .context("validate Planner collection")?;
            let loaded = LoadedPlanner {
                facts,
                reader,
                catalog,
            };
            operation(&mut collection, &loaded)
        })();
        finish_pile(collection.into_storage(), result)
    }

    fn with_view<T>(&self, operation: impl FnOnce(&LoadedPlanner) -> Result<T>) -> Result<T> {
        self.with_collection(|_, loaded| operation(loaded))
    }

    fn update<T>(
        &self,
        description: &'static str,
        operation: impl FnOnce(&LoadedPlanner) -> Result<(Option<Fragment>, T)>,
    ) -> Result<T> {
        self.with_collection(|collection, loaded| {
            let (fragment, value) = operation(loaded)?;
            if let Some(mut fragment) = fragment {
                planner_model::validate_candidate(&loaded.reader, &loaded.facts, &fragment)
                    .context("validate Planner mutation")?;
                fragment.describe_with(entity! { metadata::description: description });
                collection
                    .commit(fragment)
                    .context("commit authored Planner fragment")?;
            }
            Ok(value)
        })
    }

    #[cfg(test)]
    fn commit_count(&self) -> Result<usize> {
        let signer = load_signer(self.pile, self.key)?;
        let author = signer.verifying_key().to_bytes();
        let mut pile = open_pile_strict(self.pile)?;
        let team = signer.verifying_key();
        let result =
            faculties::storage::discover_target(&mut pile, DEFAULT_SCOPE_ID, team).map(|target| {
                target
                    .commits()
                    .iter()
                    .filter(|commit| commit.public_key().raw == author)
                    .count()
            });
        finish_pile(pile, result)
    }
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context("close Planner pile")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing Planner pile also failed: {close_error}")))
        }
    }
}

#[cfg(test)]
fn point_interval(epoch: Epoch) -> IntervalValue {
    (epoch, epoch)
        .try_to_inline()
        .expect("an Epoch point is a valid interval")
}

fn epoch_to_chrono_utc(epoch: Epoch) -> Result<DateTime<Utc>> {
    let seconds = epoch.to_unix_seconds();
    if !seconds.is_finite() {
        bail!("Planner timestamp is not finite");
    }
    let whole = seconds.floor();
    if whole < i64::MIN as f64 || whole > i64::MAX as f64 {
        bail!("Planner timestamp is outside the displayable UTC range");
    }
    let nanos = ((seconds - whole) * 1e9).round().clamp(0.0, 999_999_999.0) as u32;
    Utc.timestamp_opt(whole as i64, nanos)
        .single()
        .ok_or_else(|| anyhow!("Planner timestamp is outside the displayable UTC range"))
}

fn chrono_to_epoch(datetime: DateTime<Utc>) -> Epoch {
    Epoch::from_unix_seconds(
        datetime.timestamp() as f64 + datetime.timestamp_subsec_nanos() as f64 * 1e-9,
    )
}

fn make_interval(start: Epoch, end: Epoch) -> IntervalValue {
    (start, end)
        .try_to_inline()
        .expect("ordered Epoch endpoints form an interval")
}

fn unpack_interval(interval: IntervalValue) -> (Epoch, Epoch) {
    interval
        .try_from_inline()
        .expect("validated Planner interval")
}

fn interval_key(interval: IntervalValue) -> i128 {
    let (start, _): (i128, i128) = interval
        .try_from_inline()
        .expect("validated Planner interval");
    start
}

fn parse_iso8601(input: &str) -> Result<DateTime<Utc>> {
    let input = input.trim();
    if let Ok(datetime) = DateTime::parse_from_rfc3339(input) {
        return Ok(datetime.with_timezone(&Utc));
    }
    if let Ok(datetime) = NaiveDateTime::parse_from_str(input, "%Y-%m-%dT%H:%M:%S") {
        return Ok(Utc.from_utc_datetime(&datetime));
    }
    if let Ok(datetime) = NaiveDateTime::parse_from_str(input, "%Y-%m-%dT%H:%M") {
        return Ok(Utc.from_utc_datetime(&datetime));
    }
    if let Ok(date) = NaiveDate::parse_from_str(input, "%Y-%m-%d") {
        return Ok(Utc.from_utc_datetime(&date.and_hms_opt(0, 0, 0).expect("midnight exists")));
    }
    bail!("could not parse '{input}' as an ISO 8601 date, local datetime, or RFC 3339 datetime")
}

fn is_date_only(input: &str) -> bool {
    NaiveDate::parse_from_str(input.trim(), "%Y-%m-%d").is_ok()
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn fmt_interval(interval: IntervalValue) -> Result<String> {
    let (start, end) = unpack_interval(interval);
    let start = epoch_to_chrono_utc(start)?;
    let end = epoch_to_chrono_utc(end)?;
    let formatted = if start == end {
        start.format("%Y-%m-%d %H:%M UTC").to_string()
    } else if (end - start).num_seconds() == 86_400
        && start.format("%H:%M:%S").to_string() == "00:00:00"
    {
        start.format("%Y-%m-%d (all day)").to_string()
    } else {
        format!(
            "{} → {}",
            start.format("%Y-%m-%d %H:%M"),
            end.format("%Y-%m-%d %H:%M UTC")
        )
    };
    Ok(formatted)
}

fn resolve_event_id(input: &str, catalog: &PlannerCatalog) -> Result<Id> {
    faculties::resolve_id_prefix(input, catalog.events.keys().copied())
}

fn normalized_status(value: Option<&str>) -> String {
    value.unwrap_or(STATUS_CONFIRMED).to_ascii_uppercase()
}

fn normalized_transp(value: Option<&str>) -> String {
    value.unwrap_or(TRANSP_OPAQUE).to_ascii_uppercase()
}

fn empty_event_draft(
    uid: String,
    summary: String,
    time: IntervalValue,
    status: String,
    transp: String,
) -> EventDraft {
    EventDraft {
        uid,
        summary,
        description: None,
        time,
        rrule: None,
        rdates: BTreeSet::new(),
        exdates: BTreeSet::new(),
        location: None,
        status,
        transp,
        attendees: BTreeSet::new(),
        organizer: None,
        sequence: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_add(
    storage: PlannerStorage<'_>,
    summary: String,
    from: String,
    to: Option<String>,
    rrule: Option<String>,
    location: Option<String>,
    status: Option<String>,
    transp: Option<String>,
    description: Option<String>,
    note: Option<String>,
) -> Result<()> {
    let start = parse_iso8601(&from)?;
    let end = match to {
        Some(to) => parse_iso8601(&to)?,
        None if is_date_only(&from) => start + chrono::Duration::days(1),
        None => start + chrono::Duration::hours(1),
    };
    if end < start {
        bail!("--to is before --from");
    }
    let description = description
        .map(|value| faculties::text_arg(&value, "description"))
        .transpose()?;
    let note = note
        .map(|value| faculties::text_arg(&value, "note"))
        .transpose()?;

    // The random seed is only the local UID namespace. Once minted, both the
    // UID and event identity are ordinary deterministic content-derived data.
    let uid = format!("{:x}@triblespace", genid().id);
    let mut draft = empty_event_draft(
        uid,
        summary,
        make_interval(chrono_to_epoch(start), chrono_to_epoch(end)),
        normalized_status(status.as_deref()),
        normalized_transp(transp.as_deref()),
    );
    draft.rrule = rrule;
    draft.location = location;
    draft.description = description;

    let mut fragment = event_fragment(&draft)?;
    let event_id = fragment.root().expect("event fragment has one root");
    if let Some(note) = note {
        fragment += note_fragment(event_id, &note, clock::point_now()?)?;
    }
    storage.update("add event", |_| Ok((Some(fragment), ())))?;
    println!("Added event {}", fmt_id(event_id));
    Ok(())
}

struct Occurrence {
    event_id: Id,
    start: Epoch,
    end: Epoch,
    summary: String,
    status: String,
    location: Option<String>,
}

fn rrule_occurrences(row: &EventRow, window: (Epoch, Epoch)) -> Result<Vec<(Epoch, Epoch)>> {
    let (base_start, base_end) = unpack_interval(row.time);
    let duration = base_end - base_start;
    let (window_start, window_end) = window;
    let mut occurrences = Vec::new();

    if let Some(rule) = &row.rrule {
        let dtstart = epoch_to_chrono_utc(base_start)?
            .format("%Y%m%dT%H%M%SZ")
            .to_string();
        let combined = format!("DTSTART:{dtstart}\nRRULE:{rule}");
        let set = combined
            .parse::<RRuleSet>()
            .with_context(|| format!("parse RRULE on event {}", fmt_id(row.id)))?;
        let result = set
            .after(epoch_to_chrono_utc(window_start)?.with_timezone(&Tz::UTC))
            .before(epoch_to_chrono_utc(window_end)?.with_timezone(&Tz::UTC))
            .all(10_000);
        occurrences.extend(result.dates.into_iter().map(|datetime| {
            let start = chrono_to_epoch(datetime.with_timezone(&Utc));
            (start, start + duration)
        }));
    } else {
        occurrences.push((base_start, base_end));
    }
    occurrences.extend(row.rdates.iter().copied().map(unpack_interval));

    let exclusions: BTreeSet<(i128, i128)> = row
        .exdates
        .iter()
        .map(|value| value.try_from_inline().expect("validated EXDATE"))
        .collect();
    occurrences.retain(|(start, end)| {
        let encoded: (i128, i128) = make_interval(*start, *end)
            .try_from_inline()
            .expect("valid occurrence interval");
        !exclusions.contains(&encoded) && !(*end < window_start || *start > window_end)
    });
    occurrences.sort_by_key(|(start, end)| {
        let encoded: (i128, i128) = make_interval(*start, *end)
            .try_from_inline()
            .expect("valid occurrence interval");
        encoded
    });
    occurrences.dedup_by_key(|(start, end)| {
        let encoded: (i128, i128) = make_interval(*start, *end)
            .try_from_inline()
            .expect("valid occurrence interval");
        encoded
    });
    Ok(occurrences)
}

fn collect_occurrences(
    catalog: &PlannerCatalog,
    window: (Epoch, Epoch),
    show_cancelled: bool,
) -> Result<Vec<Occurrence>> {
    let mut occurrences = Vec::new();
    for row in catalog.events.values() {
        let cancelled = catalog.is_cancelled(row.id);
        if cancelled && !show_cancelled {
            continue;
        }
        for (start, end) in rrule_occurrences(row, window)? {
            occurrences.push(Occurrence {
                event_id: row.id,
                start,
                end,
                summary: row.summary.clone(),
                status: if cancelled {
                    STATUS_CANCELLED.to_owned()
                } else {
                    row.status.clone()
                },
                location: row.location.clone(),
            });
        }
    }
    occurrences.sort_by_key(|occurrence| {
        (
            make_interval(occurrence.start, occurrence.end).raw,
            occurrence.event_id,
        )
    });
    Ok(occurrences)
}

fn print_occurrences(occurrences: &[Occurrence]) -> Result<()> {
    if occurrences.is_empty() {
        println!("(no events)");
        return Ok(());
    }
    for occurrence in occurrences {
        let start = epoch_to_chrono_utc(occurrence.start)?;
        let end = epoch_to_chrono_utc(occurrence.end)?;
        let time = if (end - start).num_seconds() == 86_400
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
            &fmt_id(occurrence.event_id)[..8],
            time,
            occurrence.summary
        );
        if let Some(location) = &occurrence.location {
            line.push_str(&format!("  @ {location}"));
        }
        if occurrence.status != STATUS_CONFIRMED {
            line.push_str(&format!("  [{}]", occurrence.status));
        }
        println!("{line}");
    }
    Ok(())
}

fn cmd_list(
    storage: PlannerStorage<'_>,
    from: Option<String>,
    to: Option<String>,
    show_cancelled: bool,
) -> Result<()> {
    let start = from
        .map(|value| parse_iso8601(&value))
        .transpose()?
        .map(chrono_to_epoch)
        .unwrap_or_else(|| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0));
    let end = to
        .map(|value| parse_iso8601(&value))
        .transpose()?
        .map(chrono_to_epoch)
        .unwrap_or_else(|| Epoch::from_gregorian_utc(2100, 1, 1, 0, 0, 0, 0));
    storage.with_view(|loaded| {
        print_occurrences(&collect_occurrences(
            &loaded.catalog,
            (start, end),
            show_cancelled,
        )?)?;
        Ok(())
    })
}

fn local_day_window(days: i64) -> Result<(Epoch, Epoch)> {
    let timezone = chrono::Local;
    let now = epoch_to_chrono_utc(clock::now()?)?.with_timezone(&timezone);
    let start = now
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("midnight exists");
    let end = start + chrono::Duration::days(days);
    let start = timezone
        .from_local_datetime(&start)
        .single()
        .ok_or_else(|| anyhow!("local start-of-day is ambiguous or unavailable"))?;
    let end = timezone
        .from_local_datetime(&end)
        .single()
        .ok_or_else(|| anyhow!("local end-of-day is ambiguous or unavailable"))?;
    Ok((
        chrono_to_epoch(start.with_timezone(&Utc)),
        chrono_to_epoch(end.with_timezone(&Utc)),
    ))
}

fn cmd_relative(storage: PlannerStorage<'_>, days: i64) -> Result<()> {
    let window = local_day_window(days)?;
    storage.with_view(|loaded| {
        print_occurrences(&collect_occurrences(&loaded.catalog, window, false)?)?;
        Ok(())
    })
}

fn cmd_next(storage: PlannerStorage<'_>) -> Result<()> {
    let now = clock::now()?;
    let far = Epoch::from_gregorian_utc(2100, 1, 1, 0, 0, 0, 0);
    storage.with_view(|loaded| {
        let occurrences = collect_occurrences(&loaded.catalog, (now, far), false)?;
        let next: Vec<_> = occurrences
            .into_iter()
            .filter(|occurrence| occurrence.end >= now)
            .take(1)
            .collect();
        print_occurrences(&next)?;
        Ok(())
    })
}

fn cmd_note(storage: PlannerStorage<'_>, id: String, text: String) -> Result<()> {
    let text = faculties::text_arg(&text, "note")?;
    let event_id = storage.update("add event note", |loaded| {
        let event_id = resolve_event_id(&id, &loaded.catalog)?;
        let fragment = note_fragment(event_id, &text, clock::point_now()?)?;
        Ok((Some(fragment), event_id))
    })?;
    println!("Added note to event {}", fmt_id(event_id));
    Ok(())
}

fn cmd_show(storage: PlannerStorage<'_>, id: String) -> Result<()> {
    storage.with_view(|loaded| {
        let event_id = resolve_event_id(&id, &loaded.catalog)?;
        let row = &loaded.catalog.events[&event_id];
        println!("event {}  {}", fmt_id(event_id), row.summary);
        println!("  time:     {}", fmt_interval(row.time)?);
        if let Some(location) = &row.location {
            println!("  location: {location}");
        }
        let status = if loaded.catalog.is_cancelled(event_id) {
            STATUS_CANCELLED
        } else {
            &row.status
        };
        if status != STATUS_CONFIRMED {
            println!("  status:   {status}");
        }
        if let Some(rrule) = &row.rrule {
            println!("  rrule:    {rrule}");
        }
        println!("  uid:      {}", read_text(&loaded.reader, row.uid)?);
        if let Some(description) = row.description {
            println!("  ----");
            for line in read_text(&loaded.reader, description)?.lines() {
                println!("  {line}");
            }
        }

        let mut notes: Vec<_> = loaded.catalog.notes_for(event_id).copied().collect();
        notes.sort_by_key(|row| (interval_key(row.created_at), row.id));
        if !notes.is_empty() {
            println!("  notes:");
            for note in notes {
                let when = unpack_interval(note.created_at).0;
                let when = epoch_to_chrono_utc(when)?.format("%Y-%m-%d %H:%M UTC");
                println!("  - [{when}] {}", read_text(&loaded.reader, note.text)?);
            }
        }
        Ok(())
    })
}

fn cmd_cancel(storage: PlannerStorage<'_>, id: String) -> Result<()> {
    let (event_id, already_cancelled) = storage.update("cancel event", |loaded| {
        let event_id = resolve_event_id(&id, &loaded.catalog)?;
        if loaded.catalog.is_cancelled(event_id) {
            return Ok((None, (event_id, true)));
        }
        Ok((Some(cancellation_fragment(event_id)), (event_id, false)))
    })?;
    if already_cancelled {
        println!("Event {} is already cancelled", fmt_id(event_id));
    } else {
        println!("Cancelled event {}", fmt_id(event_id));
    }
    Ok(())
}

fn cmd_resolve(storage: PlannerStorage<'_>, prefix: String) -> Result<()> {
    storage.with_view(|loaded| {
        println!("{}", fmt_id(resolve_event_id(&prefix, &loaded.catalog)?));
        Ok(())
    })
}

#[derive(Debug)]
struct IcalEvent {
    uid: String,
    summary: Option<String>,
    description: Option<String>,
    dtstart: DateTime<Utc>,
    dtend: DateTime<Utc>,
    location: Option<String>,
    rrule: Option<String>,
    status: Option<String>,
    transp: Option<String>,
}

fn set_once(slot: &mut Option<String>, field: &str, value: String) -> Result<()> {
    if slot.is_some() {
        bail!("VEVENT has more than one {field} property");
    }
    *slot = Some(value);
    Ok(())
}

fn parse_ical_event(event: &ical::parser::ical::component::IcalEvent) -> Result<IcalEvent> {
    let mut uid = None;
    let mut summary = None;
    let mut description = None;
    let mut dtstart = None;
    let mut dtend = None;
    let mut location = None;
    let mut rrule = None;
    let mut status = None;
    let mut transp = None;
    let mut dtstart_is_date = None;

    for property in &event.properties {
        let value = property.value.clone().unwrap_or_default();
        match property.name.as_str() {
            "UID" => set_once(&mut uid, "UID", value)?,
            "SUMMARY" => set_once(&mut summary, "SUMMARY", value)?,
            "DESCRIPTION" => set_once(&mut description, "DESCRIPTION", value)?,
            "DTSTART" => {
                set_once(&mut dtstart, "DTSTART", value)?;
                let is_date = property.params.as_ref().is_some_and(|params| {
                    params.iter().any(|(name, values)| {
                        name == "VALUE" && values.iter().any(|value| value == "DATE")
                    })
                });
                dtstart_is_date = Some(is_date);
            }
            "DTEND" => set_once(&mut dtend, "DTEND", value)?,
            "LOCATION" => set_once(&mut location, "LOCATION", value)?,
            "RRULE" => set_once(&mut rrule, "RRULE", value)?,
            "STATUS" => set_once(&mut status, "STATUS", value)?,
            "TRANSP" => set_once(&mut transp, "TRANSP", value)?,
            _ => {}
        }
    }

    let uid = uid.ok_or_else(|| anyhow!("VEVENT missing UID"))?;
    let dtstart_raw = dtstart.ok_or_else(|| anyhow!("VEVENT missing DTSTART"))?;
    let is_date = dtstart_is_date.unwrap_or(false);
    let dtstart = parse_ical_datetime(&dtstart_raw, is_date)?;
    let dtend = match dtend {
        Some(value) => parse_ical_datetime(&value, is_date)?,
        None if is_date => dtstart + chrono::Duration::days(1),
        None => dtstart + chrono::Duration::hours(1),
    };
    if dtend < dtstart {
        bail!("VEVENT DTEND is before DTSTART");
    }

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

fn parse_ical_datetime(input: &str, is_date: bool) -> Result<DateTime<Utc>> {
    let input = input.trim();
    if is_date || input.len() == 8 {
        let date = NaiveDate::parse_from_str(input, "%Y%m%d")
            .with_context(|| format!("parse date '{input}'"))?;
        return Ok(Utc.from_utc_datetime(&date.and_hms_opt(0, 0, 0).expect("midnight exists")));
    }
    if let Some(input) = input.strip_suffix('Z') {
        let datetime = NaiveDateTime::parse_from_str(input, "%Y%m%dT%H%M%S")
            .with_context(|| format!("parse UTC datetime '{input}Z'"))?;
        return Ok(Utc.from_utc_datetime(&datetime));
    }
    let datetime = NaiveDateTime::parse_from_str(input, "%Y%m%dT%H%M%S")
        .with_context(|| format!("parse floating datetime '{input}'"))?;
    Ok(Utc.from_utc_datetime(&datetime))
}

fn truncate_short(value: &str) -> String {
    let mut value = value.replace('\n', " ");
    while value.len() > 32 {
        value.pop();
    }
    value
}

/// Stage one UID-derived import into a deterministic map. Identical records
/// collapse; same-UID conflicts are an error independent of file order.
fn stage_import_event(
    loaded: &LoadedPlanner,
    staged: &mut BTreeMap<Id, Fragment>,
    uid: &str,
    fragment: Fragment,
) -> Result<bool> {
    let id = fragment.root().expect("event fragment has one root");
    let candidate = event_facts(fragment.facts(), id);
    if loaded.catalog.events.contains_key(&id) {
        if event_facts(&loaded.facts, id) == candidate {
            return Ok(false);
        }
        bail!(
            "iCalendar UID '{uid}' names event {} but its immutable fields differ from the existing event",
            fmt_id(id)
        );
    }
    if let Some(previous) = staged.get(&id) {
        if event_facts(previous.facts(), id) == candidate {
            return Ok(false);
        }
        bail!(
            "iCalendar UID '{uid}' occurs more than once in this batch with conflicting immutable fields"
        );
    }
    staged.insert(id, fragment);
    Ok(true)
}

fn cmd_ingest(storage: PlannerStorage<'_>, files: Vec<PathBuf>) -> Result<()> {
    if files.is_empty() {
        bail!("no files supplied");
    }
    let (imported, total, duplicates) = storage.update("ingest iCalendar events", |loaded| {
        let mut staged = BTreeMap::<Id, Fragment>::new();
        let mut total = 0usize;
        let mut duplicates = 0usize;

        for path in &files {
            let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
            for calendar in ical::IcalParser::new(&bytes[..]) {
                let calendar = calendar.with_context(|| format!("parse {}", path.display()))?;
                for source in calendar.events {
                    total += 1;
                    let source = parse_ical_event(&source)
                        .with_context(|| format!("parse VEVENT in {}", path.display()))?;
                    let mut draft = empty_event_draft(
                        source.uid.clone(),
                        truncate_short(source.summary.as_deref().unwrap_or("(untitled)")),
                        make_interval(
                            chrono_to_epoch(source.dtstart),
                            chrono_to_epoch(source.dtend),
                        ),
                        normalized_status(source.status.as_deref()),
                        normalized_transp(source.transp.as_deref()),
                    );
                    draft.description = source.description;
                    draft.location = source.location.as_deref().map(truncate_short);
                    draft.rrule = source.rrule;
                    let fragment = event_fragment(&draft)?;
                    if !stage_import_event(loaded, &mut staged, &source.uid, fragment)? {
                        duplicates += 1;
                    }
                }
            }
        }

        let imported = staged.len();
        let fragment = if imported == 0 {
            None
        } else {
            let mut fragment = Fragment::empty();
            for event in staged.into_values() {
                fragment += event;
            }
            Some(fragment)
        };
        Ok((fragment, (imported, total, duplicates)))
    })?;
    println!("ingested {imported} of {total} events ({duplicates} exact duplicates skipped)");
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let storage = PlannerStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
    };
    match cli.command.unwrap_or(Command::Today) {
        Command::Add {
            summary,
            from,
            to,
            rrule,
            location,
            status,
            transp,
            description,
            note,
        } => cmd_add(
            storage,
            summary,
            from,
            to,
            rrule,
            location,
            status,
            transp,
            description,
            note,
        ),
        Command::List { from, to, all } => cmd_list(storage, from, to, all),
        Command::Today => cmd_relative(storage, 1),
        Command::Week => cmd_relative(storage, 7),
        Command::Next => cmd_next(storage),
        Command::Note { id, text } => cmd_note(storage, id, text),
        Command::Show { id } => cmd_show(storage, id),
        Command::Cancel { id } => cmd_cancel(storage, id),
        Command::Resolve { prefix } => cmd_resolve(storage, prefix),
        Command::Ingest { files } => cmd_ingest(storage, files),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "faculties-planner-live-{}-{serial}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fresh_storage(directory: &TestDirectory) -> (PathBuf, PathBuf) {
        let pile = directory.0.join("planner.pile");
        let key = directory.0.join("planner.key");
        File::create(&pile).unwrap();
        let signer = faculties::storage::initialize_signer(&pile, Some(&key)).unwrap();
        let mut store = open_pile_strict(&pile).unwrap();
        faculties::storage::ensure_team_of_one_write_authority(&mut store, &signer).unwrap();
        store.close().unwrap();
        (pile, key)
    }

    fn fixture_draft(uid: &str, summary: &str) -> EventDraft {
        empty_event_draft(
            uid.to_owned(),
            summary.to_owned(),
            make_interval(
                Epoch::from_unix_seconds(10.0),
                Epoch::from_unix_seconds(20.0),
            ),
            STATUS_CONFIRMED.to_owned(),
            TRANSP_OPAQUE.to_owned(),
        )
    }

    #[test]
    fn event_and_initial_note_publish_as_one_signed_mutation() {
        let directory = TestDirectory::new();
        let (pile, key) = fresh_storage(&directory);
        let storage = PlannerStorage {
            pile: &pile,
            key: Some(&key),
        };
        let mut fragment = event_fragment(&fixture_draft("one@example", "meeting")).unwrap();
        let event = fragment.root().unwrap();
        fragment += note_fragment(
            event,
            "agenda",
            point_interval(Epoch::from_unix_seconds(30.0)),
        )
        .unwrap();
        storage
            .update("add event", |_| Ok((Some(fragment), ())))
            .unwrap();

        assert_eq!(storage.commit_count().unwrap(), 1);
        storage
            .with_view(|loaded| {
                assert_eq!(loaded.catalog.events.len(), 1);
                assert_eq!(loaded.catalog.notes.len(), 1);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn same_batch_duplicate_uid_collapses_but_conflict_is_rejected() {
        let directory = TestDirectory::new();
        let (pile, key) = fresh_storage(&directory);
        let storage = PlannerStorage {
            pile: &pile,
            key: Some(&key),
        };
        storage
            .with_view(|loaded| {
                let mut staged = BTreeMap::new();
                let first = event_fragment(&fixture_draft("duplicate@example", "same")).unwrap();
                let duplicate =
                    event_fragment(&fixture_draft("duplicate@example", "same")).unwrap();
                let conflict =
                    event_fragment(&fixture_draft("duplicate@example", "different")).unwrap();

                assert!(
                    stage_import_event(loaded, &mut staged, "duplicate@example", first).unwrap()
                );
                assert!(
                    !stage_import_event(loaded, &mut staged, "duplicate@example", duplicate)
                        .unwrap()
                );
                let error = stage_import_event(loaded, &mut staged, "duplicate@example", conflict)
                    .unwrap_err();
                assert!(format!("{error:#}").contains("conflicting immutable fields"));
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn duplicate_scalar_ical_property_is_rejected() {
        let bytes = b"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:a@example\r\nUID:b@example\r\nDTSTART:20260809T120000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let calendars: Vec<_> = ical::IcalParser::new(&bytes[..]).collect();
        let calendar: Vec<_> = calendars
            .into_iter()
            .map(|calendar| calendar.unwrap())
            .collect();
        let error = parse_ical_event(&calendar[0].events[0]).unwrap_err();
        assert!(format!("{error:#}").contains("more than one UID"));
    }

    #[test]
    fn exact_reingest_does_not_publish_another_commit() {
        let directory = TestDirectory::new();
        let (pile, key) = fresh_storage(&directory);
        let ics = directory.0.join("event.ics");
        fs::write(
            &ics,
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:stable@example\r\nSUMMARY:Stable\r\nDTSTART:20260809T120000Z\r\nDTEND:20260809T130000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        )
        .unwrap();
        let storage = PlannerStorage {
            pile: &pile,
            key: Some(&key),
        };

        cmd_ingest(storage, vec![ics.clone()]).unwrap();
        let length = fs::metadata(&pile).unwrap().len();
        cmd_ingest(storage, vec![ics]).unwrap();

        assert_eq!(storage.commit_count().unwrap(), 1);
        assert_eq!(fs::metadata(&pile).unwrap().len(), length);
    }

    #[test]
    fn conflicting_same_batch_uid_fails_before_any_signed_commit() {
        let directory = TestDirectory::new();
        let (pile, key) = fresh_storage(&directory);
        let ics = directory.0.join("conflict.ics");
        fs::write(
            &ics,
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:fork@example\r\nSUMMARY:Left\r\nDTSTART:20260809T120000Z\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:fork@example\r\nSUMMARY:Right\r\nDTSTART:20260809T120000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        )
        .unwrap();
        let storage = PlannerStorage {
            pile: &pile,
            key: Some(&key),
        };

        let error = cmd_ingest(storage, vec![ics]).unwrap_err();

        assert!(format!("{error:#}").contains("conflicting immutable fields"));
        assert_eq!(storage.commit_count().unwrap(), 0);
        storage
            .with_view(|loaded| {
                assert!(loaded.catalog.events.is_empty());
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn cancel_adds_one_assertion_without_mutating_baseline_status() {
        let directory = TestDirectory::new();
        let (pile, key) = fresh_storage(&directory);
        let storage = PlannerStorage {
            pile: &pile,
            key: Some(&key),
        };
        let event = event_fragment(&fixture_draft("cancel@example", "meeting")).unwrap();
        let event_id = event.root().unwrap();
        storage
            .update("add event", |_| Ok((Some(event), ())))
            .unwrap();

        cmd_cancel(storage, fmt_id(event_id)).unwrap();
        cmd_cancel(storage, fmt_id(event_id)).unwrap();

        assert_eq!(storage.commit_count().unwrap(), 2);
        storage
            .with_view(|loaded| {
                assert_eq!(loaded.catalog.events[&event_id].status, STATUS_CONFIRMED);
                assert!(loaded.catalog.is_cancelled(event_id));
                assert_eq!(loaded.catalog.cancellations.len(), 1);
                Ok(())
            })
            .unwrap();
    }
}
