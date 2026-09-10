//! Planner operations over resident input and frozen authorized collections.
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crate::clock;
use crate::collection_names::open_configured;
use crate::planner::{
    self as planner_model, cancellation_fragment, event_fragment, note_fragment, read_text,
    EventDraft, EventRow, IntervalValue, TextHandle, STATUS_CANCELLED, STATUS_CONFIRMED,
    STATUS_TENTATIVE, TRANSP_OPAQUE,
};
use crate::schemas::planner::{event, DEFAULT_SCOPE_ID, KIND_EVENT_ID};
use crate::storage::FactArchive;
use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use hifitime::Epoch;
use rrule::{RRuleSet, Tz};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
#[cfg(test)]
use triblespace::core::collection::CollectionSnapshotExt;
use triblespace::core::collection::{Collection, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::SnapshotSource;
use triblespace::prelude::*;

/// Explicit observation window; never a sequence of CLI arguments.
pub type Window = (Epoch, Epoch);
#[derive(Clone, Debug)]
pub struct AddOptions {
    pub summary: String,
    pub start: Epoch,
    pub end: Epoch,
    pub rrule: Option<String>,
    pub location: Option<String>,
    pub status: String,
    pub transp: String,
    pub description: Option<String>,
    pub note: Option<String>,
}
impl AddOptions {
    pub fn new(summary: impl Into<String>, window: Window) -> Self {
        Self {
            summary: summary.into(),
            start: window.0,
            end: window.1,
            rrule: None,
            location: None,
            status: STATUS_CONFIRMED.to_owned(),
            transp: TRANSP_OPAQUE.to_owned(),
            description: None,
            note: None,
        }
    }
    pub fn validate(&self) -> Result<()> {
        validate_window((self.start, self.end))?;
        planner_model::validate_short("event summary", &self.summary)?;
        if let Some(rule) = &self.rrule {
            planner_model::validate_short("event RRULE", rule)?;
        }
        if let Some(location) = &self.location {
            planner_model::validate_short("event location", location)?;
        }
        planner_model::validate_status(&self.status)?;
        planner_model::validate_transp(&self.transp)
    }
}
#[derive(Clone, Debug)]
pub struct AddedEvent {
    pub event: Id,
    pub uid: String,
    pub note: Option<Id>,
}
#[derive(Clone, Copy, Debug)]
pub struct AddedNote {
    pub event: Id,
    pub note: Id,
}
#[derive(Clone, Copy, Debug)]
pub struct CancellationReceipt {
    pub event: Id,
    pub already_cancelled: bool,
}
#[derive(Clone, Debug)]
pub struct NoteDetail {
    pub row: planner_model::NoteRow,
    pub text: String,
}
#[derive(Clone, Debug)]
pub struct EventDetail {
    pub event: EventRow,
    pub uid: String,
    pub description: Option<String>,
    pub cancelled: bool,
    pub notes: Vec<NoteDetail>,
}
/// A resident calendar. The name is diagnostic metadata, never a path to read.
#[derive(Clone, Copy, Debug)]
pub struct CalendarInput<'a> {
    pub name: &'a str,
    pub text: &'a str,
}
#[derive(Clone, Debug)]
pub struct IngestReceipt {
    pub imported: Vec<Id>,
    pub total: usize,
    pub duplicates: usize,
}
#[derive(Clone, Debug)]
pub struct Planner {
    storage: crate::storage::Storage,
}

pub fn validate_window((start, end): Window) -> Result<()> {
    if end < start {
        bail!("window end is before its start");
    }
    Ok(())
}
pub fn default_window() -> Window {
    (
        Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0),
        Epoch::from_gregorian_utc(2100, 1, 1, 0, 0, 0, 0),
    )
}
/// ISO dates and timezone-free datetimes are UTC, matching stored Planner
/// interpretation. A missing end defaults to one day or one hour respectively.
pub fn event_window(from: &str, to: Option<&str>) -> Result<Window> {
    let start = parse_iso8601(from)?;
    let end = match to {
        Some(to) => parse_iso8601(to)?,
        None if is_date_only(from) => start + chrono::Duration::days(1),
        None => start + chrono::Duration::hours(1),
    };
    let window = (chrono_to_epoch(start), chrono_to_epoch(end));
    validate_window(window)?;
    Ok(window)
}
pub fn validate_calendars(documents: &[CalendarInput<'_>]) -> Result<()> {
    if documents.is_empty() {
        bail!("no calendar documents supplied");
    }
    if documents.iter().any(|document| document.name.is_empty()) {
        bail!("calendar document name cannot be empty");
    }
    Ok(())
}

impl Planner {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }
    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self { storage }
    }
    fn storage(&self) -> PlannerStorage<'_> {
        PlannerStorage {
            storage: &self.storage,
        }
    }
    pub fn add(&self, options: &AddOptions) -> Result<AddedEvent> {
        options.validate()?;
        let uid = format!("{:x}@triblespace", genid().id);
        let mut draft = empty_event_draft(
            uid.clone(),
            options.summary.clone(),
            make_interval(options.start, options.end),
            options.status.clone(),
            options.transp.clone(),
        );
        draft.rrule = options.rrule.clone();
        draft.location = options.location.clone();
        draft.description = options.description.clone();
        let mut fragment = event_fragment(&draft)?;
        let event = fragment.root().expect("event fragment has one root");
        let note = if let Some(note) = &options.note {
            let note = note_fragment(event, note, clock::point_now()?)?;
            let id = note.root().expect("note fragment has one root");
            fragment += note;
            Some(id)
        } else {
            None
        };
        self.storage().update("add event", |_| {
            Ok((Some(fragment), AddedEvent { event, uid, note }))
        })
    }
    pub fn list(&self, window: Window, include_cancelled: bool) -> Result<Vec<Occurrence>> {
        validate_window(window)?;
        self.storage().with_view(|loaded| {
            Ok(collect_occurrences(
                &loaded.facts,
                window,
                include_cancelled,
            ))
        })
    }
    /// Next occurrence overlapping [after, 2100-01-01]; None means capture now.
    pub fn next(&self, after: Option<Epoch>) -> Result<Option<Occurrence>> {
        let start = match after {
            Some(start) => start,
            None => clock::now()?,
        };
        let window = (start, default_window().1);
        validate_window(window)?;
        self.storage()
            .with_view(|loaded| Ok(next_occurrence(&loaded.facts, window)))
    }
    pub fn note(&self, id: &str, text: &str) -> Result<AddedNote> {
        self.storage().update("add event note", |loaded| {
            let event = resolve_event_id(id, &loaded.facts)?;
            let fragment = note_fragment(event, text, clock::point_now()?)?;
            let note = fragment.root().expect("note fragment has one root");
            Ok((Some(fragment), AddedNote { event, note }))
        })
    }
    pub fn show(&self, id: &str) -> Result<EventDetail> {
        self.storage().with_view(|loaded| {
            let event_id = resolve_event_id(id, &loaded.facts)?;
            let event = planner_model::event(&loaded.facts, event_id).ok_or_else(|| {
                anyhow!(
                    "event {} has no readable Planner projection",
                    fmt_id(event_id)
                )
            })?;
            let uid = read_text(&loaded.reader, event.uid)?;
            let description = event
                .description
                .map(|handle| read_text(&loaded.reader, handle))
                .transpose()?;
            let cancelled = planner_model::event_is_cancelled(&loaded.facts, event_id);
            let mut notes = planner_model::notes_for_event(&loaded.facts, event_id);
            notes.sort_by_key(|row| (interval_key(row.created_at), row.id));
            let notes = notes
                .into_iter()
                .map(|row| {
                    Ok(NoteDetail {
                        text: read_text(&loaded.reader, row.text)?,
                        row,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(EventDetail {
                event,
                uid,
                description,
                cancelled,
                notes,
            })
        })
    }
    pub fn cancel(&self, id: &str) -> Result<CancellationReceipt> {
        cancel(self.storage(), id)
    }
    pub fn resolve(&self, prefix: &str) -> Result<Id> {
        self.storage()
            .with_view(|loaded| resolve_event_id(prefix, &loaded.facts))
    }
    /// All resident calendars are staged before one publication. Exact
    /// duplicates are skipped; conflicting immutable definitions never replace
    /// an existing UID, including when a source offers a different SEQUENCE.
    pub fn ingest(&self, documents: &[CalendarInput<'_>]) -> Result<IngestReceipt> {
        ingest(self.storage(), documents)
    }
}
fn cancel(storage: PlannerStorage<'_>, id: &str) -> Result<CancellationReceipt> {
    storage.update("cancel event", |loaded| {
        let event = resolve_event_id(id, &loaded.facts)?;
        if planner_model::event_is_cancelled(&loaded.facts, event) {
            return Ok((
                None,
                CancellationReceipt {
                    event,
                    already_cancelled: true,
                },
            ));
        }
        Ok((
            Some(cancellation_fragment(event)),
            CancellationReceipt {
                event,
                already_cancelled: false,
            },
        ))
    })
}
#[derive(Clone, Copy)]
struct PlannerStorage<'a> {
    storage: &'a crate::storage::Storage,
}

struct LoadedPlanner {
    facts: FactArchive,
    reader: PileSnapshot,
}

impl PlannerStorage<'_> {
    fn with_store<T>(
        &self,
        operation: impl FnOnce(
            &mut Pile,
            Collection<SimpleArchive>,
            &ed25519_dalek::SigningKey,
            &LoadedPlanner,
        ) -> Result<T>,
    ) -> Result<T> {
        self.storage.with_pile(|pile, signer| {
            let result = (|| {
                let source = open_configured(pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
                let descriptor_snapshot = pile.snapshot()?;
                let policy = source.policy(&descriptor_snapshot)?;
                drop(descriptor_snapshot);
                let collection_succinct =
                    pile.derive::<SuccinctArchiveBlob>(source, (), policy.clone())?;
                let collection_rank9 = pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(
                    collection_succinct,
                    (),
                    policy,
                )?;
                let store_snapshot = pollster::block_on(async {
                    drop(pile.ensure(source).await?);
                    drop(pile.maintain(collection_succinct).await?);
                    pile.maintain(collection_rank9).await
                })
                .context("maintain Planner fact collection")?;
                let facts = store_snapshot
                    .collection(collection_rank9)
                    .context("observe maintained Planner fact collection")?
                    .view::<FactArchive>()
                    .context("attach maintained Planner fact collection")?;
                let loaded = LoadedPlanner {
                    facts,
                    reader: store_snapshot,
                };
                operation(pile, source, signer, &loaded)
            })();
            result
        })
    }

    fn with_view<T>(&self, operation: impl FnOnce(&LoadedPlanner) -> Result<T>) -> Result<T> {
        self.with_store(|_, _, _, loaded| operation(loaded))
    }

    fn update<T>(
        &self,
        description: &'static str,
        operation: impl FnOnce(&LoadedPlanner) -> Result<(Option<Fragment>, T)>,
    ) -> Result<T> {
        self.with_store(|pile, collection, signer, loaded| {
            let (fragment, value) = operation(loaded)?;
            if let Some(mut fragment) = fragment {
                fragment.describe_with(entity! { metadata::description: description });
                pile.commit(collection, signer, fragment)
                    .context("commit authored Planner fragment")?;
            }
            Ok(value)
        })
    }

    #[cfg(test)]
    fn commit_count(&self) -> Result<usize> {
        self.storage.with_pile(|pile, signer| {
            let author = signer.verifying_key().to_bytes();
            let result = (|| {
                let collection = open_configured(pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
                let store_snapshot = pile.snapshot()?;
                let cover = collection.admitted(&store_snapshot)?;
                Ok(cover
                    .commits(&store_snapshot)?
                    .iter()
                    .filter(|commit| commit.public_key().raw == author)
                    .count())
            })();
            result
        })
    }
}

#[cfg(test)]
fn point_interval(epoch: Epoch) -> IntervalValue {
    (epoch, epoch)
        .try_to_inline()
        .expect("an Epoch point is a valid interval")
}

pub(super) fn epoch_to_chrono_utc(epoch: Epoch) -> Result<DateTime<Utc>> {
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

pub fn chrono_to_epoch(datetime: DateTime<Utc>) -> Epoch {
    Epoch::from_unix_seconds(
        datetime.timestamp() as f64 + datetime.timestamp_subsec_nanos() as f64 * 1e-9,
    )
}

fn make_interval(start: Epoch, end: Epoch) -> IntervalValue {
    (start, end)
        .try_to_inline()
        .expect("ordered Epoch endpoints form an interval")
}

pub(super) fn unpack_interval(interval: IntervalValue) -> (Epoch, Epoch) {
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

pub fn parse_iso8601(input: &str) -> Result<DateTime<Utc>> {
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

pub fn is_date_only(input: &str) -> bool {
    NaiveDate::parse_from_str(input.trim(), "%Y-%m-%d").is_ok()
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

pub(super) fn fmt_interval(interval: IntervalValue) -> Result<String> {
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

fn resolve_event_id<P: TriblePattern + ?Sized>(input: &str, facts: &P) -> Result<Id> {
    crate::resolve_id_prefix(input, planner_model::event_ids(facts))
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

#[derive(Clone, Debug)]
pub struct Occurrence {
    pub event_id: Id,
    pub start: Epoch,
    pub end: Epoch,
    pub summary: String,
    pub status: String,
    pub location: Option<String>,
}

type EpochInterval = (Epoch, Epoch);

/// The fields this command needs from one event. This is deliberately not a
/// collection-wide read model: it lives only while that event's occurrences
/// are derived.
struct OccurrenceEvent {
    id: Id,
    summary: String,
    time: EpochInterval,
    rrule: Option<String>,
    rdates: Vec<EpochInterval>,
    exdates: Vec<EpochInterval>,
    location: Option<String>,
    status: String,
}

fn occurrence_event<P>(space: &P, id: Id) -> Option<OccurrenceEvent>
where
    P: TriblePattern + ?Sized,
{
    find!(
        (
            summary: String,
            time: EpochInterval,
            status: String,
        ),
        pattern!(space, [{ id @
            metadata::tag: &KIND_EVENT_ID,
            event::summary: ?summary,
            event::time: ?time,
            event::status: ?status,
        }])
    )
    .find_map(|(summary, time, status)| {
        if !matches!(
            status.as_str(),
            STATUS_CONFIRMED | STATUS_TENTATIVE | STATUS_CANCELLED
        ) || epoch_to_chrono_utc(time.0).is_err()
            || epoch_to_chrono_utc(time.1).is_err()
        {
            return None;
        }
        let rdates: Vec<EpochInterval> = find!(
            value: EpochInterval,
            pattern!(space, [{ id @ event::rdate: ?value }])
        )
        .filter(|(start, end)| {
            epoch_to_chrono_utc(*start).is_ok() && epoch_to_chrono_utc(*end).is_ok()
        })
        .collect();
        let exdates: Vec<EpochInterval> = find!(
            value: EpochInterval,
            pattern!(space, [{ id @ event::exdate: ?value }])
        )
        .filter(|(start, end)| {
            epoch_to_chrono_utc(*start).is_ok() && epoch_to_chrono_utc(*end).is_ok()
        })
        .collect();
        Some(OccurrenceEvent {
            id,
            summary,
            time,
            rrule: find!(
                value: String,
                pattern!(space, [{ id @ event::rrule: ?value }])
            )
            .next(),
            rdates,
            exdates,
            location: find!(
                value: String,
                pattern!(space, [{ id @ event::location: ?value }])
            )
            .next(),
            status,
        })
    })
}

fn interval_raw((start, end): EpochInterval) -> [u8; 32] {
    make_interval(start, end).raw
}

fn is_excluded(row: &OccurrenceEvent, interval: EpochInterval) -> bool {
    let interval = interval_raw(interval);
    row.exdates
        .iter()
        .any(|excluded| interval_raw(*excluded) == interval)
}

fn overlaps((start, end): EpochInterval, (window_start, window_end): EpochInterval) -> bool {
    !(end < window_start || start > window_end)
}

fn recurrence_set(row: &OccurrenceEvent) -> Option<RRuleSet> {
    let rule = row.rrule.as_ref()?;
    let (base_start, base_end) = row.time;
    let duration = base_end - base_start;
    let dtstart = epoch_to_chrono_utc(base_start)
        .ok()?
        .format("%Y%m%dT%H%M%SZ")
        .to_string();
    let combined = format!("DTSTART:{dtstart}\nRRULE:{rule}");
    let mut set = combined.parse::<RRuleSet>().ok()?;

    // Let `all(1)` step past exact exclusions for `next`. Recurrence DTSTARTs
    // are serialized at whole-second precision above, so only equivalent
    // whole-second intervals are safe to hand to rrule's timestamp-based
    // EXDATE comparison. The exact interval check remains below as authority.
    for &(start, end) in &row.exdates {
        let start_utc = epoch_to_chrono_utc(start).ok()?;
        if end - start == duration && start_utc.timestamp_subsec_nanos() == 0 {
            set = set.exdate(start_utc.with_timezone(&Tz::UTC));
        }
    }
    Some(set)
}

fn rrule_occurrences(row: &OccurrenceEvent, window: EpochInterval) -> Option<Vec<EpochInterval>> {
    let (base_start, base_end) = row.time;
    let duration = base_end - base_start;
    let (window_start, window_end) = window;
    let mut occurrences = Vec::new();

    if row.rrule.is_some() {
        let result = recurrence_set(row)?
            .after(
                epoch_to_chrono_utc(window_start)
                    .ok()?
                    .with_timezone(&Tz::UTC),
            )
            .before(
                epoch_to_chrono_utc(window_end)
                    .ok()?
                    .with_timezone(&Tz::UTC),
            )
            .all(10_000);
        occurrences.extend(result.dates.into_iter().map(|datetime| {
            let start = chrono_to_epoch(datetime.with_timezone(&Utc));
            (start, start + duration)
        }));
    } else {
        occurrences.push((base_start, base_end));
    }
    occurrences.extend(row.rdates.iter().copied());
    occurrences.retain(|interval| !is_excluded(row, *interval) && overlaps(*interval, window));
    occurrences.sort_by_key(|interval| interval_raw(*interval));
    occurrences.dedup_by_key(|interval| interval_raw(*interval));
    Some(occurrences)
}

fn make_occurrence(
    row: &OccurrenceEvent,
    cancelled: bool,
    (start, end): EpochInterval,
) -> Occurrence {
    Occurrence {
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
    }
}

fn occurrence_key(occurrence: &Occurrence) -> ([u8; 32], Id) {
    (
        interval_raw((occurrence.start, occurrence.end)),
        occurrence.event_id,
    )
}

fn collect_occurrences<P>(space: &P, window: EpochInterval, show_cancelled: bool) -> Vec<Occurrence>
where
    P: TriblePattern + ?Sized,
{
    let mut occurrences = Vec::new();
    for event_id in find!(
        id: Id,
        pattern!(space, [{ ?id @ metadata::tag: &KIND_EVENT_ID }])
    ) {
        let Some(row) = occurrence_event(space, event_id) else {
            continue;
        };
        let cancelled = planner_model::event_is_cancelled(space, row.id);
        if cancelled && !show_cancelled {
            continue;
        }
        let Some(event_occurrences) = rrule_occurrences(&row, window) else {
            continue;
        };
        for interval in event_occurrences {
            occurrences.push(make_occurrence(&row, cancelled, interval));
        }
    }
    occurrences.sort_by_key(occurrence_key);
    occurrences
}

fn next_event_occurrence(row: &OccurrenceEvent, window: EpochInterval) -> Option<EpochInterval> {
    let (window_start, window_end) = window;
    let mut next = if row.rrule.is_some() {
        let (base_start, base_end) = row.time;
        let duration = base_end - base_start;
        recurrence_set(row)?
            .after(
                epoch_to_chrono_utc(window_start)
                    .ok()?
                    .with_timezone(&Tz::UTC),
            )
            .before(
                epoch_to_chrono_utc(window_end)
                    .ok()?
                    .with_timezone(&Tz::UTC),
            )
            .all(1)
            .dates
            .into_iter()
            .next()
            .map(|datetime| {
                let start = chrono_to_epoch(datetime.with_timezone(&Utc));
                (start, start + duration)
            })
    } else {
        Some(row.time)
    }
    .filter(|interval| !is_excluded(row, *interval) && overlaps(*interval, window));

    for &rdate in &row.rdates {
        if is_excluded(row, rdate) || !overlaps(rdate, window) {
            continue;
        }
        if next
            .as_ref()
            .is_none_or(|current| interval_raw(rdate) < interval_raw(*current))
        {
            next = Some(rdate);
        }
    }
    next
}

fn next_occurrence<P>(space: &P, window: EpochInterval) -> Option<Occurrence>
where
    P: TriblePattern + ?Sized,
{
    let mut next = None;
    for event_id in find!(
        id: Id,
        pattern!(space, [{ ?id @ metadata::tag: &KIND_EVENT_ID }])
    ) {
        let Some(row) = occurrence_event(space, event_id) else {
            continue;
        };
        if planner_model::event_is_cancelled(space, row.id) {
            continue;
        }
        let Some(interval) = next_event_occurrence(&row, window) else {
            continue;
        };
        let candidate = make_occurrence(&row, false, interval);
        if next
            .as_ref()
            .is_none_or(|current| occurrence_key(&candidate) < occurrence_key(current))
        {
            next = Some(candidate);
        }
    }
    next
}

pub fn local_day_window(days: i64) -> Result<(Epoch, Epoch)> {
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
    staged: &mut BTreeMap<TextHandle, Fragment>,
    uid: &str,
    fragment: Fragment,
) -> Result<bool> {
    let candidate = planner_model::load_catalog(fragment.facts())?
        .events
        .into_values()
        .next()
        .ok_or_else(|| anyhow!("constructed iCalendar event has no readable projection"))?;
    let existing = planner_model::events_with_uid(&loaded.facts, candidate.uid);
    if !existing.is_empty() {
        if existing
            .iter()
            .any(|existing| same_event_definition(existing, &candidate))
        {
            return Ok(false);
        }
        bail!(
            "iCalendar UID '{uid}' already exists but its immutable fields differ from the imported event"
        );
    }
    if let Some(previous) = staged.get(&candidate.uid) {
        let previous = planner_model::load_catalog(previous.facts())?
            .events
            .into_values()
            .next()
            .ok_or_else(|| anyhow!("staged iCalendar event has no readable projection"))?;
        if same_event_definition(&previous, &candidate) {
            return Ok(false);
        }
        bail!(
            "iCalendar UID '{uid}' occurs more than once in this batch with conflicting immutable fields"
        );
    }
    staged.insert(candidate.uid, fragment);
    Ok(true)
}

fn same_event_definition(left: &EventRow, right: &EventRow) -> bool {
    left.uid == right.uid
        && left.summary == right.summary
        && left.description == right.description
        && left.time == right.time
        && left.rrule == right.rrule
        && left.rdates == right.rdates
        && left.exdates == right.exdates
        && left.location == right.location
        && left.status == right.status
        && left.transp == right.transp
        && left.attendees == right.attendees
        && left.organizer == right.organizer
        && left.sequence == right.sequence
}

fn ingest(storage: PlannerStorage<'_>, documents: &[CalendarInput<'_>]) -> Result<IngestReceipt> {
    validate_calendars(documents)?;
    storage.update("ingest iCalendar events", |loaded| {
        let mut staged = BTreeMap::<TextHandle, Fragment>::new();
        let mut total = 0usize;
        let mut duplicates = 0usize;

        for document in documents {
            for calendar in ical::IcalParser::new(document.text.as_bytes()) {
                let calendar = calendar.with_context(|| format!("parse {}", document.name))?;
                for source in calendar.events {
                    total += 1;
                    let source = parse_ical_event(&source)
                        .with_context(|| format!("parse VEVENT in {}", document.name))?;
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

        let imported = staged
            .values()
            .map(|fragment| fragment.root().expect("event fragment has one root"))
            .collect::<Vec<_>>();
        let fragment = if imported.is_empty() {
            None
        } else {
            let mut fragment = Fragment::empty();
            for event in staged.into_values() {
                fragment += event;
            }
            Some(fragment)
        };
        Ok((
            fragment,
            IngestReceipt {
                imported,
                total,
                duplicates,
            },
        ))
    })
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
