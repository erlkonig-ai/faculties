//! Canonical Planner records and open-world collection projections.
//!
//! An event is an immutable VEVENT-shaped record whose stable identity is the
//! intrinsic pair `{ KIND_EVENT_ID, event::ical_uid }`.  Local cancellation is
//! a separate intrinsic assertion.  This keeps cancellation monotone: set
//! union can make an event cancelled, but can never accidentally resurrect it
//! by choosing one of several scalar `status` values.
//!
//! Ordinary readers query the maintained fact archive directly and skip rows
//! they cannot decode. Exact identity and fact-set checks remain isolated to
//! explicit migration validation.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::core::repo::{BlobStoreGet, BlobStoreMeta};
use triblespace::prelude::*;

use crate::schemas::planner::{
    cancellation, event, note, KIND_CANCELLATION_ID, KIND_EVENT_ID, KIND_NOTE_ID,
};

pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;
pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;
pub type SequenceValue = Inline<inlineencodings::U256BE>;

pub const STATUS_CONFIRMED: &str = "CONFIRMED";
pub const STATUS_TENTATIVE: &str = "TENTATIVE";
pub const STATUS_CANCELLED: &str = "CANCELLED";
pub const TRANSP_OPAQUE: &str = "OPAQUE";
pub const TRANSP_TRANSPARENT: &str = "TRANSPARENT";

/// Complete immutable input for one canonical Planner event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventDraft {
    pub uid: String,
    pub summary: String,
    pub description: Option<String>,
    pub time: IntervalValue,
    pub rrule: Option<String>,
    pub rdates: BTreeSet<IntervalValue>,
    pub exdates: BTreeSet<IntervalValue>,
    pub location: Option<String>,
    pub status: String,
    pub transp: String,
    pub attendees: BTreeSet<Id>,
    pub organizer: Option<Id>,
    pub sequence: Option<SequenceValue>,
}

/// One exact event projected from a Planner collection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventRow {
    pub id: Id,
    pub uid: TextHandle,
    pub summary: String,
    pub description: Option<TextHandle>,
    pub time: IntervalValue,
    pub rrule: Option<String>,
    pub rdates: BTreeSet<IntervalValue>,
    pub exdates: BTreeSet<IntervalValue>,
    pub location: Option<String>,
    pub status: String,
    pub transp: String,
    pub attendees: BTreeSet<Id>,
    pub organizer: Option<Id>,
    pub sequence: Option<SequenceValue>,
}

/// One intrinsic note attached to an event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoteRow {
    pub id: Id,
    pub event: Id,
    pub text: TextHandle,
    pub created_at: IntervalValue,
}

/// One intrinsic monotone cancellation assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancellationRow {
    pub id: Id,
    pub event: Id,
}

/// Semantic projection of the Planner facts understood by this reader.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PlannerCatalog {
    pub events: BTreeMap<Id, EventRow>,
    pub notes: BTreeMap<Id, NoteRow>,
    pub cancellations: BTreeMap<Id, CancellationRow>,
}

impl PlannerCatalog {
    /// Baseline RFC cancellation or any monotone local cancellation assertion.
    pub fn is_cancelled(&self, event: Id) -> bool {
        self.events
            .get(&event)
            .is_some_and(|row| row.status == STATUS_CANCELLED)
            || self
                .cancellations
                .values()
                .any(|assertion| assertion.event == event)
    }

    pub fn notes_for(&self, event: Id) -> impl Iterator<Item = &NoteRow> {
        self.notes.values().filter(move |row| row.event == event)
    }
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn exactly_one<T>(entity: Id, field: &str, mut values: Vec<T>) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "planner entity {} has {} values for {field}; expected exactly one",
            fmt_id(entity),
            values.len()
        );
    }
    Ok(values.pop().expect("length checked above"))
}

fn at_most_one<T>(entity: Id, field: &str, mut values: Vec<T>) -> Result<Option<T>> {
    if values.len() > 1 {
        bail!(
            "planner entity {} has {} values for {field}; expected at most one",
            fmt_id(entity),
            values.len()
        );
    }
    Ok(values.pop())
}

fn validate_short(field: &str, value: &str) -> Result<()> {
    if value.len() > 32 {
        bail!("{field} exceeds 32 UTF-8 bytes");
    }
    if value.as_bytes().contains(&0) {
        bail!("{field} contains a NUL byte");
    }
    Ok(())
}

fn validate_uid(uid: &str) -> Result<()> {
    if uid.is_empty() {
        bail!("iCalendar UID is empty");
    }
    if uid.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n')) {
        bail!("iCalendar UID contains a forbidden control character");
    }
    Ok(())
}

fn validate_interval(field: &str, interval: IntervalValue) -> Result<()> {
    let (start, end): (i128, i128) = interval
        .try_from_inline()
        .map_err(|error| anyhow!("decode {field}: {error:?}"))?;
    if end < start {
        bail!("{field} ends before it starts");
    }
    Ok(())
}

fn validate_point(field: &str, interval: IntervalValue) -> Result<()> {
    let (start, end): (i128, i128) = interval
        .try_from_inline()
        .map_err(|error| anyhow!("decode {field}: {error:?}"))?;
    if start != end {
        bail!("{field} must be a point interval");
    }
    Ok(())
}

fn validate_status(status: &str) -> Result<()> {
    if !matches!(
        status,
        STATUS_CONFIRMED | STATUS_TENTATIVE | STATUS_CANCELLED
    ) {
        bail!("event status must be CONFIRMED, TENTATIVE, or CANCELLED");
    }
    Ok(())
}

fn validate_transp(transp: &str) -> Result<()> {
    if !matches!(transp, TRANSP_OPAQUE | TRANSP_TRANSPARENT) {
        bail!("event transparency must be OPAQUE or TRANSPARENT");
    }
    Ok(())
}

fn validate_event_values(row: &EventRow) -> Result<()> {
    validate_short("event summary", &row.summary)?;
    validate_interval("event time", row.time)?;
    if let Some(rule) = &row.rrule {
        validate_short("event RRULE", rule)?;
    }
    for interval in &row.rdates {
        validate_interval("event RDATE", *interval)?;
    }
    for interval in &row.exdates {
        validate_interval("event EXDATE", *interval)?;
    }
    if let Some(location) = &row.location {
        validate_short("event location", location)?;
    }
    validate_short("event status", &row.status)?;
    validate_status(&row.status)?;
    validate_short("event transparency", &row.transp)?;
    validate_transp(&row.transp)
}

fn event_identity(uid: TextHandle) -> Fragment {
    entity! {
        metadata::tag: &KIND_EVENT_ID,
        event::ical_uid: uid,
    }
}

#[allow(clippy::too_many_arguments)]
fn event_record(
    uid: TextHandle,
    summary: &str,
    description: Option<TextHandle>,
    time: IntervalValue,
    rrule: Option<&str>,
    rdates: &BTreeSet<IntervalValue>,
    exdates: &BTreeSet<IntervalValue>,
    location: Option<&str>,
    status: &str,
    transp: &str,
    attendees: &BTreeSet<Id>,
    organizer: Option<Id>,
    sequence: Option<SequenceValue>,
) -> Fragment {
    let mut fragment = event_identity(uid);
    let id = fragment
        .root()
        .expect("event identity record has one intrinsic root");
    fragment += entity! { ExclusiveId::force_ref(&id) @
        event::summary: summary,
        event::description?: description.as_ref(),
        event::time: time,
        event::rrule?: rrule,
        event::location?: location,
        event::status: status,
        event::transp: transp,
        event::organizer?: organizer.as_ref(),
        event::sequence?: sequence.as_ref(),
    };
    for value in rdates {
        fragment += entity! { ExclusiveId::force_ref(&id) @ event::rdate: value };
    }
    for value in exdates {
        fragment += entity! { ExclusiveId::force_ref(&id) @ event::exdate: value };
    }
    for attendee in attendees {
        fragment += entity! { ExclusiveId::force_ref(&id) @ event::attendee: attendee };
    }
    fragment
}

fn note_record(event_id: Id, text: TextHandle, created_at: IntervalValue) -> Fragment {
    entity! {
        metadata::tag: &KIND_NOTE_ID,
        metadata::created_at: created_at,
        note::note_about: event_id,
        note::note_text: text,
    }
}

fn cancellation_record(event_id: Id) -> Fragment {
    entity! {
        metadata::tag: &KIND_CANCELLATION_ID,
        cancellation::event: event_id,
    }
}

/// Build one self-contained canonical event fragment.
///
/// The returned root depends only on the exact UID bytes. Repeating an import
/// therefore names the same event even across processes and machines.
pub fn event_fragment(draft: &EventDraft) -> Result<Fragment> {
    validate_uid(&draft.uid)?;
    let mut fragment = Fragment::empty();
    let uid = fragment.put(draft.uid.clone());
    let description = draft
        .description
        .as_ref()
        .map(|description| fragment.put(description.clone()));
    let record = event_record(
        uid,
        &draft.summary,
        description,
        draft.time,
        draft.rrule.as_deref(),
        &draft.rdates,
        &draft.exdates,
        draft.location.as_deref(),
        &draft.status,
        &draft.transp,
        &draft.attendees,
        draft.organizer,
        draft.sequence,
    );
    let row = EventRow {
        id: record.root().expect("event record has one root"),
        uid,
        summary: draft.summary.clone(),
        description,
        time: draft.time,
        rrule: draft.rrule.clone(),
        rdates: draft.rdates.clone(),
        exdates: draft.exdates.clone(),
        location: draft.location.clone(),
        status: draft.status.clone(),
        transp: draft.transp.clone(),
        attendees: draft.attendees.clone(),
        organizer: draft.organizer,
        sequence: draft.sequence,
    };
    validate_event_values(&row)?;
    fragment += record;
    Ok(fragment)
}

/// Build one intrinsic note and carry its text attachment.
pub fn note_fragment(event_id: Id, text: &str, created_at: IntervalValue) -> Result<Fragment> {
    validate_point("note creation time", created_at)?;
    let mut fragment = Fragment::empty();
    let text = fragment.put(text.to_owned());
    fragment += note_record(event_id, text, created_at);
    Ok(fragment)
}

/// Build the unique monotone cancellation assertion for an event.
pub fn cancellation_fragment(event_id: Id) -> Fragment {
    cancellation_record(event_id)
}

fn entity_facts(space: &TribleSet, entity: Id) -> TribleSet {
    let mut facts = TribleSet::new();
    for fact in space.iter().filter(|fact| fact.e() == &entity) {
        facts.insert(fact);
    }
    facts
}

/// Immutable native definition facts asserted about one event.
///
/// Legacy event creation observations and an old scalar cancellation shadowed
/// by the canonical cancellation assertion are excluded. This keeps exact
/// iCalendar replay stable after an additive cutover.
pub fn event_facts(space: &TribleSet, event: Id) -> TribleSet {
    entity_facts(space, event)
        .iter()
        .filter(|fact| !legacy_event_fact_is_inert(space, event, fact))
        .copied()
        .collect()
}

fn canonical_event_entities(space: &TribleSet) -> BTreeSet<Id> {
    find!(
        (entity: Id, uid: TextHandle),
        pattern!(space, [{ ?entity @
            metadata::tag: &KIND_EVENT_ID,
            event::ical_uid: ?uid,
        }])
    )
    .filter_map(|(entity, uid)| (event_identity(uid).root() == Some(entity)).then_some(entity))
    .collect()
}

fn canonical_note_entities(space: &TribleSet) -> BTreeSet<Id> {
    find!(
        (
            entity: Id,
            event_id: Id,
            text: TextHandle,
            created_at: IntervalValue,
        ),
        pattern!(space, [{ ?entity @
            metadata::tag: &KIND_NOTE_ID,
            metadata::created_at: ?created_at,
            note::note_about: ?event_id,
            note::note_text: ?text,
        }])
    )
    .filter_map(|(entity, event_id, text, created_at)| {
        (note_record(event_id, text, created_at).root() == Some(entity)).then_some(entity)
    })
    .collect()
}

fn canonical_cancellation_entities(space: &TribleSet) -> BTreeSet<Id> {
    find!(
        (entity: Id, event_id: Id),
        pattern!(space, [{ ?entity @
            metadata::tag: &KIND_CANCELLATION_ID,
            cancellation::event: ?event_id,
        }])
    )
    .filter_map(|(entity, event_id)| {
        (cancellation_record(event_id).root() == Some(entity)).then_some(entity)
    })
    .collect()
}

fn has_canonical_cancellation(space: &TribleSet, event_id: Id) -> bool {
    let expected = cancellation_record(event_id);
    let present = expected.facts().iter().all(|fact| space.contains(fact));
    present
}

fn legacy_event_fact_is_inert(space: &TribleSet, event_id: Id, fact: &Trible) -> bool {
    if fact.a() == &metadata::created_at.id() {
        return true;
    }
    if fact.a() != &event::status.id() || !has_canonical_cancellation(space, event_id) {
        return false;
    }
    let status_count = find!(
        value: String,
        pattern!(space, [{ event_id @ event::status: ?value }])
    )
    .count();
    status_count > 1
        && (*fact.v::<inlineencodings::ShortString>())
            .try_from_inline::<String>()
            .is_ok_and(|value| value == STATUS_CANCELLED)
}

fn native_event_status(space: &TribleSet, id: Id) -> Result<String> {
    let mut values: Vec<String> = find!(
        value: String,
        pattern!(space, [{ id @ event::status: ?value }])
    )
    .collect();
    if values.len() == 2 && has_canonical_cancellation(space, id) {
        values.retain(|value| value != STATUS_CANCELLED);
    }
    exactly_one(id, "event::status", values)
}

fn load_validated_event(space: &TribleSet, id: Id) -> Result<EventRow> {
    let row = EventRow {
        id,
        uid: exactly_one(
            id,
            "event::ical_uid",
            find!(
                value: TextHandle,
                pattern!(space, [{ id @ event::ical_uid: ?value }])
            )
            .collect(),
        )?,
        summary: exactly_one(
            id,
            "event::summary",
            find!(
                value: String,
                pattern!(space, [{ id @ event::summary: ?value }])
            )
            .collect(),
        )?,
        description: at_most_one(
            id,
            "event::description",
            find!(
                value: TextHandle,
                pattern!(space, [{ id @ event::description: ?value }])
            )
            .collect(),
        )?,
        time: exactly_one(
            id,
            "event::time",
            find!(
                value: IntervalValue,
                pattern!(space, [{ id @ event::time: ?value }])
            )
            .collect(),
        )?,
        rrule: at_most_one(
            id,
            "event::rrule",
            find!(
                value: String,
                pattern!(space, [{ id @ event::rrule: ?value }])
            )
            .collect(),
        )?,
        rdates: find!(
            value: IntervalValue,
            pattern!(space, [{ id @ event::rdate: ?value }])
        )
        .collect(),
        exdates: find!(
            value: IntervalValue,
            pattern!(space, [{ id @ event::exdate: ?value }])
        )
        .collect(),
        location: at_most_one(
            id,
            "event::location",
            find!(
                value: String,
                pattern!(space, [{ id @ event::location: ?value }])
            )
            .collect(),
        )?,
        status: native_event_status(space, id)?,
        transp: exactly_one(
            id,
            "event::transp",
            find!(
                value: String,
                pattern!(space, [{ id @ event::transp: ?value }])
            )
            .collect(),
        )?,
        attendees: find!(
            value: Id,
            pattern!(space, [{ id @ event::attendee: ?value }])
        )
        .collect(),
        organizer: at_most_one(
            id,
            "event::organizer",
            find!(value: Id, pattern!(space, [{ id @ event::organizer: ?value }])).collect(),
        )?,
        sequence: at_most_one(
            id,
            "event::sequence",
            find!(
                value: SequenceValue,
                pattern!(space, [{ id @ event::sequence: ?value }])
            )
            .collect(),
        )?,
    };
    validate_event_values(&row)?;
    let expected = event_record(
        row.uid,
        &row.summary,
        row.description,
        row.time,
        row.rrule.as_deref(),
        &row.rdates,
        &row.exdates,
        row.location.as_deref(),
        &row.status,
        &row.transp,
        &row.attendees,
        row.organizer,
        row.sequence,
    );
    let canonical = expected
        .root()
        .expect("canonical event record has one root");
    if canonical != id {
        bail!(
            "planner event {} is not the canonical UID-derived identity {}",
            fmt_id(id),
            fmt_id(canonical)
        );
    }
    let actual = entity_facts(space, id);
    let missing = expected.facts().difference(&actual);
    let unexpected = actual.difference(expected.facts());
    let unexpected_is_legacy_noise = unexpected
        .iter()
        .all(|fact| legacy_event_fact_is_inert(space, id, fact));
    if !missing.is_empty() || !unexpected_is_legacy_noise {
        bail!(
            "planner event {} has facts outside its canonical immutable record",
            fmt_id(id)
        );
    }
    Ok(row)
}

fn load_validated_note(space: &TribleSet, id: Id) -> Result<NoteRow> {
    let row = NoteRow {
        id,
        event: exactly_one(
            id,
            "note::note_about",
            find!(
                value: Id,
                pattern!(space, [{ id @ note::note_about: ?value }])
            )
            .collect(),
        )?,
        text: exactly_one(
            id,
            "note::note_text",
            find!(
                value: TextHandle,
                pattern!(space, [{ id @ note::note_text: ?value }])
            )
            .collect(),
        )?,
        created_at: exactly_one(
            id,
            "metadata::created_at",
            find!(
                value: IntervalValue,
                pattern!(space, [{ id @ metadata::created_at: ?value }])
            )
            .collect(),
        )?,
    };
    validate_point("note creation time", row.created_at)?;
    let expected = note_record(row.event, row.text, row.created_at);
    let canonical = expected.root().expect("canonical note has one root");
    if canonical != id {
        bail!(
            "planner note {} is not intrinsic; canonical identity is {}",
            fmt_id(id),
            fmt_id(canonical)
        );
    }
    if entity_facts(space, id) != *expected.facts() {
        bail!(
            "planner note {} has facts outside its canonical immutable record",
            fmt_id(id)
        );
    }
    Ok(row)
}

fn load_validated_cancellation(space: &TribleSet, id: Id) -> Result<CancellationRow> {
    let row = CancellationRow {
        id,
        event: exactly_one(
            id,
            "cancellation::event",
            find!(
                value: Id,
                pattern!(space, [{ id @ cancellation::event: ?value }])
            )
            .collect(),
        )?,
    };
    let expected = cancellation_record(row.event);
    let canonical = expected
        .root()
        .expect("canonical cancellation has one root");
    if canonical != id {
        bail!(
            "planner cancellation {} is not intrinsic; canonical identity is {}",
            fmt_id(id),
            fmt_id(canonical)
        );
    }
    if entity_facts(space, id) != *expected.facts() {
        bail!(
            "planner cancellation {} has facts outside its canonical assertion",
            fmt_id(id)
        );
    }
    Ok(row)
}

/// Strictly project the native collection ontology without dereferencing
/// payloads.
///
/// Selection starts from each record's intrinsic identity, not merely its kind
/// tag. This is important for additive stopped-world cutovers: historical
/// random-id Planner facts remain in the collection as immutable provenance,
/// while only UID-derived events and intrinsic notes/cancellations participate
/// in the live catalog. Once selected, a native entity is validated exactly
/// apart from the two explicit legacy event residues handled above: creation
/// observations and a shadowed scalar cancellation.
fn load_validated_catalog(space: &TribleSet) -> Result<PlannerCatalog> {
    let event_ids = canonical_event_entities(space);
    let note_ids = canonical_note_entities(space);
    let cancellation_ids = canonical_cancellation_entities(space);

    let mut catalog = PlannerCatalog::default();
    for id in event_ids {
        catalog.events.insert(id, load_validated_event(space, id)?);
    }
    for id in note_ids {
        let row = load_validated_note(space, id)?;
        if !catalog.events.contains_key(&row.event) {
            bail!(
                "planner note {} refers to missing event {}",
                fmt_id(id),
                fmt_id(row.event)
            );
        }
        catalog.notes.insert(id, row);
    }
    for id in cancellation_ids {
        let row = load_validated_cancellation(space, id)?;
        if !catalog.events.contains_key(&row.event) {
            bail!(
                "planner cancellation {} refers to missing event {}",
                fmt_id(id),
                fmt_id(row.event)
            );
        }
        catalog.cancellations.insert(id, row);
    }

    Ok(catalog)
}

/// IDs of all events inhabiting the typed Planner projection.
pub fn event_ids<P>(space: &P) -> Vec<Id>
where
    P: TriblePattern + ?Sized,
{
    find!(
        id: Id,
        pattern!(space, [{ ?id @
            metadata::tag: &KIND_EVENT_ID,
            event::ical_uid: _?uid,
            event::summary: _?summary,
            event::time: _?time,
            event::status: _?status,
            event::transp: _?transp,
        }])
    )
    .collect()
}

/// Project one event if all fields needed by this reader are present.
///
/// Unknown facts and unrelated extensions remain invisible. Where this
/// version of the Planner model exposes a scalar field, the first value in
/// pattern order is its deterministic presentation choice; strict
/// stopped-world validation is reserved for migration boundaries.
pub fn event<P>(space: &P, id: Id) -> Option<EventRow>
where
    P: TriblePattern + ?Sized,
{
    find!(
        (
            uid: TextHandle,
            summary: String,
            time: IntervalValue,
            status: String,
            transp: String,
        ),
        pattern!(space, [{ id @
            metadata::tag: &KIND_EVENT_ID,
            event::ical_uid: ?uid,
            event::summary: ?summary,
            event::time: ?time,
            event::status: ?status,
            event::transp: ?transp,
        }])
    )
    .find_map(|(uid, summary, time, status, transp)| {
        let row = EventRow {
            id,
            uid,
            summary,
            description: find!(
                value: TextHandle,
                pattern!(space, [{ id @ event::description: ?value }])
            )
            .next(),
            time,
            rrule: find!(
                value: String,
                pattern!(space, [{ id @ event::rrule: ?value }])
            )
            .next(),
            rdates: find!(
                value: IntervalValue,
                pattern!(space, [{ id @ event::rdate: ?value }])
            )
            .collect(),
            exdates: find!(
                value: IntervalValue,
                pattern!(space, [{ id @ event::exdate: ?value }])
            )
            .collect(),
            location: find!(
                value: String,
                pattern!(space, [{ id @ event::location: ?value }])
            )
            .next(),
            status,
            transp,
            attendees: find!(
                value: Id,
                pattern!(space, [{ id @ event::attendee: ?value }])
            )
            .collect(),
            organizer: find!(
                value: Id,
                pattern!(space, [{ id @ event::organizer: ?value }])
            )
            .next(),
            sequence: find!(
                value: SequenceValue,
                pattern!(space, [{ id @ event::sequence: ?value }])
            )
            .next(),
        };
        validate_event_values(&row).is_ok().then_some(row)
    })
}

/// Every readable event carrying this exact UID attachment handle.
pub fn events_with_uid<P>(space: &P, uid: TextHandle) -> Vec<EventRow>
where
    P: TriblePattern + ?Sized,
{
    find!(
        id: Id,
        pattern!(space, [{ ?id @
            metadata::tag: &KIND_EVENT_ID,
            event::ical_uid: uid,
            event::summary: _?summary,
            event::time: _?time,
            event::status: _?status,
            event::transp: _?transp,
        }])
    )
    .filter_map(|id| event(space, id))
    .collect()
}

/// Every readable note attached to one event.
pub fn notes_for_event<P>(space: &P, event: Id) -> Vec<NoteRow>
where
    P: TriblePattern + ?Sized,
{
    find!(
        (
            id: Id,
            text: TextHandle,
            created_at: IntervalValue,
        ),
        pattern!(space, [{ ?id @
            metadata::tag: &KIND_NOTE_ID,
            metadata::created_at: ?created_at,
            note::note_about: event,
            note::note_text: ?text,
        }])
    )
    .filter_map(|(id, text, created_at)| {
        validate_point("note creation time", created_at)
            .is_ok()
            .then_some(NoteRow {
                id,
                event,
                text,
                created_at,
            })
    })
    .collect()
}

/// Whether the event has either an RFC cancellation status or a monotone
/// local cancellation assertion.
pub fn event_is_cancelled<P>(space: &P, event_id: Id) -> bool
where
    P: TriblePattern + ?Sized,
{
    exists!(pattern!(space, [{ event_id @
        event::status: STATUS_CANCELLED,
    }])) || exists!(pattern!(space, [{ _?assertion @
        metadata::tag: &KIND_CANCELLATION_ID,
        cancellation::event: event_id,
    }]))
}

/// Decode a bounded Planner fragment into its convenient import-time model.
///
/// Ordinary collection readers query their typed projections directly. This
/// bulk model remains for locally constructed or staged import fragments,
/// where its input is bounded independently of collection history. A record
/// participates only when it inhabits the corresponding typed projection;
/// incomplete or undecodable records are skipped.
pub fn load_catalog<P>(space: &P) -> Result<PlannerCatalog>
where
    P: TriblePattern + ?Sized,
{
    let mut catalog = PlannerCatalog::default();
    for id in event_ids(space) {
        if let Some(row) = event(space, id) {
            catalog.events.insert(id, row);
        }
    }
    for (id, event, text, created_at) in find!(
        (
            id: Id,
            event: Id,
            text: TextHandle,
            created_at: IntervalValue,
        ),
        pattern!(space, [{ ?id @
            metadata::tag: &KIND_NOTE_ID,
            metadata::created_at: ?created_at,
            note::note_about: ?event,
            note::note_text: ?text,
        }])
    ) {
        if validate_point("note creation time", created_at).is_ok() {
            catalog.notes.entry(id).or_insert(NoteRow {
                id,
                event,
                text,
                created_at,
            });
        }
    }
    for (id, event) in find!(
        (id: Id, event: Id),
        pattern!(space, [{ ?id @
            metadata::tag: &KIND_CANCELLATION_ID,
            cancellation::event: ?event,
        }])
    ) {
        catalog
            .cancellations
            .entry(id)
            .or_insert(CancellationRow { id, event });
    }
    Ok(catalog)
}

/// Strictly read a UTF8String attachment.
pub fn read_text(reader: &PileSnapshot, handle: TextHandle) -> Result<String> {
    let text: anybytes::View<str> = reader.get(handle).context("read Planner text")?;
    Ok(text.to_string())
}

/// Validate every selected native record and all of its referenced text
/// payloads. Preserved legacy and unrelated generic collection facts are not
/// part of this semantic view.
pub fn validate_catalog(reader: &PileSnapshot, space: &TribleSet) -> Result<PlannerCatalog> {
    let catalog = load_validated_catalog(space)?;
    for row in catalog.events.values() {
        let uid = read_text(reader, row.uid)
            .with_context(|| format!("read UID of planner event {}", fmt_id(row.id)))?;
        validate_uid(&uid)
            .with_context(|| format!("validate UID of planner event {}", fmt_id(row.id)))?;
        if let Some(description) = row.description {
            read_text(reader, description)
                .with_context(|| format!("read description of planner event {}", fmt_id(row.id)))?;
        }
    }
    for row in catalog.notes.values() {
        read_text(reader, row.text)
            .with_context(|| format!("read planner note {}", fmt_id(row.id)))?;
    }
    Ok(catalog)
}

/// Strictly validate a prospective legacy-migration fragment against a frozen
/// source union. Ordinary authored publication does not use this closed-world
/// check; constructors establish the local fragment invariants directly.
pub fn validate_candidate(
    reader: &PileSnapshot,
    current: &TribleSet,
    fragment: &Fragment,
) -> Result<PlannerCatalog> {
    let mut local = fragment.blobs().clone();
    let local_reader = local
        .snapshot()
        .context("snapshot staged Planner payloads")?;
    for fact in fragment.facts() {
        if fact.a() == &event::ical_uid.id()
            || fact.a() == &event::description.id()
            || fact.a() == &note::note_text.id()
        {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::UTF8String>>();
            let text: anybytes::View<str> = if local_reader.metadata(handle)?.is_some() {
                local_reader
                    .get(handle)
                    .context("read staged Planner text")?
            } else {
                reader.get(handle).context("read existing Planner text")?
            };
            if fact.a() == &event::ical_uid.id() {
                validate_uid(&text)?;
            }
        }
    }

    let mut union = current.clone();
    union += fragment.facts().clone();
    load_validated_catalog(&union)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn interval(start: i128, end: i128) -> IntervalValue {
        (
            hifitime::Epoch::from_unix_seconds(start as f64),
            hifitime::Epoch::from_unix_seconds(end as f64),
        )
            .try_to_inline()
            .unwrap()
    }

    fn draft(uid: &str, summary: &str) -> EventDraft {
        EventDraft {
            uid: uid.to_owned(),
            summary: summary.to_owned(),
            description: Some("description".to_owned()),
            time: interval(10, 20),
            rrule: None,
            rdates: BTreeSet::new(),
            exdates: BTreeSet::new(),
            location: Some("room".to_owned()),
            status: STATUS_CONFIRMED.to_owned(),
            transp: TRANSP_OPAQUE.to_owned(),
            attendees: BTreeSet::new(),
            organizer: None,
            sequence: None,
        }
    }

    #[test]
    fn event_identity_depends_on_uid_not_import_order_or_other_fields() {
        let first = event_fragment(&draft("stable@example", "first")).unwrap();
        let second = event_fragment(&draft("stable@example", "second")).unwrap();
        let other = event_fragment(&draft("other@example", "first")).unwrap();

        assert_eq!(first.root(), second.root());
        assert_ne!(first.root(), other.root());
        assert_ne!(first.facts(), second.facts());
    }

    #[test]
    fn cancellation_is_a_monotone_intrinsic_assertion() {
        let event = event_fragment(&draft("cancel@example", "meeting")).unwrap();
        let event_id = event.root().unwrap();
        let cancellation = cancellation_fragment(event_id);
        let mut facts = event.into_facts();
        facts += cancellation.clone().into_facts();

        let catalog = load_catalog(&facts).unwrap();
        assert!(catalog.is_cancelled(event_id));
        assert_eq!(cancellation_fragment(event_id), cancellation);
    }

    #[test]
    fn baseline_cancelled_is_cancelled_without_assertion() {
        let mut input = draft("baseline@example", "cancelled invite");
        input.status = STATUS_CANCELLED.to_owned();
        let event = event_fragment(&input).unwrap();
        let event_id = event.root().unwrap();
        let catalog = load_catalog(event.facts()).unwrap();

        assert!(catalog.is_cancelled(event_id));
        assert!(catalog.cancellations.is_empty());
    }

    #[test]
    fn ordinary_projection_survives_extra_values_while_strict_validation_rejects_them() {
        let event = event_fragment(&draft("fork@example", "meeting")).unwrap();
        let event_id = event.root().unwrap();
        let mut facts = event.into_facts();
        facts += entity! { ExclusiveId::force_ref(&event_id) @
            event::summary: "other",
        };

        assert!(load_catalog(&facts).unwrap().events.contains_key(&event_id));
        let error = load_validated_catalog(&facts).unwrap_err();
        assert!(format!("{error:#}").contains("2 values for event::summary"));
    }

    #[test]
    fn repeated_fields_are_sets_and_do_not_create_scalar_ambiguity() {
        let mut input = draft("sets@example", "meeting");
        input.attendees = BTreeSet::from([id(1), id(2)]);
        input.rdates = BTreeSet::from([interval(30, 40), interval(50, 60)]);
        let event = event_fragment(&input).unwrap();
        let event_id = event.root().unwrap();
        let catalog = load_catalog(event.facts()).unwrap();

        assert_eq!(catalog.events[&event_id].attendees, input.attendees);
        assert_eq!(catalog.events[&event_id].rdates, input.rdates);
    }

    #[test]
    fn note_and_cancellation_must_reference_an_event_in_the_union() {
        let note = note_fragment(id(3), "orphan", interval(1, 1)).unwrap();
        let note_error = load_validated_catalog(note.facts()).unwrap_err();
        assert!(format!("{note_error:#}").contains("refers to missing event"));

        let cancellation = cancellation_fragment(id(4));
        let cancellation_error = load_validated_catalog(cancellation.facts()).unwrap_err();
        assert!(format!("{cancellation_error:#}").contains("refers to missing event"));
    }

    #[test]
    fn legacy_random_id_records_are_inert_beside_intrinsic_records() {
        let event = event_fragment(&draft("native@example", "canonical")).unwrap();
        let event_id = event.root().unwrap();
        let uid = find!(
            value: TextHandle,
            pattern!(event.facts(), [{ event_id @ event::ical_uid: ?value }])
        )
        .next()
        .unwrap();
        let legacy_event = id(9);
        let legacy_note = id(10);
        let mut facts = event.into_facts();
        facts += entity! { ExclusiveId::force_ref(&legacy_event) @
            metadata::tag: &KIND_EVENT_ID,
            event::ical_uid: uid,
            event::summary: "legacy",
        };
        facts += entity! { ExclusiveId::force_ref(&legacy_note) @
            metadata::tag: &KIND_NOTE_ID,
            note::note_about: &legacy_event,
        };
        facts += entity! { ExclusiveId::force_ref(&KIND_EVENT_ID) @ metadata::tag: &id(11) };

        let catalog = load_validated_catalog(&facts).unwrap();
        assert_eq!(
            catalog.events.keys().copied().collect::<Vec<_>>(),
            vec![event_id]
        );
        assert!(catalog.notes.is_empty());
        assert!(catalog.cancellations.is_empty());

        let mut polluted = event_fragment(&draft("polluted@example", "canonical")).unwrap();
        let polluted_id = polluted.root().unwrap();
        polluted += entity! { ExclusiveId::force_ref(&polluted_id) @ metadata::tag: &id(12) };
        assert!(load_catalog(polluted.facts()).is_ok());
        let error = load_validated_catalog(polluted.facts()).unwrap_err();
        assert!(format!("{error:#}").contains("outside its canonical immutable record"));
    }
}
