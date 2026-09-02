//! Canonical native Orient checkpoint events.
//!
//! A checkpoint is not a cursor into storage history. It is an immutable
//! observation of exactly what one persona could see. The latest observation
//! is selected by the total order `(point time, intrinsic event id)`; equal
//! visible views therefore remain equal across commit order, merge shape, and
//! rollup layout.

use std::collections::{BTreeMap, BTreeSet};

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use triblespace::core::collection::lww_register::{
    LwwIndex, LwwRegisterCollection, RegisterCoordinatesMapping,
};
use triblespace::core::collection::CollectionStoreExt;
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::{BlobStoreGet, CapabilityProofRead, SnapshotSource};
use triblespace::macros::{entity, find, pattern};
use triblespace::prelude::*;

use crate::schemas::compass::KIND_NOTE_ID;
use crate::schemas::orient::{
    checkpoint, observation, DEFAULT_SCOPE_ID, KIND_CHECKPOINT_EVENT, KIND_SEEN, KIND_SEEN_FRONTIER,
};

use crate::legacy_hint::open_scope;

pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;
pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;

/// One coherent Orient source snapshot plus its maintained checkpoint order.
///
/// Facts, cover, payload reader, and register are captured from one exact
/// collection observation. The maintained artifact is cache exhaust and has
/// no authority beyond that source cover.
pub struct OrientSnapshot {
    facts: TribleSet,
    store_snapshot: PileSnapshot,
    checkpoints: LwwIndex,
}

impl OrientSnapshot {
    /// Materialized facts admitted by this exact source cover.
    pub fn facts(&self) -> &TribleSet {
        &self.facts
    }

    /// Store snapshot captured with the same immutable pile observation.
    pub fn store_snapshot(&self) -> &PileSnapshot {
        &self.store_snapshot
    }

    /// Maintained checkpoint order attached for this exact cover.
    pub fn checkpoint_register(&self) -> &LwwIndex {
        &self.checkpoints
    }

    /// Consume the coherent snapshot into facts, store snapshot, and checkpoint index.
    pub fn into_parts(self) -> (TribleSet, PileSnapshot, LwwIndex) {
        (self.facts, self.store_snapshot, self.checkpoints)
    }
}

/// Exact maintained LWW projection for each persona's checkpoint stream.
pub fn checkpoint_register_collection<S>(
    store: &mut S,
    authority: VerifyingKey,
) -> Result<LwwRegisterCollection>
where
    S: CollectionStoreExt + SnapshotSource,
    <S as SnapshotSource>::Snapshot: BlobStoreGet + CapabilityProofRead,
{
    let source = crate::collection_names::open_configured(store, DEFAULT_SCOPE_ID, authority)?;
    let target = store.derive(
        source,
        RegisterCoordinatesMapping::new(checkpoint::persona.id(), metadata::created_at.id()),
        crate::collection_names::private_policy(authority),
    )?;
    Ok(LwwRegisterCollection::new(source, target))
}

/// Complete semantic wake state for one persona.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WatchedView {
    pub unread: BTreeSet<Id>,
    pub mail_unread: BTreeSet<Id>,
    /// Logical Teams messages this persona has been shown. Teams carries no
    /// per-reader read state, so attention is growth of the observed message
    /// set rather than an unread flag.
    pub teams: BTreeSet<Id>,
    pub goals_view: String,
    pub roster: BTreeSet<Id>,
    pub notes: BTreeMap<Id, Id>,
}

#[derive(Debug, Deserialize, Serialize)]
struct WireView {
    version: u8,
    unread: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mail_unread: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    teams: Option<Vec<String>>,
    goals_view: String,
    roster: Vec<String>,
    notes: Vec<(String, String)>,
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn parse_id(value: &str, field: &str) -> Result<Id> {
    Id::from_hex(value).ok_or_else(|| anyhow!("invalid Orient {field} id '{value}'"))
}

fn serialize_view_version(view: &WatchedView, version: u8) -> Result<String> {
    let mail = || -> Vec<String> { view.mail_unread.iter().copied().map(fmt_id).collect() };
    let (mail_unread, teams) = match version {
        1 => (None, None),
        2 => (Some(mail()), None),
        3 => (
            Some(mail()),
            Some(view.teams.iter().copied().map(fmt_id).collect()),
        ),
        other => bail!("unsupported Orient checkpoint view version {other}"),
    };
    serde_json::to_string(&WireView {
        version,
        unread: view.unread.iter().copied().map(fmt_id).collect(),
        mail_unread,
        teams,
        goals_view: view.goals_view.clone(),
        roster: view.roster.iter().copied().map(fmt_id).collect(),
        notes: view
            .notes
            .iter()
            .map(|(note, goal)| (fmt_id(*note), fmt_id(*goal)))
            .collect(),
    })
    .context("serialize canonical Orient view")
}

/// Serialize one view in its unique current JSON representation.
pub fn serialize_view(view: &WatchedView) -> Result<String> {
    serialize_view_version(view, 3)
}

/// Parse and require the unique canonical representation.
pub fn parse_view(encoded: &str) -> Result<WatchedView> {
    let wire: WireView = serde_json::from_str(encoded).context("parse Orient checkpoint view")?;
    let mail_unread = match (wire.version, wire.mail_unread.as_ref()) {
        (1, None) => BTreeSet::new(),
        (2 | 3, Some(values)) => values
            .iter()
            .map(|value| parse_id(value, "unread mail"))
            .collect::<Result<_>>()?,
        (1, Some(_)) => bail!("Orient checkpoint view v1 unexpectedly contains unread Mail"),
        (2 | 3, None) => bail!("Orient checkpoint view v{} lacks unread Mail", wire.version),
        (other, _) => bail!("unsupported Orient checkpoint view version {other}"),
    };
    // A pre-v3 checkpoint predates Teams attention entirely. Its empty set is
    // the honest reading: everything already in the pile is unobserved, so the
    // first post-upgrade check reports the standing conversation once.
    let teams = match (wire.version, wire.teams.as_ref()) {
        (1 | 2, None) => BTreeSet::new(),
        (3, Some(values)) => values
            .iter()
            .map(|value| parse_id(value, "Teams message"))
            .collect::<Result<_>>()?,
        (1 | 2, Some(_)) => bail!(
            "Orient checkpoint view v{} unexpectedly contains Teams messages",
            wire.version
        ),
        (3, None) => bail!("Orient checkpoint view v3 lacks Teams messages"),
        (other, _) => bail!("unsupported Orient checkpoint view version {other}"),
    };
    let view = WatchedView {
        unread: wire
            .unread
            .iter()
            .map(|value| parse_id(value, "unread message"))
            .collect::<Result<_>>()?,
        mail_unread,
        teams,
        goals_view: wire.goals_view,
        roster: wire
            .roster
            .iter()
            .map(|value| parse_id(value, "roster member"))
            .collect::<Result<_>>()?,
        notes: wire
            .notes
            .iter()
            .map(|(note, goal)| Ok((parse_id(note, "note")?, parse_id(goal, "note goal")?)))
            .collect::<Result<_>>()?,
    };
    if serialize_view_version(&view, wire.version)? != encoded {
        bail!("Orient checkpoint view is not canonically serialized");
    }
    Ok(view)
}

/// Decode a timestamp and require an exact point.
pub fn point_time(value: IntervalValue) -> Result<i128> {
    let (lower, upper): (i128, i128) = value
        .try_from_inline()
        .map_err(|error| anyhow!("decode Orient checkpoint time: {error:?}"))?;
    if lower != upper {
        bail!("Orient checkpoint time must be a point interval");
    }
    Ok(lower)
}

fn checkpoint_facts(persona: Id, view: TextHandle, at: IntervalValue) -> Fragment {
    entity! {
        metadata::tag: &KIND_CHECKPOINT_EVENT,
        checkpoint::persona: &persona,
        checkpoint::view: view,
        metadata::created_at: at,
    }
}

fn seen_record(persona: Id, kind: Id, item: Id) -> Fragment {
    entity! {
        metadata::tag: &KIND_SEEN,
        observation::persona: &persona,
        observation::source_kind: &kind,
        observation::source_item: &item,
    }
}

fn seen_frontier_record(persona: Id, kind: Id) -> Fragment {
    entity! {
        metadata::tag: &KIND_SEEN_FRONTIER,
        observation::persona: &persona,
        observation::source_kind: &kind,
    }
}

/// Build the grow-only atoms that initialize one person's seen-note frontier
/// and prove every note identity observed in the same publication.
pub fn seen_notes_fragment(persona: Id, notes: impl IntoIterator<Item = Id>) -> Fragment {
    let mut fragment = seen_frontier_record(persona, KIND_NOTE_ID);
    for note in notes {
        fragment += seen_record(persona, KIND_NOTE_ID, note);
    }
    fragment
}

/// Every note observed by one exact persona anchor.
pub fn seen_notes(facts: &TribleSet, persona: Id) -> BTreeSet<Id> {
    find!(
        item: Id,
        pattern!(facts, [{
            _?seen @
            metadata::tag: &KIND_SEEN,
            observation::persona: &persona,
            observation::source_kind: &KIND_NOTE_ID,
            observation::source_item: ?item,
        }])
    )
    .collect()
}

/// Whether one exact persona anchor has initialized its Seen-note frontier.
pub fn has_seen_notes_frontier(facts: &TribleSet, persona: Id) -> bool {
    triblespace::macros::exists!(pattern!(facts, [{
        _?frontier @
        metadata::tag: &KIND_SEEN_FRONTIER,
        observation::persona: &persona,
        observation::source_kind: &KIND_NOTE_ID,
    }]))
}

/// Build one intrinsic immutable checkpoint with its serialized view payload.
pub fn checkpoint_fragment(
    persona: Id,
    view: &WatchedView,
    at: IntervalValue,
) -> Result<(Fragment, Id)> {
    point_time(at)?;
    let mut fragment = Fragment::empty();
    let handle = fragment.put::<blobencodings::UTF8String, _>(serialize_view(view)?);
    let record = checkpoint_facts(persona, handle, at);
    let event = record
        .root()
        .expect("canonical Orient checkpoint has one intrinsic root");
    fragment += record;
    Ok((fragment, event))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointEvent {
    pub event: Id,
    pub persona: Id,
    pub view: WatchedView,
    pub at: IntervalValue,
}

/// Structural fields of one selected checkpoint before its view payload is
/// read.
///
/// Hot observers use this to ask the store whether the exact payload is
/// resident without turning absence into a failed typed read. Once resident,
/// [`load_checkpoint_event`] remains the strict decoding boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointRecord {
    pub event: Id,
    pub persona: Id,
    pub view: TextHandle,
    pub at: IntervalValue,
}

fn exactly_one<T>(event: Id, field: &str, values: Vec<T>) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "Orient checkpoint {event:x} has {} values for {field}; expected exactly one",
            values.len()
        );
    }
    Ok(values.into_iter().next().expect("one value"))
}

/// Read and authenticate the inline structure of one checkpoint without
/// touching its UTF-8 view attachment.
pub fn checkpoint_record(facts: &TribleSet, event: Id) -> Result<CheckpointRecord> {
    if !exists!(pattern!(facts, [{ event @ metadata::tag: &KIND_CHECKPOINT_EVENT }])) {
        bail!("Orient checkpoint register selects non-checkpoint event {event:x}");
    }
    let record = CheckpointRecord {
        event,
        persona: exactly_one(
            event,
            "checkpoint::persona",
            find!(persona: Id, pattern!(facts, [{ event @ checkpoint::persona: ?persona }]))
                .collect(),
        )?,
        view: exactly_one(
            event,
            "checkpoint::view",
            find!(handle: TextHandle, pattern!(facts, [{ event @ checkpoint::view: ?handle }]))
                .collect(),
        )?,
        at: exactly_one(
            event,
            "metadata::created_at",
            find!(at: IntervalValue, pattern!(facts, [{ event @ metadata::created_at: ?at }]))
                .collect(),
        )?,
    };
    point_time(record.at).with_context(|| format!("validate Orient checkpoint {event:x}"))?;
    let canonical = checkpoint_facts(record.persona, record.view, record.at)
        .root()
        .expect("canonical Orient checkpoint has one intrinsic root");
    if event != canonical {
        bail!("Orient checkpoint {event:x} is not intrinsic; canonical identity is {canonical:x}");
    }
    Ok(record)
}

/// Load the exact checkpoint event set, rejecting malformed or nonintrinsic
/// records rather than letting query order select a value.
pub fn load_checkpoint_events<Store>(
    reader: &Store,
    facts: &TribleSet,
) -> Result<Vec<CheckpointEvent>>
where
    Store: BlobStoreGet + ?Sized,
{
    let event_ids: BTreeSet<Id> = find!(
        event: Id,
        pattern!(facts, [{ ?event @ metadata::tag: &KIND_CHECKPOINT_EVENT }])
    )
    .collect();
    let mut expected = TribleSet::new();
    let mut events = Vec::with_capacity(event_ids.len());
    for event in event_ids {
        let persona = exactly_one(
            event,
            "checkpoint::persona",
            find!(
                persona: Id,
                pattern!(facts, [{ event @ checkpoint::persona: ?persona }])
            )
            .collect(),
        )?;
        let handle = exactly_one(
            event,
            "checkpoint::view",
            find!(
                handle: TextHandle,
                pattern!(facts, [{ event @ checkpoint::view: ?handle }])
            )
            .collect(),
        )?;
        let at = exactly_one(
            event,
            "metadata::created_at",
            find!(
                at: IntervalValue,
                pattern!(facts, [{ event @ metadata::created_at: ?at }])
            )
            .collect(),
        )?;
        point_time(at).with_context(|| format!("validate Orient checkpoint {event:x}"))?;
        let encoded: View<str> = reader
            .get(handle)
            .with_context(|| format!("read Orient checkpoint view {}", hex::encode(handle.raw)))?;
        let view = parse_view(&encoded)?;
        let record = checkpoint_facts(persona, handle, at);
        let canonical = record
            .root()
            .expect("canonical Orient checkpoint has one intrinsic root");
        if event != canonical {
            bail!(
                "Orient checkpoint {event:x} is not intrinsic; canonical identity is {canonical:x}"
            );
        }
        expected += record.facts().clone();
        events.push(CheckpointEvent {
            event,
            persona,
            view,
            at,
        });
    }
    let seen_ids: BTreeSet<Id> = find!(
        event: Id,
        pattern!(facts, [{ ?event @ metadata::tag: &KIND_SEEN }])
    )
    .collect();
    for event in seen_ids {
        let persona = exactly_one(
            event,
            "observation::persona",
            find!(persona: Id, pattern!(facts, [{ event @ observation::persona: ?persona }]))
                .collect(),
        )?;
        let kind = exactly_one(
            event,
            "observation::source_kind",
            find!(kind: Id, pattern!(facts, [{ event @ observation::source_kind: ?kind }]))
                .collect(),
        )?;
        let item = exactly_one(
            event,
            "observation::source_item",
            find!(item: Id, pattern!(facts, [{ event @ observation::source_item: ?item }]))
                .collect(),
        )?;
        if kind != KIND_NOTE_ID {
            bail!("Orient Seen event {event:x} has unsupported kind {kind:x}");
        }
        let record = seen_record(persona, kind, item);
        let canonical = record.root().expect("canonical Seen atom has one root");
        if event != canonical {
            bail!(
                "Orient Seen event {event:x} is not intrinsic; canonical identity is {canonical:x}"
            );
        }
        expected += record.facts().clone();
    }
    let frontier_ids: BTreeSet<Id> = find!(
        event: Id,
        pattern!(facts, [{ ?event @ metadata::tag: &KIND_SEEN_FRONTIER }])
    )
    .collect();
    for event in frontier_ids {
        let persona = exactly_one(
            event,
            "observation::persona",
            find!(persona: Id, pattern!(facts, [{ event @ observation::persona: ?persona }]))
                .collect(),
        )?;
        let kind = exactly_one(
            event,
            "observation::source_kind",
            find!(kind: Id, pattern!(facts, [{ event @ observation::source_kind: ?kind }]))
                .collect(),
        )?;
        if kind != KIND_NOTE_ID {
            bail!("Orient Seen frontier {event:x} has unsupported kind {kind:x}");
        }
        let record = seen_frontier_record(persona, kind);
        let canonical = record.root().expect("canonical Seen frontier has one root");
        if event != canonical {
            bail!("Orient Seen frontier {event:x} is not intrinsic; canonical identity is {canonical:x}");
        }
        expected += record.facts().clone();
    }
    if expected != *facts {
        bail!(
            "Orient checkpoint collection is not an exact canonical ontology ({} missing, {} unexpected facts)",
            expected.difference(facts).len(),
            facts.difference(&expected).len()
        );
    }
    Ok(events)
}

/// Load and validate one checkpoint selected by a maintained index.
///
/// Exact collection materialization has already established availability of
/// the source cover. This validates the selected row and payload without
/// reparsing every historical checkpoint on each poll.
pub fn load_checkpoint_event<Store>(
    reader: &Store,
    facts: &TribleSet,
    event: Id,
) -> Result<CheckpointEvent>
where
    Store: BlobStoreGet + ?Sized,
{
    let record = checkpoint_record(facts, event)?;
    let encoded: View<str> = reader.get(record.view).with_context(|| {
        format!(
            "read Orient checkpoint view {}",
            hex::encode(record.view.raw)
        )
    })?;
    let view = parse_view(&encoded)?;
    Ok(CheckpointEvent {
        event,
        persona: record.persona,
        view,
        at: record.at,
    })
}

/// Latest checkpoint for one exact persona anchor in an exact maintained
/// register frame.
///
/// Observation history deliberately does not follow mutable identity
/// equivalence: an exact anchor's grow-only ledger must never shrink if a
/// same-person verdict is later corrected. The register and event set must
/// come from the same [`OrientSnapshot`].
pub fn latest_checkpoint(
    events: impl IntoIterator<Item = CheckpointEvent>,
    register: &LwwIndex,
    persona: Id,
) -> Result<Option<CheckpointEvent>> {
    let Some(winner) = register.winner(persona) else {
        return Ok(None);
    };
    let mut selected = events
        .into_iter()
        .filter(|event| event.persona == persona && event.event == winner);
    let result = selected.next().ok_or_else(|| {
        anyhow!(
            "Orient checkpoint register selects {winner:x} for {persona:x}, but the exact event set does not contain it"
        )
    })?;
    if selected.next().is_some() {
        bail!("Orient exact event set repeats checkpoint {winner:x}");
    }
    Ok(Some(result))
}

pub fn validate_catalog<Store>(reader: &Store, facts: &TribleSet, compass: &TribleSet) -> Result<()>
where
    Store: BlobStoreGet + ?Sized,
{
    load_checkpoint_events(reader, facts)?;
    let notes: BTreeSet<Id> = find!(
        note: Id,
        pattern!(compass, [{
            ?note @
            metadata::tag: &KIND_NOTE_ID,
            crate::schemas::compass::board::task: _?goal,
            crate::schemas::compass::board::note: _?body,
        }])
    )
    .collect();
    for item in find!(
        item: Id,
        pattern!(facts, [{
            _?event @
            metadata::tag: &KIND_SEEN,
            observation::source_kind: &KIND_NOTE_ID,
            observation::source_item: ?item,
        }])
    ) {
        if !notes.contains(&item) {
            bail!("Orient Seen marker names missing Compass note {item:x}");
        }
    }
    Ok(())
}

/// Capture Orient facts and attach the maintained checkpoint LWW index for
/// that exact source cover, constructing missing derived artifacts if needed.
///
/// This materializes the collection and its index, not a closed-world read
/// model: consumers validate selected checkpoint rows and payloads through
/// [`load_checkpoint_event`]. Explicit whole-catalog and cross-collection
/// audits remain available through [`validate_catalog`].
pub fn materialize_indexed_collection(
    pile: &mut Pile,
    signer: &SigningKey,
) -> Result<OrientSnapshot> {
    let collection = open_scope(pile, DEFAULT_SCOPE_ID, signer)?;
    let store_snapshot = pile.snapshot().context("freeze Orient store snapshot")?;
    let (facts, cover) = crate::storage::read_fact_collection(collection, &store_snapshot)
        .context("read Orient collection")?;
    let checkpoints = checkpoint_register_collection(pile, signer.verifying_key())?
        .ensure(pile, &cover)
        .map_err(|error| anyhow!("maintain Orient checkpoint register: {error}"))?;
    Ok(OrientSnapshot {
        facts,
        store_snapshot,
        checkpoints,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compass;
    use hifitime::Epoch;
    use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace::core::collection::lww_register::derive_element;

    fn at(seconds: f64) -> IntervalValue {
        let at = Epoch::from_unix_seconds(seconds);
        (at, at).try_to_inline().unwrap()
    }

    fn checkpoint_index(facts: &TribleSet) -> LwwIndex {
        let source: Blob<SimpleArchive> = facts.clone().to_blob();
        let projection =
            derive_element(&source, checkpoint::persona.id(), metadata::created_at.id())
                .expect("checkpoint facts project into the maintained register algebra");
        LwwIndex::decode(&projection).expect("checkpoint register projection attaches")
    }

    #[test]
    fn canonical_view_roundtrip_ignores_insertion_order() {
        let first = Id::new([1; 16]).unwrap();
        let second = Id::new([2; 16]).unwrap();
        let goal = Id::new([3; 16]).unwrap();
        let left = WatchedView {
            unread: BTreeSet::from([second, first]),
            mail_unread: BTreeSet::from([first, second]),
            teams: BTreeSet::from([second, first]),
            goals_view: "goal-state".to_owned(),
            roster: BTreeSet::from([second, first]),
            notes: BTreeMap::from([(second, goal), (first, goal)]),
        };
        let right = WatchedView {
            unread: [first, second].into_iter().collect(),
            mail_unread: [second, first].into_iter().collect(),
            teams: [first, second].into_iter().collect(),
            goals_view: "goal-state".to_owned(),
            roster: [first, second].into_iter().collect(),
            notes: [(first, goal), (second, goal)].into_iter().collect(),
        };
        assert_eq!(left, right);
        assert_eq!(
            serialize_view(&left).unwrap(),
            serialize_view(&right).unwrap()
        );
        assert_eq!(parse_view(&serialize_view(&left).unwrap()).unwrap(), left);
    }

    #[test]
    fn canonical_version_one_view_remains_readable() {
        let message = Id::new([1; 16]).unwrap();
        let encoded = format!(
            r#"{{"version":1,"unread":["{message:x}"],"goals_view":"","roster":[],"notes":[]}}"#
        );
        let parsed = parse_view(&encoded).unwrap();
        assert_eq!(parsed.unread, BTreeSet::from([message]));
        assert!(parsed.mail_unread.is_empty());
        assert!(parsed.teams.is_empty());
        assert!(serialize_view(&parsed)
            .unwrap()
            .starts_with(r#"{"version":3,"#));
    }

    #[test]
    fn canonical_version_two_view_remains_readable_without_teams() {
        let wire = Id::new([7; 16]).unwrap();
        let encoded = format!(
            r#"{{"version":2,"unread":[],"mail_unread":["{wire:x}"],"goals_view":"","roster":[],"notes":[]}}"#
        );
        let parsed = parse_view(&encoded).unwrap();
        assert_eq!(parsed.mail_unread, BTreeSet::from([wire]));
        assert!(parsed.teams.is_empty());
        assert_eq!(serialize_view_version(&parsed, 2).unwrap(), encoded);
    }

    #[test]
    fn latest_checkpoint_uses_event_id_for_equal_time() {
        let persona = Id::new([4; 16]).unwrap();
        let left_view = WatchedView {
            goals_view: "left".to_owned(),
            ..WatchedView::default()
        };
        let right_view = WatchedView {
            goals_view: "right".to_owned(),
            ..WatchedView::default()
        };
        let (left, left_id) = checkpoint_fragment(persona, &left_view, at(1.0)).unwrap();
        let (right, right_id) = checkpoint_fragment(persona, &right_view, at(1.0)).unwrap();
        let mut all = Fragment::empty();
        all += left;
        all += right;
        let mut staged = all.clone();
        let reader = staged.blobs_mut().snapshot().unwrap();
        let events = load_checkpoint_events(&reader, all.facts()).unwrap();
        let latest = latest_checkpoint(events, &checkpoint_index(all.facts()), persona)
            .unwrap()
            .unwrap();
        assert_eq!(latest.event, left_id.max(right_id));
        assert_eq!(
            latest.view,
            if left_id > right_id {
                left_view
            } else {
                right_view
            }
        );
    }

    #[test]
    fn selected_checkpoint_load_matches_full_catalog() {
        let persona = Id::new([4; 16]).unwrap();
        let other = Id::new([6; 16]).unwrap();
        let mut all = Fragment::empty();
        for (owner, seconds, label) in [
            (persona, 1.0, "old"),
            (other, 9.0, "other"),
            (persona, 3.0, "latest"),
            (persona, 2.0, "middle"),
        ] {
            let view = WatchedView {
                goals_view: label.to_owned(),
                ..WatchedView::default()
            };
            all += checkpoint_fragment(owner, &view, at(seconds)).unwrap().0;
        }
        let mut staged = all.clone();
        let reader = staged.blobs_mut().snapshot().unwrap();
        let index = checkpoint_index(all.facts());
        let events = load_checkpoint_events(&reader, all.facts()).unwrap();
        let full = latest_checkpoint(events, &index, persona).unwrap().unwrap();
        let selected =
            load_checkpoint_event(&reader, all.facts(), index.winner(persona).unwrap()).unwrap();
        assert_eq!(selected, full);
        assert_eq!(selected.view.goals_view, "latest");
    }

    #[test]
    fn indexed_materialization_ignores_a_discarded_malformed_checkpoint_payload() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("orient.pile");
        std::fs::File::create(&path).unwrap();
        let signer = SigningKey::from_bytes(&[33; 32]);
        let persona = Id::new([4; 16]).unwrap();

        let mut fragment = Fragment::empty();
        let malformed = fragment.put::<blobencodings::UTF8String, _>("not a checkpoint view");
        fragment += entity! {
            metadata::tag: &KIND_CHECKPOINT_EVENT,
            checkpoint::persona: &persona,
            checkpoint::view: malformed,
            metadata::created_at: at(1.0),
        };
        let expected = WatchedView {
            goals_view: "current".to_owned(),
            ..WatchedView::default()
        };
        fragment += checkpoint_fragment(persona, &expected, at(2.0)).unwrap().0;

        let mut pile = crate::storage::open_pile_strict(&path).unwrap();
        let collection = open_scope(&mut pile, DEFAULT_SCOPE_ID, &signer).unwrap();
        pile.commit(collection, &signer, fragment).unwrap();

        let snapshot = materialize_indexed_collection(&mut pile, &signer).unwrap();
        let selected = snapshot.checkpoint_register().winner(persona).unwrap();
        assert_eq!(
            load_checkpoint_event(snapshot.store_snapshot(), snapshot.facts(), selected)
                .unwrap()
                .view,
            expected,
        );
        assert!(load_checkpoint_events(snapshot.store_snapshot(), snapshot.facts()).is_err());
        pile.close().unwrap();
    }

    fn validated_compass(persona: Id, note: Id) -> Fragment {
        let goal = Id::new([5; 16]).unwrap();
        let mut compass =
            compass::replay::goal_fragment(goal, "goal", Vec::new(), None, at(1.0)).unwrap();
        compass += compass::replay::note_fragment(
            note,
            goal,
            "note",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(persona),
            at(2.0),
        )
        .unwrap();
        compass
    }

    fn validate_fragments(orient: &Fragment, compass: &Fragment) -> Result<()> {
        let mut blobs = orient.clone();
        blobs.blobs_mut().union(compass.blobs().clone());
        let reader = blobs.blobs_mut().snapshot().unwrap();
        validate_catalog(&reader, orient.facts(), compass.facts())
    }

    #[test]
    fn seen_atoms_and_frontier_are_intrinsic_and_deduplicate() {
        let persona = Id::new([4; 16]).unwrap();
        let note = Id::new([6; 16]).unwrap();
        let once = seen_notes_fragment(persona, [note]);
        let mut twice = once.clone();
        twice += seen_notes_fragment(persona, [note, note]);
        assert_eq!(once.facts(), twice.facts());
        assert!(has_seen_notes_frontier(once.facts(), persona));
        assert_eq!(seen_notes(once.facts(), persona), BTreeSet::from([note]));
        let compass = validated_compass(persona, note);
        validate_fragments(&once, &compass).unwrap();
    }

    #[test]
    fn validation_rejects_missing_seen_note() {
        let persona = Id::new([4; 16]).unwrap();
        let note = Id::new([6; 16]).unwrap();
        let missing = Id::new([7; 16]).unwrap();
        let orient = seen_notes_fragment(persona, [missing]);
        let compass = validated_compass(persona, note);
        assert!(validate_fragments(&orient, &compass)
            .unwrap_err()
            .to_string()
            .contains("missing Compass note"));
    }

    #[test]
    fn validation_accepts_preprofile_seen_and_checkpoint_personas() {
        let persona = Id::new([4; 16]).unwrap();
        let preprofile = Id::new([7; 16]).unwrap();
        let note = Id::new([6; 16]).unwrap();
        let compass = validated_compass(persona, note);
        let seen = seen_notes_fragment(preprofile, [note]);
        validate_fragments(&seen, &compass).unwrap();

        let (checkpoint, _) =
            checkpoint_fragment(preprofile, &WatchedView::default(), at(3.0)).unwrap();
        validate_fragments(&checkpoint, &compass).unwrap();
    }
}
