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
use serde::{Deserialize, Serialize};
use triblespace::core::metadata;
use triblespace::core::repo::BlobStoreGet;
use triblespace::macros::{entity, find, pattern};
use triblespace::prelude::*;

use crate::schemas::orient::{checkpoint, KIND_CHECKPOINT_EVENT};

pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;
pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;

/// Complete semantic wake state for one persona.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WatchedView {
    pub unread: BTreeSet<Id>,
    pub mail_unread: BTreeSet<Id>,
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
    let mail_unread = match version {
        1 => None,
        2 => Some(view.mail_unread.iter().copied().map(fmt_id).collect()),
        other => bail!("unsupported Orient checkpoint view version {other}"),
    };
    serde_json::to_string(&WireView {
        version,
        unread: view.unread.iter().copied().map(fmt_id).collect(),
        mail_unread,
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
    serialize_view_version(view, 2)
}

/// Parse and require the unique canonical representation.
pub fn parse_view(encoded: &str) -> Result<WatchedView> {
    let wire: WireView = serde_json::from_str(encoded).context("parse Orient checkpoint view")?;
    let mail_unread = match (wire.version, wire.mail_unread.as_ref()) {
        (1, None) => BTreeSet::new(),
        (2, Some(values)) => values
            .iter()
            .map(|value| parse_id(value, "unread mail"))
            .collect::<Result<_>>()?,
        (1, Some(_)) => bail!("Orient checkpoint view v1 unexpectedly contains unread Mail"),
        (2, None) => bail!("Orient checkpoint view v2 lacks unread Mail"),
        (other, _) => bail!("unsupported Orient checkpoint view version {other}"),
    };
    let view = WatchedView {
        unread: wire
            .unread
            .iter()
            .map(|value| parse_id(value, "unread message"))
            .collect::<Result<_>>()?,
        mail_unread,
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

fn checkpoint_record(persona: Id, view: TextHandle, at: IntervalValue) -> Fragment {
    entity! {
        metadata::tag: &KIND_CHECKPOINT_EVENT,
        checkpoint::persona: &persona,
        checkpoint::view: view,
        metadata::created_at: at,
    }
}

/// Build one intrinsic immutable checkpoint with its serialized view payload.
pub fn checkpoint_fragment(
    persona: Id,
    view: &WatchedView,
    at: IntervalValue,
) -> Result<(Fragment, Id)> {
    point_time(at)?;
    let mut fragment = Fragment::empty();
    let handle = fragment.put::<blobencodings::LongString, _>(serialize_view(view)?);
    let record = checkpoint_record(persona, handle, at);
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

fn exactly_one<T>(event: Id, field: &str, values: Vec<T>) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "Orient checkpoint {event:x} has {} values for {field}; expected exactly one",
            values.len()
        );
    }
    Ok(values.into_iter().next().expect("one value"))
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
        let record = checkpoint_record(persona, handle, at);
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
    if expected != *facts {
        bail!(
            "Orient checkpoint collection is not an exact canonical ontology ({} missing, {} unexpected facts)",
            expected.difference(facts).len(),
            facts.difference(&expected).len()
        );
    }
    Ok(events)
}

/// Latest checkpoint for one persona under a deterministic total order.
pub fn latest_checkpoint(
    events: impl IntoIterator<Item = CheckpointEvent>,
    persona: Id,
) -> Result<Option<CheckpointEvent>> {
    let mut latest: Option<((i128, Id), CheckpointEvent)> = None;
    for event in events.into_iter().filter(|event| event.persona == persona) {
        let key = (point_time(event.at)?, event.event);
        if latest.as_ref().is_none_or(|(current, _)| key > *current) {
            latest = Some((key, event));
        }
    }
    Ok(latest.map(|(_, event)| event))
}

pub fn validate_catalog<Store>(reader: &Store, facts: &TribleSet) -> Result<()>
where
    Store: BlobStoreGet + ?Sized,
{
    load_checkpoint_events(reader, facts).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hifitime::Epoch;
    use triblespace::core::repo::BlobStore;

    fn at(seconds: f64) -> IntervalValue {
        let at = Epoch::from_unix_seconds(seconds);
        (at, at).try_to_inline().unwrap()
    }

    #[test]
    fn canonical_view_roundtrip_ignores_insertion_order() {
        let first = Id::new([1; 16]).unwrap();
        let second = Id::new([2; 16]).unwrap();
        let goal = Id::new([3; 16]).unwrap();
        let left = WatchedView {
            unread: BTreeSet::from([second, first]),
            mail_unread: BTreeSet::from([first, second]),
            goals_view: "goal-state".to_owned(),
            roster: BTreeSet::from([second, first]),
            notes: BTreeMap::from([(second, goal), (first, goal)]),
        };
        let right = WatchedView {
            unread: [first, second].into_iter().collect(),
            mail_unread: [second, first].into_iter().collect(),
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
        assert!(serialize_view(&parsed)
            .unwrap()
            .starts_with(r#"{"version":2,"#));
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
        let reader = staged.blobs_mut().reader().unwrap();
        let events = load_checkpoint_events(&reader, all.facts()).unwrap();
        let latest = latest_checkpoint(events, persona).unwrap().unwrap();
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
}
