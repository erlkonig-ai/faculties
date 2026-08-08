//! Strict Status event projection shared by the Status CLI and Orient.
//!
//! Status is an immutable event log. Every tagged event has exactly one
//! window, text attachment, and timestamp. The current value for a window is
//! its maximal timestamp; distinct events at the same maximal timestamp stay
//! visible as an ambiguity instead of being ordered arbitrarily.

use std::collections::{BTreeMap, HashMap};

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::prelude::*;

use crate::schemas::status::{status, KIND_STATUS_UPDATE};

pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

/// One complete immutable Status event.
#[derive(Clone, Copy, Debug)]
pub struct StatusRow {
    pub event: Id,
    pub window: Id,
    pub text: TextHandle,
    pub at: IntervalValue,
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn point_interval_key(interval: IntervalValue) -> Result<i128> {
    let (lower, upper): (i128, i128) = interval
        .try_from_inline()
        .map_err(|error| anyhow!("decode status timestamp: {error:?}"))?;
    if lower != upper {
        bail!("status timestamp must be a point interval");
    }
    Ok(lower)
}

fn exactly_one<T>(event: Id, field: &str, values: Vec<T>) -> Result<T> {
    let count = values.len();
    let mut values = values.into_iter();
    match (values.next(), count) {
        (Some(value), 1) => Ok(value),
        _ => bail!(
            "status event {} has {count} values for {field}; expected exactly one",
            fmt_id(event)
        ),
    }
}

fn status_record(window: Id, text: TextHandle, at: IntervalValue) -> Fragment {
    entity! {
        metadata::tag: &KIND_STATUS_UPDATE,
        status::window: window,
        status::text: text,
        metadata::created_at: at,
    }
}

/// Build one intrinsic immutable point-valued Status event and carry its text
/// attachment.
pub fn status_fragment(window: Id, text: &str, at: IntervalValue) -> Result<Fragment> {
    point_interval_key(at)?;
    let mut fragment = Fragment::empty();
    let text: TextHandle = fragment.put(text.to_owned());
    fragment += status_record(window, text, at);
    Ok(fragment)
}

/// Project every tagged Status event, rejecting missing or multi-valued
/// scalar fields rather than allowing query iteration order to choose one.
pub fn load_status_rows(space: &TribleSet) -> Result<Vec<StatusRow>> {
    let mut events: Vec<Id> = find!(
        event: Id,
        pattern!(space, [{ ?event @ metadata::tag: &KIND_STATUS_UPDATE }])
    )
    .collect();
    events.sort_unstable();
    events.dedup();

    events
        .into_iter()
        .map(|event| {
            let window = exactly_one(
                event,
                "status::window",
                find!(
                    window: Id,
                    pattern!(space, [{ event @ status::window: ?window }])
                )
                .collect(),
            )?;
            let text = exactly_one(
                event,
                "status::text",
                find!(
                    text: TextHandle,
                    pattern!(space, [{ event @ status::text: ?text }])
                )
                .collect(),
            )?;
            let at = exactly_one(
                event,
                "metadata::created_at",
                find!(
                    at: IntervalValue,
                    pattern!(space, [{ event @ metadata::created_at: ?at }])
                )
                .collect(),
            )?;
            Ok(StatusRow {
                event,
                window,
                text,
                at,
            })
        })
        .collect()
}

/// Resolve the latest event per window. Equal-time distinct maximal events
/// are a fork, not an invitation to smuggle iteration order in as
/// last-write-wins.
pub fn latest_per_window(
    rows: impl IntoIterator<Item = StatusRow>,
) -> Result<HashMap<Id, StatusRow>> {
    let mut frontiers: HashMap<Id, (i128, BTreeMap<Id, StatusRow>)> = HashMap::new();
    for row in rows {
        let at = point_interval_key(row.at)
            .with_context(|| format!("validate timestamp on status event {}", fmt_id(row.event)))?;
        let entry = frontiers
            .entry(row.window)
            .or_insert_with(|| (at, BTreeMap::new()));
        match at.cmp(&entry.0) {
            std::cmp::Ordering::Greater => {
                entry.0 = at;
                entry.1.clear();
                entry.1.insert(row.event, row);
            }
            std::cmp::Ordering::Equal => {
                entry.1.insert(row.event, row);
            }
            std::cmp::Ordering::Less => {}
        }
    }

    let mut latest = HashMap::with_capacity(frontiers.len());
    for (window, (_, frontier)) in frontiers {
        let mut rows = frontier.into_values();
        let row = rows.next().expect("status frontier is never empty");
        if let Some(other) = rows.next() {
            bail!(
                "ambiguous current status for window {}: distinct events {} and {} have the same maximal timestamp",
                fmt_id(window),
                fmt_id(row.event),
                fmt_id(other.event),
            );
        }
        latest.insert(window, row);
    }
    Ok(latest)
}

/// Strictly read one Status text attachment.
pub fn read_text(reader: &PileReader, handle: TextHandle) -> Result<String> {
    let text: anybytes::View<str> = reader.get(handle).context("read status text")?;
    Ok(text.to_string())
}

/// Validate the exact collection ontology and every referenced text
/// attachment. Each event must be a point-valued intrinsic record containing
/// exactly the four Status facts, and every collection fact must belong to one
/// such event. Equal-time forks remain valid catalog state and are surfaced
/// only when a caller asks for the current value.
pub fn validate_catalog(reader: &PileReader, space: &TribleSet) -> Result<()> {
    let rows = load_status_rows(space)?;
    let mut facts_by_entity = HashMap::<Id, usize>::new();
    for fact in space.iter() {
        *facts_by_entity.entry(*fact.e()).or_default() += 1;
    }
    let mut validated_facts = 0usize;
    for row in rows {
        point_interval_key(row.at)
            .with_context(|| format!("validate timestamp on status event {}", fmt_id(row.event)))?;
        let expected = status_record(row.window, row.text, row.at);
        let expected_event = expected
            .root()
            .expect("canonical Status record has one intrinsic root");
        if row.event != expected_event {
            bail!(
                "status event {} is not intrinsic; canonical identity is {}. Legacy random-id Status events require an explicit stopped-world transforming migration",
                fmt_id(row.event),
                fmt_id(expected_event),
            );
        }

        let expected_facts = expected.facts().len();
        let actual_facts = facts_by_entity.get(&row.event).copied().unwrap_or_default();
        if actual_facts != expected_facts {
            bail!(
                "status event {} has {actual_facts} facts; expected exactly {expected_facts}",
                fmt_id(row.event),
            );
        }
        read_text(reader, row.text)
            .with_context(|| format!("validate text on status event {}", fmt_id(row.event)))?;
        validated_facts += expected_facts;
    }

    let catalog_facts = space.len();
    if validated_facts != catalog_facts {
        bail!(
            "Status collection has {} facts outside canonical Status events",
            catalog_facts - validated_facts,
        );
    }
    Ok(())
}
