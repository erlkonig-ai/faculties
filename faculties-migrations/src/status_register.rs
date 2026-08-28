//! Giving Compass's status register the identity it never had.
//!
//! Compass ordered a goal's status by `(created_at, event id)` among the
//! events reachable through `board::task`. That edge means *belongs to this
//! goal*, and notes and priority events carry it too — all of them stamped
//! with a timestamp. A grouping is not an identity: a note is not a later
//! version of a status event, and reading the two under one order let a note
//! at t=20 retire a status at t=10 on 778 of 2939 live goals.
//!
//! The register wanted is *the status of goal G*, and
//! [`board::status_of`](faculties::schemas::compass::board::status_of) says
//! exactly that. New status events are written with it. This transform gives
//! it to the events that predate it.
//!
//! # Why the delta is a pure function
//!
//! [`status_register_delta`] takes the facts and returns the facts to add.
//! It touches no pile, so the gate that proves the register reproduces
//! Compass's answers can apply it in memory against the live pile without
//! writing a byte, and the same bytes are what [`publish`] later appends.
//! The migration and its proof read the same code.
//!
//! # What is deliberately left alone
//!
//! An event that states no status, or no time, is not a state of a status
//! register — it names no status to be current and no instant to be current
//! at, and Compass's own read has always skipped it. Handing it an identity
//! would put it *into* the register, where its missing status could dominate
//! a real one. So the transform requires both, and the events without them
//! keep exactly the facts they have.
//!
//! `board::task` is not removed, because a pile is append-only and those
//! tribles are already written. Nothing reads it for status any more.

use anyhow::{Context, Result};
use std::path::Path;

use faculties::schemas::compass::{board, DEFAULT_SCOPE_ID, KIND_STATUS_ID};
use faculties::storage::{load_signer, open_pile_strict, publish_fragments};
use triblespace::core::metadata;
use triblespace::macros::{entity, find, pattern};
use triblespace::prelude::*;

/// What the transform found and would write.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StatusRegisterReport {
    /// Status events carrying a status, a time, and a goal.
    pub complete_events: usize,
    /// Of those, the ones that already name their register.
    pub already_identified: usize,
    /// Facts the transform adds — one identity per remaining event.
    pub facts: usize,
    /// Distinct goals whose status register the transform names.
    pub registers: usize,
    /// Status events left alone for want of a status, a time, or a goal.
    pub skipped_incomplete: usize,
}

/// Every `board::status_of` fact the Compass facts are missing.
///
/// Idempotent by construction: an event that already names its register
/// contributes nothing, so applying this twice appends nothing the second
/// time. No id is derived and none is recomputed — the identity is an
/// existing goal id under a new attribute, which is why re-running is a
/// query, not a hash comparison.
pub fn status_register_delta(facts: &TribleSet) -> (TribleSet, StatusRegisterReport) {
    let mut report = StatusRegisterReport::default();
    let mut delta = TribleSet::new();
    let mut registers = std::collections::BTreeSet::new();

    let all_status: std::collections::BTreeSet<Id> = find!(
        event: Id,
        pattern!(facts, [{ ?event @ metadata::tag: &KIND_STATUS_ID }])
    )
    .collect();

    let complete: Vec<(Id, Id)> = find!(
        (event: Id, goal: Id),
        pattern!(facts, [{ ?event @
            metadata::tag: &KIND_STATUS_ID,
            board::task: ?goal,
            board::status: _?any_status,
            metadata::created_at: _?any_time,
        }])
    )
    .collect();

    let mut complete_ids = std::collections::BTreeSet::new();
    for (event, goal) in complete {
        complete_ids.insert(event);
        report.complete_events += 1;
        let identified = exists!(pattern!(
            facts,
            [{ event @ board::status_of: _?any_register }]
        ));
        if identified {
            report.already_identified += 1;
            continue;
        }
        registers.insert(goal);
        delta += entity! { ExclusiveId::force_ref(&event) @ board::status_of: &goal };
    }

    report.registers = registers.len();
    report.facts = delta.len();
    report.skipped_incomplete = all_status.len() - complete_ids.len();
    (delta, report)
}

/// What one pile's Compass collection is missing, without writing anything.
pub fn plan(pile: &Path, key: Option<&Path>) -> Result<(TribleSet, StatusRegisterReport)> {
    let signer = load_signer(pile, key)?;
    let store = open_pile_strict(pile)?;
    let mut collection = faculties::collection_names::open(store, DEFAULT_SCOPE_ID, signer);
    let result = collection
        .materialize()
        .context("materialize the Compass collection")
        .map(|facts| status_register_delta(&facts));
    let close = collection
        .into_storage()
        .close()
        .map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(plan), Ok(())) => Ok(plan),
        (Ok(_), Err(error)) => Err(error.context("close Compass pile")),
        (Err(error), _) => Err(error),
    }
}

/// Append the identities to the live Compass collection.
///
/// Exact replay is idempotent: the delta is empty once every event names its
/// register, and the collection record is content addressed besides.
pub fn publish(pile: &Path, key: Option<&Path>) -> Result<StatusRegisterReport> {
    let (delta, report) = plan(pile, key)?;
    if delta.len() == 0 {
        return Ok(report);
    }
    let mut fragment = Fragment::empty();
    fragment += delta;
    publish_fragments(pile, key, DEFAULT_SCOPE_ID, vec![fragment])
        .context("publish Compass status-register identities")?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use faculties::compass::{note_fragment, status_fragment};
    use faculties::schemas::compass::{latest_status_event, IntervalValue};
    use hifitime::Epoch;
    use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace::core::collection::lww_register::{derive_element, LwwIndex};

    fn status_index(facts: &TribleSet) -> LwwIndex {
        let source: Blob<SimpleArchive> = facts.clone().to_blob();
        let projection = derive_element(&source, board::status_of.id(), metadata::created_at.id())
            .expect("status facts project into the maintained register algebra");
        LwwIndex::decode(&projection).expect("projected status register attaches")
    }

    /// A point interval, the shape Compass writes and validates.
    fn at(seconds: i128) -> IntervalValue {
        let value = Epoch::from_unix_seconds(seconds as f64);
        (value, value).try_to_inline().unwrap()
    }

    /// A legacy status event and a *later* legacy note on the same goal —
    /// the shape that broke 778 goals. Before the identity exists the goal
    /// has no current status; after it, the status stands and the note is
    /// not in the register at all.
    #[test]
    fn the_identity_is_what_keeps_a_note_out_of_the_status_register() {
        let goal = genid().id;
        let event = genid().id;
        let note = genid().id;

        let mut legacy = TribleSet::new();
        legacy += entity! { ExclusiveId::force_ref(&event) @
            metadata::tag: &KIND_STATUS_ID,
            board::task: &goal,
            board::status: "doing",
            metadata::created_at: at(10),
        };
        legacy += note_fragment(note, goal, "later", vec![], vec![], vec![], None, at(20))
            .unwrap()
            .facts()
            .clone();

        assert_eq!(
            latest_status_event(&legacy, &status_index(&legacy), goal),
            None,
            "without an identity the event is in no register"
        );

        let (delta, report) = status_register_delta(&legacy);
        assert_eq!(report.complete_events, 1);
        assert_eq!(report.already_identified, 0);
        assert_eq!(report.facts, 1);
        assert_eq!(report.registers, 1);

        let mut migrated = legacy.clone();
        migrated += delta.clone();
        assert_eq!(
            latest_status_event(&migrated, &status_index(&migrated), goal)
                .map(|(id, status, _)| (id, status)),
            Some((event, "doing".to_owned())),
            "the note carries no status identity, so it cannot dominate"
        );

        // Idempotent: a second pass has nothing left to say.
        let (again, report) = status_register_delta(&migrated);
        assert_eq!(again.len(), 0);
        assert_eq!(report.already_identified, 1);
        assert_eq!(report.facts, 0);
    }

    /// An event with no status names no status to be current, so it is not
    /// a state of the register and must not be handed one.
    #[test]
    fn an_event_without_a_status_is_left_out_of_the_register() {
        let goal = genid().id;
        let bare = genid().id;
        let mut legacy = TribleSet::new();
        legacy += entity! { ExclusiveId::force_ref(&bare) @
            metadata::tag: &KIND_STATUS_ID,
            board::task: &goal,
            metadata::created_at: at(30),
        };
        let (delta, report) = status_register_delta(&legacy);
        assert_eq!(delta.len(), 0);
        assert_eq!(report.complete_events, 0);
        assert_eq!(report.skipped_incomplete, 1);
    }

    /// Events written after the identity exists need no migration.
    #[test]
    fn a_current_status_event_already_names_its_register() {
        let goal = genid().id;
        let fragment = status_fragment(goal, "done", None, at(5)).unwrap();
        let (delta, report) = status_register_delta(fragment.facts());
        assert_eq!(delta.len(), 0);
        // Written with `status_of` and no `task`, so it is not even a
        // candidate for the `board::task` sweep.
        assert_eq!(report.complete_events, 0);
        assert_eq!(report.skipped_incomplete, 1);
        assert!(
            latest_status_event(fragment.facts(), &status_index(fragment.facts()), goal,).is_some()
        );
    }
}
