//! Orient's grow-only presentation ledger.
//!
//! Source faculties define which events deserve attention. Orient records only
//! the irreducible observer state: whether one signing zooid has already been
//! presented one exact event. New receipts belong to the signing zooid's private
//! collection; the persona field below is only the legacy import vocabulary.
//! Store snapshots and collection covers are local
//! continuation tokens, not durable facts, and therefore do not live here.

use std::collections::BTreeSet;

use triblespace::core::metadata;
use triblespace::macros::{entity, find, pattern};
use triblespace::prelude::*;

use crate::schemas::orient::{presentation, KIND_PRESENTED};

pub mod cli;
pub mod mcp;
mod operations;
pub use operations::{BaselineReceipt, Orient, ShowOptions, WaitOptions, WakeOptions};

/// Receipt facts for a key-private source collection. Event identity is stable
/// across retries; observation times annotate that identity, never qualify the
/// derived ID set. The collection descriptor identifies the observing zooid.
pub fn receipt_fragment(
    events: impl IntoIterator<Item = Id>,
    created_at: Inline<inlineencodings::NsTAIInterval>,
) -> Fragment {
    let mut fragment = Fragment::empty();
    for event in events {
        let receipt = entity! {
            metadata::tag: &KIND_PRESENTED,
            presentation::event: &event,
        };
        let id = receipt.root().expect("one receipt entity");
        fragment += receipt;
        fragment += entity! { ExclusiveId::force_ref(&id) @ metadata::created_at: &created_at };
    }
    fragment
}

fn presented_record(persona: Id, event: Id) -> Fragment {
    entity! {
        metadata::tag: &KIND_PRESENTED,
        presentation::persona: &persona,
        presentation::event: &event,
    }
}

/// Legacy mixed-persona receipt facts, retained for explicit imports.
/// Build intrinsic grow-only facts saying that `persona` was presented each
/// supplied event.
///
/// Repeating a pair produces the same entity and is therefore idempotent.
/// Presentation is deliberately distinct from a source faculty's native
/// "read", "handled", or "acknowledged" state.
pub fn presented_fragment(persona: Id, events: impl IntoIterator<Item = Id>) -> Fragment {
    let mut fragment = Fragment::empty();
    for event in events {
        fragment += presented_record(persona, event);
    }
    fragment
}

/// Exact event identities in a legacy mixed-persona receipt collection.
pub fn presented_events(facts: &TribleSet, persona: Id) -> BTreeSet<Id> {
    find!(
        event: Id,
        pattern!(facts, [{
            _?presentation @
            metadata::tag: &KIND_PRESENTED,
            presentation::persona: &persona,
            presentation::event: ?event,
        }])
    )
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_time_annotates_identity_without_qualifying_membership() {
        let event = Id::new([8; 16]).unwrap();
        let first_time = crate::clock::point(hifitime::Epoch::from_unix_seconds(10.0)).unwrap();
        let next_time = crate::clock::point(hifitime::Epoch::from_unix_seconds(20.0)).unwrap();
        let first = receipt_fragment([event], first_time);
        let next = receipt_fragment([event, event], next_time);
        let subjects = |facts: &TribleSet| {
            find!(id: Id, pattern!(facts, [{ ?id @ presentation::event: &event }]))
                .collect::<BTreeSet<_>>()
        };
        let identities = subjects(first.facts());
        assert_eq!(identities.len(), 1);
        assert_eq!(identities, subjects(next.facts()));
        let mut both = first;
        both += next;
        let receipt = *identities.first().unwrap();
        let times: BTreeSet<Inline<inlineencodings::NsTAIInterval>> = find!(
            at: Inline<inlineencodings::NsTAIInterval>,
            pattern!(both.facts(), [{ receipt @ metadata::created_at: ?at }])
        )
        .collect();
        assert_eq!(times, BTreeSet::from([first_time, next_time]));
        assert!(!exists!(
            pattern!(both.facts(), [{ _?receipt @ presentation::persona: _?persona }])
        ));
    }

    #[test]
    fn presentation_atoms_are_intrinsic_and_idempotent() {
        let persona = Id::new([1; 16]).unwrap();
        let first = Id::new([2; 16]).unwrap();
        let second = Id::new([3; 16]).unwrap();

        let once = presented_fragment(persona, [first, second]);
        let mut repeated = presented_fragment(persona, [second, first]);
        repeated += presented_fragment(persona, [first, first]);

        assert_eq!(once.facts(), repeated.facts());
        assert_eq!(
            presented_events(once.facts(), persona),
            BTreeSet::from([first, second]),
        );
    }

    #[test]
    fn presentation_is_scoped_to_the_exact_persona() {
        let first_persona = Id::new([1; 16]).unwrap();
        let second_persona = Id::new([2; 16]).unwrap();
        let shared_event = Id::new([3; 16]).unwrap();
        let private_event = Id::new([4; 16]).unwrap();

        let mut facts = presented_fragment(first_persona, [shared_event, private_event]);
        facts += presented_fragment(second_persona, [shared_event]);

        assert_eq!(
            presented_events(facts.facts(), first_persona),
            BTreeSet::from([shared_event, private_event]),
        );
        assert_eq!(
            presented_events(facts.facts(), second_persona),
            BTreeSet::from([shared_event]),
        );
    }

    #[test]
    fn unrelated_open_world_facts_are_ignored() {
        let persona = Id::new([1; 16]).unwrap();
        let event = Id::new([2; 16]).unwrap();
        let unrelated = Id::new([3; 16]).unwrap();
        let mut facts = presented_fragment(persona, [event]);
        facts += entity! {
            metadata::tag: &unrelated,
        };

        assert_eq!(
            presented_events(facts.facts(), persona),
            BTreeSet::from([event]),
        );
    }
}
