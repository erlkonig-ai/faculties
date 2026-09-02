//! Orient's grow-only presentation ledger.
//!
//! Source faculties define which events deserve attention. Orient records only
//! the irreducible observer state: whether one exact persona has already been
//! presented one exact event. Store snapshots and collection covers are local
//! continuation tokens, not durable facts, and therefore do not live here.

use std::collections::BTreeSet;

use triblespace::core::metadata;
use triblespace::macros::{entity, find, pattern};
use triblespace::prelude::*;

use crate::schemas::orient::{presentation, KIND_PRESENTED};

fn presented_record(persona: Id, event: Id) -> Fragment {
    entity! {
        metadata::tag: &KIND_PRESENTED,
        presentation::persona: &persona,
        presentation::event: &event,
    }
}

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

/// Exact event identities already presented to one persona.
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
