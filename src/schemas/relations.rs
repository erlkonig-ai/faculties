//! Relations schema: people and their labels, aliases, contact info.
//!
//! Used by `relations.rs` (the faculty CLI) and by any faculty that
//! needs to resolve a person by label or alias (e.g. `message.rs`).

use std::collections::{HashMap, HashSet};
use triblespace::core::metadata;
use triblespace::macros::{find, id_hex, pattern};
use triblespace::prelude::*;

pub const DEFAULT_BRANCH: &str = "relations";

pub const KIND_PERSON_ID: Id = id_hex!("D8ADDE47121F4E7868017463EC860726");

/// A group is an addressable party (like a person) whose membership is a
/// set of `group::member` edges. Sending a message to a group id delivers
/// to every member; a watcher wakes if a message is addressed to it OR to
/// a group it belongs to. `liora` is the all-zooids broadcast group.
pub const KIND_GROUP: Id = id_hex!("2CEE877C6C996CE66B4572CE8863DF04");

/// Soft-retirement events. Retiring a relation is monotonic (append-only):
/// we never delete the person entity — instead we append a small event
/// entity tagged `KIND_RETIRE_ID` pointing at the person via
/// `relations::subject`, carrying a `metadata::created_at` timestamp.
/// `unretire`/`restore` appends a `KIND_UNRETIRE_ID` event the same way.
/// A person's current state is the latest event by timestamp (retire vs
/// unretire — exactly like compass prioritize/deprioritize). Default views
/// exclude retired relations; `--all`/`--retired` reveal them. This keeps
/// the active roster clean (real people + live zooids) without ever losing
/// the imported cruft, which stays fully recoverable in the pile.
pub const KIND_RETIRE_ID: Id = id_hex!("CB9251505F663A9232C632CC9E68863A");
pub const KIND_UNRETIRE_ID: Id = id_hex!("D2D4AFCAD74CBD193B2EB7FE94AE27E9");

pub mod group {
    use super::*;
    attributes! {
        // Membership edge: group -> member (a person/window id). Repeated.
        // On a snapshot entity this is the FULL member set at that version.
        "EF5B6F8429FA30D503BA8B8F3ABD5FD9" as member: inlineencodings::GenId;
        // Anchor edge: snapshot -> its stable group anchor id. The current
        // group state is the snapshot of an anchor that nothing supersedes
        // (via `metadata::supersedes`). Name + members live on the snapshot,
        // so both version on rename/add/remove.
        "D944552B560826095BCEAFDAACE6DF66" as snapshot_of: inlineencodings::GenId;
    }
}

type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

fn interval_key(interval: IntervalValue) -> i128 {
    let (lower, _): (i128, i128) = interval.try_from_inline().unwrap();
    lower
}

/// Creation time of a snapshot (nanosecond lower bound), or `i128::MIN` if
/// unstamped. Used only as a deterministic tie-break between concurrent
/// un-superseded heads.
fn snapshot_created_at(space: &TribleSet, snapshot: Id) -> i128 {
    find!(
        at: IntervalValue,
        pattern!(space, [{ snapshot @ metadata::created_at: ?at }])
    )
    .map(interval_key)
    .max()
    .unwrap_or(i128::MIN)
}

/// The current head snapshot of a group `anchor`: the snapshot of `anchor`
/// that nothing supersedes.
///
/// Head resolution is non-monotonic ("nothing supersedes it"), so it is
/// computed here at the periphery over the append-only `metadata::supersedes`
/// DAG — never a stored "latest" pointer and never a monotonic pattern (the
/// engine cannot express negation). This is exactly why the supersedes model
/// is merge-safe: the facts stay append-only, so a merge only unions edges;
/// the head is recomputed at read time. Concurrent edits can leave more than
/// one un-superseded head (an honest fork); we pick the latest by
/// `created_at` as a deterministic tie-break, leaving both visible in history
/// for later reconciliation.
pub fn head_snapshot_of(space: &TribleSet, anchor: Id) -> Option<Id> {
    let snapshots: HashSet<Id> =
        find!(s: Id, pattern!(space, [{ ?s @ group::snapshot_of: anchor }])).collect();
    let superseded: HashSet<Id> = find!(
        old: Id,
        pattern!(space, [{ _?newer @ group::snapshot_of: anchor, metadata::supersedes: ?old }])
    )
    .collect();
    snapshots
        .into_iter()
        .filter(|s| !superseded.contains(s))
        .max_by_key(|&s| snapshot_created_at(space, s))
}

/// Current members of a group `anchor` = the members of its head snapshot.
pub fn head_members(space: &TribleSet, anchor: Id) -> HashSet<Id> {
    match head_snapshot_of(space, anchor) {
        Some(head) => {
            find!(m: Id, pattern!(space, [{ head @ group::member: ?m }])).collect()
        }
        None => HashSet::new(),
    }
}

/// Return every directly-addressable group whose CURRENT membership (its head
/// snapshot) contains `member`.
///
/// Message readers use this alongside the member's own id so broadcast
/// delivery, unread state, and watcher wakeups all share the same recipient
/// semantics.
pub fn groups_for_member(space: &TribleSet, member: Id) -> HashSet<Id> {
    find!(
        anchor: Id,
        pattern!(space, [{ ?anchor @ metadata::tag: &KIND_GROUP }])
    )
    .filter(|&anchor| head_members(space, anchor).contains(&member))
    .collect()
}

/// People whose latest retirement event says retired.
pub fn retired_person_ids(space: &TribleSet) -> HashSet<Id> {
    let mut latest: HashMap<Id, (i128, bool)> = HashMap::new();
    for (person, at) in find!(
        (person: Id, at: IntervalValue),
        pattern!(space, [{ _?evt @
            metadata::tag: &KIND_RETIRE_ID,
            relations::subject: ?person,
            metadata::created_at: ?at,
        }])
    ) {
        let key = interval_key(at);
        latest
            .entry(person)
            .and_modify(|(current, retired)| {
                if key >= *current {
                    *current = key;
                    *retired = true;
                }
            })
            .or_insert((key, true));
    }
    for (person, at) in find!(
        (person: Id, at: IntervalValue),
        pattern!(space, [{ _?evt @
            metadata::tag: &KIND_UNRETIRE_ID,
            relations::subject: ?person,
            metadata::created_at: ?at,
        }])
    ) {
        let key = interval_key(at);
        latest
            .entry(person)
            .and_modify(|(current, retired)| {
                if key > *current {
                    *current = key;
                    *retired = false;
                }
            })
            .or_insert((key, false));
    }
    latest
        .into_iter()
        .filter_map(|(id, (_, retired))| retired.then_some(id))
        .collect()
}

/// IDs of people that currently exist and are not soft-retired.
///
/// Review rosters snapshot these IDs into the request. Group membership may
/// change later without rewriting historical reviewer requirements.
pub fn active_person_ids(space: &TribleSet) -> HashSet<Id> {
    let retired = retired_person_ids(space);
    person_ids(space)
        .into_iter()
        .filter(|id| !retired.contains(id))
        .collect()
}

/// Every relations person, including soft-retired identities. Historical
/// review requests validate against this set so later retirement cannot
/// rewrite the meaning of a frozen roster.
pub fn person_ids(space: &TribleSet) -> HashSet<Id> {
    find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: &KIND_PERSON_ID }])).collect()
}

pub mod relations {
    use super::*;
    attributes! {
        "8F162B593D390E1424394DBF6883A72C" as alias: inlineencodings::ShortString;
        "299E28A10114DC8C3B1661CD90CB8DF6" as label_norm: inlineencodings::ShortString;
        "3E8812F6D22B2C93E2BCF0CE3C8C1979" as alias_norm: inlineencodings::ShortString;
        "32B22FBA3EC2ADC3FFEB48483FE8961F" as affinity: inlineencodings::ShortString;
        "F0AD0BBFAC4C4C899637573DC965622E" as first_name: inlineencodings::Handle<blobencodings::LongString>;
        "764DD765142B3F4725B614BD3B9118EC" as last_name: inlineencodings::Handle<blobencodings::LongString>;
        "DC0916CB5F640984EFE359A33105CA9A" as display_name: inlineencodings::Handle<blobencodings::LongString>;
        "9B3329149D54CB9A8E8075E4AA862649" as teams_user_id: inlineencodings::ShortString;
        "B563A063474CBE62ED25A8D0E9A1853C" as email: inlineencodings::ShortString;
        "9C2B10C740FCF7064A46F9B43D1FE278" as phone: inlineencodings::ShortString;
        // Generic contact facts (enrich every person, any source — booth leads,
        // mail senders, LinkedIn connections). LinkedIn-specific data stays in
        // the linkedin faculty; these are first-class here.
        "E3D486BD7C9C088D908DF1B9E1F4D925" as company: inlineencodings::Handle<blobencodings::LongString>;
        "173B771D35FEE90B83F2731DD3C59EF8" as position: inlineencodings::Handle<blobencodings::LongString>;
        "5A71C103E026FC1AC01E35EDAC274A5C" as profile_url: inlineencodings::Handle<blobencodings::LongString>;
        // Provenance: where this person came from ("linkedin" | "mail" | "summit" | …).
        "686FD344CD64C3F9C981C4028B1B6B9E" as source: inlineencodings::ShortString;
        // Identity resolution (non-destructive). Append-only stores can't
        // merge entities irreversibly, so a person's true identity is the
        // connected component under `same_as`. Imports auto-assert `same_as`
        // only on deterministic keys (matching email / profile_url); a
        // name-only collision is recorded as a `review_candidate` edge for an
        // agent to adjudicate with common-sense reasoning, recording the
        // verdict as `same_as` or `distinct_from` (both correctable via
        // supersede). All three point person → person.
        "0FCF3A17B2EBE7243BDDD791B901E2D6" as same_as: inlineencodings::GenId;
        "A89DC2F250432322D429D0E51316B6F3" as distinct_from: inlineencodings::GenId;
        "EB09A042DE6AA778D05C1EF795C434EE" as review_candidate: inlineencodings::GenId;
        // Subject of a retire/unretire event: retirement-event -> person.
        // See KIND_RETIRE_ID / KIND_UNRETIRE_ID above.
        "C9D3F48C660DADBDBFA32F30F595415A" as subject: inlineencodings::GenId;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use triblespace::macros::entity;

    #[test]
    fn groups_for_member_requires_membership_and_group_kind() {
        let member = ufoid().id;
        let other_member = ufoid().id;
        let first_group = ufoid().id;
        let first_snap = ufoid().id;
        let second_group = ufoid().id;
        let second_snap = ufoid().id;
        let non_group = ufoid().id;
        let non_snap = ufoid().id;
        let mut space = TribleSet::new();

        // Anchors carry only the KIND_GROUP tag; members live on the head snapshot.
        space += entity! { ExclusiveId::force_ref(&first_group) @ metadata::tag: &KIND_GROUP };
        space += entity! { ExclusiveId::force_ref(&first_snap) @
            group::snapshot_of: &first_group,
            group::member: member,
        };
        space += entity! { ExclusiveId::force_ref(&second_group) @ metadata::tag: &KIND_GROUP };
        space += entity! { ExclusiveId::force_ref(&second_snap) @
            group::snapshot_of: &second_group,
            group::member: member,
            group::member: other_member,
        };
        // Not a group (no KIND_GROUP tag) even though its snapshot lists the member.
        space += entity! { ExclusiveId::force_ref(&non_snap) @
            group::snapshot_of: &non_group,
            group::member: member,
        };

        assert_eq!(
            groups_for_member(&space, member),
            HashSet::from([first_group, second_group])
        );
        assert_eq!(
            groups_for_member(&space, other_member),
            HashSet::from([second_group])
        );
    }

    #[test]
    fn head_members_follows_the_unsuperseded_snapshot() {
        let anchor = ufoid().id;
        let m1 = ufoid().id;
        let m2 = ufoid().id;
        let s0 = ufoid().id;
        let s1 = ufoid().id;
        let mut space = TribleSet::new();
        space += entity! { ExclusiveId::force_ref(&anchor) @ metadata::tag: &KIND_GROUP };
        // s0 = {m1, m2}; s1 supersedes s0 with m2 removed (a `remove`).
        space += entity! { ExclusiveId::force_ref(&s0) @
            group::snapshot_of: &anchor,
            group::member: m1,
            group::member: m2,
        };
        space += entity! { ExclusiveId::force_ref(&s1) @
            group::snapshot_of: &anchor,
            group::member: m1,
            metadata::supersedes: &s0,
        };
        // Head = s1 (nothing supersedes it); current members = {m1}, not {m1, m2}.
        assert_eq!(head_snapshot_of(&space, anchor), Some(s1));
        assert_eq!(head_members(&space, anchor), HashSet::from([m1]));
        assert!(!head_members(&space, anchor).contains(&m2));
        assert_eq!(groups_for_member(&space, m1), HashSet::from([anchor]));
        assert!(groups_for_member(&space, m2).is_empty());
    }

    #[test]
    fn retirement_removes_future_assignment_without_erasing_identity() {
        let person = ufoid().id;
        let retirement = ufoid();
        let epoch = hifitime::Epoch::from_gregorian_utc(2026, 7, 13, 12, 0, 0, 0);
        let at: IntervalValue = (epoch, epoch).try_to_inline().unwrap();
        let mut space = TribleSet::new();
        space += entity! { ExclusiveId::force_ref(&person) @
            metadata::tag: &KIND_PERSON_ID,
        };
        space += entity! { &retirement @
            metadata::tag: &KIND_RETIRE_ID,
            relations::subject: &person,
            metadata::created_at: at,
        };

        assert!(person_ids(&space).contains(&person));
        assert!(!active_person_ids(&space).contains(&person));
    }
}
