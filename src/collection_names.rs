//! The name each faculty's root collection is known by within its team.
//!
//! A root collection used to be anchored by an opaque minted scope id. It
//! discriminated roots correctly and told a reader nothing: the id lived as a
//! hex constant in one faculty's source, so "which collection is this?" was
//! answerable only by someone holding the code. A root is now anchored by a
//! NAME plus its team's root public key, and this is where a faculty says its
//! name out loud.
//!
//! The scope ids have not gone anywhere — they remain each schema's stable
//! identifier and the key this table is read by, because the migration that
//! re-seats existing data has to speak both languages at once.

use ed25519_dalek::{SigningKey, VerifyingKey};

use triblespace::core::collection::records::CollectionName;
use triblespace::core::collection::{simplearchive_union, Collection};
use triblespace::core::id::Id;
use triblespace::core::trible::Fragment;

use crate::schemas::{
    atlas, blockdag, body, cognition, compass, decide, discord, embeddings, files, habit,
    headspace, mail, memory, message, orient, planner, posture, relations, status, teams, voice,
    web, wiki,
};

/// Every root collection this build writes, by the scope that used to anchor it.
///
/// A faculty that is missing here cannot be opened at all, which is the point:
/// a nameless collection is one the pile cannot describe, and shipping one
/// silently is how the old scope model stayed opaque for so long.
pub fn table() -> Vec<(Id, &'static str)> {
    vec![
        (atlas::DEFAULT_SCOPE_ID, "atlas"),
        (blockdag::DEFAULT_SCOPE_ID, "blockdag"),
        (body::DEFAULT_SCOPE_ID, "body"),
        (cognition::DEFAULT_SCOPE_ID, "cognition"),
        (compass::DEFAULT_SCOPE_ID, "compass"),
        (decide::DEFAULT_SCOPE_ID, "decide"),
        (discord::DEFAULT_SCOPE_ID, "discord"),
        (embeddings::DEFAULT_SCOPE_ID, "embeddings"),
        (files::DEFAULT_SCOPE_ID, "files"),
        (habit::DEFAULT_SCOPE_ID, "habit"),
        (headspace::DEFAULT_SCOPE_ID, "headspace"),
        (mail::DEFAULT_SCOPE_ID, "mail"),
        (memory::DEFAULT_SCOPE_ID, "memory"),
        (memory::DEFAULT_COMB_SCOPE_ID, "memory-comb"),
        (message::DEFAULT_SCOPE_ID, "message"),
        (orient::DEFAULT_SCOPE_ID, "orient"),
        (planner::DEFAULT_SCOPE_ID, "planner"),
        (posture::DEFAULT_POLICY_SCOPE_ID, "posture-policy"),
        (posture::DEFAULT_SCAN_SCOPE_ID, "posture-scan"),
        (relations::DEFAULT_SCOPE_ID, "relations"),
        (crate::secrets::schema::DEFAULT_SCOPE_ID, "secrets"),
        (status::DEFAULT_SCOPE_ID, "status"),
        (teams::DEFAULT_SCOPE_ID, "teams"),
        (voice::COLLECTION_SCOPE_ID, "voice"),
        (web::DEFAULT_SCOPE_ID, "web"),
        (wiki::DEFAULT_SCOPE_ID, "wiki"),
    ]
}

/// The name for one scope, or `None` if this build does not know it.
pub fn name_for(scope: Id) -> Option<CollectionName> {
    table()
        .into_iter()
        .find(|(candidate, _)| *candidate == scope)
        .map(|(_, name)| {
            CollectionName::new(name).expect("a name in this table is a legal collection name")
        })
}

/// The name for one scope, or a panic naming the scope that is missing.
///
/// Every collection this build opens is one it wrote the table entry for, so an
/// absence is a bug in this crate rather than anything a pile can cause. It is
/// loud because the alternative — inventing a name — would root real data at a
/// collection nothing else can find.
pub fn require_name(scope: Id) -> CollectionName {
    name_for(scope).unwrap_or_else(|| {
        panic!(
            "no collection name for scope {scope:X}; add it to \
             faculties::collection_names::table"
        )
    })
}

/// The canonical root descriptor for one scope within `team`.
///
/// `team` is the team's ROOT key, a genesis fact archived offline, not the key
/// that signs commits. They coincide only for a team of one, and a caller that
/// means that has to say so by passing `signer.verifying_key()` — defaulting to
/// it here would quietly root every collection at whichever key was writing.
pub fn root_descriptor(scope: Id, team: VerifyingKey) -> Fragment {
    simplearchive_union::descriptor(&require_name(scope), team)
}

/// Open one scope's collection as a TEAM OF ONE.
///
/// This pile's own durable identity is its team root. That is the honest anchor
/// for a pile nobody else writes to, and promoting it to a real multi-node team
/// later is a re-root — a new collection reached by deriving — rather than a
/// rename.
///
/// It lives here, in one place, precisely because it is a judgement rather than
/// a default: `Collection::new` deliberately refuses to guess a team, and
/// fifteen call sites each spelling `signer.verifying_key()` would be fifteen
/// places for that judgement to quietly diverge.
pub fn open<S>(storage: S, scope: Id, signer: SigningKey) -> Collection<S> {
    let team = signer.verifying_key();
    Collection::new(storage, &require_name(scope), team, signer)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    #[test]
    fn every_name_is_legal_and_no_two_scopes_share_one() {
        let mut names = BTreeSet::new();
        let mut scopes = BTreeSet::new();
        for (scope, name) in table() {
            assert!(
                CollectionName::new(name).is_ok(),
                "{name} is not a legal collection name"
            );
            assert!(names.insert(name), "two scopes both claim the name {name}");
            assert!(scopes.insert(scope), "scope {scope:X} appears twice");
        }
    }

    #[test]
    fn a_scope_with_no_name_is_loud_rather_than_invented() {
        assert!(name_for(Id::new([0x5a; 16]).unwrap()).is_none());
    }
}
