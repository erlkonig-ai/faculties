//! Canonical root descriptors for faculty collections.
//!
//! A root collection used to be anchored by an opaque minted scope id. It
//! discriminated roots correctly and told a reader nothing: the id lived as a
//! hex constant in one faculty's source, so "which collection is this?" was
//! answerable only by someone holding the code. A root is now a self-describing
//! fragment containing its name, representation, and immutable READ and WRITE
//! admission policies. The fragment's content handle is the collection
//! identity.
//!
//! The scope ids have not gone anywhere — they remain each schema's stable
//! identifier and the key this table is read by, because the migration that
//! re-seats existing data has to speak both languages at once.

use ed25519_dalek::VerifyingKey;

use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::collection::{
    AdmissionPolicy, Collection, CollectionPolicy, CollectionRegistrationError, CollectionStoreExt,
};
use triblespace::core::id::Id;
use triblespace::core::repo::BlobStorePut;

use crate::schemas::{
    atlas, blockdag, body, cognition, compass, decide, discord, embeddings, files, habit,
    headspace, mail, memory, message, orient, planner, posture, relations, status, teams, voice,
    web, wiki,
};

/// Every root collection this build writes: the scope that used to anchor it,
/// and the name it is known by.
///
/// A faculty that is missing here cannot be opened at all, which is the point:
/// a nameless collection is one the pile cannot describe, and shipping one
/// silently is how the old scope model stayed opaque for so long. Every
/// collection in this table deliberately uses a direct READ and WRITE policy
/// rooted at the pile's durable signer. Sharing a collection later means
/// creating or migrating to a descriptor whose policy says so; it is not an
/// ambient property hidden in this table.
///
/// The ones worth naming individually:
///
/// - `memory` and `memory-comb` are the journal, first-person and personal.
/// - `compass` and `wiki` are the two JP has floated sharing. Neither becomes
///   public here: his own design for compass is a collection that shares its
///   goals but not the personal notes attached to them, which is *two*
///   collections, not one made public. A public sibling is the shape, with its
///   own explicit admission policy.
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
        (memory::DEFAULT_SCOPE_ID, "memory-journal"),
        (memory::DEFAULT_COMB_SCOPE_ID, "memory-comb"),
        (message::DEFAULT_SCOPE_ID, "message"),
        (orient::DEFAULT_SCOPE_ID, "orient"),
        (planner::DEFAULT_SCOPE_ID, "planner"),
        (posture::DEFAULT_POLICY_SCOPE_ID, "posture-policy"),
        (posture::DEFAULT_SCAN_SCOPE_ID, "posture-scan"),
        (relations::DEFAULT_SCOPE_ID, "relations"),
        (status::DEFAULT_SCOPE_ID, "status"),
        (teams::DEFAULT_SCOPE_ID, "teams"),
        (voice::COLLECTION_SCOPE_ID, "voice"),
        (web::DEFAULT_SCOPE_ID, "web"),
        (wiki::DEFAULT_SCOPE_ID, "wiki"),
    ]
}

/// The name for one scope, or `None` if this build does not know it.
pub fn name_for(scope: Id) -> Option<&'static str> {
    table()
        .into_iter()
        .find(|(candidate, _)| *candidate == scope)
        .map(|(_, name)| name)
}

/// The name for one scope, or a panic naming the scope that is missing.
///
/// Every collection this build opens is one it wrote the table entry for, so an
/// absence is a bug in this crate rather than anything a pile can cause. It is
/// loud because the alternative — inventing a name — would root real data at a
/// collection nothing else can find.
pub fn require_name(scope: Id) -> &'static str {
    name_for(scope).unwrap_or_else(|| {
        panic!(
            "no collection name for scope {scope:X}; add it to \
             faculties::collection_names::table"
        )
    })
}

/// The private policy deliberately shared by every current faculty root.
pub fn private_policy(authority: VerifyingKey) -> CollectionPolicy {
    CollectionPolicy::new(
        AdmissionPolicy::direct(authority),
        AdmissionPolicy::direct(authority),
    )
}

/// Register one faculty root and return its typed descriptor handle.
///
/// Registration is idempotent and owns the descriptor's complete attachment
/// closure. Later publication and snapshots take only the returned handle;
/// the store remains owned by its caller.
pub fn open<S>(
    storage: &mut S,
    scope: Id,
    authority: VerifyingKey,
) -> Result<Collection<SimpleArchive>, CollectionRegistrationError<<S as BlobStorePut>::PutError>>
where
    S: CollectionStoreExt,
{
    storage.collection(require_name(scope), private_policy(authority))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use ed25519_dalek::SigningKey;
    use triblespace::core::metadata;
    use triblespace::core::repo::memoryrepo::MemoryRepo;
    use triblespace::core::repo::SnapshotSource;
    use triblespace::core::trible::TribleSet;
    use triblespace::macros::entity;

    #[test]
    fn every_name_is_nonempty_and_no_two_scopes_share_one() {
        let mut names = BTreeSet::new();
        let mut scopes = BTreeSet::new();
        for (scope, name) in table() {
            assert!(!name.is_empty());
            assert!(names.insert(name), "two scopes both claim the name {name}");
            assert!(scopes.insert(scope), "scope {scope:X} appears twice");
        }
    }

    #[test]
    fn a_scope_with_no_name_is_loud_rather_than_invented() {
        assert!(name_for(Id::new([0x5a; 16]).unwrap()).is_none());
    }

    #[test]
    fn root_policy_is_identity_and_snapshot_admission() {
        let local = SigningKey::from_bytes(&[0x31; 32]);
        let foreign = SigningKey::from_bytes(&[0x73; 32]);
        let scope = wiki::DEFAULT_SCOPE_ID;
        let evidence = entity! { _ @ metadata::tag: &scope };
        let expected = evidence.facts().clone();
        let mut store = MemoryRepo::default();
        let collection = open(&mut store, scope, local.verifying_key()).unwrap();
        store
            .commit(collection, &foreign, evidence.clone())
            .unwrap();
        let store_snapshot = store.snapshot().unwrap();
        let facts = collection.read::<TribleSet, _>(&store_snapshot).unwrap();
        assert!(facts.is_empty());

        store.commit(collection, &local, evidence).unwrap();
        let store_snapshot = store.snapshot().unwrap();
        let facts = collection.read::<TribleSet, _>(&store_snapshot).unwrap();
        assert!(expected.difference(&facts).is_empty());
    }
}
