//! Canonical root descriptors for faculty collections.
//!
//! A root collection used to be anchored by an opaque minted scope id. It
//! discriminated roots correctly and told a reader nothing: the id lived as a
//! hex constant in one faculty's source, so "which collection is this?" was
//! answerable only by someone holding the code. A root is now a self-describing
//! fragment containing its name, mandatory authority, representation, recipe,
//! and reach. The fragment's content handle is the collection identity.
//!
//! The scope ids have not gone anywhere — they remain each schema's stable
//! identifier and the key this table is read by, because the migration that
//! re-seats existing data has to speak both languages at once.

use ed25519_dalek::VerifyingKey;

use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::collection::reach;
use triblespace::core::collection::{
    simplearchive_union, Collection, CollectionRegistrationError, CollectionStoreExt,
};
use triblespace::core::id::Id;
use triblespace::core::repo::{ArtifactOfferStore, BlobStorePut};
use triblespace::core::trible::Fragment;

use crate::schemas::{
    atlas, blockdag, body, cognition, compass, decide, discord, embeddings, files, habit,
    headspace, mail, memory, message, orient, planner, posture, relations, status, teams, voice,
    web, wiki,
};

/// Every root collection this build writes: the scope that used to anchor it,
/// the name it is known by, and how far it travels.
///
/// A faculty that is missing here cannot be opened at all, which is the point:
/// a nameless collection is one the pile cannot describe, and shipping one
/// silently is how the old scope model stayed opaque for so long. Reach sits
/// in the same row for the same reason -- it is part of the collection's
/// identity, so adding a faculty makes you state it rather than inherit a
/// default you never saw.
///
/// **Everything here is [`reach::private`], and that is a decision rather than
/// a default.** Most of the collections that plausibly want to
/// travel do not want [`reach::public`]. `message`, `status`, `relations` and
/// `teams` coordinate peers on one team; what they want is "this team and
/// no one else", which is a reach law that does not exist yet. Declaring them
/// public to approximate it would be worse than declaring nothing.
///
/// The ones worth naming individually:
///
/// - `memory` and `memory-comb` are the journal, first-person and personal.
/// - `compass` and `wiki` are the two JP has floated sharing. Neither becomes
///   public here: his own design for compass is a collection that shares its
///   goals but not the personal notes attached to them, which is *two*
///   collections, not one made public. A public sibling is the shape, and
///   reach in the descriptor is what makes a sibling safe to keep in the same
///   pile.
pub fn table() -> Vec<(Id, &'static str, Fragment)> {
    vec![
        (atlas::DEFAULT_SCOPE_ID, "atlas", reach::private()),
        (blockdag::DEFAULT_SCOPE_ID, "blockdag", reach::private()),
        (body::DEFAULT_SCOPE_ID, "body", reach::private()),
        (cognition::DEFAULT_SCOPE_ID, "cognition", reach::private()),
        (compass::DEFAULT_SCOPE_ID, "compass", reach::private()),
        (decide::DEFAULT_SCOPE_ID, "decide", reach::private()),
        (discord::DEFAULT_SCOPE_ID, "discord", reach::private()),
        (embeddings::DEFAULT_SCOPE_ID, "embeddings", reach::private()),
        (files::DEFAULT_SCOPE_ID, "files", reach::private()),
        (habit::DEFAULT_SCOPE_ID, "habit", reach::private()),
        (headspace::DEFAULT_SCOPE_ID, "headspace", reach::private()),
        (mail::DEFAULT_SCOPE_ID, "mail", reach::private()),
        (memory::DEFAULT_SCOPE_ID, "memory-journal", reach::private()),
        (
            memory::DEFAULT_COMB_SCOPE_ID,
            "memory-comb",
            reach::private(),
        ),
        (message::DEFAULT_SCOPE_ID, "message", reach::private()),
        (orient::DEFAULT_SCOPE_ID, "orient", reach::private()),
        (planner::DEFAULT_SCOPE_ID, "planner", reach::private()),
        (
            posture::DEFAULT_POLICY_SCOPE_ID,
            "posture-policy",
            reach::private(),
        ),
        (
            posture::DEFAULT_SCAN_SCOPE_ID,
            "posture-scan",
            reach::private(),
        ),
        (relations::DEFAULT_SCOPE_ID, "relations", reach::private()),
        (status::DEFAULT_SCOPE_ID, "status", reach::private()),
        (teams::DEFAULT_SCOPE_ID, "teams", reach::private()),
        (voice::COLLECTION_SCOPE_ID, "voice", reach::private()),
        (web::DEFAULT_SCOPE_ID, "web", reach::private()),
        (wiki::DEFAULT_SCOPE_ID, "wiki", reach::private()),
    ]
}

/// The name for one scope, or `None` if this build does not know it.
pub fn name_for(scope: Id) -> Option<&'static str> {
    table()
        .into_iter()
        .find(|(candidate, _, _)| *candidate == scope)
        .map(|(_, name, _)| name)
}

/// How far one scope's collection travels, or `None` if this build does not
/// know the scope.
pub fn reach_for(scope: Id) -> Option<Fragment> {
    table()
        .into_iter()
        .find(|(candidate, _, _)| *candidate == scope)
        .map(|(_, _, reach)| reach)
}

/// How far one scope's collection travels, or a panic naming the missing scope.
///
/// Loud for the same reason [`require_name`] is: reach is part of the
/// descriptor, so guessing it would compute a handle for a collection nothing
/// else can find. That failure looks like an empty faculty rather than an
/// error, which is exactly the kind of silence worth refusing to produce.
pub fn require_reach(scope: Id) -> Fragment {
    reach_for(scope).unwrap_or_else(|| {
        panic!(
            "no reach for scope {scope:X}; add it to \
             faculties::collection_names::table"
        )
    })
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

/// The canonical root descriptor for one scope under `authority`.
///
/// The authority is a mandatory descriptor fact and therefore participates in
/// the returned collection's content identity. There is no parallel namespace
/// or caller-supplied admission policy which can disagree with it.
pub fn root_descriptor(scope: Id, authority: VerifyingKey) -> Fragment {
    simplearchive_union::descriptor(require_name(scope), authority, require_reach(scope))
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
) -> Result<
    Collection<SimpleArchive>,
    CollectionRegistrationError<
        <S as BlobStorePut>::PutError,
        <S as ArtifactOfferStore>::OfferError,
    >,
>
where
    S: CollectionStoreExt,
{
    storage.collection::<SimpleArchive>(root_descriptor(scope, authority))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use ed25519_dalek::SigningKey;
    use triblespace::core::collection::descriptor;
    use triblespace::core::metadata;
    use triblespace::core::repo::memoryrepo::MemoryRepo;
    use triblespace::core::repo::SnapshotSource;
    use triblespace::core::trible::TribleSet;
    use triblespace::macros::entity;

    #[test]
    fn every_name_is_nonempty_and_no_two_scopes_share_one() {
        let mut names = BTreeSet::new();
        let mut scopes = BTreeSet::new();
        for (scope, name, _reach) in table() {
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
    fn root_authority_is_identity_and_snapshot_admission() {
        let local = SigningKey::from_bytes(&[0x31; 32]);
        let foreign = SigningKey::from_bytes(&[0x73; 32]);
        let scope = wiki::DEFAULT_SCOPE_ID;
        let descriptor_fragment = root_descriptor(scope, local.verifying_key());
        assert_eq!(
            descriptor::authority(descriptor_fragment.facts()).unwrap(),
            local.verifying_key()
        );

        let evidence = entity! { _ @ metadata::tag: &scope };
        let expected = evidence.facts().clone();
        let mut store = MemoryRepo::default();
        let collection = store
            .collection::<SimpleArchive>(descriptor_fragment)
            .unwrap();
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
