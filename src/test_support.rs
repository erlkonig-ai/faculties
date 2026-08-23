use std::path::Path;

use ed25519_dalek::SigningKey;
use triblespace::core::authority::{publish_grant, AuthorityGrant, AuthorityMode, ACTION_WRITE};
use triblespace::core::collection::{records::CollectionHandle, CollectionStore};
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::BlobStorePut;

/// Give a pile fixture the explicit team-of-one WRITE authority that normal
/// deployments receive through the authority migration.
pub(crate) fn grant_team_of_one_write_authority(pile: &mut Pile, signer: &SigningKey) {
    crate::storage::ensure_team_of_one_write_authority(pile, signer)
        .expect("grant fixture team-of-one WRITE authority");
}

/// Initialize a fixture signer and publish its explicit team-of-one WRITE
/// grants before any faculty tries to commit.
pub(crate) fn initialize_team_of_one_write_fixture(
    pile_path: &Path,
    key_path: Option<&Path>,
) -> SigningKey {
    let signer =
        crate::storage::initialize_signer(pile_path, key_path).expect("initialize fixture signer");
    let mut pile = crate::storage::open_pile_strict(pile_path).expect("open fixture pile");
    grant_team_of_one_write_authority(&mut pile, &signer);
    pile.close().expect("close authorized fixture pile");
    signer
}

/// Publish one explicit root Invoke/WRITE grant for a non-pile collection
/// fixture, such as an in-memory repository.
pub(crate) fn grant_collection_write_authority<S>(
    store: &mut S,
    resource: CollectionHandle,
    signer: &SigningKey,
) where
    S: BlobStorePut + CollectionStore,
{
    let team = signer.verifying_key();
    publish_grant(
        store,
        team,
        signer,
        AuthorityGrant::root(team, resource, ACTION_WRITE, AuthorityMode::Invoke),
    )
    .expect("grant fixture collection WRITE authority");
}
