use std::path::Path;

use ed25519_dalek::SigningKey;

/// Initialize the durable signer used by a descriptor-policy collection fixture.
pub(crate) fn initialize_open_collection_fixture(
    pile_path: &Path,
    key_path: Option<&Path>,
) -> SigningKey {
    crate::storage::initialize_signer(pile_path, key_path).expect("initialize fixture signer")
}
