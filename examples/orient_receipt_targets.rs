//! Print the private receipt descriptors for one public signing key.
//!
//! `cargo run --example orient_receipt_targets -- PUBLIC_KEY_HEX`
//! constructs the same descriptors as Orient in memory: no pile, private key,
//! network, or receipt history is read or changed. The target handle can be
//! selected in an external `trible pile collection maintain-all ... --watch`.

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::VerifyingKey;
use faculties::collection_names::private_policy;
use faculties::schemas::orient::{presentation, RECEIPT_COLLECTION_NAME};
use triblespace::core::blob::encodings::entity_id_set::EntityIdSetBlob;
use triblespace::core::collection::CollectionStoreExt;
use triblespace::core::repo::memoryrepo::MemoryRepo;

fn main() -> Result<()> {
    let key = std::env::args()
        .nth(1)
        .context("usage: orient_receipt_targets PUBLIC_KEY_HEX")?;
    let bytes: [u8; 32] = hex::decode(key)?
        .try_into()
        .map_err(|_| anyhow!("public key must be 32 bytes"))?;
    let policy = private_policy(VerifyingKey::from_bytes(&bytes)?);
    let mut store = MemoryRepo::default();
    let source = store.collection(RECEIPT_COLLECTION_NAME, policy.clone())?;
    let target = store.derive::<EntityIdSetBlob>(source, presentation::event.id(), policy)?;
    println!("source {}", hex::encode(source.handle().raw));
    println!("target {}", hex::encode(target.handle().raw));
    println!("attribute {:x}", presentation::event.id());
    Ok(())
}
