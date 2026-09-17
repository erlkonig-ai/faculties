//! Configured native operations over the standalone encrypted Secrets core.
use crate::clock;
use crate::secrets::{self, storage as secret_storage};
use crate::storage::{open_secrets_collection, open_secrets_collection_read};
use anyhow::Result;
use ed25519_dalek::{SigningKey, VerifyingKey};
use faculties_secrets::resource::{DeliveryLimits, SecretTarget};
use std::path::PathBuf;
use triblespace::core::capability::CapabilityProofId;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::SnapshotSource;
use triblespace::prelude::*;
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub struct Secrets {
    storage: crate::storage::Storage,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretMetadata {
    pub id: Id,
    pub name: String,
}
impl Secrets {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }
    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self { storage }
    }
    fn storage(&self) -> SecretsStorage<'_> {
        SecretsStorage {
            storage: &self.storage,
        }
    }
    /// Encrypt resident bytes once, returning the exact newly authored version.
    pub fn add(&self, name: &str, plaintext: &[u8]) -> Result<Id> {
        self.storage().with_pile(|pile, signer| {
            let collection = open_secrets_collection(pile, signer.verifying_key())?;
            let secret = secret_storage::add_secret(
                pile,
                signer,
                collection,
                name,
                plaintext,
                clock::point_now()?,
            )?;
            Ok(secret)
        })
    }
    /// Explicitly open one exact version. Callers decide how plaintext is used.
    pub fn get(&self, secret: Id) -> Result<Zeroizing<Vec<u8>>> {
        self.storage().with_pile(|pile, signer| {
            let collection = open_secrets_collection_read(pile, signer.verifying_key())?;
            let snapshot = pollster::block_on(secret_storage::ensure_and_snapshot(
                pile, collection, signer,
            ))?;
            snapshot.open(secret, signer).map(Zeroizing::new)
        })
    }
    /// Metadata only. Listing never attempts plaintext decryption.
    pub fn list(&self) -> Result<Vec<SecretMetadata>> {
        self.storage().with_pile(|pile, signer| {
            let collection = open_secrets_collection_read(pile, signer.verifying_key())?;
            let snapshot = pollster::block_on(secret_storage::ensure_and_snapshot(
                pile, collection, signer,
            ))?;
            let Some(facts) = snapshot.facts() else {
                return Ok(Vec::new());
            };
            secrets::secret_rows(facts)
                .into_iter()
                .map(|row| {
                    Ok(SecretMetadata {
                        id: row.id,
                        name: secrets::read_text(snapshot.store_snapshot(), row.name)?,
                    })
                })
                .collect()
        })
    }
    /// Explicit key-delivery maintenance; does not grant new capabilities.
    pub fn maintain(&self) -> Result<usize> {
        self.maintain_selected(&[])
    }
    pub fn maintain_selected(&self, selected: &[SecretTarget]) -> Result<usize> {
        self.storage().with_pile(|pile, signer| {
            let collection = open_secrets_collection_read(pile, signer.verifying_key())?;
            let snapshot = pollster::block_on(secret_storage::maintain_and_snapshot(
                pile, collection, signer,
            ))?;
            let count = secret_storage::maintain_selected_recipient_envelopes(
                pile,
                signer,
                &snapshot,
                collection,
                signer,
                selected,
                clock::now()?,
            )?;
            Ok(count)
        })
    }
    /// Sign resource-specific delivery authority, without granting collection
    /// READ/WRITE and without delivering or exporting plaintext.
    pub fn grant(
        &self,
        target: SecretTarget,
        recipient: VerifyingKey,
        limits: DeliveryLimits,
        delegate: bool,
    ) -> Result<Vec<CapabilityProofId>> {
        self.storage().with_pile(|pile, signer| {
            let collection = open_secrets_collection_read(pile, signer.verifying_key())?;
            let snapshot = match target {
                SecretTarget::Resource(_) => {
                    secret_storage::snapshot(pile.snapshot()?, collection)?
                }
                SecretTarget::Secret(_) => pollster::block_on(
                    secret_storage::ensure_and_snapshot(pile, collection, signer),
                )?,
            };
            secrets::resource::grant(pile, signer, &snapshot, target, recipient, limits, delegate)
        })
    }
}

#[derive(Clone, Copy)]
struct SecretsStorage<'a> {
    storage: &'a crate::storage::Storage,
}

impl SecretsStorage<'_> {
    fn with_pile<T>(
        self,
        operation: impl FnOnce(&mut Pile, &SigningKey) -> Result<T>,
    ) -> Result<T> {
        self.storage.with_pile(operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_added_secret_is_queryable_and_openable_through_an_ordinary_read() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("secrets.pile");
        std::fs::File::create(&path).unwrap();
        let signer = crate::storage::initialize_signer(&path, None).unwrap();
        let id = Secrets::new(path.clone(), None)
            .add("eager fixture", b"generated disposable secret")
            .unwrap();

        let mut pile = crate::storage::open_pile_strict(&path).unwrap();
        let collection = open_secrets_collection_read(&mut pile, signer.verifying_key()).unwrap();
        // The ordinary read path prepares the target, exactly as get/list do.
        let snapshot = pollster::block_on(secret_storage::ensure_and_snapshot(
            &mut pile, collection, &signer,
        ))
        .unwrap();
        assert!(secrets::secret_rows(snapshot.facts().unwrap())
            .iter()
            .any(|row| row.id == id));
        assert_eq!(
            snapshot.open(id, &signer).unwrap(),
            b"generated disposable secret"
        );
        drop(snapshot);
        pile.close().unwrap();
    }
}
