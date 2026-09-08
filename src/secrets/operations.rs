//! Configured native operations over the standalone encrypted Secrets core.
use crate::clock;
use crate::secrets::{self, storage as secret_storage};
use crate::storage::{
    load_signer, open_pile_strict, open_secrets_collection, open_secrets_collection_read,
};
use anyhow::Result;
use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};
use triblespace::core::repo::pile::Pile;
use triblespace::prelude::*;
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub struct Secrets {
    pile: PathBuf,
    key: Option<PathBuf>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretMetadata {
    pub id: Id,
    pub name: String,
}
impl Secrets {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self { pile, key }
    }
    fn storage(&self) -> SecretsStorage<'_> {
        SecretsStorage {
            pile: &self.pile,
            key: self.key.as_deref(),
        }
    }
    /// Encrypt resident bytes once, returning the exact newly authored version.
    pub fn add(&self, name: &str, plaintext: &[u8]) -> Result<Id> {
        self.storage().with_pile(|pile, signer| {
            let collection = open_secrets_collection(pile, signer.verifying_key())?;
            secret_storage::add_secret(
                pile,
                signer,
                collection,
                name,
                plaintext,
                clock::point_now()?,
            )
        })
    }
    /// Explicitly open one exact version. Callers decide how plaintext is used.
    pub fn get(&self, secret: Id) -> Result<Zeroizing<Vec<u8>>> {
        self.storage().with_pile(|pile, signer| {
            let collection = open_secrets_collection_read(pile, signer.verifying_key())?;
            let snapshot =
                pollster::block_on(secret_storage::ensure_and_snapshot(pile, collection))?;
            snapshot.open(secret, signer).map(Zeroizing::new)
        })
    }
    /// Metadata only. Listing never attempts plaintext decryption.
    pub fn list(&self) -> Result<Vec<SecretMetadata>> {
        self.storage().with_pile(|pile, signer| {
            let collection = open_secrets_collection_read(pile, signer.verifying_key())?;
            let snapshot =
                pollster::block_on(secret_storage::ensure_and_snapshot(pile, collection))?;
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
        self.storage().with_pile(|pile, signer| {
            let collection = open_secrets_collection_read(pile, signer.verifying_key())?;
            let snapshot =
                pollster::block_on(secret_storage::maintain_and_snapshot(pile, collection))?;
            secret_storage::maintain_recipient_envelopes(
                pile, signer, &snapshot, collection, signer,
            )
        })
    }
}

#[derive(Clone, Copy)]
struct SecretsStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

impl SecretsStorage<'_> {
    fn with_pile<T>(
        self,
        operation: impl FnOnce(&mut Pile, &SigningKey) -> Result<T>,
    ) -> Result<T> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = operation(&mut pile, &signer);
        finish_pile(pile, result)
    }
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context("close Secrets pile")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing Secrets pile also failed: {close_error}")))
        }
    }
}
