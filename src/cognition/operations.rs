//! Whole-collection Cognition validation as a direct library operation.
//! Event authoring remains in the existing shared publication API.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::{CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::repo::SnapshotSource;

use crate::collection_names::open_configured;
use crate::schemas::cognition::DEFAULT_SCOPE_ID;
use crate::storage::{load_signer, open_pile_strict, FactArchive};

#[derive(Clone, Debug)]
pub struct Cognition {
    pile: PathBuf,
    key: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckReport {
    pub facts: usize,
}

impl CheckReport {
    pub fn summary(&self) -> String {
        format!(
            "Cognition scope {DEFAULT_SCOPE_ID:X}: {} facts validated",
            self.facts
        )
    }
}

impl Cognition {
    /// Trusted launcher-owned configuration, not caller-selected tool fields.
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self { pile, key }
    }

    pub fn check(&self) -> Result<CheckReport> {
        let signer = load_signer(&self.pile, self.key.as_deref())?;
        let mut pile = open_pile_strict(&self.pile)?;
        let result = (|| {
            let source = open_configured(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
            let descriptor_snapshot = pile.snapshot()?;
            let policy = source.policy(&descriptor_snapshot)?;
            drop(descriptor_snapshot);
            let succinct = pile.derive::<SuccinctArchiveBlob>(source, (), policy.clone())?;
            let rank9 = pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)?;
            let snapshot = pollster::block_on(async {
                drop(pile.ensure(source).await?);
                drop(pile.maintain(succinct).await?);
                pile.maintain(rank9).await
            })
            .context("maintain Cognition fact collection")?;
            let facts = snapshot
                .collection(rank9)
                .context("observe Cognition Rank9 collection")?
                .view::<FactArchive>()
                .context("read Cognition Rank9 collection")?;
            super::validate_archive(&snapshot, &facts)?;
            Ok(CheckReport {
                facts: facts.iter().count(),
            })
        })();
        match (result, pile.close()) {
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(error)) => Err(anyhow!("close Cognition pile: {error}")),
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(close_error)) => {
                Err(error.context(format!("closing Cognition pile also failed: {close_error}")))
            }
        }
    }
}
