//! Callable Atlas operations over the configured collection, without output
//! routing, CLI invocations, or MCP values.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::{CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::SnapshotSource;
use triblespace::prelude::{find, pattern, Id};

use super::{named_entries, named_entry, AtlasEntry};
use crate::collection_names::open_configured;
use crate::schemas::atlas::DEFAULT_SCOPE_ID;
use crate::storage::{load_signer, open_pile_strict, FactArchive};

/// A local Atlas reader. Each operation maintains the existing collection
/// mappings, then projects facts and attachments from one final snapshot.
/// Returned entries are owned observations, not a second mutable catalog.
///
/// Reads may append deterministic maintained derivations, but never author
/// Atlas metadata or create a signing key. Close explicitly to report flush
/// errors rather than relying on the pile's drop behavior.
pub struct Store {
    pile: Pile,
    signer: SigningKey,
}

impl Store {
    pub fn open(pile_path: &Path, key_path: Option<&Path>) -> Result<Self> {
        let signer = load_signer(pile_path, key_path)?;
        let pile = open_pile_strict(pile_path)?;
        Ok(Self { pile, signer })
    }

    /// Every named entity, ordered by all name variants and then entity id.
    pub fn list(&mut self) -> Result<Vec<AtlasEntry>> {
        self.with_view(|facts, reader| {
            let mut rows = named_entries(reader, facts)?;
            rows.sort_by(|left, right| {
                left.names
                    .cmp(&right.names)
                    .then_with(|| left.id.cmp(&right.id))
            });
            Ok(rows)
        })
    }

    /// One named entity selected by a case-insensitive hexadecimal id prefix.
    /// Missing and ambiguous prefixes are errors, never arbitrary winners.
    pub fn show(&mut self, prefix: &str) -> Result<AtlasEntry> {
        self.with_view(|facts, reader| {
            let id = resolve_prefix(facts, prefix)?;
            named_entry(reader, facts, id)?
                .ok_or_else(|| anyhow!("resolved Atlas id {id:x} has no typed name"))
        })
    }

    pub fn close(self) -> Result<()> {
        self.pile.close().context("close Atlas pile")
    }

    pub(super) fn finish<T>(self, result: Result<T>) -> Result<T> {
        match (result, self.close()) {
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(error)) | (Err(error), Ok(())) => Err(error),
            (Err(error), Err(close_error)) => {
                Err(error.context(format!("closing Atlas pile also failed: {close_error:#}")))
            }
        }
    }

    fn with_view<T>(
        &mut self,
        operation: impl FnOnce(&FactArchive, &PileSnapshot) -> Result<T>,
    ) -> Result<T> {
        let source = open_configured(
            &mut self.pile,
            DEFAULT_SCOPE_ID,
            self.signer.verifying_key(),
        )?;
        let descriptor_snapshot = self.pile.snapshot()?;
        let policy = source.policy(&descriptor_snapshot)?;
        drop(descriptor_snapshot);
        let collection_succinct =
            self.pile
                .derive::<SuccinctArchiveBlob>(source, (), policy.clone())?;
        let collection_rank9 = self.pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(
            collection_succinct,
            (),
            policy,
        )?;
        let store_snapshot = pollster::block_on(async {
            drop(self.pile.ensure(source).await?);
            drop(self.pile.maintain(collection_succinct).await?);
            self.pile.maintain(collection_rank9).await
        })
        .context("maintain Atlas fact collection")?;
        let facts = store_snapshot
            .collection(collection_rank9)
            .context("observe maintained Atlas fact collection")?
            .view::<FactArchive>()
            .context("read maintained Atlas fact collection")?;
        operation(&facts, &store_snapshot)
    }
}

fn resolve_prefix<P: TriblePattern>(facts: &P, prefix: &str) -> Result<Id> {
    let prefix = prefix.trim().to_lowercase();
    if prefix.is_empty() {
        bail!("id prefix is empty");
    }
    let mut matches = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::name: _?name }])
    )
    .filter(|id| format!("{id:x}").starts_with(&prefix))
    .collect::<BTreeSet<_>>()
    .into_iter();
    match (matches.next(), matches.next()) {
        (None, _) => bail!("no id matches prefix '{prefix}'"),
        (Some(id), None) => Ok(id),
        (Some(_), Some(_)) => bail!("multiple ids match prefix '{prefix}'"),
    }
}
