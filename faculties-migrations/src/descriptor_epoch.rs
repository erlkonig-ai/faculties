//! Re-seat every collection on its self-describing descriptor.
//!
//! A collection descriptor used to name its representation and its recipe by
//! bare id. Both are opaque to anyone without the code that minted them, which
//! is exactly the reader who most needs them, so a descriptor now embeds their
//! own `describe` fragments. That changes the descriptor's bytes and therefore
//! its handle: current code computes a handle no existing collection is under,
//! and finds an empty collection where the data is.
//!
//! This migration re-commits every collection's state under its new handle.
//!
//! It is **additive**. A pile is append-only, so the old collections stay
//! exactly where they are and remain readable by the code that wrote them;
//! this appends new commits beside them. There is nothing to roll back to
//! because nothing is taken away. Run it on a copy first regardless -- an APFS
//! clone of a 12 GB pile costs about twenty milliseconds.
//!
//! What it does NOT migrate: derive records. A derivation is a computation
//! whose artifact is checkable, so a stale one is recomputed rather than
//! carried across, and the derived collections rebuild on their next ensure.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{bail, Context, Result};

use faculties::archive_bm25::{ArchiveBlockTextBm25V1, ARCHIVE_BLOCK_TEXT_BM25_RECIPE_V1};
use faculties::storage::{load_signer, open_pile_strict};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::succinctarchive::SuccinctArchiveBlob;
use triblespace::core::collection::records::CollectionHandle;
use triblespace::core::collection::simplearchive_union::{
    TribleSetUnionV1, TRIBLE_SET_UNION_RECIPE_V1,
};
use triblespace::core::collection::{
    discover_collection_records, CollectionCommit, CollectionDescriptor, CollectionRecord,
    CollectionStore,
};
use triblespace::core::id::Id;
use triblespace::core::metadata::MetaDescribe;
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStorePut};
use triblespace::core::trible::Fragment;
use triblespace_search::portable_bm25::PortableBM25Blob;

/// One collection's move from an opaque descriptor to a self-describing one.
#[derive(Clone, Debug)]
pub struct Reseat {
    /// Handle the collection lives under today.
    pub old: CollectionHandle,
    /// Handle current code computes for the same meaning.
    pub new: CollectionHandle,
    /// Dataset anchor, carried across unchanged.
    pub scope: Id,
    /// Blob representation, carried across unchanged.
    pub representation: Id,
    /// Construction law, carried across unchanged.
    pub recipe: Id,
    /// Signed states to re-commit under `new`.
    pub commits: usize,
}

/// What a run would do, or did.
#[derive(Clone, Debug, Default)]
pub struct DescriptorEpochReport {
    /// Collections that can move, with their counts.
    pub reseats: Vec<Reseat>,
    /// Collections whose states are already all present under their new
    /// handle. The old collection is still there -- a pile is append-only and
    /// nothing removes it -- so a re-run keeps seeing it; this is how the run
    /// distinguishes "left to do" from "seen again".
    pub settled: Vec<Reseat>,
    /// Collections whose representation or recipe this build cannot describe,
    /// with the reason. These are left alone rather than guessed at.
    pub undescribable: Vec<(CollectionHandle, String)>,
    /// Collections already on a self-describing descriptor.
    pub already_current: usize,
}

impl DescriptorEpochReport {
    /// Total signed states the run would re-commit.
    pub fn commits(&self) -> usize {
        self.reseats.iter().map(|reseat| reseat.commits).sum()
    }
}

/// The `describe` fragment for a blob representation this build knows.
///
/// A representation the build cannot describe is not migrated: writing a
/// descriptor that omits a description would produce a third handle for the
/// same collection and strand it twice.
fn describe_representation(id: Id) -> Option<Fragment> {
    if id == <SimpleArchive as MetaDescribe>::id() {
        Some(<SimpleArchive as MetaDescribe>::describe())
    } else if id == <SuccinctArchiveBlob as MetaDescribe>::id() {
        Some(<SuccinctArchiveBlob as MetaDescribe>::describe())
    } else if id == <PortableBM25Blob as MetaDescribe>::id() {
        Some(<PortableBM25Blob as MetaDescribe>::describe())
    } else {
        None
    }
}

/// The `describe` fragment for a construction law this build knows.
fn describe_recipe(id: Id) -> Option<Fragment> {
    if id == TRIBLE_SET_UNION_RECIPE_V1 {
        Some(<TribleSetUnionV1 as MetaDescribe>::describe())
    } else if id == ARCHIVE_BLOCK_TEXT_BM25_RECIPE_V1 {
        Some(<ArchiveBlockTextBm25V1 as MetaDescribe>::describe())
    } else {
        None
    }
}

/// Read every collection the pile's records name, with the commits on it.
fn collections_with_commits<S>(
    store: &mut S,
) -> Result<BTreeMap<CollectionHandle, Vec<CollectionCommit>>>
where
    S: CollectionStore,
{
    let records = discover_collection_records(store).context("discover collection records")?;
    let mut by_collection: BTreeMap<CollectionHandle, Vec<CollectionCommit>> = BTreeMap::new();
    for commit in records.commits() {
        by_collection
            .entry(commit.collection())
            .or_default()
            .push(*commit);
    }
    Ok(by_collection)
}

/// Work out what would move, without writing.
/// The id a state will have once it is re-seated under `collection`.
fn expected_id(
    signer: &ed25519_dalek::SigningKey,
    collection: CollectionHandle,
    commit: &CollectionCommit,
) -> Id {
    CollectionCommit::sign(signer, collection, commit.data(), commit.metadata()).id()
}

pub fn plan(pile: &Path, key: Option<&Path>) -> Result<DescriptorEpochReport> {
    let signer = load_signer(pile, key).context("a re-commit needs the durable signing key")?;
    let mut store = open_pile_strict(pile)?;
    let by_collection = collections_with_commits(&mut store)?;
    let existing_by_collection = by_collection.clone();
    let reader = store.reader().context("open a blob reader")?;

    let mut report = DescriptorEpochReport::default();
    for (old, commits) in by_collection {
        let Ok(blob) = reader.get(old) else {
            report
                .undescribable
                .push((old, "descriptor blob not resident".into()));
            continue;
        };
        let descriptor = match CollectionDescriptor::decode(&blob) {
            Ok(descriptor) => descriptor,
            Err(error) => {
                report
                    .undescribable
                    .push((old, format!("descriptor does not decode: {error}")));
                continue;
            }
        };
        let (scope, representation, recipe) =
            match (descriptor.scope(), descriptor.representation(), descriptor.recipe()) {
                (Ok(scope), Ok(representation), Ok(recipe)) => (scope, representation, recipe),
                _ => {
                    report
                        .undescribable
                        .push((old, "descriptor is missing a structural field".into()));
                    continue;
                }
            };
        let (Some(representation_description), Some(recipe_description)) =
            (describe_representation(representation), describe_recipe(recipe))
        else {
            report.undescribable.push((
                old,
                format!(
                    "this build cannot describe representation {representation:X} or recipe {recipe:X}"
                ),
            ));
            continue;
        };
        let new = CollectionDescriptor::new(scope, representation_description, recipe_description)
            .handle();
        if new == old {
            report.already_current += 1;
            continue;
        }
        let reseat = Reseat {
            old,
            new,
            scope,
            representation,
            recipe,
            commits: commits.len(),
        };
        // Signing is deterministic over the same transcript, so a state that
        // has already moved has a predictable commit id under the new handle.
        // If every one is present, this collection is settled rather than
        // pending, however many times the migration is re-run.
        let already: &[CollectionCommit] = existing_by_collection
            .get(&new)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let landed: BTreeSet<_> = already.iter().map(CollectionCommit::id).collect();
        if commits
            .iter()
            .all(|commit| landed.contains(&expected_id(&signer, new, commit)))
        {
            report.settled.push(reseat);
        } else {
            report.reseats.push(reseat);
        }
    }
    store.close().map_err(anyhow::Error::from)?;
    Ok(report)
}

/// Append the re-seated collections to the pile.
///
/// Every commit keeps its data and metadata handles and is signed afresh for
/// the new collection, because a commit's signature covers the collection it
/// is about. The blobs it points at are already resident and are not copied.
pub fn publish(pile: &Path, key: Option<&Path>) -> Result<DescriptorEpochReport> {
    let signer = load_signer(pile, key).context("a re-commit needs the durable signing key")?;
    let report = plan(pile, key)?;
    if report.reseats.is_empty() {
        return Ok(report);
    }

    let mut store = open_pile_strict(pile)?;
    let by_collection = collections_with_commits(&mut store)?;
    let mut written = BTreeSet::new();
    for reseat in &report.reseats {
        let representation =
            describe_representation(reseat.representation).expect("plan checked this");
        let recipe = describe_recipe(reseat.recipe).expect("plan checked this");
        let descriptor = CollectionDescriptor::new(reseat.scope, representation, recipe);
        if descriptor.handle() != reseat.new {
            bail!("descriptor handle moved between plan and publish");
        }
        store
            .put::<SimpleArchive, _>(descriptor.to_blob())
            .map_err(|error| anyhow::anyhow!("store the self-describing descriptor: {error:?}"))?;
        let existing: &[CollectionCommit] = by_collection
            .get(&reseat.old)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for commit in existing {
            let reseated = CollectionCommit::sign(
                &signer,
                reseat.new,
                commit.data(),
                commit.metadata(),
            );
            if written.insert(reseated.id()) {
                store
                    .insert(CollectionRecord::Commit(reseated))
                    .map_err(|error| anyhow::anyhow!("append the re-seated commit: {error:?}"))?;
            }
        }
    }
    store.close().map_err(anyhow::Error::from)?;
    Ok(report)
}
