//! Collection-native Archive runtime over the V4 descriptor-handle calculus.
//!
//! Archive authorship has one durable Ed25519 signer and one fixed canonical
//! SimpleArchive-union descriptor. Imports stage complete projector fragments
//! in memory, validate the candidate block DAG, and cross exactly one
//! Collection::commit visibility edge. Reads materialize that same collection;
//! there is no Repository branch, CAS head, sidecar registry, or fallback
//! identity.

use std::collections::{BTreeMap, BTreeSet};

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::succinctarchive::SuccinctArchiveBlob;
use triblespace::core::blob::Blob;
use triblespace::core::collection::{
    collection_physical_cover, discover_collection_records, resolve_collection_semantics,
    simplearchive_union, succinctarchive_union, Collection, CollectionClaimValidation,
    CollectionCommit, CollectionData, CollectionDerive, CollectionDescriptor, CollectionMerge,
    CollectionRecord, CollectionResolution, CollectionStore, CollectionValidationRequest,
};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta, BlobStorePut};
use triblespace::prelude::blobencodings::{LongString, RawBytes};
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval, U256BE};
use triblespace::prelude::*;
use triblespace_search::index_bm25::query_across;
use triblespace_search::portable_bm25::{PortableBM25Blob, PortableBM25Index};
use triblespace_search::tokens::{hash_tokens, WordHash};

use crate::archive_bm25::{self, Validation as Bm25Validation};
use crate::blockdag::{self, CatalogValidation};
use crate::collection_cutover::{discover_target, load_signer, open_pile_strict};
use crate::schemas::{blockdag as schema, files as files_schema};

type TextHandle = Inline<Handle<LongString>>;
type RawHandle = Inline<Handle<RawBytes>>;
type ArchiveBm25 = PortableBM25Index<inlineencodings::GenId, WordHash>;
/// Canonical payload of one ordinal-bearing Archive content part.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchivePayload {
    Text(String),
    Resident {
        blob: RawHandle,
        media_type: Id,
    },
    External {
        pointer: String,
        namespace: Id,
        media_type: Option<Id>,
        size: Option<u128>,
        resolutions: Vec<RawHandle>,
    },
}

/// One ordered semantic part of a canonical Archive block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchivePart {
    pub id: Id,
    pub ordinal: u64,
    pub fact: Id,
    pub responds_to: Option<Id>,
    pub modality: Id,
    pub direction: Id,
    pub payload: ArchivePayload,
}

/// One exact source occurrence projected onto a canonical Archive block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveProjection {
    pub id: Id,
    pub source_namespace: Id,
    pub source_locator: String,
    pub raw_record: RawHandle,
    pub block: Id,
    pub block_previous: Vec<Id>,
    pub block_timestamp: Option<Inline<NsTAIInterval>>,
    /// Source receipts supporting the block's semantic predecessor classes;
    /// exact vendor adjacency remains in `raw_record`.
    pub semantic_predecessor_support: Vec<Id>,
    pub source_timestamp: Option<Inline<NsTAIInterval>>,
    pub author: Option<Id>,
    pub experiencer: Option<Id>,
    pub raw_author: Option<String>,
    pub raw_role: Option<String>,
    pub raw_model: Option<String>,
    pub source_paths: Vec<String>,
    pub parts: Vec<ArchivePart>,
}

/// One BM25 result over a canonical Archive block.
///
/// Search indexes semantic blocks rather than source receipts. `projections`
/// names every source occurrence which projects to the winning block.
#[derive(Clone, Debug, PartialEq)]
pub struct ArchiveSearchHit {
    pub block: Id,
    pub score: f32,
    pub projections: Vec<Id>,
}

/// One atomic canonical Archive import.
pub struct ArchiveImportWriter {
    collection: Option<Collection<Pile>>,
    current: TribleSet,
    reader: PileReader,
    delta: Fragment,
}

impl ArchiveImportWriter {
    pub fn open(pile_path: &std::path::Path, key_path: Option<&std::path::Path>) -> Result<Self> {
        let signer = load_signer(pile_path, key_path)?;
        let pile = open_pile_strict(pile_path)?;
        let mut collection = Collection::new(pile, schema::DEFAULT_SCOPE_ID, signer);
        let result = (|| {
            let current = collection
                .materialize()
                .context("materialize authored Archive collection")?;
            let reader = collection
                .storage_mut()
                .reader()
                .context("open Archive collection reader")?;
            require_accepted(
                blockdag::validate_catalog(&reader, &current)
                    .context("validate materialized Archive collection")?,
                "materialized Archive collection",
            )?;
            Ok((current, reader))
        })();
        match result {
            Ok((current, reader)) => Ok(Self {
                collection: Some(collection),
                current,
                reader,
                delta: Fragment::empty(),
            }),
            Err(error) => {
                let close = collection.into_storage().close();
                match close {
                    Ok(()) => Err(error),
                    Err(close_error) => Err(error.context(format!(
                        "closing Archive pile after failed open also failed: {close_error}"
                    ))),
                }
            }
        }
    }

    pub fn stage_fragment(&mut self, fragment: Fragment) -> Result<()> {
        self.delta += fragment;
        Ok(())
    }

    pub fn delta_len(&self) -> usize {
        self.delta.facts().len()
    }

    pub fn finish<T>(mut self, surrounding: Result<T>) -> Result<(T, Option<CollectionCommit>)> {
        let result = surrounding.and_then(|value| {
            if self.delta.facts().is_empty() {
                return Ok((value, None));
            }
            let (_, validation) =
                blockdag::validate_catalog_union(&self.reader, &self.current, &self.delta)
                    .context("validate staged Archive union")?;
            require_accepted(validation, "staged Archive union")?;
            let fragment = std::mem::replace(&mut self.delta, Fragment::empty());
            let commit = self
                .collection
                .as_mut()
                .expect("Archive writer remains open until finish")
                .commit(fragment)
                .context("commit authored Archive projection unit")?;
            Ok((value, Some(commit)))
        });
        let pile = self
            .collection
            .take()
            .expect("Archive writer can only be finished once")
            .into_storage();
        match (result, pile.close()) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(close_error)) => Err(anyhow!("close Archive pile: {close_error}")),
            (Err(error), Err(close_error)) => Err(error.context(format!(
                "closing Archive pile after failure also failed: {close_error}"
            ))),
        }
    }
}

fn require_accepted(validation: CatalogValidation, label: &str) -> Result<()> {
    match validation {
        CatalogValidation::Accepted => Ok(()),
        CatalogValidation::Pending { missing } => bail!(
            "{label} is missing {} attachment blob(s): {}",
            missing.len(),
            missing
                .iter()
                .take(8)
                .map(hex::encode_upper)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        CatalogValidation::Rejected(reason) => bail!("{label} is invalid: {reason}"),
    }
}

/// Exact V4 raw-Succinct derivation summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuccinctIndexReport {
    pub source_commits: usize,
    pub derived_elements: usize,
    pub source_collection: Inline<Handle<SimpleArchive>>,
    pub target_collection: Inline<Handle<SimpleArchive>>,
}

/// Ensure one exact raw-Succinct artifact and validated `DERIVE` record for
/// every authored Archive element.
///
/// This is a reproducible physical cover, not new authority. The target uses
/// V4's canonical raw-Succinct union descriptor and every equation is checked
/// by `succinctarchive_union::validate_derive` before either endpoint or record
/// is admitted. [`ensure_bm25_index`] provides the analogous exact projection
/// for Archive full-text search.
pub fn ensure_succinct_index(
    pile_path: &std::path::Path,
    key_path: Option<&std::path::Path>,
) -> Result<SuccinctIndexReport> {
    let signer = load_signer(pile_path, key_path)?;
    let public_key = signer.verifying_key().to_bytes();
    let pile = open_pile_strict(pile_path)?;
    let mut collection = Collection::new(pile, schema::DEFAULT_SCOPE_ID, signer);
    let result = (|| {
        let facts = collection
            .materialize()
            .context("materialize Archive before raw-Succinct derivation")?;
        let reader = collection
            .storage_mut()
            .reader()
            .context("open Archive derivation reader")?;
        require_accepted(
            blockdag::validate_catalog(&reader, &facts)
                .context("validate Archive before raw-Succinct derivation")?,
            "Archive raw-Succinct source",
        )?;

        let source_descriptor = simplearchive_union::descriptor(schema::DEFAULT_SCOPE_ID);
        let target_descriptor = succinctarchive_union::descriptor(schema::DEFAULT_SCOPE_ID);
        let commits: Vec<_> = discover_target(collection.storage_mut(), schema::DEFAULT_SCOPE_ID)?
            .commits()
            .iter()
            .copied()
            .filter(|commit| commit.public_key().raw == public_key)
            .collect();
        let reader = collection
            .storage_mut()
            .reader()
            .context("open Archive element reader")?;
        let mut prepared = Vec::with_capacity(commits.len());
        for commit in &commits {
            let input: Blob<SimpleArchive> = reader
                .get(Handle::<SimpleArchive>::from_hash(commit.data()))
                .with_context(|| {
                    format!(
                        "read Archive collection element {}",
                        hex::encode_upper(commit.data().raw)
                    )
                })?;
            let output = succinctarchive_union::derive_element(&input)
                .context("derive canonical raw SuccinctArchive element")?;
            let output_data = Handle::<SuccinctArchiveBlob>::to_hash(output.get_handle());
            let claim = CollectionDerive::new(
                source_descriptor.handle(),
                target_descriptor.handle(),
                commit.data(),
                output_data,
            );
            succinctarchive_union::validate_derive(
                &source_descriptor,
                &target_descriptor,
                &claim,
                &input,
                &output,
            )
            .context("validate canonical Archive raw-Succinct derivation")?;
            prepared.push((output, claim));
        }

        let store = collection.storage_mut();
        store
            .put::<SimpleArchive, _>(
                triblespace::core::collection::CollectionDescriptor::to_blob(&source_descriptor),
            )
            .context("store Archive source descriptor")?;
        store
            .put::<SimpleArchive, _>(
                triblespace::core::collection::CollectionDescriptor::to_blob(&target_descriptor),
            )
            .context("store Archive raw-Succinct descriptor")?;
        for (output, _) in &prepared {
            store
                .put::<SuccinctArchiveBlob, _>(output.clone())
                .context("store Archive raw-Succinct element")?;
        }
        store
            .flush()
            .context("flush Archive raw-Succinct dependencies")?;
        for (_, claim) in &prepared {
            CollectionStore::insert(store, CollectionRecord::Derive(*claim))
                .context("publish Archive raw-Succinct DERIVE")?;
        }
        store
            .flush()
            .context("flush Archive raw-Succinct derivations")?;

        Ok(SuccinctIndexReport {
            source_commits: commits.len(),
            derived_elements: prepared.len(),
            source_collection: source_descriptor.handle(),
            target_collection: target_descriptor.handle(),
        })
    })();
    let pile = collection.into_storage();
    match (result, pile.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(close_error)) => Err(anyhow!("close Archive pile: {close_error}")),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing Archive pile after raw-Succinct derivation also failed: {close_error}"
        ))),
    }
}

/// Exact V4 Archive BM25 derivation summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bm25IndexReport {
    pub source_commits: usize,
    pub derived_elements: usize,
    pub cover_segments: usize,
    pub source_collection: Inline<Handle<SimpleArchive>>,
    pub target_collection: Inline<Handle<SimpleArchive>>,
}

struct EnsuredBm25 {
    report: Bm25IndexReport,
    reader: PileReader,
    cover: Vec<CollectionData>,
}

/// Ensure the portable exact-TF projection of every locally authored Archive
/// commit and compact its current admissible physical cover through exact
/// `MERGE` equations.
pub fn ensure_bm25_index(
    pile_path: &std::path::Path,
    key_path: Option<&std::path::Path>,
) -> Result<Bm25IndexReport> {
    let archive = ArchiveSnapshot::load_local(pile_path, key_path, schema::DEFAULT_SCOPE_ID)?;
    Ok(ensure_bm25_for_snapshot(pile_path, &archive)?.report)
}

fn ensure_bm25_for_snapshot(
    pile_path: &std::path::Path,
    archive: &ArchiveSnapshot,
) -> Result<EnsuredBm25> {
    let source_descriptor = simplearchive_union::descriptor(schema::DEFAULT_SCOPE_ID);
    let target_descriptor = archive_bm25::descriptor();

    // The source snapshot is the ticket. Derive each distinct committed
    // element against its attachment reader before opening the mutable pile.
    let mut prepared = BTreeMap::new();
    for commit in archive.commits() {
        let source: Blob<SimpleArchive> = archive
            .reader()
            .get(Handle::<SimpleArchive>::from_hash(commit.data()))
            .with_context(|| {
                format!(
                    "read Archive source element {} for BM25",
                    hex::encode_upper(commit.data().raw)
                )
            })?;
        simplearchive_union::validate_commit(&source_descriptor, commit, &source)
            .context("validate Archive source commit before BM25 derivation")?;
        let output = archive_bm25::derive_element(archive.reader(), source.clone())
            .context("derive exact Archive BM25 element")?;
        let output_data = Handle::<PortableBM25Blob>::to_hash(output.get_handle());
        let claim = CollectionDerive::new(
            source_descriptor.handle(),
            target_descriptor.handle(),
            commit.data(),
            output_data,
        );
        require_bm25_accepted(
            archive_bm25::validate_derive_bytes(
                archive.reader(),
                &source_descriptor,
                &target_descriptor,
                &claim,
                &source,
                &output,
            )?,
            "fresh Archive BM25 derivation",
        )?;
        prepared.entry(commit.data()).or_insert((output, claim));
    }

    let mut pile = open_pile_strict(pile_path)?;
    let result = (|| {
        pile.put::<SimpleArchive, _>(CollectionDescriptor::to_blob(&source_descriptor))
            .context("store Archive source descriptor")?;
        pile.put::<SimpleArchive, _>(CollectionDescriptor::to_blob(&target_descriptor))
            .context("store Archive BM25 descriptor")?;
        for (output, _) in prepared.values() {
            pile.put::<PortableBM25Blob, _>(output.clone())
                .context("store Archive BM25 derived element")?;
        }
        pile.flush()
            .context("flush Archive BM25 derivation dependencies")?;
        for (_, claim) in prepared.values() {
            CollectionStore::insert(&mut pile, CollectionRecord::Derive(*claim))
                .context("publish Archive BM25 DERIVE")?;
        }
        pile.flush().context("flush Archive BM25 DERIVEs")?;

        let (resolution, reader) = resolve_bm25(&mut pile, archive.commits())?;
        require_expected_derives(&resolution, prepared.values().map(|(_, claim)| claim))?;
        let cover = bm25_physical_cover(&reader, &resolution)?;
        let merges = plan_cover_merge(&reader, &target_descriptor, &cover)?;
        if !merges.is_empty() {
            for (output, _) in &merges {
                pile.put::<PortableBM25Blob, _>(output.clone())
                    .context("store Archive BM25 merge result")?;
            }
            pile.flush()
                .context("flush Archive BM25 merge dependencies")?;
            for (_, claim) in &merges {
                CollectionStore::insert(&mut pile, CollectionRecord::Merge(*claim))
                    .context("publish Archive BM25 MERGE")?;
            }
            pile.flush().context("flush Archive BM25 MERGEs")?;
        }

        // Local construction is never an admission shortcut. Rerun the
        // stateless resolver over the appended records and take its resident
        // proof as the only search cover.
        let (resolution, reader) = resolve_bm25(&mut pile, archive.commits())?;
        require_expected_derives(&resolution, prepared.values().map(|(_, claim)| claim))?;
        let cover: Vec<_> = bm25_physical_cover(&reader, &resolution)?
            .into_iter()
            .collect();
        Ok(EnsuredBm25 {
            report: Bm25IndexReport {
                source_commits: archive.commits().len(),
                derived_elements: prepared.len(),
                cover_segments: cover.len(),
                source_collection: source_descriptor.handle(),
                target_collection: target_descriptor.handle(),
            },
            reader,
            cover,
        })
    })();
    let close = pile.close();
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(close_error)) => Err(anyhow!("close Archive BM25 pile: {close_error}")),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing Archive BM25 pile after failure also failed: {close_error}"
        ))),
    }
}

fn resolve_bm25(
    pile: &mut Pile,
    source_commits: &[CollectionCommit],
) -> Result<(CollectionResolution<String>, PileReader)> {
    let discovered = discover_collection_records(&mut *pile)
        .context("discover Archive BM25 collection records")?;
    let reader = pile.reader().context("open Archive BM25 resolver reader")?;
    let authorized: BTreeSet<_> = source_commits.iter().map(CollectionCommit::id).collect();
    let source = simplearchive_union::descriptor(schema::DEFAULT_SCOPE_ID);
    let target = archive_bm25::descriptor();
    let resolution = resolve_collection_semantics(&discovered, &authorized, |request| {
        validate_bm25_request(&reader, &source, &target, request)
    })
    .map_err(|error| anyhow!("resolve Archive BM25 collection semantics: {error}"))?;

    for commit in source_commits {
        if resolution.validation_pending().contains(&commit.id()) {
            bail!(
                "authorized Archive source commit {:X} is incomplete",
                commit.id()
            );
        }
        if let Some(reason) = resolution.rejected().get(&commit.id()) {
            bail!(
                "authorized Archive source commit {:X} was rejected: {reason}",
                commit.id()
            );
        }
        if !resolution.admitted_claims().contains(&commit.id()) {
            bail!(
                "authorized Archive source commit {:X} was not admitted",
                commit.id()
            );
        }
    }
    Ok((resolution, reader))
}

fn validate_bm25_request(
    reader: &PileReader,
    source: &CollectionDescriptor,
    target: &CollectionDescriptor,
    request: CollectionValidationRequest<'_>,
) -> Result<CollectionClaimValidation<String>> {
    match request {
        CollectionValidationRequest::Commit { claim } => {
            if claim.collection() != source.handle() {
                return Ok(CollectionClaimValidation::Rejected(
                    "authorized Archive commit names another collection".to_owned(),
                ));
            }
            let Some(data) = load_resident::<SimpleArchive>(reader, claim.data())? else {
                return Ok(CollectionClaimValidation::Pending);
            };
            Ok(
                match simplearchive_union::validate_commit(source, claim, &data) {
                    Ok(()) => CollectionClaimValidation::Accepted,
                    Err(error) => CollectionClaimValidation::Rejected(error.to_string()),
                },
            )
        }
        CollectionValidationRequest::Merge { claim } if claim.collection() == target.handle() => {
            Ok(to_claim_validation(archive_bm25::validate_merge(
                reader, target, claim,
            )?))
        }
        CollectionValidationRequest::Derive { claim }
            if claim.source() == source.handle() && claim.target() == target.handle() =>
        {
            Ok(to_claim_validation(archive_bm25::validate_derive(
                reader, source, target, claim,
            )?))
        }
        CollectionValidationRequest::Merge { .. } | CollectionValidationRequest::Derive { .. } => {
            Ok(CollectionClaimValidation::Pending)
        }
    }
}

fn to_claim_validation(value: Bm25Validation) -> CollectionClaimValidation<String> {
    match value {
        Bm25Validation::Accepted => CollectionClaimValidation::Accepted,
        Bm25Validation::Pending => CollectionClaimValidation::Pending,
        Bm25Validation::Rejected(reason) => CollectionClaimValidation::Rejected(reason),
    }
}

fn require_bm25_accepted(value: Bm25Validation, label: &str) -> Result<()> {
    match value {
        Bm25Validation::Accepted => Ok(()),
        Bm25Validation::Pending => bail!("{label} is missing a selected payload"),
        Bm25Validation::Rejected(reason) => bail!("{label} was rejected: {reason}"),
    }
}

fn require_expected_derives<'a>(
    resolution: &CollectionResolution<String>,
    claims: impl IntoIterator<Item = &'a CollectionDerive>,
) -> Result<()> {
    for claim in claims {
        if resolution.validation_pending().contains(&claim.id()) {
            bail!("Archive BM25 DERIVE {:X} is incomplete", claim.id());
        }
        if let Some(reason) = resolution.rejected().get(&claim.id()) {
            bail!(
                "Archive BM25 DERIVE {:X} was rejected: {reason}",
                claim.id()
            );
        }
        if !resolution.admitted_claims().contains(&claim.id()) {
            bail!("Archive BM25 DERIVE {:X} was not admitted", claim.id());
        }
    }
    Ok(())
}

fn load_resident<E>(reader: &PileReader, data: CollectionData) -> Result<Option<Blob<E>>>
where
    E: triblespace::core::blob::BlobEncoding,
    Handle<E>: triblespace::core::inline::InlineEncoding,
{
    let handle = Handle::<E>::from_hash(data);
    if reader.metadata(handle)?.is_none() {
        return Ok(None);
    }
    Ok(Some(reader.get(handle).with_context(|| {
        format!("read collection element {}", hex::encode_upper(data.raw))
    })?))
}

fn bm25_physical_cover(
    reader: &PileReader,
    resolution: &CollectionResolution<String>,
) -> Result<BTreeSet<CollectionData>> {
    let target = archive_bm25::descriptor().handle();
    let mut resident = BTreeSet::new();
    for data in resolution.semantics().members(target).into_iter().flatten() {
        if reader
            .metadata(Handle::<PortableBM25Blob>::from_hash(*data))?
            .is_some()
        {
            resident.insert(*data);
        }
    }
    let proof = collection_physical_cover(resolution.semantics(), target, &resident);
    if !proof.missing.is_empty() {
        bail!(
            "Archive BM25 has {} semantic frontier element(s) without a resident proof",
            proof.missing.len()
        );
    }
    Ok(proof.cover)
}

fn plan_cover_merge(
    reader: &PileReader,
    descriptor: &CollectionDescriptor,
    cover: &BTreeSet<CollectionData>,
) -> Result<Vec<(Blob<PortableBM25Blob>, CollectionMerge)>> {
    let mut layer = Vec::with_capacity(cover.len());
    for data in cover {
        let blob: Blob<PortableBM25Blob> = reader
            .get(Handle::<PortableBM25Blob>::from_hash(*data))
            .with_context(|| {
                format!(
                    "read Archive BM25 cover element {}",
                    hex::encode_upper(data.raw)
                )
            })?;
        // Attach now so malformed resident bytes reject before any append.
        ArchiveBm25::try_from_blob(blob.clone()).with_context(|| {
            format!(
                "attach Archive BM25 cover element {}",
                hex::encode_upper(data.raw)
            )
        })?;
        layer.push((*data, blob));
    }

    let mut planned = Vec::new();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut pairs = layer.into_iter();
        while let Some((low_data, low_blob)) = pairs.next() {
            let Some((high_data, high_blob)) = pairs.next() else {
                next.push((low_data, low_blob));
                break;
            };
            debug_assert!(low_data < high_data);
            let low = ArchiveBm25::try_from_blob(low_blob.clone())
                .context("attach Archive BM25 merge low input")?;
            let high = ArchiveBm25::try_from_blob(high_blob.clone())
                .context("attach Archive BM25 merge high input")?;
            let output: Blob<PortableBM25Blob> = low
                .merged(&high)
                .context("join Archive BM25 cover elements")?
                .to_blob();
            let output_data = Handle::<PortableBM25Blob>::to_hash(output.get_handle());
            let claim = CollectionMerge::new(descriptor.handle(), low_data, high_data, output_data);
            require_bm25_accepted(
                archive_bm25::validate_merge_bytes(
                    descriptor, &claim, &low_blob, &high_blob, &output,
                ),
                "fresh Archive BM25 merge",
            )?;
            planned.push((output.clone(), claim));
            next.push((output_data, output));
        }
        next.sort_unstable_by_key(|(data, _)| *data);
        next.dedup_by_key(|(data, _)| *data);
        layer = next;
    }
    Ok(planned)
}

/// One frozen Archive view and the exact portable BM25 cover derived from the
/// same set of authorized source commits.
pub struct ArchiveSearchSnapshot {
    archive: ArchiveSnapshot,
    segments: Vec<ArchiveBm25>,
}

impl ArchiveSearchSnapshot {
    pub fn ensure_local(
        pile_path: &std::path::Path,
        key_path: Option<&std::path::Path>,
    ) -> Result<Self> {
        let archive = ArchiveSnapshot::load_local(pile_path, key_path, schema::DEFAULT_SCOPE_ID)?;
        let ensured = ensure_bm25_for_snapshot(pile_path, &archive)?;
        let mut segments = Vec::with_capacity(ensured.cover.len());
        for data in &ensured.cover {
            let blob: Blob<PortableBM25Blob> = ensured
                .reader
                .get(Handle::<PortableBM25Blob>::from_hash(*data))
                .with_context(|| {
                    format!("read Archive BM25 segment {}", hex::encode_upper(data.raw))
                })?;
            segments.push(ArchiveBm25::try_from_blob(blob).with_context(|| {
                format!(
                    "attach Archive BM25 segment {}",
                    hex::encode_upper(data.raw)
                )
            })?);
        }
        Ok(Self { archive, segments })
    }

    pub fn archive(&self) -> &ArchiveSnapshot {
        &self.archive
    }

    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    pub fn search(&self, text: &str, limit: usize) -> Result<Vec<ArchiveSearchHit>> {
        if limit == 0 || self.segments.is_empty() {
            return Ok(Vec::new());
        }
        let ranked = query_across(&self.segments, &hash_tokens(text))
            .map_err(|error| anyhow!("query Archive BM25 cover: {error}"))?;
        ranked
            .into_iter()
            .take(limit)
            .map(|(document, score)| {
                let block = Id::try_from_inline(&document).map_err(|error| {
                    anyhow!("Archive BM25 document is not a block id: {error:?}")
                })?;
                let projections = self.archive.projections_for_block(block);
                if projections.is_empty() {
                    bail!("Archive BM25 block {block:X} has no source projection");
                }
                Ok(ArchiveSearchHit {
                    block,
                    score,
                    projections,
                })
            })
            .collect()
    }
}

/// One immutable materialized Archive view from the local durable authority.
pub struct ArchiveSnapshot {
    scope: Id,
    facts: TribleSet,
    reader: PileReader,
    commits: Vec<CollectionCommit>,
}

impl ArchiveSnapshot {
    pub fn load_local(
        pile_path: &std::path::Path,
        key_path: Option<&std::path::Path>,
        scope: Id,
    ) -> Result<Self> {
        if scope != schema::DEFAULT_SCOPE_ID {
            bail!(
                "Archive runtime only supports fixed scope {:X}",
                schema::DEFAULT_SCOPE_ID
            );
        }
        let signer = load_signer(pile_path, key_path)?;
        let pile = open_pile_strict(pile_path)?;
        let mut collection = Collection::new(pile, scope, signer);
        let result = (|| {
            let snapshot = collection
                .snapshot()
                .context("snapshot authored Archive collection")?;
            let (facts, commits, reader) = snapshot.into_parts();
            require_accepted(
                blockdag::validate_catalog(&reader, &facts)
                    .context("validate materialized Archive catalog")?,
                "materialized Archive catalog",
            )?;
            Ok((facts, reader, commits))
        })();
        let close = collection.into_storage().close();
        match (result, close) {
            (Ok((facts, reader, commits)), Ok(())) => Ok(Self {
                scope,
                facts,
                reader,
                commits,
            }),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(close_error)) => Err(anyhow!("close Archive pile: {close_error}")),
            (Err(error), Err(close_error)) => {
                Err(error.context(format!("closing Archive pile also failed: {close_error}")))
            }
        }
    }

    pub const fn scope(&self) -> Id {
        self.scope
    }

    pub fn catalog(&self) -> &TribleSet {
        &self.facts
    }

    pub fn reader(&self) -> &PileReader {
        &self.reader
    }

    pub fn commits(&self) -> &[CollectionCommit] {
        &self.commits
    }

    /// Canonical source-projection ids in byte order.
    pub fn projection_ids(&self) -> Vec<Id> {
        let catalog = &self.facts;
        let mut ids: Vec<_> = find!(
            projection: Id,
            pattern!(catalog, [{
                ?projection @ metadata::tag: &schema::source_projection::KIND
            }])
        )
        .collect();
        ids.sort_unstable();
        ids
    }

    /// Resolve one source-projection id from a case-insensitive hexadecimal
    /// prefix. Ambiguous prefixes fail instead of depending on physical shard
    /// or query iteration order.
    pub fn resolve_projection_prefix(&self, prefix: &str) -> Result<Id> {
        let prefix = prefix.trim();
        if prefix.is_empty()
            || prefix.len() > 32
            || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("Archive projection prefix must contain 1..=32 hexadecimal digits");
        }
        let prefix = prefix.to_ascii_uppercase();
        let mut matches = self
            .projection_ids()
            .into_iter()
            .filter(|id| format!("{id:X}").starts_with(&prefix));
        let first = matches
            .next()
            .ok_or_else(|| anyhow::anyhow!("no Archive source projection matches {prefix}"))?;
        if matches.next().is_some() {
            bail!("Archive source projection prefix {prefix} is ambiguous");
        }
        Ok(first)
    }

    /// Source receipts projecting to one canonical block, in canonical id
    /// order. Several receipts may intentionally witness the same block.
    pub fn projections_for_block(&self, block: Id) -> Vec<Id> {
        let catalog = &self.facts;
        let mut projections: Vec<_> = find!(
            projection: Id,
            pattern!(catalog, [{
                ?projection @ schema::source_projection::projects_to: block
            }])
        )
        .collect();
        projections.sort_unstable();
        projections
    }

    /// Most recent source receipts by canonical block timestamp.
    ///
    /// Untimed blocks sort after genuinely timed blocks. Ties use the source
    /// projection id, making the result independent of collection commit order.
    pub fn recent_projection_ids(&self, limit: usize) -> Vec<Id> {
        if limit == 0 {
            return Vec::new();
        }
        let mut rows: Vec<(Id, Option<i128>)> = self
            .projection_ids()
            .into_iter()
            .map(|projection| {
                let timestamp = find!(
                    value: Inline<NsTAIInterval>,
                    pattern!(&self.facts, [
                        { projection @ schema::source_projection::projects_to: _?block },
                        { _?block @ schema::block::timestamp: ?value },
                    ])
                )
                .next()
                .map(|value| {
                    let (lower, _upper): (i128, i128) = value
                        .try_from_inline()
                        .expect("validated Archive timestamp is inline");
                    lower
                });
                (projection, timestamp)
            })
            .collect();
        rows.sort_unstable_by(|left, right| {
            right.1.cmp(&left.1).then_with(|| right.0.cmp(&left.0))
        });
        rows.into_iter().take(limit).map(|(id, _)| id).collect()
    }

    /// Resolve and attach one complete source projection.
    ///
    /// Scalar ambiguity is an error. Repeated predecessor, path, resolution,
    /// and part fields retain set semantics and are returned in canonical
    /// order.
    pub fn projection(&self, id: Id) -> Result<ArchiveProjection> {
        let catalog = &self.facts;
        let tagged = find!(
            tag: Id,
            pattern!(catalog, [{ id @ metadata::tag: ?tag }])
        )
        .any(|tag| tag == schema::source_projection::KIND);
        if !tagged {
            bail!("Archive source projection {id:X} does not exist");
        }

        let source_namespace = required_one(
            find!(
                value: Id,
                pattern!(catalog, [{
                    id @ schema::source_projection::source_namespace: ?value
                }])
            )
            .collect(),
            id,
            "source namespace",
        )?;
        let source_locator = self.read_required_text(
            find!(
                value: TextHandle,
                pattern!(catalog, [{
                    id @ schema::source_projection::source_locator: ?value
                }])
            )
            .collect(),
            id,
            "source locator",
        )?;
        let raw_record = required_one(
            find!(
                value: RawHandle,
                pattern!(catalog, [{ id @ schema::source_projection::raw_record: ?value }])
            )
            .collect(),
            id,
            "raw record",
        )?;
        let block = required_one(
            find!(
                value: Id,
                pattern!(catalog, [{ id @ schema::source_projection::projects_to: ?value }])
            )
            .collect(),
            id,
            "projected block",
        )?;

        let mut semantic_predecessor_support: Vec<_> = find!(
            value: Id,
            pattern!(catalog, [{
                id @ schema::source_projection::semantic_predecessor_support: ?value
            }])
        )
        .collect();
        semantic_predecessor_support.sort_unstable();
        let source_timestamp = optional_one(
            find!(
                value: Inline<NsTAIInterval>,
                pattern!(catalog, [{
                    id @ schema::source_projection::source_timestamp: ?value
                }])
            )
            .collect(),
            id,
            "source timestamp",
        )?;
        let author = optional_one(
            find!(
                value: Id,
                pattern!(catalog, [{ id @ schema::source_projection::author: ?value }])
            )
            .collect(),
            id,
            "author",
        )?;
        let experiencer = optional_one(
            find!(
                value: Id,
                pattern!(catalog, [{ id @ schema::source_projection::experiencer: ?value }])
            )
            .collect(),
            id,
            "experiencer",
        )?;
        let raw_author = self.read_optional_text(
            find!(
                value: TextHandle,
                pattern!(catalog, [{ id @ schema::source_projection::raw_author: ?value }])
            )
            .collect(),
            id,
            "raw author",
        )?;
        let raw_role = self.read_optional_text(
            find!(
                value: TextHandle,
                pattern!(catalog, [{ id @ schema::source_projection::raw_role: ?value }])
            )
            .collect(),
            id,
            "raw role",
        )?;
        let raw_model = self.read_optional_text(
            find!(
                value: TextHandle,
                pattern!(catalog, [{ id @ schema::source_projection::raw_model: ?value }])
            )
            .collect(),
            id,
            "raw model",
        )?;
        let mut source_paths = find!(
            value: TextHandle,
            pattern!(catalog, [{ id @ files_schema::file::source_path: ?value }])
        )
        .map(|handle| self.read_text(handle))
        .collect::<Result<Vec<_>>>()?;
        source_paths.sort_unstable();

        let mut block_previous: Vec<_> = find!(
            value: Id,
            pattern!(catalog, [{ block @ schema::block::previous: ?value }])
        )
        .collect();
        block_previous.sort_unstable();
        let block_timestamp = optional_one(
            find!(
                value: Inline<NsTAIInterval>,
                pattern!(catalog, [{ block @ schema::block::timestamp: ?value }])
            )
            .collect(),
            block,
            "block timestamp",
        )?;

        let mut parts = find!(
            (
                part: Id,
                ordinal: Inline<U256BE>,
                fact: Id,
                modality: Id,
                direction: Id
            ),
            pattern!(catalog, [
                { block @ schema::block::contains: ?part },
                { ?part @ schema::content_part::ordinal: ?ordinal },
                { ?part @ schema::content_part::fact: ?fact },
                { ?fact @ schema::content_fact::modality: ?modality },
                { ?fact @ schema::content_fact::direction: ?direction },
            ])
        )
        .map(|(part, ordinal, fact, modality, direction)| {
            let ordinal = u64::try_from_inline(&ordinal)
                .map_err(|error| anyhow::anyhow!("Archive part {part:X} ordinal: {error:?}"))?;
            let responds_to = optional_one(
                find!(
                    value: Id,
                    pattern!(catalog, [{
                        part @ schema::content_part::responds_to: ?value
                    }])
                )
                .collect(),
                part,
                "responds-to",
            )?;
            let payload = self.payload(catalog, fact)?;
            Ok(ArchivePart {
                id: part,
                ordinal,
                fact,
                responds_to,
                modality,
                direction,
                payload,
            })
        })
        .collect::<Result<Vec<_>>>()?;
        parts.sort_unstable_by_key(|part| (part.ordinal, part.id));

        Ok(ArchiveProjection {
            id,
            source_namespace,
            source_locator,
            raw_record,
            block,
            block_previous,
            block_timestamp,
            semantic_predecessor_support,
            source_timestamp,
            author,
            experiencer,
            raw_author,
            raw_role,
            raw_model,
            source_paths,
            parts,
        })
    }

    fn payload(&self, catalog: &TribleSet, fact: Id) -> Result<ArchivePayload> {
        let text = optional_one(
            find!(
                value: TextHandle,
                pattern!(catalog, [{ fact @ schema::content_fact::payload: ?value }])
            )
            .collect(),
            fact,
            "text payload",
        )?;
        let blob = optional_one(
            find!(
                value: RawHandle,
                pattern!(catalog, [{ fact @ schema::content_fact::blob: ?value }])
            )
            .collect(),
            fact,
            "resident payload",
        )?;
        let pointer = optional_one(
            find!(
                value: TextHandle,
                pattern!(catalog, [{ fact @ schema::content_fact::asset_pointer: ?value }])
            )
            .collect(),
            fact,
            "asset pointer",
        )?;
        match (text, blob, pointer) {
            (Some(text), None, None) => Ok(ArchivePayload::Text(self.read_text(text)?)),
            (None, Some(blob), None) => {
                let media_type = required_one(
                    find!(
                        value: Id,
                        pattern!(catalog, [{ fact @ schema::content_fact::media_type: ?value }])
                    )
                    .collect(),
                    fact,
                    "resident media type",
                )?;
                Ok(ArchivePayload::Resident { blob, media_type })
            }
            (None, None, Some(pointer)) => {
                let namespace = required_one(
                    find!(
                        value: Id,
                        pattern!(catalog, [{
                            fact @ schema::content_fact::asset_namespace: ?value
                        }])
                    )
                    .collect(),
                    fact,
                    "asset namespace",
                )?;
                let media_type = optional_one(
                    find!(
                        value: Id,
                        pattern!(catalog, [{ fact @ schema::content_fact::media_type: ?value }])
                    )
                    .collect(),
                    fact,
                    "asset media type",
                )?;
                let size = optional_one(
                    find!(
                        value: Inline<U256BE>,
                        pattern!(catalog, [{ fact @ schema::content_fact::asset_size: ?value }])
                    )
                    .collect(),
                    fact,
                    "asset size",
                )?
                .map(|size| {
                    u128::try_from_inline(&size).map_err(|error| {
                        anyhow::anyhow!("Archive content fact {fact:X} asset size: {error:?}")
                    })
                })
                .transpose()?;
                let mut resolutions: Vec<_> = find!(
                    value: RawHandle,
                    pattern!(catalog, [{ fact @ schema::content_fact::resolved_to: ?value }])
                )
                .collect();
                resolutions.sort_unstable();
                Ok(ArchivePayload::External {
                    pointer: self.read_text(pointer)?,
                    namespace,
                    media_type,
                    size,
                    resolutions,
                })
            }
            _ => bail!(
                "Archive content fact {fact:X} must have exactly one canonical payload variant"
            ),
        }
    }

    fn read_required_text(
        &self,
        values: Vec<TextHandle>,
        entity: Id,
        field: &str,
    ) -> Result<String> {
        self.read_text(required_one(values, entity, field)?)
    }

    fn read_optional_text(
        &self,
        values: Vec<TextHandle>,
        entity: Id,
        field: &str,
    ) -> Result<Option<String>> {
        optional_one(values, entity, field)?
            .map(|handle| self.read_text(handle))
            .transpose()
    }

    fn read_text(&self, handle: TextHandle) -> Result<String> {
        let value: View<str> = self.reader.get(handle).context("read Archive text")?;
        Ok(value.to_string())
    }
}

fn required_one<T>(values: Vec<T>, entity: Id, field: &str) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "Archive entity {entity:X} has {} values for required scalar {field}",
            values.len()
        );
    }
    Ok(values.into_iter().next().expect("one checked value"))
}

fn optional_one<T>(values: Vec<T>, entity: Id, field: &str) -> Result<Option<T>> {
    if values.len() > 1 {
        bail!(
            "Archive entity {entity:X} has {} values for optional scalar {field}",
            values.len()
        );
    }
    Ok(values.into_iter().next())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collection_cutover::initialize_signer;
    use tempfile::TempDir;
    use triblespace::core::collection::discover_collection_records;

    fn projection(locator: &str, text: &str) -> Fragment {
        let fact = blockdag::text_fact(
            schema::content_fact::modality::TEXT,
            schema::content_fact::direction::IN,
            text,
        )
        .unwrap();
        let part = blockdag::content_part(0, fact, None).unwrap();
        let block = blockdag::block([], None, part).unwrap();
        blockdag::source_projection(
            schema::source_projection::SOURCE_CLAUDE_CODE,
            locator,
            format!("{{\\\"text\\\":{text:?}}}").into_bytes(),
            block,
        )
        .unwrap()
    }

    fn projection_split_across_source_elements(locator: &str, text: &str) -> (Fragment, Fragment) {
        let fact = blockdag::text_fact(
            schema::content_fact::modality::TEXT,
            schema::content_fact::direction::IN,
            text,
        )
        .unwrap();
        let part = blockdag::content_part(0, fact, None).unwrap();
        let block = blockdag::block([], None, part).unwrap();
        let block_id = block.root().unwrap();
        let projection = blockdag::source_projection(
            schema::source_projection::SOURCE_CLAUDE_CODE,
            locator,
            format!("{{\"text\":{text:?}}}").into_bytes(),
            block,
        )
        .unwrap();
        let (_, facts, metafacts, blobs) = projection.into_parts();
        let mut block_facts = TribleSet::new();
        let mut remaining_facts = TribleSet::new();
        for fact in facts.iter() {
            if fact.e() == &block_id {
                block_facts.insert(fact);
            } else {
                remaining_facts.insert(fact);
            }
        }
        (
            Fragment::from(block_facts),
            Fragment::from_parts(remaining_facts, metafacts, blobs),
        )
    }

    #[test]
    fn import_crosses_one_v4_visibility_edge_and_retries_idempotently() {
        let directory = TempDir::new().unwrap();
        let pile = directory.path().join("archive.pile");
        std::fs::File::create(&pile).unwrap();
        let key = directory.path().join("archive.key");
        initialize_signer(&pile, Some(&key)).unwrap();

        let fragment = projection("session:one", "one");
        let mut writer = ArchiveImportWriter::open(&pile, Some(&key)).unwrap();
        writer.stage_fragment(fragment.clone()).unwrap();
        let (_, first) = writer.finish(Ok(())).unwrap();
        let first = first.unwrap();
        let length = std::fs::metadata(&pile).unwrap().len();

        let mut retry = ArchiveImportWriter::open(&pile, Some(&key)).unwrap();
        retry.stage_fragment(fragment).unwrap();
        let (_, repeated) = retry.finish(Ok(())).unwrap();
        assert_eq!(repeated, Some(first));
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), length);

        let snapshot =
            ArchiveSnapshot::load_local(&pile, Some(&key), schema::DEFAULT_SCOPE_ID).unwrap();
        assert_eq!(snapshot.commits(), &[first]);
        assert_eq!(snapshot.projection_ids().len(), 1);
    }

    #[test]
    fn empty_commit_receives_exact_empty_derives_and_keeps_reads_empty() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_signer(&pile_path, Some(&key)).unwrap();

        let signer = load_signer(&pile_path, Some(&key)).unwrap();
        let pile = open_pile_strict(&pile_path).unwrap();
        let mut collection = Collection::new(pile, schema::DEFAULT_SCOPE_ID, signer);
        let commit = collection.commit(Fragment::empty()).unwrap();
        collection.into_storage().close().unwrap();

        let succinct = ensure_succinct_index(&pile_path, Some(&key)).unwrap();
        let bm25 = ensure_bm25_index(&pile_path, Some(&key)).unwrap();
        assert_eq!((succinct.source_commits, succinct.derived_elements), (1, 1));
        assert_eq!(
            (
                bm25.source_commits,
                bm25.derived_elements,
                bm25.cover_segments
            ),
            (1, 1, 1)
        );

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let records = discover_collection_records(&mut pile).unwrap();
        let derives: Vec<_> = records
            .derives()
            .iter()
            .filter(|claim| claim.mapping().0 == commit.data())
            .collect();
        assert_eq!(derives.len(), 2, "one empty derive per target recipe");
        pile.close().unwrap();

        let snapshot =
            ArchiveSnapshot::load_local(&pile_path, Some(&key), schema::DEFAULT_SCOPE_ID).unwrap();
        assert_eq!(snapshot.commits(), &[commit]);
        assert!(snapshot.recent_projection_ids(10).is_empty());
        drop(snapshot);
        let search = ArchiveSearchSnapshot::ensure_local(&pile_path, Some(&key)).unwrap();
        assert!(search.search("anything", 10).unwrap().is_empty());
    }

    #[test]
    fn succinct_index_persists_an_exact_validated_v4_derive() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_signer(&pile_path, Some(&key)).unwrap();

        let mut writer = ArchiveImportWriter::open(&pile_path, Some(&key)).unwrap();
        writer
            .stage_fragment(projection("session:index", "exact succinct"))
            .unwrap();
        writer.finish(Ok(())).unwrap();

        let report = ensure_succinct_index(&pile_path, Some(&key)).unwrap();
        assert_eq!(report.source_commits, 1);
        assert_eq!(report.derived_elements, 1);
        let length = std::fs::metadata(&pile_path).unwrap().len();
        assert_eq!(
            ensure_succinct_index(&pile_path, Some(&key)).unwrap(),
            report
        );
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), length);

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let records = discover_collection_records(&mut pile).unwrap();
        let derive = records
            .derives()
            .iter()
            .find(|derive| {
                derive.source() == report.source_collection
                    && derive.target() == report.target_collection
            })
            .copied()
            .expect("stored Archive raw-Succinct DERIVE");
        let reader = pile.reader().unwrap();
        let (input, output) = derive.mapping();
        let input: Blob<SimpleArchive> = reader
            .get(Handle::<SimpleArchive>::from_hash(input))
            .unwrap();
        let output: Blob<SuccinctArchiveBlob> = reader
            .get(Handle::<SuccinctArchiveBlob>::from_hash(output))
            .unwrap();
        succinctarchive_union::validate_derive(
            &simplearchive_union::descriptor(schema::DEFAULT_SCOPE_ID),
            &succinctarchive_union::descriptor(schema::DEFAULT_SCOPE_ID),
            &derive,
            &input,
            &output,
        )
        .unwrap();
        pile.close().unwrap();
    }

    #[test]
    fn bm25_uses_per_commit_derives_and_one_validated_merge_cover() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_signer(&pile_path, Some(&key)).unwrap();

        for (locator, text) in [("session:alpha", "alpha"), ("session:beta", "beta")] {
            let mut writer = ArchiveImportWriter::open(&pile_path, Some(&key)).unwrap();
            writer.stage_fragment(projection(locator, text)).unwrap();
            writer.finish(Ok(())).unwrap();
        }

        let report = ensure_bm25_index(&pile_path, Some(&key)).unwrap();
        assert_eq!(report.source_commits, 2);
        assert_eq!(report.derived_elements, 2);
        assert_eq!(report.cover_segments, 1);
        let length = std::fs::metadata(&pile_path).unwrap().len();
        assert_eq!(ensure_bm25_index(&pile_path, Some(&key)).unwrap(), report);
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), length);

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let records = discover_collection_records(&mut pile).unwrap();
        let source = simplearchive_union::descriptor(schema::DEFAULT_SCOPE_ID);
        let target = archive_bm25::descriptor();
        let derives: Vec<_> = records
            .derives()
            .iter()
            .filter(|claim| claim.source() == source.handle() && claim.target() == target.handle())
            .copied()
            .collect();
        let merges: Vec<_> = records
            .merges()
            .iter()
            .filter(|claim| claim.collection() == target.handle())
            .copied()
            .collect();
        assert_eq!(derives.len(), 2);
        assert_eq!(merges.len(), 1);
        let reader = pile.reader().unwrap();
        for claim in &derives {
            assert_eq!(
                archive_bm25::validate_derive(&reader, &source, &target, claim).unwrap(),
                Bm25Validation::Accepted
            );
        }
        for claim in &merges {
            assert_eq!(
                archive_bm25::validate_merge(&reader, &target, claim).unwrap(),
                Bm25Validation::Accepted
            );
        }
        pile.close().unwrap();

        let search = ArchiveSearchSnapshot::ensure_local(&pile_path, Some(&key)).unwrap();
        assert_eq!(search.segment_count(), 1);
        assert_eq!(search.search("alpha", 10).unwrap().len(), 1);
        assert_eq!(search.search("beta", 10).unwrap().len(), 1);
    }

    #[test]
    fn lazy_bm25_maintenance_extends_after_a_new_commit() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_signer(&pile_path, Some(&key)).unwrap();

        let first_fragment = projection("session:first", "alpha");
        let mut writer = ArchiveImportWriter::open(&pile_path, Some(&key)).unwrap();
        writer.stage_fragment(first_fragment).unwrap();
        writer.finish(Ok(())).unwrap();
        let first = ArchiveSearchSnapshot::ensure_local(&pile_path, Some(&key)).unwrap();
        assert_eq!(first.search("alpha", 10).unwrap().len(), 1);
        drop(first);

        let second_fragment = projection("session:second", "beta βeta 🛰️");
        let mut writer = ArchiveImportWriter::open(&pile_path, Some(&key)).unwrap();
        writer.stage_fragment(second_fragment.clone()).unwrap();
        writer.finish(Ok(())).unwrap();

        let extended = ArchiveSearchSnapshot::ensure_local(&pile_path, Some(&key)).unwrap();
        assert_eq!(extended.search("alpha", 10).unwrap().len(), 1);
        assert_eq!(extended.search("beta", 10).unwrap().len(), 1);
        assert_eq!(extended.search("🛰️", 1).unwrap().len(), 1);
        drop(extended);

        let before = std::fs::metadata(&pile_path).unwrap().len();
        let mut retry = ArchiveImportWriter::open(&pile_path, Some(&key)).unwrap();
        retry.stage_fragment(second_fragment).unwrap();
        retry.finish(Ok(())).unwrap();
        let after_retry = ArchiveSearchSnapshot::ensure_local(&pile_path, Some(&key)).unwrap();
        assert_eq!(after_retry.search("beta", 10).unwrap().len(), 1);
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), before);
    }

    #[test]
    fn bm25_rejects_a_source_element_without_its_block_closure_before_writing() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_signer(&pile_path, Some(&key)).unwrap();

        // The collection union is a valid Archive, but the tagged block and
        // the part/fact it references live in separate signed elements. The
        // BM25 homomorphism is defined per source element, so each element
        // containing a block must carry that block's complete part/fact
        // closure. Failing this contract must be loud and append nothing.
        let (block_element, remainder_element) =
            projection_split_across_source_elements("session:split", "closure needle");
        let signer = load_signer(&pile_path, Some(&key)).unwrap();
        let pile = open_pile_strict(&pile_path).unwrap();
        let mut collection = Collection::new(pile, schema::DEFAULT_SCOPE_ID, signer);
        collection.commit(block_element).unwrap();
        collection.commit(remainder_element).unwrap();
        collection.into_storage().close().unwrap();

        let archive =
            ArchiveSnapshot::load_local(&pile_path, Some(&key), schema::DEFAULT_SCOPE_ID).unwrap();
        assert_eq!(archive.commits().len(), 2);
        assert_eq!(archive.projection_ids().len(), 1);
        drop(archive);
        let before = std::fs::metadata(&pile_path).unwrap().len();

        let error = ensure_bm25_index(&pile_path, Some(&key)).unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("references absent part"), "{error}");
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), before);
    }
}
