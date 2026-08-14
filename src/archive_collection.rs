//! Collection-native Archive runtime over the V4 descriptor-handle calculus.
//!
//! Archive authorship has one durable Ed25519 signer and one fixed canonical
//! SimpleArchive-union descriptor. Imports stage complete projector fragments
//! in memory, validate the candidate block DAG, and cross exactly one
//! Collection::commit visibility edge. Reads materialize that same collection;
//! there is no Repository branch, CAS head, sidecar registry, or fallback
//! identity.

use std::collections::BTreeSet;

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::succinctarchive::SuccinctArchiveBlob;
use triblespace::core::blob::{Blob, BlobEncoding};
use triblespace::core::collection::{
    collection_physical_cover, discover_collection_records, resolve_collection_semantics,
    simplearchive_union, succinctarchive_union, Collection, CollectionClaimValidation,
    CollectionCommit, CollectionData, CollectionDerive, CollectionDescriptor, CollectionMerge,
    CollectionRecord, CollectionStore, CollectionValidationRequest, DiscoveredCollectionRecords,
};
use triblespace::core::inline::InlineEncoding;
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
use crate::collection_cutover::{load_signer, open_pile_strict};
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

fn close_collection<T>(
    collection: Collection<Pile>,
    result: Result<T>,
    failure_context: &str,
) -> Result<T> {
    match (result, collection.into_storage().close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(close_error)) => Err(anyhow!("close Archive pile: {close_error}")),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("{failure_context} also failed: {close_error}")))
        }
    }
}

/// Exact V4 raw-Succinct derivation summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuccinctIndexReport {
    pub source_commits: usize,
    /// Distinct source data elements named by the frozen commit ticket.
    pub source_elements: usize,
    pub source_collection: Inline<Handle<SimpleArchive>>,
    pub target_collection: Inline<Handle<SimpleArchive>>,
}

/// Ensure an exact resident raw-Succinct cover for the frozen Archive ticket.
///
/// This is a reproducible physical cover, not new authority. The target uses
/// V4's canonical raw-Succinct union descriptor; validated source `MERGE`,
/// target `MERGE`, and cross-representation `DERIVE` equations may cover one
/// or several signed roots. [`ensure_bm25_index`] provides the analogous exact
/// projection for Archive full-text search.
pub fn ensure_succinct_index(
    pile_path: &std::path::Path,
    key_path: Option<&std::path::Path>,
) -> Result<SuccinctIndexReport> {
    let mut collection =
        ArchiveSnapshot::open_collection(pile_path, key_path, schema::DEFAULT_SCOPE_ID)?;
    let result = (|| {
        let archive = ArchiveSnapshot::from_collection(&mut collection, schema::DEFAULT_SCOPE_ID)?;
        let source = simplearchive_union::descriptor(schema::DEFAULT_SCOPE_ID);
        let target = succinctarchive_union::descriptor(schema::DEFAULT_SCOPE_ID);
        let source_elements = distinct_ticket_data(archive.commits()).len();
        ensure_exact_target::<SuccinctArchiveBlob, _>(
            collection.storage_mut(),
            archive.commits(),
            &source,
            &target,
            validate_succinct_request,
            |reader, data| derive_succinct_element(reader, &source, &target, data),
        )?;

        Ok(SuccinctIndexReport {
            source_commits: archive.commits().len(),
            source_elements,
            source_collection: source.handle(),
            target_collection: target.handle(),
        })
    })();
    close_collection(
        collection,
        result,
        "closing Archive pile after raw-Succinct derivation",
    )
}

/// Exact V4 Archive BM25 derivation summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bm25IndexReport {
    pub source_commits: usize,
    /// Distinct source data elements named by the frozen commit ticket.
    pub source_elements: usize,
    pub cover_segments: usize,
    pub source_collection: Inline<Handle<SimpleArchive>>,
    pub target_collection: Inline<Handle<SimpleArchive>>,
}

struct EnsuredBm25 {
    report: Bm25IndexReport,
    reader: PileReader,
    cover: Vec<CollectionData>,
}

/// Ensure a portable exact-TF cover of the frozen Archive ticket, then compact
/// its current admissible physical cover through exact `MERGE` equations.
pub fn ensure_bm25_index(
    pile_path: &std::path::Path,
    key_path: Option<&std::path::Path>,
) -> Result<Bm25IndexReport> {
    let mut collection =
        ArchiveSnapshot::open_collection(pile_path, key_path, schema::DEFAULT_SCOPE_ID)?;
    let result = (|| {
        let archive = ArchiveSnapshot::from_collection(&mut collection, schema::DEFAULT_SCOPE_ID)?;
        Ok(ensure_bm25_for_snapshot(collection.storage_mut(), &archive)?.report)
    })();
    close_collection(
        collection,
        result,
        "closing Archive pile after BM25 derivation",
    )
}

fn ensure_bm25_for_snapshot(pile: &mut Pile, archive: &ArchiveSnapshot) -> Result<EnsuredBm25> {
    let source = simplearchive_union::descriptor(schema::DEFAULT_SCOPE_ID);
    let target = archive_bm25::descriptor();
    let source_elements = distinct_ticket_data(archive.commits()).len();
    let ready = ensure_exact_target::<PortableBM25Blob, _>(
        pile,
        archive.commits(),
        &source,
        &target,
        validate_bm25_request,
        |reader, data| derive_bm25_element(reader, &source, &target, data),
    )?;
    let ready = compact_bm25_target(pile, archive.commits(), &source, &target, ready)?;
    let cover: Vec<_> = ready.cover.iter().copied().collect();
    Ok(EnsuredBm25 {
        report: Bm25IndexReport {
            source_commits: archive.commits().len(),
            source_elements,
            cover_segments: cover.len(),
            source_collection: source.handle(),
            target_collection: target.handle(),
        },
        reader: ready.reader,
        cover,
    })
}

#[derive(Debug)]
struct ExactTargetProbe {
    reader: PileReader,
    cover: BTreeSet<CollectionData>,
    missing_frontier: BTreeSet<CollectionData>,
    unsupported_roots: BTreeSet<Id>,
}

impl ExactTargetProbe {
    fn is_complete(&self) -> bool {
        self.missing_frontier.is_empty() && self.unsupported_roots.is_empty()
    }
}

fn distinct_ticket_data(commits: &[CollectionCommit]) -> BTreeSet<CollectionData> {
    commits.iter().map(CollectionCommit::data).collect()
}

type DerivedValidator = for<'a> fn(
    &PileReader,
    &CollectionDescriptor,
    &CollectionDescriptor,
    CollectionValidationRequest<'a>,
) -> Result<CollectionClaimValidation<String>>;

fn ensure_exact_target<E, D>(
    pile: &mut Pile,
    ticket: &[CollectionCommit],
    source: &CollectionDescriptor,
    target: &CollectionDescriptor,
    validate: DerivedValidator,
    mut derive: D,
) -> Result<ExactTargetProbe>
where
    E: BlobEncoding,
    Handle<E>: InlineEncoding,
    D: FnMut(&PileReader, CollectionData) -> Result<Blob<E>>,
{
    let mut probe = probe_exact_target::<E>(pile, ticket, source, target, validate)?;
    if ensure_descriptor_blobs(pile, source, target)? {
        probe.reader = pile
            .reader()
            .context("refresh derived-collection reader after descriptor recovery")?;
    }
    if probe.is_complete() {
        return Ok(probe);
    }

    let residual_data: BTreeSet<_> = ticket
        .iter()
        .filter(|commit| probe.unsupported_roots.contains(&commit.id()))
        .map(CollectionCommit::data)
        .collect();
    if residual_data.is_empty() {
        bail!(
            "derived collection {} is incomplete without an unsupported source root",
            hex::encode_upper(target.handle().raw),
        );
    }

    // Produce the complete residual in memory before publishing any part of
    // it. Distinct commits with identical data intentionally share one
    // canonical mapping while retaining all signed roots in the ticket.
    let mut prepared = Vec::with_capacity(residual_data.len());
    for input in residual_data {
        let output = derive(&probe.reader, input)?;
        let output_data = Handle::<E>::to_hash(output.get_handle());
        let claim = CollectionDerive::new(source.handle(), target.handle(), input, output_data);
        prepared.push((output, claim));
    }
    append_derivations(pile, &prepared)?;

    // Local construction is not admission. A fresh reader and record scan
    // must prove the exact same frozen ticket through the canonical validator.
    probe = probe_exact_target::<E>(pile, ticket, source, target, validate)?;
    if !probe.is_complete() {
        bail!(
            "derived collection {} remains incomplete after residual construction ({} missing frontier element(s), {} unsupported frozen root(s))",
            hex::encode_upper(target.handle().raw),
            probe.missing_frontier.len(),
            probe.unsupported_roots.len(),
        );
    }
    Ok(probe)
}

fn probe_exact_target<E>(
    pile: &mut Pile,
    ticket: &[CollectionCommit],
    source: &CollectionDescriptor,
    target: &CollectionDescriptor,
    validate: DerivedValidator,
) -> Result<ExactTargetProbe>
where
    E: BlobEncoding,
    Handle<E>: InlineEncoding,
{
    let discovered = discover_collection_records(&mut *pile)
        .context("discover exact derived-collection records")?;
    let authorized = exact_ticket_ids(&discovered, ticket, source)?;
    let reader = pile.reader().context("open derived-collection reader")?;
    let resolution = resolve_collection_semantics(&discovered, &authorized, |request| {
        validate(&reader, source, target, request)
    })
    .map_err(|error| anyhow!("resolve exact derived collection: {error}"))?;

    for commit in ticket {
        if resolution.validation_pending().contains(&commit.id()) {
            bail!("frozen source commit {:X} is incomplete", commit.id());
        }
        if let Some(reason) = resolution.rejected().get(&commit.id()) {
            bail!(
                "frozen source commit {:X} was rejected: {reason}",
                commit.id()
            );
        }
        if !resolution.admitted_claims().contains(&commit.id()) {
            bail!("frozen source commit {:X} was not admitted", commit.id());
        }
    }

    let mut resident = BTreeSet::new();
    for data in resolution
        .semantics()
        .members(target.handle())
        .into_iter()
        .flatten()
    {
        if reader.metadata(Handle::<E>::from_hash(*data))?.is_some() {
            resident.insert(*data);
        }
    }
    let physical = collection_physical_cover(resolution.semantics(), target.handle(), &resident);
    let supported_roots: BTreeSet<_> = physical
        .cover
        .iter()
        .flat_map(|data| {
            resolution
                .semantics()
                .supporting_commit_ids(target.handle(), *data)
        })
        .collect();
    let foreign: Vec<_> = supported_roots.difference(&authorized).copied().collect();
    if !foreign.is_empty() {
        bail!(
            "derived target support escaped the frozen ticket through commit(s) [{}]",
            foreign
                .iter()
                .map(|id| format!("{id:X}"))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }

    Ok(ExactTargetProbe {
        reader,
        cover: physical.cover,
        missing_frontier: physical.missing,
        unsupported_roots: authorized.difference(&supported_roots).copied().collect(),
    })
}

fn exact_ticket_ids(
    discovered: &DiscoveredCollectionRecords,
    ticket: &[CollectionCommit],
    source: &CollectionDescriptor,
) -> Result<BTreeSet<Id>> {
    let mut ids = BTreeSet::new();
    for commit in ticket {
        if commit.collection() != source.handle() {
            bail!(
                "frozen source commit {:X} names collection {}, expected {}",
                commit.id(),
                hex::encode_upper(commit.collection().raw),
                hex::encode_upper(source.handle().raw),
            );
        }
        if !ids.insert(commit.id()) {
            bail!("frozen source ticket repeats commit {:X}", commit.id());
        }
        match discovered
            .commits()
            .binary_search_by_key(&commit.id(), CollectionCommit::id)
        {
            Ok(index) if discovered.commits()[index] == *commit => {}
            Ok(_) => bail!(
                "frozen source commit {:X} does not byte-match the discovered record",
                commit.id()
            ),
            Err(_) => bail!(
                "frozen source commit {:X} is absent from the current record snapshot",
                commit.id()
            ),
        }
    }
    Ok(ids)
}

fn ensure_descriptor_blobs(
    pile: &mut Pile,
    source: &CollectionDescriptor,
    target: &CollectionDescriptor,
) -> Result<bool> {
    let reader = pile
        .reader()
        .context("inspect derived-collection descriptors")?;
    let source_missing = reader.metadata(source.handle())?.is_none();
    let target_missing =
        target.handle() != source.handle() && reader.metadata(target.handle())?.is_none();
    drop(reader);
    if source_missing {
        pile.put::<SimpleArchive, _>(CollectionDescriptor::to_blob(source))
            .context("store source collection descriptor")?;
    }
    if target_missing {
        pile.put::<SimpleArchive, _>(CollectionDescriptor::to_blob(target))
            .context("store target collection descriptor")?;
    }
    Ok(source_missing || target_missing)
}

fn append_derivations<E>(pile: &mut Pile, prepared: &[(Blob<E>, CollectionDerive)]) -> Result<()>
where
    E: BlobEncoding,
{
    for (output, _) in prepared {
        pile.put::<E, _>(output.clone())
            .context("store deterministic derived collection element")?;
    }
    for (_, claim) in prepared {
        CollectionStore::insert(&mut *pile, CollectionRecord::Derive(*claim))
            .context("publish deterministic collection DERIVE")?;
    }
    Ok(())
}

fn validate_bm25_request(
    reader: &PileReader,
    source: &CollectionDescriptor,
    target: &CollectionDescriptor,
    request: CollectionValidationRequest<'_>,
) -> Result<CollectionClaimValidation<String>> {
    match request {
        CollectionValidationRequest::Commit { claim } => {
            validate_simplearchive_commit(reader, source, claim)
        }
        CollectionValidationRequest::Merge { claim } if claim.collection() == source.handle() => {
            validate_simplearchive_merge(reader, source, claim)
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

fn validate_succinct_request(
    reader: &PileReader,
    source: &CollectionDescriptor,
    target: &CollectionDescriptor,
    request: CollectionValidationRequest<'_>,
) -> Result<CollectionClaimValidation<String>> {
    match request {
        CollectionValidationRequest::Commit { claim } => {
            validate_simplearchive_commit(reader, source, claim)
        }
        CollectionValidationRequest::Merge { claim } if claim.collection() == source.handle() => {
            validate_simplearchive_merge(reader, source, claim)
        }
        CollectionValidationRequest::Merge { claim } if claim.collection() == target.handle() => {
            let (low, high) = claim.inputs();
            let Some(low) = load_resident::<SuccinctArchiveBlob>(reader, low)? else {
                return Ok(CollectionClaimValidation::Pending);
            };
            let Some(high) = load_resident::<SuccinctArchiveBlob>(reader, high)? else {
                return Ok(CollectionClaimValidation::Pending);
            };
            let Some(result) = load_resident::<SuccinctArchiveBlob>(reader, claim.result())? else {
                return Ok(CollectionClaimValidation::Pending);
            };
            Ok(
                match succinctarchive_union::validate_merge(target, claim, &low, &high, &result) {
                    Ok(()) => CollectionClaimValidation::Accepted,
                    Err(error) => CollectionClaimValidation::Rejected(error.to_string()),
                },
            )
        }
        CollectionValidationRequest::Derive { claim }
            if claim.source() == source.handle() && claim.target() == target.handle() =>
        {
            let (input, output) = claim.mapping();
            let Some(input) = load_resident::<SimpleArchive>(reader, input)? else {
                return Ok(CollectionClaimValidation::Pending);
            };
            let Some(output) = load_resident::<SuccinctArchiveBlob>(reader, output)? else {
                return Ok(CollectionClaimValidation::Pending);
            };
            Ok(
                match succinctarchive_union::validate_derive(source, target, claim, &input, &output)
                {
                    Ok(()) => CollectionClaimValidation::Accepted,
                    Err(error) => CollectionClaimValidation::Rejected(error.to_string()),
                },
            )
        }
        CollectionValidationRequest::Merge { .. } | CollectionValidationRequest::Derive { .. } => {
            Ok(CollectionClaimValidation::Pending)
        }
    }
}

fn validate_simplearchive_commit(
    reader: &PileReader,
    descriptor: &CollectionDescriptor,
    claim: &CollectionCommit,
) -> Result<CollectionClaimValidation<String>> {
    if claim.collection() != descriptor.handle() {
        return Ok(CollectionClaimValidation::Rejected(
            "frozen commit names another collection".to_owned(),
        ));
    }
    let Some(data) = load_resident::<SimpleArchive>(reader, claim.data())? else {
        return Ok(CollectionClaimValidation::Pending);
    };
    Ok(
        match simplearchive_union::validate_commit(descriptor, claim, &data) {
            Ok(()) => CollectionClaimValidation::Accepted,
            Err(error) => CollectionClaimValidation::Rejected(error.to_string()),
        },
    )
}

fn validate_simplearchive_merge(
    reader: &PileReader,
    descriptor: &CollectionDescriptor,
    claim: &CollectionMerge,
) -> Result<CollectionClaimValidation<String>> {
    let (low, high) = claim.inputs();
    let Some(low) = load_resident::<SimpleArchive>(reader, low)? else {
        return Ok(CollectionClaimValidation::Pending);
    };
    let Some(high) = load_resident::<SimpleArchive>(reader, high)? else {
        return Ok(CollectionClaimValidation::Pending);
    };
    let Some(result) = load_resident::<SimpleArchive>(reader, claim.result())? else {
        return Ok(CollectionClaimValidation::Pending);
    };
    Ok(
        match simplearchive_union::validate_merge(descriptor, claim, &low, &high, &result) {
            Ok(()) => CollectionClaimValidation::Accepted,
            Err(error) => CollectionClaimValidation::Rejected(error.to_string()),
        },
    )
}

fn derive_succinct_element(
    reader: &PileReader,
    source: &CollectionDescriptor,
    target: &CollectionDescriptor,
    input_data: CollectionData,
) -> Result<Blob<SuccinctArchiveBlob>> {
    let input = load_resident::<SimpleArchive>(reader, input_data)?
        .ok_or_else(|| anyhow!("frozen Archive source element is not resident"))?;
    let output = succinctarchive_union::derive_element(&input)
        .context("derive canonical raw SuccinctArchive element")?;
    let output_data = Handle::<SuccinctArchiveBlob>::to_hash(output.get_handle());
    let claim = CollectionDerive::new(source.handle(), target.handle(), input_data, output_data);
    succinctarchive_union::validate_derive(source, target, &claim, &input, &output)
        .context("validate fresh Archive raw-Succinct derivation")?;
    Ok(output)
}

fn derive_bm25_element(
    reader: &PileReader,
    source: &CollectionDescriptor,
    target: &CollectionDescriptor,
    input_data: CollectionData,
) -> Result<Blob<PortableBM25Blob>> {
    let input = load_resident::<SimpleArchive>(reader, input_data)?
        .ok_or_else(|| anyhow!("frozen Archive source element is not resident"))?;
    let output = archive_bm25::derive_element(reader, input.clone())
        .context("derive exact Archive BM25 element")?;
    let output_data = Handle::<PortableBM25Blob>::to_hash(output.get_handle());
    let claim = CollectionDerive::new(source.handle(), target.handle(), input_data, output_data);
    require_bm25_accepted(
        archive_bm25::validate_derive_bytes(reader, source, target, &claim, &input, &output)?,
        "fresh Archive BM25 derivation",
    )?;
    Ok(output)
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

fn load_resident<E>(reader: &PileReader, data: CollectionData) -> Result<Option<Blob<E>>>
where
    E: BlobEncoding,
    Handle<E>: InlineEncoding,
{
    let handle = Handle::<E>::from_hash(data);
    if reader.metadata(handle)?.is_none() {
        return Ok(None);
    }
    Ok(Some(reader.get(handle).with_context(|| {
        format!("read collection element {}", hex::encode_upper(data.raw))
    })?))
}

fn compact_bm25_target(
    pile: &mut Pile,
    ticket: &[CollectionCommit],
    source: &CollectionDescriptor,
    target: &CollectionDescriptor,
    ready: ExactTargetProbe,
) -> Result<ExactTargetProbe> {
    let merges = plan_cover_merge(&ready.reader, target, &ready.cover)?;
    if merges.is_empty() {
        return Ok(ready);
    }
    pile.put::<SimpleArchive, _>(CollectionDescriptor::to_blob(target))
        .context("store Archive BM25 descriptor")?;
    for (output, _) in &merges {
        pile.put::<PortableBM25Blob, _>(output.clone())
            .context("store Archive BM25 merge result")?;
    }
    for (_, claim) in &merges {
        CollectionStore::insert(&mut *pile, CollectionRecord::Merge(*claim))
            .context("publish Archive BM25 MERGE")?;
    }

    let compacted = probe_exact_target::<PortableBM25Blob>(
        pile,
        ticket,
        source,
        target,
        validate_bm25_request,
    )?;
    if !compacted.is_complete() {
        bail!(
            "Archive BM25 compaction lost exact ticket support ({} missing frontier element(s), {} unsupported frozen root(s))",
            compacted.missing_frontier.len(),
            compacted.unsupported_roots.len(),
        );
    }
    Ok(compacted)
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
        let mut collection =
            ArchiveSnapshot::open_collection(pile_path, key_path, schema::DEFAULT_SCOPE_ID)?;
        let result = (|| {
            let archive =
                ArchiveSnapshot::from_collection(&mut collection, schema::DEFAULT_SCOPE_ID)?;
            let ensured = ensure_bm25_for_snapshot(collection.storage_mut(), &archive)?;
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
        })();
        close_collection(
            collection,
            result,
            "closing Archive pile after BM25 search preparation",
        )
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
    fn open_collection(
        pile_path: &std::path::Path,
        key_path: Option<&std::path::Path>,
        scope: Id,
    ) -> Result<Collection<Pile>> {
        if scope != schema::DEFAULT_SCOPE_ID {
            bail!(
                "Archive runtime only supports fixed scope {:X}",
                schema::DEFAULT_SCOPE_ID
            );
        }
        let signer = load_signer(pile_path, key_path)?;
        let pile = open_pile_strict(pile_path)?;
        Ok(Collection::new(pile, scope, signer))
    }

    fn from_collection(collection: &mut Collection<Pile>, scope: Id) -> Result<Self> {
        let snapshot = collection
            .snapshot()
            .context("snapshot authored Archive collection")?;
        let (facts, commits, reader) = snapshot.into_parts();
        require_accepted(
            blockdag::validate_catalog(&reader, &facts)
                .context("validate materialized Archive catalog")?,
            "materialized Archive catalog",
        )?;
        Ok(Self {
            scope,
            facts,
            reader,
            commits,
        })
    }

    pub fn load_local(
        pile_path: &std::path::Path,
        key_path: Option<&std::path::Path>,
        scope: Id,
    ) -> Result<Self> {
        let mut collection = Self::open_collection(pile_path, key_path, scope)?;
        let result = Self::from_collection(&mut collection, scope);
        close_collection(collection, result, "closing Archive pile")
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
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;
    use triblespace::core::blob::IntoBlob;
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

    fn commit_projection(
        pile: &std::path::Path,
        key: &std::path::Path,
        locator: &str,
        text: &str,
    ) -> CollectionCommit {
        let mut writer = ArchiveImportWriter::open(pile, Some(key)).unwrap();
        writer.stage_fragment(projection(locator, text)).unwrap();
        writer.finish(Ok(())).unwrap().1.unwrap()
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
        assert_eq!((succinct.source_commits, succinct.source_elements), (1, 1));
        assert_eq!(
            (
                bm25.source_commits,
                bm25.source_elements,
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
        assert_eq!(report.source_elements, 1);
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
        assert_eq!(report.source_elements, 2);
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
    fn bm25_rejects_split_source_without_an_admitted_route_before_writing() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_signer(&pile_path, Some(&key)).unwrap();

        // The collection union is a valid Archive, but the tagged block and
        // its part/fact closure live in separate signed elements. With no
        // admitted source MERGE and union DERIVE, no target route covers both
        // roots. Direct residual derivation must reject the incomplete leaf
        // before publishing an accelerator payload or equation.
        let (block_element, remainder_element) =
            projection_split_across_source_elements("session:split", "closure needle");
        let signer = load_signer(&pile_path, Some(&key)).unwrap();
        let pile = open_pile_strict(&pile_path).unwrap();
        let mut collection = Collection::new(pile, schema::DEFAULT_SCOPE_ID, signer);
        collection.commit(block_element).unwrap();
        collection.commit(remainder_element).unwrap();
        collection
            .storage_mut()
            .put::<SimpleArchive, _>(CollectionDescriptor::to_blob(&archive_bm25::descriptor()))
            .unwrap();
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

    #[test]
    fn bm25_reuses_a_merge_before_derive_route_for_split_source() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_signer(&pile_path, Some(&key)).unwrap();

        let (block_element, remainder_element) =
            projection_split_across_source_elements("session:routed", "routed needle");
        let signer = load_signer(&pile_path, Some(&key)).unwrap();
        let pile = open_pile_strict(&pile_path).unwrap();
        let mut collection = Collection::new(pile, schema::DEFAULT_SCOPE_ID, signer);
        let block_commit = collection.commit(block_element).unwrap();
        let remainder_commit = collection.commit(remainder_element).unwrap();
        let source = *collection.descriptor();
        let reader = collection.storage_mut().reader().unwrap();
        let block_blob: Blob<SimpleArchive> = reader
            .get(Handle::<SimpleArchive>::from_hash(block_commit.data()))
            .unwrap();
        let remainder_blob: Blob<SimpleArchive> = reader
            .get(Handle::<SimpleArchive>::from_hash(remainder_commit.data()))
            .unwrap();
        drop(reader);
        let (_, union) = simplearchive_union::publish_merge(
            collection.storage_mut(),
            &source,
            &block_blob,
            &remainder_blob,
        )
        .unwrap();

        let target = archive_bm25::descriptor();
        let reader = collection.storage_mut().reader().unwrap();
        let output = archive_bm25::derive_element(&reader, union.clone()).unwrap();
        let input_data = Handle::<SimpleArchive>::to_hash(union.get_handle());
        let output_data = Handle::<PortableBM25Blob>::to_hash(output.get_handle());
        let derive =
            CollectionDerive::new(source.handle(), target.handle(), input_data, output_data);
        require_bm25_accepted(
            archive_bm25::validate_derive_bytes(
                &reader, &source, &target, &derive, &union, &output,
            )
            .unwrap(),
            "merge-before-derive fixture",
        )
        .unwrap();
        drop(reader);
        collection
            .storage_mut()
            .put::<SimpleArchive, _>(CollectionDescriptor::to_blob(&target))
            .unwrap();
        collection
            .storage_mut()
            .put::<PortableBM25Blob, _>(output)
            .unwrap();
        CollectionStore::insert(collection.storage_mut(), CollectionRecord::Derive(derive))
            .unwrap();
        collection.into_storage().close().unwrap();
        let before = std::fs::metadata(&pile_path).unwrap().len();

        let search = ArchiveSearchSnapshot::ensure_local(&pile_path, Some(&key)).unwrap();
        let hits = search.search("routed needle", 10).unwrap();
        assert_eq!(hits.len(), 1);
        let projections = search.archive().projection_ids();
        assert_eq!(projections.len(), 1);
        assert_eq!(hits[0].projections, projections);
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), before);
    }

    #[test]
    fn bm25_frozen_ticket_excludes_a_later_authorized_commit() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_signer(&pile_path, Some(&key)).unwrap();

        let first = commit_projection(&pile_path, &key, "session:frozen", "frozen needle");
        let frozen =
            ArchiveSnapshot::load_local(&pile_path, Some(&key), schema::DEFAULT_SCOPE_ID).unwrap();
        let later = commit_projection(&pile_path, &key, "session:later", "later needle");

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let ensured = ensure_bm25_for_snapshot(&mut pile, &frozen).unwrap();
        assert_eq!(ensured.report.source_commits, 1);
        drop(ensured);
        pile.close().unwrap();
        drop(frozen);

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let records = discover_collection_records(&mut pile).unwrap();
        let source = simplearchive_union::descriptor(schema::DEFAULT_SCOPE_ID);
        let target = archive_bm25::descriptor();
        let inputs: BTreeSet<_> = records
            .derives()
            .iter()
            .filter(|claim| claim.source() == source.handle() && claim.target() == target.handle())
            .map(|claim| claim.mapping().0)
            .collect();
        assert_eq!(inputs, BTreeSet::from([first.data()]));
        assert!(!inputs.contains(&later.data()));
        pile.close().unwrap();
    }

    #[test]
    fn bm25_exact_ensure_derives_only_the_residual_and_reuses_its_merge() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_signer(&pile_path, Some(&key)).unwrap();
        commit_projection(&pile_path, &key, "session:first", "first residual");
        commit_projection(&pile_path, &key, "session:second", "second residual");
        let archive =
            ArchiveSnapshot::load_local(&pile_path, Some(&key), schema::DEFAULT_SCOPE_ID).unwrap();
        let commits = archive.commits().to_vec();
        drop(archive);

        let source = simplearchive_union::descriptor(schema::DEFAULT_SCOPE_ID);
        let target = archive_bm25::descriptor();
        let mut pile = open_pile_strict(&pile_path).unwrap();

        let mut produced = 0;
        let first = ensure_exact_target::<PortableBM25Blob, _>(
            &mut pile,
            &commits[..1],
            &source,
            &target,
            validate_bm25_request,
            |reader, data| {
                produced += 1;
                derive_bm25_element(reader, &source, &target, data)
            },
        )
        .unwrap();
        assert_eq!(produced, 1);
        assert_eq!(first.cover.len(), 1);
        drop(first);

        produced = 0;
        let full = ensure_exact_target::<PortableBM25Blob, _>(
            &mut pile,
            &commits,
            &source,
            &target,
            validate_bm25_request,
            |reader, data| {
                produced += 1;
                derive_bm25_element(reader, &source, &target, data)
            },
        )
        .unwrap();
        assert_eq!(produced, 1, "only the newly unsupported root is derived");
        assert_eq!(full.cover.len(), 2);
        let compacted = compact_bm25_target(&mut pile, &commits, &source, &target, full).unwrap();
        assert_eq!(compacted.cover.len(), 1);
        drop(compacted);

        let records_before = discover_collection_records(&mut pile).unwrap();
        let counts_before = (
            records_before.derives().len(),
            records_before.merges().len(),
        );
        produced = 0;
        let retry = ensure_exact_target::<PortableBM25Blob, _>(
            &mut pile,
            &commits,
            &source,
            &target,
            validate_bm25_request,
            |reader, data| {
                produced += 1;
                derive_bm25_element(reader, &source, &target, data)
            },
        )
        .unwrap();
        assert_eq!(produced, 0);
        assert_eq!(retry.cover.len(), 1, "the admitted MERGE is reused");
        drop(retry);
        let records_after = discover_collection_records(&mut pile).unwrap();
        assert_eq!(
            (records_after.derives().len(), records_after.merges().len()),
            counts_before,
            "a complete retry publishes no collection records"
        );
        pile.close().unwrap();
    }

    #[test]
    fn exact_ensure_deduplicates_data_without_losing_commit_support() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_signer(&pile_path, Some(&key)).unwrap();
        let first = commit_projection(&pile_path, &key, "session:shared", "shared data");
        let source = simplearchive_union::descriptor(schema::DEFAULT_SCOPE_ID);
        let target = archive_bm25::descriptor();
        let second = CollectionCommit::sign(
            &SigningKey::from_bytes(&[0xA5; 32]),
            source.handle(),
            first.data(),
            first.metadata(),
        );

        let mut pile = open_pile_strict(&pile_path).unwrap();
        CollectionStore::insert(&mut pile, CollectionRecord::Commit(second)).unwrap();
        let mut produced = 0;
        let ready = ensure_exact_target::<PortableBM25Blob, _>(
            &mut pile,
            &[first, second],
            &source,
            &target,
            validate_bm25_request,
            |reader, data| {
                produced += 1;
                derive_bm25_element(reader, &source, &target, data)
            },
        )
        .unwrap();
        assert_eq!(produced, 1, "equal source data has one canonical image");
        assert!(ready.is_complete(), "both signed roots retain support");
        pile.close().unwrap();
    }

    #[test]
    fn exact_ensure_recovers_a_pending_derive_with_a_missing_output() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_signer(&pile_path, Some(&key)).unwrap();
        let commit = commit_projection(&pile_path, &key, "session:pending", "recover output");
        let source = simplearchive_union::descriptor(schema::DEFAULT_SCOPE_ID);
        let target = archive_bm25::descriptor();

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let reader = pile.reader().unwrap();
        let output = derive_bm25_element(&reader, &source, &target, commit.data()).unwrap();
        let output_data = Handle::<PortableBM25Blob>::to_hash(output.get_handle());
        let pending =
            CollectionDerive::new(source.handle(), target.handle(), commit.data(), output_data);
        drop(output);
        drop(reader);
        CollectionStore::insert(&mut pile, CollectionRecord::Derive(pending)).unwrap();
        assert!(pile
            .reader()
            .unwrap()
            .metadata(Handle::<PortableBM25Blob>::from_hash(output_data))
            .unwrap()
            .is_none());

        let mut produced = 0;
        let ready = ensure_exact_target::<PortableBM25Blob, _>(
            &mut pile,
            &[commit],
            &source,
            &target,
            validate_bm25_request,
            |reader, data| {
                produced += 1;
                derive_bm25_element(reader, &source, &target, data)
            },
        )
        .unwrap();
        assert_eq!(produced, 1);
        assert_eq!(ready.cover, BTreeSet::from([output_data]));
        drop(ready);
        let records = discover_collection_records(&mut pile).unwrap();
        assert_eq!(
            records
                .derives()
                .iter()
                .filter(|claim| **claim == pending)
                .count(),
            1,
            "the recovered deterministic equation remains one record"
        );
        pile.close().unwrap();
    }

    #[test]
    fn exact_ensure_restores_missing_descriptors_once_on_a_complete_fast_path() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        let signer = initialize_signer(&pile_path, Some(&key)).unwrap();
        let source = simplearchive_union::descriptor(schema::DEFAULT_SCOPE_ID);
        let target = archive_bm25::descriptor();

        let (_, facts, metafacts, mut blobs) =
            projection("session:descriptors", "descriptor recovery").into_parts();
        let data: Blob<SimpleArchive> = facts.to_blob();
        let metadata: Blob<SimpleArchive> = metafacts.to_blob();
        let commit = CollectionCommit::sign(
            &signer,
            source.handle(),
            Handle::<SimpleArchive>::to_hash(data.get_handle()),
            metadata.get_handle(),
        );
        let mut pile = open_pile_strict(&pile_path).unwrap();
        for (_, blob) in blobs.reader().unwrap() {
            pile.put::<blobencodings::UnknownBlob, _>(blob).unwrap();
        }
        pile.put::<SimpleArchive, _>(data).unwrap();
        pile.put::<SimpleArchive, _>(metadata).unwrap();
        CollectionStore::insert(&mut pile, CollectionRecord::Commit(commit)).unwrap();
        let reader = pile.reader().unwrap();
        let output = derive_bm25_element(&reader, &source, &target, commit.data()).unwrap();
        let output_data = Handle::<PortableBM25Blob>::to_hash(output.get_handle());
        let derive =
            CollectionDerive::new(source.handle(), target.handle(), commit.data(), output_data);
        drop(reader);
        pile.put::<PortableBM25Blob, _>(output).unwrap();
        CollectionStore::insert(&mut pile, CollectionRecord::Derive(derive)).unwrap();
        let reader = pile.reader().unwrap();
        assert!(reader.metadata(source.handle()).unwrap().is_none());
        assert!(reader.metadata(target.handle()).unwrap().is_none());
        drop(reader);

        let mut produced = 0;
        let ready = ensure_exact_target::<PortableBM25Blob, _>(
            &mut pile,
            &[commit],
            &source,
            &target,
            validate_bm25_request,
            |reader, data| {
                produced += 1;
                derive_bm25_element(reader, &source, &target, data)
            },
        )
        .unwrap();
        assert_eq!(produced, 0);
        assert!(ready.reader.metadata(source.handle()).unwrap().is_some());
        assert!(ready.reader.metadata(target.handle()).unwrap().is_some());
        drop(ready);
        let after_recovery = std::fs::metadata(&pile_path).unwrap().len();

        let retry = ensure_exact_target::<PortableBM25Blob, _>(
            &mut pile,
            &[commit],
            &source,
            &target,
            validate_bm25_request,
            |reader, data| {
                produced += 1;
                derive_bm25_element(reader, &source, &target, data)
            },
        )
        .unwrap();
        assert_eq!(produced, 0);
        drop(retry);
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), after_recovery);
        pile.close().unwrap();
    }

    #[test]
    fn exact_ensure_rejects_an_absent_ticket_before_derivation() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_signer(&pile_path, Some(&key)).unwrap();
        let existing = commit_projection(&pile_path, &key, "session:existing", "existing data");
        let source = simplearchive_union::descriptor(schema::DEFAULT_SCOPE_ID);
        let target = archive_bm25::descriptor();
        let absent = CollectionCommit::sign(
            &SigningKey::from_bytes(&[0x5A; 32]),
            source.handle(),
            existing.data(),
            existing.metadata(),
        );
        let before = std::fs::metadata(&pile_path).unwrap().len();

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let mut produced = 0;
        let error = ensure_exact_target::<PortableBM25Blob, _>(
            &mut pile,
            &[absent],
            &source,
            &target,
            validate_bm25_request,
            |reader, data| {
                produced += 1;
                derive_bm25_element(reader, &source, &target, data)
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("absent from the current record snapshot"));
        assert_eq!(produced, 0);
        pile.close().unwrap();
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), before);
    }
}
