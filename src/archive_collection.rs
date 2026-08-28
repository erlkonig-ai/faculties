//! Collection-native Archive runtime over the V4 descriptor-handle calculus.
//!
//! Archive authorship has one durable Ed25519 signer and one fixed canonical
//! SimpleArchive-union descriptor. Imports stage independently derivable source
//! fragments which contribute new evidence, validate the candidate block DAG,
//! and cross exactly one Collection::commit visibility edge. Reads materialize that same collection;
//! there is no Repository branch, CAS head, sidecar registry, or fallback
//! identity.

use std::collections::{BTreeMap, BTreeSet};

use anybytes::{Bytes, View};
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::blob::encodings::{simplearchive::SimpleArchive, UnknownBlob};
use triblespace::core::blob::{Blob, IntoBlob, TryFromBlob};
use triblespace::core::collection::exact_derived::{
    ExactAlgebraError, ExactCover, ExactDerivedAlgebra, ExactDerivedCollection,
};
use triblespace::core::collection::exact_target_compaction::compact_exact_target;
use triblespace::core::collection::reach;
use triblespace::core::collection::succinctarchive_union::SuccinctArchiveCollection;
use triblespace::core::collection::{
    descriptor as descriptor_facts, simplearchive_union, Collection, CollectionCommit,
    CollectionData,
};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{
    ArtifactOfferStore, BlobStore, BlobStoreGet, BlobStorePut, OfferCapture,
};
use triblespace::prelude::blobencodings::{RawBytes, UTF8String};
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval, U256BE};
use triblespace::prelude::*;
use triblespace_search::portable_bm25::{PortableBM25Blob, PortableBM25Index};
use triblespace_search::tokens::{hash_tokens, WordHash};

use crate::archive_bm25;
use crate::blockdag::{self, CatalogValidation};
use crate::schemas::{blockdag as schema, files as files_schema};
use crate::storage::{load_signer, open_pile_strict};

use crate::legacy_hint::open_scope;
#[cfg(test)]
use triblespace::core::blob::encodings::succinctarchive::SuccinctArchiveBlob;
#[cfg(test)]
use triblespace::core::collection::{
    succinctarchive_union, CollectionDerive, CollectionRecord, CollectionStore,
};
#[cfg(test)]
use triblespace::core::repo::BlobStoreMeta;

type TextHandle = Inline<Handle<UTF8String>>;
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
    /// Exact recovered body selected by this occurrence of an external fact.
    /// The fact may accumulate other resolution evidence later without making
    /// this part ambiguous.
    pub resolution: Option<RawHandle>,
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

/// One canonical semantic block together with every exact source receipt that
/// projects to it.
///
/// `semantic` is the receipt with the lowest intrinsic id. All receipts for a
/// block carry the same semantic block value; choosing one canonically avoids
/// manufacturing an import-order-dependent representative while `receipts`
/// preserves the complete occurrence evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveBlock {
    pub semantic: ArchiveProjection,
    pub receipts: Vec<ArchiveProjection>,
}

impl ArchiveBlock {
    /// Whether this block contains at least one part of `modality`.
    pub fn has_modality(&self, modality: Id) -> bool {
        self.semantic
            .parts
            .iter()
            .any(|part| part.modality == modality)
    }

    /// Timestamp used to place this block in the interleaved Archive view.
    ///
    /// A canonical semantic timestamp wins. Otherwise the earliest genuine
    /// source-receipt timestamp supplies the position; an untimed block remains
    /// absent from the temporal view.
    pub fn timeline_timestamp(&self) -> Result<Option<Inline<NsTAIInterval>>> {
        if let Some(timestamp) = self.semantic.block_timestamp {
            return Ok(Some(timestamp));
        }
        let mut earliest = None;
        for receipt in &self.receipts {
            let Some(timestamp) = receipt.source_timestamp else {
                continue;
            };
            let key = interval_lower_key(timestamp)?;
            if earliest.is_none_or(|(earliest_key, _)| key < earliest_key) {
                earliest = Some((key, timestamp));
            }
        }
        Ok(earliest.map(|(_, timestamp)| timestamp))
    }
}

/// Exact position from which to continue Archive's interleaved temporal view.
///
/// A time boundary is useful only to begin a replay. Once a block has been
/// emitted, its content identity is the cursor: unlike a bare timestamp it
/// distinguishes every member of an equal-time run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveTimelineCursor {
    AfterTime(i128),
    AfterBlock(Id),
}

/// One canonical block positioned in Archive's interleaved temporal view.
///
/// `position` is the lower TAI-nanosecond bound of the block's canonical or
/// earliest source timestamp, lifted to at least the position of every causal
/// predecessor. It therefore remains monotone even when a source clock moves
/// backwards. Independent ready roots are still interleaved by their temporal
/// positions, with canonical block id as the deterministic tie-breaker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveTimelineBlock {
    pub position: i128,
    pub block: ArchiveBlock,
}

impl ArchiveTimelineBlock {
    pub const fn cursor(&self) -> ArchiveTimelineCursor {
        ArchiveTimelineCursor::AfterBlock(self.block.semantic.block)
    }
}

/// One ordered content-addressed range in an exact source snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveSourceChunk {
    pub id: Id,
    pub offset: u128,
    pub bytes: RawHandle,
}

/// One exact source-file version retained independently of semantic messages.
///
/// Chunks stay lightweight until explicitly read, so listing a 100+ GiB
/// archive never hashes or maps all source bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveSourceSnapshot {
    pub id: Id,
    pub source_namespace: Id,
    pub source_locator: String,
    pub byte_length: u128,
    pub source_paths: Vec<String>,
    pub chunks: Vec<ArchiveSourceChunk>,
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
    delta: Fragment,
}

impl ArchiveImportWriter {
    pub fn open(pile_path: &std::path::Path, key_path: Option<&std::path::Path>) -> Result<Self> {
        let signer = load_signer(pile_path, key_path)?;
        let pile = open_pile_strict(pile_path)?;
        let mut collection = open_scope(pile, schema::DEFAULT_SCOPE_ID, signer);
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
            Ok(current)
        })();
        match result {
            Ok(current) => {
                let mut writer = Self {
                    collection: Some(collection),
                    current,
                    delta: Fragment::empty(),
                };
                if let Err(error) = writer.stage_fragment(blockdag::vocabulary_fragment()) {
                    let close = writer
                        .collection
                        .take()
                        .expect("new Archive writer owns its collection")
                        .into_storage()
                        .close();
                    return match close {
                        Ok(()) => Err(error),
                        Err(close_error) => Err(error.context(format!(
                            "closing Archive pile after vocabulary staging failed: {close_error}"
                        ))),
                    };
                }
                Ok(writer)
            }
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
        // A Fragment is the independently derivable source unit. A wholly
        // known candidate is an idempotent replay and can be skipped. Once it
        // contributes even one new fact, retain its complete closure in this
        // COMMIT element—including facts already present in older elements.
        // Set union makes that duplication semantically free, while exact
        // homomorphisms (BM25 and future derivatives) can derive every leaf
        // without depending on an implicit merge with historical commits.
        let (_, facts, metafacts, blobs) = fragment.into_parts();
        let novel = facts
            .difference(&self.current)
            .difference(self.delta.facts());
        if novel.is_empty() {
            return Ok(());
        }

        // Embedded payloads can dominate an import's resident memory. Prove
        // their content identities before touching the pile, then append them
        // immediately as content-addressed dependencies. Each streamed batch
        // is captured and offered after every put succeeds; this keeps payload
        // bytes out of the long-lived Fragment without letting direct puts
        // escape the publication protocol. They remain semantically
        // unreachable until the one signed COMMIT written by `finish` because
        // OFFER grants neither authority nor retention.
        let embedded = validated_embedded_blobs(blobs)?;
        let pile = self
            .collection
            .as_mut()
            .expect("Archive writer remains open while staging")
            .storage_mut();
        stage_embedded_blobs(pile, embedded)?;

        // Only the lightweight logical delta remains resident between source
        // fragments. Data and metadata archives are constructed once at the
        // final publication boundary.
        self.delta += Fragment::from_parts(facts, metafacts, Default::default());
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
            // `PileReader` snapshots are immutable. Open this view only after
            // every staged blob append so catalog validation sees those
            // dependencies without retaining them in the Fragment overlay.
            let reader = self
                .collection
                .as_mut()
                .expect("Archive writer remains open until finish")
                .storage_mut()
                .reader()
                .context("open staged Archive dependency reader")?;
            let (_, validation) =
                blockdag::validate_catalog_union(&reader, &self.current, &self.delta)
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

/// Write one validated streaming payload batch behind an OFFER gate.
///
/// The capture is deliberately scoped to one source fragment. A failed put or
/// offer abandons only this batch; replaying the fragment repeats the same
/// content-addressed puts and canonical grow-only offer set. The later signed
/// collection commit owns its own capture for descriptor, data, and metadata.
fn stage_embedded_blobs<S>(store: &mut S, embedded: Vec<Blob<UnknownBlob>>) -> Result<()>
where
    S: BlobStorePut + ArtifactOfferStore,
{
    let mut capture = OfferCapture::new(store);
    for blob in embedded {
        capture
            .put::<UnknownBlob, _>(blob)
            .context("stage Archive embedded blob")?;
    }
    capture
        .offer_pending()
        .context("offer staged Archive embedded blobs")
}

/// Recompute and verify every identity carried by a Fragment blob store.
///
/// `MemoryBlobStore` normally receives only safely constructed `Blob`s, but
/// its low-level reconstruction APIs can represent a forged PATCH key and
/// `Blob::with_handle` can represent a forged cached handle. Facts may name
/// either value, so silently normalizing one would publish dangling or
/// misdirected references. Match the collection publication boundary's strict
/// rule: store key, cached handle, and Blake3(bytes) must all agree.
fn validated_embedded_blobs(
    mut blobs: triblespace::core::blob::MemoryBlobStore,
) -> Result<Vec<Blob<UnknownBlob>>> {
    let reader = blobs
        .reader()
        .expect("MemoryBlobStore reader creation is infallible");
    let mut embedded: Vec<_> = reader.iter().collect();
    embedded.sort_unstable_by_key(|(store_key, _)| store_key.raw);

    embedded
        .into_iter()
        .map(|(store_key, blob)| {
            let cached_handle = blob.get_handle();
            let normalized = Blob::<UnknownBlob>::new(blob.bytes.clone());
            let actual = normalized.get_handle();
            if store_key != actual || cached_handle != actual {
                bail!(
                    "embedded blob store key {} and cached handle {} do not both match byte identity {}",
                    hex::encode_upper(store_key.raw),
                    hex::encode_upper(cached_handle.raw),
                    hex::encode_upper(actual.raw),
                );
            }
            Ok(normalized)
        })
        .collect()
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
        let namespace = collection_namespace(&collection)?;
        let archive = ArchiveSnapshot::from_collection(&mut collection, schema::DEFAULT_SCOPE_ID)?;
        // Two reaches: the archive root's, taken from the one registry that
        // decides it, and this derived index's own. A derivation does not
        // inherit its source's reach -- an index over private material still
        // describes that material -- so the index states its own, and states
        // it privately.
        let algebra = SuccinctArchiveCollection::new(
            crate::collection_names::require_name(schema::DEFAULT_SCOPE_ID),
            namespace,
            None,
            crate::collection_names::require_reach(schema::DEFAULT_SCOPE_ID),
            None,
            reach::private(),
        );
        let source = algebra.source_descriptor();
        let target = algebra.descriptor();
        let exact = ExactDerivedCollection::new(source, target);
        let source_elements = distinct_ticket_data(archive.commits()).len();
        exact
            .ensure_exact(collection.storage_mut(), archive.commits(), &algebra)
            .context("ensure exact Archive raw-Succinct cover")?;

        Ok(SuccinctIndexReport {
            source_commits: archive.commits().len(),
            source_elements,
            source_collection: exact.source_collection(),
            target_collection: exact.target_collection(),
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
    cover: ExactCover<PortableBM25Blob>,
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
        let namespace = collection_namespace(&collection)?;
        let archive = ArchiveSnapshot::from_collection(&mut collection, schema::DEFAULT_SCOPE_ID)?;
        Ok(ensure_bm25_for_snapshot(collection.storage_mut(), &archive, namespace)?.report)
    })();
    close_collection(
        collection,
        result,
        "closing Archive pile after BM25 derivation",
    )
}

/// The namespace an already-open collection belongs to.
///
/// Read back off the descriptor the collection was constructed with rather than
/// threaded in again beside it: the namespace is a property of the collection
/// already opened, and a second copy travelling alongside is a second thing
/// that can disagree with it.
fn collection_namespace(collection: &Collection<Pile>) -> Result<ed25519_dalek::VerifyingKey> {
    descriptor_facts::namespace(collection.descriptor().facts())
        .context("an Archive root descriptor names its namespace")?
        .context("decode the namespace on the Archive root descriptor")
}

fn ensure_bm25_for_snapshot(
    pile: &mut Pile,
    archive: &ArchiveSnapshot,
    namespace: ed25519_dalek::VerifyingKey,
) -> Result<EnsuredBm25> {
    let source = crate::collection_names::root_descriptor(schema::DEFAULT_SCOPE_ID, namespace);
    let target = archive_bm25::descriptor(namespace);
    let exact = ExactDerivedCollection::new(source.clone(), target.clone());
    let algebra = ArchiveBm25Algebra {
        namespace,
        reader: pile
            .reader()
            .context("open Archive BM25 attachment reader")?,
    };
    let source_elements = distinct_ticket_data(archive.commits()).len();
    let cover = compact_exact_target(&exact, pile, archive.commits(), &algebra)
        .context("ensure and compact exact Archive BM25 cover")?;
    Ok(EnsuredBm25 {
        report: Bm25IndexReport {
            source_commits: archive.commits().len(),
            source_elements,
            cover_segments: cover.len(),
            source_collection: exact.source_collection(),
            target_collection: exact.target_collection(),
        },
        cover,
    })
}

/// Archive's one attachment-aware exact homomorphism.
///
/// The reader freezes payload residency for the whole ensure/compaction call.
/// Every failure is fatal: portable BM25 has no representation-capacity
/// fallback, and an absent selected payload requires a later retry with a new
/// reader rather than a different physical cover.
struct ArchiveBm25Algebra {
    reader: PileReader,
    /// Namespace whose collections this algebra accepts, so validation
    /// compares against the exact descriptors this pile addresses.
    namespace: ed25519_dalek::VerifyingKey,
}

fn fatal_bm25(error: impl std::fmt::Display) -> ExactAlgebraError {
    ExactAlgebraError::Fatal(error.to_string())
}

impl ExactDerivedAlgebra<SimpleArchive, PortableBM25Blob> for ArchiveBm25Algebra {
    fn validate_source(
        &self,
        descriptor: &Fragment,
        source: &Blob<SimpleArchive>,
    ) -> std::result::Result<(), ExactAlgebraError> {
        if descriptor.facts()
            != crate::collection_names::root_descriptor(schema::DEFAULT_SCOPE_ID, self.namespace)
                .facts()
        {
            return Err(ExactAlgebraError::Fatal(
                "source descriptor does not match the Archive collection".to_owned(),
            ));
        }
        simplearchive_union::validate_element(source).map_err(fatal_bm25)
    }

    fn validate_target(
        &self,
        descriptor: &Fragment,
        target: &Blob<PortableBM25Blob>,
    ) -> std::result::Result<(), ExactAlgebraError> {
        if descriptor.facts() != archive_bm25::descriptor(self.namespace).facts() {
            return Err(ExactAlgebraError::Fatal(
                "target descriptor does not match the Archive BM25 recipe".to_owned(),
            ));
        }
        ArchiveBm25::try_from_blob(target.clone())
            .map(|_| ())
            .map_err(fatal_bm25)
    }

    fn join_source(
        &self,
        low: &Blob<SimpleArchive>,
        high: &Blob<SimpleArchive>,
    ) -> std::result::Result<Blob<SimpleArchive>, ExactAlgebraError> {
        simplearchive_union::join(low, high).map_err(fatal_bm25)
    }

    fn derive(
        &self,
        source: &Blob<SimpleArchive>,
    ) -> std::result::Result<Blob<PortableBM25Blob>, ExactAlgebraError> {
        archive_bm25::derive_element(&self.reader, source.clone())
            .map_err(|error| ExactAlgebraError::Fatal(format!("{error:#}")))
    }

    fn join_target(
        &self,
        low: &Blob<PortableBM25Blob>,
        high: &Blob<PortableBM25Blob>,
    ) -> std::result::Result<Blob<PortableBM25Blob>, ExactAlgebraError> {
        let low = ArchiveBm25::try_from_blob(low.clone()).map_err(fatal_bm25)?;
        let high = ArchiveBm25::try_from_blob(high.clone()).map_err(fatal_bm25)?;
        low.merged(&high)
            .map(|index| index.to_blob())
            .map_err(fatal_bm25)
    }
}

fn distinct_ticket_data(commits: &[CollectionCommit]) -> BTreeSet<CollectionData> {
    commits.iter().map(CollectionCommit::data).collect()
}

fn interval_lower_key(interval: Inline<NsTAIInterval>) -> Result<i128> {
    let (lower, _upper): (i128, i128) = interval
        .try_from_inline()
        .map_err(|error| anyhow!("decode Archive timestamp: {error:?}"))?;
    Ok(lower)
}

/// One frozen Archive view and one resident portable BM25 index attached from
/// the exact cover of the same admitted source commits.
pub struct ArchiveSearchSnapshot {
    archive: ArchiveSnapshot,
    index: ArchiveBm25,
}

impl ArchiveSearchSnapshot {
    pub fn ensure_local(
        pile_path: &std::path::Path,
        key_path: Option<&std::path::Path>,
    ) -> Result<Self> {
        let mut collection =
            ArchiveSnapshot::open_collection(pile_path, key_path, schema::DEFAULT_SCOPE_ID)?;
        let result = (|| {
            let namespace = collection_namespace(&collection)?;
            let archive =
                ArchiveSnapshot::from_collection(&mut collection, schema::DEFAULT_SCOPE_ID)?;
            let ensured = ensure_bm25_for_snapshot(collection.storage_mut(), &archive, namespace)?;
            let mut segments = Vec::with_capacity(ensured.cover.len());
            for (data, blob) in ensured.cover.into_members() {
                segments.push(ArchiveBm25::try_from_blob(blob).with_context(|| {
                    format!(
                        "attach Archive BM25 segment {}",
                        hex::encode_upper(data.raw)
                    )
                })?);
            }
            let index = match segments.len() {
                0 => ArchiveBm25::merge(std::iter::empty::<&ArchiveBm25>())
                    .context("construct the empty Archive BM25 resident view")?,
                1 => segments.pop().expect("one attached Archive BM25 element"),
                _ => ArchiveBm25::merge(segments.iter())
                    .context("join exact Archive BM25 cover for resident search")?,
            };
            Ok(Self { archive, index })
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

    pub fn search(&self, text: &str, limit: usize) -> Result<Vec<ArchiveSearchHit>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let ranked = self.index.query_multi(&hash_tokens(text));
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

/// One immutable materialized Archive view from the local durable collection.
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
        Ok(open_scope(pile, scope, signer))
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

    /// Every queryable display-name variant attached to an entity.
    ///
    /// Archive metadata is additive, so this deliberately preserves several
    /// names instead of manufacturing a last-writer-wins label.
    pub fn names(&self, id: Id) -> Result<Vec<String>> {
        let handles: BTreeSet<_> = find!(
            value: TextHandle,
            pattern!(&self.facts, [{ id @ metadata::name: ?value }])
        )
        .collect();
        handles
            .into_iter()
            .map(|handle| self.read_text(handle))
            .collect::<Result<BTreeSet<_>>>()
            .map(|names| names.into_iter().collect())
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

    /// Canonical exact-source snapshot ids in byte order.
    pub fn source_snapshot_ids(&self) -> Vec<Id> {
        let mut ids: Vec<_> = find!(
            snapshot: Id,
            pattern!(&self.facts, [{
                ?snapshot @ metadata::tag: &schema::source_snapshot::KIND
            }])
        )
        .collect();
        ids.sort_unstable();
        ids
    }

    /// Resolve an exact-source snapshot from a hexadecimal id prefix.
    pub fn resolve_source_snapshot_prefix(&self, prefix: &str) -> Result<Id> {
        let prefix = prefix.trim();
        if prefix.is_empty()
            || prefix.len() > 32
            || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("Archive source-snapshot prefix must contain 1..=32 hexadecimal digits");
        }
        let prefix = prefix.to_ascii_uppercase();
        let mut matches = self
            .source_snapshot_ids()
            .into_iter()
            .filter(|id| format!("{id:X}").starts_with(&prefix));
        let first = matches
            .next()
            .ok_or_else(|| anyhow!("no Archive source snapshot matches {prefix}"))?;
        if matches.next().is_some() {
            bail!("Archive source-snapshot prefix {prefix} is ambiguous");
        }
        Ok(first)
    }

    /// Load exact-source metadata and ordered lightweight chunk handles.
    pub fn source_snapshot(&self, id: Id) -> Result<ArchiveSourceSnapshot> {
        if !exists!(pattern!(&self.facts, [{
            id @ metadata::tag: &schema::source_snapshot::KIND
        }])) {
            bail!("Archive entity {id:X} is not a source snapshot");
        }
        let source_namespace = required_one(
            find!(
                value: Id,
                pattern!(&self.facts, [{
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
                pattern!(&self.facts, [{
                    id @ schema::source_projection::source_locator: ?value
                }])
            )
            .collect(),
            id,
            "source locator",
        )?;
        let byte_length = required_one(
            find!(
                value: Inline<U256BE>,
                pattern!(&self.facts, [{
                    id @ schema::source_snapshot::byte_length: ?value
                }])
            )
            .collect(),
            id,
            "source snapshot byte length",
        )?;
        let byte_length = u128::try_from_inline(&byte_length).map_err(|error| {
            anyhow!("Archive source snapshot {id:X} length does not fit u128: {error:?}")
        })?;

        let mut chunks = Vec::new();
        let chunk_ids: BTreeSet<_> = find!(
            chunk: Id,
            pattern!(&self.facts, [{
                id @ schema::source_snapshot::contains: ?chunk
            }])
        )
        .collect();
        for chunk in chunk_ids {
            let offset = required_one(
                find!(
                    value: Inline<U256BE>,
                    pattern!(&self.facts, [{
                        chunk @ schema::source_chunk::offset: ?value
                    }])
                )
                .collect(),
                chunk,
                "source chunk offset",
            )?;
            let offset = u128::try_from_inline(&offset).map_err(|error| {
                anyhow!("Archive source chunk {chunk:X} offset does not fit u128: {error:?}")
            })?;
            let bytes = required_one(
                find!(
                    value: RawHandle,
                    pattern!(&self.facts, [{
                        chunk @ schema::source_chunk::bytes: ?value
                    }])
                )
                .collect(),
                chunk,
                "source chunk bytes",
            )?;
            chunks.push(ArchiveSourceChunk {
                id: chunk,
                offset,
                bytes,
            });
        }
        chunks.sort_by_key(|chunk| (chunk.offset, chunk.id));

        let path_handles: BTreeSet<_> = find!(
            value: TextHandle,
            pattern!(&self.facts, [{ id @ files_schema::file::source_path: ?value }])
        )
        .collect();
        let source_paths = path_handles
            .into_iter()
            .map(|handle| self.read_text(handle))
            .collect::<Result<BTreeSet<_>>>()?
            .into_iter()
            .collect();

        Ok(ArchiveSourceSnapshot {
            id,
            source_namespace,
            source_locator,
            byte_length,
            source_paths,
            chunks,
        })
    }

    /// Retrieve and hash-validate one source chunk on demand.
    pub fn source_chunk_bytes(&self, chunk: &ArchiveSourceChunk) -> Result<Bytes> {
        self.reader
            .get(chunk.bytes)
            .with_context(|| format!("read Archive source chunk {:X}", chunk.id))
    }

    /// Stream one exact source snapshot without assembling it in memory.
    pub fn write_source_snapshot<W: std::io::Write>(
        &self,
        id: Id,
        destination: &mut W,
    ) -> Result<u128> {
        let snapshot = self.source_snapshot(id)?;
        let mut written = 0u128;
        for chunk in &snapshot.chunks {
            if chunk.offset != written {
                bail!(
                    "Archive source snapshot {id:X} chunk {:X} begins at {}, expected {written}",
                    chunk.id,
                    chunk.offset
                );
            }
            let bytes = self.source_chunk_bytes(chunk)?;
            destination
                .write_all(bytes.as_ref())
                .with_context(|| format!("write Archive source snapshot {id:X}"))?;
            written = written
                .checked_add(bytes.len() as u128)
                .ok_or_else(|| anyhow!("Archive source snapshot {id:X} length overflows u128"))?;
        }
        if written != snapshot.byte_length {
            bail!(
                "Archive source snapshot {id:X} yielded {written} bytes, expected {}",
                snapshot.byte_length
            );
        }
        Ok(written)
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

    /// Load one canonical semantic block and every exact source receipt that
    /// witnesses it.
    pub fn block(&self, block: Id) -> Result<ArchiveBlock> {
        let receipt_ids = self.projections_for_block(block);
        if receipt_ids.is_empty() {
            bail!("canonical Archive block {block:X} has no source projection");
        }
        let mut receipts = receipt_ids
            .into_iter()
            .map(|id| self.projection(id))
            .collect::<Result<Vec<_>>>()?;
        receipts.sort_unstable_by_key(|projection| projection.id);
        if receipts.iter().any(|projection| projection.block != block) {
            bail!("Archive source projection lookup crossed block identities");
        }
        Ok(ArchiveBlock {
            semantic: receipts[0].clone(),
            receipts,
        })
    }

    /// Replay canonical blocks after one exact cursor as a pure, deterministic
    /// causal-temporal view.
    ///
    /// The caller supplies the inclusion policy. This deliberately does not
    /// encode the Archive CLI's dialogue-only default: a human reader may want
    /// to hide tool-only blocks, while a mind reconstructing its own causal
    /// history must include them. Cursor ownership and mutation likewise live
    /// above this pure view.
    pub fn timeline_after<F>(
        &self,
        cursor: ArchiveTimelineCursor,
        mut include: F,
    ) -> Result<Vec<ArchiveTimelineBlock>>
    where
        F: FnMut(&ArchiveBlock) -> bool,
    {
        let catalog = &self.facts;
        let blocks: BTreeSet<Id> = find!(
            block: Id,
            pattern!(catalog, [{
                _?projection @ schema::source_projection::projects_to: ?block
            }])
        )
        .collect();
        let canonical_timestamps: BTreeMap<Id, Inline<NsTAIInterval>> = find!(
            (block: Id, timestamp: Inline<NsTAIInterval>),
            pattern!(catalog, [{ ?block @ schema::block::timestamp: ?timestamp }])
        )
        .collect();
        let mut earliest_receipt_timestamps = BTreeMap::<Id, (i128, Inline<NsTAIInterval>)>::new();
        for (block, timestamp) in find!(
            (block: Id, timestamp: Inline<NsTAIInterval>),
            pattern!(catalog, [
                { _?projection @ schema::source_projection::projects_to: ?block },
                { _?projection @ schema::source_projection::source_timestamp: ?timestamp },
            ])
        ) {
            let key = interval_lower_key(timestamp)?;
            let entry = earliest_receipt_timestamps
                .entry(block)
                .or_insert((key, timestamp));
            if key < entry.0 {
                *entry = (key, timestamp);
            }
        }

        let mut timestamps = BTreeMap::<Id, Option<i128>>::new();
        let mut predecessors = BTreeMap::<Id, BTreeSet<Id>>::new();
        let mut successors = BTreeMap::<Id, BTreeSet<Id>>::new();
        for block_id in &blocks {
            let timestamp = canonical_timestamps.get(block_id).copied().or_else(|| {
                earliest_receipt_timestamps
                    .get(block_id)
                    .map(|(_, timestamp)| *timestamp)
            });
            timestamps.insert(*block_id, timestamp.map(interval_lower_key).transpose()?);

            let previous: BTreeSet<_> = find!(
                predecessor: Id,
                pattern!(catalog, [{ block_id @ schema::block::previous: ?predecessor }])
            )
            .collect();
            for predecessor in &previous {
                successors
                    .entry(*predecessor)
                    .or_default()
                    .insert(*block_id);
            }
            predecessors.insert(*block_id, previous);
        }

        // Kahn's algorithm makes causality authoritative and time merely the
        // priority among blocks which are already ready. Untimed blocks are
        // contracted eagerly: they emit nothing, but carry their ancestors'
        // lifted position into timed descendants.
        let mut remaining: BTreeMap<Id, usize> = predecessors
            .iter()
            .map(|(block, previous)| (*block, previous.len()))
            .collect();
        let mut inherited = BTreeMap::<Id, Option<i128>>::new();
        let mut ready_untimed = BTreeSet::<Id>::new();
        let mut ready_timed = BTreeSet::<(i128, Id)>::new();
        for block in &blocks {
            inherited.insert(*block, None);
            if remaining[block] == 0 {
                match timestamps[block] {
                    Some(position) => {
                        ready_timed.insert((position, *block));
                    }
                    None => {
                        ready_untimed.insert(*block);
                    }
                }
            }
        }

        let mut positioned = Vec::<(i128, Id)>::new();
        let mut visited = 0usize;
        while visited < blocks.len() {
            let (block, position, emits) = if let Some(block) = ready_untimed.pop_first() {
                (block, inherited[&block], false)
            } else if let Some((position, block)) = ready_timed.pop_first() {
                (block, Some(position), true)
            } else {
                bail!("canonical Archive block graph became cyclic while building its timeline");
            };
            visited += 1;
            if let Some(position) = position.filter(|_| emits) {
                positioned.push((position, block));
            }

            for successor in successors.get(&block).into_iter().flatten() {
                if let Some(position) = position {
                    let inherited = inherited
                        .get_mut(successor)
                        .expect("every successor belongs to the canonical block set");
                    *inherited = Some(inherited.map_or(position, |current| current.max(position)));
                }
                let count = remaining
                    .get_mut(successor)
                    .expect("every successor has a dependency count");
                *count -= 1;
                if *count == 0 {
                    let inherited = inherited[successor];
                    match timestamps[successor] {
                        Some(timestamp) => {
                            ready_timed.insert((
                                inherited.map_or(timestamp, |value| value.max(timestamp)),
                                *successor,
                            ));
                        }
                        None => {
                            ready_untimed.insert(*successor);
                        }
                    }
                }
            }
        }

        let start = match cursor {
            ArchiveTimelineCursor::AfterTime(position) => {
                positioned.partition_point(|(candidate, _)| *candidate <= position)
            }
            ArchiveTimelineCursor::AfterBlock(anchor) => positioned
                .iter()
                .position(|(_, block)| *block == anchor)
                .map(|index| index + 1)
                .ok_or_else(|| {
                    anyhow!(
                        "Archive timeline cursor block {anchor:X} is absent or has no timestamp"
                    )
                })?,
        };

        let mut timeline = Vec::new();
        for (position, block_id) in positioned.into_iter().skip(start) {
            let block = self.block(block_id)?;
            if include(&block) {
                timeline.push(ArchiveTimelineBlock { position, block });
            }
        }
        Ok(timeline)
    }

    /// Most recent source receipts by exact source time, falling back to the
    /// canonical block time for sources which carry time semantically.
    ///
    /// Untimed blocks sort after genuinely timed blocks. Ties use the source
    /// projection id, making the result independent of collection commit order.
    pub fn recent_projection_ids(&self, limit: usize) -> Vec<Id> {
        if limit == 0 {
            return Vec::new();
        }
        let mut rows: Vec<(Id, Option<i128>)> =
            self.projection_ids()
                .into_iter()
                .map(|projection| {
                    let source_timestamp = find!(
                        value: Inline<NsTAIInterval>,
                        pattern!(&self.facts, [{
                            projection @ schema::source_projection::source_timestamp: ?value
                        }])
                    )
                    .next();
                    let timestamp = source_timestamp
                        .or_else(|| {
                            find!(
                    value: Inline<NsTAIInterval>,
                    pattern!(&self.facts, [
                        { projection @ schema::source_projection::projects_to: _?block },
                        { _?block @ schema::block::timestamp: ?value },
                    ])
                ).next()
                        })
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
            let resolution = optional_one(
                find!(
                    value: RawHandle,
                    pattern!(catalog, [{
                        part @ schema::content_part::resolution: ?value
                    }])
                )
                .collect(),
                part,
                "resolution",
            )?;
            let payload = self.payload(catalog, fact)?;
            Ok(ArchivePart {
                id: part,
                ordinal,
                fact,
                responds_to,
                resolution,
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
    use std::convert::Infallible;
    use std::error::Error;
    use std::fmt;

    use triblespace::core::collection::records::CollectionHandle;
    use triblespace::core::repo::{ArtifactHandle, ArtifactOfferSnapshot};

    /// Historical namespace of the open-admission Archive fixture.
    fn test_namespace(
        pile: &std::path::Path,
        key: &std::path::Path,
    ) -> ed25519_dalek::VerifyingKey {
        load_signer(pile, Some(key)).unwrap().verifying_key()
    }

    /// The Archive root these fixtures commit into.
    fn test_source(pile: &std::path::Path, key: &std::path::Path) -> Fragment {
        crate::collection_names::root_descriptor(
            schema::DEFAULT_SCOPE_ID,
            test_namespace(pile, key),
        )
    }

    /// The derived BM25 collection over that root.
    fn test_target(pile: &std::path::Path, key: &std::path::Path) -> Fragment {
        archive_bm25::descriptor(test_namespace(pile, key))
    }

    /// Content identity of a descriptor these tests built but have not stored.
    fn collection_of(descriptor: &Fragment) -> CollectionHandle {
        triblespace::core::blob::IntoBlob::<SimpleArchive>::to_blob(descriptor.facts().clone())
            .get_handle()
    }

    /// Initialize the durable signer used by the open-admission Archive fixture.
    fn initialize_archive_fixture(pile: &std::path::Path, key: &std::path::Path) -> SigningKey {
        initialize_signer(pile, Some(key)).unwrap()
    }

    use super::*;
    use crate::storage::initialize_signer;
    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
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

    fn projection_at(locator: &str, text: &str, unix_seconds: f64) -> Fragment {
        projection_at_modality(
            locator,
            schema::content_fact::modality::TEXT,
            text,
            unix_seconds,
        )
    }

    fn projection_at_modality(
        locator: &str,
        modality: Id,
        text: &str,
        unix_seconds: f64,
    ) -> Fragment {
        let fact =
            blockdag::text_fact(modality, schema::content_fact::direction::IN, text).unwrap();
        let part = blockdag::content_part(0, fact, None).unwrap();
        let epoch = Epoch::from_unix_seconds(unix_seconds);
        let timestamp: Inline<NsTAIInterval> =
            (epoch, epoch).try_to_inline().expect("valid test interval");
        let block = blockdag::block([], Some(timestamp), part).unwrap();
        blockdag::source_projection(
            schema::source_projection::SOURCE_CLAUDE_CODE,
            locator,
            format!("{{\"text\":{text:?}}}").into_bytes(),
            block,
        )
        .unwrap()
    }

    fn projection_after_at(
        locator: &str,
        text: &str,
        unix_seconds: Option<f64>,
        predecessors: &[Id],
    ) -> (Fragment, Id) {
        let fact = blockdag::text_fact(
            schema::content_fact::modality::TEXT,
            schema::content_fact::direction::IN,
            text,
        )
        .unwrap();
        let part = blockdag::content_part(0, fact, None).unwrap();
        let timestamp = unix_seconds.map(|seconds| {
            let epoch = Epoch::from_unix_seconds(seconds);
            (epoch, epoch).try_to_inline().expect("valid test interval")
        });
        let block = blockdag::block(predecessors.iter().copied(), timestamp, part).unwrap();
        let block_id = block.root().unwrap();
        let projection = blockdag::source_projection(
            schema::source_projection::SOURCE_CLAUDE_CODE,
            locator,
            format!("{{\"text\":{text:?}}}").into_bytes(),
            block,
        )
        .unwrap();
        (projection, block_id)
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

    fn first_embedded_handle(fragment: &Fragment) -> Inline<Handle<UnknownBlob>> {
        let mut blobs = fragment.blobs().clone();
        blobs
            .reader()
            .unwrap()
            .iter()
            .next()
            .expect("fixture carries embedded blobs")
            .0
    }

    #[test]
    fn staged_blobs_leave_the_delta_and_remain_semantically_invisible_until_finish() {
        let directory = TempDir::new().unwrap();
        let pile = directory.path().join("archive.pile");
        std::fs::File::create(&pile).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile, &key);

        let fragment = projection("session:staged", "resident only after commit");
        let embedded = first_embedded_handle(&fragment);
        let mut writer = ArchiveImportWriter::open(&pile, Some(&key)).unwrap();
        writer.stage_fragment(fragment).unwrap();

        assert!(writer.delta_len() > 0);
        assert!(
            writer.delta.blobs().is_empty(),
            "the long-lived logical delta must not retain embedded bytes"
        );

        // The payload is already durable enough to satisfy a fresh reader,
        // and its local willingness-to-serve marker is durable, but no signed
        // collection root makes its facts visible yet.
        let mut physical = open_pile_strict(&pile).unwrap();
        assert!(physical.offers_snapshot().unwrap().contains(embedded));
        let reader = physical.reader().unwrap();
        let _: Blob<UnknownBlob> = reader.get(embedded).unwrap();
        drop(reader);
        physical.close().unwrap();
        let before =
            ArchiveSnapshot::load_local(&pile, Some(&key), schema::DEFAULT_SCOPE_ID).unwrap();
        assert!(before.commits().is_empty());
        assert!(before.catalog().is_empty());
        drop(before);

        let commit = writer.finish(Ok(())).unwrap().1.unwrap();
        let after =
            ArchiveSnapshot::load_local(&pile, Some(&key), schema::DEFAULT_SCOPE_ID).unwrap();
        assert_eq!(after.commits(), &[commit]);
        assert_eq!(after.projection_ids().len(), 1);
    }

    #[test]
    fn rejected_staged_union_closes_without_publishing_a_collection_commit() {
        let directory = TempDir::new().unwrap();
        let pile = directory.path().join("archive.pile");
        std::fs::File::create(&pile).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile, &key);

        let invalid_id = Id::new([0x42; 16]).unwrap();
        let mut invalid = entity! { ExclusiveId::force_ref(&invalid_id) @
            metadata::tag: &schema::source_projection::KIND,
        };
        let embedded = invalid.put::<RawBytes, _>(b"unreachable after rejection".to_vec());
        let embedded: Inline<Handle<UnknownBlob>> = embedded.transmute();

        let mut writer = ArchiveImportWriter::open(&pile, Some(&key)).unwrap();
        writer.stage_fragment(invalid).unwrap();
        let error = writer.finish(Ok(())).unwrap_err();
        assert!(error
            .to_string()
            .contains("staged Archive union is invalid"));

        // `finish` closed the writer even on validation failure. Reopening is
        // sound, no semantic edge escaped, and the dependency is merely an
        // unreachable content-addressed record available for later GC.
        let snapshot =
            ArchiveSnapshot::load_local(&pile, Some(&key), schema::DEFAULT_SCOPE_ID).unwrap();
        assert!(snapshot.commits().is_empty());
        assert!(snapshot.catalog().is_empty());
        drop(snapshot);
        let mut physical = open_pile_strict(&pile).unwrap();
        assert!(
            physical.offers_snapshot().unwrap().contains(embedded),
            "an orphan OFFER is lawful: it grants neither authority nor retention"
        );
        let reader = physical.reader().unwrap();
        let _: Blob<UnknownBlob> = reader.get(embedded).unwrap();
        drop(reader);
        physical.close().unwrap();
    }

    #[test]
    fn staging_rejects_forged_embedded_identity_before_writing() {
        let directory = TempDir::new().unwrap();
        let pile = directory.path().join("archive.pile");
        std::fs::File::create(&pile).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile, &key);

        // Establish the canonical queryable vocabulary so the forged-fragment
        // attempt is the only candidate work in the writer under test.
        ArchiveImportWriter::open(&pile, Some(&key))
            .unwrap()
            .finish(Ok(()))
            .unwrap();

        let id = Id::new([0x43; 16]).unwrap();
        let mut fragment = entity! { ExclusiveId::force_ref(&id) @
            metadata::tag: &schema::source_projection::KIND,
        };
        let bogus = Inline::<Handle<UnknownBlob>>::new([0xAA; 32]);
        let forged = Blob::<UnknownBlob>::with_handle(
            anybytes::Bytes::from_source(b"forged Archive payload".to_vec()),
            bogus,
        );
        fragment.blobs_mut().insert(forged);

        let mut writer = ArchiveImportWriter::open(&pile, Some(&key)).unwrap();
        assert_eq!(writer.delta_len(), 0);
        let before = std::fs::metadata(&pile).unwrap().len();
        let error = writer.stage_fragment(fragment).unwrap_err();
        assert!(error
            .to_string()
            .contains("do not both match byte identity"));
        assert_eq!(writer.delta_len(), 0);
        assert!(writer.delta.blobs().is_empty());
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), before);
        assert_eq!(writer.finish(Ok(())).unwrap().1, None);
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum StageEvent {
        Put(ArtifactHandle),
        Offer(Vec<ArtifactHandle>),
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct StageOfferError;

    impl fmt::Display for StageOfferError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("injected offer failure")
        }
    }

    impl Error for StageOfferError {}

    #[derive(Default)]
    struct StageProbe {
        events: Vec<StageEvent>,
        fail_next_offer: bool,
    }

    impl BlobStorePut for StageProbe {
        type PutError = Infallible;

        fn put<S, T>(&mut self, item: T) -> std::result::Result<Inline<Handle<S>>, Self::PutError>
        where
            S: triblespace::core::blob::BlobEncoding + 'static,
            T: IntoBlob<S>,
            Handle<S>: triblespace::core::inline::InlineEncoding,
        {
            let handle = item.to_blob().get_handle();
            self.events.push(StageEvent::Put(handle.transmute()));
            Ok(handle)
        }
    }

    impl ArtifactOfferStore for StageProbe {
        type OfferError = StageOfferError;

        fn offer_all<I>(&mut self, handles: I) -> std::result::Result<(), Self::OfferError>
        where
            I: IntoIterator<Item = ArtifactHandle>,
        {
            let handles: Vec<_> = handles.into_iter().collect();
            self.events.push(StageEvent::Offer(handles));
            if self.fail_next_offer {
                self.fail_next_offer = false;
                return Err(StageOfferError);
            }
            Ok(())
        }

        fn offers_snapshot(
            &mut self,
        ) -> std::result::Result<ArtifactOfferSnapshot, Self::OfferError> {
            Ok(ArtifactOfferSnapshot::default())
        }
    }

    #[test]
    fn streamed_blob_batch_offers_canonically_and_replays_after_failure() {
        let first = Blob::<UnknownBlob>::new(Bytes::from_source(b"first".to_vec()));
        let second = Blob::<UnknownBlob>::new(Bytes::from_source(b"second".to_vec()));
        let first_handle: ArtifactHandle = first.get_handle();
        let second_handle: ArtifactHandle = second.get_handle();
        let mut offered = vec![first_handle, second_handle];
        offered.sort_unstable();

        let mut probe = StageProbe {
            fail_next_offer: true,
            ..StageProbe::default()
        };
        let error = stage_embedded_blobs(&mut probe, vec![second.clone(), first.clone()])
            .expect_err("the first canonical OFFER batch is injected to fail");
        assert!(format!("{error:#}").contains("injected offer failure"));
        assert_eq!(
            probe.events,
            vec![
                StageEvent::Put(second_handle),
                StageEvent::Put(first_handle),
                StageEvent::Offer(offered.clone()),
            ]
        );

        stage_embedded_blobs(&mut probe, vec![second, first]).unwrap();
        assert_eq!(
            &probe.events[3..],
            &[
                StageEvent::Put(second_handle),
                StageEvent::Put(first_handle),
                StageEvent::Offer(offered),
            ]
        );
    }

    #[test]
    fn import_crosses_one_v4_visibility_edge_and_retries_idempotently() {
        let directory = TempDir::new().unwrap();
        let pile = directory.path().join("archive.pile");
        std::fs::File::create(&pile).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile, &key);

        let fragment = projection("session:one", "one");
        let mut writer = ArchiveImportWriter::open(&pile, Some(&key)).unwrap();
        writer.stage_fragment(fragment.clone()).unwrap();
        let (_, first) = writer.finish(Ok(())).unwrap();
        let first = first.unwrap();
        let length = std::fs::metadata(&pile).unwrap().len();

        let mut retry = ArchiveImportWriter::open(&pile, Some(&key)).unwrap();
        retry.stage_fragment(fragment).unwrap();
        let (_, repeated) = retry.finish(Ok(())).unwrap();
        assert_eq!(repeated, None);
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), length);

        let snapshot =
            ArchiveSnapshot::load_local(&pile, Some(&key), schema::DEFAULT_SCOPE_ID).unwrap();
        assert_eq!(snapshot.commits(), &[first]);
        assert_eq!(snapshot.projection_ids().len(), 1);
    }

    #[test]
    fn exact_source_snapshots_are_listed_lazily_and_stream_reconstructible() {
        let directory = TempDir::new().unwrap();
        let pile = directory.path().join("archive.pile");
        std::fs::File::create(&pile).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile, &key);

        let source = b"opaque telemetry and encrypted reasoning\n";
        let chunks = blockdag::source_chunk(0, Bytes::from_source(source.to_vec())).unwrap();
        let fragment = blockdag::source_snapshot(
            schema::source_projection::SOURCE_CODEX,
            "snapshot/v1/session:exact",
            source.len() as u128,
            chunks,
            Some("/moved/rollout.jsonl".to_owned()),
        )
        .unwrap();
        let expected = fragment.root().unwrap();
        let mut writer = ArchiveImportWriter::open(&pile, Some(&key)).unwrap();
        writer.stage_fragment(fragment).unwrap();
        writer.finish(Ok(())).unwrap();

        let archive =
            ArchiveSnapshot::load_local(&pile, Some(&key), schema::DEFAULT_SCOPE_ID).unwrap();
        assert_eq!(archive.source_snapshot_ids(), vec![expected]);
        assert_eq!(
            archive
                .resolve_source_snapshot_prefix(&format!("{expected:X}")[..8])
                .unwrap(),
            expected
        );
        let snapshot = archive.source_snapshot(expected).unwrap();
        assert_eq!(
            snapshot.source_namespace,
            schema::source_projection::SOURCE_CODEX
        );
        assert_eq!(snapshot.source_locator, "snapshot/v1/session:exact");
        assert_eq!(snapshot.byte_length, source.len() as u128);
        assert_eq!(snapshot.source_paths, vec!["/moved/rollout.jsonl"]);
        assert_eq!(snapshot.chunks.len(), 1);
        assert_eq!(snapshot.chunks[0].offset, 0);

        let mut reconstructed = Vec::new();
        assert_eq!(
            archive
                .write_source_snapshot(expected, &mut reconstructed)
                .unwrap(),
            source.len() as u128
        );
        assert_eq!(reconstructed, source);
    }

    #[test]
    fn growing_source_skips_known_fragments_and_keeps_new_leaf_closure() {
        let directory = TempDir::new().unwrap();
        let pile = directory.path().join("archive.pile");
        std::fs::File::create(&pile).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile, &key);

        let first_fragment = projection("session:one", "shared");
        let first_len = first_fragment.facts().len();
        let mut first_writer = ArchiveImportWriter::open(&pile, Some(&key)).unwrap();
        first_writer.stage_fragment(first_fragment.clone()).unwrap();
        let first = first_writer.finish(Ok(())).unwrap().1.unwrap();

        let second_fragment = projection("session:two", "shared");
        let mut second_writer = ArchiveImportWriter::open(&pile, Some(&key)).unwrap();
        second_writer.stage_fragment(first_fragment).unwrap();
        assert_eq!(second_writer.delta_len(), 0, "known fragment is a replay");
        second_writer
            .stage_fragment(second_fragment.clone())
            .unwrap();
        assert_eq!(
            second_writer.delta_len(),
            second_fragment.facts().len(),
            "a novel source unit retains its reused fact/part/block closure"
        );
        let second = second_writer.finish(Ok(())).unwrap().1.unwrap();
        assert_ne!(first.data(), second.data());

        let snapshot =
            ArchiveSnapshot::load_local(&pile, Some(&key), schema::DEFAULT_SCOPE_ID).unwrap();
        assert_eq!(snapshot.commits().len(), 2);
        assert_eq!(snapshot.projection_ids().len(), 2);
        assert!(snapshot.catalog().len() > first_len);
    }

    #[test]
    fn zero_commit_search_uses_the_canonical_empty_resident_index() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile_path, &key);

        let report = ensure_bm25_index(&pile_path, Some(&key)).unwrap();
        assert_eq!(
            (
                report.source_commits,
                report.source_elements,
                report.cover_segments
            ),
            (0, 0, 0)
        );

        let search = ArchiveSearchSnapshot::ensure_local(&pile_path, Some(&key)).unwrap();
        assert!(search.archive().commits().is_empty());
        assert!(search.search("anything", 10).unwrap().is_empty());
    }

    #[test]
    fn empty_commit_receives_exact_empty_derives_and_keeps_reads_empty() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile_path, &key);

        let signer = load_signer(&pile_path, Some(&key)).unwrap();
        let pile = open_pile_strict(&pile_path).unwrap();
        let mut collection = crate::collection_names::open(pile, schema::DEFAULT_SCOPE_ID, signer);
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
    fn timeline_is_pure_and_leaves_inclusion_policy_to_the_caller() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile_path, &key);

        let mut writer = ArchiveImportWriter::open(&pile_path, Some(&key)).unwrap();
        writer
            .stage_fragment(projection_at_modality(
                "session:text",
                schema::content_fact::modality::TEXT,
                "spoken",
                1.0,
            ))
            .unwrap();
        writer
            .stage_fragment(projection_at_modality(
                "session:tool",
                schema::content_fact::modality::TOOL_CALL,
                "memory context",
                2.0,
            ))
            .unwrap();
        writer.finish(Ok(())).unwrap();

        let snapshot =
            ArchiveSnapshot::load_local(&pile_path, Some(&key), schema::DEFAULT_SCOPE_ID).unwrap();
        let complete = snapshot
            .timeline_after(ArchiveTimelineCursor::AfterTime(i128::MIN), |_| true)
            .unwrap();
        assert_eq!(complete.len(), 2);
        assert!(complete[0].position < complete[1].position);
        assert!(complete[0]
            .block
            .has_modality(schema::content_fact::modality::TEXT));
        assert!(complete[1]
            .block
            .has_modality(schema::content_fact::modality::TOOL_CALL));

        let dialogue = snapshot
            .timeline_after(ArchiveTimelineCursor::AfterTime(i128::MIN), |block| {
                block.has_modality(schema::content_fact::modality::TEXT)
            })
            .unwrap();
        assert_eq!(dialogue.len(), 1);
        assert_eq!(
            dialogue[0].block.semantic.block,
            complete[0].block.semantic.block
        );

        let after_first = snapshot
            .timeline_after(complete[0].cursor(), |_| true)
            .unwrap();
        assert_eq!(after_first.len(), 1);
        assert_eq!(
            after_first[0].block.semantic.block,
            complete[1].block.semantic.block
        );
    }

    #[test]
    fn timeline_cursor_preserves_equal_time_blocks_and_causal_order() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile_path, &key);

        let (parent, parent_id) = projection_after_at("thread/parent", "parent", Some(10.0), &[]);
        let (untimed, untimed_id) =
            projection_after_at("thread/untimed", "untimed", None, &[parent_id]);
        let (regressed_child, child_id) =
            projection_after_at("thread/child", "regressed child", Some(5.0), &[untimed_id]);
        let (independent, independent_id) =
            projection_after_at("other/root", "independent", Some(7.0), &[]);

        let mut writer = ArchiveImportWriter::open(&pile_path, Some(&key)).unwrap();
        // Deliberately stage out of causal and temporal order. The collection
        // is a set; replay order must come solely from canonical semantics.
        writer.stage_fragment(regressed_child).unwrap();
        writer.stage_fragment(independent).unwrap();
        writer.stage_fragment(untimed).unwrap();
        writer.stage_fragment(parent).unwrap();
        writer.finish(Ok(())).unwrap();

        let snapshot =
            ArchiveSnapshot::load_local(&pile_path, Some(&key), schema::DEFAULT_SCOPE_ID).unwrap();
        let timeline = snapshot
            .timeline_after(ArchiveTimelineCursor::AfterTime(i128::MIN), |_| true)
            .unwrap();
        assert_eq!(timeline.len(), 3, "the untimed conduit stays invisible");
        assert_eq!(timeline[0].block.semantic.block, independent_id);
        assert_eq!(timeline[1].block.semantic.block, parent_id);
        assert_eq!(timeline[2].block.semantic.block, child_id);
        assert!(timeline[0].position < timeline[1].position);
        assert_eq!(
            timeline[1].position, timeline[2].position,
            "the regressed child is lifted to its predecessor's position"
        );

        let after_parent = snapshot
            .timeline_after(timeline[1].cursor(), |_| true)
            .unwrap();
        assert_eq!(after_parent.len(), 1);
        assert_eq!(after_parent[0].block.semantic.block, child_id);
        assert!(snapshot
            .timeline_after(ArchiveTimelineCursor::AfterBlock(untimed_id), |_| true)
            .unwrap_err()
            .to_string()
            .contains("absent or has no timestamp"));
    }

    #[test]
    fn succinct_index_persists_an_exact_validated_v4_derive() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile_path, &key);

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
            .find(|derive| derive.target() == report.target_collection)
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
        let namespace = load_signer(&pile_path, Some(&key)).unwrap().verifying_key();
        let source = crate::collection_names::root_descriptor(schema::DEFAULT_SCOPE_ID, namespace);
        succinctarchive_union::validate_derive(
            &source,
            &succinctarchive_union::descriptor(
                archive_bm25::source_collection(namespace),
                None,
                reach::private(),
            ),
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
        initialize_archive_fixture(&pile_path, &key);

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
        let source = test_source(&pile_path, &key);
        let target = test_target(&pile_path, &key);
        let derives: Vec<_> = records
            .derives()
            .iter()
            .filter(|claim| claim.target() == collection_of(&target))
            .copied()
            .collect();
        let merges: Vec<_> = records
            .merges()
            .iter()
            .filter(|claim| claim.collection() == collection_of(&target))
            .copied()
            .collect();
        assert_eq!(derives.len(), 2);
        assert_eq!(merges.len(), 1);
        let commits: Vec<_> = records
            .commits()
            .iter()
            .filter(|claim| claim.collection() == collection_of(&source))
            .copied()
            .collect();
        let algebra = ArchiveBm25Algebra {
            reader: pile.reader().unwrap(),
            namespace: test_namespace(&pile_path, &key),
        };
        let exact = ExactDerivedCollection::new(source.clone(), target.clone());
        let cover = exact.attach_exact(&mut pile, &commits, &algebra).unwrap();
        assert_eq!(cover.len(), 1);
        pile.close().unwrap();

        let search = ArchiveSearchSnapshot::ensure_local(&pile_path, Some(&key)).unwrap();
        assert_eq!(search.search("alpha", 10).unwrap().len(), 1);
        assert_eq!(search.search("beta", 10).unwrap().len(), 1);
    }

    #[test]
    fn bm25_derives_repeated_content_from_each_naturally_authored_leaf() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile_path, &key);

        for (locator, seconds) in [("session:first", 1.0), ("session:second", 2.0)] {
            let mut writer = ArchiveImportWriter::open(&pile_path, Some(&key)).unwrap();
            writer
                .stage_fragment(projection_at(locator, "shared closure needle", seconds))
                .unwrap();
            writer.finish(Ok(())).unwrap();
        }

        let report = ensure_bm25_index(&pile_path, Some(&key)).unwrap();
        assert_eq!((report.source_commits, report.source_elements), (2, 2));
        let search = ArchiveSearchSnapshot::ensure_local(&pile_path, Some(&key)).unwrap();
        let hits = search.search("shared closure needle", 10).unwrap();
        assert_eq!(hits.len(), 2);
        assert_ne!(hits[0].block, hits[1].block);
    }

    #[test]
    fn lazy_bm25_maintenance_extends_after_a_new_commit() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile_path, &key);

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
        initialize_archive_fixture(&pile_path, &key);

        // The collection union is a valid Archive, but the tagged block and
        // its part/fact closure live in separate signed elements. With no
        // admitted source MERGE and union DERIVE, no target route covers both
        // roots. Direct residual derivation must reject the incomplete leaf
        // before publishing an accelerator payload or equation.
        let (block_element, remainder_element) =
            projection_split_across_source_elements("session:split", "closure needle");
        let signer = load_signer(&pile_path, Some(&key)).unwrap();
        let pile = open_pile_strict(&pile_path).unwrap();
        let mut collection = crate::collection_names::open(pile, schema::DEFAULT_SCOPE_ID, signer);
        collection.commit(block_element).unwrap();
        collection.commit(remainder_element).unwrap();
        collection
            .storage_mut()
            .put::<SimpleArchive, _>(triblespace::core::blob::IntoBlob::<SimpleArchive>::to_blob(
                test_target(&pile_path, &key).facts().clone(),
            ))
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
        initialize_archive_fixture(&pile_path, &key);

        let (block_element, remainder_element) =
            projection_split_across_source_elements("session:routed", "routed needle");
        let signer = load_signer(&pile_path, Some(&key)).unwrap();
        let pile = open_pile_strict(&pile_path).unwrap();
        let mut collection = crate::collection_names::open(pile, schema::DEFAULT_SCOPE_ID, signer);
        let block_commit = collection.commit(block_element).unwrap();
        let remainder_commit = collection.commit(remainder_element).unwrap();
        let source = collection.descriptor().clone();
        // A merge names two states of the collection, and the commits that
        // made them already put their bytes in the store, so it takes their
        // data handles rather than blobs fetched back out.
        let (_, union) = simplearchive_union::publish_merge(
            collection.storage_mut(),
            &source,
            block_commit.data(),
            remainder_commit.data(),
        )
        .unwrap();

        let target = test_target(&pile_path, &key);
        let reader = collection.storage_mut().reader().unwrap();
        let output = archive_bm25::derive_element(&reader, union.clone()).unwrap();
        let input_data = Handle::<SimpleArchive>::to_hash(union.get_handle());
        let output_data = Handle::<PortableBM25Blob>::to_hash(output.get_handle());
        let derive = CollectionDerive::new(collection_of(&target), input_data, output_data);
        let algebra = ArchiveBm25Algebra {
            reader,
            namespace: test_namespace(&pile_path, &key),
        };
        assert_eq!(algebra.derive(&union).unwrap().bytes, output.bytes);
        algebra.validate_target(&target, &output).unwrap();
        drop(algebra);
        collection
            .storage_mut()
            .put::<SimpleArchive, _>(triblespace::core::blob::IntoBlob::<SimpleArchive>::to_blob(
                target.facts().clone(),
            ))
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
    fn bm25_frozen_ticket_excludes_a_later_admitted_commit() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile_path, &key);

        let first = commit_projection(&pile_path, &key, "session:frozen", "frozen needle");
        let frozen =
            ArchiveSnapshot::load_local(&pile_path, Some(&key), schema::DEFAULT_SCOPE_ID).unwrap();
        let later = commit_projection(&pile_path, &key, "session:later", "later needle");

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let ensured =
            ensure_bm25_for_snapshot(&mut pile, &frozen, test_namespace(&pile_path, &key)).unwrap();
        assert_eq!(ensured.report.source_commits, 1);
        drop(ensured);
        pile.close().unwrap();
        drop(frozen);

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let records = discover_collection_records(&mut pile).unwrap();
        let target = test_target(&pile_path, &key);
        let inputs: BTreeSet<_> = records
            .derives()
            .iter()
            .filter(|claim| claim.target() == collection_of(&target))
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
        initialize_archive_fixture(&pile_path, &key);
        commit_projection(&pile_path, &key, "session:first", "first residual");
        commit_projection(&pile_path, &key, "session:second", "second residual");
        let archive =
            ArchiveSnapshot::load_local(&pile_path, Some(&key), schema::DEFAULT_SCOPE_ID).unwrap();
        let commits = archive.commits().to_vec();
        drop(archive);

        let source = test_source(&pile_path, &key);
        let target = test_target(&pile_path, &key);
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let exact = ExactDerivedCollection::new(source.clone(), target.clone());
        let algebra = ArchiveBm25Algebra {
            reader: pile.reader().unwrap(),
            namespace: test_namespace(&pile_path, &key),
        };

        let first = exact
            .ensure_exact(&mut pile, &commits[..1], &algebra)
            .unwrap();
        assert_eq!(first.len(), 1);
        drop(first);
        let first_records = discover_collection_records(&mut pile).unwrap();
        let first_derives = first_records
            .derives()
            .iter()
            .filter(|claim| claim.target() == collection_of(&target))
            .count();
        assert_eq!(first_derives, 1);

        let full = exact.ensure_exact(&mut pile, &commits, &algebra).unwrap();
        assert_eq!(full.len(), 2);
        let full_records = discover_collection_records(&mut pile).unwrap();
        let full_derives = full_records
            .derives()
            .iter()
            .filter(|claim| claim.target() == collection_of(&target))
            .count();
        assert_eq!(
            full_derives, 2,
            "only the newly unsupported root is derived"
        );
        let compacted = compact_exact_target(&exact, &mut pile, &commits, &algebra).unwrap();
        assert_eq!(compacted.len(), 1);
        drop(compacted);

        let records_before = discover_collection_records(&mut pile).unwrap();
        let counts_before = (
            records_before.derives().len(),
            records_before.merges().len(),
        );
        let retry = exact.ensure_exact(&mut pile, &commits, &algebra).unwrap();
        assert_eq!(retry.len(), 1, "the admitted MERGE is reused");
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
        initialize_archive_fixture(&pile_path, &key);
        let first = commit_projection(&pile_path, &key, "session:shared", "shared data");
        let source = test_source(&pile_path, &key);
        let target = test_target(&pile_path, &key);
        let second = CollectionCommit::sign(
            &SigningKey::from_bytes(&[0xA5; 32]),
            collection_of(&source),
            first.data(),
            first.metadata(),
        );

        let mut pile = open_pile_strict(&pile_path).unwrap();
        CollectionStore::insert(&mut pile, CollectionRecord::Commit(second)).unwrap();
        let algebra = ArchiveBm25Algebra {
            reader: pile.reader().unwrap(),
            namespace: test_namespace(&pile_path, &key),
        };
        let exact = ExactDerivedCollection::new(source.clone(), target.clone());
        let ready = exact
            .ensure_exact(&mut pile, &[first, second], &algebra)
            .unwrap();
        assert_eq!(ready.len(), 1, "equal source data has one canonical image");
        let records = discover_collection_records(&mut pile).unwrap();
        assert_eq!(
            records
                .derives()
                .iter()
                .filter(|claim| { claim.target() == collection_of(&target) })
                .count(),
            1,
        );
        pile.close().unwrap();
    }

    #[test]
    fn exact_ensure_recovers_a_pending_derive_with_a_missing_output() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile_path, &key);
        let commit = commit_projection(&pile_path, &key, "session:pending", "recover output");
        let source = test_source(&pile_path, &key);
        let target = test_target(&pile_path, &key);

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let reader = pile.reader().unwrap();
        let input: Blob<SimpleArchive> = reader
            .get(Handle::<SimpleArchive>::from_hash(commit.data()))
            .unwrap();
        let output = archive_bm25::derive_element(&reader, input).unwrap();
        let output_data = Handle::<PortableBM25Blob>::to_hash(output.get_handle());
        let pending = CollectionDerive::new(collection_of(&target), commit.data(), output_data);
        drop(output);
        drop(reader);
        CollectionStore::insert(&mut pile, CollectionRecord::Derive(pending)).unwrap();
        assert!(pile
            .reader()
            .unwrap()
            .metadata(Handle::<PortableBM25Blob>::from_hash(output_data))
            .unwrap()
            .is_none());

        let algebra = ArchiveBm25Algebra {
            reader: pile.reader().unwrap(),
            namespace: test_namespace(&pile_path, &key),
        };
        let exact = ExactDerivedCollection::new(source.clone(), target.clone());
        let ready = exact.ensure_exact(&mut pile, &[commit], &algebra).unwrap();
        assert_eq!(
            ready
                .members()
                .iter()
                .map(|(data, _)| *data)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([output_data])
        );
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
    fn exact_complete_fast_path_needs_no_descriptor_republication() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        let signer = initialize_archive_fixture(&pile_path, &key);
        let source = test_source(&pile_path, &key);
        let target = test_target(&pile_path, &key);

        let (_, facts, metafacts, mut blobs) =
            projection("session:descriptors", "descriptor recovery").into_parts();
        let data: Blob<SimpleArchive> = facts.to_blob();
        let metadata: Blob<SimpleArchive> = metafacts.to_blob();
        let commit = CollectionCommit::sign(
            &signer,
            collection_of(&source),
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
        let input: Blob<SimpleArchive> = reader
            .get(Handle::<SimpleArchive>::from_hash(commit.data()))
            .unwrap();
        let output = archive_bm25::derive_element(&reader, input).unwrap();
        let output_data = Handle::<PortableBM25Blob>::to_hash(output.get_handle());
        let derive = CollectionDerive::new(collection_of(&target), commit.data(), output_data);
        drop(reader);
        pile.put::<PortableBM25Blob, _>(output).unwrap();
        CollectionStore::insert(&mut pile, CollectionRecord::Derive(derive)).unwrap();
        let reader = pile.reader().unwrap();
        assert!(reader.metadata(collection_of(&source)).unwrap().is_none());
        assert!(reader.metadata(collection_of(&target)).unwrap().is_none());
        drop(reader);

        let before = std::fs::metadata(&pile_path).unwrap().len();
        let algebra = ArchiveBm25Algebra {
            reader: pile.reader().unwrap(),
            namespace: test_namespace(&pile_path, &key),
        };
        let exact = ExactDerivedCollection::new(source.clone(), target.clone());
        let ready = exact.ensure_exact(&mut pile, &[commit], &algebra).unwrap();
        assert_eq!(ready.len(), 1);
        drop(ready);
        let reader = pile.reader().unwrap();
        assert!(reader.metadata(collection_of(&source)).unwrap().is_none());
        assert!(reader.metadata(collection_of(&target)).unwrap().is_none());
        drop(reader);
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), before);

        let retry = exact.ensure_exact(&mut pile, &[commit], &algebra).unwrap();
        assert_eq!(retry.len(), 1);
        drop(retry);
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), before);
        pile.close().unwrap();
    }

    #[test]
    fn exact_ensure_rejects_an_absent_ticket_before_derivation() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile_path, &key);
        let existing = commit_projection(&pile_path, &key, "session:existing", "existing data");
        let source = test_source(&pile_path, &key);
        let target = test_target(&pile_path, &key);
        let absent = CollectionCommit::sign(
            &SigningKey::from_bytes(&[0x5A; 32]),
            collection_of(&source),
            existing.data(),
            existing.metadata(),
        );
        let before = std::fs::metadata(&pile_path).unwrap().len();

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let algebra = ArchiveBm25Algebra {
            reader: pile.reader().unwrap(),
            namespace: test_namespace(&pile_path, &key),
        };
        let exact = ExactDerivedCollection::new(source.clone(), target.clone());
        let error = match exact.ensure_exact(&mut pile, &[absent], &algebra) {
            Ok(_) => panic!("absent frozen ticket was unexpectedly admitted"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("absent or fails strict signature verification"));
        pile.close().unwrap();
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), before);
    }
}
