//! Collection-native Archive runtime over the V4 descriptor-handle calculus.
//!
//! Archive authorship has one durable Ed25519 signer and one fixed canonical
//! SimpleArchive-union descriptor. Imports stage independently derivable source
//! fragments which contribute new evidence, validate the candidate block DAG,
//! and cross exactly one signed COMMIT visibility edge. Reads snapshot that same collection;
//! there is no Repository branch, CAS head, sidecar registry, or fallback
//! identity.

use std::collections::{BTreeMap, BTreeSet};

use anybytes::{Bytes, View};
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace::core::blob::encodings::{simplearchive::SimpleArchive, UnknownBlob};
use triblespace::core::blob::Blob;
use triblespace::core::collection::{
    Collection, CollectionCommit, CollectionSnapshotExt, CollectionStoreExt, Support,
};
use triblespace::core::inline::encodings::UnknownInline;
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::{BlobStoreGet, BlobStorePut, SnapshotSource};
use triblespace::prelude::blobencodings::{RawBytes, UTF8String};
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval, U256BE};
use triblespace::prelude::*;
#[cfg(test)]
use triblespace_search::portable_bm25::PortableBM25Blob;
use triblespace_search::portable_bm25::PortableBM25Index;
use triblespace_search::tokens::{hash_tokens, WordHash};

use crate::archive_bm25;
use crate::blockdag::{self, CatalogValidation};
use crate::schemas::{blockdag as schema, files as files_schema};
use crate::storage::{load_signer, open_pile_strict, FactArchive, FactCollection};

use crate::collection_names::open_configured;
#[cfg(test)]
use triblespace::core::blob::encodings::succinctarchive::SuccinctArchiveBlob;
#[cfg(test)]
use triblespace::core::collection::succinctarchive_union::SimpleToSuccinctMapping;
#[cfg(test)]
use triblespace::core::collection::{
    CollectionDerive, CollectionMapping, CollectionMerge, CollectionRecord, CollectionStore,
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
    pile: Pile,
    collection: Collection<SimpleArchive>,
    signer: SigningKey,
    current: FactArchive,
    delta: Fragment,
}

impl ArchiveImportWriter {
    pub fn open(pile_path: &std::path::Path, key_path: Option<&std::path::Path>) -> Result<Self> {
        let signer = load_signer(pile_path, key_path)?;
        let mut pile = open_pile_strict(pile_path)?;
        let result = (|| {
            let source =
                open_configured(&mut pile, schema::DEFAULT_SCOPE_ID, signer.verifying_key())?;
            let facts = FactCollection::new(&mut pile, source)
                .context("register maintained Archive fact collection")?;
            let archive = ArchiveSnapshot::from_store(&mut pile, facts, schema::DEFAULT_SCOPE_ID)?;
            Ok((facts.source(), archive.facts))
        })();
        match result {
            Ok((collection, current)) => {
                let mut writer = Self {
                    pile,
                    collection,
                    signer,
                    current,
                    delta: Fragment::empty(),
                };
                if let Err(error) = writer.stage_fragment(blockdag::vocabulary_fragment()) {
                    return close_pile(
                        writer.pile,
                        Err(error),
                        "closing Archive pile after vocabulary staging failed",
                    );
                }
                Ok(writer)
            }
            Err(error) => close_pile(
                pile,
                Err(error),
                "closing Archive pile after failed open also failed",
            ),
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
        if facts.iter().all(|fact| {
            self.delta.facts().contains(fact) || fact_archive_contains(&self.current, fact)
        }) {
            return Ok(());
        }

        // Embedded payloads can dominate an import's resident memory. Append
        // each already-constructed content-addressed dependency immediately,
        // keeping payload bytes out of the long-lived logical delta. They
        // remain semantically unreachable until the signed COMMIT written by
        // `finish` names the facts which reference them.
        let embedded = embedded_blobs(blobs);
        stage_embedded_blobs(&mut self.pile, embedded)?;

        // Only the lightweight logical delta remains resident between source
        // fragments. Data and metadata archives are constructed once at the
        // final publication boundary.
        self.delta += Fragment::from_parts(facts, metafacts, Default::default());
        Ok(())
    }

    pub fn delta_len(&self) -> usize {
        self.delta.facts().len()
    }

    /// Publish ONE rollout's staged delta and keep the pile open.
    ///
    /// Atomicity is per rollout; it was never per PROCESS. Opening the pile
    /// costs ~9.3 s on the live 44 GB pile against ~1 s of actual projection
    /// for a 478 KB rollout (measured 2026-09-01), so paying it once per file
    /// put a full Codex backfill — 3,161 refused rollouts — at about 8.2 hours
    /// of pure pile-opening before any work. JP: "we can commit multiple times
    /// in the same process right xD?" Yes. Same one-signed-COMMIT-per-rollout
    /// guarantee, one open.
    ///
    /// `current` MUST absorb what was just published, or the next rollout's
    /// idempotence check would re-stage facts this commit already carries —
    /// which is the whole reason resumed Codex rollouts (they replay large
    /// parent prefixes) are cheap to ingest in sequence rather than expensive.
    pub fn commit_unit(&mut self) -> Result<Option<CollectionCommit>> {
        if self.delta.facts().is_empty() {
            return Ok(None);
        }
        let reader = self
            .pile
            .snapshot()
            .context("open staged Archive dependency reader")?;
        let candidate = candidate_archive(&self.current, &self.delta);
        let validation = blockdag::validate_succinct_catalog(&reader, &candidate)
            .context("validate staged Archive union")?;
        require_accepted(validation, "staged Archive union")?;
        let fragment = std::mem::replace(&mut self.delta, Fragment::empty());
        let published = fragment.facts().clone();
        let commit = self
            .pile
            .commit(self.collection, &self.signer, fragment)
            .context("commit authored Archive projection unit")?;
        self.current = extend_archive(&self.current, &published);
        Ok(Some(commit))
    }

    /// Close the pile, publishing any still-staged delta first.
    pub fn close<T>(mut self, surrounding: Result<T>) -> Result<T> {
        let result = surrounding.and_then(|value| {
            self.commit_unit()?;
            Ok(value)
        });
        close_pile(
            self.pile,
            result,
            "closing Archive pile after failure also failed",
        )
    }

    pub fn finish<T>(mut self, surrounding: Result<T>) -> Result<(T, Option<CollectionCommit>)> {
        let result = surrounding.and_then(|value| {
            if self.delta.facts().is_empty() {
                return Ok((value, None));
            }
            // `PileSnapshot` snapshots are immutable. Open this view only after
            // every staged blob append so import validation sees those
            // dependencies without retaining them in the Fragment overlay.
            let reader = self
                .pile
                .snapshot()
                .context("open staged Archive dependency reader")?;
            let candidate = candidate_archive(&self.current, &self.delta);
            let validation = blockdag::validate_succinct_catalog(&reader, &candidate)
                .context("validate staged Archive union")?;
            require_accepted(validation, "staged Archive union")?;
            let fragment = std::mem::replace(&mut self.delta, Fragment::empty());
            let commit = self
                .pile
                .commit(self.collection, &self.signer, fragment)
                .context("commit authored Archive projection unit")?;
            Ok((value, Some(commit)))
        });
        close_pile(
            self.pile,
            result,
            "closing Archive pile after failure also failed",
        )
    }
}

/// Write one validated streaming payload batch into content-addressed storage.
///
/// A failed put abandons only this batch. Replaying the fragment repeats the
/// same idempotent content-addressed writes; the later signed collection commit
/// is the sole semantic publication edge.
fn stage_embedded_blobs<S>(store: &mut S, embedded: Vec<Blob<UnknownBlob>>) -> Result<()>
where
    S: BlobStorePut,
{
    for blob in embedded {
        store
            .put::<UnknownBlob, _>(blob)
            .context("stage Archive embedded blob")?;
    }
    Ok(())
}

/// Extract the content-addressed attachments already constructed by a Fragment.
///
/// `MemoryBlobStore` and `Blob` uphold their cached-handle invariants. Rehashing
/// bytes produced in this process would only repeat work at the publication
/// boundary; untrusted bytes are validated according to their encoding when
/// they are interpreted.
fn embedded_blobs(mut blobs: triblespace::core::blob::MemoryBlobStore) -> Vec<Blob<UnknownBlob>> {
    let reader = blobs
        .snapshot()
        .expect("MemoryBlobStore reader creation is infallible");
    let mut embedded: Vec<_> = reader.iter().collect();
    embedded.sort_unstable_by_key(|(store_key, _)| store_key.raw);

    embedded.into_iter().map(|(_, blob)| blob).collect()
}

/// Exact membership without rebuilding an in-memory `TribleSet` over the
/// maintained shard union.
fn fact_archive_contains(facts: &FactArchive, fact: &Trible) -> bool {
    exists!(facts.pattern(
        inlineencodings::GenId::inline_from(*fact.e()),
        inlineencodings::GenId::inline_from(*fact.a()),
        *fact.v::<UnknownInline>(),
    ))
}

/// Shallow candidate view for the explicit Archive import boundary.
///
/// The already-maintained durable facts keep their mmap-backed shards. Only
/// facts published or staged by this writer become one transient Succinct
/// shard, so validation never rebuilds the historical six-PATCH `TribleSet`.
fn candidate_archive(current: &FactArchive, delta: &Fragment) -> FactArchive {
    extend_archive(current, delta.facts())
}

fn extend_archive(current: &FactArchive, additions: &TribleSet) -> FactArchive {
    if additions.is_empty() {
        return current.clone();
    }
    current.with_segments([
        triblespace::core::blob::encodings::succinctarchive::SuccinctArchive::from(additions),
    ])
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

fn close_pile<T>(pile: Pile, result: Result<T>, failure_context: &str) -> Result<T> {
    match (result, pile.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(close_error)) => Err(anyhow!("close Archive pile: {close_error}")),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("{failure_context} also failed: {close_error}")))
        }
    }
}

/// Exact V4 accelerated-Succinct derivation summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuccinctIndexReport {
    pub source_commits: usize,
    /// Distinct source data elements named by the frozen foundational support.
    pub source_elements: usize,
    pub source_collection: Inline<Handle<SimpleArchive>>,
    pub target_collection: Inline<Handle<SimpleArchive>>,
}

/// Ensure an exact resident accelerated-Succinct view for frozen Archive support.
///
/// This is a reproducible physical cover, not new authority. Canonical raw
/// Succinct members are derived and merged first; the public target is their
/// exact Rank9-accelerated image. [`ensure_bm25_index`] provides the analogous
/// exact projection for Archive full-text search.
pub fn ensure_succinct_index(
    pile_path: &std::path::Path,
    key_path: Option<&std::path::Path>,
) -> Result<SuccinctIndexReport> {
    let (mut pile, facts, _signer) =
        ArchiveSnapshot::open_local(pile_path, key_path, schema::DEFAULT_SCOPE_ID)?;
    let result = (|| {
        let archive = ArchiveSnapshot::from_store(&mut pile, facts, schema::DEFAULT_SCOPE_ID)?;
        let source_elements = archive.support().len();

        Ok(SuccinctIndexReport {
            source_commits: archive.commits().len(),
            source_elements,
            source_collection: archive.collections.source().handle(),
            target_collection: archive.collections.rank9().handle(),
        })
    })();
    close_pile(
        pile,
        result,
        "closing Archive pile after accelerated-Succinct derivation",
    )
}

/// Exact V4 Archive BM25 derivation summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bm25IndexReport {
    pub source_commits: usize,
    /// Distinct source data elements named by the frozen foundational support.
    pub source_elements: usize,
    pub cover_segments: usize,
    pub source_collection: Inline<Handle<SimpleArchive>>,
    pub target_collection: Inline<Handle<SimpleArchive>>,
}

struct EnsuredBm25 {
    report: Bm25IndexReport,
    index: ArchiveBm25,
}

/// Ensure and deterministically maintain a portable exact-TF cover of the
/// frozen Archive support through exact `DERIVE` and `MERGE` equations.
pub fn ensure_bm25_index(
    pile_path: &std::path::Path,
    key_path: Option<&std::path::Path>,
) -> Result<Bm25IndexReport> {
    let (mut pile, facts, signer) =
        ArchiveSnapshot::open_local(pile_path, key_path, schema::DEFAULT_SCOPE_ID)?;
    let result = (|| {
        let authority = signer.verifying_key();
        let archive = ArchiveSnapshot::from_store(&mut pile, facts, schema::DEFAULT_SCOPE_ID)?;
        Ok(ensure_bm25_for_snapshot(&mut pile, &archive, authority)?.report)
    })();
    close_pile(pile, result, "closing Archive pile after BM25 derivation")
}

fn ensure_bm25_for_snapshot(
    pile: &mut Pile,
    archive: &ArchiveSnapshot,
    authority: VerifyingKey,
) -> Result<EnsuredBm25> {
    let target = pile
        .derive(
            archive.collections.source(),
            archive_bm25::ArchiveBlockTextBm25Mapping,
            crate::collection_names::private_policy(authority),
        )
        .context("register Archive BM25 derivation")?;
    let source_elements = archive.support().len();
    let maintained = pile
        .maintain_exact::<archive_bm25::ArchiveBlockTextBm25Mapping>(target, archive.support())
        .context("maintain exact Archive BM25 cover")?;
    let attached = maintained
        .collection_exact(target, archive.support())
        .context("attach exact Archive BM25 cover")?;
    let cover_segments = attached.cover().len();
    let index = attached
        .view::<ArchiveBm25>()
        .context("read exact Archive BM25 cover")?;
    Ok(EnsuredBm25 {
        report: Bm25IndexReport {
            source_commits: archive.commits().len(),
            source_elements,
            cover_segments,
            source_collection: archive.collections.source().handle(),
            target_collection: target.handle(),
        },
        index,
    })
}

fn interval_lower_key(interval: Inline<NsTAIInterval>) -> Result<i128> {
    let (lower, _upper): (i128, i128) = interval
        .try_from_inline()
        .map_err(|error| anyhow!("decode Archive timestamp: {error:?}"))?;
    Ok(lower)
}

/// One frozen Archive view and one resident portable BM25 index attached from
/// the exact foundational support of the same admitted source commits.
pub struct ArchiveSearchSnapshot {
    archive: ArchiveSnapshot,
    index: ArchiveBm25,
}

impl ArchiveSearchSnapshot {
    pub fn ensure_local(
        pile_path: &std::path::Path,
        key_path: Option<&std::path::Path>,
    ) -> Result<Self> {
        let (mut pile, facts, signer) =
            ArchiveSnapshot::open_local(pile_path, key_path, schema::DEFAULT_SCOPE_ID)?;
        let result = (|| {
            let authority = signer.verifying_key();
            let archive = ArchiveSnapshot::from_store(&mut pile, facts, schema::DEFAULT_SCOPE_ID)?;
            let EnsuredBm25 { index, .. } =
                ensure_bm25_for_snapshot(&mut pile, &archive, authority)?;
            Ok(Self { archive, index })
        })();
        close_pile(
            pile,
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

/// One immutable shard-preserving Archive view from the local durable collection.
pub struct ArchiveSnapshot {
    scope: Id,
    collections: FactCollection,
    facts: FactArchive,
    store_snapshot: PileSnapshot,
    support: Support,
    commits: Vec<CollectionCommit>,
}

impl ArchiveSnapshot {
    fn open_local(
        pile_path: &std::path::Path,
        key_path: Option<&std::path::Path>,
        scope: Id,
    ) -> Result<(Pile, FactCollection, SigningKey)> {
        if scope != schema::DEFAULT_SCOPE_ID {
            bail!(
                "Archive runtime only supports fixed scope {:X}",
                schema::DEFAULT_SCOPE_ID
            );
        }
        let signer = load_signer(pile_path, key_path)?;
        let mut pile = open_pile_strict(pile_path)?;
        let source = open_configured(&mut pile, scope, signer.verifying_key())?;
        let collections = FactCollection::new(&mut pile, source)
            .context("register maintained Archive fact collection")?;
        Ok((pile, collections, signer))
    }

    fn from_store(pile: &mut Pile, collections: FactCollection, scope: Id) -> Result<Self> {
        let instant = crate::clock::now()?;
        let before = pile.snapshot().context("freeze Archive source snapshot")?;
        Self::maintain_from(pile, collections, scope, &before, instant)
    }

    /// Maintain and attach Archive from one caller-selected source watermark.
    ///
    /// Callers which read several collections together can freeze one
    /// pre-work snapshot, capture every collection's exact support there, and
    /// then attach all maintained views through the one immutable snapshot
    /// returned by the final maintenance step. This removes cross-watermark
    /// skew without pretending that maintenance writes change the observation.
    pub fn maintain_from(
        pile: &mut Pile,
        collections: FactCollection,
        scope: Id,
        before: &PileSnapshot,
        instant: hifitime::Epoch,
    ) -> Result<Self> {
        if scope != schema::DEFAULT_SCOPE_ID {
            bail!(
                "Archive runtime only supports fixed scope {:X}",
                schema::DEFAULT_SCOPE_ID
            );
        }
        let support = before
            .collection_at(collections.source(), instant)
            .context("observe resident Archive source collection")?
            .support()
            .clone();
        let (_, mut commits) = collections
            .source()
            .admitted_with_commits_at(before, instant)
            .context("discover admitted Archive commits")?;
        commits
            .retain(|commit| support.contains(Handle::<SimpleArchive>::from_hash(commit.data())));
        let store_snapshot = collections
            .maintain_exact(pile, &support)
            .context("maintain Archive fact collection")?;
        let facts = store_snapshot
            .collection_exact(collections.rank9(), &support)
            .context("attach exact Archive fact collection")?
            .view::<FactArchive>()
            .context("read exact Archive fact collection")?;
        Ok(Self {
            scope,
            collections,
            facts,
            store_snapshot,
            support,
            commits,
        })
    }

    pub fn load_local(
        pile_path: &std::path::Path,
        key_path: Option<&std::path::Path>,
        scope: Id,
    ) -> Result<Self> {
        let (mut pile, collections, _signer) = Self::open_local(pile_path, key_path, scope)?;
        let result = Self::from_store(&mut pile, collections, scope);
        close_pile(pile, result, "closing Archive pile")
    }

    pub const fn scope(&self) -> Id {
        self.scope
    }

    pub fn facts(&self) -> &FactArchive {
        &self.facts
    }

    pub fn store_snapshot(&self) -> &PileSnapshot {
        &self.store_snapshot
    }

    /// Exact admitted foundational support represented by this snapshot.
    pub fn support(&self) -> &Support {
        &self.support
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
        self.store_snapshot
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

    fn payload(&self, catalog: &FactArchive, fact: Id) -> Result<ArchivePayload> {
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
        let value: View<str> = self
            .store_snapshot
            .get(handle)
            .context("read Archive text")?;
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

    /// Descriptor-local authority of the Archive fixture.
    fn test_authority(
        pile: &std::path::Path,
        key: &std::path::Path,
    ) -> ed25519_dalek::VerifyingKey {
        load_signer(pile, Some(key)).unwrap().verifying_key()
    }

    /// The Archive root these fixtures commit into.
    fn test_source(
        store: &mut Pile,
        pile: &std::path::Path,
        key: &std::path::Path,
    ) -> Collection<SimpleArchive> {
        crate::collection_names::open(store, schema::DEFAULT_SCOPE_ID, test_authority(pile, key))
            .unwrap()
    }

    /// The derived BM25 collection over that root.
    fn test_target(
        store: &mut Pile,
        source: Collection<SimpleArchive>,
        pile: &std::path::Path,
        key: &std::path::Path,
    ) -> Collection<PortableBM25Blob> {
        store
            .derive(
                source,
                archive_bm25::ArchiveBlockTextBm25Mapping,
                crate::collection_names::private_policy(test_authority(pile, key)),
            )
            .unwrap()
    }

    /// Initialize the durable signer used by the Archive fixture.
    fn initialize_archive_fixture(pile: &std::path::Path, key: &std::path::Path) -> SigningKey {
        initialize_signer(pile, Some(key)).unwrap()
    }

    use super::*;
    use crate::storage::initialize_signer;
    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use tempfile::TempDir;
    use triblespace::core::blob::IntoBlob;
    use triblespace::core::collection::{discover_collection_records, simplearchive_union};

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
            .snapshot()
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

        // The payload is already durable enough to satisfy a fresh reader, but
        // no signed collection root makes its facts visible yet.
        let mut physical = open_pile_strict(&pile).unwrap();
        let reader = physical.snapshot().unwrap();
        let _: Blob<UnknownBlob> = reader.get(embedded).unwrap();
        drop(reader);
        physical.close().unwrap();
        let before =
            ArchiveSnapshot::load_local(&pile, Some(&key), schema::DEFAULT_SCOPE_ID).unwrap();
        assert!(before.commits().is_empty());
        assert!(before.facts().iter().next().is_none());
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
        assert!(snapshot.facts().iter().next().is_none());
        drop(snapshot);
        let mut physical = open_pile_strict(&pile).unwrap();
        let reader = physical.snapshot().unwrap();
        let _: Blob<UnknownBlob> = reader.get(embedded).unwrap();
        drop(reader);
        physical.close().unwrap();
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum StageEvent {
        Put(Inline<Handle<UnknownBlob>>),
    }

    #[derive(Default)]
    struct StageProbe {
        events: Vec<StageEvent>,
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

    #[test]
    fn streamed_blob_batch_writes_every_content_addressed_member() {
        let first = Blob::<UnknownBlob>::new(Bytes::from_source(b"first".to_vec()));
        let second = Blob::<UnknownBlob>::new(Bytes::from_source(b"second".to_vec()));
        let first_handle = first.get_handle();
        let second_handle = second.get_handle();
        let mut probe = StageProbe::default();
        stage_embedded_blobs(&mut probe, vec![second, first]).unwrap();
        assert_eq!(
            probe.events,
            vec![
                StageEvent::Put(second_handle),
                StageEvent::Put(first_handle),
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
        let mut retry = ArchiveImportWriter::open(&pile, Some(&key)).unwrap();
        let length = std::fs::metadata(&pile).unwrap().len();
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
    fn unauthorized_duplicate_claim_is_provenance_not_an_admitted_archive_root() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key_path = directory.path().join("archive.key");
        let signer = initialize_archive_fixture(&pile_path, &key_path);
        let fragment = projection("session:duplicate-author", "one payload");

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let collection =
            open_configured(&mut pile, schema::DEFAULT_SCOPE_ID, signer.verifying_key()).unwrap();
        let admitted = pile.commit(collection, &signer, fragment.clone()).unwrap();
        let foreign = SigningKey::from_bytes(&[0xA7; 32]);
        let duplicate = pile.commit(collection, &foreign, fragment).unwrap();
        assert_eq!(duplicate.data(), admitted.data());
        pile.close().unwrap();

        let snapshot =
            ArchiveSnapshot::load_local(&pile_path, Some(&key_path), schema::DEFAULT_SCOPE_ID)
                .unwrap();
        assert_eq!(snapshot.commits(), &[admitted]);
        assert_eq!(snapshot.projection_ids().len(), 1);
        let support = snapshot.support().clone();
        drop(snapshot);

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let store_snapshot = pile.snapshot().unwrap();
        let claims = support.commits(&store_snapshot).unwrap();
        assert_eq!(claims.len(), 2);
        assert!(claims.contains(&admitted));
        assert!(claims.contains(&duplicate));
        pile.close().unwrap();
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
        assert!(snapshot.facts().iter().count() > first_len);
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
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let collection =
            open_configured(&mut pile, schema::DEFAULT_SCOPE_ID, signer.verifying_key()).unwrap();
        let commit = pile.commit(collection, &signer, Fragment::empty()).unwrap();
        pile.close().unwrap();

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
        let records = {
            let store_snapshot = pile.snapshot().unwrap();
            discover_collection_records(&store_snapshot).unwrap()
        };
        let derives: Vec<_> = records
            .derives()
            .iter()
            .filter(|claim| claim.input() == commit.data())
            .collect();
        assert_eq!(derives.len(), 2, "one empty derive per target mapping");
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
        let authority = load_signer(&pile_path, Some(&key)).unwrap().verifying_key();
        let source = test_source(&mut pile, &pile_path, &key);
        let raw_target = pile
            .derive(
                source,
                SimpleToSuccinctMapping,
                crate::collection_names::private_policy(authority),
            )
            .unwrap();
        let records = {
            let store_snapshot = pile.snapshot().unwrap();
            discover_collection_records(&store_snapshot).unwrap()
        };
        let derive = records
            .derives()
            .iter()
            .find(|derive| derive.collection() == raw_target.handle())
            .copied()
            .expect("stored Archive raw-Succinct DERIVE");
        let reader = pile.snapshot().unwrap();
        let (input, output) = (derive.input(), derive.output());
        let input: Blob<SimpleArchive> = reader
            .get(Handle::<SimpleArchive>::from_hash(input))
            .unwrap();
        let output: Blob<SuccinctArchiveBlob> = reader
            .get(Handle::<SuccinctArchiveBlob>::from_hash(output))
            .unwrap();
        let expected = SimpleToSuccinctMapping.map(&input, &reader).unwrap();
        assert_eq!(expected.get_handle(), output.get_handle());
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
        let source = test_source(&mut pile, &pile_path, &key);
        let target = test_target(&mut pile, source, &pile_path, &key);
        let records = {
            let store_snapshot = pile.snapshot().unwrap();
            discover_collection_records(&store_snapshot).unwrap()
        };
        let derives: Vec<_> = records
            .derives()
            .iter()
            .filter(|claim| claim.collection() == target.handle())
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
        let store_snapshot = pile.snapshot().unwrap();
        let source_support = source.admitted(&store_snapshot).unwrap();
        let attached = store_snapshot
            .collection_exact(target, &source_support)
            .unwrap();
        assert_eq!(attached.cover().len(), 1);
        pile.close().unwrap();

        let search = ArchiveSearchSnapshot::ensure_local(&pile_path, Some(&key)).unwrap();
        assert_eq!(search.search("alpha", 10).unwrap().len(), 1);
        assert_eq!(search.search("beta", 10).unwrap().len(), 1);
    }

    #[test]
    fn bm25_collapses_repeated_content_to_its_canonical_block() {
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
        assert_eq!(hits.len(), 1);
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
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let collection =
            open_configured(&mut pile, schema::DEFAULT_SCOPE_ID, signer.verifying_key()).unwrap();
        pile.commit(collection, &signer, block_element).unwrap();
        pile.commit(collection, &signer, remainder_element).unwrap();
        let _target = test_target(&mut pile, collection, &pile_path, &key);
        pile.close().unwrap();

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
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let collection =
            open_configured(&mut pile, schema::DEFAULT_SCOPE_ID, signer.verifying_key()).unwrap();
        let block_commit = pile.commit(collection, &signer, block_element).unwrap();
        let remainder_commit = pile.commit(collection, &signer, remainder_element).unwrap();
        let source = test_source(&mut pile, &pile_path, &key);
        let reader = pile.snapshot().unwrap();
        let block: Blob<SimpleArchive> = reader
            .get(Handle::<SimpleArchive>::from_hash(block_commit.data()))
            .unwrap();
        let remainder: Blob<SimpleArchive> = reader
            .get(Handle::<SimpleArchive>::from_hash(remainder_commit.data()))
            .unwrap();
        let union = simplearchive_union::join(&block, &remainder).unwrap();
        drop(reader);
        let union_data =
            Handle::<SimpleArchive>::to_hash(pile.put::<SimpleArchive, _>(union.clone()).unwrap());
        CollectionStore::insert(
            &mut pile,
            CollectionRecord::Merge(CollectionMerge::new(
                source.handle(),
                block_commit.data(),
                remainder_commit.data(),
                union_data,
            )),
        )
        .unwrap();

        let target = test_target(&mut pile, source, &pile_path, &key);
        let reader = pile.snapshot().unwrap();
        let output = archive_bm25::derive_element(&reader, union.clone()).unwrap();
        let input_data = Handle::<SimpleArchive>::to_hash(union.get_handle());
        let output_data = Handle::<PortableBM25Blob>::to_hash(output.get_handle());
        let derive = CollectionDerive::new(target.handle(), input_data, output_data);
        drop(reader);
        pile.put::<PortableBM25Blob, _>(output).unwrap();
        CollectionStore::insert(&mut pile, CollectionRecord::Derive(derive)).unwrap();
        let bm25_records = |pile: &mut Pile| {
            let store_snapshot = pile.snapshot().unwrap();
            let records = discover_collection_records(&store_snapshot).unwrap();
            (
                records
                    .derives()
                    .iter()
                    .filter(|record| record.collection() == target.handle())
                    .copied()
                    .collect::<Vec<_>>(),
                records
                    .merges()
                    .iter()
                    .filter(|record| record.collection() == target.handle())
                    .copied()
                    .collect::<Vec<_>>(),
            )
        };
        let bm25_records_before = bm25_records(&mut pile);
        pile.close().unwrap();

        let search = ArchiveSearchSnapshot::ensure_local(&pile_path, Some(&key)).unwrap();
        let hits = search.search("routed needle", 10).unwrap();
        assert_eq!(hits.len(), 1);
        let projections = search.archive().projection_ids();
        assert_eq!(projections.len(), 1);
        assert_eq!(hits[0].projections, projections);
        drop(search);

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let bm25_records_after = bm25_records(&mut pile);
        assert_eq!(
            bm25_records_after, bm25_records_before,
            "the seeded BM25 merge-before-derive route is reused"
        );
        pile.close().unwrap();
    }

    #[test]
    fn bm25_frozen_cover_excludes_a_later_admitted_commit() {
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
            ensure_bm25_for_snapshot(&mut pile, &frozen, test_authority(&pile_path, &key)).unwrap();
        assert_eq!(ensured.report.source_commits, 1);
        drop(ensured);
        pile.close().unwrap();
        drop(frozen);

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let source = test_source(&mut pile, &pile_path, &key);
        let target = test_target(&mut pile, source, &pile_path, &key);
        let records = {
            let store_snapshot = pile.snapshot().unwrap();
            discover_collection_records(&store_snapshot).unwrap()
        };
        let inputs: BTreeSet<_> = records
            .derives()
            .iter()
            .filter(|claim| claim.collection() == target.handle())
            .map(|claim| claim.input())
            .collect();
        assert_eq!(inputs, BTreeSet::from([first.data()]));
        assert!(!inputs.contains(&later.data()));
        pile.close().unwrap();
    }

    #[test]
    fn bm25_exact_maintenance_derives_only_the_residual_and_reuses_its_merge() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile_path, &key);
        commit_projection(&pile_path, &key, "session:first", "first residual");
        let first_archive =
            ArchiveSnapshot::load_local(&pile_path, Some(&key), schema::DEFAULT_SCOPE_ID).unwrap();
        let first_support = first_archive.support().clone();
        drop(first_archive);
        commit_projection(&pile_path, &key, "session:second", "second residual");
        let archive =
            ArchiveSnapshot::load_local(&pile_path, Some(&key), schema::DEFAULT_SCOPE_ID).unwrap();
        let full_support = archive.support().clone();
        drop(archive);

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let source = test_source(&mut pile, &pile_path, &key);
        let target = test_target(&mut pile, source, &pile_path, &key);
        let first_snapshot = pile
            .maintain_exact::<archive_bm25::ArchiveBlockTextBm25Mapping>(target, &first_support)
            .unwrap();
        let first = first_snapshot
            .collection_exact(target, &first_support)
            .unwrap();
        assert_eq!(first.cover().len(), 1);
        drop(first);
        let first_records = {
            let store_snapshot = pile.snapshot().unwrap();
            discover_collection_records(&store_snapshot).unwrap()
        };
        let first_derives = first_records
            .derives()
            .iter()
            .filter(|claim| claim.collection() == target.handle())
            .count();
        assert_eq!(first_derives, 1);

        let full_snapshot = pile
            .maintain_exact::<archive_bm25::ArchiveBlockTextBm25Mapping>(target, &full_support)
            .unwrap();
        let full = full_snapshot
            .collection_exact(target, &full_support)
            .unwrap();
        assert_eq!(full.cover().len(), 1);
        let full_records = {
            let store_snapshot = pile.snapshot().unwrap();
            discover_collection_records(&store_snapshot).unwrap()
        };
        let full_derives = full_records
            .derives()
            .iter()
            .filter(|claim| claim.collection() == target.handle())
            .count();
        assert_eq!(
            full_derives, 2,
            "only the newly unsupported root is derived"
        );
        let records_before = {
            let store_snapshot = pile.snapshot().unwrap();
            discover_collection_records(&store_snapshot).unwrap()
        };
        let counts_before = (
            records_before.derives().len(),
            records_before.merges().len(),
        );
        let retry_snapshot = pile
            .maintain_exact::<archive_bm25::ArchiveBlockTextBm25Mapping>(target, &full_support)
            .unwrap();
        let retry = retry_snapshot
            .collection_exact(target, &full_support)
            .unwrap();
        assert_eq!(retry.cover().len(), 1, "the admitted MERGE is reused");
        drop(retry);
        let records_after = {
            let store_snapshot = pile.snapshot().unwrap();
            discover_collection_records(&store_snapshot).unwrap()
        };
        assert_eq!(
            (records_after.derives().len(), records_after.merges().len()),
            counts_before,
            "a complete retry publishes no collection records"
        );
        pile.close().unwrap();
    }

    #[test]
    fn exact_maintenance_recovers_a_pending_derive_with_a_missing_output() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile_path, &key);
        let commit = commit_projection(&pile_path, &key, "session:pending", "recover output");

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let source = test_source(&mut pile, &pile_path, &key);
        let target = test_target(&mut pile, source, &pile_path, &key);
        let store_snapshot = pile.snapshot().unwrap();
        let source_support = source.admitted(&store_snapshot).unwrap();
        let input: Blob<SimpleArchive> = store_snapshot
            .get(Handle::<SimpleArchive>::from_hash(commit.data()))
            .unwrap();
        let output = archive_bm25::derive_element(&store_snapshot, input).unwrap();
        let output_data = Handle::<PortableBM25Blob>::to_hash(output.get_handle());
        let pending = CollectionDerive::new(target.handle(), commit.data(), output_data);
        drop(output);
        drop(store_snapshot);
        CollectionStore::insert(&mut pile, CollectionRecord::Derive(pending)).unwrap();
        assert!(pile
            .snapshot()
            .unwrap()
            .metadata(Handle::<PortableBM25Blob>::from_hash(output_data))
            .unwrap()
            .is_none());

        let ready_snapshot = pile
            .maintain_exact::<archive_bm25::ArchiveBlockTextBm25Mapping>(target, &source_support)
            .unwrap();
        let ready = ready_snapshot
            .collection_exact(target, &source_support)
            .unwrap();
        assert_eq!(
            ready
                .cover()
                .members()
                .map(Handle::<PortableBM25Blob>::to_hash)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([output_data])
        );
        drop(ready);
        let records = {
            let store_snapshot = pile.snapshot().unwrap();
            discover_collection_records(&store_snapshot).unwrap()
        };
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
}
