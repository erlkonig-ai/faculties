//! Collection-native Archive runtime over the V4 descriptor-handle calculus.
//!
//! Archive authorship has one durable Ed25519 signer and one fixed canonical
//! SimpleArchive-union descriptor. Imports stage independently derivable source
//! fragments which contribute new evidence and cross exactly one signed COMMIT
//! visibility edge per publication. Reads snapshot that same collection;
//! there is no Repository branch, CAS head, sidecar registry, or fallback
//! identity.

use std::collections::{BTreeMap, BTreeSet};

use anybytes::Bytes;
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace::core::blob::encodings::succinctarchive::Rank9AcceleratedSuccinctArchiveBlob;
use triblespace::core::blob::encodings::{simplearchive::SimpleArchive, UnknownBlob};
use triblespace::core::blob::Blob;
use triblespace::core::collection::{
    Collection, CollectionCommit, CollectionSnapshot, CollectionSnapshotExt, CollectionStoreExt,
    Support,
};
use triblespace::core::inline::encodings::UnknownInline;
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::{BlobStoreGet, BlobStorePut, SnapshotSource};
use triblespace::prelude::blobencodings::RawBytes;
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;
#[cfg(test)]
use triblespace_search::portable_bm25::PortableBM25Blob;

use crate::archive_bm25;
use crate::blockdag;
use crate::schemas::blockdag as schema;
use crate::storage::{load_signer, open_pile_strict, FactArchive, FactCollection};

use crate::collection_names::open_configured;
#[cfg(test)]
use triblespace::core::blob::encodings::succinctarchive::SuccinctArchiveBlob;
#[cfg(test)]
use triblespace::core::collection::{
    CollectionDerivation, CollectionDerive, CollectionMerge, CollectionRecord, CollectionStore,
};
#[cfg(test)]
use triblespace::core::repo::BlobStoreMeta;

type RawHandle = Inline<Handle<RawBytes>>;

/// Stage Archive fragments for commit-last publication.
///
/// Supplied facts remain open-world relations, including opaque ids and further
/// annotations. Publication does not require a closed-world catalog decode.
pub struct ArchiveImportWriter {
    pile: Pile,
    collection: Collection<SimpleArchive>,
    signer: SigningKey,
    current: FactArchive,
    delta: Fragment,
}

impl ArchiveImportWriter {
    pub async fn open(
        pile_path: &std::path::Path,
        key_path: Option<&std::path::Path>,
    ) -> Result<Self> {
        let signer = load_signer(pile_path, key_path)?;
        let mut pile = open_pile_strict(pile_path)?;
        let result = async {
            let source =
                open_configured(&mut pile, schema::DEFAULT_SCOPE_ID, signer.verifying_key())?;
            let facts = FactCollection::new(&mut pile, source)
                .context("register maintained Archive fact collection")?;
            let observed = ensure_facts(&mut pile, facts).await?;
            let current = observed
                .view::<FactArchive>()
                .context("read Archive facts")?;
            Ok((facts.source(), current))
        }
        .await;
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
        // remain semantically unreachable until a signed COMMIT names the
        // facts which reference them.
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

/// Write one constructed streaming payload batch into content-addressed storage.
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

fn extend_archive(current: &FactArchive, additions: &TribleSet) -> FactArchive {
    if additions.is_empty() {
        return current.clone();
    }
    current.with_segments([
        triblespace::core::blob::encodings::succinctarchive::SuccinctArchive::from(additions),
    ])
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

/// Ensure the Archive's maintained fact representation and return the ordinary
/// collection observation. This boundary performs storage work, not domain
/// decoding: consumers choose their own typed queries over `view::<FactArchive>()`.
pub async fn ensure_local(
    pile_path: &std::path::Path,
    key_path: Option<&std::path::Path>,
) -> Result<CollectionSnapshot<PileSnapshot, Rank9AcceleratedSuccinctArchiveBlob>> {
    let (mut pile, collections, _signer) = open_local(pile_path, key_path)?;
    let result = ensure_facts(&mut pile, collections).await;
    close_pile(pile, result, "closing Archive pile")
}

fn open_local(
    pile_path: &std::path::Path,
    key_path: Option<&std::path::Path>,
) -> Result<(Pile, FactCollection, SigningKey)> {
    let signer = load_signer(pile_path, key_path)?;
    let mut pile = open_pile_strict(pile_path)?;
    let result = (|| {
        let source = open_configured(&mut pile, schema::DEFAULT_SCOPE_ID, signer.verifying_key())?;
        FactCollection::new(&mut pile, source)
            .context("register maintained Archive fact collection")
    })();
    match result {
        Ok(collections) => Ok((pile, collections, signer)),
        Err(error) => close_pile(pile, Err(error), "closing Archive pile after failed open"),
    }
}

async fn ensure_facts(
    pile: &mut Pile,
    collections: FactCollection,
) -> Result<CollectionSnapshot<PileSnapshot, Rank9AcceleratedSuccinctArchiveBlob>> {
    let prepared = pile
        .ensure(collections.source())
        .await
        .context("ensure Archive source dependencies")?;
    let support = prepared
        .collection(collections.source())
        .context("observe Archive source support")?
        .support()
        .clone();
    drop(prepared);
    let after = collections
        .maintain_exact(pile, &support)
        .await
        .context("maintain Archive fact collection")?;
    after
        .collection_exact(collections.rank9(), &support)
        .context("attach exact Archive fact collection")
}

/// Exact accelerated-Succinct derivation summary. Source membership is measured
/// in distinct data elements, never in the number of attestations over them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuccinctIndexReport {
    pub source_elements: usize,
    pub source_collection: Inline<Handle<SimpleArchive>>,
    pub target_collection: Inline<Handle<SimpleArchive>>,
}

pub async fn ensure_succinct_index(
    pile_path: &std::path::Path,
    key_path: Option<&std::path::Path>,
) -> Result<SuccinctIndexReport> {
    let observed = ensure_local(pile_path, key_path).await?;
    Ok(SuccinctIndexReport {
        source_elements: observed.support().len(),
        source_collection: observed.support().collection().handle(),
        target_collection: observed.cover().collection().handle(),
    })
}

/// Exact Archive BM25 derivation summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bm25IndexReport {
    pub source_elements: usize,
    pub cover_segments: usize,
    pub source_collection: Inline<Handle<SimpleArchive>>,
    pub target_collection: Inline<Handle<SimpleArchive>>,
}

struct EnsuredBm25 {
    report: Bm25IndexReport,
    index: archive_bm25::ArchiveBM25Index,
}

/// Maintain the BM25 representation for one explicit foundational support.
/// Provenance records are neither part of this value nor required to replay it.
async fn ensure_bm25_exact(
    pile: &mut Pile,
    support: &Support,
    authority: VerifyingKey,
) -> Result<EnsuredBm25> {
    let target = pile
        .derive_with(
            support.collection(),
            archive_bm25::ArchiveBlockTextBm25Mapping,
            crate::collection_names::private_policy(authority),
        )
        .context("register Archive BM25 derivation")?;
    let maintained = pile
        .maintain_exact_with::<archive_bm25::ArchiveBlockTextBm25Mapping>(target, support)
        .await
        .context("maintain exact Archive BM25 cover")?;
    let attached = maintained
        .collection_exact(target, support)
        .context("attach exact Archive BM25 cover")?;
    let index = attached
        .view::<archive_bm25::ArchiveBM25Index>()
        .context("read exact Archive BM25 cover")?;
    Ok(EnsuredBm25 {
        report: Bm25IndexReport {
            source_elements: support.len(),
            cover_segments: attached.cover().len(),
            source_collection: support.collection().handle(),
            target_collection: target.handle(),
        },
        index,
    })
}

pub async fn ensure_bm25_index(
    pile_path: &std::path::Path,
    key_path: Option<&std::path::Path>,
) -> Result<Bm25IndexReport> {
    let (mut pile, collections, signer) = open_local(pile_path, key_path)?;
    let result = async {
        let observed = ensure_facts(&mut pile, collections).await?;
        Ok(
            ensure_bm25_exact(&mut pile, observed.support(), signer.verifying_key())
                .await?
                .report,
        )
    }
    .await;
    close_pile(pile, result, "closing Archive pile after BM25 derivation")
}

/// Prepare fact and search values for the same exact support. The returned
/// collection snapshot exposes the usual fact view and blob reader; callers
/// query BM25 and join document ids to whatever facts their operation needs.
pub async fn ensure_search_local(
    pile_path: &std::path::Path,
    key_path: Option<&std::path::Path>,
) -> Result<(
    CollectionSnapshot<PileSnapshot, Rank9AcceleratedSuccinctArchiveBlob>,
    archive_bm25::ArchiveBM25Index,
)> {
    let (mut pile, collections, signer) = open_local(pile_path, key_path)?;
    let result = async {
        let observed = ensure_facts(&mut pile, collections).await?;
        let ensured =
            ensure_bm25_exact(&mut pile, observed.support(), signer.verifying_key()).await?;
        // Search maintenance may have acquired referenced text payloads. Attach
        // the fact view through the final reader while retaining exact support.
        let after = pile
            .snapshot()
            .context("freeze prepared Archive search snapshot")?;
        let observed = after
            .collection_exact(collections.rank9(), observed.support())
            .context("reattach exact Archive search facts")?;
        Ok((observed, ensured.index))
    }
    .await;
    close_pile(
        pile,
        result,
        "closing Archive pile after BM25 search preparation",
    )
}

/// Stream the byte geometry selected by one source snapshot. Only lightweight
/// chunk coordinates are sorted; each payload is fetched and hash-checked on
/// demand. Geometry errors affect this export, never ordinary archive reads.
///
/// The queried entity ids are opaque. Equal offset/handle rows deduplicate even
/// when different chunk ids witness them, and unrelated annotations are inert.
pub fn write_source_snapshot<P, R, W>(
    facts: &P,
    reader: &R,
    id: Id,
    destination: &mut W,
) -> Result<u128>
where
    P: TriblePattern,
    R: BlobStoreGet,
    W: std::io::Write,
{
    let lengths: BTreeSet<u128> = find!(
        length: u128,
        pattern!(facts, [{
            id @ metadata::tag: &schema::source_snapshot::KIND,
            schema::source_snapshot::byte_length: ?length
        }])
    )
    .collect();
    if lengths.is_empty() {
        bail!("Archive source snapshot {id:X} has no readable byte length");
    }
    let chunks: BTreeSet<(u128, RawHandle)> = find!(
        (offset: u128, bytes: RawHandle),
        pattern!(facts, [
            { id @ schema::source_snapshot::contains: _?chunk },
            { _?chunk @ schema::source_chunk::offset: ?offset,
                schema::source_chunk::bytes: ?bytes },
        ])
    )
    .collect();
    let mut written = 0u128;
    for (offset, handle) in chunks {
        if offset != written {
            bail!("Archive source snapshot {id:X} has a chunk at {offset}, expected {written}");
        }
        let bytes: Bytes = reader.get(handle).context("read Archive source chunk")?;
        destination
            .write_all(bytes.as_ref())
            .with_context(|| format!("write Archive source snapshot {id:X}"))?;
        written = written
            .checked_add(bytes.len() as u128)
            .ok_or_else(|| anyhow!("Archive source snapshot {id:X} length overflows u128"))?;
    }
    if !lengths.contains(&written) {
        bail!("Archive source snapshot {id:X} yielded {written} bytes, outside its stated lengths");
    }
    Ok(written)
}

/// Exact continuation point for the causal-temporal view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveTimelineCursor {
    AfterTime(i128),
    AfterBlock(Id),
}

/// One positioned identity, not a decoded domain object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveTimelineBlock {
    pub position: i128,
    pub block: Id,
}

impl ArchiveTimelineBlock {
    pub const fn cursor(&self) -> ArchiveTimelineCursor {
        ArchiveTimelineCursor::AfterBlock(self.block)
    }
}

/// Position canonical blocks in deterministic causal order. Timestamp
/// annotations may have several values: the earliest canonical timestamp wins,
/// falling back to the earliest source timestamp. Untimed nodes carry causal
/// position but emit nothing. Inclusion policy belongs to the caller after
/// positioning, so filtering cannot change cursor or predecessor semantics.
pub fn timeline_after<P>(
    facts: &P,
    cursor: ArchiveTimelineCursor,
) -> Result<Vec<ArchiveTimelineBlock>>
where
    P: TriblePattern,
{
    let blocks: BTreeSet<Id> = find!(
        block: Id,
        pattern!(facts, [{ ?block @ metadata::tag: &schema::block::KIND }])
    )
    .collect();
    let mut canonical_timestamps = BTreeMap::<Id, i128>::new();
    for (block, (lower, _)) in find!(
        (block: Id, timestamp: (i128, i128)),
        pattern!(facts, [{ ?block @ schema::block::timestamp: ?timestamp }])
    ) {
        canonical_timestamps
            .entry(block)
            .and_modify(|current| *current = (*current).min(lower))
            .or_insert(lower);
    }
    let mut receipt_timestamps = BTreeMap::<Id, i128>::new();
    for (block, (lower, _)) in find!(
        (block: Id, timestamp: (i128, i128)),
        pattern!(facts, [{
            _?projection @ schema::source_projection::projects_to: ?block,
            schema::source_projection::source_timestamp: ?timestamp
        }])
    ) {
        receipt_timestamps
            .entry(block)
            .and_modify(|current| *current = (*current).min(lower))
            .or_insert(lower);
    }
    let mut timestamps = BTreeMap::new();
    let mut predecessors = BTreeMap::<Id, BTreeSet<Id>>::new();
    let mut successors = BTreeMap::<Id, BTreeSet<Id>>::new();
    for block in &blocks {
        timestamps.insert(
            *block,
            canonical_timestamps
                .get(block)
                .or_else(|| receipt_timestamps.get(block))
                .copied(),
        );
        let previous: BTreeSet<_> = find!(
            predecessor: Id,
            pattern!(facts, [{ block @ schema::block::previous: ?predecessor }])
        )
        .collect();
        for predecessor in &previous {
            successors.entry(*predecessor).or_default().insert(*block);
        }
        predecessors.insert(*block, previous);
    }
    let mut remaining: BTreeMap<Id, usize> = predecessors
        .iter()
        .map(|(block, previous)| (*block, previous.len()))
        .collect();
    let mut inherited = BTreeMap::<Id, Option<i128>>::new();
    let mut ready_untimed = BTreeSet::new();
    let mut ready_timed = BTreeSet::new();
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
    let mut positioned = Vec::new();
    let mut visited = 0usize;
    while visited < blocks.len() {
        let (block, position, emits) = if let Some(block) = ready_untimed.pop_first() {
            (block, inherited[&block], false)
        } else if let Some((position, block)) = ready_timed.pop_first() {
            (block, Some(position), true)
        } else {
            bail!("Archive timeline has an incomplete or cyclic predecessor graph");
        };
        visited += 1;
        if let Some(position) = position.filter(|_| emits) {
            positioned.push(ArchiveTimelineBlock { position, block });
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
            positioned.partition_point(|candidate| candidate.position <= position)
        }
        ArchiveTimelineCursor::AfterBlock(anchor) => positioned
            .iter()
            .position(|candidate| candidate.block == anchor)
            .map(|index| index + 1)
            .ok_or_else(|| {
                anyhow!("Archive timeline cursor block {anchor:X} is absent or has no timestamp")
            })?,
    };
    Ok(positioned.into_iter().skip(start).collect())
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
            .derive_with(
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
    use crate::schemas::files as files_schema;
    use anybytes::View;
    use triblespace::prelude::blobencodings::UTF8String;
    use triblespace::prelude::inlineencodings::NsTAIInterval;
    use triblespace_search::tokens::hash_tokens;

    fn projection_ids(facts: &FactArchive) -> Vec<Id> {
        find!(
            projection: Id,
            pattern!(facts, [{ ?projection @ metadata::tag: &schema::source_projection::KIND }])
        )
        .collect()
    }
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
        let mut writer = pollster::block_on(ArchiveImportWriter::open(pile, Some(key))).unwrap();
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
        let mut writer = pollster::block_on(ArchiveImportWriter::open(&pile, Some(&key))).unwrap();
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
        let before = pollster::block_on(ensure_local(&pile, Some(&key))).unwrap();
        assert!(before.support().is_empty());
        assert!(before
            .view::<FactArchive>()
            .unwrap()
            .iter()
            .next()
            .is_none());
        drop(before);

        let commit = writer.finish(Ok(())).unwrap().1.unwrap();
        let after = pollster::block_on(ensure_local(&pile, Some(&key))).unwrap();
        assert_eq!(after.support().len(), 1);
        assert!(after
            .support()
            .contains(Handle::<SimpleArchive>::from_hash(commit.data())));
        assert_eq!(
            projection_ids(&after.view::<FactArchive>().unwrap()).len(),
            1
        );
    }

    #[test]
    fn source_failure_closes_without_publishing_a_collection_commit() {
        let directory = TempDir::new().unwrap();
        let pile = directory.path().join("archive.pile");
        std::fs::File::create(&pile).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile, &key);

        let fragment = projection("session:aborted", "unreachable after source failure");
        let embedded = first_embedded_handle(&fragment);

        let mut writer = pollster::block_on(ArchiveImportWriter::open(&pile, Some(&key))).unwrap();
        writer.stage_fragment(fragment).unwrap();
        let error = writer
            .finish::<()>(Err(anyhow!("source projection failed")))
            .unwrap_err();
        assert_eq!(error.to_string(), "source projection failed");

        // `finish` closed the writer even on source failure. Reopening is
        // sound, no semantic edge escaped, and the dependency is merely an
        // unreachable content-addressed record available for later GC.
        let snapshot = pollster::block_on(ensure_local(&pile, Some(&key))).unwrap();
        assert!(snapshot.support().is_empty());
        assert!(snapshot
            .view::<FactArchive>()
            .unwrap()
            .iter()
            .next()
            .is_none());
        drop(snapshot);
        let mut physical = open_pile_strict(&pile).unwrap();
        let reader = physical.snapshot().unwrap();
        let _: Blob<UnknownBlob> = reader.get(embedded).unwrap();
        drop(reader);
        physical.close().unwrap();
    }

    #[test]
    fn writer_publishes_opaque_annotations_and_multiple_bodies_idempotently() {
        let directory = TempDir::new().unwrap();
        let pile = directory.path().join("archive.pile");
        std::fs::File::create(&pile).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile, &key);

        let fact = fucid();
        let annotation_kind = fucid();
        let fragment = entity! { &fact @
            metadata::tag*: [&schema::content_fact::KIND, &annotation_kind.id],
            metadata::name*: ["first annotation", "second annotation"],
            schema::content_fact::modality: &schema::content_fact::modality::TEXT,
            schema::content_fact::direction: &schema::content_fact::direction::IN,
            schema::content_fact::payload*: ["first body", "second body"],
        };
        let annotation = entity! { &fact @
            metadata::name: "later annotation",
        };

        let mut writer = pollster::block_on(ArchiveImportWriter::open(&pile, Some(&key))).unwrap();
        writer.stage_fragment(fragment.clone()).unwrap();
        assert!(writer.commit_unit().unwrap().is_some());
        writer.stage_fragment(fragment.clone()).unwrap();
        assert_eq!(writer.delta_len(), 0);
        assert!(writer.commit_unit().unwrap().is_none());
        writer.stage_fragment(annotation.clone()).unwrap();
        assert!(writer.finish(Ok(())).unwrap().1.is_some());

        let snapshot = pollster::block_on(ensure_local(&pile, Some(&key))).unwrap();
        assert_eq!(snapshot.support().len(), 2);
        let facts = snapshot.view::<FactArchive>().unwrap();
        let tags: BTreeSet<_> = find!(
            tag: Id,
            pattern!(&facts, [{ fact.id @ metadata::tag: ?tag }])
        )
        .collect();
        assert_eq!(
            tags,
            BTreeSet::from([schema::content_fact::KIND, annotation_kind.id])
        );
        let names: BTreeSet<_> = find!(
            name: Inline<Handle<UTF8String>>,
            pattern!(&facts, [{ fact.id @ metadata::name: ?name }])
        )
        .map(|handle| {
            let name: View<str> = snapshot.snapshot().get(handle).unwrap();
            name.to_string()
        })
        .collect();
        assert_eq!(
            names,
            BTreeSet::from([
                "first annotation".to_owned(),
                "second annotation".to_owned(),
                "later annotation".to_owned(),
            ])
        );
        let bodies: BTreeSet<_> = find!(
            payload: Inline<Handle<UTF8String>>,
            pattern!(&facts, [{ fact.id @ schema::content_fact::payload: ?payload }])
        )
        .map(|handle| {
            let body: View<str> = snapshot.snapshot().get(handle).unwrap();
            body.to_string()
        })
        .collect();
        assert_eq!(
            bodies,
            BTreeSet::from(["first body".to_owned(), "second body".to_owned()])
        );
        drop(facts);
        drop(snapshot);

        let mut retry = pollster::block_on(ArchiveImportWriter::open(&pile, Some(&key))).unwrap();
        retry.stage_fragment(fragment).unwrap();
        retry.stage_fragment(annotation).unwrap();
        assert_eq!(retry.delta_len(), 0);
        assert!(retry.finish(Ok(())).unwrap().1.is_none());
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
        let mut writer = pollster::block_on(ArchiveImportWriter::open(&pile, Some(&key))).unwrap();
        writer.stage_fragment(fragment.clone()).unwrap();
        let (_, first) = writer.finish(Ok(())).unwrap();
        let first = first.unwrap();
        let mut retry = pollster::block_on(ArchiveImportWriter::open(&pile, Some(&key))).unwrap();
        let length = std::fs::metadata(&pile).unwrap().len();
        retry.stage_fragment(fragment).unwrap();
        let (_, repeated) = retry.finish(Ok(())).unwrap();
        assert_eq!(repeated, None);
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), length);

        let snapshot = pollster::block_on(ensure_local(&pile, Some(&key))).unwrap();
        assert_eq!(snapshot.support().len(), 1);
        assert!(snapshot
            .support()
            .contains(Handle::<SimpleArchive>::from_hash(first.data())));
        assert_eq!(
            projection_ids(&snapshot.view::<FactArchive>().unwrap()).len(),
            1
        );
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

        let snapshot = pollster::block_on(ensure_local(&pile_path, Some(&key_path))).unwrap();
        assert_eq!(snapshot.support().len(), 1);
        assert!(snapshot
            .support()
            .contains(Handle::<SimpleArchive>::from_hash(admitted.data())));
        assert_eq!(
            projection_ids(&snapshot.view::<FactArchive>().unwrap()).len(),
            1
        );
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
        let mut writer = pollster::block_on(ArchiveImportWriter::open(&pile, Some(&key))).unwrap();
        writer.stage_fragment(fragment).unwrap();
        writer.finish(Ok(())).unwrap();

        let archive = pollster::block_on(ensure_local(&pile, Some(&key))).unwrap();
        let facts = archive.view::<FactArchive>().unwrap();
        let snapshots: BTreeSet<_> = find!(
            snapshot: Id,
            pattern!(&facts, [{ ?snapshot @ metadata::tag: &schema::source_snapshot::KIND }])
        )
        .collect();
        assert_eq!(snapshots, BTreeSet::from([expected]));
        let (namespace, locator, length, path) = find!(
            (namespace: Id, locator: Inline<Handle<UTF8String>>, length: u128,
                path: Inline<Handle<UTF8String>>),
            pattern!(&facts, [{
                expected @ schema::source_projection::source_namespace: ?namespace,
                schema::source_projection::source_locator: ?locator,
                schema::source_snapshot::byte_length: ?length,
                files_schema::file::source_path: ?path
            }])
        )
        .next()
        .unwrap();
        assert_eq!(namespace, schema::source_projection::SOURCE_CODEX);
        assert_eq!(length, source.len() as u128);
        let locator: View<str> = archive.snapshot().get(locator).unwrap();
        let path: View<str> = archive.snapshot().get(path).unwrap();
        assert_eq!(locator.as_ref(), "snapshot/v1/session:exact");
        assert_eq!(path.as_ref(), "/moved/rollout.jsonl");
        let chunks: Vec<_> = find!(
            (offset: u128, bytes: RawHandle),
            pattern!(&facts, [
                { expected @ schema::source_snapshot::contains: _?chunk },
                { _?chunk @ schema::source_chunk::offset: ?offset,
                    schema::source_chunk::bytes: ?bytes },
            ])
        )
        .collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].0, 0);
        let mut reconstructed = Vec::new();
        assert_eq!(
            write_source_snapshot(&facts, archive.snapshot(), expected, &mut reconstructed)
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
        let mut first_writer =
            pollster::block_on(ArchiveImportWriter::open(&pile, Some(&key))).unwrap();
        first_writer.stage_fragment(first_fragment.clone()).unwrap();
        let first = first_writer.finish(Ok(())).unwrap().1.unwrap();

        let second_fragment = projection("session:two", "shared");
        let mut second_writer =
            pollster::block_on(ArchiveImportWriter::open(&pile, Some(&key))).unwrap();
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

        let snapshot = pollster::block_on(ensure_local(&pile, Some(&key))).unwrap();
        assert_eq!(snapshot.support().len(), 2);
        assert_eq!(
            projection_ids(&snapshot.view::<FactArchive>().unwrap()).len(),
            2
        );
        assert!(snapshot.view::<FactArchive>().unwrap().iter().count() > first_len);
    }

    #[test]
    fn zero_commit_search_uses_the_canonical_empty_resident_index() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile_path, &key);

        let report = pollster::block_on(ensure_bm25_index(&pile_path, Some(&key))).unwrap();
        assert_eq!((report.source_elements, report.cover_segments), (0, 0));

        let search = pollster::block_on(ensure_search_local(&pile_path, Some(&key))).unwrap();
        assert!(search.0.support().is_empty());
        assert!(search.1.query_multi(&hash_tokens("anything")).is_empty());
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

        let succinct = pollster::block_on(ensure_succinct_index(&pile_path, Some(&key))).unwrap();
        let bm25 = pollster::block_on(ensure_bm25_index(&pile_path, Some(&key))).unwrap();
        assert_eq!(succinct.source_elements, 1);
        assert_eq!((bm25.source_elements, bm25.cover_segments), (1, 1));

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

        let snapshot = pollster::block_on(ensure_local(&pile_path, Some(&key))).unwrap();
        assert_eq!(snapshot.support().len(), 1);
        assert!(snapshot
            .support()
            .contains(Handle::<SimpleArchive>::from_hash(commit.data())));
        assert!(projection_ids(&snapshot.view::<FactArchive>().unwrap()).is_empty());
        drop(snapshot);
        let search = pollster::block_on(ensure_search_local(&pile_path, Some(&key))).unwrap();
        assert!(search.1.query_multi(&hash_tokens("anything")).is_empty());
    }

    #[test]
    fn timeline_is_pure_and_leaves_inclusion_policy_to_the_caller() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile_path, &key);

        let mut writer =
            pollster::block_on(ArchiveImportWriter::open(&pile_path, Some(&key))).unwrap();
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

        let snapshot = pollster::block_on(ensure_local(&pile_path, Some(&key))).unwrap();
        let facts = snapshot.view::<FactArchive>().unwrap();
        let complete = timeline_after(&facts, ArchiveTimelineCursor::AfterTime(i128::MIN)).unwrap();
        assert_eq!(complete.len(), 2);
        assert!(complete[0].position < complete[1].position);
        let dialogue: Vec<_> = complete
            .iter()
            .filter(|item| {
                exists!(pattern!(&facts, [
                    { item.block @ schema::block::contains: _?part },
                    { _?part @ schema::content_part::fact: _?fact },
                    { _?fact @ schema::content_fact::modality:
                        &schema::content_fact::modality::TEXT },
                ]))
            })
            .collect();
        assert_eq!(dialogue.len(), 1);
        assert_eq!(dialogue[0].block, complete[0].block);
        let after_first = timeline_after(&facts, complete[0].cursor()).unwrap();
        assert_eq!(after_first.len(), 1);
        assert_eq!(after_first[0].block, complete[1].block);
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

        let mut writer =
            pollster::block_on(ArchiveImportWriter::open(&pile_path, Some(&key))).unwrap();
        // Deliberately stage out of causal and temporal order. The collection
        // is a set; replay order must come solely from canonical semantics.
        writer.stage_fragment(regressed_child).unwrap();
        writer.stage_fragment(independent).unwrap();
        writer.stage_fragment(untimed).unwrap();
        writer.stage_fragment(parent).unwrap();
        writer.finish(Ok(())).unwrap();

        let snapshot = pollster::block_on(ensure_local(&pile_path, Some(&key))).unwrap();
        let facts = snapshot.view::<FactArchive>().unwrap();
        let timeline = timeline_after(&facts, ArchiveTimelineCursor::AfterTime(i128::MIN)).unwrap();
        assert_eq!(timeline.len(), 3, "the untimed conduit stays invisible");
        assert_eq!(timeline[0].block, independent_id);
        assert_eq!(timeline[1].block, parent_id);
        assert_eq!(timeline[2].block, child_id);
        assert!(timeline[0].position < timeline[1].position);
        assert_eq!(
            timeline[1].position, timeline[2].position,
            "the regressed child is lifted to its predecessor's position"
        );

        let after_parent = timeline_after(&facts, timeline[1].cursor()).unwrap();
        assert_eq!(after_parent.len(), 1);
        assert_eq!(after_parent[0].block, child_id);
        assert!(
            timeline_after(&facts, ArchiveTimelineCursor::AfterBlock(untimed_id))
                .unwrap_err()
                .to_string()
                .contains("absent or has no timestamp")
        );
    }

    #[test]
    fn succinct_index_persists_an_exact_validated_v4_derive() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile_path, &key);

        let mut writer =
            pollster::block_on(ArchiveImportWriter::open(&pile_path, Some(&key))).unwrap();
        writer
            .stage_fragment(projection("session:index", "exact succinct"))
            .unwrap();
        writer.finish(Ok(())).unwrap();

        let report = pollster::block_on(ensure_succinct_index(&pile_path, Some(&key))).unwrap();

        assert_eq!(report.source_elements, 1);
        let length = std::fs::metadata(&pile_path).unwrap().len();
        assert_eq!(
            pollster::block_on(ensure_succinct_index(&pile_path, Some(&key))).unwrap(),
            report
        );
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), length);

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let authority = load_signer(&pile_path, Some(&key)).unwrap().verifying_key();
        let source = test_source(&mut pile, &pile_path, &key);
        let raw_target = pile
            .derive::<SuccinctArchiveBlob>(
                source,
                (),
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
        let expected =
            <SuccinctArchiveBlob as CollectionDerivation>::map(&(), &input, &reader).unwrap();
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
            let mut writer =
                pollster::block_on(ArchiveImportWriter::open(&pile_path, Some(&key))).unwrap();
            writer.stage_fragment(projection(locator, text)).unwrap();
            writer.finish(Ok(())).unwrap();
        }

        let report = pollster::block_on(ensure_bm25_index(&pile_path, Some(&key))).unwrap();

        assert_eq!(report.source_elements, 2);
        assert_eq!(report.cover_segments, 1);
        let length = std::fs::metadata(&pile_path).unwrap().len();
        assert_eq!(
            pollster::block_on(ensure_bm25_index(&pile_path, Some(&key))).unwrap(),
            report
        );
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
        let source_support = store_snapshot.collection(source).unwrap().support().clone();
        let attached = store_snapshot
            .collection_exact(target, &source_support)
            .unwrap();
        assert_eq!(attached.cover().len(), 1);
        pile.close().unwrap();

        let search = pollster::block_on(ensure_search_local(&pile_path, Some(&key))).unwrap();
        assert_eq!(search.1.query_multi(&hash_tokens("alpha")).len(), 1);
        assert_eq!(search.1.query_multi(&hash_tokens("beta")).len(), 1);
    }

    #[test]
    fn bm25_collapses_repeated_content_to_its_canonical_block() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile_path, &key);

        for (locator, seconds) in [("session:first", 1.0), ("session:second", 2.0)] {
            let mut writer =
                pollster::block_on(ArchiveImportWriter::open(&pile_path, Some(&key))).unwrap();
            writer
                .stage_fragment(projection_at(locator, "shared closure needle", seconds))
                .unwrap();
            writer.finish(Ok(())).unwrap();
        }

        let report = pollster::block_on(ensure_bm25_index(&pile_path, Some(&key))).unwrap();
        assert_eq!(report.source_elements, 2);
        let search = pollster::block_on(ensure_search_local(&pile_path, Some(&key))).unwrap();
        let hits = search.1.query_multi(&hash_tokens("shared closure needle"));
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
        let mut writer =
            pollster::block_on(ArchiveImportWriter::open(&pile_path, Some(&key))).unwrap();
        writer.stage_fragment(first_fragment).unwrap();
        writer.finish(Ok(())).unwrap();
        let first = pollster::block_on(ensure_search_local(&pile_path, Some(&key))).unwrap();
        assert_eq!(first.1.query_multi(&hash_tokens("alpha")).len(), 1);
        drop(first);

        let second_fragment = projection("session:second", "beta βeta 🛰️");
        let mut writer =
            pollster::block_on(ArchiveImportWriter::open(&pile_path, Some(&key))).unwrap();
        writer.stage_fragment(second_fragment.clone()).unwrap();
        writer.finish(Ok(())).unwrap();

        let extended = pollster::block_on(ensure_search_local(&pile_path, Some(&key))).unwrap();
        assert_eq!(extended.1.query_multi(&hash_tokens("alpha")).len(), 1);
        assert_eq!(extended.1.query_multi(&hash_tokens("beta")).len(), 1);
        assert_eq!(extended.1.query_multi(&hash_tokens("🛰️")).len(), 1);
        drop(extended);

        let before = std::fs::metadata(&pile_path).unwrap().len();
        let mut retry =
            pollster::block_on(ArchiveImportWriter::open(&pile_path, Some(&key))).unwrap();
        retry.stage_fragment(second_fragment).unwrap();
        retry.finish(Ok(())).unwrap();
        let after_retry = pollster::block_on(ensure_search_local(&pile_path, Some(&key))).unwrap();
        assert_eq!(after_retry.1.query_multi(&hash_tokens("beta")).len(), 1);
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

        let archive = pollster::block_on(ensure_local(&pile_path, Some(&key))).unwrap();
        assert_eq!(archive.support().len(), 2);
        assert_eq!(
            projection_ids(&archive.view::<FactArchive>().unwrap()).len(),
            1
        );
        drop(archive);
        let before = std::fs::metadata(&pile_path).unwrap().len();

        let error = pollster::block_on(ensure_bm25_index(&pile_path, Some(&key))).unwrap_err();
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

        let search = pollster::block_on(ensure_search_local(&pile_path, Some(&key))).unwrap();
        let hits = search.1.query_multi(&hash_tokens("routed needle"));
        assert_eq!(hits.len(), 1);
        let projections = projection_ids(&search.0.view::<FactArchive>().unwrap());
        assert_eq!(projections.len(), 1);
        let facts = search.0.view::<FactArchive>().unwrap();
        let block = Id::try_from_inline(&hits[0].0).unwrap();
        let found: Vec<_> = find!(
            projection: Id,
            pattern!(&facts, [{
                ?projection @ schema::source_projection::projects_to: block
            }])
        )
        .collect();
        assert_eq!(found, projections);
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
        let frozen = pollster::block_on(ensure_local(&pile_path, Some(&key))).unwrap();
        let later = commit_projection(&pile_path, &key, "session:later", "later needle");

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let ensured = pollster::block_on(ensure_bm25_exact(
            &mut pile,
            frozen.support(),
            test_authority(&pile_path, &key),
        ))
        .unwrap();

        assert_eq!(ensured.report.source_elements, 1);
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
        let first_archive = pollster::block_on(ensure_local(&pile_path, Some(&key))).unwrap();
        let first_support = first_archive.support().clone();
        drop(first_archive);
        commit_projection(&pile_path, &key, "session:second", "second residual");
        let archive = pollster::block_on(ensure_local(&pile_path, Some(&key))).unwrap();
        let full_support = archive.support().clone();
        drop(archive);

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let source = test_source(&mut pile, &pile_path, &key);
        let target = test_target(&mut pile, source, &pile_path, &key);
        let first_snapshot = pollster::block_on(
            pile.maintain_exact_with::<archive_bm25::ArchiveBlockTextBm25Mapping>(
                target,
                &first_support,
            ),
        )
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

        let full_snapshot = pollster::block_on(
            pile.maintain_exact_with::<archive_bm25::ArchiveBlockTextBm25Mapping>(
                target,
                &full_support,
            ),
        )
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
        let retry_snapshot = pollster::block_on(
            pile.maintain_exact_with::<archive_bm25::ArchiveBlockTextBm25Mapping>(
                target,
                &full_support,
            ),
        )
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
        let source_support = store_snapshot.collection(source).unwrap().support().clone();
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

        let ready_snapshot = pollster::block_on(
            pile.maintain_exact_with::<archive_bm25::ArchiveBlockTextBm25Mapping>(
                target,
                &source_support,
            ),
        )
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
    #[test]
    fn exact_fact_cover_and_raw_export_need_no_outer_commits() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("archive.pile");
        std::fs::File::create(&pile_path).unwrap();
        let key = directory.path().join("archive.key");
        initialize_archive_fixture(&pile_path, &key);

        // Chunk and snapshot ids are deliberately extrinsic. Two different
        // witnesses of identical byte geometry must not duplicate the output.
        let chunk_a = fucid();
        let chunk_b = fucid();
        let snapshot_id = fucid();
        let block = fucid();
        let timestamp = crate::clock::point(hifitime::Epoch::from_tai_duration(
            hifitime::Duration::from_total_nanoseconds(1),
        ))
        .unwrap();
        let mut fragment = entity! { &chunk_a @
            schema::source_chunk::offset: 0u128,
            schema::source_chunk::bytes: b"raw".to_vec(),
        };
        fragment += entity! { &chunk_b @
            schema::source_chunk::offset: 0u128,
            schema::source_chunk::bytes: b"raw".to_vec(),
        };
        fragment += entity! { &snapshot_id @
            metadata::tag: &schema::source_snapshot::KIND,
            metadata::name*: ["first annotation", "another annotation"],
            schema::source_snapshot::byte_length*: [3u128, 9u128],
            schema::source_snapshot::contains*: [&chunk_a, &chunk_b],
        };
        fragment += entity! { &block @
            metadata::tag: &schema::block::KIND,
            schema::block::timestamp: timestamp,
        };

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let source = test_source(&mut pile, &pile_path, &key);
        let collections = FactCollection::new(&mut pile, source).unwrap();
        let (_, facts, _metadata, blobs) = fragment.into_parts();
        stage_embedded_blobs(&mut pile, embedded_blobs(blobs)).unwrap();
        let data = pile.put::<SimpleArchive, _>(facts).unwrap();
        let support = source.cover([data]);
        let after = pollster::block_on(collections.maintain_exact(&mut pile, &support)).unwrap();
        let observed = after
            .collection_exact(collections.rank9(), &support)
            .unwrap();
        assert!(observed
            .support()
            .commits(observed.snapshot())
            .unwrap()
            .is_empty());
        let facts = observed.view::<FactArchive>().unwrap();
        let mut output = Vec::new();
        assert_eq!(
            write_source_snapshot(&facts, observed.snapshot(), snapshot_id.id, &mut output)
                .unwrap(),
            3,
        );
        assert_eq!(output, b"raw");
        let timeline = timeline_after(&facts, ArchiveTimelineCursor::AfterTime(i128::MIN)).unwrap();
        assert_eq!(
            timeline,
            [ArchiveTimelineBlock {
                position: 1,
                block: block.id
            }]
        );
        pile.close().unwrap();
    }

    #[test]
    fn export_geometry_failure_does_not_reject_other_fact_queries() {
        let source = fucid();
        let chunk = fucid();
        let mut fragment = entity! { &chunk @
            schema::source_chunk::offset: 1u128,
            schema::source_chunk::bytes: b"gap".to_vec(),
        };
        fragment += entity! { &source @
            metadata::tag: &schema::source_snapshot::KIND,
            schema::source_snapshot::contains: &chunk,
            schema::source_snapshot::byte_length: 3u128,
            metadata::name: "still queryable",
        };
        let reader = fragment.blobs().clone().snapshot().unwrap();
        let names: Vec<_> = find!(
            name: Inline<Handle<UTF8String>>,
            pattern!(fragment.facts(), [{ source.id @ metadata::name: ?name }])
        )
        .collect();
        assert_eq!(names.len(), 1);
        let error = write_source_snapshot(fragment.facts(), &reader, source.id, &mut Vec::new())
            .unwrap_err();
        assert!(error.to_string().contains("expected 0"));
    }

    #[test]
    fn timeline_uses_all_timestamp_annotations_without_scalar_validation() {
        let block = fucid();
        let later = crate::clock::point(hifitime::Epoch::from_tai_duration(
            hifitime::Duration::from_total_nanoseconds(9),
        ))
        .unwrap();
        let earlier = crate::clock::point(hifitime::Epoch::from_tai_duration(
            hifitime::Duration::from_total_nanoseconds(4),
        ))
        .unwrap();
        let fragment = entity! { &block @
            metadata::tag: &schema::block::KIND,
            schema::block::timestamp*: [later, earlier],
            metadata::name*: ["one", "two"],
        };
        let timeline = timeline_after(
            fragment.facts(),
            ArchiveTimelineCursor::AfterTime(i128::MIN),
        )
        .unwrap();
        assert_eq!(
            timeline,
            [ArchiveTimelineBlock {
                position: 4,
                block: block.id
            }]
        );
    }
}
