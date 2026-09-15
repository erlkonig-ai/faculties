//! Collection registration, publication, and maintained reads for Secrets.
//!
//! This module deliberately has no vault registry or access inbox. Callers
//! configure the collection descriptors they use. Authorization evidence is
//! interpreted by TribleSpace; Secrets consumes the audience of the immutable
//! resource pinned by each envelope. Collection READ governs encrypted-evidence
//! replication, never key delivery. Historical envelopes remain decryptable;
//! they do not implicitly acquire a new resource or a new delivery authority.

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::{
    Collection, CollectionHandle, CollectionPolicy, CollectionRealizationError,
    CollectionSnapshotExt, CollectionStoreExt, Support,
};
use triblespace::core::repo::async_store::AsyncBlobStoreAcquire;
use triblespace::core::repo::SnapshotSource;
use triblespace::core::repo::{BlobStoreGet, CapabilityProofRead, Store, StoreRead, StoreSnapshot};
use triblespace::macros::{find, pattern};

use super::resource::SecretTarget;
use super::{IntervalValue, SecretsFacts, SecretsSnapshot};

/// One logical Secrets policy boundary and its ordinary maintained encodings.
///
/// The source is the only commit target. Succinct and Rank9 collections are
/// deterministic physical lattices derived from it; neither is a vault,
/// custody epoch, or authorization boundary of its own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretsCollection {
    source: Collection<SimpleArchive>,
    succinct: Collection<SuccinctArchiveBlob>,
    rank9: Collection<Rank9AcceleratedSuccinctArchiveBlob>,
}

impl SecretsCollection {
    /// Register the encrypted-evidence collection and its query encodings.
    pub fn register<S>(store: &mut S, name: &str, policy: CollectionPolicy) -> Result<Self>
    where
        S: CollectionStoreExt + SnapshotSource,
        S::Snapshot: BlobStoreGet,
    {
        let source = store
            .collection(name, policy)
            .map_err(|error| anyhow!("register Secrets source collection: {error}"))?;
        Self::from_source(store, source)
    }

    /// Attach the canonical maintained encodings above one existing source.
    ///
    /// The source descriptor remains the policy boundary and identity. The
    /// two derived descriptors inherit that exact immutable policy. Delivery
    /// policies belong to secret resources, so old source descriptors stay valid.
    pub fn from_source<S>(store: &mut S, source: Collection<SimpleArchive>) -> Result<Self>
    where
        S: CollectionStoreExt + SnapshotSource,
        S::Snapshot: BlobStoreGet,
    {
        let snapshot = store
            .snapshot()
            .context("freeze Secrets source descriptor snapshot")?;
        let policy = source
            .policy(&snapshot)
            .context("read Secrets source collection policy")?;
        drop(snapshot);
        let succinct = store
            .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
            .map_err(|error| anyhow!("register Succinct Secrets collection: {error}"))?;
        let rank9 = store
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
            .map_err(|error| anyhow!("register Rank9 Secrets collection: {error}"))?;
        Ok(Self {
            source,
            succinct,
            rank9,
        })
    }

    pub const fn source(self) -> Collection<SimpleArchive> {
        self.source
    }

    pub const fn handle(self) -> CollectionHandle {
        self.source.handle()
    }

    pub const fn succinct(self) -> Collection<SuccinctArchiveBlob> {
        self.succinct
    }

    pub const fn rank9(self) -> Collection<Rank9AcceleratedSuccinctArchiveBlob> {
        self.rank9
    }

    /// Ensure both physical encodings for one exact foundational support.
    ///
    /// This constructs only what the requested support needs. It does not run
    /// LSM compaction policy or widen the caller's explicit support.
    pub async fn ensure_exact<S>(
        self,
        store: &mut S,
        signer: &SigningKey,
        support: &triblespace::core::collection::Support,
    ) -> Result<S::Snapshot>
    where
        S: Store + CollectionStoreExt + AsyncBlobStoreAcquire + Send,
    {
        drop(
            store
                .ensure_exact(self.succinct, signer, support)
                .await
                .context("ensure Succinct Secrets collection")?,
        );
        store
            .ensure_exact(self.rank9, signer, support)
            .await
            .context("ensure Rank9 Secrets collection")
    }

    /// Realize missing support without reconstructing already endorsed inputs.
    pub async fn ensure<S>(self, store: &mut S, signer: &SigningKey) -> Result<S::Snapshot>
    where
        S: Store + CollectionStoreExt + AsyncBlobStoreAcquire + Send,
    {
        let before = store.snapshot().context("freeze Secrets work selection")?;
        let admitted = self
            .source
            .admitted(&before)
            .context("admit Secrets source support")?;
        let succinct = before
            .collection(self.succinct)
            .context("observe resident Succinct Secrets support")?
            .support()
            .clone();
        let rank9 = before
            .collection(self.rank9)
            .context("observe resident Rank9 Secrets support")?
            .support()
            .clone();
        let resident = succinct.union(&rank9)?;
        let missing = admitted.difference(&resident)?;
        let support = admitted.union(&resident)?;
        drop(before);

        // Existing coarse Succinct members remain whole even if part of their
        // support is already in Rank9. Only new root support needs this hop.
        if !missing.is_empty() {
            drop(
                store
                    .ensure_exact(self.succinct, signer, &missing)
                    .await
                    .context("ensure missing Succinct Secrets support")?,
            );
        }
        store
            .ensure_exact(self.rank9, signer, &support)
            .await
            .context("ensure Rank9 Secrets collection")
    }

    /// Maintain both derived lattices for one exact foundational support.
    pub async fn maintain_exact<S>(
        self,
        store: &mut S,
        signer: &SigningKey,
        support: &triblespace::core::collection::Support,
    ) -> Result<S::Snapshot>
    where
        S: Store + CollectionStoreExt + AsyncBlobStoreAcquire + Send,
    {
        drop(
            store
                .maintain_exact(self.succinct, signer, support)
                .await
                .context("maintain Succinct Secrets collection")?,
        );
        store
            .maintain_exact(self.rank9, signer, support)
            .await
            .context("maintain Rank9 Secrets collection")
    }

    /// Maintain resident and new support without demanding target-only ancestors.
    pub async fn maintain<S>(self, store: &mut S, signer: &SigningKey) -> Result<S::Snapshot>
    where
        S: Store + CollectionStoreExt + AsyncBlobStoreAcquire + Send,
    {
        let before = store.snapshot().context("freeze Secrets work selection")?;
        let admitted = self
            .source
            .admitted(&before)
            .context("admit Secrets source support")?;
        let succinct = before
            .collection(self.succinct)
            .context("observe resident Succinct Secrets support")?
            .support()
            .clone();
        let rank9 = before
            .collection(self.rank9)
            .context("observe resident Rank9 Secrets support")?
            .support()
            .clone();
        let resident = succinct.union(&rank9)?;
        let missing = admitted.difference(&resident)?;
        let source_work = succinct.union(&missing)?;
        let support = admitted.union(&resident)?;
        drop(before);

        if !source_work.is_empty() {
            drop(
                store
                    .maintain_exact(self.succinct, signer, &source_work)
                    .await
                    .context("maintain Succinct Secrets collection")?,
            );
        }
        store
            .maintain_exact(self.rank9, signer, &support)
            .await
            .context("maintain Rank9 Secrets collection")
    }
}

/// Attach the configured collection at one immutable store boundary.
///
/// This never performs maintenance. It reports exactly the support physically
/// realized in `snapshot`, preserving the snapshot/derivation boundary.
pub fn snapshot<R>(store_snapshot: R, collection: SecretsCollection) -> Result<SecretsSnapshot<R>>
where
    R: StoreRead,
{
    let observed = store_snapshot
        .collection(collection.rank9)
        .context("observe maintained Secrets collection")?;
    let support = observed.support().clone();
    let facts = if observed.cover().is_empty() {
        None
    } else {
        Some(
            observed
                .view::<SecretsFacts>()
                .context("read maintained Secrets collection")?,
        )
    };
    Ok(SecretsSnapshot::new(
        store_snapshot,
        collection.handle(),
        support,
        facts,
    ))
}

/// Attach the already-realized Rank9 collection to its exact frozen support.
///
/// Use this when the caller intentionally limits the result to an explicit
/// support. Ordinary reads use [`snapshot`] and reflect the actual returned
/// store snapshot, including other already-certified target members.
pub fn snapshot_exact<R>(
    store_snapshot: R,
    collection: SecretsCollection,
    support: Support,
) -> Result<SecretsSnapshot<R>>
where
    R: StoreRead,
{
    let observed = store_snapshot
        .collection_exact(collection.rank9, &support)
        .context("attach exact maintained Secrets collection")?;
    let support = observed.support().clone();
    let facts = if observed.cover().is_empty() {
        None
    } else {
        Some(
            observed
                .view::<SecretsFacts>()
                .context("read exact maintained Secrets collection")?,
        )
    };
    Ok(SecretsSnapshot::new(
        store_snapshot,
        collection.handle(),
        support,
        facts,
    ))
}

/// Maintain the configured collection, then attach its actual resulting snapshot.
pub async fn maintain_and_snapshot<S>(
    store: &mut S,
    collection: SecretsCollection,
    signer: &SigningKey,
) -> Result<SecretsSnapshot<S::Snapshot>>
where
    S: Store + CollectionStoreExt + AsyncBlobStoreAcquire + Send,
{
    let store_snapshot = collection.maintain(store, signer).await?;
    snapshot(store_snapshot, collection)
}

/// Ensure missing support, then read the actual resulting target snapshot.
///
/// Work is selected once from source admission and resident derived support.
/// It does not constrain the returned view to that old selection or require
/// ancestral proofs and payloads for already-certified target members. A reader
/// without authority to publish missing derivations still reads the available
/// target; other errors propagate. No opportunistic LSM compaction is performed.
pub async fn ensure_and_snapshot<S>(
    store: &mut S,
    collection: SecretsCollection,
    signer: &SigningKey,
) -> Result<SecretsSnapshot<S::Snapshot>>
where
    S: Store + CollectionStoreExt + AsyncBlobStoreAcquire + Send,
{
    let store_snapshot = match collection.ensure(store, signer).await {
        Ok(snapshot) => snapshot,
        Err(error)
            if matches!(
                error.downcast_ref::<CollectionRealizationError>(),
                Some(CollectionRealizationError::UnauthorizedProducer { .. })
            ) =>
        {
            store
                .snapshot()
                .context("freeze resident Secrets target after unavailable upkeep")?
        }
        Err(error) => return Err(error),
    };
    snapshot(store_snapshot, collection)
}

/// Publish one immutable version to the source collection.
///
/// The adding signer is the new resource's delivery root and first recipient.
/// Generic collection admission independently decides whether this commit is
/// in the view; authoring an envelope does not grant collection WRITE or READ.
pub fn add_secret<S>(
    store: &mut S,
    signing_key: &SigningKey,
    collection: SecretsCollection,
    name: &str,
    plaintext: &[u8],
    created_at: IntervalValue,
) -> Result<triblespace::core::id::Id>
where
    S: Store + CollectionStoreExt,
{
    let sealed = super::resource::seal_version(
        collection.handle(),
        signing_key,
        name,
        plaintext,
        created_at,
    )?;
    let secret = sealed.secret;
    store
        .commit(collection.source, signing_key, sealed.fragment)
        .map_err(|error| anyhow!("publish encrypted secret version: {error}"))?;
    Ok(secret)
}

/// Add missing envelopes across every secret in one policy boundary.
///
/// The supplied snapshot fixes both the secrets and self-contained key-delivery
/// proofs to inspect. Concurrent grants and secrets wait for the next additive
/// maintenance call.
pub fn maintain_recipient_envelopes<S, R>(
    store: &mut S,
    signing_key: &SigningKey,
    secrets: &SecretsSnapshot<R>,
    collection: SecretsCollection,
    holder: &SigningKey,
) -> Result<usize>
where
    S: Store + CollectionStoreExt,
    R: StoreSnapshot + BlobStoreGet + CapabilityProofRead,
{
    maintain_selected_recipient_envelopes(store, signing_key, secrets, collection, holder, &[])
}

/// Maintain only the selected versions/resources; an empty selection visits
/// every bound resource this holder can open. Other writers' secrets and legacy
/// unbound envelopes remain untouched rather than failing the whole pass.
pub fn maintain_selected_recipient_envelopes<S, R>(
    store: &mut S,
    signing_key: &SigningKey,
    secrets: &SecretsSnapshot<R>,
    collection: SecretsCollection,
    holder: &SigningKey,
    selected: &[SecretTarget],
) -> Result<usize>
where
    S: Store + CollectionStoreExt,
    R: StoreSnapshot + BlobStoreGet + CapabilityProofRead,
{
    if secrets.collection() != collection.handle() {
        bail!("Secrets snapshot belongs to a different collection");
    }
    let Some(facts) = secrets.facts() else {
        return Ok(0);
    };
    let secret_ids = find!(
        id: triblespace::core::id::Id,
        pattern!(facts, [{
            ?id @ triblespace::core::metadata::tag: super::schema::KIND_SECRET,
        }])
    )
    .collect::<std::collections::BTreeSet<_>>();
    let mut fragment = triblespace::core::trible::Fragment::empty();
    let mut count = 0usize;
    for secret in secret_ids {
        for binding in super::envelope::recover(secrets.store_snapshot(), facts, secret, holder)? {
            if !selected.is_empty()
                && !selected.iter().any(|target| match target {
                    SecretTarget::Secret(id) => *id == secret,
                    SecretTarget::Resource(handle) => *handle == binding.resource,
                })
            {
                continue;
            }
            let recipients = super::resource::recipients(
                secrets.store_snapshot(),
                collection.handle(),
                &binding,
            )?;
            let envelopes =
                super::envelope::missing(secrets.store_snapshot(), facts, &binding, recipients)?;
            count += envelopes.recipients.len();
            fragment += envelopes.fragment;
        }
    }
    if count == 0 {
        return Ok(0);
    }
    store
        .commit(collection.source, signing_key, fragment)
        .map_err(|error| anyhow!("publish additive recipient envelopes: {error}"))?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::convert::Infallible;

    use anybytes::Bytes;
    use dryoc::types::NewByteArray;
    use ed25519_dalek::VerifyingKey;
    use hifitime::Epoch;
    use rand_core::OsRng;
    use triblespace::core::blob::encodings::UnknownBlob;
    use triblespace::core::blob::{Blob, BlobEncoding, IntoBlob};
    use triblespace::core::capability::{CapabilityProof, CapabilityResource};
    use triblespace::core::collection::{
        grant_collection_capability, grant_collection_read, grant_collection_write,
        write_capability, AdmissionPolicy, CollectionCommit, CollectionData, CollectionPolicy,
        CollectionRead, CollectionRecord, CollectionStore,
    };
    use triblespace::core::inline::encodings::hash::Handle;
    use triblespace::core::inline::{Inline, InlineEncoding};
    use triblespace::core::metadata;
    use triblespace::core::repo::memoryrepo::{MemoryRepo, MemoryRepoSnapshot};
    use triblespace::core::repo::{
        BlobStoreList, BlobStorePut, CapabilityProofStore, SnapshotSource, WantRead,
    };
    use triblespace::prelude::TryToInline;

    use super::super::resource::{self, DeliveryLimits, SecretTarget};
    use super::super::{key_delivery_capability, seal_version};
    use super::*;

    fn at(second: i64) -> IntervalValue {
        let epoch = Epoch::from_unix_seconds(second as f64);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn direct_policy(key: VerifyingKey) -> CollectionPolicy {
        CollectionPolicy::new(AdmissionPolicy::direct(key), AdmissionPolicy::direct(key))
            .with_capability(
                super::super::key_delivery_definition(),
                AdmissionPolicy::direct(key),
            )
    }

    #[derive(Default)]
    struct AcquiringStore {
        inner: MemoryRepo,
        offered: BTreeMap<CollectionData, Bytes>,
        acquired: Vec<CollectionData>,
        inject_proof_on_derive: Option<CapabilityProof>,
    }

    impl AcquiringStore {
        fn offer<E>(&mut self, blob: &Blob<E>)
        where
            E: BlobEncoding,
            Handle<E>: InlineEncoding,
        {
            self.offered
                .insert(Handle::<E>::to_hash(blob.get_handle()), blob.bytes.clone());
        }
    }

    impl SnapshotSource for AcquiringStore {
        type Snapshot = MemoryRepoSnapshot;
        type SnapshotError = Infallible;

        fn snapshot_at(
            &mut self,
            instant: Epoch,
        ) -> std::result::Result<Self::Snapshot, Self::SnapshotError> {
            self.inner.snapshot_at(instant)
        }
    }

    impl BlobStorePut for AcquiringStore {
        type PutError = <MemoryRepo as BlobStorePut>::PutError;

        fn put<S, T>(&mut self, item: T) -> std::result::Result<Inline<Handle<S>>, Self::PutError>
        where
            S: BlobEncoding + 'static,
            T: IntoBlob<S>,
            Handle<S>: InlineEncoding,
        {
            self.inner.put(item)
        }
    }

    impl CollectionStore for AcquiringStore {
        type InsertError = <MemoryRepo as CollectionStore>::InsertError;

        fn insert(
            &mut self,
            record: CollectionRecord,
        ) -> std::result::Result<(), Self::InsertError> {
            self.inner.insert(record)?;
            if matches!(record, CollectionRecord::Derive(_)) {
                if let Some(proof) = self.inject_proof_on_derive.take() {
                    self.inner
                        .insert_proof(proof)
                        .expect("injected test proof has valid signed structure");
                }
            }
            Ok(())
        }
    }

    impl CapabilityProofStore for AcquiringStore {
        type InsertError = <MemoryRepo as CapabilityProofStore>::InsertError;

        fn insert_proof(
            &mut self,
            proof: CapabilityProof,
        ) -> std::result::Result<(), Self::InsertError> {
            self.inner.insert_proof(proof)
        }
    }

    impl AsyncBlobStoreAcquire for AcquiringStore {
        type AcquireError = Infallible;

        fn acquire(
            &mut self,
            handle: Inline<Handle<UnknownBlob>>,
        ) -> impl std::future::Future<Output = std::result::Result<Option<Bytes>, Self::AcquireError>>
               + Send {
            let data = Handle::<UnknownBlob>::to_hash(handle);
            self.acquired.push(data);
            let bytes = self.offered.get(&data).cloned();
            if let Some(bytes) = &bytes {
                self.inner.put::<UnknownBlob, _>(bytes.clone()).unwrap();
            }
            std::future::ready(Ok(bytes))
        }
    }

    fn detached_secret_commit(
        collection: Collection<SimpleArchive>,
        signing_key: &SigningKey,
        name: &str,
        plaintext: &[u8],
        created_at: IntervalValue,
    ) -> (
        triblespace::core::id::Id,
        CollectionCommit,
        Vec<Blob<UnknownBlob>>,
    ) {
        let sealed =
            seal_version(name, plaintext, [signing_key.verifying_key()], created_at).unwrap();
        let secret = sealed.secret;
        let mut staging = MemoryRepo::default();
        staging
            .commit(collection, signing_key, sealed.fragment)
            .unwrap();
        let snapshot = staging.snapshot().unwrap();
        let commit = snapshot
            .records()
            .unwrap()
            .find_map(|record| match record.unwrap() {
                CollectionRecord::Commit(commit) => Some(commit),
                _ => None,
            })
            .expect("staging one fragment publishes one commit");
        let blobs = snapshot
            .blobs()
            .map(|info| {
                let info = info.unwrap();
                snapshot
                    .get(info.handle)
                    .expect("listed staging blob remains readable")
            })
            .collect();
        (secret, commit, blobs)
    }

    #[test]
    fn exact_snapshot_hydrates_cold_data_without_widening_support_during_derivation() {
        pollster::block_on(async {
            let authority = SigningKey::generate(&mut OsRng);
            let left_writer = SigningKey::generate(&mut OsRng);
            let right_writer = SigningKey::generate(&mut OsRng);
            let mut store = AcquiringStore::default();
            let collection = SecretsCollection::register(
                &mut store,
                "cold-and-concurrent",
                direct_policy(authority.verifying_key()),
            )
            .unwrap();

            let (left_secret, left_commit, left_blobs) =
                detached_secret_commit(collection.source(), &left_writer, "left", b"cold", at(30));
            for blob in &left_blobs {
                store.offer(blob);
            }
            store.insert(CollectionRecord::Commit(left_commit)).unwrap();

            let left_proof = CapabilityProof::new(
                CapabilityResource::from(collection.handle()),
                &authority,
                write_capability(),
                left_writer.verifying_key(),
            );
            store.insert_proof(left_proof).unwrap();

            let (right_secret, right_commit, right_blobs) = detached_secret_commit(
                collection.source(),
                &right_writer,
                "right",
                b"concurrent",
                at(31),
            );
            let right_proof = CapabilityProof::new(
                CapabilityResource::from(collection.handle()),
                &authority,
                write_capability(),
                right_writer.verifying_key(),
            );

            // A producer already validated and realized the right-hand input.
            // Build that honest witness chain where its WRITE proof is present,
            // then replicate records and blobs without replicating the proof.
            let mut right_staging = MemoryRepo::default();
            let descriptors = store.snapshot().unwrap();
            for info in descriptors.blobs() {
                let info = info.unwrap();
                right_staging
                    .put::<UnknownBlob, _>(
                        descriptors
                            .get::<Blob<UnknownBlob>, _>(info.handle)
                            .unwrap(),
                    )
                    .unwrap();
            }
            for blob in right_blobs {
                right_staging.put::<UnknownBlob, _>(blob).unwrap();
            }
            right_staging
                .insert(CollectionRecord::Commit(right_commit))
                .unwrap();
            right_staging.insert_proof(right_proof.clone()).unwrap();
            let right_support = collection
                .source()
                .cover([Handle::<SimpleArchive>::from_hash(right_commit.data())]);
            drop(
                collection
                    .ensure_exact(&mut right_staging, &authority, &right_support)
                    .await
                    .unwrap(),
            );
            let realized = right_staging.snapshot().unwrap();
            for info in realized.blobs() {
                let info = info.unwrap();
                store
                    .inner
                    .put::<UnknownBlob, _>(
                        realized.get::<Blob<UnknownBlob>, _>(info.handle).unwrap(),
                    )
                    .unwrap();
            }
            for record in realized.records().unwrap() {
                store.inner.insert(record.unwrap()).unwrap();
            }

            let before = store.snapshot().unwrap();
            assert!(!collection
                .source()
                .writer_is_admitted(&before, right_writer.verifying_key())
                .unwrap());
            assert_eq!(
                before
                    .collection_exact(collection.rank9(), &right_support)
                    .unwrap()
                    .support(),
                &right_support,
            );
            assert!(snapshot(before, collection).unwrap().contains(right_secret));

            // The caller explicitly requests only left. This proof arrives
            // during the first mapping edge and must not widen that exact
            // request across the second edge. An ordinary target snapshot,
            // unlike this exact observation, already includes right above.
            store.inject_proof_on_derive = Some(right_proof);
            let left_support = collection
                .source()
                .cover([Handle::<SimpleArchive>::from_hash(left_commit.data())]);
            drop(
                store
                    .ensure_exact(collection.source(), &authority, &left_support)
                    .await
                    .unwrap(),
            );
            let first_snapshot = collection
                .ensure_exact(&mut store, &authority, &left_support)
                .await
                .unwrap();
            let first = snapshot_exact(first_snapshot, collection, left_support.clone()).unwrap();
            assert!(first.contains(left_secret));
            assert!(!first.contains(right_secret));
            assert_eq!(first.support(), &left_support);
            assert!(store.acquired.contains(&left_commit.data()));
            assert!(store.inject_proof_on_derive.is_none());
            assert_eq!(store.snapshot().unwrap().wants().unwrap().count(), 0);
            drop(first);

            let second = ensure_and_snapshot(&mut store, collection, &authority)
                .await
                .unwrap();
            assert!(second.contains(left_secret));
            assert!(second.contains(right_secret));
            assert_eq!(
                second.support(),
                &collection.source().cover([
                    Handle::<SimpleArchive>::from_hash(left_commit.data()),
                    Handle::<SimpleArchive>::from_hash(right_commit.data()),
                ]),
            );
        });
    }

    #[test]
    fn ordinary_reads_reuse_derived_endorsements_without_ancestral_proof_or_payloads() {
        pollster::block_on(async {
            for rank9_ready in [false, true] {
                let authority = SigningKey::generate(&mut OsRng);
                let writer = SigningKey::generate(&mut OsRng);
                let mut staging = MemoryRepo::default();
                let collection = SecretsCollection::register(
                    &mut staging,
                    "endorsed-without-ancestors",
                    direct_policy(authority.verifying_key()),
                )
                .unwrap();
                let (secret, commit, blobs) = detached_secret_commit(
                    collection.source(),
                    &writer,
                    "endorsed",
                    b"resident derived value",
                    at(40),
                );
                for blob in blobs {
                    staging.put::<UnknownBlob, _>(blob).unwrap();
                }
                staging.insert(CollectionRecord::Commit(commit)).unwrap();
                let proof = CapabilityProof::new(
                    CapabilityResource::from(collection.handle()),
                    &authority,
                    write_capability(),
                    writer.verifying_key(),
                );
                staging.insert_proof(proof.clone()).unwrap();
                let support = collection
                    .source()
                    .cover([Handle::<SimpleArchive>::from_hash(commit.data())]);
                drop(
                    staging
                        .ensure_exact(collection.succinct(), &authority, &support)
                        .await
                        .unwrap(),
                );
                if rank9_ready {
                    drop(
                        staging
                            .ensure_exact(collection.rank9(), &authority, &support)
                            .await
                            .unwrap(),
                    );
                }

                // Replicate an honestly produced witness chain but neither the
                // original writer's grant nor its data/metadata archive bytes.
                let realized = staging.snapshot().unwrap();
                let mut store = AcquiringStore::default();
                let metadata = Handle::<SimpleArchive>::to_hash(commit.metadata());
                for info in realized.blobs() {
                    let info = info.unwrap();
                    let data = Handle::<UnknownBlob>::to_hash(info.handle);
                    if data != commit.data() && data != metadata {
                        store
                            .inner
                            .put::<UnknownBlob, _>(
                                realized.get::<Blob<UnknownBlob>, _>(info.handle).unwrap(),
                            )
                            .unwrap();
                    }
                }
                for record in realized.records().unwrap() {
                    store.inner.insert(record.unwrap()).unwrap();
                }
                let before = store.snapshot().unwrap();
                assert!(!collection
                    .source()
                    .writer_is_admitted(&before, writer.verifying_key())
                    .unwrap());
                assert!(!before
                    .contains_blob(Handle::<UnknownBlob>::from_hash(commit.data()))
                    .unwrap());
                assert!(!before
                    .contains_blob(Handle::<UnknownBlob>::from_hash(metadata))
                    .unwrap());
                assert_eq!(
                    snapshot(before.clone(), collection)
                        .unwrap()
                        .contains(secret),
                    rank9_ready,
                );
                let records_before = before.records().unwrap().count();

                let observed = ensure_and_snapshot(&mut store, collection, &authority)
                    .await
                    .unwrap();
                assert!(observed.contains(secret));
                assert_eq!(observed.support(), &support);
                assert!(store.acquired.is_empty());
                let after = store.snapshot().unwrap();
                assert!(!collection
                    .source()
                    .writer_is_admitted(&after, writer.verifying_key())
                    .unwrap());
                assert_eq!(
                    after.records().unwrap().count(),
                    records_before + usize::from(!rank9_ready),
                );

                let maintained = maintain_and_snapshot(&mut store, collection, &authority)
                    .await
                    .unwrap();
                assert!(maintained.contains(secret));
                assert_eq!(maintained.support(), &support);
                assert!(store.acquired.is_empty());

                // Even once root admission becomes possible, existing target
                // support must prevent reacquiring its absent source payload.
                store.insert_proof(proof).unwrap();
                let again = ensure_and_snapshot(&mut store, collection, &authority)
                    .await
                    .unwrap();
                assert!(again.contains(secret));
                assert!(store.acquired.is_empty());
                assert!(!store
                    .snapshot()
                    .unwrap()
                    .contains_blob(Handle::<UnknownBlob>::from_hash(commit.data()))
                    .unwrap());
            }
        });
    }

    #[test]
    fn ordinary_read_without_write_keeps_resident_target_when_source_is_ahead() {
        pollster::block_on(async {
            let owner = SigningKey::generate(&mut OsRng);
            let reader = SigningKey::generate(&mut OsRng);
            let mut store = AcquiringStore::default();
            let collection = SecretsCollection::register(
                &mut store,
                "reader-without-write",
                direct_policy(owner.verifying_key()),
            )
            .unwrap();
            let old = add_secret(&mut store, &owner, collection, "old", b"old", at(50)).unwrap();
            let warm = ensure_and_snapshot(&mut store, collection, &owner)
                .await
                .unwrap();
            let support = warm.support().clone();
            let new = add_secret(&mut store, &owner, collection, "new", b"new", at(51)).unwrap();
            let before = store.snapshot().unwrap();
            let records_before = before.records().unwrap().count();
            assert!(!collection
                .succinct()
                .writer_is_admitted(&before, reader.verifying_key())
                .unwrap());

            let observed = ensure_and_snapshot(&mut store, collection, &reader)
                .await
                .unwrap();
            assert!(observed.contains(old));
            assert!(!observed.contains(new));
            assert_eq!(observed.support(), &support);
            assert_eq!(
                store.snapshot().unwrap().records().unwrap().count(),
                records_before,
            );
            assert!(store.acquired.is_empty());

            let error = maintain_and_snapshot(&mut store, collection, &reader)
                .await
                .err()
                .expect("explicit maintenance still reports missing producer authority");
            assert!(matches!(
                error.downcast_ref::<CollectionRealizationError>(),
                Some(CollectionRealizationError::UnauthorizedProducer { .. }),
            ));
        });
    }

    #[test]
    fn ordinary_read_does_not_hide_missing_payload_errors() {
        pollster::block_on(async {
            let owner = SigningKey::generate(&mut OsRng);
            let mut store = AcquiringStore::default();
            let collection = SecretsCollection::register(
                &mut store,
                "missing-source-payload",
                direct_policy(owner.verifying_key()),
            )
            .unwrap();
            let (_, commit, _) =
                detached_secret_commit(collection.source(), &owner, "cold", b"unavailable", at(60));
            store.insert(CollectionRecord::Commit(commit)).unwrap();

            let error = ensure_and_snapshot(&mut store, collection, &owner)
                .await
                .err()
                .expect("a missing blob is not an unauthorized-producer fallback");
            assert!(matches!(
                error.downcast_ref::<CollectionRealizationError>(),
                Some(
                    CollectionRealizationError::MissingDependency { .. }
                        | CollectionRealizationError::IncompleteCover { .. }
                ),
            ));
            assert!(store.acquired.contains(&commit.data()));
            assert_eq!(store.snapshot().unwrap().wants().unwrap().count(), 0);
        });
    }

    fn observed(
        store: &mut MemoryRepo,
        collection: SecretsCollection,
        owner: &SigningKey,
        second: f64,
    ) -> SecretsSnapshot<MemoryRepoSnapshot> {
        drop(pollster::block_on(ensure_and_snapshot(store, collection, owner)).unwrap());
        snapshot(
            store.snapshot_at(Epoch::from_unix_seconds(second)).unwrap(),
            collection,
        )
        .unwrap()
    }

    fn resource_of(
        secrets: &SecretsSnapshot<MemoryRepoSnapshot>,
        secret: triblespace::core::id::Id,
        holder: &SigningKey,
    ) -> CollectionHandle {
        super::super::envelope::recover(
            secrets.store_snapshot(),
            secrets.facts().unwrap(),
            secret,
            holder,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
        .resource
    }

    #[test]
    fn collection_read_and_old_collection_delivery_grants_do_not_deliver_new_secrets() {
        let owner = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let mut store = MemoryRepo::default();
        let collection = SecretsCollection::register(
            &mut store,
            "secrets",
            direct_policy(owner.verifying_key()),
        )
        .unwrap();
        grant_collection_read(&mut store, collection.handle(), &owner, bob.verifying_key())
            .unwrap();
        grant_collection_capability(
            &mut store,
            collection.handle(),
            key_delivery_capability(),
            &owner,
            bob.verifying_key(),
        )
        .unwrap();
        let secret = add_secret(&mut store, &owner, collection, "token", b"value", at(1)).unwrap();
        let before = observed(&mut store, collection, &owner, 10.0);
        assert_eq!(before.open(secret, &owner).unwrap(), b"value");
        assert!(before.open(secret, &bob).is_err());
        assert_eq!(
            maintain_recipient_envelopes(&mut store, &owner, &before, collection, &owner).unwrap(),
            0
        );
        assert!(collection
            .source()
            .reader_is_admitted(before.store_snapshot(), bob.verifying_key())
            .unwrap());
        resource::grant(
            &mut store,
            &owner,
            &before,
            SecretTarget::Secret(secret),
            bob.verifying_key(),
            DeliveryLimits::default(),
            false,
        )
        .unwrap();
        assert_eq!(
            maintain_recipient_envelopes(&mut store, &owner, &before, collection, &owner).unwrap(),
            0,
            "frozen AUTH frontier"
        );
        let current = observed(&mut store, collection, &owner, 11.0);
        assert_eq!(
            maintain_recipient_envelopes(&mut store, &owner, &current, collection, &owner).unwrap(),
            1
        );
        let after = observed(&mut store, collection, &owner, 12.0);
        assert_eq!(after.open(secret, &bob).unwrap(), b"value");
        assert_eq!(
            maintain_recipient_envelopes(&mut store, &owner, &after, collection, &owner).unwrap(),
            0
        );
        assert_eq!(
            super::super::secret_rows_for(before.facts().unwrap(), secret)[0].body,
            super::super::secret_rows_for(after.facts().unwrap(), secret)[0].body
        );
    }

    #[test]
    fn historical_collection_descriptor_and_open_replication_need_no_delivery_binding() {
        let owner = SigningKey::generate(&mut OsRng);
        let mut store = MemoryRepo::default();
        let source = store
            .collection(
                "historical",
                CollectionPolicy::new(
                    AdmissionPolicy::Open,
                    AdmissionPolicy::direct(owner.verifying_key()),
                ),
            )
            .unwrap();
        let handle = source.handle();
        let collection = SecretsCollection::from_source(&mut store, source).unwrap();
        assert_eq!(collection.handle(), handle);
        let secret =
            add_secret(&mut store, &owner, collection, "token", b"private", at(2)).unwrap();
        assert_eq!(
            observed(&mut store, collection, &owner, 20.0)
                .open(secret, &owner)
                .unwrap(),
            b"private"
        );
    }

    #[test]
    fn legacy_envelopes_open_but_cannot_infer_new_delivery_roots() {
        let owner = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let mut store = MemoryRepo::default();
        let collection =
            SecretsCollection::register(&mut store, "legacy", direct_policy(owner.verifying_key()))
                .unwrap();
        let sealed = seal_version(
            "old",
            b"already delivered",
            [owner.verifying_key(), bob.verifying_key()],
            at(3),
        )
        .unwrap();
        let secret = sealed.secret;
        store
            .commit(collection.source(), &owner, sealed.fragment)
            .unwrap();
        let current = observed(&mut store, collection, &owner, 500.0);
        assert_eq!(current.open(secret, &bob).unwrap(), b"already delivered");
        assert_eq!(
            maintain_recipient_envelopes(&mut store, &owner, &current, collection, &owner).unwrap(),
            0
        );
        assert!(resource::grant(
            &mut store,
            &owner,
            &current,
            SecretTarget::Secret(secret),
            bob.verifying_key(),
            DeliveryLimits::default(),
            false
        )
        .is_err());
    }

    #[test]
    fn an_offline_commit_preserves_its_own_adding_signer_after_write_admission() {
        let owner = SigningKey::generate(&mut OsRng);
        let writer = SigningKey::generate(&mut OsRng);
        let mut store = MemoryRepo::default();
        let collection = SecretsCollection::register(
            &mut store,
            "offline",
            direct_policy(owner.verifying_key()),
        )
        .unwrap();
        let secret =
            add_secret(&mut store, &writer, collection, "token", b"offline", at(3)).unwrap();
        assert!(!observed(&mut store, collection, &owner, 10.0).contains(secret));
        grant_collection_write(
            &mut store,
            collection.handle(),
            &owner,
            writer.verifying_key(),
        )
        .unwrap();
        let after = observed(&mut store, collection, &owner, 10.0);
        assert_eq!(after.open(secret, &writer).unwrap(), b"offline");
        assert!(
            after.open(secret, &owner).is_err(),
            "collection owner is not every secret's recipient"
        );
        assert_eq!(
            maintain_recipient_envelopes(&mut store, &owner, &after, collection, &owner).unwrap(),
            0
        );
    }

    #[test]
    fn selected_maintenance_and_grants_do_not_cross_secret_versions() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let mut store = MemoryRepo::default();
        let collection = SecretsCollection::register(
            &mut store,
            "selected",
            direct_policy(alice.verifying_key()),
        )
        .unwrap();
        let first = add_secret(&mut store, &alice, collection, "token", b"first", at(1)).unwrap();
        let second = add_secret(&mut store, &alice, collection, "token", b"second", at(2)).unwrap();
        let before = observed(&mut store, collection, &alice, 10.0);
        for secret in [first, second] {
            resource::grant(
                &mut store,
                &alice,
                &before,
                SecretTarget::Secret(secret),
                bob.verifying_key(),
                DeliveryLimits::default(),
                false,
            )
            .unwrap();
        }
        let current = observed(&mut store, collection, &alice, 10.0);
        assert_eq!(
            maintain_selected_recipient_envelopes(
                &mut store,
                &alice,
                &current,
                collection,
                &alice,
                &[SecretTarget::Secret(first)]
            )
            .unwrap(),
            1
        );
        let after = observed(&mut store, collection, &alice, 10.0);
        assert_eq!(after.open(first, &bob).unwrap(), b"first");
        assert!(after.open(second, &bob).is_err());
        let resource = resource_of(&after, second, &alice);
        assert_eq!(
            maintain_selected_recipient_envelopes(
                &mut store,
                &alice,
                &after,
                collection,
                &alice,
                &[SecretTarget::Resource(resource)]
            )
            .unwrap(),
            1
        );
        let third = add_secret(&mut store, &alice, collection, "token", b"third", at(3)).unwrap();
        let current = observed(&mut store, collection, &alice, 10.0);
        assert_eq!(
            maintain_recipient_envelopes(&mut store, &alice, &current, collection, &alice).unwrap(),
            0
        );
        assert!(current.open(third, &bob).is_err());
    }

    #[test]
    fn resource_delegation_needs_no_dek_and_ancestor_deadlines_limit_only_new_delivery() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let carol = SigningKey::generate(&mut OsRng);
        let dave = SigningKey::generate(&mut OsRng);
        let mut store = MemoryRepo::default();
        let collection =
            SecretsCollection::register(&mut store, "expiry", direct_policy(alice.verifying_key()))
                .unwrap();
        let secret = add_secret(&mut store, &alice, collection, "token", b"kept", at(1)).unwrap();
        let before = observed(&mut store, collection, &alice, 100.0);
        let resource = resource_of(&before, secret, &alice);
        resource::grant(
            &mut store,
            &alice,
            &before,
            SecretTarget::Secret(secret),
            bob.verifying_key(),
            DeliveryLimits {
                not_before: Some(Epoch::from_unix_seconds(50.0)),
                expires_at: Some(Epoch::from_unix_seconds(150.0)),
            },
            true,
        )
        .unwrap();
        let delegated = observed(&mut store, collection, &alice, 100.0);
        assert!(delegated.open(secret, &bob).is_err());
        resource::grant(
            &mut store,
            &bob,
            &delegated,
            SecretTarget::Resource(resource),
            carol.verifying_key(),
            DeliveryLimits::default(),
            false,
        )
        .unwrap();
        let early = observed(&mut store, collection, &alice, 49.0);
        assert_eq!(
            maintain_recipient_envelopes(&mut store, &alice, &early, collection, &alice).unwrap(),
            0
        );
        let expired = observed(&mut store, collection, &alice, 150.0);
        assert_eq!(
            maintain_recipient_envelopes(&mut store, &alice, &expired, collection, &alice).unwrap(),
            0
        );
        let current = observed(&mut store, collection, &alice, 100.0);
        assert_eq!(
            maintain_recipient_envelopes(&mut store, &alice, &current, collection, &alice).unwrap(),
            2
        );
        // A child without bounds cannot erase its parent's restriction.
        let later = observed(&mut store, collection, &alice, 200.0);
        resource::grant(
            &mut store,
            &bob,
            &later,
            SecretTarget::Resource(resource),
            dave.verifying_key(),
            DeliveryLimits::default(),
            false,
        )
        .unwrap();
        let later = observed(&mut store, collection, &alice, 200.0);
        assert_eq!(
            maintain_recipient_envelopes(&mut store, &alice, &later, collection, &alice).unwrap(),
            0
        );
        assert_eq!(later.open(secret, &bob).unwrap(), b"kept");
        assert_eq!(later.open(secret, &carol).unwrap(), b"kept");
        assert!(later.open(secret, &dave).is_err());
        assert!(!collection
            .source()
            .reader_is_admitted(later.store_snapshot(), bob.verifying_key())
            .unwrap());
        assert!(!collection
            .source()
            .writer_is_admitted(later.store_snapshot(), bob.verifying_key())
            .unwrap());
    }

    #[test]
    fn invocation_only_grant_cannot_delegate() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let carol = SigningKey::generate(&mut OsRng);
        let mut store = MemoryRepo::default();
        let collection =
            SecretsCollection::register(&mut store, "invoke", direct_policy(alice.verifying_key()))
                .unwrap();
        let secret = add_secret(&mut store, &alice, collection, "token", b"value", at(1)).unwrap();
        let before = observed(&mut store, collection, &alice, 100.0);
        let resource = resource_of(&before, secret, &alice);
        resource::grant(
            &mut store,
            &alice,
            &before,
            SecretTarget::Secret(secret),
            bob.verifying_key(),
            DeliveryLimits::default(),
            false,
        )
        .unwrap();
        let current = observed(&mut store, collection, &alice, 100.0);
        assert!(resource::grant(
            &mut store,
            &bob,
            &current,
            SecretTarget::Resource(resource),
            carol.verifying_key(),
            DeliveryLimits::default(),
            false
        )
        .is_err());
    }

    #[test]
    fn arbitrary_policy_fact_and_foreign_collection_do_not_rebind_a_real_dek() {
        use triblespace::core::capability::policy::{
            resource_collection, resource_handle, resource_policy,
        };
        use triblespace::prelude::*;
        let alice = SigningKey::generate(&mut OsRng);
        let attacker = SigningKey::generate(&mut OsRng);
        let mut store = MemoryRepo::default();
        let collection =
            SecretsCollection::register(&mut store, "honest", direct_policy(alice.verifying_key()))
                .unwrap();
        let other = SecretsCollection::register(
            &mut store,
            "other",
            direct_policy(attacker.verifying_key()),
        )
        .unwrap();
        let secret = add_secret(
            &mut store,
            &alice,
            collection,
            "token",
            b"real secret",
            at(1),
        )
        .unwrap();
        let before = observed(&mut store, collection, &alice, 10.0);
        let binding = super::super::envelope::recover(
            before.store_snapshot(),
            before.facts().unwrap(),
            secret,
            &alice,
        )
        .unwrap()
        .remove(0);
        let false_descriptor = entity! {
            metadata::tag: super::super::schema::KIND_SECRET_RESOURCE,
            super::super::schema::wrap_secret: secret,
            super::super::schema::secret_body: binding.body,
            resource_collection: other.handle(),
            resource_policy*: AdmissionPolicy::direct(attacker.verifying_key()).binding(key_delivery_capability()),
        };
        let false_resource = store
            .put::<SimpleArchive, _>(false_descriptor.facts().clone())
            .unwrap();
        let same_collection_descriptor = entity! {
            metadata::tag: super::super::schema::KIND_SECRET_RESOURCE,
            super::super::schema::wrap_secret: secret,
            super::super::schema::secret_body: binding.body,
            resource_collection: collection.handle(),
            resource_policy*: AdmissionPolicy::direct(attacker.verifying_key()).binding(key_delivery_capability()),
        };
        let same_collection_resource = store
            .put::<SimpleArchive, _>(same_collection_descriptor.facts().clone())
            .unwrap();
        grant_collection_write(
            &mut store,
            collection.handle(),
            &alice,
            attacker.verifying_key(),
        )
        .unwrap();
        store.commit(collection.source(), &attacker, entity! {
            ExclusiveId::force_ref(&secret) @ resource_handle*: [false_resource, same_collection_resource],
            resource_policy*: AdmissionPolicy::direct(attacker.verifying_key()).binding(key_delivery_capability()),
        }).unwrap();
        store
            .insert_proof(CapabilityProof::new(
                CapabilityResource::from(binding.resource),
                &attacker,
                key_delivery_capability(),
                attacker.verifying_key(),
            ))
            .unwrap();
        store
            .insert_proof(CapabilityProof::new(
                CapabilityResource::from(same_collection_resource),
                &attacker,
                key_delivery_capability(),
                attacker.verifying_key(),
            ))
            .unwrap();
        let current = observed(&mut store, collection, &alice, 10.0);
        assert_eq!(
            maintain_recipient_envelopes(&mut store, &alice, &current, collection, &alice).unwrap(),
            0
        );
        assert!(current.open(secret, &attacker).is_err());
        assert!(
            resource::grant(
                &mut store,
                &attacker,
                &current,
                SecretTarget::Resource(false_resource),
                attacker.verifying_key(),
                DeliveryLimits::default(),
                false
            )
            .is_err(),
            "immutable containing collection differs"
        );
    }

    #[test]
    fn forged_well_shaped_recipient_wrap_does_not_suppress_delivery() {
        use triblespace::prelude::*;
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let mut store = MemoryRepo::default();
        let collection = SecretsCollection::register(
            &mut store,
            "forged-wrap",
            direct_policy(alice.verifying_key()),
        )
        .unwrap();
        let secret = add_secret(&mut store, &alice, collection, "token", b"value", at(1)).unwrap();
        let before = observed(&mut store, collection, &alice, 10.0);
        let binding = super::super::envelope::recover(
            before.store_snapshot(),
            before.facts().unwrap(),
            secret,
            &alice,
        )
        .unwrap()
        .remove(0);
        let false_binding = super::super::envelope::BoundKey {
            secret: binding.secret,
            body: binding.body,
            resource: binding.resource,
            dek: dryoc::dryocsecretbox::Key::gen(),
        };
        let fake =
            super::super::envelope::seal(&false_binding, bob.verifying_key().to_bytes()).unwrap();
        let fragment = super::super::recipient_wrap_fragment(
            genid().id,
            secret,
            bob.verifying_key().to_bytes(),
            fake,
        )
        .unwrap();
        store.commit(collection.source(), &alice, fragment).unwrap();
        resource::grant(
            &mut store,
            &alice,
            &before,
            SecretTarget::Secret(secret),
            bob.verifying_key(),
            DeliveryLimits::default(),
            false,
        )
        .unwrap();
        let current = observed(&mut store, collection, &alice, 10.0);
        assert!(current.open(secret, &bob).is_err());
        assert_eq!(
            maintain_recipient_envelopes(&mut store, &alice, &current, collection, &alice).unwrap(),
            1
        );
        let after = observed(&mut store, collection, &alice, 10.0);
        assert_eq!(after.open(secret, &bob).unwrap(), b"value");
        assert_eq!(
            maintain_recipient_envelopes(&mut store, &alice, &after, collection, &alice).unwrap(),
            0
        );
    }
}
