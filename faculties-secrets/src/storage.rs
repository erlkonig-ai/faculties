//! Collection registration, publication, and maintained reads for Secrets.
//!
//! This module deliberately has no vault registry or access inbox. Callers
//! configure the collection descriptors they use. Authorization evidence is
//! interpreted by TribleSpace; Secrets consumes only the finite admitted
//! `READ(collection)` audience needed to deliver per-version DEKs.

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::{
    collection_read_audience, Collection, CollectionHandle, CollectionPolicy,
    CollectionReadAudience, CollectionSnapshotExt, CollectionStoreExt, Support,
};
use triblespace::core::repo::async_store::AsyncBlobStoreAcquire;
use triblespace::core::repo::SnapshotSource;
use triblespace::core::repo::{BlobStoreGet, CapabilityProofRead, Store, StoreRead, StoreSnapshot};
use triblespace::macros::{find, pattern};

use super::{
    add_recipient_envelopes_from_facts, seal_version, IntervalValue, SecretsFacts, SecretsSnapshot,
};

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
    /// Register one source collection and its maintained query encodings.
    pub fn register<S>(store: &mut S, name: &str, policy: CollectionPolicy) -> Result<Self>
    where
        S: CollectionStoreExt,
    {
        let source = store
            .collection(name, policy.clone())
            .map_err(|error| anyhow!("register Secrets source collection: {error}"))?;
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

    /// Attach the canonical maintained encodings above one existing source.
    ///
    /// The source descriptor remains the policy boundary and identity. The
    /// two derived descriptors inherit that exact immutable policy.
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
    /// LSM compaction policy and is therefore the normal foreground read path.
    pub async fn ensure_exact<S>(
        self,
        store: &mut S,
        support: &triblespace::core::collection::Support,
    ) -> Result<S::Snapshot>
    where
        S: Store + CollectionStoreExt + AsyncBlobStoreAcquire + Send,
    {
        drop(
            store
                .ensure_exact(self.succinct, support)
                .await
                .context("ensure Succinct Secrets collection")?,
        );
        store
            .ensure_exact(self.rank9, support)
            .await
            .context("ensure Rank9 Secrets collection")
    }

    /// Ensure the root, then realize its selected support across both encodings.
    pub async fn ensure<S>(self, store: &mut S) -> Result<S::Snapshot>
    where
        S: Store + CollectionStoreExt + AsyncBlobStoreAcquire + Send,
    {
        let ready = store
            .ensure(self.source)
            .await
            .context("ensure Secrets source collection")?;
        let support = self
            .source
            .admitted(&ready)
            .context("admit Secrets source support")?;
        drop(ready);
        self.ensure_exact(store, &support).await
    }

    /// Maintain both derived lattices for one exact foundational support.
    pub async fn maintain_exact<S>(
        self,
        store: &mut S,
        support: &triblespace::core::collection::Support,
    ) -> Result<S::Snapshot>
    where
        S: Store + CollectionStoreExt + AsyncBlobStoreAcquire + Send,
    {
        drop(
            store
                .maintain_exact(self.succinct, support)
                .await
                .context("maintain Succinct Secrets collection")?,
        );
        store
            .maintain_exact(self.rank9, support)
            .await
            .context("maintain Rank9 Secrets collection")
    }

    /// Ensure the root, then maintain its selected support across both encodings.
    pub async fn maintain<S>(self, store: &mut S) -> Result<S::Snapshot>
    where
        S: Store + CollectionStoreExt + AsyncBlobStoreAcquire + Send,
    {
        let ready = store
            .ensure(self.source)
            .await
            .context("ensure Secrets source collection")?;
        let support = self
            .source
            .admitted(&ready)
            .context("admit Secrets source support")?;
        drop(ready);
        self.maintain_exact(store, &support).await
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
/// Active maintenance must use this path: re-running admission against the
/// later residency snapshot could accidentally admit concurrent proofs or
/// commits that were outside the support-selection snapshot.
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

/// Ensure the root and maintain the configured collection's selected support, then
/// attach its exact support to the resulting store snapshot.
pub async fn maintain_and_snapshot<S>(
    store: &mut S,
    collection: SecretsCollection,
) -> Result<SecretsSnapshot<S::Snapshot>>
where
    S: Store + CollectionStoreExt + AsyncBlobStoreAcquire + Send,
{
    let ready = store
        .ensure(collection.source)
        .await
        .context("ensure Secrets source collection")?;
    let support = collection
        .source
        .admitted(&ready)
        .context("admit Secrets source support")?;
    drop(ready);
    let store_snapshot = collection.maintain_exact(store, &support).await?;
    snapshot_exact(store_snapshot, collection, support)
}

/// Ensure the root and the configured collection's selected support, then attach
/// its exact support to the resulting store snapshot.
///
/// Source support is selected from one snapshot after root acquisition and
/// remains fixed across both derivations. This is the ordinary
/// consumer path; unlike [`maintain_and_snapshot`] it performs no
/// opportunistic LSM compaction.
pub async fn ensure_and_snapshot<S>(
    store: &mut S,
    collection: SecretsCollection,
) -> Result<SecretsSnapshot<S::Snapshot>>
where
    S: Store + CollectionStoreExt + AsyncBlobStoreAcquire + Send,
{
    let ready = store
        .ensure(collection.source)
        .await
        .context("ensure Secrets source collection")?;
    let support = collection
        .source
        .admitted(&ready)
        .context("admit Secrets source support")?;
    drop(ready);
    let store_snapshot = collection.ensure_exact(store, &support).await?;
    snapshot_exact(store_snapshot, collection, support)
}

fn admitted_readers<R>(snapshot: &R, collection: SecretsCollection) -> Result<Vec<VerifyingKey>>
where
    R: StoreSnapshot + BlobStoreGet + CapabilityProofRead,
{
    let audience = collection_read_audience(snapshot, collection.handle())
        .map_err(|error| anyhow!("resolve admitted Secrets readers: {error}"))?;
    finite_readers(audience)
}

fn finite_readers(audience: CollectionReadAudience) -> Result<Vec<VerifyingKey>> {
    match audience {
        CollectionReadAudience::Open => {
            bail!("cannot seal a finite DEK envelope set for an open-read collection")
        }
        CollectionReadAudience::Restricted(readers) if readers.is_empty() => {
            bail!("Secrets collection has no admitted readers")
        }
        CollectionReadAudience::Restricted(readers) => Ok(readers),
    }
}

/// Publish one immutable version to the source collection.
///
/// Local `commit` is unconditional. The audience snapshot only selects
/// cryptographic recipients; generic collection admission later decides
/// whether this signed commit contributes to a view.
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
    let snapshot = store
        .snapshot()
        .context("freeze Secrets audience before publication")?;
    let recipients = admitted_readers(&snapshot, collection)?;
    drop(snapshot);
    let sealed = seal_version(name, plaintext, recipients, created_at)?;
    let secret = sealed.secret;
    store
        .commit(collection.source, signing_key, sealed.fragment)
        .map_err(|error| anyhow!("publish encrypted secret version: {error}"))?;
    Ok(secret)
}

/// Add missing envelopes across every secret in one policy boundary.
///
/// The supplied snapshot fixes both the secrets and self-contained READ proofs
/// to inspect. Concurrent grants and secrets wait for the next additive
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
    if secrets.collection() != collection.handle() {
        bail!("Secrets snapshot belongs to a different collection");
    }
    let Some(facts) = secrets.facts() else {
        return Ok(0);
    };
    let audience = collection_read_audience(secrets.store_snapshot(), collection.handle())
        .map_err(|error| anyhow!("resolve admitted Secrets readers: {error}"))?;
    let recipients = finite_readers(audience)?;
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
        let envelopes = add_recipient_envelopes_from_facts(
            secrets.store_snapshot(),
            facts,
            secret,
            holder,
            recipients.iter().copied(),
        )?;
        count += envelopes.recipients.len();
        fragment += envelopes.fragment;
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
    use hifitime::Epoch;
    use rand_core::OsRng;
    use triblespace::core::blob::encodings::UnknownBlob;
    use triblespace::core::blob::{Blob, BlobEncoding, IntoBlob};
    use triblespace::core::capability::{
        Capability, CapabilityAction, CapabilityMode, CapabilityProof, CapabilityResource,
        CapabilityValidity,
    };
    use triblespace::core::collection::{
        grant_collection_read, grant_collection_write, AdmissionPolicy, CollectionCommit,
        CollectionData, CollectionPolicy, CollectionRead, CollectionRecord, CollectionStore,
        ACTION_READ, ACTION_WRITE,
    };
    use triblespace::core::inline::encodings::hash::Handle;
    use triblespace::core::inline::{Inline, InlineEncoding};
    use triblespace::core::repo::memoryrepo::{MemoryRepo, MemoryRepoSnapshot};
    use triblespace::core::repo::{
        BlobStoreList, BlobStorePut, CapabilityProofStore, SnapshotSource, WantRead,
    };
    use triblespace::prelude::TryToInline;

    use super::*;

    fn at(second: i64) -> IntervalValue {
        let epoch = Epoch::from_unix_seconds(second as f64);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn direct_policy(key: VerifyingKey) -> CollectionPolicy {
        CollectionPolicy::new(AdmissionPolicy::direct(key), AdmissionPolicy::direct(key))
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
    fn collection_write_maintain_and_read_round_trip() {
        pollster::block_on(async {
            let alice = SigningKey::generate(&mut OsRng);
            let bob = SigningKey::generate(&mut OsRng);
            let mut store = MemoryRepo::default();
            let collection = SecretsCollection::register(
                &mut store,
                "production-secrets",
                direct_policy(alice.verifying_key()),
            )
            .unwrap();
            grant_collection_read(&mut store, collection.handle(), &alice, bob.verifying_key())
                .unwrap();

            let secret = add_secret(
                &mut store,
                &alice,
                collection,
                "database",
                b"hunter2",
                at(1),
            )
            .unwrap();
            let secrets = maintain_and_snapshot(&mut store, collection).await.unwrap();
            assert_eq!(secrets.instant(), secrets.store_snapshot().instant());
            assert_eq!(secrets.collection(), collection.handle());
            assert!(secrets.contains(secret));
            assert_eq!(secrets.open(secret, &alice).unwrap(), b"hunter2");
            assert_eq!(secrets.open(secret, &bob).unwrap(), b"hunter2");

            let instant = Epoch::from_unix_seconds(100.0);
            let frozen = snapshot(store.snapshot_at(instant).unwrap(), collection).unwrap();
            let copied = snapshot(frozen.store_snapshot().clone(), collection).unwrap();
            assert_eq!(frozen.instant(), instant);
            assert_eq!(copied.instant(), instant);
            assert_eq!(copied.open(secret, &bob).unwrap(), b"hunter2");
        });
    }

    #[test]
    fn open_audience_is_rejected_before_publication() {
        let alice = SigningKey::generate(&mut OsRng);
        let mut store = MemoryRepo::default();
        let collection = SecretsCollection::register(
            &mut store,
            "public-secrets",
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::direct(alice.verifying_key()),
            ),
        )
        .unwrap();
        let error =
            add_secret(&mut store, &alice, collection, "token", b"value", at(2)).unwrap_err();
        assert!(format!("{error:#}").contains("open-read"));
    }

    #[test]
    fn an_offline_commit_can_be_admitted_by_later_write_evidence() {
        pollster::block_on(async {
            let owner = SigningKey::generate(&mut OsRng);
            let offline_writer = SigningKey::generate(&mut OsRng);
            let mut store = MemoryRepo::default();
            let collection = SecretsCollection::register(
                &mut store,
                "offline-secrets",
                direct_policy(owner.verifying_key()),
            )
            .unwrap();

            let secret = add_secret(
                &mut store,
                &offline_writer,
                collection,
                "token",
                b"authored offline",
                at(3),
            )
            .unwrap();
            let before = ensure_and_snapshot(&mut store, collection).await.unwrap();
            assert!(!before.contains(secret));
            drop(before);

            grant_collection_write(
                &mut store,
                collection.handle(),
                &owner,
                offline_writer.verifying_key(),
            )
            .unwrap();
            let after = ensure_and_snapshot(&mut store, collection).await.unwrap();
            assert_eq!(after.open(secret, &owner).unwrap(), b"authored offline");
        });
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

            let left_proof = CapabilityProof::issue_root(
                &authority,
                CapabilityResource::from(collection.handle()),
                Capability::new(CapabilityAction::new(ACTION_WRITE), CapabilityMode::Invoke),
                None,
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
            for blob in right_blobs {
                store.inner.put::<UnknownBlob, _>(blob).unwrap();
            }
            let right_support = collection
                .source()
                .cover([Handle::<SimpleArchive>::from_hash(right_commit.data())]);
            drop(
                collection
                    .ensure_exact(&mut store, &right_support)
                    .await
                    .unwrap(),
            );
            store
                .insert(CollectionRecord::Commit(right_commit))
                .unwrap();

            let right_proof = CapabilityProof::issue_root(
                &authority,
                CapabilityResource::from(collection.handle()),
                Capability::new(CapabilityAction::new(ACTION_WRITE), CapabilityMode::Invoke),
                None,
                right_writer.verifying_key(),
            );
            // Root acquisition finishes before support is selected. This
            // proof arrives later, during the first mapping edge, and must
            // not widen the exact support carried across the second edge.
            store.inject_proof_on_derive = Some(right_proof);

            let first = ensure_and_snapshot(&mut store, collection).await.unwrap();
            assert!(first.contains(left_secret));
            assert!(!first.contains(right_secret));
            assert_eq!(store.snapshot().unwrap().wants().unwrap().count(), 0);
            drop(first);

            let second = ensure_and_snapshot(&mut store, collection).await.unwrap();
            assert!(second.contains(left_secret));
            assert!(second.contains(right_secret));
        });
    }

    #[test]
    fn newly_admitted_reader_gets_an_additive_wrap() {
        pollster::block_on(async {
            let alice = SigningKey::generate(&mut OsRng);
            let bob = SigningKey::generate(&mut OsRng);
            let mut store = MemoryRepo::default();
            let collection = SecretsCollection::register(
                &mut store,
                "shared-secrets",
                direct_policy(alice.verifying_key()),
            )
            .unwrap();
            let first =
                add_secret(&mut store, &alice, collection, "token", b"value", at(4)).unwrap();
            let second =
                add_secret(&mut store, &alice, collection, "password", b"other", at(5)).unwrap();
            let before = maintain_and_snapshot(&mut store, collection).await.unwrap();
            assert!(before.open(first, &bob).is_err());
            assert!(before.open(second, &bob).is_err());

            grant_collection_read(&mut store, collection.handle(), &alice, bob.verifying_key())
                .unwrap();
            // A later proof cannot change the audience of an existing snapshot.
            assert_eq!(
                maintain_recipient_envelopes(&mut store, &alice, &before, collection, &alice)
                    .unwrap(),
                0
            );
            let current = maintain_and_snapshot(&mut store, collection).await.unwrap();
            let added =
                maintain_recipient_envelopes(&mut store, &alice, &current, collection, &alice)
                    .unwrap();
            assert_eq!(added, 2);

            let after = maintain_and_snapshot(&mut store, collection).await.unwrap();
            assert_eq!(after.open(first, &bob).unwrap(), b"value");
            assert_eq!(after.open(second, &bob).unwrap(), b"other");
            assert!(before.open(first, &bob).is_err());
            assert_eq!(
                maintain_recipient_envelopes(&mut store, &alice, &after, collection, &alice)
                    .unwrap(),
                0
            );
        });
    }

    #[test]
    fn recipient_maintenance_reads_a_self_contained_proof_without_blob_acquisition() {
        pollster::block_on(async {
            let alice = SigningKey::generate(&mut OsRng);
            let bob = SigningKey::generate(&mut OsRng);
            let mut store = AcquiringStore::default();
            let collection = SecretsCollection::register(
                &mut store,
                "remotely-granted-secrets",
                direct_policy(alice.verifying_key()),
            )
            .unwrap();
            let secret =
                add_secret(&mut store, &alice, collection, "token", b"value", at(5)).unwrap();

            let proof = CapabilityProof::issue_root(
                &alice,
                CapabilityResource::from(collection.handle()),
                Capability::new(CapabilityAction::new(ACTION_READ), CapabilityMode::Invoke),
                None,
                bob.verifying_key(),
            );
            store.insert_proof(proof).unwrap();

            let current = maintain_and_snapshot(&mut store, collection).await.unwrap();
            assert!(current.open(secret, &bob).is_err());

            let added =
                maintain_recipient_envelopes(&mut store, &alice, &current, collection, &alice)
                    .unwrap();
            assert_eq!(added, 1);
            assert!(store.acquired.is_empty());
            assert_eq!(store.snapshot().unwrap().wants().unwrap().count(), 0);
            drop(current);

            let after = maintain_and_snapshot(&mut store, collection).await.unwrap();
            assert_eq!(after.open(secret, &bob).unwrap(), b"value");
        });
    }

    #[test]
    fn delegated_readers_expire_for_delivery_not_for_existing_envelopes() {
        pollster::block_on(async {
            let alice = SigningKey::generate(&mut OsRng);
            let bob = SigningKey::generate(&mut OsRng);
            let carol = SigningKey::generate(&mut OsRng);
            let mut store = MemoryRepo::default();
            let collection = SecretsCollection::register(
                &mut store,
                "delegated-secrets",
                direct_policy(alice.verifying_key()),
            )
            .unwrap();
            let old_secret =
                add_secret(&mut store, &alice, collection, "old", b"delivered", at(6)).unwrap();

            let root = CapabilityProof::issue_root(
                &alice,
                CapabilityResource::from(collection.handle()),
                Capability::new(
                    CapabilityAction::new(ACTION_READ),
                    CapabilityMode::InvokeAndDelegate,
                ),
                Some(
                    CapabilityValidity::new(
                        Epoch::from_unix_seconds(0.0),
                        Epoch::from_unix_seconds(150.0),
                    )
                    .unwrap(),
                ),
                bob.verifying_key(),
            );
            let proof = root
                .extend(
                    &bob,
                    Capability::new(CapabilityAction::new(ACTION_READ), CapabilityMode::Invoke),
                    None,
                    carol.verifying_key(),
                )
                .unwrap();
            // The final proof contains the signed prefix granting Bob READ too.
            store.insert_proof(proof).unwrap();
            drop(ensure_and_snapshot(&mut store, collection).await.unwrap());
            let instant = Epoch::from_unix_seconds(100.0);
            let current = snapshot(store.snapshot_at(instant).unwrap(), collection).unwrap();
            let expired_instant = Epoch::from_unix_seconds(200.0);
            let expired_same_content =
                snapshot(store.snapshot_at(expired_instant).unwrap(), collection).unwrap();
            assert!(expired_same_content
                .store_snapshot()
                .changes_since(current.store_snapshot())
                .is_empty());
            assert_eq!(current.instant(), instant);
            assert_eq!(expired_same_content.instant(), expired_instant);
            assert_eq!(
                maintain_recipient_envelopes(
                    &mut store,
                    &alice,
                    &expired_same_content,
                    collection,
                    &alice,
                )
                .unwrap(),
                0
            );
            assert_eq!(
                maintain_recipient_envelopes(&mut store, &alice, &current, collection, &alice)
                    .unwrap(),
                2
            );

            let sealed =
                seal_version("new", b"not delivered", [alice.verifying_key()], at(200)).unwrap();
            let new_secret = sealed.secret;
            store
                .commit(collection.source(), &alice, sealed.fragment)
                .unwrap();
            drop(ensure_and_snapshot(&mut store, collection).await.unwrap());
            let expired =
                snapshot(store.snapshot_at(expired_instant).unwrap(), collection).unwrap();
            assert_eq!(
                maintain_recipient_envelopes(&mut store, &alice, &expired, collection, &alice)
                    .unwrap(),
                0
            );
            for reader in [&bob, &carol] {
                assert_eq!(expired.open(old_secret, reader).unwrap(), b"delivered");
                assert!(expired.open(new_secret, reader).is_err());
            }
        });
    }
}
