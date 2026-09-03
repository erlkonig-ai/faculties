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
    collection_read_audience_at, Collection, CollectionHandle, CollectionPolicy,
    CollectionReadAudience, CollectionSnapshotExt, CollectionStoreExt,
};
use triblespace::core::repo::async_store::AsyncBlobStoreAcquire;
use triblespace::core::repo::SnapshotSource;
use triblespace::core::repo::{
    BlobStoreGet, BlobStoreList, CapabilityProofRead, Store, StoreRead, StoreSnapshot,
};
use triblespace::macros::{find, pattern};

use super::{
    add_recipient_envelopes_for_target, seal_version, IntervalValue, SecretsFacts, SecretsSnapshot,
    SecretsView,
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

    /// Ensure the source support admitted at the caller's authorization instant.
    pub async fn ensure<S>(self, store: &mut S, instant: hifitime::Epoch) -> Result<S::Snapshot>
    where
        S: Store + CollectionStoreExt + AsyncBlobStoreAcquire + Send,
    {
        let before = store
            .snapshot()
            .context("freeze Secrets support before ensure")?;
        let support = self
            .source
            .admitted_at(&before, instant)
            .context("admit Secrets source support")?;
        drop(before);
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

    /// Maintain the source support admitted at the caller's authorization instant.
    pub async fn maintain<S>(self, store: &mut S, instant: hifitime::Epoch) -> Result<S::Snapshot>
    where
        S: Store + CollectionStoreExt + AsyncBlobStoreAcquire + Send,
    {
        let before = store
            .snapshot()
            .context("freeze Secrets support before maintenance")?;
        let support = self
            .source
            .admitted_at(&before, instant)
            .context("admit Secrets source support")?;
        drop(before);
        self.maintain_exact(store, &support).await
    }
}

/// Attach explicitly configured collections at one immutable store boundary.
///
/// This never performs maintenance. It reports exactly the support physically
/// realized in `snapshot`, preserving the snapshot/derivation boundary.
pub fn snapshot<R, I>(
    store_snapshot: R,
    collections: I,
    instant: hifitime::Epoch,
) -> Result<SecretsSnapshot<R>>
where
    R: StoreRead,
    I: IntoIterator<Item = SecretsCollection>,
{
    let mut views = Vec::new();
    for collection in collections {
        let observed = store_snapshot
            .collection_at(collection.rank9, instant)
            .context("observe maintained Secrets collection")?;
        if observed.cover().is_empty() {
            continue;
        }
        let support = observed.support().clone();
        let facts = observed
            .view::<SecretsFacts>()
            .context("read maintained Secrets collection")?;
        views.push(SecretsView::new(collection.handle(), support, facts));
    }
    Ok(SecretsSnapshot::new(store_snapshot, instant, views))
}

/// Maintain each explicit policy boundary at one caller-selected authorization
/// instant, then freeze and attach one shared store snapshot.
pub async fn maintain_and_snapshot<S, I>(
    store: &mut S,
    collections: I,
    instant: hifitime::Epoch,
) -> Result<SecretsSnapshot<S::Snapshot>>
where
    S: Store + CollectionStoreExt + AsyncBlobStoreAcquire + Send,
    I: IntoIterator<Item = SecretsCollection>,
{
    let collections = collections.into_iter().collect::<Vec<_>>();
    let before = store
        .snapshot()
        .context("freeze Secrets supports before maintenance")?;
    let supports = collections
        .iter()
        .map(|collection| {
            collection
                .source
                .admitted_at(&before, instant)
                .context("admit Secrets source support")
        })
        .collect::<Result<Vec<_>>>()?;
    drop(before);
    for (collection, support) in collections.iter().zip(&supports) {
        drop(collection.maintain_exact(store, support).await?);
    }
    let store_snapshot = store
        .snapshot()
        .context("freeze maintained Secrets snapshot")?;
    snapshot(store_snapshot, collections, instant)
}

/// Ensure each explicit policy boundary at one caller-selected authorization
/// instant, then attach one shared snapshot.
///
/// All source supports are selected from one frozen prefix. This is the
/// ordinary consumer path; unlike [`maintain_and_snapshot`] it performs no
/// opportunistic LSM compaction.
pub async fn ensure_and_snapshot<S, I>(
    store: &mut S,
    collections: I,
    instant: hifitime::Epoch,
) -> Result<SecretsSnapshot<S::Snapshot>>
where
    S: Store + CollectionStoreExt + AsyncBlobStoreAcquire + Send,
    I: IntoIterator<Item = SecretsCollection>,
{
    let collections = collections.into_iter().collect::<Vec<_>>();
    let before = store
        .snapshot()
        .context("freeze Secrets supports before ensure")?;
    let supports = collections
        .iter()
        .map(|collection| {
            collection
                .source
                .admitted_at(&before, instant)
                .context("admit Secrets source support")
        })
        .collect::<Result<Vec<_>>>()?;
    drop(before);
    for (collection, support) in collections.iter().zip(&supports) {
        drop(collection.ensure_exact(store, support).await?);
    }
    let store_snapshot = store
        .snapshot()
        .context("freeze ensured Secrets snapshot")?;
    snapshot(store_snapshot, collections, instant)
}

fn admitted_readers<R>(
    snapshot: &R,
    collection: SecretsCollection,
    instant: hifitime::Epoch,
) -> Result<Vec<VerifyingKey>>
where
    R: BlobStoreGet + BlobStoreList + CapabilityProofRead,
{
    match collection_read_audience_at(snapshot, collection.handle(), instant)
        .map_err(|error| anyhow!("resolve admitted Secrets readers: {error}"))?
    {
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
    let instant = triblespace::core::clock::epoch_now();
    let snapshot = store
        .snapshot()
        .context("freeze Secrets audience before publication")?;
    let recipients = admitted_readers(&snapshot, collection, instant)?;
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
/// One frozen post-maintenance store snapshot supplies both the immutable fact
/// view and admitted audience. New evidence arriving later cannot split the
/// decision across temporal boundaries; another maintenance call observes it.
pub fn maintain_recipient_envelopes<S, R>(
    store: &mut S,
    signing_key: &SigningKey,
    secrets: &SecretsSnapshot<R>,
    collection: SecretsCollection,
    holder: &SigningKey,
) -> Result<usize>
where
    S: Store + CollectionStoreExt,
    R: StoreSnapshot + BlobStoreGet + BlobStoreList + CapabilityProofRead,
{
    let Some(view) = secrets
        .collections()
        .iter()
        .find(|view| view.collection() == collection.handle())
    else {
        return Ok(0);
    };
    let Some(facts) = secrets.facts() else {
        return Ok(0);
    };
    let recipients = admitted_readers(secrets.store_snapshot(), collection, secrets.instant())?;
    let secret_ids = find!(
        id: triblespace::core::id::Id,
        pattern!(view.facts(), [{
            ?id @ triblespace::core::metadata::tag: super::schema::KIND_SECRET,
        }])
    )
    .collect::<std::collections::BTreeSet<_>>();
    let mut fragment = triblespace::core::trible::Fragment::empty();
    let mut count = 0usize;
    for secret in secret_ids {
        let envelopes = add_recipient_envelopes_for_target(
            secrets.store_snapshot(),
            facts,
            view.facts(),
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
    use hifitime::Epoch;
    use rand_core::OsRng;
    use triblespace::core::collection::{
        grant_collection_read, grant_collection_write, AdmissionPolicy, CollectionPolicy,
    };
    use triblespace::core::repo::memoryrepo::MemoryRepo;
    use triblespace::prelude::TryToInline;

    use super::*;

    fn at(second: i64) -> IntervalValue {
        let epoch = Epoch::from_unix_seconds(second as f64);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn direct_policy(key: VerifyingKey) -> CollectionPolicy {
        CollectionPolicy::new(AdmissionPolicy::direct(key), AdmissionPolicy::direct(key))
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
            let instant = Epoch::from_unix_seconds(100.0);
            let secrets = maintain_and_snapshot(&mut store, [collection], instant)
                .await
                .unwrap();

            assert_eq!(secrets.instant(), instant);
            assert_eq!(secrets.collections().len(), 1);
            assert!(secrets.contains(secret));
            assert_eq!(secrets.open(secret, &alice).unwrap(), b"hunter2");
            assert_eq!(secrets.open(secret, &bob).unwrap(), b"hunter2");
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
            let before =
                ensure_and_snapshot(&mut store, [collection], Epoch::from_unix_seconds(100.0))
                    .await
                    .unwrap();
            assert!(!before.contains(secret));
            drop(before);

            grant_collection_write(
                &mut store,
                collection.handle(),
                &owner,
                offline_writer.verifying_key(),
            )
            .unwrap();
            let after =
                ensure_and_snapshot(&mut store, [collection], Epoch::from_unix_seconds(100.0))
                    .await
                    .unwrap();
            assert_eq!(after.open(secret, &owner).unwrap(), b"authored offline");
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
            let before =
                maintain_and_snapshot(&mut store, [collection], Epoch::from_unix_seconds(100.0))
                    .await
                    .unwrap();
            assert!(before.open(first, &bob).is_err());
            assert!(before.open(second, &bob).is_err());

            grant_collection_read(&mut store, collection.handle(), &alice, bob.verifying_key())
                .unwrap();
            let current =
                maintain_and_snapshot(&mut store, [collection], Epoch::from_unix_seconds(100.0))
                    .await
                    .unwrap();
            let added =
                maintain_recipient_envelopes(&mut store, &alice, &current, collection, &alice)
                    .unwrap();
            assert_eq!(added, 2);

            let after =
                maintain_and_snapshot(&mut store, [collection], Epoch::from_unix_seconds(100.0))
                    .await
                    .unwrap();
            assert_eq!(after.open(first, &bob).unwrap(), b"value");
            assert_eq!(after.open(second, &bob).unwrap(), b"other");
        });
    }

    #[test]
    fn configured_collection_views_conjoin_before_querying() {
        pollster::block_on(async {
            let alice = SigningKey::generate(&mut OsRng);
            let bob = SigningKey::generate(&mut OsRng);
            let policy = direct_policy(alice.verifying_key());
            let mut store = MemoryRepo::default();
            let left =
                SecretsCollection::register(&mut store, "split-secret", policy.clone()).unwrap();
            let right = SecretsCollection::register(&mut store, "split-wrap", policy).unwrap();
            let sealed =
                seal_version("split", b"still one entity", [alice.verifying_key()], at(6)).unwrap();
            let secret = sealed.secret;
            let (_, facts, metafacts, blobs) = sealed.fragment.into_parts();
            let mut secret_facts = triblespace::core::trible::TribleSet::new();
            let mut wrap_facts = triblespace::core::trible::TribleSet::new();
            for fact in facts.iter() {
                if fact.e() == &secret {
                    secret_facts.insert(fact);
                } else {
                    wrap_facts.insert(fact);
                }
            }
            let wrap = *wrap_facts
                .iter()
                .next()
                .expect("sealed version has a wrap")
                .e();
            store
                .commit(
                    left.source(),
                    &alice,
                    triblespace::core::trible::Fragment::rooted_from_parts(
                        secret,
                        secret_facts,
                        metafacts.clone(),
                        blobs.clone(),
                    ),
                )
                .unwrap();
            store
                .commit(
                    right.source(),
                    &alice,
                    triblespace::core::trible::Fragment::rooted_from_parts(
                        wrap, wrap_facts, metafacts, blobs,
                    ),
                )
                .unwrap();

            grant_collection_read(&mut store, left.handle(), &alice, bob.verifying_key()).unwrap();
            let secrets =
                maintain_and_snapshot(&mut store, [left, right], Epoch::from_unix_seconds(100.0))
                    .await
                    .unwrap();
            assert!(secrets.contains(secret));
            assert_eq!(secrets.open(secret, &alice).unwrap(), b"still one entity");

            let added =
                maintain_recipient_envelopes(&mut store, &alice, &secrets, left, &alice).unwrap();
            assert_eq!(added, 2);
            drop(secrets);

            let left_only =
                ensure_and_snapshot(&mut store, [left], Epoch::from_unix_seconds(100.0))
                    .await
                    .unwrap();
            assert_eq!(left_only.open(secret, &bob).unwrap(), b"still one entity");
        });
    }
}
