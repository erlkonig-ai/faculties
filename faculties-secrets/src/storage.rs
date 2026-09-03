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
use triblespace::core::collection::succinctarchive_union::{
    RawToRank9AcceleratedMapping, SimpleToSuccinctMapping,
};
use triblespace::core::collection::{
    collection_read_audience_at, Collection, CollectionHandle, CollectionPolicy,
    CollectionReadAudience, CollectionSnapshotExt, CollectionStoreExt,
};
use triblespace::core::repo::{BlobStoreGet, CapabilityProofRead, Store, StoreSnapshot};

use super::{
    add_recipient_envelopes_from_facts, seal_version, secret_rows, IntervalValue, SecretsFacts,
    SecretsSnapshot, SecretsView,
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
            .derive(source, SimpleToSuccinctMapping, policy.clone())
            .map_err(|error| anyhow!("register Succinct Secrets collection: {error}"))?;
        let rank9 = store
            .derive(succinct, RawToRank9AcceleratedMapping, policy)
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

    /// Maintain both derived lattices for one frozen admitted support.
    pub fn maintain<S>(self, store: &mut S) -> Result<S::Snapshot>
    where
        S: Store + CollectionStoreExt,
    {
        let before = store
            .snapshot()
            .context("freeze Secrets support before maintenance")?;
        let support = self
            .source
            .admitted(&before)
            .context("admit Secrets source support")?;
        drop(before);
        drop(
            store
                .maintain_exact::<SimpleToSuccinctMapping>(self.succinct, &support)
                .context("maintain Succinct Secrets collection")?,
        );
        store
            .maintain_exact::<RawToRank9AcceleratedMapping>(self.rank9, &support)
            .context("maintain Rank9 Secrets collection")
    }
}

/// Attach explicitly configured collections at one immutable store boundary.
///
/// This never performs maintenance. It reports exactly the support physically
/// realized in `snapshot`, preserving the snapshot/derivation boundary.
pub fn snapshot<R, I>(store_snapshot: R, collections: I) -> Result<SecretsSnapshot<R>>
where
    R: StoreSnapshot
        + BlobStoreGet
        + triblespace::core::repo::BlobStoreList
        + triblespace::core::repo::BlobStoreMeta
        + triblespace::core::collection::CollectionRead
        + triblespace::core::repo::CapabilityProofRead,
    I: IntoIterator<Item = SecretsCollection>,
{
    let mut views = Vec::new();
    for collection in collections {
        let observed = store_snapshot
            .collection(collection.rank9)
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
    Ok(SecretsSnapshot::new(store_snapshot, views))
}

/// Maintain each explicit policy boundary, then freeze and attach one shared
/// store snapshot.
pub fn maintain_and_snapshot<S, I>(
    store: &mut S,
    collections: I,
) -> Result<SecretsSnapshot<S::Snapshot>>
where
    S: Store + CollectionStoreExt,
    I: IntoIterator<Item = SecretsCollection>,
{
    let collections = collections.into_iter().collect::<Vec<_>>();
    for collection in &collections {
        drop(collection.maintain(store)?);
    }
    let store_snapshot = store
        .snapshot()
        .context("freeze maintained Secrets snapshot")?;
    snapshot(store_snapshot, collections)
}

fn admitted_readers<R>(snapshot: &R, collection: SecretsCollection) -> Result<Vec<VerifyingKey>>
where
    R: BlobStoreGet + CapabilityProofRead,
{
    match collection_read_audience_at(
        snapshot,
        collection.handle(),
        triblespace::core::clock::epoch_now(),
    )
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
/// Local `commit` remains unconditional. The audience snapshot only selects
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
/// One frozen post-maintenance store snapshot supplies both the immutable fact
/// view and admitted audience. New evidence arriving later cannot split the
/// decision across temporal boundaries; another maintenance call observes it.
pub fn maintain_recipient_envelopes<S>(
    store: &mut S,
    signing_key: &SigningKey,
    collection: SecretsCollection,
    holder: &SigningKey,
) -> Result<usize>
where
    S: Store + CollectionStoreExt,
{
    let store_snapshot = collection.maintain(store)?;
    let secrets = snapshot(store_snapshot, [collection])?;
    let Some(view) = secrets
        .collections()
        .iter()
        .find(|view| view.collection() == collection.handle())
    else {
        return Ok(0);
    };
    let recipients = admitted_readers(secrets.store_snapshot(), collection)?;
    let secret_ids = secret_rows(view.facts())
        .into_iter()
        .map(|row| row.id)
        .collect::<std::collections::BTreeSet<_>>();
    let mut fragment = triblespace::core::trible::Fragment::empty();
    let mut count = 0usize;
    for secret in secret_ids {
        let envelopes = add_recipient_envelopes_from_facts(
            secrets.store_snapshot(),
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
    use triblespace::core::collection::{grant_collection_read, AdmissionPolicy, CollectionPolicy};
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
        let secrets = maintain_and_snapshot(&mut store, [collection]).unwrap();

        assert_eq!(secrets.collections().len(), 1);
        assert!(secrets.contains(secret));
        assert_eq!(secrets.open(secret, &alice).unwrap(), b"hunter2");
        assert_eq!(secrets.open(secret, &bob).unwrap(), b"hunter2");
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
    fn newly_admitted_reader_gets_an_additive_wrap() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let mut store = MemoryRepo::default();
        let collection = SecretsCollection::register(
            &mut store,
            "shared-secrets",
            direct_policy(alice.verifying_key()),
        )
        .unwrap();
        let first = add_secret(&mut store, &alice, collection, "token", b"value", at(3)).unwrap();
        let second =
            add_secret(&mut store, &alice, collection, "password", b"other", at(4)).unwrap();
        let before = maintain_and_snapshot(&mut store, [collection]).unwrap();
        assert!(before.open(first, &bob).is_err());
        assert!(before.open(second, &bob).is_err());

        grant_collection_read(&mut store, collection.handle(), &alice, bob.verifying_key())
            .unwrap();
        let added = maintain_recipient_envelopes(&mut store, &alice, collection, &alice).unwrap();
        assert_eq!(added, 2);

        let after = maintain_and_snapshot(&mut store, [collection]).unwrap();
        assert_eq!(after.open(first, &bob).unwrap(), b"value");
        assert_eq!(after.open(second, &bob).unwrap(), b"other");
    }
}
