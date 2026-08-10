//! Minimal bridge from legacy faculty piles to native collection publication.
//!
//! The live side of this module knows only immutable collection records:
//! discovery reads [`CollectionStore`], and publication passes one complete
//! [`Fragment`] to [`Collection<Pile>::commit`](Collection::commit). It has no
//! target pin, head, compare-and-swap cell, activation manifest, or mutable
//! progress protocol.
//!
//! [`FrozenSource`] is the deliberately narrow exception. A stopped-world
//! migration may need the old pin table as read-only coordinates into an
//! immutable [`PileReader`] snapshot. Those coordinates never become target
//! authority and no operation on a frozen source can update them.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;

use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::collection::simplearchive_union;
use triblespace::core::collection::{
    discover_collection_records, Collection, CollectionCommit, CollectionDefinition,
    CollectionDerive, CollectionMerge, CollectionRecordDiagnostic, CollectionStore,
};
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::Inline;
use triblespace::core::repo::pile::{Pile, PileReader, ReadError};
use triblespace::core::repo::{BlobStore, BlobStoreGet, PinStore};
use triblespace::core::signing_key_file;
use triblespace::core::trible::{Fragment, TribleSet};

/// Canonical records currently known for one scoped target collection.
///
/// Discovery verifies commit self-signatures, but deliberately does not turn
/// authorship into authorization. Consumers still decide which signing keys
/// may introduce membership roots. Unsigned merge and derive records are only
/// structurally canonical here; their recipes still require
/// representation-specific validation before they become usable equations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetDiscovery {
    definition: CollectionDefinition,
    definition_present: bool,
    commits: Vec<CollectionCommit>,
    merges: Vec<CollectionMerge>,
    derives: Vec<CollectionDerive>,
    diagnostics: Vec<CollectionRecordDiagnostic>,
}

impl TargetDiscovery {
    /// Canonical `SimpleArchive`-union definition for the requested scope.
    pub const fn definition(&self) -> CollectionDefinition {
        self.definition
    }

    /// Whether the definition record is already present in the store.
    pub const fn definition_present(&self) -> bool {
        self.definition_present
    }

    /// Valid self-signed commits targeting this collection, ordered by id.
    pub fn commits(&self) -> &[CollectionCommit] {
        &self.commits
    }

    /// Structurally canonical merge claims inside this collection, ordered by
    /// id. Their recipe has not been validated by this facade.
    pub fn merges(&self) -> &[CollectionMerge] {
        &self.merges
    }

    /// Structurally canonical derive claims whose target is this collection,
    /// ordered by id. Their recipe has not been validated by this facade.
    pub fn derives(&self) -> &[CollectionDerive] {
        &self.derives
    }

    /// Invalid signed records observed during the same store enumeration.
    ///
    /// Core diagnostics intentionally retain only record identity, so they
    /// cannot be soundly scoped after signature verification fails. They are
    /// surfaced here rather than silently hidden from migration preflight.
    pub fn diagnostics(&self) -> &[CollectionRecordDiagnostic] {
        &self.diagnostics
    }
}

/// Discover one target directly through the native collection-record store.
///
/// An absent definition is represented by `definition_present == false`; the
/// canonical definition itself is still derived from `scope`. No blob scan or
/// legacy pin lookup participates in target discovery.
pub fn discover_target<S>(store: &mut S, scope: Id) -> Result<TargetDiscovery>
where
    S: CollectionStore,
{
    let definition = simplearchive_union::definition(scope);
    let records =
        discover_collection_records(store).context("discover native collection records")?;
    let definition_present = records
        .definitions()
        .iter()
        .any(|candidate| candidate == &definition);
    let commits = records
        .commits()
        .iter()
        .copied()
        .filter(|commit| commit.collection() == definition.id())
        .collect();
    let merges = records
        .merges()
        .iter()
        .copied()
        .filter(|merge| merge.collection() == definition.id())
        .collect();
    let derives = records
        .derives()
        .iter()
        .copied()
        .filter(|derive| derive.target() == definition.id())
        .collect();

    Ok(TargetDiscovery {
        definition,
        definition_present,
        commits,
        merges,
        derives,
        diagnostics: records.diagnostics().to_vec(),
    })
}

/// Resolve the durable signer path for a pile without touching the filesystem.
pub fn signer_path(pile: &Path, explicit: Option<&Path>) -> PathBuf {
    signing_key_file::resolve_path(explicit, pile)
}

/// Strictly load an existing durable signer.
///
/// This never creates a key and never substitutes an ephemeral identity.
pub fn load_signer(pile: &Path, explicit: Option<&Path>) -> Result<SigningKey> {
    let path = signer_path(pile, explicit);
    signing_key_file::load_existing(&path)
        .with_context(|| format!("load durable signing key {}", path.display()))
}

/// Explicitly initialize a durable signer, or load the concurrent winner.
///
/// Initialization is separate from ordinary reads and writes so publication
/// cannot silently mint a new authority.
pub fn initialize_signer(pile: &Path, explicit: Option<&Path>) -> Result<SigningKey> {
    let path = signer_path(pile, explicit);
    signing_key_file::init(&path)
        .with_context(|| format!("initialize durable signing key {}", path.display()))
}

/// Open and refresh an existing pile without automatic repair.
pub fn open_pile_strict(path: &Path) -> Result<Pile> {
    let mut pile = Pile::open(path).with_context(|| format!("open pile {}", path.display()))?;
    if let Err(error) = pile.refresh() {
        let close = pile.close();
        let mut failure = read_error(path, error);
        if let Err(close_error) = close {
            failure = failure.context(format!(
                "closing pile after failed refresh also failed: {close_error}"
            ));
        }
        return Err(failure);
    }
    Ok(pile)
}

/// Publish one complete fragment into one scoped native collection.
///
/// The signer is loaded before the pile is touched. Facts become collection
/// data, metafacts become signed commit metadata, and the fragment's shared
/// blob store supplies attachments referenced by either channel. Publication
/// is performed only by [`Collection<Pile>::commit`](Collection::commit),
/// whose record identity makes exact replay idempotent.
pub fn publish_fragment(
    pile_path: &Path,
    key_path: Option<&Path>,
    scope: Id,
    fragment: Fragment,
) -> Result<CollectionCommit> {
    let signer = load_signer(pile_path, key_path)?;
    let pile = open_pile_strict(pile_path)?;
    let mut collection = Collection::new(pile, scope, signer);
    let result = collection
        .commit(fragment)
        .context("publish native collection fragment");
    finish_pile(collection.into_storage(), result)
}

/// Semantic identity of the legacy coordinates seen by a migration.
///
/// The sorted pin coordinates contain content-addressed roots, so they
/// authenticate their immutable reachable closure without hashing the entire
/// physical pile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceFingerprint {
    pub pin_count: u64,
    pub digest: [u8; 32],
}

/// One legacy pin coordinate captured in an immutable source snapshot.
///
/// `value` is the exact `SimpleArchive` handle stored in the old named cell.
/// It is evidence about the source only; native target collections never use
/// this id or value as a mutable head.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct LegacyPinCoordinate {
    pub id: Id,
    pub value: Inline<Handle<SimpleArchive>>,
}

/// Read-only stopped-world input for deterministic migration transforms.
#[derive(Debug)]
pub struct FrozenSource {
    path: PathBuf,
    fingerprint: SourceFingerprint,
    legacy_pins: Vec<LegacyPinCoordinate>,
    reader: PileReader,
}

impl FrozenSource {
    /// Semantic legacy-source identity captured by this snapshot.
    pub const fn fingerprint(&self) -> SourceFingerprint {
        self.fingerprint
    }

    /// Legacy pin coordinates in canonical id order.
    pub fn legacy_pins(&self) -> &[LegacyPinCoordinate] {
        &self.legacy_pins
    }

    /// Immutable blob reader captured with the legacy coordinates.
    pub fn reader(&self) -> &PileReader {
        &self.reader
    }

    /// Fail unless the source still exposes the captured legacy coordinates.
    pub fn verify_unchanged(&self) -> Result<()> {
        let initial_length = fs::metadata(&self.path)?.len();
        let mut pile = open_pile_strict(&self.path)?;
        let result = legacy_pin_coordinates(&mut pile);
        let coordinates = finish_pile(pile, result)?;
        let final_length = fs::metadata(&self.path)?.len();
        if final_length != initial_length {
            bail!(
                "source pile changed while checking frozen coordinates ({initial_length} -> {final_length} bytes); retry"
            );
        }
        let current = fingerprint_legacy_pins(&coordinates);
        if current != self.fingerprint {
            bail!(
                "legacy coordinates in source pile {} changed after it was frozen",
                self.path.display()
            );
        }
        Ok(())
    }
}

/// Capture an immutable reader plus read-only legacy pin coordinates.
///
/// Every writer must already be stopped. The source is opened once, refreshed,
/// snapshotted, and closed without mutation. Length checks around that snapshot
/// catch an append racing the freeze and turn it into a retry rather than a
/// mixed migration input. The durable fingerprint covers only the canonical
/// pin coordinates: content-addressed values authenticate their closure, while
/// physical compaction and unrelated append history remain irrelevant.
pub fn freeze_source(path: &Path) -> Result<FrozenSource> {
    let initial_length = fs::metadata(path)
        .with_context(|| format!("stat source pile {}", path.display()))?
        .len();
    let mut pile = open_pile_strict(path)?;
    let result = (|| {
        let legacy_pins = legacy_pin_coordinates(&mut pile)?;
        let reader = pile.reader().context("snapshot frozen source pile")?;
        for pin in &legacy_pins {
            let _: TribleSet = reader
                .get(pin.value)
                .with_context(|| format!("read frozen legacy pin {:X}", pin.id))?;
        }
        Ok((legacy_pins, reader))
    })();
    let close = pile.close();
    let (legacy_pins, reader) = match (result, close) {
        (Ok(value), Ok(())) => value,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(error)) => return Err(anyhow!("close frozen source pile: {error}")),
        (Err(error), Err(close_error)) => {
            return Err(error.context(format!("closing frozen source also failed: {close_error}")))
        }
    };

    let final_length = fs::metadata(path)?.len();
    if final_length != initial_length {
        bail!(
            "source pile changed while freezing ({initial_length} -> {final_length} bytes); stop every writer and retry"
        );
    }
    let fingerprint = fingerprint_legacy_pins(&legacy_pins);

    Ok(FrozenSource {
        path: path.to_owned(),
        fingerprint,
        legacy_pins,
        reader,
    })
}

fn legacy_pin_coordinates(pile: &mut Pile) -> Result<Vec<LegacyPinCoordinate>> {
    let snapshot = pile.pin_snapshot().context("snapshot frozen legacy pins")?;
    let mut coordinates = Vec::new();
    for raw_id in snapshot.iter_ordered() {
        let id = Id::new(*raw_id).expect("legacy pin snapshot contains nil id");
        let value = *snapshot
            .get(raw_id)
            .expect("legacy pin snapshot key has no value");
        coordinates.push(LegacyPinCoordinate { id, value });
    }
    Ok(coordinates)
}

fn fingerprint_legacy_pins(pins: &[LegacyPinCoordinate]) -> SourceFingerprint {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"faculties.frozen-source.legacy-pins.v1\0");
    hasher.update(&(pins.len() as u64).to_be_bytes());
    for pin in pins {
        let id: [u8; 16] = pin.id.into();
        hasher.update(&id);
        hasher.update(&pin.value.raw);
    }
    SourceFingerprint {
        pin_count: pins.len() as u64,
        digest: *hasher.finalize().as_bytes(),
    }
}

fn read_error(path: &Path, error: ReadError) -> anyhow::Error {
    match error {
        ReadError::CorruptPile { valid_length } => anyhow!(
            "pile {} is corrupt at byte {valid_length}; refusing to auto-repair",
            path.display()
        ),
        other => anyhow!("refresh pile {}: {other}", path.display()),
    }
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    let close = pile.close();
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(anyhow!("close pile: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing pile also failed: {close_error}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::sync::atomic::{AtomicU64, Ordering};

    use anybytes::View;
    use triblespace::core::blob::encodings::longstring::LongString;
    use triblespace::core::inline::encodings::hash::Handle;
    use triblespace::core::metadata;
    use triblespace::core::repo::{BlobStorePut, PinStore, PushResult};
    use triblespace::macros::entity;

    use super::*;

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestFiles {
        directory: PathBuf,
        pile: PathBuf,
        key: PathBuf,
    }

    impl TestFiles {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "faculties-native-collection-{}-{serial}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&directory);
            fs::create_dir_all(&directory).unwrap();
            let pile = directory.join("test.pile");
            File::create(&pile).unwrap();
            let key = directory.join("test.key");
            Self {
                directory,
                pile,
                key,
            }
        }
    }

    impl Drop for TestFiles {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    #[test]
    fn publication_conserves_both_fact_channels_and_attachments_and_replays_idempotently() {
        let files = TestFiles::new();
        initialize_signer(&files.pile, Some(&files.key)).unwrap();

        let mut fragment = entity! { _ @ metadata::name: "content attachment" };
        let content_root = fragment.root().unwrap();
        let description = entity! { _ @ metadata::name: "metadata attachment" };
        let metadata_root = description.root().unwrap();
        fragment.describe_with(description);
        let expected_facts = fragment.facts().clone();
        let expected_metafacts = fragment.metafacts().clone();
        assert!(!expected_facts.is_empty());
        assert!(!expected_metafacts.is_empty());

        let first =
            publish_fragment(&files.pile, Some(&files.key), id(1), fragment.clone()).unwrap();
        let after_first = fs::metadata(&files.pile).unwrap().len();

        let unrelated = entity! { _ @ metadata::tag: &id(9) };
        publish_fragment(&files.pile, Some(&files.key), id(2), unrelated).unwrap();
        let before_replay = fs::metadata(&files.pile).unwrap().len();
        let repeated = publish_fragment(&files.pile, Some(&files.key), id(1), fragment).unwrap();
        let after_replay = fs::metadata(&files.pile).unwrap().len();

        assert_eq!(repeated, first);
        assert!(before_replay > after_first);
        assert_eq!(after_replay, before_replay);

        let mut pile = open_pile_strict(&files.pile).unwrap();
        assert!(pile
            .pins()
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
            .is_empty());
        let target = discover_target(&mut pile, id(1)).unwrap();
        assert!(target.definition_present());
        assert_eq!(target.commits(), &[first]);
        assert!(target.merges().is_empty());
        assert!(target.derives().is_empty());
        assert!(target.diagnostics().is_empty());

        let unrelated_target = discover_target(&mut pile, id(2)).unwrap();
        assert!(unrelated_target.definition_present());
        assert_eq!(unrelated_target.commits().len(), 1);

        let reader = pile.reader().unwrap();
        let data_handle = Handle::<SimpleArchive>::from_hash(first.data());
        let actual_facts: TribleSet = reader.get(data_handle).unwrap();
        let actual_metafacts: TribleSet = reader.get(first.metadata()).unwrap();
        assert_eq!(actual_facts, expected_facts);
        assert_eq!(actual_metafacts, expected_metafacts);

        let content_handle = actual_facts
            .iter()
            .find(|fact| fact.e() == &content_root && fact.a() == &metadata::name.id())
            .map(|fact| *fact.v::<Handle<LongString>>())
            .expect("content attachment handle");
        let content: View<str> = reader.get(content_handle).unwrap();
        assert_eq!(&*content, "content attachment");
        let metadata_handle = actual_metafacts
            .iter()
            .find(|fact| fact.e() == &metadata_root && fact.a() == &metadata::name.id())
            .map(|fact| *fact.v::<Handle<LongString>>())
            .expect("metadata attachment handle");
        let metadata_text: View<str> = reader.get(metadata_handle).unwrap();
        assert_eq!(&*metadata_text, "metadata attachment");
        pile.close().unwrap();
    }

    #[test]
    fn frozen_source_is_read_only_and_detects_semantic_pin_changes() {
        let files = TestFiles::new();
        let pin_id = id(7);
        let pin_facts = entity! { _ @ metadata::tag: &id(8) }.into_facts();
        let mut pile = open_pile_strict(&files.pile).unwrap();
        let value = pile.put::<SimpleArchive, _>(pin_facts.clone()).unwrap();
        assert!(matches!(
            pile.update(pin_id, None, Some(value)).unwrap(),
            PushResult::Success()
        ));
        pile.close().unwrap();

        let before = fs::read(&files.pile).unwrap();
        let frozen = freeze_source(&files.pile).unwrap();
        assert_eq!(fs::read(&files.pile).unwrap(), before);
        assert_eq!(
            frozen.legacy_pins(),
            &[LegacyPinCoordinate { id: pin_id, value }]
        );
        let from_snapshot: TribleSet = frozen.reader().get(value).unwrap();
        assert_eq!(from_snapshot, pin_facts);
        frozen.verify_unchanged().unwrap();

        // Physical append history is not source identity. A blob that changes
        // no legacy coordinate must not invalidate a deterministic transform.
        let mut pile = open_pile_strict(&files.pile).unwrap();
        pile.put::<SimpleArchive, _>(entity! { _ @ metadata::tag: &id(11) }.into_facts())
            .unwrap();
        pile.close().unwrap();
        frozen.verify_unchanged().unwrap();

        let mut pile = open_pile_strict(&files.pile).unwrap();
        let later_value = pile
            .put::<SimpleArchive, _>(entity! { _ @ metadata::tag: &id(9) }.into_facts())
            .unwrap();
        assert!(matches!(
            pile.update(id(10), None, Some(later_value)).unwrap(),
            PushResult::Success()
        ));
        pile.close().unwrap();
        let error = frozen.verify_unchanged().unwrap_err();
        assert!(format!("{error:#}").contains("changed after it was frozen"));
    }

    #[test]
    fn missing_signer_fails_before_the_pile_is_touched() {
        let files = TestFiles::new();
        let missing = files.directory.join("missing.key");
        let before = fs::metadata(&files.pile).unwrap().len();

        let error = publish_fragment(
            &files.pile,
            Some(&missing),
            id(1),
            entity! { _ @ metadata::tag: &id(2) },
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("load durable signing key"));
        assert!(!missing.exists());
        assert_eq!(fs::metadata(&files.pile).unwrap().len(), before);
    }
}
