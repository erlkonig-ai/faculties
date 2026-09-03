//! Durable signing identity and native-collection plumbing shared by every faculty.
//!
//! Three concerns that every faculty needs before it can read or write
//! anything, and that none of them should re-implement:
//!
//! - **Signing identity.** [`signer_path`], [`load_signer`], and [`initialize_signer`]
//!   resolve one durable signing key per pile. Ordinary commands load; only an
//!   explicit initialization mints. No faculty falls back to an ephemeral
//!   identity.
//! - **Opening.** [`open_pile_strict`] refreshes eagerly and reports a
//!   malformed suffix as evidence through [`pile_read_error`] rather than
//!   silently truncating it.
//! - **Publication and discovery.** [`publish_fragment`] / [`publish_fragments`]
//!   commit whole fragments into one scoped collection; [`discover_target`]
//!   reports what a scope already holds.
//!
//! This module was carved out of the storage cutover, which is where these
//! primitives were first written. The cutover itself now lives in the separate
//! `faculties-migrations` crate and depends on this module rather than the
//! other way round.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};

use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::collection::{
    Collection, CollectionCommit, CollectionDerive, CollectionMerge, CollectionRead,
    CollectionRecord, CollectionRecordDiagnostic, CollectionRecordDiagnosticError,
    CollectionRecordSelector, CollectionSnapshotExt, CollectionStoreExt, Support,
};
use triblespace::core::id::Id;
use triblespace::core::repo::pile::{Pile, ReadError};
use triblespace::core::repo::{BlobStoreGet, CapabilityProofRead, SnapshotSource, StoreRead};
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
    commits: Vec<CollectionCommit>,
    merges: Vec<CollectionMerge>,
    derives: Vec<CollectionDerive>,
    diagnostics: Vec<CollectionRecordDiagnostic>,
}

impl TargetDiscovery {
    /// Valid self-signed commits targeting this collection, in deterministic
    /// store order.
    pub fn commits(&self) -> &[CollectionCommit] {
        &self.commits
    }

    /// Structurally canonical merge claims inside this collection, in
    /// deterministic store order. Their recipe has not been validated here.
    pub fn merges(&self) -> &[CollectionMerge] {
        &self.merges
    }

    /// Structurally canonical derive claims whose target is this collection,
    /// in deterministic store order. Their recipe has not been validated here.
    pub fn derives(&self) -> &[CollectionDerive] {
        &self.derives
    }

    /// Invalid signed records observed during the same store enumeration.
    ///
    /// Core diagnostics retain the exact structurally valid commit, so they
    /// can still be scoped after signature verification fails. They are
    /// surfaced here rather than silently hidden from migration preflight.
    pub fn diagnostics(&self) -> &[CollectionRecordDiagnostic] {
        &self.diagnostics
    }
}

/// Discover one target directly through the native collection-record store.
///
/// `scope` resolves the faculty's canonical name. Without an exact override,
/// `authority` seeds the descriptor's direct READ and WRITE policies; with an
/// override, the selected descriptor keeps its own immutable policies and the
/// signer must already satisfy WRITE admission. The returned handle selects
/// records. No definition registry, blob scan, or legacy pin lookup
/// participates in target discovery.
pub fn discover_target<S>(
    store: &mut S,
    scope: Id,
    authority: VerifyingKey,
) -> Result<TargetDiscovery>
where
    S: CollectionStoreExt + SnapshotSource,
    <S as SnapshotSource>::Snapshot: BlobStoreGet + CapabilityProofRead + CollectionRead,
{
    let collection = crate::collection_names::open_configured(store, scope, authority)
        .context("open target collection descriptor")?;
    let snapshot = store
        .snapshot()
        .context("freeze target collection store snapshot")?;
    let selectors = std::collections::BTreeSet::from([CollectionRecordSelector::Collection(
        collection.handle(),
    )]);
    let records = snapshot
        .select_records(&selectors)
        .context("discover native collection records")?;
    let mut commits = Vec::new();
    let mut merges = Vec::new();
    let mut derives = Vec::new();
    let mut diagnostics = Vec::new();
    for record in records {
        match record {
            CollectionRecord::Commit(commit) => match commit.verify_strict() {
                Ok(()) => commits.push(commit),
                Err(error) => diagnostics.push(CollectionRecordDiagnostic {
                    record: commit,
                    error: CollectionRecordDiagnosticError::InvalidCommit(error),
                }),
            },
            CollectionRecord::Merge(merge) => merges.push(merge),
            CollectionRecord::Derive(derive) => derives.push(derive),
        }
    }

    Ok(TargetDiscovery {
        commits,
        merges,
        derives,
        diagnostics,
    })
}

/// Read one authorized SimpleArchive union through a caller-supplied coherent
/// store snapshot, returning the foundational support used for maintained indexes.
pub fn read_fact_collection<S>(
    collection: Collection<SimpleArchive>,
    snapshot: &S,
) -> Result<(TribleSet, Support)>
where
    S: StoreRead,
{
    let support = collection
        .admitted(snapshot)
        .context("discover authorized collection support")?;
    let facts = snapshot
        .collection_exact(collection, &support)
        .context("attach authorized collection support")?
        .view::<TribleSet>()
        .context("read authorized collection facts")?;
    Ok((facts, support))
}

/// Read one authorized SimpleArchive union and retain the exact provenance
/// claims selected by the same admission decision.
pub fn read_fact_collection_with_commits<S>(
    collection: Collection<SimpleArchive>,
    snapshot: &S,
) -> Result<(TribleSet, Support, Vec<CollectionCommit>)>
where
    S: StoreRead,
{
    let (support, commits) = collection
        .admitted_with_commits(snapshot)
        .context("discover authorized collection support and commits")?;
    let facts = snapshot
        .collection_exact(collection, &support)
        .context("attach authorized collection support")?
        .view::<TribleSet>()
        .context("read authorized collection facts")?;
    Ok((facts, support, commits))
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
/// cannot silently mint a new identity.
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
        let mut failure = pile_read_error(path, error);
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
/// is performed only by [`CollectionStoreExt::commit`]; equality of its exact
/// canonical record makes replay idempotent.
pub fn publish_fragment(
    pile_path: &Path,
    key_path: Option<&Path>,
    scope: Id,
    fragment: Fragment,
) -> Result<CollectionCommit> {
    let mut commits = publish_fragments(pile_path, key_path, scope, [fragment])?;
    Ok(commits
        .pop()
        .expect("one input fragment produces one collection commit"))
}

/// Publish a deterministic sequence of complete fragments into one collection.
///
/// This is the authored-commit migration path: the target pile is opened once,
/// each input crosses the same narrow
/// [`CollectionStoreExt::commit`] boundary, and the
/// pile is closed even if a later publication fails. Replaying a prefix or the
/// whole sequence is idempotent because both blobs and collection records are
/// content addressed.
pub fn publish_fragments(
    pile_path: &Path,
    key_path: Option<&Path>,
    scope: Id,
    fragments: impl IntoIterator<Item = Fragment>,
) -> Result<Vec<CollectionCommit>> {
    let signer = load_signer(pile_path, key_path)?;
    let mut pile = open_pile_strict(pile_path)?;
    let collection =
        crate::collection_names::open_configured(&mut pile, scope, signer.verifying_key())
            .context("open native collection descriptor")?;
    let result = (|| {
        let mut commits = Vec::new();
        for fragment in fragments {
            commits.push(
                pile.commit(collection, &signer, fragment)
                    .context("publish native collection fragment")?,
            );
        }
        Ok(commits)
    })();
    finish_pile(pile, result)
}

/// Render one non-mutating pile read failure without presenting data loss as
/// routine repair.
///
/// A malformed known record and an interrupted append share the same
/// conservative core error. Only an operator inspecting the bytes can decide
/// whether the suffix is disposable, so faculties report evidence and stop.
pub fn pile_read_error(path: &Path, error: ReadError) -> anyhow::Error {
    match error {
        ReadError::CorruptPile { valid_length } => anyhow!(
            "pile {} has a malformed or incomplete known record at byte {valid_length}; this \
             reader cannot prove that the remaining bytes are a disposable torn write. The pile \
             was left unchanged. Upgrade `trible` to the matching current source cohort, then \
             inspect that boundary with `trible pile diagnose record-at {} {valid_length}` before \
             considering any destructive action",
            path.display(),
            path.display()
        ),
        ReadError::UnsupportedRecord { .. } => anyhow!(
            "pile {} contains a record format unsupported by this binary ({error}); this is \
             likely version skew. Upgrade to a reader that recognizes the marker. The pile was \
             left unchanged",
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
    use std::fs::{self, File};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use anybytes::View;
    use ed25519_dalek::SigningKey;
    use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace::core::blob::encodings::utf8string::UTF8String;
    use triblespace::core::collection::{empty_metadata_handle, CollectionRecord, CollectionStore};
    use triblespace::core::inline::encodings::hash::Handle;
    use triblespace::core::inline::Inline;
    use triblespace::core::metadata;
    use triblespace::core::repo::memoryrepo::MemoryRepo;
    use triblespace::core::repo::{BlobStoreGet, SnapshotSource};
    use triblespace::core::trible::TribleSet;
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
    fn strict_open_reports_evidence_without_prescribing_data_loss() {
        let files = TestFiles::new();
        fs::write(&files.pile, [0xFF; 8]).unwrap();
        let before = fs::read(&files.pile).unwrap();

        let error = open_pile_strict(&files.pile)
            .err()
            .expect("malformed pile must fail strict open");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("malformed or incomplete known record at byte 0"));
        assert!(rendered.contains("cannot prove"));
        assert!(rendered.contains("matching current source cohort"));
        assert!(rendered.contains("pile diagnose record-at"));
        assert!(!rendered.contains("pile amputate"));
        assert_eq!(fs::read(&files.pile).unwrap(), before);

        let mut unsupported = [0u8; 256];
        unsupported[..16].fill(0xA5);
        fs::write(&files.pile, unsupported).unwrap();
        let error = open_pile_strict(&files.pile)
            .err()
            .expect("unsupported marker must fail strict open");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("unsupported by this binary"));
        assert!(rendered.contains("likely version skew"));
        assert!(!rendered.contains("pile amputate"));
        assert_eq!(fs::read(&files.pile).unwrap(), unsupported);
    }

    #[test]
    fn target_discovery_registers_descriptor_without_definition_record() {
        // Two REAL scopes rather than two arbitrary ids: a root is anchored by
        // a name now, and an id this build has never named is one it cannot
        // open at all. Any two distinct faculties prove the same thing.
        let signer = SigningKey::from_bytes(&[7; 32]);
        let team = signer.verifying_key();
        let target_scope = crate::schemas::wiki::DEFAULT_SCOPE_ID;
        let other_scope = crate::schemas::compass::DEFAULT_SCOPE_ID;
        let mut store = MemoryRepo::default();
        let target = crate::collection_names::open(&mut store, target_scope, team)
            .unwrap()
            .handle();
        let other = crate::collection_names::open(&mut store, other_scope, team)
            .unwrap()
            .handle();

        let target_commit = CollectionCommit::sign(
            &signer,
            target,
            Inline::new([1; 32]),
            empty_metadata_handle(),
        );
        let other_commit = CollectionCommit::sign(
            &signer,
            other,
            Inline::new([2; 32]),
            empty_metadata_handle(),
        );
        let target_merge = CollectionMerge::new(
            target,
            Inline::new([3; 32]),
            Inline::new([4; 32]),
            Inline::new([5; 32]),
        );
        let other_merge = CollectionMerge::new(
            other,
            Inline::new([6; 32]),
            Inline::new([7; 32]),
            Inline::new([8; 32]),
        );
        let derive_to_target =
            CollectionDerive::new(target, Inline::new([9; 32]), Inline::new([10; 32]));
        let derive_from_target =
            CollectionDerive::new(other, Inline::new([11; 32]), Inline::new([12; 32]));

        for record in [
            CollectionRecord::Commit(target_commit),
            CollectionRecord::Commit(other_commit),
            CollectionRecord::Merge(target_merge),
            CollectionRecord::Merge(other_merge),
            CollectionRecord::Derive(derive_to_target),
            CollectionRecord::Derive(derive_from_target),
        ] {
            store.insert(record).unwrap();
        }

        let discovered = discover_target(&mut store, target_scope, team).unwrap();
        assert_eq!(discovered.commits(), &[target_commit]);
        assert_eq!(discovered.merges(), &[target_merge]);
        assert_eq!(discovered.derives(), &[derive_to_target]);
        assert!(discovered.diagnostics().is_empty());
        assert!(
            !store.blobs.is_empty(),
            "registration retains the descriptor attachment closure"
        );
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

        let team = load_signer(&files.pile, Some(&files.key))
            .unwrap()
            .verifying_key();
        let target_scope = crate::schemas::wiki::DEFAULT_SCOPE_ID;
        let other_scope = crate::schemas::compass::DEFAULT_SCOPE_ID;
        let first = publish_fragment(
            &files.pile,
            Some(&files.key),
            target_scope,
            fragment.clone(),
        )
        .unwrap();
        let after_first = fs::metadata(&files.pile).unwrap().len();

        let unrelated = entity! { _ @ metadata::tag: &id(9) };
        publish_fragment(&files.pile, Some(&files.key), other_scope, unrelated).unwrap();
        let before_replay = fs::metadata(&files.pile).unwrap().len();
        let repeated =
            publish_fragment(&files.pile, Some(&files.key), target_scope, fragment).unwrap();
        let after_replay = fs::metadata(&files.pile).unwrap().len();

        assert_eq!(repeated, first);
        assert!(before_replay > after_first);
        assert_eq!(after_replay, before_replay);

        let mut pile = open_pile_strict(&files.pile).unwrap();
        let target_collection =
            crate::collection_names::open(&mut pile, target_scope, team).unwrap();
        let target = discover_target(&mut pile, target_scope, team).unwrap();
        assert_eq!(target.commits(), &[first]);
        assert_eq!(target.commits()[0].collection(), target_collection.handle());
        assert!(target.merges().is_empty());
        assert!(target.derives().is_empty());
        assert!(target.diagnostics().is_empty());

        let unrelated_target = discover_target(&mut pile, other_scope, team).unwrap();
        assert_eq!(unrelated_target.commits().len(), 1);

        let reader = pile.snapshot().unwrap();
        let data_handle = Handle::<SimpleArchive>::from_hash(first.data());
        let actual_facts: TribleSet = reader.get(data_handle).unwrap();
        let actual_metafacts: TribleSet = reader.get(first.metadata()).unwrap();
        assert_eq!(actual_facts, expected_facts);
        assert_eq!(actual_metafacts, expected_metafacts);

        let content_handle = actual_facts
            .iter()
            .find(|fact| fact.e() == &content_root && fact.a() == &metadata::name.id())
            .map(|fact| *fact.v::<Handle<UTF8String>>())
            .expect("content attachment handle");
        let content: View<str> = reader.get(content_handle).unwrap();
        assert_eq!(&*content, "content attachment");
        let metadata_handle = actual_metafacts
            .iter()
            .find(|fact| fact.e() == &metadata_root && fact.a() == &metadata::name.id())
            .map(|fact| *fact.v::<Handle<UTF8String>>())
            .expect("metadata attachment handle");
        let metadata_text: View<str> = reader.get(metadata_handle).unwrap();
        assert_eq!(&*metadata_text, "metadata attachment");
        pile.close().unwrap();
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
