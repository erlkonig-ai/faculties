//! Durable authority and native-collection plumbing shared by every faculty.
//!
//! Three concerns that every faculty needs before it can read or write
//! anything, and that none of them should re-implement:
//!
//! - **Authority.** [`signer_path`], [`load_signer`], and [`initialize_signer`]
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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};

use triblespace::core::authority::{
    publish_grant, resolve_authority, AuthorityDiagnostic, AuthorityGrant, AuthorityMode,
    ACTION_WRITE,
};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::IntoBlob;
use triblespace::core::blob::{Blob, TryFromBlob};
use triblespace::core::collection::records::CollectionHandle;
use triblespace::core::collection::{
    discover_collection_records, CollectionCommit, CollectionDerive, CollectionMerge,
    CollectionRecordDiagnostic, CollectionStore,
};
use triblespace::core::id::Id;
use triblespace::core::repo::memoryrepo::MemoryRepo;
use triblespace::core::repo::pile::{Pile, ReadError};
use triblespace::core::repo::{BlobStore, BlobStoreGet};
use triblespace::core::signing_key_file;
use triblespace::core::trible::{Fragment, TribleSet};

/// One configured faculty root and its deterministic team-of-one WRITE grant.
///
/// The row comes from [`crate::collection_names::table`], never from collection
/// discovery. `target_commits` is therefore only a diagnostic about whether
/// that configured resource has already been used; it does not decide whether
/// the resource receives authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeamOfOneWriteGrantRow {
    scope: Id,
    name: &'static str,
    resource: CollectionHandle,
    commit: CollectionCommit,
    target_commits: usize,
    accepted: bool,
}

impl TeamOfOneWriteGrantRow {
    pub const fn scope(&self) -> Id {
        self.scope
    }

    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn resource(&self) -> CollectionHandle {
        self.resource
    }

    pub const fn commit(&self) -> CollectionCommit {
        self.commit
    }

    pub const fn target_commits(&self) -> usize {
        self.target_commits
    }

    pub const fn accepted(&self) -> bool {
        self.accepted
    }
}

/// Exact state of the current build's team-of-one faculty WRITE bootstrap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeamOfOneWriteAuthorityReport {
    team_root: [u8; 32],
    rows: Vec<TeamOfOneWriteGrantRow>,
    diagnostics: Vec<AuthorityDiagnostic>,
    published: Vec<Id>,
    ignored_foreign_roots: usize,
    ignored_unknown_roots: usize,
}

impl TeamOfOneWriteAuthorityReport {
    pub const fn team_root(&self) -> [u8; 32] {
        self.team_root
    }

    pub fn rows(&self) -> &[TeamOfOneWriteGrantRow] {
        &self.rows
    }

    pub fn diagnostics(&self) -> &[AuthorityDiagnostic] {
        &self.diagnostics
    }

    /// Grant records this call actually had to publish.
    ///
    /// Plans and exact replays return an empty slice. Consumers that need
    /// stable output should report [`Self::rows`] instead: their commit ids do
    /// not depend on whether this was the first run.
    pub fn published(&self) -> &[Id] {
        &self.published
    }

    pub const fn ignored_foreign_roots(&self) -> usize {
        self.ignored_foreign_roots
    }

    pub const fn ignored_unknown_roots(&self) -> usize {
        self.ignored_unknown_roots
    }

    pub fn accepted(&self) -> usize {
        self.rows.iter().filter(|row| row.accepted).count()
    }

    pub fn missing(&self) -> usize {
        self.rows.len() - self.accepted()
    }
}

/// Canonical records currently known for one scoped target collection.
///
/// Discovery verifies commit self-signatures, but deliberately does not turn
/// authorship into authorization. Consumers still decide which signing keys
/// may introduce membership roots. Unsigned merge and derive records are only
/// structurally canonical here; their recipes still require
/// representation-specific validation before they become usable equations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetDiscovery {
    descriptor: Fragment,
    commits: Vec<CollectionCommit>,
    merges: Vec<CollectionMerge>,
    derives: Vec<CollectionDerive>,
    diagnostics: Vec<CollectionRecordDiagnostic>,
}

impl TargetDiscovery {
    /// Canonical `SimpleArchive`-union descriptor for the requested scope.
    ///
    /// A `Fragment` rather than a bare `TribleSet`: this one was BUILT here, so
    /// it still carries its root and metafacts, and throwing those away only to
    /// scan for them again later would be paying to lose information.
    pub fn descriptor(&self) -> &Fragment {
        &self.descriptor
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
/// The canonical descriptor and its collection handle are derived from `scope`
/// and `team`; no definition registry, blob scan, or legacy pin lookup
/// participates in target discovery.
///
/// `team` is the team's ROOT key, not the key that signs commits — they
/// coincide only for a team of one, and it is a parameter rather than a default
/// because a collection rooted at the wrong key is one nothing else can find.
pub fn discover_target<S>(store: &mut S, scope: Id, team: VerifyingKey) -> Result<TargetDiscovery>
where
    S: CollectionStore,
{
    let descriptor = crate::collection_names::root_descriptor(scope, team);
    // Written out rather than reached for: core deliberately offers no helper
    // for hashing a descriptor it did not store, because a handle computed
    // beside a store instead of by it can name a collection whose descriptor is
    // absent. Discovery only ever compares against this one.
    let collection = IntoBlob::<SimpleArchive>::to_blob(descriptor.facts().clone()).get_handle();
    let records =
        discover_collection_records(store).context("discover native collection records")?;
    let commits = records
        .commits()
        .iter()
        .copied()
        .filter(|commit| commit.collection() == collection)
        .collect();
    let merges = records
        .merges()
        .iter()
        .copied()
        .filter(|merge| merge.collection() == collection)
        .collect();
    let derives = records
        .derives()
        .iter()
        .copied()
        .filter(|derive| derive.target() == collection)
        .collect();

    Ok(TargetDiscovery {
        descriptor,
        commits,
        merges,
        derives,
        diagnostics: records.diagnostics().to_vec(),
    })
}

/// One node the pile itself attests, by the key it signed its commits with.
///
/// A pile is a roster of its own writers: every commit carries the public key
/// that signed it, and discovery keeps only commits whose signature verifies.
/// So the set of keys that have ever written is readable from the pile, with
/// no registry to maintain and no key to distribute.
///
/// This is *discovery*, and discovery is not entitlement. Having written to a
/// pile makes a node addressable — something a secret can be sealed to by
/// name — and nothing more. What a node may read is decided entirely by the
/// grants an admin issues and the wraps a holder creates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeObservation {
    public_key: [u8; 32],
    commits: usize,
    collections: BTreeSet<CollectionHandle>,
}

impl NodeObservation {
    /// Ed25519 public key this node signs with.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Commits in this pile whose signature this key verifies.
    pub fn commits(&self) -> usize {
        self.commits
    }

    /// Distinct collections this node has written into.
    pub fn collections(&self) -> usize {
        self.collections.len()
    }
}

/// Every node that has written a verifiable commit into this pile.
///
/// Ordered by public key, so two runs over the same pile report the same
/// roster in the same order.
pub fn discover_nodes<S>(store: &mut S) -> Result<Vec<NodeObservation>>
where
    S: CollectionStore,
{
    let records =
        discover_collection_records(store).context("discover native collection records")?;
    let mut by_key: BTreeMap<[u8; 32], (usize, BTreeSet<CollectionHandle>)> = BTreeMap::new();
    for commit in records.commits() {
        let entry = by_key.entry(commit.public_key().raw).or_default();
        entry.0 += 1;
        entry.1.insert(commit.collection());
    }
    Ok(by_key
        .into_iter()
        .map(|(public_key, (commits, collections))| NodeObservation {
            public_key,
            commits,
            collections,
        })
        .collect())
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

#[derive(Default)]
struct FacultyRootObservation {
    target_commits: BTreeMap<CollectionHandle, usize>,
    local_known_roots: usize,
    foreign_known_roots: usize,
    unknown_named_roots: usize,
}

/// Observe named roots only to diagnose the migration boundary.
///
/// Discovery never supplies grant targets. The closed target set comes from
/// `collection_names::table`; this pass exists only to count already-used
/// targets, report ignored roots, and reject the common wrong-`--key` failure
/// before it grants an otherwise empty parallel team.
fn observe_faculty_roots(pile: &mut Pile, team: VerifyingKey) -> Result<FacultyRootObservation> {
    let records =
        discover_collection_records(pile).context("discover roots before WRITE bootstrap")?;
    let mut observed = FacultyRootObservation::default();
    let mut collections = BTreeSet::new();
    for commit in records.commits() {
        *observed
            .target_commits
            .entry(commit.collection())
            .or_default() += 1;
        collections.insert(commit.collection());
    }

    let known_names = crate::collection_names::table()
        .into_iter()
        .map(|(_, name, _)| name)
        .collect::<BTreeSet<_>>();
    let reader = pile
        .reader()
        .context("open descriptor view before WRITE bootstrap")?;
    for collection in collections {
        let Ok(blob): Result<Blob<SimpleArchive>, _> = reader.get(collection) else {
            continue;
        };
        let Ok(facts) = TribleSet::try_from_blob(blob) else {
            continue;
        };
        let Some(Ok(name)) = triblespace::core::collection::descriptor::name(&facts) else {
            // Pre-naming roots are intentionally not authority targets.
            continue;
        };
        let descriptor_team = triblespace::core::collection::descriptor::team(&facts);
        if name.as_str() == triblespace::core::authority::AUTHORITY_COLLECTION_NAME {
            // The authority ledger governs roots, so it is never a grant
            // target. It is still decisive evidence of which team already
            // inhabits this pile: ignoring it would let an interrupted
            // grant-only initialization be silently parallel-rooted by a
            // different key.
            match descriptor_team {
                Some(Ok(root)) if root == team => observed.local_known_roots += 1,
                Some(Ok(_)) => observed.foreign_known_roots += 1,
                _ => {}
            }
            continue;
        }
        if !known_names.contains(name.as_str()) {
            observed.unknown_named_roots += 1;
            continue;
        }
        match descriptor_team {
            Some(Ok(root)) if root == team => observed.local_known_roots += 1,
            Some(Ok(_)) => observed.foreign_known_roots += 1,
            _ => {}
        }
    }

    if observed.local_known_roots == 0 && observed.foreign_known_roots > 0 {
        anyhow::bail!(
            "the supplied signing key roots none of this pile's recognized faculty collections, \
             while {} recognized root(s) belong to another team; refusing to create a parallel \
             empty authority epoch — use the durable key that named the existing collections",
            observed.foreign_known_roots
        );
    }
    Ok(observed)
}

/// Construct the closed, deterministic grant set without touching `pile`.
///
/// A scratch store deliberately runs the same public [`publish_grant`] path as
/// the real publication. This keeps planning from duplicating the authority
/// collection's signing transcript while guaranteeing that dry-run performs
/// no `put` against the destination.
fn expected_team_of_one_write_grants(
    signer: &SigningKey,
) -> Result<
    Vec<(
        Id,
        &'static str,
        CollectionHandle,
        AuthorityGrant,
        CollectionCommit,
    )>,
> {
    let team = signer.verifying_key();
    let mut scratch = MemoryRepo::default();
    crate::collection_names::table()
        .into_iter()
        .map(|(scope, name, _reach)| {
            let resource = IntoBlob::<SimpleArchive>::to_blob(
                crate::collection_names::root_descriptor(scope, team).into_facts(),
            )
            .get_handle();
            let grant = AuthorityGrant::root(team, resource, ACTION_WRITE, AuthorityMode::Invoke);
            let commit = publish_grant(&mut scratch, team, signer, grant)
                .map_err(|error| anyhow!("prepare {name} WRITE grant: {error}"))?;
            Ok((scope, name, resource, grant, commit))
        })
        .collect()
}

/// Plan exact self-WRITE authority for every root collection in this build.
///
/// The pile is read only. Existing collection records influence reporting and
/// the wrong-key guard, never the grant set. In particular, pre-naming,
/// unknown, and foreign-team descriptors remain outside authority.
pub fn plan_team_of_one_write_authority(
    pile: &mut Pile,
    signer: &SigningKey,
) -> Result<TeamOfOneWriteAuthorityReport> {
    let team = signer.verifying_key();
    let observed = observe_faculty_roots(pile, team)?;
    let resolution = resolve_authority(pile, team)
        .map_err(|error| anyhow!("resolve current team authority: {error}"))?;
    let rows = expected_team_of_one_write_grants(signer)?
        .into_iter()
        .map(|(scope, name, resource, grant, commit)| {
            let accepted = resolution
                .grant(commit.id())
                .is_some_and(|accepted| accepted.commit() == commit && accepted.grant() == grant);
            TeamOfOneWriteGrantRow {
                scope,
                name,
                resource,
                commit,
                target_commits: observed
                    .target_commits
                    .get(&resource)
                    .copied()
                    .unwrap_or_default(),
                accepted,
            }
        })
        .collect();

    Ok(TeamOfOneWriteAuthorityReport {
        team_root: team.to_bytes(),
        rows,
        diagnostics: resolution.diagnostics().to_vec(),
        published: Vec::new(),
        ignored_foreign_roots: observed.foreign_known_roots,
        ignored_unknown_roots: observed.unknown_named_roots,
    })
}

/// Ensure the current build's exact team-of-one self-WRITE grant set.
///
/// Missing or incomplete occurrences are replayed through [`publish_grant`].
/// Dependencies and records are content addressed, so an interrupted prefix
/// and an exact rerun converge to the same bytes. The final positive fixed
/// point is resolved again before success is returned.
pub fn ensure_team_of_one_write_authority(
    pile: &mut Pile,
    signer: &SigningKey,
) -> Result<TeamOfOneWriteAuthorityReport> {
    let before = plan_team_of_one_write_authority(pile, signer)?;
    let team = signer.verifying_key();
    let expected = expected_team_of_one_write_grants(signer)?;
    let missing = before
        .rows
        .iter()
        .filter(|row| !row.accepted)
        .map(|row| row.commit.id())
        .collect::<BTreeSet<_>>();
    let mut published = Vec::new();
    for (_, name, _, grant, expected_commit) in expected {
        if !missing.contains(&expected_commit.id()) {
            continue;
        }
        let commit = publish_grant(pile, team, signer, grant)
            .map_err(|error| anyhow!("publish {name} WRITE grant: {error}"))?;
        if commit != expected_commit {
            anyhow::bail!("{name} WRITE grant changed identity between planning and publication");
        }
        published.push(commit.id());
    }

    let mut after = plan_team_of_one_write_authority(pile, signer)?;
    if after.missing() != 0 {
        anyhow::bail!(
            "WRITE authority publication left {} of {} configured faculty roots unauthorized",
            after.missing(),
            after.rows.len()
        );
    }
    after.published = published;
    Ok(after)
}

/// Publish one complete fragment into one scoped native collection.
///
/// The signer is loaded before the pile is touched. Facts become collection
/// data, metafacts become signed commit metadata, and the fragment's shared
/// blob store supplies attachments referenced by either channel. Publication
/// is performed only by [`triblespace::core::collection::Collection::commit`],
/// whose record identity makes exact replay idempotent.
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
/// [`triblespace::core::collection::Collection::commit`] boundary, and the
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
    let pile = open_pile_strict(pile_path)?;
    let mut collection = crate::collection_names::open(pile, scope, signer);
    let result = (|| {
        let mut commits = Vec::new();
        for fragment in fragments {
            commits.push(
                collection
                    .commit(fragment)
                    .context("publish native collection fragment")?,
            );
        }
        Ok(commits)
    })();
    finish_pile(collection.into_storage(), result)
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
    /// Content identity of a descriptor these tests built but have not stored.
    fn collection_of(descriptor: &Fragment) -> CollectionHandle {
        IntoBlob::<SimpleArchive>::to_blob(descriptor.facts().clone()).get_handle()
    }

    use std::fs::{self, File};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use anybytes::View;
    use ed25519_dalek::SigningKey;
    use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace::core::blob::encodings::utf8string::UTF8String;
    use triblespace::core::collection::records::CollectionName;
    use triblespace::core::collection::{
        empty_metadata_handle, reach, simplearchive_union, CollectionRecord,
    };
    use triblespace::core::inline::encodings::hash::Handle;
    use triblespace::core::inline::Inline;
    use triblespace::core::metadata;
    use triblespace::core::repo::memoryrepo::MemoryRepo;
    use triblespace::core::repo::{BlobStore, BlobStoreGet};
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
    fn target_discovery_uses_descriptor_handle_without_registry_record() {
        // Two REAL scopes rather than two arbitrary ids: a root is anchored by
        // a name now, and an id this build has never named is one it cannot
        // open at all. Any two distinct faculties prove the same thing.
        let signer = SigningKey::from_bytes(&[7; 32]);
        let team = signer.verifying_key();
        let target_scope = crate::schemas::wiki::DEFAULT_SCOPE_ID;
        let other_scope = crate::schemas::compass::DEFAULT_SCOPE_ID;
        let target_descriptor = crate::collection_names::root_descriptor(target_scope, team);
        let other_descriptor = crate::collection_names::root_descriptor(other_scope, team);
        let target = collection_of(&target_descriptor);
        let other = collection_of(&other_descriptor);

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

        let mut store = MemoryRepo::default();
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
        assert_eq!(discovered.descriptor().facts(), target_descriptor.facts());
        assert_eq!(discovered.commits(), &[target_commit]);
        assert_eq!(discovered.merges(), &[target_merge]);
        assert_eq!(discovered.derives(), &[derive_to_target]);
        assert!(discovered.diagnostics().is_empty());
        assert!(store.blobs.is_empty());
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
        let before_denied = fs::metadata(&files.pile).unwrap().len();
        let denied = publish_fragment(
            &files.pile,
            Some(&files.key),
            target_scope,
            fragment.clone(),
        )
        .unwrap_err();
        assert!(format!("{denied:#}").contains("no positive WRITE authority"));
        assert_eq!(fs::metadata(&files.pile).unwrap().len(), before_denied);

        let mut pile = open_pile_strict(&files.pile).unwrap();
        let signer = load_signer(&files.pile, Some(&files.key)).unwrap();
        ensure_team_of_one_write_authority(&mut pile, &signer).unwrap();
        pile.close().unwrap();

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
        let target = discover_target(&mut pile, target_scope, team).unwrap();
        assert_eq!(
            target.descriptor().facts(),
            crate::collection_names::root_descriptor(target_scope, team).facts()
        );
        assert_eq!(target.commits(), &[first]);
        assert!(target.merges().is_empty());
        assert!(target.derives().is_empty());
        assert!(target.diagnostics().is_empty());

        let unrelated_target = discover_target(&mut pile, other_scope, team).unwrap();
        assert_eq!(
            unrelated_target.descriptor().facts(),
            crate::collection_names::root_descriptor(other_scope, team).facts()
        );
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
    fn write_authority_dry_run_and_exact_replay_are_byte_identical() {
        let files = TestFiles::new();
        let signer = initialize_signer(&files.pile, Some(&files.key)).unwrap();
        let empty = fs::read(&files.pile).unwrap();

        let mut pile = open_pile_strict(&files.pile).unwrap();
        let plan = plan_team_of_one_write_authority(&mut pile, &signer).unwrap();
        pile.close().unwrap();
        assert_eq!(fs::read(&files.pile).unwrap(), empty);
        assert_eq!(plan.rows().len(), crate::collection_names::table().len());
        assert_eq!(plan.accepted(), 0);
        assert_eq!(plan.missing(), plan.rows().len());
        assert!(plan.published().is_empty());
        let names = plan
            .rows()
            .iter()
            .map(|row| row.name())
            .collect::<BTreeSet<_>>();
        for name in ["memory", "memory-comb", "posture-policy", "posture-scan"] {
            assert!(names.contains(name));
        }

        let mut pile = open_pile_strict(&files.pile).unwrap();
        let first = ensure_team_of_one_write_authority(&mut pile, &signer).unwrap();
        pile.close().unwrap();
        assert_eq!(first.published().len(), first.rows().len());
        assert_eq!(first.accepted(), first.rows().len());
        assert_eq!(first.missing(), 0);
        let after_first = fs::read(&files.pile).unwrap();

        let mut pile = open_pile_strict(&files.pile).unwrap();
        let replay = ensure_team_of_one_write_authority(&mut pile, &signer).unwrap();
        pile.close().unwrap();
        assert!(replay.published().is_empty());
        assert_eq!(replay.rows(), first.rows());
        assert_eq!(fs::read(&files.pile).unwrap(), after_first);
    }

    #[test]
    fn write_authority_rejects_a_foreign_team_key_before_mutation() {
        let files = TestFiles::new();
        let local = initialize_signer(&files.pile, Some(&files.key)).unwrap();
        let descriptor = crate::collection_names::root_descriptor(
            crate::schemas::wiki::DEFAULT_SCOPE_ID,
            local.verifying_key(),
        );
        let mut pile = open_pile_strict(&files.pile).unwrap();
        simplearchive_union::publish_fragment_commit(
            &mut pile,
            &descriptor,
            entity! { _ @ metadata::tag: &id(31) },
            &local,
        )
        .unwrap();
        pile.close().unwrap();
        let before = fs::read(&files.pile).unwrap();

        let foreign = SigningKey::from_bytes(&[19; 32]);
        let mut pile = open_pile_strict(&files.pile).unwrap();
        let error = plan_team_of_one_write_authority(&mut pile, &foreign).unwrap_err();
        pile.close().unwrap();
        assert!(format!("{error:#}").contains("refusing to create a parallel empty authority"));
        assert_eq!(fs::read(&files.pile).unwrap(), before);
    }

    #[test]
    fn write_authority_rejects_a_foreign_key_after_grant_only_initialization() {
        let files = TestFiles::new();
        let local = initialize_signer(&files.pile, Some(&files.key)).unwrap();
        let descriptor = crate::collection_names::root_descriptor(
            crate::schemas::wiki::DEFAULT_SCOPE_ID,
            local.verifying_key(),
        );
        let resource = collection_of(&descriptor);
        let mut pile = open_pile_strict(&files.pile).unwrap();
        publish_grant(
            &mut pile,
            local.verifying_key(),
            &local,
            AuthorityGrant::root(
                local.verifying_key(),
                resource,
                ACTION_WRITE,
                AuthorityMode::Invoke,
            ),
        )
        .unwrap();
        pile.close().unwrap();
        let before = fs::read(&files.pile).unwrap();

        let foreign = SigningKey::from_bytes(&[29; 32]);
        let mut pile = open_pile_strict(&files.pile).unwrap();
        let error = plan_team_of_one_write_authority(&mut pile, &foreign).unwrap_err();
        pile.close().unwrap();
        assert!(format!("{error:#}").contains("refusing to create a parallel empty authority"));
        assert_eq!(fs::read(&files.pile).unwrap(), before);
    }

    #[test]
    fn write_authority_ignores_unknown_and_foreign_roots_without_rewriting_targets() {
        let files = TestFiles::new();
        let signer = initialize_signer(&files.pile, Some(&files.key)).unwrap();
        let foreign = SigningKey::from_bytes(&[23; 32]);
        let local_known = crate::collection_names::root_descriptor(
            crate::schemas::wiki::DEFAULT_SCOPE_ID,
            signer.verifying_key(),
        );
        let foreign_known = crate::collection_names::root_descriptor(
            crate::schemas::compass::DEFAULT_SCOPE_ID,
            foreign.verifying_key(),
        );
        let unknown = simplearchive_union::descriptor(
            &CollectionName::new("outside-faculties").unwrap(),
            signer.verifying_key(),
            reach::private(),
        );

        let mut pile = open_pile_strict(&files.pile).unwrap();
        for (descriptor, writer, marker) in [
            (&local_known, &signer, 41),
            (&foreign_known, &foreign, 42),
            (&unknown, &signer, 43),
        ] {
            simplearchive_union::publish_fragment_commit(
                &mut pile,
                descriptor,
                entity! { _ @ metadata::tag: &id(marker) },
                writer,
            )
            .unwrap();
        }
        let baseline = discover_collection_records(&mut pile)
            .unwrap()
            .commits()
            .to_vec();
        let report = ensure_team_of_one_write_authority(&mut pile, &signer).unwrap();
        let final_commits = discover_collection_records(&mut pile)
            .unwrap()
            .commits()
            .to_vec();
        pile.close().unwrap();

        assert_eq!(report.ignored_foreign_roots(), 1);
        assert_eq!(report.ignored_unknown_roots(), 1);
        assert_eq!(report.rows().len(), crate::collection_names::table().len());
        assert_eq!(report.accepted(), report.rows().len());
        assert_eq!(
            report
                .rows()
                .iter()
                .find(|row| row.name() == "wiki")
                .unwrap()
                .target_commits(),
            1
        );

        let mut expected = baseline
            .into_iter()
            .map(|commit| (commit.id(), commit))
            .collect::<BTreeMap<_, _>>();
        for row in report.rows() {
            expected.insert(row.commit().id(), row.commit());
        }
        assert_eq!(
            final_commits
                .into_iter()
                .map(|commit| (commit.id(), commit))
                .collect::<BTreeMap<_, _>>(),
            expected
        );
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
