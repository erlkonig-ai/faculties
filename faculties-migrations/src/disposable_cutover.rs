//! One-shot activation through a disposable sibling pile.
//!
//! The algorithm is intentionally small: copy the frozen live bytes into a
//! new sibling, publish every planned collection through one open [`Pile`],
//! prove the resulting world, recheck both files, and rename. Any failure
//! before rename deletes the candidate. There is no manifest, checkpoint,
//! resume path, backup generation, compare-and-swap cell, or retention policy.
//! The stopped-world caller also owns the derived candidate pathname for the
//! attempt; this deliberately is not a hostile-writer locking protocol.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(any(not(target_vendor = "apple"), test))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[cfg(target_vendor = "apple")]
use std::ffi::CString;
#[cfg(target_vendor = "apple")]
use std::os::unix::ffi::OsStrExt;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;

use triblespace::core::blob::encodings::UnknownBlob;
use triblespace::core::blob::Blob;
use triblespace::core::collection::{
    discover_collection_records, Collection, CollectionCommit, DiscoveredCollectionRecords,
};
use triblespace::core::id::Id;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet};
use triblespace::core::trible::{Fragment, TribleSet};

use crate::activation_cutover::{ActivationPlan, PlannedCollection};
use crate::collection_cutover::{FrozenSource, PhysicalSourceFingerprint};
use faculties::storage::{load_signer, open_pile_strict};

/// Result of a completely validated activation attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationOutcome {
    /// New collection records were appended and the candidate replaced live.
    Activated { appended_bytes: u64 },
    /// Every planned commit was already present, so live was left untouched.
    AlreadyActive,
}

/// Publish `plan` into a private sibling and atomically replace `live`.
///
/// The signer is resolved relative to the live pile before the candidate is
/// created. `validate` sees one closed final blob snapshot and the matching
/// final fact view for every planned collection; the intended production
/// callback is [`crate::activation_cutover::validate_candidate_views`].
pub fn activate<F>(
    live: &Path,
    key: Option<&Path>,
    source: &FrozenSource,
    plan: &ActivationPlan,
    validate: F,
) -> Result<ActivationOutcome>
where
    F: FnOnce(&PileReader, &BTreeMap<Id, TribleSet>) -> Result<()>,
{
    plan.verify_source_coverage(source)?;
    let (signer, target, candidate) = activation_paths(live, key)?;
    let publications = plan
        .collections()
        .iter()
        .map(Publication::from)
        .collect::<Vec<_>>();
    activate_publications(
        live,
        &target,
        &candidate,
        source,
        &signer,
        &publications,
        validate,
    )
}

fn activation_paths(
    lexical_live: &Path,
    key: Option<&Path>,
) -> Result<(SigningKey, PathBuf, PathBuf)> {
    // The default key belongs beside the stable caller-facing path, not beside
    // a possibly relocated symlink target.
    let signer = load_signer(lexical_live, key)?;
    let target = fs::canonicalize(lexical_live)
        .with_context(|| format!("resolve live pile target {}", lexical_live.display()))?;
    let mut candidate_name = target
        .file_name()
        .ok_or_else(|| anyhow!("live pile target must name a file"))?
        .to_owned();
    candidate_name.push(".activation-candidate");
    let candidate = target.with_file_name(candidate_name);
    Ok((signer, target, candidate))
}

#[derive(Clone, Copy)]
struct Publication<'a> {
    name: &'static str,
    scope: Id,
    fragments: &'a [Fragment],
    facts: &'a TribleSet,
}

impl<'a> From<&'a PlannedCollection> for Publication<'a> {
    fn from(plan: &'a PlannedCollection) -> Self {
        Self {
            name: plan.name(),
            scope: plan.scope(),
            fragments: plan.fragments(),
            facts: plan.expected_facts(),
        }
    }
}

#[derive(Clone)]
struct ScopeSnapshot {
    facts: TribleSet,
    commits: Vec<CollectionCommit>,
}

struct CandidateWorld {
    baseline_records: DiscoveredCollectionRecords,
    final_records: DiscoveredCollectionRecords,
    baseline: BTreeMap<Id, ScopeSnapshot>,
    final_scopes: BTreeMap<Id, ScopeSnapshot>,
    returned: BTreeMap<Id, Vec<CollectionCommit>>,
    reader: PileReader,
}

fn activate_publications<F>(
    lexical_live: &Path,
    target: &Path,
    candidate: &Path,
    source: &FrozenSource,
    signer: &SigningKey,
    publications: &[Publication<'_>],
    validate: F,
) -> Result<ActivationOutcome>
where
    F: FnOnce(&PileReader, &BTreeMap<Id, TribleSet>) -> Result<()>,
{
    validate_plan(publications)?;
    assert_live_unchanged(source, lexical_live, target)?;
    require_private_sibling(target, candidate)?;
    let permissions = fs::metadata(target)
        .with_context(|| format!("stat live pile {}", target.display()))?
        .permissions();
    let mut disposable = copy_candidate(target, candidate, source.physical_fingerprint())?;

    let result = (|| {
        let initial_length = fs::metadata(candidate)?.len();
        let world = build_world(candidate, signer, publications)?;
        let final_length = fs::metadata(candidate)?.len();
        let appended_bytes = final_length
            .checked_sub(initial_length)
            .ok_or_else(|| anyhow!("candidate became shorter during publication"))?;

        require_prefix(candidate, source.physical_fingerprint())?;
        let final_fingerprint = PhysicalSourceFingerprint::capture(candidate)
            .context("fingerprint fully published candidate")?;
        validate_world(&world, publications)?;
        validate_attachments(&world.reader, publications)?;
        let views = world
            .final_scopes
            .iter()
            .map(|(scope, snapshot)| (*scope, snapshot.facts.clone()))
            .collect();
        validate(&world.reader, &views)
            .context("validate faculty-local and cross-collection candidate semantics")?;

        if appended_bytes == 0 {
            final_fingerprint.assert_unchanged(candidate)?;
            assert_live_unchanged(source, lexical_live, target)?;
            disposable.discard()?;
            return Ok(ActivationOutcome::AlreadyActive);
        }

        fs::set_permissions(candidate, permissions)
            .with_context(|| format!("preserve source mode on {}", candidate.display()))?;
        File::open(candidate)
            .with_context(|| format!("open completed candidate {}", candidate.display()))?
            .sync_all()
            .with_context(|| format!("sync completed candidate {}", candidate.display()))?;

        // One combined lexical-target and byte guard is deliberately the last
        // fallible operation before rename. The candidate guard covers the
        // validator interval.
        final_fingerprint.assert_unchanged(candidate)?;
        assert_live_unchanged(source, lexical_live, target)?;
        disposable.replace(target)?;
        Ok(ActivationOutcome::Activated { appended_bytes })
    })();

    match result {
        Err(error) if disposable.armed => disposable.fail(error),
        result => result,
    }
}

fn assert_live_unchanged(source: &FrozenSource, lexical_live: &Path, target: &Path) -> Result<()> {
    let current = fs::canonicalize(lexical_live)
        .with_context(|| format!("resolve live pile target {}", lexical_live.display()))?;
    if current != target {
        bail!(
            "live pile {} was retargeted during activation",
            lexical_live.display()
        );
    }
    source.assert_unchanged(&current)
}

fn validate_plan(publications: &[Publication<'_>]) -> Result<()> {
    let mut scopes = BTreeSet::new();
    for publication in publications {
        if !scopes.insert(publication.scope) {
            bail!(
                "candidate plan repeats target scope {:X}",
                publication.scope
            );
        }
        let facts: TribleSet = publication
            .fragments
            .iter()
            .flat_map(|fragment| fragment.facts().iter().copied())
            .collect();
        if &facts != publication.facts {
            bail!(
                "candidate plan for {} stages {} facts but expects {}",
                publication.name,
                facts.len(),
                publication.facts.len()
            );
        }
    }
    Ok(())
}

fn build_world(
    candidate: &Path,
    signer: &SigningKey,
    publications: &[Publication<'_>],
) -> Result<CandidateWorld> {
    let mut pile = open_pile_strict(candidate)?;
    let result = (|| {
        let baseline_records = discover_collection_records(&mut pile)?;
        let baseline = snapshots(&mut pile, signer, publications)?;
        let mut returned = BTreeMap::new();
        for publication in publications {
            let mut collection = faculties::collection_names::open(&mut pile, publication.scope, signer.clone());
            let mut commits = Vec::new();
            for fragment in publication.fragments {
                commits.push(
                    collection
                        .commit(fragment.clone())
                        .with_context(|| format!("publish {} commit", publication.name))?,
                );
            }
            returned.insert(publication.scope, commits);
        }
        let final_scopes = snapshots(&mut pile, signer, publications)?;
        let final_records = discover_collection_records(&mut pile)?;
        let reader = pile.reader()?;
        Ok(CandidateWorld {
            baseline_records,
            final_records,
            baseline,
            final_scopes,
            returned,
            reader,
        })
    })();
    finish_pile(pile, result)
}

fn snapshots(
    pile: &mut Pile,
    signer: &SigningKey,
    publications: &[Publication<'_>],
) -> Result<BTreeMap<Id, ScopeSnapshot>> {
    publications
        .iter()
        .map(|publication| {
            let mut collection = faculties::collection_names::open(&mut *pile, publication.scope, signer.clone());
            let (facts, commits, _) = collection
                .snapshot()
                .with_context(|| format!("snapshot {} collection", publication.name))?
                .into_parts();
            Ok((publication.scope, ScopeSnapshot { facts, commits }))
        })
        .collect()
}

fn validate_world(world: &CandidateWorld, publications: &[Publication<'_>]) -> Result<()> {
    let mut expected_commits = commit_map(world.baseline_records.commits());
    for commit in world.returned.values().flatten() {
        if let Some(previous) = expected_commits.insert(commit.id(), *commit) {
            if previous != *commit {
                bail!("returned COMMIT {:X} collides with baseline", commit.id());
            }
        }
    }
    if commit_map(world.final_records.commits()) != expected_commits
        || world.final_records.merges() != world.baseline_records.merges()
        || world.final_records.derives() != world.baseline_records.derives()
        || world.final_records.diagnostics() != world.baseline_records.diagnostics()
    {
        bail!("final collection-record census is not exactly baseline plus returned COMMITs");
    }

    for publication in publications {
        let baseline = &world.baseline[&publication.scope];
        let final_scope = &world.final_scopes[&publication.scope];
        let mut expected_facts = baseline.facts.clone();
        expected_facts += publication.facts.clone();
        if final_scope.facts != expected_facts {
            bail!(
                "final {} facts are not exactly baseline union planned facts",
                publication.name
            );
        }

        let mut expected = commit_map(&baseline.commits);
        for commit in &world.returned[&publication.scope] {
            expected.insert(commit.id(), *commit);
        }
        if commit_map(&final_scope.commits) != expected {
            bail!(
                "final {} COMMIT set is not exactly baseline plus returned COMMITs",
                publication.name
            );
        }
    }
    Ok(())
}

fn commit_map(commits: &[CollectionCommit]) -> BTreeMap<Id, CollectionCommit> {
    commits
        .iter()
        .copied()
        .map(|commit| (commit.id(), commit))
        .collect()
}

fn validate_attachments(reader: &PileReader, publications: &[Publication<'_>]) -> Result<()> {
    for publication in publications {
        for fragment in publication.fragments {
            let mut blobs = fragment.blobs().clone();
            let embedded = blobs.reader().expect("memory blob reader is infallible");
            for (handle, expected) in embedded.iter() {
                let expected = Blob::<UnknownBlob>::new(expected.bytes.clone());
                if expected.get_handle() != handle {
                    bail!("planned {} attachment has a false handle", publication.name);
                }
                let actual: Blob<UnknownBlob> = reader
                    .get(handle)
                    .with_context(|| format!("read planned {} attachment", publication.name))?;
                let rehashed = Blob::<UnknownBlob>::new(actual.bytes.clone());
                if rehashed.get_handle() != handle || actual.bytes != expected.bytes {
                    bail!(
                        "candidate {} attachment differs from plan",
                        publication.name
                    );
                }
            }
        }
    }
    Ok(())
}

fn copy_candidate(
    live: &Path,
    candidate: &Path,
    source: PhysicalSourceFingerprint,
) -> Result<DisposableCandidate> {
    #[cfg(target_vendor = "apple")]
    return clone_candidate(live, candidate, source);

    #[cfg(not(target_vendor = "apple"))]
    return stream_candidate(live, candidate, source);
}

/// Clone the immutable source snapshot without copying its data blocks.
///
/// Activation on Apple platforms deliberately requires `clonefile(2)` rather
/// than silently falling back to a physical copy.  A large pile is normally on
/// APFS, where the clone is constant-space and copy-on-write; falling back
/// during the stopped-world window would turn a cheap atomic cutover into an
/// unexpectedly long, full-pile rewrite.  An unsupported filesystem therefore
/// fails before publication and leaves the live pile untouched.
#[cfg(target_vendor = "apple")]
fn clone_candidate(
    live: &Path,
    candidate: &Path,
    source: PhysicalSourceFingerprint,
) -> Result<DisposableCandidate> {
    let live_c = CString::new(live.as_os_str().as_bytes())
        .context("live pile path contains an interior NUL")?;
    let candidate_c = CString::new(candidate.as_os_str().as_bytes())
        .context("candidate pile path contains an interior NUL")?;

    // SAFETY: both pointers name live NUL-terminated strings for the duration
    // of the call. `require_private_sibling` proved that `candidate` does not
    // exist, and clonefile is asked to create exactly that sibling.
    let cloned = unsafe { libc::clonefile(live_c.as_ptr(), candidate_c.as_ptr(), 0) };
    if cloned != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "clone disposable candidate {} from {} with clonefile(2); the filesystem must support copy-on-write clones",
                candidate.display(),
                live.display(),
            )
        });
    }

    let mut disposable = DisposableCandidate::new(candidate.to_owned());
    let result = (|| {
        let length = fs::metadata(candidate)
            .with_context(|| format!("stat cloned candidate {}", candidate.display()))?
            .len();
        if length != source.length {
            bail!(
                "cloned candidate has {length} bytes, expected frozen source length {}",
                source.length
            );
        }
        File::open(candidate)
            .with_context(|| format!("open cloned candidate {}", candidate.display()))?
            .sync_all()
            .with_context(|| format!("sync cloned candidate {}", candidate.display()))?;
        sync_parent(candidate)?;
        require_prefix(candidate, source)
    })();
    match result {
        Ok(()) => Ok(disposable),
        Err(error) => disposable.fail(error),
    }
}

#[cfg(not(target_vendor = "apple"))]
fn stream_candidate(
    live: &Path,
    candidate: &Path,
    source: PhysicalSourceFingerprint,
) -> Result<DisposableCandidate> {
    let mut input = File::open(live)?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(candidate)
        .with_context(|| format!("create disposable candidate {}", candidate.display()))?;
    let mut disposable = DisposableCandidate::new(candidate.to_owned());
    let result = (|| {
        let copied = std::io::copy(
            &mut std::io::Read::by_ref(&mut input).take(source.length),
            &mut output,
        )?;
        if copied != source.length {
            bail!("live pile ended during candidate copy");
        }
        output.sync_all()?;
        Ok(())
    })();
    drop(output);
    let result = result
        .and_then(|()| sync_parent(candidate))
        .and_then(|()| require_prefix(candidate, source));
    match result {
        Ok(()) => Ok(disposable),
        Err(error) => disposable.fail(error),
    }
}

fn require_prefix(path: &Path, source: PhysicalSourceFingerprint) -> Result<()> {
    if hash_prefix(path, source.length)? != source.digest {
        bail!("candidate does not retain the exact frozen source prefix");
    }
    Ok(())
}

fn hash_prefix(path: &Path, length: u64) -> Result<[u8; 32]> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(0))?;
    let mut remaining = length;
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut hasher = blake3::Hasher::new();
    while remaining > 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();
        let read = file.read(&mut buffer[..wanted])?;
        if read == 0 {
            bail!("{} ended before its {length}-byte prefix", path.display());
        }
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    Ok(*hasher.finalize().as_bytes())
}

fn require_private_sibling(live: &Path, candidate: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(live)
        .with_context(|| format!("inspect live pile {}", live.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("live pile must be a regular non-symlink file");
    }
    match fs::symlink_metadata(candidate) {
        Ok(_) => bail!(
            "disposable candidate {} already exists; refusing resume or overwrite",
            candidate.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let live_slot = canonical_slot(live)?;
    let candidate_slot = canonical_slot(candidate)?;
    if live_slot == candidate_slot {
        bail!("live and candidate must be distinct pile paths");
    }
    if live_slot.0 != candidate_slot.0 {
        bail!("candidate must be a sibling of live for atomic rename");
    }
    Ok(())
}

fn canonical_slot(path: &Path) -> Result<(PathBuf, std::ffi::OsString)> {
    let parent = fs::canonicalize(path.parent().unwrap_or_else(|| Path::new(".")))?;
    let name = path
        .file_name()
        .ok_or_else(|| anyhow!("pile path must name a file"))?
        .to_owned();
    Ok((parent, name))
}

fn sync_parent(path: &Path) -> Result<()> {
    File::open(path.parent().unwrap_or_else(|| Path::new(".")))?
        .sync_all()
        .with_context(|| format!("sync parent directory of {}", path.display()))
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    match (result, pile.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(anyhow!("close candidate pile: {error}")),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing candidate also failed: {close_error}")))
        }
    }
}

struct DisposableCandidate {
    path: PathBuf,
    armed: bool,
}

impl DisposableCandidate {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn discard(&mut self) -> Result<()> {
        fs::remove_file(&self.path)
            .with_context(|| format!("remove candidate {}", self.path.display()))?;
        self.armed = false;
        sync_parent(&self.path)
    }

    fn fail<T>(&mut self, error: anyhow::Error) -> Result<T> {
        match self.discard() {
            Ok(()) => Err(error),
            Err(cleanup) => {
                Err(error.context(format!("candidate cleanup also failed: {cleanup:#}")))
            }
        }
    }

    fn replace(&mut self, live: &Path) -> Result<()> {
        fs::rename(&self.path, live).with_context(|| {
            format!(
                "atomically replace {} with {}",
                live.display(),
                self.path.display()
            )
        })?;
        self.armed = false;
        sync_parent(live).context(
            "candidate rename succeeded but parent sync failed; activation may already be visible",
        )
    }
}

impl Drop for DisposableCandidate {
    fn drop(&mut self) {
        if self.armed && fs::remove_file(&self.path).is_ok() {
            let _ = sync_parent(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::Write;

    #[cfg(unix)]
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    use triblespace::core::blob::encodings::utf8string::UTF8String;
    use triblespace::core::metadata;
    use triblespace::macros::entity;

    use super::*;
    use crate::collection_cutover::{freeze_source};
use faculties::storage::{initialize_signer};

    /// A REAL scope, not a synthetic id. A root is anchored by a name now, so
    /// an id this build has never named is one it cannot open at all; which
    /// faculty it is does not matter to a cutover test, only that it is named.
    const SCOPE: Id = faculties::schemas::wiki::DEFAULT_SCOPE_ID;

    struct Fixture {
        _directory: tempfile::TempDir,
        live: PathBuf,
        candidate: PathBuf,
        signer: SigningKey,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let live = directory.path().join("self.pile");
            let candidate = directory.path().join("self.candidate.pile");
            let key = directory.path().join("self.key");
            File::create(&live).unwrap();
            let signer = initialize_signer(&live, Some(&key)).unwrap();
            Self {
                _directory: directory,
                live,
                candidate,
                signer,
            }
        }

        fn publish(&self, fragment: Fragment) -> CollectionCommit {
            let pile = open_pile_strict(&self.live).unwrap();
            let mut collection = faculties::collection_names::open(pile, SCOPE, self.signer.clone());
            let commit = collection.commit(fragment).unwrap();
            collection.close().unwrap();
            commit
        }

        fn target(&self) -> PathBuf {
            self.live.canonicalize().unwrap()
        }

        fn facts(&self) -> TribleSet {
            let pile = open_pile_strict(&self.live).unwrap();
            let mut collection = faculties::collection_names::open(pile, SCOPE, self.signer.clone());
            let facts = collection.snapshot().unwrap().into_facts();
            collection.close().unwrap();
            facts
        }
    }

    fn text_fragment(tag: u8, text: &str) -> Fragment {
        let mut fragment = Fragment::empty();
        let text = fragment.put::<UTF8String, _>(text.to_owned());
        fragment += entity! {
            metadata::tag: Id::new([tag; 16]).unwrap(),
            metadata::description: text,
        };
        fragment
    }

    fn publications(fragment: &Fragment) -> Vec<Publication<'_>> {
        vec![Publication {
            name: "test",
            scope: SCOPE,
            fragments: std::slice::from_ref(fragment),
            facts: fragment.facts(),
        }]
    }

    #[test]
    fn activates_exact_union_and_preserves_mode() {
        let fixture = Fixture::new();
        let baseline = text_fragment(0x62, "baseline");
        fixture.publish(baseline.clone());
        #[cfg(unix)]
        fs::set_permissions(&fixture.live, fs::Permissions::from_mode(0o640)).unwrap();
        let frozen_bytes = fs::read(&fixture.live).unwrap();
        let frozen = freeze_source(&fixture.live).unwrap();
        let planned = text_fragment(0x63, "planned attachment");
        let validator_ran = Cell::new(false);

        let outcome = activate_publications(
            &fixture.live,
            &fixture.target(),
            &fixture.candidate,
            &frozen,
            &fixture.signer,
            &publications(&planned),
            |reader, views| {
                validator_ran.set(true);
                assert_eq!(
                    views[&SCOPE].len(),
                    baseline.facts().len() + planned.facts().len()
                );
                let handle = *planned
                    .facts()
                    .iter()
                    .find(|fact| fact.a() == &metadata::description.id())
                    .unwrap()
                    .v::<triblespace::prelude::inlineencodings::Handle<UTF8String>>();
                let _: anybytes::View<str> = reader.get(handle)?;
                Ok(())
            },
        )
        .unwrap();

        assert!(matches!(
            outcome,
            ActivationOutcome::Activated { appended_bytes } if appended_bytes > 0
        ));
        assert!(validator_ran.get());
        assert!(!fixture.candidate.exists());
        assert_eq!(
            &fs::read(&fixture.live).unwrap()[..frozen_bytes.len()],
            frozen_bytes
        );
        let mut expected = baseline.facts().clone();
        expected += planned.facts().clone();
        assert_eq!(fixture.facts(), expected);
        #[cfg(unix)]
        assert_eq!(fs::metadata(&fixture.live).unwrap().mode() & 0o777, 0o640);
    }

    #[test]
    fn zero_append_keeps_the_live_inode() {
        let fixture = Fixture::new();
        let fragment = text_fragment(0x64, "already present");
        fixture.publish(fragment.clone());
        let before = fs::read(&fixture.live).unwrap();
        #[cfg(unix)]
        let inode = fs::metadata(&fixture.live).unwrap().ino();
        let frozen = freeze_source(&fixture.live).unwrap();

        let outcome = activate_publications(
            &fixture.live,
            &fixture.target(),
            &fixture.candidate,
            &frozen,
            &fixture.signer,
            &publications(&fragment),
            |_, _| Ok(()),
        )
        .unwrap();
        assert_eq!(outcome, ActivationOutcome::AlreadyActive);
        assert_eq!(fs::read(&fixture.live).unwrap(), before);
        assert!(!fixture.candidate.exists());
        #[cfg(unix)]
        assert_eq!(fs::metadata(&fixture.live).unwrap().ino(), inode);
    }

    #[test]
    fn validation_failure_durably_deletes_candidate() {
        let fixture = Fixture::new();
        let before = fs::read(&fixture.live).unwrap();
        let frozen = freeze_source(&fixture.live).unwrap();
        let fragment = text_fragment(0x65, "rejected");
        let error = activate_publications(
            &fixture.live,
            &fixture.target(),
            &fixture.candidate,
            &frozen,
            &fixture.signer,
            &publications(&fragment),
            |_, _| bail!("fixture semantic rejection"),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("fixture semantic rejection"));
        assert!(!fixture.candidate.exists());
        assert_eq!(fs::read(&fixture.live).unwrap(), before);
    }

    #[test]
    fn final_guard_rejects_a_changed_source() {
        let fixture = Fixture::new();
        fixture.publish(text_fragment(0x66, "mutable source"));
        let frozen = freeze_source(&fixture.live).unwrap();
        let fragment = text_fragment(0x67, "candidate");
        let live = fixture.live.clone();
        let error = activate_publications(
            &fixture.live,
            &fixture.target(),
            &fixture.candidate,
            &frozen,
            &fixture.signer,
            &publications(&fragment),
            move |_, _| {
                let mut bytes = fs::read(&live)?;
                *bytes.last_mut().unwrap() ^= 0xFF;
                fs::write(&live, bytes)?;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("changed after freezing"));
        assert!(!fixture.candidate.exists());
    }

    #[test]
    fn final_guard_rejects_a_changed_candidate() {
        let fixture = Fixture::new();
        let before = fs::read(&fixture.live).unwrap();
        let frozen = freeze_source(&fixture.live).unwrap();
        let fragment = text_fragment(0x68, "candidate");
        let candidate = fixture.candidate.clone();
        let error = activate_publications(
            &fixture.live,
            &fixture.target(),
            &fixture.candidate,
            &frozen,
            &fixture.signer,
            &publications(&fragment),
            move |_, _| {
                OpenOptions::new()
                    .append(true)
                    .open(candidate)?
                    .write_all(b"unvalidated suffix")?;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("length changed after freezing"));
        assert!(!fixture.candidate.exists());
        assert_eq!(fs::read(&fixture.live).unwrap(), before);
    }

    #[test]
    fn existing_candidate_is_never_accepted_or_deleted() {
        let fixture = Fixture::new();
        fs::write(&fixture.candidate, b"operator-owned sentinel").unwrap();
        let frozen = freeze_source(&fixture.live).unwrap();
        let fragment = text_fragment(0x69, "unused");
        let error = activate_publications(
            &fixture.live,
            &fixture.target(),
            &fixture.candidate,
            &frozen,
            &fixture.signer,
            &publications(&fragment),
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("refusing resume or overwrite"));
        assert_eq!(
            fs::read(&fixture.candidate).unwrap(),
            b"operator-owned sentinel"
        );
    }

    #[cfg(unix)]
    #[test]
    fn lexical_symlink_keeps_its_key_and_targets_canonical_data() {
        let fixture = Fixture::new();
        let target_directory = tempfile::tempdir().unwrap();
        let real = target_directory.path().join("real.pile");
        fs::rename(&fixture.live, &real).unwrap();
        symlink(&real, &fixture.live).unwrap();
        let (signer, target, candidate) = activation_paths(&fixture.live, None).unwrap();
        assert_eq!(signer.verifying_key(), fixture.signer.verifying_key());
        assert_eq!(target, real.canonicalize().unwrap());
        assert_eq!(candidate.parent(), target.parent());
        assert!(!faculties::storage::signer_path(&real, None).exists());

        let frozen = freeze_source(&fixture.live).unwrap();
        let fragment = text_fragment(0x6A, "through symlink");
        let outcome = activate_publications(
            &fixture.live,
            &target,
            &candidate,
            &frozen,
            &signer,
            &publications(&fragment),
            |_, _| Ok(()),
        )
        .unwrap();
        assert!(matches!(outcome, ActivationOutcome::Activated { .. }));
        assert!(fixture
            .live
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fixture.facts(), fragment.facts().clone());
        assert!(!candidate.exists());
    }

    #[cfg(unix)]
    #[test]
    fn lexical_retarget_before_rename_is_rejected() {
        let fixture = Fixture::new();
        let targets = tempfile::tempdir().unwrap();
        let original = targets.path().join("original.pile");
        let replacement = targets.path().join("replacement.pile");
        fs::rename(&fixture.live, &original).unwrap();
        fs::copy(&original, &replacement).unwrap();
        symlink(&original, &fixture.live).unwrap();
        let before = fs::read(&original).unwrap();
        let frozen = freeze_source(&fixture.live).unwrap();
        let (_, target, candidate) = activation_paths(&fixture.live, None).unwrap();
        let lexical = fixture.live.clone();
        let replacement_for_callback = replacement.clone();
        let fragment = text_fragment(0x6D, "must not land");

        let error = activate_publications(
            &fixture.live,
            &target,
            &candidate,
            &frozen,
            &fixture.signer,
            &publications(&fragment),
            move |_, _| {
                fs::remove_file(&lexical)?;
                symlink(&replacement_for_callback, &lexical)?;
                Ok(())
            },
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("retargeted during activation"));
        assert_eq!(fs::read(&original).unwrap(), before);
        assert_eq!(
            fixture.live.canonicalize().unwrap(),
            replacement.canonicalize().unwrap()
        );
        assert!(!candidate.exists());
    }

    #[test]
    fn candidate_must_be_a_new_sibling() {
        let fixture = Fixture::new();
        let elsewhere = tempfile::tempdir().unwrap();
        let candidate = elsewhere.path().join("candidate.pile");
        let frozen = freeze_source(&fixture.live).unwrap();
        let fragment = text_fragment(0x6B, "unused");
        let error = activate_publications(
            &fixture.live,
            &fixture.target(),
            &candidate,
            &frozen,
            &fixture.signer,
            &publications(&fragment),
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("must be a sibling"));
        assert!(!candidate.exists());
    }

    #[test]
    fn planned_attachment_must_reside_with_exact_bytes() {
        let fixture = Fixture::new();
        let fragment = text_fragment(0x6C, "not in pile");
        let publications = publications(&fragment);
        let mut pile = open_pile_strict(&fixture.live).unwrap();
        let reader = pile.reader().unwrap();
        let error = validate_attachments(&reader, &publications).unwrap_err();
        pile.close().unwrap();
        assert!(format!("{error:#}").contains("read planned test attachment"));
    }
}
