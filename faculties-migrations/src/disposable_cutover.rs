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
use triblespace::core::blob::{Blob, IntoBlob};
use triblespace::core::capability::{
    CapabilityAction, CapabilityAtom, CapabilityClaim, CapabilityMode, CapabilityResource,
};
use triblespace::core::collection::{
    discover_collection_records, simplearchive_union, CollectionAdmission, CollectionCommit,
    CollectionHandle, DiscoveredCollectionRecords, ACTION_WRITE,
};
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::Inline;
use triblespace::core::repo::memoryrepo::MemoryRepo;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
use triblespace::core::trible::{Fragment, TribleSet};
use triblespace::prelude::{Collection, CollectionName};

#[cfg(test)]
use crate::activation_cutover::materialized_facts;
use crate::activation_cutover::{
    ActivationPlan, CandidateViewKey, CandidateViews, PlannedCollection, TargetPolicy,
};
use crate::collection_cutover::{FrozenSource, PhysicalSourceFingerprint};
use faculties::storage::open_pile_strict;

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
    signer: &SigningKey,
    source: &FrozenSource,
    plan: &ActivationPlan,
    validate: F,
) -> Result<ActivationOutcome>
where
    F: FnOnce(&PileReader, &CandidateViews) -> Result<()>,
{
    if plan.namespace() != signer.verifying_key().to_bytes() {
        bail!("activation plan belongs to a different durable collection namespace");
    }
    plan.verify_source_coverage(source)?;
    let (target, candidate) = activation_paths(live)?;
    let publications = plan
        .collections()
        .iter()
        .map(|plan| Publication::new(plan, signer.verifying_key()))
        .collect::<Vec<_>>();
    activate_publications(
        live,
        &target,
        &candidate,
        source,
        signer,
        &publications,
        validate,
    )
}

fn activation_paths(lexical_live: &Path) -> Result<(PathBuf, PathBuf)> {
    let target = fs::canonicalize(lexical_live)
        .with_context(|| format!("resolve live pile target {}", lexical_live.display()))?;
    let mut candidate_name = target
        .file_name()
        .ok_or_else(|| anyhow!("live pile target must name a file"))?
        .to_owned();
    candidate_name.push(".activation-candidate");
    let candidate = target.with_file_name(candidate_name);
    Ok((target, candidate))
}

#[derive(Clone, Copy)]
struct Publication<'a> {
    handle: CollectionHandle,
    name: &'a CollectionName,
    reach: &'a Fragment,
    view: CandidateViewKey,
    policy: &'a TargetPolicy,
    fragments: &'a [Fragment],
    facts: &'a TribleSet,
}

impl<'a> Publication<'a> {
    fn new(plan: &'a PlannedCollection, namespace: ed25519_dalek::VerifyingKey) -> Self {
        let authority = match plan.policy() {
            TargetPolicy::Open => None,
            TargetPolicy::Vault { authority, .. } => Some(*authority),
        };
        let descriptor = simplearchive_union::descriptor(
            plan.name(),
            namespace,
            authority,
            plan.reach().clone(),
        );
        Self {
            handle: descriptor.facts().clone().to_blob().get_handle(),
            name: plan.name(),
            reach: plan.reach(),
            view: plan.view(),
            policy: plan.policy(),
            fragments: plan.fragments(),
            facts: plan.expected_facts(),
        }
    }
}

/// Read-only state of one deterministic cutover publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativePublicationStatus {
    /// None of the planned target COMMITs is present.
    Missing,
    /// Some exact evidence is present, but publication or authority is incomplete.
    Partial,
    /// Every planned record and dependency is present under the exact authority policy.
    Complete,
}

impl NativePublicationStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Partial => "partial",
            Self::Complete => "already complete",
        }
    }
}

/// Exact subset check for one target collection in an activation plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionPublicationPresence {
    status: NativePublicationStatus,
    planned_commits: usize,
    present_commits: usize,
    required_dependencies: usize,
    resident_dependencies: usize,
}

impl CollectionPublicationPresence {
    pub const fn status(&self) -> NativePublicationStatus {
        self.status
    }

    pub const fn planned_commits(&self) -> usize {
        self.planned_commits
    }

    pub const fn present_commits(&self) -> usize {
        self.present_commits
    }

    pub const fn required_dependencies(&self) -> usize {
        self.required_dependencies
    }

    pub const fn resident_dependencies(&self) -> usize {
        self.resident_dependencies
    }
}

/// Exact native-publication presence for one frozen activation plan.
///
/// `Complete` means deterministic replay has no planned collection bytes to
/// add. It deliberately does not re-run the aggregate faculty semantic
/// validator; `activate-cutover` remains the authoritative validation command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CutoverPublicationPresence {
    status: NativePublicationStatus,
    collections: Vec<CollectionPublicationPresence>,
}

impl CutoverPublicationPresence {
    pub const fn status(&self) -> NativePublicationStatus {
        self.status
    }

    pub fn collections(&self) -> &[CollectionPublicationPresence] {
        &self.collections
    }
}

#[derive(Default)]
struct ExpectedPublication {
    commits: BTreeMap<Id, CollectionCommit>,
    dependencies: BTreeSet<[u8; 32]>,
}

fn scratch_dependencies(scratch: &mut MemoryRepo) -> BTreeSet<[u8; 32]> {
    scratch
        .reader()
        .expect("memory repository reader is infallible")
        .iter()
        .map(|(handle, _)| handle.raw)
        .collect()
}

fn expected_publication(
    publication: &Publication<'_>,
    signer: &SigningKey,
) -> Result<ExpectedPublication> {
    let authority = match publication.policy {
        TargetPolicy::Open => None,
        TargetPolicy::Vault { authority, .. } => Some(*authority),
    };
    let descriptor = simplearchive_union::descriptor(
        publication.name,
        signer.verifying_key(),
        authority,
        publication.reach.clone(),
    );
    let mut commits = BTreeMap::new();
    let mut dependencies = BTreeSet::new();
    for fragment in publication.fragments {
        // Bound scratch memory to one fragment. Large migrations can carry
        // thousands of independent authored leaves, and only their identities
        // and dependency handles are needed after preparation.
        let mut scratch = MemoryRepo::default();
        let commit = simplearchive_union::publish_fragment_commit(
            &mut scratch,
            &descriptor,
            fragment.clone(),
            signer,
        )
        .map_err(|error| anyhow!("prepare {} COMMIT: {error}", publication.name.as_str()))?;
        commits.insert(commit.id(), commit);
        dependencies.extend(scratch_dependencies(&mut scratch));
    }
    Ok(ExpectedPublication {
        commits,
        dependencies,
    })
}

fn resident_dependencies(reader: &PileReader, dependencies: &BTreeSet<[u8; 32]>) -> Result<usize> {
    dependencies.iter().try_fold(0, |present, raw| {
        let handle = Inline::<Handle<UnknownBlob>>::new(*raw);
        let resident = reader
            .metadata(handle)
            .context("inspect planned cutover dependency")?
            .is_some();
        Ok(present + usize::from(resident))
    })
}

/// Inspect exact deterministic cutover publication against its frozen source.
///
/// This performs no writes, creates no candidate, and ignores unrelated later
/// collection history. A complete result proves only that the planned records,
/// dependencies, and authority policy are already represented in this frozen
/// prefix; aggregate semantic validation still belongs to [`activate`].
pub fn inspect_publication(
    source: &FrozenSource,
    signer: &SigningKey,
    plan: &ActivationPlan,
) -> Result<CutoverPublicationPresence> {
    if plan.namespace() != signer.verifying_key().to_bytes() {
        bail!("activation plan belongs to a different durable collection namespace");
    }
    plan.verify_source_coverage(source)?;
    let publications = plan
        .collections()
        .iter()
        .map(|plan| Publication::new(plan, signer.verifying_key()))
        .collect::<Vec<_>>();
    validate_plan(signer, &publications)?;
    inspect_publications(source, signer, &publications)
}

fn inspect_publications(
    source: &FrozenSource,
    signer: &SigningKey,
    publications: &[Publication<'_>],
) -> Result<CutoverPublicationPresence> {
    let mut store = source.collection_store();
    let records = discover_collection_records(&mut store)
        .context("discover frozen native collection records")?;
    let observed_commits = commit_map(records.commits());

    let mut collections = Vec::with_capacity(publications.len());
    for publication in publications {
        let expected = expected_publication(publication, signer)?;
        let present_commits = expected
            .commits
            .iter()
            .filter(|(id, commit)| observed_commits.get(*id) == Some(*commit))
            .count();
        let resident = resident_dependencies(source.reader(), &expected.dependencies)?;

        let complete =
            present_commits == expected.commits.len() && resident == expected.dependencies.len();
        let status = if complete {
            NativePublicationStatus::Complete
        } else if !expected.commits.is_empty() && present_commits == 0 {
            NativePublicationStatus::Missing
        } else {
            NativePublicationStatus::Partial
        };
        collections.push(CollectionPublicationPresence {
            status,
            planned_commits: expected.commits.len(),
            present_commits,
            required_dependencies: expected.dependencies.len(),
            resident_dependencies: resident,
        });
    }

    let all_complete = collections
        .iter()
        .all(|collection| collection.status == NativePublicationStatus::Complete);
    let planned_commits = collections
        .iter()
        .map(CollectionPublicationPresence::planned_commits)
        .sum::<usize>();
    let present_commits = collections
        .iter()
        .map(CollectionPublicationPresence::present_commits)
        .sum::<usize>();
    let status = if all_complete {
        NativePublicationStatus::Complete
    } else if planned_commits > 0 && present_commits == 0 {
        NativePublicationStatus::Missing
    } else {
        NativePublicationStatus::Partial
    };

    Ok(CutoverPublicationPresence {
        status,
        collections,
    })
}

#[derive(Clone)]
struct ScopeSnapshot {
    facts: TribleSet,
    commits: Vec<CollectionCommit>,
}

struct CandidateWorld {
    baseline_records: DiscoveredCollectionRecords,
    final_records: DiscoveredCollectionRecords,
    baseline: BTreeMap<CollectionHandle, ScopeSnapshot>,
    final_scopes: BTreeMap<CollectionHandle, ScopeSnapshot>,
    returned: BTreeMap<CollectionHandle, Vec<CollectionCommit>>,
    views: CandidateViews,
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
    F: FnOnce(&PileReader, &CandidateViews) -> Result<()>,
{
    validate_plan(signer, publications)?;
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
        validate(&world.reader, &world.views)
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

fn validate_plan(signer: &SigningKey, publications: &[Publication<'_>]) -> Result<()> {
    let mut handles = BTreeSet::new();
    let mut saw_access_inbox = false;
    for publication in publications {
        let handle = publication_handle(publication, signer.verifying_key());
        if !handles.insert(handle) {
            bail!(
                "candidate plan repeats target collection handle {}",
                hex::encode_upper(handle.raw)
            );
        }
        match (publication.view, publication.policy) {
            (CandidateViewKey::Faculty(_), TargetPolicy::Open) => {}
            (CandidateViewKey::AccessInbox, TargetPolicy::Open) => {
                saw_access_inbox = true;
            }
            (CandidateViewKey::Vault(_), TargetPolicy::Vault { authority, write }) => {
                if !saw_access_inbox {
                    bail!("custody vault publication precedes its founder access inbox");
                }
                if *authority != signer.verifying_key() || write.subject() != signer.verifying_key()
                {
                    bail!("planned custody vault is not rooted in the durable founder");
                }
                let atom = CapabilityAtom::new(
                    CapabilityAction::new(ACTION_WRITE),
                    CapabilityResource::from(publication.handle),
                );
                let verified = write
                    .proof()
                    .verify_claim(
                        *authority,
                        triblespace::core::clock::epoch_now(),
                        CapabilityClaim::new(
                            write.subject(),
                            atom,
                            CapabilityMode::InvokeAndDelegate,
                        ),
                    )
                    .context("verify planned founder WRITE proof")?;
                if verified.effective_validity().is_some() {
                    bail!("planned founder WRITE proof is bounded");
                }
            }
            _ => bail!("candidate target policy disagrees with its semantic view"),
        }
        let facts: TribleSet = publication
            .fragments
            .iter()
            .flat_map(|fragment| fragment.facts().iter().copied())
            .collect();
        if &facts != publication.facts {
            bail!(
                "candidate plan for {} stages {} facts but expects {}",
                publication.name.as_str(),
                facts.len(),
                publication.facts.len()
            );
        }
    }
    Ok(())
}

fn publication_handle(
    publication: &Publication<'_>,
    _namespace: ed25519_dalek::VerifyingKey,
) -> CollectionHandle {
    publication.handle
}

fn publication_collection<S>(
    storage: S,
    signer: &SigningKey,
    publication: &Publication<'_>,
) -> Collection<S> {
    let admission = match publication.policy {
        TargetPolicy::Open => CollectionAdmission::open(),
        TargetPolicy::Vault { authority, write } => {
            CollectionAdmission::capability(*authority, vec![write.clone()])
        }
    };
    Collection::new(
        storage,
        publication.name,
        signer.verifying_key(),
        signer.clone(),
        publication.reach.clone(),
        admission,
    )
}

fn build_world(
    candidate: &Path,
    signer: &SigningKey,
    publications: &[Publication<'_>],
) -> Result<CandidateWorld> {
    let mut pile = open_pile_strict(candidate)?;
    let result =
        (|| {
            let baseline_records = discover_collection_records(&mut pile)?;
            let namespace = signer.verifying_key();
            let baseline = snapshots(&mut pile, signer, publications)?;
            let mut returned = BTreeMap::new();
            for publication in publications {
                let mut collection = publication_collection(&mut pile, signer, publication);
                let handle = collection.collection();
                let mut commits = Vec::new();
                for fragment in publication.fragments {
                    commits.push(collection.commit(fragment.clone()).with_context(|| {
                        format!("publish {} commit", publication.name.as_str())
                    })?);
                }
                returned.insert(handle, commits);
            }
            let final_scopes = snapshots(&mut pile, signer, publications)?;
            let mut faculty_views = BTreeMap::new();
            for publication in publications {
                let handle = publication_handle(publication, namespace);
                let facts = final_scopes[&handle].facts.clone();
                match publication.view {
                    CandidateViewKey::Faculty(scope) => {
                        faculty_views.insert(scope, facts);
                    }
                    CandidateViewKey::AccessInbox | CandidateViewKey::Vault(_) => {}
                }
            }
            let discovered = faculties::secrets::storage::discover_local_vaults(&mut pile, signer)
                .context("discover inbox-addressed candidate vaults")?;
            for publication in publications {
                let CandidateViewKey::Vault(vault) = publication.view else {
                    continue;
                };
                let location = discovered.location_exact(publication.handle).ok_or_else(|| {
                anyhow!("planned custody vault {vault:X} is not ready through the founder inbox")
            })?;
                let TargetPolicy::Vault { authority, .. } = publication.policy else {
                    unreachable!("view/policy agreement validated before publication")
                };
                if location.authority() != *authority {
                    bail!("planned custody vault {vault:X} resolved under a different authority");
                }
                if discovered
                    .snapshot()
                    .vault_exact(publication.handle)
                    .expect("ready location has a vault snapshot")
                    .facts()
                    != &final_scopes[&publication.handle].facts
                {
                    bail!(
                        "planned custody vault {vault:X} differs from its runtime materialization"
                    );
                }
            }
            let local_vault_views = discovered
                .snapshot()
                .vaults()
                .iter()
                .map(|snapshot| {
                    (
                        snapshot
                            .collection()
                            .expect("inbox-discovered snapshot has exact collection identity"),
                        (snapshot.id(), snapshot.facts().clone()),
                    )
                })
                .collect();
            let views = CandidateViews::new(faculty_views, local_vault_views)?;
            drop(discovered);
            let final_records = discover_collection_records(&mut pile)?;
            let reader = pile.reader()?;
            Ok(CandidateWorld {
                baseline_records,
                final_records,
                baseline,
                final_scopes,
                returned,
                views,
                reader,
            })
        })();
    finish_pile(pile, result)
}

fn snapshots(
    pile: &mut Pile,
    signer: &SigningKey,
    publications: &[Publication<'_>],
) -> Result<BTreeMap<CollectionHandle, ScopeSnapshot>> {
    publications
        .iter()
        .map(|publication| {
            let mut collection = publication_collection(&mut *pile, signer, publication);
            let handle = collection.collection();
            let (facts, commits, _) = collection
                .snapshot()
                .with_context(|| format!("snapshot {} collection", publication.name.as_str()))?
                .into_parts();
            Ok((handle, ScopeSnapshot { facts, commits }))
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
        let handle = publication.handle;
        let baseline = &world.baseline[&handle];
        let final_scope = &world.final_scopes[&handle];
        let mut expected_facts = baseline.facts.clone();
        expected_facts += publication.facts.clone();
        if final_scope.facts != expected_facts {
            bail!(
                "final {} facts are not exactly baseline union planned facts",
                publication.name.as_str()
            );
        }

        let mut expected = commit_map(&baseline.commits);
        for commit in &world.returned[&handle] {
            expected.insert(commit.id(), *commit);
        }
        if commit_map(&final_scope.commits) != expected {
            bail!(
                "final {} COMMIT set is not exactly baseline plus returned COMMITs",
                publication.name.as_str()
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
                    bail!(
                        "planned {} attachment has a false handle",
                        publication.name.as_str()
                    );
                }
                let actual: Blob<UnknownBlob> = reader.get(handle).with_context(|| {
                    format!("read planned {} attachment", publication.name.as_str())
                })?;
                let rehashed = Blob::<UnknownBlob>::new(actual.bytes.clone());
                if rehashed.get_handle() != handle || actual.bytes != expected.bytes {
                    bail!(
                        "candidate {} attachment differs from plan",
                        publication.name.as_str()
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
    use triblespace::core::repo::BlobStoreMeta;
    use triblespace::macros::entity;
    use triblespace::prelude::{blobencodings, BlobStorePut, ExclusiveId, Inline};

    use super::*;
    use crate::collection_cutover::freeze_source;
    use crate::collection_cutover::test_support::{TestBranchSpec, TestDeltaSpec, TestSourceSpec};
    use crate::legacy_secrets_v1 as legacy_secrets;
    use crate::legacy_secrets_v1::test_support as legacy_fixture;
    use crate::{secrets_cutover, secrets_vault_cutover};
    use faculties::storage::initialize_signer;

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
            let mut collection =
                faculties::collection_names::open(pile, SCOPE, self.signer.clone());
            let commit = collection.commit(fragment).unwrap();
            collection.close().unwrap();
            commit
        }

        fn target(&self) -> PathBuf {
            self.live.canonicalize().unwrap()
        }

        fn facts(&self) -> TribleSet {
            let pile = open_pile_strict(&self.live).unwrap();
            let mut collection =
                faculties::collection_names::open(pile, SCOPE, self.signer.clone());
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

    fn publications<'a>(fragment: &'a Fragment, signer: &SigningKey) -> Vec<Publication<'a>> {
        publications_many(std::slice::from_ref(fragment), signer)
    }

    fn publications_many<'a>(
        fragments: &'a [Fragment],
        signer: &SigningKey,
    ) -> Vec<Publication<'a>> {
        let name = Box::leak(Box::new(faculties::collection_names::require_name(SCOPE)));
        let reach = Box::leak(Box::new(faculties::collection_names::require_reach(SCOPE)));
        let handle =
            simplearchive_union::descriptor(name, signer.verifying_key(), None, reach.clone())
                .facts()
                .clone()
                .to_blob()
                .get_handle();
        let facts = Box::leak(Box::new(fragments.iter().fold(
            TribleSet::new(),
            |mut all, fragment| {
                all += fragment.facts().clone();
                all
            },
        )));
        vec![Publication {
            handle,
            name,
            reach,
            view: CandidateViewKey::Faculty(SCOPE),
            policy: &TargetPolicy::Open,
            fragments,
            facts,
        }]
    }

    fn at(byte: u8) -> faculties::secrets::IntervalValue {
        Inline::new([byte; 32])
    }

    fn direct_legacy_fragment(
        fixture: &Fixture,
    ) -> (Fragment, Id, Id, Vec<u8>, legacy_secrets::BytesHandle) {
        let signer = &fixture.signer;
        let identity = legacy_fixture::prepare_node_identity(
            "durable-node",
            signer.verifying_key().as_bytes(),
            at(1),
        )
        .unwrap();
        let identity_id = identity.id;
        let scope_fragment = legacy_fixture::scope_fragment(identity_id, "epoch", at(2));
        let vault = scope_fragment.root().unwrap();
        let mut foundation = identity.fragment;
        foundation += scope_fragment;
        foundation += legacy_fixture::grant_fragment(
            Id::new([0x31; 16]).unwrap(),
            vault,
            "member",
            identity_id,
            identity_id,
            at(3),
        );
        let mut pile = open_pile_strict(&fixture.live).unwrap();
        let mut foundation_blobs = foundation.blobs().clone();
        let embedded = foundation_blobs.reader().unwrap();
        for (_, blob) in embedded.iter() {
            pile.put::<UnknownBlob, _>(blob.clone()).unwrap();
        }
        let reader = pile.reader().unwrap();
        let catalog = legacy_secrets::validate_catalog(&reader, foundation.facts()).unwrap();
        let sealed = legacy_fixture::seal_version(
            &reader,
            &catalog,
            vault,
            "opaque",
            b"this plaintext must never be opened by activation",
            at(4),
        )
        .unwrap();
        drop(reader);
        pile.close().unwrap();

        let secret = sealed.secret;
        let (_, facts, metafacts, sealed_blobs) = sealed.fragment.into_parts();
        let body_facts = facts
            .iter()
            .filter(|fact| fact.a() == &legacy_secrets::secret_body.id())
            .copied()
            .collect::<TribleSet>();
        let malformed_body = vec![0_u8; 24 + 16];
        let mut sealed =
            Fragment::from_parts(facts.difference(&body_facts), metafacts, sealed_blobs);
        let body = sealed.put::<blobencodings::RawBytes, _>(malformed_body.clone());
        sealed += entity! { ExclusiveId::force_ref(&secret) @
            legacy_secrets::secret_body: body,
        };
        foundation += sealed;
        // This recipient becomes effective only after the original version
        // was sealed. The custody cutover must preserve that historical wrap
        // set rather than reconstructing an enumerable reader census.
        let late_signer = SigningKey::from_bytes(&[0x32; 32]);
        let late = legacy_fixture::prepare_node_identity(
            "late-reader",
            late_signer.verifying_key().as_bytes(),
            at(5),
        )
        .unwrap();
        foundation += late.fragment;
        foundation += legacy_fixture::grant_fragment(
            Id::new([0x32; 16]).unwrap(),
            vault,
            "member",
            late.id,
            identity_id,
            at(6),
        );
        (foundation, vault, secret, malformed_body, body)
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
            &publications(&planned, &fixture.signer),
            |reader, views| {
                validator_ran.set(true);
                assert_eq!(
                    views.faculties()[&SCOPE].len(),
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
    fn direct_secrets_activation_has_no_fixed_target_and_replays_byte_identically() {
        let fixture = Fixture::new();
        let (legacy, vault, secret, malformed_body, legacy_body) = direct_legacy_fragment(&fixture);
        let frozen = TestSourceSpec::new(vec![TestBranchSpec::new(
            legacy_secrets::COLLECTION_NAME,
            Id::new([0x42; 16]).unwrap(),
            SigningKey::from_bytes(&[0x42; 32]),
            vec![TestDeltaSpec::authored(legacy.clone(), "legacy Secrets")],
        )])
        .freeze(&fixture.live)
        .unwrap()
        .source;
        let frozen_bytes = fs::read(&fixture.live).unwrap();

        let projection = secrets_cutover::plan(&frozen).unwrap();
        let mut store = frozen.collection_store();
        let direct = secrets_vault_cutover::plan_from_legacy_in_store(
            &mut store,
            &fixture.signer,
            frozen.reader(),
            projection.retained_facts().clone(),
            None,
        )
        .unwrap();
        assert_eq!(direct.vaults().len(), 1);
        assert_eq!(direct.report().custody_wraps_added(), 1);
        assert_eq!(direct.report().pending_access_envelopes(), 1);
        let vault_plan = &direct.vaults()[0];
        let vault_collection = faculties::secrets::vault_handle(
            vault,
            fixture.signer.verifying_key(),
            vault_plan.authority,
        );
        let vault_fragments = vault_plan
            .report
            .data_pending
            .then(|| vault_plan.required.clone())
            .into_iter()
            .collect::<Vec<_>>();
        let access_fragments = direct.access_inbox().to_vec();
        let access_plan = PlannedCollection::access_inbox(
            fixture.signer.verifying_key(),
            access_fragments.clone(),
            materialized_facts(&access_fragments),
        )
        .unwrap();
        let target_plan = PlannedCollection::vault(
            vault,
            vault_fragments.clone(),
            materialized_facts(&vault_fragments),
            vault_plan.authority,
            vault_plan.write_presentation.clone(),
        )
        .unwrap();
        let planned = [access_plan, target_plan];
        let publications = planned
            .iter()
            .map(|plan| Publication::new(plan, fixture.signer.verifying_key()))
            .collect::<Vec<_>>();
        let outcome = activate_publications(
            &fixture.live,
            &fixture.target(),
            &fixture.candidate,
            &frozen,
            &fixture.signer,
            &publications,
            |_, views| {
                assert!(views.local_vaults().contains_key(&vault_collection));
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(outcome, ActivationOutcome::Activated { .. }));
        assert_eq!(
            &fs::read(&fixture.live).unwrap()[..frozen_bytes.len()],
            frozen_bytes
        );

        let mut pile = open_pile_strict(&fixture.live).unwrap();
        let discovered =
            faculties::secrets::storage::discover_local_vaults(&mut pile, &fixture.signer).unwrap();
        let snapshot = discovered.snapshot().vault_exact(vault_collection).unwrap();
        let catalog = snapshot.catalog();
        assert_eq!(catalog.secrets[&secret].body, legacy_body);
        assert_eq!(
            catalog
                .wraps_for(secret, catalog.custody.unwrap().public_key)
                .len(),
            1
        );
        let body: anybytes::Bytes = discovered
            .snapshot()
            .reader()
            .get(catalog.secrets[&secret].body)
            .unwrap();
        assert_eq!(body.as_ref(), malformed_body);
        drop(discovered);
        pile.close().unwrap();

        let activated_bytes = fs::read(&fixture.live).unwrap();
        let replay_source = TestSourceSpec::new(vec![TestBranchSpec::new(
            legacy_secrets::COLLECTION_NAME,
            Id::new([0x42; 16]).unwrap(),
            SigningKey::from_bytes(&[0x42; 32]),
            vec![TestDeltaSpec::authored(legacy, "legacy Secrets")],
        )])
        .freeze(&fixture.live)
        .unwrap()
        .source;
        assert_eq!(fs::read(&fixture.live).unwrap(), activated_bytes);
        let replay_projection = secrets_cutover::plan(&replay_source).unwrap();
        let mut replay_store = replay_source.collection_store();
        let replay = secrets_vault_cutover::plan_from_legacy_in_store(
            &mut replay_store,
            &fixture.signer,
            replay_source.reader(),
            replay_projection.retained_facts().clone(),
            None,
        )
        .unwrap();
        assert_eq!(replay.report().custody_wraps_added(), 0);
        assert_eq!(replay.report().pending_access_envelopes(), 0);
        assert_eq!(replay.report().pending_vaults(), 0);
        let replay_vault = &replay.vaults()[0];
        let replay_access_fragments = replay.access_inbox().to_vec();
        let replay_access = PlannedCollection::access_inbox(
            fixture.signer.verifying_key(),
            replay_access_fragments.clone(),
            materialized_facts(&replay_access_fragments),
        )
        .unwrap();
        let replay_target = PlannedCollection::vault(
            vault,
            Vec::new(),
            TribleSet::new(),
            replay_vault.authority,
            replay_vault.write_presentation.clone(),
        )
        .unwrap();
        let replay_planned = [replay_access, replay_target];
        let replay_publications = replay_planned
            .iter()
            .map(|plan| Publication::new(plan, fixture.signer.verifying_key()))
            .collect::<Vec<_>>();
        let before_replay = fs::read(&fixture.live).unwrap();
        let outcome = activate_publications(
            &fixture.live,
            &fixture.target(),
            &fixture.candidate,
            &replay_source,
            &fixture.signer,
            &replay_publications,
            |_, _| Ok(()),
        )
        .unwrap();
        assert_eq!(outcome, ActivationOutcome::AlreadyActive);
        assert_eq!(fs::read(&fixture.live).unwrap(), before_replay);
    }

    #[test]
    fn direct_secrets_migration_preserves_post_v1_versions_and_only_rewraps_their_dek() {
        let fixture = Fixture::new();
        let vault = Id::new([0x45; 16]).unwrap();
        let mut post_v1 =
            faculties::secrets::legacy_vault_header_fragment(vault, "epoch", at(2)).unwrap();
        let sealed = faculties::secrets::seal_version(
            "post-v1",
            b"the encrypted body must remain byte-identical",
            fixture.signer.verifying_key().to_bytes(),
            at(7),
        )
        .unwrap();
        let post_secret = sealed.secret;
        post_v1 += sealed.fragment;
        let post_facts = post_v1.facts().clone();
        let mut post_blobs = post_v1.blobs().clone();
        let post_reader = post_blobs.reader().unwrap();
        let post_catalog =
            faculties::secrets::validate_catalog(&post_reader, vault, &post_facts).unwrap();
        let post_body = post_catalog.secrets[&post_secret].body;
        let post_body_bytes: anybytes::Bytes = post_reader.get(post_body).unwrap();
        let post_body_bytes = post_body_bytes.as_ref().to_vec();
        let post_wrap = *post_catalog
            .wraps
            .values()
            .find(|wrap| wrap.secret == post_secret)
            .unwrap();
        drop(post_reader);

        let direct_descriptor = simplearchive_union::descriptor(
            &faculties::secrets::vault_name(vault),
            fixture.signer.verifying_key(),
            None,
            triblespace::core::collection::reach::private(),
        );
        let legacy_collection = direct_descriptor.facts().clone().to_blob().get_handle();
        let pile = open_pile_strict(&fixture.live).unwrap();
        let mut direct_collection = Collection::new(
            pile,
            &faculties::secrets::vault_name(vault),
            fixture.signer.verifying_key(),
            fixture.signer.clone(),
            triblespace::core::collection::reach::private(),
            CollectionAdmission::open(),
        );
        direct_collection.commit(post_v1).unwrap();
        direct_collection.close().unwrap();

        let foreign = text_fragment(0x46, "foreign dormant direct-vault commit");
        let mut pile = open_pile_strict(&fixture.live).unwrap();
        simplearchive_union::publish_fragment_commit(
            &mut pile,
            &direct_descriptor,
            foreign.clone(),
            &SigningKey::from_bytes(&[0x46; 32]),
        )
        .unwrap();
        simplearchive_union::publish_fragment_commit(
            &mut pile,
            &crate::legacy_authority::test_support::descriptor(fixture.signer.verifying_key()),
            crate::legacy_authority::test_support::root_read_grant(
                fixture.signer.verifying_key(),
                legacy_collection,
            ),
            &fixture.signer,
        )
        .unwrap();
        pile.close().unwrap();

        let frozen = TestSourceSpec::new(vec![TestBranchSpec::new(
            legacy_secrets::COLLECTION_NAME,
            Id::new([0x44; 16]).unwrap(),
            SigningKey::from_bytes(&[0x44; 32]),
            vec![TestDeltaSpec::authored(
                Fragment::empty(),
                "authored empty legacy Secrets",
            )],
        )])
        .freeze(&fixture.live)
        .unwrap()
        .source;
        let projection = secrets_cutover::plan(&frozen).unwrap();
        let mut store = frozen.collection_store();
        let direct = secrets_vault_cutover::plan_from_legacy_in_store(
            &mut store,
            &fixture.signer,
            frozen.reader(),
            projection.retained_facts().clone(),
            None,
        )
        .unwrap();
        assert_eq!(direct.report().source_facts, 0);
        assert_eq!(direct.vaults().len(), 1);
        assert_eq!(direct.vaults()[0].vault, vault);
        assert_eq!(direct.report().custody_wraps_added(), 1);
        assert_eq!(direct.report().preserved_wraps(), 1);
        assert_eq!(direct.report().pending_access_envelopes(), 1);
        assert_eq!(direct.report().pending_vaults(), 1);

        let mut staged = direct.vaults()[0].required.clone();
        assert!(post_facts.difference(staged.facts()).is_empty());
        assert_eq!(
            foreign.facts().difference(staged.facts()),
            foreign.facts().clone()
        );
        let staged_facts = staged.facts().clone();
        let staged_reader = staged.blobs_mut().reader().unwrap();
        let catalog =
            faculties::secrets::validate_catalog(&staged_reader, vault, &staged_facts).unwrap();
        assert_eq!(catalog.secrets[&post_secret].body, post_body);
        assert_eq!(catalog.wraps[&post_wrap.id], post_wrap);
        assert_eq!(
            catalog
                .wraps_for(post_secret, catalog.custody.unwrap().public_key)
                .len(),
            1
        );
        let staged_body: anybytes::Bytes = staged_reader.get(post_body).unwrap();
        assert_eq!(staged_body.as_ref(), post_body_bytes);
        drop(staged_reader);

        let vault_plan = &direct.vaults()[0];
        let target_collection = faculties::secrets::vault_handle(
            vault,
            fixture.signer.verifying_key(),
            vault_plan.authority,
        );
        let access_fragments = direct.access_inbox().to_vec();
        let vault_fragments = vec![vault_plan.required.clone()];
        let planned = [
            PlannedCollection::access_inbox(
                fixture.signer.verifying_key(),
                access_fragments.clone(),
                materialized_facts(&access_fragments),
            )
            .unwrap(),
            PlannedCollection::vault(
                vault,
                vault_fragments.clone(),
                materialized_facts(&vault_fragments),
                vault_plan.authority,
                vault_plan.write_presentation.clone(),
            )
            .unwrap(),
        ];
        let publications = planned
            .iter()
            .map(|plan| Publication::new(plan, fixture.signer.verifying_key()))
            .collect::<Vec<_>>();
        let outcome = activate_publications(
            &fixture.live,
            &fixture.target(),
            &fixture.candidate,
            &frozen,
            &fixture.signer,
            &publications,
            |_, _| Ok(()),
        )
        .unwrap();
        assert!(matches!(outcome, ActivationOutcome::Activated { .. }));

        let mut pile = open_pile_strict(&fixture.live).unwrap();
        let discovered =
            faculties::secrets::storage::discover_local_vaults(&mut pile, &fixture.signer).unwrap();
        assert_eq!(discovered.snapshot().vaults().len(), 1);
        assert!(discovered.location_exact(legacy_collection).is_none());
        let target = discovered
            .snapshot()
            .vault_exact(target_collection)
            .unwrap();
        assert_eq!(target.catalog().secrets[&post_secret].body, post_body);
        assert_eq!(target.catalog().wraps[&post_wrap.id], post_wrap);
        drop(discovered);
        pile.close().unwrap();
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
            &publications(&fragment, &fixture.signer),
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
    fn publication_presence_distinguishes_missing_partial_and_complete_with_later_history() {
        let fixture = Fixture::new();
        let first = text_fragment(0x81, "first planned publication");
        let second = text_fragment(0x82, "second planned publication");
        let planned = [first.clone(), second.clone()];
        let publications = publications_many(&planned, &fixture.signer);

        let frozen = freeze_source(&fixture.live).unwrap();
        let missing = inspect_publications(&frozen, &fixture.signer, &publications).unwrap();
        assert_eq!(missing.status(), NativePublicationStatus::Missing);
        assert_eq!(
            missing.collections()[0].status(),
            NativePublicationStatus::Missing
        );
        assert_eq!(missing.collections()[0].present_commits(), 0);
        assert_eq!(missing.collections()[0].planned_commits(), 2);

        fixture.publish(first);
        fixture.publish(text_fragment(0x83, "unrelated later history"));
        let frozen = freeze_source(&fixture.live).unwrap();
        let partial = inspect_publications(&frozen, &fixture.signer, &publications).unwrap();
        assert_eq!(partial.status(), NativePublicationStatus::Partial);
        assert_eq!(
            partial.collections()[0].status(),
            NativePublicationStatus::Partial
        );
        assert_eq!(partial.collections()[0].present_commits(), 1);

        fixture.publish(second);
        let frozen = freeze_source(&fixture.live).unwrap();
        let complete = inspect_publications(&frozen, &fixture.signer, &publications).unwrap();
        assert_eq!(complete.status(), NativePublicationStatus::Complete);
        assert_eq!(
            complete.collections()[0].status(),
            NativePublicationStatus::Complete
        );
        assert_eq!(complete.collections()[0].present_commits(), 2);

        let before = fs::read(&fixture.live).unwrap();
        let outcome = activate_publications(
            &fixture.live,
            &fixture.target(),
            &fixture.candidate,
            &frozen,
            &fixture.signer,
            &publications,
            |_, _| Ok(()),
        )
        .unwrap();
        assert_eq!(outcome, ActivationOutcome::AlreadyActive);
        assert_eq!(fs::read(&fixture.live).unwrap(), before);
    }

    #[test]
    fn publication_presence_distinguishes_no_output_from_an_authored_empty_commit() {
        let fixture = Fixture::new();
        let no_fragments: [Fragment; 0] = [];
        let no_publication = publications_many(&no_fragments, &fixture.signer);
        let frozen = freeze_source(&fixture.live).unwrap();
        assert!(frozen
            .reader()
            .metadata(no_publication[0].handle)
            .unwrap()
            .is_none());
        let empty_target = inspect_publications(&frozen, &fixture.signer, &no_publication).unwrap();
        assert_eq!(empty_target.status(), NativePublicationStatus::Complete);
        assert_eq!(
            empty_target.collections()[0].status(),
            NativePublicationStatus::Complete
        );
        assert_eq!(empty_target.collections()[0].planned_commits(), 0);
        assert_eq!(empty_target.collections()[0].required_dependencies(), 0);

        let authored_empty = Fragment::empty();
        let authored = publications(&authored_empty, &fixture.signer);
        let missing = inspect_publications(&frozen, &fixture.signer, &authored).unwrap();
        assert_eq!(missing.status(), NativePublicationStatus::Missing);
        assert_eq!(missing.collections()[0].planned_commits(), 1);

        fixture.publish(authored_empty.clone());
        let frozen = freeze_source(&fixture.live).unwrap();
        let present = inspect_publications(&frozen, &fixture.signer, &authored).unwrap();
        assert_eq!(present.status(), NativePublicationStatus::Complete);
        assert_eq!(present.collections()[0].present_commits(), 1);
    }

    #[test]
    fn publication_presence_requires_the_planned_commit_blob_closure() {
        use triblespace::core::collection::{CollectionRecord, CollectionStore};

        let fixture = Fixture::new();
        let fragment = text_fragment(0x84, "record without its closure");
        let publications = publications(&fragment, &fixture.signer);
        let expected = expected_publication(&publications[0], &fixture.signer).unwrap();
        let commit = *expected
            .commits
            .values()
            .next()
            .expect("one planned fragment produces one COMMIT");
        let mut pile = open_pile_strict(&fixture.live).unwrap();
        pile.insert(CollectionRecord::Commit(commit)).unwrap();
        pile.close().unwrap();

        let frozen = freeze_source(&fixture.live).unwrap();
        let presence = inspect_publications(&frozen, &fixture.signer, &publications).unwrap();
        assert_eq!(presence.status(), NativePublicationStatus::Partial);
        assert_eq!(presence.collections()[0].present_commits(), 1);
        assert!(
            presence.collections()[0].resident_dependencies()
                < presence.collections()[0].required_dependencies()
        );
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
            &publications(&fragment, &fixture.signer),
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
            &publications(&fragment, &fixture.signer),
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
            &publications(&fragment, &fixture.signer),
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
            &publications(&fragment, &fixture.signer),
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
        let (target, candidate) = activation_paths(&fixture.live).unwrap();
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
            &fixture.signer,
            &publications(&fragment, &fixture.signer),
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
        let (target, candidate) = activation_paths(&fixture.live).unwrap();
        let lexical = fixture.live.clone();
        let replacement_for_callback = replacement.clone();
        let fragment = text_fragment(0x6D, "must not land");

        let error = activate_publications(
            &fixture.live,
            &target,
            &candidate,
            &frozen,
            &fixture.signer,
            &publications(&fragment, &fixture.signer),
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
            &publications(&fragment, &fixture.signer),
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
        let publications = publications(&fragment, &fixture.signer);
        let mut pile = open_pile_strict(&fixture.live).unwrap();
        let reader = pile.reader().unwrap();
        let error = validate_attachments(&reader, &publications).unwrap_err();
        pile.close().unwrap();
        assert!(format!("{error:#}").contains("read planned wiki attachment"));
    }
}
