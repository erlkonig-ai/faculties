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

use triblespace::core::authority::{
    publish_grant, resolve_authority, AuthorityGrant, AuthorityMode, ACTION_WRITE,
};
use triblespace::core::blob::encodings::UnknownBlob;
use triblespace::core::blob::{Blob, IntoBlob};
use triblespace::core::collection::{
    discover_collection_records, simplearchive_union, CollectionCommit, CollectionHandle,
    DiscoveredCollectionRecords,
};
use triblespace::core::id::Id;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet};
use triblespace::core::trible::{Fragment, TribleSet};
use triblespace::prelude::{Collection, CollectionName};

use crate::activation_cutover::{
    ActivationPlan, CandidateViewKey, CandidateViews, PlannedCollection, TargetPolicy,
};
use crate::collection_cutover::{FrozenSource, PhysicalSourceFingerprint};
use faculties::storage::{ensure_team_of_one_write_authority, open_pile_strict};

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
    if plan.team() != signer.verifying_key().to_bytes() {
        bail!("activation plan belongs to a different durable team root");
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
    fn new(plan: &'a PlannedCollection, team: ed25519_dalek::VerifyingKey) -> Self {
        let descriptor = simplearchive_union::descriptor(plan.name(), team, plan.reach().clone());
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

#[derive(Clone)]
struct ScopeSnapshot {
    facts: TribleSet,
    commits: Vec<CollectionCommit>,
}

struct CandidateWorld {
    baseline_records: DiscoveredCollectionRecords,
    final_records: DiscoveredCollectionRecords,
    authority: Vec<CollectionCommit>,
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
    for publication in publications {
        let handle = publication_handle(publication, signer.verifying_key());
        if !handles.insert(handle) {
            bail!(
                "candidate plan repeats target collection handle {}",
                hex::encode_upper(handle.raw)
            );
        }
        if !matches!(
            (publication.view, publication.policy),
            (CandidateViewKey::Faculty(_), TargetPolicy::Faculty)
                | (CandidateViewKey::Vault(_), TargetPolicy::Vault { .. })
        ) {
            bail!("candidate target policy disagrees with its semantic view");
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

fn planned_grants(
    publication: &Publication<'_>,
    signer: &SigningKey,
) -> Result<Vec<AuthorityGrant>> {
    match publication.policy {
        TargetPolicy::Faculty => Ok(Vec::new()),
        TargetPolicy::Vault { readers } => {
            let mut grants = vec![AuthorityGrant::root(
                signer.verifying_key(),
                publication.handle,
                ACTION_WRITE,
                AuthorityMode::Invoke,
            )];
            for reader in readers {
                grants.push(AuthorityGrant::root(
                    ed25519_dalek::VerifyingKey::from_bytes(reader)
                        .context("validate planned vault READ recipient")?,
                    publication.handle,
                    faculties::secrets::v2::ACTION_READ,
                    AuthorityMode::Invoke,
                ));
            }
            Ok(grants)
        }
    }
}

fn future_write_targets(
    signer: &SigningKey,
    publications: &[Publication<'_>],
) -> BTreeSet<CollectionHandle> {
    let team = signer.verifying_key();
    faculties::collection_names::table()
        .into_iter()
        .map(|(scope, _, _)| {
            faculties::collection_names::root_descriptor(scope, team)
                .facts()
                .clone()
                .to_blob()
                .get_handle()
        })
        .chain(publications.iter().map(|publication| publication.handle))
        .collect()
}

fn reject_dormant_commits_awakened_by_planned_write(
    pile: &mut Pile,
    signer: &SigningKey,
    records: &DiscoveredCollectionRecords,
    publications: &[Publication<'_>],
) -> Result<()> {
    let team = signer.verifying_key();
    let authority = resolve_authority(&mut *pile, team)
        .map_err(|error| anyhow!("resolve pre-activation authority: {error}"))?;
    let targets = future_write_targets(signer, publications);
    for commit in records.commits() {
        if targets.contains(&commit.collection())
            && commit.public_key().raw == team.to_bytes()
            && !authority.allows(&commit.public_key(), ACTION_WRITE, commit.collection())
        {
            bail!(
                "planned WRITE authority would awaken dormant local COMMIT {:X} on collection {}",
                commit.id(),
                hex::encode_upper(commit.collection().raw)
            );
        }
    }
    Ok(())
}

fn publication_handle(
    publication: &Publication<'_>,
    _team: ed25519_dalek::VerifyingKey,
) -> CollectionHandle {
    publication.handle
}

fn publication_collection<S>(
    storage: S,
    signer: &SigningKey,
    publication: &Publication<'_>,
) -> Collection<S> {
    Collection::new(
        storage,
        publication.name,
        signer.verifying_key(),
        signer.clone(),
        publication.reach.clone(),
    )
}

fn build_world(
    candidate: &Path,
    signer: &SigningKey,
    publications: &[Publication<'_>],
) -> Result<CandidateWorld> {
    let mut pile = open_pile_strict(candidate)?;
    let result = (|| {
        let baseline_records = discover_collection_records(&mut pile)?;
        reject_dormant_commits_awakened_by_planned_write(
            &mut pile,
            signer,
            &baseline_records,
            publications,
        )?;
        let mut authority = ensure_team_of_one_write_authority(&mut pile, signer)
            .context("initialize candidate WRITE authority")?
            .rows()
            .iter()
            .map(|row| row.commit())
            .collect::<Vec<_>>();
        let team = signer.verifying_key();
        for publication in publications {
            for grant in planned_grants(publication, signer)? {
                authority.push(
                    publish_grant(&mut pile, team, signer, grant)
                        .map_err(|error| anyhow!("publish planned candidate authority: {error}"))?,
                );
            }
        }
        let baseline = snapshots(&mut pile, signer, publications)?;
        let mut returned = BTreeMap::new();
        for publication in publications {
            let mut collection = publication_collection(&mut pile, signer, publication);
            let handle = collection.collection();
            let mut commits = Vec::new();
            for fragment in publication.fragments {
                commits.push(
                    collection
                        .commit(fragment.clone())
                        .with_context(|| format!("publish {} commit", publication.name.as_str()))?,
                );
            }
            returned.insert(handle, commits);
        }
        let final_scopes = snapshots(&mut pile, signer, publications)?;
        let authority_resolution = resolve_authority(&mut pile, team)
            .map_err(|error| anyhow!("resolve final candidate authority: {error}"))?;
        let mut faculty_views = BTreeMap::new();
        for publication in publications {
            let handle = publication_handle(publication, team);
            let facts = final_scopes[&handle].facts.clone();
            match publication.view {
                CandidateViewKey::Faculty(scope) => {
                    faculty_views.insert(scope, facts);
                }
                CandidateViewKey::Vault(vault) => {
                    let readers = faculties::secrets::v2::read_authority_recipient_keys(
                        &authority_resolution,
                        handle,
                    );
                    let TargetPolicy::Vault { readers: expected } = publication.policy else {
                        unreachable!("view/policy agreement validated before publication")
                    };
                    if readers != *expected {
                        bail!(
                            "final vault {vault:X} READ recipients differ from the projected legacy effective-recipient set"
                        );
                    }
                }
            }
        }
        let global = faculties::secrets::v2::storage::discover_all_vaults_strict(&mut pile, signer)
            .context("discover complete global candidate vault snapshot")?;
        let mut vault_views = BTreeMap::new();
        let mut local_vault_views = BTreeMap::new();
        for (vault, snapshot) in global.snapshot().vaults() {
            let location = &global.locations()[vault];
            let authority = resolve_authority(&mut pile, location.team()).map_err(|error| {
                anyhow!("resolve candidate vault {vault:X} READ authority: {error}")
            })?;
            let readers = faculties::secrets::v2::read_authority_recipient_keys(
                &authority,
                location.collection(),
            );
            for secret in snapshot.catalog().secrets.keys().copied() {
                if !readers.is_subset(&snapshot.catalog().wrap_holders(secret)) {
                    bail!(
                        "final vault {vault:X} leaves an accepted READ recipient without a wrap for secret {secret:X}"
                    );
                }
            }
            if readers.contains(&signer.verifying_key().to_bytes()) {
                local_vault_views.insert(*vault, snapshot.facts().clone());
            }
            vault_views.insert(*vault, snapshot.facts().clone());
        }
        let views = CandidateViews::new(faculty_views, vault_views, local_vault_views)?;
        let final_records = discover_collection_records(&mut pile)?;
        let reader = pile.reader()?;
        Ok(CandidateWorld {
            baseline_records,
            final_records,
            authority,
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
    for commit in &world.authority {
        if let Some(previous) = expected_commits.insert(commit.id(), *commit) {
            if previous != *commit {
                bail!(
                    "WRITE grant COMMIT {:X} collides with baseline",
                    commit.id()
                );
            }
        }
    }
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
        bail!(
            "final collection-record census is not exactly baseline plus WRITE grants and \
             returned COMMITs"
        );
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
    use crate::{secrets_cutover, secrets_v2_cutover};
    use faculties::secrets as legacy_secrets;
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
            crate::write_authority::publish(&live, Some(&key)).unwrap();
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
        let name = Box::leak(Box::new(faculties::collection_names::require_name(SCOPE)));
        let reach = Box::leak(Box::new(faculties::collection_names::require_reach(SCOPE)));
        let handle = simplearchive_union::descriptor(name, signer.verifying_key(), reach.clone())
            .facts()
            .clone()
            .to_blob()
            .get_handle();
        vec![Publication {
            handle,
            name,
            reach,
            view: CandidateViewKey::Faculty(SCOPE),
            policy: &TargetPolicy::Faculty,
            fragments: std::slice::from_ref(fragment),
            facts: fragment.facts(),
        }]
    }

    struct VaultPublication {
        handle: CollectionHandle,
        name: CollectionName,
        reach: Fragment,
        view: CandidateViewKey,
        policy: TargetPolicy,
        fragments: Vec<Fragment>,
        facts: TribleSet,
    }

    impl VaultPublication {
        fn new(
            vault: Id,
            signer: &SigningKey,
            readers: BTreeSet<faculties::secrets::v2::RecipientPublicKey>,
            fragments: Vec<Fragment>,
        ) -> Self {
            let name = faculties::secrets::v2::vault_name(vault);
            let reach = triblespace::core::collection::reach::private();
            let handle =
                simplearchive_union::descriptor(&name, signer.verifying_key(), reach.clone())
                    .facts()
                    .clone()
                    .to_blob()
                    .get_handle();
            let facts = fragments
                .iter()
                .fold(TribleSet::new(), |mut all, fragment| {
                    all += fragment.facts().clone();
                    all
                });
            Self {
                handle,
                name,
                reach,
                view: CandidateViewKey::Vault(vault),
                policy: TargetPolicy::Vault { readers },
                fragments,
                facts,
            }
        }

        fn publication(&self) -> Publication<'_> {
            Publication {
                handle: self.handle,
                name: &self.name,
                reach: &self.reach,
                view: self.view,
                policy: &self.policy,
                fragments: &self.fragments,
                facts: &self.facts,
            }
        }
    }

    fn at(byte: u8) -> faculties::secrets::v2::IntervalValue {
        Inline::new([byte; 32])
    }

    fn direct_legacy_fragment(
        fixture: &Fixture,
    ) -> (Fragment, Id, Id, Vec<u8>, legacy_secrets::BytesHandle) {
        let signer = &fixture.signer;
        let identity = legacy_secrets::prepare_node_identity(
            "durable-node",
            signer.verifying_key().as_bytes(),
            at(1),
        )
        .unwrap();
        let identity_id = identity.id;
        let scope_fragment = legacy_secrets::scope_fragment(identity_id, "epoch", at(2)).unwrap();
        let vault = scope_fragment.root().unwrap();
        let mut foundation = identity.fragment;
        foundation += scope_fragment;
        foundation += legacy_secrets::grant_fragment(
            Id::new([0x31; 16]).unwrap(),
            vault,
            "member",
            identity_id,
            identity_id,
            at(3),
        )
        .unwrap();
        let mut pile = open_pile_strict(&fixture.live).unwrap();
        let mut foundation_blobs = foundation.blobs().clone();
        let embedded = foundation_blobs.reader().unwrap();
        for (_, blob) in embedded.iter() {
            pile.put::<UnknownBlob, _>(blob.clone()).unwrap();
        }
        let reader = pile.reader().unwrap();
        let catalog = legacy_secrets::validate_catalog(&reader, foundation.facts()).unwrap();
        let sealed = legacy_secrets::seal_version(
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
            .filter(|fact| fact.a() == &legacy_secrets::schema::secret_body.id())
            .copied()
            .collect::<TribleSet>();
        let malformed_body = vec![0_u8; 24 + 16];
        let mut sealed =
            Fragment::from_parts(facts.difference(&body_facts), metafacts, sealed_blobs);
        let body = sealed.put::<blobencodings::RawBytes, _>(malformed_body.clone());
        sealed += entity! { ExclusiveId::force_ref(&secret) @
            legacy_secrets::schema::secret_body: body,
        };
        foundation += sealed;
        // This recipient becomes effective only after the original version
        // was sealed, so direct planning must synthesize exactly one DEK wrap
        // without ever authenticating or decrypting the opaque body.
        let late_signer = SigningKey::from_bytes(&[0x32; 32]);
        let late = legacy_secrets::prepare_node_identity(
            "late-reader",
            late_signer.verifying_key().as_bytes(),
            at(5),
        )
        .unwrap();
        foundation += late.fragment;
        foundation += legacy_secrets::grant_fragment(
            Id::new([0x32; 16]).unwrap(),
            vault,
            "member",
            late.id,
            identity_id,
            at(6),
        )
        .unwrap();
        (foundation, vault, secret, malformed_body, body)
    }

    fn publish_vault(
        fixture: &Fixture,
        vault: Id,
        fragment: Fragment,
        readers: impl IntoIterator<Item = ed25519_dalek::VerifyingKey>,
    ) {
        let mut pile = open_pile_strict(&fixture.live).unwrap();
        let handle = faculties::secrets::v2::vault_handle(vault, fixture.signer.verifying_key());
        publish_grant(
            &mut pile,
            fixture.signer.verifying_key(),
            &fixture.signer,
            AuthorityGrant::root(
                fixture.signer.verifying_key(),
                handle,
                ACTION_WRITE,
                AuthorityMode::Invoke,
            ),
        )
        .unwrap();
        faculties::secrets::v2::vault_collection(
            &mut pile,
            vault,
            fixture.signer.verifying_key(),
            fixture.signer.clone(),
        )
        .commit(fragment)
        .unwrap();
        for reader in readers {
            publish_grant(
                &mut pile,
                fixture.signer.verifying_key(),
                &fixture.signer,
                AuthorityGrant::root(
                    reader,
                    handle,
                    faculties::secrets::v2::ACTION_READ,
                    AuthorityMode::Invoke,
                ),
            )
            .unwrap();
        }
        pile.close().unwrap();
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
            legacy_secrets::schema::LEGACY_BRANCH_NAME,
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
        let direct = secrets_v2_cutover::plan_from_legacy_in_store(
            &mut store,
            &fixture.signer,
            frozen.reader(),
            projection.retained_facts().clone(),
            None,
        )
        .unwrap();
        assert_eq!(direct.vaults().len(), 1);
        assert_eq!(direct.report().synthesized_wraps(), 1);
        let vault_plan = &direct.vaults()[0];
        let fragments = vault_plan
            .report
            .data_pending
            .then(|| vault_plan.required.clone())
            .into_iter()
            .collect();
        let publication = VaultPublication::new(
            vault,
            &fixture.signer,
            vault_plan.recipients.clone(),
            fragments,
        );
        let outcome = activate_publications(
            &fixture.live,
            &fixture.target(),
            &fixture.candidate,
            &frozen,
            &fixture.signer,
            &[publication.publication()],
            |_, views| {
                assert!(views.vaults().contains_key(&vault));
                assert!(views.local_vaults().contains_key(&vault));
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(outcome, ActivationOutcome::Activated { .. }));
        assert_eq!(
            &fs::read(&fixture.live).unwrap()[..frozen_bytes.len()],
            frozen_bytes
        );

        let fixed_name = CollectionName::new("secrets").unwrap();
        let fixed_reach = triblespace::core::collection::reach::private();
        let fixed_handle = simplearchive_union::descriptor(
            &fixed_name,
            fixture.signer.verifying_key(),
            fixed_reach,
        )
        .facts()
        .clone()
        .to_blob()
        .get_handle();
        let mut pile = open_pile_strict(&fixture.live).unwrap();
        let records = discover_collection_records(&mut pile).unwrap();
        assert!(records
            .commits()
            .iter()
            .all(|commit| commit.collection() != fixed_handle));
        let authority = resolve_authority(&mut pile, fixture.signer.verifying_key()).unwrap();
        assert!(authority
            .grants()
            .all(|accepted| accepted.grant().resource() != fixed_handle));
        let reader = pile.reader().unwrap();
        assert!(reader.metadata(fixed_handle).unwrap().is_none());
        let facts = faculties::secrets::v2::vault_collection(
            &mut pile,
            vault,
            fixture.signer.verifying_key(),
            fixture.signer.clone(),
        )
        .materialize()
        .unwrap();
        let catalog = faculties::secrets::v2::validate_catalog(&reader, vault, &facts).unwrap();
        assert_eq!(catalog.secrets[&secret].body, legacy_body);
        let body: anybytes::Bytes = reader.get(catalog.secrets[&secret].body).unwrap();
        assert_eq!(body.as_ref(), malformed_body);
        drop(reader);
        pile.close().unwrap();

        let activated_bytes = fs::read(&fixture.live).unwrap();
        let replay_source = TestSourceSpec::new(vec![TestBranchSpec::new(
            legacy_secrets::schema::LEGACY_BRANCH_NAME,
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
        let replay = secrets_v2_cutover::plan_from_legacy_in_store(
            &mut replay_store,
            &fixture.signer,
            replay_source.reader(),
            replay_projection.retained_facts().clone(),
            None,
        )
        .unwrap();
        assert_eq!(replay.report().synthesized_wraps(), 0);
        assert_eq!(replay.report().pending_vaults(), 0);
        let replay_vault = &replay.vaults()[0];
        let replay_publication = VaultPublication::new(
            vault,
            &fixture.signer,
            replay_vault.recipients.clone(),
            Vec::new(),
        );
        let before_replay = fs::read(&fixture.live).unwrap();
        let outcome = activate_publications(
            &fixture.live,
            &fixture.target(),
            &fixture.candidate,
            &replay_source,
            &fixture.signer,
            &[replay_publication.publication()],
            |_, _| Ok(()),
        )
        .unwrap();
        assert_eq!(outcome, ActivationOutcome::AlreadyActive);
        assert_eq!(fs::read(&fixture.live).unwrap(), before_replay);
    }

    #[test]
    fn direct_plan_rejects_local_dormant_commit_but_global_discovery_ignores_foreign_inert_commit()
    {
        let fixture = Fixture::new();
        let (legacy, vault, _, _, _) = direct_legacy_fragment(&fixture);
        let header =
            faculties::secrets::v2::vault_header_fragment(vault, "dormant", at(5)).unwrap();
        let mut pile = open_pile_strict(&fixture.live).unwrap();
        simplearchive_union::publish_fragment_commit(
            &mut pile,
            &faculties::secrets::v2::vault_descriptor(vault, fixture.signer.verifying_key()),
            header,
            &fixture.signer,
        )
        .unwrap();
        pile.close().unwrap();

        let frozen = TestSourceSpec::new(vec![TestBranchSpec::new(
            legacy_secrets::schema::LEGACY_BRANCH_NAME,
            Id::new([0x43; 16]).unwrap(),
            SigningKey::from_bytes(&[0x43; 32]),
            vec![TestDeltaSpec::authored(legacy, "legacy Secrets")],
        )])
        .freeze(&fixture.live)
        .unwrap()
        .source;
        let projection = secrets_cutover::plan(&frozen).unwrap();
        let mut store = frozen.collection_store();
        let error = match secrets_v2_cutover::plan_from_legacy_in_store(
            &mut store,
            &fixture.signer,
            frozen.reader(),
            projection.retained_facts().clone(),
            None,
        ) {
            Ok(_) => panic!("dormant local vault COMMIT was accepted"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("dormant pre-existing COMMIT"));

        let foreign_fixture = Fixture::new();
        let foreign = SigningKey::from_bytes(&[0x77; 32]);
        let foreign_vault = Id::new([0x77; 16]).unwrap();
        let mut pile = open_pile_strict(&foreign_fixture.live).unwrap();
        simplearchive_union::publish_fragment_commit(
            &mut pile,
            &faculties::secrets::v2::vault_descriptor(
                foreign_vault,
                foreign_fixture.signer.verifying_key(),
            ),
            faculties::secrets::v2::vault_header_fragment(foreign_vault, "foreign", at(6)).unwrap(),
            &foreign,
        )
        .unwrap();
        pile.close().unwrap();
        let before = fs::read(&foreign_fixture.live).unwrap();
        let frozen = freeze_source(&foreign_fixture.live).unwrap();
        let outcome = activate_publications(
            &foreign_fixture.live,
            &foreign_fixture.target(),
            &foreign_fixture.candidate,
            &frozen,
            &foreign_fixture.signer,
            &[],
            |_, views| {
                assert!(!views.vaults().contains_key(&foreign_vault));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(outcome, ActivationOutcome::AlreadyActive);
        assert_eq!(fs::read(&foreign_fixture.live).unwrap(), before);
    }

    #[test]
    fn activation_rejects_local_dormant_commit_on_any_fixed_grant_target() {
        let directory = tempfile::tempdir().unwrap();
        let live = directory.path().join("self.pile");
        let candidate = directory.path().join("self.candidate.pile");
        let key = directory.path().join("self.key");
        File::create(&live).unwrap();
        let signer = initialize_signer(&live, Some(&key)).unwrap();
        let mut pile = open_pile_strict(&live).unwrap();
        // Seed a resolvable authority ledger without granting any canonical
        // faculty root. Activation's deterministic team-of-one grant set will
        // later include Wiki and would otherwise awaken this local COMMIT.
        publish_grant(
            &mut pile,
            signer.verifying_key(),
            &signer,
            AuthorityGrant::root(
                signer.verifying_key(),
                Inline::new([0xA1; 32]),
                ACTION_WRITE,
                AuthorityMode::Invoke,
            ),
        )
        .unwrap();
        simplearchive_union::publish_fragment_commit(
            &mut pile,
            &faculties::collection_names::root_descriptor(
                faculties::schemas::wiki::DEFAULT_SCOPE_ID,
                signer.verifying_key(),
            ),
            text_fragment(0xA2, "dormant Wiki"),
            &signer,
        )
        .unwrap();
        pile.close().unwrap();

        let before = fs::read(&live).unwrap();
        let frozen = freeze_source(&live).unwrap();
        let error = activate_publications(
            &live,
            &live.canonicalize().unwrap(),
            &candidate,
            &frozen,
            &signer,
            &[],
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("would awaken dormant local COMMIT"));
        assert_eq!(fs::read(&live).unwrap(), before);
        assert!(!candidate.exists());
    }

    #[test]
    fn exact_vault_readers_reject_extra_baseline_grant_without_a_target_commit() {
        let fixture = Fixture::new();
        let vault = Id::new([0x78; 16]).unwrap();
        let outsider = SigningKey::from_bytes(&[0x78; 32]).verifying_key();
        let handle = faculties::secrets::v2::vault_handle(vault, fixture.signer.verifying_key());
        let mut pile = open_pile_strict(&fixture.live).unwrap();
        publish_grant(
            &mut pile,
            fixture.signer.verifying_key(),
            &fixture.signer,
            AuthorityGrant::root(
                outsider,
                handle,
                faculties::secrets::v2::ACTION_READ,
                AuthorityMode::Invoke,
            ),
        )
        .unwrap();
        pile.close().unwrap();
        let before = fs::read(&fixture.live).unwrap();
        let frozen = freeze_source(&fixture.live).unwrap();
        let publication = VaultPublication::new(
            vault,
            &fixture.signer,
            BTreeSet::from([fixture.signer.verifying_key().to_bytes()]),
            Vec::new(),
        );
        let error = activate_publications(
            &fixture.live,
            &fixture.target(),
            &fixture.candidate,
            &frozen,
            &fixture.signer,
            &[publication.publication()],
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("READ recipients differ"));
        assert_eq!(fs::read(&fixture.live).unwrap(), before);
        assert!(!fixture.candidate.exists());
    }

    #[test]
    fn final_world_rejects_reader_without_wrap_and_cross_vault_secret_collision() {
        let fixture = Fixture::new();
        let vault = Id::new([0x79; 16]).unwrap();
        let secret = Id::new([0x7A; 16]).unwrap();
        let outsider = SigningKey::from_bytes(&[0x79; 32]).verifying_key();
        let mut fragment =
            faculties::secrets::v2::vault_header_fragment(vault, "missing-wrap", at(7)).unwrap();
        fragment += faculties::secrets::v2::encrypted_secret_fragment(
            secret,
            "credential",
            vec![0; 24 + 16],
            at(8),
        )
        .unwrap();
        fragment += faculties::secrets::v2::recipient_wrap_fragment(
            Id::new([0x7B; 16]).unwrap(),
            secret,
            fixture.signer.verifying_key().to_bytes(),
            vec![0; 48 + 32],
        )
        .unwrap();
        publish_vault(
            &fixture,
            vault,
            fragment,
            [fixture.signer.verifying_key(), outsider],
        );
        let before = fs::read(&fixture.live).unwrap();
        let frozen = freeze_source(&fixture.live).unwrap();
        let error = activate_publications(
            &fixture.live,
            &fixture.target(),
            &fixture.candidate,
            &frozen,
            &fixture.signer,
            &[],
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("accepted READ recipient without a wrap"));
        assert_eq!(fs::read(&fixture.live).unwrap(), before);

        let duplicate_fixture = Fixture::new();
        let vault_a = Id::new([0x7C; 16]).unwrap();
        let vault_b = Id::new([0x7D; 16]).unwrap();
        let duplicate_secret = Id::new([0x7E; 16]).unwrap();
        let secret_fragment = faculties::secrets::v2::encrypted_secret_fragment(
            duplicate_secret,
            "duplicate",
            vec![0; 24 + 16],
            at(9),
        )
        .unwrap();
        for (vault, wrap_byte) in [(vault_a, 0x7F), (vault_b, 0x80)] {
            let mut fragment = faculties::secrets::v2::vault_header_fragment(
                vault,
                if vault == vault_a { "one" } else { "two" },
                at(10),
            )
            .unwrap();
            fragment += secret_fragment.clone();
            fragment += faculties::secrets::v2::recipient_wrap_fragment(
                Id::new([wrap_byte; 16]).unwrap(),
                duplicate_secret,
                duplicate_fixture.signer.verifying_key().to_bytes(),
                vec![0; 48 + 32],
            )
            .unwrap();
            publish_vault(&duplicate_fixture, vault, fragment, std::iter::empty());
        }
        let before = fs::read(&duplicate_fixture.live).unwrap();
        let frozen = freeze_source(&duplicate_fixture.live).unwrap();
        let error = activate_publications(
            &duplicate_fixture.live,
            &duplicate_fixture.target(),
            &duplicate_fixture.candidate,
            &frozen,
            &duplicate_fixture.signer,
            &[],
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("occurs in both vault"));
        assert_eq!(fs::read(&duplicate_fixture.live).unwrap(), before);
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
