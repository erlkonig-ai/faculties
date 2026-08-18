//! The read-only source side of every migration.
//!
//! [`freeze_source`] captures one stopped-world snapshot: an immutable
//! [`PileReader`] plus the legacy pin table as read-only coordinates into it,
//! fingerprinted both semantically (the pin coordinates) and physically (every
//! source byte). Nothing here can update a pin, and those coordinates never
//! become target authority.
//!
//! [`project_legacy_authored_commits`] turns one named legacy branch into
//! self-contained content and metadata fragments: signatures are verified,
//! contentless merges stay ancestry without acquiring authority, and the
//! resident attachment closure travels with the facts. Each faculty's typed
//! transform starts from that projection.
//!
//! The live target side — signer resolution, strict pile opening, publication,
//! and target discovery — is `faculties::storage`, because every faculty needs
//! it whether or not a migration ever runs.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::Seek;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};

use triblespace::core::attribute::Attribute;
use triblespace::core::blob::encodings::longstring::LongString;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::UnknownBlob;
use triblespace::core::blob::{Blob, IntoBlob, MemoryBlobStore};
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::{Inline, InlineEncoding};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{ PileReader };
use triblespace::core::repo::{self, BlobStore, BlobStoreGet, CommitHandle, PinSnapshotSource};
use triblespace::core::trible::{Fragment, TribleSet};
use triblespace::macros::{entity, find, pattern};
use faculties::storage::{open_pile_strict };


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

/// Physical identity of the source pile captured for stopped-world activation.
///
/// This is deliberately independent of [`SourceFingerprint`]. The semantic
/// fingerprint identifies the legacy coordinates being transformed; this
/// fingerprint proves that the path still names the same file object with the
/// same complete byte content immediately before activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalSourceFingerprint {
    /// Filesystem device containing the source file.
    #[cfg(unix)]
    pub device: u64,
    /// Inode of the source file on `device`.
    #[cfg(unix)]
    pub inode: u64,
    /// Exact source length in bytes.
    pub length: u64,
    /// BLAKE3 over every source byte, in file order.
    pub digest: [u8; 32],
}

impl PhysicalSourceFingerprint {
    /// Capture the current complete byte identity of one file.
    pub(crate) fn capture(path: &Path) -> Result<Self> {
        let mut file = File::open(path)
            .with_context(|| format!("open {} for physical fingerprint", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("stat {} for physical fingerprint", path.display()))?;
        physical_fingerprint_from_open_file(path, &mut file, metadata)
    }

    /// Verify that `path` still names the captured file object and bytes.
    ///
    /// Replacement and length changes fail from metadata alone on Unix. A
    /// same-length rewrite is detected by hashing the complete file. This is a
    /// stopped-world guard, not a substitute for excluding writers: a writer
    /// that races after this method returns can still invalidate activation.
    pub fn assert_unchanged(&self, path: &Path) -> Result<()> {
        let mut file = File::open(path)
            .with_context(|| format!("open frozen source pile {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("stat frozen source pile {}", path.display()))?;
        self.assert_same_file_and_length(path, &metadata)?;

        let current = physical_fingerprint_from_open_file(path, &mut file, metadata)?;
        if current.digest != self.digest {
            bail!(
                "source pile {} contents changed after freezing; stop every writer and retry",
                path.display()
            );
        }
        Ok(())
    }

    fn assert_same_file_and_length(&self, path: &Path, metadata: &fs::Metadata) -> Result<()> {
        #[cfg(unix)]
        if metadata.dev() != self.device || metadata.ino() != self.inode {
            bail!(
                "source pile {} was replaced after freezing (device/inode {}:{} -> {}:{}); stop every writer and retry",
                path.display(),
                self.device,
                self.inode,
                metadata.dev(),
                metadata.ino()
            );
        }
        if metadata.len() != self.length {
            bail!(
                "source pile {} length changed after freezing ({} -> {} bytes); stop every writer and retry",
                path.display(),
                self.length,
                metadata.len()
            );
        }
        Ok(())
    }
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

/// Exact frozen-source coordinate of one verified legacy authored commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct LegacyCommitCoordinate {
    pub branch: Id,
    pub pin: Inline<Handle<SimpleArchive>>,
    pub commit: CommitHandle,
}

/// One verified legacy commit in a frozen branch DAG.
///
/// `content == None` identifies a canonical contentless merge. An authored
/// commit whose archive is the empty set still has `content == Some(_)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenLegacyDelta {
    pub commit: CommitHandle,
    pub parents: Vec<CommitHandle>,
    pub subject: Id,
    pub facts: TribleSet,
    commit_metadata: TribleSet,
    content: Option<Inline<Handle<SimpleArchive>>>,
    frozen: FrozenLegacyDeltaData,
}

/// Bytes already authenticated while freezing one legacy delta.
///
/// Keeping the authored content blob beside its decoded facts lets projection
/// hydrate the exact immutable attachment closure without fetching or decoding
/// the root archive a second time. This is deliberately crate-private source
/// evidence, not a cache or a target-side publication concept.
#[derive(Clone, Debug, Eq, PartialEq)]
struct FrozenLegacyDeltaData {
    content: Option<Blob<SimpleArchive>>,
    verified_facts: TribleSet,
}

/// A legacy commit metadata archive fetched and decoded exactly once while
/// walking the frozen DAG.
///
/// The head's raw archive is verified before this value is built; projection
/// needs only these decoded fields and the authenticated authored content blob.
struct FrozenLegacyCommitMetadata {
    commit: CommitHandle,
    facts: TribleSet,
    subject: Id,
    parents: Vec<CommitHandle>,
    content: Option<Inline<Handle<SimpleArchive>>>,
}

impl FrozenLegacyDelta {
    pub fn commit_metadata(&self) -> &TribleSet {
        &self.commit_metadata
    }

    pub const fn content_handle(&self) -> Option<Inline<Handle<SimpleArchive>>> {
        self.content
    }

    pub const fn is_authored(&self) -> bool {
        self.content.is_some()
    }
}

/// Exact named legacy branch observed in one frozen source snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenLegacyBranch {
    pub branch: Id,
    pub pin: Inline<Handle<SimpleArchive>>,
    pub head: Option<CommitHandle>,
    /// Verified commits in deterministic parent-before-child order.
    pub deltas: Vec<FrozenLegacyDelta>,
}

impl FrozenLegacyBranch {
    pub const fn pin_coordinate(&self) -> LegacyPinCoordinate {
        LegacyPinCoordinate {
            id: self.branch,
            value: self.pin,
        }
    }
}

/// One self-contained authored commit projected from a frozen legacy branch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedLegacyCommit {
    pub source: LegacyCommitCoordinate,
    pub content: Fragment,
    pub metadata: Fragment,
}

/// Read-only stopped-world input for deterministic migration transforms.
#[derive(Debug)]
pub struct FrozenSource {
    fingerprint: SourceFingerprint,
    physical_fingerprint: PhysicalSourceFingerprint,
    legacy_pins: Vec<LegacyPinCoordinate>,
    reader: PileReader,
}

impl FrozenSource {
    /// Semantic legacy-source identity captured by this snapshot.
    pub const fn fingerprint(&self) -> SourceFingerprint {
        self.fingerprint
    }

    /// Physical file identity and complete-byte digest captured by this freeze.
    pub const fn physical_fingerprint(&self) -> PhysicalSourceFingerprint {
        self.physical_fingerprint
    }

    /// Assert that the source path is physically unchanged since this freeze.
    ///
    /// Activation must call this after all candidate work and immediately
    /// before replacing the live path.
    pub fn assert_unchanged(&self, path: &Path) -> Result<()> {
        self.physical_fingerprint.assert_unchanged(path)
    }

    /// Legacy pin coordinates in canonical id order.
    pub fn legacy_pins(&self) -> &[LegacyPinCoordinate] {
        &self.legacy_pins
    }

    /// Immutable blob reader captured with the legacy coordinates.
    pub fn reader(&self) -> &PileReader {
        &self.reader
    }

    /// Resolve and verify one exact-name legacy branch from this snapshot.
    ///
    /// Duplicate names are rejected. The branch-head signature, every
    /// authored commit signature, and every contentless canonical merge are
    /// checked before a value is returned. This method never reopens or
    /// mutates the source pile.
    pub fn legacy_branch(&self, name: &str) -> Result<Option<FrozenLegacyBranch>> {
        let wanted: Inline<Handle<triblespace::core::blob::encodings::longstring::LongString>> =
            name.to_owned().to_blob().get_handle();
        let mut matches = Vec::new();
        for pin in &self.legacy_pins {
            let facts: TribleSet = self
                .reader
                .get(pin.value)
                .with_context(|| format!("read frozen legacy pin {:X}", pin.id))?;
            let Ok(entity) = repo::branch::branch_entity(&facts, pin.id) else {
                continue;
            };
            let branch_name = one_legacy_value(&facts, entity, &metadata::name, "branch name")?;
            if branch_name == Some(wanted) {
                matches.push((*pin, facts, entity));
            }
        }

        let (pin, branch_facts, branch_entity) = match matches.len() {
            0 => return Ok(None),
            1 => matches.pop().expect("one legacy branch match"),
            count => bail!("frozen source contains {count} legacy branches named {name}"),
        };
        let head = one_legacy_value(&branch_facts, branch_entity, &repo::head, "branch head")?;
        let deltas = if let Some(head) = head {
            // Fetch the head metadata once. The same immutable blob first
            // authenticates the branch coordinate and is then decoded to seed
            // the DAG walk, so neither operation performs another lookup.
            let head_archive = read_legacy_commit_archive(&self.reader, head)
                .with_context(|| format!("read frozen legacy {name} branch head"))?;
            repo::branch::verify(pin.id, head_archive.clone(), branch_facts.clone())
                .map_err(|_| anyhow!("frozen legacy {name} branch-head signature is invalid"))?;
            let head_metadata = decode_legacy_commit_metadata(head, head_archive)?;

            legacy_topological(&self.reader, head_metadata)?
                .into_iter()
                .map(|metadata| freeze_legacy_delta(&self.reader, name, metadata))
                .collect::<Result<Vec<_>>>()?
        } else {
            Vec::new()
        };

        Ok(Some(FrozenLegacyBranch {
            branch: pin.id,
            pin: pin.value,
            head,
            deltas,
        }))
    }
}

/// Project every authored legacy delta into self-contained content and
/// metadata fragments.
///
/// Contentless merge nodes remain verified ancestry but produce no collection
/// authority. Authored empty archives do produce an empty content fragment.
/// The payload validator must strictly load every schema-known direct handle;
/// conservative closure hydration then carries every resident attachment.
pub fn project_legacy_authored_commits<V>(
    source: &FrozenSource,
    branch: &FrozenLegacyBranch,
    validate_payloads: V,
) -> Result<Vec<ProjectedLegacyCommit>>
where
    V: Fn(&PileReader, &TribleSet) -> Result<()>,
{
    if !source.legacy_pins.contains(&branch.pin_coordinate()) {
        bail!(
            "frozen legacy branch {:X} pin is not part of this source snapshot",
            branch.branch
        );
    }
    if branch.head != branch.deltas.last().map(|delta| delta.commit) {
        bail!(
            "frozen legacy branch {:X} deltas do not end at its captured head",
            branch.branch
        );
    }

    let mut projected = Vec::new();
    for delta in &branch.deltas {
        let Some(content_blob) = delta.frozen.content.as_ref() else {
            continue;
        };
        if delta.facts != delta.frozen.verified_facts {
            bail!(
                "frozen legacy commit {} content differs from its verified delta",
                hex::encode_upper(delta.commit.raw)
            );
        }
        let facts = delta.frozen.verified_facts.clone();
        validate_payloads(&source.reader, &facts).with_context(|| {
            format!(
                "validate frozen legacy content payloads in commit {}",
                hex::encode_upper(delta.commit.raw)
            )
        })?;
        let content = Fragment::from_facts_and_blobs(
            facts,
            hydrate_resident_closure(
                &source.reader,
                [content_blob.clone().transmute::<UnknownBlob>()],
            ),
        );
        let metadata = project_legacy_metadata(&source.reader, delta, &validate_payloads)?;
        projected.push(ProjectedLegacyCommit {
            source: LegacyCommitCoordinate {
                branch: branch.branch,
                pin: branch.pin,
                commit: delta.commit,
            },
            content,
            metadata,
        });
    }
    Ok(projected)
}

fn one_legacy_value<V: InlineEncoding>(
    facts: &TribleSet,
    subject: Id,
    attribute: &Attribute<V>,
    field: &str,
) -> Result<Option<Inline<V>>> {
    let mut values = facts
        .iter()
        .filter(|fact| fact.e() == &subject && fact.a() == &attribute.id())
        .map(|fact| *fact.v::<V>());
    let first = values.next();
    if values.next().is_some() {
        bail!("frozen legacy commit or branch has repeated {field}");
    }
    Ok(first)
}

fn legacy_commit_subject(facts: &TribleSet, handle: CommitHandle) -> Result<Id> {
    let entities: BTreeSet<Id> = facts.iter().map(|fact| *fact.e()).collect();
    if entities.len() != 1 {
        bail!(
            "frozen legacy commit {} must contain exactly one metadata entity, found {}",
            hex::encode_upper(handle.raw),
            entities.len()
        );
    }
    Ok(*entities.iter().next().expect("one legacy commit entity"))
}

fn legacy_parents(facts: &TribleSet, subject: Id) -> Vec<CommitHandle> {
    let mut parents: Vec<_> = find!(
        (parent: CommitHandle),
        pattern!(facts, [{ subject @ repo::parent: ?parent }])
    )
    .map(|(parent,)| parent)
    .collect();
    parents.sort_unstable_by_key(|parent| parent.raw);
    parents.dedup();
    parents
}

fn load_legacy_commit_metadata(
    reader: &PileReader,
    commit: CommitHandle,
) -> Result<FrozenLegacyCommitMetadata> {
    decode_legacy_commit_metadata(commit, read_legacy_commit_archive(reader, commit)?)
}

fn read_legacy_commit_archive(
    reader: &PileReader,
    commit: CommitHandle,
) -> Result<Blob<SimpleArchive>> {
    reader.get(commit).with_context(|| {
        format!(
            "read frozen legacy commit {}",
            hex::encode_upper(commit.raw)
        )
    })
}

fn decode_legacy_commit_metadata(
    commit: CommitHandle,
    archive: Blob<SimpleArchive>,
) -> Result<FrozenLegacyCommitMetadata> {
    let facts: TribleSet = archive.try_from_blob().with_context(|| {
        format!(
            "decode frozen legacy commit {}",
            hex::encode_upper(commit.raw)
        )
    })?;
    let subject = legacy_commit_subject(&facts, commit)?;
    let parents = legacy_parents(&facts, subject);
    let content = one_legacy_value(&facts, subject, &repo::content, "content")?;
    Ok(FrozenLegacyCommitMetadata {
        commit,
        facts,
        subject,
        parents,
        content,
    })
}

fn freeze_legacy_delta(
    reader: &PileReader,
    branch_name: &str,
    metadata: FrozenLegacyCommitMetadata,
) -> Result<FrozenLegacyDelta> {
    let FrozenLegacyCommitMetadata {
        commit,
        facts: commit_metadata,
        subject,
        parents,
        content,
    } = metadata;
    let (facts, content) = match content {
        Some(handle) => {
            let blob: Blob<SimpleArchive> = reader.get(handle).with_context(|| {
                format!(
                    "read frozen legacy {branch_name} content {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
            repo::commit::verify(blob.clone(), commit_metadata.clone()).map_err(|_| {
                anyhow!(
                    "frozen legacy authored commit {} has an invalid content signature",
                    hex::encode_upper(commit.raw)
                )
            })?;
            let facts: TribleSet = blob.clone().try_from_blob().with_context(|| {
                format!(
                    "decode frozen legacy {branch_name} content {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
            (facts, Some(blob))
        }
        None => {
            validate_contentless_merge(&commit_metadata, subject, commit)?;
            (TribleSet::new(), None)
        }
    };
    let frozen_facts = facts.clone();
    Ok(FrozenLegacyDelta {
        commit,
        parents,
        subject,
        facts,
        commit_metadata,
        content: content.as_ref().map(Blob::get_handle),
        frozen: FrozenLegacyDeltaData {
            content,
            verified_facts: frozen_facts,
        },
    })
}

fn legacy_topological(
    reader: &PileReader,
    head: FrozenLegacyCommitMetadata,
) -> Result<Vec<FrozenLegacyCommitMetadata>> {
    let head_commit = head.commit;
    let mut ordered = Vec::new();
    let mut emitted = HashSet::new();
    let mut active = HashSet::new();
    let mut loaded = BTreeMap::from([(head_commit, head)]);
    let mut stack = vec![(head_commit, false)];
    while let Some((commit, expanded)) = stack.pop() {
        if emitted.contains(&commit) {
            continue;
        }
        if expanded {
            active.remove(&commit);
            emitted.insert(commit);
            ordered.push(commit);
            continue;
        }
        if !active.insert(commit) {
            bail!(
                "cycle in frozen legacy commit ancestry at {}",
                hex::encode_upper(commit.raw)
            );
        }
        if let std::collections::btree_map::Entry::Vacant(entry) = loaded.entry(commit) {
            entry.insert(load_legacy_commit_metadata(reader, commit)?);
        }
        let parents = loaded
            .get(&commit)
            .expect("visited legacy commit metadata was loaded")
            .parents
            .clone();
        stack.push((commit, true));
        for parent in parents.into_iter().rev() {
            if active.contains(&parent) {
                bail!(
                    "cycle in frozen legacy commit ancestry at {}",
                    hex::encode_upper(parent.raw)
                );
            }
            if !emitted.contains(&parent) {
                stack.push((parent, false));
            }
        }
    }
    Ok(ordered
        .into_iter()
        .map(|commit| {
            loaded
                .remove(&commit)
                .expect("ordered legacy commit metadata was loaded")
        })
        .collect())
}

fn validate_contentless_merge(facts: &TribleSet, subject: Id, commit: CommitHandle) -> Result<()> {
    let parents = legacy_parents(facts, subject);
    let only_parents = facts
        .iter()
        .all(|fact| fact.e() == &subject && fact.a() == &repo::parent.id());
    let current = entity! { repo::parent*: parents.clone() }.root();
    let historical = triblespace::core::trible::intrinsic_entity_id_v1(
        parents
            .iter()
            .map(|parent| (repo::parent.id(), parent.raw))
            .collect(),
    );
    if parents.len() < 2 || !only_parents || (current != Some(subject) && historical != subject) {
        bail!(
            "frozen contentless legacy commit {} is not a canonical merge",
            hex::encode_upper(commit.raw)
        );
    }
    Ok(())
}

fn project_legacy_metadata<V>(
    reader: &PileReader,
    delta: &FrozenLegacyDelta,
    validate_payloads: &V,
) -> Result<Fragment>
where
    V: Fn(&PileReader, &TribleSet) -> Result<()> + ?Sized,
{
    let commit = delta.commit_metadata();
    let attached = one_legacy_value(
        commit,
        delta.subject,
        &metadata::archive,
        "metadata archive",
    )?;
    let message = one_legacy_value(commit, delta.subject, &repo::message, "message")?;
    let created = one_legacy_value(commit, delta.subject, &metadata::created_at, "created_at")?;

    let (mut facts, mut blobs) = if let Some(handle) = attached {
        let blob: Blob<SimpleArchive> = reader.get(handle).with_context(|| {
            format!(
                "strictly read attached frozen legacy metadata {}",
                hex::encode_upper(handle.raw)
            )
        })?;
        let facts: TribleSet = blob.clone().try_from_blob().with_context(|| {
            format!(
                "decode attached frozen legacy metadata {}",
                hex::encode_upper(handle.raw)
            )
        })?;
        validate_payloads(reader, &facts).with_context(|| {
            format!(
                "validate attached frozen legacy semantic metadata in commit {}",
                hex::encode_upper(delta.commit.raw)
            )
        })?;
        (
            facts,
            hydrate_resident_closure(reader, [blob.transmute::<UnknownBlob>()]),
        )
    } else {
        (TribleSet::new(), MemoryBlobStore::new())
    };

    if let Some(handle) = message {
        let blob: Blob<LongString> = reader.get(handle).with_context(|| {
            format!(
                "strictly read frozen legacy commit message {}",
                hex::encode_upper(handle.raw)
            )
        })?;
        let _: View<str> = blob.clone().try_from_blob().with_context(|| {
            format!(
                "decode frozen legacy commit message {}",
                hex::encode_upper(handle.raw)
            )
        })?;
        blobs.union(hydrate_resident_closure(
            reader,
            [blob.transmute::<UnknownBlob>()],
        ));
    }

    let projected = match (created, message) {
        (Some(created), Some(message)) => entity! {
            metadata::created_at: created,
            metadata::description: message,
        },
        (Some(created), None) => entity! { metadata::created_at: created },
        (None, Some(message)) => entity! { metadata::description: message },
        (None, None) => Fragment::empty(),
    };
    let (_, projected_facts, projected_metafacts, projected_blobs) = projected.into_parts();
    facts += projected_facts;
    facts += projected_metafacts;
    blobs.union(projected_blobs);
    Ok(Fragment::from_facts_and_blobs(facts, blobs))
}

fn hydrate_resident_closure(
    reader: &PileReader,
    roots: impl IntoIterator<Item = Blob<UnknownBlob>>,
) -> MemoryBlobStore {
    let mut blobs = MemoryBlobStore::new();
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    for blob in roots {
        if seen.insert(blob.get_handle().raw) {
            queue.push_back(blob);
        }
    }

    while let Some(blob) = queue.pop_front() {
        // This is the same conservative 32-byte scan as BlobChildren's
        // default traversal, but starts from the already loaded root and
        // carries each successfully resolved child blob forward. No closure
        // member is fetched twice merely to enumerate and then copy it.
        for raw in blob.bytes.as_ref().chunks_exact(32) {
            let mut candidate = [0; 32];
            candidate.copy_from_slice(raw);
            if seen.contains(&candidate) {
                continue;
            }
            let handle = Inline::<Handle<UnknownBlob>>::new(candidate);
            if let Ok(child) = reader.get::<Blob<UnknownBlob>, UnknownBlob>(handle) {
                // `seen` is the reachable-handle set, not an index of every
                // arbitrary 32-byte word in an opaque payload. Recording a
                // miss here can retain the complete contents of a large file
                // as hundreds of millions of unrelated hash-set entries.
                seen.insert(candidate);
                queue.push_back(child);
            }
        }
        blobs.insert(blob);
    }
    blobs
}

/// Capture an immutable reader plus read-only legacy pin coordinates.
///
/// Every writer must already be stopped. A read-only file handle anchors the
/// physical file object while the pile is opened, refreshed, snapshotted, and
/// closed without mutation. Identity and length checks around that snapshot
/// catch replacement, append, or truncation racing the freeze. The physical
/// fingerprint covers every source byte; the separate semantic fingerprint
/// covers only canonical pin coordinates and remains insensitive to physical
/// compaction and unrelated append history.
pub fn freeze_source(path: &Path) -> Result<FrozenSource> {
    let mut physical_file = File::open(path)
        .with_context(|| format!("open source pile {} for physical freeze", path.display()))?;
    let initial_metadata = physical_file
        .metadata()
        .with_context(|| format!("stat source pile {}", path.display()))?;
    let physical_fingerprint =
        physical_fingerprint_from_open_file(path, &mut physical_file, initial_metadata)?;
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

    let final_metadata = fs::metadata(path)
        .with_context(|| format!("stat source pile {} after freezing", path.display()))?;
    physical_fingerprint.assert_same_file_and_length(path, &final_metadata)?;
    let fingerprint = fingerprint_legacy_pins(&legacy_pins);

    Ok(FrozenSource {
        fingerprint,
        physical_fingerprint,
        legacy_pins,
        reader,
    })
}

fn physical_fingerprint_from_open_file(
    path: &Path,
    file: &mut File,
    initial_metadata: fs::Metadata,
) -> Result<PhysicalSourceFingerprint> {
    let mut hasher = blake3::Hasher::new();
    file.rewind()
        .with_context(|| format!("rewind source pile {} for hashing", path.display()))?;
    hasher
        .update_reader(&mut *file)
        .with_context(|| format!("hash complete source pile {}", path.display()))?;
    let bytes_read = file
        .stream_position()
        .with_context(|| format!("measure hashed source pile {}", path.display()))?;
    let final_metadata = file
        .metadata()
        .with_context(|| format!("restat open source pile {}", path.display()))?;

    #[cfg(unix)]
    if initial_metadata.dev() != final_metadata.dev()
        || initial_metadata.ino() != final_metadata.ino()
    {
        bail!(
            "open source pile {} changed file identity while hashing; stop every writer and retry",
            path.display()
        );
    }
    if initial_metadata.len() != final_metadata.len() || bytes_read != initial_metadata.len() {
        bail!(
            "open source pile {} changed length while hashing (expected {}, read {}, now {} bytes); stop every writer and retry",
            path.display(),
            initial_metadata.len(),
            bytes_read,
            final_metadata.len()
        );
    }

    Ok(PhysicalSourceFingerprint {
        #[cfg(unix)]
        device: final_metadata.dev(),
        #[cfg(unix)]
        inode: final_metadata.ino(),
        length: final_metadata.len(),
        digest: *hasher.finalize().as_bytes(),
    })
}

fn legacy_pin_coordinates<S>(source: &mut S) -> Result<Vec<LegacyPinCoordinate>>
where
    S: PinSnapshotSource,
{
    let snapshot = source
        .snapshot_pin_heads()
        .context("snapshot frozen legacy pins")?;
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


#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::path::PathBuf;
    use std::io::{Seek, SeekFrom, Write};
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use triblespace::core::blob::encodings::longstring::LongString;
    use triblespace::core::metadata;
    use triblespace::core::repo::{BlobStorePut, PinStore, PushResult, Repository};
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
    fn frozen_source_is_read_only_and_captures_semantic_coordinates() {
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

        let physical = frozen.physical_fingerprint();
        assert_eq!(physical.length, before.len() as u64);
        assert_eq!(physical.digest, *blake3::hash(&before).as_bytes());
        frozen.assert_unchanged(&files.pile).unwrap();
    }

    #[test]
    fn projection_reuses_the_frozen_verified_content_blob() {
        const BRANCH: &str = "single-decode";
        let files = TestFiles::new();
        let pile = open_pile_strict(&files.pile).unwrap();
        let mut repository =
            Repository::new(pile, SigningKey::from_bytes(&[0x5A; 32]), Fragment::empty()).unwrap();
        let branch_id = *repository.create_branch(BRANCH, None).unwrap();
        let expected = entity! { _ @ metadata::tag: &id(12) };
        let expected_facts = expected.facts().clone();
        let mut workspace = repository.pull(branch_id).unwrap();
        workspace.commit(expected, "frozen once");
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();

        let source = freeze_source(&files.pile).unwrap();
        let branch = source.legacy_branch(BRANCH).unwrap().unwrap();
        let delta = branch
            .deltas
            .iter()
            .find(|delta| delta.is_authored())
            .expect("one authored legacy delta");
        let content = delta.content_handle().unwrap();
        let attached = one_legacy_value(
            delta.commit_metadata(),
            delta.subject,
            &metadata::archive,
            "metadata archive",
        )
        .unwrap()
        .unwrap();
        let message = one_legacy_value(
            delta.commit_metadata(),
            delta.subject,
            &repo::message,
            "message",
        )
        .unwrap()
        .unwrap();

        // Projection still needs semantic metadata roots, but deliberately
        // receives a reader from which the authored content archive is absent.
        // Success therefore proves it consumes the verified blob frozen on the
        // delta rather than retrieving/decoding the content a second time.
        let detached_path = files.directory.join("detached.pile");
        File::create(&detached_path).unwrap();
        let mut detached = open_pile_strict(&detached_path).unwrap();
        let attached_blob: Blob<SimpleArchive> = source.reader().get(attached).unwrap();
        detached
            .put::<SimpleArchive, _>(attached_blob)
            .expect("copy attached semantic metadata");
        let message_blob: Blob<LongString> = source.reader().get(message).unwrap();
        detached
            .put::<LongString, _>(message_blob)
            .expect("copy legacy message");
        let detached_reader = detached.reader().unwrap();
        assert!(detached_reader
            .get::<Blob<SimpleArchive>, SimpleArchive>(content)
            .is_err());
        detached.close().unwrap();

        let detached_source = FrozenSource {
            fingerprint: source.fingerprint,
            physical_fingerprint: source.physical_fingerprint,
            legacy_pins: source.legacy_pins.clone(),
            reader: detached_reader,
        };

        let mut tampered = branch.clone();
        tampered
            .deltas
            .iter_mut()
            .find(|delta| delta.is_authored())
            .unwrap()
            .facts += entity! { _ @ metadata::tag: &id(13) }.into_facts();
        let error = project_legacy_authored_commits(&detached_source, &tampered, |_, _| Ok(()))
            .unwrap_err();
        assert!(format!("{error:#}").contains("content differs from its verified delta"));

        let projected =
            project_legacy_authored_commits(&detached_source, &branch, |_, _| Ok(())).unwrap();
        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0].content.facts(), &expected_facts);
    }

    #[test]
    fn physical_source_guard_rejects_append() {
        let files = TestFiles::new();
        let frozen = freeze_source(&files.pile).unwrap();

        OpenOptions::new()
            .append(true)
            .open(&files.pile)
            .unwrap()
            .write_all(b"appended")
            .unwrap();

        let error = frozen.assert_unchanged(&files.pile).unwrap_err();
        assert!(format!("{error:#}").contains("length changed after freezing"));
    }

    #[test]
    fn physical_source_guard_rejects_truncation() {
        let files = TestFiles::new();
        let mut pile = open_pile_strict(&files.pile).unwrap();
        pile.put::<SimpleArchive, _>(TribleSet::new()).unwrap();
        pile.close().unwrap();
        let frozen = freeze_source(&files.pile).unwrap();
        let length = fs::metadata(&files.pile).unwrap().len();
        OpenOptions::new()
            .write(true)
            .open(&files.pile)
            .unwrap()
            .set_len(length - 1)
            .unwrap();

        let error = frozen.assert_unchanged(&files.pile).unwrap_err();
        assert!(format!("{error:#}").contains("length changed after freezing"));
    }

    #[test]
    fn physical_source_guard_rejects_same_length_rewrite() {
        let files = TestFiles::new();
        let mut pile = open_pile_strict(&files.pile).unwrap();
        pile.put::<SimpleArchive, _>(TribleSet::new()).unwrap();
        pile.close().unwrap();
        let frozen = freeze_source(&files.pile).unwrap();

        let mut file = OpenOptions::new().write(true).open(&files.pile).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"X").unwrap();
        file.sync_all().unwrap();

        let error = frozen.assert_unchanged(&files.pile).unwrap_err();
        assert!(format!("{error:#}").contains("contents changed after freezing"));
    }

    #[cfg(unix)]
    #[test]
    fn physical_source_guard_rejects_byte_identical_replacement() {
        let files = TestFiles::new();
        let frozen = freeze_source(&files.pile).unwrap();
        let bytes = fs::read(&files.pile).unwrap();
        let replacement = files.directory.join("replacement.pile");
        fs::write(&replacement, bytes).unwrap();
        fs::rename(replacement, &files.pile).unwrap();

        let error = frozen.assert_unchanged(&files.pile).unwrap_err();
        assert!(format!("{error:#}").contains("was replaced after freezing"));
    }

}

