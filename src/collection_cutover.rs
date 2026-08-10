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

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;

use triblespace::core::attribute::Attribute;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::UnknownBlob;
use triblespace::core::blob::{Blob, IntoBlob, MemoryBlobStore};
use triblespace::core::collection::simplearchive_union;
use triblespace::core::collection::{
    discover_collection_records, Collection, CollectionCommit, CollectionDefinition,
    CollectionDerive, CollectionMerge, CollectionRecordDiagnostic, CollectionStore,
};
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::{Inline, InlineEncoding};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader, ReadError};
use triblespace::core::repo::{self, reachable, BlobStore, BlobStoreGet, CommitHandle, PinStore};
use triblespace::core::signing_key_file;
use triblespace::core::trible::{Fragment, TribleSet};
use triblespace::macros::{entity, find, pattern};

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
    let mut commits = publish_fragments(pile_path, key_path, scope, [fragment])?;
    Ok(commits
        .pop()
        .expect("one input fragment produces one collection commit"))
}

/// Publish a deterministic sequence of complete fragments into one collection.
///
/// This is the authored-leaf migration path: the target pile is opened once,
/// each input crosses the same narrow [`Collection::commit`] boundary, and the
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
    let mut collection = Collection::new(pile, scope, signer);
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
        if let Some(head) = head {
            let blob: Blob<SimpleArchive> = self
                .reader
                .get(head)
                .with_context(|| format!("read frozen legacy {name} branch head"))?;
            repo::branch::verify(pin.id, blob, branch_facts.clone())
                .map_err(|_| anyhow!("frozen legacy {name} branch-head signature is invalid"))?;
        }

        let mut deltas = Vec::new();
        if let Some(head) = head {
            for commit in legacy_topological(&self.reader, head)? {
                let commit_metadata = legacy_commit_metadata(&self.reader, commit)?;
                let subject = legacy_commit_subject(&commit_metadata, commit)?;
                let parents = legacy_parents(&commit_metadata, subject);
                let content =
                    one_legacy_value(&commit_metadata, subject, &repo::content, "content")?;
                let facts = match content {
                    Some(content) => {
                        let blob: Blob<SimpleArchive> =
                            self.reader.get(content).with_context(|| {
                                format!(
                                    "read frozen legacy {name} content {}",
                                    hex::encode_upper(content.raw)
                                )
                            })?;
                        repo::commit::verify(blob, commit_metadata.clone()).map_err(|_| {
                            anyhow!(
                                "frozen legacy authored commit {} has an invalid content signature",
                                hex::encode_upper(commit.raw)
                            )
                        })?;
                        self.reader.get(content).with_context(|| {
                            format!(
                                "decode frozen legacy {name} content {}",
                                hex::encode_upper(content.raw)
                            )
                        })?
                    }
                    None => {
                        validate_contentless_merge(&commit_metadata, subject, commit)?;
                        TribleSet::new()
                    }
                };
                deltas.push(FrozenLegacyDelta {
                    commit,
                    parents,
                    subject,
                    facts,
                    commit_metadata,
                    content,
                });
            }
        }

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
        let Some(content_handle) = delta.content_handle() else {
            continue;
        };
        let content_blob: Blob<SimpleArchive> =
            source.reader.get(content_handle).with_context(|| {
                format!(
                    "read frozen legacy content {}",
                    hex::encode_upper(content_handle.raw)
                )
            })?;
        repo::commit::verify(content_blob, delta.commit_metadata.clone()).map_err(|_| {
            anyhow!(
                "frozen legacy authored commit {} has an invalid content signature",
                hex::encode_upper(delta.commit.raw)
            )
        })?;
        let facts: TribleSet = source.reader.get(content_handle).with_context(|| {
            format!(
                "decode frozen legacy content {}",
                hex::encode_upper(content_handle.raw)
            )
        })?;
        if facts != delta.facts {
            bail!(
                "frozen legacy commit {} content differs from its verified delta",
                hex::encode_upper(delta.commit.raw)
            );
        }
        validate_payloads(&source.reader, &facts).with_context(|| {
            format!(
                "validate frozen legacy content payloads in commit {}",
                hex::encode_upper(delta.commit.raw)
            )
        })?;
        let content = Fragment::from_facts_and_blobs(
            facts,
            hydrate_resident_closure(&source.reader, [content_handle.transmute()])?,
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

fn legacy_commit_metadata(reader: &PileReader, handle: CommitHandle) -> Result<TribleSet> {
    reader.get(handle).with_context(|| {
        format!(
            "read frozen legacy commit {}",
            hex::encode_upper(handle.raw)
        )
    })
}

fn legacy_topological(reader: &PileReader, head: CommitHandle) -> Result<Vec<CommitHandle>> {
    let mut ordered = Vec::new();
    let mut emitted = HashSet::new();
    let mut active = HashSet::new();
    let mut stack = vec![(head, false)];
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
        let facts = legacy_commit_metadata(reader, commit)?;
        let subject = legacy_commit_subject(&facts, commit)?;
        let parents = legacy_parents(&facts, subject);
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
    Ok(ordered)
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
        let _: Blob<SimpleArchive> = reader.get(handle).with_context(|| {
            format!(
                "strictly read attached frozen legacy metadata {}",
                hex::encode_upper(handle.raw)
            )
        })?;
        let facts: TribleSet = reader.get(handle).with_context(|| {
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
            hydrate_resident_closure(reader, [handle.transmute()])?,
        )
    } else {
        (TribleSet::new(), MemoryBlobStore::new())
    };

    if let Some(handle) = message {
        let _: View<str> = reader.get(handle).with_context(|| {
            format!(
                "strictly read frozen legacy commit message {}",
                hex::encode_upper(handle.raw)
            )
        })?;
        blobs.union(hydrate_resident_closure(reader, [handle.transmute()])?);
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
    roots: impl IntoIterator<Item = Inline<Handle<UnknownBlob>>>,
) -> Result<MemoryBlobStore> {
    let mut blobs = MemoryBlobStore::new();
    for handle in reachable(reader, roots) {
        let blob: Blob<UnknownBlob> = reader.get(handle).with_context(|| {
            format!(
                "load reachable frozen legacy attachment {}",
                hex::encode_upper(handle.raw)
            )
        })?;
        blobs.insert(blob);
    }
    Ok(blobs)
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
