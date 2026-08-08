//! Shared access to `SimpleArchive`-union collections in a pile.
//!
//! This is intentionally a composition boundary, not another repository
//! model. Callers supply an extrinsic scope and explicit signer authority;
//! the collection definition, signed commits, reproducible merge equations,
//! and physical cover remain the canonical TribleSpace objects.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};

use triblespace::core::attribute::Attribute;
use triblespace::core::blob::encodings::longstring::LongString;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::UnknownBlob;
use triblespace::core::blob::{Blob, IntoBlob, MemoryBlobStore};
use triblespace::core::collection::simplearchive_union::{
    self, prepare_fragment_commit, publish_fragment_commit, validate_commit, validate_merge,
    StagedCollectionCommit,
};
use triblespace::core::collection::{
    discover_collection_records, plan_collection_retention, resolve_collection_semantics,
    CollectionClaimValidation, CollectionCommit, CollectionData, CollectionDefinition,
    CollectionResolution, CollectionValidationRequest, DiscoveredCollectionRecords,
};
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::{Inline, InlineEncoding};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader, ReadError};
use triblespace::core::repo::{
    self, reachable, BlobStore, BlobStoreGet, BlobStoreMeta, CommitHandle, PinStore, RetentionRoots,
};
use triblespace::core::signing_key_file;
use triblespace::core::trible::{Fragment, TribleSet};
use triblespace::macros::{entity, find, pattern};

/// Canonical identity of one authorized collection view.
///
/// The digest commits to the exact intrinsic collection-definition id, sorted
/// authorization roster, and sorted ids of every authorized, admitted target
/// [`CollectionCommit`]. It deliberately excludes unsigned equations and
/// unauthorized records.
///
/// Version 1 describes direct target-COMMIT roots: this module currently keeps
/// every `DERIVE` claim pending. Admitting cross-collection derives in the
/// future requires a new transcript version covering the relevant active claim
/// ids and supporting source commits; the v1 formula must not be silently
/// extended.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CollectionRevision([u8; 32]);

impl CollectionRevision {
    /// Raw BLAKE3 revision digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for CollectionRevision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&hex::encode_upper(self.0))
    }
}

/// One immutable materialization of a real collection.
///
/// `commits` is the exact sorted set of authorized target commit records which
/// passed concrete validation. The reader owns the same immutable pile
/// snapshot used for discovery and remains usable for attachment reads after
/// the writable [`Pile`] used to create the snapshot has been closed.
#[derive(Debug)]
pub struct CollectionView {
    pub facts: TribleSet,
    pub reader: PileReader,
    pub commits: Vec<CollectionCommit>,
    pub revision: CollectionRevision,
}

/// Temporary read result for one named legacy repository branch.
///
/// Legacy branches have no collection definition, authorization roster, or
/// admitted collection commits and therefore cannot honestly carry a
/// [`CollectionRevision`]. New collection-native readers should use
/// [`CollectionSnapshot`] and [`CollectionView`] instead.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LegacyBranchRevision([u8; 32]);

impl LegacyBranchRevision {
    /// Raw handle of the exact signed legacy branch-pin metadata snapshot.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug)]
pub struct LegacyBranchView {
    pub facts: TribleSet,
    pub reader: PileReader,
    pub revision: LegacyBranchRevision,
}

/// One immutable pile snapshot with collection records discovered exactly once.
///
/// Reuse a snapshot to materialize any number of scopes. Each call supplies an
/// independent signer roster while sharing the exact same record discovery and
/// attachment-reader boundary. Opening and reading a snapshot never resolves a
/// signer and never writes to the pile.
#[derive(Debug)]
pub struct CollectionSnapshot {
    reader: PileReader,
    records: DiscoveredCollectionRecords,
}

/// An explicitly closed writer for repeated publications into one collection.
///
/// This is only an ownership seam around an open [`Pile`], one intrinsic
/// collection definition, and one durable signer. It does not introduce a
/// head, checkout, or mutable workspace. [`Self::stage_fragment`] is only a
/// consuming crash-order seam around one exact commit: it durably writes
/// dependencies while withholding that record. Each completed call to
/// [`Self::publish_fragment`] remains an independently signed collection root.
///
/// Call [`Self::finish`] even when the surrounding operation failed so close
/// errors remain observable. Dropping the writer without finishing delegates
/// to [`Pile`]'s loud unclosed-pile warning; `Drop` is not a durability path.
#[derive(Debug)]
pub struct CollectionWriter {
    pile: Option<Pile>,
    definition: CollectionDefinition,
    signer: SigningKey,
}

impl CollectionWriter {
    /// Open one collection for repeated publication with an existing signer.
    ///
    /// The signer is loaded before the pile is touched. Neither a missing key
    /// nor a corrupt pile is repaired implicitly.
    pub fn open(pile_path: &Path, key_path: Option<&Path>, scope: Id) -> Result<Self> {
        let signer = load_signer(pile_path, key_path)?;
        let definition = simplearchive_union::definition(scope);
        let pile = open_pile_strict(pile_path)?;
        Ok(Self {
            pile: Some(pile),
            definition,
            signer,
        })
    }

    /// Durably stage one signed fragment while withholding its `COMMIT` record.
    ///
    /// Dependencies and attachments are flushed before this returns. The
    /// returned value keeps this writer's pile mutably borrowed so callers can
    /// append intervening unsigned collection equations through
    /// [`StagedCollectionCommit::store_mut`], then consume it with
    /// [`StagedCollectionCommit::finalize`] to append the exact prepared
    /// `COMMIT` last. Dropping it is deliberately inert and never publishes
    /// the withheld record.
    pub fn stage_fragment(
        &mut self,
        content: impl Into<Fragment>,
        metadata: impl Into<Fragment>,
    ) -> Result<StagedCollectionCommit<'_, Pile>> {
        let prepared = prepare_fragment_commit(&self.definition, content, metadata, &self.signer)
            .context("prepare collection fragment")?;
        let pile = self
            .pile
            .as_mut()
            .expect("collection writer is open until consumed by finish");
        prepared
            .stage(pile)
            .context("stage collection fragment dependencies")
    }

    /// Publish one independent signed fragment without reopening the pile.
    pub fn publish_fragment(
        &mut self,
        content: impl Into<Fragment>,
        metadata: impl Into<Fragment>,
    ) -> Result<CollectionCommit> {
        self.stage_fragment(content, metadata)?
            .finalize()
            .context("finalize collection fragment")
    }

    /// Close the pile and combine its result with the surrounding operation.
    ///
    /// This makes the common `let result = ...; writer.finish(result)` pattern
    /// preserve the primary operation error while still observing and
    /// reporting a simultaneous close failure.
    pub fn finish<T>(mut self, result: Result<T>) -> Result<T> {
        let pile = self
            .pile
            .take()
            .expect("collection writer can only be finished once");
        finish_pile(pile, result)
    }

    /// Explicitly close a successfully used writer.
    pub fn close(self) -> Result<()> {
        self.finish(Ok(()))
    }
}

/// Resolve the durable signer path for a pile without touching the filesystem.
///
/// Resolution is explicit path, then `TRIBLESPACE_KEY`, then `self.key` beside
/// the pile, exactly as defined by [`signing_key_file::resolve_path`].
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

/// Explicitly initialize a durable signer, or load the valid concurrent winner.
///
/// This is deliberately separate from [`load_signer`] and all read/write
/// operations so ordinary use can never create a new signing identity.
pub fn initialize_signer(pile: &Path, explicit: Option<&Path>) -> Result<SigningKey> {
    let path = signer_path(pile, explicit);
    signing_key_file::init(&path)
        .with_context(|| format!("initialize durable signing key {}", path.display()))
}

/// Open and refresh an existing pile without automatic repair.
///
/// A corrupt tail is reported with the last valid byte offset. Amputation is
/// an explicit destructive operator action and is never performed here.
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

impl CollectionSnapshot {
    /// Open one strict immutable pile snapshot and discover collection records.
    ///
    /// Discovery happens exactly once here. Later materializations reuse both
    /// these canonicalized records and this snapshot-owned attachment reader.
    pub fn open(pile_path: &Path) -> Result<Self> {
        let mut pile = open_pile_strict(pile_path)?;
        let result = (|| {
            let reader = pile.reader().context("snapshot pile for collection read")?;
            let records =
                discover_collection_records(&reader).context("discover collection records")?;
            Ok(Self { reader, records })
        })();
        finish_pile(pile, result)
    }

    /// Materialize one scope under an independent explicit signer roster.
    ///
    /// Every structurally valid target commit signed by a roster member must
    /// validate now. Unauthorized commits and unsigned pending/rejected noise
    /// do not poison the view or enter its revision.
    pub fn materialize_scope(
        &self,
        scope: Id,
        allowed_signers: &HashSet<VerifyingKey>,
    ) -> Result<CollectionView> {
        let resolved = resolve_reader_scope(&self.reader, &self.records, scope, allowed_signers)?;
        let facts = simplearchive_union::materialize(
            resolved.resolution.semantics(),
            &resolved.definition,
            &self.reader,
        )
        .context("materialize collection physical cover")?;
        let admitted = resolved.resolution.admitted_claims();
        let mut commits: Vec<_> = self
            .records
            .commits()
            .iter()
            .filter(|commit| {
                resolved.authorized_target_commits.contains(&commit.id())
                    && admitted.contains(&commit.id())
            })
            .cloned()
            .collect();
        commits.sort_unstable_by_key(CollectionCommit::id);
        let revision = collection_revision(resolved.definition.id(), allowed_signers, &commits);

        Ok(CollectionView {
            facts,
            reader: self.reader.clone(),
            commits,
            revision,
        })
    }
}

/// Publish one self-contained content fragment and metadata fragment.
///
/// The signer must already exist. The publication is a signed root in
/// `simplearchive_union::definition(scope)` and inherits the core helper's
/// dependency-before-record durability ordering.
pub fn publish_fragment(
    pile_path: &Path,
    key_path: Option<&Path>,
    scope: Id,
    content: impl Into<Fragment>,
    metadata: impl Into<Fragment>,
) -> Result<CollectionCommit> {
    let mut writer = CollectionWriter::open(pile_path, key_path, scope)?;
    let result = writer.publish_fragment(content, metadata);
    writer.finish(result)
}

/// Materialize one scope under an explicit set of authorized signing keys.
///
/// Discovery admits only structurally canonical, strictly self-signed commit
/// records. This boundary further authorizes only commits for the exact target
/// collection whose embedded public key belongs to `allowed_signers`.
/// Every such commit must validate now: a missing definition/data blob or an
/// invalid element makes the view incomplete. Malformed discovery diagnostics,
/// unauthorized commits, and pending/rejected unsigned merge/derive noise do
/// not globally poison an otherwise complete target view.
///
/// This convenience opens a fresh [`CollectionSnapshot`] per call. Readers
/// requiring a coherent multi-scope view must open one snapshot themselves and
/// reuse [`CollectionSnapshot::materialize_scope`].
pub fn materialize_scope(
    pile_path: &Path,
    scope: Id,
    allowed_signers: &HashSet<VerifyingKey>,
) -> Result<CollectionView> {
    CollectionSnapshot::open(pile_path)?.materialize_scope(scope, allowed_signers)
}

/// Plan conservative roots for every union collection owned by authorized keys.
///
/// Signed collection commits are the durable declaration of desire: every
/// strictly valid commit signed by `allowed_signers` is admitted. Each admitted
/// COMMIT roots its collection definition, canonical record, data, metadata,
/// and resident attachment closure. Unsigned MERGE and DERIVE equations are
/// reproducible caches and root nothing. This avoids a separate mutable
/// retained-scope registry while covering all of one owner's collections in a
/// shared pile, not merely the scope a caller happens to be reading now.
///
/// The returned roots are still a pure result for this observed pile snapshot.
/// A future rewrite must rediscover and replan; this helper persists no policy.
pub fn plan_authorized_union_retention(
    pile_path: &Path,
    allowed_signers: &HashSet<VerifyingKey>,
) -> Result<RetentionRoots> {
    let mut pile = open_pile_strict(pile_path)?;
    let result = (|| {
        let reader = pile.reader().context("snapshot pile for retention plan")?;
        let records =
            discover_collection_records(&reader).context("discover collection records")?;
        let allowed_key_bytes: HashSet<[u8; 32]> =
            allowed_signers.iter().map(VerifyingKey::to_bytes).collect();
        let authorized_commits: BTreeSet<Id> = records
            .commits()
            .iter()
            .filter(|commit| allowed_key_bytes.contains(&commit.public_key().raw))
            .map(CollectionCommit::id)
            .collect();
        let resolution: CollectionResolution<String> =
            resolve_collection_semantics(&records, &authorized_commits, |request| {
                validate_retention_request(&reader, &authorized_commits, request)
            })
            .map_err(|error| anyhow!("resolve collection semantics: {error}"))?;
        require_authorized_commits(&resolution, &authorized_commits)?;
        plan_collection_retention(&records, &resolution, &reader)
            .context("plan strong collection retention")
    })();
    finish_pile(pile, result)
}

/// Materialize one exact-name legacy repository branch without constructing a
/// signer or mutating the pile.
///
/// A missing branch returns `None`; a present empty branch returns an empty
/// [`LegacyBranchView`]. Duplicate names are rejected. Present branch heads,
/// authored commits, and contentless merge nodes are verified before their
/// content facts are returned. Schema-typed attachment reads remain the
/// caller's responsibility through the snapshot-owned `reader`.
pub fn materialize_named_legacy_branch(
    pile_path: &Path,
    legacy_branch_name: &str,
) -> Result<Option<LegacyBranchView>> {
    let mut pile = open_pile_strict(pile_path)?;
    let snapshot = named_legacy_branch_snapshot(&mut pile, legacy_branch_name, None);
    let Some((branch_id, pin_metadata, reader)) = finish_pile(pile, snapshot)? else {
        return Ok(None);
    };

    let branch_facts: TribleSet = reader
        .get(pin_metadata)
        .with_context(|| format!("read snapshotted legacy {legacy_branch_name} branch metadata"))?;
    let branch_entity = repo::branch::branch_entity(&branch_facts, branch_id)
        .map_err(|error| anyhow!("resolve legacy branch entity: {error:?}"))?;
    let head = one_legacy_commit_value(&branch_facts, branch_entity, &repo::head, "branch head")?;
    if let Some(head) = head {
        let head_blob: Blob<SimpleArchive> = reader
            .get(head)
            .with_context(|| format!("read legacy {legacy_branch_name} branch head commit"))?;
        repo::branch::verify(branch_id, head_blob, branch_facts)
            .map_err(|_| anyhow!("legacy {legacy_branch_name} branch-head signature is invalid"))?;
    }

    let mut facts = TribleSet::new();
    let sources = match head {
        Some(head) => legacy_commits_topological(&reader, head)?,
        None => Vec::new(),
    };
    for source in sources {
        let commit_facts = load_legacy_commit_metadata(&reader, source)?;
        let subject = legacy_commit_subject(&commit_facts, source)?;
        let Some(content_handle) =
            one_legacy_commit_value(&commit_facts, subject, &repo::content, "content")?
        else {
            validate_contentless_legacy_merge(&commit_facts, subject, source)?;
            continue;
        };
        let content_blob: Blob<SimpleArchive> = reader.get(content_handle).with_context(|| {
            format!(
                "read legacy {legacy_branch_name} content {}",
                hex::encode_upper(content_handle.raw)
            )
        })?;
        repo::commit::verify(content_blob, commit_facts).map_err(|_| {
            anyhow!(
                "legacy authored commit {} has an invalid content signature",
                hex::encode_upper(source.raw)
            )
        })?;
        let content_facts: TribleSet = reader.get(content_handle).with_context(|| {
            format!(
                "decode legacy {legacy_branch_name} content {}",
                hex::encode_upper(content_handle.raw)
            )
        })?;
        facts += content_facts;
    }

    Ok(Some(LegacyBranchView {
        facts,
        reader,
        revision: LegacyBranchRevision(pin_metadata.raw),
    }))
}

/// Outcome of publishing one named legacy repository branch into a union scope.
///
/// `commits` is in deterministic topological order and maps each authored
/// legacy commit to the id of its independently signed collection COMMIT.
/// Contentless canonical merge nodes are counted but deliberately omitted.
#[derive(Debug)]
pub struct LegacyMigrationReport {
    pub branch_id: Id,
    pub head: Option<CommitHandle>,
    pub commits: Vec<(CommitHandle, Id)>,
    pub skipped_merges: usize,
    pub facts: usize,
    pub retention_direct: usize,
    pub retention_recursive: usize,
}

/// Publish one named legacy `Repository` branch into a `SimpleArchive`-union
/// collection and verify the exact resulting materialization.
///
/// The durable target signer is loaded before the pile is touched. The entire
/// legacy DAG, every authored signature, every commit message, all
/// caller-known direct payloads, and the complete resulting materialized union
/// are preflighted before the first collection append. `validate_payloads` is
/// called for both authored content facts and attached semantic-metadata facts
/// because conservative resident-closure traversal cannot prove that a
/// directly named nonresident child is absent. `validate_materialized` is a
/// distinct callback because individual legacy commits are deltas and need not
/// satisfy invariants which only make sense over the complete union.
///
/// `explicit_legacy_branch` only disambiguates the input pin. It never selects
/// an output branch; publication always targets `target_scope`.
///
/// Empty named branches are valid zero-COMMIT migrations. Callers must keep
/// both the legacy branch and collection-native writers for `target_scope`
/// quiescent during the operation. The legacy pin is checked before and after
/// publication and is never updated or removed. Strong retention is verified
/// and reported but is not persisted as recurring policy.
pub fn migrate_legacy_simplearchive_branch(
    pile_path: &Path,
    key_path: Option<&Path>,
    target_scope: Id,
    legacy_branch_name: &str,
    explicit_legacy_branch: Option<Id>,
    validate_payloads: impl Fn(&PileReader, &TribleSet) -> Result<()>,
    validate_materialized: impl Fn(&PileReader, &TribleSet) -> Result<()>,
) -> Result<LegacyMigrationReport> {
    // A missing durable signer must fail before even opening the pile.
    let signer = load_signer(pile_path, key_path)?;
    let allowed = HashSet::from([signer.verifying_key()]);
    let plan = build_legacy_migration_plan(
        pile_path,
        &signer,
        target_scope,
        legacy_branch_name,
        explicit_legacy_branch,
        &validate_payloads,
    )?;

    let existing = materialize_scope(pile_path, target_scope, &allowed)?;
    let mut expected = existing.facts;
    expected += plan.facts.clone();
    validate_materialized(&existing.reader, &expected)
        .context("preflight materialized target union")?;

    // Validate every collection already owned by this signer before adding a
    // byte, not only the target scope observed above.
    plan_authorized_union_retention(pile_path, &allowed)
        .context("preflight existing authorized collection retention")?;

    let mut pile = open_pile_strict(pile_path)?;
    let result = (|| {
        let current = pile.head(plan.branch_id).with_context(|| {
            format!("recheck legacy {legacy_branch_name} pin before publication")
        })?;
        if current != Some(plan.pin_metadata) {
            bail!(
                "legacy {legacy_branch_name} pin changed after snapshot; no collection commit was published"
            );
        }

        let definition = simplearchive_union::definition(target_scope);
        let mut published = Vec::with_capacity(plan.commits.len());
        for migration in &plan.commits {
            let commit = publish_fragment_commit(
                &mut pile,
                &definition,
                migration.content.clone(),
                migration.metadata.clone(),
                &signer,
            )
            .with_context(|| format!("publish migrated {legacy_branch_name} collection commit"))?;
            if commit != migration.target {
                bail!("published migration commit differs from its preflight identity");
            }
            commit.verify_strict().with_context(|| {
                format!("verify migrated {legacy_branch_name} collection signature")
            })?;
            published.push((migration.source, commit));
        }
        Ok(published)
    })();
    let published = finish_pile(pile, result)?;

    let view = materialize_scope(pile_path, target_scope, &allowed)?;
    if view.facts != expected {
        bail!(
            "migrated {legacy_branch_name} collection does not equal the prior collection union legacy facts"
        );
    }
    verify_resident_collection_closure(&view, published.iter().map(|(_, commit)| commit.clone()))?;

    let retention = plan_authorized_union_retention(pile_path, &allowed)?;
    let retention_direct = retention.direct().len();
    let retention_recursive = retention.recursive().len();
    if !confirm_legacy_pin(
        pile_path,
        plan.branch_id,
        plan.pin_metadata,
        legacy_branch_name,
    )? {
        bail!(
            "legacy {legacy_branch_name} pin advanced during migration; collection commits may already have been appended. Stop every legacy writer, then rerun to migrate the new prefix; deterministic replay will reuse matching records"
        );
    }

    Ok(LegacyMigrationReport {
        branch_id: plan.branch_id,
        head: plan.head,
        commits: published
            .into_iter()
            .map(|(source, target)| (source, target.id()))
            .collect(),
        skipped_merges: plan.skipped_merges,
        facts: plan.facts.len() as usize,
        retention_direct,
        retention_recursive,
    })
}

#[derive(Debug)]
struct PlannedLegacyCommit {
    source: CommitHandle,
    target: CollectionCommit,
    content: Fragment,
    metadata: Fragment,
}

#[derive(Debug)]
struct LegacyMigrationPlan {
    branch_id: Id,
    pin_metadata: Inline<Handle<SimpleArchive>>,
    head: Option<CommitHandle>,
    commits: Vec<PlannedLegacyCommit>,
    skipped_merges: usize,
    facts: TribleSet,
}

fn one_legacy_commit_value<V: InlineEncoding>(
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
        bail!("legacy commit has repeated {field}");
    }
    Ok(first)
}

fn legacy_commit_subject(facts: &TribleSet, handle: CommitHandle) -> Result<Id> {
    let entities: BTreeSet<Id> = facts.iter().map(|fact| *fact.e()).collect();
    if entities.len() != 1 {
        bail!(
            "legacy commit {} must contain exactly one metadata entity, found {}",
            hex::encode_upper(handle.raw),
            entities.len()
        );
    }
    Ok(*entities.iter().next().expect("one entity"))
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

fn load_legacy_commit_metadata(reader: &PileReader, handle: CommitHandle) -> Result<TribleSet> {
    reader
        .get(handle)
        .with_context(|| format!("read legacy commit {}", hex::encode_upper(handle.raw)))
}

fn legacy_commits_topological(
    reader: &PileReader,
    head: CommitHandle,
) -> Result<Vec<CommitHandle>> {
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
                "cycle in legacy commit ancestry at {}",
                hex::encode_upper(commit.raw)
            );
        }

        let facts = load_legacy_commit_metadata(reader, commit)?;
        let subject = legacy_commit_subject(&facts, commit)?;
        let parents = legacy_parents(&facts, subject);
        stack.push((commit, true));
        for parent in parents.into_iter().rev() {
            if active.contains(&parent) {
                bail!(
                    "cycle in legacy commit ancestry at {}",
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

/// Hydrate only the transitive closure which is already resident.
///
/// Direct schema-known handles are checked by the mandatory caller validator;
/// without their types this conservative traversal cannot prove absence.
fn hydrate_resident_closure(
    reader: &PileReader,
    roots: impl IntoIterator<Item = Inline<Handle<UnknownBlob>>>,
) -> Result<MemoryBlobStore> {
    let mut blobs = MemoryBlobStore::new();
    for handle in reachable(reader, roots) {
        let blob: Blob<UnknownBlob> = reader.get(handle).with_context(|| {
            format!(
                "load reachable legacy attachment {}",
                hex::encode_upper(handle.raw)
            )
        })?;
        blobs.insert(blob);
    }
    Ok(blobs)
}

fn legacy_content_fragment<V>(
    reader: &PileReader,
    content: Inline<Handle<SimpleArchive>>,
    source: CommitHandle,
    legacy_branch_name: &str,
    validate_payloads: &V,
) -> Result<(Blob<SimpleArchive>, Fragment)>
where
    V: Fn(&PileReader, &TribleSet) -> Result<()> + ?Sized,
{
    let archive: Blob<SimpleArchive> = reader
        .get(content)
        .with_context(|| format!("read legacy content {}", hex::encode_upper(content.raw)))?;
    let facts: TribleSet = reader
        .get(content)
        .with_context(|| format!("decode legacy content {}", hex::encode_upper(content.raw)))?;
    validate_payloads(reader, &facts).with_context(|| {
        format!(
            "validate legacy {legacy_branch_name} content payloads in commit {}",
            hex::encode_upper(source.raw)
        )
    })?;
    let blobs = hydrate_resident_closure(reader, [content.transmute()])?;
    Ok((archive, Fragment::from_facts_and_blobs(facts, blobs)))
}

fn legacy_metadata_fragment<V>(
    reader: &PileReader,
    facts: &TribleSet,
    subject: Id,
    source: CommitHandle,
    legacy_branch_name: &str,
    validate_payloads: &V,
) -> Result<Fragment>
where
    V: Fn(&PileReader, &TribleSet) -> Result<()> + ?Sized,
{
    let attached = one_legacy_commit_value(facts, subject, &repo::metadata, "metadata")?;
    let message = one_legacy_commit_value(facts, subject, &repo::message, "message")?;
    let created = one_legacy_commit_value(facts, subject, &metadata::created_at, "created_at")?;

    let (mut projected_facts, mut projected_blobs) = if let Some(handle) = attached {
        let attached_facts: TribleSet = reader.get(handle).with_context(|| {
            format!(
                "read attached legacy metadata {}",
                hex::encode_upper(handle.raw)
            )
        })?;
        validate_payloads(reader, &attached_facts).with_context(|| {
            format!(
                "validate attached legacy {legacy_branch_name} semantic-metadata payloads in commit {}",
                hex::encode_upper(source.raw)
            )
        })?;
        let blobs = hydrate_resident_closure(reader, [handle.transmute()])?;
        (attached_facts, blobs)
    } else {
        (TribleSet::new(), MemoryBlobStore::new())
    };

    if let Some(handle) = message {
        let _: View<str> = reader.get(handle).with_context(|| {
            format!(
                "strictly read legacy commit message {}",
                hex::encode_upper(handle.raw)
            )
        })?;
        projected_blobs.union(hydrate_resident_closure(reader, [handle.transmute()])?);
    }

    let projection = match (created, message) {
        (Some(created), Some(message)) => entity! {
            metadata::created_at: created,
            metadata::description: message,
        },
        (Some(created), None) => entity! { metadata::created_at: created },
        (None, Some(message)) => entity! { metadata::description: message },
        (None, None) => Fragment::empty(),
    };
    let (projection_facts, projection_blobs) = projection.into_facts_and_blobs();
    projected_facts += projection_facts;
    projected_blobs.union(projection_blobs);
    Ok(Fragment::from_facts_and_blobs(
        projected_facts,
        projected_blobs,
    ))
}

fn validate_contentless_legacy_merge(
    facts: &TribleSet,
    subject: Id,
    source: CommitHandle,
) -> Result<()> {
    let parents = legacy_parents(facts, subject);
    let contains_only_parent_edges = facts
        .iter()
        .all(|fact| fact.e() == &subject && fact.a() == &repo::parent.id());
    let canonical_subject = entity! { repo::parent*: parents.clone() }.root();
    if parents.len() < 2 || !contains_only_parent_edges || canonical_subject != Some(subject) {
        bail!(
            "legacy contentless commit {} is not a canonical merge",
            hex::encode_upper(source.raw)
        );
    }
    Ok(())
}

fn named_legacy_branch_snapshot(
    pile: &mut Pile,
    legacy_branch_name: &str,
    explicit: Option<Id>,
) -> Result<Option<(Id, Inline<Handle<SimpleArchive>>, PileReader)>> {
    let ids: Vec<Id> = if let Some(branch) = explicit {
        vec![branch]
    } else {
        pile.pins()
            .context("list legacy pins")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("read legacy pin id")?
    };
    let mut heads = Vec::new();
    for id in ids {
        if let Some(head) = pile.head(id).context("read legacy pin head")? {
            heads.push((id, head));
        } else if explicit == Some(id) {
            bail!("legacy branch {id:X} does not exist");
        }
    }

    let reader = pile
        .reader()
        .with_context(|| format!("snapshot legacy {legacy_branch_name} branch"))?;
    let wanted: Inline<Handle<LongString>> = legacy_branch_name.to_owned().to_blob().get_handle();
    let mut matches = Vec::new();
    for (branch_id, pin_metadata) in heads {
        let branch_facts: TribleSet = reader
            .get(pin_metadata)
            .with_context(|| format!("read legacy branch metadata for {branch_id:X}"))?;
        let Ok(entity) = repo::branch::branch_entity(&branch_facts, branch_id) else {
            continue;
        };
        let name = one_legacy_commit_value(&branch_facts, entity, &metadata::name, "branch name")?;
        if name == Some(wanted) {
            matches.push((branch_id, pin_metadata));
        }
    }
    match matches.len() {
        0 if explicit.is_some() => {
            bail!("the selected legacy pin is not the named {legacy_branch_name} branch")
        }
        0 => Ok(None),
        1 => Ok(Some((matches[0].0, matches[0].1, reader))),
        _ => bail!(
            "multiple legacy branches are named {legacy_branch_name}; rerun with --legacy-branch-id"
        ),
    }
}

fn build_legacy_migration_plan<V>(
    pile_path: &Path,
    signer: &SigningKey,
    target_scope: Id,
    legacy_branch_name: &str,
    explicit_branch: Option<Id>,
    validate_payloads: &V,
) -> Result<LegacyMigrationPlan>
where
    V: Fn(&PileReader, &TribleSet) -> Result<()> + ?Sized,
{
    let mut pile = open_pile_strict(pile_path)?;
    let snapshot = named_legacy_branch_snapshot(&mut pile, legacy_branch_name, explicit_branch);
    let Some((branch_id, pin_metadata, reader)) = finish_pile(pile, snapshot)? else {
        bail!("no legacy {legacy_branch_name} branch exists");
    };

    let branch_facts: TribleSet = reader
        .get(pin_metadata)
        .context("read snapshotted legacy branch metadata")?;
    let branch_entity = repo::branch::branch_entity(&branch_facts, branch_id)
        .map_err(|error| anyhow!("resolve legacy branch entity: {error:?}"))?;
    let head = one_legacy_commit_value(&branch_facts, branch_entity, &repo::head, "branch head")?;
    if let Some(head) = head {
        let head_blob: Blob<SimpleArchive> =
            reader.get(head).context("read legacy branch head commit")?;
        repo::branch::verify(branch_id, head_blob, branch_facts.clone())
            .map_err(|_| anyhow!("legacy {legacy_branch_name} branch-head signature is invalid"))?;
    }

    let definition = simplearchive_union::definition(target_scope);
    let mut commits = Vec::new();
    let mut targets = BTreeMap::new();
    let mut skipped_merges = 0;
    let mut union = TribleSet::new();

    let sources = match head {
        Some(head) => legacy_commits_topological(&reader, head)?,
        None => Vec::new(),
    };
    for source in sources {
        let commit_facts = load_legacy_commit_metadata(&reader, source)?;
        let subject = legacy_commit_subject(&commit_facts, source)?;
        let Some(content_handle) =
            one_legacy_commit_value(&commit_facts, subject, &repo::content, "content")?
        else {
            validate_contentless_legacy_merge(&commit_facts, subject, source)?;
            skipped_merges += 1;
            continue;
        };
        let (content_blob, content) = legacy_content_fragment(
            &reader,
            content_handle,
            source,
            legacy_branch_name,
            validate_payloads,
        )?;
        repo::commit::verify(content_blob, commit_facts.clone()).map_err(|_| {
            anyhow!(
                "legacy authored commit {} has an invalid content signature",
                hex::encode_upper(source.raw)
            )
        })?;
        let metadata = legacy_metadata_fragment(
            &reader,
            &commit_facts,
            subject,
            source,
            legacy_branch_name,
            validate_payloads,
        )?;
        let data_blob: Blob<SimpleArchive> = content.facts().clone().to_blob();
        let metadata_blob: Blob<SimpleArchive> = metadata.facts().clone().to_blob();
        let data: CollectionData = data_blob.get_handle().into();
        let metadata_handle = metadata_blob.get_handle();
        let target = CollectionCommit::sign(signer, definition.id(), data, metadata_handle);
        if let Some(previous) = targets.insert(target.id(), source) {
            bail!(
                "legacy commits {} and {} collapse to collection commit {}; refusing to invent identity",
                hex::encode_upper(previous.raw),
                hex::encode_upper(source.raw),
                target.id()
            );
        }
        union += content.facts().clone();
        commits.push(PlannedLegacyCommit {
            source,
            target,
            content,
            metadata,
        });
    }

    Ok(LegacyMigrationPlan {
        branch_id,
        pin_metadata,
        head,
        commits,
        skipped_merges,
        facts: union,
    })
}

fn confirm_legacy_pin(
    pile_path: &Path,
    branch_id: Id,
    expected: Inline<Handle<SimpleArchive>>,
    legacy_branch_name: &str,
) -> Result<bool> {
    let mut pile = open_pile_strict(pile_path)?;
    let current = pile
        .head(branch_id)
        .with_context(|| format!("recheck legacy {legacy_branch_name} pin"))?;
    finish_pile(pile, Ok(current == Some(expected)))
}

fn verify_resident_collection_closure(
    view: &CollectionView,
    commits: impl IntoIterator<Item = CollectionCommit>,
) -> Result<()> {
    let roots = commits.into_iter().flat_map(|commit| {
        [
            Handle::<UnknownBlob>::from_hash(commit.data()),
            commit.metadata().transmute(),
        ]
    });
    for handle in reachable(&view.reader, roots) {
        let _: Blob<UnknownBlob> = view.reader.get(handle).with_context(|| {
            format!(
                "verify migrated collection attachment {}",
                hex::encode_upper(handle.raw)
            )
        })?;
    }
    Ok(())
}

const COLLECTION_REVISION_CONTEXT: &str = "triblespace.faculties.collection-snapshot.revision.v1";

fn collection_revision(
    definition_id: Id,
    allowed_signers: &HashSet<VerifyingKey>,
    commits: &[CollectionCommit],
) -> CollectionRevision {
    let mut roster: Vec<[u8; 32]> = allowed_signers.iter().map(VerifyingKey::to_bytes).collect();
    roster.sort_unstable();
    roster.dedup();
    let mut commit_ids: Vec<Id> = commits.iter().map(CollectionCommit::id).collect();
    commit_ids.sort_unstable();
    commit_ids.dedup();
    let roster_len = u64::try_from(roster.len()).expect("authorization roster fits u64");
    let commit_count = u64::try_from(commit_ids.len()).expect("commit roster fits u64");

    let mut hasher = blake3::Hasher::new_derive_key(COLLECTION_REVISION_CONTEXT);
    hasher.update(b"definition-id\0");
    hasher.update(&definition_id.raw());
    hasher.update(b"authorization-roster\0");
    hasher.update(&roster_len.to_be_bytes());
    for public_key in roster {
        hasher.update(&public_key);
    }
    hasher.update(b"admitted-commit-ids\0");
    hasher.update(&commit_count.to_be_bytes());
    for commit_id in commit_ids {
        hasher.update(&commit_id.raw());
    }
    CollectionRevision(*hasher.finalize().as_bytes())
}

struct ResolvedScope {
    definition: CollectionDefinition,
    resolution: CollectionResolution<String>,
    authorized_target_commits: BTreeSet<Id>,
}

fn resolve_reader_scope(
    reader: &PileReader,
    records: &DiscoveredCollectionRecords,
    scope: Id,
    allowed_signers: &HashSet<VerifyingKey>,
) -> Result<ResolvedScope> {
    let definition = simplearchive_union::definition(scope);

    // Discovery already established strict self-signatures. Authorization is
    // a separate exact byte comparison against caller-supplied keys.
    let allowed_key_bytes: HashSet<[u8; 32]> =
        allowed_signers.iter().map(VerifyingKey::to_bytes).collect();
    let authorized_target_commits: BTreeSet<Id> = records
        .commits()
        .iter()
        .filter(|commit| commit.collection() == definition.id())
        .filter(|commit| allowed_key_bytes.contains(&commit.public_key().raw))
        .map(CollectionCommit::id)
        .collect();

    let resolution: CollectionResolution<String> =
        resolve_collection_semantics(records, &authorized_target_commits, |request| {
            validate_scope_request(reader, definition.id(), &authorized_target_commits, request)
        })
        .map_err(|error| anyhow!("resolve collection semantics: {error}"))?;

    // Only policy-eligible signed roots are mandatory. Unsigned equations may
    // be inert, incomplete, or malicious append noise; unless positively
    // validated and activated they are diagnostics, not a global stop switch.
    require_authorized_commits(&resolution, &authorized_target_commits)?;

    Ok(ResolvedScope {
        definition,
        resolution,
        authorized_target_commits,
    })
}

fn require_authorized_commits(
    resolution: &CollectionResolution<String>,
    authorized: &BTreeSet<Id>,
) -> Result<()> {
    for commit in authorized {
        if resolution.validation_pending().contains(commit) {
            return Err(anyhow!(
                "authorized collection commit {commit:X} is incomplete"
            ));
        }
        if let Some(reason) = resolution.rejected().get(commit) {
            return Err(anyhow!(
                "authorized collection commit {commit:X} was rejected: {reason}"
            ));
        }
    }
    Ok(())
}

fn validate_commit_request(
    reader: &PileReader,
    definition: &CollectionDefinition,
    claim: &CollectionCommit,
) -> Result<CollectionClaimValidation<String>> {
    let Some(data) = load_element(reader, claim.data())? else {
        return Ok(CollectionClaimValidation::Pending);
    };
    Ok(match validate_commit(definition, claim, &data) {
        Ok(()) => CollectionClaimValidation::Accepted,
        Err(error) => CollectionClaimValidation::Rejected(error.to_string()),
    })
}

fn validate_retention_request(
    reader: &PileReader,
    authorized_commits: &BTreeSet<Id>,
    request: CollectionValidationRequest<'_>,
) -> Result<CollectionClaimValidation<String>> {
    match request {
        CollectionValidationRequest::Commit { definition, claim }
            if authorized_commits.contains(&claim.id()) =>
        {
            validate_commit_request(reader, definition, claim)
        }
        CollectionValidationRequest::Commit { .. }
        | CollectionValidationRequest::Merge { .. }
        | CollectionValidationRequest::Derive { .. } => Ok(CollectionClaimValidation::Pending),
    }
}

fn validate_scope_request(
    reader: &PileReader,
    target_collection: Id,
    authorized_commits: &BTreeSet<Id>,
    request: CollectionValidationRequest<'_>,
) -> Result<CollectionClaimValidation<String>> {
    match request {
        CollectionValidationRequest::Commit { definition, claim } => {
            if !authorized_commits.contains(&claim.id()) {
                return Ok(CollectionClaimValidation::Pending);
            }
            validate_commit_request(reader, definition, claim)
        }
        CollectionValidationRequest::Merge { definition, claim } => {
            if claim.collection() != target_collection {
                return Ok(CollectionClaimValidation::Pending);
            }
            let (low, high) = claim.inputs();
            let Some(low) = load_element(reader, low)? else {
                return Ok(CollectionClaimValidation::Pending);
            };
            let Some(high) = load_element(reader, high)? else {
                return Ok(CollectionClaimValidation::Pending);
            };
            let Some(result) = load_element(reader, claim.result())? else {
                return Ok(CollectionClaimValidation::Pending);
            };
            Ok(
                match validate_merge(definition, claim, &low, &high, &result) {
                    Ok(()) => CollectionClaimValidation::Accepted,
                    Err(error) => CollectionClaimValidation::Rejected(error.to_string()),
                },
            )
        }
        // This first boundary has no cross-representation recipe oracle. The
        // generic resolver must not infer DERIVE validity, and claims for
        // unrelated collections must not trigger arbitrary blob reads.
        CollectionValidationRequest::Derive { .. } => Ok(CollectionClaimValidation::Pending),
    }
}

fn load_element(reader: &PileReader, data: CollectionData) -> Result<Option<Blob<SimpleArchive>>> {
    let handle = Handle::<SimpleArchive>::from_hash(data);
    let metadata = match reader.metadata(handle) {
        Ok(metadata) => metadata,
        Err(never) => match never {},
    };
    if metadata.is_none() {
        return Ok(None);
    }
    let blob = reader
        .get(handle)
        .with_context(|| format!("read collection element {}", hex::encode_upper(data.raw)))?;
    Ok(Some(blob))
}

fn read_error(path: &Path, error: ReadError) -> anyhow::Error {
    match error {
        ReadError::CorruptPile { valid_length } => anyhow!(
            "pile {} is corrupt at byte {valid_length}; refusing to auto-repair. \
             If and only if the tail is a genuinely torn write, repair it \
             explicitly with `trible pile amputate {}`",
            path.display(),
            path.display(),
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
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing pile after the operation failed too: {close_error}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;

    use anybytes::View;
    use triblespace::core::blob::encodings::longstring::LongString;
    use triblespace::core::collection::{empty_metadata_handle, CollectionMerge};
    use triblespace::core::inline::Inline;
    use triblespace::core::metadata;
    use triblespace::core::repo::BlobStorePut;
    use triblespace::prelude::*;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn fresh_pile(directory: &tempfile::TempDir) -> PathBuf {
        let path = directory.path().join("test.pile");
        File::create(&path).unwrap();
        path
    }

    fn allowed(key: &SigningKey) -> HashSet<VerifyingKey> {
        HashSet::from([key.verifying_key()])
    }

    fn description_fragment(kind: Id, text: &str) -> Fragment {
        let mut fragment = Fragment::empty();
        let description: Inline<Handle<LongString>> = fragment.put(text.to_owned());
        fragment += entity! {
            metadata::tag: &kind,
            metadata::description: description,
        };
        fragment
    }

    fn validate_description_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
        for fact in facts
            .iter()
            .filter(|fact| fact.a() == &metadata::description.id())
        {
            let handle = *fact.v::<Handle<LongString>>();
            let _: View<str> = reader.get(handle).with_context(|| {
                format!(
                    "strictly read test description payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
        Ok(())
    }

    fn accept_materialized_union(_: &PileReader, _: &TribleSet) -> Result<()> {
        Ok(())
    }

    struct LegacyFixture {
        pile: PathBuf,
        key: PathBuf,
        scope: Id,
        branch: Id,
        facts: TribleSet,
    }

    fn legacy_fixture(directory: &tempfile::TempDir) -> LegacyFixture {
        let pile = directory.path().join("legacy.pile");
        let key = directory.path().join("collection.key");
        File::create(&pile).unwrap();

        let first_signer = SigningKey::from_bytes(&[0x31; 32]);
        let storage = open_pile_strict(&pile).unwrap();
        let mut repository = Repository::new(storage, first_signer, Fragment::empty()).unwrap();
        let branch = *repository.create_branch("legacy-test", None).unwrap();

        let first = description_fragment(id(20), "first content payload");
        let semantic = description_fragment(id(21), "attached semantic payload");
        let mut first_workspace = repository.pull(branch).unwrap();
        first_workspace.commit_with_metadata(first.clone(), semantic, "first legacy message");
        repository.push(&mut first_workspace).unwrap();

        // A real fork gives the migration one canonical contentless merge to
        // validate and omit while retaining both authored leaves.
        let mut left = repository.pull(branch).unwrap();
        let mut right = repository.pull(branch).unwrap();
        let left_content = description_fragment(id(22), "left content payload");
        let right_content = description_fragment(id(23), "right content payload");
        left.commit(left_content.clone(), "left legacy message");
        right.commit(right_content.clone(), "right legacy message");
        repository.push(&mut left).unwrap();
        repository.push(&mut right).unwrap();
        repository.close().unwrap();

        // Legacy faculties used ephemeral per-process identities. The final
        // authored node therefore deliberately has a different valid signer.
        let storage = open_pile_strict(&pile).unwrap();
        let mut repository = Repository::new(
            storage,
            SigningKey::from_bytes(&[0x32; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let last = description_fragment(id(24), "heterogeneous signer payload");
        let mut last_workspace = repository.pull(branch).unwrap();
        last_workspace.commit(last.clone(), "last legacy message");
        repository.push(&mut last_workspace).unwrap();
        repository.close().unwrap();

        initialize_signer(&pile, Some(&key)).unwrap();
        let mut facts = first.into_facts();
        facts += left_content.into_facts();
        facts += right_content.into_facts();
        facts += last.into_facts();
        LegacyFixture {
            pile,
            key,
            scope: id(30),
            branch,
            facts,
        }
    }

    fn pin_head(pile_path: &Path, branch: Id) -> Inline<Handle<SimpleArchive>> {
        let mut pile = open_pile_strict(pile_path).unwrap();
        let head = pile.head(branch).unwrap().unwrap();
        pile.close().unwrap();
        head
    }

    fn migrated_commits(fixture: &LegacyFixture) -> (PileReader, Vec<CollectionCommit>) {
        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let definition = simplearchive_union::definition(fixture.scope);
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        let reader = pile.reader().unwrap();
        pile.close().unwrap();
        let records = discover_collection_records(&reader).unwrap();
        let commits = records
            .commits()
            .iter()
            .filter(|commit| commit.collection() == definition.id())
            .filter(|commit| commit.public_key().raw == signer.verifying_key().to_bytes())
            .cloned()
            .collect();
        (reader, commits)
    }

    #[test]
    fn legacy_migration_is_exact_metadata_preserving_and_byte_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = legacy_fixture(&directory);
        let old_pin = pin_head(&fixture.pile, fixture.branch);

        let first = migrate_legacy_simplearchive_branch(
            &fixture.pile,
            Some(&fixture.key),
            fixture.scope,
            "legacy-test",
            None,
            validate_description_payloads,
            accept_materialized_union,
        )
        .unwrap();
        let length = std::fs::metadata(&fixture.pile).unwrap().len();
        let second = migrate_legacy_simplearchive_branch(
            &fixture.pile,
            Some(&fixture.key),
            fixture.scope,
            "legacy-test",
            Some(fixture.branch),
            validate_description_payloads,
            accept_materialized_union,
        )
        .unwrap();

        assert_eq!(first.branch_id, fixture.branch);
        assert!(first.head.is_some());
        assert_eq!(first.commits.len(), 4);
        assert_eq!(first.skipped_merges, 1);
        assert_eq!(first.commits, second.commits);
        assert_eq!(std::fs::metadata(&fixture.pile).unwrap().len(), length);
        assert_eq!(pin_head(&fixture.pile, fixture.branch), old_pin);

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let view = materialize_scope(&fixture.pile, fixture.scope, &allowed(&signer)).unwrap();
        assert_eq!(view.facts, fixture.facts);
        for handle in find!(
            (description: Inline<Handle<LongString>>),
            pattern!(&view.facts, [{ metadata::description: ?description }])
        )
        .map(|(handle,)| handle)
        {
            let _: View<str> = view.reader.get(handle).unwrap();
        }

        let (reader, commits) = migrated_commits(&fixture);
        assert_eq!(commits.len(), 4);
        let mut projected = TribleSet::new();
        for commit in commits {
            commit.verify_strict().unwrap();
            assert_eq!(commit.public_key().raw, signer.verifying_key().to_bytes());
            let facts: TribleSet = reader.get(commit.metadata()).unwrap();
            projected += facts;
        }
        let descriptions: BTreeSet<String> = find!(
            (description: Inline<Handle<LongString>>),
            pattern!(&projected, [{ metadata::description: ?description }])
        )
        .map(|(handle,)| reader.get::<View<str>, _>(handle).unwrap().to_string())
        .collect();
        for expected in [
            "first legacy message",
            "left legacy message",
            "right legacy message",
            "last legacy message",
            "attached semantic payload",
        ] {
            assert!(descriptions.contains(expected));
        }
        assert_eq!(
            find!(
                (created: Inline<_>),
                pattern!(&projected, [{ metadata::created_at: ?created }])
            )
            .count(),
            4
        );
    }

    #[test]
    fn empty_legacy_branch_is_a_zero_commit_noop() {
        let directory = tempfile::tempdir().unwrap();
        let pile = fresh_pile(&directory);
        let key = directory.path().join("collection.key");
        let storage = open_pile_strict(&pile).unwrap();
        let mut repository = Repository::new(
            storage,
            SigningKey::from_bytes(&[0x41; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let branch = *repository.create_branch("empty-test", None).unwrap();
        repository.close().unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        let old_pin = pin_head(&pile, branch);
        let length = std::fs::metadata(&pile).unwrap().len();

        let report = migrate_legacy_simplearchive_branch(
            &pile,
            Some(&key),
            id(31),
            "empty-test",
            Some(branch),
            validate_description_payloads,
            accept_materialized_union,
        )
        .unwrap();

        assert_eq!(report.branch_id, branch);
        assert!(report.head.is_none());
        assert!(report.commits.is_empty());
        assert_eq!(report.facts, 0);
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), length);
        assert_eq!(pin_head(&pile, branch), old_pin);
    }

    #[test]
    fn named_legacy_branch_view_is_read_only_and_keeps_attachments() {
        let directory = tempfile::tempdir().unwrap();
        let pile = fresh_pile(&directory);
        let storage = open_pile_strict(&pile).unwrap();
        let mut repository = Repository::new(
            storage,
            SigningKey::from_bytes(&[0x43; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let branch = *repository.create_branch("snapshot-test", None).unwrap();
        let content = description_fragment(id(42), "snapshot attachment");
        let expected = content.facts().clone();
        let mut workspace = repository.pull(branch).unwrap();
        workspace.commit(content, "snapshot commit");
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();
        let pin = pin_head(&pile, branch);
        let length = std::fs::metadata(&pile).unwrap().len();

        let view = materialize_named_legacy_branch(&pile, "snapshot-test")
            .unwrap()
            .unwrap();
        assert_eq!(view.facts, expected);
        assert_eq!(view.revision.as_bytes(), &pin.raw);
        let description = find!(
            (description: Inline<Handle<LongString>>),
            pattern!(&view.facts, [{ metadata::description: ?description }])
        )
        .next()
        .unwrap()
        .0;
        assert_eq!(
            &*view.reader.get::<View<str>, _>(description).unwrap(),
            "snapshot attachment"
        );
        assert!(materialize_named_legacy_branch(&pile, "missing-test")
            .unwrap()
            .is_none());
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), length);
    }

    #[test]
    fn explicit_legacy_branch_disambiguates_duplicate_names() {
        let directory = tempfile::tempdir().unwrap();
        let pile = fresh_pile(&directory);
        let key = directory.path().join("collection.key");
        let storage = open_pile_strict(&pile).unwrap();
        let mut repository = Repository::new(
            storage,
            SigningKey::from_bytes(&[0x44; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let first_branch = *repository.create_branch("duplicate-test", None).unwrap();
        let second_branch = *repository.create_branch("duplicate-test", None).unwrap();
        assert_ne!(first_branch, second_branch);

        let first = description_fragment(id(43), "unselected branch");
        let mut first_workspace = repository.pull(first_branch).unwrap();
        first_workspace.commit(first, "first duplicate branch");
        repository.push(&mut first_workspace).unwrap();

        let second = description_fragment(id(44), "selected branch");
        let expected = second.facts().clone();
        let mut second_workspace = repository.pull(second_branch).unwrap();
        second_workspace.commit(second, "second duplicate branch");
        repository.push(&mut second_workspace).unwrap();
        repository.close().unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        let length = std::fs::metadata(&pile).unwrap().len();

        let read_error = materialize_named_legacy_branch(&pile, "duplicate-test").unwrap_err();
        assert!(format!("{read_error:#}").contains("multiple legacy branches"));
        let migration_error = migrate_legacy_simplearchive_branch(
            &pile,
            Some(&key),
            id(33),
            "duplicate-test",
            None,
            validate_description_payloads,
            accept_materialized_union,
        )
        .unwrap_err();
        assert!(format!("{migration_error:#}").contains("multiple legacy branches"));
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), length);

        let report = migrate_legacy_simplearchive_branch(
            &pile,
            Some(&key),
            id(33),
            "duplicate-test",
            Some(second_branch),
            validate_description_payloads,
            accept_materialized_union,
        )
        .unwrap();
        assert_eq!(report.branch_id, second_branch);
        assert_eq!(report.commits.len(), 1);
        let signer = load_signer(&pile, Some(&key)).unwrap();
        let view = materialize_scope(&pile, id(33), &allowed(&signer)).unwrap();
        assert_eq!(view.facts, expected);
    }

    #[test]
    fn attached_semantic_payload_failure_precedes_publication() {
        let directory = tempfile::tempdir().unwrap();
        let pile = fresh_pile(&directory);
        let key = directory.path().join("collection.key");
        let storage = open_pile_strict(&pile).unwrap();
        let mut repository = Repository::new(
            storage,
            SigningKey::from_bytes(&[0x42; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let branch = *repository.create_branch("metadata-test", None).unwrap();
        let content = entity! { metadata::tag: &id(40) };
        let missing: Inline<Handle<LongString>> = Inline::new([0x91; 32]);
        let semantic = entity! { metadata::description: missing };
        let mut workspace = repository.pull(branch).unwrap();
        workspace.commit_with_metadata(content, semantic, "valid message");
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        let length = std::fs::metadata(&pile).unwrap().len();

        let error = migrate_legacy_simplearchive_branch(
            &pile,
            Some(&key),
            id(32),
            "metadata-test",
            None,
            validate_description_payloads,
            accept_materialized_union,
        )
        .unwrap_err();

        let message = format!("{error:#}");
        assert!(message.contains("semantic-metadata payloads"));
        assert!(message.contains("strictly read test description payload"));
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), length);
    }

    #[test]
    fn invalid_materialized_union_leaves_the_pile_byte_identical() {
        let directory = tempfile::tempdir().unwrap();
        let pile = fresh_pile(&directory);
        let key = directory.path().join("collection.key");
        let scope = id(36);
        let subject = id(37);
        let existing_kind = id(38);
        let legacy_kind = id(39);

        let storage = open_pile_strict(&pile).unwrap();
        let mut repository = Repository::new(
            storage,
            SigningKey::from_bytes(&[0x46; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let branch = *repository.create_branch("union-test", None).unwrap();
        let mut workspace = repository.pull(branch).unwrap();
        workspace.commit(
            entity! { ExclusiveId::force(subject) @ metadata::tag: &legacy_kind },
            "legacy conflicting kind",
        );
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();

        initialize_signer(&pile, Some(&key)).unwrap();
        publish_fragment(
            &pile,
            Some(&key),
            scope,
            entity! { ExclusiveId::force(subject) @ metadata::tag: &existing_kind },
            Fragment::empty(),
        )
        .unwrap();
        let before = std::fs::read(&pile).unwrap();

        let error = migrate_legacy_simplearchive_branch(
            &pile,
            Some(&key),
            scope,
            "union-test",
            Some(branch),
            |_, _| Ok(()),
            |_, facts| {
                let kinds: BTreeSet<Id> = find!(
                    kind: Id,
                    pattern!(facts, [{ subject @ metadata::tag: ?kind }])
                )
                .collect();
                if kinds.len() != 1 {
                    bail!("subject has conflicting kinds in materialized union");
                }
                Ok(())
            },
        )
        .unwrap_err();

        let message = format!("{error:#}");
        assert!(message.contains("preflight materialized target union"));
        assert!(message.contains("conflicting kinds"));
        assert_eq!(std::fs::read(&pile).unwrap(), before);
    }

    #[test]
    fn missing_legacy_commit_message_precedes_publication() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = legacy_fixture(&directory);
        let signer = SigningKey::from_bytes(&[0x32; 32]);
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        let old_pin = pile.head(fixture.branch).unwrap().unwrap();
        let reader = pile.reader().unwrap();
        let branch_facts: TribleSet = reader.get(old_pin).unwrap();
        let branch_entity = repo::branch::branch_entity(&branch_facts, fixture.branch).unwrap();
        let name =
            one_legacy_commit_value(&branch_facts, branch_entity, &metadata::name, "branch name")
                .unwrap()
                .unwrap();
        let old_head =
            one_legacy_commit_value(&branch_facts, branch_entity, &repo::head, "branch head")
                .unwrap()
                .unwrap();
        let content = entity! { metadata::tag: &id(41) }.into_facts().to_blob();
        pile.put::<SimpleArchive, _>(content.clone()).unwrap();
        let missing_message: Inline<Handle<LongString>> = Inline::new([0x92; 32]);
        let commit = repo::commit::commit_metadata(
            &signer,
            [old_head],
            Some(missing_message),
            Some(content),
            None,
        )
        .to_blob();
        pile.put::<SimpleArchive, _>(commit.clone()).unwrap();
        let branch_metadata =
            repo::branch::branch_metadata(&signer, fixture.branch, name, Some(commit)).to_blob();
        let bad_pin = pile.put::<SimpleArchive, _>(branch_metadata).unwrap();
        pile.update(fixture.branch, Some(old_pin), Some(bad_pin))
            .unwrap();
        pile.flush().unwrap();
        pile.close().unwrap();
        let length = std::fs::metadata(&fixture.pile).unwrap().len();

        let error = migrate_legacy_simplearchive_branch(
            &fixture.pile,
            Some(&fixture.key),
            fixture.scope,
            "legacy-test",
            None,
            validate_description_payloads,
            accept_materialized_union,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("strictly read legacy commit message"));
        assert_eq!(std::fs::metadata(&fixture.pile).unwrap().len(), length);
        assert!(migrated_commits(&fixture).1.is_empty());
    }

    #[test]
    fn migration_requires_the_durable_signer_before_touching_the_pile() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = legacy_fixture(&directory);
        let missing_key = directory.path().join("missing.key");
        let pin = pin_head(&fixture.pile, fixture.branch);
        let length = std::fs::metadata(&fixture.pile).unwrap().len();

        let error = migrate_legacy_simplearchive_branch(
            &fixture.pile,
            Some(&missing_key),
            fixture.scope,
            "legacy-test",
            None,
            validate_description_payloads,
            accept_materialized_union,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("load durable signing key"));
        assert!(!missing_key.exists());
        assert_eq!(std::fs::metadata(&fixture.pile).unwrap().len(), length);
        assert_eq!(pin_head(&fixture.pile, fixture.branch), pin);
        assert!(migrated_commits(&fixture).1.is_empty());
    }

    #[test]
    fn colliding_legacy_commit_identities_fail_before_publication() {
        let directory = tempfile::tempdir().unwrap();
        let pile = fresh_pile(&directory);
        let key = directory.path().join("collection.key");
        let legacy_signer = SigningKey::from_bytes(&[0x45; 32]);
        let storage = open_pile_strict(&pile).unwrap();
        let mut repository =
            Repository::new(storage, legacy_signer.clone(), Fragment::empty()).unwrap();
        let branch = *repository.create_branch("collision-test", None).unwrap();
        repository.close().unwrap();

        let mut pile_store = open_pile_strict(&pile).unwrap();
        let old_pin = pile_store.head(branch).unwrap().unwrap();
        let reader = pile_store.reader().unwrap();
        let branch_facts: TribleSet = reader.get(old_pin).unwrap();
        let branch_entity = repo::branch::branch_entity(&branch_facts, branch).unwrap();
        let name =
            one_legacy_commit_value(&branch_facts, branch_entity, &metadata::name, "branch name")
                .unwrap()
                .unwrap();

        let content: Blob<SimpleArchive> =
            entity! { metadata::tag: &id(45) }.into_facts().to_blob();
        pile_store.put::<SimpleArchive, _>(content.clone()).unwrap();
        let message_blob: Blob<LongString> = "same projected metadata".to_owned().to_blob();
        let message = pile_store.put::<LongString, _>(message_blob).unwrap();
        let first_facts = repo::commit::commit_metadata(
            &legacy_signer,
            [],
            Some(message),
            Some(content.clone()),
            None,
        );
        let first_blob: Blob<SimpleArchive> = first_facts.clone().to_blob();
        let first_subject = legacy_commit_subject(&first_facts, first_blob.get_handle()).unwrap();
        let created = one_legacy_commit_value(
            &first_facts,
            first_subject,
            &metadata::created_at,
            "created_at",
        )
        .unwrap()
        .unwrap();
        let content_handle =
            one_legacy_commit_value(&first_facts, first_subject, &repo::content, "content")
                .unwrap()
                .unwrap();
        let signed_by =
            one_legacy_commit_value(&first_facts, first_subject, &repo::signed_by, "signed_by")
                .unwrap()
                .unwrap();
        let signature_r = one_legacy_commit_value(
            &first_facts,
            first_subject,
            &repo::signature_r,
            "signature_r",
        )
        .unwrap()
        .unwrap();
        let signature_s = one_legacy_commit_value(
            &first_facts,
            first_subject,
            &repo::signature_s,
            "signature_s",
        )
        .unwrap()
        .unwrap();
        let first = pile_store.put::<SimpleArchive, _>(first_blob).unwrap();

        // The parent edge gives this authored commit a distinct canonical
        // legacy identity while every field projected into the collection
        // COMMIT remains byte-identical to the first commit.
        let second_facts = entity! {
            metadata::created_at: created,
            repo::content: content_handle,
            repo::signed_by: signed_by,
            repo::signature_r: signature_r,
            repo::signature_s: signature_s,
            repo::message: message,
            repo::parent: first,
        }
        .into_facts();
        assert!(repo::commit::verify(content.clone(), second_facts.clone()).is_ok());
        let second_blob: Blob<SimpleArchive> = second_facts.to_blob();
        let second = pile_store
            .put::<SimpleArchive, _>(second_blob.clone())
            .unwrap();
        assert_eq!(second, second_blob.get_handle());
        let branch_metadata =
            repo::branch::branch_metadata(&legacy_signer, branch, name, Some(second_blob))
                .to_blob();
        let new_pin = pile_store.put::<SimpleArchive, _>(branch_metadata).unwrap();
        pile_store
            .update(branch, Some(old_pin), Some(new_pin))
            .unwrap();
        pile_store.flush().unwrap();
        pile_store.close().unwrap();

        initialize_signer(&pile, Some(&key)).unwrap();
        let length = std::fs::metadata(&pile).unwrap().len();
        let error = migrate_legacy_simplearchive_branch(
            &pile,
            Some(&key),
            id(34),
            "collision-test",
            None,
            validate_description_payloads,
            accept_materialized_union,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("collapse to collection commit"));
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), length);
        assert_eq!(pin_head(&pile, branch), new_pin);
        let signer = load_signer(&pile, Some(&key)).unwrap();
        assert!(materialize_scope(&pile, id(34), &allowed(&signer))
            .unwrap()
            .facts
            .is_empty());
    }

    #[test]
    fn existing_retention_failure_precedes_migration_publication() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = legacy_fixture(&directory);
        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let unrelated = simplearchive_union::definition(id(35));
        let missing: CollectionData = Inline::new([0xA5; 32]);
        let incomplete =
            CollectionCommit::sign(&signer, unrelated.id(), missing, empty_metadata_handle());
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        pile.put::<SimpleArchive, _>(CollectionDefinition::to_blob(&unrelated))
            .unwrap();
        pile.put::<SimpleArchive, _>(CollectionCommit::to_blob(&incomplete))
            .unwrap();
        pile.flush().unwrap();
        pile.close().unwrap();
        let legacy_pin = pin_head(&fixture.pile, fixture.branch);
        let length = std::fs::metadata(&fixture.pile).unwrap().len();

        let error = migrate_legacy_simplearchive_branch(
            &fixture.pile,
            Some(&fixture.key),
            fixture.scope,
            "legacy-test",
            None,
            validate_description_payloads,
            accept_materialized_union,
        )
        .unwrap_err();

        let message = format!("{error:#}");
        assert!(message.contains("preflight existing authorized collection retention"));
        assert!(message.contains("authorized collection commit"));
        assert_eq!(std::fs::metadata(&fixture.pile).unwrap().len(), length);
        assert_eq!(pin_head(&fixture.pile, fixture.branch), legacy_pin);
        assert!(migrated_commits(&fixture).1.is_empty());
    }

    #[test]
    fn full_dag_preflight_rejects_a_late_noncanonical_merge_before_publication() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = legacy_fixture(&directory);
        let signer = SigningKey::from_bytes(&[0x32; 32]);
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        let old_pin = pile.head(fixture.branch).unwrap().unwrap();
        let reader = pile.reader().unwrap();
        let branch_facts: TribleSet = reader.get(old_pin).unwrap();
        let branch_entity = repo::branch::branch_entity(&branch_facts, fixture.branch).unwrap();
        let name =
            one_legacy_commit_value(&branch_facts, branch_entity, &metadata::name, "branch name")
                .unwrap()
                .unwrap();
        let old_head =
            one_legacy_commit_value(&branch_facts, branch_entity, &repo::head, "branch head")
                .unwrap()
                .unwrap();
        let bad_commit = entity! { repo::parent: old_head }.into_facts().to_blob();
        pile.put::<SimpleArchive, _>(bad_commit.clone()).unwrap();
        let bad_branch =
            repo::branch::branch_metadata(&signer, fixture.branch, name, Some(bad_commit))
                .to_blob();
        let bad_pin = pile.put::<SimpleArchive, _>(bad_branch).unwrap();
        pile.update(fixture.branch, Some(old_pin), Some(bad_pin))
            .unwrap();
        pile.flush().unwrap();
        pile.close().unwrap();
        let length = std::fs::metadata(&fixture.pile).unwrap().len();

        let error = migrate_legacy_simplearchive_branch(
            &fixture.pile,
            Some(&fixture.key),
            fixture.scope,
            "legacy-test",
            None,
            validate_description_payloads,
            accept_materialized_union,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("not a canonical merge"));
        assert_eq!(std::fs::metadata(&fixture.pile).unwrap().len(), length);
        assert_eq!(pin_head(&fixture.pile, fixture.branch), bad_pin);
        assert!(migrated_commits(&fixture).1.is_empty());
    }

    #[test]
    fn contentless_legacy_node_requires_canonical_parent_set_subject() {
        let first: CommitHandle = Inline::new([0x51; 32]);
        let second: CommitHandle = Inline::new([0x52; 32]);
        let source: CommitHandle = Inline::new([0x53; 32]);
        let canonical = entity! { repo::parent*: [first, second] };
        let subject = canonical.root().unwrap();
        let facts = canonical.into_facts();
        validate_contentless_legacy_merge(&facts, subject, source).unwrap();

        let forged = ExclusiveId::force(id(42));
        let mut forged_facts = entity! { &forged @ repo::parent: first }.into_facts();
        forged_facts += entity! { &forged @ repo::parent: second }.into_facts();
        assert!(validate_contentless_legacy_merge(&forged_facts, forged.id, source).is_err());

        let explicit = ExclusiveId::force(subject);
        let mut annotated = facts;
        annotated += entity! { &explicit @ metadata::tag: &id(43) }.into_facts();
        assert!(validate_contentless_legacy_merge(&annotated, subject, source).is_err());

        let one_parent = entity! { repo::parent: first };
        let one_subject = one_parent.root().unwrap();
        assert!(
            validate_contentless_legacy_merge(&one_parent.into_facts(), one_subject, source,)
                .is_err()
        );
    }

    #[test]
    fn attachments_roundtrip_and_reader_outlives_closed_pile() {
        let directory = tempfile::tempdir().unwrap();
        let pile = fresh_pile(&directory);
        let key_path = directory.path().join("writer.key");
        let signer = initialize_signer(&pile, Some(&key_path)).unwrap();
        let content = entity! { metadata::name: "reader survives close" };
        let entity = content.root().unwrap();

        publish_fragment(&pile, Some(&key_path), id(1), content, Fragment::empty()).unwrap();
        let view = materialize_scope(&pile, id(1), &allowed(&signer)).unwrap();

        let fact = view
            .facts
            .iter()
            .find(|fact| fact.e() == &entity && fact.a() == &metadata::name.id())
            .unwrap();
        let handle = *fact.v::<Handle<LongString>>();
        let text: View<str> = view.reader.get(handle).unwrap();
        assert_eq!(&*text, "reader survives close");
    }

    #[test]
    fn one_snapshot_materializes_two_scopes_with_independent_authority() {
        let directory = tempfile::tempdir().unwrap();
        let pile = fresh_pile(&directory);
        let first_path = directory.path().join("first.key");
        let second_path = directory.path().join("second.key");
        let first = initialize_signer(&pile, Some(&first_path)).unwrap();
        let second = initialize_signer(&pile, Some(&second_path)).unwrap();
        let first_scope = id(1);
        let second_scope = id(2);

        let first_author = entity! { metadata::tag: &id(20) };
        let second_author = entity! { metadata::tag: &id(21) };
        let other_scope = entity! { metadata::tag: &id(22) };
        let expected_first_only = first_author.facts().clone();
        let mut expected_union = expected_first_only.clone();
        expected_union += second_author.facts().clone();
        let expected_other = other_scope.facts().clone();
        let first_commit = publish_fragment(
            &pile,
            Some(&first_path),
            first_scope,
            first_author,
            Fragment::empty(),
        )
        .unwrap();
        let second_commit = publish_fragment(
            &pile,
            Some(&second_path),
            first_scope,
            second_author,
            Fragment::empty(),
        )
        .unwrap();
        let other_commit = publish_fragment(
            &pile,
            Some(&first_path),
            second_scope,
            other_scope,
            Fragment::empty(),
        )
        .unwrap();

        let snapshot = CollectionSnapshot::open(&pile).unwrap();
        let both = HashSet::from([first.verifying_key(), second.verifying_key()]);
        let union = snapshot.materialize_scope(first_scope, &both).unwrap();
        let first_only = snapshot
            .materialize_scope(first_scope, &allowed(&first))
            .unwrap();
        let other = snapshot
            .materialize_scope(second_scope, &allowed(&first))
            .unwrap();

        assert_eq!(union.facts, expected_union);
        assert_eq!(first_only.facts, expected_first_only);
        assert_eq!(other.facts, expected_other);
        let mut expected_ids = vec![first_commit.id(), second_commit.id()];
        expected_ids.sort_unstable();
        assert_eq!(
            union
                .commits
                .iter()
                .map(CollectionCommit::id)
                .collect::<Vec<_>>(),
            expected_ids
        );
        assert_eq!(first_only.commits, vec![first_commit]);
        assert_eq!(other.commits, vec![other_commit]);
        assert_ne!(union.revision, first_only.revision);
        assert_ne!(first_only.revision, other.revision);

        let mut reversed = union.commits.clone();
        reversed.reverse();
        assert_eq!(
            union.revision,
            collection_revision(
                simplearchive_union::definition(first_scope).id(),
                &both,
                &reversed,
            )
        );
    }

    #[test]
    fn revision_tracks_roster_and_same_facts_metadata_only_commits() {
        let directory = tempfile::tempdir().unwrap();
        let pile = fresh_pile(&directory);
        let first_path = directory.path().join("first.key");
        let second_path = directory.path().join("second.key");
        let first = initialize_signer(&pile, Some(&first_path)).unwrap();
        let second = initialize_signer(&pile, Some(&second_path)).unwrap();
        let scope = id(3);
        let kind = id(23);
        let content = entity! { metadata::tag: &kind };
        let expected = content.facts().clone();
        let first_commit = publish_fragment(
            &pile,
            Some(&first_path),
            scope,
            content,
            entity! { metadata::description: "first metadata" },
        )
        .unwrap();

        let old_snapshot = CollectionSnapshot::open(&pile).unwrap();
        let first_roster = allowed(&first);
        let expanded_roster = HashSet::from([first.verifying_key(), second.verifying_key()]);
        let old = old_snapshot
            .materialize_scope(scope, &first_roster)
            .unwrap();
        let roster_changed = old_snapshot
            .materialize_scope(scope, &expanded_roster)
            .unwrap();
        assert_eq!(old.facts, roster_changed.facts);
        assert_eq!(old.commits, roster_changed.commits);
        assert_ne!(old.revision, roster_changed.revision);

        let second_commit = publish_fragment(
            &pile,
            Some(&first_path),
            scope,
            entity! { metadata::tag: &kind },
            entity! { metadata::description: "second metadata" },
        )
        .unwrap();
        assert_ne!(first_commit.id(), second_commit.id());

        let old_again = old_snapshot
            .materialize_scope(scope, &first_roster)
            .unwrap();
        assert_eq!(old_again.facts, expected);
        assert_eq!(old_again.commits, vec![first_commit]);
        assert_eq!(old_again.revision, old.revision);

        let new_snapshot = CollectionSnapshot::open(&pile).unwrap();
        let new = new_snapshot
            .materialize_scope(scope, &first_roster)
            .unwrap();
        assert_eq!(new.facts, expected);
        assert_eq!(new.commits.len(), 2);
        assert_ne!(new.revision, old.revision);
    }

    #[test]
    fn revision_ignores_unauthorized_commits_and_unsigned_noise() {
        let directory = tempfile::tempdir().unwrap();
        let pile = fresh_pile(&directory);
        let first_path = directory.path().join("first.key");
        let second_path = directory.path().join("second.key");
        let first = initialize_signer(&pile, Some(&first_path)).unwrap();
        initialize_signer(&pile, Some(&second_path)).unwrap();
        let scope = id(4);
        let accepted = entity! { metadata::tag: &id(24) };
        let expected = accepted.facts().clone();
        publish_fragment(&pile, Some(&first_path), scope, accepted, Fragment::empty()).unwrap();
        let roster = allowed(&first);
        let before = CollectionSnapshot::open(&pile)
            .unwrap()
            .materialize_scope(scope, &roster)
            .unwrap();

        publish_fragment(
            &pile,
            Some(&second_path),
            scope,
            entity! { metadata::tag: &id(25) },
            Fragment::empty(),
        )
        .unwrap();
        let definition = simplearchive_union::definition(scope);
        let pending = CollectionMerge::new(
            definition.id(),
            Inline::new([0xA1; 32]),
            Inline::new([0xA2; 32]),
            Inline::new([0xA3; 32]),
        );
        let mut pile_store = open_pile_strict(&pile).unwrap();
        pile_store
            .put::<SimpleArchive, _>(CollectionMerge::to_blob(&pending))
            .unwrap();
        pile_store.flush().unwrap();
        pile_store.close().unwrap();

        let after = CollectionSnapshot::open(&pile)
            .unwrap()
            .materialize_scope(scope, &roster)
            .unwrap();
        assert_eq!(after.facts, expected);
        assert_eq!(after.commits, before.commits);
        assert_eq!(after.revision, before.revision);
    }

    #[test]
    fn collection_revision_v1_transcript_is_stable() {
        let first = SigningKey::from_bytes(&[0x51; 32]);
        let second = SigningKey::from_bytes(&[0x52; 32]);
        let definition_id = id(5);
        let first_commit = CollectionCommit::sign(
            &first,
            definition_id,
            Inline::new([0x61; 32]),
            Inline::new([0x71; 32]),
        );
        let second_commit = CollectionCommit::sign(
            &second,
            definition_id,
            Inline::new([0x62; 32]),
            Inline::new([0x72; 32]),
        );
        let roster = HashSet::from([second.verifying_key(), first.verifying_key()]);
        let revision = collection_revision(definition_id, &roster, &[second_commit, first_commit]);

        assert_eq!(
            hex::encode_upper(revision.as_bytes()),
            "7C701F2FC9FF707C1A8D384F4D4D1730AE03476F56147597FA8CC1C5AABE3947"
        );
    }

    #[test]
    fn writer_publishes_multiple_commits_before_explicit_close() {
        let directory = tempfile::tempdir().unwrap();
        let pile = fresh_pile(&directory);
        let key_path = directory.path().join("writer.key");
        let signer = initialize_signer(&pile, Some(&key_path)).unwrap();
        let first_kind = id(20);
        let second_kind = id(21);
        let first = entity! { metadata::tag: &first_kind };
        let second = entity! { metadata::tag: &second_kind };
        let expected = first.clone() + second.clone();

        let mut writer = CollectionWriter::open(&pile, Some(&key_path), id(1)).unwrap();
        writer.publish_fragment(first, Fragment::empty()).unwrap();
        writer.publish_fragment(second, Fragment::empty()).unwrap();
        writer.close().unwrap();

        let view = materialize_scope(&pile, id(1), &allowed(&signer)).unwrap();
        assert_eq!(view.facts, expected.into_facts());
    }

    #[test]
    fn writer_can_abandon_or_finalize_the_same_staged_fragment_explicitly() {
        let directory = tempfile::tempdir().unwrap();
        let pile = fresh_pile(&directory);
        let key_path = directory.path().join("writer.key");
        let signer = initialize_signer(&pile, Some(&key_path)).unwrap();
        let scope = id(1);
        let kind = id(20);
        let content = description_fragment(kind, "withheld until commit-last");
        let expected = content.facts().clone();

        let mut writer = CollectionWriter::open(&pile, Some(&key_path), scope).unwrap();
        let staged = writer.stage_fragment(content, Fragment::empty()).unwrap();
        let withheld = staged.commit().clone();
        drop(staged);
        writer.close().unwrap();

        let abandoned = materialize_scope(&pile, scope, &allowed(&signer)).unwrap();
        assert!(abandoned.facts.is_empty());
        assert!(abandoned.commits.is_empty());
        assert!(plan_authorized_union_retention(&pile, &allowed(&signer))
            .unwrap()
            .is_empty());

        let mut writer = CollectionWriter::open(&pile, Some(&key_path), scope).unwrap();
        let staged = writer
            .stage_fragment(
                description_fragment(kind, "withheld until commit-last"),
                Fragment::empty(),
            )
            .unwrap();
        assert_eq!(staged.commit(), &withheld);
        let finalized = staged.finalize().unwrap();
        assert_eq!(finalized, withheld);
        writer.close().unwrap();

        let published = materialize_scope(&pile, scope, &allowed(&signer)).unwrap();
        assert_eq!(published.facts, expected);
        assert_eq!(published.commits, vec![withheld]);
    }

    #[test]
    fn unauthorized_same_scope_commit_is_ignored() {
        let directory = tempfile::tempdir().unwrap();
        let pile = fresh_pile(&directory);
        let first_path = directory.path().join("first.key");
        let second_path = directory.path().join("second.key");
        let first = initialize_signer(&pile, Some(&first_path)).unwrap();
        initialize_signer(&pile, Some(&second_path)).unwrap();

        let accepted_kind = id(20);
        let ignored_kind = id(21);
        let accepted = entity! { metadata::tag: &accepted_kind };
        let ignored = entity! { metadata::tag: &ignored_kind };
        let expected = accepted.facts().clone();
        publish_fragment(&pile, Some(&first_path), id(1), accepted, Fragment::empty()).unwrap();
        publish_fragment(&pile, Some(&second_path), id(1), ignored, Fragment::empty()).unwrap();

        let view = materialize_scope(&pile, id(1), &allowed(&first)).unwrap();
        assert_eq!(view.facts, expected);
    }

    #[test]
    fn missing_authorized_target_data_is_hard_incomplete() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = fresh_pile(&directory);
        let key_path = directory.path().join("writer.key");
        let signer = initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let definition = simplearchive_union::definition(id(1));
        let missing: CollectionData = Inline::new([7; 32]);
        let commit =
            CollectionCommit::sign(&signer, definition.id(), missing, empty_metadata_handle());

        let mut pile = open_pile_strict(&pile_path).unwrap();
        pile.put::<SimpleArchive, _>(
            triblespace::core::collection::CollectionDefinition::to_blob(&definition),
        )
        .unwrap();
        pile.put::<SimpleArchive, _>(CollectionCommit::to_blob(&commit))
            .unwrap();
        pile.flush().unwrap();
        pile.close().unwrap();

        let snapshot = CollectionSnapshot::open(&pile_path).unwrap();
        let error = snapshot
            .materialize_scope(id(1), &allowed(&signer))
            .unwrap_err();
        assert!(format!("{error:#}").contains("authorized collection commit"));
        assert!(format!("{error:#}").contains("incomplete"));
        let convenience_error =
            materialize_scope(&pile_path, id(1), &allowed(&signer)).unwrap_err();
        assert!(format!("{convenience_error:#}").contains("incomplete"));
    }

    #[test]
    fn signer_wide_retention_covers_every_authorized_collection() {
        let directory = tempfile::tempdir().unwrap();
        let pile = fresh_pile(&directory);
        let first_path = directory.path().join("first.key");
        let second_path = directory.path().join("second.key");
        let first = initialize_signer(&pile, Some(&first_path)).unwrap();
        initialize_signer(&pile, Some(&second_path)).unwrap();

        let one = publish_fragment(
            &pile,
            Some(&first_path),
            id(1),
            entity! { metadata::tag: &id(20) },
            Fragment::empty(),
        )
        .unwrap();
        let two = publish_fragment(
            &pile,
            Some(&first_path),
            id(2),
            entity! { metadata::tag: &id(21) },
            Fragment::empty(),
        )
        .unwrap();
        let other = publish_fragment(
            &pile,
            Some(&second_path),
            id(3),
            entity! { metadata::tag: &id(22) },
            Fragment::empty(),
        )
        .unwrap();

        let roots = plan_authorized_union_retention(&pile, &allowed(&first)).unwrap();
        let direct: BTreeSet<_> = roots.direct().map(|handle| handle.raw).collect();
        let recursive: BTreeSet<_> = roots.recursive().map(|handle| handle.raw).collect();
        for commit in [&one, &two] {
            assert!(direct.contains(&CollectionCommit::to_blob(commit).get_handle().raw));
            assert!(recursive.contains(&Handle::<SimpleArchive>::from_hash(commit.data()).raw));
            assert!(recursive.contains(&commit.metadata().raw));
        }
        assert!(!direct.contains(&CollectionCommit::to_blob(&other).get_handle().raw));
        assert!(!recursive.contains(&Handle::<SimpleArchive>::from_hash(other.data()).raw));
    }

    #[test]
    fn retention_validation_never_reads_merge_endpoints() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = fresh_pile(&directory);
        let unrelated = simplearchive_union::definition(id(2));
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let invalid = pile
            .put::<triblespace::core::blob::encodings::UnknownBlob, _>(
                anybytes::Bytes::from_source(b"not an archive".to_vec()),
            )
            .unwrap();
        let reader = pile.reader().unwrap();
        pile.close().unwrap();
        let endpoint: CollectionData = invalid.into();
        let claim = CollectionMerge::new(unrelated.id(), endpoint, endpoint, endpoint);

        let result = validate_retention_request(
            &reader,
            &BTreeSet::new(),
            CollectionValidationRequest::Merge {
                definition: &unrelated,
                claim: &claim,
            },
        )
        .unwrap();

        assert!(matches!(result, CollectionClaimValidation::Pending));
    }

    #[test]
    fn inert_unsigned_pending_merge_does_not_block() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = fresh_pile(&directory);
        let key_path = directory.path().join("writer.key");
        let signer = initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let kind = id(20);
        let content = entity! { metadata::tag: &kind };
        let expected = content.facts().clone();
        publish_fragment(
            &pile_path,
            Some(&key_path),
            id(1),
            content,
            Fragment::empty(),
        )
        .unwrap();

        let definition = simplearchive_union::definition(id(1));
        let pending = CollectionMerge::new(
            definition.id(),
            Inline::new([1; 32]),
            Inline::new([2; 32]),
            Inline::new([3; 32]),
        );
        let mut pile = open_pile_strict(&pile_path).unwrap();
        pile.put::<SimpleArchive, _>(CollectionMerge::to_blob(&pending))
            .unwrap();
        pile.flush().unwrap();
        pile.close().unwrap();

        let view = materialize_scope(&pile_path, id(1), &allowed(&signer)).unwrap();
        assert_eq!(view.facts, expected);
    }

    #[test]
    fn snapshot_reads_leave_the_pile_and_missing_key_untouched() {
        let directory = tempfile::tempdir().unwrap();
        let pile = fresh_pile(&directory);
        let missing_key = directory.path().join("missing.key");
        let length = std::fs::metadata(&pile).unwrap().len();
        let before: BTreeSet<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();

        let snapshot = CollectionSnapshot::open(&pile).unwrap();
        assert!(snapshot
            .materialize_scope(id(1), &HashSet::new())
            .unwrap()
            .facts
            .is_empty());
        assert!(snapshot
            .materialize_scope(id(2), &HashSet::new())
            .unwrap()
            .facts
            .is_empty());
        assert!(materialize_scope(&pile, id(1), &HashSet::new())
            .unwrap()
            .facts
            .is_empty());
        let after: BTreeSet<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(after, before);
        assert!(!missing_key.exists());
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), length);
    }

    #[test]
    fn publish_requires_an_existing_signer_before_touching_the_pile() {
        let directory = tempfile::tempdir().unwrap();
        let pile = fresh_pile(&directory);
        let missing_key = directory.path().join("missing.key");
        let content = entity! { metadata::tag: &id(20) };

        let error = publish_fragment(&pile, Some(&missing_key), id(1), content, Fragment::empty())
            .unwrap_err();

        assert!(format!("{error:#}").contains("load durable signing key"));
        assert!(!missing_key.exists());
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), 0);
    }

    #[test]
    fn corrupt_tail_is_reported_without_repairing_it() {
        let directory = tempfile::tempdir().unwrap();
        let pile = fresh_pile(&directory);
        let corrupt = b"this is not a pile record";
        std::fs::write(&pile, corrupt).unwrap();

        let error = materialize_scope(&pile, id(1), &HashSet::new()).unwrap_err();

        assert!(format!("{error:#}").contains("refusing to auto-repair"));
        assert_eq!(std::fs::read(&pile).unwrap(), corrupt);
    }
}
