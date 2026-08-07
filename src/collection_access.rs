//! Shared access to `SimpleArchive`-union collections in a pile.
//!
//! This is intentionally a composition boundary, not another repository
//! model. Callers supply an extrinsic scope and explicit signer authority;
//! the collection definition, signed commits, reproducible merge equations,
//! and physical cover remain the canonical TribleSpace objects.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};

use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::Blob;
use triblespace::core::collection::simplearchive_union::{
    self, publish_fragment_commit, validate_commit, validate_merge,
};
use triblespace::core::collection::{
    discover_collection_records, plan_collection_retention, resolve_collection_semantics,
    CollectionClaimValidation, CollectionCommit, CollectionData, CollectionDefinition,
    CollectionResolution, CollectionValidationRequest,
};
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::repo::pile::{Pile, PileReader, ReadError};
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta, RetentionRoots};
use triblespace::core::signing_key_file;
use triblespace::core::trible::{Fragment, TribleSet};

/// The minimum useful read view: queryable facts plus their attachment reader.
///
/// The reader owns an immutable pile snapshot. It remains usable after the
/// writable [`Pile`] used to create the view has been closed.
#[derive(Debug)]
pub struct CollectionView {
    pub facts: TribleSet,
    pub reader: PileReader,
}

/// An explicitly closed writer for repeated publications into one collection.
///
/// This is only an ownership seam around an open [`Pile`], one intrinsic
/// collection definition, and one durable signer. It does not introduce a
/// head, staging area, checkout, or mutable workspace. Each call to
/// [`Self::publish_fragment`] remains an independently signed, crash-ordered
/// collection commit.
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

    /// Publish one independent signed fragment without reopening the pile.
    pub fn publish_fragment(
        &mut self,
        content: impl Into<Fragment>,
        metadata: impl Into<Fragment>,
    ) -> Result<CollectionCommit> {
        let pile = self
            .pile
            .as_mut()
            .expect("collection writer is open until consumed by finish");
        publish_fragment_commit(pile, &self.definition, content, metadata, &self.signer)
            .context("publish collection fragment")
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
pub fn materialize_scope(
    pile_path: &Path,
    scope: Id,
    allowed_signers: &HashSet<VerifyingKey>,
) -> Result<CollectionView> {
    let mut pile = open_pile_strict(pile_path)?;
    let result = (|| {
        let reader = pile.reader().context("snapshot pile for collection read")?;
        let facts = materialize_reader_scope(&reader, scope, allowed_signers)?;
        Ok(CollectionView { facts, reader })
    })();
    finish_pile(pile, result)
}

fn materialize_reader_scope(
    reader: &PileReader,
    scope: Id,
    allowed_signers: &HashSet<VerifyingKey>,
) -> Result<TribleSet> {
    let resolved = resolve_reader_scope(reader, scope, allowed_signers)?;
    simplearchive_union::materialize(
        resolved.resolution.semantics(),
        &resolved.definition,
        reader,
    )
    .context("materialize collection physical cover")
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

struct ResolvedScope {
    definition: CollectionDefinition,
    resolution: CollectionResolution<String>,
}

fn resolve_reader_scope(
    reader: &PileReader,
    scope: Id,
    allowed_signers: &HashSet<VerifyingKey>,
) -> Result<ResolvedScope> {
    let definition = simplearchive_union::definition(scope);
    let records = discover_collection_records(reader).context("discover collection records")?;

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
        resolve_collection_semantics(&records, &authorized_target_commits, |request| {
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

        let error = materialize_scope(&pile_path, id(1), &allowed(&signer)).unwrap_err();
        assert!(format!("{error:#}").contains("authorized collection commit"));
        assert!(format!("{error:#}").contains("incomplete"));
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
    fn read_does_not_create_a_missing_signing_key() {
        let directory = tempfile::tempdir().unwrap();
        let pile = fresh_pile(&directory);
        let before: BTreeSet<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();

        let view = materialize_scope(&pile, id(1), &HashSet::new()).unwrap();
        assert!(view.facts.is_empty());
        let after: BTreeSet<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(after, before);
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
