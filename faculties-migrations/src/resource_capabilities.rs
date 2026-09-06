//! Additive transition from the READ/WRITE-policy epoch at core 35ec1817.
//!
//! Only the exact direct-policy predecessor descriptors for the standard
//! Faculties roots are selected. A name is never an authority bridge. New
//! descriptors carry generic resource-capability bindings; Secrets additionally
//! binds key delivery to its owner. Same-author COMMITs are re-signed over their
//! unchanged data and metadata handles, without acquiring either archive.
//!
//! Old descriptors, records, blobs, and domain entity ids remain untouched.
//! MERGE/DERIVE artifacts are left for ordinary current maintenance to rebuild.
//! AUTH signatures cover incompatible bytes and are never transformed here:
//! current grants must be issued separately by the relevant keys.

use std::collections::BTreeSet;
use std::path::Path;

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};

use faculties::storage::{load_signer, open_pile_strict};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::utf8string::UTF8String;
use triblespace::core::blob::{Blob, IntoBlob};
use triblespace::core::capability::policy::{
    admission_invoke_threshold, admission_policy_root, KIND_ADMISSION_POLICY_QUORUM,
};
use triblespace::core::collection::records::{
    collection_name, collection_representation, CollectionHandle, KIND_COLLECTION_DESCRIPTOR,
};
use triblespace::core::collection::{
    descriptor, read_capability, write_capability, AdmissionPolicy, CollectionCommit,
    CollectionRead, CollectionRecord, CollectionRecordSelector, CollectionStore,
    CollectionStoreExt,
};
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::genid::GenId;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::Inline;
use triblespace::core::metadata::{self, MetaDescribe};
use triblespace::core::repo::memoryrepo::MemoryRepo;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::{BlobStoreGet, SnapshotSource};
use triblespace::core::trible::{Fragment, TribleSet};
use triblespace::macros::{attributes, entity, find, pattern};

mod retired {
    use super::*;

    attributes! {
        // Published anchors from 2026-08-30, with their unchanged GenId encoding.
        "4108A59A03E8F8EC9DCDCC3C8597A292" as pub collection_read_policy: GenId;
        "06930EAD5B83C83A30B6061B53A2840B" as pub collection_write_policy: GenId;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootTransition {
    pub scope: Id,
    pub name: String,
    pub old: CollectionHandle,
    pub new: CollectionHandle,
    pub source_commits: usize,
    pub selected_commits: usize,
    pub target_commits: usize,
    pub missing_commits: usize,
    pub invalid_commits: usize,
    pub deferred_commits: usize,
    pub invalid_deferred_commits: usize,
    pub skipped_merges: usize,
    pub skipped_derives: usize,
}

/// A resident predecessor root outside this invocation's exact mapping.
/// This optional inventory is descriptive, never a publication precondition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnmappedRoot {
    pub collection: CollectionHandle,
    pub names: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceCapabilitiesPlan {
    pub authority: VerifyingKey,
    pub author: VerifyingKey,
    pub roots: Vec<RootTransition>,
    pub unmapped_roots: Vec<UnmappedRoot>,
    pub unreadable_descriptors: usize,
}

impl ResourceCapabilitiesPlan {
    pub fn source_commits(&self) -> usize {
        self.roots.iter().map(|root| root.source_commits).sum()
    }

    pub fn missing_commits(&self) -> usize {
        self.roots.iter().map(|root| root.missing_commits).sum()
    }

    pub fn selected_commits(&self) -> usize {
        self.roots.iter().map(|root| root.selected_commits).sum()
    }

    pub fn invalid_commits(&self) -> usize {
        self.roots.iter().map(|root| root.invalid_commits).sum()
    }

    pub fn deferred_commits(&self) -> usize {
        self.roots.iter().map(|root| root.deferred_commits).sum()
    }

    /// Coverage of this author only. Other authors need their own passes.
    pub fn settled(&self) -> bool {
        self.missing_commits() == 0 && self.invalid_commits() == 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceCapabilitiesReport {
    pub plan: ResourceCapabilitiesPlan,
    pub appended_commits: usize,
}

struct PreparedMigration {
    plan: ResourceCapabilitiesPlan,
    missing: BTreeSet<CollectionCommit>,
}

/// Exact direct policy emitted by core 35ec1817, before capability bindings.
fn predecessor_descriptor(name: &str, owner: VerifyingKey) -> Fragment {
    let policy = entity! {
        metadata::tag: KIND_ADMISSION_POLICY_QUORUM,
        admission_policy_root: owner,
        admission_invoke_threshold: 1_u32,
    };
    entity! {
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        collection_name: name.to_owned(),
        retired::collection_read_policy*: policy.clone(),
        retired::collection_write_policy*: policy,
        collection_representation*: <SimpleArchive as MetaDescribe>::describe(),
    }
}

fn successor<S: CollectionStoreExt>(
    store: &mut S,
    scope: Id,
    owner: VerifyingKey,
) -> Result<CollectionHandle> {
    let policy = faculties::collection_names::private_policy(owner);
    let policy = if scope == faculties::secrets::DEFAULT_SCOPE_ID {
        policy.with_capability(
            faculties::secrets::key_delivery_definition(),
            AdmissionPolicy::direct(owner),
        )
    } else {
        policy
    };
    store
        .collection(faculties::collection_names::require_name(scope), policy)
        .map(|collection| collection.handle())
        .map_err(|error| anyhow!("register resource-capability descriptor: {error}"))
}

fn prepare(
    snapshot: &PileSnapshot,
    signer: &SigningKey,
    owner: VerifyingKey,
    inventory: bool,
) -> Result<PreparedMigration> {
    AdmissionPolicy::quorum([owner], 1, None).context("validate explicit policy root")?;
    let author = signer.verifying_key();
    let mut scratch = MemoryRepo::default();
    let mut roots = Vec::new();
    let mut missing = BTreeSet::new();
    for (scope, name) in faculties::collection_names::table() {
        let old_blob: Blob<SimpleArchive> = predecessor_descriptor(name, owner)
            .facts()
            .clone()
            .to_blob();
        let old = old_blob.get_handle();
        let new = successor(&mut scratch, scope, owner)?;
        let mut root = RootTransition {
            scope,
            name: name.to_owned(),
            old,
            new,
            source_commits: 0,
            selected_commits: 0,
            target_commits: 0,
            missing_commits: 0,
            invalid_commits: 0,
            deferred_commits: 0,
            invalid_deferred_commits: 0,
            skipped_merges: 0,
            skipped_derives: 0,
        };
        // Pile's collection index selects this root only, not a materialized
        // catalog of every record in every collection.
        for record in snapshot
            .select_records(&BTreeSet::from([CollectionRecordSelector::Collection(old)]))
            .with_context(|| format!("select predecessor {name} records"))?
        {
            match record {
                CollectionRecord::Commit(commit) => {
                    root.source_commits += 1;
                    if commit.public_key().raw != author.to_bytes() {
                        root.deferred_commits += 1;
                        if commit.verify_strict().is_err() {
                            root.invalid_deferred_commits += 1;
                        }
                        continue;
                    }
                    root.selected_commits += 1;
                    if commit.verify_strict().is_err() {
                        root.invalid_commits += 1;
                        continue;
                    }
                    let commit =
                        CollectionCommit::sign(signer, new, commit.data(), commit.metadata());
                    let record = CollectionRecord::Commit(commit);
                    if snapshot
                        .record(record.fingerprint())
                        .context("look up exact successor COMMIT")?
                        != Some(record)
                        && missing.insert(commit)
                    {
                        root.missing_commits += 1;
                    }
                }
                CollectionRecord::Merge(_) => root.skipped_merges += 1,
                CollectionRecord::Derive(_) => root.skipped_derives += 1,
            }
        }
        root.target_commits = snapshot
            .select_records(&BTreeSet::from([CollectionRecordSelector::Collection(new)]))
            .with_context(|| format!("select successor {name} records"))?
            .iter()
            .filter(|record| matches!(record, CollectionRecord::Commit(_)))
            .count();
        roots.push(root);
    }
    roots.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    let mut plan = ResourceCapabilitiesPlan {
        authority: owner,
        author,
        roots,
        unmapped_roots: Vec::new(),
        unreadable_descriptors: 0,
    };
    if inventory {
        // Only remember which descriptor handles were visited. Query each
        // descriptor at the point of use; do not retain the source record set.
        let mut seen: BTreeSet<_> = plan.roots.iter().map(|root| root.old).collect();
        for record in snapshot
            .records()
            .context("inventory referenced descriptors")?
        {
            let CollectionRecord::Commit(commit) = record.context("read inventory record")? else {
                continue;
            };
            let collection = commit.collection();
            if !seen.insert(collection) {
                continue;
            }
            let Ok(facts) = snapshot.get::<TribleSet, SimpleArchive>(collection) else {
                plan.unreadable_descriptors += 1;
                continue;
            };
            // Current policy bindings can coexist with retired annotations.
            if descriptor::admission_policies(&facts, read_capability(), Some(SimpleArchive::id()))
                .next()
                .is_some()
                && descriptor::admission_policies(
                    &facts,
                    write_capability(),
                    Some(SimpleArchive::id()),
                )
                .next()
                .is_some()
            {
                continue;
            }
            let names: BTreeSet<_> = find!(
                name: Inline<Handle<UTF8String>>,
                pattern!(&facts, [{
                    metadata::tag: KIND_COLLECTION_DESCRIPTOR,
                    collection_name: ?name,
                    retired::collection_read_policy: _?read,
                    retired::collection_write_policy: _?write,
                }])
            )
            .map(|name| {
                snapshot
                    .get::<View<str>, UTF8String>(name)
                    .map(|name| name.to_string())
                    .unwrap_or_else(|_| format!("<absent name blake3:{}>", hex::encode(name.raw)))
            })
            .collect();
            if !names.is_empty() {
                plan.unmapped_roots.push(UnmappedRoot {
                    collection,
                    names: names.into_iter().collect(),
                });
            }
        }
        plan.unmapped_roots
            .sort_unstable_by_key(|root| root.collection);
    }
    Ok(PreparedMigration { plan, missing })
}

fn publish_open(
    pile: &mut Pile,
    signer: &SigningKey,
    authority: VerifyingKey,
    inventory: bool,
) -> Result<ResourceCapabilitiesReport> {
    let snapshot = pile
        .snapshot()
        .context("freeze resource-capabilities source")?;
    let prepared = prepare(&snapshot, signer, authority, false)?;
    drop(snapshot);
    if prepared.plan.invalid_commits() != 0 {
        bail!(
            "resource-capabilities selected author has {} invalid-signature predecessor COMMIT(s); no publication was attempted; inspect --dry-run --handles",
            prepared.plan.invalid_commits(),
        );
    }
    for root in &prepared.plan.roots {
        if root.selected_commits == 0 {
            continue;
        }
        let registered = successor(pile, root.scope, authority)?;
        if registered != root.new {
            bail!(
                "{} successor identity changed during publication",
                root.name
            );
        }
    }
    let appended_commits = prepared.missing.len();
    for commit in prepared.missing {
        pile.insert(CollectionRecord::Commit(commit))
            .context("append same-author resource-capabilities COMMIT")?;
    }
    let snapshot = pile
        .snapshot()
        .context("freeze resource-capabilities verification")?;
    let after = prepare(&snapshot, signer, authority, inventory)?;
    if !after.plan.settled() {
        bail!(
            "resource-capabilities selected-author verification found {} missing and {} invalid-signature COMMIT(s); old writers may have appended after planning; quiesce them and replay",
            after.plan.missing_commits(),
            after.plan.invalid_commits(),
        );
    }
    Ok(ResourceCapabilitiesReport {
        plan: after.plan,
        appended_commits,
    })
}

fn with_pile<T>(
    path: &Path,
    key: Option<&Path>,
    operation: impl FnOnce(&mut Pile, &SigningKey) -> Result<T>,
) -> Result<T> {
    let signer = load_signer(path, key).context("load resource-capabilities durable signer")?;
    let mut pile = open_pile_strict(path)?;
    let result = operation(&mut pile, &signer);
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context("close resource-capabilities pile")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close)) => {
            Err(error.context(format!("closing pile also failed: {close}")))
        }
    }
}

/// Observe one immutable pile prefix without registering descriptors or proofs.
pub fn plan_path(
    pile: &Path,
    key: Option<&Path>,
    authority: Option<VerifyingKey>,
    inventory: bool,
) -> Result<ResourceCapabilitiesPlan> {
    with_pile(pile, key, |pile, signer| {
        let snapshot = pile
            .snapshot()
            .context("freeze resource-capabilities plan")?;
        Ok(prepare(
            &snapshot,
            signer,
            authority.unwrap_or_else(|| signer.verifying_key()),
            inventory,
        )?
        .plan)
    })
}

/// Replan, append deterministic successors, then verify from a fresh snapshot.
/// Zero matching selected-author COMMITs is a no-op, including registration.
/// Unrelated history is never adopted, dropped, or a publication precondition.
pub fn publish_path(
    pile: &Path,
    key: Option<&Path>,
    authority: Option<VerifyingKey>,
    inventory: bool,
) -> Result<ResourceCapabilitiesReport> {
    with_pile(pile, key, |pile, signer| {
        publish_open(
            pile,
            signer,
            authority.unwrap_or_else(|| signer.verifying_key()),
            inventory,
        )
    })
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::path::PathBuf;

    use faculties::storage::initialize_signer;
    use triblespace::core::blob::encodings::UnknownBlob;
    use triblespace::core::collection::{CollectionDerive, CollectionMerge};
    use triblespace::core::id::fucid;
    use triblespace::core::repo::{BlobStorePut, CapabilityProofRead};

    use super::*;

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, SigningKey) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("test.pile");
        let key = directory.path().join("test.key");
        File::create(&path).unwrap();
        let signer = initialize_signer(&path, Some(&key)).unwrap();
        (directory, path, key, signer)
    }

    fn old_handle(name: &str, authority: VerifyingKey) -> CollectionHandle {
        let blob: Blob<SimpleArchive> = predecessor_descriptor(name, authority)
            .facts()
            .clone()
            .to_blob();
        blob.get_handle()
    }

    fn sparse_commit(
        signer: &SigningKey,
        collection: CollectionHandle,
        seed: u8,
    ) -> CollectionCommit {
        CollectionCommit::sign(
            signer,
            collection,
            Inline::new([seed; 32]),
            Inline::new([seed.wrapping_add(1); 32]),
        )
    }

    fn store_fragment(pile: &mut Pile, fragment: Fragment) -> CollectionHandle {
        let (_, facts, _, mut blobs) = fragment.into_parts();
        for (_, blob) in blobs.snapshot().unwrap() {
            pile.put::<UnknownBlob, _>(blob).unwrap();
        }
        pile.put::<SimpleArchive, _>(facts).unwrap()
    }

    #[test]
    fn predecessor_matches_live_core_35ec1817_descriptor_handles() {
        // Public identity and exact handles independently observed from the
        // pre-cutover Mac descriptors on 2026-09-06; never a secret seed.
        let bytes = hex::decode("C5C9F620F067CBB1169D60D02B7EA4EEE9656DAB082E040A00FEBC490021D802")
            .unwrap();
        let root = VerifyingKey::from_bytes(bytes.as_slice().try_into().unwrap()).unwrap();
        assert_eq!(
            hex::encode(old_handle("compass", root).raw),
            "776f93fbd4c4e89c868410ef3132c0ed63c00612596614bcf40bd8ae923baf5b",
        );
        assert_eq!(
            hex::encode(old_handle("wiki", root).raw),
            "c71d6a14eac46e89be0e46865a343053a74068c8fda866d2ae07cd3ae394a9af",
        );
    }

    #[test]
    fn absent_descriptor_data_and_metadata_reseat_by_handle_and_replay_without_growth() {
        let (_directory, path, key, signer) = fixture();
        let old = old_handle("wiki", signer.verifying_key());
        let source = sparse_commit(&signer, old, 0x51);
        let mut pile = open_pile_strict(&path).unwrap();
        pile.insert(CollectionRecord::Commit(source)).unwrap();
        pile.insert(CollectionRecord::Merge(CollectionMerge::new(
            old,
            Inline::new([1; 32]),
            Inline::new([2; 32]),
            Inline::new([3; 32]),
        )))
        .unwrap();
        pile.insert(CollectionRecord::Derive(CollectionDerive::new(
            old,
            Inline::new([4; 32]),
            Inline::new([5; 32]),
        )))
        .unwrap();
        pile.close().unwrap();
        let before = fs::read(&path).unwrap();
        let dry = plan_path(&path, Some(&key), None, false).unwrap();
        assert_eq!(dry.selected_commits(), 1);
        assert_eq!(dry.missing_commits(), 1);
        assert_eq!(fs::read(&path).unwrap(), before);
        let root = dry.roots.iter().find(|root| root.name == "wiki").unwrap();
        assert_eq!(root.skipped_merges, 1);
        assert_eq!(root.skipped_derives, 1);

        let first = publish_path(&path, Some(&key), None, false).unwrap();
        assert_eq!(first.appended_commits, 1);
        assert!(first.plan.settled());
        let after = fs::read(&path).unwrap();
        assert!(after.starts_with(&before));
        let mut pile = open_pile_strict(&path).unwrap();
        let snapshot = pile.snapshot().unwrap();
        assert_eq!(
            snapshot
                .record(CollectionRecord::Commit(source).fingerprint())
                .unwrap(),
            Some(CollectionRecord::Commit(source))
        );
        let target = snapshot
            .select_records(&BTreeSet::from([CollectionRecordSelector::Collection(
                root.new,
            )]))
            .unwrap();
        assert_eq!(
            target,
            vec![CollectionRecord::Commit(CollectionCommit::sign(
                &signer,
                root.new,
                source.data(),
                source.metadata(),
            ))]
        );
        let _: Blob<SimpleArchive> = snapshot.get(root.new).unwrap();
        let _: Blob<SimpleArchive> = snapshot.get(read_capability()).unwrap();
        let _: Blob<SimpleArchive> = snapshot.get(write_capability()).unwrap();
        assert_eq!(snapshot.proofs().unwrap().count(), 0);
        drop(snapshot);
        pile.close().unwrap();
        let replay = publish_path(&path, Some(&key), None, false).unwrap();
        assert_eq!(replay.appended_commits, 0);
        assert_eq!(fs::read(&path).unwrap(), after);
    }

    #[test]
    fn random_domain_entity_ids_and_metafacts_remain_exact() {
        let (_directory, path, key, signer) = fixture();
        let old = old_handle("compass", signer.verifying_key());
        let entity = fucid();
        let annotation = fucid();
        let facts = entity! { &entity @ metadata::tag: metadata::KIND_MULTI };
        let metafacts = entity! { &annotation @ metadata::tag: metadata::KIND_INLINE_ENCODING };
        let mut pile = open_pile_strict(&path).unwrap();
        let data = pile.put::<SimpleArchive, _>(facts.facts().clone()).unwrap();
        let metadata = pile
            .put::<SimpleArchive, _>(metafacts.facts().clone())
            .unwrap();
        let source = CollectionCommit::sign(&signer, old, Inline::new(data.raw), metadata);
        pile.insert(CollectionRecord::Commit(source)).unwrap();
        pile.close().unwrap();

        let result = publish_path(&path, Some(&key), None, false).unwrap();
        let target = result
            .plan
            .roots
            .iter()
            .find(|root| root.name == "compass")
            .unwrap()
            .new;
        let expected = CollectionRecord::Commit(CollectionCommit::sign(
            &signer,
            target,
            source.data(),
            source.metadata(),
        ));
        let mut pile = open_pile_strict(&path).unwrap();
        let snapshot = pile.snapshot().unwrap();
        assert_eq!(
            snapshot.record(expected.fingerprint()).unwrap(),
            Some(expected)
        );
        assert_eq!(
            snapshot.get::<TribleSet, SimpleArchive>(data).unwrap(),
            *facts.facts()
        );
        assert_eq!(
            snapshot.get::<TribleSet, SimpleArchive>(metadata).unwrap(),
            *metafacts.facts()
        );
        drop(snapshot);
        pile.close().unwrap();
    }

    #[test]
    fn separate_author_passes_preserve_signers_and_defer_each_other() {
        let (directory, path, key, root_signer) = fixture();
        let writer_key = directory.path().join("writer.key");
        let writer = initialize_signer(&path, Some(&writer_key)).unwrap();
        let authority = root_signer.verifying_key();
        let old = old_handle("wiki", authority);
        let root_commit = sparse_commit(&root_signer, old, 0x41);
        let writer_commit = sparse_commit(&writer, old, 0x61);
        let mut pile = open_pile_strict(&path).unwrap();
        pile.insert(CollectionRecord::Commit(root_commit)).unwrap();
        pile.insert(CollectionRecord::Commit(writer_commit))
            .unwrap();
        pile.close().unwrap();

        let first = publish_path(&path, Some(&key), Some(authority), false).unwrap();
        assert_eq!(first.plan.selected_commits(), 1);
        assert_eq!(first.plan.deferred_commits(), 1);
        assert_eq!(first.appended_commits, 1);
        assert!(first.plan.settled());
        let target = first
            .plan
            .roots
            .iter()
            .find(|root| root.name == "wiki")
            .unwrap()
            .new;
        let second = publish_path(&path, Some(&writer_key), Some(authority), false).unwrap();
        assert_eq!(second.plan.selected_commits(), 1);
        assert_eq!(second.plan.deferred_commits(), 1);
        assert_eq!(second.appended_commits, 1);
        assert_eq!(
            second
                .plan
                .roots
                .iter()
                .find(|root| root.name == "wiki")
                .unwrap()
                .new,
            target
        );
        let mut pile = open_pile_strict(&path).unwrap();
        let snapshot = pile.snapshot().unwrap();
        for (signer, source) in [(&root_signer, root_commit), (&writer, writer_commit)] {
            let expected = CollectionRecord::Commit(CollectionCommit::sign(
                signer,
                target,
                source.data(),
                source.metadata(),
            ));
            assert_eq!(
                snapshot.record(expected.fingerprint()).unwrap(),
                Some(expected)
            );
        }
        assert_eq!(snapshot.proofs().unwrap().count(), 0);
        drop(snapshot);
        pile.close().unwrap();
        let before = fs::read(&path).unwrap();
        assert_eq!(
            publish_path(&path, Some(&writer_key), Some(authority), false)
                .unwrap()
                .appended_commits,
            0
        );
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn wrong_key_or_only_deferred_authors_never_publish_empty_descriptors() {
        let (directory, path, key, owner) = fixture();
        let other_key = directory.path().join("other.key");
        initialize_signer(&path, Some(&other_key)).unwrap();
        let mut pile = open_pile_strict(&path).unwrap();
        let old = old_handle("wiki", owner.verifying_key());
        pile.insert(CollectionRecord::Commit(sparse_commit(&owner, old, 0x21)))
            .unwrap();
        pile.close().unwrap();
        let before = fs::read(&path).unwrap();
        for authority in [None, Some(owner.verifying_key())] {
            let result = publish_path(&path, Some(&other_key), authority, true).unwrap();
            assert_eq!(result.plan.selected_commits(), 0);
            assert_eq!(result.appended_commits, 0);
            assert_eq!(fs::read(&path).unwrap(), before);
        }
        assert_eq!(
            plan_path(&path, Some(&key), None, false)
                .unwrap()
                .missing_commits(),
            1
        );
    }

    #[test]
    fn invalid_selected_signature_refuses_all_publication() {
        let (_directory, path, key, owner) = fixture();
        let old = old_handle("wiki", owner.verifying_key());
        let source = sparse_commit(&owner, old, 0x71);
        let mut bytes = source.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let invalid = CollectionCommit::from_bytes(bytes);
        let mut pile = open_pile_strict(&path).unwrap();
        pile.insert(CollectionRecord::Commit(invalid)).unwrap();
        pile.close().unwrap();
        let before = fs::read(&path).unwrap();
        assert_eq!(
            plan_path(&path, Some(&key), None, false)
                .unwrap()
                .invalid_commits(),
            1
        );
        assert!(publish_path(&path, Some(&key), None, false)
            .unwrap_err()
            .to_string()
            .contains("invalid-signature"));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn secrets_successor_has_exact_runtime_identity_and_complete_definition_closure() {
        let (_directory, path, key, owner) = fixture();
        let old = old_handle("secrets", owner.verifying_key());
        let mut pile = open_pile_strict(&path).unwrap();
        pile.insert(CollectionRecord::Commit(sparse_commit(&owner, old, 0x31)))
            .unwrap();
        pile.close().unwrap();
        let result = publish_path(&path, Some(&key), None, false).unwrap();
        let target = result
            .plan
            .roots
            .iter()
            .find(|root| root.name == "secrets")
            .unwrap()
            .new;
        let mut scratch = MemoryRepo::default();
        let runtime = faculties::secrets::storage::SecretsCollection::register(
            &mut scratch,
            "secrets",
            faculties::collection_names::private_policy(owner.verifying_key()).with_capability(
                faculties::secrets::key_delivery_definition(),
                AdmissionPolicy::direct(owner.verifying_key()),
            ),
        )
        .unwrap();
        assert_eq!(target, runtime.handle());
        let mut pile = open_pile_strict(&path).unwrap();
        let snapshot = pile.snapshot().unwrap();
        let facts: TribleSet = snapshot.get(target).unwrap();
        for capability in [
            read_capability(),
            write_capability(),
            faculties::secrets::key_delivery_capability(),
        ] {
            let _: Blob<SimpleArchive> = snapshot.get(capability).unwrap();
            assert_eq!(
                descriptor::admission_policies(&facts, capability, Some(SimpleArchive::id()))
                    .collect::<Vec<_>>(),
                vec![AdmissionPolicy::direct(owner.verifying_key())],
            );
        }
        let mut attachments = faculties::secrets::key_delivery_definition()
            .blobs()
            .clone();
        for (handle, _) in attachments.snapshot().unwrap() {
            let _: Blob<UnknownBlob> = snapshot.get(handle).unwrap();
        }
        assert_eq!(snapshot.proofs().unwrap().count(), 0);
        drop(snapshot);
        pile.close().unwrap();
    }

    #[test]
    fn unrelated_predecessor_inventory_is_report_only_and_never_name_selected() {
        let (_directory, path, key, owner) = fixture();
        let mut pile = open_pile_strict(&path).unwrap();
        let old = old_handle("wiki", owner.verifying_key());
        pile.insert(CollectionRecord::Commit(sparse_commit(&owner, old, 0x11)))
            .unwrap();
        let unrelated = store_fragment(
            &mut pile,
            predecessor_descriptor("not-a-faculty", owner.verifying_key()),
        );
        let original = CollectionRecord::Commit(sparse_commit(&owner, unrelated, 0x22));
        pile.insert(original).unwrap();
        pile.close().unwrap();
        let result = publish_path(&path, Some(&key), None, true).unwrap();
        assert_eq!(result.appended_commits, 1);
        assert_eq!(
            result.plan.unmapped_roots,
            vec![UnmappedRoot {
                collection: unrelated,
                names: vec!["not-a-faculty".to_owned()],
            }]
        );
        let mut pile = open_pile_strict(&path).unwrap();
        let snapshot = pile.snapshot().unwrap();
        assert_eq!(
            snapshot.record(original.fingerprint()).unwrap(),
            Some(original)
        );
        drop(snapshot);
        pile.close().unwrap();
    }
}
