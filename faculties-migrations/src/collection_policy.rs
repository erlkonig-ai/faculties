//! Additive re-seat of the immediately previous Faculties collection roots.
//!
//! The consumed epoch named a root with a UTF-8 name, one mandatory
//! `collection_authority`, and the `SimpleArchive` representation. Every
//! Faculty root deliberately used private reach, whose representation was an
//! empty Fragment, so the descriptor contains no reach row. The current epoch
//! replaces that authority field with independent, self-contained READ and
//! WRITE policies. This migration recognizes only the exact predecessor
//! descriptors constructed for [`faculties::collection_names::table`]. It
//! never guesses from a human-readable name and never walks older epochs.
//!
//! A source `COMMIT` already signs the exact data and metadata handles. The
//! migration therefore signs those same handles under the successor
//! descriptor directly; it does not materialize either archive, reconstruct a
//! Fragment, or require referenced blobs to be resident. This is both the
//! smallest transform and the one compatible with partial replicas. MERGE and
//! DERIVE records are cache exhaust tied to the old descriptor and are rebuilt
//! lazily.
//!
//! Secrets is intentionally not transformed. Its access envelopes, sealed
//! frames, and capability proofs bind an exact vault descriptor handle. Merely
//! re-signing its collection leaves would create an inaccessible vault. The
//! old records remain additive history; operators initialize a fresh
//! policy-era vault and supply the credentials again.

use std::collections::BTreeMap;
use std::path::Path;

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};

use faculties::storage::{load_signer, open_pile_strict};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::utf8string::UTF8String;
use triblespace::core::blob::{Blob, IntoBlob, TryFromBlob};
use triblespace::core::collection::records::{
    collection_name, collection_representation, CollectionHandle, KIND_COLLECTION_DESCRIPTOR,
};
use triblespace::core::collection::{
    CollectionCommit, CollectionRead, CollectionRecord, CollectionStore,
};
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::ed25519::ED25519PublicKey;
use triblespace::core::metadata::{self, MetaDescribe};
use triblespace::core::repo::memoryrepo::MemoryRepo;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::{BlobStoreGet, SnapshotSource};
use triblespace::core::trible::{Fragment, TribleSet};
use triblespace::macros::{attributes, entity};

mod retired {
    use super::*;

    attributes! {
        /// Mandatory authority of the immediately previous descriptor epoch.
        ///
        /// The anchor was minted on 2026-08-24. This is deliberately the safe
        /// anchored form rather than `unsafe as`: the Ed25519 encoding has
        /// always participated in the published attribute identity.
        "7C31D328E9C369CCB6049D05CC8E8C77" as pub collection_authority:
            ED25519PublicKey;
    }
}

/// One ordinary root selected for the policy re-seat.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootReseat {
    pub scope: Id,
    pub name: String,
    pub old: CollectionHandle,
    pub new: CollectionHandle,
    pub source_records: usize,
    pub source_commits: usize,
    pub target_records: usize,
    pub target_commits: usize,
    pub missing_commits: usize,
    pub invalid_commits: usize,
    pub unsupported_non_root_commits: usize,
    pub skipped_merges: usize,
    pub skipped_derives: usize,
}

/// One exact predecessor vault deliberately left in place.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExcludedVault {
    pub name: String,
    pub collection: CollectionHandle,
    pub records: usize,
}

/// Secrets state excluded because its cryptographic bindings name old handles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretsExclusion {
    pub access_collection: CollectionHandle,
    pub access_records: usize,
    pub vaults: Vec<ExcludedVault>,
}

/// Complete dry-run view of the one supported descriptor transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionPolicyPlan {
    pub roots: Vec<RootReseat>,
    pub secrets: SecretsExclusion,
}

impl CollectionPolicyPlan {
    pub fn missing_commits(&self) -> usize {
        self.roots.iter().map(|root| root.missing_commits).sum()
    }

    pub fn unsupported_non_root_commits(&self) -> usize {
        self.roots
            .iter()
            .map(|root| root.unsupported_non_root_commits)
            .sum()
    }

    pub fn invalid_commits(&self) -> usize {
        self.roots.iter().map(|root| root.invalid_commits).sum()
    }

    pub fn settled(&self) -> bool {
        self.missing_commits() == 0 && self.unsupported_non_root_commits() == 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionPolicyReport {
    pub plan: CollectionPolicyPlan,
    pub appended_commits: usize,
}

#[derive(Clone)]
struct RootSpec {
    scope: Id,
    name: &'static str,
    old: CollectionHandle,
    new: CollectionHandle,
}

struct PreparedRoot {
    summary: RootReseat,
    missing: Vec<CollectionCommit>,
}

struct PreparedMigration {
    plan: CollectionPolicyPlan,
    roots: Vec<PreparedRoot>,
}

/// Reconstruct the exact private descriptor written immediately before
/// collection policies became explicit.
fn retired_root_descriptor(name: &str, authority: VerifyingKey) -> Fragment {
    entity! {
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        collection_name: name.to_owned(),
        retired::collection_authority: authority,
        collection_representation*: <SimpleArchive as MetaDescribe>::describe(),
    }
}

fn descriptor_handle(descriptor: &Fragment) -> CollectionHandle {
    let blob: Blob<SimpleArchive> = descriptor.facts().clone().to_blob();
    blob.get_handle()
}

/// Build predecessor identities directly and successor identities through the
/// exact runtime facade, without writing to the destination pile.
fn root_specs(authority: VerifyingKey) -> Result<Vec<RootSpec>> {
    let mut scratch = MemoryRepo::default();
    faculties::collection_names::table()
        .into_iter()
        .map(|(scope, name)| {
            let old = descriptor_handle(&retired_root_descriptor(name, authority));
            let new = faculties::collection_names::open(&mut scratch, scope, authority)
                .map_err(|error| anyhow!("construct current {name} descriptor: {error}"))?
                .handle();
            Ok(RootSpec {
                scope,
                name,
                old,
                new,
            })
        })
        .collect()
}

fn records_by_collection(
    snapshot: &PileSnapshot,
) -> Result<BTreeMap<CollectionHandle, Vec<CollectionRecord>>> {
    let mut grouped = BTreeMap::new();
    let records = snapshot
        .records()
        .context("enumerate native collection records for policy re-seat")?;
    for record in records {
        let record = record.context("read native collection record for policy re-seat")?;
        let collection = match record {
            CollectionRecord::Commit(commit) => commit.collection(),
            CollectionRecord::Merge(merge) => merge.collection(),
            CollectionRecord::Derive(derive) => derive.collection(),
        };
        grouped
            .entry(collection)
            .or_insert_with(Vec::new)
            .push(record);
    }
    Ok(grouped)
}

fn exact_retired_name(
    snapshot: &PileSnapshot,
    collection: CollectionHandle,
    authority: VerifyingKey,
) -> Option<String> {
    let descriptor: Blob<SimpleArchive> = snapshot.get(collection).ok()?;
    let facts = TribleSet::try_from_blob(descriptor).ok()?;
    let name_handle = triblespace::core::collection::descriptor::name(&facts).ok()??;
    let name: View<str> = snapshot.get::<View<str>, UTF8String>(name_handle).ok()?;
    let name = name.to_string();
    (descriptor_handle(&retired_root_descriptor(&name, authority)) == collection).then_some(name)
}

fn secrets_exclusion(
    snapshot: &PileSnapshot,
    records: &BTreeMap<CollectionHandle, Vec<CollectionRecord>>,
    authority: VerifyingKey,
) -> SecretsExclusion {
    let access_collection =
        descriptor_handle(&retired_root_descriptor("secrets-access", authority));
    let access_records = records.get(&access_collection).map_or(0, Vec::len);
    let mut vaults = records
        .iter()
        .filter_map(|(collection, records)| {
            if *collection == access_collection {
                return None;
            }
            let name = exact_retired_name(snapshot, *collection, authority)?;
            faculties::secrets::parse_vault_name(&name).ok()?;
            Some(ExcludedVault {
                name,
                collection: *collection,
                records: records.len(),
            })
        })
        .collect::<Vec<_>>();
    vaults.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    SecretsExclusion {
        access_collection,
        access_records,
        vaults,
    }
}

fn prepare(snapshot: &PileSnapshot, signer: &SigningKey) -> Result<PreparedMigration> {
    let authority = signer.verifying_key();
    let specs = root_specs(authority)?;
    let records = records_by_collection(snapshot)?;
    let mut roots = Vec::new();

    for spec in specs {
        let source = records.get(&spec.old).map(Vec::as_slice).unwrap_or(&[]);
        let mut source_commits = 0usize;
        let mut invalid_commits = 0usize;
        let mut unsupported_non_root_commits = 0usize;
        let mut skipped_merges = 0usize;
        let mut skipped_derives = 0usize;
        let mut expected = BTreeMap::new();

        for record in source {
            match record {
                CollectionRecord::Commit(commit) => {
                    if commit.verify_strict().is_err() {
                        invalid_commits += 1;
                        continue;
                    }
                    if commit.public_key().raw != authority.to_bytes() {
                        unsupported_non_root_commits += 1;
                        continue;
                    }
                    source_commits += 1;
                    let successor =
                        CollectionCommit::sign(signer, spec.new, commit.data(), commit.metadata());
                    expected.insert(successor.id(), successor);
                }
                CollectionRecord::Merge(_) => skipped_merges += 1,
                CollectionRecord::Derive(_) => skipped_derives += 1,
            }
        }

        let target = records.get(&spec.new).map(Vec::as_slice).unwrap_or(&[]);
        let mut target_by_id = BTreeMap::new();
        let mut target_commits = 0usize;
        for record in target {
            if matches!(record, CollectionRecord::Commit(_)) {
                target_commits += 1;
            }
            target_by_id.insert(record.id(), *record);
        }

        let mut missing = Vec::new();
        for commit in expected.values() {
            match target_by_id.get(&commit.id()) {
                Some(CollectionRecord::Commit(existing)) if existing == commit => {}
                Some(_) => {
                    bail!(
                        "collection-record id {} collides while re-seating {}",
                        commit.id(),
                        spec.name,
                    );
                }
                None => missing.push(*commit),
            }
        }

        let summary = RootReseat {
            scope: spec.scope,
            name: spec.name.to_owned(),
            old: spec.old,
            new: spec.new,
            source_records: source.len(),
            source_commits,
            target_records: target.len(),
            target_commits,
            missing_commits: missing.len(),
            invalid_commits,
            unsupported_non_root_commits,
            skipped_merges,
            skipped_derives,
        };
        roots.push(PreparedRoot { summary, missing });
    }

    roots.sort_unstable_by(|left, right| left.summary.name.cmp(&right.summary.name));
    let secrets = secrets_exclusion(snapshot, &records, authority);
    let plan = CollectionPolicyPlan {
        roots: roots.iter().map(|root| root.summary.clone()).collect(),
        secrets,
    };
    Ok(PreparedMigration { plan, roots })
}

fn publish_open(pile: &mut Pile, signer: &SigningKey) -> Result<CollectionPolicyReport> {
    let snapshot = pile
        .snapshot()
        .context("freeze collection-policy source snapshot")?;
    let prepared = prepare(&snapshot, signer)?;
    drop(snapshot);

    if prepared.plan.unsupported_non_root_commits() != 0 {
        bail!(
            "collection-policy found {} strictly signed predecessor COMMIT(s) by non-root writers; this minimal migration will neither silently adopt nor discard potentially delegated data",
            prepared.plan.unsupported_non_root_commits(),
        );
    }

    // Every source record and every deterministic successor is prepared before
    // the first descriptor or record is appended. A concurrent predecessor
    // writer is detected by the fresh verification snapshot below; replay
    // then carries the newly observed suffix.
    let mut appended_commits = 0usize;
    for root in &prepared.roots {
        let collection =
            faculties::collection_names::open(pile, root.summary.scope, signer.verifying_key())
                .map_err(|error| {
                    anyhow!("register current {} descriptor: {error}", root.summary.name)
                })?;
        if collection.handle() != root.summary.new {
            bail!(
                "current {} descriptor changed identity between planning and publication",
                root.summary.name,
            );
        }
        for commit in &root.missing {
            pile.insert(CollectionRecord::Commit(*commit))
                .map_err(|error| {
                    anyhow!("append re-seated {} COMMIT: {error}", root.summary.name)
                })?;
            appended_commits += 1;
        }
    }

    let snapshot = pile
        .snapshot()
        .context("freeze collection-policy verification snapshot")?;
    let after = prepare(&snapshot, signer)?;
    if !after.plan.settled() {
        bail!(
            "collection-policy verification found {} missing successor COMMIT(s) and {} unsupported non-root predecessor COMMIT(s); replay after predecessor writers are quiescent",
            after.plan.missing_commits(),
            after.plan.unsupported_non_root_commits(),
        );
    }
    for root in &after.roots {
        let _: Blob<SimpleArchive> = snapshot.get(root.summary.new).with_context(|| {
            format!(
                "read registered current {} descriptor after publication",
                root.summary.name,
            )
        })?;
    }
    drop(snapshot);

    Ok(CollectionPolicyReport {
        plan: after.plan,
        appended_commits,
    })
}

fn finish_pile<T>(pile: Pile, result: Result<T>, operation: &str) -> Result<T> {
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context(format!("close pile after {operation}"))),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing after {operation} also failed: {close_error}",
        ))),
    }
}

pub fn plan_path(pile: &Path, key: Option<&Path>) -> Result<CollectionPolicyPlan> {
    let signer = load_signer(pile, key).context("load durable collection-policy signer")?;
    let mut store = open_pile_strict(pile)?;
    let snapshot = store
        .snapshot()
        .context("freeze collection-policy planning snapshot")?;
    let result = prepare(&snapshot, &signer).map(|prepared| prepared.plan);
    drop(snapshot);
    finish_pile(store, result, "collection-policy planning")
}

/// Additively re-seat every exact predecessor root visible in one frozen
/// source snapshot.
///
/// Old binaries should be quiesced for the final run. Publication remains
/// replayable if one appends late: the fresh verification reports the newly
/// missing deterministic successor, and another invocation completes it.
pub fn publish_path(pile: &Path, key: Option<&Path>) -> Result<CollectionPolicyReport> {
    let signer = load_signer(pile, key).context("load durable collection-policy signer")?;
    let mut store = open_pile_strict(pile)?;
    let result = publish_open(&mut store, &signer);
    finish_pile(store, result, "collection-policy publication")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs::{self, File};

    use super::*;
    use faculties::storage::initialize_signer;
    use triblespace::core::blob::encodings::UnknownBlob;
    use triblespace::core::collection::{
        CollectionData, CollectionDerive, CollectionMerge, CollectionRecordSelector,
        CollectionStore, CollectionStoreExt,
    };
    use triblespace::core::inline::encodings::hash::Handle;
    use triblespace::core::inline::Inline;
    use triblespace::core::repo::BlobStorePut;

    fn fixture() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        SigningKey,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("test.pile");
        let key = directory.path().join("test.key");
        File::create(&pile).unwrap();
        let signer = initialize_signer(&pile, Some(&key)).unwrap();
        (directory, pile, key, signer)
    }

    fn store_fragment(pile: &mut Pile, fragment: Fragment) -> CollectionHandle {
        let expected = descriptor_handle(&fragment);
        let (_, facts, _, mut blobs) = fragment.into_parts();
        let embedded = blobs
            .snapshot()
            .expect("memory blob snapshot")
            .into_iter()
            .map(|(_, blob)| blob)
            .collect::<Vec<Blob<UnknownBlob>>>();
        for blob in embedded {
            pile.put::<UnknownBlob, _>(blob).unwrap();
        }
        let stored = pile.put::<SimpleArchive, _>(facts).unwrap();
        assert_eq!(stored, expected);
        stored
    }

    fn missing_data(seed: u8) -> CollectionData {
        Inline::new([seed; 32])
    }

    fn missing_metadata(seed: u8) -> Inline<Handle<SimpleArchive>> {
        Inline::new([seed; 32])
    }

    fn collection_records(
        snapshot: &PileSnapshot,
        collection: CollectionHandle,
    ) -> Vec<CollectionRecord> {
        snapshot
            .select_records(&BTreeSet::from([CollectionRecordSelector::Collection(
                collection,
            )]))
            .unwrap()
    }

    #[test]
    fn predecessor_builder_matches_live_descriptor_golden() {
        let raw = hex::decode("C5C9F620F067CBB1169D60D02B7EA4EEE9656DAB082E040A00FEBC490021D802")
            .unwrap();
        let authority = VerifyingKey::from_bytes(raw.as_slice().try_into().unwrap()).unwrap();
        assert_eq!(
            hex::encode(descriptor_handle(&retired_root_descriptor("compass", authority)).raw),
            "5dfade2e60bf6c178e83668f7ce47d72e54bca5a643abee119998cf18405c1a3",
        );
        assert_eq!(
            hex::encode(descriptor_handle(&retired_root_descriptor("wiki", authority)).raw),
            "a417b2d62b6ec21b89f05bae09b4caa850295b02bb6fc21ca11aa410ac97b62d",
        );
    }

    #[test]
    fn missing_payloads_reseat_by_handle_and_replay_without_growth() {
        let (_directory, path, key, signer) = fixture();
        let (scope, name) = faculties::collection_names::table()[0];
        let mut pile = open_pile_strict(&path).unwrap();
        let old = store_fragment(
            &mut pile,
            retired_root_descriptor(name, signer.verifying_key()),
        );
        let data = missing_data(0x51);
        let metadata = missing_metadata(0xA7);
        let source = CollectionCommit::sign(&signer, old, data, metadata);
        pile.insert(CollectionRecord::Commit(source)).unwrap();
        pile.close().unwrap();

        let before = plan_path(&path, Some(&key)).unwrap();
        assert_eq!(
            before.roots.len(),
            faculties::collection_names::table().len()
        );
        assert_eq!(before.missing_commits(), 1);
        let target = before
            .roots
            .iter()
            .find(|root| root.name == name)
            .unwrap()
            .new;

        let first = publish_path(&path, Some(&key)).unwrap();
        assert_eq!(first.appended_commits, 1);
        assert!(first.plan.settled());
        let length = fs::metadata(&path).unwrap().len();

        let mut pile = open_pile_strict(&path).unwrap();
        let snapshot = pile.snapshot().unwrap();
        for root in &first.plan.roots {
            let _: Blob<SimpleArchive> = snapshot.get(root.new).unwrap();
        }
        let target_commits = collection_records(&snapshot, target)
            .into_iter()
            .filter_map(|record| match record {
                CollectionRecord::Commit(commit) => Some(commit),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(target_commits.len(), 1);
        assert_eq!(target_commits[0].data(), data);
        assert_eq!(target_commits[0].metadata(), metadata);
        assert_eq!(
            target_commits[0].public_key().raw,
            signer.verifying_key().to_bytes()
        );
        drop(snapshot);
        pile.close().unwrap();

        let second = publish_path(&path, Some(&key)).unwrap();
        assert_eq!(second.appended_commits, 0);
        assert!(second.plan.settled());
        assert_eq!(fs::metadata(&path).unwrap().len(), length);

        let mut scratch = MemoryRepo::default();
        assert_eq!(
            faculties::collection_names::open(&mut scratch, scope, signer.verifying_key())
                .unwrap()
                .handle(),
            target,
        );
    }

    #[test]
    fn equations_and_secrets_stay_in_their_predecessor_epochs() {
        let (_directory, path, key, signer) = fixture();
        let (_scope, name) = faculties::collection_names::table()[0];
        let mut pile = open_pile_strict(&path).unwrap();
        let old = store_fragment(
            &mut pile,
            retired_root_descriptor(name, signer.verifying_key()),
        );
        let source = CollectionCommit::sign(&signer, old, missing_data(1), missing_metadata(2));
        pile.insert(CollectionRecord::Commit(source)).unwrap();
        pile.insert(CollectionRecord::Merge(CollectionMerge::new(
            old,
            missing_data(1),
            missing_data(3),
            missing_data(4),
        )))
        .unwrap();
        pile.insert(CollectionRecord::Derive(CollectionDerive::new(
            old,
            missing_data(1),
            missing_data(5),
        )))
        .unwrap();

        let access = store_fragment(
            &mut pile,
            retired_root_descriptor("secrets-access", signer.verifying_key()),
        );
        pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
            &signer,
            access,
            missing_data(6),
            missing_metadata(7),
        )))
        .unwrap();
        let vault_name = faculties::secrets::vault_name(Id::new([0x33; 16]).unwrap());
        let vault = store_fragment(
            &mut pile,
            retired_root_descriptor(&vault_name, signer.verifying_key()),
        );
        pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
            &signer,
            vault,
            missing_data(8),
            missing_metadata(9),
        )))
        .unwrap();
        pile.close().unwrap();

        let plan = plan_path(&path, Some(&key)).unwrap();
        let ordinary = plan.roots.iter().find(|root| root.name == name).unwrap();
        assert_eq!(ordinary.skipped_merges, 1);
        assert_eq!(ordinary.skipped_derives, 1);
        assert_eq!(plan.secrets.access_collection, access);
        assert_eq!(plan.secrets.access_records, 1);
        assert_eq!(plan.secrets.vaults.len(), 1);
        assert_eq!(plan.secrets.vaults[0].collection, vault);
        let target = ordinary.new;

        publish_path(&path, Some(&key)).unwrap();
        let mut pile = open_pile_strict(&path).unwrap();
        let snapshot = pile.snapshot().unwrap();
        let target_records = collection_records(&snapshot, target);
        assert_eq!(
            target_records
                .iter()
                .filter(|record| matches!(record, CollectionRecord::Commit(_)))
                .count(),
            1,
        );
        assert!(target_records
            .iter()
            .all(|record| matches!(record, CollectionRecord::Commit(_))));

        let mut scratch = MemoryRepo::default();
        let policy_access = scratch
            .collection(
                "secrets-access",
                faculties::secrets::vault_policy(signer.verifying_key()),
            )
            .unwrap();
        assert!(collection_records(&snapshot, policy_access.handle()).is_empty());
        drop(snapshot);
        pile.close().unwrap();
    }
}
