//! One-shot re-seat of named Faculties roots into authority-local descriptors.
//!
//! The retired descriptor epoch identified a root by an inline short name and
//! a public-key namespace. The current epoch instead carries an unbounded
//! UTF-8 name attachment and exactly one authority, with no namespace. This
//! migration knows only the ordinary roots in collection_names::table, reuses
//! their data/metadata handles, and signs the same leaves under the new handle.
//! MERGE/DERIVE caches are rebuilt lazily. Secrets is classified as deferred
//! because vault handles occur inside proofs and sealed envelopes.
//!
//! No disposable pile is needed: the record wire format and every referenced
//! blob remain unchanged, target COMMIT identities are deterministic, and a
//! partial publication is completed by exact replay. Writers from the retired
//! epoch must still be stopped for the source census so no late leaf is missed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};

use faculties::storage::{load_signer, open_pile_strict};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::{Blob, IntoBlob, TryFromBlob};
use triblespace::core::collection::records::{
    collection_authority, collection_reach, collection_recipe, collection_representation,
    collection_source, CollectionCommit, CollectionHandle, KIND_COLLECTION_DESCRIPTOR,
};
use triblespace::core::collection::simplearchive_union::{self, TribleSetUnionV1};
use triblespace::core::collection::{
    discover_collection_records, CollectionRecord, CollectionStore, CollectionStoreExt,
};
use triblespace::core::id::{ExclusiveId, Id};
use triblespace::core::inline::encodings::ed25519::ED25519PublicKey;
use triblespace::core::inline::encodings::genid::GenId;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::encodings::shortstring::ShortString;
use triblespace::core::inline::{Inline, IntoInline};
use triblespace::core::metadata::{self, MetaDescribe};
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet};
use triblespace::core::trible::{Fragment, Trible, TribleSet};
use triblespace::macros::{attributes, entity};

mod retired {
    use super::*;

    attributes! {
        "436A04C372CBBFBD9C619CF50F59C4A1" unsafe as pub collection_name: ShortString;
        "6C1ED6495491E32FEBB9FDD4EE5E8907" unsafe as pub collection_namespace: ED25519PublicKey;
        "D3418873C70392E3ADAA05C00E11A583" unsafe as pub collection_scope: GenId;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootReseat {
    pub scope: Id,
    pub name: String,
    pub old: CollectionHandle,
    pub new: CollectionHandle,
    pub source_commits: usize,
    pub target_commits: usize,
    pub missing_commits: usize,
    pub skipped_merges: usize,
    pub skipped_derives: usize,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResidueKind {
    Derived,
    SecretsDeferred,
    RetiredNamedRoot,
    PreNamingRoot,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Residue {
    pub collection: CollectionHandle,
    pub kind: ResidueKind,
    pub records: usize,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DescriptorAuthorityPlan {
    pub roots: Vec<RootReseat>,
    pub residues: Vec<Residue>,
    pub invalid_records: usize,
}

impl DescriptorAuthorityPlan {
    pub fn missing_commits(&self) -> usize {
        self.roots.iter().map(|root| root.missing_commits).sum()
    }

    pub fn settled(&self) -> bool {
        self.missing_commits() == 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescriptorAuthorityReport {
    pub plan: DescriptorAuthorityPlan,
    pub appended_commits: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RetiredRoot {
    name: String,
    namespace: VerifyingKey,
    authority: Option<VerifyingKey>,
}

fn one_attribute<'a>(
    facts: &'a TribleSet,
    descriptor: Id,
    attribute: Id,
    field: &str,
    required: bool,
) -> Result<Option<&'a Trible>> {
    let rows = facts
        .iter()
        .filter(|fact| fact.a() == &attribute)
        .collect::<Vec<_>>();
    if rows.len() > 1 {
        bail!("retired descriptor contains repeated {field}");
    }
    match rows.as_slice() {
        [] if !required => Ok(None),
        [] => bail!("retired descriptor is missing {field}"),
        [fact] if fact.e() == &descriptor => Ok(Some(*fact)),
        [_] => bail!("retired descriptor contains {field} on another entity"),
        _ => unreachable!("row multiplicity was checked above"),
    }
}

fn retired_descriptor_entity(facts: &TribleSet) -> Result<Id> {
    let kind = KIND_COLLECTION_DESCRIPTOR.to_inline();
    let roots = facts
        .iter()
        .filter(|fact| fact.a() == &metadata::tag.id() && *fact.v::<GenId>() == kind)
        .map(|fact| *fact.e())
        .collect::<Vec<_>>();
    match roots.as_slice() {
        [root] => Ok(*root),
        [] => bail!("archive contains no retired collection descriptor entity"),
        _ => bail!("archive contains more than one collection descriptor entity"),
    }
}

/// Strictly decode one retired named-root descriptor.
///
/// Every identity-bearing field must occur on the exact tagged descriptor
/// entity. Embedded descriptions cannot satisfy descriptor shape.
fn decode_retired_root(facts: &TribleSet) -> Result<RetiredRoot> {
    let descriptor = retired_descriptor_entity(facts)?;
    if one_attribute(
        facts,
        descriptor,
        collection_source.id(),
        "collection_source",
        false,
    )?
    .is_some()
    {
        bail!("retired descriptor is derived rather than a named root");
    }
    let name = one_attribute(
        facts,
        descriptor,
        retired::collection_name.id(),
        "collection_name",
        true,
    )?
    .expect("required")
    .v::<ShortString>()
    .to_owned()
    .try_from_inline::<String>()
    .map_err(|_| anyhow!("retired collection_name is not a canonical ShortString"))?;
    let namespace = one_attribute(
        facts,
        descriptor,
        retired::collection_namespace.id(),
        "collection_namespace",
        true,
    )?
    .expect("required")
    .v::<ED25519PublicKey>()
    .to_owned()
    .try_from_inline::<VerifyingKey>()
    .map_err(|_| anyhow!("retired collection_namespace is not a valid Ed25519 key"))?;
    let authority = one_attribute(
        facts,
        descriptor,
        collection_authority.id(),
        "collection_authority",
        false,
    )?
    .map(|fact| {
        fact.v::<ED25519PublicKey>()
            .to_owned()
            .try_from_inline::<VerifyingKey>()
            .map_err(|_| anyhow!("retired collection_authority is not a valid Ed25519 key"))
    })
    .transpose()?;
    Ok(RetiredRoot {
        name,
        namespace,
        authority,
    })
}

fn retired_descriptor(
    name: &str,
    namespace: VerifyingKey,
    authority: Option<VerifyingKey>,
    reach: Fragment,
) -> Fragment {
    entity! {
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        retired::collection_name: name,
        retired::collection_namespace: namespace,
        collection_authority?: authority,
        collection_representation*: <SimpleArchive as MetaDescribe>::describe(),
        collection_recipe*: <TribleSetUnionV1 as MetaDescribe>::describe(),
        collection_reach*: reach,
    }
}

fn descriptor_handle(fragment: &Fragment) -> CollectionHandle {
    IntoBlob::<SimpleArchive>::to_blob(fragment.facts().clone()).get_handle()
}

fn descriptor_facts(reader: &PileReader, collection: CollectionHandle) -> Result<TribleSet> {
    let blob: Blob<SimpleArchive> = reader
        .get(collection)
        .with_context(|| format!("read descriptor {}", hex::encode_upper(collection.raw)))?;
    if blob.get_handle() != collection {
        bail!("descriptor bytes do not match their collection handle");
    }
    TribleSet::try_from_blob(blob).context("decode descriptor SimpleArchive")
}

fn expected_target_commits(
    signer: &SigningKey,
    target: CollectionHandle,
    source: &[CollectionCommit],
) -> BTreeMap<Id, CollectionCommit> {
    source
        .iter()
        .map(|commit| {
            let target = CollectionCommit::sign(signer, target, commit.data(), commit.metadata());
            (target.id(), target)
        })
        .collect()
}

fn collection_record_counts(
    commits: &[CollectionCommit],
    merges: &[triblespace::core::collection::CollectionMerge],
    derives: &[triblespace::core::collection::CollectionDerive],
) -> BTreeMap<CollectionHandle, usize> {
    let mut counts = BTreeMap::new();
    for commit in commits {
        *counts.entry(commit.collection()).or_default() += 1;
    }
    for merge in merges {
        *counts.entry(merge.collection()).or_default() += 1;
    }
    for derive in derives {
        *counts.entry(derive.target()).or_default() += 1;
    }
    counts
}

fn has_attribute(facts: &TribleSet, attribute: Id) -> bool {
    facts.iter().any(|fact| fact.a() == &attribute)
}

fn classify_residue(reader: &PileReader, collection: CollectionHandle) -> (ResidueKind, String) {
    let Ok(facts) = descriptor_facts(reader, collection) else {
        return (
            ResidueKind::Unknown,
            "descriptor is missing or malformed".to_owned(),
        );
    };
    if has_attribute(&facts, collection_source.id()) {
        return (
            ResidueKind::Derived,
            "derived cache exhaust is rebuilt lazily".to_owned(),
        );
    }
    if has_attribute(&facts, retired::collection_scope.id()) {
        return (
            ResidueKind::PreNamingRoot,
            "scope-anchored predecessor remains additive history".to_owned(),
        );
    }
    match decode_retired_root(&facts) {
        Ok(root)
            if root.name == "secrets-access"
                || root.name == "secrets"
                || root.name.starts_with("vault-") =>
        {
            (
                ResidueKind::SecretsDeferred,
                format!(
                    "Secrets root '{}' requires proof/envelope migration",
                    root.name
                ),
            )
        }
        Ok(root) => (
            ResidueKind::RetiredNamedRoot,
            format!("retired or external named root '{}'", root.name),
        ),
        Err(error) => (ResidueKind::Unknown, error.to_string()),
    }
}

fn plan_open(pile: &mut Pile, signer: &SigningKey) -> Result<DescriptorAuthorityPlan> {
    let discovered = discover_collection_records(&mut *pile)
        .context("discover records for descriptor-authority cutover")?;
    let commits = discovered.commits().to_vec();
    let merges = discovered.merges().to_vec();
    let derives = discovered.derives().to_vec();
    let invalid_records = discovered.diagnostics().len();
    let counts = collection_record_counts(&commits, &merges, &derives);
    let existing_ids = commits
        .iter()
        .map(CollectionCommit::id)
        .collect::<BTreeSet<_>>();
    let reader = pile.reader().context("open descriptor cutover reader")?;
    let authority = signer.verifying_key();
    let mut roots = Vec::new();
    let mut recognized = BTreeSet::new();

    for (scope, name, reach) in faculties::collection_names::table() {
        let old_descriptor = retired_descriptor(name, authority, None, reach.clone());
        let old = descriptor_handle(&old_descriptor);
        let new_descriptor = simplearchive_union::descriptor(name, authority, reach);
        let new = descriptor_handle(&new_descriptor);
        recognized.insert(old);
        recognized.insert(new);

        let source = commits
            .iter()
            .copied()
            .filter(|commit| commit.collection() == old)
            .collect::<Vec<_>>();
        // This is a transform of retired leaves, not a registry audit. A
        // current-epoch-only root has nothing to migrate and must not make a
        // clean pile depend on retaining the retired descriptor forever.
        if source.is_empty() {
            continue;
        }

        let old_facts = descriptor_facts(&reader, old)
            .with_context(|| format!("read retired descriptor for {name}"))?;
        if old_facts != *old_descriptor.facts() {
            bail!("retired descriptor for {name} is not the exact registered epoch");
        }
        let decoded = decode_retired_root(&old_facts)
            .with_context(|| format!("strictly decode retired descriptor for {name}"))?;
        if decoded.name != name || decoded.namespace != authority || decoded.authority.is_some() {
            bail!("retired descriptor for {name} disagrees with the ordinary-root registry");
        }

        let expected = expected_target_commits(signer, new, &source);
        let missing_commits = expected
            .keys()
            .filter(|id| !existing_ids.contains(*id))
            .count();
        roots.push(RootReseat {
            scope,
            name: name.to_owned(),
            old,
            new,
            source_commits: source.len(),
            target_commits: expected.len(),
            missing_commits,
            skipped_merges: merges
                .iter()
                .filter(|merge| merge.collection() == old)
                .count(),
            skipped_derives: derives
                .iter()
                .filter(|derive| derive.target() == old)
                .count(),
        });
    }

    let mut residues = counts
        .into_iter()
        .filter(|(collection, _)| !recognized.contains(collection))
        .map(|(collection, records)| {
            let (kind, detail) = classify_residue(&reader, collection);
            Residue {
                collection,
                kind,
                records,
                detail,
            }
        })
        .collect::<Vec<_>>();
    roots.sort_by(|left, right| left.name.cmp(&right.name));
    residues.sort_by_key(|residue| (residue.kind, residue.collection));
    Ok(DescriptorAuthorityPlan {
        roots,
        residues,
        invalid_records,
    })
}

fn validate_resident_commit_inputs(
    reader: &PileReader,
    root: &RootReseat,
    source: &[CollectionCommit],
) -> Result<()> {
    let mut data_seen = BTreeSet::new();
    let mut metadata_seen = BTreeSet::new();
    for commit in source {
        let data: Inline<Handle<SimpleArchive>> = commit.data().transmute();
        if data_seen.insert(data) {
            let blob: Blob<SimpleArchive> = reader
                .get(data)
                .with_context(|| format!("{} COMMIT {} data is absent", root.name, commit.id()))?;
            TribleSet::try_from_blob(blob).with_context(|| {
                format!("{} COMMIT {} data is not canonical", root.name, commit.id())
            })?;
        }
        if metadata_seen.insert(commit.metadata()) {
            let blob: Blob<SimpleArchive> = reader.get(commit.metadata()).with_context(|| {
                format!("{} COMMIT {} metadata is absent", root.name, commit.id())
            })?;
            TribleSet::try_from_blob(blob).with_context(|| {
                format!(
                    "{} COMMIT {} metadata is not canonical",
                    root.name,
                    commit.id()
                )
            })?;
        }
    }
    Ok(())
}

fn publish_open(pile: &mut Pile, signer: &SigningKey) -> Result<DescriptorAuthorityReport> {
    let before = plan_open(pile, signer)?;
    let discovered = discover_collection_records(&mut *pile)
        .context("rediscover frozen source records before publication")?;
    let commits = discovered.commits().to_vec();
    let existing = commits
        .iter()
        .map(CollectionCommit::id)
        .collect::<BTreeSet<_>>();
    let reader = pile
        .reader()
        .context("open publication dependency reader")?;
    let authority = signer.verifying_key();
    let mut appended_commits = 0;
    let sources = before
        .roots
        .iter()
        .map(|root| {
            let source = commits
                .iter()
                .copied()
                .filter(|commit| commit.collection() == root.old)
                .collect::<Vec<_>>();
            (root.old, source)
        })
        .collect::<BTreeMap<_, _>>();

    // Validate the complete frozen source before making even the first target
    // COMMIT visible. Descriptor registration below may still be retried, but
    // malformed legacy leaves cannot leave a partially populated new epoch.
    for root in &before.roots {
        validate_resident_commit_inputs(&reader, root, &sources[&root.old])?;
    }

    for root in &before.roots {
        let source = &sources[&root.old];
        let (_, _, reach) = faculties::collection_names::table()
            .into_iter()
            .find(|(scope, _, _)| *scope == root.scope)
            .expect("planned root remains in the registry");
        let registered = pile
            .collection(simplearchive_union::descriptor(
                &root.name, authority, reach,
            ))
            .map_err(|error| anyhow!("register {} descriptor: {error}", root.name))?;
        if registered != root.new {
            bail!(
                "{} descriptor changed identity between plan and publish",
                root.name
            );
        }
        for commit in expected_target_commits(signer, root.new, source).into_values() {
            if existing.contains(&commit.id()) {
                continue;
            }
            pile.insert(CollectionRecord::Commit(commit))
                .map_err(|error| anyhow!("append re-seated {} COMMIT: {error}", root.name))?;
            appended_commits += 1;
        }
    }

    let after = plan_open(pile, signer)?;
    verify_open(pile, signer, &after)?;
    if !after.settled() {
        bail!("descriptor-authority publication left expected COMMITs missing");
    }
    Ok(DescriptorAuthorityReport {
        plan: after,
        appended_commits,
    })
}

fn materialize_source(reader: &PileReader, commits: &[CollectionCommit]) -> Result<TribleSet> {
    let mut facts = TribleSet::new();
    let mut seen = BTreeSet::new();
    for commit in commits {
        if !seen.insert(commit.data()) {
            continue;
        }
        let handle: Inline<Handle<SimpleArchive>> = commit.data().transmute();
        let blob: Blob<SimpleArchive> = reader
            .get(handle)
            .with_context(|| format!("read source data {}", hex::encode_upper(handle.raw)))?;
        facts += TribleSet::try_from_blob(blob).context("decode source collection element")?;
    }
    Ok(facts)
}

fn verify_open(pile: &mut Pile, signer: &SigningKey, plan: &DescriptorAuthorityPlan) -> Result<()> {
    let discovered = discover_collection_records(&mut *pile)
        .context("discover records for descriptor-authority verification")?;
    let commits = discovered.commits().to_vec();
    let ids = commits
        .iter()
        .map(CollectionCommit::id)
        .collect::<BTreeSet<_>>();
    let reader = pile.reader().context("open verification reader")?;

    for root in &plan.roots {
        let descriptor = descriptor_facts(&reader, root.new)
            .with_context(|| format!("read new {} descriptor", root.name))?;
        let parsed_authority = triblespace::core::collection::descriptor::authority(&descriptor)
            .with_context(|| format!("decode new {} authority", root.name))?;
        if parsed_authority != signer.verifying_key() {
            bail!("new {} descriptor names a different authority", root.name);
        }
        let source = commits
            .iter()
            .copied()
            .filter(|commit| commit.collection() == root.old)
            .collect::<Vec<_>>();
        let expected = expected_target_commits(signer, root.new, &source);
        if let Some(missing) = expected.keys().find(|id| !ids.contains(*id)) {
            bail!("new {} collection is missing COMMIT {missing}", root.name);
        }
        let old_facts = materialize_source(&reader, &source)?;
        let ticket = pile
            .ticket(root.new, &[])
            .map_err(|error| anyhow!("admit new {} collection: {error}", root.name))?;
        let new_facts = pile
            .materialize(&ticket)
            .map_err(|error| anyhow!("materialize new {} collection: {error}", root.name))?;
        if !old_facts.difference(&new_facts).is_empty() {
            bail!(
                "new {} collection does not contain the retired open union",
                root.name
            );
        }
    }
    Ok(())
}

fn finish_pile<T>(pile: Pile, result: Result<T>, operation: &str) -> Result<T> {
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context(format!("close pile after {operation}"))),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing after {operation} also failed: {close_error}"
        ))),
    }
}

pub fn plan_path(pile: &Path, key: Option<&Path>) -> Result<DescriptorAuthorityPlan> {
    let signer = load_signer(pile, key).context("load durable descriptor authority")?;
    let mut store = open_pile_strict(pile)?;
    let result = plan_open(&mut store, &signer);
    finish_pile(store, result, "descriptor-authority planning")
}

/// Stop old-epoch writers before publication. The transform is additive and
/// replayable, but a concurrent old writer could append after the source census.
pub fn publish_path(pile: &Path, key: Option<&Path>) -> Result<DescriptorAuthorityReport> {
    let signer = load_signer(pile, key).context("load durable descriptor authority")?;
    let mut store = open_pile_strict(pile)?;
    let result = publish_open(&mut store, &signer);
    finish_pile(store, result, "descriptor-authority publication")
}

/// Recompute the exact expected target from the still-present retired leaves
/// and prove both record completeness and materialized set equality.
pub fn verify_path(pile: &Path, key: Option<&Path>) -> Result<DescriptorAuthorityPlan> {
    let signer = load_signer(pile, key).context("load durable descriptor authority")?;
    let mut store = open_pile_strict(pile)?;
    let result = (|| {
        let plan = plan_open(&mut store, &signer)?;
        if !plan.settled() {
            bail!("descriptor-authority publication is incomplete");
        }
        verify_open(&mut store, &signer, &plan)?;
        Ok(plan)
    })();
    finish_pile(store, result, "descriptor-authority verification")
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;
    use faculties::storage::initialize_signer;
    use triblespace::core::blob::encodings::UnknownBlob;
    use triblespace::core::collection::{CollectionMerge, CollectionRecord};
    use triblespace::core::repo::BlobStorePut;

    fn store_fragment(pile: &mut Pile, fragment: Fragment) -> CollectionHandle {
        let (_, facts, _, mut blobs) = fragment.into_parts();
        let embedded = blobs
            .reader()
            .expect("memory blob reader")
            .into_iter()
            .map(|(_, blob)| blob)
            .collect::<Vec<Blob<UnknownBlob>>>();
        for blob in embedded {
            pile.put::<UnknownBlob, _>(blob).unwrap();
        }
        pile.put::<SimpleArchive, _>(facts).unwrap()
    }

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

    fn one_fact(seed: u8) -> TribleSet {
        let marker = Id::new([seed; 16]).unwrap();
        entity! { metadata::tag: &marker }.into_facts()
    }

    #[test]
    fn strict_retired_decoder_rejects_an_off_entity_namespace() {
        let signer = SigningKey::from_bytes(&[0x31; 32]);
        let mut descriptor = retired_descriptor(
            "wiki",
            signer.verifying_key(),
            None,
            triblespace::core::collection::reach::private(),
        );
        let wrong = Id::new([0x77; 16]).unwrap();
        let extra = entity! {
            ExclusiveId::force_ref(&wrong) @ retired::collection_namespace: signer.verifying_key()
        };
        descriptor
            .facts_mut()
            .insert(extra.facts().iter().next().unwrap());
        assert!(decode_retired_root(descriptor.facts())
            .unwrap_err()
            .to_string()
            .contains("repeated collection_namespace"));
    }

    #[test]
    fn every_registered_root_is_planned_and_reseated_idempotently() {
        let (_directory, path, key, signer) = fixture();
        let mut pile = open_pile_strict(&path).unwrap();
        let mut expected_names = BTreeSet::new();
        for (index, (_scope, name, reach)) in
            faculties::collection_names::table().into_iter().enumerate()
        {
            expected_names.insert(name.to_owned());
            let old = store_fragment(
                &mut pile,
                retired_descriptor(name, signer.verifying_key(), None, reach),
            );
            let data = pile
                .put::<SimpleArchive, _>(one_fact((index + 1) as u8))
                .unwrap();
            let metadata = pile.put::<SimpleArchive, _>(TribleSet::new()).unwrap();
            pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
                &signer,
                old,
                data.transmute(),
                metadata,
            )))
            .unwrap();
        }
        pile.close().unwrap();

        let planned = plan_path(&path, Some(&key)).unwrap();
        assert_eq!(
            planned
                .roots
                .iter()
                .map(|root| root.name.clone())
                .collect::<BTreeSet<_>>(),
            expected_names
        );
        assert_eq!(planned.missing_commits(), expected_names.len());

        let first = publish_path(&path, Some(&key)).unwrap();
        assert_eq!(first.appended_commits, expected_names.len());
        assert!(first.plan.settled());
        let second = publish_path(&path, Some(&key)).unwrap();
        assert_eq!(second.appended_commits, 0);
        assert!(second.plan.settled());

        // Activation is additive: a later current-epoch leaf may extend the
        // target without invalidating the proof that every retired leaf was
        // carried across.
        let (_scope, name, reach) = faculties::collection_names::table()
            .into_iter()
            .next()
            .unwrap();
        let mut pile = open_pile_strict(&path).unwrap();
        let current = pile
            .collection(simplearchive_union::descriptor(
                name,
                signer.verifying_key(),
                reach,
            ))
            .unwrap();
        pile.commit(current, &signer, Fragment::from(one_fact(0x7f)))
            .unwrap();
        pile.close().unwrap();
        assert!(verify_path(&path, Some(&key)).unwrap().settled());
    }

    #[test]
    fn current_epoch_only_roots_do_not_require_retired_descriptors() {
        let (_directory, path, key, signer) = fixture();
        let (_scope, name, reach) = faculties::collection_names::table()
            .into_iter()
            .next()
            .unwrap();
        let mut pile = open_pile_strict(&path).unwrap();
        let current = pile
            .collection(simplearchive_union::descriptor(
                name,
                signer.verifying_key(),
                reach,
            ))
            .unwrap();
        pile.commit(current, &signer, Fragment::from(one_fact(0x7e)))
            .unwrap();
        pile.close().unwrap();

        let plan = verify_path(&path, Some(&key)).unwrap();
        assert!(plan.roots.is_empty());
        assert!(plan.residues.is_empty());
        assert!(plan.settled());
    }

    #[test]
    fn publication_reuses_handles_collapses_duplicate_open_leaves_and_skips_merges() {
        let (_directory, path, key, signer) = fixture();
        let foreign = SigningKey::from_bytes(&[0x52; 32]);
        let (scope, name, reach) = faculties::collection_names::table()
            .into_iter()
            .next()
            .unwrap();
        let mut pile = open_pile_strict(&path).unwrap();
        let old = store_fragment(
            &mut pile,
            retired_descriptor(name, signer.verifying_key(), None, reach),
        );
        let data = pile.put::<SimpleArchive, _>(one_fact(0x41)).unwrap();
        let metadata = pile.put::<SimpleArchive, _>(TribleSet::new()).unwrap();
        for writer in [&signer, &foreign] {
            pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
                writer,
                old,
                data.transmute(),
                metadata,
            )))
            .unwrap();
        }
        pile.insert(CollectionRecord::Merge(CollectionMerge::new(
            old,
            Inline::new([1; 32]),
            Inline::new([2; 32]),
            Inline::new([3; 32]),
        )))
        .unwrap();
        pile.close().unwrap();

        let report = publish_path(&path, Some(&key)).unwrap();
        let root = report
            .plan
            .roots
            .iter()
            .find(|root| root.scope == scope)
            .unwrap();
        assert_ne!(root.old, root.new);
        assert_eq!(root.source_commits, 2);
        assert_eq!(root.target_commits, 1);
        assert_eq!(root.skipped_merges, 1);
        assert_eq!(root.skipped_derives, 0);
        assert_eq!(report.appended_commits, 1);

        let mut pile = open_pile_strict(&path).unwrap();
        let records = discover_collection_records(&mut pile).unwrap();
        let target = records
            .commits()
            .iter()
            .find(|commit| commit.collection() == root.new)
            .unwrap();
        assert_eq!(target.data(), data.transmute());
        assert_eq!(target.metadata(), metadata);
        assert_eq!(target.public_key().raw, signer.verifying_key().to_bytes());
        assert!(records
            .merges()
            .iter()
            .all(|merge| merge.collection() != root.new));
        pile.close().unwrap();
    }

    #[test]
    fn secrets_and_derived_collections_are_classified_not_translated() {
        let (_directory, path, key, signer) = fixture();
        let mut pile = open_pile_strict(&path).unwrap();
        let secrets = store_fragment(
            &mut pile,
            retired_descriptor(
                "secrets-access",
                signer.verifying_key(),
                None,
                triblespace::core::collection::reach::private(),
            ),
        );
        let derived_fragment = entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            collection_source: secrets,
            collection_authority: signer.verifying_key(),
            collection_representation: <SimpleArchive as MetaDescribe>::id(),
            collection_recipe: simplearchive_union::TRIBLE_SET_UNION_RECIPE_V1,
        };
        let derived = store_fragment(&mut pile, derived_fragment);
        let data = pile.put::<SimpleArchive, _>(one_fact(0x62)).unwrap();
        let metadata = pile.put::<SimpleArchive, _>(TribleSet::new()).unwrap();
        for collection in [secrets, derived] {
            pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
                &signer,
                collection,
                data.transmute(),
                metadata,
            )))
            .unwrap();
        }
        pile.close().unwrap();

        let plan = plan_path(&path, Some(&key)).unwrap();
        assert!(plan.residues.iter().any(|residue| {
            residue.collection == secrets && residue.kind == ResidueKind::SecretsDeferred
        }));
        assert!(plan.residues.iter().any(|residue| {
            residue.collection == derived && residue.kind == ResidueKind::Derived
        }));
    }
}
