//! Additive, handle-aware re-seat of Secrets vaults and access delivery.
//!
//! The retired collection descriptor put a short inline name beside a
//! namespace and optional authority.  The current descriptor puts an
//! unbounded UTF-8 name attachment beside one mandatory authority.  For an
//! ordinary collection the resulting handle change only requires re-signing
//! its leaves.  Secrets additionally binds the exact vault handle into READ
//! and WRITE claims and into each recipient-sealed custody frame.
//!
//! This migration therefore accepts only vaults founded by the durable local
//! signer.  It preserves every canonical source data and metadata handle,
//! opens one strictly valid retired founder envelope to recover the existing
//! custody seed, issues fresh exact proofs over the successor handle, and
//! publishes a new founder envelope before re-signing the leaves.  A vault
//! governed by another authority is reported as requiring a fresh grant; this
//! module never fabricates authority on its behalf.
//!
//! Publication is additive and replayable.  The retired records remain the
//! frozen source, deterministic proof and COMMIT identities collapse exact
//! retries, and an already-valid successor envelope is reused after an
//! interrupted activation.  Planning performs no writes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};

use faculties::secrets::access::{load_access_envelope, open_access_envelope};
use faculties::secrets::schema::KIND_ACCESS_ENVELOPE;
use faculties::secrets::storage::{
    access_inbox_descriptor, access_inbox_handle, founder_proofs, publish_access_envelope,
    VaultLocation,
};
use faculties::secrets::{self, validate_catalog};
use faculties::storage::{load_signer, open_pile_strict};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::{Blob, IntoBlob, TryFromBlob};
use triblespace::core::capability::{
    CapabilityAction, CapabilityMode, CapabilityProofBundle, CapabilityProofId, CapabilityRequest,
    CapabilityResource,
};
use triblespace::core::collection::records::{
    collection_authority, collection_reach, collection_recipe, collection_representation,
    collection_source, CollectionCommit, CollectionHandle, KIND_COLLECTION_DESCRIPTOR,
};
use triblespace::core::collection::simplearchive_union::{self, TribleSetUnionV1};
use triblespace::core::collection::{
    discover_collection_records, CollectionRecord, CollectionStore, CollectionStoreExt,
    ACTION_WRITE,
};
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::ed25519::ED25519PublicKey;
use triblespace::core::inline::encodings::genid::GenId;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::encodings::shortstring::ShortString;
use triblespace::core::inline::{Inline, IntoInline};
use triblespace::core::metadata::{self, MetaDescribe};
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet, CapabilityProofStore};
use triblespace::core::trible::{Fragment, Trible, TribleSet};
use triblespace::macros::{attributes, entity, find, pattern};

mod retired {
    use super::*;

    attributes! {
        "436A04C372CBBFBD9C619CF50F59C4A1" unsafe as pub collection_name: ShortString;
        "6C1ED6495491E32FEBB9FDD4EE5E8907" unsafe as pub collection_namespace: ED25519PublicKey;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultReseat {
    pub vault: Id,
    pub old: CollectionHandle,
    pub new: CollectionHandle,
    pub source_commits: usize,
    pub target_commits: usize,
    pub missing_commits: usize,
    pub access_ready: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegatedVault {
    pub vault: Id,
    pub old: CollectionHandle,
    pub authority: VerifyingKey,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SecretsDescriptorAuthorityPlan {
    pub vaults: Vec<VaultReseat>,
    pub delegated: Vec<DelegatedVault>,
    pub invalid_records: usize,
}

impl SecretsDescriptorAuthorityPlan {
    pub fn missing_commits(&self) -> usize {
        self.vaults.iter().map(|vault| vault.missing_commits).sum()
    }

    pub fn pending_envelopes(&self) -> usize {
        self.vaults
            .iter()
            .filter(|vault| !vault.access_ready)
            .count()
    }

    pub fn blocked(&self) -> bool {
        !self.delegated.is_empty()
    }

    pub fn settled(&self) -> bool {
        !self.blocked() && self.missing_commits() == 0 && self.pending_envelopes() == 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretsDescriptorAuthorityReport {
    pub plan: SecretsDescriptorAuthorityPlan,
    pub appended_commits: usize,
    pub published_envelopes: usize,
    pub persisted_proofs: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RetiredRoot {
    name: String,
    namespace: VerifyingKey,
    authority: Option<VerifyingKey>,
}

#[derive(Clone)]
struct AccessCandidate {
    vault: CollectionHandle,
    custody: SigningKey,
    writer: VerifyingKey,
    write_bundle: CapabilityProofBundle,
}

struct PreparedVault {
    summary: VaultReseat,
    source_facts: TribleSet,
    expected: Vec<CollectionCommit>,
    custody: SigningKey,
    read: CapabilityProofBundle,
    write: CapabilityProofBundle,
}

struct PreparedPlan {
    public: SecretsDescriptorAuthorityPlan,
    vaults: Vec<PreparedVault>,
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

fn descriptor_entity(facts: &TribleSet) -> Result<Id> {
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

fn decode_retired_root(facts: &TribleSet) -> Result<RetiredRoot> {
    let descriptor = descriptor_entity(facts)?;
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
) -> Fragment {
    entity! {
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        retired::collection_name: name,
        retired::collection_namespace: namespace,
        collection_authority?: authority,
        collection_representation*: <SimpleArchive as MetaDescribe>::describe(),
        collection_recipe*: <TribleSetUnionV1 as MetaDescribe>::describe(),
        collection_reach*: triblespace::core::collection::reach::private(),
    }
}

fn retired_inbox_descriptor(recipient: VerifyingKey) -> Fragment {
    retired_descriptor("secrets-access", recipient, None)
}

fn retired_vault_descriptor(
    vault: Id,
    namespace: VerifyingKey,
    authority: VerifyingKey,
) -> Fragment {
    retired_descriptor(&secrets::vault_name(vault), namespace, Some(authority))
}

fn descriptor_handle(fragment: &Fragment) -> CollectionHandle {
    fragment.facts().clone().to_blob().get_handle()
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

fn has_attribute(facts: &TribleSet, attribute: Id) -> bool {
    facts.iter().any(|fact| fact.a() == &attribute)
}

fn discover_retired_vaults(
    reader: &PileReader,
    commits: &[CollectionCommit],
) -> Result<BTreeMap<CollectionHandle, (Id, RetiredRoot)>> {
    let mut vaults = BTreeMap::new();
    let collections = commits
        .iter()
        .map(CollectionCommit::collection)
        .collect::<BTreeSet<_>>();
    for collection in collections {
        let Ok(facts) = descriptor_facts(reader, collection) else {
            continue;
        };
        if !has_attribute(&facts, retired::collection_name.id()) {
            continue;
        }
        let root = decode_retired_root(&facts)
            .with_context(|| format!("strictly decode retired descriptor {collection:?}"))?;
        let Ok(vault) = secrets::parse_vault_name(&root.name) else {
            continue;
        };
        let authority = root
            .authority
            .context("retired Secrets vault descriptor has no authority")?;
        let expected = retired_vault_descriptor(vault, root.namespace, authority);
        if expected.facts() != &facts || descriptor_handle(&expected) != collection {
            bail!("retired vault descriptor for {vault:X} is not the exact supported epoch");
        }
        vaults.insert(collection, (vault, root));
    }
    Ok(vaults)
}

fn load_proof_bundle(
    pile: &mut Pile,
    reader: &PileReader,
    id: CapabilityProofId,
    label: &str,
) -> Result<CapabilityProofBundle> {
    let proof = pile
        .proof(id)
        .map_err(|error| anyhow!("look up exact {label} proof: {error}"))?
        .ok_or_else(|| anyhow!("exact {label} proof is not resident"))?;
    if proof.id() != id {
        bail!("proof store returned the wrong {label} proof id");
    }
    let claims = proof
        .claim_handles()
        .enumerate()
        .map(|(step, handle)| {
            reader
                .get::<Blob<SimpleArchive>, _>(handle)
                .map_err(|error| anyhow!("read {label} claim {step}: {error}"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(CapabilityProofBundle::new(proof, claims))
}

fn inbox_rows(
    pile: &mut Pile,
    reader: &PileReader,
    commits: &[CollectionCommit],
    inbox: CollectionHandle,
    recipient: &SigningKey,
    authorities: &BTreeMap<CollectionHandle, VerifyingKey>,
) -> Vec<AccessCandidate> {
    let instant = triblespace::core::clock::epoch_now();
    let mut candidates = Vec::new();
    for commit in commits.iter().filter(|commit| commit.collection() == inbox) {
        let Ok(publisher) = VerifyingKey::from_bytes(&commit.public_key().raw) else {
            continue;
        };
        let Ok(metadata) = reader.get::<Blob<SimpleArchive>, _>(commit.metadata()) else {
            continue;
        };
        if simplearchive_union::validate_element(&metadata).is_err() {
            continue;
        }
        let data: Inline<Handle<SimpleArchive>> = commit.data().transmute();
        let Ok(data) = reader.get::<Blob<SimpleArchive>, _>(data) else {
            continue;
        };
        let Ok(facts) = TribleSet::try_from_blob(data) else {
            continue;
        };
        let ids = find!(
            id: Id,
            pattern!(&facts, [{ ?id @ metadata::tag: KIND_ACCESS_ENVELOPE }])
        )
        .collect::<BTreeSet<_>>();
        let mut local = Vec::new();
        let mut valid = true;
        for id in ids {
            let result = (|| {
                let row = load_access_envelope(&facts, id)?;
                let authority = authorities
                    .get(&row.vault)
                    .copied()
                    .context("access envelope names an unrecognized vault descriptor")?;
                let read = load_proof_bundle(pile, reader, row.read_proof, "READ")?;
                let write = load_proof_bundle(pile, reader, row.write_proof, "WRITE")?;
                let opened =
                    open_access_envelope(reader, &row, recipient, authority, instant, read, write);
                opened
            })();
            let opened = match result {
                Ok(opened) => opened,
                Err(_) => {
                    valid = false;
                    continue;
                }
            };
            if publisher != opened.read_issuer {
                valid = false;
                continue;
            }
            local.push(AccessCandidate {
                vault: load_access_envelope(&facts, id)
                    .expect("the row was validated above")
                    .vault,
                custody: opened.custody,
                writer: opened.writer,
                write_bundle: opened.write_bundle,
            });
        }
        if valid {
            candidates.extend(local);
        }
    }
    candidates
}

fn write_request(collection: CollectionHandle) -> CapabilityRequest {
    CapabilityRequest::new(
        triblespace::core::capability::CapabilityAtom::new(
            CapabilityAction::new(ACTION_WRITE),
            CapabilityResource::from(collection),
        ),
        CapabilityMode::Invoke,
    )
}

fn authorized_source_commits(
    commits: &[CollectionCommit],
    collection: CollectionHandle,
    authority: VerifyingKey,
    candidates: &[AccessCandidate],
) -> Result<Vec<CollectionCommit>> {
    let instant = triblespace::core::clock::epoch_now();
    let mut authorized = Vec::new();
    for commit in commits
        .iter()
        .copied()
        .filter(|commit| commit.collection() == collection)
    {
        let writer = VerifyingKey::from_bytes(&commit.public_key().raw)
            .context("retired vault COMMIT has an invalid writer key")?;
        let admitted = writer == authority
            || candidates.iter().any(|candidate| {
                candidate.vault == collection
                    && candidate.writer == writer
                    && candidate
                        .write_bundle
                        .verify(authority, instant, writer, write_request(collection))
                        .is_ok_and(|verified| verified.effective_validity().is_none())
            });
        if !admitted {
            bail!(
                "retired vault {} has COMMIT {} by a writer with no exact unbounded WRITE proof",
                hex::encode_upper(collection.raw),
                commit.id()
            );
        }
        authorized.push(commit);
    }
    Ok(authorized)
}

fn materialize_source(reader: &PileReader, commits: &[CollectionCommit]) -> Result<TribleSet> {
    let mut facts = TribleSet::new();
    let mut seen = BTreeSet::new();
    for commit in commits {
        let data: Inline<Handle<SimpleArchive>> = commit.data().transmute();
        if seen.insert(data) {
            let blob: Blob<SimpleArchive> = reader
                .get(data)
                .with_context(|| format!("read source data {}", hex::encode_upper(data.raw)))?;
            simplearchive_union::validate_element(&blob)
                .context("validate source collection element")?;
            facts += TribleSet::try_from_blob(blob).context("decode source collection element")?;
        }
        let metadata: Blob<SimpleArchive> = reader
            .get(commit.metadata())
            .with_context(|| format!("read source metadata for COMMIT {}", commit.id()))?;
        simplearchive_union::validate_element(&metadata)
            .context("validate source collection metadata")?;
    }
    Ok(facts)
}

fn expected_target_commits(
    signer: &SigningKey,
    target: CollectionHandle,
    source: &[CollectionCommit],
) -> Vec<CollectionCommit> {
    source
        .iter()
        .map(|commit| {
            let target = CollectionCommit::sign(signer, target, commit.data(), commit.metadata());
            (target.id(), target)
        })
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect()
}

fn matching_custody(
    expected: [u8; 32],
    old: &[AccessCandidate],
    current: &[AccessCandidate],
    old_handle: CollectionHandle,
    new_handle: CollectionHandle,
) -> Result<(SigningKey, bool)> {
    let old = old
        .iter()
        .filter(|candidate| {
            candidate.vault == old_handle
                && candidate.custody.verifying_key().to_bytes() == expected
        })
        .map(|candidate| candidate.custody.clone());
    let current_matches = current
        .iter()
        .filter(|candidate| {
            candidate.vault == new_handle
                && candidate.custody.verifying_key().to_bytes() == expected
        })
        .collect::<Vec<_>>();
    let mut keys = old
        .chain(
            current_matches
                .iter()
                .map(|candidate| candidate.custody.clone()),
        )
        .collect::<Vec<_>>();
    let first = keys
        .pop()
        .context("vault has no valid old or current founder envelope for its custody key")?;
    if keys
        .iter()
        .any(|candidate| candidate.to_bytes() != first.to_bytes())
    {
        bail!("valid access envelopes disagree on the custody seed");
    }
    Ok((first, !current_matches.is_empty()))
}

fn plan_open(pile: &mut Pile, signer: &SigningKey) -> Result<PreparedPlan> {
    let discovered = discover_collection_records(&mut *pile)
        .context("discover records for Secrets descriptor-authority migration")?;
    let commits = discovered.commits().to_vec();
    let existing_ids = commits
        .iter()
        .map(CollectionCommit::id)
        .collect::<BTreeSet<_>>();
    let invalid_records = discovered.diagnostics().len();
    let reader = pile.reader().context("open Secrets migration reader")?;
    let retired_vaults = discover_retired_vaults(&reader, &commits)?;
    let authority_map = retired_vaults
        .iter()
        .map(|(handle, (_, root))| {
            (
                *handle,
                root.authority.expect("vault discovery requires authority"),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let old_inbox_descriptor = retired_inbox_descriptor(signer.verifying_key());
    let old_inbox = descriptor_handle(&old_inbox_descriptor);
    if commits
        .iter()
        .any(|commit| commit.collection() == old_inbox)
    {
        let resident = descriptor_facts(&reader, old_inbox)
            .context("read retired local Secrets access-inbox descriptor")?;
        if resident != *old_inbox_descriptor.facts() {
            bail!("retired local Secrets access inbox is not the exact supported epoch");
        }
    }
    let old_candidates = inbox_rows(pile, &reader, &commits, old_inbox, signer, &authority_map);

    let current_inbox = access_inbox_handle(signer.verifying_key());
    let current_authorities = retired_vaults
        .values()
        .map(|(vault, root)| {
            let authority = root.authority.expect("vault discovery requires authority");
            (secrets::vault_handle(*vault, authority), authority)
        })
        .collect::<BTreeMap<_, _>>();
    if commits
        .iter()
        .any(|commit| commit.collection() == current_inbox)
    {
        let resident = descriptor_facts(&reader, current_inbox)
            .context("read current local Secrets access-inbox descriptor")?;
        if resident != *access_inbox_descriptor(signer.verifying_key()).facts() {
            bail!("current local Secrets access inbox has a noncanonical descriptor");
        }
    }
    let current_candidates = inbox_rows(
        pile,
        &reader,
        &commits,
        current_inbox,
        signer,
        &current_authorities,
    );

    let mut public = SecretsDescriptorAuthorityPlan {
        vaults: Vec::new(),
        delegated: Vec::new(),
        invalid_records,
    };
    let mut prepared = Vec::new();
    for (old, (vault, root)) in retired_vaults {
        let source_count = commits
            .iter()
            .filter(|commit| commit.collection() == old)
            .count();
        if source_count == 0 {
            continue;
        }
        let authority = root.authority.expect("vault discovery requires authority");
        if authority != signer.verifying_key() {
            public.delegated.push(DelegatedVault {
                vault,
                old,
                authority,
                reason: "vault authority is not the durable local signer; obtain a successor-handle regrant from the founder".to_owned(),
            });
            continue;
        }

        let source = authorized_source_commits(&commits, old, authority, &old_candidates)?;
        let source_facts = materialize_source(&reader, &source)?;
        let catalog = validate_catalog(&reader, vault, &source_facts)
            .with_context(|| format!("validate retired vault {vault:X}"))?;
        let custody_public = catalog
            .custody
            .context("retired capability-native vault has no custody declaration")?
            .public_key;
        let new = secrets::vault_handle(vault, authority);
        let (custody, access_ready) = matching_custody(
            custody_public,
            &old_candidates,
            &current_candidates,
            old,
            new,
        )?;
        let location = VaultLocation::new(vault, authority);
        if location.collection() != new {
            bail!("current vault location changed identity while planning");
        }
        let (read, write) = founder_proofs(signer, location);
        let expected = expected_target_commits(signer, new, &source);
        let missing_commits = expected
            .iter()
            .filter(|commit| !existing_ids.contains(&commit.id()))
            .count();
        let summary = VaultReseat {
            vault,
            old,
            new,
            source_commits: source_count,
            target_commits: expected.len(),
            missing_commits,
            access_ready,
        };
        public.vaults.push(summary.clone());
        prepared.push(PreparedVault {
            summary,
            source_facts,
            expected,
            custody,
            read,
            write,
        });
    }
    public.vaults.sort_by_key(|vault| (vault.vault, vault.old));
    public
        .delegated
        .sort_by_key(|vault| (vault.vault, vault.old));
    prepared.sort_by_key(|vault| (vault.summary.vault, vault.summary.old));
    Ok(PreparedPlan {
        public,
        vaults: prepared,
    })
}

fn proof_ids(pile: &mut Pile) -> Result<BTreeSet<CapabilityProofId>> {
    pile.proofs()
        .map_err(|error| anyhow!("enumerate capability proofs: {error}"))?
        .map(|proof| {
            proof
                .map(|proof| proof.id())
                .map_err(|error| anyhow!("read capability proof: {error}"))
        })
        .collect()
}

fn publish_open(pile: &mut Pile, signer: &SigningKey) -> Result<SecretsDescriptorAuthorityReport> {
    let before = plan_open(pile, signer)?;
    if !before.public.delegated.is_empty() {
        let blocked = before
            .public
            .delegated
            .iter()
            .map(|vault| format!("{:X}", vault.vault))
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "Secrets descriptor-authority activation requires fresh grants for delegated vaults: {blocked}"
        );
    }
    let existing = discover_collection_records(&mut *pile)
        .context("rediscover target records before Secrets publication")?
        .commits()
        .iter()
        .map(CollectionCommit::id)
        .collect::<BTreeSet<_>>();
    let proofs_before = proof_ids(pile)?;
    let mut appended_commits = 0;
    let mut published_envelopes = 0;

    for vault in &before.vaults {
        let descriptor = secrets::vault_descriptor(vault.summary.vault, signer.verifying_key());
        let registered = pile
            .collection(descriptor)
            .map_err(|error| anyhow!("register current vault descriptor: {error}"))?;
        if registered != vault.summary.new {
            bail!("registered current vault descriptor changed identity");
        }
        if !vault.summary.access_ready {
            publish_access_envelope(
                pile,
                signer,
                VaultLocation::new(vault.summary.vault, signer.verifying_key()),
                &vault.custody,
                signer.verifying_key(),
                &vault.read,
                signer.verifying_key(),
                &vault.write,
                triblespace::core::clock::epoch_now(),
            )
            .with_context(|| {
                format!(
                    "publish successor founder envelope for vault {:X}",
                    vault.summary.vault
                )
            })?;
            published_envelopes += 1;
        }
        for commit in &vault.expected {
            if existing.contains(&commit.id()) {
                continue;
            }
            pile.insert(CollectionRecord::Commit(*commit))
                .map_err(|error| anyhow!("append re-seated Secrets COMMIT: {error}"))?;
            appended_commits += 1;
        }
    }

    let proofs_after = proof_ids(pile)?;
    let persisted_proofs = proofs_after.difference(&proofs_before).count();
    let after = plan_open(pile, signer)?;
    verify_open(pile, signer, &after)?;
    if !after.public.settled() {
        bail!("Secrets descriptor-authority publication did not settle");
    }
    Ok(SecretsDescriptorAuthorityReport {
        plan: after.public,
        appended_commits,
        published_envelopes,
        persisted_proofs,
    })
}

fn verify_open(pile: &mut Pile, signer: &SigningKey, plan: &PreparedPlan) -> Result<()> {
    let records = discover_collection_records(&mut *pile)
        .context("discover records for Secrets migration verification")?;
    let ids = records
        .commits()
        .iter()
        .map(CollectionCommit::id)
        .collect::<BTreeSet<_>>();
    for vault in &plan.vaults {
        if vault
            .expected
            .iter()
            .any(|commit| !ids.contains(&commit.id()))
        {
            bail!(
                "current vault {:X} is missing an expected re-seated COMMIT",
                vault.summary.vault
            );
        }
        let snapshot = pile
            .snapshot(vault.summary.new, &[])
            .map_err(|error| anyhow!("snapshot migrated vault: {error}"))?;
        if !vault.source_facts.difference(snapshot.facts()).is_empty() {
            bail!(
                "current vault {:X} does not contain the retired fact union",
                vault.summary.vault
            );
        }
    }
    let discovery = faculties::secrets::storage::discover_local_vaults(pile, signer)
        .context("discover migrated Secrets vaults through the runtime path")?;
    for vault in &plan.vaults {
        let ready = discovery
            .snapshot()
            .vault_exact(vault.summary.new)
            .with_context(|| {
                format!(
                    "runtime discovery did not admit migrated vault {:X}",
                    vault.summary.vault
                )
            })?;
        if ready.catalog().custody.map(|row| row.public_key)
            != Some(vault.custody.verifying_key().to_bytes())
        {
            bail!("migrated vault custody differs from the retired custody seed");
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

pub fn plan_path(pile: &Path, key: Option<&Path>) -> Result<SecretsDescriptorAuthorityPlan> {
    let signer = load_signer(pile, key).context("load durable Secrets authority")?;
    let mut store = open_pile_strict(pile)?;
    let result = plan_open(&mut store, &signer).map(|plan| plan.public);
    finish_pile(store, result, "Secrets descriptor-authority planning")
}

/// Stop retired Secrets writers before activation so the source census cannot
/// gain a late leaf after its successor is verified.
pub fn publish_path(pile: &Path, key: Option<&Path>) -> Result<SecretsDescriptorAuthorityReport> {
    let signer = load_signer(pile, key).context("load durable Secrets authority")?;
    let mut store = open_pile_strict(pile)?;
    let result = publish_open(&mut store, &signer);
    finish_pile(store, result, "Secrets descriptor-authority publication")
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::path::PathBuf;

    use hifitime::Epoch;

    use super::*;
    use faculties::secrets::access::build_access_envelope;
    use faculties::secrets::storage::{discover_local_vaults, persist_proof_bundle};
    use faculties::storage::initialize_signer;
    use triblespace::core::blob::encodings::UnknownBlob;
    use triblespace::core::capability::{CapabilityAtom, CapabilityClaim};
    use triblespace::core::repo::BlobStorePut;
    use triblespace::prelude::TryToInline;

    struct Fixture {
        _directory: tempfile::TempDir,
        pile: PathBuf,
        key: PathBuf,
        signer: SigningKey,
        custody: SigningKey,
        vault: Id,
        source: Vec<CollectionCommit>,
        secret: Id,
    }

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn at(second: i64) -> secrets::IntervalValue {
        let instant = Epoch::from_unix_seconds(second as f64);
        (instant, instant).try_to_inline().unwrap()
    }

    fn store_fragment(pile: &mut Pile, fragment: Fragment) -> CollectionHandle {
        let (_, facts, _, mut blobs) = fragment.into_parts();
        let embedded = blobs
            .reader()
            .unwrap()
            .into_iter()
            .map(|(_, blob)| blob)
            .collect::<Vec<Blob<UnknownBlob>>>();
        for blob in embedded {
            pile.put::<UnknownBlob, _>(blob).unwrap();
        }
        pile.put::<SimpleArchive, _>(facts).unwrap()
    }

    fn commit_fragment(
        pile: &mut Pile,
        signer: &SigningKey,
        collection: CollectionHandle,
        fragment: Fragment,
    ) -> CollectionCommit {
        let (_, facts, metafacts, mut blobs) = fragment.into_parts();
        let embedded = blobs
            .reader()
            .unwrap()
            .into_iter()
            .map(|(_, blob)| blob)
            .collect::<Vec<Blob<UnknownBlob>>>();
        for blob in embedded {
            pile.put::<UnknownBlob, _>(blob).unwrap();
        }
        let data = pile.put::<SimpleArchive, _>(facts).unwrap();
        let metadata = pile.put::<SimpleArchive, _>(metafacts).unwrap();
        let commit = CollectionCommit::sign(signer, collection, data.transmute(), metadata);
        pile.insert(CollectionRecord::Commit(commit)).unwrap();
        commit
    }

    fn root_bundle(
        root: &SigningKey,
        collection: CollectionHandle,
        action: Id,
    ) -> CapabilityProofBundle {
        let atom = CapabilityAtom::new(
            CapabilityAction::new(action),
            CapabilityResource::from(collection),
        );
        CapabilityProofBundle::issue_root(
            root,
            CapabilityClaim::root(atom, CapabilityMode::InvokeAndDelegate, None),
            root.verifying_key(),
        )
        .unwrap()
    }

    fn founder_fixture() -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("test.pile");
        let key_path = directory.path().join("test.key");
        File::create(&pile_path).unwrap();
        let signer = initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let vault = id(0x21);
        let custody = key(0x22);
        let old_descriptor =
            retired_vault_descriptor(vault, signer.verifying_key(), signer.verifying_key());
        let old = descriptor_handle(&old_descriptor);
        let old_inbox_descriptor = retired_inbox_descriptor(signer.verifying_key());
        let old_inbox = descriptor_handle(&old_inbox_descriptor);
        let mut pile = open_pile_strict(&pile_path).unwrap();
        assert_eq!(store_fragment(&mut pile, old_descriptor), old);
        assert_eq!(store_fragment(&mut pile, old_inbox_descriptor), old_inbox);

        let header = secrets::vault_header_fragment(
            vault,
            "production",
            at(1),
            custody.verifying_key().to_bytes(),
        )
        .unwrap();
        let sealed = secrets::seal_version(
            "api token",
            b"correct horse battery staple",
            custody.verifying_key().to_bytes(),
            at(2),
        )
        .unwrap();
        let secret = sealed.secret;
        let source = vec![
            commit_fragment(&mut pile, &signer, old, header),
            commit_fragment(&mut pile, &signer, old, sealed.fragment),
        ];

        let read = root_bundle(&signer, old, secrets::ACTION_READ);
        let write = root_bundle(&signer, old, ACTION_WRITE);
        persist_proof_bundle(&mut pile, &read).unwrap();
        persist_proof_bundle(&mut pile, &write).unwrap();
        let envelope = build_access_envelope(
            old,
            &custody,
            signer.verifying_key(),
            &read,
            signer.verifying_key(),
            &write,
            signer.verifying_key(),
            triblespace::core::clock::epoch_now(),
        )
        .unwrap();
        commit_fragment(&mut pile, &signer, old_inbox, envelope);
        pile.close().unwrap();

        Fixture {
            _directory: directory,
            pile: pile_path,
            key: key_path,
            signer,
            custody,
            vault,
            source,
            secret,
        }
    }

    #[test]
    fn founder_vault_preserves_exact_leaves_custody_and_plaintext_and_replays_exactly() {
        let fixture = founder_fixture();
        let bytes_before_plan = fs::read(&fixture.pile).unwrap();
        let plan = plan_path(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(fs::read(&fixture.pile).unwrap(), bytes_before_plan);
        assert_eq!(plan.vaults.len(), 1);
        assert!(plan.delegated.is_empty());
        assert_eq!(plan.vaults[0].source_commits, 2);
        assert_eq!(plan.vaults[0].target_commits, 2);
        assert_eq!(plan.vaults[0].missing_commits, 2);
        assert!(!plan.vaults[0].access_ready);

        let report = publish_path(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(report.appended_commits, 2);
        assert_eq!(report.published_envelopes, 1);
        assert_eq!(report.persisted_proofs, 2);
        assert!(report.plan.settled());

        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        let records = discover_collection_records(&mut pile).unwrap();
        let target = secrets::vault_handle(fixture.vault, fixture.signer.verifying_key());
        let source_pairs = fixture
            .source
            .iter()
            .map(|commit| (commit.data(), commit.metadata()))
            .collect::<BTreeSet<_>>();
        let target_pairs = records
            .commits()
            .iter()
            .filter(|commit| commit.collection() == target)
            .map(|commit| (commit.data(), commit.metadata()))
            .collect::<BTreeSet<_>>();
        assert_eq!(target_pairs, source_pairs);
        assert!(fixture
            .source
            .iter()
            .all(|source| records.commits().contains(source)));
        let discovery = discover_local_vaults(&mut pile, &fixture.signer).unwrap();
        let vault = discovery.snapshot().vault_exact(target).unwrap();
        assert_eq!(
            discovery
                .snapshot()
                .open_exact(target, fixture.secret, &fixture.signer)
                .unwrap(),
            b"correct horse battery staple"
        );
        assert_eq!(
            vault.catalog().custody.unwrap().public_key,
            key(0x22).verifying_key().to_bytes()
        );
        pile.close().unwrap();

        let replay = publish_path(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(replay.appended_commits, 0);
        assert_eq!(replay.published_envelopes, 0);
        assert_eq!(replay.persisted_proofs, 0);
        assert!(replay.plan.settled());
    }

    #[test]
    fn partial_target_commit_is_completed_without_rewriting_the_existing_leaf() {
        let fixture = founder_fixture();
        let target = secrets::vault_handle(fixture.vault, fixture.signer.verifying_key());
        let partial = CollectionCommit::sign(
            &fixture.signer,
            target,
            fixture.source[0].data(),
            fixture.source[0].metadata(),
        );
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        let registered = pile
            .collection(secrets::vault_descriptor(
                fixture.vault,
                fixture.signer.verifying_key(),
            ))
            .unwrap();
        assert_eq!(registered, target);
        let location = VaultLocation::new(fixture.vault, fixture.signer.verifying_key());
        let (read, write) = founder_proofs(&fixture.signer, location);
        publish_access_envelope(
            &mut pile,
            &fixture.signer,
            location,
            &fixture.custody,
            fixture.signer.verifying_key(),
            &read,
            fixture.signer.verifying_key(),
            &write,
            triblespace::core::clock::epoch_now(),
        )
        .unwrap();
        pile.insert(CollectionRecord::Commit(partial)).unwrap();
        pile.close().unwrap();

        let plan = plan_path(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(plan.missing_commits(), 1);
        assert_eq!(plan.pending_envelopes(), 0);
        let report = publish_path(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(report.appended_commits, 1);
        assert_eq!(report.published_envelopes, 0);
        assert_eq!(report.persisted_proofs, 0);
        assert!(report.plan.settled());

        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        let records = discover_collection_records(&mut pile).unwrap();
        assert_eq!(
            records
                .commits()
                .iter()
                .filter(|commit| commit.id() == partial.id())
                .count(),
            1
        );
        pile.close().unwrap();
    }

    #[test]
    fn delegated_vault_is_reported_and_activation_writes_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("test.pile");
        let key_path = directory.path().join("test.key");
        File::create(&pile_path).unwrap();
        let local = initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let founder = key(0x61);
        let vault = id(0x62);
        let old_descriptor =
            retired_vault_descriptor(vault, founder.verifying_key(), founder.verifying_key());
        let old = descriptor_handle(&old_descriptor);
        let mut pile = open_pile_strict(&pile_path).unwrap();
        assert_eq!(store_fragment(&mut pile, old_descriptor), old);
        let header = secrets::vault_header_fragment(
            vault,
            "delegated",
            at(1),
            key(0x63).verifying_key().to_bytes(),
        )
        .unwrap();
        commit_fragment(&mut pile, &founder, old, header);
        pile.close().unwrap();

        let plan = plan_path(&pile_path, Some(&key_path)).unwrap();
        assert!(plan.vaults.is_empty());
        assert_eq!(plan.delegated.len(), 1);
        assert_eq!(plan.delegated[0].authority, founder.verifying_key());
        assert!(plan.blocked());
        let bytes_before = fs::read(&pile_path).unwrap();
        let error = publish_path(&pile_path, Some(&key_path)).unwrap_err();
        assert!(error.to_string().contains("requires fresh grants"));
        assert_eq!(fs::read(&pile_path).unwrap(), bytes_before);
        assert_ne!(local.verifying_key(), founder.verifying_key());
    }
}
