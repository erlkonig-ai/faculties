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
    access_inbox_descriptor, access_inbox_handle, founder_proofs, persist_proof_bundle,
    publish_access_envelope, VaultLocation,
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
    discover_collection_records, CapabilityPresentation, CollectionRecord, CollectionStore,
    CollectionStoreExt, ACTION_WRITE,
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
    pub authority: VerifyingKey,
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

struct RetiredVaultDiscovery {
    vaults: BTreeMap<CollectionHandle, (Id, RetiredRoot)>,
    unreadable: BTreeMap<CollectionHandle, String>,
}

#[derive(Clone)]
struct AccessCandidate {
    inbox_commit: CollectionCommit,
    vault: CollectionHandle,
    custody: SigningKey,
    read_issuer: VerifyingKey,
    read_bundle: CapabilityProofBundle,
    writer: VerifyingKey,
    write_bundle: CapabilityProofBundle,
}

struct PreparedVault {
    summary: VaultReseat,
    source_facts: TribleSet,
    source: Vec<CollectionCommit>,
    expected: Vec<CollectionCommit>,
    source_ids: BTreeSet<Id>,
    current_record_ids: BTreeSet<Id>,
    current_ids: BTreeSet<Id>,
    presentation: Vec<CapabilityPresentation>,
    successor_inbox_commits: Vec<CollectionCommit>,
    successor_proofs: Vec<CapabilityProofBundle>,
    custody: SigningKey,
    founder_access: Option<(CapabilityProofBundle, CapabilityProofBundle)>,
}

struct PreparedPlan {
    public: SecretsDescriptorAuthorityPlan,
    vaults: Vec<PreparedVault>,
    old_inbox_ids: BTreeSet<Id>,
    current_inbox_ids: BTreeSet<Id>,
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
) -> Result<RetiredVaultDiscovery> {
    let mut vaults = BTreeMap::new();
    let mut unreadable = BTreeMap::new();
    let collections = commits
        .iter()
        .map(CollectionCommit::collection)
        .collect::<BTreeSet<_>>();
    for collection in collections {
        let facts = match descriptor_facts(reader, collection) {
            Ok(facts) => facts,
            Err(error) => {
                unreadable.insert(
                    collection,
                    format!(
                        "read descriptor referenced by COMMITs for {}: {error:#}",
                        hex::encode_upper(collection.raw)
                    ),
                );
                continue;
            }
        };
        if !has_attribute(&facts, retired::collection_name.id()) {
            continue;
        }
        let root = decode_retired_root(&facts)
            .with_context(|| format!("strictly decode retired descriptor {collection:?}"))?;
        let vault = match secrets::parse_vault_name(&root.name) {
            Ok(vault) => vault,
            Err(error) if root.name.starts_with(secrets::VAULT_NAME_PREFIX) => {
                return Err(error).context("decode recognizable retired Secrets vault name")
            }
            Err(_) => continue,
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
    Ok(RetiredVaultDiscovery { vaults, unreadable })
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
                inbox_commit: *commit,
                vault: load_access_envelope(&facts, id)
                    .expect("the row was validated above")
                    .vault,
                custody: opened.custody,
                read_issuer: opened.read_issuer,
                read_bundle: opened.read_bundle,
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
    current: &[CollectionCommit],
) -> Vec<CollectionCommit> {
    let current_pairs = current
        .iter()
        .map(|commit| (commit.data(), commit.metadata()))
        .collect::<BTreeSet<_>>();
    source
        .iter()
        .filter(|commit| !current_pairs.contains(&(commit.data(), commit.metadata())))
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
) -> Result<SigningKey> {
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
    Ok(first)
}

fn exact_founder_access(
    candidates: &[AccessCandidate],
    collection: CollectionHandle,
    authority: VerifyingKey,
    custody_public: [u8; 32],
    read: &CapabilityProofBundle,
    write: &CapabilityProofBundle,
) -> bool {
    candidates.iter().any(|candidate| {
        candidate.vault == collection
            && candidate.custody.verifying_key().to_bytes() == custody_public
            && candidate.read_issuer == authority
            && candidate.read_bundle.proof().id() == read.proof().id()
            && candidate.writer == authority
            && candidate.write_bundle.proof().id() == write.proof().id()
    })
}

fn unbounded_write_presentation(
    candidate: &AccessCandidate,
    authority: VerifyingKey,
    subject: VerifyingKey,
    collection: CollectionHandle,
    custody_public: [u8; 32],
) -> bool {
    candidate.vault == collection
        && candidate.custody.verifying_key().to_bytes() == custody_public
        && candidate.writer == subject
        && candidate
            .write_bundle
            .verify(
                authority,
                triblespace::core::clock::epoch_now(),
                subject,
                write_request(collection),
            )
            .is_ok_and(|verified| verified.effective_validity().is_none())
}

fn current_presentations(
    candidates: &[AccessCandidate],
    collection: CollectionHandle,
) -> Vec<CapabilityPresentation> {
    candidates
        .iter()
        .filter(|candidate| candidate.vault == collection)
        .map(|candidate| {
            (
                (
                    candidate.writer.to_bytes(),
                    candidate.write_bundle.proof().id().raw,
                ),
                CapabilityPresentation::new(candidate.writer, candidate.write_bundle.clone()),
            )
        })
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect()
}

fn successor_proofs(
    candidates: &[AccessCandidate],
    collection: CollectionHandle,
) -> Vec<CapabilityProofBundle> {
    candidates
        .iter()
        .filter(|candidate| candidate.vault == collection)
        .flat_map(|candidate| {
            [
                candidate.read_bundle.clone(),
                candidate.write_bundle.clone(),
            ]
        })
        .map(|bundle| (bundle.proof().id(), bundle))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect()
}

fn successor_inbox_commits(
    candidates: &[AccessCandidate],
    collection: CollectionHandle,
) -> Vec<CollectionCommit> {
    candidates
        .iter()
        .filter(|candidate| candidate.vault == collection)
        .map(|candidate| (candidate.inbox_commit.id(), candidate.inbox_commit))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect()
}

fn potentially_admitted_current_record(
    commits: &[CollectionCommit],
    collection: CollectionHandle,
    authority: VerifyingKey,
    candidates: &[AccessCandidate],
) -> bool {
    let authority = authority.to_bytes();
    let delegated = candidates
        .iter()
        .filter(|candidate| candidate.vault == collection)
        .map(|candidate| candidate.writer.to_bytes())
        .collect::<BTreeSet<_>>();
    commits
        .iter()
        .filter(|commit| commit.collection() == collection)
        .any(|commit| {
            commit.public_key().raw == authority || delegated.contains(&commit.public_key().raw)
        })
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
    let discovery = discover_retired_vaults(&reader, &commits)?;
    let authority_map = discovery
        .vaults
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
    let old_candidates = inbox_rows(pile, &reader, &commits, old_inbox, signer, &authority_map);
    if !old_candidates.is_empty() {
        let resident = descriptor_facts(&reader, old_inbox)
            .context("read retired local Secrets access-inbox descriptor")?;
        if resident != *old_inbox_descriptor.facts() {
            bail!("retired local Secrets access inbox is not the exact supported epoch");
        }
    }

    let current_inbox = access_inbox_handle(signer.verifying_key());
    let current_authorities = discovery
        .vaults
        .values()
        .map(|(vault, root)| {
            let authority = root.authority.expect("vault discovery requires authority");
            (secrets::vault_handle(*vault, authority), authority)
        })
        .collect::<BTreeMap<_, _>>();
    let current_candidates = inbox_rows(
        pile,
        &reader,
        &commits,
        current_inbox,
        signer,
        &current_authorities,
    );
    if !current_candidates.is_empty() {
        let resident = descriptor_facts(&reader, current_inbox)
            .context("read current local Secrets access-inbox descriptor")?;
        if resident != *access_inbox_descriptor(signer.verifying_key()).facts() {
            bail!("current local Secrets access inbox has a noncanonical descriptor");
        }
    }

    for (collection, error) in &discovery.unreadable {
        let inert_inbox = (*collection == old_inbox && old_candidates.is_empty())
            || (*collection == current_inbox && current_candidates.is_empty());
        let inert_successor = current_authorities
            .get(collection)
            .is_some_and(|authority| {
                !potentially_admitted_current_record(
                    &commits,
                    *collection,
                    *authority,
                    &current_candidates,
                )
            });
        if !inert_inbox && !inert_successor {
            bail!("{error}");
        }
    }

    let mut public = SecretsDescriptorAuthorityPlan {
        vaults: Vec::new(),
        delegated: Vec::new(),
        invalid_records,
    };
    let mut prepared = Vec::new();
    for (old, (vault, root)) in discovery.vaults {
        let source_count = commits
            .iter()
            .filter(|commit| commit.collection() == old)
            .count();
        if source_count == 0 {
            continue;
        }
        let authority = root.authority.expect("vault discovery requires authority");
        if root.namespace != authority {
            bail!(
                "retired vault {vault:X} uses namespace {} but authority {}; refusing a many-to-one descriptor collapse",
                hex::encode_upper(root.namespace.to_bytes()),
                hex::encode_upper(authority.to_bytes()),
            );
        }
        let source = authorized_source_commits(&commits, old, authority, &old_candidates)?;
        let source_facts = materialize_source(&reader, &source)?;
        let new = secrets::vault_handle(vault, authority);
        let presentation = current_presentations(&current_candidates, new);
        let current_record_ids = commits
            .iter()
            .filter(|commit| commit.collection() == new)
            .map(CollectionCommit::id)
            .collect::<BTreeSet<_>>();
        let mut prospective_facts = source_facts.clone();
        let current = if !potentially_admitted_current_record(
            &commits,
            new,
            authority,
            &current_candidates,
        ) {
            Vec::new()
        } else {
            let expected_descriptor = secrets::vault_descriptor(vault, authority);
            let resident = descriptor_facts(&reader, new)
                .with_context(|| format!("read current vault descriptor for {vault:X}"))?;
            if resident != *expected_descriptor.facts() {
                bail!("current vault descriptor for {vault:X} is not canonical");
            }
            let ticket = pile
                .ticket(new, &presentation)
                .map_err(|error| anyhow!("admit current vault {vault:X}: {error}"))?;
            prospective_facts += pile
                .materialize(&ticket)
                .map_err(|error| anyhow!("materialize current vault {vault:X}: {error}"))?;
            ticket.commits().to_vec()
        };
        let current_ids = current
            .iter()
            .map(CollectionCommit::id)
            .collect::<BTreeSet<_>>();
        // Namespace removal is many-to-one in principle. The historical
        // namespace==authority invariant above makes the old source unique;
        // validating its union with every admitted current leaf here proves
        // the target catalog cannot be poisoned before the first append.
        let catalog = validate_catalog(&reader, vault, &prospective_facts)
            .with_context(|| format!("validate prospective successor vault {vault:X}"))?;
        let custody_public = catalog
            .custody
            .context("retired capability-native vault has no custody declaration")?
            .public_key;
        let location = VaultLocation::new(vault, authority);
        if location.collection() != new {
            bail!("current vault location changed identity while planning");
        }
        // A founder's own assertions are the durable basis of its collection.
        // A currently admitted delegated writer may later expire, and the new
        // deterministic founder envelope does not preserve that writer's
        // grant. Only a delegated replica may treat its admitted target pairs
        // as the surviving basis and avoid re-signing them locally.
        let coverage = if authority == signer.verifying_key() {
            current
                .iter()
                .copied()
                .filter(|commit| commit.public_key().raw == authority.to_bytes())
                .collect::<Vec<_>>()
        } else {
            current.clone()
        };
        let expected = expected_target_commits(signer, new, &source, &coverage);
        let successor_read_ready = current_candidates.iter().any(|candidate| {
            candidate.vault == new && candidate.custody.verifying_key().to_bytes() == custody_public
        });
        let delegated_successor_grant = authority != signer.verifying_key()
            && current_candidates.iter().any(|candidate| {
                unbounded_write_presentation(
                    candidate,
                    authority,
                    signer.verifying_key(),
                    new,
                    custody_public,
                )
            });
        if authority != signer.verifying_key()
            && (!successor_read_ready || (!expected.is_empty() && !delegated_successor_grant))
        {
            let reason = if !successor_read_ready {
                "obtain a valid successor-handle READ/custody envelope"
            } else {
                "some retired leaves are absent from the admitted successor; obtain an unbounded successor WRITE grant for the local signer or have an authorized writer publish those exact data/metadata pairs"
            };
            public.delegated.push(DelegatedVault {
                vault,
                old,
                authority,
                reason: reason.to_owned(),
            });
            continue;
        }
        let custody = matching_custody(
            custody_public,
            &old_candidates,
            &current_candidates,
            old,
            new,
        )?;
        let (access_ready, founder_access) = if authority == signer.verifying_key() {
            let (read, write) = founder_proofs(signer, location);
            (
                exact_founder_access(
                    &current_candidates,
                    new,
                    authority,
                    custody_public,
                    &read,
                    &write,
                ),
                Some((read, write)),
            )
        } else {
            debug_assert!(successor_read_ready);
            debug_assert!(expected.is_empty() || delegated_successor_grant);
            (true, None)
        };
        let missing_commits = expected
            .iter()
            .filter(|commit| !existing_ids.contains(&commit.id()))
            .count();
        let summary = VaultReseat {
            vault,
            authority,
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
            source: source.clone(),
            expected,
            source_ids: source.iter().map(CollectionCommit::id).collect(),
            current_record_ids,
            current_ids,
            presentation,
            successor_inbox_commits: successor_inbox_commits(&current_candidates, new),
            successor_proofs: successor_proofs(&current_candidates, new),
            custody,
            founder_access,
        });
    }
    public.vaults.sort_by_key(|vault| (vault.vault, vault.old));
    public
        .delegated
        .sort_by_key(|vault| (vault.vault, vault.old));
    prepared.sort_by_key(|vault| (vault.summary.vault, vault.summary.old));
    let old_inbox_ids = commits
        .iter()
        .filter(|commit| commit.collection() == old_inbox)
        .map(CollectionCommit::id)
        .collect();
    let current_inbox_ids = commits
        .iter()
        .filter(|commit| commit.collection() == current_inbox)
        .map(CollectionCommit::id)
        .collect();
    Ok(PreparedPlan {
        public,
        vaults: prepared,
        old_inbox_ids,
        current_inbox_ids,
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
    let discovered = discover_collection_records(&mut *pile)
        .context("rediscover frozen records before Secrets publication")?;
    let commits = discovered.commits().to_vec();
    let old_inbox = descriptor_handle(&retired_inbox_descriptor(signer.verifying_key()));
    let current_inbox = access_inbox_handle(signer.verifying_key());
    let old_inbox_ids = commits
        .iter()
        .filter(|commit| commit.collection() == old_inbox)
        .map(CollectionCommit::id)
        .collect::<BTreeSet<_>>();
    let current_inbox_ids = commits
        .iter()
        .filter(|commit| commit.collection() == current_inbox)
        .map(CollectionCommit::id)
        .collect::<BTreeSet<_>>();
    if old_inbox_ids != before.old_inbox_ids || current_inbox_ids != before.current_inbox_ids {
        bail!("Secrets access inbox changed after the final plan; re-plan before publication");
    }
    for vault in &before.vaults {
        let source_ids = commits
            .iter()
            .filter(|commit| commit.collection() == vault.summary.old)
            .map(CollectionCommit::id)
            .collect::<BTreeSet<_>>();
        let current_record_ids = commits
            .iter()
            .filter(|commit| commit.collection() == vault.summary.new)
            .map(CollectionCommit::id)
            .collect::<BTreeSet<_>>();
        if source_ids != vault.source_ids || current_record_ids != vault.current_record_ids {
            bail!(
                "Secrets vault {:X} changed after the final plan; re-plan before publication",
                vault.summary.vault,
            );
        }
        let current_ids = if vault.current_ids.is_empty() {
            BTreeSet::new()
        } else {
            pile.ticket(vault.summary.new, &vault.presentation)
                .map_err(|error| {
                    anyhow!(
                        "re-admit frozen successor vault {:X}: {error}",
                        vault.summary.vault
                    )
                })?
                .commits()
                .iter()
                .map(CollectionCommit::id)
                .collect()
        };
        if current_ids != vault.current_ids {
            bail!(
                "Secrets vault {:X} admission changed after the final plan; re-plan before publication",
                vault.summary.vault,
            );
        }
    }
    let existing = commits
        .iter()
        .map(CollectionCommit::id)
        .collect::<BTreeSet<_>>();
    let proofs_before = proof_ids(pile)?;
    let mut appended_commits = 0;
    let mut published_envelopes = 0;

    // A reused successor envelope or proof can already be discoverable even
    // though its descriptor, payload closure, or claim blobs predate Artifact
    // OFFERs. Repair every exact access path this plan relies on before
    // publishing any target COMMIT. Founder proofs are also staged here so a
    // newly published envelope cannot race ahead of its DHT providers;
    // publish_access_envelope's repeat is deliberately idempotent.
    for vault in &before.vaults {
        if !vault.successor_inbox_commits.is_empty() {
            crate::offer_backfill::offer_reused_commit_closure(
                pile,
                current_inbox,
                &vault.successor_inbox_commits,
            )
            .with_context(|| {
                format!(
                    "offer existing successor access envelope closure for vault {:X}",
                    vault.summary.vault
                )
            })?;
        }
        for proof in &vault.successor_proofs {
            persist_proof_bundle(pile, proof).with_context(|| {
                format!(
                    "offer existing successor proof closure for vault {:X}",
                    vault.summary.vault
                )
            })?;
        }
        if let Some((read, write)) = &vault.founder_access {
            persist_proof_bundle(pile, read).with_context(|| {
                format!(
                    "stage successor founder READ proof for vault {:X}",
                    vault.summary.vault
                )
            })?;
            persist_proof_bundle(pile, write).with_context(|| {
                format!(
                    "stage successor founder WRITE proof for vault {:X}",
                    vault.summary.vault
                )
            })?;
        }
    }

    for vault in &before.vaults {
        let descriptor = secrets::vault_descriptor(vault.summary.vault, vault.summary.authority);
        let registered = pile
            .collection(descriptor)
            .map_err(|error| anyhow!("register current vault descriptor: {error}"))?;
        if registered != vault.summary.new {
            bail!("registered current vault descriptor changed identity");
        }
        crate::offer_backfill::offer_reused_commit_closure(pile, vault.summary.new, &vault.source)
            .with_context(|| {
                format!(
                    "offer re-seated Secrets vault {:X} dependency closure",
                    vault.summary.vault
                )
            })?;
        if !vault.summary.access_ready {
            let (read, write) = vault
                .founder_access
                .as_ref()
                .context("only a local founder may synthesize a successor envelope")?;
            publish_access_envelope(
                pile,
                signer,
                VaultLocation::new(vault.summary.vault, vault.summary.authority),
                &vault.custody,
                signer.verifying_key(),
                read,
                signer.verifying_key(),
                write,
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
        let ticket = pile
            .ticket(vault.summary.new, &vault.presentation)
            .map_err(|error| anyhow!("admit migrated vault: {error}"))?;
        let snapshot = pile
            .materialize(&ticket)
            .map_err(|error| anyhow!("materialize migrated vault: {error}"))?;
        if !vault.source_facts.difference(&snapshot).is_empty() {
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
    use triblespace::core::repo::{ArtifactOfferStore, BlobStorePut};
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
        root_bundle_for(root, root.verifying_key(), collection, action)
    }

    fn root_bundle_for(
        root: &SigningKey,
        subject: VerifyingKey,
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
            subject,
        )
        .unwrap()
    }

    fn persist_legacy_proof_without_offers(pile: &mut Pile, bundle: &CapabilityProofBundle) {
        let handles = bundle.proof().claim_handles().collect::<Vec<_>>();
        assert_eq!(handles.len(), bundle.claims().len());
        for (expected, claim) in handles.into_iter().zip(bundle.claims()) {
            assert_eq!(
                pile.put::<SimpleArchive, _>(claim.clone()).unwrap(),
                expected
            );
        }
        pile.insert_proof(bundle.proof().clone()).unwrap();
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
    fn alternate_current_access_does_not_stand_in_for_the_exact_founder_envelope() {
        let fixture = founder_fixture();
        let location = VaultLocation::new(fixture.vault, fixture.signer.verifying_key());
        let read_atom = CapabilityAtom::new(
            CapabilityAction::new(secrets::ACTION_READ),
            CapabilityResource::from(location.collection()),
        );
        let alternate_read = CapabilityProofBundle::issue_root(
            &fixture.signer,
            CapabilityClaim::root(read_atom, CapabilityMode::Invoke, None),
            fixture.signer.verifying_key(),
        )
        .unwrap();
        let (_, founder_write) = founder_proofs(&fixture.signer, location);

        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        publish_access_envelope(
            &mut pile,
            &fixture.signer,
            location,
            &fixture.custody,
            fixture.signer.verifying_key(),
            &alternate_read,
            fixture.signer.verifying_key(),
            &founder_write,
            triblespace::core::clock::epoch_now(),
        )
        .unwrap();
        pile.close().unwrap();

        let plan = plan_path(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(plan.pending_envelopes(), 1);
        let report = publish_path(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(report.published_envelopes, 1);
        assert_eq!(report.plan.pending_envelopes(), 0);
    }

    #[test]
    fn exact_founder_proofs_with_the_wrong_custody_do_not_count_ready() {
        let fixture = founder_fixture();
        let location = VaultLocation::new(fixture.vault, fixture.signer.verifying_key());
        let (read, write) = founder_proofs(&fixture.signer, location);
        let wrong_custody = key(0x7a);
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        publish_access_envelope(
            &mut pile,
            &fixture.signer,
            location,
            &wrong_custody,
            fixture.signer.verifying_key(),
            &read,
            fixture.signer.verifying_key(),
            &write,
            triblespace::core::clock::epoch_now(),
        )
        .unwrap();
        pile.close().unwrap();

        let plan = plan_path(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(plan.pending_envelopes(), 1);
        let report = publish_path(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(report.published_envelopes, 1);
        assert!(report.plan.settled());
    }

    #[test]
    fn existing_successor_proof_claims_gain_offers_before_reseat() {
        let fixture = founder_fixture();
        let location = VaultLocation::new(fixture.vault, fixture.signer.verifying_key());
        let (read, write) = founder_proofs(&fixture.signer, location);
        let claims = read
            .proof()
            .claim_handles()
            .chain(write.proof().claim_handles())
            .map(|handle| handle.transmute())
            .collect::<BTreeSet<_>>();
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        store_fragment(
            &mut pile,
            secrets::vault_descriptor(fixture.vault, fixture.signer.verifying_key()),
        );
        store_fragment(
            &mut pile,
            access_inbox_descriptor(fixture.signer.verifying_key()),
        );
        persist_legacy_proof_without_offers(&mut pile, &read);
        persist_legacy_proof_without_offers(&mut pile, &write);
        let envelope = build_access_envelope(
            location.collection(),
            &fixture.custody,
            fixture.signer.verifying_key(),
            &read,
            fixture.signer.verifying_key(),
            &write,
            fixture.signer.verifying_key(),
            triblespace::core::clock::epoch_now(),
        )
        .unwrap();
        let envelope_id = envelope.root().unwrap();
        let sealed_seed = load_access_envelope(envelope.facts(), envelope_id)
            .unwrap()
            .sealed_seed;
        let inbox_commit = commit_fragment(
            &mut pile,
            &fixture.signer,
            access_inbox_handle(fixture.signer.verifying_key()),
            envelope,
        );
        let inbox_artifacts = [
            access_inbox_handle(fixture.signer.verifying_key()).transmute(),
            Handle::<UnknownBlob>::from_hash(inbox_commit.data()),
            inbox_commit.metadata().transmute(),
            sealed_seed.transmute(),
        ];
        let offers = pile.offers_snapshot().unwrap();
        assert!(claims.iter().all(|claim| !offers.contains(*claim)));
        assert!(inbox_artifacts
            .iter()
            .all(|artifact| !offers.contains(*artifact)));
        pile.close().unwrap();

        let plan = plan_path(&fixture.pile, Some(&fixture.key)).unwrap();
        assert!(plan.vaults[0].access_ready);
        let report = publish_path(&fixture.pile, Some(&fixture.key)).unwrap();
        assert!(report.plan.settled());

        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        let offers = pile.offers_snapshot().unwrap();
        assert!(claims.iter().all(|claim| offers.contains(*claim)));
        assert!(inbox_artifacts
            .iter()
            .all(|artifact| offers.contains(*artifact)));
        pile.close().unwrap();
    }

    #[test]
    fn foreign_inert_exact_pair_does_not_suppress_the_authority_reseat() {
        let fixture = founder_fixture();
        let target = secrets::vault_handle(fixture.vault, fixture.signer.verifying_key());
        let foreign = key(0x7b);
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        store_fragment(
            &mut pile,
            secrets::vault_descriptor(fixture.vault, fixture.signer.verifying_key()),
        );
        pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
            &foreign,
            target,
            fixture.source[0].data(),
            fixture.source[0].metadata(),
        )))
        .unwrap();
        pile.close().unwrap();

        let plan = plan_path(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(plan.vaults[0].target_commits, fixture.source.len());
        let report = publish_path(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(report.appended_commits, fixture.source.len());
        assert!(report.plan.settled());
    }

    #[test]
    fn foreign_inert_target_commit_without_a_descriptor_cannot_block_reseat() {
        let fixture = founder_fixture();
        let target = secrets::vault_handle(fixture.vault, fixture.signer.verifying_key());
        let foreign = key(0x7d);
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
            &foreign,
            target,
            fixture.source[0].data(),
            fixture.source[0].metadata(),
        )))
        .unwrap();
        pile.close().unwrap();

        let plan = plan_path(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(plan.vaults[0].target_commits, fixture.source.len());
        let report = publish_path(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(report.appended_commits, fixture.source.len());
        assert!(report.plan.settled());
    }

    #[test]
    fn delegated_current_pair_does_not_replace_the_founders_durable_reseat() {
        let fixture = founder_fixture();
        let location = VaultLocation::new(fixture.vault, fixture.signer.verifying_key());
        let writer = key(0x7c);
        let (read, _) = founder_proofs(&fixture.signer, location);
        let write = root_bundle_for(
            &fixture.signer,
            writer.verifying_key(),
            location.collection(),
            ACTION_WRITE,
        );
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        store_fragment(
            &mut pile,
            secrets::vault_descriptor(fixture.vault, fixture.signer.verifying_key()),
        );
        publish_access_envelope(
            &mut pile,
            &fixture.signer,
            location,
            &fixture.custody,
            fixture.signer.verifying_key(),
            &read,
            writer.verifying_key(),
            &write,
            triblespace::core::clock::epoch_now(),
        )
        .unwrap();
        pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
            &writer,
            location.collection(),
            fixture.source[0].data(),
            fixture.source[0].metadata(),
        )))
        .unwrap();
        pile.close().unwrap();

        let plan = plan_path(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(plan.vaults[0].target_commits, fixture.source.len());
        let report = publish_path(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(report.appended_commits, fixture.source.len());
        assert!(report.plan.settled());
    }

    #[test]
    fn conflicting_current_catalog_is_rejected_before_publication() {
        let fixture = founder_fixture();
        let target = secrets::vault_handle(fixture.vault, fixture.signer.verifying_key());
        let conflicting = secrets::vault_header_fragment(
            fixture.vault,
            "conflicting epoch",
            at(9),
            fixture.custody.verifying_key().to_bytes(),
        )
        .unwrap();
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        store_fragment(
            &mut pile,
            secrets::vault_descriptor(fixture.vault, fixture.signer.verifying_key()),
        );
        commit_fragment(&mut pile, &fixture.signer, target, conflicting);
        pile.close().unwrap();
        let before = fs::read(&fixture.pile).unwrap();

        assert!(plan_path(&fixture.pile, Some(&fixture.key)).is_err());
        assert!(publish_path(&fixture.pile, Some(&fixture.key)).is_err());
        assert_eq!(fs::read(&fixture.pile).unwrap(), before);
    }

    #[test]
    fn namespace_collapse_is_rejected_before_publication() {
        let fixture = founder_fixture();
        let alternate_namespace = key(0x79).verifying_key();
        let descriptor = retired_vault_descriptor(
            fixture.vault,
            alternate_namespace,
            fixture.signer.verifying_key(),
        );
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        let alternate = store_fragment(&mut pile, descriptor);
        let header = secrets::vault_header_fragment(
            fixture.vault,
            "alternate namespace",
            at(11),
            fixture.custody.verifying_key().to_bytes(),
        )
        .unwrap();
        commit_fragment(&mut pile, &fixture.signer, alternate, header);
        pile.close().unwrap();
        let before = fs::read(&fixture.pile).unwrap();

        let error = plan_path(&fixture.pile, Some(&fixture.key)).unwrap_err();
        assert!(error
            .to_string()
            .contains("many-to-one descriptor collapse"));
        assert!(publish_path(&fixture.pile, Some(&fixture.key)).is_err());
        assert_eq!(fs::read(&fixture.pile).unwrap(), before);
    }

    #[test]
    fn successor_grant_settles_a_delegated_vault() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("test.pile");
        let key_path = directory.path().join("test.key");
        File::create(&pile_path).unwrap();
        let local = initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let founder = key(0x81);
        let custody = key(0x82);
        let vault = id(0x83);
        let old_descriptor =
            retired_vault_descriptor(vault, founder.verifying_key(), founder.verifying_key());
        let old = descriptor_handle(&old_descriptor);
        let old_inbox_descriptor = retired_inbox_descriptor(local.verifying_key());
        let old_inbox = descriptor_handle(&old_inbox_descriptor);
        let mut pile = open_pile_strict(&pile_path).unwrap();
        store_fragment(&mut pile, old_descriptor);
        store_fragment(&mut pile, old_inbox_descriptor);
        let source = commit_fragment(
            &mut pile,
            &founder,
            old,
            secrets::vault_header_fragment(
                vault,
                "delegated",
                at(1),
                custody.verifying_key().to_bytes(),
            )
            .unwrap(),
        );

        let old_read = root_bundle_for(&founder, local.verifying_key(), old, secrets::ACTION_READ);
        let old_write = root_bundle(&founder, old, ACTION_WRITE);
        persist_proof_bundle(&mut pile, &old_read).unwrap();
        persist_proof_bundle(&mut pile, &old_write).unwrap();
        let old_envelope = build_access_envelope(
            old,
            &custody,
            local.verifying_key(),
            &old_read,
            founder.verifying_key(),
            &old_write,
            founder.verifying_key(),
            triblespace::core::clock::epoch_now(),
        )
        .unwrap();
        commit_fragment(&mut pile, &founder, old_inbox, old_envelope);

        let location = VaultLocation::new(vault, founder.verifying_key());
        let current_read = root_bundle_for(
            &founder,
            local.verifying_key(),
            location.collection(),
            secrets::ACTION_READ,
        );
        let current_write = root_bundle_for(
            &founder,
            local.verifying_key(),
            location.collection(),
            ACTION_WRITE,
        );
        publish_access_envelope(
            &mut pile,
            &founder,
            location,
            &custody,
            local.verifying_key(),
            &current_read,
            local.verifying_key(),
            &current_write,
            triblespace::core::clock::epoch_now(),
        )
        .unwrap();
        pile.close().unwrap();

        let plan = plan_path(&pile_path, Some(&key_path)).unwrap();
        assert!(plan.delegated.is_empty());
        assert_eq!(plan.vaults.len(), 1);
        assert!(plan.vaults[0].access_ready);
        let report = publish_path(&pile_path, Some(&key_path)).unwrap();
        assert_eq!(report.appended_commits, 1);
        assert_eq!(report.published_envelopes, 0);
        assert!(report.plan.settled());

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let records = discover_collection_records(&mut pile).unwrap();
        let target = records
            .commits()
            .iter()
            .find(|commit| commit.collection() == location.collection())
            .unwrap();
        assert_eq!(
            (target.data(), target.metadata()),
            (source.data(), source.metadata())
        );
        assert_eq!(target.public_key().raw, local.verifying_key().to_bytes());
        pile.close().unwrap();

        let replay = publish_path(&pile_path, Some(&key_path)).unwrap();
        assert_eq!(replay.appended_commits, 0);
        assert!(replay.plan.settled());
    }

    #[test]
    fn admitted_successor_pair_needs_no_local_write_grant() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("test.pile");
        let key_path = directory.path().join("test.key");
        File::create(&pile_path).unwrap();
        let local = initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let founder = key(0x91);
        let custody = key(0x92);
        let vault = id(0x93);
        let old_descriptor =
            retired_vault_descriptor(vault, founder.verifying_key(), founder.verifying_key());
        let old = descriptor_handle(&old_descriptor);
        let mut pile = open_pile_strict(&pile_path).unwrap();
        store_fragment(&mut pile, old_descriptor);
        let source = commit_fragment(
            &mut pile,
            &founder,
            old,
            secrets::vault_header_fragment(
                vault,
                "already moved",
                at(1),
                custody.verifying_key().to_bytes(),
            )
            .unwrap(),
        );

        let location = VaultLocation::new(vault, founder.verifying_key());
        store_fragment(
            &mut pile,
            secrets::vault_descriptor(vault, founder.verifying_key()),
        );
        pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
            &founder,
            location.collection(),
            source.data(),
            source.metadata(),
        )))
        .unwrap();
        let current_read = root_bundle_for(
            &founder,
            local.verifying_key(),
            location.collection(),
            secrets::ACTION_READ,
        );
        let founder_write = root_bundle(&founder, location.collection(), ACTION_WRITE);
        publish_access_envelope(
            &mut pile,
            &founder,
            location,
            &custody,
            local.verifying_key(),
            &current_read,
            founder.verifying_key(),
            &founder_write,
            triblespace::core::clock::epoch_now(),
        )
        .unwrap();
        pile.close().unwrap();

        let plan = plan_path(&pile_path, Some(&key_path)).unwrap();
        assert!(plan.delegated.is_empty());
        assert_eq!(plan.missing_commits(), 0);
        assert!(plan.settled());
        let report = publish_path(&pile_path, Some(&key_path)).unwrap();
        assert_eq!(report.appended_commits, 0);
        assert_eq!(report.published_envelopes, 0);
        assert!(report.plan.settled());
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
