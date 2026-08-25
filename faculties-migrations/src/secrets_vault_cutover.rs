//! Projection from pre-collection Secrets to capability-anchored custody
//! vault epochs.
//!
//! The source generation remains immutable evidence. Planning validates every
//! source and target catalog, stages the exact encrypted
//! bodies and direct wraps, adds one custody declaration and exactly one
//! custody wrap per secret, and emits one founder access envelope into the
//! durable signer's deterministic inbox. There is no intermediary fixed
//! `secrets` collection and no enumerable authority census.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Context, Result};
use dryoc::dryocsecretbox::Key as RandomSeed;
use dryoc::types::{ByteArray, NewByteArray};
use ed25519_dalek::{SigningKey, VerifyingKey};
use faculties::secrets::access::build_access_envelope;
use faculties::secrets::storage::{
    discover_access_candidates, ValidatedAccessCandidate, VaultLocation,
};
use faculties::secrets::{self, RecipientPublicKey, VaultCatalog};
use hifitime::Epoch;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::capability::{
    CapabilityAction, CapabilityAtom, CapabilityClaim, CapabilityMode, CapabilityProofBundle,
    CapabilityRequest, CapabilityResource,
};
use triblespace::core::collection::{
    CapabilityPresentation, CollectionAdmission, CollectionHandle, ACTION_WRITE,
};
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta, CapabilityProofStore};
use triblespace::prelude::*;

use crate::legacy_secrets_v1 as legacy;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultMigrationReport {
    pub vault: Id,
    pub secret_versions: usize,
    pub preserved_wraps: usize,
    pub custody_wraps_added: usize,
    pub access_pending: bool,
    pub data_pending: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SecretsVaultMigrationReport {
    /// Total pre-collection source facts consumed.
    pub source_facts: usize,
    pub vaults: Vec<VaultMigrationReport>,
}

impl SecretsVaultMigrationReport {
    pub fn secret_versions(&self) -> usize {
        self.vaults.iter().map(|vault| vault.secret_versions).sum()
    }

    pub fn preserved_wraps(&self) -> usize {
        self.vaults.iter().map(|vault| vault.preserved_wraps).sum()
    }

    pub fn custody_wraps_added(&self) -> usize {
        self.vaults
            .iter()
            .map(|vault| vault.custody_wraps_added)
            .sum()
    }

    pub fn pending_access_envelopes(&self) -> usize {
        self.vaults
            .iter()
            .filter(|vault| vault.access_pending)
            .count()
    }

    pub fn pending_vaults(&self) -> usize {
        self.vaults
            .iter()
            .filter(|vault| vault.data_pending)
            .count()
    }
}

#[derive(Clone)]
pub(crate) struct VaultPlan {
    pub(crate) vault: Id,
    pub(crate) authority: VerifyingKey,
    pub(crate) write_presentation: CapabilityPresentation,
    pub(crate) required: Fragment,
    pub(crate) report: VaultMigrationReport,
}

/// Complete read-only preflight.  The plan owns every attachment needed by a
/// later vault commit; publication never needs the password or plaintext DEK.
#[derive(Clone)]
pub struct SecretsVaultMigrationPlan {
    namespace: RecipientPublicKey,
    access_inbox: Vec<Fragment>,
    access_bundles: Vec<CapabilityProofBundle>,
    vaults: Vec<VaultPlan>,
    report: SecretsVaultMigrationReport,
}

impl SecretsVaultMigrationPlan {
    pub fn report(&self) -> &SecretsVaultMigrationReport {
        &self.report
    }

    pub(crate) fn namespace(&self) -> RecipientPublicKey {
        self.namespace
    }

    pub(crate) fn vaults(&self) -> &[VaultPlan] {
        &self.vaults
    }

    pub(crate) fn access_inbox(&self) -> &[Fragment] {
        &self.access_inbox
    }

    pub(crate) fn access_bundles(&self) -> &[CapabilityProofBundle] {
        &self.access_bundles
    }
}

fn capability_atom(collection: CollectionHandle, action: Id) -> CapabilityAtom {
    CapabilityAtom::new(
        CapabilityAction::new(action),
        CapabilityResource::from(collection),
    )
}

fn root_bundle(
    root: &SigningKey,
    collection: CollectionHandle,
    action: Id,
) -> CapabilityProofBundle {
    CapabilityProofBundle::issue_root(
        root,
        CapabilityClaim::root(
            capability_atom(collection, action),
            CapabilityMode::InvokeAndDelegate,
            None,
        ),
        root.verifying_key(),
    )
    .expect("a parentless founder claim is issuable")
}

fn planning_instant() -> Epoch {
    // Migration-issued founder proofs are unbounded. A fixed instant keeps the
    // pure plan independent of a wall-clock read while still exercising the
    // same claim verification as the live envelope path.
    Epoch::from_tai_seconds(0.0)
}

fn materialize_custody_vault<S>(
    pile: &mut S,
    vault: Id,
    namespace: VerifyingKey,
    signer: &SigningKey,
    authority: VerifyingKey,
    write_presentation: CapabilityPresentation,
) -> Result<TribleSet>
where
    S: BlobStore + triblespace::core::collection::CollectionStore,
    S::Reader: BlobStoreMeta,
{
    secrets::vault_collection(
        pile,
        vault,
        namespace,
        signer.clone(),
        CollectionAdmission::capability(authority, vec![write_presentation]),
    )
    .materialize()
    .with_context(|| format!("materialize capability-anchored custody vault {vault:X}"))
}

#[derive(Clone)]
struct FounderAccess {
    custody: SigningKey,
    read_bundle: CapabilityProofBundle,
    write_presentation: CapabilityPresentation,
}

fn existing_founder_access(
    candidates: &[ValidatedAccessCandidate],
    signer: &SigningKey,
    vault: Id,
    authority: VerifyingKey,
    collection: CollectionHandle,
    expected_custody: Option<RecipientPublicKey>,
) -> Result<Option<FounderAccess>> {
    let instant = planning_instant();
    let mut usable = Vec::new();
    let location = VaultLocation::new(vault, signer.verifying_key(), authority);
    debug_assert_eq!(location.collection(), collection);
    for candidate in candidates {
        if candidate.location() != location || candidate.publisher() != signer.verifying_key() {
            continue;
        }
        if candidate.writer() != signer.verifying_key() {
            continue;
        }
        let Ok(read) = candidate.read_bundle().verify(
            authority,
            instant,
            signer.verifying_key(),
            CapabilityRequest::new(
                capability_atom(collection, secrets::ACTION_READ),
                CapabilityMode::InvokeAndDelegate,
            ),
        ) else {
            continue;
        };
        let Ok(write) = candidate.write_bundle().verify(
            authority,
            instant,
            candidate.writer(),
            CapabilityRequest::new(
                capability_atom(collection, ACTION_WRITE),
                CapabilityMode::InvokeAndDelegate,
            ),
        ) else {
            continue;
        };
        if read.effective_validity().is_some() || write.effective_validity().is_some() {
            continue;
        }
        if expected_custody
            .is_some_and(|expected| candidate.custody().verifying_key().to_bytes() != expected)
        {
            continue;
        }
        usable.push(FounderAccess {
            custody: candidate.custody().clone(),
            read_bundle: candidate.read_bundle().clone(),
            write_presentation: CapabilityPresentation::new(
                candidate.writer(),
                candidate.write_bundle().clone(),
            ),
        });
    }
    let custody = usable
        .iter()
        .map(|access| access.custody.verifying_key().to_bytes())
        .collect::<BTreeSet<_>>();
    if custody.len() > 1 {
        bail!("existing founder envelopes disagree about the vault custody key");
    }
    Ok(usable.into_iter().next())
}

fn retain_vault_descriptor(
    fragment: &mut Fragment,
    vault: Id,
    namespace: VerifyingKey,
    authority: VerifyingKey,
) -> Result<CollectionHandle> {
    let expected = secrets::vault_handle(vault, namespace, authority);
    let actual = fragment.put::<SimpleArchive, _>(
        secrets::vault_descriptor(vault, namespace, authority).into_facts(),
    );
    if actual != expected {
        bail!("canonical custody-vault descriptor changed identity while staging access")
    }
    Ok(actual)
}

fn put_text_exact(
    destination: &mut Fragment,
    expected: legacy::TextHandle,
    value: String,
    field: &str,
) -> Result<()> {
    let actual = destination.put(value);
    if actual != expected {
        bail!("content address changed while staging {field}");
    }
    Ok(())
}

fn put_bytes_exact(
    destination: &mut Fragment,
    expected: legacy::BytesHandle,
    value: Vec<u8>,
    field: &str,
) -> Result<()> {
    let actual = destination.put::<blobencodings::RawBytes, _>(value);
    if actual != expected {
        bail!("content address changed while staging {field}");
    }
    Ok(())
}

fn stage_existing_payloads(
    reader: &PileReader,
    catalog: &VaultCatalog,
    destination: &mut Fragment,
) -> Result<()> {
    let name: anybytes::View<str> = reader
        .get(catalog.header.name)
        .context("read existing vault name")?;
    let actual = destination.put(name.to_string());
    if actual != catalog.header.name {
        bail!("existing vault name changed content address while staging");
    }
    for secret in catalog.secrets.values() {
        let name: anybytes::View<str> = reader
            .get(secret.name)
            .with_context(|| format!("read existing vault secret {} name", secret.id))?;
        let actual = destination.put(name.to_string());
        if actual != secret.name {
            bail!("existing vault secret name changed content address while staging");
        }
        let body: anybytes::Bytes = reader
            .get(secret.body)
            .with_context(|| format!("read existing vault secret {} body", secret.id))?;
        let actual = destination.put::<blobencodings::RawBytes, _>(body.as_ref().to_vec());
        if actual != secret.body {
            bail!("existing vault secret body changed content address while staging");
        }
    }
    for wrap in catalog.wraps.values() {
        let sealed: anybytes::Bytes = reader
            .get(wrap.sealed_dek)
            .with_context(|| format!("read existing vault wrap {} payload", wrap.id))?;
        let actual = destination.put::<blobencodings::RawBytes, _>(sealed.as_ref().to_vec());
        if actual != wrap.sealed_dek {
            bail!("existing vault wrap changed content address while staging");
        }
    }
    Ok(())
}

fn next_unused_id(used: &mut BTreeSet<Id>) -> Id {
    loop {
        let id = genid().id;
        if used.insert(id) {
            return id;
        }
    }
}

fn fresh_custody_key(disallowed: &BTreeSet<RecipientPublicKey>) -> SigningKey {
    loop {
        let seed = RandomSeed::generate();
        let custody = SigningKey::from_bytes(seed.as_array());
        if !disallowed.contains(&custody.verifying_key().to_bytes()) {
            return custody;
        }
    }
}

fn merge_materialized_vault(
    reader: &PileReader,
    vault: Id,
    facts: &TribleSet,
    destination: &mut Fragment,
    label: &str,
) -> Result<Option<VaultCatalog>> {
    if facts.is_empty() {
        return Ok(None);
    }
    let catalog = secrets::validate_catalog(reader, vault, facts)
        .with_context(|| format!("validate {label} vault {vault:X}"))?;
    stage_existing_payloads(reader, &catalog, destination)
        .with_context(|| format!("stage {label} vault {vault:X} attachments"))?;
    *destination += Fragment::from(facts.clone());
    Ok(Some(catalog))
}

fn validate_staged_vault(vault: Id, fragment: &mut Fragment) -> Result<VaultCatalog> {
    let facts = fragment.facts().clone();
    let local = fragment
        .blobs_mut()
        .reader()
        .context("snapshot staged custody-vault attachments")?;
    secrets::validate_catalog(&local, vault, &facts)
        .with_context(|| format!("validate staged custody vault {vault:X}"))
}

/// Project historical scope-creation observations onto one vault genesis.
///
/// Legacy scope identity was `(creator, name)`, so repeated creation calls
/// reasserted the same intrinsic scope with another timestamp. The earliest
/// point is the actual genesis: it is deterministic, independent of authored
/// order, and composes over union (`min(A ∪ B) = min(min(A), min(B))`). The
/// preserved legacy prefix still carries every original observation.
fn vault_created_at(scope: &legacy::ScopeRow) -> Result<legacy::IntervalValue> {
    scope
        .created_at
        .first()
        .copied()
        .ok_or_else(|| anyhow!("legacy scope {} has no creation observation", scope.id))
}

/// Project one exact pre-collection source into freshly issued direct-proof
/// custody successors. No native authority ledger or retired signature blobs
/// participate in source discovery.
fn plan_from_source_in_store<S>(
    pile: &mut S,
    signer: &SigningKey,
    reader: &PileReader,
    source: TribleSet,
    password: Option<&[u8]>,
) -> Result<SecretsVaultMigrationPlan>
where
    S: BlobStore<Reader = PileReader>
        + CapabilityProofStore
        + triblespace::core::collection::CollectionStore,
    S::Reader: BlobStoreMeta,
{
    let authority = signer.verifying_key();
    let namespace = authority;
    let namespace_bytes = authority.to_bytes();
    let catalog = legacy::validate_catalog(reader, &source)
        .context("validate projected pre-collection Secrets catalog")?;
    let identity_keys = legacy::identity_public_keys(reader, &catalog)?;
    let (access_candidates, _) = discover_access_candidates(&mut *pile, signer)
        .context("discover existing founder access candidates")?;
    let source_vaults = catalog.scopes.keys().copied().collect::<BTreeSet<_>>();

    let mut target_by_vault = BTreeMap::new();
    let mut used_ids = source.iter().map(|fact| *fact.e()).collect::<BTreeSet<_>>();
    used_ids.extend(access_candidates.iter().map(ValidatedAccessCandidate::id));
    for vault in source_vaults.iter().copied() {
        let collection = secrets::vault_handle(vault, namespace, authority);
        let write = root_bundle(signer, collection, ACTION_WRITE);
        let target = materialize_custody_vault(
            pile,
            vault,
            namespace,
            signer,
            authority,
            CapabilityPresentation::new(authority, write),
        )?;
        used_ids.extend(target.iter().map(|fact| *fact.e()));
        target_by_vault.insert(vault, target);
    }
    let source_facts = source.len();

    let mut claimed_secrets = BTreeMap::<Id, Id>::new();
    let mut access_inbox = Vec::new();
    let mut access_bundles = Vec::new();
    let mut vaults = Vec::with_capacity(source_vaults.len());

    for vault in source_vaults {
        let scope = catalog
            .scopes
            .get(&vault)
            .expect("source vault ids came from the validated scope catalog");
        let mut required = Fragment::empty();
        let created_at = vault_created_at(scope)?;
        let vault_name = legacy::read_text(reader, scope.name)
            .with_context(|| format!("read legacy scope {} name", scope.id))?;
        required += secrets::legacy_vault_header_fragment(scope.id, &vault_name, created_at)?;
        let header = secrets::load_catalog(scope.id, required.facts())?.header;
        if header.name != scope.name {
            bail!("vault header did not preserve the legacy scope name handle");
        }

        let scoped_secrets = catalog
            .secrets
            .values()
            .filter(|secret| secret.scope == scope.id)
            .collect::<Vec<_>>();
        for secret in &scoped_secrets {
            let body = legacy::read_bytes(reader, secret.body)
                .with_context(|| format!("read legacy secret {} encrypted body", secret.id))?;
            required += secrets::encrypted_secret_fragment(
                secret.id,
                &secret.name,
                body.clone(),
                secret.created_at,
            )?;
            put_text_exact(
                &mut required,
                secret.display_name,
                secret.name.clone(),
                "legacy secret name",
            )?;
            put_bytes_exact(
                &mut required,
                secret.body,
                body,
                "legacy encrypted secret body",
            )?;
        }

        let scoped_secret_ids = scoped_secrets
            .iter()
            .map(|secret| secret.id)
            .collect::<BTreeSet<_>>();
        let old_wraps = catalog
            .wraps
            .values()
            .filter(|wrap| scoped_secret_ids.contains(&wrap.secret))
            .collect::<Vec<_>>();
        for wrap in &old_wraps {
            let recipient = identity_keys
                .get(&wrap.recipient)
                .copied()
                .ok_or_else(|| anyhow!("legacy wrap {} recipient has no exact key", wrap.id))?;
            let sealed = legacy::read_bytes(reader, wrap.sealed_dek)
                .with_context(|| format!("read legacy wrap {} sealed DEK", wrap.id))?;
            required +=
                secrets::recipient_wrap_fragment(wrap.id, wrap.secret, recipient, sealed.clone())?;
            put_bytes_exact(&mut required, wrap.sealed_dek, sealed, "legacy sealed DEK")?;
        }

        let source_catalog = validate_staged_vault(vault, &mut required)?;
        if source_catalog.custody.is_some() {
            bail!("pre-collection source vault {vault:X} already declares custody");
        }

        let target_existing = target_by_vault
            .remove(&vault)
            .expect("one anchored target snapshot per source vault");
        let target_catalog = if target_existing.is_empty() {
            None
        } else {
            let target = secrets::validate_catalog(reader, vault, &target_existing)
                .with_context(|| format!("validate anchored target vault {vault:X}"))?;
            if target.custody.is_none() {
                bail!("anchored target vault {vault:X} has no custody declaration");
            }
            Some(target)
        };

        let collection = secrets::vault_handle(vault, namespace, authority);
        let root_read = root_bundle(signer, collection, secrets::ACTION_READ);
        let root_write = root_bundle(signer, collection, ACTION_WRITE);
        let existing_access = existing_founder_access(
            &access_candidates,
            signer,
            vault,
            authority,
            collection,
            target_catalog
                .as_ref()
                .and_then(|target| target.custody)
                .map(|custody| custody.public_key),
        )?;
        if !target_existing.is_empty() && existing_access.is_none() {
            bail!(
                "anchored target vault {vault:X} has no usable direct-proof founder access envelope; run `migrations secrets-direct-proofs activate` to bridge an unpublished subject-bearing predecessor before replaying this plan"
            );
        }

        let source_recipients = source_catalog
            .wraps
            .values()
            .map(|wrap| wrap.recipient)
            .collect::<BTreeSet<_>>();
        let (founder, access_pending) = match existing_access {
            Some(founder) => (founder, false),
            None => (
                FounderAccess {
                    custody: fresh_custody_key(&source_recipients),
                    read_bundle: root_read,
                    write_presentation: CapabilityPresentation::new(authority, root_write),
                },
                true,
            ),
        };

        if access_pending {
            let mut envelope = build_access_envelope(
                collection,
                &founder.custody,
                authority,
                &founder.read_bundle,
                founder.write_presentation.expected_leaf(),
                founder.write_presentation.bundle(),
                authority,
                planning_instant(),
            )
            .with_context(|| format!("build founder access envelope for vault {vault:X}"))?;
            retain_vault_descriptor(&mut envelope, vault, namespace, authority)?;
            access_bundles.push(founder.read_bundle.clone());
            access_bundles.push(founder.write_presentation.bundle().clone());
            access_inbox.push(envelope);
        }

        merge_materialized_vault(
            reader,
            vault,
            &target_existing,
            &mut required,
            "anchored custody target",
        )?;
        required += secrets::vault_header_fragment(
            vault,
            &vault_name,
            created_at,
            founder.custody.verifying_key().to_bytes(),
        )?;

        let custody_public = founder.custody.verifying_key().to_bytes();
        let mut known_wraps = source_catalog.wraps.clone();
        if let Some(target) = &target_catalog {
            for (id, wrap) in &target.wraps {
                if known_wraps
                    .insert(*id, *wrap)
                    .is_some_and(|previous| previous != *wrap)
                {
                    bail!("pre-collection source and anchored target disagree about wrap {id:X}");
                }
            }
        }
        let secret_ids = source_catalog
            .secrets
            .keys()
            .copied()
            .chain(
                target_catalog
                    .iter()
                    .flat_map(|target| target.secrets.keys().copied()),
            )
            .collect::<BTreeSet<_>>();
        let mut custody_wraps_added = 0;
        for secret in secret_ids {
            let custody_wraps = known_wraps
                .values()
                .filter(|wrap| wrap.secret == secret && wrap.recipient == custody_public)
                .count();
            match custody_wraps {
                1 => continue,
                count if count > 1 => bail!(
                    "vault {:X} already has {count} wraps to the selected custody key for secret {secret:X}",
                    vault
                ),
                _ => {}
            }
            if !source_catalog.secrets.contains_key(&secret) {
                bail!("anchored target secret {secret:X} has no custody wrap and no pre-collection source");
            }
            let wrap = next_unused_id(&mut used_ids);
            let dek =
                legacy::recover_dek_for_migration(reader, &catalog, secret, signer, password)?;
            let sealed = legacy::seal_dek_for_recipient(&dek, custody_public)?;
            let fragment = secrets::recipient_wrap_fragment(wrap, secret, custody_public, sealed)?;
            required += fragment;
            custody_wraps_added += 1;
        }

        let final_catalog = validate_staged_vault(vault, &mut required)?;
        let final_custody = final_catalog
            .custody
            .context("staged anchored vault lost its custody declaration")?;
        if final_custody.public_key != custody_public {
            bail!("staged anchored vault custody differs from its founder envelope");
        }
        for secret in final_catalog.secrets.keys().copied() {
            if let Some(previous) = claimed_secrets.insert(secret, vault) {
                bail!("secret {secret:X} appears in both vault {previous:X} and {vault:X}");
            }
        }

        let data_pending = !required.facts().difference(&target_existing).is_empty();
        let report = VaultMigrationReport {
            vault,
            secret_versions: final_catalog.secrets.len(),
            preserved_wraps: final_catalog.wraps.len() - custody_wraps_added,
            custody_wraps_added,
            access_pending,
            data_pending,
        };
        vaults.push(VaultPlan {
            vault,
            authority,
            write_presentation: founder.write_presentation,
            required,
            report,
        });
    }

    let report = SecretsVaultMigrationReport {
        source_facts,
        vaults: vaults.iter().map(|vault| vault.report.clone()).collect(),
    };
    Ok(SecretsVaultMigrationPlan {
        namespace: namespace_bytes,
        access_inbox,
        access_bundles,
        vaults,
        report,
    })
}

/// Translate an exact pre-collection Secrets projection directly into zero or
/// more current vault plans. The projection is an in-memory source boundary,
/// never a fixed native `secrets` collection or an authority target.
pub(crate) fn plan_from_legacy_in_store<S>(
    pile: &mut S,
    signer: &SigningKey,
    reader: &PileReader,
    source: TribleSet,
    password: Option<&[u8]>,
) -> Result<SecretsVaultMigrationPlan>
where
    S: BlobStore<Reader = PileReader>
        + CapabilityProofStore
        + triblespace::core::collection::CollectionStore,
    S::Reader: BlobStoreMeta,
{
    plan_from_source_in_store(pile, signer, reader, source, password)
        .context("plan custody successors from pre-collection Secrets evidence")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hifitime::Epoch;
    use triblespace::prelude::TryToInline;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn at(seconds: f64) -> legacy::IntervalValue {
        let instant = Epoch::from_unix_seconds(seconds);
        (instant, instant).try_to_inline().unwrap()
    }

    #[test]
    fn repeated_legacy_creation_observations_project_to_the_earliest_point() {
        let scope = legacy::ScopeRow {
            id: id(1),
            creator: id(2),
            created_at: BTreeSet::from([at(4.0), at(3.0)]),
            name: Inline::new([5; 32]),
        };

        assert_eq!(vault_created_at(&scope).unwrap(), at(3.0));
    }
}
