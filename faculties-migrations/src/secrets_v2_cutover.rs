//! Stopped-world projection from the frozen pre-collection Secrets branch to
//! one direct-key v2 vault collection per confidentiality epoch.
//!
//! The copied pile prefix retains the old branch byte-for-byte. Planning
//! validates every source and target catalog, stages the exact encrypted
//! payloads needed by direct vault commits, and proves cross-vault identity
//! uniqueness. There is no intermediary fixed `secrets` collection.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use faculties::secrets::v2::{self, RecipientPublicKey, VaultCatalog};
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
use triblespace::prelude::*;

use crate::legacy_secrets_v1 as legacy;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultMigrationReport {
    pub vault: Id,
    pub current_readers: usize,
    pub secret_versions: usize,
    pub preserved_wraps: usize,
    pub synthesized_wraps: usize,
    pub data_pending: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SecretsV2MigrationReport {
    pub source_facts: usize,
    pub vaults: Vec<VaultMigrationReport>,
}

impl SecretsV2MigrationReport {
    pub fn secret_versions(&self) -> usize {
        self.vaults.iter().map(|vault| vault.secret_versions).sum()
    }

    pub fn preserved_wraps(&self) -> usize {
        self.vaults.iter().map(|vault| vault.preserved_wraps).sum()
    }

    pub fn synthesized_wraps(&self) -> usize {
        self.vaults
            .iter()
            .map(|vault| vault.synthesized_wraps)
            .sum()
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
    pub(crate) recipients: BTreeSet<RecipientPublicKey>,
    pub(crate) required: Fragment,
    pub(crate) report: VaultMigrationReport,
}

/// Complete read-only preflight.  The plan owns every attachment needed by a
/// later vault commit; publication never needs the password or plaintext DEK.
#[derive(Clone)]
pub struct SecretsV2MigrationPlan {
    team: RecipientPublicKey,
    vaults: Vec<VaultPlan>,
    report: SecretsV2MigrationReport,
}

impl SecretsV2MigrationPlan {
    pub fn report(&self) -> &SecretsV2MigrationReport {
        &self.report
    }

    pub(crate) fn team(&self) -> RecipientPublicKey {
        self.team
    }

    pub(crate) fn vaults(&self) -> &[VaultPlan] {
        &self.vaults
    }
}

fn materialize_vault<S>(
    pile: &mut S,
    vault: Id,
    team: VerifyingKey,
    signer: &SigningKey,
) -> Result<TribleSet>
where
    S: BlobStore + triblespace::core::collection::CollectionStore,
    S::Reader: BlobStoreMeta,
{
    v2::vault_collection(pile, vault, team, signer.clone())
        .materialize()
        .with_context(|| format!("materialize v2 vault {vault:X}"))
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
        .context("read existing v2 vault name")?;
    let actual = destination.put(name.to_string());
    if actual != catalog.header.name {
        bail!("existing v2 vault name changed content address while staging");
    }
    for secret in catalog.secrets.values() {
        let name: anybytes::View<str> = reader
            .get(secret.name)
            .with_context(|| format!("read existing v2 secret {} name", secret.id))?;
        let actual = destination.put(name.to_string());
        if actual != secret.name {
            bail!("existing v2 secret name changed content address while staging");
        }
        let body: anybytes::Bytes = reader
            .get(secret.body)
            .with_context(|| format!("read existing v2 secret {} body", secret.id))?;
        let actual = destination.put::<blobencodings::RawBytes, _>(body.as_ref().to_vec());
        if actual != secret.body {
            bail!("existing v2 secret body changed content address while staging");
        }
    }
    for wrap in catalog.wraps.values() {
        let sealed: anybytes::Bytes = reader
            .get(wrap.sealed_dek)
            .with_context(|| format!("read existing v2 wrap {} payload", wrap.id))?;
        let actual = destination.put::<blobencodings::RawBytes, _>(sealed.as_ref().to_vec());
        if actual != wrap.sealed_dek {
            bail!("existing v2 wrap changed content address while staging");
        }
    }
    Ok(())
}

fn validate_candidate(
    reader: &PileReader,
    vault: Id,
    existing: &TribleSet,
    required: &Fragment,
) -> Result<VaultCatalog> {
    let mut candidate = Fragment::from(existing.clone());
    if !existing.is_empty() {
        let existing_catalog = v2::load_catalog(vault, existing)
            .with_context(|| format!("strictly load existing v2 vault {vault:X}"))?;
        stage_existing_payloads(reader, &existing_catalog, &mut candidate)?;
    }
    candidate += required.clone();
    let facts = candidate.facts().clone();
    let local = candidate
        .blobs_mut()
        .reader()
        .context("snapshot complete v2 vault candidate attachments")?;
    v2::validate_catalog(&local, vault, &facts)
        .with_context(|| format!("validate complete v2 vault candidate {vault:X}"))
}

fn next_unused_id(used: &mut BTreeSet<Id>) -> Id {
    loop {
        let id = genid().id;
        if used.insert(id) {
            return id;
        }
    }
}

/// Translate an exact pre-collection legacy Secrets projection directly into
/// zero or more vault plans. The projection is an in-memory source boundary,
/// never a fixed native `secrets` collection or an authority target.
pub(crate) fn plan_from_legacy_in_store<S>(
    pile: &mut S,
    signer: &SigningKey,
    reader: &PileReader,
    source: TribleSet,
    password: Option<&[u8]>,
) -> Result<SecretsV2MigrationPlan>
where
    S: BlobStore + triblespace::core::collection::CollectionStore,
    S::Reader: BlobStoreMeta,
{
    let team = signer.verifying_key();
    let catalog = legacy::validate_catalog(reader, &source)
        .context("validate projected pre-collection Secrets catalog")?;
    crate::collection_cutover::reject_dormant_local_commits(
        &mut *pile,
        signer,
        catalog
            .scopes
            .keys()
            .copied()
            .map(|vault| v2::vault_handle(vault, team)),
    )
    .context("preflight dormant COMMITs on direct vault WRITE targets")?;
    let identity_keys = legacy::identity_public_keys(reader, &catalog)?;

    let mut existing_by_vault = BTreeMap::new();
    for vault in catalog.scopes.keys().copied() {
        existing_by_vault.insert(vault, materialize_vault(pile, vault, team, signer)?);
    }

    let mut used_ids = source.iter().map(|fact| *fact.e()).collect::<BTreeSet<_>>();
    for facts in existing_by_vault.values() {
        used_ids.extend(facts.iter().map(|fact| *fact.e()));
    }
    let mut claimed_secrets = BTreeMap::<Id, Id>::new();
    let mut vaults = Vec::with_capacity(catalog.scopes.len());

    for scope in catalog.scopes.values() {
        if scope.created_at.len() != 1 {
            bail!(
                "legacy scope {} has {} creation observations; v2 requires exactly one",
                scope.id,
                scope.created_at.len()
            );
        }
        let created_at = *scope
            .created_at
            .first()
            .expect("one legacy scope creation observation checked above");
        let vault_name = legacy::read_text(reader, scope.name)
            .with_context(|| format!("read legacy scope {} name", scope.id))?;
        let recipient_ids = catalog.recipients_of(scope.id);
        if recipient_ids.is_empty() {
            bail!("legacy scope {} has no effective recipients", scope.id);
        }
        let recipients = recipient_ids
            .iter()
            .map(|identity| {
                identity_keys.get(identity).copied().ok_or_else(|| {
                    anyhow!(
                        "legacy recipient identity {} has no exact public key",
                        identity
                    )
                })
            })
            .collect::<Result<BTreeSet<_>>>()?;

        let mut required = v2::vault_header_fragment(scope.id, &vault_name, created_at)?;
        let header = v2::load_catalog(scope.id, required.facts())?.header;
        if header.name != scope.name {
            bail!("v2 vault header did not preserve the legacy scope name handle");
        }

        let scoped_secrets = catalog
            .secrets
            .values()
            .filter(|secret| secret.scope == scope.id)
            .collect::<Vec<_>>();
        for secret in &scoped_secrets {
            let body = legacy::read_bytes(reader, secret.body)
                .with_context(|| format!("read legacy secret {} encrypted body", secret.id))?;
            required += v2::encrypted_secret_fragment(
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
                v2::recipient_wrap_fragment(wrap.id, wrap.secret, recipient, sealed.clone())?;
            put_bytes_exact(&mut required, wrap.sealed_dek, sealed, "legacy sealed DEK")?;
        }

        let existing = existing_by_vault
            .remove(&scope.id)
            .expect("one target snapshot per scope");
        let existing_catalog = if existing.is_empty() {
            None
        } else {
            Some(
                v2::validate_catalog(reader, scope.id, &existing)
                    .with_context(|| format!("validate existing v2 vault {}", scope.id))?,
            )
        };
        let mut holders = BTreeMap::<Id, BTreeSet<RecipientPublicKey>>::new();
        for wrap in &old_wraps {
            holders
                .entry(wrap.secret)
                .or_default()
                .insert(identity_keys[&wrap.recipient]);
        }
        if let Some(existing_catalog) = &existing_catalog {
            for wrap in existing_catalog.wraps.values() {
                holders
                    .entry(wrap.secret)
                    .or_default()
                    .insert(wrap.recipient);
            }
        }

        let mut synthesized_wraps = 0;
        for secret in &scoped_secrets {
            let missing = recipients
                .difference(holders.entry(secret.id).or_default())
                .copied()
                .collect::<Vec<_>>();
            if missing.is_empty() {
                continue;
            }
            let dek =
                legacy::recover_dek_for_migration(reader, &catalog, secret.id, signer, password)?;
            for recipient in missing {
                let sealed = legacy::seal_dek_for_recipient(&dek, recipient)?;
                required += v2::recipient_wrap_fragment(
                    next_unused_id(&mut used_ids),
                    secret.id,
                    recipient,
                    sealed,
                )?;
                holders.entry(secret.id).or_default().insert(recipient);
                synthesized_wraps += 1;
            }
        }

        let final_catalog = validate_candidate(reader, scope.id, &existing, &required)?;
        for secret in final_catalog.secrets.keys().copied() {
            let holders = final_catalog.wrap_holders(secret);
            if !recipients.is_subset(&holders) {
                bail!(
                    "v2 vault candidate leaves a current reader without a wrap for secret {secret:X}"
                );
            }
        }
        for secret in final_catalog.secrets.keys().copied() {
            if let Some(previous) = claimed_secrets.insert(secret, scope.id) {
                bail!(
                    "secret {secret:X} appears in both v2 vault {previous:X} and {:X}",
                    scope.id
                );
            }
        }

        let data_pending = !required.facts().difference(&existing).is_empty();
        let report = VaultMigrationReport {
            vault: scope.id,
            current_readers: recipients.len(),
            secret_versions: scoped_secrets.len(),
            preserved_wraps: old_wraps.len(),
            synthesized_wraps,
            data_pending,
        };
        vaults.push(VaultPlan {
            vault: scope.id,
            recipients,
            required,
            report,
        });
    }

    let report = SecretsV2MigrationReport {
        source_facts: source.len(),
        vaults: vaults.iter().map(|vault| vault.report.clone()).collect(),
    };
    Ok(SecretsV2MigrationPlan {
        team: team.to_bytes(),
        vaults,
        report,
    })
}
