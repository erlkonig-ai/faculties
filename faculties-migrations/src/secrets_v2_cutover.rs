//! Additive stopped-world cutover from the frozen v1 Secrets collection to
//! one direct-key v2 vault collection per confidentiality epoch.
//!
//! The old collection is retained byte-for-byte.  Planning first validates
//! every source and target catalog, copies the exact encrypted payloads into a
//! self-contained candidate, and proves cross-vault identity uniqueness.  No
//! destination byte is appended until that complete preflight succeeds.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use faculties::secrets::v2::{self, RecipientPublicKey, VaultCatalog, ACTION_READ};
use triblespace::core::authority::{
    publish_grant, resolve_authority, AuthorityGrant, AuthorityMode, ACTION_WRITE,
};
use triblespace::core::collection::reach;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet};
use triblespace::prelude::*;

use crate::legacy_secrets_v1 as legacy;
use faculties::storage::{load_signer, open_pile_strict};

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
struct VaultPlan {
    vault: Id,
    recipients: BTreeSet<RecipientPublicKey>,
    existing: TribleSet,
    required: Fragment,
    report: VaultMigrationReport,
}

/// Complete read-only preflight.  The plan owns every attachment needed by a
/// later vault commit; publication never needs the password or plaintext DEK.
#[derive(Clone)]
pub struct SecretsV2MigrationPlan {
    team: RecipientPublicKey,
    source: TribleSet,
    vaults: Vec<VaultPlan>,
    report: SecretsV2MigrationReport,
}

impl SecretsV2MigrationPlan {
    pub fn report(&self) -> &SecretsV2MigrationReport {
        &self.report
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SecretsV2PublicationReport {
    pub write_grants: usize,
    pub vault_commits: usize,
    pub read_grants: usize,
}

fn legacy_collection<S>(storage: S, team: VerifyingKey, signer: SigningKey) -> Collection<S> {
    Collection::new(
        storage,
        &CollectionName::new(legacy::COLLECTION_NAME)
            .expect("the frozen legacy collection name is valid"),
        team,
        signer,
        reach::private(),
    )
}

fn materialize_legacy(
    pile: &mut Pile,
    team: VerifyingKey,
    signer: &SigningKey,
) -> Result<TribleSet> {
    legacy_collection(pile, team, signer.clone())
        .materialize()
        .context("materialize frozen v1 Secrets collection")
}

fn materialize_vault(
    pile: &mut Pile,
    vault: Id,
    team: VerifyingKey,
    signer: &SigningKey,
) -> Result<TribleSet> {
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

fn plan_in_open_pile(
    pile: &mut Pile,
    signer: &SigningKey,
    password: Option<&[u8]>,
) -> Result<SecretsV2MigrationPlan> {
    let team = signer.verifying_key();
    let source = materialize_legacy(pile, team, signer)?;
    if source.is_empty() {
        bail!("the frozen v1 Secrets collection is empty; refuse to create parallel empty vaults");
    }

    let reader = pile
        .reader()
        .context("open v1 Secrets preflight attachment reader")?;
    let catalog =
        legacy::validate_catalog(&reader, &source).context("validate frozen v1 Secrets catalog")?;
    let identity_keys = legacy::identity_public_keys(&reader, &catalog)?;
    drop(reader);

    let mut existing_by_vault = BTreeMap::new();
    for vault in catalog.scopes.keys().copied() {
        existing_by_vault.insert(vault, materialize_vault(pile, vault, team, signer)?);
    }

    let reader = pile
        .reader()
        .context("open complete Secrets v2 planning attachment reader")?;
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
        let vault_name = legacy::read_text(&reader, scope.name)
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
            let body = legacy::read_bytes(&reader, secret.body)
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
            let sealed = legacy::read_bytes(&reader, wrap.sealed_dek)
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
                v2::validate_catalog(&reader, scope.id, &existing)
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
                legacy::recover_dek_for_migration(&reader, &catalog, secret.id, signer, password)?;
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

        let final_catalog = validate_candidate(&reader, scope.id, &existing, &required)?;
        for secret in &scoped_secrets {
            let actual = final_catalog
                .wrap_holders(secret.id)
                .intersection(&recipients)
                .count();
            if actual != recipients.len() {
                bail!("v2 vault candidate leaves a current reader without a secret wrap");
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
            existing,
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
        source,
        vaults,
        report,
    })
}

/// Build a complete read-only migration plan.  `password` is needed only if a
/// current reader lacks a wrap and no locally held node key can recover the
/// exact legacy DEK.  Completed replay therefore needs no retired password.
pub fn plan(
    pile: &Path,
    key: Option<&Path>,
    password: Option<&[u8]>,
) -> Result<SecretsV2MigrationPlan> {
    let signer = load_signer(pile, key).context("load durable signer for Secrets v2 planning")?;
    let mut store = open_pile_strict(pile)?;
    let result = plan_in_open_pile(&mut store, &signer, password);
    finish_pile(store, result)
}

fn preflight_plan(
    pile: &mut Pile,
    signer: &SigningKey,
    plan: &SecretsV2MigrationPlan,
) -> Result<()> {
    if signer.verifying_key().to_bytes() != plan.team {
        bail!("Secrets v2 plan belongs to a different durable team root");
    }
    let team = signer.verifying_key();
    let source = materialize_legacy(pile, team, signer)?;
    if source != plan.source {
        bail!("v1 Secrets source changed after complete migration preflight");
    }
    let mut current = Vec::with_capacity(plan.vaults.len());
    for vault in &plan.vaults {
        let facts = materialize_vault(pile, vault.vault, team, signer)?;
        if facts != vault.existing {
            bail!(
                "v2 vault {} changed after complete migration preflight",
                vault.vault
            );
        }
        current.push(facts);
    }
    let reader = pile
        .reader()
        .context("open Secrets v2 publication preflight reader")?;
    let mut claimed = BTreeMap::<Id, Id>::new();
    for (vault, existing) in plan.vaults.iter().zip(current) {
        let catalog = validate_candidate(&reader, vault.vault, &existing, &vault.required)?;
        for secret in catalog.secrets.keys().copied() {
            if let Some(previous) = claimed.insert(secret, vault.vault) {
                bail!(
                    "secret {secret:X} appears in both v2 vault {previous:X} and {:X}",
                    vault.vault
                );
            }
        }
    }
    Ok(())
}

fn exact_grant_present(pile: &mut Pile, team: VerifyingKey, grant: AuthorityGrant) -> Result<bool> {
    let resolution = resolve_authority(pile, team)
        .map_err(|error| anyhow!("resolve v2 vault authority: {error}"))?;
    let present = resolution
        .grants()
        .any(|accepted| accepted.grant() == grant);
    Ok(present)
}

fn ensure_grant(
    pile: &mut Pile,
    team: VerifyingKey,
    signer: &SigningKey,
    grant: AuthorityGrant,
) -> Result<bool> {
    if exact_grant_present(pile, team, grant)? {
        return Ok(false);
    }
    publish_grant(pile, team, signer, grant)
        .map_err(|error| anyhow!("publish v2 vault authority grant: {error}"))?;
    if !exact_grant_present(pile, team, grant)? {
        bail!("published v2 vault grant did not enter the accepted authority fixed point");
    }
    Ok(true)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StopAfter {
    Write,
    Data,
}

fn publish_in_open_pile(
    pile: &mut Pile,
    signer: &SigningKey,
    plan: &SecretsV2MigrationPlan,
    #[cfg(test)] stop_after: Option<StopAfter>,
) -> Result<SecretsV2PublicationReport> {
    preflight_plan(pile, signer, plan)?;
    let team = signer.verifying_key();
    let mut report = SecretsV2PublicationReport::default();

    for vault in &plan.vaults {
        let expected = v2::vault_handle(vault.vault, team);
        let write = AuthorityGrant::root(team, expected, ACTION_WRITE, AuthorityMode::Invoke);
        if ensure_grant(pile, team, signer, write)? {
            report.write_grants += 1;
        }
        #[cfg(test)]
        if stop_after == Some(StopAfter::Write) {
            bail!("injected crash after v2 vault WRITE grant");
        }

        if vault.report.data_pending {
            v2::vault_collection(&mut *pile, vault.vault, team, signer.clone())
                .commit(vault.required.clone())
                .with_context(|| format!("commit complete v2 vault {}", vault.vault))?;
            report.vault_commits += 1;
        }
        #[cfg(test)]
        if stop_after == Some(StopAfter::Data) {
            bail!("injected crash after complete v2 vault data commit");
        }

        for recipient in &vault.recipients {
            let recipient = VerifyingKey::from_bytes(recipient)
                .context("validate planned v2 READ recipient")?;
            let read =
                AuthorityGrant::root(recipient, expected, ACTION_READ, AuthorityMode::Invoke);
            if ensure_grant(pile, team, signer, read)? {
                report.read_grants += 1;
            }
        }
    }

    for vault in &plan.vaults {
        let facts = materialize_vault(pile, vault.vault, team, signer)?;
        let reader = pile
            .reader()
            .context("open published v2 vault validation reader")?;
        v2::validate_catalog(&reader, vault.vault, &facts)
            .with_context(|| format!("validate published v2 vault {}", vault.vault))?;
        let authority = resolve_authority(pile, team)
            .map_err(|error| anyhow!("resolve final v2 READ authority: {error}"))?;
        let actual =
            v2::read_authority_recipient_keys(&authority, v2::vault_handle(vault.vault, team));
        if !vault.recipients.is_subset(&actual) {
            bail!("published v2 vault is missing one or more planned READ grants");
        }
    }
    Ok(report)
}

/// Publish root WRITE -> one complete vault commit -> root READ for every
/// vault. `Collection::commit` carries the descriptor alongside the first
/// complete data commit. An interrupted prefix is safe and a fresh plan adopts
/// a committed synthetic wrap instead of generating another.
pub fn publish(
    pile: &Path,
    key: Option<&Path>,
    plan: &SecretsV2MigrationPlan,
) -> Result<SecretsV2PublicationReport> {
    let signer = load_signer(pile, key).context("load durable signer for Secrets v2 publish")?;
    let mut store = open_pile_strict(pile)?;
    let result = publish_in_open_pile(
        &mut store,
        &signer,
        plan,
        #[cfg(test)]
        None,
    );
    finish_pile(store, result)
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    let close = pile.close();
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(anyhow!("close Secrets v2 pile: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing Secrets v2 pile also failed: {close_error}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};

    use hifitime::Epoch;
    use tempfile::TempDir;

    use super::*;
    use faculties::secrets as old;
    use faculties::storage::{
        ensure_team_of_one_write_authority, initialize_signer, load_signer, open_pile_strict,
    };

    fn at(second: i64) -> legacy::IntervalValue {
        let epoch = Epoch::from_unix_seconds(second as f64);
        (epoch, epoch).try_to_inline().unwrap()
    }

    struct Fixture {
        _directory: TempDir,
        pile: std::path::PathBuf,
        key: std::path::PathBuf,
        password: Vec<u8>,
        scope: Id,
        secret: Id,
        historical_key: RecipientPublicKey,
        source: TribleSet,
        source_catalog: legacy::Catalog,
    }

    fn commit_legacy(pile_path: &Path, key_path: &Path, fragment: Fragment) {
        let signer = load_signer(pile_path, Some(key_path)).unwrap();
        let pile = open_pile_strict(pile_path).unwrap();
        let mut collection =
            faculties::collection_names::open(pile, old::schema::DEFAULT_SCOPE_ID, signer);
        collection.commit(fragment).unwrap();
        collection.into_storage().close().unwrap();
    }

    fn snapshot_legacy(pile_path: &Path, key_path: &Path) -> (TribleSet, legacy::Catalog) {
        let signer = load_signer(pile_path, Some(key_path)).unwrap();
        let pile = open_pile_strict(pile_path).unwrap();
        let mut collection =
            faculties::collection_names::open(pile, old::schema::DEFAULT_SCOPE_ID, signer);
        let facts = collection.materialize().unwrap();
        let reader = collection.storage_mut().reader().unwrap();
        let catalog = legacy::validate_catalog(&reader, &facts).unwrap();
        drop(reader);
        collection.into_storage().close().unwrap();
        (facts, catalog)
    }

    fn fixture() -> Fixture {
        fixture_with_body_authentication(true)
    }

    fn fixture_with_body_authentication(authenticated_body: bool) -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("faculties.pile");
        let key = directory.path().join("faculties.key");
        let password = b"migration fixture password".to_vec();
        let signer = initialize_signer(&pile, Some(&key)).unwrap();

        File::create(&pile).unwrap();
        let mut store = Pile::open(&pile).unwrap();
        ensure_team_of_one_write_authority(&mut store, &signer).unwrap();
        store.close().unwrap();

        let creator = old::prepare_identity("creator", &password, at(1)).unwrap();
        let creator_id = creator.id;
        let historical_signer = SigningKey::from_bytes(&[0x41; 32]);
        let historical_key = historical_signer.verifying_key().to_bytes();
        let historical = old::prepare_node_identity("historical", &historical_key, at(2)).unwrap();
        let historical_id = historical.id;
        let scope_fragment = old::scope_fragment(creator_id, "epoch", at(3)).unwrap();
        let scope = scope_fragment.root().unwrap();
        let historical_grant = genid().id;
        let mut foundation = creator.fragment;
        foundation += historical.fragment;
        foundation += scope_fragment;
        foundation += old::grant_fragment(
            historical_grant,
            scope,
            "member",
            historical_id,
            creator_id,
            at(4),
        )
        .unwrap();
        commit_legacy(&pile, &key, foundation);

        let signer_for_view = load_signer(&pile, Some(&key)).unwrap();
        let pile_store = open_pile_strict(&pile).unwrap();
        let mut collection = faculties::collection_names::open(
            pile_store,
            old::schema::DEFAULT_SCOPE_ID,
            signer_for_view,
        );
        let facts = collection.materialize().unwrap();
        let reader = collection.storage_mut().reader().unwrap();
        let catalog = old::validate_catalog(&reader, &facts).unwrap();
        let sealed = old::seal_version(
            &reader,
            &catalog,
            scope,
            "service",
            b"body remains encrypted during cutover",
            at(5),
        )
        .unwrap();
        let secret = sealed.secret;
        drop(reader);
        let sealed_fragment = if authenticated_body {
            sealed.fragment
        } else {
            let (_, facts, metafacts, blobs) = sealed.fragment.into_parts();
            let old_body_facts = facts
                .iter()
                .filter(|fact| fact.a() == &old::schema::secret_body.id())
                .copied()
                .collect::<TribleSet>();
            let facts = facts.difference(&old_body_facts);
            let mut fragment = Fragment::from_parts(facts, metafacts, blobs);
            // nonce(24) || a syntactically valid 16-byte secretbox MAC.  It
            // cannot authenticate under the original DEK, so any migration
            // code that crosses the DEM boundary will fail this fixture.
            let body = fragment.put::<blobencodings::RawBytes, _>(vec![0; 24 + 16]);
            fragment += entity! { ExclusiveId::force_ref(&secret) @
                old::schema::secret_body: body
            };
            fragment
        };
        collection.commit(sealed_fragment).unwrap();
        collection.into_storage().close().unwrap();

        let node =
            old::prepare_node_identity("durable-node", signer.verifying_key().as_bytes(), at(6))
                .unwrap();
        let node_id = node.id;
        let mut authority_change = node.fragment;
        authority_change +=
            old::grant_fragment(genid().id, scope, "member", node_id, creator_id, at(7)).unwrap();
        authority_change += old::retraction_fragment([historical_grant], at(8)).unwrap();
        commit_legacy(&pile, &key, authority_change);

        let (source, source_catalog) = snapshot_legacy(&pile, &key);
        Fixture {
            _directory: directory,
            pile,
            key,
            password,
            scope,
            secret,
            historical_key,
            source,
            source_catalog,
        }
    }

    #[test]
    fn exact_additive_cutover_preserves_history_repairs_one_dek_and_replays_to_noop() {
        let fixture = fixture();
        let missing = match plan(&fixture.pile, Some(&fixture.key), None) {
            Ok(_) => panic!("cutover unexpectedly planned without the legacy password"),
            Err(error) => error,
        };
        assert!(
            missing.downcast_ref::<legacy::PasswordRequired>().is_some(),
            "{missing:#}"
        );

        let migration_plan =
            plan(&fixture.pile, Some(&fixture.key), Some(&fixture.password)).unwrap();
        assert_eq!(migration_plan.report().vaults.len(), 1);
        assert_eq!(migration_plan.report().secret_versions(), 1);
        assert_eq!(migration_plan.report().preserved_wraps(), 2);
        assert_eq!(migration_plan.report().synthesized_wraps(), 1);
        assert_eq!(migration_plan.report().pending_vaults(), 1);

        let vault_plan = &migration_plan.vaults[0];
        let projected = v2::load_catalog(fixture.scope, vault_plan.required.facts()).unwrap();
        let old_secret = &fixture.source_catalog.secrets[&fixture.secret];
        assert_eq!(projected.secrets[&fixture.secret].body, old_secret.body);
        assert_eq!(
            projected.secrets[&fixture.secret].name,
            old_secret.display_name
        );
        for old_wrap in fixture
            .source_catalog
            .wraps
            .values()
            .filter(|wrap| wrap.secret == fixture.secret)
        {
            let projected_wrap = projected.wraps.get(&old_wrap.id).unwrap();
            assert_eq!(projected_wrap.sealed_dek, old_wrap.sealed_dek);
        }

        let published = publish(&fixture.pile, Some(&fixture.key), &migration_plan).unwrap();
        assert_eq!(published.vault_commits, 1);
        assert_eq!(published.write_grants, 1);
        assert_eq!(published.read_grants, 2);
        let (source_after, _) = snapshot_legacy(&fixture.pile, &fixture.key);
        assert_eq!(source_after, fixture.source);

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        let facts =
            materialize_vault(&mut pile, fixture.scope, signer.verifying_key(), &signer).unwrap();
        let reader = pile.reader().unwrap();
        let catalog = v2::validate_catalog(&reader, fixture.scope, &facts).unwrap();
        assert_eq!(
            v2::open_version(&reader, &catalog, fixture.secret, &signer).unwrap(),
            b"body remains encrypted during cutover"
        );
        assert!(catalog
            .wraps
            .values()
            .any(|wrap| wrap.recipient == fixture.historical_key));
        let authority = resolve_authority(&mut pile, signer.verifying_key()).unwrap();
        let readers = v2::read_authority_recipient_keys(
            &authority,
            v2::vault_handle(fixture.scope, signer.verifying_key()),
        );
        assert!(!readers.contains(&fixture.historical_key));
        drop(reader);
        pile.close().unwrap();

        let replay = plan(&fixture.pile, Some(&fixture.key), None).unwrap();
        assert_eq!(replay.report().synthesized_wraps(), 0);
        assert_eq!(replay.report().pending_vaults(), 0);
        let before = fs::metadata(&fixture.pile).unwrap().len();
        assert_eq!(
            publish(&fixture.pile, Some(&fixture.key), &replay).unwrap(),
            SecretsV2PublicationReport::default()
        );
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), before);
    }

    #[test]
    fn every_publication_crash_prefix_resumes_without_reencrypting_a_body() {
        for stop in [StopAfter::Write, StopAfter::Data] {
            let fixture = fixture();
            let initial = plan(&fixture.pile, Some(&fixture.key), Some(&fixture.password)).unwrap();
            let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
            let mut store = open_pile_strict(&fixture.pile).unwrap();
            let interrupted = publish_in_open_pile(&mut store, &signer, &initial, Some(stop));
            assert!(interrupted.is_err());
            store.close().unwrap();

            let resumed = if stop == StopAfter::Data {
                let plan = plan(&fixture.pile, Some(&fixture.key), None).unwrap();
                assert_eq!(plan.report().synthesized_wraps(), 0);
                plan
            } else {
                plan(&fixture.pile, Some(&fixture.key), Some(&fixture.password)).unwrap()
            };
            publish(&fixture.pile, Some(&fixture.key), &resumed).unwrap();
            let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
            let mut pile = open_pile_strict(&fixture.pile).unwrap();
            let facts =
                materialize_vault(&mut pile, fixture.scope, signer.verifying_key(), &signer)
                    .unwrap();
            let reader = pile.reader().unwrap();
            let catalog = v2::validate_catalog(&reader, fixture.scope, &facts).unwrap();
            assert_eq!(
                v2::open_version(&reader, &catalog, fixture.secret, &signer).unwrap(),
                b"body remains encrypted during cutover"
            );
            drop(reader);
            pile.close().unwrap();
        }
    }

    #[test]
    fn cutover_never_authenticates_or_decrypts_the_encrypted_body() {
        let fixture = fixture_with_body_authentication(false);
        let migration_plan =
            plan(&fixture.pile, Some(&fixture.key), Some(&fixture.password)).unwrap();
        publish(&fixture.pile, Some(&fixture.key), &migration_plan).unwrap();

        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        let facts =
            materialize_vault(&mut pile, fixture.scope, signer.verifying_key(), &signer).unwrap();
        let reader = pile.reader().unwrap();
        let catalog = v2::validate_catalog(&reader, fixture.scope, &facts).unwrap();
        let error = v2::open_version(&reader, &catalog, fixture.secret, &signer).unwrap_err();
        assert!(format!("{error:#}").contains("decrypt secret body failed"));
        drop(reader);
        pile.close().unwrap();
    }

    #[test]
    fn multiple_legacy_scope_creation_observations_fail_closed() {
        let fixture = fixture();
        let duplicate = entity! { ExclusiveId::force_ref(&fixture.scope) @
            triblespace::core::metadata::created_at: at(99)
        };
        commit_legacy(&fixture.pile, &fixture.key, duplicate);
        let error = match plan(&fixture.pile, Some(&fixture.key), Some(&fixture.password)) {
            Ok(_) => panic!("cutover accepted competing scope creation observations"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("requires exactly one"),
            "{error:#}"
        );
    }

    #[test]
    fn stale_full_preflight_fails_before_any_destination_byte_is_appended() {
        let fixture = fixture();
        let migration_plan =
            plan(&fixture.pile, Some(&fixture.key), Some(&fixture.password)).unwrap();
        let late_source_fact = entity! { ExclusiveId::force_ref(&fixture.scope) @
            triblespace::core::metadata::created_at: at(99)
        };
        commit_legacy(&fixture.pile, &fixture.key, late_source_fact);
        let before = fs::metadata(&fixture.pile).unwrap().len();
        let error = publish(&fixture.pile, Some(&fixture.key), &migration_plan).unwrap_err();
        assert!(
            format!("{error:#}").contains("source changed after complete migration preflight"),
            "{error:#}"
        );
        assert_eq!(
            fs::metadata(&fixture.pile).unwrap().len(),
            before,
            "a stale full preflight appended destination bytes before failing"
        );
    }
}
