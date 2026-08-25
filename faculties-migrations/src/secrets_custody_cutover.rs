//! Native direct-recipient Secrets vaults to capability/custody successors.
//!
//! This is deliberately separate from the pre-collection branch cutover. Its
//! source is the retired *native* direct-vault generation named by the durable
//! root's exact historical READ grants. The retained `secrets` branch is not
//! consulted, so a pile may discard that older source generation without
//! losing its path to the current custody model.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use triblespace::prelude::{BlobStore, TribleSet};

use crate::activation_cutover::{
    materialized_facts, CandidateViews, PlannedActivationReader, PlannedCollection,
};
use crate::collection_cutover::FrozenSource;
use crate::secrets_vault_cutover::{self, SecretsVaultMigrationReport};
use faculties::{decide, files, headspace, mail, relations, schemas, secrets, teams};

/// Complete publication plan for one native Secrets generation upgrade.
#[derive(Clone)]
pub struct SecretsCustodyCutoverPlan {
    namespace: [u8; 32],
    collections: Vec<PlannedCollection>,
    report: SecretsVaultMigrationReport,
}

impl SecretsCustodyCutoverPlan {
    pub const fn namespace(&self) -> [u8; 32] {
        self.namespace
    }

    pub fn collections(&self) -> &[PlannedCollection] {
        &self.collections
    }

    pub const fn report(&self) -> &SecretsVaultMigrationReport {
        &self.report
    }
}

/// Plan only from the already-native direct-recipient generation.
pub fn plan(source: &FrozenSource, signer: &SigningKey) -> Result<SecretsCustodyCutoverPlan> {
    let mut store = source.collection_store();
    let direct =
        secrets_vault_cutover::plan_from_direct_in_store(&mut store, signer, source.reader())
            .context("plan native Secrets custody cutover")?;
    if direct.namespace() != signer.verifying_key().to_bytes() {
        bail!("Secrets custody plan belongs to a different durable namespace");
    }

    let mut collections = Vec::new();
    if !direct.vaults().is_empty() {
        let fragments = direct.access_inbox().to_vec();
        collections.push(PlannedCollection::access_inbox(
            signer.verifying_key(),
            fragments.clone(),
            materialized_facts(&fragments),
        )?);
    }
    for vault in direct.vaults() {
        let fragments = vault
            .report
            .data_pending
            .then(|| vault.required.clone())
            .into_iter()
            .collect::<Vec<_>>();
        let expected_facts = materialized_facts(&fragments);
        collections.push(PlannedCollection::vault(
            vault.vault,
            fragments,
            expected_facts,
            vault.authority,
            vault.write_presentation.clone(),
        )?);
    }
    validate_planned_world(source, signer, &direct)
        .context("validate native Secrets custody plan against current consumers")?;
    // These are observations, not write targets. They put the exact native
    // consumers of Secrets into the candidate view so the final validator can
    // prove that every stored reference still resolves after the successor is
    // published. Empty fragment lists mean no COMMIT can be emitted.
    collections.extend(
        observed_scopes()
            .into_iter()
            .map(PlannedCollection::observe),
    );

    Ok(SecretsCustodyCutoverPlan {
        namespace: direct.namespace(),
        collections,
        report: direct.report().clone(),
    })
}

/// Validate the exact Secrets world exposed through the recipient's inbox.
///
/// Candidate construction has already required every planned target to be
/// discoverable through its founder envelope. Re-running the domain parser
/// here keeps the standalone migration's final semantic check explicit rather
/// than borrowing the unrelated all-faculty validator.
pub fn validate_candidate_views(
    reader: &triblespace::core::repo::pile::PileReader,
    views: &CandidateViews,
) -> Result<()> {
    let expected_scopes = BTreeSet::from(observed_scopes());
    if views.faculties().keys().copied().collect::<BTreeSet<_>>() != expected_scopes {
        bail!("Secrets custody candidate has the wrong observed consumer set");
    }
    for (collection, (vault, facts)) in views.local_vaults() {
        let catalog = secrets::validate_catalog(reader, *vault, facts)
            .with_context(|| format!("validate custody vault {vault:X} at {collection:?}"))?;
        if catalog.custody.is_none() {
            bail!("inbox-discovered vault {vault:X} has no custody declaration");
        }
    }

    let local_secrets = secrets::SecretsSnapshot::new_exact(
        reader.clone(),
        views
            .local_vaults()
            .iter()
            .map(|(collection, (vault, facts))| (*collection, *vault, facts.clone())),
    )
    .context("validate inbox-discovered Secrets custody snapshot")?;
    validate_consumers(reader, views.faculties(), &local_secrets)
}

fn validate_planned_world(
    source: &FrozenSource,
    signer: &SigningKey,
    direct: &secrets_vault_cutover::SecretsVaultMigrationPlan,
) -> Result<()> {
    let mut store = source.collection_store();
    let discovered = secrets::storage::discover_local_vaults(&mut store, signer)
        .context("discover current inbox-addressed Secrets baseline")?;
    let mut vaults = discovered
        .snapshot()
        .vaults()
        .iter()
        .map(|snapshot| {
            let collection = snapshot
                .collection()
                .context("inbox-discovered vault lost its exact collection identity")?;
            Ok((collection, (snapshot.id(), snapshot.facts().clone())))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    drop(discovered);

    let mut staged = triblespace::prelude::Fragment::empty();
    for vault in direct.vaults() {
        let collection =
            secrets::vault_handle(vault.vault, signer.verifying_key(), vault.authority);
        let (id, facts) = vaults
            .entry(collection)
            .or_insert_with(|| (vault.vault, TribleSet::new()));
        if *id != vault.vault {
            bail!("one exact custody collection resolved to two vault ids");
        }
        *facts += vault.required.facts().clone();
        staged += vault.required.clone();
    }
    let staged_reader = staged
        .blobs_mut()
        .reader()
        .context("snapshot planned custody attachments")?;
    let local_secrets = secrets::SecretsSnapshot::new_exact(
        PlannedActivationReader::new(&staged_reader, source.reader()),
        vaults
            .iter()
            .map(|(collection, (vault, facts))| (*collection, *vault, facts.clone())),
    )
    .context("validate planned custody successor vaults")?;

    let scopes = observed_scopes();
    let consumer_facts = scopes
        .into_iter()
        .map(|scope| {
            let facts = faculties::collection_names::open(&mut store, scope, signer.clone())
                .materialize()
                .with_context(|| format!("materialize observed consumer {scope:X}"))?;
            Ok((scope, facts))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    validate_consumers(source.reader(), &consumer_facts, &local_secrets)
}

fn validate_consumers<R>(
    reader: &triblespace::core::repo::pile::PileReader,
    views: &BTreeMap<triblespace::prelude::Id, TribleSet>,
    local_secrets: &secrets::SecretsSnapshot<R>,
) -> Result<()> {
    let files_facts = observed(views, schemas::files::DEFAULT_SCOPE_ID, "Files")?;
    files::validate_catalog(reader, files_facts).context("validate observed Files collection")?;
    let decide_facts = observed(views, schemas::decide::DEFAULT_SCOPE_ID, "Decide")?;
    decide::validate_catalog(reader, decide_facts)
        .context("validate observed Decide collection")?;
    let relation_facts = observed(views, schemas::relations::DEFAULT_SCOPE_ID, "Relations")?;
    relations::validate_catalog(reader, relation_facts)
        .context("validate observed Relations collection")?;
    let headspace_facts = observed(views, schemas::headspace::DEFAULT_SCOPE_ID, "Headspace")?;
    let headspace_catalog = headspace::project_result(reader, headspace_facts)
        .context("validate observed Headspace collection")?;
    headspace::validate_secret_references(&headspace_catalog, &local_secrets)
        .context("validate Headspace references against custody successors")?;
    let teams_facts = observed(views, schemas::teams::DEFAULT_SCOPE_ID, "Teams")?;
    teams::validate_catalog(reader, teams_facts).context("validate observed Teams collection")?;
    teams::validate_auth_secret_references(teams_facts, &local_secrets)
        .context("validate Teams references against custody successors")?;
    let mail_facts = observed(views, schemas::mail::DEFAULT_SCOPE_ID, "Mail")?;
    mail::validate_local_catalog(reader, mail_facts)
        .context("validate observed Mail collection")?;
    mail::validate_catalog(
        reader,
        mail_facts,
        files_facts,
        decide_facts,
        relation_facts,
        &local_secrets,
    )
    .context("validate Mail references against custody successors")?;
    Ok(())
}

fn observed_scopes() -> [triblespace::prelude::Id; 6] {
    [
        schemas::files::DEFAULT_SCOPE_ID,
        schemas::decide::DEFAULT_SCOPE_ID,
        schemas::relations::DEFAULT_SCOPE_ID,
        schemas::headspace::DEFAULT_SCOPE_ID,
        schemas::mail::DEFAULT_SCOPE_ID,
        schemas::teams::DEFAULT_SCOPE_ID,
    ]
}

fn observed<'a>(
    views: &'a BTreeMap<triblespace::prelude::Id, TribleSet>,
    scope: triblespace::prelude::Id,
    name: &str,
) -> Result<&'a TribleSet> {
    views
        .get(&scope)
        .ok_or_else(|| anyhow!("Secrets custody candidate has no observed {name} collection"))
}
