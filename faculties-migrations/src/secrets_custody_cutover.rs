//! Native direct-recipient Secrets vaults to capability/custody successors.
//!
//! This is deliberately separate from the pre-collection branch cutover. Its
//! source is the retired *native* direct-vault generation named by the durable
//! root's exact historical READ grants. The retained `secrets` branch is not
//! consulted, so a pile may discard that older source generation without
//! losing its path to the current custody model.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use triblespace::core::collection::CollectionAdmission;
use triblespace::core::repo::pile::Pile;
use triblespace::prelude::{BlobStore, TribleSet};

use crate::activation_cutover::PlannedActivationReader;
use crate::collection_cutover::{snapshot_native_collections_in, NativeCollectionSnapshot};
use crate::secrets_vault_cutover::{self, SecretsVaultMigrationPlan, SecretsVaultMigrationReport};
use faculties::storage::open_pile_strict;
use faculties::{decide, files, headspace, mail, relations, schemas, secrets, teams};

/// Complete publication plan for one native Secrets generation upgrade.
#[derive(Clone)]
pub struct SecretsCustodyCutoverPlan {
    direct: SecretsVaultMigrationPlan,
}

impl SecretsCustodyCutoverPlan {
    fn namespace(&self) -> [u8; 32] {
        self.direct.namespace()
    }

    pub fn report(&self) -> &SecretsVaultMigrationReport {
        self.direct.report()
    }

    pub fn pending_commits(&self) -> usize {
        self.pending_access_commits() + self.pending_vault_commits()
    }

    pub fn pending_access_commits(&self) -> usize {
        self.direct.access_inbox().len()
    }

    pub fn pending_vault_commits(&self) -> usize {
        self.direct
            .vaults()
            .iter()
            .filter(|vault| vault.report.data_pending)
            .count()
    }
}

/// Result of ensuring the custody successor directly in the live pile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdditiveActivationOutcome {
    Published { commits: usize },
    AlreadyActive,
}

/// Additively publish and validate the native custody successor.
///
/// A host-local advisory lock keyed by the opened pile's physical identity
/// serializes only competing custody activators. It does not lock the pile:
/// unrelated collection and blob appends continue to commute with the
/// migration. Every COMMIT remains its own atomic visibility boundary, with
/// the access envelope intentionally published before the vault. Re-running
/// this function repairs any crash prefix idempotently.
pub fn activate(pile_path: &Path, signer: &SigningKey) -> Result<AdditiveActivationOutcome> {
    let mut pile = open_pile_strict(pile_path)?;
    let _activation = match CustodyActivationLock::acquire(&pile) {
        Ok(activation) => activation,
        Err(error) => return finish_live_pile(pile, Err(error)),
    };
    let result = (|| {
        let source = snapshot_native_collections_in(&mut pile)
            .context("capture native collection snapshot for Secrets custody activation")?;
        let migration = plan(&source, signer)?;
        let pending = migration.pending_commits();
        if pending == 0 {
            return Ok(AdditiveActivationOutcome::AlreadyActive);
        }

        publish_live(&mut pile, signer, &migration)?;
        let final_source = snapshot_native_collections_in(&mut pile)
            .context("capture published Secrets custody snapshot")?;
        let remaining = plan(&final_source, signer)
            .context("replan additive Secrets custody publication")?
            .pending_commits();
        if remaining != 0 {
            bail!("Secrets custody publication left {remaining} pending COMMIT(s)");
        }
        Ok(AdditiveActivationOutcome::Published { commits: pending })
    })();
    finish_live_pile(pile, result)
}

struct CustodyActivationLock {
    file: File,
}

impl CustodyActivationLock {
    fn acquire(pile: &Pile) -> Result<Self> {
        let path = custody_activation_lock_path(pile)?;
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
        }
        let file = options
            .open(&path)
            .with_context(|| format!("open custody activation lock {}", path.display()))?;
        match file.try_lock() {
            Ok(()) => Ok(Self { file }),
            Err(TryLockError::WouldBlock) => bail!(
                "another Secrets custody activation already holds {}",
                path.display()
            ),
            Err(TryLockError::Error(error)) => {
                Err(error).with_context(|| format!("lock custody activation {}", path.display()))
            }
        }
    }
}

#[cfg(unix)]
fn custody_activation_lock_path(pile: &Pile) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    let metadata = pile
        .backing_file_metadata()
        .context("inspect physical pile identity for custody activation")?;
    Ok(PathBuf::from(format!(
        "/tmp/faculties-secrets-custody-v1-{:016x}-{:016x}.lock",
        metadata.dev(),
        metadata.ino()
    )))
}

#[cfg(not(unix))]
fn custody_activation_lock_path(_pile: &Pile) -> Result<PathBuf> {
    bail!("safe physical-identity custody activation locking is not implemented on this platform")
}

impl Drop for CustodyActivationLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn publish_live(
    pile: &mut triblespace::core::repo::pile::Pile,
    signer: &SigningKey,
    plan: &SecretsCustodyCutoverPlan,
) -> Result<usize> {
    if plan.namespace() != signer.verifying_key().to_bytes() {
        bail!("Secrets custody plan belongs to a different durable namespace");
    }
    let mut published = 0;
    {
        let mut inbox = secrets::storage::access_inbox_collection(
            &mut *pile,
            signer.verifying_key(),
            signer.clone(),
        );
        for fragment in plan.direct.access_inbox() {
            inbox
                .commit(fragment.clone())
                .context("publish founder access-inbox COMMIT")?;
            published += 1;
        }
    }

    for vault in plan
        .direct
        .vaults()
        .iter()
        .filter(|vault| vault.report.data_pending)
    {
        if vault.authority != signer.verifying_key()
            || vault.write_presentation.subject() != signer.verifying_key()
        {
            bail!("custody vault is not rooted in the durable signer");
        }
        secrets::vault_collection(
            &mut *pile,
            vault.vault,
            signer.verifying_key(),
            signer.clone(),
            CollectionAdmission::capability(
                vault.authority,
                vec![vault.write_presentation.clone()],
            ),
        )
        .commit(vault.required.clone())
        .with_context(|| format!("publish custody vault {:X} COMMIT", vault.vault))?;
        published += 1;
    }
    Ok(published)
}

fn finish_live_pile<T>(pile: triblespace::core::repo::pile::Pile, result: Result<T>) -> Result<T> {
    let close = pile.close();
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(anyhow!("close live pile: {error}")),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing live pile also failed: {close_error}")))
        }
    }
}

/// Plan only from the already-native direct-recipient generation.
pub fn plan(
    source: &NativeCollectionSnapshot,
    signer: &SigningKey,
) -> Result<SecretsCustodyCutoverPlan> {
    let mut store = source.collection_store();
    let direct =
        secrets_vault_cutover::plan_from_direct_in_store(&mut store, signer, source.reader())
            .context("plan native Secrets custody cutover")?;
    if direct.namespace() != signer.verifying_key().to_bytes() {
        bail!("Secrets custody plan belongs to a different durable namespace");
    }

    validate_planned_world(source, signer, &direct)
        .context("validate native Secrets custody plan against current consumers")?;
    Ok(SecretsCustodyCutoverPlan { direct })
}

fn validate_planned_world(
    source: &NativeCollectionSnapshot,
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
    validate_staged_access_inbox(signer, direct, &local_secrets)?;

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

fn validate_staged_access_inbox<R>(
    signer: &SigningKey,
    direct: &SecretsVaultMigrationPlan,
    local_secrets: &secrets::SecretsSnapshot<R>,
) -> Result<()>
where
    R: triblespace::core::repo::BlobStoreGet,
{
    let expected = direct
        .vaults()
        .iter()
        .filter(|vault| vault.report.access_pending)
        .map(|vault| {
            let location = secrets::storage::VaultLocation::new(
                vault.vault,
                signer.verifying_key(),
                vault.authority,
            );
            (location.collection(), (location, vault))
        })
        .collect::<BTreeMap<_, _>>();
    if expected.len() != direct.access_inbox().len() {
        bail!(
            "Secrets custody plan staged {} access envelope(s) for {} pending vault(s)",
            direct.access_inbox().len(),
            expected.len()
        );
    }
    if expected.is_empty() {
        return Ok(());
    }

    // Exercise the exact runtime inbox path in memory before the first live
    // COMMIT. This catches a malformed row, missing descriptor/proof blob,
    // publisher mismatch, or sealed-frame mismatch while the live pile is
    // still untouched.
    let (candidates, issues) =
        secrets::storage::discover_staged_access_candidates(direct.access_inbox(), signer, signer)
            .context("discover staged founder access envelopes")?;
    if !issues.is_empty() {
        let detail = issues
            .iter()
            .map(|issue| format!("{:?}: {}", issue.kind(), issue.detail()))
            .collect::<Vec<_>>()
            .join("; ");
        bail!("staged founder access envelope failed runtime discovery: {detail}");
    }
    if candidates.len() != expected.len() {
        bail!(
            "runtime discovery admitted {} staged access candidate(s); expected {}",
            candidates.len(),
            expected.len()
        );
    }

    let mut seen = BTreeMap::new();
    for candidate in candidates {
        let location = candidate.location();
        let Some((expected_location, vault)) = expected.get(&location.collection()) else {
            bail!(
                "runtime discovery admitted unexpected custody collection {:?}",
                location.collection()
            );
        };
        if location != *expected_location
            || candidate.publisher() != signer.verifying_key()
            || candidate.writer() != vault.write_presentation.subject()
        {
            bail!(
                "runtime discovery changed the authority of custody vault {:X}",
                vault.vault
            );
        }
        let declared_custody = local_secrets
            .vault_exact(location.collection())
            .and_then(|snapshot| snapshot.catalog().custody)
            .context("planned custody vault has no exact custody declaration")?
            .public_key;
        if candidate.custody().verifying_key().to_bytes() != declared_custody {
            bail!(
                "staged access envelope and custody vault {:X} name different custody keys",
                vault.vault
            );
        }
        if seen.insert(location.collection(), candidate.id()).is_some() {
            bail!(
                "runtime discovery admitted competing founder envelopes for vault {:X}",
                vault.vault
            );
        }
    }
    Ok(())
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
        .ok_or_else(|| anyhow!("Secrets custody plan has no observed {name} collection"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn activation_lock_serializes_only_competing_activators() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("self.pile");
        File::create(&path).unwrap();
        let first_pile = open_pile_strict(&path).unwrap();
        let second_pile = open_pile_strict(&path).unwrap();

        let first = CustodyActivationLock::acquire(&first_pile).unwrap();
        let error = CustodyActivationLock::acquire(&second_pile)
            .err()
            .expect("a second activator must not plan a competing custody epoch");
        assert!(format!("{error:#}").contains("another Secrets custody activation"));

        drop(first);
        CustodyActivationLock::acquire(&second_pile).unwrap();
        first_pile.close().unwrap();
        second_pile.close().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn activation_lock_converges_across_hard_links_and_renames() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("self.pile");
        let alias = directory.path().join("hard-link.pile");
        let renamed = directory.path().join("renamed.pile");
        File::create(&original).unwrap();
        std::fs::hard_link(&original, &alias).unwrap();

        let first_pile = open_pile_strict(&original).unwrap();
        let first = CustodyActivationLock::acquire(&first_pile).unwrap();
        let alias_pile = open_pile_strict(&alias).unwrap();
        assert!(CustodyActivationLock::acquire(&alias_pile).is_err());

        std::fs::rename(&original, &renamed).unwrap();
        let renamed_pile = open_pile_strict(&renamed).unwrap();
        assert!(CustodyActivationLock::acquire(&renamed_pile).is_err());

        drop(first);
        CustodyActivationLock::acquire(&renamed_pile).unwrap();
        first_pile.close().unwrap();
        alias_pile.close().unwrap();
        renamed_pile.close().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn activation_lock_does_not_serialize_distinct_piles() {
        let directory = tempfile::tempdir().unwrap();
        let first_path = directory.path().join("first.pile");
        let second_path = directory.path().join("second.pile");
        File::create(&first_path).unwrap();
        File::create(&second_path).unwrap();
        let first_pile = open_pile_strict(&first_path).unwrap();
        let second_pile = open_pile_strict(&second_path).unwrap();

        let _first = CustodyActivationLock::acquire(&first_pile).unwrap();
        let _second = CustodyActivationLock::acquire(&second_pile).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn activation_lock_does_not_block_ordinary_pile_appends() {
        use triblespace::prelude::{blobencodings, BlobStorePut};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("self.pile");
        File::create(&path).unwrap();
        let activation_pile = open_pile_strict(&path).unwrap();
        let _activation = CustodyActivationLock::acquire(&activation_pile).unwrap();

        let mut writer = open_pile_strict(&path).unwrap();
        writer
            .put::<blobencodings::RawBytes, _>(b"ordinary concurrent append".to_vec())
            .unwrap();
        writer.close().unwrap();
        drop(_activation);
        activation_pile.close().unwrap();
    }
}
