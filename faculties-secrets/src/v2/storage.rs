//! Pile-backed discovery and publication workflows for vault-epoch Secrets.
//!
//! A vault is not registered anywhere. It becomes visible to one node when a
//! team's positive authority ledger contains an accepted exact `READ` grant
//! for that node's durable public key. Discovery validates each resulting
//! descriptor and vault independently: incomplete replication remains a
//! pending diagnostic and cannot suppress an otherwise ready vault.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace::core::authority::{self, AuthorityGrant, AuthorityMode, ACTION_WRITE};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::{Blob, TryFromBlob};
use triblespace::core::collection::{
    descriptor, discover_collection_records, CollectionCommit, CollectionHandle,
};
use triblespace::core::inline::encodings::ed25519::ED25519PublicKey;
use triblespace::core::inline::Inline;
use triblespace::core::metadata;
use triblespace::core::repo::pile::{GetBlobError, Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet};
use triblespace::prelude::*;

use super::schema::KIND_VAULT;
use super::{
    load_catalog, parse_vault_name, read_authority_recipient_keys, seal_version, share_version,
    validate_catalog, vault_collection, vault_descriptor, vault_handle, vault_header_fragment,
    IntervalValue, RecipientPublicKey, SecretsSnapshot, VaultCatalog, ACTION_READ,
};

/// One ready vault's exact collection identity and owning team.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultLocation {
    vault: Id,
    team: VerifyingKey,
    collection: CollectionHandle,
}

impl VaultLocation {
    pub const fn vault(&self) -> Id {
        self.vault
    }

    pub const fn team(&self) -> VerifyingKey {
        self.team
    }

    pub const fn collection(&self) -> CollectionHandle {
        self.collection
    }
}

/// Classification of one candidate that did not become a ready vault.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum VaultDiscoveryIssueKind {
    AuthorityUnavailable,
    MissingDescriptor,
    InvalidDescriptor,
    ConflictingVaultId,
    MaterializationFailed,
    MissingHeader,
    InvalidVault,
}

/// Independent evidence about one non-ready candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultDiscoveryIssue {
    kind: VaultDiscoveryIssueKind,
    team: VerifyingKey,
    collection: CollectionHandle,
    vault: Option<Id>,
    detail: String,
}

impl VaultDiscoveryIssue {
    pub const fn kind(&self) -> VaultDiscoveryIssueKind {
        self.kind
    }

    pub const fn team(&self) -> VerifyingKey {
        self.team
    }

    pub const fn collection(&self) -> CollectionHandle {
        self.collection
    }

    pub const fn vault(&self) -> Option<Id> {
        self.vault
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Ready local vaults plus pending or rejected candidates from one observation.
pub struct VaultDiscovery {
    snapshot: SecretsSnapshot<PileReader>,
    locations: BTreeMap<Id, VaultLocation>,
    issues: Vec<VaultDiscoveryIssue>,
}

impl VaultDiscovery {
    pub fn snapshot(&self) -> &SecretsSnapshot<PileReader> {
        &self.snapshot
    }

    pub fn locations(&self) -> &BTreeMap<Id, VaultLocation> {
        &self.locations
    }

    pub fn location(&self, vault: Id) -> Option<&VaultLocation> {
        self.locations.get(&vault)
    }

    pub fn issues(&self) -> &[VaultDiscoveryIssue] {
        &self.issues
    }

    pub fn into_parts(
        self,
    ) -> (
        SecretsSnapshot<PileReader>,
        BTreeMap<Id, VaultLocation>,
        Vec<VaultDiscoveryIssue>,
    ) {
        (self.snapshot, self.locations, self.issues)
    }
}

enum DescriptorReadError {
    Missing(String),
    Invalid(String),
}

fn descriptor_facts(
    reader: &PileReader,
    collection: CollectionHandle,
) -> std::result::Result<TribleSet, DescriptorReadError> {
    let blob: Blob<SimpleArchive> = match reader.get(collection) {
        Ok(blob) => blob,
        Err(GetBlobError::BlobNotFound) => {
            return Err(DescriptorReadError::Missing(format!(
                "collection descriptor {} is not resident",
                bytes_hex(&collection.raw)
            )));
        }
        Err(GetBlobError::ValidationError(_)) => {
            return Err(DescriptorReadError::Invalid(format!(
                "collection descriptor {} failed content-hash validation",
                bytes_hex(&collection.raw)
            )));
        }
        Err(GetBlobError::ConversionError(error)) => match error {},
    };
    let actual = blob.get_handle();
    if actual != collection {
        return Err(DescriptorReadError::Invalid(format!(
            "descriptor bytes hash to {} instead of {}",
            bytes_hex(&actual.raw),
            bytes_hex(&collection.raw)
        )));
    }
    TribleSet::try_from_blob(blob)
        .map_err(|error| DescriptorReadError::Invalid(format!("decode descriptor: {error}")))
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn discover_team_roots(store: &mut Pile) -> Result<BTreeSet<[u8; 32]>> {
    let records = discover_collection_records(store).context("discover collection records")?;
    let collections = records
        .commits()
        .iter()
        .map(CollectionCommit::collection)
        .collect::<BTreeSet<_>>();
    let reader = store.reader().context("open collection descriptor view")?;
    let mut teams = BTreeSet::new();

    for collection in collections {
        let Ok(facts) = descriptor_facts(&reader, collection) else {
            continue;
        };
        let Some(Ok(name)) = descriptor::name(&facts) else {
            continue;
        };
        if name.as_str() != authority::AUTHORITY_COLLECTION_NAME {
            continue;
        }
        let Some(Ok(team)) = descriptor::team(&facts) else {
            continue;
        };
        if collection == authority::collection(team)
            && facts == *authority::descriptor(team).facts()
        {
            teams.insert(team.to_bytes());
        }
    }
    Ok(teams)
}

fn issue(
    kind: VaultDiscoveryIssueKind,
    team: VerifyingKey,
    collection: CollectionHandle,
    vault: Option<Id>,
    detail: impl Into<String>,
) -> VaultDiscoveryIssue {
    VaultDiscoveryIssue {
        kind,
        team,
        collection,
        vault,
        detail: detail.into(),
    }
}

fn header_count(facts: &TribleSet) -> usize {
    find!(
        (header: Id),
        pattern!(facts, [{ ?header @ metadata::tag: KIND_VAULT }])
    )
    .count()
}

/// Discover every ready vault for which `signing_key` has accepted `READ`.
///
/// Missing target descriptors, absent headers, and malformed individual vaults
/// are retained as issues outside the aggregate. They never poison ready
/// vaults. Fatal errors are limited to the global collection-record or final
/// reader observation itself.
pub fn discover_local_vaults(store: &mut Pile, signing_key: &SigningKey) -> Result<VaultDiscovery> {
    let local = signing_key.verifying_key().to_bytes();
    let teams = discover_team_roots(store)?;
    let mut candidates = BTreeSet::<([u8; 32], CollectionHandle)>::new();
    let mut issues = Vec::new();

    for team_bytes in teams {
        let team = VerifyingKey::from_bytes(&team_bytes)
            .expect("discovered team bytes came from a validated verifying key");
        let authority = match authority::resolve_authority(store, team) {
            Ok(authority) => authority,
            Err(error) => {
                issues.push(issue(
                    VaultDiscoveryIssueKind::AuthorityUnavailable,
                    team,
                    authority::collection(team),
                    None,
                    error.to_string(),
                ));
                continue;
            }
        };
        for accepted in authority.grants() {
            let grant = accepted.grant();
            if grant.action() == ACTION_READ && grant.invoke() && grant.subject().raw == local {
                candidates.insert((team_bytes, grant.resource()));
            }
        }
    }

    let descriptor_reader = store.reader().context("open vault descriptor view")?;
    let mut described = BTreeMap::<Id, Vec<VaultLocation>>::new();
    for (team_bytes, collection) in candidates {
        let team = VerifyingKey::from_bytes(&team_bytes)
            .expect("candidate team bytes came from a validated verifying key");
        let facts = match descriptor_facts(&descriptor_reader, collection) {
            Ok(facts) => facts,
            Err(DescriptorReadError::Missing(detail)) => {
                issues.push(issue(
                    VaultDiscoveryIssueKind::MissingDescriptor,
                    team,
                    collection,
                    None,
                    detail,
                ));
                continue;
            }
            Err(DescriptorReadError::Invalid(detail)) => {
                issues.push(issue(
                    VaultDiscoveryIssueKind::InvalidDescriptor,
                    team,
                    collection,
                    None,
                    detail,
                ));
                continue;
            }
        };
        let vault = match descriptor::name(&facts) {
            Some(Ok(name)) => match parse_vault_name(&name) {
                Ok(vault) => vault,
                Err(error) => {
                    issues.push(issue(
                        VaultDiscoveryIssueKind::InvalidDescriptor,
                        team,
                        collection,
                        None,
                        error.to_string(),
                    ));
                    continue;
                }
            },
            Some(Err(error)) => {
                issues.push(issue(
                    VaultDiscoveryIssueKind::InvalidDescriptor,
                    team,
                    collection,
                    None,
                    error.to_string(),
                ));
                continue;
            }
            None => {
                issues.push(issue(
                    VaultDiscoveryIssueKind::InvalidDescriptor,
                    team,
                    collection,
                    None,
                    "vault descriptor has no collection name",
                ));
                continue;
            }
        };
        let expected = vault_descriptor(vault, team);
        if collection != vault_handle(vault, team) || facts != *expected.facts() {
            issues.push(issue(
                VaultDiscoveryIssueKind::InvalidDescriptor,
                team,
                collection,
                Some(vault),
                "descriptor is not the exact private SimpleArchive-union vault descriptor",
            ));
            continue;
        }
        described.entry(vault).or_default().push(VaultLocation {
            vault,
            team,
            collection,
        });
    }
    drop(descriptor_reader);

    let mut unique = BTreeMap::new();
    for (vault, locations) in described {
        if locations.len() != 1 {
            for location in locations {
                issues.push(issue(
                    VaultDiscoveryIssueKind::ConflictingVaultId,
                    location.team,
                    location.collection,
                    Some(vault),
                    "the same vault id is anchored by more than one team",
                ));
            }
            continue;
        }
        let location = locations[0];
        unique.insert(vault, location);
    }

    let mut materialized = BTreeMap::<Id, (VaultLocation, TribleSet)>::new();
    for (vault, location) in unique {
        let facts = match vault_collection(&mut *store, vault, location.team, signing_key.clone())
            .materialize()
        {
            Ok(facts) => facts,
            Err(error) => {
                issues.push(issue(
                    VaultDiscoveryIssueKind::MaterializationFailed,
                    location.team,
                    location.collection,
                    Some(vault),
                    error.to_string(),
                ));
                continue;
            }
        };
        if header_count(&facts) == 0 {
            issues.push(issue(
                VaultDiscoveryIssueKind::MissingHeader,
                location.team,
                location.collection,
                Some(vault),
                "vault has no resident canonical header yet",
            ));
            continue;
        }
        materialized.insert(vault, (location, facts));
    }

    let reader = store
        .reader()
        .context("open shared vault attachment view")?;
    let mut valid = BTreeMap::<Id, (VaultLocation, TribleSet, VaultCatalog)>::new();
    for (vault, (location, facts)) in materialized {
        match validate_catalog(&reader, vault, &facts) {
            Ok(catalog) => {
                valid.insert(vault, (location, facts, catalog));
            }
            Err(error) => issues.push(issue(
                VaultDiscoveryIssueKind::InvalidVault,
                location.team,
                location.collection,
                Some(vault),
                error.to_string(),
            )),
        }
    }

    let mut secret_owners = BTreeMap::<Id, Vec<Id>>::new();
    for (vault, (_, _, catalog)) in &valid {
        for secret in catalog.secrets.keys() {
            secret_owners.entry(*secret).or_default().push(*vault);
        }
    }
    let conflicting_vaults = secret_owners
        .values()
        .filter(|owners| owners.len() > 1)
        .flatten()
        .copied()
        .collect::<BTreeSet<_>>();
    for vault in &conflicting_vaults {
        let (location, _, _) = valid
            .get(vault)
            .expect("conflicting vault came from validated candidates");
        issues.push(issue(
            VaultDiscoveryIssueKind::InvalidVault,
            location.team,
            location.collection,
            Some(*vault),
            "one or more secret ids also occur in another vault",
        ));
    }

    let mut locations = BTreeMap::new();
    let ready = valid
        .into_iter()
        .filter(|(vault, _)| !conflicting_vaults.contains(vault))
        .map(|(vault, (location, facts, _))| {
            locations.insert(vault, location);
            (vault, facts)
        })
        .collect::<Vec<_>>();
    let snapshot = SecretsSnapshot::new(reader, ready)
        .context("construct aggregate from independently validated vaults")?;
    issues.sort_by_key(|issue| (issue.vault, issue.collection, issue.kind as u8));
    Ok(VaultDiscovery {
        snapshot,
        locations,
        issues,
    })
}

/// Create one explicit team-of-one vault in crash-safe publication order.
///
/// The header is validated before mutation. Publication then proceeds as
/// `WRITE grant -> header commit -> READ grant`; no implicit root privilege is
/// assumed at any step.
pub fn create_vault(
    store: &mut Pile,
    signing_key: &SigningKey,
    vault: Id,
    name: &str,
    created_at: IntervalValue,
) -> Result<VaultLocation> {
    let header = vault_header_fragment(vault, name, created_at)?;
    load_catalog(vault, header.facts()).context("validate vault genesis")?;
    let team = signing_key.verifying_key();
    let collection = vault_handle(vault, team);

    authority::publish_grant(
        store,
        team,
        signing_key,
        AuthorityGrant::root(
            signing_key.verifying_key(),
            collection,
            ACTION_WRITE,
            AuthorityMode::Invoke,
        ),
    )
    .context("publish vault WRITE grant")?;
    vault_collection(&mut *store, vault, team, signing_key.clone())
        .commit(header)
        .context("publish vault header")?;
    authority::publish_grant(
        store,
        team,
        signing_key,
        AuthorityGrant::root(
            signing_key.verifying_key(),
            collection,
            ACTION_READ,
            AuthorityMode::Invoke,
        ),
    )
    .context("publish vault READ grant")?;

    Ok(VaultLocation {
        vault,
        team,
        collection,
    })
}

/// Accepted direct recipient keys for one exact vault's current `READ` atom.
pub fn vault_members(
    store: &mut Pile,
    location: &VaultLocation,
) -> Result<BTreeSet<RecipientPublicKey>> {
    let authority = authority::resolve_authority(store, location.team)
        .context("resolve vault READ authority")?;
    Ok(read_authority_recipient_keys(
        &authority,
        location.collection,
    ))
}

/// Seal and publish one new exact secret version to current `READ` members.
pub fn add_secret<R: BlobStoreGet>(
    store: &mut Pile,
    signing_key: &SigningKey,
    location: &VaultLocation,
    snapshot: &SecretsSnapshot<R>,
    name: &str,
    plaintext: &[u8],
    created_at: IntervalValue,
) -> Result<(Id, usize)> {
    let catalog = checked_vault(snapshot, location)?;
    let recipients = vault_members(store, location)?;
    let sealed = seal_version(name, plaintext, &recipients, created_at)?;
    let current = snapshot
        .vault(location.vault)
        .expect("checked vault above")
        .facts();
    validate_prospective_union(catalog.header.id, current, &sealed.fragment)?;
    let secret = sealed.secret;
    let recipient_count = sealed.recipient_count;
    vault_collection(
        &mut *store,
        location.vault,
        location.team,
        signing_key.clone(),
    )
    .commit(sealed.fragment)
    .context("publish encrypted secret version")?;
    Ok((secret, recipient_count))
}

fn checked_vault<'a, R>(
    snapshot: &'a SecretsSnapshot<R>,
    location: &VaultLocation,
) -> Result<&'a VaultCatalog> {
    snapshot
        .vault(location.vault)
        .map(|vault| vault.catalog())
        .ok_or_else(|| anyhow!("vault {} is not ready in this snapshot", location.vault))
}

fn validate_prospective_union(vault: Id, current: &TribleSet, candidate: &Fragment) -> Result<()> {
    let mut prospective = current.clone();
    prospective += candidate.facts().clone();
    load_catalog(vault, &prospective).context("validate prospective vault union")?;
    Ok(())
}

/// Add every missing wrap for one exact secret to current `READ` members.
pub fn share_secret<R: BlobStoreGet>(
    store: &mut Pile,
    signing_key: &SigningKey,
    location: &VaultLocation,
    snapshot: &SecretsSnapshot<R>,
    secret: Id,
) -> Result<usize> {
    let (vault, _) = snapshot
        .lookup(secret)
        .ok_or_else(|| anyhow!("secret {secret} not found"))?;
    if vault != location.vault {
        bail!(
            "secret {secret} does not belong to vault {}",
            location.vault
        );
    }
    let catalog = checked_vault(snapshot, location)?;
    let recipients = vault_members(store, location)?;
    let shared = share_version(snapshot.reader(), catalog, secret, signing_key, &recipients)?;
    if shared.new_recipient_count != 0 {
        let current = snapshot
            .vault(location.vault)
            .expect("checked vault above")
            .facts();
        validate_prospective_union(location.vault, current, &shared.fragment)?;
        vault_collection(
            &mut *store,
            location.vault,
            location.team,
            signing_key.clone(),
        )
        .commit(shared.fragment)
        .context("publish recipient wraps")?;
    }
    Ok(shared.new_recipient_count)
}

/// Wrap every secret in `snapshot` before exposing a new accepted `READ` grant.
///
/// A concurrent add may have observed the old recipient set and therefore
/// remain temporarily unavailable to the new reader. `READ` alone grants no
/// decryption, and exact [`share_secret`] monotonically repairs that case.
pub fn grant_vault_read<R: BlobStoreGet>(
    store: &mut Pile,
    signing_key: &SigningKey,
    location: &VaultLocation,
    snapshot: &SecretsSnapshot<R>,
    recipient: VerifyingKey,
) -> Result<(usize, bool)> {
    if signing_key.verifying_key() != location.team {
        bail!("vault grant requires this explicit team-of-one root key");
    }
    let catalog = checked_vault(snapshot, location)?;
    let authority = authority::resolve_authority(store, location.team)
        .context("resolve vault READ authority")?;
    let recipient_inline = Inline::<ED25519PublicKey>::new(recipient.to_bytes());
    let already_granted = authority.allows(&recipient_inline, ACTION_READ, location.collection);
    let mut recipients = read_authority_recipient_keys(&authority, location.collection);
    recipients.insert(recipient.to_bytes());

    let mut wraps = Fragment::empty();
    let mut added = 0;
    for secret in catalog.secrets.keys() {
        let shared = share_version(
            snapshot.reader(),
            catalog,
            *secret,
            signing_key,
            &recipients,
        )?;
        added += shared.new_recipient_count;
        wraps += shared.fragment;
    }
    if added != 0 {
        let current = snapshot
            .vault(location.vault)
            .expect("checked vault above")
            .facts();
        validate_prospective_union(location.vault, current, &wraps)?;
        vault_collection(
            &mut *store,
            location.vault,
            location.team,
            signing_key.clone(),
        )
        .commit(wraps)
        .context("publish wraps before READ grant")?;
    }

    if !already_granted {
        authority::publish_grant(
            store,
            location.team,
            signing_key,
            AuthorityGrant::root(
                recipient,
                location.collection,
                ACTION_READ,
                AuthorityMode::Invoke,
            ),
        )
        .context("publish vault READ grant")?;
    }
    Ok((added, !already_granted))
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::path::{Path, PathBuf};

    use hifitime::Epoch;
    use tempfile::TempDir;
    use triblespace::core::collection::{reach, CollectionRecord};
    use triblespace::core::repo::pile::{PileRecordContent, PileRecords};
    use triblespace::core::repo::BlobStorePut;
    use triblespace::prelude::*;

    use super::*;

    struct TestPile {
        _directory: TempDir,
        path: PathBuf,
    }

    impl TestPile {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("test.pile");
            File::create(&path).unwrap();
            Self {
                _directory: directory,
                path,
            }
        }

        fn open(&self) -> Pile {
            Pile::open(&self.path).unwrap()
        }
    }

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn at(second: i64) -> IntervalValue {
        let epoch = Epoch::from_unix_seconds(second as f64);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn physical_collection_records(path: &Path) -> Vec<CollectionRecord> {
        PileRecords::open(path)
            .unwrap()
            .map(|record| record.unwrap().content)
            .filter_map(|content| match content {
                PileRecordContent::Collection { record } => Some(record),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn create_requires_explicit_write_and_publishes_write_header_read() {
        let files = TestPile::new();
        let signer = key(1);
        let team = signer.verifying_key();
        let vault = id(1);
        let mut pile = files.open();

        let denied = vault_collection(&mut pile, vault, team, signer.clone())
            .commit(vault_header_fragment(vault, "production", at(1)).unwrap())
            .unwrap_err();
        assert!(denied.to_string().contains("no positive WRITE authority"));
        assert!(discover_collection_records(&mut pile)
            .unwrap()
            .commits()
            .is_empty());

        let location = create_vault(&mut pile, &signer, vault, "production", at(1)).unwrap();
        let authority = authority::resolve_authority(&mut pile, team).unwrap();
        let write = authority
            .grants()
            .find(|accepted| accepted.grant().action() == ACTION_WRITE)
            .unwrap();
        let read = authority
            .grants()
            .find(|accepted| accepted.grant().action() == ACTION_READ)
            .unwrap();
        for accepted in [write, read] {
            assert_eq!(accepted.grant().parent(), None);
            assert_eq!(accepted.grant().subject().raw, team.to_bytes());
            assert_eq!(accepted.grant().resource(), location.collection());
            assert_eq!(accepted.commit().public_key().raw, team.to_bytes());
        }
        let header = discover_collection_records(&mut pile)
            .unwrap()
            .commits()
            .iter()
            .find(|commit| commit.collection() == location.collection())
            .copied()
            .unwrap();
        pile.close().unwrap();

        let actual = physical_collection_records(&files.path)
            .into_iter()
            .filter_map(|record| match record {
                CollectionRecord::Commit(commit) => Some(commit.id()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            vec![write.commit().id(), header.id(), read.commit().id()]
        );
    }

    #[test]
    fn pending_descriptor_and_header_candidates_do_not_poison_ready_vaults() {
        let files = TestPile::new();
        let signer = key(2);
        let team = signer.verifying_key();
        let mut pile = files.open();
        let ready = create_vault(&mut pile, &signer, id(2), "ready", at(2)).unwrap();

        let missing_descriptor = vault_handle(id(3), team);
        authority::publish_grant(
            &mut pile,
            team,
            &signer,
            AuthorityGrant::root(team, missing_descriptor, ACTION_READ, AuthorityMode::Invoke),
        )
        .unwrap();

        let headerless_descriptor = vault_descriptor(id(4), team);
        let headerless: CollectionHandle = pile
            .put::<SimpleArchive, _>(headerless_descriptor.into_facts())
            .unwrap();
        authority::publish_grant(
            &mut pile,
            team,
            &signer,
            AuthorityGrant::root(team, headerless, ACTION_READ, AuthorityMode::Invoke),
        )
        .unwrap();

        let noncanonical_descriptor =
            triblespace::core::collection::simplearchive_union::descriptor(
                &super::super::vault_name(id(5)),
                team,
                reach::public(),
            );
        let noncanonical: CollectionHandle = pile
            .put::<SimpleArchive, _>(noncanonical_descriptor.into_facts())
            .unwrap();
        authority::publish_grant(
            &mut pile,
            team,
            &signer,
            AuthorityGrant::root(team, noncanonical, ACTION_READ, AuthorityMode::Invoke),
        )
        .unwrap();

        let other = key(9).verifying_key();
        authority::publish_grant(
            &mut pile,
            team,
            &signer,
            AuthorityGrant::root(
                other,
                vault_handle(id(6), team),
                ACTION_READ,
                AuthorityMode::Invoke,
            ),
        )
        .unwrap();

        let discovered = discover_local_vaults(&mut pile, &signer).unwrap();
        assert_eq!(
            discovered.locations().keys().copied().collect::<Vec<_>>(),
            vec![ready.vault()]
        );
        assert!(discovered.snapshot().vault(ready.vault()).is_some());
        let kinds = discovered
            .issues()
            .iter()
            .map(VaultDiscoveryIssue::kind)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            kinds,
            BTreeSet::from([
                VaultDiscoveryIssueKind::MissingDescriptor,
                VaultDiscoveryIssueKind::InvalidDescriptor,
                VaultDiscoveryIssueKind::MissingHeader,
            ])
        );
        assert!(discovered
            .issues()
            .iter()
            .all(|issue| { issue.collection() != vault_handle(id(6), team) }));
        pile.close().unwrap();
    }

    #[test]
    fn grant_publishes_wraps_before_read_and_new_reader_opens_every_secret() {
        let files = TestPile::new();
        let signer = key(3);
        let recipient = key(4);
        let mut pile = files.open();
        let location = create_vault(&mut pile, &signer, id(7), "shared", at(3)).unwrap();
        let snapshot = discover_local_vaults(&mut pile, &signer).unwrap();
        let first = add_secret(
            &mut pile,
            &signer,
            &location,
            snapshot.snapshot(),
            "same-name",
            b"first",
            at(4),
        )
        .unwrap()
        .0;
        drop(snapshot);
        let snapshot = discover_local_vaults(&mut pile, &signer).unwrap();
        let second = add_secret(
            &mut pile,
            &signer,
            &location,
            snapshot.snapshot(),
            "same-name",
            b"second",
            at(5),
        )
        .unwrap()
        .0;
        drop(snapshot);
        assert_ne!(first, second);

        let before = physical_collection_records(&files.path).len();
        let local = discover_local_vaults(&mut pile, &signer).unwrap();
        let (wraps, granted) = grant_vault_read(
            &mut pile,
            &signer,
            &location,
            local.snapshot(),
            recipient.verifying_key(),
        )
        .unwrap();
        assert_eq!(wraps, 2);
        assert!(granted);
        drop(local);
        pile.close().unwrap();

        let appended = physical_collection_records(&files.path)
            .into_iter()
            .skip(before)
            .filter_map(|record| match record {
                CollectionRecord::Commit(commit) => Some(commit.collection()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            appended,
            vec![
                location.collection(),
                authority::collection(location.team())
            ]
        );

        let mut pile = files.open();
        let remote = discover_local_vaults(&mut pile, &recipient).unwrap();
        assert_eq!(remote.snapshot().open(first, &recipient).unwrap(), b"first");
        assert_eq!(
            remote.snapshot().open(second, &recipient).unwrap(),
            b"second"
        );
        assert_eq!(
            super::super::read_text(
                remote.snapshot().reader(),
                remote.snapshot().lookup(first).unwrap().1.name,
            )
            .unwrap(),
            "same-name"
        );
        assert_eq!(
            super::super::read_text(
                remote.snapshot().reader(),
                remote.snapshot().lookup(second).unwrap().1.name,
            )
            .unwrap(),
            "same-name"
        );
        pile.close().unwrap();
    }

    #[test]
    fn exact_share_repairs_a_preexisting_read_grant_without_latest_arbitration() {
        let files = TestPile::new();
        let signer = key(5);
        let recipient = key(6);
        let mut pile = files.open();
        let location = create_vault(&mut pile, &signer, id(8), "repair", at(6)).unwrap();
        let snapshot = discover_local_vaults(&mut pile, &signer).unwrap();
        let secret = add_secret(
            &mut pile,
            &signer,
            &location,
            snapshot.snapshot(),
            "credential",
            b"exact",
            at(7),
        )
        .unwrap()
        .0;
        drop(snapshot);
        authority::publish_grant(
            &mut pile,
            location.team(),
            &signer,
            AuthorityGrant::root(
                recipient.verifying_key(),
                location.collection(),
                ACTION_READ,
                AuthorityMode::Invoke,
            ),
        )
        .unwrap();

        let local = discover_local_vaults(&mut pile, &signer).unwrap();
        assert_eq!(
            share_secret(&mut pile, &signer, &location, local.snapshot(), secret).unwrap(),
            1
        );
        drop(local);

        let remote = discover_local_vaults(&mut pile, &recipient).unwrap();
        assert_eq!(
            remote.snapshot().open(secret, &recipient).unwrap(),
            b"exact"
        );
        pile.close().unwrap();
    }

    #[test]
    fn prospective_union_rejects_a_candidate_that_corrupts_existing_shape() {
        let vault = id(10);
        let header = vault_header_fragment(vault, "checked", at(8)).unwrap();
        let recipients = BTreeSet::from([key(10).verifying_key().to_bytes()]);
        let sealed = seal_version("credential", b"value", &recipients, at(9)).unwrap();
        validate_prospective_union(vault, header.facts(), &sealed.fragment).unwrap();

        let mut malformed = sealed.fragment;
        malformed += entity! { ExclusiveId::force_ref(&sealed.secret) @
            metadata::tag: &KIND_VAULT,
        };
        let error = validate_prospective_union(vault, header.facts(), &malformed).unwrap_err();
        assert!(error.to_string().contains("prospective vault union"));
    }
}
