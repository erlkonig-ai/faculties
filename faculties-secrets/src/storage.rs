//! Pile-backed discovery and publication for capability-native Secrets vaults.
//!
//! Vault authority is never discovered by enumerating a global ledger. Each
//! recipient instead has one private access inbox whose signed commits are
//! deliberately read as raw, untrusted candidates. The envelope, exact proof
//! closure, and exact vault descriptor are validated independently before a
//! candidate can contribute either decryption custody or snapshot admission.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Context, Result};
use dryoc::dryocsecretbox::Key as RandomSeed;
use dryoc::types::{ByteArray, NewByteArray};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hifitime::Epoch;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::utf8string::UTF8String;
use triblespace::core::blob::{Blob, TryFromBlob};
use triblespace::core::capability::{
    CapabilityAction, CapabilityAtom, CapabilityClaim, CapabilityMode, CapabilityProofBundle,
    CapabilityProofId, CapabilityRequest, CapabilityResource,
};
use triblespace::core::collection::{
    descriptor, simplearchive_union, Collection, CollectionHandle, CollectionRead,
    CollectionRecord, CollectionRecordSelector, CollectionSnapshotExt, CollectionStoreExt, Support,
    ACTION_WRITE,
};
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::metadata;
use triblespace::core::repo::pile::{GetBlobError, Pile, PileSnapshot};
use triblespace::core::repo::{
    BlobStoreGet, BlobStoreMeta, BlobStorePut, CapabilityProofRead, CapabilityProofStore,
    SnapshotSource, StoreRead,
};
use triblespace::prelude::*;

use super::access::{build_access_envelope, load_access_envelope, open_access_envelope};
use super::schema::{KIND_ACCESS_ENVELOPE, KIND_VAULT};
use super::{
    load_catalog, parse_vault_name, seal_version, validate_catalog, vault_header_fragment,
    vault_name, vault_policy, IntervalValue, SecretsSnapshot, VaultAccess, VaultCatalog,
    ACTION_READ,
};

const ACCESS_INBOX_NAME: &str = "secrets-access";

/// One ready vault's exact collection identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultLocation {
    vault: Id,
    authority: VerifyingKey,
    collection: Collection<SimpleArchive>,
}

impl VaultLocation {
    /// Register and bind the exact private vault collection in `store`.
    pub fn open<S>(store: &mut S, vault: Id, authority: VerifyingKey) -> Result<Self>
    where
        S: CollectionStoreExt,
    {
        let collection = store
            .collection(&vault_name(vault), vault_policy(authority))
            .map_err(|error| anyhow!("register Secrets vault collection: {error}"))?;
        Ok(Self {
            vault,
            authority,
            collection,
        })
    }

    pub const fn vault(&self) -> Id {
        self.vault
    }

    pub fn authority(&self) -> VerifyingKey {
        self.authority
    }

    pub const fn collection(&self) -> CollectionHandle {
        self.collection.handle()
    }
}

/// Classification of one inbox candidate that did not become a ready vault.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum VaultDiscoveryIssueKind {
    InvalidEnvelope,
    MissingDescriptor,
    InvalidDescriptor,
    MaterializationFailed,
    MissingHeader,
    InvalidVault,
    CustodyMismatch,
}

/// Independent evidence about one non-ready candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultDiscoveryIssue {
    kind: VaultDiscoveryIssueKind,
    candidate: Option<Id>,
    authority: Option<VerifyingKey>,
    collection: CollectionHandle,
    vault: Option<Id>,
    detail: String,
}

impl VaultDiscoveryIssue {
    pub const fn kind(&self) -> VaultDiscoveryIssueKind {
        self.kind
    }

    pub const fn candidate(&self) -> Option<Id> {
        self.candidate
    }

    pub fn authority(&self) -> Option<VerifyingKey> {
        self.authority
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

/// Ready local vaults plus independently rejected access candidates.
pub struct VaultDiscovery {
    snapshot: SecretsSnapshot<PileSnapshot>,
    locations: BTreeMap<CollectionHandle, VaultLocation>,
    issues: Vec<VaultDiscoveryIssue>,
}

impl VaultDiscovery {
    pub fn snapshot(&self) -> &SecretsSnapshot<PileSnapshot> {
        &self.snapshot
    }

    pub fn locations(&self) -> &BTreeMap<CollectionHandle, VaultLocation> {
        &self.locations
    }

    /// Resolve a graph-local vault id only when it names one exact collection.
    pub fn location(&self, vault: Id) -> Option<&VaultLocation> {
        let mut matching = self
            .locations
            .values()
            .filter(|location| location.vault == vault);
        let first = matching.next()?;
        matching.next().is_none().then_some(first)
    }

    /// Resolve one exact collection identity without graph-local arbitration.
    pub fn location_exact(&self, collection: CollectionHandle) -> Option<&VaultLocation> {
        self.locations.get(&collection)
    }

    pub fn issues(&self) -> &[VaultDiscoveryIssue] {
        &self.issues
    }

    pub fn into_parts(
        self,
    ) -> (
        SecretsSnapshot<PileSnapshot>,
        BTreeMap<CollectionHandle, VaultLocation>,
        Vec<VaultDiscoveryIssue>,
    ) {
        (self.snapshot, self.locations, self.issues)
    }
}

fn register_access_inbox<S>(
    store: &mut S,
    recipient: VerifyingKey,
) -> Result<Collection<SimpleArchive>>
where
    S: CollectionStoreExt,
{
    store
        .collection(ACCESS_INBOX_NAME, vault_policy(recipient))
        .map_err(|error| anyhow!("register Secrets access inbox: {error}"))
}

#[derive(Clone, Copy)]
struct ParsedVaultDescriptor {
    vault: Id,
    authority: VerifyingKey,
    collection: CollectionHandle,
}

enum DescriptorReadError {
    Missing(String),
    Invalid(String),
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn descriptor_facts(
    reader: &PileSnapshot,
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
    decode_descriptor_facts(blob, collection)
}

fn decode_descriptor_facts(
    blob: Blob<SimpleArchive>,
    collection: CollectionHandle,
) -> std::result::Result<TribleSet, DescriptorReadError> {
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

fn parse_descriptor(
    reader: &PileSnapshot,
    collection: CollectionHandle,
) -> std::result::Result<ParsedVaultDescriptor, (VaultDiscoveryIssueKind, String)> {
    let facts = descriptor_facts(reader, collection).map_err(classify_descriptor_error)?;
    parse_descriptor_value(reader, facts, collection)
}

fn classify_descriptor_error(error: DescriptorReadError) -> (VaultDiscoveryIssueKind, String) {
    match error {
        DescriptorReadError::Missing(detail) => {
            (VaultDiscoveryIssueKind::MissingDescriptor, detail)
        }
        DescriptorReadError::Invalid(detail) => {
            (VaultDiscoveryIssueKind::InvalidDescriptor, detail)
        }
    }
}

fn parse_descriptor_value<R>(
    reader: &R,
    facts: TribleSet,
    collection: CollectionHandle,
) -> std::result::Result<ParsedVaultDescriptor, (VaultDiscoveryIssueKind, String)>
where
    R: BlobStoreGet,
{
    let name = descriptor::name(&facts)
        .map_err(|error| {
            (
                VaultDiscoveryIssueKind::InvalidDescriptor,
                format!("decode vault collection name: {error}"),
            )
        })?
        .ok_or_else(|| {
            (
                VaultDiscoveryIssueKind::InvalidDescriptor,
                "vault descriptor has no collection name".to_owned(),
            )
        })?;
    let name: Blob<UTF8String> = reader.get(name).map_err(|error| {
        (
            VaultDiscoveryIssueKind::InvalidDescriptor,
            format!("read vault collection name: {error}"),
        )
    })?;
    let name = name
        .try_from_blob::<anybytes::View<str>>()
        .map_err(|error| {
            (
                VaultDiscoveryIssueKind::InvalidDescriptor,
                format!("decode vault collection name: {error}"),
            )
        })?;
    let vault = parse_vault_name(&name).map_err(|error| {
        (
            VaultDiscoveryIssueKind::InvalidDescriptor,
            error.to_string(),
        )
    })?;
    let policy = descriptor::policy(&facts).map_err(|error| {
        (
            VaultDiscoveryIssueKind::InvalidDescriptor,
            format!("decode vault policy: {error}"),
        )
    })?;
    let authority = policy
        .write()
        .roots()
        .and_then(|roots| (roots.len() == 1).then_some(roots[0]))
        .ok_or_else(|| {
            (
                VaultDiscoveryIssueKind::InvalidDescriptor,
                "vault WRITE policy is not rooted at one direct authority".to_owned(),
            )
        })?;
    if policy != vault_policy(authority)
        || descriptor::representation(&facts).ok() != Some(<SimpleArchive as MetaDescribe>::id())
        || descriptor::source(&facts).ok().flatten().is_some()
        || descriptor::mapping(&facts).ok().flatten().is_some()
    {
        return Err((
            VaultDiscoveryIssueKind::InvalidDescriptor,
            "descriptor is not the exact private SimpleArchive-union vault descriptor".to_owned(),
        ));
    }
    Ok(ParsedVaultDescriptor {
        vault,
        authority,
        collection,
    })
}

fn issue(
    kind: VaultDiscoveryIssueKind,
    candidate: Option<Id>,
    authority: Option<VerifyingKey>,
    collection: CollectionHandle,
    vault: Option<Id>,
    detail: impl Into<String>,
) -> VaultDiscoveryIssue {
    VaultDiscoveryIssue {
        kind,
        candidate,
        authority,
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

fn load_proof_bundle<R>(
    snapshot: &R,
    id: CapabilityProofId,
    label: &str,
) -> Result<CapabilityProofBundle>
where
    R: BlobStoreGet + CapabilityProofRead,
{
    let proof = snapshot
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
            snapshot
                .get::<Blob<SimpleArchive>, _>(handle)
                .map_err(|error| anyhow!("read {label} claim {step}: {error}"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(CapabilityProofBundle::new(proof, claims))
}

/// Persist one explicit proof closure in publication order: all named claims,
/// then the native proof record that makes its exact id discoverable.
///
/// Storage does not confer authority. Callers must verify the bundle against
/// their exact root, subject, action, resource, mode, and instant before using
/// it for an authorization decision.
pub fn persist_proof_bundle<S>(store: &mut S, bundle: &CapabilityProofBundle) -> Result<()>
where
    S: BlobStorePut + CapabilityProofStore,
{
    let handles = bundle.proof().claim_handles().collect::<Vec<_>>();
    if handles.len() != bundle.claims().len() {
        bail!(
            "proof names {} claims but its bundle carries {}",
            handles.len(),
            bundle.claims().len()
        );
    }
    for (step, (expected, claim)) in handles.into_iter().zip(bundle.claims()).enumerate() {
        let actual = store
            .put::<SimpleArchive, _>(claim.clone())
            .map_err(|error| anyhow!("persist capability claim {step}: {error}"))?;
        if actual != expected {
            bail!("capability claim {step} does not match its proof handle");
        }
    }
    store
        .insert_proof(bundle.proof().clone())
        .map_err(|error| anyhow!("persist exact capability proof: {error}"))
}

/// One commit-local access-inbox candidate whose descriptor, proofs, sealed
/// seed, and delivery signer have all been validated.
///
/// The vault itself may not have been committed yet. This is the narrow
/// pre-genesis view used by crash-safe creation and additive migration.
#[derive(Clone)]
pub struct ValidatedAccessCandidate {
    id: Id,
    publisher: VerifyingKey,
    location: VaultLocation,
    custody: SigningKey,
    read_bundle: CapabilityProofBundle,
    writer: VerifyingKey,
    write_bundle: CapabilityProofBundle,
}

impl ValidatedAccessCandidate {
    pub const fn id(&self) -> Id {
        self.id
    }

    pub fn publisher(&self) -> VerifyingKey {
        self.publisher
    }

    pub const fn location(&self) -> VaultLocation {
        self.location
    }

    pub fn custody(&self) -> &SigningKey {
        &self.custody
    }

    pub fn read_bundle(&self) -> &CapabilityProofBundle {
        &self.read_bundle
    }

    pub fn writer(&self) -> VerifyingKey {
        self.writer
    }

    pub fn write_bundle(&self) -> &CapabilityProofBundle {
        &self.write_bundle
    }
}

/// Discover independently validated access candidates without requiring the
/// referenced vault collection to exist yet.
pub fn discover_access_candidates<S>(
    store: &mut S,
    recipient: &SigningKey,
) -> Result<(Vec<ValidatedAccessCandidate>, Vec<VaultDiscoveryIssue>)>
where
    S: CollectionStoreExt + CapabilityProofStore + SnapshotSource<Snapshot = PileSnapshot>,
{
    discover_access_candidates_with(store, recipient, parse_descriptor)
}

fn discover_access_candidates_with<S, F>(
    store: &mut S,
    recipient: &SigningKey,
    mut parse: F,
) -> Result<(Vec<ValidatedAccessCandidate>, Vec<VaultDiscoveryIssue>)>
where
    S: CollectionStoreExt + CapabilityProofStore + SnapshotSource,
    <S as SnapshotSource>::Snapshot: BlobStoreGet
        + BlobStoreMeta
        + CapabilityProofRead
        + triblespace::core::collection::CollectionRead,
    F: FnMut(
        &<S as SnapshotSource>::Snapshot,
        CollectionHandle,
    ) -> std::result::Result<ParsedVaultDescriptor, (VaultDiscoveryIssueKind, String)>,
{
    let inbox = register_access_inbox(store, recipient.verifying_key())?;
    // The inbox is intentionally a raw candidate surface rather than an
    // authorized collection view. Any signer may deliver a candidate; the
    // envelope, proof closure, publisher, and target descriptor below decide
    // whether that candidate contributes access.
    let snapshot = store
        .snapshot()
        .context("freeze Secrets access-inbox store snapshot")?;
    let selectors = BTreeSet::from([CollectionRecordSelector::Collection(inbox.handle())]);
    let commits = snapshot
        .select_records(&selectors)
        .context("select raw Secrets access-inbox candidates")?
        .into_iter()
        .filter_map(|record| match record {
            CollectionRecord::Commit(commit) if commit.verify_strict().is_ok() => Some(commit),
            _ => None,
        })
        .collect::<Vec<_>>();
    let instant = triblespace::core::clock::epoch_now();
    let mut candidates = Vec::new();
    let mut issues = Vec::new();

    // Materialize each admitted leaf independently. The aggregate union
    // remains the collection's value, but commit-local boundaries prevent an
    // unavailable or malformed leaf from poisoning earlier valid delivery.
    // Rows inside one signed leaf are atomic: multi-writer grants deliberately
    // publish their complete writer-proof set in one COMMIT.
    for commit in commits {
        let publisher = VerifyingKey::from_bytes(&commit.public_key().raw)
            .expect("collection discovery strictly verifies commit signer keys");
        let metadata: std::result::Result<Blob<SimpleArchive>, _> = snapshot.get(commit.metadata());
        let metadata = match metadata {
            Ok(metadata) => metadata,
            Err(error) => {
                issues.push(issue(
                    VaultDiscoveryIssueKind::InvalidEnvelope,
                    None,
                    None,
                    inbox.handle(),
                    None,
                    format!(
                        "access-inbox record fingerprint {} metadata: {error}",
                        CollectionRecord::Commit(commit).fingerprint()
                    ),
                ));
                continue;
            }
        };
        if let Err(error) = simplearchive_union::validate_element(&metadata) {
            issues.push(issue(
                VaultDiscoveryIssueKind::InvalidEnvelope,
                None,
                None,
                inbox.handle(),
                None,
                format!(
                    "access-inbox record fingerprint {} metadata: {error}",
                    CollectionRecord::Commit(commit).fingerprint()
                ),
            ));
            continue;
        }
        let data_handle = Handle::<SimpleArchive>::from_hash(commit.data());
        let blob: Blob<SimpleArchive> = match snapshot.get(data_handle) {
            Ok(blob) => blob,
            Err(error) => {
                issues.push(issue(
                    VaultDiscoveryIssueKind::InvalidEnvelope,
                    None,
                    None,
                    inbox.handle(),
                    None,
                    format!(
                        "access-inbox record fingerprint {} data: {error}",
                        CollectionRecord::Commit(commit).fingerprint()
                    ),
                ));
                continue;
            }
        };
        let facts = match TribleSet::try_from_blob(blob) {
            Ok(facts) => facts,
            Err(error) => {
                issues.push(issue(
                    VaultDiscoveryIssueKind::InvalidEnvelope,
                    None,
                    None,
                    inbox.handle(),
                    None,
                    format!(
                        "access-inbox record fingerprint {} data: {error}",
                        CollectionRecord::Commit(commit).fingerprint()
                    ),
                ));
                continue;
            }
        };
        let ids = find!(
            id: Id,
            pattern!(&facts, [{ ?id @ metadata::tag: KIND_ACCESS_ENVELOPE }])
        )
        .collect::<BTreeSet<_>>();
        let mut commit_candidates = Vec::new();
        let mut commit_valid = true;
        for id in ids {
            let row = match load_access_envelope(&facts, id) {
                Ok(row) => row,
                Err(error) => {
                    commit_valid = false;
                    issues.push(issue(
                        VaultDiscoveryIssueKind::InvalidEnvelope,
                        Some(id),
                        None,
                        inbox.handle(),
                        None,
                        error.to_string(),
                    ));
                    continue;
                }
            };
            let parsed = match parse(&snapshot, row.vault) {
                Ok(parsed) => parsed,
                Err((kind, detail)) => {
                    commit_valid = false;
                    issues.push(issue(kind, Some(id), None, row.vault, None, detail));
                    continue;
                }
            };
            let location = match VaultLocation::open(store, parsed.vault, parsed.authority) {
                Ok(location) if location.collection.handle() == parsed.collection => location,
                Ok(_) => {
                    commit_valid = false;
                    issues.push(issue(
                        VaultDiscoveryIssueKind::InvalidDescriptor,
                        Some(id),
                        Some(parsed.authority),
                        parsed.collection,
                        Some(parsed.vault),
                        "vault descriptor is not the canonical store-created collection",
                    ));
                    continue;
                }
                Err(error) => {
                    commit_valid = false;
                    issues.push(issue(
                        VaultDiscoveryIssueKind::InvalidDescriptor,
                        Some(id),
                        Some(parsed.authority),
                        parsed.collection,
                        Some(parsed.vault),
                        error.to_string(),
                    ));
                    continue;
                }
            };
            let read_bundle = match load_proof_bundle(&snapshot, row.read_proof, "READ") {
                Ok(bundle) => bundle,
                Err(error) => {
                    commit_valid = false;
                    issues.push(issue(
                        VaultDiscoveryIssueKind::InvalidEnvelope,
                        Some(id),
                        Some(location.authority),
                        location.collection.handle(),
                        Some(location.vault),
                        error.to_string(),
                    ));
                    continue;
                }
            };
            let write_bundle = match load_proof_bundle(&snapshot, row.write_proof, "WRITE") {
                Ok(bundle) => bundle,
                Err(error) => {
                    commit_valid = false;
                    issues.push(issue(
                        VaultDiscoveryIssueKind::InvalidEnvelope,
                        Some(id),
                        Some(location.authority),
                        location.collection.handle(),
                        Some(location.vault),
                        error.to_string(),
                    ));
                    continue;
                }
            };
            let opened = match open_access_envelope(
                &snapshot,
                &row,
                recipient,
                location.authority,
                instant,
                read_bundle,
                write_bundle,
            ) {
                Ok(opened) => opened,
                Err(error) => {
                    commit_valid = false;
                    issues.push(issue(
                        VaultDiscoveryIssueKind::InvalidEnvelope,
                        Some(id),
                        Some(location.authority),
                        location.collection.handle(),
                        Some(location.vault),
                        error.to_string(),
                    ));
                    continue;
                }
            };
            if publisher != opened.read_issuer {
                commit_valid = false;
                issues.push(issue(
                    VaultDiscoveryIssueKind::InvalidEnvelope,
                    Some(id),
                    Some(location.authority),
                    location.collection.handle(),
                    Some(location.vault),
                    "access-inbox commit signer is not the exact READ leaf issuer",
                ));
                continue;
            }
            commit_candidates.push(ValidatedAccessCandidate {
                id,
                publisher,
                location,
                custody: opened.custody,
                read_bundle: opened.read_bundle,
                writer: opened.writer,
                write_bundle: opened.write_bundle,
            });
        }
        if commit_valid {
            candidates.extend(commit_candidates);
        }
    }
    Ok((candidates, issues))
}

fn write_bundles(candidates: &[ValidatedAccessCandidate]) -> Vec<CapabilityProofBundle> {
    candidates
        .iter()
        .map(|candidate| candidate.write_bundle.clone())
        .collect()
}

/// Construct the exact vault cover admitted by the collection's immutable
/// WRITE policy and the proof evidence in this coherent snapshot.
fn admitted_vault_cover<S>(snapshot: &S, location: VaultLocation) -> Result<Support>
where
    S: BlobStoreGet + CapabilityProofRead + CollectionRead,
{
    let (support, _commits) = location
        .collection
        .admitted_with_commits(snapshot)
        .context("discover policy-admitted vault support")?;
    Ok(support)
}

fn read_vault_cover<S>(snapshot: &S, support: &Support) -> Result<TribleSet>
where
    S: StoreRead,
{
    snapshot
        .collection_exact(support.collection(), support)
        .context("attach candidate-scoped vault support")?
        .view::<TribleSet>()
        .context("read candidate-scoped vault support")
}

fn read_atom(collection: CollectionHandle) -> CapabilityAtom {
    CapabilityAtom::new(
        CapabilityAction::new(ACTION_READ),
        CapabilityResource::from(collection),
    )
}

fn write_atom(collection: CollectionHandle) -> CapabilityAtom {
    CapabilityAtom::new(
        CapabilityAction::new(ACTION_WRITE),
        CapabilityResource::from(collection),
    )
}

fn root_bundle(
    root: &SigningKey,
    atom: CapabilityAtom,
    mode: CapabilityMode,
) -> CapabilityProofBundle {
    CapabilityProofBundle::issue_root(
        root,
        CapabilityClaim::root(atom, mode, None),
        root.verifying_key(),
    )
    .expect("a parentless root claim is issuable")
}

/// Root-issued, unbounded founder proofs for one exact vault.
pub fn founder_proofs(
    root: &SigningKey,
    location: VaultLocation,
) -> (CapabilityProofBundle, CapabilityProofBundle) {
    (
        root_bundle(
            root,
            read_atom(location.collection.handle()),
            CapabilityMode::InvokeAndDelegate,
        ),
        root_bundle(
            root,
            write_atom(location.collection.handle()),
            CapabilityMode::InvokeAndDelegate,
        ),
    )
}

/// Publish one self-contained access envelope to its subject's deterministic
/// inbox.
///
/// The publisher must be the exact issuer of the READ leaf. This makes the
/// inbox COMMIT the delivery signature and prevents a third party from copying
/// valid proof evidence while substituting a different custody seed.
#[allow(clippy::too_many_arguments)]
pub fn publish_access_envelope(
    store: &mut Pile,
    publisher: &SigningKey,
    location: VaultLocation,
    custody: &SigningKey,
    subject: VerifyingKey,
    read_bundle: &CapabilityProofBundle,
    writer: VerifyingKey,
    write_bundle: &CapabilityProofBundle,
    instant: Epoch,
) -> Result<Id> {
    let envelope = build_access_envelope(
        location.collection.handle(),
        custody,
        subject,
        read_bundle,
        writer,
        write_bundle,
        location.authority,
        instant,
    )
    .context("build custody access envelope")?;
    let issuer = read_bundle.proof().leaf_issuer();
    if publisher.verifying_key() != issuer {
        bail!("access-inbox publisher is not the exact READ leaf issuer");
    }
    let envelope_id = envelope
        .root()
        .context("access envelope did not export its intrinsic id")?;
    persist_proof_bundle(store, read_bundle).context("persist READ proof closure")?;
    persist_proof_bundle(store, write_bundle).context("persist WRITE proof closure")?;
    let inbox = register_access_inbox(store, subject)?;
    store
        .commit(inbox, publisher, envelope)
        .context("publish subject-specific access envelope")?;
    Ok(envelope_id)
}

/// Discover every ready vault represented by a valid candidate in the local
/// recipient's access inbox.
///
/// Candidate failures are isolated.  In particular, stale pre-commit
/// envelopes merely report `MissingHeader`, and envelopes with the wrong
/// custody key are discarded only after the real vault catalog is known.
pub fn discover_local_vaults<S>(store: &mut S, signing_key: &SigningKey) -> Result<VaultDiscovery>
where
    S: CollectionStoreExt + CapabilityProofStore + SnapshotSource<Snapshot = PileSnapshot>,
{
    let (candidates, mut issues) = discover_access_candidates(store, signing_key)?;
    let mut by_collection = BTreeMap::<CollectionHandle, Vec<ValidatedAccessCandidate>>::new();
    for candidate in candidates {
        by_collection
            .entry(candidate.location.collection.handle())
            .or_default()
            .push(candidate);
    }

    let store_snapshot = store
        .snapshot()
        .context("freeze shared vault store snapshot")?;
    let mut materialized = Vec::new();
    for candidates in by_collection.into_values() {
        let location = candidates[0].location;
        let cover = match admitted_vault_cover(&store_snapshot, location) {
            Ok(cover) => cover,
            Err(error) => {
                issues.push(issue(
                    VaultDiscoveryIssueKind::MaterializationFailed,
                    candidates.first().map(|candidate| candidate.id),
                    Some(location.authority),
                    location.collection.handle(),
                    Some(location.vault),
                    error.to_string(),
                ));
                continue;
            }
        };
        let facts = match read_vault_cover(&store_snapshot, &cover) {
            Ok(facts) => facts,
            Err(error) => {
                issues.push(issue(
                    VaultDiscoveryIssueKind::MaterializationFailed,
                    candidates.first().map(|candidate| candidate.id),
                    Some(location.authority),
                    location.collection.handle(),
                    Some(location.vault),
                    error.to_string(),
                ));
                continue;
            }
        };
        if header_count(&facts) == 0 {
            issues.push(issue(
                VaultDiscoveryIssueKind::MissingHeader,
                candidates.first().map(|candidate| candidate.id),
                Some(location.authority),
                location.collection.handle(),
                Some(location.vault),
                "vault has no resident canonical header yet",
            ));
            continue;
        }
        materialized.push((location, facts, candidates));
    }

    let mut ready = Vec::<(VaultLocation, TribleSet, VaultAccess)>::new();
    for (location, facts, candidates) in materialized {
        let catalog = match validate_catalog(&store_snapshot, location.vault, &facts) {
            Ok(catalog) => catalog,
            Err(error) => {
                issues.push(issue(
                    VaultDiscoveryIssueKind::InvalidVault,
                    candidates.first().map(|candidate| candidate.id),
                    Some(location.authority),
                    location.collection.handle(),
                    Some(location.vault),
                    error.to_string(),
                ));
                continue;
            }
        };
        let Some(custody) = catalog.custody else {
            issues.push(issue(
                VaultDiscoveryIssueKind::InvalidVault,
                candidates.first().map(|candidate| candidate.id),
                Some(location.authority),
                location.collection.handle(),
                Some(location.vault),
                "capability-native vault has no custody declaration",
            ));
            continue;
        };
        let mut matching = Vec::new();
        for candidate in &candidates {
            if candidate.custody.verifying_key().to_bytes() == custody.public_key {
                matching.push(candidate);
            } else {
                issues.push(issue(
                    VaultDiscoveryIssueKind::CustodyMismatch,
                    Some(candidate.id),
                    Some(location.authority),
                    location.collection.handle(),
                    Some(location.vault),
                    "opened envelope custody does not match the materialized vault",
                ));
            }
        }
        let Some(first) = matching.first() else {
            continue;
        };
        let access = match VaultAccess::new(
            location.vault,
            location.authority,
            location.collection,
            signing_key.verifying_key(),
            first.custody.clone(),
            matching
                .iter()
                .map(|candidate| candidate.read_bundle.clone())
                .collect(),
            write_bundles(&candidates),
        ) {
            Ok(access) => access,
            Err(error) => {
                issues.push(issue(
                    VaultDiscoveryIssueKind::InvalidEnvelope,
                    Some(first.id),
                    Some(location.authority),
                    location.collection.handle(),
                    Some(location.vault),
                    error.to_string(),
                ));
                continue;
            }
        };
        ready.push((location, facts, access));
    }

    let mut locations = BTreeMap::new();
    let ready = ready
        .into_iter()
        .map(|(location, facts, access)| {
            locations.insert(location.collection.handle(), location);
            (location.vault, facts, access)
        })
        .collect::<Vec<_>>();
    let snapshot = SecretsSnapshot::new_accessible(store_snapshot, ready)
        .context("construct aggregate from independently validated vaults")?;
    issues.sort_by_key(|issue| (issue.vault, issue.collection, issue.candidate, issue.kind));
    Ok(VaultDiscovery {
        snapshot,
        locations,
        issues,
    })
}

fn fresh_custody_key() -> SigningKey {
    let seed = RandomSeed::generate();
    SigningKey::from_bytes(seed.as_array())
}

/// Create one capability-anchored custody vault.
///
/// The founder envelope is published first.  A retry reuses a valid
/// pre-existing founder envelope for the same exact vault, avoiding a second
/// custody epoch after a crash between the inbox and vault commits. If the
/// genesis already exists, its stored creation time wins; `created_at` is only
/// used when this call actually creates the epoch.
pub fn create_vault(
    store: &mut Pile,
    signing_key: &SigningKey,
    vault: Id,
    name: &str,
    created_at: IntervalValue,
) -> Result<VaultLocation> {
    let authority = signing_key.verifying_key();
    let location = VaultLocation::open(store, vault, authority)?;
    let collection = location.collection;
    let instant = triblespace::core::clock::epoch_now();
    let (root_read, root_write) = founder_proofs(signing_key, location);

    let (all_candidates, _) = discover_access_candidates(store, signing_key)?;
    let candidates = all_candidates
        .into_iter()
        .filter(|candidate| candidate.location == location)
        .collect::<Vec<_>>();
    let suitable = candidates
        .iter()
        .filter(|candidate| {
            candidate.writer == signing_key.verifying_key()
                && candidate
                    .read_bundle
                    .verify(
                        authority,
                        instant,
                        signing_key.verifying_key(),
                        CapabilityRequest::new(
                            read_atom(collection.handle()),
                            CapabilityMode::InvokeAndDelegate,
                        ),
                    )
                    .is_ok_and(|verified| verified.effective_validity().is_none())
        })
        .cloned()
        .collect::<Vec<_>>();

    let store_snapshot = store
        .snapshot()
        .context("freeze vault store snapshot before creation")?;
    let cover =
        admitted_vault_cover(&store_snapshot, location).context("admit vault before creation")?;
    let existing = read_vault_cover(&store_snapshot, &cover)
        .context("inspect policy-admitted vault before creation")?;
    if !existing.is_empty() {
        let catalog = validate_catalog(&store_snapshot, vault, &existing)
            .context("validate existing vault during idempotent create")?;
        let custody = catalog
            .custody
            .context("existing capability-native vault has no custody declaration")?;
        let expected = load_catalog(
            vault,
            vault_header_fragment(vault, name, catalog.header.created_at, custody.public_key)?
                .facts(),
        )?;
        if catalog.header != expected.header || catalog.custody != expected.custody {
            bail!("vault id already exists with a different header or custody declaration");
        }
        if !suitable
            .iter()
            .any(|candidate| candidate.custody.verifying_key().to_bytes() == custody.public_key)
        {
            bail!("existing vault has no usable founder access envelope in the local inbox");
        }
        return Ok(location);
    }

    let custody_keys = suitable
        .iter()
        .map(|candidate| candidate.custody.verifying_key().to_bytes())
        .collect::<BTreeSet<_>>();
    if custody_keys.len() > 1 {
        bail!("pre-commit founder envelopes disagree about the vault custody key");
    }
    let (custody, already_published) = match suitable.first() {
        Some(candidate) => (candidate.custody.clone(), true),
        None => (fresh_custody_key(), false),
    };
    if !already_published {
        publish_access_envelope(
            store,
            signing_key,
            location,
            &custody,
            signing_key.verifying_key(),
            &root_read,
            signing_key.verifying_key(),
            &root_write,
            instant,
        )
        .context("publish founder access envelope before vault genesis")?;
    }

    let header =
        vault_header_fragment(vault, name, created_at, custody.verifying_key().to_bytes())?;
    load_catalog(vault, header.facts()).context("validate vault genesis")?;
    store
        .commit(collection, signing_key, header)
        .context("publish capability-anchored vault genesis")?;
    Ok(location)
}

fn checked_vault<'a, R>(
    snapshot: &'a SecretsSnapshot<R>,
    location: &VaultLocation,
) -> Result<&'a VaultCatalog> {
    let access = snapshot
        .access_exact(location.collection.handle())
        .ok_or_else(|| anyhow!("vault {} has no verified local access", location.vault))?;
    if access.collection() != location.collection.handle()
        || access.trust_root() != location.authority
    {
        bail!("vault location disagrees with its verified access evidence");
    }
    snapshot
        .vault_exact(location.collection.handle())
        .map(|vault| vault.catalog())
        .ok_or_else(|| anyhow!("vault {} is not ready in this snapshot", location.vault))
}

fn validate_prospective_union(vault: Id, current: &TribleSet, candidate: &Fragment) -> Result<()> {
    let mut prospective = current.clone();
    prospective += candidate.facts().clone();
    load_catalog(vault, &prospective).context("validate prospective vault union")?;
    Ok(())
}

/// Seal one immutable secret to the vault's single custody key and publish it.
///
/// Local publication is unconditional. A later snapshot discovers resident
/// WRITE proofs and admits this signer only when one authorizes the vault.
pub fn add_secret<R: BlobStoreGet>(
    store: &mut Pile,
    signing_key: &SigningKey,
    location: &VaultLocation,
    snapshot: &SecretsSnapshot<R>,
    name: &str,
    plaintext: &[u8],
    created_at: IntervalValue,
) -> Result<Id> {
    let catalog = checked_vault(snapshot, location)?;
    let custody = catalog
        .custody
        .context("capability-native vault has no custody declaration")?;
    let sealed = seal_version(name, plaintext, custody.public_key, created_at)?;
    let current = snapshot
        .vault_exact(location.collection.handle())
        .expect("checked vault above")
        .facts();
    validate_prospective_union(location.vault, current, &sealed.fragment)?;
    let secret = sealed.secret;
    store
        .commit(location.collection, signing_key, sealed.fragment)
        .context("publish encrypted secret version")?;
    Ok(secret)
}

fn delegating_read_bundle(
    access: &VaultAccess,
    issuer: &SigningKey,
    recipient: VerifyingKey,
    instant: Epoch,
) -> Result<CapabilityProofBundle> {
    if issuer.verifying_key() != access.subject() {
        bail!("vault READ delegation requires the access-envelope subject key");
    }
    let atom = read_atom(access.collection());
    for parent in access.read_bundles() {
        let verified = match parent.verify(
            access.trust_root(),
            instant,
            issuer.verifying_key(),
            CapabilityRequest::new(atom, CapabilityMode::InvokeAndDelegate),
        ) {
            Ok(verified) => verified,
            Err(_) => continue,
        };
        let child_claim =
            CapabilityClaim::delegated(verified.claim_handle(), atom, CapabilityMode::Invoke, None);
        let child = verified
            .delegate(issuer, child_claim, recipient)
            .context("issue delegated READ proof")?;
        child
            .verify(
                access.trust_root(),
                instant,
                recipient,
                CapabilityRequest::new(atom, CapabilityMode::Invoke),
            )
            .context("verify newly delegated READ proof")?;
        return Ok(child);
    }
    bail!("no supplied READ proof permits delegation for this vault")
}

/// Deliver one exact child READ capability and the same vault custody seed to
/// a recipient's deterministic access inbox.
///
/// One access envelope is emitted for every distinct WRITE proof bundle needed
/// to reconstruct the current multi-writer collection. They are committed as
/// one inbox fragment, so a recipient never observes only a prefix of the
/// required writer set.  Work is independent of the number of vault secrets.
pub fn grant_vault_read<R: BlobStoreGet>(
    store: &mut Pile,
    signing_key: &SigningKey,
    location: &VaultLocation,
    snapshot: &SecretsSnapshot<R>,
    recipient: VerifyingKey,
) -> Result<Vec<Id>> {
    checked_vault(snapshot, location)?;
    let access = snapshot
        .access_exact(location.collection.handle())
        .expect("checked_vault requires access");
    let instant = triblespace::core::clock::epoch_now();
    let child_read = delegating_read_bundle(access, signing_key, recipient, instant)?;
    let mut envelope_ids = Vec::new();
    let mut envelopes = Fragment::empty();
    let mut seen = BTreeSet::new();
    let mut write_bundles = Vec::new();
    for bundle in access.write_bundles() {
        let writer = bundle.proof().leaf_key();
        let proof_id = bundle.proof().id();
        if !seen.insert((writer.to_bytes(), proof_id.raw)) {
            continue;
        }
        let envelope = build_access_envelope(
            location.collection.handle(),
            access.custody(),
            recipient,
            &child_read,
            writer,
            bundle,
            access.trust_root(),
            instant,
        )
        .context("build delegated access envelope")?;
        envelope_ids.push(
            envelope
                .root()
                .context("delegated access envelope did not export its intrinsic id")?,
        );
        envelopes += envelope;
        write_bundles.push(bundle.clone());
    }
    if envelope_ids.is_empty() {
        bail!("vault access has no distinct WRITE proof bundle");
    }
    persist_proof_bundle(store, &child_read).context("persist delegated READ proof closure")?;
    for (index, bundle) in write_bundles.iter().enumerate() {
        persist_proof_bundle(store, bundle)
            .with_context(|| format!("persist WRITE proof bundle {index}"))?;
    }
    let inbox = register_access_inbox(store, recipient)?;
    store
        .commit(inbox, signing_key, envelopes)
        .context("publish complete delegated access envelope set")?;
    Ok(envelope_ids)
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::path::PathBuf;

    use hifitime::Epoch;
    use tempfile::TempDir;
    use triblespace::core::capability::CapabilityValidity;
    use triblespace::core::repo::memoryrepo::MemoryRepo;

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

    #[test]
    fn proof_claims_are_persisted_before_the_proof_becomes_discoverable() {
        let founder = key(99);
        let mut store = MemoryRepo::default();
        let location = VaultLocation::open(&mut store, id(99), founder.verifying_key()).unwrap();
        let (read, _) = founder_proofs(&founder, location);
        let expected = read.proof().claim_handles().collect::<Vec<_>>();

        persist_proof_bundle(&mut store, &read).unwrap();

        let snapshot = store.snapshot().unwrap();
        assert!(expected
            .into_iter()
            .all(|claim| snapshot.metadata(claim).unwrap().is_some()));
        assert_eq!(
            snapshot.proof(read.proof().id()).unwrap(),
            Some(read.proof().clone())
        );
    }

    #[test]
    fn create_retry_reuses_custody_and_delegation_is_constant_in_vault_size() {
        let files = TestPile::new();
        let founder = key(1);
        let recipient = key(2);
        let mut pile = files.open();
        let location = create_vault(&mut pile, &founder, id(1), "production", at(1)).unwrap();
        create_vault(&mut pile, &founder, id(1), "production", at(999)).unwrap();

        let discovery = discover_local_vaults(&mut pile, &founder).unwrap();
        assert!(discovery.issues().is_empty());
        let first = add_secret(
            &mut pile,
            &founder,
            &location,
            discovery.snapshot(),
            "first",
            b"one",
            at(2),
        )
        .unwrap();
        drop(discovery);

        let discovery = discover_local_vaults(&mut pile, &founder).unwrap();
        grant_vault_read(
            &mut pile,
            &founder,
            &location,
            discovery.snapshot(),
            recipient.verifying_key(),
        )
        .unwrap();
        drop(discovery);

        let recipient_view = discover_local_vaults(&mut pile, &recipient).unwrap();
        assert!(recipient_view.issues().is_empty());
        assert_eq!(
            recipient_view.snapshot().open(first, &recipient).unwrap(),
            b"one"
        );
        pile.close().unwrap();
    }

    #[test]
    fn authorized_ambient_writer_participates_in_policy_admission() {
        let files = TestPile::new();
        let founder = key(35);
        let ambient = key(36);
        let vault = id(35);
        let mut pile = files.open();
        let location = create_vault(&mut pile, &founder, vault, "stable", at(1)).unwrap();

        let ambient_write = CapabilityProofBundle::issue_root(
            &founder,
            CapabilityClaim::root(
                write_atom(location.collection()),
                CapabilityMode::Invoke,
                None,
            ),
            ambient.verifying_key(),
        )
        .unwrap();
        persist_proof_bundle(&mut pile, &ambient_write).unwrap();
        let poison = vault_header_fragment(
            vault,
            "ambient-conflict",
            at(2),
            key(37).verifying_key().to_bytes(),
        )
        .unwrap();
        pile.commit(location.collection, &ambient, poison).unwrap();

        assert!(create_vault(&mut pile, &founder, vault, "stable", at(999)).is_err());
        let discovery = discover_local_vaults(&mut pile, &founder).unwrap();
        assert!(discovery
            .issues()
            .iter()
            .any(|issue| issue.kind() == VaultDiscoveryIssueKind::InvalidVault));
        assert!(discovery
            .snapshot()
            .vault_exact(location.collection())
            .is_none());
        pile.close().unwrap();
    }

    #[test]
    fn grant_delivers_every_writer_in_one_inbox_commit() {
        let files = TestPile::new();
        let founder = key(3);
        let writer = key(4);
        let recipient = key(5);
        let mut pile = files.open();
        let location = create_vault(&mut pile, &founder, id(3), "multi-writer", at(1)).unwrap();

        let founder_view = discover_local_vaults(&mut pile, &founder).unwrap();
        let custody = SigningKey::from_bytes(
            &founder_view
                .snapshot()
                .access_exact(location.collection())
                .unwrap()
                .custody()
                .to_bytes(),
        );
        drop(founder_view);

        let (founder_read, founder_write) = founder_proofs(&founder, location);
        let write_atom = write_atom(location.collection());
        let instant = triblespace::core::clock::epoch_now();
        let verified_founder_write = founder_write
            .verify(
                founder.verifying_key(),
                instant,
                founder.verifying_key(),
                CapabilityRequest::new(write_atom, CapabilityMode::InvokeAndDelegate),
            )
            .unwrap();
        let writer_write = verified_founder_write
            .delegate(
                &founder,
                CapabilityClaim::delegated(
                    verified_founder_write.claim_handle(),
                    write_atom,
                    CapabilityMode::Invoke,
                    None,
                ),
                writer.verifying_key(),
            )
            .unwrap();
        publish_access_envelope(
            &mut pile,
            &founder,
            location,
            &custody,
            founder.verifying_key(),
            &founder_read,
            writer.verifying_key(),
            &writer_write,
            triblespace::core::clock::epoch_now(),
        )
        .unwrap();

        let sealed = seal_version(
            "written-elsewhere",
            b"two writers",
            custody.verifying_key().to_bytes(),
            at(2),
        )
        .unwrap();
        let secret = sealed.secret;
        pile.commit(location.collection, &writer, sealed.fragment)
            .unwrap();

        let founder_view = discover_local_vaults(&mut pile, &founder).unwrap();
        let envelope_ids = grant_vault_read(
            &mut pile,
            &founder,
            &location,
            founder_view.snapshot(),
            recipient.verifying_key(),
        )
        .unwrap();
        assert_eq!(envelope_ids.len(), 2);
        drop(founder_view);

        let recipient_view = discover_local_vaults(&mut pile, &recipient).unwrap();
        assert!(recipient_view.issues().is_empty());
        assert_eq!(
            recipient_view
                .snapshot()
                .open_exact(location.collection(), secret, &recipient)
                .unwrap(),
            b"two writers"
        );
        pile.close().unwrap();
    }

    #[test]
    fn policy_admission_uses_all_resident_writer_proofs() {
        let files = TestPile::new();
        let founder = key(31);
        let ambient = key(32);
        let leased = key(33);
        let recipient = key(34);
        let mut pile = files.open();
        let location = create_vault(&mut pile, &founder, id(31), "scoped-writers", at(1)).unwrap();

        let founder_view = discover_local_vaults(&mut pile, &founder).unwrap();
        let custody = SigningKey::from_bytes(
            &founder_view
                .snapshot()
                .access_exact(location.collection())
                .unwrap()
                .custody()
                .to_bytes(),
        );
        drop(founder_view);

        let instant = triblespace::core::clock::epoch_now();
        let unbounded = CapabilityProofBundle::issue_root(
            &founder,
            CapabilityClaim::root(
                write_atom(location.collection()),
                CapabilityMode::Invoke,
                None,
            ),
            ambient.verifying_key(),
        )
        .unwrap();
        let validity = CapabilityValidity::new(
            instant - hifitime::Duration::from_seconds(60.0),
            instant + hifitime::Duration::from_seconds(3600.0),
        )
        .unwrap();
        let bounded = CapabilityProofBundle::issue_root(
            &founder,
            CapabilityClaim::root(
                write_atom(location.collection()),
                CapabilityMode::Invoke,
                Some(validity),
            ),
            leased.verifying_key(),
        )
        .unwrap();
        persist_proof_bundle(&mut pile, &unbounded).unwrap();
        persist_proof_bundle(&mut pile, &bounded).unwrap();

        let ambient_secret = seal_version(
            "ambient-unbounded",
            b"must stay outside the envelope scope",
            custody.verifying_key().to_bytes(),
            at(2),
        )
        .unwrap();
        let ambient_id = ambient_secret.secret;
        pile.commit(location.collection, &ambient, ambient_secret.fragment)
            .unwrap();
        let leased_secret = seal_version(
            "ambient-bounded",
            b"must not appear and later expire",
            custody.verifying_key().to_bytes(),
            at(3),
        )
        .unwrap();
        let leased_id = leased_secret.secret;
        pile.commit(location.collection, &leased, leased_secret.fragment)
            .unwrap();

        let founder_view = discover_local_vaults(&mut pile, &founder).unwrap();
        assert!(founder_view.issues().is_empty());
        let founder_access = founder_view
            .snapshot()
            .access_exact(location.collection())
            .unwrap();
        assert_eq!(founder_access.write_bundles().len(), 1);
        assert_eq!(
            founder_access.write_bundles()[0].proof().leaf_key(),
            founder.verifying_key()
        );
        assert_eq!(
            founder_view
                .snapshot()
                .open_exact(location.collection(), ambient_id, &founder)
                .unwrap(),
            b"must stay outside the envelope scope"
        );
        assert_eq!(
            founder_view
                .snapshot()
                .open_exact(location.collection(), leased_id, &founder)
                .unwrap(),
            b"must not appear and later expire"
        );

        let envelopes = grant_vault_read(
            &mut pile,
            &founder,
            &location,
            founder_view.snapshot(),
            recipient.verifying_key(),
        )
        .unwrap();
        assert_eq!(envelopes.len(), 1);
        drop(founder_view);

        let recipient_view = discover_local_vaults(&mut pile, &recipient).unwrap();
        assert!(recipient_view.issues().is_empty());
        let recipient_access = recipient_view
            .snapshot()
            .access_exact(location.collection())
            .unwrap();
        assert_eq!(recipient_access.write_bundles().len(), 1);
        assert_eq!(
            recipient_access.write_bundles()[0].proof().leaf_key(),
            founder.verifying_key()
        );
        assert_eq!(
            recipient_view
                .snapshot()
                .open_exact(location.collection(), ambient_id, &recipient)
                .unwrap(),
            b"must stay outside the envelope scope"
        );
        assert_eq!(
            recipient_view
                .snapshot()
                .open_exact(location.collection(), leased_id, &recipient)
                .unwrap(),
            b"must not appear and later expire"
        );
        pile.close().unwrap();
    }

    #[test]
    fn colliding_graph_local_vault_ids_remain_exactly_addressable() {
        let files = TestPile::new();
        let first = key(6);
        let second = key(7);
        let recipient = key(8);
        let vault = id(6);
        let mut pile = files.open();
        let first_location = create_vault(&mut pile, &first, vault, "first", at(1)).unwrap();
        let second_location = create_vault(&mut pile, &second, vault, "second", at(2)).unwrap();

        let first_view = discover_local_vaults(&mut pile, &first).unwrap();
        grant_vault_read(
            &mut pile,
            &first,
            &first_location,
            first_view.snapshot(),
            recipient.verifying_key(),
        )
        .unwrap();
        drop(first_view);
        let second_view = discover_local_vaults(&mut pile, &second).unwrap();
        grant_vault_read(
            &mut pile,
            &second,
            &second_location,
            second_view.snapshot(),
            recipient.verifying_key(),
        )
        .unwrap();
        drop(second_view);

        let discovery = discover_local_vaults(&mut pile, &recipient).unwrap();
        assert_eq!(discovery.locations().len(), 2);
        assert!(discovery.location(vault).is_none());
        assert_eq!(
            discovery.location_exact(first_location.collection()),
            Some(&first_location)
        );
        assert_eq!(
            discovery.location_exact(second_location.collection()),
            Some(&second_location)
        );
        assert!(discovery
            .snapshot()
            .vault_exact(first_location.collection())
            .is_some());
        assert!(discovery
            .snapshot()
            .vault_exact(second_location.collection())
            .is_some());
        pile.close().unwrap();
    }

    #[test]
    fn create_does_not_adopt_a_bounded_founder_read_lease() {
        let files = TestPile::new();
        let founder = key(9);
        let vault = id(9);
        let stale_custody = key(10);
        let mut pile = files.open();
        let location = VaultLocation::open(&mut pile, vault, founder.verifying_key()).unwrap();
        let instant = triblespace::core::clock::epoch_now();
        let validity = CapabilityValidity::new(
            instant - hifitime::Duration::from_seconds(1.0),
            instant + hifitime::Duration::from_seconds(3600.0),
        )
        .unwrap();
        let bounded_read = CapabilityProofBundle::issue_root(
            &founder,
            CapabilityClaim::root(
                read_atom(location.collection()),
                CapabilityMode::InvokeAndDelegate,
                Some(validity),
            ),
            founder.verifying_key(),
        )
        .unwrap();
        let (_, write) = founder_proofs(&founder, location);
        publish_access_envelope(
            &mut pile,
            &founder,
            location,
            &stale_custody,
            founder.verifying_key(),
            &bounded_read,
            founder.verifying_key(),
            &write,
            instant,
        )
        .unwrap();

        create_vault(&mut pile, &founder, vault, "durable", at(1)).unwrap();
        let discovery = discover_local_vaults(&mut pile, &founder).unwrap();
        let actual = discovery
            .snapshot()
            .access_exact(location.collection())
            .unwrap()
            .custody()
            .verifying_key();
        assert_ne!(actual, stale_custody.verifying_key());
        assert!(discovery
            .issues()
            .iter()
            .any(|issue| issue.kind() == VaultDiscoveryIssueKind::CustodyMismatch));
        pile.close().unwrap();
    }

    #[test]
    fn copied_envelope_under_wrong_inbox_signer_is_isolated() {
        let files = TestPile::new();
        let founder = key(11);
        let attacker = key(12);
        let mut pile = files.open();
        let location = create_vault(&mut pile, &founder, id(11), "isolated", at(1)).unwrap();

        let inbox = register_access_inbox(&mut pile, founder.verifying_key()).unwrap();
        let snapshot = pile.snapshot().unwrap();
        let selectors = BTreeSet::from([CollectionRecordSelector::Collection(inbox.handle())]);
        let commits = snapshot
            .select_records(&selectors)
            .unwrap()
            .into_iter()
            .filter_map(|record| match record {
                CollectionRecord::Commit(commit) if commit.verify_strict().is_ok() => Some(commit),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(commits.len(), 1);
        let data: Blob<SimpleArchive> = snapshot
            .get(Handle::<SimpleArchive>::from_hash(commits[0].data()))
            .unwrap();
        let copied_facts = TribleSet::try_from_blob(data).unwrap();
        drop(snapshot);

        pile.commit(
            inbox,
            &attacker,
            Fragment::new(std::iter::empty(), copied_facts),
        )
        .unwrap();

        let discovery = discover_local_vaults(&mut pile, &founder).unwrap();
        assert_eq!(discovery.location(location.vault()), Some(&location));
        assert_eq!(
            discovery
                .issues()
                .iter()
                .filter(|issue| issue.kind() == VaultDiscoveryIssueKind::InvalidEnvelope)
                .count(),
            1
        );
        assert!(discovery.issues().iter().any(|issue| issue
            .detail()
            .contains("commit signer is not the exact READ leaf issuer")));
        pile.close().unwrap();
    }

    #[test]
    fn malformed_sibling_rejects_one_atomic_inbox_commit() {
        let files = TestPile::new();
        let founder = key(13);
        let mut pile = files.open();
        let location = VaultLocation::open(&mut pile, id(13), founder.verifying_key()).unwrap();
        let custody = key(14);
        let (read, write) = founder_proofs(&founder, location);
        let instant = triblespace::core::clock::epoch_now();
        let mut delivery = build_access_envelope(
            location.collection(),
            &custody,
            founder.verifying_key(),
            &read,
            founder.verifying_key(),
            &write,
            founder.verifying_key(),
            instant,
        )
        .unwrap();
        delivery += entity! { _ @ metadata::tag: &KIND_ACCESS_ENVELOPE };

        persist_proof_bundle(&mut pile, &read).unwrap();
        persist_proof_bundle(&mut pile, &write).unwrap();
        let inbox = register_access_inbox(&mut pile, founder.verifying_key()).unwrap();
        pile.commit(inbox, &founder, delivery).unwrap();
        let (candidates, issues) = discover_access_candidates(&mut pile, &founder).unwrap();
        assert!(candidates.is_empty());
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].kind(), VaultDiscoveryIssueKind::InvalidEnvelope);
        pile.close().unwrap();
    }

    #[test]
    fn stale_wrong_custody_envelope_does_not_poison_committed_vault() {
        let files = TestPile::new();
        let founder = key(21);
        let wrong_custody = key(22);
        let mut pile = files.open();
        let location = create_vault(&mut pile, &founder, id(21), "stable", at(1)).unwrap();
        let (read, write) = founder_proofs(&founder, location);
        publish_access_envelope(
            &mut pile,
            &founder,
            location,
            &wrong_custody,
            founder.verifying_key(),
            &read,
            founder.verifying_key(),
            &write,
            triblespace::core::clock::epoch_now(),
        )
        .unwrap();

        let discovery = discover_local_vaults(&mut pile, &founder).unwrap();
        assert_eq!(discovery.location(location.vault()), Some(&location));
        assert_eq!(
            discovery
                .issues()
                .iter()
                .filter(|issue| issue.kind() == VaultDiscoveryIssueKind::CustodyMismatch)
                .count(),
            1
        );
        pile.close().unwrap();
    }
}
