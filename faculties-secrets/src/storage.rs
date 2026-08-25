//! Pile-backed discovery and publication for capability-native Secrets vaults.
//!
//! Vault authority is never discovered by enumerating a global ledger.  Each
//! recipient instead has one private, open-admission access inbox.  An inbox
//! commit is merely an untrusted candidate: its envelope, exact proof closure,
//! and exact vault descriptor are validated independently before the candidate
//! can contribute either decryption custody or collection admission.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Context, Result};
use dryoc::dryocsecretbox::Key as RandomSeed;
use dryoc::types::{ByteArray, NewByteArray};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hifitime::Epoch;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::{Blob, TryFromBlob};
use triblespace::core::capability::{
    CapabilityAction, CapabilityAtom, CapabilityClaim, CapabilityGrant, CapabilityMode,
    CapabilityProof, CapabilityProofStep, CapabilityResource,
};
use triblespace::core::collection::{
    descriptor, reach, simplearchive_union, CapabilityPresentation, CollectionAdmission,
    CollectionHandle, ACTION_WRITE,
};
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::metadata;
use triblespace::core::repo::memoryrepo::MemoryRepo;
use triblespace::core::repo::pile::{GetBlobError, Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
use triblespace::prelude::*;

use super::access::{
    build_access_envelope, load_access_envelope, open_access_envelope, read_proof_issuer,
};
use super::schema::{KIND_ACCESS_ENVELOPE, KIND_VAULT};
use super::{
    load_catalog, parse_vault_name, seal_version, validate_catalog, vault_collection,
    vault_descriptor, vault_handle, vault_header_fragment, IntervalValue, SecretsSnapshot,
    VaultAccess, VaultCatalog, ACTION_READ,
};

const ACCESS_INBOX_NAME: &str = "secrets-access";

/// One ready vault's exact collection identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultLocation {
    vault: Id,
    namespace: VerifyingKey,
    authority: VerifyingKey,
    collection: CollectionHandle,
}

impl VaultLocation {
    /// Construct the exact canonical private vault location.
    pub fn new(vault: Id, namespace: VerifyingKey, authority: VerifyingKey) -> Self {
        Self {
            vault,
            namespace,
            authority,
            collection: vault_handle(vault, namespace, authority),
        }
    }

    pub const fn vault(&self) -> Id {
        self.vault
    }

    pub fn namespace(&self) -> VerifyingKey {
        self.namespace
    }

    pub fn authority(&self) -> VerifyingKey {
        self.authority
    }

    pub const fn collection(&self) -> CollectionHandle {
        self.collection
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
    snapshot: SecretsSnapshot<PileReader>,
    locations: BTreeMap<CollectionHandle, VaultLocation>,
    issues: Vec<VaultDiscoveryIssue>,
}

impl VaultDiscovery {
    pub fn snapshot(&self) -> &SecretsSnapshot<PileReader> {
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
        SecretsSnapshot<PileReader>,
        BTreeMap<CollectionHandle, VaultLocation>,
        Vec<VaultDiscoveryIssue>,
    ) {
        (self.snapshot, self.locations, self.issues)
    }
}

/// Canonical private inbox descriptor for one direct recipient.
pub fn access_inbox_descriptor(recipient: VerifyingKey) -> Fragment {
    simplearchive_union::descriptor(
        &CollectionName::new(ACCESS_INBOX_NAME).expect("the static inbox name is canonical"),
        recipient,
        None,
        reach::private(),
    )
}

/// Exact content identity of one recipient's private access inbox.
pub fn access_inbox_handle(recipient: VerifyingKey) -> CollectionHandle {
    access_inbox_descriptor(recipient)
        .into_facts()
        .to_blob()
        .get_handle()
}

/// Construct the low-level collection facade for one recipient's private
/// access inbox. Inbox COMMITs remain untrusted candidates until discovery
/// validates their envelope, proof closure, publisher, and vault descriptor.
pub fn access_inbox_collection<S>(
    storage: S,
    recipient: VerifyingKey,
    publisher: SigningKey,
) -> Collection<S> {
    Collection::new(
        storage,
        &CollectionName::new(ACCESS_INBOX_NAME).expect("the static inbox name is canonical"),
        recipient,
        publisher,
        reach::private(),
        CollectionAdmission::open(),
    )
}

enum DescriptorReadError {
    Missing(String),
    Invalid(String),
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
    decode_descriptor_facts(blob, collection)
}

fn portable_descriptor_facts<R>(
    reader: &R,
    collection: CollectionHandle,
) -> std::result::Result<TribleSet, DescriptorReadError>
where
    R: BlobStoreGet + BlobStoreMeta,
{
    match reader.metadata(collection) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(DescriptorReadError::Missing(format!(
                "collection descriptor {} is not resident",
                bytes_hex(&collection.raw)
            )));
        }
        Err(error) => {
            return Err(DescriptorReadError::Invalid(format!(
                "inspect collection descriptor {}: {error}",
                bytes_hex(&collection.raw)
            )));
        }
    }
    let blob: Blob<SimpleArchive> = reader.get(collection).map_err(|error| {
        DescriptorReadError::Invalid(format!(
            "read collection descriptor {}: {error}",
            bytes_hex(&collection.raw)
        ))
    })?;
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
    reader: &PileReader,
    collection: CollectionHandle,
) -> std::result::Result<VaultLocation, (VaultDiscoveryIssueKind, String)> {
    let facts = descriptor_facts(reader, collection).map_err(classify_descriptor_error)?;
    parse_descriptor_value(facts, collection)
}

fn parse_portable_descriptor<R>(
    reader: &R,
    collection: CollectionHandle,
) -> std::result::Result<VaultLocation, (VaultDiscoveryIssueKind, String)>
where
    R: BlobStoreGet + BlobStoreMeta,
{
    let facts = portable_descriptor_facts(reader, collection).map_err(classify_descriptor_error)?;
    parse_descriptor_value(facts, collection)
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

fn parse_descriptor_value(
    facts: TribleSet,
    collection: CollectionHandle,
) -> std::result::Result<VaultLocation, (VaultDiscoveryIssueKind, String)> {
    let name = descriptor::name(&facts)
        .ok_or_else(|| {
            (
                VaultDiscoveryIssueKind::InvalidDescriptor,
                "vault descriptor has no collection name".to_owned(),
            )
        })?
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
    let namespace = descriptor::namespace(&facts)
        .ok_or_else(|| {
            (
                VaultDiscoveryIssueKind::InvalidDescriptor,
                "vault descriptor has no namespace".to_owned(),
            )
        })?
        .map_err(|error| {
            (
                VaultDiscoveryIssueKind::InvalidDescriptor,
                format!("decode vault namespace: {error}"),
            )
        })?;
    let authority = descriptor::authority(&facts)
        .ok_or_else(|| {
            (
                VaultDiscoveryIssueKind::InvalidDescriptor,
                "vault descriptor has no capability authority".to_owned(),
            )
        })?
        .map_err(|error| {
            (
                VaultDiscoveryIssueKind::InvalidDescriptor,
                format!("decode vault authority: {error}"),
            )
        })?;
    let expected = vault_descriptor(vault, namespace, authority);
    if expected.facts() != &facts || vault_handle(vault, namespace, authority) != collection {
        return Err((
            VaultDiscoveryIssueKind::InvalidDescriptor,
            "descriptor is not the exact private SimpleArchive-union vault descriptor".to_owned(),
        ));
    }
    Ok(VaultLocation {
        vault,
        namespace,
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
    read_proof: CapabilityProof,
    writer: VerifyingKey,
    write_proof: CapabilityProof,
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

    pub fn read_proof(&self) -> &CapabilityProof {
        &self.read_proof
    }

    pub fn writer(&self) -> VerifyingKey {
        self.writer
    }

    pub fn write_proof(&self) -> &CapabilityProof {
        &self.write_proof
    }
}

/// Discover independently validated access candidates without requiring the
/// referenced vault collection to exist yet.
pub fn discover_access_candidates<S>(
    store: &mut S,
    recipient: &SigningKey,
) -> Result<(Vec<ValidatedAccessCandidate>, Vec<VaultDiscoveryIssue>)>
where
    S: BlobStore<Reader = PileReader> + triblespace::core::collection::CollectionStore,
{
    discover_access_candidates_with(store, recipient, parse_descriptor)
}

/// Publish proposed inbox fragments into an ephemeral repository and discover
/// them through the same commit-local validation loop as a live pile.
///
/// This is a pre-publication boundary for migrations and other producers that
/// must prove exact row shape, descriptor closure, proof validity, publisher
/// authority, and sealed-frame readability before touching durable storage.
pub fn discover_staged_access_candidates(
    fragments: &[Fragment],
    recipient: &SigningKey,
    publisher: &SigningKey,
) -> Result<(Vec<ValidatedAccessCandidate>, Vec<VaultDiscoveryIssue>)> {
    let mut scratch = MemoryRepo::default();
    for fragment in fragments {
        access_inbox_collection(&mut scratch, recipient.verifying_key(), publisher.clone())
            .commit(fragment.clone())
            .context("stage access-inbox COMMIT for runtime validation")?;
    }
    discover_access_candidates_with(&mut scratch, recipient, parse_portable_descriptor)
}

fn discover_access_candidates_with<S, F>(
    store: &mut S,
    recipient: &SigningKey,
    mut parse: F,
) -> Result<(Vec<ValidatedAccessCandidate>, Vec<VaultDiscoveryIssue>)>
where
    S: BlobStore + triblespace::core::collection::CollectionStore,
    S::Reader: BlobStoreMeta,
    F: FnMut(
        &S::Reader,
        CollectionHandle,
    ) -> std::result::Result<VaultLocation, (VaultDiscoveryIssueKind, String)>,
{
    let inbox = access_inbox_handle(recipient.verifying_key());
    let commits =
        access_inbox_collection(&mut *store, recipient.verifying_key(), recipient.clone())
            .ticket()
            .context("discover local Secrets access inbox")?;
    let reader = store.reader().context("open Secrets access-inbox view")?;
    let instant = triblespace::core::clock::epoch_now();
    let mut candidates = Vec::new();
    let mut issues = Vec::new();

    // Materialize each admitted leaf independently. The aggregate union
    // remains the collection's value, but commit-local boundaries prevent an
    // unavailable or malformed leaf from poisoning earlier valid delivery.
    // Rows inside one signed leaf are atomic: multi-writer grants deliberately
    // publish their complete presentation set in one COMMIT.
    for commit in commits {
        let publisher = VerifyingKey::from_bytes(&commit.public_key().raw)
            .expect("collection discovery strictly verifies commit signer keys");
        let metadata: std::result::Result<Blob<SimpleArchive>, _> = reader.get(commit.metadata());
        let metadata = match metadata {
            Ok(metadata) => metadata,
            Err(error) => {
                issues.push(issue(
                    VaultDiscoveryIssueKind::InvalidEnvelope,
                    None,
                    None,
                    inbox,
                    None,
                    format!("access-inbox commit {} metadata: {error}", commit.id()),
                ));
                continue;
            }
        };
        if let Err(error) = simplearchive_union::validate_element(&metadata) {
            issues.push(issue(
                VaultDiscoveryIssueKind::InvalidEnvelope,
                None,
                None,
                inbox,
                None,
                format!("access-inbox commit {} metadata: {error}", commit.id()),
            ));
            continue;
        }
        let data_handle = Handle::<SimpleArchive>::from_hash(commit.data());
        let blob: Blob<SimpleArchive> = match reader.get(data_handle) {
            Ok(blob) => blob,
            Err(error) => {
                issues.push(issue(
                    VaultDiscoveryIssueKind::InvalidEnvelope,
                    None,
                    None,
                    inbox,
                    None,
                    format!("access-inbox commit {} data: {error}", commit.id()),
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
                    inbox,
                    None,
                    format!("access-inbox commit {} data: {error}", commit.id()),
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
                        inbox,
                        None,
                        error.to_string(),
                    ));
                    continue;
                }
            };
            let location = match parse(&reader, row.vault) {
                Ok(location) => location,
                Err((kind, detail)) => {
                    commit_valid = false;
                    issues.push(issue(kind, Some(id), None, row.vault, None, detail));
                    continue;
                }
            };
            let opened =
                match open_access_envelope(&reader, &row, recipient, location.authority, instant) {
                    Ok(opened) => opened,
                    Err(error) => {
                        commit_valid = false;
                        issues.push(issue(
                            VaultDiscoveryIssueKind::InvalidEnvelope,
                            Some(id),
                            Some(location.authority),
                            location.collection,
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
                    location.collection,
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
                read_proof: opened.read_proof,
                writer: opened.writer,
                write_proof: opened.write_proof,
            });
        }
        if commit_valid {
            candidates.extend(commit_candidates);
        }
    }
    Ok((candidates, issues))
}

fn presentations(candidates: &[ValidatedAccessCandidate]) -> Vec<CapabilityPresentation> {
    candidates
        .iter()
        .map(|candidate| {
            CapabilityPresentation::new(candidate.writer, candidate.write_proof.clone())
        })
        .collect()
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

fn root_proof(root: &SigningKey, atom: CapabilityAtom, mode: CapabilityMode) -> CapabilityProof {
    CapabilityProof::new(vec![CapabilityProofStep::issue(
        root,
        CapabilityGrant::root(root.verifying_key(), atom, mode, None),
    )])
}

/// Root-issued, unbounded founder proofs for one exact vault.
pub fn founder_proofs(
    root: &SigningKey,
    location: VaultLocation,
) -> (CapabilityProof, CapabilityProof) {
    (
        root_proof(
            root,
            read_atom(location.collection),
            CapabilityMode::InvokeAndDelegate,
        ),
        root_proof(
            root,
            write_atom(location.collection),
            CapabilityMode::InvokeAndDelegate,
        ),
    )
}

fn retain_descriptor(fragment: &mut Fragment, location: VaultLocation) -> Result<()> {
    let retained = fragment.put::<SimpleArchive, _>(
        vault_descriptor(location.vault, location.namespace, location.authority).into_facts(),
    );
    if retained != location.collection {
        bail!("canonical vault descriptor changed identity while retaining it")
    }
    Ok(())
}

/// Publish one self-contained access envelope to its subject's deterministic
/// inbox.
///
/// The publisher must be the exact issuer of the READ leaf. This makes the
/// inbox COMMIT the delivery signature and prevents a third party from copying
/// valid proof blobs while substituting a different custody seed.
#[allow(clippy::too_many_arguments)]
pub fn publish_access_envelope(
    store: &mut Pile,
    publisher: &SigningKey,
    location: VaultLocation,
    custody: &SigningKey,
    subject: VerifyingKey,
    read_proof: &CapabilityProof,
    writer: VerifyingKey,
    write_proof: &CapabilityProof,
    instant: Epoch,
) -> Result<Id> {
    let mut envelope = build_access_envelope(
        location.collection,
        custody,
        subject,
        read_proof,
        writer,
        write_proof,
        location.authority,
        instant,
    )
    .context("build custody access envelope")?;
    let issuer = read_proof_issuer(read_proof, location.authority, "READ")?;
    if publisher.verifying_key() != issuer {
        bail!("access-inbox publisher is not the exact READ leaf issuer");
    }
    let envelope_id = envelope
        .root()
        .context("access envelope did not export its intrinsic id")?;
    retain_descriptor(&mut envelope, location)?;
    access_inbox_collection(&mut *store, subject, publisher.clone())
        .commit(envelope)
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
    S: BlobStore<Reader = PileReader> + triblespace::core::collection::CollectionStore,
{
    let (candidates, mut issues) = discover_access_candidates(store, signing_key)?;
    let mut by_collection = BTreeMap::<CollectionHandle, Vec<ValidatedAccessCandidate>>::new();
    for candidate in candidates {
        by_collection
            .entry(candidate.location.collection)
            .or_default()
            .push(candidate);
    }

    let mut materialized = Vec::new();
    for candidates in by_collection.into_values() {
        let location = candidates[0].location;
        let admission =
            CollectionAdmission::capability(location.authority, presentations(&candidates));
        let facts = match vault_collection(
            &mut *store,
            location.vault,
            location.namespace,
            signing_key.clone(),
            admission,
        )
        .materialize()
        {
            Ok(facts) => facts,
            Err(error) => {
                issues.push(issue(
                    VaultDiscoveryIssueKind::MaterializationFailed,
                    candidates.first().map(|candidate| candidate.id),
                    Some(location.authority),
                    location.collection,
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
                location.collection,
                Some(location.vault),
                "vault has no resident canonical header yet",
            ));
            continue;
        }
        materialized.push((location, facts, candidates));
    }

    let reader = store
        .reader()
        .context("open shared vault attachment view")?;
    let mut ready = Vec::<(VaultLocation, TribleSet, VaultAccess)>::new();
    for (location, facts, candidates) in materialized {
        let catalog = match validate_catalog(&reader, location.vault, &facts) {
            Ok(catalog) => catalog,
            Err(error) => {
                issues.push(issue(
                    VaultDiscoveryIssueKind::InvalidVault,
                    candidates.first().map(|candidate| candidate.id),
                    Some(location.authority),
                    location.collection,
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
                location.collection,
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
                    location.collection,
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
            location.namespace,
            location.authority,
            signing_key.verifying_key(),
            first.custody.clone(),
            matching
                .iter()
                .map(|candidate| candidate.read_proof.clone())
                .collect(),
            presentations(&candidates),
        ) {
            Ok(access) => access,
            Err(error) => {
                issues.push(issue(
                    VaultDiscoveryIssueKind::InvalidEnvelope,
                    Some(first.id),
                    Some(location.authority),
                    location.collection,
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
            locations.insert(location.collection, location);
            (location.vault, facts, access)
        })
        .collect::<Vec<_>>();
    let snapshot = SecretsSnapshot::new_accessible(reader, ready)
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

fn proof_allows(
    proof: &CapabilityProof,
    root: VerifyingKey,
    subject: VerifyingKey,
    atom: CapabilityAtom,
    mode: CapabilityMode,
    instant: Epoch,
) -> bool {
    proof
        .verify_claim(root, instant, CapabilityClaim::new(subject, atom, mode))
        .is_ok()
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
    let namespace = signing_key.verifying_key();
    let authority = namespace;
    let location = VaultLocation::new(vault, namespace, authority);
    let collection = location.collection;
    let instant = triblespace::core::clock::epoch_now();
    let (root_read, root_write) = founder_proofs(signing_key, location);
    let admission = CollectionAdmission::capability(
        authority,
        vec![CapabilityPresentation::new(
            signing_key.verifying_key(),
            root_write.clone(),
        )],
    );

    let (all_candidates, _) = discover_access_candidates(store, signing_key)?;
    let suitable = all_candidates
        .into_iter()
        .filter(|candidate| {
            candidate.location == location
                && candidate.writer == signing_key.verifying_key()
                && candidate
                    .read_proof
                    .verify_claim(
                        authority,
                        instant,
                        CapabilityClaim::new(
                            signing_key.verifying_key(),
                            read_atom(collection),
                            CapabilityMode::InvokeAndDelegate,
                        ),
                    )
                    .is_ok_and(|verified| verified.effective_validity().is_none())
        })
        .collect::<Vec<_>>();

    let existing = vault_collection(
        &mut *store,
        vault,
        namespace,
        signing_key.clone(),
        admission.clone(),
    )
    .materialize()
    .context("inspect exact vault before creation")?;
    if !existing.is_empty() {
        let reader = store.reader().context("open existing vault attachments")?;
        let catalog = validate_catalog(&reader, vault, &existing)
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
    vault_collection(
        &mut *store,
        vault,
        namespace,
        signing_key.clone(),
        admission,
    )
    .commit(header)
    .context("publish capability-anchored vault genesis")?;
    Ok(location)
}

fn checked_vault<'a, R>(
    snapshot: &'a SecretsSnapshot<R>,
    location: &VaultLocation,
) -> Result<&'a VaultCatalog> {
    let access = snapshot
        .access_exact(location.collection)
        .ok_or_else(|| anyhow!("vault {} has no verified local access", location.vault))?;
    if access.collection() != location.collection || access.trust_root() != location.authority {
        bail!("vault location disagrees with its verified access evidence");
    }
    snapshot
        .vault_exact(location.collection)
        .map(|vault| vault.catalog())
        .ok_or_else(|| anyhow!("vault {} is not ready in this snapshot", location.vault))
}

fn validate_prospective_union(vault: Id, current: &TribleSet, candidate: &Fragment) -> Result<()> {
    let mut prospective = current.clone();
    prospective += candidate.facts().clone();
    load_catalog(vault, &prospective).context("validate prospective vault union")?;
    Ok(())
}

/// Seal one immutable secret to the vault's single custody key and publish it
/// under the exact WRITE presentations carried by the local access envelope.
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
    let access = snapshot
        .access_exact(location.collection)
        .expect("checked_vault requires access");
    let custody = catalog
        .custody
        .context("capability-native vault has no custody declaration")?;
    let sealed = seal_version(name, plaintext, custody.public_key, created_at)?;
    let current = snapshot
        .vault_exact(location.collection)
        .expect("checked vault above")
        .facts();
    validate_prospective_union(location.vault, current, &sealed.fragment)?;
    let secret = sealed.secret;
    vault_collection(
        &mut *store,
        location.vault,
        location.namespace,
        signing_key.clone(),
        access.admission(),
    )
    .commit(sealed.fragment)
    .context("publish encrypted secret version")?;
    Ok(secret)
}

fn delegating_read_proof(
    access: &VaultAccess,
    issuer: &SigningKey,
    recipient: VerifyingKey,
    instant: Epoch,
) -> Result<CapabilityProof> {
    if issuer.verifying_key() != access.subject() {
        bail!("vault READ delegation requires the access-envelope subject key");
    }
    let atom = read_atom(access.collection());
    for parent in access.read_proofs() {
        if !proof_allows(
            parent,
            access.trust_root(),
            issuer.verifying_key(),
            atom,
            CapabilityMode::InvokeAndDelegate,
            instant,
        ) {
            continue;
        }
        let parent_credential = parent
            .credential()
            .expect("a verified nonempty proof has a leaf credential");
        let child = CapabilityProofStep::issue(
            issuer,
            CapabilityGrant::delegated(
                parent_credential,
                recipient,
                atom,
                CapabilityMode::Invoke,
                None,
            ),
        );
        let mut steps = parent.steps().to_vec();
        steps.push(child);
        let child = CapabilityProof::new(steps);
        child
            .verify_claim(
                access.trust_root(),
                instant,
                CapabilityClaim::new(recipient, atom, CapabilityMode::Invoke),
            )
            .context("verify newly delegated READ proof")?;
        return Ok(child);
    }
    bail!("no supplied READ proof permits delegation for this vault")
}

/// Deliver one exact child READ capability and the same vault custody seed to
/// a recipient's deterministic access inbox.
///
/// One access envelope is emitted for every distinct WRITE presentation needed
/// to reconstruct the current multi-writer collection.  They are committed as
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
        .access_exact(location.collection)
        .expect("checked_vault requires access");
    let instant = triblespace::core::clock::epoch_now();
    let child_read = delegating_read_proof(access, signing_key, recipient, instant)?;
    let mut envelope_ids = Vec::new();
    let mut envelopes = Fragment::empty();
    let mut seen = BTreeSet::new();
    for writer in access.write_presentations() {
        let credential = writer
            .proof()
            .credential()
            .context("vault WRITE presentation has no leaf credential")?;
        if !seen.insert((writer.subject().to_bytes(), credential.raw)) {
            continue;
        }
        let envelope = build_access_envelope(
            location.collection,
            access.custody(),
            recipient,
            &child_read,
            writer.subject(),
            writer.proof(),
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
    }
    if envelope_ids.is_empty() {
        bail!("vault access has no distinct WRITE presentation");
    }
    retain_descriptor(&mut envelopes, *location)?;
    access_inbox_collection(&mut *store, recipient, signing_key.clone())
        .commit(envelopes)
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
        let parent = founder_write.credential().unwrap();
        let mut writer_steps = founder_write.steps().to_vec();
        writer_steps.push(CapabilityProofStep::issue(
            &founder,
            CapabilityGrant::delegated(
                parent,
                writer.verifying_key(),
                write_atom,
                CapabilityMode::Invoke,
                None,
            ),
        ));
        let writer_write = CapabilityProof::new(writer_steps);
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
        vault_collection(
            &mut pile,
            location.vault(),
            location.namespace(),
            writer.clone(),
            CollectionAdmission::capability(
                location.authority(),
                vec![CapabilityPresentation::new(
                    writer.verifying_key(),
                    writer_write,
                )],
            ),
        )
        .commit(sealed.fragment)
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
        let location = VaultLocation::new(vault, founder.verifying_key(), founder.verifying_key());
        let stale_custody = key(10);
        let mut pile = files.open();
        let instant = triblespace::core::clock::epoch_now();
        let validity = CapabilityValidity::new(
            instant - hifitime::Duration::from_seconds(1.0),
            instant + hifitime::Duration::from_seconds(3600.0),
        )
        .unwrap();
        let bounded_read = CapabilityProof::new(vec![CapabilityProofStep::issue(
            &founder,
            CapabilityGrant::root(
                founder.verifying_key(),
                read_atom(location.collection()),
                CapabilityMode::InvokeAndDelegate,
                Some(validity),
            ),
        )]);
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

        let commits = access_inbox_collection(&mut pile, founder.verifying_key(), founder.clone())
            .ticket()
            .unwrap();
        assert_eq!(commits.len(), 1);
        let reader = pile.reader().unwrap();
        let data: Blob<SimpleArchive> = reader
            .get(Handle::<SimpleArchive>::from_hash(commits[0].data()))
            .unwrap();
        let copied_facts = TribleSet::try_from_blob(data).unwrap();
        drop(reader);

        access_inbox_collection(&mut pile, founder.verifying_key(), attacker.clone())
            .commit(Fragment::new(std::iter::empty(), copied_facts))
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
        let location = VaultLocation::new(id(13), founder.verifying_key(), founder.verifying_key());
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
        retain_descriptor(&mut delivery, location).unwrap();

        let mut pile = files.open();
        access_inbox_collection(&mut pile, founder.verifying_key(), founder.clone())
            .commit(delivery)
            .unwrap();
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
