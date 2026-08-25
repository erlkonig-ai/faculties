//! One-time bridge from the unpublished subject-bearing Secrets envelope to
//! the direct capability-proof generation.
//!
//! The retired proof signatures are deliberately not interpreted here. The
//! migration's authority is narrower and explicit: the durable root key must
//! have signed the old delivery COMMIT into its own deterministic private
//! inbox, the closed old row and sealed frame must agree byte-for-byte, and
//! the recovered custody key must match the already-materialized root/root
//! vault. Possession of that external root key then authorizes issuing fresh
//! direct root proofs for the same vault and custody epoch.
//!
//! Runtime keeps no compatibility parser. The old and new envelope tags are
//! distinct, so retired rows remain inert after this additive bridge.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use dryoc::classic::crypto_sign_ed25519::{
    crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519,
};
use dryoc::dryocbox::{DryocBox, KeyPair as BoxKeyPair};
use dryoc::types::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hifitime::Epoch;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::{Blob, TryFromBlob};
use triblespace::core::capability::CapabilityProofBundle;
use triblespace::core::collection::{
    descriptor, CapabilityPresentation, CollectionAdmission, CollectionHandle,
};
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{BlobStoreGet, CapabilityProofStore};
use triblespace::prelude::*;
use zeroize::Zeroizing;

use faculties::secrets::access::build_access_envelope;
use faculties::secrets::storage::{
    access_inbox_collection, discover_access_candidates, discover_staged_access_candidates,
    founder_proofs, persist_proof_bundle, ValidatedAccessCandidate, VaultLocation,
};
use faculties::{secrets, storage::open_pile_strict};

/// Tag of the unpublished subject-bearing credential envelope generation.
pub const RETIRED_KIND_ACCESS_ENVELOPE: Id =
    triblespace::macros::id_hex!("CFBD2DA0773F23E0C27E9CE23887AB4D");

/// Sealed-frame marker of the unpublished subject-bearing generation.
pub const RETIRED_ACCESS_ENVELOPE_FORMAT_V1: Id =
    triblespace::macros::id_hex!("B4A31C5D175AD83A341C3BABBB1138A7");

// These are literal pins of already-written, unpublished bytes. The three
// shared fields retain the same encoding in the direct generation; the two
// credential fields exist only inside this migration module.
attributes! {
    "176DF52B59F579E74CBD960B5EFDC2A7" unsafe as retired_custody_public_key:
        inlineencodings::ED25519PublicKey;
    "106941F1D8DC9C744373F22ED6E74675" unsafe as retired_access_vault:
        inlineencodings::Handle<blobencodings::SimpleArchive>;
    "F99B956013F819583DEE21894E786EF6" unsafe as retired_access_read_credential:
        inlineencodings::Handle<blobencodings::SimpleArchive>;
    "DB5C707B5D3F67A12F5053955B62F6BB" unsafe as retired_access_write_credential:
        inlineencodings::Handle<blobencodings::SimpleArchive>;
    "9ABBB200A36063069AA2A29424A4575E" unsafe as retired_access_sealed_seed:
        inlineencodings::Handle<blobencodings::RawBytes>;
}

type CredentialHandle = Inline<inlineencodings::Handle<blobencodings::SimpleArchive>>;
type BytesHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;

const FRAME_WORD_BYTES: usize = 32;
const FRAME_WORDS: usize = 6;
const RETIRED_FRAME_BYTES: usize = 16 + FRAME_WORDS * FRAME_WORD_BYTES;
const SEALED_BOX_OVERHEAD_BYTES: usize = 48;
const RETIRED_SEALED_FRAME_BYTES: usize = RETIRED_FRAME_BYTES + SEALED_BOX_OVERHEAD_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetiredEnvelopeRow {
    id: Id,
    custody_public_key: VerifyingKey,
    vault: CollectionHandle,
    read_credential: CredentialHandle,
    write_credential: CredentialHandle,
    sealed_seed: BytesHandle,
}

#[derive(Clone)]
struct RetiredAccess {
    row: RetiredEnvelopeRow,
    location: VaultLocation,
    custody: SigningKey,
}

/// Exact disposition of one predecessor or malformed candidate observed by a
/// read-only plan.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DirectProofState {
    Pending,
    Complete,
    Ambiguous,
    Malformed,
}

impl DirectProofState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Complete => "complete",
            Self::Ambiguous => "ambiguous",
            Self::Malformed => "malformed",
        }
    }
}

/// Human-readable, non-authoritative report row. Activation uses the private
/// validated candidates retained by [`SecretsDirectProofPlan`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultDirectProofReport {
    pub vault: Option<Id>,
    pub predecessor: Option<Id>,
    pub state: DirectProofState,
    pub secret_versions: Option<usize>,
    pub detail: String,
}

#[derive(Clone)]
struct PendingSuccessor {
    location: VaultLocation,
    read_bundle: CapabilityProofBundle,
    write_bundle: CapabilityProofBundle,
    envelope: Fragment,
}

/// Complete read-only preflight over one known pile prefix.
#[derive(Clone)]
pub struct SecretsDirectProofPlan {
    root: VerifyingKey,
    reports: Vec<VaultDirectProofReport>,
    pending: Vec<PendingSuccessor>,
    pending_proofs: usize,
}

impl SecretsDirectProofPlan {
    pub fn reports(&self) -> &[VaultDirectProofReport] {
        &self.reports
    }

    pub fn count(&self, state: DirectProofState) -> usize {
        self.reports
            .iter()
            .filter(|report| report.state == state)
            .count()
    }

    pub fn pending_vaults(&self) -> usize {
        self.pending.len()
    }

    /// Exact number of deterministic successor proof records not yet resident
    /// in the planned pile prefix. A proof-only crash prefix therefore reports
    /// zero here while its unpublished inbox COMMIT remains pending.
    pub fn pending_proofs(&self) -> usize {
        self.pending_proofs
    }

    pub fn is_blocked(&self) -> bool {
        self.reports.iter().any(|report| {
            matches!(
                report.state,
                DirectProofState::Ambiguous | DirectProofState::Malformed
            )
        })
    }

    fn ensure_activatable(&self) -> Result<()> {
        let blockers = self
            .reports
            .iter()
            .filter(|report| {
                matches!(
                    report.state,
                    DirectProofState::Ambiguous | DirectProofState::Malformed
                )
            })
            .map(|report| {
                let subject = report
                    .vault
                    .map(|vault| format!("vault {vault:X}"))
                    .or_else(|| {
                        report
                            .predecessor
                            .map(|candidate| format!("candidate {candidate:X}"))
                    })
                    .unwrap_or_else(|| "unidentified candidate".to_owned());
                format!("{} {}: {}", report.state.label(), subject, report.detail)
            })
            .collect::<Vec<_>>();
        if !blockers.is_empty() {
            bail!(
                "Secrets direct-proof migration is blocked: {}",
                blockers.join("; ")
            );
        }
        if self.pending.len() != self.count(DirectProofState::Pending) {
            bail!("Secrets direct-proof plan lost an exact pending candidate");
        }
        Ok(())
    }
}

/// Result of idempotently ensuring every direct-proof successor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdditiveActivationOutcome {
    Published { inbox_commits: usize },
    AlreadyActive,
}

fn retired_envelope_record(
    custody: VerifyingKey,
    vault: CollectionHandle,
    read_credential: CredentialHandle,
    write_credential: CredentialHandle,
    sealed_seed: BytesHandle,
) -> Fragment {
    let custody = Inline::<inlineencodings::ED25519PublicKey>::new(custody.to_bytes());
    entity! { _ @
        metadata::tag: &RETIRED_KIND_ACCESS_ENVELOPE,
        retired_custody_public_key: custody,
        retired_access_vault: vault,
        retired_access_read_credential: read_credential,
        retired_access_write_credential: write_credential,
        retired_access_sealed_seed: sealed_seed,
    }
}

fn exactly_one<T>(id: Id, field: &str, mut values: Vec<T>) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "retired access envelope {id:X} has {} values for {field}; expected exactly one",
            values.len()
        );
    }
    Ok(values.pop().expect("length checked above"))
}

fn load_retired_envelope(facts: &TribleSet, id: Id) -> Result<RetiredEnvelopeRow> {
    let custody = exactly_one(
        id,
        "custody_public_key",
        find!(
            value: Inline<inlineencodings::ED25519PublicKey>,
            pattern!(facts, [{ id @ retired_custody_public_key: ?value }])
        )
        .collect(),
    )?;
    let row = RetiredEnvelopeRow {
        id,
        custody_public_key: VerifyingKey::from_bytes(&custody.raw)
            .context("retired envelope has an invalid custody Ed25519 key")?,
        vault: exactly_one(
            id,
            "access_vault",
            find!(
                value: CollectionHandle,
                pattern!(facts, [{ id @ retired_access_vault: ?value }])
            )
            .collect(),
        )?,
        read_credential: exactly_one(
            id,
            "access_read_credential",
            find!(
                value: CredentialHandle,
                pattern!(facts, [{ id @ retired_access_read_credential: ?value }])
            )
            .collect(),
        )?,
        write_credential: exactly_one(
            id,
            "access_write_credential",
            find!(
                value: CredentialHandle,
                pattern!(facts, [{ id @ retired_access_write_credential: ?value }])
            )
            .collect(),
        )?,
        sealed_seed: exactly_one(
            id,
            "access_sealed_seed",
            find!(
                value: BytesHandle,
                pattern!(facts, [{ id @ retired_access_sealed_seed: ?value }])
            )
            .collect(),
        )?,
    };
    let canonical = retired_envelope_record(
        row.custody_public_key,
        row.vault,
        row.read_credential,
        row.write_credential,
        row.sealed_seed,
    );
    if canonical.root() != Some(id) || canonical.facts() != facts {
        bail!("retired access envelope {id:X} is not one exact canonical commit-local row");
    }
    Ok(row)
}

fn box_keypair(signing_key: &SigningKey) -> Result<BoxKeyPair> {
    let public = signing_key.verifying_key().to_bytes();
    let secret = Zeroizing::new(signing_key.to_keypair_bytes());
    let mut converted_public = [0u8; 32];
    let mut converted_secret = Zeroizing::new([0u8; 32]);
    crypto_sign_ed25519_pk_to_curve25519(&mut converted_public, &public)
        .map_err(|error| anyhow!("recipient public-key conversion: {error:?}"))?;
    crypto_sign_ed25519_sk_to_curve25519(&mut converted_secret, &secret);
    BoxKeyPair::from_slices(&converted_public, converted_secret.as_slice())
        .map_err(|error| anyhow!("recipient X25519 keypair: {error:?}"))
}

fn take_word(bytes: &[u8], offset: &mut usize) -> [u8; FRAME_WORD_BYTES] {
    let mut word = [0u8; FRAME_WORD_BYTES];
    let end = *offset + FRAME_WORD_BYTES;
    word.copy_from_slice(&bytes[*offset..end]);
    *offset = end;
    word
}

fn open_retired_envelope<R: BlobStoreGet>(
    reader: &R,
    row: &RetiredEnvelopeRow,
    root: &SigningKey,
) -> Result<SigningKey> {
    let sealed: anybytes::Bytes = reader
        .get(row.sealed_seed)
        .context("read retired access-envelope sealed seed")?;
    if sealed.len() != RETIRED_SEALED_FRAME_BYTES {
        bail!(
            "retired sealed access frame has {} bytes; expected {RETIRED_SEALED_FRAME_BYTES}",
            sealed.len()
        );
    }
    let root_box = box_keypair(root)?;
    let plaintext = Zeroizing::new(
        DryocBox::from_sealed_bytes(sealed.as_ref())
            .map_err(|error| anyhow!("parse retired sealed frame: {error:?}"))?
            .unseal_to_vec(&root_box)
            .map_err(|_| anyhow!("unseal retired access frame for durable root failed"))?,
    );
    if plaintext.len() != RETIRED_FRAME_BYTES {
        bail!(
            "retired opened access frame has {} bytes; expected {RETIRED_FRAME_BYTES}",
            plaintext.len()
        );
    }
    let magic = RETIRED_ACCESS_ENVELOPE_FORMAT_V1.raw();
    if plaintext[..magic.len()] != magic {
        bail!("retired opened access frame has an unknown format marker");
    }
    let mut offset = magic.len();
    let bound_vault = Inline::new(take_word(&plaintext, &mut offset));
    let bound_custody = VerifyingKey::from_bytes(&take_word(&plaintext, &mut offset))
        .context("retired frame has an invalid custody public key")?;
    let bound_read = Inline::new(take_word(&plaintext, &mut offset));
    let bound_subject = VerifyingKey::from_bytes(&take_word(&plaintext, &mut offset))
        .context("retired frame has an invalid subject public key")?;
    let bound_write = Inline::new(take_word(&plaintext, &mut offset));
    let custody_seed = Zeroizing::new(take_word(&plaintext, &mut offset));
    debug_assert_eq!(offset, plaintext.len());

    if bound_vault != row.vault {
        bail!("retired frame is bound to a different vault descriptor");
    }
    if bound_custody != row.custody_public_key {
        bail!("retired frame is bound to a different custody key");
    }
    if bound_read != row.read_credential {
        bail!("retired frame is bound to a different READ credential");
    }
    if bound_subject != root.verifying_key() {
        bail!("retired frame is not bound to the durable root recipient");
    }
    if bound_write != row.write_credential {
        bail!("retired frame is bound to a different WRITE credential");
    }
    let custody = SigningKey::from_bytes(&custody_seed);
    if custody.verifying_key() != row.custody_public_key {
        bail!("retired custody seed does not match its declared public key");
    }
    Ok(custody)
}

fn parse_root_vault_descriptor<R: BlobStoreGet>(
    reader: &R,
    handle: CollectionHandle,
    root: VerifyingKey,
) -> Result<VaultLocation> {
    let blob: Blob<SimpleArchive> = reader
        .get(handle)
        .context("read retired envelope vault descriptor")?;
    let facts = TribleSet::try_from_blob(blob).context("decode retired vault descriptor")?;
    let name = descriptor::name(&facts)
        .context("retired vault descriptor has no name")?
        .context("decode retired vault descriptor name")?;
    let vault = secrets::parse_vault_name(&name)
        .context("retired envelope does not name a canonical vault")?;
    let namespace = descriptor::namespace(&facts)
        .context("retired vault descriptor has no namespace")?
        .context("decode retired vault namespace")?;
    let authority = descriptor::authority(&facts)
        .context("retired vault descriptor has no capability authority")?
        .context("decode retired vault authority")?;
    if namespace != root || authority != root {
        bail!("retired vault descriptor is not rooted root/root in the durable signer");
    }
    let location = VaultLocation::new(vault, root, root);
    let expected = secrets::vault_descriptor(vault, root, root).into_facts();
    if location.collection() != handle || facts != expected {
        bail!("retired vault descriptor is not the exact canonical private descriptor");
    }
    Ok(location)
}

fn read_commit_facts<R: BlobStoreGet>(
    reader: &R,
    commit: &triblespace::core::collection::CollectionCommit,
) -> Result<TribleSet> {
    let data: Blob<SimpleArchive> = reader
        .get(Handle::<SimpleArchive>::from_hash(commit.data()))
        .context("read retired access-inbox COMMIT data")?;
    TribleSet::try_from_blob(data).context("decode retired access-inbox COMMIT data")
}

fn malformed(
    predecessor: Option<Id>,
    vault: Option<Id>,
    detail: impl Into<String>,
) -> VaultDirectProofReport {
    VaultDirectProofReport {
        vault,
        predecessor,
        state: DirectProofState::Malformed,
        secret_versions: None,
        detail: detail.into(),
    }
}

fn exact_current_candidate(
    candidate: &ValidatedAccessCandidate,
    old: &RetiredAccess,
    root: VerifyingKey,
    read: &CapabilityProofBundle,
    write: &CapabilityProofBundle,
) -> bool {
    candidate.location() == old.location
        && candidate.publisher() == root
        && candidate.writer() == root
        && candidate.custody().to_bytes() == old.custody.to_bytes()
        && candidate.read_bundle() == read
        && candidate.write_bundle() == write
}

fn stage_successor(
    root: &SigningKey,
    old: &RetiredAccess,
    read_bundle: CapabilityProofBundle,
    write_bundle: CapabilityProofBundle,
) -> Result<PendingSuccessor> {
    let mut envelope = build_access_envelope(
        old.location.collection(),
        &old.custody,
        root.verifying_key(),
        &read_bundle,
        root.verifying_key(),
        &write_bundle,
        root.verifying_key(),
        Epoch::from_tai_seconds(0.0),
    )
    .context("build direct-proof successor envelope")?;
    let retained = envelope.put::<SimpleArchive, _>(
        secrets::vault_descriptor(
            old.location.vault(),
            old.location.namespace(),
            old.location.authority(),
        )
        .into_facts(),
    );
    if retained != old.location.collection() {
        bail!("direct-proof successor retained the wrong vault descriptor");
    }

    let (candidates, issues) = discover_staged_access_candidates(
        std::slice::from_ref(&envelope),
        &[read_bundle.clone(), write_bundle.clone()],
        root,
        root,
    )
    .context("exercise current direct-proof runtime on staged successor")?;
    if !issues.is_empty() {
        let detail = issues
            .iter()
            .map(|issue| format!("{:?}: {}", issue.kind(), issue.detail()))
            .collect::<Vec<_>>()
            .join("; ");
        bail!("staged direct-proof successor was rejected: {detail}");
    }
    if candidates.len() != 1
        || !exact_current_candidate(
            &candidates[0],
            old,
            root.verifying_key(),
            &read_bundle,
            &write_bundle,
        )
    {
        bail!("staged direct-proof successor did not admit one exact root candidate");
    }

    Ok(PendingSuccessor {
        location: old.location,
        read_bundle,
        write_bundle,
        envelope,
    })
}

/// Read one pile prefix without appending anything and classify every retired
/// predecessor as pending, complete, ambiguous, or malformed.
pub fn plan(pile: &mut Pile, root: &SigningKey) -> Result<SecretsDirectProofPlan> {
    let root_key = root.verifying_key();
    let inbox = access_inbox_collection(&mut *pile, root_key, root.clone())
        .snapshot()
        .context("snapshot durable root's deterministic Secrets access inbox")?;
    let mut reports = Vec::new();
    let mut valid = BTreeMap::<CollectionHandle, Vec<RetiredAccess>>::new();

    for commit in inbox.commits() {
        let facts = read_commit_facts(inbox.reader(), commit)?;
        let ids = find!(
            id: Id,
            pattern!(&facts, [{ ?id @ metadata::tag: RETIRED_KIND_ACCESS_ENVELOPE }])
        )
        .collect::<Vec<_>>();
        if ids.is_empty() {
            continue;
        }
        let candidate = (ids.len() == 1).then_some(ids[0]);
        let parsed = (|| {
            if ids.len() != 1 {
                bail!(
                    "retired access-inbox COMMIT contains {} tagged rows; expected exactly one",
                    ids.len()
                );
            }
            if commit.public_key().raw != root_key.to_bytes() {
                bail!("retired access-inbox COMMIT was not published by the durable root");
            }
            let row = load_retired_envelope(&facts, ids[0])?;
            let location = parse_root_vault_descriptor(inbox.reader(), row.vault, root_key)?;
            let custody = open_retired_envelope(inbox.reader(), &row, root)?;
            Ok(RetiredAccess {
                row,
                location,
                custody,
            })
        })();
        match parsed {
            Ok(access) => valid
                .entry(access.location.collection())
                .or_default()
                .push(access),
            Err(error) => reports.push(malformed(candidate, None, format!("{error:#}"))),
        }
    }

    let (current, current_issues) = discover_access_candidates(&mut *pile, root)
        .context("discover current direct-proof candidates")?;
    for issue in current_issues {
        reports.push(malformed(
            issue.candidate(),
            issue.vault(),
            format!(
                "current direct-proof candidate: {:?}: {}",
                issue.kind(),
                issue.detail()
            ),
        ));
    }
    let mut current_by_collection =
        BTreeMap::<CollectionHandle, Vec<ValidatedAccessCandidate>>::new();
    for candidate in current {
        current_by_collection
            .entry(candidate.location().collection())
            .or_default()
            .push(candidate);
    }

    let mut pending = Vec::new();
    let mut pending_proofs = 0;
    for (collection, predecessors) in valid {
        if predecessors.len() != 1 {
            reports.push(VaultDirectProofReport {
                vault: predecessors.first().map(|old| old.location.vault()),
                predecessor: None,
                state: DirectProofState::Ambiguous,
                secret_versions: None,
                detail: format!(
                    "{} distinct canonical retired envelopes name the same exact vault",
                    predecessors.len()
                ),
            });
            continue;
        }
        let old = &predecessors[0];
        let (read_bundle, write_bundle) = founder_proofs(root, old.location);
        let vault_snapshot = match secrets::vault_collection(
            &mut *pile,
            old.location.vault(),
            old.location.namespace(),
            root.clone(),
            CollectionAdmission::capability(
                old.location.authority(),
                vec![CapabilityPresentation::new(root_key, write_bundle.clone())],
            ),
        )
        .snapshot()
        {
            Ok(snapshot) => snapshot,
            Err(error) => {
                reports.push(malformed(
                    Some(old.row.id),
                    Some(old.location.vault()),
                    format!("materialize existing root WRITE vault: {error}"),
                ));
                continue;
            }
        };
        let catalog = match secrets::validate_catalog(
            vault_snapshot.reader(),
            old.location.vault(),
            vault_snapshot.facts(),
        ) {
            Ok(catalog) => catalog,
            Err(error) => {
                reports.push(malformed(
                    Some(old.row.id),
                    Some(old.location.vault()),
                    format!("validate existing vault catalog: {error:#}"),
                ));
                continue;
            }
        };
        let Some(declared_custody) = catalog.custody else {
            reports.push(malformed(
                Some(old.row.id),
                Some(old.location.vault()),
                "existing vault has no custody declaration",
            ));
            continue;
        };
        if declared_custody.public_key != old.custody.verifying_key().to_bytes() {
            reports.push(malformed(
                Some(old.row.id),
                Some(old.location.vault()),
                "retired envelope custody does not match the existing vault header",
            ));
            continue;
        }
        let secret_versions = catalog.secrets.len();

        let successors = current_by_collection
            .remove(&collection)
            .unwrap_or_default();
        match successors.as_slice() {
            [] => match stage_successor(root, old, read_bundle, write_bundle) {
                Ok(successor) => {
                    for bundle in [&successor.read_bundle, &successor.write_bundle] {
                        if pile
                            .proof(bundle.proof().id())
                            .context("look up deterministic successor proof")?
                            .is_none()
                        {
                            pending_proofs += 1;
                        }
                    }
                    pending.push(successor);
                    reports.push(VaultDirectProofReport {
                        vault: Some(old.location.vault()),
                        predecessor: Some(old.row.id),
                        state: DirectProofState::Pending,
                        secret_versions: Some(secret_versions),
                        detail: "one exact direct-proof successor is ready to publish".to_owned(),
                    });
                }
                Err(error) => reports.push(malformed(
                    Some(old.row.id),
                    Some(old.location.vault()),
                    format!("stage direct-proof successor: {error:#}"),
                )),
            },
            [candidate]
                if exact_current_candidate(
                    candidate,
                    old,
                    root_key,
                    &read_bundle,
                    &write_bundle,
                ) =>
            {
                reports.push(VaultDirectProofReport {
                    vault: Some(old.location.vault()),
                    predecessor: Some(old.row.id),
                    state: DirectProofState::Complete,
                    secret_versions: Some(secret_versions),
                    detail: "one exact direct-proof successor is already active".to_owned(),
                });
            }
            [candidate] => reports.push(VaultDirectProofReport {
                vault: Some(old.location.vault()),
                predecessor: Some(old.row.id),
                state: DirectProofState::Ambiguous,
                secret_versions: Some(secret_versions),
                detail: format!(
                    "current successor {} conflicts in root, proof, writer, or custody",
                    candidate.id()
                ),
            }),
            candidates => reports.push(VaultDirectProofReport {
                vault: Some(old.location.vault()),
                predecessor: Some(old.row.id),
                state: DirectProofState::Ambiguous,
                secret_versions: Some(secret_versions),
                detail: format!(
                    "{} current direct-proof candidates name the same exact vault",
                    candidates.len()
                ),
            }),
        }
    }

    reports.sort_by_key(|report| (report.vault, report.predecessor, report.state));
    Ok(SecretsDirectProofPlan {
        root: root_key,
        reports,
        pending,
        pending_proofs,
    })
}

/// Read-only convenience boundary used by `migrations ... plan`.
pub fn plan_path(path: &Path, root: &SigningKey) -> Result<SecretsDirectProofPlan> {
    let mut pile = open_pile_strict(path)?;
    let result = plan(&mut pile, root);
    finish_live_pile(pile, result)
}

/// Additively publish direct proof claims, then native proof records, then one
/// access-inbox COMMIT per pending vault. Replanning repairs every crash prefix
/// and proves that no predecessor remains pending.
pub fn activate(path: &Path, root: &SigningKey) -> Result<AdditiveActivationOutcome> {
    let mut pile = open_pile_strict(path)?;
    let _activation = match DirectProofActivationLock::acquire(&pile) {
        Ok(activation) => activation,
        Err(error) => return finish_live_pile(pile, Err(error)),
    };
    let result = (|| {
        let migration = plan(&mut pile, root)?;
        migration.ensure_activatable()?;
        if migration.root != root.verifying_key() {
            bail!("Secrets direct-proof plan belongs to a different durable root");
        }
        if migration.pending.is_empty() {
            return Ok(AdditiveActivationOutcome::AlreadyActive);
        }
        let published = migration.pending.len();
        for successor in &migration.pending {
            let (expected_read, expected_write) = founder_proofs(root, successor.location);
            if successor.location.namespace() != root.verifying_key()
                || successor.location.authority() != root.verifying_key()
                || successor.read_bundle != expected_read
                || successor.write_bundle != expected_write
            {
                bail!("pending Secrets successor lost its exact root/root proof identity");
            }
            persist_proof_bundle(&mut pile, &successor.read_bundle)
                .context("persist direct READ proof closure")?;
            persist_proof_bundle(&mut pile, &successor.write_bundle)
                .context("persist direct WRITE proof closure")?;
            access_inbox_collection(&mut pile, root.verifying_key(), root.clone())
                .commit(successor.envelope.clone())
                .with_context(|| {
                    format!(
                        "publish direct-proof access successor for vault {:X}",
                        successor.location.vault()
                    )
                })?;
        }

        let final_plan = plan(&mut pile, root).context("replan direct-proof publication")?;
        final_plan.ensure_activatable()?;
        if final_plan.pending_vaults() != 0 {
            bail!(
                "Secrets direct-proof publication left {} pending vault(s)",
                final_plan.pending_vaults()
            );
        }
        Ok(AdditiveActivationOutcome::Published {
            inbox_commits: published,
        })
    })();
    finish_live_pile(pile, result)
}

struct DirectProofActivationLock {
    file: File,
}

impl DirectProofActivationLock {
    fn acquire(pile: &Pile) -> Result<Self> {
        let path = direct_proof_activation_lock_path(pile)?;
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
        }
        let file = options
            .open(&path)
            .with_context(|| format!("open direct-proof activation lock {}", path.display()))?;
        match file.try_lock() {
            Ok(()) => Ok(Self { file }),
            Err(TryLockError::WouldBlock) => bail!(
                "another Secrets direct-proof activation already holds {}",
                path.display()
            ),
            Err(TryLockError::Error(error)) => Err(error)
                .with_context(|| format!("lock direct-proof activation {}", path.display())),
        }
    }
}

#[cfg(unix)]
fn direct_proof_activation_lock_path(pile: &Pile) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    let metadata = pile
        .backing_file_metadata()
        .context("inspect physical pile identity for direct-proof activation")?;
    Ok(PathBuf::from(format!(
        "/tmp/faculties-secrets-direct-proofs-v1-{:016x}-{:016x}.lock",
        metadata.dev(),
        metadata.ino()
    )))
}

#[cfg(not(unix))]
fn direct_proof_activation_lock_path(_pile: &Pile) -> Result<PathBuf> {
    bail!("safe physical-identity direct-proof activation locking is not implemented here")
}

impl Drop for DirectProofActivationLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn finish_live_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;

    use dryoc::dryocbox::PublicKey as BoxPublicKey;
    use hifitime::Epoch;
    use tempfile::TempDir;
    use triblespace::core::collection::{CollectionRecord, CollectionStore};
    use triblespace::core::repo::BlobStore;

    use super::*;

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

    fn box_public_key(public: VerifyingKey) -> BoxPublicKey {
        let mut converted = [0u8; 32];
        crypto_sign_ed25519_pk_to_curve25519(&mut converted, &public.to_bytes()).unwrap();
        BoxPublicKey::try_from(&converted[..]).unwrap()
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RetiredMutation {
        None,
        WrongPublisher,
        WrongRecipient,
        BadFrameMagic,
        WrongDescriptor,
        CustodyMismatch,
        MalformedRow,
    }

    fn retired_frame(
        location: VaultLocation,
        custody: &SigningKey,
        read: CredentialHandle,
        subject: VerifyingKey,
        write: CredentialHandle,
        magic: Id,
    ) -> Zeroizing<Vec<u8>> {
        let seed = Zeroizing::new(custody.to_bytes());
        let mut frame = Zeroizing::new(Vec::with_capacity(RETIRED_FRAME_BYTES));
        frame.extend_from_slice(&magic.raw());
        frame.extend_from_slice(&location.collection().raw);
        frame.extend_from_slice(&custody.verifying_key().to_bytes());
        frame.extend_from_slice(&read.raw);
        frame.extend_from_slice(&subject.to_bytes());
        frame.extend_from_slice(&write.raw);
        frame.extend_from_slice(seed.as_slice());
        assert_eq!(frame.len(), RETIRED_FRAME_BYTES);
        frame
    }

    fn publish_retired_envelope(
        pile: &mut Pile,
        root: &SigningKey,
        location: VaultLocation,
        vault_custody: &SigningKey,
        mutation: RetiredMutation,
        variant: u8,
    ) -> Id {
        let attacker = key(90);
        let row_location = if mutation == RetiredMutation::WrongDescriptor {
            VaultLocation::new(
                location.vault(),
                root.verifying_key(),
                attacker.verifying_key(),
            )
        } else {
            location
        };
        let row_custody = if mutation == RetiredMutation::CustodyMismatch {
            key(91)
        } else {
            vault_custody.clone()
        };
        let subject = if mutation == RetiredMutation::WrongRecipient {
            attacker.verifying_key()
        } else {
            root.verifying_key()
        };
        let magic = if mutation == RetiredMutation::BadFrameMagic {
            id(92)
        } else {
            RETIRED_ACCESS_ENVELOPE_FORMAT_V1
        };

        let mut delivery = Fragment::empty();
        let read_claim = entity! { _ @ metadata::tag: &id(100 + variant) }.into_facts();
        let write_claim = entity! { _ @ metadata::tag: &id(120 + variant) }.into_facts();
        let read = delivery.put::<SimpleArchive, _>(read_claim);
        let write = delivery.put::<SimpleArchive, _>(write_claim);
        let frame = retired_frame(row_location, &row_custody, read, subject, write, magic);
        let sealed = DryocBox::seal_to_vecbox(frame.as_slice(), &box_public_key(subject))
            .unwrap()
            .to_vec();
        assert_eq!(sealed.len(), RETIRED_SEALED_FRAME_BYTES);
        let sealed = delivery.put::<blobencodings::RawBytes, _>(sealed);
        let row = retired_envelope_record(
            row_custody.verifying_key(),
            row_location.collection(),
            read,
            write,
            sealed,
        );
        let row_id = row.root().unwrap();
        delivery += row;
        let retained = delivery.put::<SimpleArchive, _>(
            secrets::vault_descriptor(
                row_location.vault(),
                row_location.namespace(),
                row_location.authority(),
            )
            .into_facts(),
        );
        assert_eq!(retained, row_location.collection());
        if mutation == RetiredMutation::MalformedRow {
            let name = delivery.put("unexpected sibling fact".to_owned());
            delivery += entity! { ExclusiveId::force_ref(&row_id) @ metadata::name: name };
        }
        let publisher = if mutation == RetiredMutation::WrongPublisher {
            attacker
        } else {
            root.clone()
        };
        access_inbox_collection(&mut *pile, root.verifying_key(), publisher)
            .commit(delivery)
            .unwrap();
        row_id
    }

    struct Fixture {
        _directory: TempDir,
        path: PathBuf,
        root: SigningKey,
        custody: SigningKey,
        location: VaultLocation,
        secret: Id,
        vault_facts: TribleSet,
        predecessor: Id,
    }

    impl Fixture {
        fn new(mutation: RetiredMutation) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("self.pile");
            File::create(&path).unwrap();
            let root = key(1);
            let custody = key(2);
            let vault = id(3);
            let location = VaultLocation::new(vault, root.verifying_key(), root.verifying_key());
            let mut payload = secrets::vault_header_fragment(
                vault,
                "fixture",
                at(1),
                custody.verifying_key().to_bytes(),
            )
            .unwrap();
            let sealed = secrets::seal_version(
                "database",
                b"unchanged secret",
                custody.verifying_key().to_bytes(),
                at(2),
            )
            .unwrap();
            let secret = sealed.secret;
            payload += sealed.fragment;
            let vault_facts = payload.facts().clone();

            let mut pile = open_pile_strict(&path).unwrap();
            let (_, write) = founder_proofs(&root, location);
            secrets::vault_collection(
                &mut pile,
                vault,
                root.verifying_key(),
                root.clone(),
                CollectionAdmission::capability(
                    root.verifying_key(),
                    vec![CapabilityPresentation::new(root.verifying_key(), write)],
                ),
            )
            .commit(payload)
            .unwrap();
            let predecessor =
                publish_retired_envelope(&mut pile, &root, location, &custody, mutation, 1);
            pile.close().unwrap();

            Self {
                _directory: directory,
                path,
                root,
                custody,
                location,
                secret,
                vault_facts,
                predecessor,
            }
        }

        fn bytes(&self) -> Vec<u8> {
            fs::read(&self.path).unwrap()
        }
    }

    fn records(pile: &mut Pile) -> Vec<CollectionRecord> {
        pile.records()
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>()
    }

    fn persist_ordered_prefix(
        pile: &mut Pile,
        successor: &PendingSuccessor,
        mut operations: usize,
    ) {
        assert!(operations <= 4);
        for bundle in [&successor.read_bundle, &successor.write_bundle] {
            assert_eq!(bundle.claims().len(), 1);
            let expected = bundle.proof().claim_handles().next().unwrap();
            if operations == 0 {
                return;
            }
            assert_eq!(
                pile.put::<SimpleArchive, _>(bundle.claims()[0].clone())
                    .unwrap(),
                expected
            );
            operations -= 1;
            if operations == 0 {
                return;
            }
            pile.insert_proof(bundle.proof().clone()).unwrap();
            operations -= 1;
        }
        assert_eq!(operations, 0);
    }

    #[test]
    fn retired_and_current_wire_ids_and_frame_shape_are_pinned() {
        assert_eq!(
            format!("{RETIRED_KIND_ACCESS_ENVELOPE:X}"),
            "CFBD2DA0773F23E0C27E9CE23887AB4D"
        );
        assert_eq!(
            format!("{:X}", secrets::schema::KIND_ACCESS_ENVELOPE),
            "3BF25F54D4B6B0947ED2CE830C0114D2"
        );
        assert_eq!(
            format!("{RETIRED_ACCESS_ENVELOPE_FORMAT_V1:X}"),
            "B4A31C5D175AD83A341C3BABBB1138A7"
        );
        assert_eq!(
            format!("{:X}", retired_custody_public_key.id()),
            "176DF52B59F579E74CBD960B5EFDC2A7"
        );
        assert_eq!(
            format!("{:X}", retired_access_vault.id()),
            "106941F1D8DC9C744373F22ED6E74675"
        );
        assert_eq!(
            format!("{:X}", retired_access_read_credential.id()),
            "F99B956013F819583DEE21894E786EF6"
        );
        assert_eq!(
            format!("{:X}", retired_access_write_credential.id()),
            "DB5C707B5D3F67A12F5053955B62F6BB"
        );
        assert_eq!(
            format!("{:X}", retired_access_sealed_seed.id()),
            "9ABBB200A36063069AA2A29424A4575E"
        );
        assert_eq!(RETIRED_FRAME_BYTES, 16 + 6 * 32);
        assert_eq!(RETIRED_SEALED_FRAME_BYTES, RETIRED_FRAME_BYTES + 48);
    }

    #[test]
    fn live_format_predecessor_plans_activates_and_replays_without_touching_vault() {
        let fixture = Fixture::new(RetiredMutation::None);
        let original = fixture.bytes();

        let mut pile = open_pile_strict(&fixture.path).unwrap();
        let invisible = secrets::storage::discover_local_vaults(&mut pile, &fixture.root).unwrap();
        assert!(invisible.snapshot().vaults().is_empty());
        assert!(invisible.issues().is_empty());
        drop(invisible);
        let records_before = records(&mut pile);
        assert_eq!(pile.proofs().unwrap().count(), 0);
        pile.close().unwrap();

        let migration = plan_path(&fixture.path, &fixture.root).unwrap();
        assert_eq!(fixture.bytes(), original, "plan must be byte-read-only");
        assert_eq!(migration.count(DirectProofState::Pending), 1);
        assert_eq!(migration.count(DirectProofState::Complete), 0);
        assert_eq!(migration.pending_proofs(), 2);
        assert!(!migration.is_blocked());
        assert_eq!(
            migration.reports()[0].predecessor,
            Some(fixture.predecessor)
        );
        let expected_proof_ids = BTreeSet::from([
            migration.pending[0].read_bundle.proof().id(),
            migration.pending[0].write_bundle.proof().id(),
        ]);
        let expected_claims = migration.pending[0]
            .read_bundle
            .proof()
            .claim_handles()
            .chain(migration.pending[0].write_bundle.proof().claim_handles())
            .collect::<BTreeSet<_>>();
        assert_eq!(expected_proof_ids.len(), 2);
        assert_eq!(expected_claims.len(), 2);

        assert_eq!(
            activate(&fixture.path, &fixture.root).unwrap(),
            AdditiveActivationOutcome::Published { inbox_commits: 1 }
        );
        let activated = fixture.bytes();
        assert!(activated.starts_with(&original));

        let mut pile = open_pile_strict(&fixture.path).unwrap();
        let records_after = records(&mut pile);
        assert_eq!(records_after.len(), records_before.len() + 1);
        let vault_commits_before = records_before
            .iter()
            .filter(|record| {
                matches!(record, CollectionRecord::Commit(commit) if commit.collection() == fixture.location.collection())
            })
            .count();
        let vault_commits_after = records_after
            .iter()
            .filter(|record| {
                matches!(record, CollectionRecord::Commit(commit) if commit.collection() == fixture.location.collection())
            })
            .count();
        assert_eq!(vault_commits_before, vault_commits_after);
        let proofs = pile
            .proofs()
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        assert_eq!(proofs.len(), 2);
        assert_eq!(
            proofs
                .iter()
                .map(|proof| proof.id())
                .collect::<BTreeSet<_>>(),
            expected_proof_ids
        );
        let reader = pile.reader().unwrap();
        for claim in expected_claims {
            let _: Blob<SimpleArchive> = reader.get(claim).unwrap();
        }
        drop(reader);

        let discovery = secrets::storage::discover_local_vaults(&mut pile, &fixture.root).unwrap();
        assert!(discovery.issues().is_empty());
        let vault = discovery
            .snapshot()
            .vault_exact(fixture.location.collection())
            .unwrap();
        assert_eq!(vault.facts(), &fixture.vault_facts);
        assert_eq!(
            vault.catalog().custody.unwrap().public_key,
            fixture.custody.verifying_key().to_bytes()
        );
        assert_eq!(vault.catalog().secrets.len(), 1);
        assert_eq!(vault.catalog().wraps.len(), 1);
        assert_eq!(
            discovery
                .snapshot()
                .open_exact(fixture.location.collection(), fixture.secret, &fixture.root)
                .unwrap(),
            b"unchanged secret"
        );
        drop(discovery);
        pile.close().unwrap();

        assert_eq!(
            activate(&fixture.path, &fixture.root).unwrap(),
            AdditiveActivationOutcome::AlreadyActive
        );
        assert_eq!(
            fixture.bytes(),
            activated,
            "exact replay must append nothing"
        );
        let complete = plan_path(&fixture.path, &fixture.root).unwrap();
        assert_eq!(complete.count(DirectProofState::Complete), 1);
        assert_eq!(complete.pending_vaults(), 0);
    }

    #[test]
    fn every_ordered_claim_and_proof_crash_prefix_repairs_exactly_once() {
        for prefix in 0..=4 {
            let fixture = Fixture::new(RetiredMutation::None);
            let migration = plan_path(&fixture.path, &fixture.root).unwrap();
            let pending = migration.pending[0].clone();
            let mut pile = open_pile_strict(&fixture.path).unwrap();
            persist_ordered_prefix(&mut pile, &pending, prefix);
            pile.close().unwrap();
            let prefix_bytes = fixture.bytes();

            let still_pending = plan_path(&fixture.path, &fixture.root).unwrap();
            assert_eq!(still_pending.pending_vaults(), 1, "prefix {prefix}");
            let resident_proofs = usize::from(prefix >= 2) + usize::from(prefix >= 4);
            assert_eq!(
                still_pending.pending_proofs(),
                2 - resident_proofs,
                "prefix {prefix}"
            );
            assert_eq!(fixture.bytes(), prefix_bytes, "prefix {prefix}");
            assert_eq!(
                activate(&fixture.path, &fixture.root).unwrap(),
                AdditiveActivationOutcome::Published { inbox_commits: 1 },
                "prefix {prefix}"
            );
            let activated = fixture.bytes();
            let complete = plan_path(&fixture.path, &fixture.root).unwrap();
            assert_eq!(complete.count(DirectProofState::Complete), 1);
            assert_eq!(complete.pending_vaults(), 0);
            assert_eq!(
                activate(&fixture.path, &fixture.root).unwrap(),
                AdditiveActivationOutcome::AlreadyActive
            );
            assert_eq!(fixture.bytes(), activated, "prefix {prefix}");
        }
    }

    #[test]
    fn interrupted_two_vault_publication_repairs_only_the_missing_commit() {
        let fixture = Fixture::new(RetiredMutation::None);
        let second_location = VaultLocation::new(
            id(31),
            fixture.root.verifying_key(),
            fixture.root.verifying_key(),
        );
        let second_custody = key(32);
        let mut pile = open_pile_strict(&fixture.path).unwrap();
        let (_, second_write) = founder_proofs(&fixture.root, second_location);
        secrets::vault_collection(
            &mut pile,
            second_location.vault(),
            second_location.namespace(),
            fixture.root.clone(),
            CollectionAdmission::capability(
                second_location.authority(),
                vec![CapabilityPresentation::new(
                    fixture.root.verifying_key(),
                    second_write,
                )],
            ),
        )
        .commit(
            secrets::vault_header_fragment(
                second_location.vault(),
                "second fixture",
                at(3),
                second_custody.verifying_key().to_bytes(),
            )
            .unwrap(),
        )
        .unwrap();
        publish_retired_envelope(
            &mut pile,
            &fixture.root,
            second_location,
            &second_custody,
            RetiredMutation::None,
            2,
        );
        pile.close().unwrap();

        let migration = plan_path(&fixture.path, &fixture.root).unwrap();
        assert_eq!(migration.pending_vaults(), 2);
        assert_eq!(migration.pending_proofs(), 4);
        let first = migration.pending[0].clone();
        let second = migration.pending[1].clone();
        let mut pile = open_pile_strict(&fixture.path).unwrap();
        persist_ordered_prefix(&mut pile, &first, 4);
        access_inbox_collection(
            &mut pile,
            fixture.root.verifying_key(),
            fixture.root.clone(),
        )
        .commit(first.envelope)
        .unwrap();
        persist_ordered_prefix(&mut pile, &second, 2);
        pile.close().unwrap();

        let interrupted = plan_path(&fixture.path, &fixture.root).unwrap();
        assert_eq!(interrupted.count(DirectProofState::Complete), 1);
        assert_eq!(interrupted.pending_vaults(), 1);
        assert_eq!(interrupted.pending_proofs(), 1);
        assert_eq!(
            activate(&fixture.path, &fixture.root).unwrap(),
            AdditiveActivationOutcome::Published { inbox_commits: 1 }
        );
        let complete = plan_path(&fixture.path, &fixture.root).unwrap();
        assert_eq!(complete.count(DirectProofState::Complete), 2);
        assert_eq!(complete.pending_vaults(), 0);
    }

    #[test]
    fn wrong_publisher_recipient_frame_descriptor_custody_and_row_fail_before_write() {
        for (mutation, needle) in [
            (RetiredMutation::WrongPublisher, "not published by"),
            (RetiredMutation::WrongRecipient, "unseal retired"),
            (RetiredMutation::BadFrameMagic, "unknown format marker"),
            (RetiredMutation::WrongDescriptor, "rooted root/root"),
            (
                RetiredMutation::CustodyMismatch,
                "does not match the existing vault",
            ),
            (RetiredMutation::MalformedRow, "not one exact canonical"),
        ] {
            let fixture = Fixture::new(mutation);
            let before = fixture.bytes();
            let migration = plan_path(&fixture.path, &fixture.root).unwrap();
            assert!(migration.is_blocked(), "{mutation:?}");
            assert!(
                migration
                    .reports()
                    .iter()
                    .any(|report| report.state == DirectProofState::Malformed
                        && report.detail.contains(needle)),
                "{mutation:?}: {:?}",
                migration.reports()
            );
            assert_eq!(fixture.bytes(), before, "plan wrote for {mutation:?}");
            let error = activate(&fixture.path, &fixture.root).unwrap_err();
            assert!(format!("{error:#}").contains("blocked"));
            assert_eq!(fixture.bytes(), before, "activation wrote for {mutation:?}");
        }
    }

    #[test]
    fn multiple_predecessors_and_conflicting_successor_are_ambiguous_and_inert() {
        let duplicate = Fixture::new(RetiredMutation::None);
        let mut pile = open_pile_strict(&duplicate.path).unwrap();
        publish_retired_envelope(
            &mut pile,
            &duplicate.root,
            duplicate.location,
            &duplicate.custody,
            RetiredMutation::None,
            2,
        );
        pile.close().unwrap();
        let before = duplicate.bytes();
        let migration = plan_path(&duplicate.path, &duplicate.root).unwrap();
        assert_eq!(migration.count(DirectProofState::Ambiguous), 1);
        assert!(activate(&duplicate.path, &duplicate.root).is_err());
        assert_eq!(duplicate.bytes(), before);

        let conflict = Fixture::new(RetiredMutation::None);
        let wrong_custody = key(77);
        let (read, write) = founder_proofs(&conflict.root, conflict.location);
        let mut pile = open_pile_strict(&conflict.path).unwrap();
        secrets::storage::publish_access_envelope(
            &mut pile,
            &conflict.root,
            conflict.location,
            &wrong_custody,
            conflict.root.verifying_key(),
            &read,
            conflict.root.verifying_key(),
            &write,
            Epoch::from_tai_seconds(0.0),
        )
        .unwrap();
        pile.close().unwrap();
        let before = conflict.bytes();
        let migration = plan_path(&conflict.path, &conflict.root).unwrap();
        assert_eq!(migration.count(DirectProofState::Ambiguous), 1);
        assert!(migration.reports().iter().any(|report| report
            .detail
            .contains("conflicts in root, proof, writer, or custody")));
        assert!(activate(&conflict.path, &conflict.root).is_err());
        assert_eq!(conflict.bytes(), before);
    }

    #[cfg(unix)]
    #[test]
    fn activation_lock_tracks_physical_pile_identity() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("self.pile");
        let alias = directory.path().join("alias.pile");
        File::create(&original).unwrap();
        fs::hard_link(&original, &alias).unwrap();
        let first_pile = open_pile_strict(&original).unwrap();
        let second_pile = open_pile_strict(&alias).unwrap();
        let first = DirectProofActivationLock::acquire(&first_pile).unwrap();
        assert!(DirectProofActivationLock::acquire(&second_pile).is_err());
        drop(first);
        DirectProofActivationLock::acquire(&second_pile).unwrap();
        first_pile.close().unwrap();
        second_pile.close().unwrap();
    }
}
