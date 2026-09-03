//! Additive cutover from vault custody to direct Secrets reader envelopes.
//!
//! The runtime no longer interprets vault headers, custody declarations,
//! access inboxes, or the consumer-local legacy READ action. This migration is
//! their only reader. Operators name every legacy vault source explicitly and
//! choose one current Secrets target policy boundary. The default target is
//! the ordinary `secrets` collection selected by
//! `TRIBLESPACE_COLLECTION_SECRETS` or by the durable signer's private
//! descriptor.
//!
//! Planning freezes one pile snapshot and performs every semantic and
//! cryptographic check before publication. It copies the admitted legacy fact
//! union without changing any entity id or value handle, translates every
//! structurally valid legacy reader-proof prefix to the target's exact core
//! `READ(collection)` atom, and builds only the direct DEK wraps missing for
//! the target audience at that instant. Old facts and records remain in place
//! and become inert when callers cut over to the target collection.
//!
//! This is a quiesced, locally complete cutover. Every source must use the
//! legacy direct policy rooted at the supplied durable signer, that signer's
//! access envelope must recover custody for every source carrying secrets, and
//! every envelope/proof/blob to preserve must already be resident. Translating
//! a target READ quorum wider than one root requires those additional root
//! signers and is therefore refused by this one-key command.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

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
use triblespace::core::capability::{
    CapabilityAction, CapabilityAtom, CapabilityClaim, CapabilityMode, CapabilityProofBundle,
    CapabilityProofId, CapabilityResource, CapabilityValidity,
};
use triblespace::core::collection::simplearchive_union;
use triblespace::core::collection::{
    collection_read_audience_by_policy_at, Collection, CollectionHandle, CollectionPolicy,
    CollectionRead, CollectionReadAudience, CollectionRecord, CollectionStore, CollectionStoreExt,
    PreparedCollectionCommit, ACTION_READ, ACTION_WRITE,
};
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::Inline;
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::memoryrepo::MemoryRepo;
use triblespace::core::repo::pile::{GetBlobError, Pile, PileSnapshot};
use triblespace::core::repo::{
    BlobStoreGet, BlobStorePut, CapabilityProofRead, CapabilityProofStore, SnapshotSource,
};
use triblespace::core::trible::{Fragment, TribleSet};
use triblespace::macros::{attributes, find, pattern};
use zeroize::Zeroizing;

use faculties::secrets::{
    add_recipient_envelopes_for_target, open_version_from_facts, recipient_wraps, secret_rows,
};
use faculties::storage::{load_signer, open_pile_strict};

mod legacy {
    use super::*;
    use triblespace::prelude::{blobencodings, inlineencodings};

    /// Consumer-local action formerly meaning permission to decrypt one vault.
    pub const ACTION_READ: Id = triblespace::macros::id_hex!("A6378B816786E9F08A579B8E5F8F4FF4");
    /// Direct-proof access-envelope kind retired by the direct-wrap model.
    pub const KIND_ACCESS_ENVELOPE: Id =
        triblespace::macros::id_hex!("3BF25F54D4B6B0947ED2CE830C0114D2");
    /// Vault custody declaration retired by the direct-wrap model.
    pub const KIND_VAULT_CUSTODY: Id =
        triblespace::macros::id_hex!("7DD14F755D8038BBC8F32242BEBD6031");
    /// Marker at the start of the retired sealed custody frame.
    pub const ACCESS_ENVELOPE_FORMAT_V1: Id =
        triblespace::macros::id_hex!("0444B547B64A83CB156D3CAA917DAB89");

    // These are the original minted anchors and unchanged encodings of facts
    // already present in deployed piles. They stay local to this migration;
    // ordinary Secrets code has no compatibility vocabulary.
    attributes! {
        "DA8C5893DEA1F00964C07F38B2B34D86" as pub custody_public_key:
            inlineencodings::ED25519PublicKey;
        "2C36A12555B4DFB50D4755F4E3029706" as pub access_vault:
            inlineencodings::Handle<blobencodings::SimpleArchive>;
        "2E952183B637CFE37BBE6DFF2DA2CB10" as pub access_read_proof:
            inlineencodings::Hash<inlineencodings::Blake3>;
        "AC8C48C8C73CCF16028C539CCAF8962D" as pub access_write_proof:
            inlineencodings::Hash<inlineencodings::Blake3>;
        "693B927F0A8EFC1389B5E5DF6A9ED790" as pub access_sealed_seed:
            inlineencodings::Handle<blobencodings::RawBytes>;
    }
}

const ACCESS_INBOX_NAME: &str = "secrets-access";
const FRAME_WORD_BYTES: usize = 32;
const FRAME_WORDS: usize = 6;
const FRAME_BYTES: usize = 16 + FRAME_WORDS * FRAME_WORD_BYTES;
const SEALED_BOX_OVERHEAD_BYTES: usize = 48;
const SEALED_FRAME_BYTES: usize = FRAME_BYTES + SEALED_BOX_OVERHEAD_BYTES;

type BytesHandle = Inline<
    triblespace::core::inline::encodings::hash::Handle<
        triblespace::core::blob::encodings::rawbytes::RawBytes,
    >,
>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LegacyEnvelopeRow {
    id: Id,
    custody_public_key: VerifyingKey,
    vault: CollectionHandle,
    read_proof: CapabilityProofId,
    write_proof: CapabilityProofId,
    sealed_seed: BytesHandle,
}

#[derive(Clone, Copy)]
struct SignedLegacyEnvelope {
    inbox: CollectionHandle,
    publisher: VerifyingKey,
    row: LegacyEnvelopeRow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LegacyPrefix {
    subject: VerifyingKey,
    mode: CapabilityMode,
    validity: Option<CapabilityValidity>,
}

#[derive(Clone)]
struct ValidatedLegacyEnvelope {
    row: LegacyEnvelopeRow,
    subject: VerifyingKey,
    prefixes: Vec<LegacyPrefix>,
}

/// Read-only summary of one fully preflighted cutover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretsReaderEnvelopesPlan {
    /// Exact legacy source descriptors supplied by the operator.
    pub sources: Vec<CollectionHandle>,
    /// Exact current Secrets destination descriptor.
    pub target: CollectionHandle,
    /// Facts visible in the admitted legacy source union.
    pub source_facts: usize,
    /// Source facts not yet visible in the target.
    pub copied_facts: usize,
    /// Distinct complete secret-version ids in source plus target.
    pub secret_versions: usize,
    /// Fully validated legacy access-envelope interpretations.
    pub legacy_access_envelopes: usize,
    /// Distinct reader-proof prefixes translated to the core READ atom.
    pub translated_prefixes: usize,
    /// Complete translated proof closures not yet resident.
    pub missing_proof_closures: usize,
    /// Readers admitted by the target at the frozen migration instant.
    pub current_readers: usize,
    /// Locally recovered legacy custody keypairs.
    pub recovered_custodies: usize,
    /// Complete legacy candidate interpretations skipped as invalid.
    pub skipped_legacy_candidates: usize,
    /// Missing direct recipient wraps prepared for the target.
    pub missing_recipient_wraps: usize,
    /// Whether publication needs one target collection COMMIT.
    pub pending_commit: bool,
}

impl SecretsReaderEnvelopesPlan {
    /// Whether every required fact and proof is already present.
    pub const fn settled(&self) -> bool {
        !self.pending_commit && self.missing_proof_closures == 0
    }
}

/// Publication result after semantic verification through a fresh snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretsReaderEnvelopesReport {
    pub plan: SecretsReaderEnvelopesPlan,
    pub appended_commits: usize,
    pub ensured_proof_closures: usize,
}

#[derive(Clone, Copy)]
enum TargetSelection {
    Default,
    Exact,
}

struct ResolvedTarget {
    collection: Collection<SimpleArchive>,
    policy: CollectionPolicy,
    selection: TargetSelection,
    resident: bool,
}

struct PreparedMigration {
    plan: SecretsReaderEnvelopesPlan,
    target: ResolvedTarget,
    publication: Option<PreparedCollectionCommit>,
    proof_closures: Vec<CapabilityProofBundle>,
    source_facts: TribleSet,
    expected_wraps: BTreeSet<(Id, [u8; 32])>,
    expected_readers: BTreeSet<[u8; 32]>,
    instant: Epoch,
}

fn private_policy(authority: VerifyingKey) -> CollectionPolicy {
    triblespace::core::collection::CollectionPolicy::new(
        triblespace::core::collection::AdmissionPolicy::direct(authority),
        triblespace::core::collection::AdmissionPolicy::direct(authority),
    )
}

fn legacy_read_atom(vault: CollectionHandle) -> CapabilityAtom {
    CapabilityAtom::new(
        CapabilityAction::new(legacy::ACTION_READ),
        CapabilityResource::from(vault),
    )
}

fn collection_atom(action: Id, collection: CollectionHandle) -> CapabilityAtom {
    CapabilityAtom::new(
        CapabilityAction::new(action),
        CapabilityResource::from(collection),
    )
}

fn legacy_envelopes<P>(facts: &P) -> Vec<LegacyEnvelopeRow>
where
    P: TriblePattern,
{
    find!(
        (
            id: Id,
            custody: Inline<triblespace::core::inline::encodings::ed25519::ED25519PublicKey>,
            vault: CollectionHandle,
            read_proof: CapabilityProofId,
            write_proof: CapabilityProofId,
            sealed_seed: BytesHandle
        ),
        pattern!(facts, [{
            ?id @
                metadata::tag: legacy::KIND_ACCESS_ENVELOPE,
                legacy::custody_public_key: ?custody,
                legacy::access_vault: ?vault,
                legacy::access_read_proof: ?read_proof,
                legacy::access_write_proof: ?write_proof,
                legacy::access_sealed_seed: ?sealed_seed,
        }])
    )
    .filter_map(
        |(id, custody, vault, read_proof, write_proof, sealed_seed)| {
            VerifyingKey::from_bytes(&custody.raw)
                .ok()
                .map(|custody_public_key| LegacyEnvelopeRow {
                    id,
                    custody_public_key,
                    vault,
                    read_proof,
                    write_proof,
                    sealed_seed,
                })
        },
    )
    .collect()
}

fn custody_keys<P>(facts: &P) -> BTreeSet<[u8; 32]>
where
    P: TriblePattern,
{
    find!(
        key: Inline<triblespace::core::inline::encodings::ed25519::ED25519PublicKey>,
        pattern!(facts, [{
            _?id @
                metadata::tag: legacy::KIND_VAULT_CUSTODY,
                legacy::custody_public_key: ?key,
        }])
    )
    .filter_map(|key| {
        VerifyingKey::from_bytes(&key.raw)
            .ok()
            .map(|key| key.to_bytes())
    })
    .collect()
}

fn signed_legacy_envelopes(snapshot: &PileSnapshot) -> Result<Vec<SignedLegacyEnvelope>> {
    let mut rows = Vec::new();
    for record in snapshot
        .records()
        .context("enumerate collection records for legacy access envelopes")?
    {
        let record = record.context("read collection record for legacy access envelopes")?;
        let CollectionRecord::Commit(commit) = record else {
            continue;
        };
        if commit.verify_strict().is_err() {
            continue;
        }
        let metadata: Blob<SimpleArchive> = match snapshot.get(commit.metadata()) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if simplearchive_union::validate_element(&metadata).is_err() {
            continue;
        }
        let data = Handle::<SimpleArchive>::from_hash(commit.data());
        let blob: Blob<SimpleArchive> = match snapshot.get(data) {
            Ok(blob) => blob,
            Err(_) => continue,
        };
        let facts = match TribleSet::try_from_blob(blob) {
            Ok(facts) => facts,
            Err(_) => continue,
        };
        let publisher = VerifyingKey::from_bytes(&commit.public_key().raw)
            .expect("strict collection signatures contain a valid public key");
        rows.extend(
            legacy_envelopes(&facts)
                .into_iter()
                .map(|row| SignedLegacyEnvelope {
                    inbox: commit.collection(),
                    publisher,
                    row,
                }),
        );
    }
    Ok(rows)
}

fn load_proof_bundle(
    snapshot: &PileSnapshot,
    id: CapabilityProofId,
) -> Result<CapabilityProofBundle> {
    let proof = snapshot
        .proof(id)
        .context("look up legacy capability proof")?
        .ok_or_else(|| anyhow!("proof {id:?} is not resident"))?;
    if proof.id() != id {
        bail!("proof store returned a different capability proof identity");
    }
    let claims = proof
        .claim_handles()
        .enumerate()
        .map(|(step, handle)| {
            snapshot
                .get::<Blob<SimpleArchive>, _>(handle)
                .with_context(|| format!("read capability claim {step}"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(CapabilityProofBundle::new(proof, claims))
}

fn resident_proof_bundles(snapshot: &PileSnapshot) -> Result<Vec<CapabilityProofBundle>> {
    let mut bundles = Vec::new();
    for proof in snapshot
        .proofs()
        .context("enumerate resident capability proofs")?
    {
        let proof = proof.context("read resident capability proof")?;
        let claims = proof
            .claim_handles()
            .map(|handle| snapshot.get::<Blob<SimpleArchive>, _>(handle).ok())
            .collect::<Option<Vec<_>>>();
        if let Some(claims) = claims {
            bundles.push(CapabilityProofBundle::new(proof, claims));
        }
    }
    Ok(bundles)
}

fn intersect_validity(
    left: Option<CapabilityValidity>,
    right: Option<CapabilityValidity>,
) -> Option<CapabilityValidity> {
    match (left, right) {
        (None, None) => None,
        (Some(value), None) | (None, Some(value)) => Some(value),
        (Some(left), Some(right)) => {
            let (left_lower, left_upper) = left.bounds();
            let (right_lower, right_upper) = right.bounds();
            let left_lower_ns = left_lower.to_tai_duration().total_nanoseconds();
            let right_lower_ns = right_lower.to_tai_duration().total_nanoseconds();
            let left_upper_ns = left_upper.to_tai_duration().total_nanoseconds();
            let right_upper_ns = right_upper.to_tai_duration().total_nanoseconds();
            let lower = if left_lower_ns >= right_lower_ns {
                left_lower
            } else {
                right_lower
            };
            let upper = if left_upper_ns <= right_upper_ns {
                left_upper
            } else {
                right_upper
            };
            Some(
                CapabilityValidity::new(lower, upper)
                    .expect("structural proof validation established a nonempty intersection"),
            )
        }
    }
}

fn structural_prefixes(
    bundle: &CapabilityProofBundle,
    root: VerifyingKey,
    atom: CapabilityAtom,
) -> Result<Vec<LegacyPrefix>> {
    if bundle.proof().root_key() != root {
        bail!("capability proof is rooted at a different authority");
    }
    bundle
        .validate_structure_for_atom(atom)
        .context("validate capability proof structure")?;
    let subjects = bundle.proof().delegated_keys().collect::<Vec<_>>();
    if subjects.len() != bundle.claims().len() {
        bail!("capability proof and claim closure have different lengths");
    }
    let mut mode = None::<CapabilityMode>;
    let mut validity = None::<CapabilityValidity>;
    let mut prefixes = Vec::with_capacity(subjects.len());
    for (subject, blob) in subjects.into_iter().zip(bundle.claims()) {
        let claim = CapabilityClaim::from_blob(blob.clone()).context("decode capability claim")?;
        mode = Some(match mode {
            None => claim.mode(),
            Some(parent) => parent
                .meet(claim.mode())
                .expect("structural validation rejected empty mode intersections"),
        });
        validity = intersect_validity(validity, claim.validity());
        prefixes.push(LegacyPrefix {
            subject,
            mode: mode.expect("one claim established a mode"),
            validity,
        });
    }
    Ok(prefixes)
}

fn expected_inbox(subject: VerifyingKey) -> Result<CollectionHandle> {
    let mut scratch = MemoryRepo::default();
    scratch
        .collection(ACCESS_INBOX_NAME, private_policy(subject))
        .map(|collection| collection.handle())
        .map_err(|error| anyhow!("construct legacy access-inbox descriptor: {error}"))
}

fn validate_legacy_envelope(
    snapshot: &PileSnapshot,
    candidate: SignedLegacyEnvelope,
    source: CollectionHandle,
    authority: VerifyingKey,
    declared_custodies: &BTreeSet<[u8; 32]>,
) -> Result<ValidatedLegacyEnvelope> {
    let row = candidate.row;
    if row.vault != source {
        bail!("access envelope names another vault");
    }
    if !declared_custodies.contains(&row.custody_public_key.to_bytes()) {
        bail!("access envelope names an undeclared custody key");
    }
    let read = load_proof_bundle(snapshot, row.read_proof).context("load legacy READ proof")?;
    let prefixes = structural_prefixes(&read, authority, legacy_read_atom(source))
        .context("validate legacy READ proof")?;
    let final_prefix = prefixes
        .last()
        .ok_or_else(|| anyhow!("legacy READ proof has no subject"))?;
    if !final_prefix.mode.satisfies(CapabilityMode::Invoke) {
        bail!("legacy READ proof does not permit invocation");
    }
    let subject = read.proof().leaf_key();
    if candidate.inbox != expected_inbox(subject)? {
        bail!("access envelope was not delivered through the subject's exact legacy inbox");
    }
    if candidate.publisher != read.proof().leaf_issuer() {
        bail!("access-inbox COMMIT signer is not the legacy READ leaf issuer");
    }
    let sealed: anybytes::Bytes = snapshot
        .get(row.sealed_seed)
        .context("read legacy sealed custody attachment")?;
    if sealed.len() != SEALED_FRAME_BYTES {
        bail!(
            "legacy sealed custody attachment has {} bytes; expected {SEALED_FRAME_BYTES}",
            sealed.len()
        );
    }

    let write = load_proof_bundle(snapshot, row.write_proof).context("load legacy WRITE proof")?;
    let write_prefixes =
        structural_prefixes(&write, authority, collection_atom(ACTION_WRITE, source))
            .context("validate legacy WRITE proof")?;
    let write_final = write_prefixes
        .last()
        .ok_or_else(|| anyhow!("legacy WRITE proof has no subject"))?;
    if !write_final.mode.satisfies(CapabilityMode::Invoke) {
        bail!("legacy WRITE proof does not permit invocation");
    }
    if write_final.validity.is_some() {
        bail!("legacy WRITE proof is bounded");
    }

    Ok(ValidatedLegacyEnvelope {
        row,
        subject,
        prefixes,
    })
}

fn box_keypair(signing_key: &SigningKey) -> Result<BoxKeyPair> {
    let public = signing_key.verifying_key().to_bytes();
    let secret = Zeroizing::new(signing_key.to_keypair_bytes());
    let mut converted_public = [0u8; 32];
    let mut converted_secret = Zeroizing::new([0u8; 32]);
    crypto_sign_ed25519_pk_to_curve25519(&mut converted_public, &public)
        .map_err(|error| anyhow!("legacy recipient public-key conversion: {error:?}"))?;
    crypto_sign_ed25519_sk_to_curve25519(&mut converted_secret, &secret);
    BoxKeyPair::from_slices(&converted_public, converted_secret.as_slice())
        .map_err(|error| anyhow!("legacy recipient X25519 keypair: {error:?}"))
}

fn take_word(bytes: &[u8], offset: &mut usize) -> [u8; FRAME_WORD_BYTES] {
    let mut word = [0u8; FRAME_WORD_BYTES];
    let end = *offset + FRAME_WORD_BYTES;
    word.copy_from_slice(&bytes[*offset..end]);
    *offset = end;
    word
}

fn open_legacy_custody(
    snapshot: &PileSnapshot,
    row: &LegacyEnvelopeRow,
    recipient: &SigningKey,
) -> Result<SigningKey> {
    let sealed: anybytes::Bytes = snapshot
        .get(row.sealed_seed)
        .context("read legacy sealed custody attachment")?;
    if sealed.len() != SEALED_FRAME_BYTES {
        bail!("legacy sealed custody attachment has the wrong length");
    }
    let recipient_box = box_keypair(recipient)?;
    let plaintext = Zeroizing::new(
        DryocBox::from_sealed_bytes(sealed.as_ref())
            .map_err(|error| anyhow!("parse legacy sealed custody frame: {error:?}"))?
            .unseal_to_vec(&recipient_box)
            .map_err(|_| anyhow!("unseal legacy custody frame for local signer failed"))?,
    );
    if plaintext.len() != FRAME_BYTES {
        bail!("opened legacy custody frame has the wrong length");
    }
    let magic = legacy::ACCESS_ENVELOPE_FORMAT_V1.raw();
    if plaintext[..magic.len()] != magic {
        bail!("opened legacy custody frame has an unknown format marker");
    }
    let mut offset = magic.len();
    let vault = Inline::new(take_word(&plaintext, &mut offset));
    let custody = VerifyingKey::from_bytes(&take_word(&plaintext, &mut offset))
        .context("opened legacy frame has an invalid custody public key")?;
    let read_proof = Inline::new(take_word(&plaintext, &mut offset));
    let subject = VerifyingKey::from_bytes(&take_word(&plaintext, &mut offset))
        .context("opened legacy frame has an invalid subject public key")?;
    let write_proof = Inline::new(take_word(&plaintext, &mut offset));
    let seed = Zeroizing::new(take_word(&plaintext, &mut offset));
    debug_assert_eq!(offset, plaintext.len());
    if vault != row.vault
        || custody != row.custody_public_key
        || read_proof != row.read_proof
        || subject != recipient.verifying_key()
        || write_proof != row.write_proof
    {
        bail!("opened legacy custody frame does not match its typed envelope row");
    }
    let custody_key = SigningKey::from_bytes(&seed);
    if custody_key.verifying_key() != row.custody_public_key {
        bail!("opened legacy custody seed does not match its declared public key");
    }
    Ok(custody_key)
}

fn resolve_target(
    snapshot: &PileSnapshot,
    signer: &SigningKey,
    exact: Option<CollectionHandle>,
) -> Result<ResolvedTarget> {
    if let Some(handle) = exact {
        let collection = faculties::collection_names::open_exact_in(
            snapshot,
            faculties::secrets::DEFAULT_SCOPE_ID,
            handle,
        )
        .context("open exact Secrets migration target")?;
        let policy = collection
            .policy(snapshot)
            .context("read exact Secrets migration target policy")?;
        return Ok(ResolvedTarget {
            collection,
            policy,
            selection: TargetSelection::Exact,
            resident: true,
        });
    }

    if let Some(handle) =
        faculties::collection_names::configured_handle(faculties::secrets::DEFAULT_SCOPE_ID)?
    {
        let collection = faculties::collection_names::open_exact_in(
            snapshot,
            faculties::secrets::DEFAULT_SCOPE_ID,
            handle,
        )
        .context("open configured Secrets migration target")?;
        let policy = collection
            .policy(snapshot)
            .context("read configured Secrets migration target policy")?;
        return Ok(ResolvedTarget {
            collection,
            policy,
            selection: TargetSelection::Default,
            resident: true,
        });
    }

    let mut scratch = MemoryRepo::default();
    let collection = faculties::collection_names::open(
        &mut scratch,
        faculties::secrets::DEFAULT_SCOPE_ID,
        signer.verifying_key(),
    )
    .context("construct default Secrets migration target")?;
    let policy = private_policy(signer.verifying_key());
    let resident = match snapshot.get::<Blob<SimpleArchive>, _>(collection.handle()) {
        Ok(_) => true,
        Err(GetBlobError::BlobNotFound) => false,
        Err(error) => return Err(anyhow!("read default Secrets target descriptor: {error}")),
    };
    if resident {
        faculties::collection_names::open_exact_in(
            snapshot,
            faculties::secrets::DEFAULT_SCOPE_ID,
            collection.handle(),
        )
        .context("validate resident default Secrets migration target")?;
    }
    Ok(ResolvedTarget {
        collection,
        policy,
        selection: TargetSelection::Default,
        resident,
    })
}

fn source_facts_at(
    snapshot: &PileSnapshot,
    source: CollectionHandle,
    signer: &SigningKey,
    instant: Epoch,
) -> Result<TribleSet> {
    let collection = Collection::<SimpleArchive>::open(snapshot, source)
        .with_context(|| format!("open legacy vault {}", hex::encode(source.raw)))?;
    let policy = collection
        .policy(snapshot)
        .with_context(|| format!("read legacy vault {} policy", hex::encode(source.raw)))?;
    if policy != private_policy(signer.verifying_key()) {
        bail!(
            "legacy vault {} is not the exact signer-rooted direct-policy generation",
            hex::encode(source.raw)
        );
    }
    collection
        .read_at::<TribleSet, _>(snapshot, instant)
        .with_context(|| {
            format!(
                "read admitted legacy vault {} facts",
                hex::encode(source.raw)
            )
        })
}

fn target_facts_at(
    snapshot: &PileSnapshot,
    target: &ResolvedTarget,
    instant: Epoch,
) -> Result<TribleSet> {
    if !target.resident {
        return Ok(TribleSet::new());
    }
    target
        .collection
        .read_at::<TribleSet, _>(snapshot, instant)
        .context("read admitted current Secrets target facts")
}

fn issue_translated_bundle(
    signer: &SigningKey,
    target: CollectionHandle,
    prefix: LegacyPrefix,
) -> Result<CapabilityProofBundle> {
    CapabilityProofBundle::issue_root(
        signer,
        CapabilityClaim::root(
            collection_atom(ACTION_READ, target),
            prefix.mode,
            prefix.validity,
        ),
        prefix.subject,
    )
    .context("issue translated core READ proof")
}

fn prepare(
    snapshot: &PileSnapshot,
    signer: &SigningKey,
    sources: &[CollectionHandle],
    exact_target: Option<CollectionHandle>,
    instant: Epoch,
) -> Result<PreparedMigration> {
    let mut sources = sources.iter().copied().collect::<BTreeSet<_>>();
    if sources.is_empty() {
        bail!("Secrets reader-envelope migration needs at least one --legacy-vault");
    }
    let target = resolve_target(snapshot, signer, exact_target)?;
    if sources.remove(&target.collection.handle()) {
        bail!("a legacy vault cannot also be the current Secrets target");
    }
    let sources = sources.into_iter().collect::<Vec<_>>();

    let resident_bundles = resident_proof_bundles(snapshot)?;
    let signer_key = signer.verifying_key();
    if !triblespace::core::collection::collection_writer_is_admitted_by_policy_at(
        target.collection.handle(),
        &target.policy,
        signer_key,
        &resident_bundles,
        instant,
    ) {
        bail!("the durable signer is not admitted to WRITE the Secrets target");
    }

    let access = signed_legacy_envelopes(snapshot)?;
    let mut source_union = TribleSet::new();
    let mut holders = BTreeMap::<[u8; 32], SigningKey>::new();
    holders.insert(signer_key.to_bytes(), signer.clone());
    let mut prefixes = Vec::new();
    let mut legacy_access_envelopes = 0usize;
    let mut skipped_legacy_candidates = 0usize;

    for source in &sources {
        let facts = source_facts_at(snapshot, *source, signer, instant)?;
        let source_secrets = secret_rows(&facts)
            .into_iter()
            .map(|row| row.id)
            .collect::<BTreeSet<_>>();
        let declared_custodies = custody_keys(&facts);
        let mut recovered_here = 0usize;
        let mut candidate_errors = Vec::new();
        for candidate in access
            .iter()
            .copied()
            .filter(|row| row.row.vault == *source)
        {
            match validate_legacy_envelope(
                snapshot,
                candidate,
                *source,
                signer_key,
                &declared_custodies,
            ) {
                Ok(validated) => {
                    legacy_access_envelopes += 1;
                    prefixes.extend(validated.prefixes.iter().copied());
                    if validated.subject == signer_key {
                        match open_legacy_custody(snapshot, &validated.row, signer) {
                            Ok(custody) => {
                                holders.insert(custody.verifying_key().to_bytes(), custody);
                                recovered_here += 1;
                            }
                            Err(error) => candidate_errors.push(error.to_string()),
                        }
                    }
                }
                Err(error) => {
                    skipped_legacy_candidates += 1;
                    candidate_errors.push(error.to_string());
                }
            }
        }
        if !source_secrets.is_empty() && recovered_here == 0 {
            let detail = if candidate_errors.is_empty() {
                "no complete signer-addressed legacy access envelope was found".to_owned()
            } else {
                candidate_errors.join("; ")
            };
            bail!(
                "legacy vault {} has {} secret version(s), but its custody cannot be recovered: {detail}",
                hex::encode(source.raw),
                source_secrets.len(),
            );
        }
        source_union.union(facts);
    }

    let mut translated = BTreeMap::<CapabilityProofId, CapabilityProofBundle>::new();
    for prefix in prefixes {
        if prefix.subject == signer_key {
            continue;
        }
        let bundle = issue_translated_bundle(signer, target.collection.handle(), prefix)?;
        translated.entry(bundle.proof().id()).or_insert(bundle);
    }
    if !translated.is_empty() {
        let roots = target.policy.read().roots().unwrap_or(&[]);
        if !roots.contains(&signer_key) || target.policy.read().invoke_threshold() != Some(1) {
            bail!(
                "the Secrets target READ quorum cannot be translated with the one supplied root signer"
            );
        }
    }

    let resident_ids = resident_bundles
        .iter()
        .map(|bundle| bundle.proof().id())
        .collect::<BTreeSet<_>>();
    let proof_closures = translated
        .values()
        .filter(|bundle| !resident_ids.contains(&bundle.proof().id()))
        .cloned()
        .collect::<Vec<_>>();
    let mut audience_bundles = resident_bundles;
    audience_bundles.extend(translated.values().cloned());
    let readers = match collection_read_audience_by_policy_at(
        target.collection.handle(),
        &target.policy,
        &audience_bundles,
        instant,
    ) {
        CollectionReadAudience::Open => {
            bail!("cannot migrate encrypted Secrets into an open-read collection")
        }
        CollectionReadAudience::Restricted(readers) if readers.is_empty() => {
            bail!("the Secrets target has no reader admitted at the migration instant")
        }
        CollectionReadAudience::Restricted(readers) => readers,
    };
    let expected_readers = readers
        .iter()
        .map(VerifyingKey::to_bytes)
        .collect::<BTreeSet<_>>();

    let target_facts = target_facts_at(snapshot, &target, instant)?;
    let copied = source_union.difference(&target_facts);
    let copied_facts = copied.len();
    let mut planning_facts = target_facts;
    planning_facts.union(source_union.clone());
    let secrets = secret_rows(&planning_facts)
        .into_iter()
        .map(|row| row.id)
        .collect::<BTreeSet<_>>();

    let mut publication = Fragment::from(copied);
    let mut expected_wraps = BTreeSet::new();
    let mut missing_recipient_wraps = 0usize;
    for secret in &secrets {
        let mut selected = None::<SigningKey>;
        let mut plaintext = None::<Zeroizing<Vec<u8>>>;
        let mut failures = Vec::new();
        for holder in holders.values() {
            match open_version_from_facts(snapshot, &planning_facts, *secret, holder) {
                Ok(candidate) => {
                    if plaintext
                        .as_ref()
                        .is_some_and(|known| known.as_slice() != candidate.as_slice())
                    {
                        bail!("secret {secret} opens to competing plaintext through local custody evidence");
                    }
                    if selected.is_none() {
                        selected = Some(holder.clone());
                        plaintext = Some(Zeroizing::new(candidate));
                    }
                }
                Err(error) => failures.push(error.to_string()),
            }
        }
        let holder = selected.ok_or_else(|| {
            anyhow!(
                "secret {secret} cannot be recovered from any locally available legacy custody: {}",
                failures.join("; ")
            )
        })?;
        let envelopes = add_recipient_envelopes_for_target(
            snapshot,
            &planning_facts,
            &planning_facts,
            *secret,
            &holder,
            readers.iter().copied(),
        )
        .with_context(|| format!("prepare direct reader envelopes for secret {secret}"))?;
        missing_recipient_wraps += envelopes.recipients.len();
        expected_wraps.extend(
            envelopes
                .recipients
                .iter()
                .map(|recipient| (*secret, recipient.to_bytes())),
        );
        publication += envelopes.fragment;
    }
    let pending_commit = !publication.facts().is_empty();
    let publication = pending_commit.then(|| PreparedCollectionCommit::from_fragment(publication));
    let plan = SecretsReaderEnvelopesPlan {
        sources,
        target: target.collection.handle(),
        source_facts: source_union.len(),
        copied_facts,
        secret_versions: secrets.len(),
        legacy_access_envelopes,
        translated_prefixes: translated.len(),
        missing_proof_closures: proof_closures.len(),
        current_readers: readers.len(),
        recovered_custodies: holders.len().saturating_sub(1),
        skipped_legacy_candidates,
        missing_recipient_wraps,
        pending_commit,
    };
    Ok(PreparedMigration {
        plan,
        target,
        publication,
        proof_closures,
        source_facts: source_union,
        expected_wraps,
        expected_readers,
        instant,
    })
}

fn persist_proof_bundle(pile: &mut Pile, bundle: &CapabilityProofBundle) -> Result<()> {
    let handles = bundle.proof().claim_handles().collect::<Vec<_>>();
    if handles.len() != bundle.claims().len() {
        bail!("translated capability proof has an incomplete claim closure");
    }
    for (step, claim) in bundle.claims().iter().enumerate() {
        pile.put::<SimpleArchive, _>(claim.clone())
            .map_err(|error| anyhow!("persist translated READ claim {step}: {error}"))?;
    }
    pile.insert_proof(bundle.proof().clone())
        .map_err(|error| anyhow!("persist translated READ proof: {error}"))
}

fn publish_open(
    pile: &mut Pile,
    signer: &SigningKey,
    sources: &[CollectionHandle],
    exact_target: Option<CollectionHandle>,
    instant: Epoch,
) -> Result<SecretsReaderEnvelopesReport> {
    let snapshot = pile
        .snapshot()
        .context("freeze Secrets reader-envelope preflight snapshot")?;
    let mut prepared = prepare(&snapshot, signer, sources, exact_target, instant)?;
    drop(snapshot);

    let target = match prepared.target.selection {
        TargetSelection::Default => faculties::collection_names::open_configured(
            pile,
            faculties::secrets::DEFAULT_SCOPE_ID,
            signer.verifying_key(),
        )
        .context("open default Secrets migration target")?,
        TargetSelection::Exact => prepared.target.collection,
    };
    if target.handle() != prepared.plan.target {
        bail!("Secrets target changed identity between preflight and publication");
    }

    // Stage the complete fact payload before any proof or COMMIT becomes
    // visible. Dropping the staged value withholds its signed COMMIT while
    // retaining only inert dependency blobs.
    let commit = if let Some(publication) = prepared.publication.take() {
        let staged = publication
            .stage_for(pile, target, signer)
            .context("stage additive Secrets target fragment")?;
        let commit = *staged.commit();
        drop(staged);
        Some(commit)
    } else {
        None
    };

    let appended_commits = usize::from(commit.is_some());
    if let Some(commit) = commit {
        pile.insert(CollectionRecord::Commit(commit))
            .map_err(|error| anyhow!("publish additive Secrets target COMMIT: {error}"))?;
    }
    // New READ evidence becomes visible only after every direct envelope it
    // admits is present in the target. A crash after the COMMIT but before
    // proof insertion therefore leaves readers unavailable, never admitted
    // without their DEK wrap; replay finishes the idempotent proof closure.
    for bundle in &prepared.proof_closures {
        persist_proof_bundle(pile, bundle)?;
    }

    let after = pile
        .snapshot()
        .context("freeze Secrets reader-envelope verification snapshot")?;
    let target = Collection::<SimpleArchive>::open(&after, prepared.plan.target)
        .context("open published Secrets target")?;
    let facts = target
        .read_at::<TribleSet, _>(&after, prepared.instant)
        .context("read published Secrets target facts")?;
    if !prepared.source_facts.difference(&facts).is_empty() {
        bail!("published Secrets target is missing legacy source facts");
    }
    for (secret, recipient) in &prepared.expected_wraps {
        if recipient_wraps(&facts, *secret, *recipient).is_empty() {
            bail!("published Secrets target is missing an expected direct recipient wrap");
        }
    }
    for bundle in &prepared.proof_closures {
        load_proof_bundle(&after, bundle.proof().id())
            .context("verify translated READ proof closure")?;
    }
    let audience = triblespace::core::collection::collection_read_audience_at(
        &after,
        prepared.plan.target,
        prepared.instant,
    )
    .map_err(|error| anyhow!("verify published Secrets READ audience: {error}"))?;
    let CollectionReadAudience::Restricted(readers) = audience else {
        bail!("published Secrets target unexpectedly has open READ admission");
    };
    let readers = readers
        .into_iter()
        .map(|reader| reader.to_bytes())
        .collect::<BTreeSet<_>>();
    if readers != prepared.expected_readers {
        bail!("Secrets target READ audience changed across cutover publication; rerun after quiescing authority writers");
    }
    drop(after);

    Ok(SecretsReaderEnvelopesReport {
        appended_commits,
        ensured_proof_closures: prepared.proof_closures.len(),
        plan: prepared.plan,
    })
}

fn finish_pile<T>(pile: Pile, result: Result<T>, operation: &str) -> Result<T> {
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context(format!("close pile after {operation}"))),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing after {operation} also failed: {close_error}",
        ))),
    }
}

/// Fully preflight one explicit legacy-vault set without writing the pile.
pub fn plan_path(
    pile: &Path,
    key: Option<&Path>,
    sources: &[CollectionHandle],
    target: Option<CollectionHandle>,
) -> Result<SecretsReaderEnvelopesPlan> {
    let signer = load_signer(pile, key).context("load durable Secrets migration signer")?;
    let mut store = open_pile_strict(pile)?;
    let snapshot = store
        .snapshot()
        .context("freeze Secrets reader-envelope planning snapshot")?;
    let instant = triblespace::core::clock::epoch_now();
    let result =
        prepare(&snapshot, &signer, sources, target, instant).map(|prepared| prepared.plan);
    drop(snapshot);
    finish_pile(store, result, "Secrets reader-envelope planning")
}

/// Publish one fully preflighted additive cutover.
///
/// Legacy vault, inbox, and capability-evidence writers must be quiesced before
/// this final cutover. The target COMMIT is one atomic fact union; exact proof
/// and blob reinsertion is idempotent, and a replay adds only newly missing
/// facts or reader wraps.
pub fn publish_path(
    pile: &Path,
    key: Option<&Path>,
    sources: &[CollectionHandle],
    target: Option<CollectionHandle>,
) -> Result<SecretsReaderEnvelopesReport> {
    let signer = load_signer(pile, key).context("load durable Secrets migration signer")?;
    let mut store = open_pile_strict(pile)?;
    let instant = triblespace::core::clock::epoch_now();
    let result = publish_open(&mut store, &signer, sources, target, instant);
    finish_pile(store, result, "Secrets reader-envelope publication")
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};

    use dryoc::dryocbox::PublicKey as BoxPublicKey;
    use triblespace::core::capability::CapabilityRequest;
    use triblespace::core::collection::CollectionStoreExt;
    use triblespace::core::repo::SnapshotSource;
    use triblespace::macros::entity;
    use triblespace::prelude::TryToInline;

    use super::*;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn point(second: i64) -> faculties::secrets::IntervalValue {
        let instant = Epoch::from_unix_seconds(second as f64);
        (instant, instant).try_to_inline().unwrap()
    }

    fn fixture() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        SigningKey,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("test.pile");
        let key_path = directory.path().join("test.key");
        File::create(&pile).unwrap();
        let signer = faculties::storage::initialize_signer(&pile, Some(&key_path)).unwrap();
        (directory, pile, key_path, signer)
    }

    fn custody_fragment(custody: VerifyingKey) -> Fragment {
        entity! {
            metadata::tag: legacy::KIND_VAULT_CUSTODY,
            legacy::custody_public_key: custody,
        }
    }

    fn box_public_key(public: &VerifyingKey) -> BoxPublicKey {
        let mut converted = [0u8; 32];
        crypto_sign_ed25519_pk_to_curve25519(&mut converted, &public.to_bytes()).unwrap();
        BoxPublicKey::try_from(&converted[..]).unwrap()
    }

    fn legacy_envelope_fragment(
        vault: CollectionHandle,
        custody: &SigningKey,
        subject: VerifyingKey,
        read: &CapabilityProofBundle,
        write: &CapabilityProofBundle,
    ) -> Fragment {
        let mut frame = Zeroizing::new(Vec::with_capacity(FRAME_BYTES));
        frame.extend_from_slice(&legacy::ACCESS_ENVELOPE_FORMAT_V1.raw());
        frame.extend_from_slice(&vault.raw);
        frame.extend_from_slice(&custody.verifying_key().to_bytes());
        frame.extend_from_slice(&read.proof().id().raw);
        frame.extend_from_slice(&subject.to_bytes());
        frame.extend_from_slice(&write.proof().id().raw);
        frame.extend_from_slice(&custody.to_bytes());
        let sealed = DryocBox::seal_to_vecbox(frame.as_slice(), &box_public_key(&subject))
            .unwrap()
            .to_vec();
        let mut fragment = Fragment::empty();
        let sealed =
            fragment.put::<triblespace::core::blob::encodings::rawbytes::RawBytes, _>(sealed);
        fragment += entity! { _ @
            metadata::tag: legacy::KIND_ACCESS_ENVELOPE,
            legacy::custody_public_key: custody.verifying_key(),
            legacy::access_vault: vault,
            legacy::access_read_proof: read.proof().id(),
            legacy::access_write_proof: write.proof().id(),
            legacy::access_sealed_seed: sealed,
        };
        fragment
    }

    fn read_bundle(
        root: &SigningKey,
        vault: CollectionHandle,
        subject: VerifyingKey,
        mode: CapabilityMode,
        validity: Option<CapabilityValidity>,
    ) -> CapabilityProofBundle {
        CapabilityProofBundle::issue_root(
            root,
            CapabilityClaim::root(legacy_read_atom(vault), mode, validity),
            subject,
        )
        .unwrap()
    }

    fn write_bundle(root: &SigningKey, vault: CollectionHandle) -> CapabilityProofBundle {
        CapabilityProofBundle::issue_root(
            root,
            CapabilityClaim::root(
                collection_atom(ACTION_WRITE, vault),
                CapabilityMode::InvokeAndDelegate,
                None,
            ),
            root.verifying_key(),
        )
        .unwrap()
    }

    fn publish_legacy_envelope(
        pile: &mut Pile,
        publisher: &SigningKey,
        custody: &SigningKey,
        vault: CollectionHandle,
        read: &CapabilityProofBundle,
        write: &CapabilityProofBundle,
    ) {
        persist_proof_bundle(pile, read).unwrap();
        persist_proof_bundle(pile, write).unwrap();
        let subject = read.proof().leaf_key();
        let inbox = pile
            .collection(ACCESS_INBOX_NAME, private_policy(subject))
            .unwrap();
        let fragment = legacy_envelope_fragment(vault, custody, subject, read, write);
        pile.commit(inbox, publisher, fragment).unwrap();
    }

    struct LegacyFixture {
        source: Collection<SimpleArchive>,
        target: Collection<SimpleArchive>,
        custody: SigningKey,
        secret: Id,
        body: faculties::secrets::BytesHandle,
    }

    fn legacy_secret(pile: &mut Pile, root: &SigningKey, source_name: &str) -> LegacyFixture {
        let source = pile
            .collection(source_name, private_policy(root.verifying_key()))
            .unwrap();
        let target = pile
            .collection("secrets", private_policy(root.verifying_key()))
            .unwrap();
        let custody = key(*source_name
            .as_bytes()
            .last()
            .expect("nonempty fixture name"));
        let mut sealed = faculties::secrets::seal_version(
            "database",
            b"unchanged ciphertext",
            [custody.verifying_key()],
            point(1),
        )
        .unwrap();
        let secret = sealed.secret;
        let body = secret_rows(sealed.fragment.facts())[0].body;
        sealed.fragment += custody_fragment(custody.verifying_key());
        pile.commit(source, root, sealed.fragment).unwrap();
        LegacyFixture {
            source,
            target,
            custody,
            secret,
            body,
        }
    }

    #[test]
    fn migration_local_legacy_wire_ids_are_exact() {
        for (actual, expected) in [
            (legacy::ACTION_READ, "A6378B816786E9F08A579B8E5F8F4FF4"),
            (
                legacy::KIND_ACCESS_ENVELOPE,
                "3BF25F54D4B6B0947ED2CE830C0114D2",
            ),
            (
                legacy::KIND_VAULT_CUSTODY,
                "7DD14F755D8038BBC8F32242BEBD6031",
            ),
            (
                legacy::ACCESS_ENVELOPE_FORMAT_V1,
                "0444B547B64A83CB156D3CAA917DAB89",
            ),
            (
                legacy::custody_public_key.id(),
                "176DF52B59F579E74CBD960B5EFDC2A7",
            ),
            (
                legacy::access_vault.id(),
                "106941F1D8DC9C744373F22ED6E74675",
            ),
            (
                legacy::access_read_proof.id(),
                "472847C47C11D45DED10E45DA9D6E690",
            ),
            (
                legacy::access_write_proof.id(),
                "490A38AEEB2B9127D9AB70C164D37CDA",
            ),
            (
                legacy::access_sealed_seed.id(),
                "9ABBB200A36063069AA2A29424A4575E",
            ),
        ] {
            assert_eq!(format!("{actual:X}"), expected);
        }
    }

    #[test]
    fn translates_reader_prefixes_and_preserves_secret_identity_and_body() {
        let (_directory, path, key_path, root) = fixture();
        let mut pile = open_pile_strict(&path).unwrap();
        let legacy = legacy_secret(&mut pile, &root, "legacy-vault-a");
        let intermediary = key(41);
        let reader = key(42);
        let root_access = read_bundle(
            &root,
            legacy.source.handle(),
            root.verifying_key(),
            CapabilityMode::InvokeAndDelegate,
            None,
        );
        let parent = read_bundle(
            &root,
            legacy.source.handle(),
            intermediary.verifying_key(),
            CapabilityMode::InvokeAndDelegate,
            None,
        );
        let verified = parent
            .verify(
                root.verifying_key(),
                triblespace::core::clock::epoch_now(),
                intermediary.verifying_key(),
                CapabilityRequest::new(
                    legacy_read_atom(legacy.source.handle()),
                    CapabilityMode::InvokeAndDelegate,
                ),
            )
            .unwrap();
        let child = verified
            .delegate(
                &intermediary,
                CapabilityClaim::delegated(
                    verified.claim_handle(),
                    legacy_read_atom(legacy.source.handle()),
                    CapabilityMode::Invoke,
                    None,
                ),
                reader.verifying_key(),
            )
            .unwrap();
        let write = write_bundle(&root, legacy.source.handle());
        publish_legacy_envelope(
            &mut pile,
            &root,
            &legacy.custody,
            legacy.source.handle(),
            &root_access,
            &write,
        );
        publish_legacy_envelope(
            &mut pile,
            &intermediary,
            &legacy.custody,
            legacy.source.handle(),
            &child,
            &write,
        );
        pile.close().unwrap();

        let before = plan_path(
            &path,
            Some(&key_path),
            &[legacy.source.handle()],
            Some(legacy.target.handle()),
        )
        .unwrap();
        assert_eq!(before.secret_versions, 1);
        assert_eq!(before.translated_prefixes, 2);
        assert_eq!(before.missing_proof_closures, 2);
        assert_eq!(before.current_readers, 3);
        assert_eq!(before.missing_recipient_wraps, 3);

        let first = publish_path(
            &path,
            Some(&key_path),
            &[legacy.source.handle()],
            Some(legacy.target.handle()),
        )
        .unwrap();
        assert_eq!(first.appended_commits, 1);
        assert_eq!(first.ensured_proof_closures, 2);

        let mut pile = open_pile_strict(&path).unwrap();
        let snapshot = pile.snapshot().unwrap();
        let facts = legacy.target.read::<TribleSet, _>(&snapshot).unwrap();
        let migrated = secret_rows(&facts)
            .into_iter()
            .find(|row| row.id == legacy.secret)
            .unwrap();
        assert_eq!(migrated.body, legacy.body);
        assert_eq!(
            open_version_from_facts(&snapshot, &facts, legacy.secret, &root).unwrap(),
            b"unchanged ciphertext"
        );
        assert_eq!(
            open_version_from_facts(&snapshot, &facts, legacy.secret, &intermediary).unwrap(),
            b"unchanged ciphertext"
        );
        assert_eq!(
            open_version_from_facts(&snapshot, &facts, legacy.secret, &reader).unwrap(),
            b"unchanged ciphertext"
        );
        let translated = resident_proof_bundles(&snapshot)
            .unwrap()
            .into_iter()
            .filter_map(|bundle| {
                structural_prefixes(
                    &bundle,
                    root.verifying_key(),
                    collection_atom(ACTION_READ, legacy.target.handle()),
                )
                .ok()
            })
            .flatten()
            .collect::<Vec<_>>();
        assert!(translated.iter().any(|prefix| {
            prefix.subject == intermediary.verifying_key()
                && prefix.mode == CapabilityMode::InvokeAndDelegate
                && prefix.validity.is_none()
        }));
        assert!(translated.iter().any(|prefix| {
            prefix.subject == reader.verifying_key()
                && prefix.mode == CapabilityMode::Invoke
                && prefix.validity.is_none()
        }));
        drop(snapshot);
        pile.close().unwrap();

        let length = fs::metadata(&path).unwrap().len();
        let replay = publish_path(
            &path,
            Some(&key_path),
            &[legacy.source.handle()],
            Some(legacy.target.handle()),
        )
        .unwrap();
        assert_eq!(replay.appended_commits, 0);
        assert_eq!(replay.ensured_proof_closures, 0);
        assert!(replay.plan.settled());
        assert_eq!(fs::metadata(&path).unwrap().len(), length);
    }

    #[test]
    fn unavailable_custody_refuses_before_any_append() {
        let (_directory, path, key_path, root) = fixture();
        let mut pile = open_pile_strict(&path).unwrap();
        let legacy = legacy_secret(&mut pile, &root, "legacy-vault-b");
        let reader = key(52);
        let reader_access = read_bundle(
            &root,
            legacy.source.handle(),
            reader.verifying_key(),
            CapabilityMode::Invoke,
            None,
        );
        let write = write_bundle(&root, legacy.source.handle());
        publish_legacy_envelope(
            &mut pile,
            &root,
            &legacy.custody,
            legacy.source.handle(),
            &reader_access,
            &write,
        );
        pile.close().unwrap();
        let length = fs::metadata(&path).unwrap().len();

        let error = publish_path(
            &path,
            Some(&key_path),
            &[legacy.source.handle()],
            Some(legacy.target.handle()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("custody cannot be recovered"));
        assert_eq!(fs::metadata(&path).unwrap().len(), length);
    }

    #[test]
    fn several_vaults_are_copied_with_original_ids_in_one_target_commit() {
        let (_directory, path, key_path, root) = fixture();
        let mut pile = open_pile_strict(&path).unwrap();
        let first = legacy_secret(&mut pile, &root, "legacy-vault-d");
        let second = legacy_secret(&mut pile, &root, "legacy-vault-e");
        for legacy in [&first, &second] {
            let read = read_bundle(
                &root,
                legacy.source.handle(),
                root.verifying_key(),
                CapabilityMode::InvokeAndDelegate,
                None,
            );
            let write = write_bundle(&root, legacy.source.handle());
            publish_legacy_envelope(
                &mut pile,
                &root,
                &legacy.custody,
                legacy.source.handle(),
                &read,
                &write,
            );
        }
        pile.close().unwrap();

        let report = publish_path(
            &path,
            Some(&key_path),
            &[first.source.handle(), second.source.handle()],
            Some(first.target.handle()),
        )
        .unwrap();
        assert_eq!(report.appended_commits, 1);
        assert_eq!(report.plan.secret_versions, 2);

        let mut pile = open_pile_strict(&path).unwrap();
        let snapshot = pile.snapshot().unwrap();
        let facts = first.target.read::<TribleSet, _>(&snapshot).unwrap();
        let rows = secret_rows(&facts)
            .into_iter()
            .map(|row| (row.id, row.body))
            .collect::<BTreeSet<_>>();
        assert!(rows.contains(&(first.secret, first.body)));
        assert!(rows.contains(&(second.secret, second.body)));
        assert_eq!(
            open_version_from_facts(&snapshot, &facts, first.secret, &root).unwrap(),
            b"unchanged ciphertext"
        );
        assert_eq!(
            open_version_from_facts(&snapshot, &facts, second.secret, &root).unwrap(),
            b"unchanged ciphertext"
        );
        let target_commits = snapshot
            .records()
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|record| {
                matches!(
                    record,
                    CollectionRecord::Commit(commit)
                        if commit.collection() == first.target.handle()
                )
            })
            .count();
        assert_eq!(target_commits, 1);
        drop(snapshot);
        pile.close().unwrap();
    }

    #[test]
    fn future_reader_proof_is_translated_without_a_premature_wrap() {
        let (_directory, path, key_path, root) = fixture();
        let mut pile = open_pile_strict(&path).unwrap();
        let legacy = legacy_secret(&mut pile, &root, "legacy-vault-c");
        let reader = key(62);
        let now = triblespace::core::clock::epoch_now();
        let lower = now + hifitime::Duration::from_days(1.0);
        let upper = now + hifitime::Duration::from_days(2.0);
        let future = CapabilityValidity::new(lower, upper).unwrap();
        let root_access = read_bundle(
            &root,
            legacy.source.handle(),
            root.verifying_key(),
            CapabilityMode::InvokeAndDelegate,
            None,
        );
        let future_access = read_bundle(
            &root,
            legacy.source.handle(),
            reader.verifying_key(),
            CapabilityMode::Invoke,
            Some(future),
        );
        let write = write_bundle(&root, legacy.source.handle());
        publish_legacy_envelope(
            &mut pile,
            &root,
            &legacy.custody,
            legacy.source.handle(),
            &root_access,
            &write,
        );
        publish_legacy_envelope(
            &mut pile,
            &root,
            &legacy.custody,
            legacy.source.handle(),
            &future_access,
            &write,
        );
        pile.close().unwrap();

        let report = publish_path(
            &path,
            Some(&key_path),
            &[legacy.source.handle()],
            Some(legacy.target.handle()),
        )
        .unwrap();
        assert_eq!(report.ensured_proof_closures, 1);
        assert_eq!(report.plan.current_readers, 1);
        assert_eq!(report.plan.missing_recipient_wraps, 1);

        let mut pile = open_pile_strict(&path).unwrap();
        let snapshot = pile.snapshot().unwrap();
        let facts = legacy.target.read::<TribleSet, _>(&snapshot).unwrap();
        assert!(
            recipient_wraps(&facts, legacy.secret, reader.verifying_key().to_bytes()).is_empty()
        );
        let audience = triblespace::core::collection::collection_read_audience_at(
            &snapshot,
            legacy.target.handle(),
            lower,
        )
        .unwrap();
        assert!(matches!(
            audience,
            CollectionReadAudience::Restricted(readers)
                if readers.contains(&reader.verifying_key())
        ));
        let translated = resident_proof_bundles(&snapshot)
            .unwrap()
            .into_iter()
            .filter_map(|bundle| {
                structural_prefixes(
                    &bundle,
                    root.verifying_key(),
                    collection_atom(ACTION_READ, legacy.target.handle()),
                )
                .ok()
            })
            .flatten()
            .collect::<Vec<_>>();
        assert!(translated.iter().any(|prefix| {
            prefix.subject == reader.verifying_key()
                && prefix.mode == CapabilityMode::Invoke
                && prefix.validity == Some(future)
        }));
        drop(snapshot);

        let activated = publish_open(
            &mut pile,
            &root,
            &[legacy.source.handle()],
            Some(legacy.target.handle()),
            lower,
        )
        .unwrap();
        assert_eq!(activated.appended_commits, 1);
        assert_eq!(activated.ensured_proof_closures, 0);
        assert_eq!(activated.plan.missing_recipient_wraps, 1);
        let snapshot = pile.snapshot().unwrap();
        let facts = legacy.target.read::<TribleSet, _>(&snapshot).unwrap();
        assert_eq!(
            open_version_from_facts(&snapshot, &facts, legacy.secret, &reader).unwrap(),
            b"unchanged ciphertext"
        );
        drop(snapshot);
        pile.close().unwrap();
    }
}
