//! Subject-specific delivery of one vault epoch's custody seed.
//!
//! An access envelope is deliberately not an authority record. It names the
//! exact `READ` and `WRITE` credentials whose complete proof blobs travel with
//! the fragment, and seals the custody seed to one direct Ed25519 subject.
//! Both proofs are reconstructed by exact handles and verified afresh at the
//! caller's explicit instant before any opened seed is accepted.

use anyhow::{anyhow, bail, Context, Result};
use dryoc::classic::crypto_sign_ed25519::{
    crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519,
};
use dryoc::dryocbox::{DryocBox, KeyPair as BoxKeyPair, PublicKey as BoxPublicKey};
use dryoc::types::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hifitime::Epoch;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::Blob;
use triblespace::core::capability::{
    CapabilityAction, CapabilityAtom, CapabilityBlobHandle, CapabilityClaim, CapabilityGrant,
    CapabilityMode, CapabilityProof, CapabilityResource,
};
use triblespace::core::collection::{CollectionHandle, ACTION_WRITE};
use triblespace::core::metadata;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::*;
use zeroize::Zeroizing;

use crate::schema::{
    access_read_credential, access_sealed_seed, access_vault, access_write_credential,
    custody_public_key, KIND_ACCESS_ENVELOPE,
};

const FRAME_WORD_BYTES: usize = 32;
const FRAME_WORDS: usize = 6;
const FRAME_BYTES: usize = 16 + FRAME_WORDS * FRAME_WORD_BYTES;
const SEALED_BOX_OVERHEAD_BYTES: usize = 48;
const SEALED_FRAME_BYTES: usize = FRAME_BYTES + SEALED_BOX_OVERHEAD_BYTES;

type BytesHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;

/// One closed, content-derived access-envelope record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessEnvelopeRow {
    /// Intrinsic identity derived from the other six facts.
    pub id: Id,
    /// Public half of the delivered vault custody keypair.
    pub custody_public_key: VerifyingKey,
    /// Exact private vault descriptor governed by both credentials.
    pub vault: CollectionHandle,
    /// Exact leaf-signature credential proving `READ(vault)` for the recipient.
    pub read_credential: CapabilityBlobHandle,
    /// Exact leaf-signature credential proving `WRITE(vault)` for `writer`.
    pub write_credential: CapabilityBlobHandle,
    /// Recipient-sealed, context-bound custody seed attachment.
    pub sealed_seed: BytesHandle,
}

/// Result of opening and revalidating one access envelope.
pub struct OpenedAccessEnvelope {
    /// Recovered vault-epoch custody keypair.
    pub custody: SigningKey,
    /// Exact reconstructed and verified `READ` proof.
    pub read_proof: CapabilityProof,
    /// Verified issuer of the leaf `READ` grant. The inbox COMMIT carrying
    /// this envelope must be signed by this key.
    pub read_issuer: VerifyingKey,
    /// Exact reconstructed and verified `WRITE` proof.
    pub write_proof: CapabilityProof,
    /// Verified leaf subject of `write_proof`.
    pub writer: VerifyingKey,
}

fn read_atom(vault: CollectionHandle) -> CapabilityAtom {
    CapabilityAtom::new(
        CapabilityAction::new(crate::ACTION_READ),
        CapabilityResource::from(vault),
    )
}

fn write_atom(vault: CollectionHandle) -> CapabilityAtom {
    CapabilityAtom::new(
        CapabilityAction::new(ACTION_WRITE),
        CapabilityResource::from(vault),
    )
}

fn envelope_record(
    custody: VerifyingKey,
    vault: CollectionHandle,
    read_credential: CapabilityBlobHandle,
    write_credential: CapabilityBlobHandle,
    sealed_seed: BytesHandle,
) -> Fragment {
    let custody = Inline::<inlineencodings::ED25519PublicKey>::new(custody.to_bytes());
    entity! { _ @
        metadata::tag: &KIND_ACCESS_ENVELOPE,
        custody_public_key: custody,
        access_vault: vault,
        access_read_credential: read_credential,
        access_write_credential: write_credential,
        access_sealed_seed: sealed_seed,
    }
}

fn proof_leaf_subject(proof: &CapabilityProof, label: &str) -> Result<VerifyingKey> {
    let step = proof
        .steps()
        .last()
        .ok_or_else(|| anyhow!("{label} proof is empty"))?;
    CapabilityGrant::from_blob(step.claim().clone())
        .with_context(|| format!("decode {label} proof leaf claim"))
        .map(CapabilityGrant::subject)
}

/// Verified signer who issued the leaf grant in one proof chain.
///
/// A root leaf is issued by the external trust root. A delegated leaf is
/// issued by the subject of its immediately preceding grant.
pub fn read_proof_issuer(
    proof: &CapabilityProof,
    trust_root: VerifyingKey,
    label: &str,
) -> Result<VerifyingKey> {
    match proof.steps() {
        [] => bail!("{label} proof is empty"),
        [_root] => Ok(trust_root),
        steps => CapabilityGrant::from_blob(steps[steps.len() - 2].claim().clone())
            .with_context(|| format!("decode {label} proof parent claim"))
            .map(CapabilityGrant::subject),
    }
}

fn insert_proof_blobs(fragment: &mut Fragment, proof: &CapabilityProof) {
    for step in proof.steps() {
        fragment.put::<SimpleArchive, _>(step.claim().clone());
        fragment.put::<SimpleArchive, _>(step.signature().clone());
    }
}

fn box_public_key(public: &VerifyingKey) -> Result<BoxPublicKey> {
    let mut converted = [0u8; 32];
    crypto_sign_ed25519_pk_to_curve25519(&mut converted, &public.to_bytes())
        .map_err(|error| anyhow!("recipient public-key conversion: {error:?}"))?;
    BoxPublicKey::try_from(&converted[..])
        .map_err(|error| anyhow!("recipient X25519 public key: {error:?}"))
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

fn frame(
    vault: CollectionHandle,
    custody: &SigningKey,
    read_credential: CapabilityBlobHandle,
    subject: VerifyingKey,
    write_credential: CapabilityBlobHandle,
) -> Zeroizing<Vec<u8>> {
    let seed = Zeroizing::new(custody.to_bytes());
    let mut frame = Zeroizing::new(Vec::with_capacity(FRAME_BYTES));
    frame.extend_from_slice(&crate::ACCESS_ENVELOPE_FORMAT_V1.raw());
    frame.extend_from_slice(&vault.raw);
    frame.extend_from_slice(&custody.verifying_key().to_bytes());
    frame.extend_from_slice(&read_credential.raw);
    frame.extend_from_slice(&subject.to_bytes());
    frame.extend_from_slice(&write_credential.raw);
    frame.extend_from_slice(seed.as_slice());
    debug_assert_eq!(frame.len(), FRAME_BYTES);
    frame
}

/// Build one self-contained, subject-specific access envelope.
///
/// Both supplied proofs are verified against the exact vault before the
/// custody seed is sealed. The returned fragment owns every claim and
/// signature blob in both proof chains plus the sealed seed attachment.
#[allow(clippy::too_many_arguments)]
pub fn build_access_envelope(
    vault: CollectionHandle,
    custody: &SigningKey,
    subject: VerifyingKey,
    read_proof: &CapabilityProof,
    writer: VerifyingKey,
    write_proof: &CapabilityProof,
    trust_root: VerifyingKey,
    instant: Epoch,
) -> Result<Fragment> {
    let read_credential = read_proof
        .credential()
        .ok_or_else(|| anyhow!("READ proof is empty"))?;
    let write_credential = write_proof
        .credential()
        .ok_or_else(|| anyhow!("WRITE proof is empty"))?;

    read_proof
        .verify_claim(
            trust_root,
            instant,
            CapabilityClaim::new(subject, read_atom(vault), CapabilityMode::Invoke),
        )
        .context("verify exact READ proof before sealing custody seed")?;
    let verified_write = write_proof
        .verify_claim(
            trust_root,
            instant,
            CapabilityClaim::new(writer, write_atom(vault), CapabilityMode::Invoke),
        )
        .context("verify exact WRITE proof before sealing custody seed")?;
    if verified_write.effective_validity().is_some() {
        bail!("vault WRITE proof must be unbounded so historical commits remain materializable");
    }

    let plaintext = frame(vault, custody, read_credential, subject, write_credential);
    let recipient = box_public_key(&subject)?;
    let sealed = DryocBox::seal_to_vecbox(plaintext.as_slice(), &recipient)
        .map_err(|error| anyhow!("seal custody seed to access subject: {error:?}"))?
        .to_vec();
    if sealed.len() != SEALED_FRAME_BYTES {
        bail!(
            "sealed access frame has {} bytes; expected {SEALED_FRAME_BYTES}",
            sealed.len()
        );
    }

    let mut fragment = Fragment::empty();
    insert_proof_blobs(&mut fragment, read_proof);
    insert_proof_blobs(&mut fragment, write_proof);
    let sealed_seed = fragment.put::<blobencodings::RawBytes, _>(sealed);
    fragment += envelope_record(
        custody.verifying_key(),
        vault,
        read_credential,
        write_credential,
        sealed_seed,
    );
    Ok(fragment)
}

fn exactly_one<T>(id: Id, field: &str, mut values: Vec<T>) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "access envelope {id:x} has {} values for {field}; expected exactly one",
            values.len()
        );
    }
    Ok(values.pop().expect("length checked above"))
}

fn entity_facts(space: &TribleSet, entity: Id) -> TribleSet {
    let mut facts = TribleSet::new();
    for fact in space.iter().filter(|fact| fact.e() == &entity) {
        facts.insert(fact);
    }
    facts
}

/// Strictly load one closed intrinsic envelope row from an inbox fact set.
///
/// Facts belonging to other entities are ignored; every fact on `id` must be
/// exactly one of the six canonical envelope facts, and `id` must be the
/// intrinsic identity recomputed from those facts.
pub fn load_access_envelope(space: &TribleSet, id: Id) -> Result<AccessEnvelopeRow> {
    let custody = exactly_one(
        id,
        "custody_public_key",
        find!(
            value: Inline<inlineencodings::ED25519PublicKey>,
            pattern!(space, [{ id @ custody_public_key: ?value }])
        )
        .collect(),
    )?;
    let custody_key = VerifyingKey::from_bytes(&custody.raw)
        .context("access envelope has an invalid custody Ed25519 public key")?;
    let row = AccessEnvelopeRow {
        id,
        custody_public_key: custody_key,
        vault: exactly_one(
            id,
            "access_vault",
            find!(
                value: CollectionHandle,
                pattern!(space, [{ id @ access_vault: ?value }])
            )
            .collect(),
        )?,
        read_credential: exactly_one(
            id,
            "access_read_credential",
            find!(
                value: CapabilityBlobHandle,
                pattern!(space, [{ id @ access_read_credential: ?value }])
            )
            .collect(),
        )?,
        write_credential: exactly_one(
            id,
            "access_write_credential",
            find!(
                value: CapabilityBlobHandle,
                pattern!(space, [{ id @ access_write_credential: ?value }])
            )
            .collect(),
        )?,
        sealed_seed: exactly_one(
            id,
            "access_sealed_seed",
            find!(
                value: BytesHandle,
                pattern!(space, [{ id @ access_sealed_seed: ?value }])
            )
            .collect(),
        )?,
    };
    let canonical = envelope_record(
        row.custody_public_key,
        row.vault,
        row.read_credential,
        row.write_credential,
        row.sealed_seed,
    );
    if canonical.root() != Some(id) || entity_facts(space, id) != *canonical.facts() {
        bail!("access envelope {id:x} is not one canonical intrinsic record");
    }
    Ok(row)
}

fn load_proof<R: BlobStoreGet>(
    reader: &R,
    credential: CapabilityBlobHandle,
    label: &str,
) -> Result<CapabilityProof> {
    CapabilityProof::load(credential, |handle| {
        let result: std::result::Result<Blob<SimpleArchive>, _> = reader.get(handle);
        result
            .map(Some)
            .map_err(|error| anyhow!("read {label} proof blob: {error}"))
    })
    .map_err(|error| anyhow!("load exact {label} proof: {error}"))
}

fn take_word(bytes: &[u8], offset: &mut usize) -> [u8; FRAME_WORD_BYTES] {
    let mut word = [0u8; FRAME_WORD_BYTES];
    let end = *offset + FRAME_WORD_BYTES;
    word.copy_from_slice(&bytes[*offset..end]);
    *offset = end;
    word
}

/// Open one row for `recipient` and revalidate all of its authority and sealed
/// context at one explicit instant.
pub fn open_access_envelope<R: BlobStoreGet>(
    reader: &R,
    row: &AccessEnvelopeRow,
    recipient: &SigningKey,
    trust_root: VerifyingKey,
    instant: Epoch,
) -> Result<OpenedAccessEnvelope> {
    let read_proof = load_proof(reader, row.read_credential, "READ")?;
    let subject = recipient.verifying_key();
    read_proof
        .verify_claim(
            trust_root,
            instant,
            CapabilityClaim::new(subject, read_atom(row.vault), CapabilityMode::Invoke),
        )
        .context("verify access-envelope READ proof")?;
    let read_issuer = read_proof_issuer(&read_proof, trust_root, "READ")?;

    let write_proof = load_proof(reader, row.write_credential, "WRITE")?;
    let writer = proof_leaf_subject(&write_proof, "WRITE")?;
    let verified_write = write_proof
        .verify_claim(
            trust_root,
            instant,
            CapabilityClaim::new(writer, write_atom(row.vault), CapabilityMode::Invoke),
        )
        .context("verify access-envelope WRITE proof")?;
    if verified_write.effective_validity().is_some() {
        bail!("vault WRITE proof must be unbounded so historical commits remain materializable");
    }

    let sealed: anybytes::Bytes = reader
        .get(row.sealed_seed)
        .context("read access-envelope sealed seed attachment")?;
    if sealed.len() != SEALED_FRAME_BYTES {
        bail!(
            "sealed access frame has {} bytes; expected {SEALED_FRAME_BYTES}",
            sealed.len()
        );
    }
    let recipient_box = box_keypair(recipient)?;
    let plaintext = Zeroizing::new(
        DryocBox::from_sealed_bytes(sealed.as_ref())
            .map_err(|error| anyhow!("parse sealed access frame: {error:?}"))?
            .unseal_to_vec(&recipient_box)
            .map_err(|_| anyhow!("unseal access frame for recipient failed"))?,
    );
    if plaintext.len() != FRAME_BYTES {
        bail!(
            "opened access frame has {} bytes; expected {FRAME_BYTES}",
            plaintext.len()
        );
    }
    let magic = crate::ACCESS_ENVELOPE_FORMAT_V1.raw();
    if plaintext[..magic.len()] != magic {
        bail!("opened access frame has an unknown format marker");
    }
    let mut offset = magic.len();
    let bound_vault = Inline::new(take_word(&plaintext, &mut offset));
    let bound_custody = VerifyingKey::from_bytes(&take_word(&plaintext, &mut offset))
        .context("opened access frame has an invalid custody public key")?;
    let bound_read = Inline::new(take_word(&plaintext, &mut offset));
    let bound_subject = VerifyingKey::from_bytes(&take_word(&plaintext, &mut offset))
        .context("opened access frame has an invalid subject public key")?;
    let bound_write = Inline::new(take_word(&plaintext, &mut offset));
    let custody_seed = Zeroizing::new(take_word(&plaintext, &mut offset));
    debug_assert_eq!(offset, plaintext.len());

    if bound_vault != row.vault {
        bail!("opened access frame is bound to a different vault");
    }
    if bound_custody != row.custody_public_key {
        bail!("opened access frame is bound to a different custody key");
    }
    if bound_read != row.read_credential {
        bail!("opened access frame is bound to a different READ credential");
    }
    if bound_subject != subject {
        bail!("opened access frame is bound to a different recipient");
    }
    if bound_write != row.write_credential {
        bail!("opened access frame is bound to a different WRITE credential");
    }
    let custody = SigningKey::from_bytes(&custody_seed);
    if custody.verifying_key() != row.custody_public_key {
        bail!("opened custody seed does not match the declared custody public key");
    }

    Ok(OpenedAccessEnvelope {
        custody,
        read_proof,
        read_issuer,
        write_proof,
        writer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use triblespace::core::capability::{CapabilityGrant, CapabilityProofStep};
    use triblespace::core::repo::BlobStore;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn root_proof(
        root: &SigningKey,
        subject: VerifyingKey,
        atom: CapabilityAtom,
    ) -> CapabilityProof {
        CapabilityProof::new(vec![CapabilityProofStep::issue(
            root,
            CapabilityGrant::root(subject, atom, CapabilityMode::Invoke, None),
        )])
    }

    #[test]
    fn envelope_round_trip_is_intrinsic_self_contained_and_context_bound() {
        let root = key(1);
        let subject = key(2);
        let writer = key(3);
        let custody = key(4);
        let vault = Inline::new([5; 32]);
        let read = root_proof(&root, subject.verifying_key(), read_atom(vault));
        let write = root_proof(&root, writer.verifying_key(), write_atom(vault));
        let instant = Epoch::from_tai_seconds(0.0);

        let fragment = build_access_envelope(
            vault,
            &custody,
            subject.verifying_key(),
            &read,
            writer.verifying_key(),
            &write,
            root.verifying_key(),
            instant,
        )
        .expect("build envelope");
        let id = fragment.root().expect("intrinsic row root");
        let (_, facts, _, mut blobs) = fragment.into_parts();
        let row = load_access_envelope(&facts, id).expect("strict row");
        let reader = blobs.reader().expect("blob snapshot");
        let opened = open_access_envelope(&reader, &row, &subject, root.verifying_key(), instant)
            .expect("open envelope");

        assert_eq!(opened.custody.to_bytes(), custody.to_bytes());
        assert_eq!(opened.writer, writer.verifying_key());
        assert_eq!(opened.read_issuer, root.verifying_key());
        assert_eq!(opened.read_proof, read);
        assert_eq!(opened.write_proof, write);
    }

    #[test]
    fn wrong_recipient_cannot_open_even_with_the_inbox_facts() {
        let root = key(11);
        let subject = key(12);
        let writer = key(13);
        let custody = key(14);
        let vault = Inline::new([15; 32]);
        let read = root_proof(&root, subject.verifying_key(), read_atom(vault));
        let write = root_proof(&root, writer.verifying_key(), write_atom(vault));
        let instant = Epoch::from_tai_seconds(0.0);
        let fragment = build_access_envelope(
            vault,
            &custody,
            subject.verifying_key(),
            &read,
            writer.verifying_key(),
            &write,
            root.verifying_key(),
            instant,
        )
        .expect("build envelope");
        let id = fragment.root().expect("intrinsic row root");
        let (_, facts, _, mut blobs) = fragment.into_parts();
        let row = load_access_envelope(&facts, id).expect("strict row");
        let reader = blobs.reader().expect("blob snapshot");

        assert!(
            open_access_envelope(&reader, &row, &key(16), root.verifying_key(), instant,).is_err()
        );
    }
}
