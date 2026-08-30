//! Subject-specific delivery of one vault epoch's custody seed.
//!
//! An access envelope is deliberately not an authority record. It names the
//! exact complete `READ` and `WRITE` proof identities, and seals the custody
//! seed to one direct Ed25519 subject. Both proof bundles are supplied
//! explicitly and verified afresh at the caller's instant before any opened
//! seed is accepted.

use anyhow::{anyhow, bail, Context, Result};
use dryoc::classic::crypto_sign_ed25519::{
    crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519,
};
use dryoc::dryocbox::{DryocBox, KeyPair as BoxKeyPair, PublicKey as BoxPublicKey};
use dryoc::types::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hifitime::Epoch;
use triblespace::core::capability::{
    CapabilityAction, CapabilityAtom, CapabilityMode, CapabilityProofBundle, CapabilityProofId,
    CapabilityRequest, CapabilityResource,
};
use triblespace::core::collection::{CollectionHandle, ACTION_WRITE};
use triblespace::core::metadata;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::*;
use zeroize::Zeroizing;

use crate::schema::{
    access_read_proof, access_sealed_seed, access_vault, access_write_proof, custody_public_key,
    KIND_ACCESS_ENVELOPE,
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
    /// Exact private vault descriptor governed by both proofs.
    pub vault: CollectionHandle,
    /// Exact identity of the complete `READ(vault)` proof.
    pub read_proof: CapabilityProofId,
    /// Exact identity of the complete `WRITE(vault)` proof.
    pub write_proof: CapabilityProofId,
    /// Recipient-sealed, context-bound custody seed attachment.
    pub sealed_seed: BytesHandle,
}

/// Result of opening and revalidating one access envelope.
pub struct OpenedAccessEnvelope {
    /// Recovered vault-epoch custody keypair.
    pub custody: SigningKey,
    /// Exact reconstructed and verified `READ` proof bundle.
    pub read_bundle: CapabilityProofBundle,
    /// Verified issuer of the leaf `READ` grant. The inbox COMMIT carrying
    /// this envelope must be signed by this key.
    pub read_issuer: VerifyingKey,
    /// Exact reconstructed and verified `WRITE` proof bundle.
    pub write_bundle: CapabilityProofBundle,
    /// Verified leaf subject of `write_bundle`.
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
    read_proof: CapabilityProofId,
    write_proof: CapabilityProofId,
    sealed_seed: BytesHandle,
) -> Fragment {
    let custody = Inline::<inlineencodings::ED25519PublicKey>::new(custody.to_bytes());
    entity! { _ @
        metadata::tag: &KIND_ACCESS_ENVELOPE,
        custody_public_key: custody,
        access_vault: vault,
        access_read_proof: read_proof,
        access_write_proof: write_proof,
        access_sealed_seed: sealed_seed,
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
    read_proof: CapabilityProofId,
    subject: VerifyingKey,
    write_proof: CapabilityProofId,
) -> Zeroizing<Vec<u8>> {
    let seed = Zeroizing::new(custody.to_bytes());
    let mut frame = Zeroizing::new(Vec::with_capacity(FRAME_BYTES));
    frame.extend_from_slice(&crate::ACCESS_ENVELOPE_FORMAT_V1.raw());
    frame.extend_from_slice(&vault.raw);
    frame.extend_from_slice(&custody.verifying_key().to_bytes());
    frame.extend_from_slice(&read_proof.raw);
    frame.extend_from_slice(&subject.to_bytes());
    frame.extend_from_slice(&write_proof.raw);
    frame.extend_from_slice(seed.as_slice());
    debug_assert_eq!(frame.len(), FRAME_BYTES);
    frame
}

/// Build one subject-specific access envelope.
///
/// Both supplied bundles are verified against the exact vault before the
/// custody seed is sealed. The returned fragment owns the sealed seed and
/// envelope row only; the storage boundary must persist each accepted claim
/// closure followed by its native proof record before publishing the fragment.
#[allow(clippy::too_many_arguments)]
pub fn build_access_envelope(
    vault: CollectionHandle,
    custody: &SigningKey,
    subject: VerifyingKey,
    read_bundle: &CapabilityProofBundle,
    writer: VerifyingKey,
    write_bundle: &CapabilityProofBundle,
    trust_root: VerifyingKey,
    instant: Epoch,
) -> Result<Fragment> {
    let read_proof = read_bundle.proof().id();
    let write_proof = write_bundle.proof().id();
    read_bundle
        .verify(
            trust_root,
            instant,
            subject,
            CapabilityRequest::new(read_atom(vault), CapabilityMode::Invoke),
        )
        .context("verify exact READ proof before sealing custody seed")?;
    let verified_write = write_bundle
        .verify(
            trust_root,
            instant,
            writer,
            CapabilityRequest::new(write_atom(vault), CapabilityMode::Invoke),
        )
        .context("verify exact WRITE proof before sealing custody seed")?;
    if verified_write.effective_validity().is_some() {
        bail!("vault WRITE proof must be unbounded so historical commits remain materializable");
    }

    let plaintext = frame(vault, custody, read_proof, subject, write_proof);
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
    let sealed_seed = fragment.put::<blobencodings::RawBytes, _>(sealed);
    fragment += envelope_record(
        custody.verifying_key(),
        vault,
        read_proof,
        write_proof,
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
        read_proof: exactly_one(
            id,
            "access_read_proof",
            find!(
                value: CapabilityProofId,
                pattern!(space, [{ id @ access_read_proof: ?value }])
            )
            .collect(),
        )?,
        write_proof: exactly_one(
            id,
            "access_write_proof",
            find!(
                value: CapabilityProofId,
                pattern!(space, [{ id @ access_write_proof: ?value }])
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
        row.read_proof,
        row.write_proof,
        row.sealed_seed,
    );
    if canonical.root() != Some(id) || entity_facts(space, id) != *canonical.facts() {
        bail!("access envelope {id:x} is not one canonical intrinsic record");
    }
    Ok(row)
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
    read_bundle: CapabilityProofBundle,
    write_bundle: CapabilityProofBundle,
) -> Result<OpenedAccessEnvelope> {
    if read_bundle.proof().id() != row.read_proof {
        bail!("supplied READ bundle does not match the envelope proof id");
    }
    if write_bundle.proof().id() != row.write_proof {
        bail!("supplied WRITE bundle does not match the envelope proof id");
    }
    let subject = recipient.verifying_key();
    read_bundle
        .verify(
            trust_root,
            instant,
            subject,
            CapabilityRequest::new(read_atom(row.vault), CapabilityMode::Invoke),
        )
        .context("verify access-envelope READ proof")?;
    let read_issuer = read_bundle.proof().leaf_issuer();

    let writer = write_bundle.proof().leaf_key();
    let verified_write = write_bundle
        .verify(
            trust_root,
            instant,
            writer,
            CapabilityRequest::new(write_atom(row.vault), CapabilityMode::Invoke),
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
    if bound_read != row.read_proof {
        bail!("opened access frame is bound to a different READ proof");
    }
    if bound_subject != subject {
        bail!("opened access frame is bound to a different recipient");
    }
    if bound_write != row.write_proof {
        bail!("opened access frame is bound to a different WRITE proof");
    }
    let custody = SigningKey::from_bytes(&custody_seed);
    if custody.verifying_key() != row.custody_public_key {
        bail!("opened custody seed does not match the declared custody public key");
    }

    Ok(OpenedAccessEnvelope {
        custody,
        read_bundle,
        read_issuer,
        write_bundle,
        writer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use triblespace::core::capability::CapabilityClaim;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn root_bundle(
        root: &SigningKey,
        subject: VerifyingKey,
        atom: CapabilityAtom,
    ) -> CapabilityProofBundle {
        CapabilityProofBundle::issue_root(
            root,
            CapabilityClaim::root(atom, CapabilityMode::Invoke, None),
            subject,
        )
        .expect("issue root bundle")
    }

    #[test]
    fn envelope_round_trip_is_intrinsic_exact_and_context_bound() {
        let root = key(1);
        let subject = key(2);
        let writer = key(3);
        let custody = key(4);
        let vault = Inline::new([5; 32]);
        let read = root_bundle(&root, subject.verifying_key(), read_atom(vault));
        let write = root_bundle(&root, writer.verifying_key(), write_atom(vault));
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
        let reader = blobs.snapshot().expect("blob snapshot");
        let opened = open_access_envelope(
            &reader,
            &row,
            &subject,
            root.verifying_key(),
            instant,
            read.clone(),
            write.clone(),
        )
        .expect("open envelope");

        assert_eq!(opened.custody.to_bytes(), custody.to_bytes());
        assert_eq!(opened.writer, writer.verifying_key());
        assert_eq!(opened.read_issuer, root.verifying_key());
        assert_eq!(opened.read_bundle, read);
        assert_eq!(opened.write_bundle, write);

        let alternate_read = CapabilityProofBundle::issue_root(
            &root,
            CapabilityClaim::root(read_atom(vault), CapabilityMode::InvokeAndDelegate, None),
            subject.verifying_key(),
        )
        .expect("issue alternate READ bundle");
        let error = open_access_envelope(
            &reader,
            &row,
            &subject,
            root.verifying_key(),
            instant,
            alternate_read,
            write.clone(),
        )
        .err()
        .expect("a different valid proof must not satisfy the exact envelope id");
        assert!(error
            .to_string()
            .contains("does not match the envelope proof id"));
    }

    #[test]
    fn wrong_recipient_cannot_open_even_with_the_inbox_facts() {
        let root = key(11);
        let subject = key(12);
        let writer = key(13);
        let custody = key(14);
        let vault = Inline::new([15; 32]);
        let read = root_bundle(&root, subject.verifying_key(), read_atom(vault));
        let write = root_bundle(&root, writer.verifying_key(), write_atom(vault));
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
        let reader = blobs.snapshot().expect("blob snapshot");

        assert!(open_access_envelope(
            &reader,
            &row,
            &key(16),
            root.verifying_key(),
            instant,
            read,
            write,
        )
        .is_err());
    }
}
