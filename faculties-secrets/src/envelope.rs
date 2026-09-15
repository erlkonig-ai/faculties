//! Recipient envelopes whose encrypted payload binds the DEK to its authority.
//!
//! The sealed payload is S | H | R | DEK. A separate DEK-derived authenticator
//! covers the recipient and sealed bytes, so a holder can recognize a delivery
//! to somebody else without opening it. Shape alone is never delivery evidence.

use dryoc::classic::crypto_auth::{crypto_auth, crypto_auth_verify};
use dryoc::classic::crypto_kdf::crypto_kdf_derive_from_key;

use super::*;
use crate::schema::BOUND_ENVELOPE_MAGIC;

const PAYLOAD_BYTES: usize = 16 + 32 + 32 + 32;
const SEALED_BYTES: usize = 48 + PAYLOAD_BYTES;
const AUTHENTICATOR_BYTES: usize = 32;
const ENVELOPE_BYTES: usize = 16 + SEALED_BYTES + AUTHENTICATOR_BYTES;

/// A recovered binding is kept with the key that authenticated its ciphertext.
/// Never select a delivery policy by joining this DEK to mutable union facts.
pub(crate) struct BoundKey {
    pub secret: Id,
    pub body: BytesHandle,
    pub resource: CollectionHandle,
    pub dek: Key,
}

fn authentication_key(dek: &Key) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0; 32]);
    // The format's minted 128 bits provide the independent KDF domain.
    let context = BOUND_ENVELOPE_MAGIC[..8].try_into().expect("eight bytes");
    let subkey_id = u64::from_le_bytes(BOUND_ENVELOPE_MAGIC[8..].try_into().unwrap());
    crypto_kdf_derive_from_key(&mut key[..], subkey_id, &context, dek.as_array())
        .map_err(|error| anyhow!("derive envelope authentication key: {error}"))?;
    Ok(key)
}

fn authenticated_message(
    binding: &BoundKey,
    recipient: RecipientPublicKey,
    sealed: &[u8],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(16 + 16 + 32 + 32 + 32 + sealed.len());
    message.extend_from_slice(&BOUND_ENVELOPE_MAGIC);
    message.extend_from_slice(&binding.secret.raw());
    message.extend_from_slice(&binding.body.raw);
    message.extend_from_slice(&binding.resource.raw);
    message.extend_from_slice(&recipient);
    message.extend_from_slice(sealed);
    message
}

pub(crate) fn sealed_payload(bytes: &[u8]) -> Option<&[u8]> {
    (bytes.len() == ENVELOPE_BYTES && bytes.starts_with(&BOUND_ENVELOPE_MAGIC))
        .then(|| &bytes[16..16 + SEALED_BYTES])
}

pub(crate) fn authenticates(
    binding: &BoundKey,
    recipient: RecipientPublicKey,
    bytes: &[u8],
) -> bool {
    let Some(sealed) = sealed_payload(bytes) else {
        return false;
    };
    let Ok(key) = authentication_key(&binding.dek) else {
        return false;
    };
    let tag = bytes[16 + SEALED_BYTES..]
        .try_into()
        .expect("fixed tag length");
    crypto_auth_verify(
        &tag,
        &authenticated_message(binding, recipient, sealed),
        &key,
    )
    .is_ok()
}

pub(crate) fn seal(binding: &BoundKey, recipient: RecipientPublicKey) -> Result<Vec<u8>> {
    let mut payload = Zeroizing::new(Vec::with_capacity(PAYLOAD_BYTES));
    payload.extend_from_slice(&binding.secret.raw());
    payload.extend_from_slice(&binding.body.raw);
    payload.extend_from_slice(&binding.resource.raw);
    payload.extend_from_slice(&binding.dek);
    let sealed = DryocBox::seal_to_vecbox(&payload[..], &box_pk_from_ed25519(&recipient)?)
        .map_err(|error| anyhow!("seal bound DEK: {error}"))?
        .to_vec();
    let mut tag = [0; AUTHENTICATOR_BYTES];
    crypto_auth(
        &mut tag,
        &authenticated_message(binding, recipient, &sealed),
        &*authentication_key(&binding.dek)?,
    );
    let mut bytes = Vec::with_capacity(ENVELOPE_BYTES);
    bytes.extend_from_slice(&BOUND_ENVELOPE_MAGIC);
    bytes.extend_from_slice(&sealed);
    bytes.extend_from_slice(&tag);
    Ok(bytes)
}

pub(crate) fn open(
    bytes: &[u8],
    secret: Id,
    keypair: &BoxKeyPair,
    recipient: RecipientPublicKey,
) -> Option<BoundKey> {
    let sealed = sealed_payload(bytes)?;
    let boxed: dryoc::dryocbox::VecBox = DryocBox::from_sealed_bytes(sealed).ok()?;
    let payload = Zeroizing::new(boxed.unseal_to_vec(keypair).ok()?);
    if payload.len() != PAYLOAD_BYTES || payload[..16] != secret.raw() {
        return None;
    }
    let binding = BoundKey {
        secret,
        body: BytesHandle::new(payload[16..48].try_into().ok()?),
        resource: CollectionHandle::new(payload[48..80].try_into().ok()?),
        dek: Key::try_from(&payload[80..112]).ok()?,
    };
    authenticates(&binding, recipient, bytes).then_some(binding)
}

pub(crate) fn fragment(binding: &BoundKey, recipient: RecipientPublicKey) -> Result<Fragment> {
    let mut fragment = Fragment::empty();
    let handle = fragment.put::<blobencodings::RawBytes, _>(seal(binding, recipient)?);
    fragment += wrap_record(genid().id, binding.secret, recipient, handle);
    Ok(fragment)
}

pub(crate) fn decrypt_body<R: BlobStoreGet>(
    reader: &R,
    body: BytesHandle,
    dek: &Key,
) -> Result<Zeroizing<Vec<u8>>> {
    let body = read_bytes(reader, body)?;
    validate_encrypted_body(&body)?;
    let nonce = Nonce::try_from(&body[..24]).context("secret nonce")?;
    let boxed: dryoc::dryocsecretbox::VecBox = DryocSecretBox::from_bytes(&body[24..])
        .map_err(|error| anyhow!("parse secret ciphertext: {error}"))?;
    boxed
        .decrypt_to_vec(&nonce, dek)
        .map(Zeroizing::new)
        .map_err(|error| anyhow!("open secret ciphertext: {error}"))
}

/// Recover only bound envelopes whose DEK actually opens their exact body.
/// Unrelated or malicious wraps are nonmatching rows, not a veto on the rest.
pub(crate) fn recover<R: BlobStoreGet, P: TriblePattern>(
    reader: &R,
    facts: &P,
    secret: Id,
    holder: &SigningKey,
) -> Result<Vec<BoundKey>> {
    let recipient = holder.verifying_key().to_bytes();
    let keypair = box_keypair_from_signing_key(holder)?;
    let mut seen = BTreeSet::new();
    let mut bindings = Vec::new();
    for wrap in recipient_wraps(facts, secret, recipient) {
        let Ok(bytes) = read_bytes(reader, wrap.sealed_dek) else {
            continue;
        };
        let Some(binding) = open(&bytes, secret, &keypair, recipient) else {
            continue;
        };
        if seen.contains(&(binding.body, binding.resource))
            || decrypt_body(reader, binding.body, &binding.dek).is_err()
        {
            continue;
        }
        seen.insert((binding.body, binding.resource));
        bindings.push(binding);
    }
    Ok(bindings)
}

pub(crate) fn missing<R, P>(
    reader: &R,
    facts: &P,
    binding: &BoundKey,
    recipients: impl IntoIterator<Item = VerifyingKey>,
) -> Result<RecipientEnvelopes>
where
    R: BlobStoreGet,
    P: TriblePattern,
{
    let mut fragment = Fragment::empty();
    let mut added = Vec::new();
    for recipient in deduplicated_recipients(recipients) {
        let delivered = recipient_wraps(facts, binding.secret, recipient)
            .into_iter()
            .any(|wrap| {
                read_bytes(reader, wrap.sealed_dek)
                    .is_ok_and(|bytes| authenticates(binding, recipient, &bytes))
            });
        if !delivered {
            fragment += self::fragment(binding, recipient)?;
            added.push(VerifyingKey::from_bytes(&recipient).expect("validated recipient"));
        }
    }
    Ok(RecipientEnvelopes {
        fragment,
        recipients: added,
    })
}
