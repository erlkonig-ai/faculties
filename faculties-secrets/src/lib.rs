//! Immutable encrypted secrets in ordinary capability-governed collections.
//!
//! A secret version owns one fresh random data-encryption key (DEK). Its body
//! is encrypted once and the DEK is sealed independently to every subject
//! admitted for `READ(collection)` when the version is published. Granting a
//! reader later adds another wrap; it never rewrites the body or changes the
//! secret id. Collection capability proofs remain the authority. A wrap is
//! only cryptographic delivery for an already-admitted reader, not a second
//! authorization system.

use std::collections::BTreeSet;

use anyhow::{anyhow, bail, Context, Result};
use dryoc::classic::crypto_sign_ed25519::{
    crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519,
};
use dryoc::dryocbox::{DryocBox, KeyPair as BoxKeyPair, PublicKey as BoxPublicKey};
use dryoc::dryocsecretbox::{DryocSecretBox, Key, Nonce};
use dryoc::types::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hifitime::Epoch;
use triblespace::core::blob::encodings::succinctarchive::{OrderedUniverse, UnionArchive};
use triblespace::core::collection::{CollectionHandle, Support};
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::*;
use zeroize::Zeroizing;

pub mod schema;
pub mod storage;

pub use self::schema::DEFAULT_SCOPE_ID;

use self::schema::{
    secret_body, wrap_dek, wrap_recipient_key, wrap_secret, KIND_SECRET, KIND_WRAP,
};

const SECRET_BODY_MIN_BYTES: usize = 24 + 16;
const SEALED_DEK_BYTES: usize = 48 + 32;

pub type RecipientPublicKey = [u8; 32];
pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;
pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;
pub type BytesHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;

/// Shard-preserving logical query view over a maintained Secrets collection.
pub type SecretsFacts = UnionArchive<OrderedUniverse>;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SecretRow {
    pub id: Id,
    pub created_at: IntervalValue,
    pub name: TextHandle,
    pub body: BytesHandle,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WrapRow {
    pub id: Id,
    pub secret: Id,
    pub recipient: RecipientPublicKey,
    pub sealed_dek: BytesHandle,
}

/// One explicitly configured collection observed through its maintained view.
#[derive(Clone)]
pub struct SecretsView {
    collection: CollectionHandle,
    support: Support,
    facts: SecretsFacts,
}

impl SecretsView {
    pub(crate) fn new(collection: CollectionHandle, support: Support, facts: SecretsFacts) -> Self {
        Self {
            collection,
            support,
            facts,
        }
    }

    pub const fn collection(&self) -> CollectionHandle {
        self.collection
    }

    pub fn support(&self) -> &Support {
        &self.support
    }

    pub fn facts(&self) -> &SecretsFacts {
        &self.facts
    }
}

/// Storage-agnostic aggregate over explicitly configured Secrets collections.
///
/// Collection discovery is deliberately outside this type. A caller supplies
/// the policy boundaries it intends to inspect; no ambient inbox or global
/// collection registry is introduced merely to find ciphertext.
pub struct SecretsSnapshot<R> {
    store_snapshot: R,
    instant: Epoch,
    collections: Vec<SecretsView>,
    facts: Option<SecretsFacts>,
}

impl<R> SecretsSnapshot<R> {
    pub(crate) fn new(store_snapshot: R, instant: Epoch, collections: Vec<SecretsView>) -> Self {
        let facts = collections
            .iter()
            .map(|view| view.facts.clone())
            .reduce(|left, right| left.union(&right));
        Self {
            store_snapshot,
            instant,
            collections,
            facts,
        }
    }

    pub fn store_snapshot(&self) -> &R {
        &self.store_snapshot
    }

    /// Authorization instant shared by every collection view in this snapshot.
    pub const fn instant(&self) -> Epoch {
        self.instant
    }

    pub fn collections(&self) -> &[SecretsView] {
        &self.collections
    }

    /// Logical union of all explicitly configured collection views.
    ///
    /// This is a shallow union of mmap/Bytes-backed Succinct shards, not a
    /// temporary TribleSet or eagerly reconstructed catalog. Facts for one
    /// entity may therefore conjoin across policy boundaries in the ordinary
    /// open-world TribleSpace model.
    pub fn facts(&self) -> Option<&SecretsFacts> {
        self.facts.as_ref()
    }

    /// Whether one opaque immutable secret id occurs in any configured view.
    pub fn contains(&self, secret: Id) -> bool {
        self.facts
            .as_ref()
            .is_some_and(|facts| !secret_rows_for(facts, secret).is_empty())
    }
}

impl<R: BlobStoreGet> SecretsSnapshot<R> {
    /// Open one global secret id with the caller's ordinary signing key.
    ///
    /// This performs no clock or capability check. Admission already selected
    /// the collection view; possession of the matching private key is what
    /// opens its additive DEK envelope. Every independently decryptable
    /// occurrence must agree on plaintext.
    pub fn open(&self, secret: Id, signing_key: &SigningKey) -> Result<Vec<u8>> {
        let facts = self
            .facts
            .as_ref()
            .ok_or_else(|| anyhow!("secret {secret} not found"))?;
        open_version_from_facts(&self.store_snapshot, facts, secret, signing_key)
    }
}

/// Project every complete, decodable immutable-secret row.
pub fn secret_rows<P>(facts: &P) -> Vec<SecretRow>
where
    P: TriblePattern,
{
    find!(
        (
            id: Id,
            created_at: IntervalValue,
            name: TextHandle,
            body: BytesHandle
        ),
        pattern!(facts, [{
            ?id @
                metadata::tag: KIND_SECRET,
                metadata::created_at: ?created_at,
                metadata::name: ?name,
                secret_body: ?body,
        }])
    )
    .filter_map(|(id, created_at, name, body)| {
        point_value("secret creation time", created_at)
            .is_ok()
            .then_some(SecretRow {
                id,
                created_at,
                name,
                body,
            })
    })
    .collect()
}

/// Project every complete, decodable row for one exact opaque secret id.
pub fn secret_rows_for<P>(facts: &P, secret: Id) -> Vec<SecretRow>
where
    P: TriblePattern,
{
    find!(
        (created_at: IntervalValue, name: TextHandle, body: BytesHandle),
        pattern!(facts, [{
            secret @
                metadata::tag: KIND_SECRET,
                metadata::created_at: ?created_at,
                metadata::name: ?name,
                secret_body: ?body,
        }])
    )
    .filter_map(|(created_at, name, body)| {
        point_value("secret creation time", created_at)
            .is_ok()
            .then_some(SecretRow {
                id: secret,
                created_at,
                name,
                body,
            })
    })
    .collect()
}

/// Project every complete wrap for one secret and recipient.
pub fn recipient_wraps<P>(facts: &P, secret: Id, recipient: RecipientPublicKey) -> Vec<WrapRow>
where
    P: TriblePattern,
{
    let recipient_value = Inline::<inlineencodings::ED25519PublicKey>::new(recipient);
    find!(
        (id: Id, sealed_dek: BytesHandle),
        pattern!(facts, [{
            ?id @
                metadata::tag: KIND_WRAP,
                wrap_secret: secret,
                wrap_recipient_key: recipient_value,
                wrap_dek: ?sealed_dek,
        }])
    )
    .map(|(id, sealed_dek)| WrapRow {
        id,
        secret,
        recipient,
        sealed_dek,
    })
    .collect()
}

/// Every recipient which already has a complete envelope for one secret.
pub fn wrap_recipients<P>(facts: &P, secret: Id) -> BTreeSet<RecipientPublicKey>
where
    P: TriblePattern,
{
    find!(
        recipient: Inline<inlineencodings::ED25519PublicKey>,
        pattern!(facts, [{
            _?id @
                metadata::tag: KIND_WRAP,
                wrap_secret: secret,
                wrap_recipient_key: ?recipient,
                wrap_dek: _?sealed_dek,
        }])
    )
    .map(|recipient| recipient.raw)
    .collect()
}

/// Every recipient whose wrap attachment is resident and structurally valid.
///
/// A typed fact row alone is not evidence that an envelope is usable. In an
/// open-world store a malformed or missing attachment must not suppress a
/// later additive repair for the same recipient.
fn resident_wrap_recipients<R, P>(reader: &R, facts: &P, secret: Id) -> BTreeSet<RecipientPublicKey>
where
    R: BlobStoreGet,
    P: TriblePattern,
{
    find!(
        (
            recipient: Inline<inlineencodings::ED25519PublicKey>,
            sealed_dek: BytesHandle
        ),
        pattern!(facts, [{
            _?id @
                metadata::tag: KIND_WRAP,
                wrap_secret: secret,
                wrap_recipient_key: ?recipient,
                wrap_dek: ?sealed_dek,
        }])
    )
    .filter_map(|(recipient, sealed_dek)| {
        read_bytes(reader, sealed_dek)
            .ok()
            .filter(|sealed| validate_sealed_dek(sealed).is_ok())
            .map(|_| recipient.raw)
    })
    .collect()
}

pub fn read_text<R: BlobStoreGet>(reader: &R, handle: TextHandle) -> Result<String> {
    let value: anybytes::View<str> = reader.get(handle).context("read UTF-8 string blob")?;
    Ok(value.as_ref().to_owned())
}

fn read_bytes<R: BlobStoreGet>(reader: &R, handle: BytesHandle) -> Result<Vec<u8>> {
    let bytes: anybytes::Bytes = reader.get(handle).context("read byte blob")?;
    Ok(bytes.as_ref().to_vec())
}

fn point_value(field: &str, value: IntervalValue) -> Result<()> {
    let (lower, upper): (i128, i128) = value
        .try_from_inline()
        .map_err(|error| anyhow!("decode {field}: {error:?}"))?;
    if lower != upper {
        bail!("{field} must be a point interval");
    }
    Ok(())
}

fn validate_name(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.trim() != value {
        bail!("{field} must be non-empty and have no surrounding whitespace");
    }
    if value.as_bytes().contains(&0) {
        bail!("{field} contains a NUL byte");
    }
    Ok(())
}

fn validate_encrypted_body(body: &[u8]) -> Result<()> {
    if body.len() < SECRET_BODY_MIN_BYTES {
        bail!("encrypted secret body is too short");
    }
    Nonce::try_from(&body[..24]).context("secret nonce")?;
    let _: dryoc::dryocsecretbox::VecBox = DryocSecretBox::from_bytes(&body[24..])
        .map_err(|error| anyhow!("parse encrypted secret body: {error:?}"))?;
    Ok(())
}

fn validate_sealed_dek(sealed: &[u8]) -> Result<()> {
    if sealed.len() != SEALED_DEK_BYTES {
        bail!("sealed DEK must be {SEALED_DEK_BYTES} bytes");
    }
    let _: dryoc::dryocbox::VecBox = DryocBox::from_sealed_bytes(sealed)
        .map_err(|error| anyhow!("parse sealed DEK: {error:?}"))?;
    Ok(())
}

fn secret_record(
    secret: Id,
    name: TextHandle,
    body: BytesHandle,
    created_at: IntervalValue,
) -> Fragment {
    entity! { ExclusiveId::force_ref(&secret) @
        metadata::tag: &KIND_SECRET,
        metadata::name: name,
        metadata::created_at: created_at,
        secret_body: body,
    }
}

fn wrap_record(
    wrap: Id,
    secret: Id,
    recipient: RecipientPublicKey,
    sealed_dek: BytesHandle,
) -> Fragment {
    let recipient = Inline::<inlineencodings::ED25519PublicKey>::new(recipient);
    entity! { ExclusiveId::force_ref(&wrap) @
        metadata::tag: &KIND_WRAP,
        wrap_secret: secret,
        wrap_recipient_key: recipient,
        wrap_dek: sealed_dek,
    }
}

/// Immutable encrypted secret record with caller-selected opaque identity.
///
/// This constructor remains public for additive migrations. Ordinary writes
/// should use [`seal_version`], which mints the id and DEK together.
pub fn encrypted_secret_fragment(
    secret: Id,
    name: &str,
    encrypted_body: Vec<u8>,
    created_at: IntervalValue,
) -> Result<Fragment> {
    validate_name("secret name", name)?;
    point_value("secret creation time", created_at)?;
    validate_encrypted_body(&encrypted_body)?;
    let mut fragment = Fragment::empty();
    let name = fragment.put(name.to_owned());
    let body = fragment.put::<blobencodings::RawBytes, _>(encrypted_body);
    fragment += secret_record(secret, name, body, created_at);
    Ok(fragment)
}

/// One recipient-key wrap with caller-selected occurrence identity.
///
/// This remains public so a migration can preserve old secret ids while
/// adding new direct-recipient envelopes.
pub fn recipient_wrap_fragment(
    wrap: Id,
    secret: Id,
    recipient: RecipientPublicKey,
    sealed_dek: Vec<u8>,
) -> Result<Fragment> {
    let _ = box_pk_from_ed25519(&recipient)?;
    validate_sealed_dek(&sealed_dek)?;
    let mut fragment = Fragment::empty();
    let sealed_dek = fragment.put::<blobencodings::RawBytes, _>(sealed_dek);
    fragment += wrap_record(wrap, secret, recipient, sealed_dek);
    Ok(fragment)
}

fn box_pk_from_ed25519(public: &RecipientPublicKey) -> Result<BoxPublicKey> {
    VerifyingKey::from_bytes(public).context("invalid Ed25519 recipient public key")?;
    let mut x25519 = [0u8; 32];
    crypto_sign_ed25519_pk_to_curve25519(&mut x25519, public)
        .map_err(|error| anyhow!("public-key conversion: {error:?}"))?;
    BoxPublicKey::try_from(&x25519[..]).map_err(|error| anyhow!("X25519 public key: {error:?}"))
}

fn box_keypair_from_signing_key(signing_key: &SigningKey) -> Result<BoxKeyPair> {
    let public = signing_key.verifying_key().to_bytes();
    let secret = Zeroizing::new(signing_key.to_keypair_bytes());
    let mut x_public = [0u8; 32];
    let mut x_secret = Zeroizing::new([0u8; 32]);
    crypto_sign_ed25519_pk_to_curve25519(&mut x_public, &public)
        .map_err(|error| anyhow!("public-key conversion: {error:?}"))?;
    crypto_sign_ed25519_sk_to_curve25519(&mut x_secret, &secret);
    BoxKeyPair::from_slices(&x_public, x_secret.as_slice())
        .map_err(|error| anyhow!("X25519 keypair: {error:?}"))
}

fn deduplicated_recipients<I>(recipients: I) -> BTreeSet<RecipientPublicKey>
where
    I: IntoIterator<Item = VerifyingKey>,
{
    recipients
        .into_iter()
        .map(|recipient| recipient.to_bytes())
        .collect()
}

fn sealed_dek_fragment(secret: Id, recipient: RecipientPublicKey, dek: &Key) -> Result<Fragment> {
    let recipient_box = box_pk_from_ed25519(&recipient)?;
    let sealed = DryocBox::seal_to_vecbox(dek, &recipient_box)
        .map_err(|error| anyhow!("seal DEK to recipient: {error:?}"))?
        .to_vec();
    recipient_wrap_fragment(genid().id, secret, recipient, sealed)
}

pub struct SealedVersion {
    pub fragment: Fragment,
    pub secret: Id,
    pub recipients: Vec<VerifyingKey>,
}

/// Encrypt one immutable version with a fresh DEK and seal that DEK to every
/// distinct admitted reader.
pub fn seal_version<I>(
    name: &str,
    plaintext: &[u8],
    recipients: I,
    created_at: IntervalValue,
) -> Result<SealedVersion>
where
    I: IntoIterator<Item = VerifyingKey>,
{
    let recipients = deduplicated_recipients(recipients);
    if recipients.is_empty() {
        bail!("a secret requires at least one finite admitted reader");
    }

    let dek = Key::gen();
    let nonce = Nonce::gen();
    let ciphertext = DryocSecretBox::encrypt_to_vecbox(plaintext, &nonce, &dek).to_vec();
    let mut body = Vec::with_capacity(nonce.len() + ciphertext.len());
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&ciphertext);

    let secret = genid().id;
    let mut fragment = encrypted_secret_fragment(secret, name, body, created_at)?;
    let mut wrapped = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        fragment += sealed_dek_fragment(secret, recipient, &dek)?;
        wrapped.push(
            VerifyingKey::from_bytes(&recipient)
                .expect("recipients came from validated VerifyingKey values"),
        );
    }
    Ok(SealedVersion {
        fragment,
        secret,
        recipients: wrapped,
    })
}

fn recover_dek_from_facts<R, P>(
    reader: &R,
    facts: &P,
    secret: Id,
    signing_key: &SigningKey,
) -> Result<Option<Key>>
where
    R: BlobStoreGet,
    P: TriblePattern,
{
    let recipient = signing_key.verifying_key().to_bytes();
    let wraps = recipient_wraps(facts, secret, recipient);
    if wraps.is_empty() {
        return Ok(None);
    }
    let keypair = box_keypair_from_signing_key(signing_key)?;
    let mut recovered = None::<Zeroizing<Vec<u8>>>;
    for wrap in wraps {
        let Ok(sealed) = read_bytes(reader, wrap.sealed_dek) else {
            continue;
        };
        if validate_sealed_dek(&sealed).is_err() {
            continue;
        }
        let Ok(boxed) = DryocBox::from_sealed_bytes(&sealed) else {
            continue;
        };
        let Ok(opened) = boxed.unseal_to_vec(&keypair) else {
            continue;
        };
        let bytes = Zeroizing::new(opened);
        if bytes.len() != 32 {
            continue;
        }
        if recovered
            .as_ref()
            .is_some_and(|previous| previous.as_slice() != bytes.as_slice())
        {
            bail!("wraps for secret {secret} and one recipient contain competing DEKs");
        }
        if recovered.is_none() {
            recovered = Some(bytes);
        }
    }
    let Some(bytes) = recovered else {
        return Ok(None);
    };
    Ok(Some(Key::try_from(&bytes[..]).context("decode DEK")?))
}

fn decrypt_secret_body_from_facts<R, P>(
    reader: &R,
    facts: &P,
    secret: Id,
    dek: &Key,
) -> Result<Vec<u8>>
where
    R: BlobStoreGet,
    P: TriblePattern,
{
    let bodies = secret_rows_for(facts, secret)
        .into_iter()
        .map(|row| row.body)
        .collect::<BTreeSet<_>>();
    if bodies.is_empty() {
        bail!("secret {secret} not found");
    }

    let mut plaintext = None::<Vec<u8>>;
    for body in bodies {
        let Ok(body) = read_bytes(reader, body) else {
            continue;
        };
        if validate_encrypted_body(&body).is_err() {
            continue;
        }
        let Ok(nonce) = Nonce::try_from(&body[..24]) else {
            continue;
        };
        let Ok(boxed) = DryocSecretBox::from_bytes(&body[24..]) else {
            continue;
        };
        let Ok(candidate) = boxed.decrypt_to_vec(&nonce, dek) else {
            continue;
        };
        if plaintext
            .as_ref()
            .is_some_and(|previous| previous != &candidate)
        {
            bail!("secret {secret} contains competing decryptable bodies");
        }
        if plaintext.is_none() {
            plaintext = Some(candidate);
        }
    }
    plaintext.ok_or_else(|| anyhow!("secret {secret} has no resident decryptable body"))
}

/// Open one secret directly from any queryable fact view.
pub fn open_version_from_facts<R, P>(
    reader: &R,
    facts: &P,
    secret: Id,
    signing_key: &SigningKey,
) -> Result<Vec<u8>>
where
    R: BlobStoreGet,
    P: TriblePattern,
{
    if secret_rows_for(facts, secret).is_empty() {
        bail!("secret {secret} not found");
    }
    let dek = recover_dek_from_facts(reader, facts, secret, signing_key)?
        .ok_or_else(|| anyhow!("no wrap for this signing key on secret {secret}"))?;
    decrypt_secret_body_from_facts(reader, facts, secret, &dek)
}

pub struct RecipientEnvelopes {
    pub fragment: Fragment,
    pub recipients: Vec<VerifyingKey>,
}

impl RecipientEnvelopes {
    pub fn is_empty(&self) -> bool {
        self.recipients.is_empty()
    }
}

/// Build only the missing direct-recipient envelopes for an existing version.
///
/// `holder` must already have a valid wrap and is used only to recover the
/// existing DEK. The returned fragment contains no secret-body facts and can
/// be committed additively into the same source collection.
pub fn add_recipient_envelopes_from_facts<R, P, I>(
    reader: &R,
    facts: &P,
    secret: Id,
    holder: &SigningKey,
    recipients: I,
) -> Result<RecipientEnvelopes>
where
    R: BlobStoreGet,
    P: TriblePattern,
    I: IntoIterator<Item = VerifyingKey>,
{
    add_recipient_envelopes_for_target(reader, facts, facts, secret, holder, recipients)
}

/// Build missing envelopes for `target_facts`, recovering the existing DEK
/// from a possibly wider aggregate `recovery_facts` view.
///
/// This is the collection-boundary primitive: cross-collection facts may help
/// recover a split historical version, while an envelope only counts as
/// already published when it is resident in the explicit target collection.
pub fn add_recipient_envelopes_for_target<R, P, Q, I>(
    reader: &R,
    recovery_facts: &P,
    target_facts: &Q,
    secret: Id,
    holder: &SigningKey,
    recipients: I,
) -> Result<RecipientEnvelopes>
where
    R: BlobStoreGet,
    P: TriblePattern,
    Q: TriblePattern,
    I: IntoIterator<Item = VerifyingKey>,
{
    if secret_rows_for(recovery_facts, secret).is_empty() {
        bail!("secret {secret} not found");
    }
    let dek = recover_dek_from_facts(reader, recovery_facts, secret, holder)?
        .ok_or_else(|| anyhow!("holder has no wrap on secret {secret}"))?;
    let existing = resident_wrap_recipients(reader, target_facts, secret);
    let recipients = deduplicated_recipients(recipients);
    let mut fragment = Fragment::empty();
    let mut added = Vec::new();
    for recipient in recipients.difference(&existing).copied() {
        fragment += sealed_dek_fragment(secret, recipient, &dek)?;
        added.push(
            VerifyingKey::from_bytes(&recipient)
                .expect("recipients came from validated VerifyingKey values"),
        );
    }
    Ok(RecipientEnvelopes {
        fragment,
        recipients: added,
    })
}

#[cfg(test)]
mod tests {
    use hifitime::Epoch;
    use rand_core::OsRng;
    use triblespace::core::repo::SnapshotSource;

    use super::*;

    fn at(second: i64) -> IntervalValue {
        let epoch = Epoch::from_unix_seconds(second as f64);
        (epoch, epoch).try_to_inline().unwrap()
    }

    #[test]
    fn one_fresh_dek_is_delivered_to_every_distinct_reader() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let outsider = SigningKey::generate(&mut OsRng);
        let mut sealed = seal_version(
            "database",
            b"hunter2",
            [
                alice.verifying_key(),
                bob.verifying_key(),
                alice.verifying_key(),
            ],
            at(1),
        )
        .unwrap();
        assert_eq!(sealed.recipients.len(), 2);
        assert_eq!(
            wrap_recipients(sealed.fragment.facts(), sealed.secret).len(),
            2
        );

        let reader = sealed.fragment.blobs_mut().snapshot().unwrap();
        assert_eq!(
            open_version_from_facts(&reader, sealed.fragment.facts(), sealed.secret, &alice)
                .unwrap(),
            b"hunter2"
        );
        assert_eq!(
            open_version_from_facts(&reader, sealed.fragment.facts(), sealed.secret, &bob).unwrap(),
            b"hunter2"
        );
        assert!(open_version_from_facts(
            &reader,
            sealed.fragment.facts(),
            sealed.secret,
            &outsider,
        )
        .is_err());
    }

    #[test]
    fn later_reader_adds_only_an_envelope_and_preserves_the_body() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let mut sealed = seal_version(
            "database",
            b"unchanged ciphertext",
            [alice.verifying_key()],
            at(2),
        )
        .unwrap();
        let secret = sealed.secret;
        let original = secret_rows_for(sealed.fragment.facts(), secret)[0].body;
        let reader = sealed.fragment.blobs_mut().snapshot().unwrap();
        let added = add_recipient_envelopes_from_facts(
            &reader,
            sealed.fragment.facts(),
            secret,
            &alice,
            [
                alice.verifying_key(),
                bob.verifying_key(),
                bob.verifying_key(),
            ],
        )
        .unwrap();
        drop(reader);

        assert_eq!(added.recipients, vec![bob.verifying_key()]);
        assert!(secret_rows_for(added.fragment.facts(), secret).is_empty());
        sealed.fragment += added.fragment;
        assert_eq!(
            secret_rows_for(sealed.fragment.facts(), secret)[0].body,
            original
        );
        let reader = sealed.fragment.blobs_mut().snapshot().unwrap();
        assert_eq!(
            open_version_from_facts(&reader, sealed.fragment.facts(), secret, &bob).unwrap(),
            b"unchanged ciphertext"
        );
    }

    #[test]
    fn missing_wrap_attachment_does_not_suppress_additive_repair() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let mut sealed =
            seal_version("database", b"value", [alice.verifying_key()], at(3)).unwrap();
        let secret = sealed.secret;
        let missing = Inline::<inlineencodings::Handle<blobencodings::RawBytes>>::new([0x55; 32]);
        sealed.fragment += wrap_record(genid().id, secret, bob.verifying_key().to_bytes(), missing);

        let reader = sealed.fragment.blobs_mut().snapshot().unwrap();
        let added = add_recipient_envelopes_from_facts(
            &reader,
            sealed.fragment.facts(),
            secret,
            &alice,
            [bob.verifying_key()],
        )
        .unwrap();

        assert_eq!(added.recipients, vec![bob.verifying_key()]);
    }

    #[test]
    fn missing_body_occurrence_does_not_hide_a_decryptable_body() {
        let alice = SigningKey::generate(&mut OsRng);
        let mut sealed =
            seal_version("database", b"value", [alice.verifying_key()], at(4)).unwrap();
        let secret = sealed.secret;
        let row = secret_rows_for(sealed.fragment.facts(), secret)[0];
        let missing = Inline::<inlineencodings::Handle<blobencodings::RawBytes>>::new([0x66; 32]);
        sealed.fragment += secret_record(secret, row.name, missing, row.created_at);

        let reader = sealed.fragment.blobs_mut().snapshot().unwrap();
        assert_eq!(
            open_version_from_facts(&reader, sealed.fragment.facts(), secret, &alice).unwrap(),
            b"value"
        );
    }

    #[test]
    fn recipient_list_cannot_be_empty() {
        assert!(
            seal_version("token", b"value", std::iter::empty::<VerifyingKey>(), at(5),).is_err()
        );
    }
}
