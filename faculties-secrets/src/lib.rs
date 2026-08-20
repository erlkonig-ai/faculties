//! Canonical Secrets records and strict collection semantics.
//!
//! The collection is a monotone union of immutable identities, rooted
//! intrinsic scopes, independent grant occurrences, grant-retraction facts,
//! immutable secret versions, and recipient wraps.  Authorization is the
//! least rooted grant fixpoint; no read path chooses an arbitrary scalar from
//! competing values.
//!
//! A fresh DEK secretboxes each secret version once and is sealed-boxed to the
//! X25519 key derived from every recipient's Ed25519 identity. That one keypair
//! does both jobs, so an identity's private half may rest either in a
//! password-locked lockbox carried in its record or in the node's durable pile
//! signing key -- the same key that signs its collection commits. A node
//! therefore has one identity, not two, and any node that has ever written to
//! the pile can be named as a recipient from the pile alone.
//!
//! Naming is not entitlement. Discovering a node's key makes it *addressable*;
//! it is sealed to only after an effective admin grants it into a scope, and it
//! reads a version only through a wrap addressed to it. A grant is
//! effective only when its issuer belongs to the effective-admin fixpoint of
//! its object. Retracting one admin grant therefore transitively invalidates
//! authority derived solely through it, while another independent live grant
//! preserves OR-set membership.
//!
//! Removal is operational rather than retroactively cryptographic: append-only
//! storage cannot make a recipient forget an old wrap. The rotation view thus
//! reports source credentials that must be changed and published as a fresh
//! version; it never pretends that re-encrypting the same value revokes past
//! knowledge.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use anyhow::{anyhow, bail, Context, Result};
use dryoc::classic::crypto_pwhash::{crypto_pwhash, PasswordHashAlgorithm};
use dryoc::classic::crypto_sign_ed25519::{
    crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519,
};
use dryoc::constants::{
    CRYPTO_PWHASH_MEMLIMIT_MODERATE, CRYPTO_PWHASH_OPSLIMIT_MODERATE, CRYPTO_PWHASH_SALTBYTES,
};
use dryoc::dryocbox::{DryocBox, KeyPair as BoxKeyPair, PublicKey as BoxPublicKey};
use dryoc::dryocsecretbox::{DryocSecretBox, Key, Nonce};
use dryoc::sign::SigningKeyPair;
use dryoc::types::*;
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
use triblespace::prelude::*;

pub mod password;
pub mod schema;

use crate::schema::{
    grant_issuer, grant_object, grant_relation, grant_retracted_at, grant_subject,
    identity_lockbox, identity_sign_pk, scope_creator, secret_body, secret_name, secret_scope,
    wrap_dek, wrap_recipient, wrap_secret, KIND_GRANT, KIND_IDENTITY, KIND_SCOPE, KIND_SECRET,
    KIND_WRAP,
};

pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;
pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
pub type BytesHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;

const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const LOCKBOX_BYTES: usize = 16 + 24 + 16 + 64;
const SECRET_BODY_MIN_BYTES: usize = 24 + 16;
const SEALED_DEK_BYTES: usize = 48 + 32;

/// A freshly prepared identity and the public material callers may display.
/// A password-protected private key, when there is one, remains embedded in
/// `fragment`; a node identity has none, because its private half never leaves
/// the node's signing-key file.
pub struct PreparedIdentity {
    pub fragment: Fragment,
    pub id: Id,
    pub public_key: Vec<u8>,
}

/// One immutable encrypted secret version and all of its initial wraps.
pub struct SealedVersion {
    pub fragment: Fragment,
    pub secret: Id,
    pub recipient_count: usize,
}

/// Additional recipient wraps for an existing immutable secret version.
pub struct SharedVersion {
    pub fragment: Fragment,
    pub new_recipient_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityRow {
    pub id: Id,
    pub created_at: IntervalValue,
    pub name: TextHandle,
    pub sign_pk: BytesHandle,
    /// Password-locked private key, when the identity keeps one. `None` is a
    /// node identity: the same private half rests in the node's durable
    /// signing-key file beside its pile, so the record carries nothing to lock.
    pub lockbox: Option<BytesHandle>,
}

impl IdentityRow {
    /// Whether this identity's private half rests in a node signing-key file
    /// rather than in a lockbox carried by the record.
    pub fn is_node_identity(&self) -> bool {
        self.lockbox.is_none()
    }
}

/// What a caller presents to act as one identity.
///
/// Both arms open the same keypair. They differ only in where its private half
/// was resting, which is why widening from one to two costs the model nothing:
/// sealing is unchanged, and every recipient is still a specific identity.
pub enum IdentitySecret {
    /// The password that opens a lockbox carried in the identity record.
    Password(Vec<u8>),
    /// A node's durable pile signing key. Its public half must be the
    /// identity's own, and that is checked before anything is unsealed.
    Node(SigningKey),
}

impl std::fmt::Debug for IdentitySecret {
    /// Hand-written so neither a password nor a private key can reach a log.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => formatter.write_str("IdentitySecret::Password(<redacted>)"),
            Self::Node(_) => formatter.write_str("IdentitySecret::Node(<redacted>)"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeRow {
    pub id: Id,
    pub creator: Id,
    /// Independent observations that this intrinsic scope was created.
    /// Repeating the same `(creator, name)` operation is therefore monotone
    /// and never creates a competing scalar.
    pub created_at: BTreeSet<IntervalValue>,
    pub name: TextHandle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantRow {
    pub id: Id,
    pub created_at: IntervalValue,
    pub object: Id,
    pub relation: String,
    pub subject: Id,
    pub issuer: Id,
    /// Retractions are an unordered set of monotone observations. Their
    /// existence, not an arbitrated timestamp, makes the grant non-live.
    pub retracted_at: BTreeSet<IntervalValue>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretRow {
    pub id: Id,
    pub created_at: IntervalValue,
    pub scope: Id,
    pub name: String,
    pub display_name: TextHandle,
    pub body: BytesHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WrapRow {
    pub id: Id,
    pub created_at: IntervalValue,
    pub secret: Id,
    pub recipient: Id,
    pub sealed_dek: BytesHandle,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SecretsCatalog {
    pub identities: BTreeMap<Id, IdentityRow>,
    pub scopes: BTreeMap<Id, ScopeRow>,
    pub grants: BTreeMap<Id, GrantRow>,
    pub secrets: BTreeMap<Id, SecretRow>,
    pub wraps: BTreeMap<Id, WrapRow>,
}

impl SecretsCatalog {
    pub fn grant_is_live(&self, grant: Id) -> bool {
        self.grants
            .get(&grant)
            .is_some_and(|row| row.retracted_at.is_empty())
    }

    pub fn scope_creator(&self, scope: Id) -> Option<Id> {
        self.scopes.get(&scope).map(|row| row.creator)
    }

    /// Least fixpoint rooted at the intrinsic scope creator.
    pub fn effective_admins(&self, scope: Id) -> HashSet<Id> {
        let mut admins = HashSet::new();
        let Some(creator) = self.scope_creator(scope) else {
            return admins;
        };
        admins.insert(creator);
        loop {
            let mut grew = false;
            for grant in self.grants.values() {
                if grant.object == scope
                    && grant.relation == "admin"
                    && grant.retracted_at.is_empty()
                    && admins.contains(&grant.issuer)
                    && admins.insert(grant.subject)
                {
                    grew = true;
                }
            }
            if !grew {
                return admins;
            }
        }
    }

    /// Identity leaves reachable through effective grants, plus the root
    /// creator. Nested scopes are traversed as groups without becoming
    /// recipients unless they are also identity records.
    pub fn recipients_of(&self, scope: Id) -> Vec<Id> {
        let mut admin_cache: HashMap<Id, HashSet<Id>> = HashMap::new();
        let mut edges: BTreeMap<Id, BTreeSet<Id>> = BTreeMap::new();
        for grant in self.grants.values() {
            if !grant.retracted_at.is_empty() {
                continue;
            }
            let admins = admin_cache
                .entry(grant.object)
                .or_insert_with(|| self.effective_admins(grant.object));
            if admins.contains(&grant.issuer) {
                edges.entry(grant.object).or_default().insert(grant.subject);
            }
        }

        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::from([scope]);
        while let Some(object) = queue.pop_front() {
            if !visited.insert(object) {
                continue;
            }
            if let Some(subjects) = edges.get(&object) {
                queue.extend(subjects.iter().copied());
            }
        }

        let mut recipients: BTreeSet<Id> = visited
            .into_iter()
            .filter(|id| self.identities.contains_key(id))
            .collect();
        if let Some(creator) = self.scope_creator(scope) {
            recipients.insert(creator);
        }
        recipients.into_iter().collect()
    }

    pub fn wrap_holders(&self, secret: Id) -> Vec<Id> {
        self.wraps
            .values()
            .filter(|row| row.secret == secret)
            .map(|row| row.recipient)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn secret_versions(&self, scope: Id, name: &str) -> usize {
        self.secrets
            .values()
            .filter(|row| row.scope == scope && row.name == name)
            .count()
    }

    /// Resolve latest-wins addressing without hiding a concurrent timestamp
    /// tie. A tie between distinct versions is visible ambiguity.
    pub fn latest_secret(&self, scope: Id, name: &str) -> Result<Option<Id>> {
        let mut candidates: Vec<&SecretRow> = self
            .secrets
            .values()
            .filter(|row| row.scope == scope && row.name == name)
            .collect();
        if candidates.is_empty() {
            return Ok(None);
        }
        candidates.sort_by_key(|row| interval_start(row.created_at));
        let latest_time = interval_start(candidates.last().expect("non-empty").created_at);
        let latest: Vec<_> = candidates
            .into_iter()
            .filter(|row| interval_start(row.created_at) == latest_time)
            .collect();
        match latest.as_slice() {
            [row] => Ok(Some(row.id)),
            rows => bail!(
                "{} secret versions named '{name}' in scope {} share the latest timestamp; address is ambiguous",
                rows.len(),
                fmt_id(scope)
            ),
        }
    }

    pub fn wraps_for(&self, secret: Id, recipient: Id) -> Vec<&WrapRow> {
        self.wraps
            .values()
            .filter(|row| row.secret == secret && row.recipient == recipient)
            .collect()
    }
}

fn derive_key(password: &[u8], salt: &[u8]) -> Key {
    let mut output = [0u8; 32];
    crypto_pwhash(
        &mut output,
        password,
        salt,
        CRYPTO_PWHASH_OPSLIMIT_MODERATE,
        CRYPTO_PWHASH_MEMLIMIT_MODERATE,
        PasswordHashAlgorithm::Argon2id13,
    )
    .expect("argon2id");
    Key::try_from(&output[..]).expect("32-byte secretbox key")
}

/// `salt(16) || nonce(24) || secretbox(ed25519 secret key)`.
fn lock_secret_key(password: &[u8], secret_key: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; CRYPTO_PWHASH_SALTBYTES];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt);
    let nonce = Nonce::gen();
    let ciphertext = DryocSecretBox::encrypt_to_vecbox(secret_key, &nonce, &key).to_vec();
    let mut output = Vec::with_capacity(salt.len() + nonce.len() + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    output
}

fn unlock_secret_key(password: &[u8], lockbox: &[u8]) -> Result<Vec<u8>> {
    if lockbox.len() < CRYPTO_PWHASH_SALTBYTES + 24 {
        bail!("malformed lockbox");
    }
    let salt = &lockbox[..CRYPTO_PWHASH_SALTBYTES];
    let nonce = Nonce::try_from(&lockbox[CRYPTO_PWHASH_SALTBYTES..][..24]).context("nonce")?;
    let ciphertext = &lockbox[CRYPTO_PWHASH_SALTBYTES + 24..];
    let key = derive_key(password, salt);
    DryocSecretBox::from_bytes(ciphertext)
        .map_err(|error| anyhow!("parse lockbox: {error:?}"))?
        .decrypt_to_vec(&nonce, &key)
        .map_err(|_| anyhow!("wrong password"))
}

fn box_pk_from_ed25519(ed_pk: &[u8]) -> Result<BoxPublicKey> {
    let public: &[u8; 32] = ed_pk.try_into().context("Ed25519 public key length")?;
    let mut x25519 = [0u8; 32];
    crypto_sign_ed25519_pk_to_curve25519(&mut x25519, public)
        .map_err(|error| anyhow!("public-key conversion: {error:?}"))?;
    BoxPublicKey::try_from(&x25519[..]).map_err(|error| anyhow!("X25519 public key: {error:?}"))
}

fn box_keypair_from_ed25519(ed_sk: &[u8], ed_pk: &[u8]) -> Result<BoxKeyPair> {
    let secret: &[u8; 64] = ed_sk.try_into().context("Ed25519 secret key length")?;
    let public: &[u8; 32] = ed_pk.try_into().context("Ed25519 public key length")?;
    let mut x_public = [0u8; 32];
    let mut x_secret = [0u8; 32];
    crypto_sign_ed25519_pk_to_curve25519(&mut x_public, public)
        .map_err(|error| anyhow!("public-key conversion: {error:?}"))?;
    crypto_sign_ed25519_sk_to_curve25519(&mut x_secret, secret);
    BoxKeyPair::from_slices(&x_public, &x_secret)
        .map_err(|error| anyhow!("X25519 keypair: {error:?}"))
}

fn identity_box_keypair(
    reader: &PileReader,
    catalog: &SecretsCatalog,
    identity: Id,
    secret: &IdentitySecret,
) -> Result<BoxKeyPair> {
    let row = catalog
        .identities
        .get(&identity)
        .ok_or_else(|| anyhow!("identity {} not found", fmt_id(identity)))?;
    let public = read_bytes(reader, row.sign_pk).context("read identity public key")?;
    match secret {
        IdentitySecret::Password(password) => {
            let lockbox = row.lockbox.ok_or_else(|| {
                anyhow!(
                    "identity {} keeps no lockbox; it is a node identity, so unlock it with that node's signing key",
                    fmt_id(identity)
                )
            })?;
            let lockbox = read_bytes(reader, lockbox).context("read identity lockbox")?;
            let private = unlock_secret_key(password, &lockbox)?;
            box_keypair_from_ed25519(&private, &public)
        }
        IdentitySecret::Node(signing_key) => {
            if signing_key.verifying_key().to_bytes()[..] != public[..] {
                bail!(
                    "the presented signing key is not the key of identity {}",
                    fmt_id(identity)
                );
            }
            box_keypair_from_ed25519(&signing_key.to_keypair_bytes(), &public)
        }
    }
}

/// Recover the unique DEK assertion without selecting an arbitrary wrap.
/// Independent duplicate wraps are valid iff they all open to the same key.
fn recover_dek(
    reader: &PileReader,
    catalog: &SecretsCatalog,
    secret: Id,
    identity: Id,
    identity_secret: &IdentitySecret,
) -> Result<Key> {
    let keypair = identity_box_keypair(reader, catalog, identity, identity_secret)?;
    let wraps = catalog.wraps_for(secret, identity);
    if wraps.is_empty() {
        bail!("no wrap for {} on this secret", fmt_id(identity));
    }
    let mut keys = BTreeSet::new();
    for wrap in wraps {
        let sealed = read_bytes(reader, wrap.sealed_dek)
            .with_context(|| format!("read wrap {}", fmt_id(wrap.id)))?;
        let bytes = DryocBox::from_sealed_bytes(&sealed)
            .map_err(|error| anyhow!("parse wrap {}: {error:?}", fmt_id(wrap.id)))?
            .unseal_to_vec(&keypair)
            .map_err(|_| anyhow!("unseal wrap {} failed", fmt_id(wrap.id)))?;
        if bytes.len() != 32 {
            bail!("wrap {} opened to a malformed DEK", fmt_id(wrap.id));
        }
        keys.insert(bytes);
    }
    if keys.len() != 1 {
        bail!(
            "{} independent wraps for secret {} and identity {} open to competing DEKs",
            keys.len(),
            fmt_id(secret),
            fmt_id(identity)
        );
    }
    let bytes = keys.into_iter().next().expect("one DEK checked above");
    Key::try_from(&bytes[..]).context("decode DEK")
}

fn decrypt_secret_body(
    reader: &PileReader,
    catalog: &SecretsCatalog,
    secret: Id,
    dek: &Key,
) -> Result<Vec<u8>> {
    let row = catalog
        .secrets
        .get(&secret)
        .ok_or_else(|| anyhow!("secret {} not found", fmt_id(secret)))?;
    let body = read_bytes(reader, row.body).context("read encrypted secret body")?;
    if body.len() < SECRET_BODY_MIN_BYTES {
        bail!(
            "secret {} body is too short: expected at least {SECRET_BODY_MIN_BYTES} bytes, got {}",
            fmt_id(secret),
            body.len(),
        );
    }
    let nonce = Nonce::try_from(&body[..24]).context("secret nonce")?;
    DryocSecretBox::from_bytes(&body[24..])
        .map_err(|error| anyhow!("parse secret body: {error:?}"))?
        .decrypt_to_vec(&nonce, dek)
        .map_err(|_| anyhow!("decrypt secret body failed"))
}

fn recipient_public_keys(
    reader: &PileReader,
    catalog: &SecretsCatalog,
    scope: Id,
) -> Result<Vec<(Id, BoxPublicKey)>> {
    let recipients = catalog.recipients_of(scope);
    if recipients.is_empty() {
        bail!(
            "scope {} has no live recipients; grant access first",
            fmt_id(scope)
        );
    }
    recipients
        .into_iter()
        .map(|recipient| {
            let row = catalog
                .identities
                .get(&recipient)
                .ok_or_else(|| anyhow!("recipient {} has no identity record", fmt_id(recipient)))?;
            let public = read_bytes(reader, row.sign_pk)
                .with_context(|| format!("read key for {}", fmt_id(recipient)))?;
            Ok((recipient, box_pk_from_ed25519(&public)?))
        })
        .collect()
}

/// Prepare an Ed25519 identity whose private key is password-locked in the
/// canonical Secrets wire format.
pub fn prepare_identity(
    nickname: &str,
    password: &[u8],
    created_at: IntervalValue,
) -> Result<PreparedIdentity> {
    let keypair = SigningKeyPair::gen_with_defaults();
    let public_key = keypair.public_key.to_vec();
    let lockbox = lock_secret_key(password, &keypair.secret_key);
    let id = genid().id;
    let fragment =
        identity_fragment(id, nickname, public_key.clone(), Some(lockbox), created_at)?;
    Ok(PreparedIdentity {
        fragment,
        id,
        public_key,
    })
}

/// Name one node's Ed25519 signing key as an identity.
///
/// The record carries only public material, so this needs neither the node's
/// private key nor its participation: a public key read out of a commit the
/// node already signed is enough. That is what removes the key-distribution
/// ceremony -- and it grants nothing. The named identity is a principal an
/// admin may now grant into a scope, no more.
pub fn prepare_node_identity(
    nickname: &str,
    sign_pk: &[u8],
    created_at: IntervalValue,
) -> Result<PreparedIdentity> {
    let public_key = sign_pk.to_vec();
    let id = genid().id;
    let fragment = identity_fragment(id, nickname, public_key.clone(), None, created_at)?;
    Ok(PreparedIdentity {
        fragment,
        id,
        public_key,
    })
}

/// Encrypt one immutable version and seal its DEK to every current recipient.
pub fn seal_version(
    reader: &PileReader,
    catalog: &SecretsCatalog,
    scope: Id,
    name: &str,
    plaintext: &[u8],
    created_at: IntervalValue,
) -> Result<SealedVersion> {
    let recipients = recipient_public_keys(reader, catalog, scope)?;
    let dek = Key::gen();
    let nonce = Nonce::gen();
    let ciphertext = DryocSecretBox::encrypt_to_vecbox(plaintext, &nonce, &dek).to_vec();
    let mut body = Vec::with_capacity(nonce.len() + ciphertext.len());
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&ciphertext);

    let wraps: Result<Vec<_>> = recipients
        .iter()
        .map(|(recipient, public)| {
            let sealed_dek = DryocBox::seal_to_vecbox(&dek, public)
                .map_err(|error| anyhow!("seal to {}: {error:?}", fmt_id(*recipient)))?
                .to_vec();
            Ok(SealedWrap {
                id: genid().id,
                recipient: *recipient,
                sealed_dek,
            })
        })
        .collect();
    let secret = genid().id;
    let fragment = secret_version_fragment(secret, scope, name, body, wraps?, created_at)?;
    Ok(SealedVersion {
        fragment,
        secret,
        recipient_count: recipients.len(),
    })
}

/// Open one exact immutable secret version as one identity.
pub fn open_version(
    reader: &PileReader,
    catalog: &SecretsCatalog,
    secret: Id,
    identity: Id,
    identity_secret: &IdentitySecret,
) -> Result<Vec<u8>> {
    let dek = recover_dek(reader, catalog, secret, identity, identity_secret)?;
    decrypt_secret_body(reader, catalog, secret, &dek)
}

/// Add wraps for current recipients who cannot yet open an existing version.
/// An empty fragment and zero count mean that the version is already shared
/// to the complete current recipient set.
pub fn share_version(
    reader: &PileReader,
    catalog: &SecretsCatalog,
    secret: Id,
    acting_identity: Id,
    identity_secret: &IdentitySecret,
    created_at: IntervalValue,
) -> Result<SharedVersion> {
    let scope = catalog
        .secrets
        .get(&secret)
        .ok_or_else(|| anyhow!("secret {} not found", fmt_id(secret)))?
        .scope;
    let dek = recover_dek(reader, catalog, secret, acting_identity, identity_secret)?;
    let existing: BTreeSet<Id> = catalog.wrap_holders(secret).into_iter().collect();
    let missing: Vec<_> = recipient_public_keys(reader, catalog, scope)?
        .into_iter()
        .filter(|(recipient, _)| !existing.contains(recipient))
        .collect();

    let mut fragment = Fragment::empty();
    for (recipient, public) in &missing {
        let sealed_dek = DryocBox::seal_to_vecbox(&dek, public)
            .map_err(|error| anyhow!("seal to {}: {error:?}", fmt_id(*recipient)))?
            .to_vec();
        fragment += wrap_fragment(genid().id, secret, *recipient, sealed_dek, created_at)?;
    }
    Ok(SharedVersion {
        fragment,
        new_recipient_count: missing.len(),
    })
}

/// Exercise the crypto envelope without touching a pile.
pub fn envelope_selftest() -> Result<()> {
    let alice = BoxKeyPair::gen_with_defaults();
    let outsider = BoxKeyPair::gen_with_defaults();
    let plaintext = b"the prod database password is hunter2";
    let dek = Key::gen();
    let nonce = Nonce::gen();
    let body = DryocSecretBox::encrypt_to_vecbox(plaintext, &nonce, &dek).to_vec();
    let wrap = DryocBox::seal_to_vecbox(&dek, &alice.public_key)?.to_vec();

    let recovered = DryocBox::from_sealed_bytes(&wrap)
        .map_err(|error| anyhow!("{error:?}"))?
        .unseal_to_vec(&alice)
        .map_err(|error| anyhow!("{error:?}"))?;
    let recovered = Key::try_from(&recovered[..])?;
    let opened = DryocSecretBox::from_bytes(&body)
        .map_err(|error| anyhow!("{error:?}"))?
        .decrypt_to_vec(&nonce, &recovered)
        .map_err(|error| anyhow!("{error:?}"))?;
    if opened != plaintext {
        bail!("envelope round-trip changed the plaintext");
    }
    if DryocBox::from_sealed_bytes(&wrap)
        .expect("the same valid sealed box")
        .unseal_to_vec(&outsider)
        .is_ok()
    {
        bail!("an unrelated identity opened the envelope");
    }
    Ok(())
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn exactly_one<T>(entity: Id, field: &str, mut values: Vec<T>) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "Secrets entity {} has {} values for {field}; expected exactly one",
            fmt_id(entity),
            values.len()
        );
    }
    Ok(values.pop().expect("length checked above"))
}

fn at_most_one<T>(entity: Id, field: &str, mut values: Vec<T>) -> Result<Option<T>> {
    if values.len() > 1 {
        bail!(
            "Secrets entity {} has {} values for {field}; expected at most one",
            fmt_id(entity),
            values.len()
        );
    }
    Ok(values.pop())
}

fn point_interval(entity: Id, field: &str, value: IntervalValue) -> Result<()> {
    let (lower, upper): (i128, i128) = value
        .try_from_inline()
        .map_err(|error| anyhow!("decode {field} on Secrets entity {entity:x}: {error:?}"))?;
    if lower != upper {
        bail!("{field} on Secrets entity {entity:x} must be a point interval");
    }
    Ok(())
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

pub fn interval_start(value: IntervalValue) -> i128 {
    let (start, _): (i128, i128) = value
        .try_from_inline()
        .expect("validated Secrets point interval");
    start
}

fn validate_short(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.trim() != value {
        bail!("{field} must be non-empty and have no surrounding whitespace");
    }
    if value.len() > 32 {
        bail!("{field} exceeds 32 UTF-8 bytes");
    }
    if value.as_bytes().contains(&0) {
        bail!("{field} contains a NUL byte");
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

fn identity_record(
    id: Id,
    created_at: IntervalValue,
    name: TextHandle,
    sign_pk: BytesHandle,
    lockbox: Option<BytesHandle>,
) -> Fragment {
    let mut fragment = entity! { ExclusiveId::force_ref(&id) @
        metadata::tag: &KIND_IDENTITY,
        metadata::created_at: created_at,
        metadata::name: name,
        identity_sign_pk: sign_pk,
    };
    if let Some(lockbox) = lockbox {
        fragment += entity! { ExclusiveId::force_ref(&id) @ identity_lockbox: lockbox };
    }
    fragment
}

fn scope_identity(creator: Id, name: TextHandle) -> Fragment {
    entity! { _ @
        scope_creator: creator,
        metadata::name: name,
    }
}

fn scope_identity_epochs(creator: Id, name: TextHandle) -> (Id, Id) {
    let current = scope_identity(creator, name)
        .root()
        .expect("scope identity has one intrinsic root");
    let creator: Inline<inlineencodings::GenId> = creator.to_inline();
    let legacy = triblespace::core::trible::intrinsic_entity_id_v1(vec![
        (scope_creator.id(), creator.raw),
        (metadata::name.id(), name.raw),
    ]);
    (current, legacy)
}

fn scope_record_at(
    id: Id,
    creator: Id,
    name: TextHandle,
    created_at: &BTreeSet<IntervalValue>,
) -> Fragment {
    let mut fragment = entity! { ExclusiveId::force_ref(&id) @
        scope_creator: creator,
        metadata::name: name,
        metadata::tag: &KIND_SCOPE,
    };
    for at in created_at {
        fragment += entity! { ExclusiveId::force_ref(&id) @ metadata::created_at: at };
    }
    fragment
}

fn scope_record(creator: Id, name: TextHandle, created_at: &BTreeSet<IntervalValue>) -> Fragment {
    let mut fragment = scope_identity(creator, name);
    let id = fragment
        .root()
        .expect("scope identity has one intrinsic root");
    fragment += entity! { ExclusiveId::force_ref(&id) @ metadata::tag: &KIND_SCOPE };
    for at in created_at {
        fragment += entity! { ExclusiveId::force_ref(&id) @ metadata::created_at: at };
    }
    fragment
}

fn grant_record(
    id: Id,
    created_at: IntervalValue,
    object: Id,
    relation: &str,
    subject: Id,
    issuer: Id,
    retractions: &BTreeSet<IntervalValue>,
) -> Fragment {
    let mut fragment = entity! { ExclusiveId::force_ref(&id) @
        metadata::tag: &KIND_GRANT,
        metadata::created_at: created_at,
        grant_object: object,
        grant_relation: relation,
        grant_subject: subject,
        grant_issuer: issuer,
    };
    for at in retractions {
        fragment += entity! { ExclusiveId::force_ref(&id) @ grant_retracted_at: at };
    }
    fragment
}

fn secret_record(
    id: Id,
    created_at: IntervalValue,
    scope: Id,
    name: &str,
    display_name: TextHandle,
    body: BytesHandle,
) -> Fragment {
    entity! { ExclusiveId::force_ref(&id) @
        metadata::tag: &KIND_SECRET,
        metadata::created_at: created_at,
        metadata::name: display_name,
        secret_scope: scope,
        secret_name: name,
        secret_body: body,
    }
}

fn wrap_record(
    id: Id,
    created_at: IntervalValue,
    secret: Id,
    recipient: Id,
    sealed_dek: BytesHandle,
) -> Fragment {
    entity! { ExclusiveId::force_ref(&id) @
        metadata::tag: &KIND_WRAP,
        metadata::created_at: created_at,
        wrap_secret: secret,
        wrap_recipient: recipient,
        wrap_dek: sealed_dek,
    }
}

fn identity_fragment(
    id: Id,
    nickname: &str,
    sign_pk: Vec<u8>,
    lockbox: Option<Vec<u8>>,
    created_at: IntervalValue,
) -> Result<Fragment> {
    validate_name("identity nickname", nickname)?;
    point_value("identity creation time", created_at)?;
    if sign_pk.len() != ED25519_PUBLIC_KEY_BYTES {
        bail!("Ed25519 public key must be {ED25519_PUBLIC_KEY_BYTES} bytes");
    }
    if lockbox.as_ref().is_some_and(|bytes| bytes.len() != LOCKBOX_BYTES) {
        bail!("identity lockbox must be {LOCKBOX_BYTES} bytes");
    }
    let mut fragment = Fragment::empty();
    let name = fragment.put(nickname.to_owned());
    let sign_pk = fragment.put::<blobencodings::RawBytes, _>(sign_pk);
    let lockbox = lockbox.map(|bytes| fragment.put::<blobencodings::RawBytes, _>(bytes));
    fragment += identity_record(id, created_at, name, sign_pk, lockbox);
    Ok(fragment)
}

pub fn scope_fragment(creator: Id, name: &str, created_at: IntervalValue) -> Result<Fragment> {
    validate_name("scope name", name)?;
    point_value("scope creation time", created_at)?;
    let mut fragment = Fragment::empty();
    let name = fragment.put(name.to_owned());
    fragment += scope_record(creator, name, &BTreeSet::from([created_at]));
    Ok(fragment)
}

pub fn grant_fragment(
    id: Id,
    object: Id,
    relation: &str,
    subject: Id,
    issuer: Id,
    created_at: IntervalValue,
) -> Result<Fragment> {
    validate_short("grant relation", relation)?;
    point_value("grant creation time", created_at)?;
    Ok(grant_record(
        id,
        created_at,
        object,
        relation,
        subject,
        issuer,
        &BTreeSet::new(),
    ))
}

pub fn retraction_fragment(
    grants: impl IntoIterator<Item = Id>,
    at: IntervalValue,
) -> Result<Fragment> {
    point_value("grant retraction time", at)?;
    let mut fragment = Fragment::empty();
    for grant in grants.into_iter().collect::<BTreeSet<_>>() {
        fragment += entity! { ExclusiveId::force_ref(&grant) @ grant_retracted_at: at };
    }
    Ok(fragment)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SealedWrap {
    id: Id,
    recipient: Id,
    sealed_dek: Vec<u8>,
}

fn secret_version_fragment(
    id: Id,
    scope: Id,
    name: &str,
    encrypted_body: Vec<u8>,
    wraps: Vec<SealedWrap>,
    created_at: IntervalValue,
) -> Result<Fragment> {
    validate_short("secret name", name)?;
    point_value("secret creation time", created_at)?;
    if encrypted_body.len() < SECRET_BODY_MIN_BYTES {
        bail!("encrypted secret body is too short");
    }
    if wraps.is_empty() {
        bail!("a secret version must have at least one recipient wrap");
    }
    let mut recipients = BTreeSet::new();
    let mut wrap_ids = BTreeSet::new();
    for wrap in &wraps {
        if !recipients.insert(wrap.recipient) {
            bail!("a newly sealed version contains duplicate recipient wraps");
        }
        if !wrap_ids.insert(wrap.id) {
            bail!("a newly sealed version contains duplicate wrap ids");
        }
        if wrap.sealed_dek.len() != SEALED_DEK_BYTES {
            bail!("sealed DEK must be {SEALED_DEK_BYTES} bytes");
        }
    }

    let mut fragment = Fragment::empty();
    let display_name = fragment.put(name.to_owned());
    let body = fragment.put::<blobencodings::RawBytes, _>(encrypted_body);
    fragment += secret_record(id, created_at, scope, name, display_name, body);
    for wrap in wraps {
        let sealed_dek = fragment.put::<blobencodings::RawBytes, _>(wrap.sealed_dek);
        fragment += wrap_record(wrap.id, created_at, id, wrap.recipient, sealed_dek);
    }
    Ok(fragment)
}

fn wrap_fragment(
    id: Id,
    secret: Id,
    recipient: Id,
    sealed_dek: Vec<u8>,
    created_at: IntervalValue,
) -> Result<Fragment> {
    point_value("wrap creation time", created_at)?;
    if sealed_dek.len() != SEALED_DEK_BYTES {
        bail!("sealed DEK must be {SEALED_DEK_BYTES} bytes");
    }
    let mut fragment = Fragment::empty();
    let handle = fragment.put::<blobencodings::RawBytes, _>(sealed_dek);
    fragment += wrap_record(id, created_at, secret, recipient, handle);
    Ok(fragment)
}

fn entity_facts(space: &TribleSet, entity: Id) -> TribleSet {
    let mut facts = TribleSet::new();
    for fact in space.iter().filter(|fact| fact.e() == &entity) {
        facts.insert(fact);
    }
    facts
}

fn tagged_entities(space: &TribleSet, kind: Id) -> BTreeSet<Id> {
    find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: kind }])).collect()
}

fn load_identity(space: &TribleSet, id: Id) -> Result<IdentityRow> {
    let row = IdentityRow {
        id,
        created_at: exactly_one(
            id,
            "metadata::created_at",
            find!(value: IntervalValue, pattern!(space, [{ id @ metadata::created_at: ?value }]))
                .collect(),
        )?,
        name: exactly_one(
            id,
            "metadata::name",
            find!(value: TextHandle, pattern!(space, [{ id @ metadata::name: ?value }])).collect(),
        )?,
        sign_pk: exactly_one(
            id,
            "identity_sign_pk",
            find!(value: BytesHandle, pattern!(space, [{ id @ identity_sign_pk: ?value }]))
                .collect(),
        )?,
        lockbox: at_most_one(
            id,
            "identity_lockbox",
            find!(value: BytesHandle, pattern!(space, [{ id @ identity_lockbox: ?value }]))
                .collect(),
        )?,
    };
    point_interval(id, "identity creation time", row.created_at)?;
    if entity_facts(space, id)
        != *identity_record(id, row.created_at, row.name, row.sign_pk, row.lockbox).facts()
    {
        bail!(
            "Secrets identity {} is not one canonical immutable record",
            fmt_id(id)
        );
    }
    Ok(row)
}

fn load_scope(space: &TribleSet, id: Id) -> Result<ScopeRow> {
    let row = ScopeRow {
        id,
        creator: exactly_one(
            id,
            "scope_creator",
            find!(value: Id, pattern!(space, [{ id @ scope_creator: ?value }])).collect(),
        )?,
        created_at: find!(
            value: IntervalValue,
            pattern!(space, [{ id @ metadata::created_at: ?value }])
        )
        .collect(),
        name: exactly_one(
            id,
            "metadata::name",
            find!(value: TextHandle, pattern!(space, [{ id @ metadata::name: ?value }])).collect(),
        )?,
    };
    if row.created_at.is_empty() {
        bail!("Secrets scope {} has no creation observation", fmt_id(id));
    }
    for value in &row.created_at {
        point_interval(id, "scope creation time", *value)?;
    }
    let (current, legacy) = scope_identity_epochs(row.creator, row.name);
    if id != current && id != legacy {
        bail!(
            "Secrets scope {} is neither the current {} nor legacy {} intrinsic creator/name identity",
            fmt_id(id),
            fmt_id(current),
            fmt_id(legacy),
        );
    }
    let expected = scope_record_at(id, row.creator, row.name, &row.created_at);
    if entity_facts(space, id) != *expected.facts() {
        bail!(
            "Secrets scope {} is not one canonical immutable record",
            fmt_id(id)
        );
    }
    Ok(row)
}

fn load_grant(space: &TribleSet, id: Id) -> Result<GrantRow> {
    let row = GrantRow {
        id,
        created_at: exactly_one(
            id,
            "metadata::created_at",
            find!(value: IntervalValue, pattern!(space, [{ id @ metadata::created_at: ?value }]))
                .collect(),
        )?,
        object: exactly_one(
            id,
            "grant_object",
            find!(value: Id, pattern!(space, [{ id @ grant_object: ?value }])).collect(),
        )?,
        relation: exactly_one(
            id,
            "grant_relation",
            find!(value: String, pattern!(space, [{ id @ grant_relation: ?value }])).collect(),
        )?,
        subject: exactly_one(
            id,
            "grant_subject",
            find!(value: Id, pattern!(space, [{ id @ grant_subject: ?value }])).collect(),
        )?,
        issuer: exactly_one(
            id,
            "grant_issuer",
            find!(value: Id, pattern!(space, [{ id @ grant_issuer: ?value }])).collect(),
        )?,
        retracted_at: find!(
            value: IntervalValue,
            pattern!(space, [{ id @ grant_retracted_at: ?value }])
        )
        .collect(),
    };
    point_interval(id, "grant creation time", row.created_at)?;
    validate_short("grant relation", &row.relation)?;
    for value in &row.retracted_at {
        point_interval(id, "grant retraction time", *value)?;
    }
    let expected = grant_record(
        id,
        row.created_at,
        row.object,
        &row.relation,
        row.subject,
        row.issuer,
        &row.retracted_at,
    );
    if entity_facts(space, id) != *expected.facts() {
        bail!(
            "Secrets grant {} is not one canonical grant record",
            fmt_id(id)
        );
    }
    Ok(row)
}

fn load_secret(space: &TribleSet, id: Id) -> Result<SecretRow> {
    let row = SecretRow {
        id,
        created_at: exactly_one(
            id,
            "metadata::created_at",
            find!(value: IntervalValue, pattern!(space, [{ id @ metadata::created_at: ?value }]))
                .collect(),
        )?,
        scope: exactly_one(
            id,
            "secret_scope",
            find!(value: Id, pattern!(space, [{ id @ secret_scope: ?value }])).collect(),
        )?,
        name: exactly_one(
            id,
            "secret_name",
            find!(value: String, pattern!(space, [{ id @ secret_name: ?value }])).collect(),
        )?,
        display_name: exactly_one(
            id,
            "metadata::name",
            find!(value: TextHandle, pattern!(space, [{ id @ metadata::name: ?value }])).collect(),
        )?,
        body: exactly_one(
            id,
            "secret_body",
            find!(value: BytesHandle, pattern!(space, [{ id @ secret_body: ?value }])).collect(),
        )?,
    };
    point_interval(id, "secret creation time", row.created_at)?;
    validate_short("secret name", &row.name)?;
    let expected = secret_record(
        id,
        row.created_at,
        row.scope,
        &row.name,
        row.display_name,
        row.body,
    );
    if entity_facts(space, id) != *expected.facts() {
        bail!(
            "Secrets version {} is not one canonical immutable record",
            fmt_id(id)
        );
    }
    Ok(row)
}

fn load_wrap(space: &TribleSet, id: Id) -> Result<WrapRow> {
    let row = WrapRow {
        id,
        created_at: exactly_one(
            id,
            "metadata::created_at",
            find!(value: IntervalValue, pattern!(space, [{ id @ metadata::created_at: ?value }]))
                .collect(),
        )?,
        secret: exactly_one(
            id,
            "wrap_secret",
            find!(value: Id, pattern!(space, [{ id @ wrap_secret: ?value }])).collect(),
        )?,
        recipient: exactly_one(
            id,
            "wrap_recipient",
            find!(value: Id, pattern!(space, [{ id @ wrap_recipient: ?value }])).collect(),
        )?,
        sealed_dek: exactly_one(
            id,
            "wrap_dek",
            find!(value: BytesHandle, pattern!(space, [{ id @ wrap_dek: ?value }])).collect(),
        )?,
    };
    point_interval(id, "wrap creation time", row.created_at)?;
    if entity_facts(space, id)
        != *wrap_record(
            id,
            row.created_at,
            row.secret,
            row.recipient,
            row.sealed_dek,
        )
        .facts()
    {
        bail!(
            "Secrets wrap {} is not one canonical immutable record",
            fmt_id(id)
        );
    }
    Ok(row)
}

/// Strictly project the complete collection without dereferencing attachments.
pub fn load_catalog(space: &TribleSet) -> Result<SecretsCatalog> {
    let identity_ids = tagged_entities(space, KIND_IDENTITY);
    let scope_ids = tagged_entities(space, KIND_SCOPE);
    let grant_ids = tagged_entities(space, KIND_GRANT);
    let secret_ids = tagged_entities(space, KIND_SECRET);
    let wrap_ids = tagged_entities(space, KIND_WRAP);

    let mut catalog = SecretsCatalog::default();
    for id in &identity_ids {
        catalog.identities.insert(*id, load_identity(space, *id)?);
    }
    for id in &scope_ids {
        catalog.scopes.insert(*id, load_scope(space, *id)?);
    }
    let mut logical_scopes = BTreeMap::new();
    for scope in catalog.scopes.values() {
        if let Some(previous) = logical_scopes.insert((scope.creator, scope.name), scope.id) {
            bail!(
                "Secrets scopes {} and {} claim the same intrinsic creator/name identity",
                fmt_id(previous),
                fmt_id(scope.id),
            );
        }
    }
    for id in &grant_ids {
        catalog.grants.insert(*id, load_grant(space, *id)?);
    }
    for id in &secret_ids {
        catalog.secrets.insert(*id, load_secret(space, *id)?);
    }
    for id in &wrap_ids {
        catalog.wraps.insert(*id, load_wrap(space, *id)?);
    }

    for scope in catalog.scopes.values() {
        if !catalog.identities.contains_key(&scope.creator) {
            bail!(
                "Secrets scope {} refers to missing creator identity {}",
                fmt_id(scope.id),
                fmt_id(scope.creator)
            );
        }
    }
    for grant in catalog.grants.values() {
        if !catalog.scopes.contains_key(&grant.object) {
            bail!(
                "Secrets grant {} refers to missing scope {}",
                fmt_id(grant.id),
                fmt_id(grant.object)
            );
        }
        if !catalog.identities.contains_key(&grant.issuer) {
            bail!(
                "Secrets grant {} refers to missing issuer identity {}",
                fmt_id(grant.id),
                fmt_id(grant.issuer)
            );
        }
        if !catalog.identities.contains_key(&grant.subject)
            && !catalog.scopes.contains_key(&grant.subject)
        {
            bail!(
                "Secrets grant {} refers to missing identity or scope subject {}",
                fmt_id(grant.id),
                fmt_id(grant.subject)
            );
        }
    }
    for secret in catalog.secrets.values() {
        if !catalog.scopes.contains_key(&secret.scope) {
            bail!(
                "Secrets version {} refers to missing scope {}",
                fmt_id(secret.id),
                fmt_id(secret.scope)
            );
        }
        if !catalog.wraps.values().any(|wrap| wrap.secret == secret.id) {
            bail!(
                "Secrets version {} has no recipient wrap",
                fmt_id(secret.id)
            );
        }
    }
    for wrap in catalog.wraps.values() {
        if !catalog.secrets.contains_key(&wrap.secret) {
            bail!(
                "Secrets wrap {} refers to missing secret version {}",
                fmt_id(wrap.id),
                fmt_id(wrap.secret)
            );
        }
        if !catalog.identities.contains_key(&wrap.recipient) {
            bail!(
                "Secrets wrap {} refers to missing recipient identity {}",
                fmt_id(wrap.id),
                fmt_id(wrap.recipient)
            );
        }
    }

    let all_ids: BTreeSet<Id> = identity_ids
        .into_iter()
        .chain(scope_ids)
        .chain(grant_ids)
        .chain(secret_ids)
        .chain(wrap_ids)
        .collect();
    let accounted: usize = all_ids
        .iter()
        .map(|id| entity_facts(space, *id).len())
        .sum();
    if accounted != space.len() {
        bail!(
            "Secrets collection has {} facts outside canonical identity, scope, grant, secret, and wrap records",
            space.len() - accounted.min(space.len())
        );
    }
    Ok(catalog)
}

fn read_text_overlay<Overlay>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    handle: TextHandle,
) -> Result<String>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    if let Some(overlay) = overlay {
        if overlay.metadata(handle)?.is_some() {
            let value: anybytes::View<str> = overlay.get(handle)?;
            return Ok(value.to_string());
        }
    }
    let value: anybytes::View<str> = reader.get(handle)?;
    Ok(value.to_string())
}

fn read_bytes_overlay<Overlay>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    handle: BytesHandle,
) -> Result<Vec<u8>>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    if let Some(overlay) = overlay {
        if overlay.metadata(handle)?.is_some() {
            let value: anybytes::Bytes = overlay.get(handle)?;
            return Ok(value.as_ref().to_vec());
        }
    }
    let value: anybytes::Bytes = reader.get(handle)?;
    Ok(value.as_ref().to_vec())
}

fn validate_payloads<Overlay>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    catalog: &SecretsCatalog,
) -> Result<()>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    let mut keys: BTreeMap<Vec<u8>, Id> = BTreeMap::new();
    for identity in catalog.identities.values() {
        let name = read_text_overlay(reader, overlay, identity.name)
            .with_context(|| format!("read identity {} nickname", fmt_id(identity.id)))?;
        validate_name("identity nickname", &name)?;
        let pk = read_bytes_overlay(reader, overlay, identity.sign_pk)
            .with_context(|| format!("read identity {} public key", fmt_id(identity.id)))?;
        if pk.len() != ED25519_PUBLIC_KEY_BYTES {
            bail!(
                "identity {} has a malformed Ed25519 public key",
                fmt_id(identity.id)
            );
        }
        // One key, one identity. Without this a node key could be named twice
        // and `identity_by_public_key` would have to choose, which is exactly
        // the arbitration this collection refuses everywhere else.
        if let Some(previous) = keys.insert(pk, identity.id) {
            bail!(
                "identities {} and {} claim the same Ed25519 public key",
                fmt_id(previous),
                fmt_id(identity.id)
            );
        }
        if let Some(handle) = identity.lockbox {
            let lockbox = read_bytes_overlay(reader, overlay, handle)
                .with_context(|| format!("read identity {} lockbox", fmt_id(identity.id)))?;
            if lockbox.len() != LOCKBOX_BYTES {
                bail!("identity {} has a malformed lockbox", fmt_id(identity.id));
            }
        }
    }
    for scope in catalog.scopes.values() {
        let name = read_text_overlay(reader, overlay, scope.name)
            .with_context(|| format!("read scope {} name", fmt_id(scope.id)))?;
        validate_name("scope name", &name)?;
    }
    for secret in catalog.secrets.values() {
        let display_name = read_text_overlay(reader, overlay, secret.display_name)
            .with_context(|| format!("read secret {} display name", fmt_id(secret.id)))?;
        if display_name != secret.name {
            bail!(
                "secret {} has disagreeing metadata::name and secret_name values",
                fmt_id(secret.id)
            );
        }
        let body = read_bytes_overlay(reader, overlay, secret.body)
            .with_context(|| format!("read secret {} body", fmt_id(secret.id)))?;
        if body.len() < SECRET_BODY_MIN_BYTES {
            bail!(
                "secret {} has a malformed encrypted body",
                fmt_id(secret.id)
            );
        }
    }
    for wrap in catalog.wraps.values() {
        let sealed = read_bytes_overlay(reader, overlay, wrap.sealed_dek)
            .with_context(|| format!("read wrap {} sealed DEK", fmt_id(wrap.id)))?;
        if sealed.len() != SEALED_DEK_BYTES {
            bail!("wrap {} has a malformed sealed DEK", fmt_id(wrap.id));
        }
    }
    Ok(())
}

/// Validate one complete authorized Secrets collection and every attachment.
pub fn validate_catalog(reader: &PileReader, facts: &TribleSet) -> Result<SecretsCatalog> {
    let catalog = load_catalog(facts)?;
    validate_payloads(reader, None::<&PileReader>, &catalog)?;
    Ok(catalog)
}

/// Validate the exact union a proposed publication would create, including
/// attachments staged only inside `fragment`, before any pile bytes are
/// written or signed root is published.
pub fn validate_candidate(
    reader: &PileReader,
    current: &TribleSet,
    fragment: &Fragment,
) -> Result<SecretsCatalog> {
    let mut union = current.clone();
    union += fragment.facts().clone();
    let catalog = load_catalog(&union)?;
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .reader()
        .context("snapshot staged Secrets attachments")?;
    validate_payloads(reader, Some(&overlay), &catalog)?;
    Ok(catalog)
}

pub fn read_text(reader: &PileReader, handle: TextHandle) -> Result<String> {
    read_text_overlay(reader, None::<&PileReader>, handle)
}

pub fn read_bytes(reader: &PileReader, handle: BytesHandle) -> Result<Vec<u8>> {
    read_bytes_overlay(reader, None::<&PileReader>, handle)
}

fn named_candidates(
    reader: &PileReader,
    rows: impl IntoIterator<Item = (Id, TextHandle)>,
    input: &str,
) -> Result<Vec<Id>> {
    let mut matches = Vec::new();
    for (id, handle) in rows {
        if read_text(reader, handle)? == input {
            matches.push(id);
        }
    }
    matches.sort_unstable();
    matches.dedup();
    Ok(matches)
}

fn resolve_rows(
    reader: &PileReader,
    rows: Vec<(Id, TextHandle)>,
    input: &str,
    kind: &str,
) -> Result<Id> {
    if let Ok(id) = resolve_id_prefix(input, rows.iter().map(|(id, _)| *id)) {
        return Ok(id);
    }
    let named = named_candidates(reader, rows, input)?;
    match named.as_slice() {
        [id] => Ok(*id),
        [] => bail!("no {kind} matches '{input}' by id or name"),
        ids => bail!("{kind} name '{input}' is ambiguous ({} matches)", ids.len()),
    }
}

fn resolve_id_prefix(input: &str, candidates: impl IntoIterator<Item = Id>) -> Result<Id> {
    let input = input.trim();
    if input.len() == 32 {
        return Id::from_hex(input).ok_or_else(|| anyhow!("invalid entity id '{input}'"));
    }
    if input.is_empty() || input.len() > 32 || !input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid entity id prefix '{input}'");
    }
    let input = input.to_ascii_lowercase();
    let mut matches: Vec<_> = candidates
        .into_iter()
        .filter(|candidate| format!("{candidate:x}").starts_with(&input))
        .collect();
    matches.sort_unstable();
    matches.dedup();
    match matches.as_slice() {
        [id] => Ok(*id),
        [] => bail!("no entity matches id prefix '{input}'"),
        many => bail!(
            "entity id prefix '{input}' is ambiguous ({} matches)",
            many.len()
        ),
    }
}

pub fn resolve_identity(reader: &PileReader, catalog: &SecretsCatalog, input: &str) -> Result<Id> {
    resolve_rows(
        reader,
        catalog
            .identities
            .values()
            .map(|row| (row.id, row.name))
            .collect(),
        input,
        "identity",
    )
}

pub fn resolve_scope(reader: &PileReader, catalog: &SecretsCatalog, input: &str) -> Result<Id> {
    resolve_rows(
        reader,
        catalog
            .scopes
            .values()
            .map(|row| (row.id, row.name))
            .collect(),
        input,
        "scope",
    )
}

/// Find the one scope with an exact logical `(creator, name)` identity across
/// both intrinsic-identity epochs. New scopes use the current epoch, while an
/// exact legacy scope is reused rather than duplicated under a new id.
pub fn scope_by_creator_and_name(
    reader: &PileReader,
    catalog: &SecretsCatalog,
    creator: Id,
    name: &str,
) -> Result<Option<Id>> {
    let mut matches = Vec::new();
    for scope in catalog
        .scopes
        .values()
        .filter(|scope| scope.creator == creator)
    {
        if read_text(reader, scope.name)? == name {
            matches.push(scope.id);
        }
    }
    matches.sort_unstable();
    matches.dedup();
    match matches.as_slice() {
        [] => Ok(None),
        [scope] => Ok(Some(*scope)),
        many => bail!(
            "creator {} has {} scopes named '{name}'",
            fmt_id(creator),
            many.len(),
        ),
    }
}

/// Resolve a grant subject across identities and nested scopes. A label shared
/// by both kinds is explicitly ambiguous.
pub fn resolve_principal(reader: &PileReader, catalog: &SecretsCatalog, input: &str) -> Result<Id> {
    let rows: Vec<_> = catalog
        .identities
        .values()
        .map(|row| (row.id, row.name))
        .chain(catalog.scopes.values().map(|row| (row.id, row.name)))
        .collect();
    resolve_rows(reader, rows, input, "identity or scope")
}

/// The Ed25519 public key one identity is bound to.
pub fn identity_public_key(
    reader: &PileReader,
    catalog: &SecretsCatalog,
    identity: Id,
) -> Result<Vec<u8>> {
    let row = catalog
        .identities
        .get(&identity)
        .ok_or_else(|| anyhow!("identity {} not found", fmt_id(identity)))?;
    read_bytes(reader, row.sign_pk)
}

/// The identity, if any, already bound to one Ed25519 public key.
///
/// This is the join between a node observed in the pile's commits and a named
/// Secrets principal. It reports naming, never authority: an identity found
/// here still holds exactly the grants it was given.
pub fn identity_by_public_key(
    reader: &PileReader,
    catalog: &SecretsCatalog,
    public_key: &[u8],
) -> Result<Option<Id>> {
    for row in catalog.identities.values() {
        if read_bytes(reader, row.sign_pk)? == public_key {
            // `validate_payloads` rejects two identities on one key, so the
            // first match on a validated catalog is the only match.
            return Ok(Some(row.id));
        }
    }
    Ok(None)
}

pub fn entity_name(reader: &PileReader, catalog: &SecretsCatalog, id: Id) -> Result<String> {
    if let Some(row) = catalog.identities.get(&id) {
        return read_text(reader, row.name);
    }
    if let Some(row) = catalog.scopes.get(&id) {
        return read_text(reader, row.name);
    }
    Ok(fmt_id(id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::path::Path;

    use crate::schema::DEFAULT_SCOPE_ID;
    use triblespace::core::collection::{discover_collection_records, Collection};
    use triblespace::core::repo::pile::{Pile, PileReader};
    use triblespace::core::repo::BlobStore;

    struct TestView {
        facts: TribleSet,
        reader: PileReader,
    }

    fn test_collection(path: &Path) -> Collection<Pile> {
        File::create(path).unwrap();
        let mut pile = Pile::open(path).unwrap();
        pile.refresh().unwrap();
        Collection::new(pile, DEFAULT_SCOPE_ID, SigningKey::generate(&mut OsRng))
    }

    fn test_view(collection: &mut Collection<Pile>) -> TestView {
        let facts = collection.materialize().unwrap();
        let reader = collection.storage_mut().reader().unwrap();
        TestView { facts, reader }
    }

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn at(second: i64) -> IntervalValue {
        let epoch = hifitime::Epoch::from_unix_seconds(second as f64);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn fixture() -> (Fragment, Id, Id, Id) {
        let alice = id(1);
        let bob = id(2);
        let mut fragment = identity_fragment(
            alice,
            "alice",
            vec![1; ED25519_PUBLIC_KEY_BYTES],
            Some(vec![2; LOCKBOX_BYTES]),
            at(1),
        )
        .unwrap();
        fragment += identity_fragment(
            bob,
            "bob",
            vec![3; ED25519_PUBLIC_KEY_BYTES],
            Some(vec![4; LOCKBOX_BYTES]),
            at(2),
        )
        .unwrap();
        let scope = scope_fragment(alice, "prod", at(3)).unwrap();
        let scope_id = scope.root().unwrap();
        fragment += scope;
        (fragment, alice, bob, scope_id)
    }

    #[test]
    fn high_level_envelope_roundtrip_share_and_competing_wrap_refusal() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("secrets.pile");
        let mut collection = test_collection(&pile);

        let alice_password = IdentitySecret::Password(b"alice correct horse".to_vec());
        let bob_password = IdentitySecret::Password(b"bob battery staple".to_vec());
        let alice = prepare_identity("alice", b"alice correct horse", at(1)).unwrap();
        let bob = prepare_identity("bob", b"bob battery staple", at(2)).unwrap();
        let alice_id = alice.id;
        let bob_id = bob.id;
        let mut foundation = alice.fragment;
        foundation += bob.fragment;
        let scope_fragment = scope_fragment(alice_id, "prod", at(3)).unwrap();
        let scope = scope_fragment.root().unwrap();
        foundation += scope_fragment;
        collection.commit(foundation).unwrap();

        let base = test_view(&mut collection);
        let base_catalog = validate_catalog(&base.reader, &base.facts).unwrap();
        let sealed = seal_version(
            &base.reader,
            &base_catalog,
            scope,
            "database",
            b"hunter2",
            at(4),
        )
        .unwrap();
        let secret = sealed.secret;
        assert_eq!(sealed.recipient_count, 1);
        collection.commit(sealed.fragment).unwrap();

        let sealed_view = test_view(&mut collection);
        let sealed_catalog = validate_catalog(&sealed_view.reader, &sealed_view.facts).unwrap();
        assert_eq!(
            open_version(
                &sealed_view.reader,
                &sealed_catalog,
                secret,
                alice_id,
                &alice_password,
            )
            .unwrap(),
            b"hunter2"
        );
        assert!(open_version(
            &sealed_view.reader,
            &sealed_catalog,
            secret,
            alice_id,
            &IdentitySecret::Password(b"wrong password".to_vec()),
        )
        .is_err());

        let grant = grant_fragment(id(90), scope, "member", bob_id, alice_id, at(5)).unwrap();
        collection.commit(grant).unwrap();
        let granted_view = test_view(&mut collection);
        let granted_catalog = validate_catalog(&granted_view.reader, &granted_view.facts).unwrap();
        let shared = share_version(
            &granted_view.reader,
            &granted_catalog,
            secret,
            alice_id,
            &alice_password,
            at(6),
        )
        .unwrap();
        assert_eq!(shared.new_recipient_count, 1);
        collection.commit(shared.fragment).unwrap();

        let shared_view = test_view(&mut collection);
        let shared_catalog = validate_catalog(&shared_view.reader, &shared_view.facts).unwrap();
        assert_eq!(
            open_version(
                &shared_view.reader,
                &shared_catalog,
                secret,
                bob_id,
                &bob_password,
            )
            .unwrap(),
            b"hunter2"
        );

        let bob_public = read_bytes(
            &shared_view.reader,
            shared_catalog.identities[&bob_id].sign_pk,
        )
        .unwrap();
        let competing_dek = Key::gen();
        let competing_wrap =
            DryocBox::seal_to_vecbox(&competing_dek, &box_pk_from_ed25519(&bob_public).unwrap())
                .unwrap()
                .to_vec();
        let competing = wrap_fragment(id(91), secret, bob_id, competing_wrap, at(7)).unwrap();
        collection.commit(competing).unwrap();
        let conflicting_view = test_view(&mut collection);
        let conflicting_catalog =
            validate_catalog(&conflicting_view.reader, &conflicting_view.facts).unwrap();
        let error = open_version(
            &conflicting_view.reader,
            &conflicting_catalog,
            secret,
            bob_id,
            &bob_password,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("competing DEKs"));
        collection.into_storage().close().unwrap();
    }

    /// The whole point of one key per node: the identity that signs a pile's
    /// commits is the identity a secret is sealed to, and its private half
    /// never leaves the signing-key file.
    #[test]
    fn a_node_identity_opens_a_version_with_its_own_signing_key() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("secrets.pile");
        let mut collection = test_collection(&pile);

        let alice_secret = IdentitySecret::Password(b"alice correct horse".to_vec());
        let alice = prepare_identity("alice", b"alice correct horse", at(1)).unwrap();
        let alice_id = alice.id;
        let node_key = SigningKey::generate(&mut OsRng);
        let node = prepare_node_identity(
            "node",
            node_key.verifying_key().as_bytes(),
            at(2),
        )
        .unwrap();
        let node_id = node.id;
        let mut foundation = alice.fragment;
        foundation += node.fragment;
        let scope_fragment = scope_fragment(alice_id, "prod", at(3)).unwrap();
        let scope = scope_fragment.root().unwrap();
        foundation += scope_fragment;
        collection.commit(foundation).unwrap();

        let base = test_view(&mut collection);
        let base_catalog = validate_catalog(&base.reader, &base.facts).unwrap();
        assert!(base_catalog.identities[&node_id].is_node_identity());
        assert!(!base_catalog.identities[&alice_id].is_node_identity());
        assert_eq!(
            identity_by_public_key(&base.reader, &base_catalog, node_key.verifying_key().as_bytes())
                .unwrap(),
            Some(node_id)
        );

        // Naming the node did not entitle it: the scope's recipients are still
        // its creator alone, so the new version is sealed only to alice.
        assert_eq!(base_catalog.recipients_of(scope), vec![alice_id]);
        let sealed = seal_version(
            &base.reader,
            &base_catalog,
            scope,
            "database",
            b"hunter2",
            at(4),
        )
        .unwrap();
        let secret = sealed.secret;
        assert_eq!(sealed.recipient_count, 1);
        collection.commit(sealed.fragment).unwrap();

        let sealed_view = test_view(&mut collection);
        let sealed_catalog = validate_catalog(&sealed_view.reader, &sealed_view.facts).unwrap();
        let refused = open_version(
            &sealed_view.reader,
            &sealed_catalog,
            secret,
            node_id,
            &IdentitySecret::Node(node_key.clone()),
        )
        .unwrap_err();
        assert!(format!("{refused:#}").contains("no wrap"), "{refused:#}");

        // Entitlement is the admin's separate act.
        let grant = grant_fragment(id(90), scope, "member", node_id, alice_id, at(5)).unwrap();
        collection.commit(grant).unwrap();
        let granted_view = test_view(&mut collection);
        let granted_catalog = validate_catalog(&granted_view.reader, &granted_view.facts).unwrap();
        let shared = share_version(
            &granted_view.reader,
            &granted_catalog,
            secret,
            alice_id,
            &alice_secret,
            at(6),
        )
        .unwrap();
        assert_eq!(shared.new_recipient_count, 1);
        collection.commit(shared.fragment).unwrap();

        let shared_view = test_view(&mut collection);
        let shared_catalog = validate_catalog(&shared_view.reader, &shared_view.facts).unwrap();
        assert_eq!(
            open_version(
                &shared_view.reader,
                &shared_catalog,
                secret,
                node_id,
                &IdentitySecret::Node(node_key),
            )
            .unwrap(),
            b"hunter2"
        );

        // Another node's key is not this identity, and says so before it
        // unseals anything.
        let stranger = open_version(
            &shared_view.reader,
            &shared_catalog,
            secret,
            node_id,
            &IdentitySecret::Node(SigningKey::generate(&mut OsRng)),
        )
        .unwrap_err();
        assert!(
            format!("{stranger:#}").contains("is not the key of identity"),
            "{stranger:#}"
        );

        // A node identity has no lockbox, so a password is not a way in.
        let by_password = open_version(
            &shared_view.reader,
            &shared_catalog,
            secret,
            node_id,
            &IdentitySecret::Password(b"guess".to_vec()),
        )
        .unwrap_err();
        assert!(format!("{by_password:#}").contains("keeps no lockbox"), "{by_password:#}");
        collection.into_storage().close().unwrap();
    }

    /// Removing a node is still expressible, and still lands on the rotation
    /// worklist rather than pretending the old wrap was forgotten.
    #[test]
    fn revoking_a_node_leaves_its_wrap_on_the_rotation_worklist() {
        let (mut fragment, alice, _bob, scope) = fixture();
        let node_key = SigningKey::generate(&mut OsRng);
        let node = prepare_node_identity("node", node_key.verifying_key().as_bytes(), at(4))
            .unwrap();
        let node_id = node.id;
        fragment += node.fragment;
        let grant = id(10);
        fragment += grant_fragment(grant, scope, "member", node_id, alice, at(5)).unwrap();

        let mut version = Fragment::empty();
        let name = version.put("db".to_owned());
        let body = version.put::<blobencodings::RawBytes, _>(vec![0; SECRET_BODY_MIN_BYTES]);
        let secret = id(20);
        version += secret_record(secret, at(6), scope, "db", name, body);
        for (wrap, recipient) in [(id(30), alice), (id(31), node_id)] {
            let sealed = version.put::<blobencodings::RawBytes, _>(vec![0; SEALED_DEK_BYTES]);
            version += wrap_record(wrap, at(6), secret, recipient, sealed);
        }
        fragment += version;

        let before = load_catalog(fragment.facts()).unwrap();
        assert_eq!(before.recipients_of(scope), vec![alice, node_id]);
        assert_eq!(before.wrap_holders(secret), vec![alice, node_id]);

        fragment += retraction_fragment([grant], at(7)).unwrap();
        let after = load_catalog(fragment.facts()).unwrap();
        assert_eq!(after.recipients_of(scope), vec![alice]);
        // Still holding a wrap it is no longer entitled to: exactly the
        // condition `secret rotate` reports.
        assert_eq!(after.wrap_holders(secret), vec![alice, node_id]);
    }

    #[test]
    fn two_identities_cannot_claim_one_node_key() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("secrets.pile");
        let mut collection = test_collection(&pile);
        let node_key = SigningKey::generate(&mut OsRng);
        let public = node_key.verifying_key();
        let mut fragment =
            prepare_node_identity("node", public.as_bytes(), at(1)).unwrap().fragment;
        fragment += prepare_node_identity("node-again", public.as_bytes(), at(2))
            .unwrap()
            .fragment;
        collection.commit(fragment).unwrap();

        let view = test_view(&mut collection);
        let error = validate_catalog(&view.reader, &view.facts).unwrap_err();
        assert!(
            format!("{error:#}").contains("claim the same Ed25519 public key"),
            "{error:#}"
        );
        collection.into_storage().close().unwrap();
    }

    #[test]
    fn opening_a_short_unvalidated_body_fails_instead_of_panicking() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("secrets.pile");
        let mut collection = test_collection(&pile);
        let mut resident = Fragment::empty();
        let body = resident.put::<blobencodings::RawBytes, _>(vec![0; 23]);
        let display_name = resident.put("broken".to_owned());
        collection.commit(resident).unwrap();

        let view = test_view(&mut collection);
        let secret = id(92);
        let mut catalog = SecretsCatalog::default();
        catalog.secrets.insert(
            secret,
            SecretRow {
                id: secret,
                created_at: at(1),
                scope: id(93),
                name: "broken".to_owned(),
                display_name,
                body,
            },
        );

        let error = decrypt_secret_body(&view.reader, &catalog, secret, &Key::gen()).unwrap_err();
        assert!(format!("{error:#}").contains("body is too short"));
        collection.into_storage().close().unwrap();
    }

    #[test]
    fn rooted_admin_fixpoint_and_or_set_retraction_survive_port() {
        let (mut fragment, alice, bob, scope) = fixture();
        let first = id(10);
        let second = id(11);
        fragment += grant_fragment(first, scope, "admin", bob, alice, at(4)).unwrap();
        fragment += grant_fragment(second, scope, "admin", bob, alice, at(5)).unwrap();
        fragment += retraction_fragment([first], at(6)).unwrap();

        let catalog = load_catalog(fragment.facts()).unwrap();
        assert_eq!(catalog.effective_admins(scope), HashSet::from([alice, bob]));
        assert!(!catalog.grant_is_live(first));
        assert!(catalog.grant_is_live(second));
    }

    #[test]
    fn removal_cascades_through_delegated_admins() {
        let (mut fragment, alice, bob, scope) = fixture();
        let carol = id(3);
        let dave = id(4);
        fragment += identity_fragment(
            carol,
            "carol",
            vec![5; ED25519_PUBLIC_KEY_BYTES],
            Some(vec![6; LOCKBOX_BYTES]),
            at(3),
        )
        .unwrap();
        fragment += identity_fragment(
            dave,
            "dave",
            vec![7; ED25519_PUBLIC_KEY_BYTES],
            Some(vec![8; LOCKBOX_BYTES]),
            at(4),
        )
        .unwrap();
        let bob_grant = id(10);
        fragment += grant_fragment(bob_grant, scope, "admin", bob, alice, at(5)).unwrap();
        fragment += grant_fragment(id(11), scope, "admin", carol, bob, at(6)).unwrap();
        fragment += retraction_fragment([bob_grant], at(7)).unwrap();
        fragment += grant_fragment(id(12), scope, "admin", dave, carol, at(8)).unwrap();

        let catalog = load_catalog(fragment.facts()).unwrap();
        assert_eq!(catalog.effective_admins(scope), HashSet::from([alice]));
    }

    #[test]
    fn concurrent_confederate_grant_by_removed_admin_is_inert() {
        let (mut fragment, alice, bob, scope) = fixture();
        let mallory = id(3);
        fragment += identity_fragment(
            mallory,
            "mallory",
            vec![5; ED25519_PUBLIC_KEY_BYTES],
            Some(vec![6; LOCKBOX_BYTES]),
            at(3),
        )
        .unwrap();
        let bob_grant = id(10);
        fragment += grant_fragment(bob_grant, scope, "admin", bob, alice, at(4)).unwrap();
        fragment += retraction_fragment([bob_grant], at(5)).unwrap();
        fragment += grant_fragment(id(11), scope, "admin", mallory, bob, at(6)).unwrap();

        let catalog = load_catalog(fragment.facts()).unwrap();
        assert_eq!(catalog.effective_admins(scope), HashSet::from([alice]));
    }

    #[test]
    fn root_admin_has_no_retractable_grant() {
        let (mut fragment, alice, bob, scope) = fixture();
        let grant = id(10);
        fragment += grant_fragment(grant, scope, "admin", bob, alice, at(4)).unwrap();
        fragment += retraction_fragment([grant], at(5)).unwrap();
        let catalog = load_catalog(fragment.facts()).unwrap();
        assert_eq!(catalog.effective_admins(scope), HashSet::from([alice]));
    }

    #[test]
    fn competing_scalar_values_are_rejected() {
        let (mut fragment, alice, bob, scope) = fixture();
        let grant = id(10);
        fragment += grant_fragment(grant, scope, "member", bob, alice, at(4)).unwrap();
        fragment += entity! { ExclusiveId::force_ref(&grant) @ grant_relation: "admin" };
        let error = load_catalog(fragment.facts()).unwrap_err();
        assert!(format!("{error:#}").contains("2 values for grant_relation"));
    }

    #[test]
    fn retractions_are_a_set_not_a_scalar_conflict() {
        let (mut fragment, alice, bob, scope) = fixture();
        let grant = id(10);
        fragment += grant_fragment(grant, scope, "member", bob, alice, at(4)).unwrap();
        fragment += retraction_fragment([grant], at(5)).unwrap();
        fragment += retraction_fragment([grant], at(6)).unwrap();
        let catalog = load_catalog(fragment.facts()).unwrap();
        assert_eq!(catalog.grants[&grant].retracted_at.len(), 2);
        assert!(!catalog.grant_is_live(grant));
    }

    #[test]
    fn scope_identity_is_intrinsic_and_creator_bound() {
        let first = scope_fragment(id(1), "prod", at(1)).unwrap();
        let same = scope_fragment(id(1), "prod", at(1)).unwrap();
        let other = scope_fragment(id(2), "prod", at(1)).unwrap();
        assert_eq!(first.root(), same.root());
        assert_ne!(first.root(), other.root());
    }

    #[test]
    fn repeated_intrinsic_scope_creation_is_a_set_of_observations() {
        let (mut fragment, alice, _bob, scope) = fixture();
        fragment += scope_fragment(alice, "prod", at(9)).unwrap();
        let catalog = load_catalog(fragment.facts()).unwrap();
        assert_eq!(
            catalog.scopes[&scope].created_at,
            BTreeSet::from([at(3), at(9)])
        );
    }

    #[test]
    fn legacy_intrinsic_scope_epoch_is_admitted_and_reused_logically() {
        let (mut fragment, alice, _bob, _current_scope) = fixture();
        let mut legacy_scope = Fragment::empty();
        let name = legacy_scope.put("legacy-prod".to_owned());
        let (current, legacy) = scope_identity_epochs(alice, name);
        assert_ne!(current, legacy);
        legacy_scope += scope_record_at(legacy, alice, name, &BTreeSet::from([at(8)]));
        fragment += legacy_scope;

        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("secrets.pile");
        let mut collection = test_collection(&pile);
        collection.commit(fragment).unwrap();
        let view = test_view(&mut collection);
        let catalog = validate_catalog(&view.reader, &view.facts).unwrap();
        assert_eq!(
            scope_by_creator_and_name(&view.reader, &catalog, alice, "legacy-prod").unwrap(),
            Some(legacy)
        );
        collection.into_storage().close().unwrap();
    }

    #[test]
    fn latest_timestamp_tie_is_visible_not_arbitrated() {
        let (mut fragment, alice, _bob, scope) = fixture();
        for (secret, wrap) in [(id(20), id(30)), (id(21), id(31))] {
            let mut record = Fragment::empty();
            let name = record.put("db".to_owned());
            let body = record.put::<blobencodings::RawBytes, _>(vec![0; SECRET_BODY_MIN_BYTES]);
            record += secret_record(secret, at(9), scope, "db", name, body);
            let sealed = record.put::<blobencodings::RawBytes, _>(vec![0; SEALED_DEK_BYTES]);
            record += wrap_record(wrap, at(9), secret, alice, sealed);
            fragment += record;
        }
        let catalog = load_catalog(fragment.facts()).unwrap();
        assert!(catalog.latest_secret(scope, "db").is_err());
    }

    #[test]
    fn nested_scope_membership_reaches_identity_leaves() {
        let (mut fragment, alice, bob, root) = fixture();
        let group = scope_fragment(bob, "group", at(4)).unwrap();
        let group_id = group.root().unwrap();
        fragment += group;
        fragment += grant_fragment(id(10), root, "member", group_id, alice, at(5)).unwrap();
        fragment += grant_fragment(id(11), group_id, "member", bob, bob, at(6)).unwrap();

        let catalog = load_catalog(fragment.facts()).unwrap();
        assert_eq!(catalog.recipients_of(root), vec![alice, bob]);
    }

    #[test]
    fn orphan_references_are_rejected_before_publication() {
        let (mut fragment, alice, bob, _scope) = fixture();
        fragment += grant_fragment(id(10), id(99), "member", bob, alice, at(4)).unwrap();
        let error = load_catalog(fragment.facts()).unwrap_err();
        assert!(format!("{error:#}").contains("refers to missing scope"));
    }

    #[test]
    fn staged_attachments_validate_and_roundtrip_one_signed_root() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("secrets.pile");
        let mut collection = test_collection(&pile);

        let before = test_view(&mut collection);
        let (fragment, alice, _bob, scope) = fixture();
        let candidate = validate_candidate(&before.reader, &before.facts, &fragment).unwrap();
        assert_eq!(candidate.scope_creator(scope), Some(alice));

        collection.commit(fragment).unwrap();
        let after = test_view(&mut collection);
        let catalog = validate_catalog(&after.reader, &after.facts).unwrap();
        assert_eq!(catalog.scope_creator(scope), Some(alice));
        let records = discover_collection_records(collection.storage_mut()).unwrap();
        assert_eq!(records.commits().len(), 1);
        collection.into_storage().close().unwrap();
    }
}
