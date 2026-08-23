//! Vault-epoch Secrets: direct key custody over exact private collections.
//!
//! One vault epoch is one private `SimpleArchive`-union collection. The
//! team's positive authority ledger is the only access-control language:
//! accepted `READ` invocation grants for that exact collection are projected
//! directly to Ed25519 recipient keys. The vault itself contains only its
//! immutable header, immutable encrypted secret versions, and direct-key DEK
//! wraps. It carries no identity, scope, grant, retraction, or administrator
//! graph of its own.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Context, Result};
use dryoc::classic::crypto_sign_ed25519::{
    crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519,
};
use dryoc::dryocbox::{DryocBox, KeyPair as BoxKeyPair, PublicKey as BoxPublicKey};
use dryoc::dryocsecretbox::{DryocSecretBox, Key, Nonce};
use dryoc::types::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace::core::authority::AuthorityResolution;
use triblespace::core::collection::{reach, simplearchive_union, CollectionHandle};
use triblespace::core::metadata;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::*;
use zeroize::Zeroizing;

pub mod schema;
pub mod storage;

use self::schema::{
    secret_body, wrap_dek, wrap_recipient_key, wrap_secret, KIND_SECRET, KIND_VAULT, KIND_WRAP,
};

/// Consumer-owned action meaning permission to decrypt one exact vault.
///
/// Minted with `trible genid` for the vault-epoch Secrets protocol on
/// 2026-08-23. Actions are uninterpreted atoms; this one neither implies nor
/// is implied by collection `WRITE`.
pub const ACTION_READ: Id = triblespace::macros::id_hex!("A6378B816786E9F08A579B8E5F8F4FF4");

pub const VAULT_NAME_PREFIX: &str = "vault-";
pub const VAULT_NAME_DIGITS: usize = 25;

const BASE36: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
const SECRET_BODY_MIN_BYTES: usize = 24 + 16;
const SEALED_DEK_BYTES: usize = 48 + 32;

pub type RecipientPublicKey = [u8; 32];
pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;
pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;
pub type BytesHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;

/// Canonical fixed-width collection name of one nonzero vault id.
pub fn vault_name(vault: Id) -> CollectionName {
    let mut value = u128::from_be_bytes(vault.raw());
    let mut digits = [b'0'; VAULT_NAME_DIGITS];
    for digit in digits.iter_mut().rev() {
        *digit = BASE36[(value % 36) as usize];
        value /= 36;
    }
    debug_assert_eq!(value, 0, "25 base36 digits cover every u128");
    let suffix = std::str::from_utf8(&digits).expect("base36 is ASCII");
    CollectionName::new(&format!("{VAULT_NAME_PREFIX}{suffix}"))
        .expect("canonical vault names satisfy CollectionName")
}

/// Reverse one exact canonical vault collection name to its nonzero id.
pub fn parse_vault_name(name: &CollectionName) -> Result<Id> {
    let text = name.as_str();
    let suffix = text
        .strip_prefix(VAULT_NAME_PREFIX)
        .ok_or_else(|| anyhow!("vault collection name must begin with '{VAULT_NAME_PREFIX}'"))?;
    if suffix.len() != VAULT_NAME_DIGITS {
        bail!("vault collection name must contain exactly {VAULT_NAME_DIGITS} base36 digits");
    }
    let mut value = 0u128;
    for byte in suffix.bytes() {
        let digit = match byte {
            b'0'..=b'9' => (byte - b'0') as u128,
            b'a'..=b'z' => (byte - b'a' + 10) as u128,
            _ => bail!("vault collection name contains a non-base36 digit"),
        };
        value = value
            .checked_mul(36)
            .and_then(|value| value.checked_add(digit))
            .ok_or_else(|| anyhow!("vault collection name exceeds 128 bits"))?;
    }
    let id = Id::new(value.to_be_bytes())
        .ok_or_else(|| anyhow!("vault collection name encodes the forbidden nil id"))?;
    if vault_name(id).as_str() != name.as_str() {
        bail!("vault collection name is not canonical");
    }
    Ok(id)
}

/// Canonical private `SimpleArchive`-union descriptor of one vault epoch.
pub fn vault_descriptor(vault: Id, team: VerifyingKey) -> Fragment {
    simplearchive_union::descriptor(&vault_name(vault), team, reach::private())
}

/// Exact collection resource governed by `WRITE` and `READ` authority.
pub fn vault_handle(vault: Id, team: VerifyingKey) -> CollectionHandle {
    vault_descriptor(vault, team)
        .into_facts()
        .to_blob()
        .get_handle()
}

/// Construct the ordinary collection facade for one vault epoch.
pub fn vault_collection<S>(
    storage: S,
    vault: Id,
    team: VerifyingKey,
    signing_key: SigningKey,
) -> Collection<S> {
    Collection::new(
        storage,
        &vault_name(vault),
        team,
        signing_key,
        reach::private(),
    )
}

/// Direct keys entitled to receive wraps for one exact vault resource.
///
/// Delegation alone is not decryption. Only accepted grants carrying Invoke
/// for this consumer-owned action and this exact collection are projected.
pub fn read_authority_recipient_keys(
    authority: &AuthorityResolution,
    vault: CollectionHandle,
) -> BTreeSet<RecipientPublicKey> {
    authority
        .grants()
        .filter_map(|accepted| {
            let grant = accepted.grant();
            (grant.action() == ACTION_READ && grant.resource() == vault && grant.invoke())
                .then_some(grant.subject().raw)
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultHeader {
    pub id: Id,
    pub created_at: IntervalValue,
    pub name: TextHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretRow {
    pub id: Id,
    pub created_at: IntervalValue,
    pub name: TextHandle,
    pub body: BytesHandle,
}

/// A wrap deliberately carries no timestamp. Its exact extrinsic id names the
/// immutable occurrence, while secret creation time lives on the secret. The
/// old v1 `metadata::created_at` fact remains only in the separately retained
/// legacy collection during additive cutover.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WrapRow {
    pub id: Id,
    pub secret: Id,
    pub recipient: RecipientPublicKey,
    pub sealed_dek: BytesHandle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultCatalog {
    pub header: VaultHeader,
    pub secrets: BTreeMap<Id, SecretRow>,
    pub wraps: BTreeMap<Id, WrapRow>,
}

impl VaultCatalog {
    pub fn wraps_for(&self, secret: Id, recipient: RecipientPublicKey) -> Vec<&WrapRow> {
        self.wraps
            .values()
            .filter(|wrap| wrap.secret == secret && wrap.recipient == recipient)
            .collect()
    }

    pub fn wrap_holders(&self, secret: Id) -> BTreeSet<RecipientPublicKey> {
        self.wraps
            .values()
            .filter(|wrap| wrap.secret == secret)
            .map(|wrap| wrap.recipient)
            .collect()
    }
}

/// One validated vault epoch retained exactly as it was materialized.
///
/// The facts remain available beside their projection so a later mutation can
/// validate the prospective monotone union before publishing it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultSnapshot {
    facts: TribleSet,
    catalog: VaultCatalog,
}

impl VaultSnapshot {
    /// Complete canonical facts of this exact vault epoch.
    pub fn facts(&self) -> &TribleSet {
        &self.facts
    }

    /// Strict v2 projection of [`Self::facts`].
    pub fn catalog(&self) -> &VaultCatalog {
        &self.catalog
    }
}

/// Storage-agnostic aggregate over an exact set of validated vault epochs.
///
/// Secret identities are global within one snapshot: the constructor rejects
/// a secret id observed in more than one vault. Lookup and opening therefore
/// select only by exact secret id; this type performs no name, timestamp, or
/// “latest” arbitration. Vault catalogs retain every historical wrap admitted
/// by their facts without comparing them to current `READ` authority.
pub struct SecretsSnapshot<R> {
    reader: R,
    vaults: BTreeMap<Id, VaultSnapshot>,
    secret_vaults: BTreeMap<Id, Id>,
}

impl<R> SecretsSnapshot<R> {
    /// Shared blob reader used to validate and open every retained vault.
    pub fn reader(&self) -> &R {
        &self.reader
    }

    /// Validated vaults keyed by their exact epoch ids.
    pub fn vaults(&self) -> &BTreeMap<Id, VaultSnapshot> {
        &self.vaults
    }

    /// Facts and catalog for one exact vault epoch.
    pub fn vault(&self, vault: Id) -> Option<&VaultSnapshot> {
        self.vaults.get(&vault)
    }

    /// Whether one exact immutable secret id occurs in this snapshot.
    pub fn contains(&self, secret: Id) -> bool {
        self.secret_vaults.contains_key(&secret)
    }

    /// Locate one exact immutable secret as `(vault_id, row)`.
    pub fn lookup(&self, secret: Id) -> Option<(Id, &SecretRow)> {
        let vault = *self.secret_vaults.get(&secret)?;
        let row = self.vaults.get(&vault)?.catalog.secrets.get(&secret)?;
        Some((vault, row))
    }
}

impl<R: BlobStoreGet> SecretsSnapshot<R> {
    /// Validate and index an exact set of materialized vault epochs.
    ///
    /// Both duplicate vault inputs and secret ids shared across vaults are
    /// rejected rather than silently coalesced.
    pub fn new<I>(reader: R, vaults: I) -> Result<Self>
    where
        I: IntoIterator<Item = (Id, TribleSet)>,
    {
        let mut by_vault = BTreeMap::new();
        let mut secret_vaults = BTreeMap::new();
        for (vault, facts) in vaults {
            let catalog = validate_catalog(&reader, vault, &facts)
                .with_context(|| format!("validate vault {vault}"))?;
            if by_vault.contains_key(&vault) {
                bail!("vault {vault} was supplied more than once");
            }
            for secret in catalog.secrets.keys() {
                if let Some(previous) = secret_vaults.insert(*secret, vault) {
                    bail!("secret {secret} occurs in both vault {previous} and vault {vault}");
                }
            }
            by_vault.insert(vault, VaultSnapshot { facts, catalog });
        }
        Ok(Self {
            reader,
            vaults: by_vault,
            secret_vaults,
        })
    }

    /// Open one exact immutable secret with its recipient signing key.
    pub fn open(&self, secret: Id, signing_key: &SigningKey) -> Result<Vec<u8>> {
        let vault = *self
            .secret_vaults
            .get(&secret)
            .ok_or_else(|| anyhow!("secret {secret} not found in any vault"))?;
        let snapshot = self
            .vaults
            .get(&vault)
            .expect("secret index only contains retained vaults");
        open_version(&self.reader, &snapshot.catalog, secret, signing_key)
            .with_context(|| format!("open secret {secret} from vault {vault}"))
    }
}

pub struct SealedVersion {
    pub fragment: Fragment,
    pub secret: Id,
    pub recipient_count: usize,
}

pub struct SharedVersion {
    pub fragment: Fragment,
    pub new_recipient_count: usize,
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

fn validate_recipient_key(key: &RecipientPublicKey) -> Result<VerifyingKey> {
    VerifyingKey::from_bytes(key).context("invalid Ed25519 recipient public key")
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

fn header_record(vault: Id, name: TextHandle, created_at: IntervalValue) -> Fragment {
    entity! { ExclusiveId::force_ref(&vault) @
        metadata::tag: &KIND_VAULT,
        metadata::name: name,
        metadata::created_at: created_at,
    }
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

/// Canonical header-only genesis payload of one vault epoch.
pub fn vault_header_fragment(vault: Id, name: &str, created_at: IntervalValue) -> Result<Fragment> {
    validate_name("vault name", name)?;
    point_value("vault creation time", created_at)?;
    let mut fragment = Fragment::empty();
    let name = fragment.put(name.to_owned());
    fragment += header_record(vault, name, created_at);
    Ok(fragment)
}

/// Canonical immutable encrypted secret record with caller-selected identity.
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

/// Canonical direct-key wrap record with caller-selected identity.
pub fn recipient_wrap_fragment(
    wrap: Id,
    secret: Id,
    recipient: RecipientPublicKey,
    sealed_dek: Vec<u8>,
) -> Result<Fragment> {
    box_pk_from_ed25519(&recipient)?;
    validate_sealed_dek(&sealed_dek)?;
    let mut fragment = Fragment::empty();
    let sealed_dek = fragment.put::<blobencodings::RawBytes, _>(sealed_dek);
    fragment += wrap_record(wrap, secret, recipient, sealed_dek);
    Ok(fragment)
}

fn exactly_one<T>(entity: Id, field: &str, mut values: Vec<T>) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "vault entity {entity:x} has {} values for {field}; expected exactly one",
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

fn tagged_entities(space: &TribleSet, kind: Id) -> BTreeSet<Id> {
    find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: kind }])).collect()
}

fn load_header(space: &TribleSet, id: Id) -> Result<VaultHeader> {
    let row = VaultHeader {
        id,
        created_at: exactly_one(
            id,
            "metadata::created_at",
            find!(
                value: IntervalValue,
                pattern!(space, [{ id @ metadata::created_at: ?value }])
            )
            .collect(),
        )?,
        name: exactly_one(
            id,
            "metadata::name",
            find!(
                value: TextHandle,
                pattern!(space, [{ id @ metadata::name: ?value }])
            )
            .collect(),
        )?,
    };
    point_value("vault creation time", row.created_at)?;
    if entity_facts(space, id) != *header_record(id, row.name, row.created_at).facts() {
        bail!("vault header {id:x} is not one canonical immutable record");
    }
    Ok(row)
}

fn load_secret(space: &TribleSet, id: Id) -> Result<SecretRow> {
    let row = SecretRow {
        id,
        created_at: exactly_one(
            id,
            "metadata::created_at",
            find!(
                value: IntervalValue,
                pattern!(space, [{ id @ metadata::created_at: ?value }])
            )
            .collect(),
        )?,
        name: exactly_one(
            id,
            "metadata::name",
            find!(
                value: TextHandle,
                pattern!(space, [{ id @ metadata::name: ?value }])
            )
            .collect(),
        )?,
        body: exactly_one(
            id,
            "secret_body",
            find!(value: BytesHandle, pattern!(space, [{ id @ secret_body: ?value }])).collect(),
        )?,
    };
    point_value("secret creation time", row.created_at)?;
    if entity_facts(space, id) != *secret_record(id, row.name, row.body, row.created_at).facts() {
        bail!("secret {id:x} is not one canonical immutable record");
    }
    Ok(row)
}

fn load_wrap(space: &TribleSet, id: Id) -> Result<WrapRow> {
    let recipient = exactly_one(
        id,
        "wrap_recipient_key",
        find!(
            value: Inline<inlineencodings::ED25519PublicKey>,
            pattern!(space, [{ id @ wrap_recipient_key: ?value }])
        )
        .collect(),
    )?;
    let row = WrapRow {
        id,
        secret: exactly_one(
            id,
            "wrap_secret",
            find!(value: Id, pattern!(space, [{ id @ wrap_secret: ?value }])).collect(),
        )?,
        recipient: recipient.raw,
        sealed_dek: exactly_one(
            id,
            "wrap_dek",
            find!(value: BytesHandle, pattern!(space, [{ id @ wrap_dek: ?value }])).collect(),
        )?,
    };
    box_pk_from_ed25519(&row.recipient)?;
    if entity_facts(space, id)
        != *wrap_record(id, row.secret, row.recipient, row.sealed_dek).facts()
    {
        bail!("wrap {id:x} is not one canonical immutable record");
    }
    Ok(row)
}

/// Strictly project one vault's complete canonical fact shape.
pub fn load_catalog(vault: Id, space: &TribleSet) -> Result<VaultCatalog> {
    let header_ids = tagged_entities(space, KIND_VAULT);
    if header_ids.len() != 1 {
        bail!(
            "vault collection has {} headers; expected exactly one",
            header_ids.len()
        );
    }
    let header_id = *header_ids.iter().next().expect("one header checked above");
    if header_id != vault {
        bail!("vault header id {header_id:x} does not match collection epoch {vault:x}");
    }
    let header = load_header(space, header_id)?;

    let secret_ids = tagged_entities(space, KIND_SECRET);
    let wrap_ids = tagged_entities(space, KIND_WRAP);
    let mut secrets = BTreeMap::new();
    let mut wraps = BTreeMap::new();
    for id in &secret_ids {
        secrets.insert(*id, load_secret(space, *id)?);
    }
    for id in &wrap_ids {
        wraps.insert(*id, load_wrap(space, *id)?);
    }
    for wrap in wraps.values() {
        if !secrets.contains_key(&wrap.secret) {
            bail!("wrap {} refers to missing secret {}", wrap.id, wrap.secret);
        }
    }
    for secret in secrets.values() {
        if !wraps.values().any(|wrap| wrap.secret == secret.id) {
            bail!("secret {} has no recipient wrap", secret.id);
        }
    }

    let all_ids: BTreeSet<Id> = header_ids
        .into_iter()
        .chain(secret_ids)
        .chain(wrap_ids)
        .collect();
    let accounted: usize = all_ids
        .iter()
        .map(|id| entity_facts(space, *id).len())
        .sum();
    if accounted != space.len() {
        bail!(
            "vault collection has {} facts outside canonical header, secret, and wrap records",
            space.len() - accounted.min(space.len())
        );
    }

    Ok(VaultCatalog {
        header,
        secrets,
        wraps,
    })
}

/// Read one canonical UTF-8 attachment referenced by a vault record.
pub fn read_text<R: BlobStoreGet>(reader: &R, handle: TextHandle) -> Result<String> {
    let value: anybytes::View<str> = reader.get(handle).context("read UTF-8 attachment")?;
    Ok(value.to_string())
}

fn read_bytes<R: BlobStoreGet>(reader: &R, handle: BytesHandle) -> Result<Vec<u8>> {
    let value: anybytes::Bytes = reader.get(handle).context("read byte attachment")?;
    Ok(value.as_ref().to_vec())
}

/// Validate one vault's canonical facts and every referenced attachment.
///
/// Two randomized sealed boxes cannot be compared for plaintext equality
/// without the recipient's private key. [`open_version`] performs that final
/// consistency check over every duplicate wrap addressed to its signing key.
pub fn validate_catalog<R: BlobStoreGet>(
    reader: &R,
    vault: Id,
    space: &TribleSet,
) -> Result<VaultCatalog> {
    let catalog = load_catalog(vault, space)?;
    let name = read_text(reader, catalog.header.name).context("read vault name")?;
    validate_name("vault name", &name)?;
    for secret in catalog.secrets.values() {
        let name = read_text(reader, secret.name)
            .with_context(|| format!("read secret {} name", secret.id))?;
        validate_name("secret name", &name)?;
        let body = read_bytes(reader, secret.body)
            .with_context(|| format!("read secret {} body", secret.id))?;
        validate_encrypted_body(&body)?;
    }
    for wrap in catalog.wraps.values() {
        let sealed = read_bytes(reader, wrap.sealed_dek)
            .with_context(|| format!("read wrap {} sealed DEK", wrap.id))?;
        validate_sealed_dek(&sealed)?;
    }
    Ok(catalog)
}

fn box_pk_from_ed25519(public: &RecipientPublicKey) -> Result<BoxPublicKey> {
    validate_recipient_key(public)?;
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

fn recover_dek<R: BlobStoreGet>(
    reader: &R,
    catalog: &VaultCatalog,
    secret: Id,
    signing_key: &SigningKey,
) -> Result<Key> {
    if !catalog.secrets.contains_key(&secret) {
        bail!("secret {secret} not found");
    }
    let recipient = signing_key.verifying_key().to_bytes();
    let wraps = catalog.wraps_for(secret, recipient);
    if wraps.is_empty() {
        bail!("no wrap for this signing key on secret {secret}");
    }
    let keypair = box_keypair_from_signing_key(signing_key)?;
    let mut recovered: Option<Zeroizing<Vec<u8>>> = None;
    for wrap in wraps {
        let sealed = read_bytes(reader, wrap.sealed_dek)
            .with_context(|| format!("read wrap {}", wrap.id))?;
        validate_sealed_dek(&sealed)?;
        let bytes = Zeroizing::new(
            DryocBox::from_sealed_bytes(&sealed)
                .map_err(|error| anyhow!("parse wrap {}: {error:?}", wrap.id))?
                .unseal_to_vec(&keypair)
                .map_err(|_| anyhow!("unseal wrap {} failed", wrap.id))?,
        );
        if bytes.len() != 32 {
            bail!("wrap {} opened to a malformed DEK", wrap.id);
        }
        if recovered
            .as_ref()
            .is_some_and(|previous| previous.as_slice() != bytes.as_slice())
        {
            bail!("independent wraps for secret {secret} and one recipient open to competing DEKs");
        }
        if recovered.is_none() {
            recovered = Some(bytes);
        }
    }
    let bytes = recovered.expect("at least one wrap checked above");
    Key::try_from(&bytes[..]).context("decode DEK")
}

fn decrypt_secret_body<R: BlobStoreGet>(
    reader: &R,
    catalog: &VaultCatalog,
    secret: Id,
    dek: &Key,
) -> Result<Vec<u8>> {
    let row = catalog
        .secrets
        .get(&secret)
        .ok_or_else(|| anyhow!("secret {secret} not found"))?;
    let body = read_bytes(reader, row.body).context("read encrypted secret body")?;
    validate_encrypted_body(&body)?;
    let nonce = Nonce::try_from(&body[..24]).context("secret nonce")?;
    DryocSecretBox::from_bytes(&body[24..])
        .map_err(|error| anyhow!("parse secret body: {error:?}"))?
        .decrypt_to_vec(&nonce, dek)
        .map_err(|_| anyhow!("decrypt secret body failed"))
}

/// Encrypt one immutable version and seal its DEK to an explicit key set.
pub fn seal_version(
    name: &str,
    plaintext: &[u8],
    recipients: &BTreeSet<RecipientPublicKey>,
    created_at: IntervalValue,
) -> Result<SealedVersion> {
    if recipients.is_empty() {
        bail!("a secret version must have at least one recipient");
    }
    let recipients: Vec<_> = recipients
        .iter()
        .map(|recipient| Ok((*recipient, box_pk_from_ed25519(recipient)?)))
        .collect::<Result<_>>()?;
    let recipient_count = recipients.len();
    let dek = Key::gen();
    let nonce = Nonce::gen();
    let ciphertext = DryocSecretBox::encrypt_to_vecbox(plaintext, &nonce, &dek).to_vec();
    let mut body = Vec::with_capacity(nonce.len() + ciphertext.len());
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&ciphertext);

    let secret = genid().id;
    let mut fragment = encrypted_secret_fragment(secret, name, body, created_at)?;
    for (recipient, public) in recipients {
        let sealed = DryocBox::seal_to_vecbox(&dek, &public)
            .map_err(|error| anyhow!("seal to recipient: {error:?}"))?
            .to_vec();
        fragment += recipient_wrap_fragment(genid().id, secret, recipient, sealed)?;
    }
    Ok(SealedVersion {
        fragment,
        secret,
        recipient_count,
    })
}

/// Open one exact immutable version with the matching durable signing key.
pub fn open_version<R: BlobStoreGet>(
    reader: &R,
    catalog: &VaultCatalog,
    secret: Id,
    signing_key: &SigningKey,
) -> Result<Vec<u8>> {
    let dek = recover_dek(reader, catalog, secret, signing_key)?;
    decrypt_secret_body(reader, catalog, secret, &dek)
}

/// Add missing wraps for an explicit recipient set using one existing reader.
pub fn share_version<R: BlobStoreGet>(
    reader: &R,
    catalog: &VaultCatalog,
    secret: Id,
    signing_key: &SigningKey,
    recipients: &BTreeSet<RecipientPublicKey>,
) -> Result<SharedVersion> {
    if !catalog.secrets.contains_key(&secret) {
        bail!("secret {secret} not found");
    }
    let mut missing = Vec::new();
    let existing = catalog.wrap_holders(secret);
    for recipient in recipients {
        if !existing.contains(recipient) {
            missing.push((*recipient, box_pk_from_ed25519(recipient)?));
        }
    }
    let dek = recover_dek(reader, catalog, secret, signing_key)?;
    if missing.is_empty() {
        return Ok(SharedVersion {
            fragment: Fragment::empty(),
            new_recipient_count: 0,
        });
    }
    let mut fragment = Fragment::empty();
    for (recipient, public) in &missing {
        let sealed = DryocBox::seal_to_vecbox(&dek, public)
            .map_err(|error| anyhow!("seal to recipient: {error:?}"))?
            .to_vec();
        fragment += recipient_wrap_fragment(genid().id, secret, *recipient, sealed)?;
    }
    Ok(SharedVersion {
        fragment,
        new_recipient_count: missing.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use triblespace::core::authority::{self, AuthorityGrant, AuthorityMode, ACTION_WRITE};
    use triblespace::core::blob::IntoBlob;
    use triblespace::core::collection::descriptor as descriptor_facts;
    use triblespace::core::collection::simplearchive_union::TRIBLE_SET_UNION_RECIPE_V1;
    use triblespace::core::repo::memoryrepo::MemoryRepo;
    use triblespace::core::repo::BlobStore;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn at(second: i64) -> IntervalValue {
        let epoch = hifitime::Epoch::from_unix_seconds(second as f64);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn catalog_from_fragment(vault: Id, fragment: &mut Fragment) -> VaultCatalog {
        let facts = fragment.facts().clone();
        let reader = fragment.blobs_mut().reader().unwrap();
        validate_catalog(&reader, vault, &facts).unwrap()
    }

    #[test]
    fn base36_roundtrips_full_range_and_preserves_leading_zeros() {
        assert_eq!(
            format!("{ACTION_READ:X}"),
            "A6378B816786E9F08A579B8E5F8F4FF4"
        );
        let one = Id::new(1u128.to_be_bytes()).unwrap();
        assert_eq!(vault_name(one).as_str(), "vault-0000000000000000000000001");
        for value in [1, 35, 36, u64::MAX as u128, u128::MAX] {
            let id = Id::new(value.to_be_bytes()).unwrap();
            assert_eq!(parse_vault_name(&vault_name(id)).unwrap(), id);
        }
    }

    #[test]
    fn base36_rejects_malformed_noncanonical_and_out_of_range_names() {
        for malformed in [
            "other-0000000000000000000000001",
            "vault-000000000000000000000001",
            "vault-0000000000000000000000000",
            "vault-zzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            let name = CollectionName::new(malformed).unwrap();
            assert!(parse_vault_name(&name).is_err(), "accepted {malformed}");
        }
        assert!(CollectionName::new("vault-000000000000000000000000A").is_err());
    }

    #[test]
    fn descriptor_roundtrip_is_exact_private_simplearchive_union() {
        let vault = id(7);
        let team = key(1).verifying_key();
        let descriptor = vault_descriptor(vault, team);
        assert_eq!(
            descriptor_facts::name(descriptor.facts()).unwrap().unwrap(),
            vault_name(vault)
        );
        assert_eq!(
            descriptor_facts::team(descriptor.facts()).unwrap().unwrap(),
            team
        );
        assert_eq!(
            descriptor_facts::representation(descriptor.facts()).unwrap(),
            <blobencodings::SimpleArchive as MetaDescribe>::id()
        );
        assert_eq!(
            descriptor_facts::recipe(descriptor.facts()).unwrap(),
            TRIBLE_SET_UNION_RECIPE_V1
        );
        assert!(!reach::travels(descriptor.facts()));
        assert_eq!(
            vault_handle(vault, team),
            descriptor.into_facts().to_blob().get_handle()
        );
    }

    #[test]
    fn header_only_genesis_is_one_exact_valid_vault() {
        let vault = id(8);
        let mut genesis = vault_header_fragment(vault, "production", at(1)).unwrap();
        assert_eq!(genesis.root(), Some(vault));
        assert_eq!(genesis.facts().len(), 3);
        let catalog = catalog_from_fragment(vault, &mut genesis);
        assert_eq!(catalog.header.id, vault);
        assert!(catalog.secrets.is_empty());
        assert!(catalog.wraps.is_empty());
    }

    #[test]
    fn read_projection_is_exact_delegated_invoke_only_and_deduplicated() {
        let root = key(1);
        let delegate = key(2);
        let direct = key(3);
        let child = key(4);
        let delegate_only = key(5);
        let wrong = key(6);
        let team = root.verifying_key();
        let target = vault_handle(id(7), team);
        let other = vault_handle(id(8), team);
        let mut repo = MemoryRepo::default();

        for mode in [AuthorityMode::Invoke, AuthorityMode::InvokeAndDelegate] {
            authority::publish_grant(
                &mut repo,
                team,
                &root,
                AuthorityGrant::root(direct.verifying_key(), target, ACTION_READ, mode),
            )
            .unwrap();
        }
        let parent = authority::publish_grant(
            &mut repo,
            team,
            &root,
            AuthorityGrant::root(
                delegate.verifying_key(),
                target,
                ACTION_READ,
                AuthorityMode::Delegate,
            ),
        )
        .unwrap();
        authority::publish_grant(
            &mut repo,
            team,
            &delegate,
            AuthorityGrant::delegated(
                parent.id(),
                child.verifying_key(),
                target,
                ACTION_READ,
                AuthorityMode::Invoke,
            ),
        )
        .unwrap();
        authority::publish_grant(
            &mut repo,
            team,
            &root,
            AuthorityGrant::root(
                delegate_only.verifying_key(),
                target,
                ACTION_READ,
                AuthorityMode::Delegate,
            ),
        )
        .unwrap();
        authority::publish_grant(
            &mut repo,
            team,
            &root,
            AuthorityGrant::root(
                wrong.verifying_key(),
                target,
                ACTION_WRITE,
                AuthorityMode::Invoke,
            ),
        )
        .unwrap();
        authority::publish_grant(
            &mut repo,
            team,
            &root,
            AuthorityGrant::root(
                wrong.verifying_key(),
                other,
                ACTION_READ,
                AuthorityMode::Invoke,
            ),
        )
        .unwrap();

        let resolved = authority::resolve_authority(&mut repo, team).unwrap();
        assert_eq!(
            read_authority_recipient_keys(&resolved, target),
            BTreeSet::from([
                direct.verifying_key().to_bytes(),
                child.verifying_key().to_bytes(),
            ])
        );
    }

    #[test]
    fn sealing_opening_sharing_and_outsider_refusal_use_direct_keys() {
        let vault = id(9);
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let outsider = SigningKey::generate(&mut OsRng);
        let mut recipients = BTreeSet::from([alice.verifying_key().to_bytes()]);
        let sealed = seal_version("database", b"hunter2", &recipients, at(2)).unwrap();
        let secret = sealed.secret;
        assert_eq!(sealed.recipient_count, 1);
        let mut fragment = vault_header_fragment(vault, "production", at(1)).unwrap();
        fragment += sealed.fragment;
        let catalog = catalog_from_fragment(vault, &mut fragment);
        let reader = fragment.blobs_mut().reader().unwrap();
        assert_eq!(
            open_version(&reader, &catalog, secret, &alice).unwrap(),
            b"hunter2"
        );
        assert!(open_version(&reader, &catalog, secret, &outsider).is_err());

        recipients.insert(bob.verifying_key().to_bytes());
        let shared = share_version(&reader, &catalog, secret, &alice, &recipients).unwrap();
        assert_eq!(shared.new_recipient_count, 1);
        drop(reader);
        fragment += shared.fragment;
        let catalog = catalog_from_fragment(vault, &mut fragment);
        let reader = fragment.blobs_mut().reader().unwrap();
        assert_eq!(
            open_version(&reader, &catalog, secret, &bob).unwrap(),
            b"hunter2"
        );
    }

    #[test]
    fn aggregate_snapshot_uses_exact_ids_and_retains_historical_wraps() {
        let vault_a = id(30);
        let vault_b = id(31);
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let historical = SigningKey::generate(&mut OsRng);

        let sealed_a = seal_version(
            "database",
            b"alpha",
            &BTreeSet::from([
                alice.verifying_key().to_bytes(),
                historical.verifying_key().to_bytes(),
            ]),
            at(2),
        )
        .unwrap();
        let secret_a = sealed_a.secret;
        let sealed_b = seal_version(
            "database",
            b"beta",
            &BTreeSet::from([bob.verifying_key().to_bytes()]),
            at(3),
        )
        .unwrap();
        let secret_b = sealed_b.secret;

        let mut fragment_a = vault_header_fragment(vault_a, "alpha", at(1)).unwrap();
        fragment_a += sealed_a.fragment;
        let facts_a = fragment_a.facts().clone();
        let mut fragment_b = vault_header_fragment(vault_b, "beta", at(1)).unwrap();
        fragment_b += sealed_b.fragment;
        let facts_b = fragment_b.facts().clone();

        let mut blobs = Fragment::empty();
        blobs += fragment_a;
        blobs += fragment_b;
        let reader = blobs.blobs_mut().reader().unwrap();
        let snapshot =
            SecretsSnapshot::new(reader, [(vault_b, facts_b), (vault_a, facts_a.clone())]).unwrap();

        assert_eq!(
            snapshot.vaults().keys().copied().collect::<Vec<_>>(),
            vec![vault_a, vault_b]
        );
        assert_eq!(snapshot.vault(vault_a).unwrap().facts(), &facts_a);
        assert!(snapshot.contains(secret_a));
        assert!(snapshot.contains(secret_b));
        assert!(!snapshot.contains(id(99)));
        assert_eq!(snapshot.lookup(secret_a).unwrap().0, vault_a);
        assert_eq!(snapshot.lookup(secret_b).unwrap().0, vault_b);
        assert!(snapshot.lookup(id(99)).is_none());
        assert_eq!(snapshot.open(secret_a, &alice).unwrap(), b"alpha");
        assert_eq!(snapshot.open(secret_b, &bob).unwrap(), b"beta");
        assert!(snapshot.open(secret_a, &bob).is_err());
        assert!(snapshot.open(id(99), &alice).is_err());

        // The aggregate accepts no current READ-member set and therefore
        // retains the historical recipient's immutable wrap verbatim.
        assert_eq!(
            snapshot
                .vault(vault_a)
                .unwrap()
                .catalog()
                .wrap_holders(secret_a),
            BTreeSet::from([
                alice.verifying_key().to_bytes(),
                historical.verifying_key().to_bytes(),
            ])
        );
        assert_eq!(snapshot.open(secret_a, &historical).unwrap(), b"alpha");
    }

    #[test]
    fn aggregate_snapshot_rejects_cross_vault_secret_ids_and_duplicate_vault_inputs() {
        let vault_a = id(32);
        let vault_b = id(33);
        let alice = SigningKey::generate(&mut OsRng);
        let sealed = seal_version(
            "database",
            b"shared identity",
            &BTreeSet::from([alice.verifying_key().to_bytes()]),
            at(2),
        )
        .unwrap();
        let secret = sealed.secret;

        let mut fragment_a = vault_header_fragment(vault_a, "alpha", at(1)).unwrap();
        fragment_a += sealed.fragment.clone();
        let facts_a = fragment_a.facts().clone();
        let mut fragment_b = vault_header_fragment(vault_b, "beta", at(1)).unwrap();
        fragment_b += sealed.fragment;
        let facts_b = fragment_b.facts().clone();

        let mut blobs = Fragment::empty();
        blobs += fragment_a;
        blobs += fragment_b;
        let reader = blobs.blobs_mut().reader().unwrap();
        let error = SecretsSnapshot::new(
            reader.clone(),
            [(vault_a, facts_a.clone()), (vault_b, facts_b)],
        )
        .err()
        .expect("cross-vault duplicate secret must fail");
        let rendered = format!("{error:#}");
        assert!(rendered.contains(&secret.to_string()), "{rendered}");
        assert!(rendered.contains(&vault_a.to_string()), "{rendered}");
        assert!(rendered.contains(&vault_b.to_string()), "{rendered}");

        let error = SecretsSnapshot::new(reader, [(vault_a, facts_a.clone()), (vault_a, facts_a)])
            .err()
            .expect("duplicate vault input must fail");
        assert!(
            format!("{error:#}").contains("supplied more than once"),
            "{error:#}"
        );
    }

    #[test]
    fn aggregate_snapshot_strictly_validates_attachments() {
        let vault = id(34);
        let alice = SigningKey::generate(&mut OsRng);
        let recipient = alice.verifying_key().to_bytes();
        let mut malformed = vault_header_fragment(vault, "production", at(1)).unwrap();
        let name = malformed.put("broken".to_owned());
        let body = malformed.put::<blobencodings::RawBytes, _>(vec![0; 23]);
        let secret = id(35);
        malformed += secret_record(secret, name, body, at(2));
        let sealed =
            DryocBox::seal_to_vecbox(&Key::gen(), &box_pk_from_ed25519(&recipient).unwrap())
                .unwrap()
                .to_vec();
        malformed += recipient_wrap_fragment(id(36), secret, recipient, sealed).unwrap();

        // Structural loading succeeds, so this specifically proves the
        // aggregate constructor performs attachment-aware v2 validation.
        load_catalog(vault, malformed.facts()).unwrap();
        let facts = malformed.facts().clone();
        let reader = malformed.blobs_mut().reader().unwrap();
        let error = SecretsSnapshot::new(reader, [(vault, facts)])
            .err()
            .expect("malformed body attachment must fail");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(&format!("validate vault {vault}")),
            "{rendered}"
        );
        assert!(rendered.contains("too short"), "{rendered}");
    }

    #[test]
    fn duplicate_wraps_must_open_to_one_dek() {
        let vault = id(10);
        let alice = SigningKey::generate(&mut OsRng);
        let recipient = alice.verifying_key().to_bytes();
        let sealed =
            seal_version("database", b"hunter2", &BTreeSet::from([recipient]), at(2)).unwrap();
        let secret = sealed.secret;
        let mut fragment = vault_header_fragment(vault, "production", at(1)).unwrap();
        fragment += sealed.fragment;
        let catalog = catalog_from_fragment(vault, &mut fragment);
        let reader = fragment.blobs_mut().reader().unwrap();
        let dek = recover_dek(&reader, &catalog, secret, &alice).unwrap();
        drop(reader);

        let public = box_pk_from_ed25519(&recipient).unwrap();
        let same = DryocBox::seal_to_vecbox(&dek, &public).unwrap().to_vec();
        fragment += recipient_wrap_fragment(id(90), secret, recipient, same).unwrap();
        let catalog = catalog_from_fragment(vault, &mut fragment);
        let reader = fragment.blobs_mut().reader().unwrap();
        assert_eq!(
            open_version(&reader, &catalog, secret, &alice).unwrap(),
            b"hunter2"
        );
        drop(reader);

        let competing = DryocBox::seal_to_vecbox(&Key::gen(), &public)
            .unwrap()
            .to_vec();
        fragment += recipient_wrap_fragment(id(91), secret, recipient, competing).unwrap();
        let catalog = catalog_from_fragment(vault, &mut fragment);
        let reader = fragment.blobs_mut().reader().unwrap();
        let error = open_version(&reader, &catalog, secret, &alice).unwrap_err();
        assert!(format!("{error:#}").contains("competing DEKs"), "{error:#}");
    }

    #[test]
    fn strict_shape_rejects_extra_facts_multiple_headers_and_dangling_wraps() {
        let vault = id(11);
        let alice = SigningKey::generate(&mut OsRng);
        let recipient = alice.verifying_key().to_bytes();
        let sealed =
            seal_version("database", b"hunter2", &BTreeSet::from([recipient]), at(2)).unwrap();
        let secret = sealed.secret;
        let mut valid = vault_header_fragment(vault, "production", at(1)).unwrap();
        valid += sealed.fragment;
        catalog_from_fragment(vault, &mut valid);

        let mut extra = valid.clone();
        extra += entity! { ExclusiveId::force_ref(&secret) @
            metadata::description: "not part of the canonical secret record",
        };
        assert!(load_catalog(vault, extra.facts()).is_err());

        let mut conflicting = valid.clone();
        let current = load_catalog(vault, conflicting.facts()).unwrap();
        let body = conflicting.put::<blobencodings::RawBytes, _>(vec![0; SECRET_BODY_MIN_BYTES]);
        conflicting += secret_record(secret, current.secrets[&secret].name, body, at(2));
        let error = load_catalog(vault, conflicting.facts()).unwrap_err();
        assert!(
            format!("{error:#}").contains("2 values for secret_body"),
            "{error:#}"
        );

        let mut multiple = valid.clone();
        multiple += vault_header_fragment(id(12), "other", at(3)).unwrap();
        assert!(load_catalog(vault, multiple.facts()).is_err());

        let sealed_dek =
            DryocBox::seal_to_vecbox(&Key::gen(), &box_pk_from_ed25519(&recipient).unwrap())
                .unwrap()
                .to_vec();
        let mut dangling = vault_header_fragment(vault, "production", at(1)).unwrap();
        dangling += recipient_wrap_fragment(id(92), id(99), recipient, sealed_dek).unwrap();
        assert!(load_catalog(vault, dangling.facts()).is_err());
    }

    #[test]
    fn validation_rejects_malformed_attachments_without_read_set_comparison() {
        let vault = id(13);
        let alice = SigningKey::generate(&mut OsRng);
        let recipient = alice.verifying_key().to_bytes();
        let mut fragment = vault_header_fragment(vault, "production", at(1)).unwrap();
        let name = fragment.put("broken".to_owned());
        let body = fragment.put::<blobencodings::RawBytes, _>(vec![0; 23]);
        let secret = id(20);
        fragment += secret_record(secret, name, body, at(2));
        let sealed =
            DryocBox::seal_to_vecbox(&Key::gen(), &box_pk_from_ed25519(&recipient).unwrap())
                .unwrap()
                .to_vec();
        fragment += recipient_wrap_fragment(id(21), secret, recipient, sealed).unwrap();
        let facts = fragment.facts().clone();
        let reader = fragment.blobs_mut().reader().unwrap();
        let error = validate_catalog(&reader, vault, &facts).unwrap_err();
        assert!(format!("{error:#}").contains("too short"), "{error:#}");

        // Historical wraps are intentionally valid even when an unrelated
        // authority projection would now return a different recipient set.
        let mut proper = vault_header_fragment(vault, "production", at(1)).unwrap();
        proper += seal_version("database", b"hunter2", &BTreeSet::from([recipient]), at(2))
            .unwrap()
            .fragment;
        catalog_from_fragment(vault, &mut proper);
    }
}
