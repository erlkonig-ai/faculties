//! Vault-epoch Secrets: capability-gated custody over exact private collections.
//!
//! One vault epoch is one private `SimpleArchive`-union collection with one
//! random custody keypair. Every new secret has one DEK wrap to that custody
//! key. Exact native `READ(vault)` proof bundles authorize subject-specific
//! delivery of the custody seed; they are never enumerated into ambient
//! membership. Collection `WRITE` remains a separate exact capability.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Context, Result};
use dryoc::classic::crypto_sign_ed25519::{
    crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519,
};
use dryoc::dryocbox::{DryocBox, KeyPair as BoxKeyPair, PublicKey as BoxPublicKey};
use dryoc::dryocsecretbox::{DryocSecretBox, Key, Nonce};
use dryoc::types::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hifitime::Epoch;
use triblespace::core::capability::{
    CapabilityAction, CapabilityAtom, CapabilityMode, CapabilityProofBundle, CapabilityRequest,
    CapabilityResource,
};
use triblespace::core::collection::{
    AdmissionPolicy, Collection, CollectionHandle, CollectionPolicy, ACTION_WRITE,
};
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::*;
use zeroize::Zeroizing;

use triblespace::core::blob::encodings::succinctarchive::{
    OrderedUniverse, SuccinctArchive, UnionArchive,
};

pub mod access;
pub mod schema;
pub mod storage;

use self::schema::{
    custody_public_key, secret_body, wrap_dek, wrap_recipient_key, wrap_secret, KIND_SECRET,
    KIND_VAULT, KIND_VAULT_CUSTODY, KIND_WRAP,
};

/// Consumer-owned action meaning permission to decrypt one exact vault.
///
/// Minted with `trible genid` for the vault-epoch Secrets protocol on
/// 2026-08-23. Actions are uninterpreted atoms; this one neither implies nor
/// is implied by collection `WRITE`.
pub const ACTION_READ: Id = triblespace::macros::id_hex!("A6378B816786E9F08A579B8E5F8F4FF4");

/// Version marker at the start of every sealed custody-seed plaintext.
///
/// Minted with `trible genid` on 2026-08-25 for the direct-proof envelope
/// frame. The prior unpublished leaf-credential format has no runtime
/// compatibility path; only the explicit one-time migration recognizes it.
pub const ACCESS_ENVELOPE_FORMAT_V1: Id =
    triblespace::macros::id_hex!("0444B547B64A83CB156D3CAA917DAB89");

pub const VAULT_NAME_PREFIX: &str = "vault-";
pub const VAULT_NAME_DIGITS: usize = 25;

const BASE36: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
const SECRET_BODY_MIN_BYTES: usize = 24 + 16;
const SEALED_DEK_BYTES: usize = 48 + 32;

pub type RecipientPublicKey = [u8; 32];
pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;
pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;
pub type BytesHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;

/// Shard-preserving logical view used for ordinary vault queries.
///
/// Vault discovery attaches this to the maintained Rank9 collection.  It is
/// intentionally a query surface rather than a materialized Rust catalog.
pub type VaultFacts = UnionArchive<OrderedUniverse>;

/// Canonical fixed-width collection name of one nonzero vault id.
pub fn vault_name(vault: Id) -> String {
    let mut value = u128::from_be_bytes(vault.raw());
    let mut digits = [b'0'; VAULT_NAME_DIGITS];
    for digit in digits.iter_mut().rev() {
        *digit = BASE36[(value % 36) as usize];
        value /= 36;
    }
    debug_assert_eq!(value, 0, "25 base36 digits cover every u128");
    let suffix = std::str::from_utf8(&digits).expect("base36 is ASCII");
    format!("{VAULT_NAME_PREFIX}{suffix}")
}

/// Reverse one exact canonical vault collection name to its nonzero id.
pub fn parse_vault_name(name: &str) -> Result<Id> {
    let suffix = name
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
    if vault_name(id) != name {
        bail!("vault collection name is not canonical");
    }
    Ok(id)
}

/// Immutable collection policy for one private vault epoch.
pub fn vault_policy(authority: VerifyingKey) -> CollectionPolicy {
    CollectionPolicy::new(
        AdmissionPolicy::direct(authority),
        AdmissionPolicy::direct(authority),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultHeader {
    pub id: Id,
    pub created_at: IntervalValue,
    pub name: TextHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodyRow {
    pub id: Id,
    pub public_key: RecipientPublicKey,
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
/// historical `metadata::created_at` fact remains only in the migration
/// source parser; current vault records never arbitrate wraps by time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WrapRow {
    pub id: Id,
    pub secret: Id,
    pub recipient: RecipientPublicKey,
    pub sealed_dek: BytesHandle,
}

/// Strict stopped-world projection retained for explicit migration and tests.
///
/// Ordinary vault reads query [`VaultFacts`] directly instead of reconstructing
/// this catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultCatalog {
    pub header: VaultHeader,
    /// Absent only on preserved direct-recipient vaults awaiting the additive
    /// custody migration.
    pub custody: Option<CustodyRow>,
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

/// One immutable, collection-scoped vault view.
///
/// This owns the maintained query surface only.  Rows are projected where an
/// operation needs them; there is no eagerly reconstructed vault catalog.
#[derive(Clone)]
pub struct VaultView {
    vault: Id,
    collection: Option<CollectionHandle>,
    facts: VaultFacts,
}

/// Exact local evidence needed to use one vault epoch.
///
/// This is not a member record. It is the result of opening one or more
/// subject-specific envelopes and verifying their exact proofs. READ is
/// checked again whenever plaintext is requested, so an expired lease cannot
/// survive merely because a process kept this snapshot alive.
#[derive(Clone)]
pub struct VaultAccess {
    vault: Id,
    trust_root: VerifyingKey,
    collection: Collection<blobencodings::SimpleArchive>,
    subject: VerifyingKey,
    custody: SigningKey,
    read_bundles: Vec<CapabilityProofBundle>,
    write_bundles: Vec<CapabilityProofBundle>,
}

impl VaultAccess {
    pub(crate) fn new(
        vault: Id,
        trust_root: VerifyingKey,
        collection: Collection<blobencodings::SimpleArchive>,
        subject: VerifyingKey,
        custody: SigningKey,
        read_bundles: Vec<CapabilityProofBundle>,
        write_bundles: Vec<CapabilityProofBundle>,
    ) -> Result<Self> {
        if read_bundles.is_empty() {
            bail!("vault access requires at least one exact READ proof bundle");
        }
        if write_bundles.is_empty() {
            bail!("vault access requires at least one exact WRITE proof bundle");
        }
        let access = Self {
            vault,
            trust_root,
            collection,
            subject,
            custody,
            read_bundles,
            write_bundles,
        };
        let instant = triblespace::core::clock::epoch_now();
        access.verify_read_at(instant)?;
        access.verify_write_at(instant)?;
        Ok(access)
    }

    pub const fn vault(&self) -> Id {
        self.vault
    }

    pub fn trust_root(&self) -> VerifyingKey {
        self.trust_root
    }

    pub const fn collection(&self) -> CollectionHandle {
        self.collection.handle()
    }

    pub fn subject(&self) -> VerifyingKey {
        self.subject
    }

    pub fn custody(&self) -> &SigningKey {
        &self.custody
    }

    pub fn read_bundles(&self) -> &[CapabilityProofBundle] {
        &self.read_bundles
    }

    pub fn write_bundles(&self) -> &[CapabilityProofBundle] {
        &self.write_bundles
    }

    pub fn verify_read_at(&self, instant: Epoch) -> Result<()> {
        let atom = CapabilityAtom::new(
            CapabilityAction::new(ACTION_READ),
            CapabilityResource::from(self.collection.handle()),
        );
        let request = CapabilityRequest::new(atom, CapabilityMode::Invoke);
        let mut failures = Vec::new();
        for bundle in &self.read_bundles {
            match bundle.verify(self.trust_root, instant, self.subject, request) {
                Ok(_) => return Ok(()),
                Err(error) => failures.push(error.to_string()),
            }
        }
        bail!(
            "no supplied READ proof currently authorizes this vault: {}",
            failures.join("; ")
        )
    }

    /// Reverify every supplied collection writer at an explicit instant.
    ///
    /// Vault WRITE evidence must be unbounded. Collection admission is checked
    /// when taking a snapshot, so a bounded writer would otherwise make
    /// already-committed ciphertext disappear when its lease expired.
    pub fn verify_write_at(&self, instant: Epoch) -> Result<()> {
        let atom = CapabilityAtom::new(
            CapabilityAction::new(ACTION_WRITE),
            CapabilityResource::from(self.collection.handle()),
        );
        for (index, bundle) in self.write_bundles.iter().enumerate() {
            let verified = bundle
                .verify(
                    self.trust_root,
                    instant,
                    bundle.proof().leaf_key(),
                    CapabilityRequest::new(atom, CapabilityMode::Invoke),
                )
                .with_context(|| format!("verify vault WRITE proof bundle {index}"))?;
            if verified.effective_validity().is_some() {
                bail!(
                    "vault WRITE proof bundle {index} is bounded; historical commits require unbounded admission"
                );
            }
        }
        Ok(())
    }
}

impl VaultView {
    /// Vault-local graph identity carried by the canonical header.
    pub const fn id(&self) -> Id {
        self.vault
    }

    /// Exact collection identity, when this snapshot came through verified
    /// access discovery rather than an offline unscoped validation input.
    pub const fn collection(&self) -> Option<CollectionHandle> {
        self.collection
    }

    /// Maintained facts admitted for this exact vault collection.
    pub fn facts(&self) -> &VaultFacts {
        &self.facts
    }
}

/// Project every complete, decodable header row for one vault identity.
///
/// Extra facts and partial rows are intentionally irrelevant.  The operation
/// which needs a header decides which projected value is useful rather than
/// imposing a closed-world shape on the collection.
pub fn vault_headers<P>(facts: &P, vault: Id) -> Vec<VaultHeader>
where
    P: TriblePattern,
{
    find!(
        (created_at: IntervalValue, name: TextHandle),
        pattern!(facts, [{
            vault @
                metadata::tag: KIND_VAULT,
                metadata::created_at: ?created_at,
                metadata::name: ?name,
        }])
    )
    .filter_map(|(created_at, name)| {
        point_value("vault creation time", created_at)
            .is_ok()
            .then_some(VaultHeader {
                id: vault,
                created_at,
                name,
            })
    })
    .collect()
}

/// Project every complete custody declaration visible in a vault view.
pub fn custody_rows<P>(facts: &P) -> Vec<CustodyRow>
where
    P: TriblePattern,
{
    find!(
        (id: Id, public_key: Inline<inlineencodings::ED25519PublicKey>),
        pattern!(facts, [{
            ?id @
                metadata::tag: KIND_VAULT_CUSTODY,
                custody_public_key: ?public_key,
        }])
    )
    .filter_map(|(id, public_key)| {
        box_pk_from_ed25519(&public_key.raw)
            .is_ok()
            .then_some(CustodyRow {
                id,
                public_key: public_key.raw,
            })
    })
    .collect()
}

/// Whether one complete custody declaration names `public_key`.
pub fn has_custody<P>(facts: &P, public_key: RecipientPublicKey) -> bool
where
    P: TriblePattern,
{
    let value = Inline::<inlineencodings::ED25519PublicKey>::new(public_key);
    exists!(pattern!(facts, [{
        _?id @
            metadata::tag: KIND_VAULT_CUSTODY,
            custody_public_key: value,
    }]))
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
        (
            created_at: IntervalValue,
            name: TextHandle,
            body: BytesHandle
        ),
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

/// Project every complete, decodable wrap row for one secret and recipient.
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

/// Storage-agnostic aggregate over admitted, maintained vault views.
///
/// Access-discovered vaults retain their exact collection identity. Bare vault
/// and secret ids are conveniences only when unique in this snapshot; exact
/// collection lookup remains available when independently valid authorities
/// happen to reuse the same graph-local ids. Offline [`Self::new`] inputs have
/// no collection provenance and therefore retain the stricter historical
/// uniqueness checks. This type performs no name, timestamp, or “latest”
/// arbitration.
pub struct SecretsSnapshot<R> {
    store_snapshot: R,
    vaults: Vec<VaultView>,
    access: BTreeMap<CollectionHandle, VaultAccess>,
}

impl<R> SecretsSnapshot<R> {
    /// Shared store snapshot used to validate and open every retained vault.
    pub fn store_snapshot(&self) -> &R {
        &self.store_snapshot
    }

    /// Every ready vault, ordered by construction input.
    pub fn vaults(&self) -> &[VaultView] {
        &self.vaults
    }

    /// Maintained facts for a unique graph-local vault id.
    ///
    /// Returns `None` both when absent and when multiple exact collections use
    /// the id. Use [`Self::vault_exact`] when collection identity is known.
    pub fn vault(&self, vault: Id) -> Option<&VaultView> {
        let mut matching = self
            .vaults
            .iter()
            .filter(|snapshot| snapshot.vault == vault);
        let first = matching.next()?;
        matching.next().is_none().then_some(first)
    }

    /// Maintained facts for one exact access-discovered collection.
    pub fn vault_exact(&self, collection: CollectionHandle) -> Option<&VaultView> {
        self.vaults
            .iter()
            .find(|snapshot| snapshot.collection == Some(collection))
    }

    /// Whether one exact immutable secret id occurs in this snapshot.
    pub fn contains(&self, secret: Id) -> bool {
        self.vaults
            .iter()
            .any(|vault| !secret_rows_for(&vault.facts, secret).is_empty())
    }

    /// Locate a globally unique immutable secret as `(vault_id, row)`.
    ///
    /// Returns `None` when more than one exact collection contains the id.
    pub fn lookup(&self, secret: Id) -> Option<(Id, SecretRow)> {
        let mut matching = self.vaults.iter().filter_map(|vault| {
            secret_rows_for(&vault.facts, secret)
                .into_iter()
                .next()
                .map(|row| (vault.vault, row))
        });
        let first = matching.next()?;
        matching.next().is_none().then_some(first)
    }

    /// Locate one immutable secret inside an exact collection.
    pub fn lookup_exact(&self, collection: CollectionHandle, secret: Id) -> Option<SecretRow> {
        secret_rows_for(&self.vault_exact(collection)?.facts, secret)
            .into_iter()
            .next()
    }

    /// Verified local access evidence for a unique graph-local vault id.
    pub fn access(&self, vault: Id) -> Option<&VaultAccess> {
        let snapshot = self.vault(vault)?;
        self.access.get(&snapshot.collection?)
    }

    /// Verified local access evidence for one exact collection.
    pub fn access_exact(&self, collection: CollectionHandle) -> Option<&VaultAccess> {
        self.access.get(&collection)
    }
}

impl<R: BlobStoreGet> SecretsSnapshot<R> {
    /// Strictly validate explicit stopped-world vault inputs.
    ///
    /// Both duplicate vault inputs and secret ids shared across vaults are
    /// rejected rather than silently coalesced.
    pub fn new<I>(reader: R, vaults: I) -> Result<Self>
    where
        I: IntoIterator<Item = (Id, TribleSet)>,
    {
        let mut snapshots = Vec::new();
        let mut vault_ids = BTreeSet::new();
        let mut secret_vaults = BTreeMap::new();
        for (vault, facts) in vaults {
            if !vault_ids.insert(vault) {
                bail!("vault {vault} was supplied more than once");
            }
            let catalog = validate_catalog(&reader, vault, &facts)
                .with_context(|| format!("validate vault {vault}"))?;
            for secret in catalog.secrets.keys() {
                if let Some(previous) = secret_vaults.insert(*secret, vault) {
                    bail!("secret {secret} occurs in both vault {previous} and vault {vault}");
                }
            }
            snapshots.push(VaultView {
                vault,
                collection: None,
                facts: VaultFacts::new(vec![SuccinctArchive::from(&facts)]),
            });
        }
        Ok(Self {
            store_snapshot: reader,
            vaults: snapshots,
            access: BTreeMap::new(),
        })
    }

    /// Validate exact collection-scoped vaults without attaching local access.
    ///
    /// This is the stopped-world planning counterpart to runtime access
    /// discovery. Independently valid collections may reuse graph-local vault
    /// or secret ids; only the exact collection handle must be unique.
    pub fn new_exact<I>(reader: R, vaults: I) -> Result<Self>
    where
        I: IntoIterator<Item = (CollectionHandle, Id, TribleSet)>,
    {
        let mut snapshots = Vec::new();
        let mut collections = BTreeSet::new();
        for (collection, vault, facts) in vaults {
            if !collections.insert(collection) {
                bail!("collection {collection:?} was supplied more than once");
            }
            validate_catalog(&reader, vault, &facts)
                .with_context(|| format!("validate vault {vault}"))?;
            snapshots.push(VaultView {
                vault,
                collection: Some(collection),
                facts: VaultFacts::new(vec![SuccinctArchive::from(&facts)]),
            });
        }
        Ok(Self {
            store_snapshot: reader,
            vaults: snapshots,
            access: BTreeMap::new(),
        })
    }

    /// Attach maintained vault views together with explicit local access.
    pub(crate) fn new_accessible<I>(reader: R, vaults: I) -> Result<Self>
    where
        I: IntoIterator<Item = (Id, VaultFacts, VaultAccess)>,
    {
        let mut snapshots = Vec::new();
        let mut by_access = BTreeMap::new();
        for (vault, facts, access) in vaults {
            if access.vault != vault {
                bail!(
                    "vault {vault} access evidence is bound to vault {}",
                    access.vault
                );
            }
            let collection = access.collection.handle();
            let custody = access.custody.verifying_key().to_bytes();
            if !has_custody(&facts, custody) {
                bail!("vault {vault} access envelope opens to a different custody key");
            }
            if by_access.insert(collection, access).is_some() {
                bail!("collection {collection:?} was supplied more than once");
            }
            snapshots.push(VaultView {
                vault,
                collection: Some(collection),
                facts,
            });
        }
        Ok(Self {
            store_snapshot: reader,
            vaults: snapshots,
            access: by_access,
        })
    }

    /// Open one exact immutable secret with its recipient signing key.
    pub fn open(&self, secret: Id, signing_key: &SigningKey) -> Result<Vec<u8>> {
        let mut matching = self
            .vaults
            .iter()
            .filter(|vault| !secret_rows_for(&vault.facts, secret).is_empty());
        let snapshot = matching
            .next()
            .ok_or_else(|| anyhow!("secret {secret} not found in any vault"))?;
        if matching.next().is_some() {
            bail!("secret {secret} is ambiguous across exact vault collections");
        }
        let collection = snapshot
            .collection
            .context("the selected vault has no exact collection identity")?;
        let access = self.access.get(&collection).ok_or_else(|| {
            anyhow!(
                "no verified local access envelope for vault {}",
                snapshot.vault
            )
        })?;
        if signing_key.verifying_key() != access.subject {
            bail!("the supplied signing key is not the access-envelope subject");
        }
        access.verify_read_at(triblespace::core::clock::epoch_now())?;
        open_version_from_facts(
            &self.store_snapshot,
            &snapshot.facts,
            secret,
            &access.custody,
        )
        .with_context(|| format!("open secret {secret} from vault {}", snapshot.vault))
    }

    /// Open one immutable secret from an exact collection.
    pub fn open_exact(
        &self,
        collection: CollectionHandle,
        secret: Id,
        signing_key: &SigningKey,
    ) -> Result<Vec<u8>> {
        let snapshot = self
            .vault_exact(collection)
            .ok_or_else(|| anyhow!("vault collection {collection:?} is not present"))?;
        if secret_rows_for(&snapshot.facts, secret).is_empty() {
            bail!("secret {secret} is not present in vault collection {collection:?}");
        }
        let access = self
            .access_exact(collection)
            .ok_or_else(|| anyhow!("no verified local access envelope for {collection:?}"))?;
        if signing_key.verifying_key() != access.subject {
            bail!("the supplied signing key is not the access-envelope subject");
        }
        access.verify_read_at(triblespace::core::clock::epoch_now())?;
        open_version_from_facts(
            &self.store_snapshot,
            &snapshot.facts,
            secret,
            &access.custody,
        )
        .with_context(|| format!("open secret {secret} from vault collection {collection:?}"))
    }
}

pub struct SealedVersion {
    pub fragment: Fragment,
    pub secret: Id,
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

fn custody_record(custody: RecipientPublicKey) -> Fragment {
    let custody = Inline::<inlineencodings::ED25519PublicKey>::new(custody);
    entity! { _ @
        metadata::tag: &KIND_VAULT_CUSTODY,
        custody_public_key: custody,
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

fn build_vault_header_fragment(
    vault: Id,
    name: &str,
    created_at: IntervalValue,
    custody: Option<RecipientPublicKey>,
) -> Result<Fragment> {
    validate_name("vault name", name)?;
    point_value("vault creation time", created_at)?;
    if let Some(custody) = custody {
        box_pk_from_ed25519(&custody).context("validate vault custody public key")?;
    }
    let mut fragment = Fragment::empty();
    let name = fragment.put(name.to_owned());
    fragment += header_record(vault, name, created_at);
    if let Some(custody) = custody {
        fragment += custody_record(custody);
    }
    // The custody singleton is part of the committed graph, not a second
    // entry point. Preserve the vault id as this genesis fragment's one public
    // root even though its facts contain two intrinsic entities.
    let (_, facts, metafacts, blobs) = fragment.into_parts();
    Ok(Fragment::rooted_from_parts(vault, facts, metafacts, blobs))
}

/// Canonical genesis payload of one custody-backed vault epoch.
pub fn vault_header_fragment(
    vault: Id,
    name: &str,
    created_at: IntervalValue,
    custody: RecipientPublicKey,
) -> Result<Fragment> {
    build_vault_header_fragment(vault, name, created_at, Some(custody))
}

/// Frozen three-fact header shape used only while reading or migrating the
/// direct-recipient vault generation.
pub fn legacy_vault_header_fragment(
    vault: Id,
    name: &str,
    created_at: IntervalValue,
) -> Result<Fragment> {
    build_vault_header_fragment(vault, name, created_at, None)
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

/// Canonical recipient-key wrap record with caller-selected identity.
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

fn load_custody(space: &TribleSet, id: Id) -> Result<CustodyRow> {
    let public_key = exactly_one(
        id,
        "custody_public_key",
        find!(
            value: Inline<inlineencodings::ED25519PublicKey>,
            pattern!(space, [{ id @ custody_public_key: ?value }])
        )
        .collect(),
    )?
    .raw;
    box_pk_from_ed25519(&public_key).context("validate vault custody public key")?;
    if entity_facts(space, id) != *custody_record(public_key).facts() {
        bail!("vault custody declaration {id:x} is not one canonical immutable record");
    }
    Ok(CustodyRow { id, public_key })
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

    let custody_ids = tagged_entities(space, KIND_VAULT_CUSTODY);
    if custody_ids.len() > 1 {
        bail!(
            "vault collection has {} custody declarations; expected at most one",
            custody_ids.len()
        );
    }
    let custody = custody_ids
        .iter()
        .next()
        .copied()
        .map(|id| load_custody(space, id))
        .transpose()?;

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
        if let Some(custody) = custody {
            let custody_wraps = wraps
                .values()
                .filter(|wrap| wrap.secret == secret.id && wrap.recipient == custody.public_key)
                .count();
            if custody_wraps != 1 {
                bail!(
                    "secret {} has {custody_wraps} custody wraps; expected exactly one",
                    secret.id
                );
            }
        }
    }

    let all_ids: BTreeSet<Id> = header_ids
        .into_iter()
        .chain(custody_ids)
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
        custody,
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

fn recover_dek_from_facts<R, P>(
    reader: &R,
    facts: &P,
    secret: Id,
    signing_key: &SigningKey,
) -> Result<Key>
where
    R: BlobStoreGet,
    P: TriblePattern,
{
    if secret_rows_for(facts, secret).is_empty() {
        bail!("secret {secret} not found");
    }
    let recipient = signing_key.verifying_key().to_bytes();
    let wraps = recipient_wraps(facts, secret, recipient);
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
        let body = read_bytes(reader, body).context("read encrypted secret body")?;
        validate_encrypted_body(&body)?;
        let nonce = Nonce::try_from(&body[..24]).context("secret nonce")?;
        let candidate = DryocSecretBox::from_bytes(&body[24..])
            .map_err(|error| anyhow!("parse secret body: {error:?}"))?
            .decrypt_to_vec(&nonce, dek)
            .map_err(|_| anyhow!("decrypt secret body failed"))?;
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
    Ok(plaintext.expect("at least one body checked above"))
}

/// Open one exact immutable version through a maintained vault query view.
///
/// Only the header facts needed by this operation are projected. Additional
/// facts and independently malformed rows do not turn the surrounding vault
/// into a closed record; cryptographic conflicts for the selected secret do
/// remain hard failures.
pub fn open_version_from_facts<R, P>(
    reader: &R,
    facts: &P,
    secret: Id,
    custody: &SigningKey,
) -> Result<Vec<u8>>
where
    R: BlobStoreGet,
    P: TriblePattern,
{
    let expected = custody.verifying_key().to_bytes();
    if !has_custody(facts, expected) {
        bail!("supplied custody seed does not match any vault custody declaration");
    }
    let dek = recover_dek_from_facts(reader, facts, secret, custody)?;
    decrypt_secret_body_from_facts(reader, facts, secret, &dek)
}

/// Encrypt one immutable version and seal its DEK exactly once to the vault
/// epoch's custody key.
pub fn seal_version(
    name: &str,
    plaintext: &[u8],
    custody: RecipientPublicKey,
    created_at: IntervalValue,
) -> Result<SealedVersion> {
    let custody_box = box_pk_from_ed25519(&custody)?;
    let dek = Key::gen();
    let nonce = Nonce::gen();
    let ciphertext = DryocSecretBox::encrypt_to_vecbox(plaintext, &nonce, &dek).to_vec();
    let mut body = Vec::with_capacity(nonce.len() + ciphertext.len());
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&ciphertext);

    let secret = genid().id;
    let mut fragment = encrypted_secret_fragment(secret, name, body, created_at)?;
    let sealed = DryocBox::seal_to_vecbox(&dek, &custody_box)
        .map_err(|error| anyhow!("seal to vault custody key: {error:?}"))?
        .to_vec();
    fragment += recipient_wrap_fragment(genid().id, secret, custody, sealed)?;
    Ok(SealedVersion { fragment, secret })
}

/// Re-seal one existing direct-vault DEK to a successor custody key without
/// reading or rewriting the encrypted secret body.
///
/// This is an explicit stopped-world migration seam, not a sharing API. The
/// source signing key must already have a valid direct wrap in `catalog`; all
/// such wraps are checked for one consistent DEK before the caller-selected
/// custody-wrap occurrence is constructed.
pub fn rewrap_version_for_migration<R: BlobStoreGet>(
    reader: &R,
    catalog: &VaultCatalog,
    secret: Id,
    source: &SigningKey,
    custody: RecipientPublicKey,
    wrap: Id,
) -> Result<Fragment> {
    let dek = recover_dek(reader, catalog, secret, source)
        .context("recover direct-vault DEK for custody migration")?;
    let custody_box = box_pk_from_ed25519(&custody)?;
    let sealed = DryocBox::seal_to_vecbox(&dek, &custody_box)
        .map_err(|error| anyhow!("seal migrated DEK to vault custody key: {error:?}"))?
        .to_vec();
    recipient_wrap_fragment(wrap, secret, custody, sealed)
}

/// Open one exact immutable version with its vault epoch custody key.
pub fn open_version<R: BlobStoreGet>(
    reader: &R,
    catalog: &VaultCatalog,
    secret: Id,
    custody: &SigningKey,
) -> Result<Vec<u8>> {
    let expected = catalog
        .custody
        .context("vault has no custody key; migrate the direct-recipient epoch first")?
        .public_key;
    if custody.verifying_key().to_bytes() != expected {
        bail!("supplied custody seed does not match the vault header");
    }
    let dek = recover_dek(reader, catalog, secret, custody)?;
    decrypt_secret_body(reader, catalog, secret, &dek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use triblespace::core::blob::IntoBlob;
    use triblespace::core::capability::CapabilityClaim;
    use triblespace::core::collection::descriptor as descriptor_facts;
    use triblespace::core::repo::memoryrepo::MemoryRepo;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn at(second: i64) -> IntervalValue {
        let epoch = Epoch::from_unix_seconds(second as f64);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn atom(collection: CollectionHandle, action: Id) -> CapabilityAtom {
        CapabilityAtom::new(
            CapabilityAction::new(action),
            CapabilityResource::from(collection),
        )
    }

    fn root_bundle(
        root: &SigningKey,
        subject: VerifyingKey,
        collection: CollectionHandle,
        action: Id,
        mode: CapabilityMode,
    ) -> CapabilityProofBundle {
        CapabilityProofBundle::issue_root(
            root,
            CapabilityClaim::root(atom(collection, action), mode, None),
            subject,
        )
        .unwrap()
    }

    fn catalog_from_fragment(vault: Id, fragment: &mut Fragment) -> VaultCatalog {
        let facts = fragment.facts().clone();
        let reader = fragment.blobs_mut().snapshot().unwrap();
        validate_catalog(&reader, vault, &facts).unwrap()
    }

    #[test]
    fn base36_roundtrips_full_range_and_rejects_noncanonical_names() {
        assert_eq!(
            format!("{ACTION_READ:X}"),
            "A6378B816786E9F08A579B8E5F8F4FF4"
        );
        let one = Id::new(1u128.to_be_bytes()).unwrap();
        assert_eq!(vault_name(one), "vault-0000000000000000000000001");
        for value in [1, 35, 36, u64::MAX as u128, u128::MAX] {
            let value = Id::new(value.to_be_bytes()).unwrap();
            assert_eq!(parse_vault_name(&vault_name(value)).unwrap(), value);
        }
        for malformed in [
            "other-0000000000000000000000001",
            "vault-000000000000000000000001",
            "vault-0000000000000000000000000",
            "vault-zzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            assert!(parse_vault_name(malformed).is_err(), "accepted {malformed}");
        }
    }

    #[test]
    fn store_created_vault_descriptor_has_exact_private_policy() {
        let vault = id(7);
        let authority = key(2).verifying_key();
        let mut store = MemoryRepo::default();
        let collection = store
            .collection(&vault_name(vault), vault_policy(authority))
            .unwrap();
        let snapshot = store.snapshot().unwrap();
        let descriptor: TribleSet = snapshot.get(collection.handle()).unwrap();

        assert_eq!(
            descriptor_facts::name(&descriptor).unwrap().unwrap(),
            vault_name(vault).to_blob().get_handle()
        );
        assert_eq!(
            descriptor_facts::policy(&descriptor).unwrap(),
            vault_policy(authority)
        );
        assert_eq!(
            descriptor_facts::representation(&descriptor).unwrap(),
            <blobencodings::SimpleArchive as MetaDescribe>::id()
        );
        assert_eq!(descriptor_facts::source(&descriptor).unwrap(), None);
        assert_eq!(descriptor_facts::mapping(&descriptor).unwrap(), None);
        drop(snapshot);
        let foreign = store
            .collection(&vault_name(vault), vault_policy(key(3).verifying_key()))
            .unwrap();
        assert_ne!(collection.handle(), foreign.handle());
    }

    #[test]
    fn legacy_header_stays_three_facts_and_custody_genesis_is_five() {
        let vault = id(8);
        let custody = SigningKey::generate(&mut OsRng);

        let mut legacy = legacy_vault_header_fragment(vault, "production", at(1)).unwrap();
        assert_eq!(legacy.root(), Some(vault));
        assert_eq!(legacy.facts().len(), 3);
        let legacy_catalog = catalog_from_fragment(vault, &mut legacy);
        assert_eq!(legacy_catalog.header.id, vault);
        assert!(legacy_catalog.custody.is_none());

        let mut genesis = vault_header_fragment(
            vault,
            "production",
            at(1),
            custody.verifying_key().to_bytes(),
        )
        .unwrap();
        assert_eq!(genesis.root(), Some(vault));
        assert_eq!(genesis.facts().len(), 5);
        let catalog = catalog_from_fragment(vault, &mut genesis);
        assert_eq!(
            catalog.custody.unwrap().public_key,
            custody.verifying_key().to_bytes()
        );
        assert!(catalog.secrets.is_empty());
        assert!(catalog.wraps.is_empty());
    }

    #[test]
    fn one_custody_wrap_opens_only_with_the_matching_custody_key() {
        let vault = id(9);
        let custody = SigningKey::generate(&mut OsRng);
        let outsider = SigningKey::generate(&mut OsRng);
        let sealed = seal_version(
            "database",
            b"hunter2",
            custody.verifying_key().to_bytes(),
            at(2),
        )
        .unwrap();
        let secret = sealed.secret;
        let mut fragment = vault_header_fragment(
            vault,
            "production",
            at(1),
            custody.verifying_key().to_bytes(),
        )
        .unwrap();
        fragment += sealed.fragment;

        let catalog = catalog_from_fragment(vault, &mut fragment);
        assert_eq!(catalog.wraps.len(), 1);
        assert_eq!(
            catalog
                .wraps_for(secret, custody.verifying_key().to_bytes())
                .len(),
            1
        );
        let reader = fragment.blobs_mut().snapshot().unwrap();
        assert_eq!(
            open_version(&reader, &catalog, secret, &custody).unwrap(),
            b"hunter2"
        );
        assert!(open_version(&reader, &catalog, secret, &outsider).is_err());
    }

    #[test]
    fn migration_rewraps_only_the_dek_and_preserves_the_encrypted_body() {
        let vault = id(60);
        let direct_reader = SigningKey::generate(&mut OsRng);
        let custody = SigningKey::generate(&mut OsRng);
        let sealed = seal_version(
            "database",
            b"unchanged ciphertext",
            direct_reader.verifying_key().to_bytes(),
            at(2),
        )
        .unwrap();
        let secret = sealed.secret;
        let mut fragment = legacy_vault_header_fragment(vault, "legacy", at(1)).unwrap();
        fragment += sealed.fragment;
        let direct_catalog = catalog_from_fragment(vault, &mut fragment);
        let original_body = direct_catalog.secrets[&secret].body;
        let reader = fragment.blobs_mut().snapshot().unwrap();
        let custody_wrap = rewrap_version_for_migration(
            &reader,
            &direct_catalog,
            secret,
            &direct_reader,
            custody.verifying_key().to_bytes(),
            id(61),
        )
        .unwrap();
        drop(reader);

        fragment += custody_record(custody.verifying_key().to_bytes());
        fragment += custody_wrap;
        let catalog = catalog_from_fragment(vault, &mut fragment);
        assert_eq!(catalog.secrets[&secret].body, original_body);
        let reader = fragment.blobs_mut().snapshot().unwrap();
        assert_eq!(
            open_version(&reader, &catalog, secret, &custody).unwrap(),
            b"unchanged ciphertext"
        );
    }

    #[test]
    fn catalog_rejects_missing_duplicate_or_competing_custody_rows_and_wraps() {
        let vault = id(10);
        let custody = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);

        let sealed_for_other = seal_version(
            "database",
            b"hunter2",
            other.verifying_key().to_bytes(),
            at(2),
        )
        .unwrap();
        let mut missing = vault_header_fragment(
            vault,
            "production",
            at(1),
            custody.verifying_key().to_bytes(),
        )
        .unwrap();
        missing += sealed_for_other.fragment;
        let error = load_catalog(vault, missing.facts()).unwrap_err();
        assert!(
            format!("{error:#}").contains("0 custody wraps"),
            "{error:#}"
        );

        let sealed = seal_version(
            "database",
            b"hunter2",
            custody.verifying_key().to_bytes(),
            at(2),
        )
        .unwrap();
        let secret = sealed.secret;
        let mut duplicate_wrap = vault_header_fragment(
            vault,
            "production",
            at(1),
            custody.verifying_key().to_bytes(),
        )
        .unwrap();
        duplicate_wrap += sealed.fragment;
        let extra = DryocBox::seal_to_vecbox(
            &Key::gen(),
            &box_pk_from_ed25519(&custody.verifying_key().to_bytes()).unwrap(),
        )
        .unwrap()
        .to_vec();
        duplicate_wrap +=
            recipient_wrap_fragment(id(90), secret, custody.verifying_key().to_bytes(), extra)
                .unwrap();
        let error = load_catalog(vault, duplicate_wrap.facts()).unwrap_err();
        assert!(
            format!("{error:#}").contains("2 custody wraps"),
            "{error:#}"
        );

        let mut competing_custody = vault_header_fragment(
            vault,
            "production",
            at(1),
            custody.verifying_key().to_bytes(),
        )
        .unwrap();
        competing_custody += custody_record(other.verifying_key().to_bytes());
        let error = load_catalog(vault, competing_custody.facts()).unwrap_err();
        assert!(
            format!("{error:#}").contains("2 custody declarations"),
            "{error:#}"
        );
    }

    #[test]
    fn snapshot_rejects_duplicate_vaults_and_secret_ids_across_vaults() {
        let vault_a = id(30);
        let vault_b = id(31);
        let custody = SigningKey::generate(&mut OsRng);
        let sealed = seal_version(
            "database",
            b"shared identity",
            custody.verifying_key().to_bytes(),
            at(2),
        )
        .unwrap();
        let secret = sealed.secret;

        let mut fragment_a =
            vault_header_fragment(vault_a, "alpha", at(1), custody.verifying_key().to_bytes())
                .unwrap();
        fragment_a += sealed.fragment.clone();
        let facts_a = fragment_a.facts().clone();

        let mut fragment_b =
            vault_header_fragment(vault_b, "beta", at(1), custody.verifying_key().to_bytes())
                .unwrap();
        fragment_b += sealed.fragment;
        let facts_b = fragment_b.facts().clone();

        let mut blobs = Fragment::empty();
        blobs += fragment_a;
        blobs += fragment_b;
        let reader = blobs.blobs_mut().snapshot().unwrap();

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
    fn vault_access_binds_exact_read_and_write_proofs() {
        let vault = id(40);
        let root = key(1);
        let subject = key(3);
        let outsider = key(4);
        let custody = SigningKey::generate(&mut OsRng);
        let mut authorized = MemoryRepo::default();
        let collection = authorized
            .collection(&vault_name(vault), vault_policy(root.verifying_key()))
            .unwrap();
        let wrong_resource = authorized
            .collection(&vault_name(id(41)), vault_policy(root.verifying_key()))
            .unwrap()
            .handle();
        let collection_handle = collection.handle();
        let read = root_bundle(
            &root,
            subject.verifying_key(),
            collection_handle,
            ACTION_READ,
            CapabilityMode::InvokeAndDelegate,
        );
        let write = root_bundle(
            &root,
            subject.verifying_key(),
            collection_handle,
            ACTION_WRITE,
            CapabilityMode::Invoke,
        );
        write
            .verify(
                root.verifying_key(),
                triblespace::core::clock::epoch_now(),
                subject.verifying_key(),
                CapabilityRequest::new(
                    atom(collection_handle, ACTION_WRITE),
                    CapabilityMode::Invoke,
                ),
            )
            .unwrap();

        let access = VaultAccess::new(
            vault,
            root.verifying_key(),
            collection,
            subject.verifying_key(),
            SigningKey::from_bytes(&custody.to_bytes()),
            vec![read.clone()],
            vec![write.clone()],
        )
        .unwrap();

        let sealed = seal_version(
            "database",
            b"hunter2",
            custody.verifying_key().to_bytes(),
            at(2),
        )
        .unwrap();
        let secret = sealed.secret;
        let mut fragment = vault_header_fragment(
            vault,
            "production",
            at(1),
            custody.verifying_key().to_bytes(),
        )
        .unwrap();
        fragment += sealed.fragment;
        let facts = fragment.facts().clone();

        crate::storage::persist_proof_bundle(&mut authorized, &write).unwrap();
        authorized
            .commit(collection, &subject, fragment.clone())
            .unwrap();
        let store_snapshot = authorized.snapshot().unwrap();
        let admitted: TribleSet = collection.read(&store_snapshot).unwrap();
        assert_eq!(admitted, facts);

        let reader = fragment.blobs_mut().snapshot().unwrap();
        let snapshot = SecretsSnapshot::new_accessible(
            reader.clone(),
            [(
                vault,
                VaultFacts::new(vec![SuccinctArchive::from(&facts)]),
                access,
            )],
        )
        .unwrap();
        assert_eq!(snapshot.open(secret, &subject).unwrap(), b"hunter2");
        assert!(snapshot.open(secret, &outsider).is_err());

        let wrong_read = root_bundle(
            &root,
            subject.verifying_key(),
            wrong_resource,
            ACTION_READ,
            CapabilityMode::Invoke,
        );
        assert!(VaultAccess::new(
            vault,
            root.verifying_key(),
            collection,
            subject.verifying_key(),
            SigningKey::from_bytes(&custody.to_bytes()),
            vec![wrong_read],
            vec![write.clone()],
        )
        .is_err());

        let wrong_subject_read = root_bundle(
            &root,
            outsider.verifying_key(),
            collection_handle,
            ACTION_READ,
            CapabilityMode::Invoke,
        );
        assert!(VaultAccess::new(
            vault,
            root.verifying_key(),
            collection,
            subject.verifying_key(),
            SigningKey::from_bytes(&custody.to_bytes()),
            vec![wrong_subject_read],
            vec![write.clone()],
        )
        .is_err());

        let wrong_custody = SigningKey::generate(&mut OsRng);
        let wrong_custody_access = VaultAccess::new(
            vault,
            root.verifying_key(),
            collection,
            subject.verifying_key(),
            wrong_custody,
            vec![read.clone()],
            vec![write.clone()],
        )
        .unwrap();
        assert!(SecretsSnapshot::new_accessible(
            reader.clone(),
            [(
                vault,
                VaultFacts::new(vec![SuccinctArchive::from(&facts)]),
                wrong_custody_access,
            )],
        )
        .is_err());

        let wrong_write = root_bundle(
            &root,
            subject.verifying_key(),
            wrong_resource,
            ACTION_WRITE,
            CapabilityMode::Invoke,
        );
        assert!(VaultAccess::new(
            vault,
            root.verifying_key(),
            collection,
            subject.verifying_key(),
            custody,
            vec![read],
            vec![wrong_write],
        )
        .is_err());
    }

    #[test]
    fn strict_shape_and_attachment_validation_rejects_unaccounted_or_bad_data() {
        let vault = id(50);
        let custody = SigningKey::generate(&mut OsRng);
        let sealed = seal_version(
            "database",
            b"hunter2",
            custody.verifying_key().to_bytes(),
            at(2),
        )
        .unwrap();
        let secret = sealed.secret;
        let mut valid = vault_header_fragment(
            vault,
            "production",
            at(1),
            custody.verifying_key().to_bytes(),
        )
        .unwrap();
        valid += sealed.fragment;
        catalog_from_fragment(vault, &mut valid);

        let mut extra = valid.clone();
        extra += entity! { ExclusiveId::force_ref(&secret) @
            metadata::description: "not part of the canonical secret record",
        };
        assert!(load_catalog(vault, extra.facts()).is_err());

        let mut malformed = vault_header_fragment(
            vault,
            "production",
            at(1),
            custody.verifying_key().to_bytes(),
        )
        .unwrap();
        let name = malformed.put("broken".to_owned());
        let body = malformed.put::<blobencodings::RawBytes, _>(vec![0; 23]);
        let malformed_secret = id(51);
        malformed += secret_record(malformed_secret, name, body, at(2));
        let wrapped = DryocBox::seal_to_vecbox(
            &Key::gen(),
            &box_pk_from_ed25519(&custody.verifying_key().to_bytes()).unwrap(),
        )
        .unwrap()
        .to_vec();
        malformed += recipient_wrap_fragment(
            id(52),
            malformed_secret,
            custody.verifying_key().to_bytes(),
            wrapped,
        )
        .unwrap();

        load_catalog(vault, malformed.facts()).unwrap();
        let facts = malformed.facts().clone();
        let reader = malformed.blobs_mut().snapshot().unwrap();
        let error = validate_catalog(&reader, vault, &facts).unwrap_err();
        assert!(format!("{error:#}").contains("too short"), "{error:#}");
    }
}
