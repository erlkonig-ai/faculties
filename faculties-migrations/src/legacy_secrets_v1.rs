//! Frozen reader for the retired v1 Secrets collection.
//!
//! This module is deliberately migration-local.  Current faculties must not
//! learn the identity/scope/grant/retraction language again merely so an old
//! pile can be upgraded.  The constants below pin the already-written v1 wire
//! identity and the parser accepts only its exact canonical records.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::error::Error as StdError;
use std::fmt;

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
use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace::core::metadata;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::*;
use zeroize::Zeroizing;

pub const COLLECTION_NAME: &str = "secrets";

pub const KIND_IDENTITY: Id = triblespace::macros::id_hex!("0B870F06D1B502EBE1259C90234E8BA2");
pub const KIND_GRANT: Id = triblespace::macros::id_hex!("BB95E8D2D7DC644B39396A1B6C10ECC6");
pub const KIND_SECRET: Id = triblespace::macros::id_hex!("72B64C9F3644B8016B64820D7F3F23C1");
pub const KIND_WRAP: Id = triblespace::macros::id_hex!("EB8549BAF679C5D11ECEDB416AAD76E3");
pub const KIND_SCOPE: Id = triblespace::macros::id_hex!("B2920B23494B9DBD4500158D84432325");

attributes! {
    "FD0897D627CF18F4E49A93968A8D6301" unsafe as identity_sign_pk:
        inlineencodings::Handle<blobencodings::RawBytes>;
    "1E4279231655D8C67835865C3AFB629F" unsafe as identity_lockbox:
        inlineencodings::Handle<blobencodings::RawBytes>;
    "B3F0E5A5FFACC159B651BFDA19EAE18C" unsafe as grant_object:
        inlineencodings::GenId;
    "22F807F93FADFE092C8CE0698044680B" unsafe as grant_relation:
        inlineencodings::ShortString;
    "B44AF03BA7AF04ED81096D7900D70A12" unsafe as grant_subject:
        inlineencodings::GenId;
    "B177568BEE389D76D9D71110E9067EF1" unsafe as grant_issuer:
        inlineencodings::GenId;
    "73CE206E6B9B81CB2BD2388ECC5D3AA8" unsafe as grant_retracted_at:
        inlineencodings::NsTAIInterval;
    "A66C795299212D16BA6BA25BD1D9F983" unsafe as secret_scope:
        inlineencodings::GenId;
    "8FD8C43D3490ACD6AFAD6D691B748CA3" unsafe as secret_name:
        inlineencodings::ShortString;
    "7FC38805FDC9FA4D8449497B298B51BB" unsafe as secret_body:
        inlineencodings::Handle<blobencodings::RawBytes>;
    "D17EC6F6A9F9D6B7A3B9A329A9CFC4CC" unsafe as wrap_secret:
        inlineencodings::GenId;
    "CAD2A79E7F5B1A870F5814BDEE5C90F8" unsafe as wrap_recipient:
        inlineencodings::GenId;
    "B30CE37D4DC3CAACC34D946B3D71E37C" unsafe as wrap_dek:
        inlineencodings::Handle<blobencodings::RawBytes>;
    "CE866212934742FF5B27DEF25E366E07" unsafe as scope_creator:
        inlineencodings::GenId;
}

pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;
pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;
pub type BytesHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;
pub type RecipientPublicKey = [u8; 32];

const LOCKBOX_BYTES: usize = 16 + 24 + 16 + 64;
const SECRET_BODY_MIN_BYTES: usize = 24 + 16;
const SEALED_DEK_BYTES: usize = 48 + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityRow {
    pub id: Id,
    pub created_at: IntervalValue,
    pub name: TextHandle,
    pub sign_pk: BytesHandle,
    pub lockbox: Option<BytesHandle>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeRow {
    pub id: Id,
    pub creator: Id,
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
pub struct Catalog {
    pub identities: BTreeMap<Id, IdentityRow>,
    pub scopes: BTreeMap<Id, ScopeRow>,
    pub grants: BTreeMap<Id, GrantRow>,
    pub secrets: BTreeMap<Id, SecretRow>,
    pub wraps: BTreeMap<Id, WrapRow>,
}

impl Catalog {
    fn effective_admins(&self, scope: Id) -> HashSet<Id> {
        let mut admins = HashSet::new();
        let Some(creator) = self.scopes.get(&scope).map(|row| row.creator) else {
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

    /// The exact v1 least fixpoint: live grant edges rooted in each scope's
    /// effective administrators, with the scope creator always included.
    pub fn recipients_of(&self, scope: Id) -> BTreeSet<Id> {
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
        let mut recipients = visited
            .into_iter()
            .filter(|id| self.identities.contains_key(id))
            .collect::<BTreeSet<_>>();
        if let Some(creator) = self.scopes.get(&scope).map(|row| row.creator) {
            recipients.insert(creator);
        }
        recipients
    }

    pub fn wraps_for(&self, secret: Id, recipient: Id) -> Vec<&WrapRow> {
        self.wraps
            .values()
            .filter(|row| row.secret == secret && row.recipient == recipient)
            .collect()
    }
}

#[derive(Debug)]
pub struct PasswordRequired;

impl fmt::Display for PasswordRequired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a legacy identity password is required to migrate one or more DEKs")
    }
}

impl StdError for PasswordRequired {}

fn fmt_id(id: Id) -> String {
    format!("{id:X}")
}

fn exactly_one<T>(entity: Id, field: &str, mut values: Vec<T>) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "legacy Secrets entity {} has {} values for {field}; expected exactly one",
            fmt_id(entity),
            values.len()
        );
    }
    Ok(values.pop().expect("length checked"))
}

fn at_most_one<T>(entity: Id, field: &str, mut values: Vec<T>) -> Result<Option<T>> {
    if values.len() > 1 {
        bail!(
            "legacy Secrets entity {} has {} values for {field}; expected at most one",
            fmt_id(entity),
            values.len()
        );
    }
    Ok(values.pop())
}

fn point_interval(entity: Id, field: &str, value: IntervalValue) -> Result<()> {
    let (lower, upper): (i128, i128) = value
        .try_from_inline()
        .map_err(|error| anyhow!("decode {field} on {}: {error:?}", fmt_id(entity)))?;
    if lower != upper {
        bail!("{field} on {} must be a point interval", fmt_id(entity));
    }
    Ok(())
}

fn validate_short(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.trim() != value || value.as_bytes().contains(&0) {
        bail!("{field} is not one canonical non-empty string");
    }
    if value.len() > 32 {
        bail!("{field} exceeds 32 UTF-8 bytes");
    }
    Ok(())
}

fn validate_name(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.trim() != value || value.as_bytes().contains(&0) {
        bail!("{field} is not one canonical non-empty string");
    }
    Ok(())
}

fn entity_facts(space: &TribleSet, entity: Id) -> TribleSet {
    space
        .iter()
        .filter(|fact| fact.e() == &entity)
        .copied()
        .collect()
}

fn tagged_entities(space: &TribleSet, kind: Id) -> BTreeSet<Id> {
    find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: kind }])).collect()
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
    entity! { _ @ scope_creator: creator, metadata::name: name }
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

fn scope_record(row: &ScopeRow) -> Fragment {
    let mut fragment = entity! { ExclusiveId::force_ref(&row.id) @
        scope_creator: row.creator,
        metadata::name: row.name,
        metadata::tag: &KIND_SCOPE,
    };
    for created_at in &row.created_at {
        fragment += entity! { ExclusiveId::force_ref(&row.id) @
            metadata::created_at: *created_at
        };
    }
    fragment
}

fn grant_record(row: &GrantRow) -> Fragment {
    let mut fragment = entity! { ExclusiveId::force_ref(&row.id) @
        metadata::tag: &KIND_GRANT,
        metadata::created_at: row.created_at,
        grant_object: row.object,
        grant_relation: row.relation.as_str(),
        grant_subject: row.subject,
        grant_issuer: row.issuer,
    };
    for retracted_at in &row.retracted_at {
        fragment += entity! { ExclusiveId::force_ref(&row.id) @
            grant_retracted_at: *retracted_at
        };
    }
    fragment
}

fn secret_record(row: &SecretRow) -> Fragment {
    entity! { ExclusiveId::force_ref(&row.id) @
        metadata::tag: &KIND_SECRET,
        metadata::created_at: row.created_at,
        metadata::name: row.display_name,
        secret_scope: row.scope,
        secret_name: row.name.as_str(),
        secret_body: row.body,
    }
}

fn wrap_record(row: &WrapRow) -> Fragment {
    entity! { ExclusiveId::force_ref(&row.id) @
        metadata::tag: &KIND_WRAP,
        metadata::created_at: row.created_at,
        wrap_secret: row.secret,
        wrap_recipient: row.recipient,
        wrap_dek: row.sealed_dek,
    }
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
        bail!("legacy Secrets identity {} is not canonical", fmt_id(id));
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
        bail!("legacy Secrets scope {} has no creation time", fmt_id(id));
    }
    for value in &row.created_at {
        point_interval(id, "scope creation time", *value)?;
    }
    let (current, legacy) = scope_identity_epochs(row.creator, row.name);
    if id != current && id != legacy {
        bail!(
            "legacy Secrets scope {} has a noncanonical identity",
            fmt_id(id)
        );
    }
    if entity_facts(space, id) != *scope_record(&row).facts() {
        bail!("legacy Secrets scope {} is not canonical", fmt_id(id));
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
    if entity_facts(space, id) != *grant_record(&row).facts() {
        bail!("legacy Secrets grant {} is not canonical", fmt_id(id));
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
    if entity_facts(space, id) != *secret_record(&row).facts() {
        bail!("legacy Secrets version {} is not canonical", fmt_id(id));
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
    if entity_facts(space, id) != *wrap_record(&row).facts() {
        bail!("legacy Secrets wrap {} is not canonical", fmt_id(id));
    }
    Ok(row)
}

/// Strictly decode the complete v1 fact grammar without touching attachments.
pub fn load_catalog(space: &TribleSet) -> Result<Catalog> {
    let identity_ids = tagged_entities(space, KIND_IDENTITY);
    let scope_ids = tagged_entities(space, KIND_SCOPE);
    let grant_ids = tagged_entities(space, KIND_GRANT);
    let secret_ids = tagged_entities(space, KIND_SECRET);
    let wrap_ids = tagged_entities(space, KIND_WRAP);

    let mut catalog = Catalog::default();
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
                "legacy scopes {} and {} claim one intrinsic identity",
                fmt_id(previous),
                fmt_id(scope.id)
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
            bail!("legacy scope {} has a missing creator", fmt_id(scope.id));
        }
    }
    for grant in catalog.grants.values() {
        if !catalog.scopes.contains_key(&grant.object)
            || !catalog.identities.contains_key(&grant.issuer)
            || (!catalog.identities.contains_key(&grant.subject)
                && !catalog.scopes.contains_key(&grant.subject))
        {
            bail!("legacy grant {} has a dangling reference", fmt_id(grant.id));
        }
    }
    for secret in catalog.secrets.values() {
        if !catalog.scopes.contains_key(&secret.scope) {
            bail!("legacy secret {} has a missing scope", fmt_id(secret.id));
        }
        if !catalog.wraps.values().any(|wrap| wrap.secret == secret.id) {
            bail!("legacy secret {} has no recipient wrap", fmt_id(secret.id));
        }
    }
    for wrap in catalog.wraps.values() {
        if !catalog.secrets.contains_key(&wrap.secret)
            || !catalog.identities.contains_key(&wrap.recipient)
        {
            bail!("legacy wrap {} has a dangling reference", fmt_id(wrap.id));
        }
    }

    let all_ids = identity_ids
        .into_iter()
        .chain(scope_ids)
        .chain(grant_ids)
        .chain(secret_ids)
        .chain(wrap_ids)
        .collect::<BTreeSet<_>>();
    let accounted = all_ids
        .iter()
        .map(|id| entity_facts(space, *id).len())
        .sum::<usize>();
    if accounted != space.len() {
        bail!(
            "legacy Secrets collection has {} facts outside its frozen grammar",
            space.len() - accounted.min(space.len())
        );
    }
    Ok(catalog)
}

pub fn read_text<R: BlobStoreGet>(reader: &R, handle: TextHandle) -> Result<String> {
    let value: anybytes::View<str> = reader.get(handle).context("read legacy UTF-8 attachment")?;
    Ok(value.to_string())
}

pub fn read_bytes<R: BlobStoreGet>(reader: &R, handle: BytesHandle) -> Result<Vec<u8>> {
    let value: anybytes::Bytes = reader.get(handle).context("read legacy byte attachment")?;
    Ok(value.as_ref().to_vec())
}

/// Validate every direct v1 attachment and return the strict catalog.
pub fn validate_catalog<R: BlobStoreGet>(reader: &R, space: &TribleSet) -> Result<Catalog> {
    let catalog = load_catalog(space)?;
    let mut public_keys = BTreeMap::new();
    for identity in catalog.identities.values() {
        let name = read_text(reader, identity.name)
            .with_context(|| format!("read legacy identity {} name", fmt_id(identity.id)))?;
        validate_name("legacy identity name", &name)?;
        let key = read_bytes(reader, identity.sign_pk)
            .with_context(|| format!("read legacy identity {} public key", fmt_id(identity.id)))?;
        let key: RecipientPublicKey = key.try_into().map_err(|_| {
            anyhow!(
                "legacy identity {} has a malformed key",
                fmt_id(identity.id)
            )
        })?;
        VerifyingKey::from_bytes(&key)
            .with_context(|| format!("validate legacy identity {} key", fmt_id(identity.id)))?;
        box_pk_from_ed25519(&key)?;
        if let Some(previous) = public_keys.insert(key, identity.id) {
            bail!(
                "legacy identities {} and {} claim one public key",
                fmt_id(previous),
                fmt_id(identity.id)
            );
        }
        if let Some(lockbox) = identity.lockbox {
            let bytes = read_bytes(reader, lockbox)
                .with_context(|| format!("read legacy identity {} lockbox", fmt_id(identity.id)))?;
            if bytes.len() != LOCKBOX_BYTES {
                bail!(
                    "legacy identity {} has a malformed lockbox",
                    fmt_id(identity.id)
                );
            }
        }
    }
    for scope in catalog.scopes.values() {
        validate_name("legacy scope name", &read_text(reader, scope.name)?)?;
    }
    for secret in catalog.secrets.values() {
        let display = read_text(reader, secret.display_name)?;
        if display != secret.name {
            bail!("legacy secret {} has disagreeing names", fmt_id(secret.id));
        }
        let body = read_bytes(reader, secret.body)?;
        if body.len() < SECRET_BODY_MIN_BYTES {
            bail!("legacy secret {} has a malformed body", fmt_id(secret.id));
        }
    }
    for wrap in catalog.wraps.values() {
        let sealed = read_bytes(reader, wrap.sealed_dek)?;
        if sealed.len() != SEALED_DEK_BYTES {
            bail!("legacy wrap {} has a malformed sealed DEK", fmt_id(wrap.id));
        }
        let _: dryoc::dryocbox::VecBox = DryocBox::from_sealed_bytes(&sealed)
            .map_err(|error| anyhow!("parse legacy wrap {}: {error:?}", fmt_id(wrap.id)))?;
    }
    Ok(catalog)
}

/// Translate every v1 identity occurrence to its exact direct Ed25519 key.
pub fn identity_public_keys<R: BlobStoreGet>(
    reader: &R,
    catalog: &Catalog,
) -> Result<BTreeMap<Id, RecipientPublicKey>> {
    catalog
        .identities
        .values()
        .map(|identity| {
            let bytes = read_bytes(reader, identity.sign_pk)?;
            let key = bytes.try_into().map_err(|_| {
                anyhow!(
                    "legacy identity {} has a malformed key",
                    fmt_id(identity.id)
                )
            })?;
            Ok((identity.id, key))
        })
        .collect()
}

fn derive_key(password: &[u8], salt: &[u8]) -> Key {
    let mut output = Zeroizing::new([0u8; 32]);
    crypto_pwhash(
        output.as_mut_slice(),
        password,
        salt,
        CRYPTO_PWHASH_OPSLIMIT_MODERATE,
        CRYPTO_PWHASH_MEMLIMIT_MODERATE,
        PasswordHashAlgorithm::Argon2id13,
    )
    .expect("argon2id parameters are fixed and valid");
    Key::try_from(output.as_slice()).expect("32-byte secretbox key")
}

fn unlock_secret_key(password: &[u8], lockbox: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if lockbox.len() != LOCKBOX_BYTES {
        bail!("malformed legacy identity lockbox");
    }
    let salt = &lockbox[..CRYPTO_PWHASH_SALTBYTES];
    let nonce = Nonce::try_from(&lockbox[CRYPTO_PWHASH_SALTBYTES..][..24])
        .context("legacy lockbox nonce")?;
    let ciphertext = &lockbox[CRYPTO_PWHASH_SALTBYTES + 24..];
    let key = derive_key(password, salt);
    let plaintext = DryocSecretBox::from_bytes(ciphertext)
        .map_err(|error| anyhow!("parse legacy lockbox: {error:?}"))?
        .decrypt_to_vec(&nonce, &key)
        .map_err(|_| anyhow!("legacy identity password did not open a lockbox"))?;
    Ok(Zeroizing::new(plaintext))
}

fn box_pk_from_ed25519(public: &RecipientPublicKey) -> Result<BoxPublicKey> {
    VerifyingKey::from_bytes(public).context("invalid legacy Ed25519 public key")?;
    let mut x25519 = [0u8; 32];
    crypto_sign_ed25519_pk_to_curve25519(&mut x25519, public)
        .map_err(|error| anyhow!("legacy public-key conversion: {error:?}"))?;
    BoxPublicKey::try_from(&x25519[..])
        .map_err(|error| anyhow!("legacy X25519 public key: {error:?}"))
}

fn box_keypair_from_ed25519(secret: &[u8], public: &RecipientPublicKey) -> Result<BoxKeyPair> {
    let secret: &[u8; 64] = secret
        .try_into()
        .context("legacy Ed25519 private-key length")?;
    let mut x_public = [0u8; 32];
    let mut x_secret = Zeroizing::new([0u8; 32]);
    crypto_sign_ed25519_pk_to_curve25519(&mut x_public, public)
        .map_err(|error| anyhow!("legacy public-key conversion: {error:?}"))?;
    crypto_sign_ed25519_sk_to_curve25519(&mut x_secret, secret);
    BoxKeyPair::from_slices(&x_public, x_secret.as_slice())
        .map_err(|error| anyhow!("legacy X25519 keypair: {error:?}"))
}

fn recover_for_identity<R: BlobStoreGet>(
    reader: &R,
    catalog: &Catalog,
    secret: Id,
    identity: Id,
    keypair: &BoxKeyPair,
) -> Result<Zeroizing<[u8; 32]>> {
    let wraps = catalog.wraps_for(secret, identity);
    if wraps.is_empty() {
        bail!("legacy identity has no wrap for requested secret");
    }
    let mut recovered: Option<Zeroizing<[u8; 32]>> = None;
    for wrap in wraps {
        let sealed = read_bytes(reader, wrap.sealed_dek)?;
        let bytes = Zeroizing::new(
            DryocBox::from_sealed_bytes(&sealed)
                .map_err(|error| anyhow!("parse legacy sealed DEK: {error:?}"))?
                .unseal_to_vec(keypair)
                .map_err(|_| anyhow!("unseal legacy DEK failed"))?,
        );
        let candidate: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("legacy wrap opened to a malformed DEK"))?;
        if recovered
            .as_ref()
            .is_some_and(|previous| previous.as_ref() != candidate)
        {
            bail!("legacy wraps for one identity open to competing DEKs");
        }
        recovered.get_or_insert_with(|| Zeroizing::new(candidate));
    }
    recovered.ok_or_else(|| anyhow!("no legacy DEK recovered"))
}

/// Recover a DEK through every locally accessible legacy wrap and require all
/// accessible assertions to agree.  The encrypted secret body is never read.
pub fn recover_dek_for_migration<R: BlobStoreGet>(
    reader: &R,
    catalog: &Catalog,
    secret: Id,
    signer: &SigningKey,
    password: Option<&[u8]>,
) -> Result<Zeroizing<[u8; 32]>> {
    if !catalog.secrets.contains_key(&secret) {
        bail!("legacy secret {} does not exist", fmt_id(secret));
    }
    let keys = identity_public_keys(reader, catalog)?;
    let signer_public = signer.verifying_key().to_bytes();
    let holders = catalog
        .wraps
        .values()
        .filter(|wrap| wrap.secret == secret)
        .map(|wrap| wrap.recipient)
        .collect::<BTreeSet<_>>();
    let mut recovered: Option<Zeroizing<[u8; 32]>> = None;
    let mut password_candidate = false;

    for identity_id in holders {
        let identity = &catalog.identities[&identity_id];
        let public = keys[&identity_id];
        let keypair = if public == signer_public {
            let secret = Zeroizing::new(signer.to_keypair_bytes());
            Some(box_keypair_from_ed25519(secret.as_slice(), &public)?)
        } else if let Some(lockbox) = identity.lockbox {
            password_candidate = true;
            let Some(password) = password else {
                continue;
            };
            let lockbox = read_bytes(reader, lockbox)?;
            match unlock_secret_key(password, &lockbox) {
                Ok(secret) => Some(box_keypair_from_ed25519(secret.as_slice(), &public)?),
                Err(_) => None,
            }
        } else {
            None
        };
        let Some(keypair) = keypair else {
            continue;
        };
        let candidate = recover_for_identity(reader, catalog, secret, identity_id, &keypair)?;
        if recovered
            .as_ref()
            .is_some_and(|previous| previous.as_ref() != candidate.as_ref())
        {
            bail!("accessible legacy wraps open to competing DEKs");
        }
        if recovered.is_none() {
            recovered = Some(candidate);
        }
    }

    match recovered {
        Some(dek) => Ok(dek),
        None if password.is_none() && password_candidate => Err(PasswordRequired.into()),
        None => bail!("no local credential opens a legacy wrap for the requested secret"),
    }
}

/// Seal one already-recovered v1 DEK to a v2 direct recipient.  This crosses
/// only the KEM boundary and cannot inspect or rewrite the encrypted body.
pub fn seal_dek_for_recipient(dek: &[u8; 32], recipient: RecipientPublicKey) -> Result<Vec<u8>> {
    let dek = Key::try_from(&dek[..]).context("decode recovered legacy DEK")?;
    let recipient = box_pk_from_ed25519(&recipient)?;
    DryocBox::seal_to_vecbox(&dek, &recipient)
        .map(|sealed| sealed.to_vec())
        .map_err(|_| anyhow!("seal recovered legacy DEK to v2 recipient failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_anchors_match_the_retired_runtime_wire_identity() {
        assert_eq!(KIND_IDENTITY, faculties::secrets::schema::KIND_IDENTITY);
        assert_eq!(KIND_SCOPE, faculties::secrets::schema::KIND_SCOPE);
        assert_eq!(KIND_GRANT, faculties::secrets::schema::KIND_GRANT);
        assert_eq!(KIND_SECRET, faculties::secrets::schema::KIND_SECRET);
        assert_eq!(KIND_WRAP, faculties::secrets::schema::KIND_WRAP);
        assert_eq!(
            identity_sign_pk.id(),
            faculties::secrets::schema::identity_sign_pk.id()
        );
        assert_eq!(
            secret_body.id(),
            faculties::secrets::schema::secret_body.id()
        );
        assert_eq!(
            wrap_recipient.id(),
            faculties::secrets::schema::wrap_recipient.id()
        );
    }
}
