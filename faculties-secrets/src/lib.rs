//! faculties-secrets — the capability + envelope-encryption core of the `secrets`
//! faculty, extracted from the monolithic `src/bin/secrets.rs` so both the CLI
//! and (later) the playground/OAuth can depend on it without pulling all of
//! faculties (no mary/GORBIE/egui). This crate is the shared data layout (the 5
//! KIND ids + attributes), the crypto primitives, the capability queries (the
//! effective-admin fixpoint), and the mutating operations — everything the
//! `secrets` bin does MINUS the clap parsing and the `println!` output.
//!
//! Design captured in the `authz`-tagged wiki (hub 4448d5fc).
//!
//! The envelope (KEM-DEM): a fresh data key (DEK) encrypts a secret body once
//! via secretbox; the DEK is sealed-boxed to each recipient's X25519 key (the
//! key is *derived* from their Ed25519 identity key). Removal = rotate. The
//! current recipient set is enumerated from the grant tuples with the query
//! engine — never stored, "work as its own ledger".
//!
//! Scopes are content-derived and rooted at their creator
//! (`scope_id = Blake3(creator_pk, name)`); a grant is *effective* only if its
//! issuer chains, through admin-grants, back to that root (the
//! `effective_admins` fixpoint). Strong/transitive removal therefore falls out
//! for free — retracting an admin drops everything that depended on it.
//! Transitive group membership is `path!`'s closure over *effective* grants.
//! Secrets are `(scope, name)` addressed, latest-wins (`secret_add` of an
//! existing name is a new version, sealed to the *current* recipients).
//!
//! Removal is *operational, not cryptographic*: a removed user keeps the wrap
//! (= the value) they already held — the append-only pile cannot delete it, and
//! re-encrypting the same value protects nothing. So `rotate_worklist` is not a
//! crypto op; it lists every credential still readable by a removed user, so you
//! can change it at its source and `secret_add` the new value.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use hifitime::Epoch;
use rand_core::{OsRng, RngCore};

use dryoc::classic::crypto_pwhash::{PasswordHashAlgorithm, crypto_pwhash};
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

use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::prelude::blobencodings::{LongString, RawBytes};
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;

// ── schema ──────────────────────────────────────────────────────────────────
// Minted with `trible genid` 2026-06-19. Reserved-but-unused (for the
// correctness/governance layers): grant_sig 74521A9057EBC9B75C957F25D504B5FA,
// grant_issued_at 7411C2DDB81DC5C1B1AC85F4449B2EB9 (we use metadata::created_at),
// secret_created_at 6A0708F6F48490661F55240ED5D1C279 (idem),
// identity_nickname FF6BE7814DFCA5401E48DBDF0429C3EB (we use metadata::name),
// secrets_metadata B906AE45B1F40AE47C9924A18E7CE2B9.
pub mod schema {
    use triblespace::macros::id_hex;
    use triblespace::prelude::blobencodings::RawBytes;
    use triblespace::prelude::inlineencodings::{GenId, Handle, NsTAIInterval, ShortString};
    use triblespace::prelude::*;

    attributes! {
        "FD0897D627CF18F4E49A93968A8D6301" as pub identity_sign_pk: Handle<RawBytes>;
        "1E4279231655D8C67835865C3AFB629F" as pub identity_lockbox: Handle<RawBytes>;
        "B3F0E5A5FFACC159B651BFDA19EAE18C" as pub grant_object: GenId;
        "22F807F93FADFE092C8CE0698044680B" as pub grant_relation: ShortString;
        "B44AF03BA7AF04ED81096D7900D70A12" as pub grant_subject: GenId;
        "B177568BEE389D76D9D71110E9067EF1" as pub grant_issuer: GenId;
        "73CE206E6B9B81CB2BD2388ECC5D3AA8" as pub grant_retracted_at: NsTAIInterval;
        "A66C795299212D16BA6BA25BD1D9F983" as pub secret_scope: GenId;
        "8FD8C43D3490ACD6AFAD6D691B748CA3" as pub secret_name: ShortString;
        "7FC38805FDC9FA4D8449497B298B51BB" as pub secret_body: Handle<RawBytes>;
        "D17EC6F6A9F9D6B7A3B9A329A9CFC4CC" as pub wrap_secret: GenId;
        "CAD2A79E7F5B1A870F5814BDEE5C90F8" as pub wrap_recipient: GenId;
        "B30CE37D4DC3CAACC34D946B3D71E37C" as pub wrap_dek: Handle<RawBytes>;
        // Ephemeral edge, only ever asserted into an in-memory TribleSet for
        // `path!` transitive closure — never persisted. (minted 2026-06-19)
        "ABAF427C4F1CB01AA7091A9C38F0DA3A" as pub reaches: GenId;
        // A scope is a content-derived entity: id = Blake3(creator_pk, name).
        // The creator is the implicit root admin. (minted 2026-06-19)
        "CE866212934742FF5B27DEF25E366E07" as pub scope_creator: GenId;
    }

    pub const KIND_IDENTITY: Id = id_hex!("0B870F06D1B502EBE1259C90234E8BA2");
    pub const KIND_GRANT: Id = id_hex!("BB95E8D2D7DC644B39396A1B6C10ECC6");
    pub const KIND_SECRET: Id = id_hex!("72B64C9F3644B8016B64820D7F3F23C1");
    pub const KIND_WRAP: Id = id_hex!("EB8549BAF679C5D11ECEDB416AAD76E3");
    pub const KIND_SCOPE: Id = id_hex!("B2920B23494B9DBD4500158D84432325");
}

use schema::{
    KIND_GRANT, KIND_IDENTITY, KIND_SCOPE, KIND_SECRET, KIND_WRAP, grant_issuer, grant_object,
    grant_relation, grant_retracted_at, grant_subject, identity_lockbox, identity_sign_pk, reaches,
    scope_creator, secret_body, secret_name, secret_scope, wrap_dek, wrap_recipient, wrap_secret,
};

/// The default branch the `secrets` faculty stores its data on.
pub const DEFAULT_BRANCH: &str = "secrets";

type IntervalValue = Inline<inlineencodings::NsTAIInterval>;
type TextHandle = Inline<Handle<LongString>>;
type BytesHandle = Inline<Handle<RawBytes>>;

// ── crypto ──────────────────────────────────────────────────────────────────

/// Derive a 32-byte secretbox key from a password and salt via Argon2id.
fn derive_key(password: &[u8], salt: &[u8]) -> Key {
    let mut out = [0u8; 32];
    crypto_pwhash(
        &mut out,
        password,
        salt,
        CRYPTO_PWHASH_OPSLIMIT_MODERATE,
        CRYPTO_PWHASH_MEMLIMIT_MODERATE,
        PasswordHashAlgorithm::Argon2id13,
    )
    .expect("argon2id");
    Key::try_from(&out[..]).expect("32-byte key")
}

/// Password-lock an Ed25519 secret key: `salt(16) ‖ nonce(24) ‖ secretbox(sk)`.
pub fn lock_secret_key(password: &[u8], sk: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; CRYPTO_PWHASH_SALTBYTES];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt);
    let nonce = Nonce::gen();
    let ct = DryocSecretBox::encrypt_to_vecbox(sk, &nonce, &key).to_vec();
    let mut out = Vec::with_capacity(salt.len() + nonce.len() + ct.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Recover the Ed25519 secret key from a lockbox.
pub fn unlock_secret_key(password: &[u8], lockbox: &[u8]) -> Result<Vec<u8>> {
    if lockbox.len() < CRYPTO_PWHASH_SALTBYTES + 24 {
        bail!("malformed lockbox");
    }
    let salt = &lockbox[..CRYPTO_PWHASH_SALTBYTES];
    let nonce = Nonce::try_from(&lockbox[CRYPTO_PWHASH_SALTBYTES..CRYPTO_PWHASH_SALTBYTES + 24])
        .context("nonce")?;
    let ct = &lockbox[CRYPTO_PWHASH_SALTBYTES + 24..];
    let key = derive_key(password, salt);
    DryocSecretBox::from_bytes(ct)
        .map_err(|e| anyhow::anyhow!("parse lockbox: {e:?}"))?
        .decrypt_to_vec(&nonce, &key)
        .map_err(|_| anyhow::anyhow!("wrong password"))
}

/// A scope's identity *is* its `(creator, name)`: build the intrinsic fragment
/// whose entity id `entity!` derives from exactly those two facts. Creating
/// "the same scope" twice converges to one entity (idempotent), and the id can
/// never drift from what it commits to — the derivation is the macro's job, not
/// a hand-rolled hash. Non-identifying facts (tag, created_at) are added by the
/// caller under `fragment.root()`.
pub fn scope_fragment(creator: Id, name_handle: TextHandle) -> Fragment {
    entity! { _ @
        scope_creator: &creator,
        metadata::name: name_handle,
    }
}

/// Derive the X25519 public key (for sealing) from an Ed25519 public key.
pub fn box_pk_from_ed25519(ed_pk: &[u8]) -> Result<BoxPublicKey> {
    let arr: &[u8; 32] = ed_pk.try_into().context("ed25519 public key length")?;
    let mut xpk = [0u8; 32];
    crypto_sign_ed25519_pk_to_curve25519(&mut xpk, arr)
        .map_err(|e| anyhow::anyhow!("pk convert: {e:?}"))?;
    BoxPublicKey::try_from(&xpk[..]).map_err(|e| anyhow::anyhow!("x25519 pk: {e:?}"))
}

/// Build the X25519 keypair (for unsealing) from an Ed25519 keypair.
pub fn box_keypair_from_ed25519(ed_sk: &[u8], ed_pk: &[u8]) -> Result<BoxKeyPair> {
    let sk_arr: &[u8; 64] = ed_sk.try_into().context("ed25519 secret key length")?;
    let pk_arr: &[u8; 32] = ed_pk.try_into().context("ed25519 public key length")?;
    let mut xpk = [0u8; 32];
    let mut xsk = [0u8; 32];
    crypto_sign_ed25519_pk_to_curve25519(&mut xpk, pk_arr)
        .map_err(|e| anyhow::anyhow!("pk convert: {e:?}"))?;
    crypto_sign_ed25519_sk_to_curve25519(&mut xsk, sk_arr);
    BoxKeyPair::from_slices(&xpk, &xsk).map_err(|e| anyhow::anyhow!("x25519 keypair: {e:?}"))
}

// ── pile plumbing (mirrors decide.rs) ─────────────────────────────────────────

fn open_repo(path: &Path) -> Result<Repository<Pile>> {
    let mut pile =
        Pile::open(path).map_err(|e| anyhow::anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.refresh() {
        let _ = pile.close();
        return Err(match err {
            triblespace::core::repo::pile::ReadError::CorruptPile { valid_length } => anyhow::anyhow!(
                "pile corrupt at byte {valid_length}: refusing to auto-repair (a stale binary \
                 could truncate newer data). If, and only if, the tail is a genuinely torn write, truncate it explicitly (DESTRUCTIVE) with: trible pile amputate {}",
                path.display()
            ),
            other => anyhow::anyhow!("refresh pile {}: {other:?}", path.display()),
        });
    }
    let signing_key = SigningKey::generate(&mut OsRng);
    Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|err| anyhow::anyhow!("create repository: {err:?}"))
}

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

/// Wrap an instant as a zero-width `[at, at]` interval value.
pub fn instant_interval(at: Epoch) -> IntervalValue {
    (at, at).try_to_inline().unwrap()
}

/// Format an [`Id`] as its lowercase hex string.
pub fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn read_text(ws: &mut Workspace<Pile>, h: TextHandle) -> Option<String> {
    ws.get::<View<str>, LongString>(h).ok().map(|v| v.to_string())
}

fn read_bytes(ws: &mut Workspace<Pile>, h: BytesHandle) -> Option<Vec<u8>> {
    ws.get::<anybytes::Bytes, _>(h).ok().map(|b| b.as_ref().to_vec())
}

fn put_bytes(ws: &mut Workspace<Pile>, bytes: Vec<u8>) -> BytesHandle {
    ws.put::<RawBytes, _>(bytes)
}

// ── enumerate (the engine does the work) ──────────────────────────────────────

/// A grant is *live* at `now` if it carries no retraction coordinate (the
/// non-concurrent cursor; the concurrency-safe rules are the next layer).
pub fn grant_is_live(space: &TribleSet, grant: Id) -> bool {
    !exists!(pattern!(space, [{ grant @ grant_retracted_at: _?r }]))
}

fn interval_start(iv: IntervalValue) -> Epoch {
    let (start, _end): (Epoch, Epoch) = iv.try_from_inline().unwrap();
    start
}

/// The latest version of a secret named `name` within `scope` — `secret add`
/// with an existing (scope, name) makes a new version; this picks the newest by
/// creation time (latest-wins addressing = rotation).
pub fn latest_secret(space: &TribleSet, scope: Id, name: &str) -> Option<Id> {
    find!(
        (s: Id, t: IntervalValue),
        pattern!(space, [{ ?s @ metadata::tag: KIND_SECRET, secret_scope: scope, secret_name: name, metadata::created_at: ?t }])
    )
    .max_by_key(|(_, t)| interval_start(*t))
    .map(|(s, _)| s)
}

/// Count versions of a (scope, name) secret.
pub fn secret_versions(space: &TribleSet, scope: Id, name: &str) -> usize {
    find!(
        s: Id,
        pattern!(space, [{ ?s @ metadata::tag: KIND_SECRET, secret_scope: scope, secret_name: name }])
    )
    .count()
}

/// The identities currently holding a wrap on a given secret version.
pub fn wrap_holders(space: &TribleSet, secret_id: Id) -> Vec<Id> {
    let mut v: Vec<Id> = find!(
        (w: Id, r: Id),
        pattern!(space, [{ ?w @ metadata::tag: KIND_WRAP, wrap_secret: secret_id, wrap_recipient: ?r }])
    )
    .map(|(_, r)| r)
    .collect();
    v.sort();
    v.dedup();
    v
}

/// The creator (implicit root admin) of a rooted scope, if any.
pub fn scope_creator_of(space: &TribleSet, scope: Id) -> Option<Id> {
    find!(
        c: Id,
        pattern!(space, [{ scope @ metadata::tag: KIND_SCOPE, scope_creator: ?c }])
    )
    .next()
}

/// Effective admins of a scope: the least fixpoint seeded by the scope's
/// creator and grown through non-retracted admin-grants whose issuer is
/// *already* an effective admin. An unrooted scope (no creator) has none —
/// so none of its grants can be effective. This is the predecessor-only
/// validity rule made constructive (wiki D02D6767 / 65a1835b).
pub fn effective_admins(space: &TribleSet, scope: Id) -> HashSet<Id> {
    let mut admins = HashSet::new();
    match scope_creator_of(space, scope) {
        Some(creator) => {
            admins.insert(creator);
        }
        None => return admins,
    }
    let admin_grants: Vec<(Id, Id)> = find!(
        (g: Id, iss: Id, subj: Id),
        pattern!(space, [{ ?g @ metadata::tag: KIND_GRANT, grant_object: scope, grant_relation: "admin", grant_issuer: ?iss, grant_subject: ?subj }])
    )
    .filter(|(g, _, _)| grant_is_live(space, *g))
    .map(|(_, iss, subj)| (iss, subj))
    .collect();
    loop {
        let mut grew = false;
        for (iss, subj) in &admin_grants {
            if admins.contains(iss) && admins.insert(*subj) {
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    admins
}

/// A grant is *effective* iff it is not retracted AND its issuer is an
/// effective admin of its object. (Issuerless grants never match the
/// pattern, so they are inert.)
///
/// Recipients of a scope = identities transitively reachable through its live,
/// *effective* grants. A "group" is just a scope that is itself a grant subject
/// elsewhere; any id can be both object and subject, so membership nests with no
/// extra entity kind. We project effective grants into an ephemeral
/// object->subject edge set and let the engine's `path!` take the transitive
/// closure — the edge set is never persisted (work as its own ledger:
/// recipients are a derived view).
pub fn recipients_of(space: &TribleSet, scope: Id) -> Vec<Id> {
    let mut admin_cache: HashMap<Id, HashSet<Id>> = HashMap::new();
    let mut edges = TribleSet::new();
    for (g, obj, subj, iss) in find!(
        (g: Id, o: Id, s: Id, i: Id),
        pattern!(space, [{ ?g @ metadata::tag: KIND_GRANT, grant_object: ?o, grant_subject: ?s, grant_issuer: ?i }])
    ) {
        if !grant_is_live(space, g) {
            continue;
        }
        let admins = admin_cache
            .entry(obj)
            .or_insert_with(|| effective_admins(space, obj));
        if admins.contains(&iss) {
            edges += entity! { ExclusiveId::force_ref(&obj) @ reaches: &subj };
        }
    }
    let mut out: Vec<Id> = find!(
        (start: Id, leaf: Id),
        and!(start.is(scope.to_inline()), path!(edges, start reaches+ leaf))
    )
    .map(|(_, leaf)| leaf)
    // keep only identity leaves (intermediate groups carry no signing key)
    .filter(|l| {
        let lid = *l;
        exists!(pattern!(space, [{ lid @ identity_sign_pk: _?p }]))
    })
    .collect();
    // The root admin (creator) is always a recipient of her own scope, even
    // though she is never a grant *subject*.
    if let Some(creator) = scope_creator_of(space, scope) {
        out.push(creator);
    }
    out.sort();
    out.dedup();
    out
}

/// An entity's `metadata::name` (an identity's nickname, a scope's name), or
/// its short id if unnamed.
pub fn entity_name(ws: &mut Workspace<Pile>, space: &TribleSet, id: Id) -> String {
    find!(n: TextHandle, pattern!(space, [{ id @ metadata::name: ?n }]))
        .next()
        .and_then(|n| read_text(ws, n))
        .unwrap_or_else(|| fmt_id(id))
}

// ── open / seal (shared by get/rotate and add/rotate) ─────────────────────────

/// Decrypt the latest-resolved secret `secret_id` as identity `me`: unlock me,
/// unseal my wrap to the DEK, open the body. The single read/decrypt path
/// shared by `get` and `rotate`.
fn open_secret_value(
    pw: &[u8],
    ws: &mut Workspace<Pile>,
    space: &TribleSet,
    secret_id: Id,
    me: Id,
) -> Result<Vec<u8>> {
    let (lock_h, my_pk_h): (BytesHandle, BytesHandle) = find!(
        (l: BytesHandle, p: BytesHandle),
        pattern!(space, [{ me @ identity_lockbox: ?l, identity_sign_pk: ?p }])
    )
    .next()
    .ok_or_else(|| anyhow::anyhow!("identity {} not found", fmt_id(me)))?;
    let lockbox = read_bytes(ws, lock_h).context("read lockbox")?;
    let my_pk = read_bytes(ws, my_pk_h).context("read pk")?;
    let my_sk = unlock_secret_key(pw, &lockbox)?;
    let box_kp = box_keypair_from_ed25519(&my_sk, &my_pk)?;

    let dek_h: BytesHandle = find!(
        (w: Id, d: BytesHandle),
        pattern!(space, [{ ?w @ metadata::tag: KIND_WRAP, wrap_secret: secret_id, wrap_recipient: me, wrap_dek: ?d }])
    )
    .next()
    .map(|(_, d)| d)
    .ok_or_else(|| anyhow::anyhow!("no wrap for {} on this secret", fmt_id(me)))?;
    let sealed = read_bytes(ws, dek_h).context("read wrap")?;
    let dek_bytes = DryocBox::from_sealed_bytes(&sealed)
        .map_err(|e| anyhow::anyhow!("parse wrap: {e:?}"))?
        .unseal_to_vec(&box_kp)
        .map_err(|_| anyhow::anyhow!("unseal failed (wrong key?)"))?;
    let dek = Key::try_from(&dek_bytes[..]).context("dek")?;

    let body_h: BytesHandle = find!(
        h: BytesHandle,
        pattern!(space, [{ secret_id @ secret_body: ?h }])
    )
    .next()
    .ok_or_else(|| anyhow::anyhow!("secret body missing"))?;
    let body_blob = read_bytes(ws, body_h).context("read body")?;
    if body_blob.len() < 24 {
        bail!("malformed body");
    }
    let nonce = Nonce::try_from(&body_blob[..24]).context("nonce")?;
    DryocSecretBox::from_bytes(&body_blob[24..])
        .map_err(|e| anyhow::anyhow!("parse body: {e:?}"))?
        .decrypt_to_vec(&nonce, &dek)
        .map_err(|_| anyhow::anyhow!("decrypt failed"))
}

/// Build the trible change for a fresh secret version of `(scope, name)`:
/// a new DEK secretboxes the body, and the DEK is sealed to *every current*
/// recipient (so a member removed since the last version is excluded). Returns
/// (change, new secret id, recipient count). The single seal path shared by
/// `add` and `rotate`; the caller commits.
fn build_seal_change(
    ws: &mut Workspace<Pile>,
    space: &TribleSet,
    scope_id: Id,
    name: &str,
    plaintext: &[u8],
) -> Result<(TribleSet, Id, usize)> {
    let recipients = recipients_of(space, scope_id);
    if recipients.is_empty() {
        bail!("scope {} has no live recipients; grant access first", fmt_id(scope_id));
    }
    let mut recipient_keys: Vec<(Id, BoxPublicKey)> = Vec::new();
    for r in &recipients {
        let rid = *r;
        let pk_h: BytesHandle = find!(h: BytesHandle, pattern!(space, [{ rid @ identity_sign_pk: ?h }]))
            .next()
            .ok_or_else(|| anyhow::anyhow!("recipient {} has no signing key", fmt_id(*r)))?;
        let pk = read_bytes(ws, pk_h).ok_or_else(|| anyhow::anyhow!("read pk for {}", fmt_id(*r)))?;
        recipient_keys.push((*r, box_pk_from_ed25519(&pk)?));
    }

    let dek = Key::gen();
    let nonce = Nonce::gen();
    let body = DryocSecretBox::encrypt_to_vecbox(plaintext, &nonce, &dek).to_vec();
    let mut body_blob = Vec::with_capacity(nonce.len() + body.len());
    body_blob.extend_from_slice(&nonce);
    body_blob.extend_from_slice(&body);

    let secret_id = ufoid();
    let now = instant_interval(now_epoch());
    let body_h = put_bytes(ws, body_blob);
    let name_h = ws.put(name.to_string());
    let mut change = TribleSet::new();
    change += entity! { &secret_id @
        metadata::tag: &KIND_SECRET,
        metadata::created_at: now,
        metadata::name: name_h,
        secret_scope: &scope_id,
        secret_name: name,
        secret_body: body_h,
    };
    for (r, rx_pk) in &recipient_keys {
        let sealed = DryocBox::seal_to_vecbox(&dek, rx_pk)
            .map_err(|e| anyhow::anyhow!("seal to {}: {e:?}", fmt_id(*r)))?
            .to_vec();
        let dek_h = put_bytes(ws, sealed);
        let w = ufoid();
        change += entity! { &w @
            metadata::tag: &KIND_WRAP,
            metadata::created_at: now,
            wrap_secret: &secret_id.id,
            wrap_recipient: r,
            wrap_dek: dek_h,
        };
    }
    Ok((change, secret_id.id, recipient_keys.len()))
}

// ── the repo handle ───────────────────────────────────────────────────────────

/// Outcome of `identity_init`.
pub struct IdentityInit {
    pub id: Id,
    pub nickname: String,
    /// The Ed25519 signing public key.
    pub sign_pk: Vec<u8>,
}

/// A resolved identity row (`identity_list`).
pub struct IdentityRow {
    pub id: Id,
    pub nickname: String,
}

/// Outcome of `scope_create`.
pub struct ScopeCreated {
    pub id: Id,
    pub name: String,
    pub creator: Id,
}

/// A resolved scope row (`scope_list`), with a self-derivation check.
pub struct ScopeRow {
    pub id: Id,
    pub name: String,
    pub creator: Id,
    /// True iff the scope's id re-derives from its own `(creator, name)` facts.
    pub rooted: bool,
}

/// A resolved member of a scope (`scope_members`).
pub struct Member {
    pub id: Id,
    pub name: String,
    pub role: MemberRole,
}

/// The role a member holds within a scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberRole {
    RootAdmin,
    Admin,
    Member,
}

/// Outcome of `grant`.
pub struct GrantResult {
    pub grant_id: Id,
    pub object: Id,
    pub relation: String,
    pub subject: Id,
    pub issuer: Id,
}

/// Outcome of `secret_add`.
pub struct SecretAdded {
    pub secret_id: Id,
    pub name: String,
    pub recipients: usize,
}

/// A summary row for `secret_list` (grouped by scope+name, newest version).
pub struct SecretSummary {
    pub name: String,
    pub scope: Id,
    pub versions: usize,
    pub recipients: usize,
}

/// A credential still readable by a removed user (`rotate_worklist`).
pub struct Exposure {
    pub scope: Id,
    pub scope_name: String,
    pub name: String,
    /// Identity ids still holding a wrap on the current version but no longer
    /// current recipients.
    pub exposed: Vec<Id>,
}

/// A handle over a pile branch that performs the secrets capability operations.
///
/// Each mutating method is a full transaction: it opens the pile, ensures the
/// branch, pulls, checks out, mutates, commits, pushes, and closes — exactly
/// what the old `cmd_*` handlers did, minus the `println!`. Read queries take a
/// checked-out [`TribleSet`] the caller obtains via [`SecretsRepo::read`].
pub struct SecretsRepo {
    pile: std::path::PathBuf,
    branch: String,
}

impl SecretsRepo {
    /// Open a handle on `pile`'s `branch`. Does no I/O until a method runs.
    pub fn open(pile: impl Into<std::path::PathBuf>, branch: impl Into<String>) -> Self {
        Self { pile: pile.into(), branch: branch.into() }
    }

    /// Open a handle on `pile`'s default `secrets` branch.
    pub fn open_default(pile: impl Into<std::path::PathBuf>) -> Self {
        Self::open(pile, DEFAULT_BRANCH)
    }

    /// Run `f` against an open repository, closing the pile afterwards.
    fn with_repo<T>(&self, f: impl FnOnce(&mut Repository<Pile>) -> Result<T>) -> Result<T> {
        let mut repo = open_repo(&self.pile)?;
        let result = f(&mut repo);
        let close_res = repo.close().map_err(|e| anyhow::anyhow!("close pile: {e:?}"));
        if let Err(err) = close_res {
            if result.is_ok() {
                return Err(err);
            }
            eprintln!("warning: failed to close pile cleanly: {err:#}");
        }
        result
    }

    /// Checkout the branch's current space and run a read-only query against it.
    /// The closure also receives the workspace (needed to read blob handles for
    /// names/keys). This is the read counterpart to the mutating methods.
    pub fn read<T>(
        &self,
        f: impl FnOnce(&mut Workspace<Pile>, &TribleSet) -> Result<T>,
    ) -> Result<T> {
        self.with_repo(|repo| {
            let branch_id = repo
                .ensure_branch(&self.branch, None)
                .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
            let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
            let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
            f(&mut ws, &space)
        })
    }

    /// Create an identity: Ed25519 keypair, password-locked private key in the
    /// pile.
    pub fn identity_init(&self, pw: &[u8], nickname: &str) -> Result<IdentityInit> {
        let kp = SigningKeyPair::gen_with_defaults();
        let sign_pk = kp.public_key.to_vec();
        let lockbox = lock_secret_key(pw, &kp.secret_key);

        let id = self.with_repo(|repo| {
            let branch_id = repo
                .ensure_branch(&self.branch, None)
                .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
            let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
            let id = ufoid();
            let now = instant_interval(now_epoch());
            let nick_h = ws.put(nickname.to_string());
            let pk_h = put_bytes(&mut ws, sign_pk.clone());
            let lock_h = put_bytes(&mut ws, lockbox.clone());
            let mut change = TribleSet::new();
            change += entity! { &id @
                metadata::tag: &KIND_IDENTITY,
                metadata::created_at: now,
                metadata::name: nick_h,
                identity_sign_pk: pk_h,
                identity_lockbox: lock_h,
            };
            ws.commit(change, "secrets: identity init");
            repo.push(&mut ws).map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
            Ok(id.id)
        })?;
        Ok(IdentityInit { id, nickname: nickname.to_string(), sign_pk })
    }

    /// List identities `(id, nickname)`.
    pub fn identity_list(&self) -> Result<Vec<IdentityRow>> {
        self.read(|ws, space| {
            let rows: Vec<(Id, TextHandle)> = find!(
                (e: Id, n: TextHandle),
                pattern!(space, [{ ?e @ metadata::tag: KIND_IDENTITY, metadata::name: ?n }])
            )
            .collect();
            let mut out = Vec::new();
            for (e, n) in rows {
                out.push(IdentityRow { id: e, nickname: read_text(ws, n).unwrap_or_default() });
            }
            Ok(out)
        })
    }

    /// Create a scope rooted at identity `creator` (its implicit root admin).
    /// The scope id is content-derived from `(creator, name)`.
    pub fn scope_create(&self, name: &str, creator: Id) -> Result<ScopeCreated> {
        self.with_repo(|repo| {
            let branch_id = repo
                .ensure_branch(&self.branch, None)
                .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
            let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
            let now = instant_interval(now_epoch());
            let name_h = ws.put(name.to_string());

            // Intrinsic id from (creator, name); extra facts go under it.
            let mut change = scope_fragment(creator, name_h);
            let scope_id = change.root().expect("entity! derives a root id");
            change += entity! { ExclusiveId::force_ref(&scope_id) @
                metadata::tag: &KIND_SCOPE,
                metadata::created_at: now,
            };
            ws.commit(change, "secrets: scope create");
            repo.push(&mut ws).map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
            Ok(ScopeCreated { id: scope_id, name: name.to_string(), creator })
        })
    }

    /// List scopes with a self-derivation (`rooted`) check.
    pub fn scope_list(&self) -> Result<Vec<ScopeRow>> {
        self.read(|ws, space| {
            let rows: Vec<(Id, Id, TextHandle)> = find!(
                (s: Id, c: Id, n: TextHandle),
                pattern!(space, [{ ?s @ metadata::tag: KIND_SCOPE, scope_creator: ?c, metadata::name: ?n }])
            )
            .collect();
            let mut out = Vec::new();
            for (s, c, n) in rows {
                let name = read_text(ws, n).unwrap_or_default();
                // Self-validation: the id must derive from the scope's own
                // (creator, name) facts — the same intrinsic derivation used at
                // create time, so a forged id-vs-facts pairing shows as a mismatch.
                let rooted = scope_fragment(c, n).root() == Some(s);
                out.push(ScopeRow { id: s, name, creator: c, rooted });
            }
            Ok(out)
        })
    }

    /// The current members (recipients) of a scope, with their roles — the audit
    /// view. Uses a checked-out `space` and the workspace for names.
    pub fn scope_members(
        &self,
        space: &TribleSet,
        ws: &mut Workspace<Pile>,
        scope: Id,
    ) -> Vec<Member> {
        let creator = scope_creator_of(space, scope);
        let admins = effective_admins(space, scope);
        recipients_of(space, scope)
            .into_iter()
            .map(|r| {
                let name = entity_name(ws, space, r);
                let role = if creator == Some(r) {
                    MemberRole::RootAdmin
                } else if admins.contains(&r) {
                    MemberRole::Admin
                } else {
                    MemberRole::Member
                };
                Member { id: r, name, role }
            })
            .collect()
    }

    /// Grant a relation `(object, relation, subject)` issued by `issuer`. The
    /// issuer must be an effective admin of the object (for a fresh scope, its
    /// creator).
    pub fn grant(
        &self,
        object: Id,
        relation: &str,
        subject: Id,
        issuer: Id,
    ) -> Result<GrantResult> {
        self.with_repo(|repo| {
            let branch_id = repo
                .ensure_branch(&self.branch, None)
                .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
            let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
            let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;

            // The issuer must be an effective admin of the object — otherwise this
            // grant could never chain to the scope root and would be inert anyway.
            let admins = effective_admins(&space, object);
            if !admins.contains(&issuer) {
                if scope_creator_of(&space, object).is_none() {
                    bail!("scope {} is not rooted — run `scope create` first", fmt_id(object));
                }
                bail!(
                    "{} is not an effective admin of {}; only an admin can grant",
                    fmt_id(issuer),
                    fmt_id(object)
                );
            }

            let g = ufoid();
            let now = instant_interval(now_epoch());
            let mut change = TribleSet::new();
            change += entity! { &g @
                metadata::tag: &KIND_GRANT,
                metadata::created_at: now,
                grant_object: &object,
                grant_relation: relation,
                grant_subject: &subject,
                grant_issuer: &issuer,
            };
            ws.commit(change, "secrets: grant");
            repo.push(&mut ws).map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
            Ok(GrantResult {
                grant_id: g.id,
                object,
                relation: relation.to_string(),
                subject,
                issuer,
            })
        })
    }

    /// Revoke a subject's live grants on a scope (sets the retraction cursor).
    /// Returns the number of grants revoked. Errors if none are live.
    pub fn revoke(&self, object: Id, subject: Id) -> Result<usize> {
        self.with_repo(|repo| {
            let branch_id = repo
                .ensure_branch(&self.branch, None)
                .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
            let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
            let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
            let grants: Vec<Id> = find!(
                g: Id,
                pattern!(&space, [{ ?g @ metadata::tag: KIND_GRANT, grant_object: object, grant_subject: subject }])
            )
            .filter(|g| grant_is_live(&space, *g))
            .collect();
            if grants.is_empty() {
                bail!("no live grant for {} on {}", fmt_id(subject), fmt_id(object));
            }
            let now = instant_interval(now_epoch());
            let mut change = TribleSet::new();
            for g in &grants {
                change += entity! { ExclusiveId::force_ref(g) @ grant_retracted_at: now };
            }
            ws.commit(change, "secrets: revoke");
            repo.push(&mut ws).map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
            Ok(grants.len())
        })
    }

    /// Add a secret to a scope, sealed to every live recipient. An add of an
    /// existing `(scope, name)` makes a new version.
    pub fn secret_add(&self, scope: Id, name: &str, plaintext: &[u8]) -> Result<SecretAdded> {
        self.with_repo(|repo| {
            let branch_id = repo
                .ensure_branch(&self.branch, None)
                .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
            let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
            let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
            let (change, secret_id, n) = build_seal_change(&mut ws, &space, scope, name, plaintext)?;
            ws.commit(change, "secrets: secret add");
            repo.push(&mut ws).map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
            Ok(SecretAdded { secret_id, name: name.to_string(), recipients: n })
        })
    }

    /// Get the latest version of a named secret, decrypted as identity `me`
    /// (needs the identity password).
    pub fn secret_get(&self, pw: &[u8], scope: Id, name: &str, me: Id) -> Result<Vec<u8>> {
        self.with_repo(|repo| {
            let branch_id = repo
                .ensure_branch(&self.branch, None)
                .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
            let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
            let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
            let secret_id = latest_secret(&space, scope, name)
                .ok_or_else(|| anyhow::anyhow!("no secret named '{name}' in that scope"))?;
            open_secret_value(pw, &mut ws, &space, secret_id, me)
        })
    }

    /// Re-wrap a named secret's DEK to recipients added after it was created.
    /// Run as an existing recipient `me` (needs the password to unlock the DEK).
    /// Returns the number of newly-shared recipients (0 if already complete).
    pub fn secret_share(&self, pw: &[u8], scope: Id, name: &str, me: Id) -> Result<usize> {
        self.with_repo(|repo| {
            let branch_id = repo
                .ensure_branch(&self.branch, None)
                .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
            let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
            let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
            let secret_id = latest_secret(&space, scope, name)
                .ok_or_else(|| anyhow::anyhow!("no secret named '{name}' in that scope"))?;

            // Unlock my key and recover the DEK from my own wrap.
            let (lock_h, my_pk_h): (BytesHandle, BytesHandle) = find!(
                (l: BytesHandle, p: BytesHandle),
                pattern!(&space, [{ me @ identity_lockbox: ?l, identity_sign_pk: ?p }])
            )
            .next()
            .ok_or_else(|| anyhow::anyhow!("identity {} not found", fmt_id(me)))?;
            let lockbox = read_bytes(&mut ws, lock_h).context("read lockbox")?;
            let my_pk = read_bytes(&mut ws, my_pk_h).context("read pk")?;
            let my_sk = unlock_secret_key(pw, &lockbox)?;
            let box_kp = box_keypair_from_ed25519(&my_sk, &my_pk)?;

            let my_wrap_h: BytesHandle = find!(
                (w: Id, d: BytesHandle),
                pattern!(&space, [{ ?w @ metadata::tag: KIND_WRAP, wrap_secret: secret_id, wrap_recipient: me, wrap_dek: ?d }])
            )
            .next()
            .map(|(_, d)| d)
            .ok_or_else(|| anyhow::anyhow!("you ({}) are not a recipient of this secret", fmt_id(me)))?;
            let sealed = read_bytes(&mut ws, my_wrap_h).context("read wrap")?;
            let dek_bytes = DryocBox::from_sealed_bytes(&sealed)
                .map_err(|e| anyhow::anyhow!("parse wrap: {e:?}"))?
                .unseal_to_vec(&box_kp)
                .map_err(|_| anyhow::anyhow!("unseal failed (wrong key?)"))?;
            let dek = Key::try_from(&dek_bytes[..]).context("dek")?;

            // Current recipients minus those who already hold a wrap.
            let recipients = recipients_of(&space, scope);
            let existing: HashSet<Id> = find!(
                (w: Id, r: Id),
                pattern!(&space, [{ ?w @ metadata::tag: KIND_WRAP, wrap_secret: secret_id, wrap_recipient: ?r }])
            )
            .map(|(_, r)| r)
            .collect();
            let missing: Vec<Id> = recipients.into_iter().filter(|r| !existing.contains(r)).collect();
            if missing.is_empty() {
                return Ok(0);
            }

            let now = instant_interval(now_epoch());
            let mut change = TribleSet::new();
            for r in &missing {
                let rid = *r;
                let pk_h: BytesHandle = find!(h: BytesHandle, pattern!(&space, [{ rid @ identity_sign_pk: ?h }]))
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("recipient {} has no signing key", fmt_id(*r)))?;
                let pk = read_bytes(&mut ws, pk_h).ok_or_else(|| anyhow::anyhow!("read pk"))?;
                let rx_pk = box_pk_from_ed25519(&pk)?;
                let sealed = DryocBox::seal_to_vecbox(&dek, &rx_pk)
                    .map_err(|e| anyhow::anyhow!("seal to {}: {e:?}", fmt_id(*r)))?
                    .to_vec();
                let dek_h = put_bytes(&mut ws, sealed);
                let w = ufoid();
                change += entity! { &w @
                    metadata::tag: &KIND_WRAP,
                    metadata::created_at: now,
                    wrap_secret: &secret_id,
                    wrap_recipient: r,
                    wrap_dek: dek_h,
                };
            }
            ws.commit(change, "secrets: secret share");
            repo.push(&mut ws).map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
            Ok(missing.len())
        })
    }

    /// The rotate worklist: credentials whose current version is still wrapped to
    /// someone no longer a recipient. `filter` narrows to a single scope.
    /// Re-encrypting them here changes nothing (they keep their old wrap = the
    /// value); the fix is to change each credential at its source and
    /// `secret_add` the new value.
    pub fn rotate_worklist(&self, filter: Option<Id>) -> Result<Vec<Exposure>> {
        self.read(|ws, space| {
            // Unique (scope, name) credentials.
            let rows: Vec<(Id, TextHandle)> = find!(
                (sc: Id, n: TextHandle),
                pattern!(space, [{ _?s @ metadata::tag: KIND_SECRET, secret_scope: ?sc, metadata::name: ?n }])
            )
            .collect();
            let mut seen: HashSet<(Id, String)> = HashSet::new();
            let mut findings: Vec<Exposure> = Vec::new();
            for (sc, nh) in rows {
                if let Some(f) = filter {
                    if sc != f {
                        continue;
                    }
                }
                let name = match read_text(ws, nh) {
                    Some(n) => n,
                    None => continue,
                };
                if !seen.insert((sc, name.clone())) {
                    continue;
                }
                let latest = match latest_secret(space, sc, &name) {
                    Some(l) => l,
                    None => continue,
                };
                let current: HashSet<Id> = recipients_of(space, sc).into_iter().collect();
                let exposed: Vec<Id> = wrap_holders(space, latest)
                    .into_iter()
                    .filter(|h| !current.contains(h))
                    .collect();
                if !exposed.is_empty() {
                    let scope_name = entity_name(ws, space, sc);
                    findings.push(Exposure { scope: sc, scope_name, name, exposed });
                }
            }
            Ok(findings)
        })
    }

    /// List secrets grouped by (scope, name), newest version, with version count
    /// and current recipient count.
    pub fn secret_list(&self) -> Result<Vec<SecretSummary>> {
        self.read(|ws, space| {
            // Group versions by (scope, name); show the newest of each.
            let rows: Vec<(Id, Id, TextHandle)> = find!(
                (s: Id, sc: Id, n: TextHandle),
                pattern!(space, [{ ?s @ metadata::tag: KIND_SECRET, secret_scope: ?sc, metadata::name: ?n }])
            )
            .collect();
            let mut seen: HashSet<(Id, String)> = HashSet::new();
            let mut out = Vec::new();
            for (_s, sc, n) in rows {
                let name = read_text(ws, n).unwrap_or_default();
                if !seen.insert((sc, name.clone())) {
                    continue;
                }
                let versions = secret_versions(space, sc, &name);
                let recipients = recipients_of(space, sc).len();
                out.push(SecretSummary { name, scope: sc, versions, recipients });
            }
            Ok(out)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use triblespace::core::blob::IntoBlob;

    #[test]
    fn lockbox_roundtrips_and_rejects_wrong_password() {
        let kp = SigningKeyPair::gen_with_defaults();
        let sk = kp.secret_key.to_vec();
        let lb = lock_secret_key(b"correct horse", &sk);
        assert_eq!(unlock_secret_key(b"correct horse", &lb).unwrap(), sk);
        assert!(unlock_secret_key(b"wrong horse", &lb).is_err());
        // distinct salts => distinct lockboxes for the same key+password
        let lb2 = lock_secret_key(b"correct horse", &sk);
        assert_ne!(lb, lb2);
    }

    #[test]
    fn derived_x25519_pub_and_secret_agree() {
        // The subtlest bit: the X25519 public key derived from the Ed25519
        // *public* key must pair with the X25519 secret derived from the
        // Ed25519 *secret* key. Seal to the former, open with the latter.
        let kp = SigningKeyPair::gen_with_defaults();
        let pk = kp.public_key.to_vec();
        let sk = kp.secret_key.to_vec();
        let box_pk = box_pk_from_ed25519(&pk).unwrap();
        let box_kp = box_keypair_from_ed25519(&sk, &pk).unwrap();
        let msg = b"a 32-byte data key would go here";
        let sealed = DryocBox::seal_to_vecbox(&msg[..], &box_pk).unwrap().to_vec();
        let opened = DryocBox::from_sealed_bytes(&sealed)
            .unwrap()
            .unseal_to_vec(&box_kp)
            .unwrap();
        assert_eq!(opened.as_slice(), msg);
    }

    #[test]
    fn latest_secret_picks_newest_version() {
        let scope = ufoid().id;
        let mut space = TribleSet::new();
        let add_version = |space: &mut TribleSet, year: i32| -> Id {
            let s = ufoid().id;
            let t = instant_interval(Epoch::from_gregorian_utc(year, 1, 1, 0, 0, 0, 0));
            *space += entity! { ExclusiveId::force_ref(&s) @
                metadata::tag: &KIND_SECRET,
                secret_scope: &scope,
                secret_name: "db",
                metadata::created_at: t,
            };
            s
        };
        let _v1 = add_version(&mut space, 2020);
        let v2 = add_version(&mut space, 2025);
        let v3_older = add_version(&mut space, 2023);
        assert_eq!(latest_secret(&space, scope, "db"), Some(v2), "2025 is newest");
        assert_eq!(secret_versions(&space, scope, "db"), 3);
        assert_eq!(latest_secret(&space, scope, "absent"), None);
        let _ = v3_older;
    }

    // ── concurrent two-admin harness ─────────────────────────────────────────
    // triblespace merge is set-union, so a merged pile of two admins' diverged
    // branches is exactly the union of their tribles. We model "concurrent
    // branches, then merge" by building one TribleSet that contains BOTH
    // admins' ops, and ask the CURRENT model for its verdict. These reproduce
    // the cluster-G duelling-admin / backdating scenarios (wiki 65a1835b) to
    // show what the effective-admin fixpoint already defends against.
    fn mk_scope(space: &mut TribleSet, creator: &Id) -> Id {
        let s = ufoid().id;
        *space += entity! { ExclusiveId::force_ref(&s) @
            metadata::tag: &KIND_SCOPE, scope_creator: creator };
        s
    }
    fn mk_grant(space: &mut TribleSet, scope: &Id, iss: &Id, rel: &str, subj: &Id) -> Id {
        let g = ufoid().id;
        *space += entity! { ExclusiveId::force_ref(&g) @
            metadata::tag: &KIND_GRANT,
            grant_object: scope,
            grant_relation: rel,
            grant_issuer: iss,
            grant_subject: subj,
        };
        g
    }
    fn retract(space: &mut TribleSet, g: &Id) {
        *space += entity! { ExclusiveId::force_ref(g) @
            grant_retracted_at: instant_interval(now_epoch()) };
    }

    #[test]
    fn concurrent_confederate_add_is_defeated() {
        // alice (root) -> admin -> bob. Then, concurrently: alice REMOVES bob,
        // while bob (not yet seeing the removal) makes mallory an admin. After
        // merge, both ops are present. The removal must win: mallory's grant was
        // issued by bob, who is no longer an effective admin.
        let (alice, bob, mallory) = (ufoid().id, ufoid().id, ufoid().id);
        let mut space = TribleSet::new();
        let s = mk_scope(&mut space, &alice);
        let g_bob = mk_grant(&mut space, &s, &alice, "admin", &bob);
        // branch A: alice removes bob.  branch B: bob adds mallory.  (union)
        retract(&mut space, &g_bob);
        mk_grant(&mut space, &s, &bob, "admin", &mallory);

        let admins = effective_admins(&space, s);
        assert_eq!(admins.len(), 1);
        assert!(admins.contains(&alice));
        assert!(!admins.contains(&bob), "bob was removed");
        assert!(!admins.contains(&mallory), "confederate-add by a removed admin is inert");
    }

    #[test]
    fn concurrent_removal_cascades_through_delegated_admin() {
        // alice -> admin -> bob -> admin -> carol. Concurrently: alice removes
        // bob, while carol (whose admin came via bob) makes dave an admin. The
        // removal of bob must transitively void carol AND dave.
        let (alice, bob, carol, dave) = (ufoid().id, ufoid().id, ufoid().id, ufoid().id);
        let mut space = TribleSet::new();
        let s = mk_scope(&mut space, &alice);
        let g_bob = mk_grant(&mut space, &s, &alice, "admin", &bob);
        mk_grant(&mut space, &s, &bob, "admin", &carol);
        retract(&mut space, &g_bob); // alice removes bob
        mk_grant(&mut space, &s, &carol, "admin", &dave); // concurrent, by carol

        let admins = effective_admins(&space, s);
        assert_eq!(admins, HashSet::from([alice]));
    }

    #[test]
    fn root_is_unremovable_no_headless_group() {
        // Even if every admin grant is retracted, the content-derived creator
        // remains — there is no grant to retract for the root, so the group can
        // never become headless.
        let (alice, bob) = (ufoid().id, ufoid().id);
        let mut space = TribleSet::new();
        let s = mk_scope(&mut space, &alice);
        let g = mk_grant(&mut space, &s, &alice, "admin", &bob);
        retract(&mut space, &g);
        assert_eq!(effective_admins(&space, s), HashSet::from([alice]));
    }

    #[test]
    fn concurrent_independent_grants_both_apply() {
        // Two non-conflicting concurrent ops by the same effective admin both
        // survive the merge (convergence, no spurious loss).
        let (alice, bob, carol, dave) = (ufoid().id, ufoid().id, ufoid().id, ufoid().id);
        let mut space = TribleSet::new();
        let s = mk_scope(&mut space, &alice);
        mk_grant(&mut space, &s, &alice, "admin", &bob);
        mk_grant(&mut space, &s, &bob, "admin", &carol); // branch A
        mk_grant(&mut space, &s, &bob, "admin", &dave); // branch B
        assert_eq!(effective_admins(&space, s), HashSet::from([alice, bob, carol, dave]));
    }

    #[test]
    fn exposure_is_wrap_holders_minus_current_recipients() {
        // A secret version wrapped to {alice, bob}; bob later revoked. The
        // exposure set (what `secret rotate` reports) = wrap-holders not in the
        // current recipient set = {bob}. Adding a newer version wrapped only to
        // {alice} clears it (latest-version check).
        let (alice, bob) = (ufoid().id, ufoid().id);
        let secret_v1 = ufoid().id;
        let mut space = TribleSet::new();
        // wraps on v1 to both
        for r in [alice, bob] {
            let w = ufoid().id;
            space += entity! { ExclusiveId::force_ref(&w) @
                metadata::tag: &KIND_WRAP, wrap_secret: &secret_v1, wrap_recipient: &r };
        }
        let holders = wrap_holders(&space, secret_v1);
        assert_eq!(holders, {
            let mut v = vec![alice, bob];
            v.sort();
            v
        });
        // current recipients after bob's revocation = {alice}
        let current: HashSet<Id> = HashSet::from([alice]);
        let exposed: Vec<Id> = holders.into_iter().filter(|h| !current.contains(h)).collect();
        assert_eq!(exposed, vec![bob]);
    }

    #[test]
    fn or_set_redundant_grant_survives_one_retraction() {
        // bob is made admin by two independent grants; retracting one must not
        // remove him (OR-set semantics — authority survives on any live path).
        let (alice, bob) = (ufoid().id, ufoid().id);
        let mut space = TribleSet::new();
        let s = mk_scope(&mut space, &alice);
        let g1 = mk_grant(&mut space, &s, &alice, "admin", &bob);
        let _g2 = mk_grant(&mut space, &s, &alice, "admin", &bob);
        retract(&mut space, &g1);
        assert_eq!(effective_admins(&space, s), HashSet::from([alice, bob]));
    }

    #[test]
    fn effective_admins_fixpoint_and_transitive_removal() {
        // Pure TribleSet (no pile/blobs): exercises the validity fixpoint.
        let sid = ufoid().id;
        let (aid, bid, cid, did, eid) =
            (ufoid().id, ufoid().id, ufoid().id, ufoid().id, ufoid().id);
        let mut space = TribleSet::new();
        // scope rooted at alice
        space += entity! { ExclusiveId::force_ref(&sid) @
            metadata::tag: &KIND_SCOPE, scope_creator: &aid };
        let grant = |space: &mut TribleSet, iss: &Id, rel: &str, subj: &Id| -> Id {
            let g = ufoid().id;
            *space += entity! { ExclusiveId::force_ref(&g) @
                metadata::tag: &KIND_GRANT,
                grant_object: &sid,
                grant_relation: rel,
                grant_issuer: iss,
                grant_subject: subj,
            };
            g
        };
        let g_bob = grant(&mut space, &aid, "admin", &bid); // alice -> admin -> bob
        grant(&mut space, &bid, "admin", &cid); // bob -> admin -> carol (transitive)
        grant(&mut space, &did, "admin", &eid); // dave (not admin) -> eve (inert)

        let admins = effective_admins(&space, sid);
        assert!(admins.contains(&aid) && admins.contains(&bid) && admins.contains(&cid));
        assert!(!admins.contains(&eid), "dave isn't an admin, so eve must not be");
        assert!(!admins.contains(&did));

        // Transitive strong removal: retract bob's admin -> bob AND carol drop.
        space += entity! { ExclusiveId::force_ref(&g_bob) @
            grant_retracted_at: instant_interval(now_epoch()) };
        let admins2 = effective_admins(&space, sid);
        assert!(admins2.contains(&aid));
        assert!(!admins2.contains(&bid), "bob's admin was retracted");
        assert!(!admins2.contains(&cid), "carol's admin chained through bob -> gone");
        assert_eq!(admins2.len(), 1);
    }

    #[test]
    fn scope_id_derives_from_creator_and_name() {
        // The scope id is `entity!`'s intrinsic derivation over (creator, name):
        // idempotent in those facts, and changes when either changes.
        let a = ufoid().id;
        let b = ufoid().id;
        let id = |c: Id, name: &'static str| {
            scope_fragment(c, name.to_blob().get_handle()).root().unwrap()
        };
        assert_eq!(id(a, "prod"), id(a, "prod")); // idempotent creation
        assert_ne!(id(a, "prod"), id(b, "prod")); // creator-bound
        assert_ne!(id(a, "prod"), id(a, "staging")); // name-bound
    }

    #[test]
    fn envelope_seals_to_many_and_refuses_outsiders() {
        let alice = SigningKeyPair::gen_with_defaults();
        let bob = SigningKeyPair::gen_with_defaults();
        let carol = SigningKeyPair::gen_with_defaults();
        let recipients: Vec<BoxPublicKey> = [&alice, &bob]
            .iter()
            .map(|kp| box_pk_from_ed25519(&kp.public_key.to_vec()).unwrap())
            .collect();

        let secret = b"prod db password";
        let dek = Key::gen();
        let nonce = Nonce::gen();
        let body = DryocSecretBox::encrypt_to_vecbox(&secret[..], &nonce, &dek).to_vec();
        let wraps: Vec<Vec<u8>> = recipients
            .iter()
            .map(|pk| DryocBox::seal_to_vecbox(&dek, pk).unwrap().to_vec())
            .collect();

        // each intended recipient opens to the same plaintext
        for kp in [&alice, &bob] {
            let box_kp =
                box_keypair_from_ed25519(&kp.secret_key.to_vec(), &kp.public_key.to_vec()).unwrap();
            let dek_bytes = DryocBox::from_sealed_bytes(&wraps[0])
                .unwrap()
                .unseal_to_vec(&box_kp);
            // alice's keypair opens wraps[0]; bob's does not — verify per-wrap below
            let _ = dek_bytes;
        }
        let alice_kp =
            box_keypair_from_ed25519(&alice.secret_key.to_vec(), &alice.public_key.to_vec())
                .unwrap();
        let dek_bytes = DryocBox::from_sealed_bytes(&wraps[0])
            .unwrap()
            .unseal_to_vec(&alice_kp)
            .unwrap();
        let dek2 = Key::try_from(&dek_bytes[..]).unwrap();
        let opened = DryocSecretBox::from_bytes(&body)
            .unwrap()
            .decrypt_to_vec(&nonce, &dek2)
            .unwrap();
        assert_eq!(opened.as_slice(), secret);

        // carol (not a recipient) cannot open alice's wrap
        let carol_kp =
            box_keypair_from_ed25519(&carol.secret_key.to_vec(), &carol.public_key.to_vec())
                .unwrap();
        assert!(
            DryocBox::from_sealed_bytes(&wraps[0])
                .unwrap()
                .unseal_to_vec(&carol_kp)
                .is_err()
        );
    }
}
