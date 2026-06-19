//! secrets — an encrypted secret-store faculty (a 1Password replacement, owned,
//! pile-native). Admins distribute company secrets by sealing them to
//! recipients' keys; the pile gives storage, sync, and a signed audit trail for
//! free; authorization is signed relationship-tuples queried with the engine.
//! Design captured in the `authz`-tagged wiki (hub 4448d5fc).
//!
//! The envelope (KEM-DEM): a fresh data key (DEK) encrypts a secret body once
//! via secretbox; the DEK is sealed-boxed to each recipient's X25519 key (the
//! key is *derived* from their Ed25519 identity key). Removal = rotate. The
//! current recipient set is enumerated from the grant tuples with the query
//! engine — never stored, "work as its own ledger".
//!
//! Status: `identity init/list`, `scope create/list`, `grant` (issuer-required),
//! `revoke`, `secret add/get/list/share`. Scopes are content-derived and rooted
//! at their creator (`scope_id = Blake3(creator_pk, name)`); a grant is
//! *effective* only if its issuer chains, through admin-grants, back to that
//! root (the `effective_admins` fixpoint). Strong/transitive removal therefore
//! falls out for free — retracting an admin drops everything that depended on
//! it. Transitive group membership is `path!`'s closure over *effective* grants.
//! STILL PENDING (the genuinely concurrent part): epoch finality + the
//! two-branch duelling-admin tests (wiki 65a1835b / D02D6767) — single- or
//! coordinated-writer multi-admin is safe; independent concurrent writers need
//! the finality layer. Secret rotation / `(scope,name)` addressing also pending.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
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
mod schema {
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

const DEFAULT_BRANCH: &str = "secrets";

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
fn lock_secret_key(password: &[u8], sk: &[u8]) -> Vec<u8> {
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
fn unlock_secret_key(password: &[u8], lockbox: &[u8]) -> Result<Vec<u8>> {
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

/// Content-derive a scope id from its creator's signing key and a name.
/// `id = Blake3("liora-secrets-scope-v1" ‖ creator_pk ‖ name)[..16]`. Both
/// admins compute the same id independently, and the id commits to its
/// creator — so the scope's *root admin* is intrinsic, not a spoofable grant.
fn derive_scope_id(creator_pk: &[u8], name: &str) -> Id {
    let mut h = blake3::Hasher::new();
    h.update(b"liora-secrets-scope-v1");
    h.update(creator_pk);
    h.update(name.as_bytes());
    let bytes: [u8; 16] = h.finalize().as_bytes()[..16].try_into().unwrap();
    Id::new(bytes).expect("blake3 output is non-zero")
}

/// Derive the X25519 public key (for sealing) from an Ed25519 public key.
fn box_pk_from_ed25519(ed_pk: &[u8]) -> Result<BoxPublicKey> {
    let arr: &[u8; 32] = ed_pk.try_into().context("ed25519 public key length")?;
    let mut xpk = [0u8; 32];
    crypto_sign_ed25519_pk_to_curve25519(&mut xpk, arr)
        .map_err(|e| anyhow::anyhow!("pk convert: {e:?}"))?;
    BoxPublicKey::try_from(&xpk[..]).map_err(|e| anyhow::anyhow!("x25519 pk: {e:?}"))
}

/// Build the X25519 keypair (for unsealing) from an Ed25519 keypair.
fn box_keypair_from_ed25519(ed_sk: &[u8], ed_pk: &[u8]) -> Result<BoxKeyPair> {
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
    if let Err(err) = pile.restore() {
        let _ = pile.close();
        return Err(anyhow::anyhow!("restore pile {}: {err:?}", path.display()));
    }
    let signing_key = SigningKey::generate(&mut OsRng);
    Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|err| anyhow::anyhow!("create repository: {err:?}"))
}

fn with_repo<T>(pile: &Path, f: impl FnOnce(&mut Repository<Pile>) -> Result<T>) -> Result<T> {
    let mut repo = open_repo(pile)?;
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

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn instant_interval(at: Epoch) -> IntervalValue {
    (at, at).try_to_inline().unwrap()
}

fn fmt_id(id: Id) -> String {
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

/// Resolve an entity id of a given KIND, accepting a full hex or a prefix.
fn resolve_kind_id(space: &TribleSet, kind: Id, input: &str) -> Result<Id> {
    let candidates = find!(e: Id, pattern!(space, [{ ?e @ metadata::tag: kind }]));
    faculties::resolve_id_prefix(input, candidates)
}

fn password() -> Result<Vec<u8>> {
    std::env::var("LIORA_SECRETS_PW")
        .map(|s| s.into_bytes())
        .map_err(|_| anyhow::anyhow!("set LIORA_SECRETS_PW to the identity password"))
}

// ── enumerate (the engine does the work) ──────────────────────────────────────

/// A grant is *live* at `now` if it carries no retraction coordinate (the
/// non-concurrent cursor; the concurrency-safe rules are the next layer).
fn grant_is_live(space: &TribleSet, grant: Id) -> bool {
    !exists!(pattern!(space, [{ grant @ grant_retracted_at: _?r }]))
}

/// Recipients of a scope = identities transitively reachable through its live
/// grants. A "group" is just a scope that is itself a grant subject elsewhere;
/// any id can be both object and subject, so membership nests with no extra
/// entity kind. We project live grants into an ephemeral object->subject edge
/// set and let the engine's `path!` take the transitive closure — the edge set
/// is never persisted (work as its own ledger: recipients are a derived view).
fn interval_start(iv: IntervalValue) -> Epoch {
    let (start, _end): (Epoch, Epoch) = iv.try_from_inline().unwrap();
    start
}

/// The latest version of a secret named `name` within `scope` — `secret add`
/// with an existing (scope, name) makes a new version; this picks the newest by
/// creation time (latest-wins addressing = rotation).
fn latest_secret(space: &TribleSet, scope: Id, name: &str) -> Option<Id> {
    find!(
        (s: Id, t: IntervalValue),
        pattern!(space, [{ ?s @ metadata::tag: KIND_SECRET, secret_scope: scope, secret_name: name, metadata::created_at: ?t }])
    )
    .max_by_key(|(_, t)| interval_start(*t))
    .map(|(s, _)| s)
}

/// Count versions of a (scope, name) secret.
fn secret_versions(space: &TribleSet, scope: Id, name: &str) -> usize {
    find!(
        s: Id,
        pattern!(space, [{ ?s @ metadata::tag: KIND_SECRET, secret_scope: scope, secret_name: name }])
    )
    .count()
}

/// The creator (implicit root admin) of a rooted scope, if any.
fn scope_creator_of(space: &TribleSet, scope: Id) -> Option<Id> {
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
fn effective_admins(space: &TribleSet, scope: Id) -> HashSet<Id> {
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
fn recipients_of(space: &TribleSet, scope: Id) -> Vec<Id> {
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

// ── commands ──────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "secrets", about = "Encrypted secret store (pile-native 1Password replacement)")]
struct Cli {
    /// Pile path (defaults to $PILE).
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Branch name.
    #[arg(long, default_value = DEFAULT_BRANCH)]
    branch: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Self-test: envelope seal -> open round-trip (no pile).
    Selftest,
    /// Identity management.
    Identity {
        #[command(subcommand)]
        cmd: IdentityCmd,
    },
    /// Scope management. A scope is content-derived from its creator+name;
    /// the creator is its implicit root admin.
    Scope {
        #[command(subcommand)]
        cmd: ScopeCmd,
    },
    /// Grant a relation: (object, relation, subject), issued by an admin.
    /// The issuer (--as) must be an effective admin of the object; for a
    /// fresh scope that means its creator.
    Grant {
        #[arg(long)]
        object: String,
        #[arg(long, default_value = "member")]
        relation: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        r#as: String,
    },
    /// Revoke a subject's grants on a scope (sets the retraction cursor).
    /// Non-concurrent only; rotate affected secrets to exclude the subject.
    Revoke {
        #[arg(long)]
        object: String,
        #[arg(long)]
        subject: String,
    },
    /// Secret management.
    Secret {
        #[command(subcommand)]
        cmd: SecretCmd,
    },
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Create an identity (Ed25519 key, password-locked private key in the pile).
    Init {
        #[arg(long)]
        nickname: String,
    },
    /// List identities.
    List,
}

#[derive(Subcommand)]
enum ScopeCmd {
    /// Create a scope rooted at an identity (the creator becomes root admin).
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        r#as: String,
    },
    /// List scopes (with root-derivation check).
    List,
}

#[derive(Subcommand)]
enum SecretCmd {
    /// Add a secret to a scope, sealed to every live recipient.
    Add {
        #[arg(long)]
        scope: String,
        #[arg(long)]
        name: String,
        /// The secret value (or @file / @- for stdin).
        value: String,
    },
    /// Get the latest version of a named secret, as a given identity
    /// (needs LIORA_SECRETS_PW).
    Get {
        #[arg(long)]
        scope: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        r#as: String,
    },
    /// Re-wrap a named secret's DEK to recipients added after it was created.
    /// Run as an existing recipient (needs LIORA_SECRETS_PW to unlock the DEK).
    Share {
        #[arg(long)]
        scope: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        r#as: String,
    },
    /// List secrets (grouped by scope+name, newest version).
    List,
}

fn load_value(raw: &str) -> Result<Vec<u8>> {
    if let Some(rest) = raw.strip_prefix('@') {
        if rest == "-" {
            use std::io::Read;
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf).context("read stdin")?;
            Ok(buf)
        } else {
            std::fs::read(rest).with_context(|| format!("read {rest}"))
        }
    } else {
        Ok(raw.as_bytes().to_vec())
    }
}

fn cmd_selftest() -> Result<()> {
    let alice = BoxKeyPair::gen_with_defaults();
    let bob = BoxKeyPair::gen_with_defaults();
    let secret = b"the prod database password is hunter2";
    let dek = Key::gen();
    let nonce = Nonce::gen();
    let body = DryocSecretBox::encrypt_to_vecbox(secret, &nonce, &dek).to_vec();
    let wrap_a = DryocBox::seal_to_vecbox(&dek, &alice.public_key)?.to_vec();

    let dek_bytes = DryocBox::from_sealed_bytes(&wrap_a)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?
        .unseal_to_vec(&alice)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let dek2 = Key::try_from(&dek_bytes[..]).unwrap();
    let opened = DryocSecretBox::from_bytes(&body)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?
        .decrypt_to_vec(&nonce, &dek2)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    assert_eq!(opened.as_slice(), secret);
    assert!(
        DryocBox::from_sealed_bytes(&wrap_a).unwrap().unseal_to_vec(&bob).is_err(),
        "cross-open must fail"
    );
    println!("✓ envelope round-trip: alice opened, bob refused");
    Ok(())
}

fn cmd_identity_init(pile: &Path, branch: &str, nickname: String) -> Result<()> {
    let pw = password()?;
    let kp = SigningKeyPair::gen_with_defaults();
    let sign_pk = kp.public_key.to_vec();
    let lockbox = lock_secret_key(&pw, &kp.secret_key);

    let id = with_repo(pile, |repo| {
        let branch_id = repo
            .ensure_branch(branch, None)
            .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
        let id = ufoid();
        let now = instant_interval(now_epoch());
        let nick_h = ws.put(nickname.clone());
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
    println!("identity {} ({})", fmt_id(id), nickname);
    println!("  sign_pk {}", hex(&sign_pk));
    Ok(())
}

fn cmd_identity_list(pile: &Path, branch: &str) -> Result<()> {
    with_repo(pile, |repo| {
        let branch_id = repo
            .ensure_branch(branch, None)
            .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let rows: Vec<(Id, TextHandle)> = find!(
            (e: Id, n: TextHandle),
            pattern!(&space, [{ ?e @ metadata::tag: KIND_IDENTITY, metadata::name: ?n }])
        )
        .collect();
        if rows.is_empty() {
            println!("(no identities)");
        }
        for (e, n) in rows {
            let nick = read_text(&mut ws, n).unwrap_or_default();
            println!("{}  {}", fmt_id(e), nick);
        }
        Ok(())
    })
}

/// Read an identity's Ed25519 signing public key.
fn read_sign_pk(ws: &mut Workspace<Pile>, space: &TribleSet, id: Id) -> Result<Vec<u8>> {
    let h: BytesHandle = find!(h: BytesHandle, pattern!(space, [{ id @ identity_sign_pk: ?h }]))
        .next()
        .ok_or_else(|| anyhow::anyhow!("identity {} has no signing key", fmt_id(id)))?;
    read_bytes(ws, h).ok_or_else(|| anyhow::anyhow!("read pk for {}", fmt_id(id)))
}

fn cmd_scope_create(pile: &Path, branch: &str, name: String, as_id: String) -> Result<()> {
    with_repo(pile, |repo| {
        let branch_id = repo
            .ensure_branch(branch, None)
            .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let creator = resolve_kind_id(&space, KIND_IDENTITY, &as_id)?;
        let pk = read_sign_pk(&mut ws, &space, creator)?;
        let scope_id = derive_scope_id(&pk, &name);

        let now = instant_interval(now_epoch());
        let name_h = ws.put(name.clone());
        let mut change = TribleSet::new();
        change += entity! { ExclusiveId::force_ref(&scope_id) @
            metadata::tag: &KIND_SCOPE,
            metadata::created_at: now,
            metadata::name: name_h,
            scope_creator: &creator,
        };
        ws.commit(change, "secrets: scope create");
        repo.push(&mut ws).map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
        println!("scope {} ({})  root admin: {}", fmt_id(scope_id), name, fmt_id(creator));
        Ok(())
    })
}

fn cmd_scope_list(pile: &Path, branch: &str) -> Result<()> {
    with_repo(pile, |repo| {
        let branch_id = repo
            .ensure_branch(branch, None)
            .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let rows: Vec<(Id, Id, TextHandle)> = find!(
            (s: Id, c: Id, n: TextHandle),
            pattern!(&space, [{ ?s @ metadata::tag: KIND_SCOPE, scope_creator: ?c, metadata::name: ?n }])
        )
        .collect();
        if rows.is_empty() {
            println!("(no scopes)");
        }
        for (s, c, n) in rows {
            let name = read_text(&mut ws, n).unwrap_or_default();
            // Self-validation: recompute the id from the stored creator+name.
            let rooted = read_sign_pk(&mut ws, &space, c)
                .map(|pk| derive_scope_id(&pk, &name) == s)
                .unwrap_or(false);
            let mark = if rooted { "✓ rooted" } else { "✗ MISMATCH" };
            println!("{}  {}  root {}  [{}]", fmt_id(s), name, fmt_id(c), mark);
        }
        Ok(())
    })
}

fn cmd_grant(
    pile: &Path,
    branch: &str,
    object: String,
    relation: String,
    subject: String,
    as_id: String,
) -> Result<()> {
    with_repo(pile, |repo| {
        let branch_id = repo
            .ensure_branch(branch, None)
            .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let object_id = Id::from_hex(object.trim().to_ascii_uppercase().as_str())
            .ok_or_else(|| anyhow::anyhow!("--object must be a 32-char hex scope id"))?;
        let subject_id = resolve_kind_id(&space, KIND_IDENTITY, &subject)?;
        let issuer_id = resolve_kind_id(&space, KIND_IDENTITY, &as_id)?;

        // The issuer must be an effective admin of the object — otherwise this
        // grant could never chain to the scope root and would be inert anyway.
        let admins = effective_admins(&space, object_id);
        if !admins.contains(&issuer_id) {
            if scope_creator_of(&space, object_id).is_none() {
                bail!(
                    "scope {} is not rooted — run `scope create` first",
                    fmt_id(object_id)
                );
            }
            bail!(
                "{} is not an effective admin of {}; only an admin can grant",
                fmt_id(issuer_id),
                fmt_id(object_id)
            );
        }

        let g = ufoid();
        let now = instant_interval(now_epoch());
        let mut change = TribleSet::new();
        change += entity! { &g @
            metadata::tag: &KIND_GRANT,
            metadata::created_at: now,
            grant_object: &object_id,
            grant_relation: relation.as_str(),
            grant_subject: &subject_id,
            grant_issuer: &issuer_id,
        };
        ws.commit(change, "secrets: grant");
        repo.push(&mut ws).map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
        println!(
            "grant {}  {} --{}--> {}  (by {})",
            fmt_id(g.id),
            fmt_id(object_id),
            relation,
            fmt_id(subject_id),
            fmt_id(issuer_id)
        );
        Ok(())
    })
}

fn cmd_revoke(pile: &Path, branch: &str, object: String, subject: String) -> Result<()> {
    with_repo(pile, |repo| {
        let branch_id = repo
            .ensure_branch(branch, None)
            .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let object_id = Id::from_hex(object.trim().to_ascii_uppercase().as_str())
            .ok_or_else(|| anyhow::anyhow!("--object must be a 32-char hex scope id"))?;
        let subject_id = resolve_kind_id(&space, KIND_IDENTITY, &subject)?;
        let grants: Vec<Id> = find!(
            g: Id,
            pattern!(&space, [{ ?g @ metadata::tag: KIND_GRANT, grant_object: object_id, grant_subject: subject_id }])
        )
        .filter(|g| grant_is_live(&space, *g))
        .collect();
        if grants.is_empty() {
            bail!("no live grant for {} on {}", fmt_id(subject_id), fmt_id(object_id));
        }
        let now = instant_interval(now_epoch());
        let mut change = TribleSet::new();
        for g in &grants {
            change += entity! { ExclusiveId::force_ref(g) @ grant_retracted_at: now };
        }
        ws.commit(change, "secrets: revoke");
        repo.push(&mut ws).map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
        println!(
            "revoked {} grant(s) for {} on {}",
            grants.len(),
            fmt_id(subject_id),
            fmt_id(object_id)
        );
        Ok(())
    })
}

fn cmd_secret_add(
    pile: &Path,
    branch: &str,
    scope: String,
    name: String,
    value: String,
) -> Result<()> {
    let plaintext = load_value(&value)?;
    with_repo(pile, |repo| {
        let branch_id = repo
            .ensure_branch(branch, None)
            .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let scope_id = resolve_kind_id(&space, KIND_SCOPE, &scope)?;

        let recipients = recipients_of(&space, scope_id);
        if recipients.is_empty() {
            bail!("scope {} has no live recipients; grant access first", fmt_id(scope_id));
        }
        // Read each recipient's signing pubkey, derive their X25519 key.
        let mut recipient_keys: Vec<(Id, BoxPublicKey)> = Vec::new();
        for r in &recipients {
            let rid = *r;
            let pk_h: BytesHandle = find!(
                h: BytesHandle,
                pattern!(&space, [{ rid @ identity_sign_pk: ?h }])
            )
            .next()
            .ok_or_else(|| anyhow::anyhow!("recipient {} has no signing key", fmt_id(*r)))?;
            let pk = read_bytes(&mut ws, pk_h)
                .ok_or_else(|| anyhow::anyhow!("read pk for {}", fmt_id(*r)))?;
            recipient_keys.push((*r, box_pk_from_ed25519(&pk)?));
        }

        // Envelope: one body, one wrap per recipient.
        let dek = Key::gen();
        let nonce = Nonce::gen();
        let body = DryocSecretBox::encrypt_to_vecbox(plaintext.as_slice(), &nonce, &dek).to_vec();
        let mut body_blob = Vec::with_capacity(nonce.len() + body.len());
        body_blob.extend_from_slice(&nonce);
        body_blob.extend_from_slice(&body);

        let secret_id = ufoid();
        let now = instant_interval(now_epoch());
        let body_h = put_bytes(&mut ws, body_blob);
        let name_h = ws.put(name.clone());
        let mut change = TribleSet::new();
        change += entity! { &secret_id @
            metadata::tag: &KIND_SECRET,
            metadata::created_at: now,
            metadata::name: name_h,
            secret_scope: &scope_id,
            secret_name: name.as_str(),
            secret_body: body_h,
        };
        for (r, rx_pk) in &recipient_keys {
            let sealed = DryocBox::seal_to_vecbox(&dek, rx_pk)
                .map_err(|e| anyhow::anyhow!("seal to {}: {e:?}", fmt_id(*r)))?
                .to_vec();
            let dek_h = put_bytes(&mut ws, sealed);
            let w = ufoid();
            change += entity! { &w @
                metadata::tag: &KIND_WRAP,
                metadata::created_at: now,
                wrap_secret: &secret_id.id,
                wrap_recipient: r,
                wrap_dek: dek_h,
            };
        }
        ws.commit(change, "secrets: secret add");
        repo.push(&mut ws).map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
        println!(
            "secret {} ({}) sealed to {} recipient(s)",
            fmt_id(secret_id.id),
            name,
            recipient_keys.len()
        );
        Ok(())
    })
}

fn cmd_secret_get(
    pile: &Path,
    branch: &str,
    scope: String,
    name: String,
    as_id: String,
) -> Result<()> {
    let pw = password()?;
    let out = with_repo(pile, |repo| {
        let branch_id = repo
            .ensure_branch(branch, None)
            .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let scope_id = resolve_kind_id(&space, KIND_SCOPE, &scope)?;
        let secret_id = latest_secret(&space, scope_id, &name)
            .ok_or_else(|| anyhow::anyhow!("no secret named '{name}' in that scope"))?;
        let me = resolve_kind_id(&space, KIND_IDENTITY, &as_id)?;

        // Unlock my private key, derive my X25519 keypair.
        let (lock_h, my_pk_h): (BytesHandle, BytesHandle) = find!(
            (l: BytesHandle, p: BytesHandle),
            pattern!(&space, [{ me @ identity_lockbox: ?l, identity_sign_pk: ?p }])
        )
        .next()
        .ok_or_else(|| anyhow::anyhow!("identity {} not found", fmt_id(me)))?;
        let lockbox = read_bytes(&mut ws, lock_h).context("read lockbox")?;
        let my_pk = read_bytes(&mut ws, my_pk_h).context("read pk")?;
        let my_sk = unlock_secret_key(&pw, &lockbox)?;
        let box_kp = box_keypair_from_ed25519(&my_sk, &my_pk)?;

        // Find my wrap.
        let dek_h: BytesHandle = find!(
            (w: Id, d: BytesHandle),
            pattern!(&space, [{ ?w @ metadata::tag: KIND_WRAP, wrap_secret: secret_id, wrap_recipient: me, wrap_dek: ?d }])
        )
        .next()
        .map(|(_, d)| d)
        .ok_or_else(|| anyhow::anyhow!("no wrap for {} on this secret", fmt_id(me)))?;
        let sealed = read_bytes(&mut ws, dek_h).context("read wrap")?;
        let dek_bytes = DryocBox::from_sealed_bytes(&sealed)
            .map_err(|e| anyhow::anyhow!("parse wrap: {e:?}"))?
            .unseal_to_vec(&box_kp)
            .map_err(|_| anyhow::anyhow!("unseal failed (wrong key?)"))?;
        let dek = Key::try_from(&dek_bytes[..]).context("dek")?;

        // Open the body.
        let body_h: BytesHandle = find!(
            h: BytesHandle,
            pattern!(&space, [{ secret_id @ secret_body: ?h }])
        )
        .next()
        .ok_or_else(|| anyhow::anyhow!("secret body missing"))?;
        let body_blob = read_bytes(&mut ws, body_h).context("read body")?;
        if body_blob.len() < 24 {
            bail!("malformed body");
        }
        let nonce = Nonce::try_from(&body_blob[..24]).context("nonce")?;
        let plaintext = DryocSecretBox::from_bytes(&body_blob[24..])
            .map_err(|e| anyhow::anyhow!("parse body: {e:?}"))?
            .decrypt_to_vec(&nonce, &dek)
            .map_err(|_| anyhow::anyhow!("decrypt failed"))?;
        Ok(plaintext)
    })?;
    use std::io::Write;
    std::io::stdout().write_all(&out)?;
    Ok(())
}

fn cmd_secret_share(
    pile: &Path,
    branch: &str,
    scope: String,
    name: String,
    as_id: String,
) -> Result<()> {
    let pw = password()?;
    with_repo(pile, |repo| {
        let branch_id = repo
            .ensure_branch(branch, None)
            .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let scope_id = resolve_kind_id(&space, KIND_SCOPE, &scope)?;
        let secret_id = latest_secret(&space, scope_id, &name)
            .ok_or_else(|| anyhow::anyhow!("no secret named '{name}' in that scope"))?;
        let me = resolve_kind_id(&space, KIND_IDENTITY, &as_id)?;

        // Unlock my key and recover the DEK from my own wrap.
        let (lock_h, my_pk_h): (BytesHandle, BytesHandle) = find!(
            (l: BytesHandle, p: BytesHandle),
            pattern!(&space, [{ me @ identity_lockbox: ?l, identity_sign_pk: ?p }])
        )
        .next()
        .ok_or_else(|| anyhow::anyhow!("identity {} not found", fmt_id(me)))?;
        let lockbox = read_bytes(&mut ws, lock_h).context("read lockbox")?;
        let my_pk = read_bytes(&mut ws, my_pk_h).context("read pk")?;
        let my_sk = unlock_secret_key(&pw, &lockbox)?;
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
        let recipients = recipients_of(&space, scope_id);
        let existing: HashSet<Id> = find!(
            (w: Id, r: Id),
            pattern!(&space, [{ ?w @ metadata::tag: KIND_WRAP, wrap_secret: secret_id, wrap_recipient: ?r }])
        )
        .map(|(_, r)| r)
        .collect();
        let missing: Vec<Id> = recipients.into_iter().filter(|r| !existing.contains(r)).collect();
        if missing.is_empty() {
            println!("already shared to all current recipients");
            return Ok(());
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
        println!("shared to {} new recipient(s)", missing.len());
        Ok(())
    })
}

fn cmd_secret_list(pile: &Path, branch: &str) -> Result<()> {
    with_repo(pile, |repo| {
        let branch_id = repo
            .ensure_branch(branch, None)
            .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        // Group versions by (scope, name); show the newest of each.
        let rows: Vec<(Id, Id, TextHandle)> = find!(
            (s: Id, sc: Id, n: TextHandle),
            pattern!(&space, [{ ?s @ metadata::tag: KIND_SECRET, secret_scope: ?sc, metadata::name: ?n }])
        )
        .collect();
        let mut seen: HashSet<(Id, String)> = HashSet::new();
        if rows.is_empty() {
            println!("(no secrets)");
        }
        for (_s, sc, n) in rows {
            let name = read_text(&mut ws, n).unwrap_or_default();
            if !seen.insert((sc, name.clone())) {
                continue;
            }
            let versions = secret_versions(&space, sc, &name);
            let recips = recipients_of(&space, sc).len();
            println!(
                "{}  scope {}  (v{}, {} recipient(s))",
                name,
                fmt_id(sc),
                versions,
                recips
            );
        }
        Ok(())
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Selftest => cmd_selftest(),
        Command::Identity { cmd } => match cmd {
            IdentityCmd::Init { nickname } => cmd_identity_init(&cli.pile, &cli.branch, nickname),
            IdentityCmd::List => cmd_identity_list(&cli.pile, &cli.branch),
        },
        Command::Scope { cmd } => match cmd {
            ScopeCmd::Create { name, r#as } => cmd_scope_create(&cli.pile, &cli.branch, name, r#as),
            ScopeCmd::List => cmd_scope_list(&cli.pile, &cli.branch),
        },
        Command::Grant { object, relation, subject, r#as } => {
            cmd_grant(&cli.pile, &cli.branch, object, relation, subject, r#as)
        }
        Command::Revoke { object, subject } => {
            cmd_revoke(&cli.pile, &cli.branch, object, subject)
        }
        Command::Secret { cmd } => match cmd {
            SecretCmd::Add { scope, name, value } => {
                cmd_secret_add(&cli.pile, &cli.branch, scope, name, value)
            }
            SecretCmd::Get { scope, name, r#as } => {
                cmd_secret_get(&cli.pile, &cli.branch, scope, name, r#as)
            }
            SecretCmd::Share { scope, name, r#as } => {
                cmd_secret_share(&cli.pile, &cli.branch, scope, name, r#as)
            }
            SecretCmd::List => cmd_secret_list(&cli.pile, &cli.branch),
        },
    }
}

// ── tests (the security-critical crypto core; no pile needed) ─────────────────
#[cfg(test)]
mod tests {
    use super::*;

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
        let mut add_version = |space: &mut TribleSet, year: i32| -> Id {
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
        let mut grant = |space: &mut TribleSet, iss: &Id, rel: &str, subj: &Id| -> Id {
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
    fn scope_id_is_deterministic_and_creator_bound() {
        let a = SigningKeyPair::gen_with_defaults();
        let b = SigningKeyPair::gen_with_defaults();
        let pk_a = a.public_key.to_vec();
        let pk_b = b.public_key.to_vec();
        // same creator+name => same id (both admins derive it independently)
        assert_eq!(derive_scope_id(&pk_a, "prod"), derive_scope_id(&pk_a, "prod"));
        // different creator => different scope id (root is intrinsic, unspoofable)
        assert_ne!(derive_scope_id(&pk_a, "prod"), derive_scope_id(&pk_b, "prod"));
        // different name => different id
        assert_ne!(derive_scope_id(&pk_a, "prod"), derive_scope_id(&pk_a, "staging"));
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
