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
//! Status: MVP slice. `identity init/list`, `grant`, `secret add/get/list`,
//! non-concurrent retraction. The concurrency-safe correctness layer
//! (strong-removal + predecessor-validity + epoch finality, wiki 65a1835b) is
//! NOT yet wired — do not run multi-admin removal flows against this until it is.

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
    }

    pub const KIND_IDENTITY: Id = id_hex!("0B870F06D1B502EBE1259C90234E8BA2");
    pub const KIND_GRANT: Id = id_hex!("BB95E8D2D7DC644B39396A1B6C10ECC6");
    pub const KIND_SECRET: Id = id_hex!("72B64C9F3644B8016B64820D7F3F23C1");
    pub const KIND_WRAP: Id = id_hex!("EB8549BAF679C5D11ECEDB416AAD76E3");
}

use schema::{
    KIND_GRANT, KIND_IDENTITY, KIND_SECRET, KIND_WRAP, grant_object, grant_relation,
    grant_retracted_at, grant_subject, identity_lockbox, identity_sign_pk, secret_body, secret_name,
    secret_scope, wrap_dek, wrap_recipient, wrap_secret,
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

/// Recipients of a scope = subjects of its live grants. One hop for the MVP;
/// transitive group nesting via `path!` is the next increment.
fn recipients_of(space: &TribleSet, scope: Id) -> Vec<Id> {
    let mut out: Vec<Id> = find!(
        (g: Id, subj: Id),
        pattern!(space, [{ ?g @ metadata::tag: KIND_GRANT, grant_object: scope, grant_subject: ?subj }])
    )
    .filter(|(g, _)| grant_is_live(space, *g))
    .map(|(_, subj)| subj)
    .collect();
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
    /// Grant a relation: (object, relation, subject).
    Grant {
        #[arg(long)]
        object: String,
        #[arg(long, default_value = "member")]
        relation: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        issuer: Option<String>,
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
    /// Get a secret as a given identity (needs LIORA_SECRETS_PW).
    Get {
        secret: String,
        #[arg(long)]
        r#as: String,
    },
    /// List secrets.
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

fn cmd_grant(
    pile: &Path,
    branch: &str,
    object: String,
    relation: String,
    subject: String,
    issuer: Option<String>,
) -> Result<()> {
    with_repo(pile, |repo| {
        let branch_id = repo
            .ensure_branch(branch, None)
            .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        // object is a free scope id (any 32-char hex); subject/issuer are identities.
        let object_id = Id::from_hex(object.trim().to_ascii_uppercase().as_str())
            .ok_or_else(|| anyhow::anyhow!("--object must be a 32-char hex scope id"))?;
        let subject_id = resolve_kind_id(&space, KIND_IDENTITY, &subject)?;
        let issuer_id = issuer
            .as_deref()
            .map(|i| resolve_kind_id(&space, KIND_IDENTITY, i))
            .transpose()?;

        let g = ufoid();
        let now = instant_interval(now_epoch());
        let mut change = TribleSet::new();
        change += entity! { &g @
            metadata::tag: &KIND_GRANT,
            metadata::created_at: now,
            grant_object: &object_id,
            grant_relation: relation.as_str(),
            grant_subject: &subject_id,
            schema::grant_issuer?: issuer_id.as_ref(),
        };
        ws.commit(change, "secrets: grant");
        repo.push(&mut ws).map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
        println!(
            "grant {}  {} --{}--> {}",
            fmt_id(g.id),
            fmt_id(object_id),
            relation,
            fmt_id(subject_id)
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
        let scope_id = Id::from_hex(scope.trim().to_ascii_uppercase().as_str())
            .ok_or_else(|| anyhow::anyhow!("--scope must be a 32-char hex scope id"))?;

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
        let mut change = TribleSet::new();
        change += entity! { &secret_id @
            metadata::tag: &KIND_SECRET,
            metadata::created_at: now,
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

fn cmd_secret_get(pile: &Path, branch: &str, secret: String, as_id: String) -> Result<()> {
    let pw = password()?;
    let out = with_repo(pile, |repo| {
        let branch_id = repo
            .ensure_branch(branch, None)
            .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let secret_id = resolve_kind_id(&space, KIND_SECRET, &secret)?;
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

fn cmd_secret_list(pile: &Path, branch: &str) -> Result<()> {
    with_repo(pile, |repo| {
        let branch_id = repo
            .ensure_branch(branch, None)
            .map_err(|e| anyhow::anyhow!("ensure branch: {e:?}"))?;
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let rows: Vec<(Id, Id)> = find!(
            (s: Id, sc: Id),
            pattern!(&space, [{ ?s @ metadata::tag: KIND_SECRET, secret_scope: ?sc }])
        )
        .collect();
        if rows.is_empty() {
            println!("(no secrets)");
        }
        for (s, sc) in rows {
            let n = recipients_of(&space, sc).len();
            println!("{}  scope {}  ({} recipient(s))", fmt_id(s), fmt_id(sc), n);
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
        Command::Grant { object, relation, subject, issuer } => {
            cmd_grant(&cli.pile, &cli.branch, object, relation, subject, issuer)
        }
        Command::Revoke { object, subject } => {
            cmd_revoke(&cli.pile, &cli.branch, object, subject)
        }
        Command::Secret { cmd } => match cmd {
            SecretCmd::Add { scope, name, value } => {
                cmd_secret_add(&cli.pile, &cli.branch, scope, name, value)
            }
            SecretCmd::Get { secret, r#as } => {
                cmd_secret_get(&cli.pile, &cli.branch, secret, r#as)
            }
            SecretCmd::List => cmd_secret_list(&cli.pile, &cli.branch),
        },
    }
}
