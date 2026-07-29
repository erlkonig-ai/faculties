//! Shared mail-account resolution over the **secrets** branch.
//!
//! A mail account = one `KIND_MAIL_ACCOUNT` entity on the secrets branch:
//! a cleartext `address` (the select/human key) plus a password-locked
//! `box` holding the server credentials + hosts/ports as JSON. The lock
//! is the exact envelope the secrets identity key uses — argon2id-derived
//! key + secretbox, `salt(16) ‖ nonce(24) ‖ secretbox(json)` — keyed on
//! `FACULTIES_SECRETS_PW`. Storing a machine credential this way (rather
//! than through the identity/scope/grant ceremony) is the right altitude:
//! it is the *operator's own* credential, unlocked by the same operator
//! with the same password, so the sharing/authz layer buys nothing.
//!
//! There is deliberately NO active-account pointer. Reading is total —
//! `mail fetch` and `orient` drain every configured mailbox — and only
//! sending pins one address, explicitly, because a `From:` header has to
//! be a single identity. Ambient latest-wins state is a single-writer
//! assumption, and this pile has several writers. This module is the
//! single place the crypto and the resolution live so `mail` (writer)
//! and `orient` (reader) can never drift.

use anyhow::{bail, Context, Result};
use dryoc::classic::crypto_pwhash::{crypto_pwhash, PasswordHashAlgorithm};
use dryoc::constants::{
    CRYPTO_PWHASH_MEMLIMIT_MODERATE, CRYPTO_PWHASH_OPSLIMIT_MODERATE, CRYPTO_PWHASH_SALTBYTES,
};
use dryoc::dryocsecretbox::{DryocSecretBox, Key, Nonce};
use dryoc::types::*;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::prelude::blobencodings::RawBytes;
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;

use crate::schemas::mail::{mail_account, KIND_MAIL_ACCOUNT};

type BytesHandle = Inline<Handle<RawBytes>>;
type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

/// The default display name on outgoing From when an account omits one.
pub const DEFAULT_FROM_NAME: &str = "Toby Trible";

/// The full, decrypted mail-account configuration. The `address` comes
/// from the cleartext entity attribute; the rest is the locked JSON body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailAccount {
    pub address: String,
    pub pass: String,
    pub from_name: String,
    pub pop3_host: String,
    pub pop3_port: u16,
    pub smtp_host: String,
    pub smtp_port: u16,
}

/// The JSON body that is password-locked into `mail_account::box`. The
/// address is stored cleartext on the entity, not here.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountBody {
    pass: String,
    from_name: String,
    pop3_host: String,
    pop3_port: u16,
    smtp_host: String,
    smtp_port: u16,
}

/// Read `FACULTIES_SECRETS_PW` — the password that locks/unlocks account
/// bodies (the same one the secrets faculty uses).
pub fn password() -> Result<Vec<u8>> {
    crate::secret_pw::read("unlock the stored mail account")
}

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

/// Password-lock a plaintext body: `salt(16) ‖ nonce(24) ‖ secretbox(body)`.
fn lock(password: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; CRYPTO_PWHASH_SALTBYTES];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt);
    let nonce = Nonce::gen();
    let ct = DryocSecretBox::encrypt_to_vecbox(plaintext, &nonce, &key).to_vec();
    let mut out = Vec::with_capacity(salt.len() + nonce.len() + ct.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Recover a plaintext body from a lockbox produced by [`lock`].
fn unlock(password: &[u8], lockbox: &[u8]) -> Result<Vec<u8>> {
    if lockbox.len() < CRYPTO_PWHASH_SALTBYTES + 24 {
        bail!("malformed mail-account box");
    }
    let salt = &lockbox[..CRYPTO_PWHASH_SALTBYTES];
    let nonce = Nonce::try_from(&lockbox[CRYPTO_PWHASH_SALTBYTES..CRYPTO_PWHASH_SALTBYTES + 24])
        .context("nonce")?;
    let ct = &lockbox[CRYPTO_PWHASH_SALTBYTES + 24..];
    let key = derive_key(password, salt);
    DryocSecretBox::from_bytes(ct)
        .map_err(|e| anyhow::anyhow!("parse mail-account box: {e:?}"))?
        .decrypt_to_vec(&nonce, &key)
        .map_err(|_| anyhow::anyhow!("wrong FACULTIES_SECRETS_PW (mail-account unlock failed)"))
}

/// Encode + password-lock a full account into the `box` bytes. The
/// address is returned separately (it is stored cleartext on the entity).
/// Shared by `mail account add` so the lockbox format is defined
/// once.
pub fn seal_account(pw: &[u8], account: &MailAccount) -> Result<Vec<u8>> {
    let body = AccountBody {
        pass: account.pass.clone(),
        from_name: account.from_name.clone(),
        pop3_host: account.pop3_host.clone(),
        pop3_port: account.pop3_port,
        smtp_host: account.smtp_host.clone(),
        smtp_port: account.smtp_port,
    };
    let json = serde_json::to_vec(&body).context("serialize account body")?;
    Ok(lock(pw, &json))
}

fn open_account(pw: &[u8], address: String, box_bytes: &[u8]) -> Result<MailAccount> {
    let json = unlock(pw, box_bytes)?;
    let body: AccountBody = serde_json::from_slice(&json).context("parse account body")?;
    Ok(MailAccount {
        address,
        pass: body.pass,
        from_name: body.from_name,
        pop3_host: body.pop3_host,
        pop3_port: body.pop3_port,
        smtp_host: body.smtp_host,
        smtp_port: body.smtp_port,
    })
}

/// Every stored account's cleartext address (no password needed) — the
/// list/select view. Sorted, deduped.
pub fn list_addresses(space: &TribleSet) -> Vec<String> {
    let mut out: Vec<String> = find!(
        (e: Id, a: String),
        pattern!(space, [{ ?e @ metadata::tag: KIND_MAIL_ACCOUNT, mail_account::address: ?a }])
    )
    .map(|(_, a)| a)
    .collect();
    out.sort();
    out.dedup();
    out
}

/// The `box` handle for a given account address, if the account exists.
fn box_handle_for(space: &TribleSet, address: &str) -> Option<BytesHandle> {
    find!(
        (e: Id, h: BytesHandle),
        pattern!(space, [{
            ?e @ metadata::tag: KIND_MAIL_ACCOUNT,
            mail_account::address: address,
            mail_account::r#box: ?h,
        }])
    )
    .next()
    .map(|(_, h)| h)
}

/// Resolve + decrypt one named account from an already-checked-out secrets
/// space.
///
/// This is the *pinned* path, for operations that must act as exactly one
/// identity — sending. Reading never picks; see [`resolve_all`].
pub fn resolve_one(
    ws: &mut Workspace<Pile>,
    space: &TribleSet,
    address: &str,
) -> Result<Option<MailAccount>> {
    let Some(h) = box_handle_for(space, address) else {
        return Ok(None);
    };
    let box_bytes = ws
        .get::<anybytes::Bytes, RawBytes>(h)
        .map_err(|e| anyhow::anyhow!("read mail-account box: {e:?}"))?
        .as_ref()
        .to_vec();
    let pw = password()?;
    Ok(Some(open_account(&pw, address.to_string(), &box_bytes)?))
}

/// Resolve + decrypt EVERY stored account.
///
/// # Why reading never picks one
///
/// There is deliberately no "active account". An active pointer is
/// latest-wins ambient state, which is a single-writer assumption inside a
/// pile that several zooids write concurrently — whoever ran `add` last
/// silently redirects everyone else's `fetch` and everyone else's `orient`
/// news. The failure is invisible: mail still arrives, just into the wrong
/// window, and nothing errors.
///
/// So reading is total (every configured mailbox is drained, which is what
/// a colony wants — each window keeps its own address and all of them are
/// seen) and only *sending* pins an identity, explicitly, because a
/// `From:` header genuinely has to be one address.
///
/// An account that cannot be unlocked is an error rather than a skip: a
/// silently-dropped mailbox reads exactly like an empty one.
pub fn resolve_all(ws: &mut Workspace<Pile>, space: &TribleSet) -> Result<Vec<MailAccount>> {
    let addresses = list_addresses(space);
    if addresses.is_empty() {
        return Ok(Vec::new());
    }
    let pw = password()?;
    let mut out = Vec::with_capacity(addresses.len());
    for address in addresses {
        let Some(h) = box_handle_for(space, &address) else {
            continue;
        };
        let box_bytes = ws
            .get::<anybytes::Bytes, RawBytes>(h)
            .map_err(|e| anyhow::anyhow!("read mail-account box for {address}: {e:?}"))?
            .as_ref()
            .to_vec();
        out.push(open_account(&pw, address, &box_bytes)?);
    }
    Ok(out)
}

/// Convenience for the readers (`mail`, `orient`): open the secrets branch
/// on an existing repo and decrypt every stored account.
///
/// Returns an empty vec when the branch is absent, so callers can fall back
/// to env config.
///
/// Uses `lookup_branch`, NOT `ensure_branch`: a reader must never create the
/// branch it is reading. `ensure_branch` is check-then-create with no
/// atomicity, so two zooids reading concurrently against a fresh pile could
/// each mint a different branch id for the same name — after which every
/// name-based lookup fails with `NameConflict`, permanently, while both
/// branches hold real data. A read path has no business risking that.
pub fn resolve_all_on_repo(
    repo: &mut Repository<Pile>,
    secrets_branch: &str,
) -> Result<Vec<MailAccount>> {
    let branch_id = match repo.lookup_branch(secrets_branch) {
        Ok(Some(id)) => id,
        Ok(None) => return Ok(Vec::new()),
        Err(_) => return Ok(Vec::new()),
    };
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow::anyhow!("pull secrets: {e:?}"))?;
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow::anyhow!("checkout secrets: {e:?}"))?;
    resolve_all(&mut ws, &space)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MailAccount {
        MailAccount {
            address: "toby@trible.space".into(),
            pass: "hunter2".into(),
            from_name: "Toby Trible".into(),
            pop3_host: "pop.migadu.com".into(),
            pop3_port: 995,
            smtp_host: "smtp.migadu.com".into(),
            smtp_port: 465,
        }
    }

    #[test]
    fn seal_open_roundtrips_and_rejects_wrong_password() {
        let acct = sample();
        let sealed = seal_account(b"correct horse", &acct).unwrap();
        let opened = open_account(b"correct horse", acct.address.clone(), &sealed).unwrap();
        assert_eq!(opened, acct);
        assert!(open_account(b"wrong horse", acct.address.clone(), &sealed).is_err());
        // distinct salts => distinct boxes for the same account+password
        let sealed2 = seal_account(b"correct horse", &acct).unwrap();
        assert_ne!(sealed, sealed2);
    }

    #[test]
    fn list_addresses_sorts_and_dedups() {
        let mut space = TribleSet::new();
        for addr in ["b@x.com", "a@x.com", "b@x.com"] {
            let e = ufoid().id;
            space += entity! { ExclusiveId::force_ref(&e) @
                metadata::tag: &KIND_MAIL_ACCOUNT,
                mail_account::address: addr,
            };
        }
        assert_eq!(list_addresses(&space), vec!["a@x.com", "b@x.com"]);
    }
}
