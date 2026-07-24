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
//! The active account is named by a latest-wins `KIND_MAIL_ACTIVE`
//! pointer (`mail_account::address`). This module is the single place the
//! crypto and the resolution live so `secrets` (writer), `mail`, and
//! `orient` (readers) can never drift.

use anyhow::{Context, Result, bail};
use dryoc::classic::crypto_pwhash::{PasswordHashAlgorithm, crypto_pwhash};
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

use crate::schemas::mail::{KIND_MAIL_ACCOUNT, KIND_MAIL_ACTIVE, mail_account};

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
    std::env::var("FACULTIES_SECRETS_PW")
        .map(|s| s.into_bytes())
        .map_err(|_| {
            anyhow::anyhow!("set FACULTIES_SECRETS_PW to unlock the stored mail account")
        })
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
/// Shared by `secrets mail-account add` so the lockbox format is defined
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

fn interval_start(iv: IntervalValue) -> i128 {
    let (start, _): (i128, i128) = iv.try_from_inline().unwrap();
    start
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

/// The address named by the newest active-pointer, if any (no password
/// needed). If no pointer was ever set but exactly one account exists,
/// that account is implicitly active — a single-account setup needs no
/// explicit `use`.
pub fn active_address(space: &TribleSet) -> Option<String> {
    let newest = find!(
        (e: Id, a: String, t: IntervalValue),
        pattern!(space, [{
            ?e @ metadata::tag: KIND_MAIL_ACTIVE,
            mail_account::address: ?a,
            metadata::created_at: ?t,
        }])
    )
    .max_by_key(|(_, _, t)| interval_start(*t))
    .map(|(_, a, _)| a);
    if newest.is_some() {
        return newest;
    }
    let all = list_addresses(space);
    if all.len() == 1 { all.into_iter().next() } else { None }
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

/// Resolve + decrypt the active account from an already-checked-out
/// secrets space. Returns `Ok(None)` when no account is configured (so
/// callers can fall back to env vars), `Err` only when an account IS
/// configured but can't be unlocked (wrong/missing password) — a real
/// misconfiguration the operator should see, not a silent env fallback.
pub fn resolve_active(
    ws: &mut Workspace<Pile>,
    space: &TribleSet,
) -> Result<Option<MailAccount>> {
    let Some(address) = active_address(space) else {
        return Ok(None);
    };
    let Some(h) = box_handle_for(space, &address) else {
        // Active pointer names an address with no stored account — treat
        // as unconfigured rather than erroring the whole faculty.
        return Ok(None);
    };
    let box_bytes = ws
        .get::<anybytes::Bytes, RawBytes>(h)
        .map_err(|e| anyhow::anyhow!("read mail-account box: {e:?}"))?
        .as_ref()
        .to_vec();
    let pw = password()?;
    Ok(Some(open_account(&pw, address, &box_bytes)?))
}

/// Convenience for the readers (`mail`, `orient`): open the secrets branch
/// on an existing repo, resolve the active account. `secrets_branch` names
/// the branch (default "secrets"). Returns `Ok(None)` if the branch/pointer
/// is absent so the caller can fall back to env config.
pub fn resolve_active_on_repo(
    repo: &mut Repository<Pile>,
    secrets_branch: &str,
) -> Result<Option<MailAccount>> {
    let branch_id = match repo.ensure_branch(secrets_branch, None) {
        Ok(id) => id,
        Err(_) => return Ok(None),
    };
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow::anyhow!("pull secrets: {e:?}"))?;
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow::anyhow!("checkout secrets: {e:?}"))?;
    resolve_active(&mut ws, &space)
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
    fn active_falls_back_to_the_single_account() {
        // No explicit pointer, exactly one account => that one is active.
        let e = ufoid().id;
        let mut space = TribleSet::new();
        space += entity! { ExclusiveId::force_ref(&e) @
            metadata::tag: &KIND_MAIL_ACCOUNT,
            mail_account::address: "solo@example.com",
        };
        assert_eq!(active_address(&space).as_deref(), Some("solo@example.com"));
    }

    #[test]
    fn explicit_pointer_selects_among_many_latest_wins() {
        let (a, b) = (ufoid().id, ufoid().id);
        let mut space = TribleSet::new();
        for (e, addr) in [(a, "a@x.com"), (b, "b@x.com")] {
            space += entity! { ExclusiveId::force_ref(&e) @
                metadata::tag: &KIND_MAIL_ACCOUNT,
                mail_account::address: addr,
            };
        }
        // Two accounts, no pointer => ambiguous, none active.
        assert_eq!(active_address(&space), None);
        // Older pointer -> a, newer pointer -> b: newest wins.
        let older = ufoid().id;
        let newer = ufoid().id;
        let t_old: IntervalValue = {
            let e = hifitime::Epoch::from_gregorian_utc(2026, 1, 1, 0, 0, 0, 0);
            (e, e).try_to_inline().unwrap()
        };
        let t_new: IntervalValue = {
            let e = hifitime::Epoch::from_gregorian_utc(2026, 6, 1, 0, 0, 0, 0);
            (e, e).try_to_inline().unwrap()
        };
        space += entity! { ExclusiveId::force_ref(&older) @
            metadata::tag: &KIND_MAIL_ACTIVE,
            mail_account::address: "a@x.com",
            metadata::created_at: t_old,
        };
        space += entity! { ExclusiveId::force_ref(&newer) @
            metadata::tag: &KIND_MAIL_ACTIVE,
            mail_account::address: "b@x.com",
            metadata::created_at: t_new,
        };
        assert_eq!(active_address(&space).as_deref(), Some("b@x.com"));
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
