//! Recover the Mail account the Secrets cutover deliberately retired.
//!
//! Before the collection cutover a mail account was one record on the legacy
//! `secrets` branch: a cleartext address plus a password-locked `box` holding
//! the mailbox password and the hosts and ports to reach it. `secrets_cutover`
//! validates that record exactly and then retires it — it is bounded evidence,
//! not Secrets authority, so neither its facts nor its envelope enter the
//! native Secrets collection. The cutover note says live configuration would
//! restart from a Mail account record naming an encrypted Secrets version.
//!
//! Nothing built that restart, and it is the same gap Teams had. On a migrated
//! pile `mail account list` is empty and `mail fetch` does nothing, while the
//! only copy of the mailbox password sits sealed on the legacy branch.
//!
//! This is the bridge, and like [`crate::teams_credentials`] it is deliberately
//! **not** a pile writer. Publishing the recovered credential means sealing it
//! to a Secrets scope and authoring a Mail account, which `mail account set`
//! already does under an operator's authority. So this reads the frozen legacy
//! branch, reports what survives, and on request unlocks the envelope and
//! materializes the mailbox password into a `0600` file, alongside the
//! non-secret settings the operator must pass back on the command line.
//!
//! The one difference from the Teams recovery is that the legacy rows here are
//! *not* plaintext: the envelope is argon2id + secretbox keyed on the same root
//! password the Secrets store uses, so exporting needs that password. Reporting
//! does not.
//!
//! It opens the pile read-only, appends nothing, and prints no secret.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use dryoc::classic::crypto_pwhash::{crypto_pwhash, PasswordHashAlgorithm};
use dryoc::constants::{
    CRYPTO_PWHASH_MEMLIMIT_MODERATE, CRYPTO_PWHASH_OPSLIMIT_MODERATE, CRYPTO_PWHASH_SALTBYTES,
};
use dryoc::dryocsecretbox::{DryocSecretBox, Key, Nonce};
use hifitime::Epoch;
use triblespace::core::metadata;
use triblespace::macros::{attributes, id_hex};
use triblespace::prelude::blobencodings::RawBytes;
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval, ShortString};
use triblespace::prelude::*;

use crate::collection_cutover::{freeze_source, FrozenSource};
use faculties::secrets::schema::LEGACY_BRANCH_NAME;

/// The retired Mail vocabulary, repeated here rather than imported so the
/// recovery path stays readable next to `secrets_cutover`'s own copy.
mod legacy {
    use super::*;

    attributes! {
        "7F0AE7B9E5D59E9DF7EB539AD75CEE6D" unsafe as pub address: ShortString;
        "7C878C936BCF83E1905C8FB58DEC29ED" unsafe as pub r#box: Handle<RawBytes>;
    }

    pub const KIND_ACCOUNT: Id = id_hex!("BC1F0E3D5DB2DC2AD00AE42FCF3AD495");
    pub const KIND_ACTIVE: Id = id_hex!("792EC015AB18E82DBB001A30B4CA2C0A");
}

/// The exact envelope the legacy `faculties::mail_account` wrote:
/// `salt(16) ‖ nonce(24) ‖ secretbox(json)`, keyed by an argon2id derivation of
/// the root password at libsodium's MODERATE limits. Repeated here because the
/// module that wrote it was deleted by the cutover, and a recovery path must
/// keep reading bytes its writer no longer exists to explain.
const SALT: usize = CRYPTO_PWHASH_SALTBYTES;
const NONCE: usize = 24;

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
    .map_err(|error| anyhow!("derive retired Mail envelope key: {error:?}"))
    .expect("argon2id over a in-memory buffer cannot fail");
    Key::try_from(&out[..]).expect("32-byte key")
}

fn unlock(password: &[u8], envelope: &[u8]) -> Result<Vec<u8>> {
    if envelope.len() < SALT + NONCE {
        bail!("retired Mail envelope is shorter than its cryptographic framing");
    }
    let key = derive_key(password, &envelope[..SALT]);
    let nonce = Nonce::try_from(&envelope[SALT..SALT + NONCE]).context("envelope nonce")?;
    DryocSecretBox::from_bytes(&envelope[SALT + NONCE..])
        .map_err(|error| anyhow!("parse retired Mail envelope: {error:?}"))?
        .decrypt_to_vec(&nonce, &key)
        .map_err(|_| {
            anyhow!(
                "wrong root password: the retired Mail envelope did not open. It is locked with \
                 the same FACULTIES_SECRETS_PW the Secrets store uses."
            )
        })
}

/// The JSON the envelope holds. The address is not in here: it is the
/// cleartext select key on the entity.
#[derive(serde::Deserialize)]
struct AccountBody {
    pass: String,
    from_name: String,
    pop3_host: String,
    pop3_port: u16,
    smtp_host: String,
    smtp_port: u16,
}

/// The mailbox password, held for export and never rendered.
///
/// `Debug` is implemented by hand: a derived one would put a live mailbox
/// password into any log line, backtrace, or panic message that touched a
/// recovered account.
#[derive(Clone)]
struct SecretMaterial(String);

impl std::fmt::Debug for SecretMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretMaterial(…)")
    }
}

/// One surviving retired account record, still sealed.
#[derive(Clone, Debug)]
pub struct LegacyAccount {
    pub entity: Id,
    pub created_at: Option<Epoch>,
    /// Cleartext select key, stored beside the envelope rather than in it.
    pub address: String,
    /// Content handle of the sealed envelope, for provenance.
    pub envelope_handle: String,
    /// Sealed envelope length. Nothing about it is readable without the
    /// password, so its size is safe to print and is the only shape there is.
    pub envelope_len: Option<usize>,
    envelope: Option<Vec<u8>>,
}

impl LegacyAccount {
    /// Whether the pile can still read this record's envelope.
    pub fn is_recoverable(&self) -> bool {
        self.envelope.is_some()
    }
}

/// Everything a run needs to decide what to do, with no secret in it.
#[derive(Clone, Debug, Default)]
pub struct MailCredentialReport {
    /// Legacy branch was absent (nothing to recover from).
    pub legacy_branch_missing: bool,
    /// Verified authored commits on the legacy Secrets branch.
    pub authored_commits: usize,
    /// Retired account records, newest first.
    pub accounts: Vec<LegacyAccount>,
    /// Address named by the newest active pointer, when one was ever set.
    pub active_address: Option<String>,
    /// Envelopes an account record names but the pile can no longer read.
    pub unreadable_envelopes: usize,
}

impl MailCredentialReport {
    /// The account to recover: the newest readable record for the active
    /// address, or simply the newest readable record when no pointer was set.
    pub fn selected(&self) -> Option<&LegacyAccount> {
        let recoverable = || self.accounts.iter().filter(|row| row.is_recoverable());
        match self.active_address.as_deref() {
            Some(active) => recoverable()
                .find(|row| row.address == active)
                .or_else(|| recoverable().next()),
            None => recoverable().next(),
        }
    }
}

/// Read the frozen legacy Secrets branch and report every retired account.
///
/// The pile is opened read-only and never written, and no password is needed:
/// the envelope stays sealed until [`open`]. Branch-head and authored commit
/// signatures are verified by the freeze, so a row reported here is evidence,
/// not a guess.
pub fn plan(pile: &Path) -> Result<MailCredentialReport> {
    let source = freeze_source(pile).context("freeze legacy source for the Mail account")?;
    plan_source(&source)
}

fn plan_source(source: &FrozenSource) -> Result<MailCredentialReport> {
    let Some(branch) = source
        .legacy_branch(LEGACY_BRANCH_NAME)
        .context("resolve legacy Secrets branch")?
    else {
        return Ok(MailCredentialReport {
            legacy_branch_missing: true,
            ..Default::default()
        });
    };

    let mut facts = TribleSet::new();
    let mut authored_commits = 0;
    for delta in &branch.deltas {
        if delta.is_authored() {
            authored_commits += 1;
        }
        facts += delta.facts.clone();
    }

    let reader = source.reader();
    let created_at = |entity: &Id| -> Option<Epoch> {
        facts
            .iter()
            .filter(|fact| fact.e() == entity && fact.a() == &metadata::created_at.id())
            .filter_map(|fact| {
                fact.v::<NsTAIInterval>()
                    .try_from_inline::<(Epoch, Epoch)>()
                    .ok()
            })
            .map(|(start, _)| start)
            .min()
    };
    let address = |entity: &Id| -> Option<String> {
        facts
            .iter()
            .filter(|fact| fact.e() == entity && fact.a() == &legacy::address.id())
            .filter_map(|fact| fact.v::<ShortString>().try_from_inline::<String>().ok())
            .next()
    };

    let mut unreadable_envelopes = 0;
    let mut accounts = Vec::new();
    for entity in find!(
        entity: Id,
        pattern!(&facts, [{ ?entity @ metadata::tag: legacy::KIND_ACCOUNT }])
    ) {
        let Some(address) = address(&entity) else {
            bail!("retired Mail account {entity:x} has no readable address");
        };
        let handle = facts
            .iter()
            .filter(|fact| fact.e() == &entity && fact.a() == &legacy::r#box.id())
            .map(|fact| *fact.v::<Handle<RawBytes>>())
            .next()
            .ok_or_else(|| anyhow!("retired Mail account {entity:x} has no envelope"))?;
        let envelope = match reader.get::<anybytes::Bytes, _>(handle) {
            Ok(bytes) => Some(bytes.as_ref().to_vec()),
            Err(_) => {
                unreadable_envelopes += 1;
                None
            }
        };
        accounts.push(LegacyAccount {
            entity,
            created_at: created_at(&entity),
            address,
            envelope_handle: hex::encode_upper(handle.raw),
            envelope_len: envelope.as_ref().map(Vec::len),
            envelope,
        });
    }
    // Newest first: the account record is latest-wins, so a rotation history
    // ends at the record written last.
    accounts.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then(left.entity.cmp(&right.entity))
    });

    let active_address = find!(
        entity: Id,
        pattern!(&facts, [{ ?entity @ metadata::tag: legacy::KIND_ACTIVE }])
    )
    .filter_map(|entity| Some((created_at(&entity), address(&entity)?)))
    .max_by(|left, right| left.0.cmp(&right.0))
    .map(|(_, address)| address);

    Ok(MailCredentialReport {
        legacy_branch_missing: false,
        authored_commits,
        accounts,
        active_address,
        unreadable_envelopes,
    })
}

/// One retired account, opened.
///
/// Every field but the password is ordinary configuration the operator has to
/// pass back to `mail account set`, so they are printable — and only
/// recoverable at all because they were sealed alongside the password.
#[derive(Clone, Debug)]
pub struct RecoveredAccount {
    pub entity: Id,
    pub address: String,
    /// `mail account set --display-name`; the legacy field was `from_name`.
    pub display_name: String,
    /// `mail account set --pop-endpoint`, as `host:port`.
    pub pop_endpoint: String,
    /// `mail account set --smtp-endpoint`, as `host:port`.
    pub smtp_endpoint: String,
    /// Mailbox password length, so a run can be told apart from an empty one
    /// without rendering the value.
    pub password_len: usize,
    password: SecretMaterial,
}

/// Unlock one retired account's envelope.
///
/// `password` is the Secrets root password — the legacy envelope predates the
/// identity/scope/grant ceremony and is keyed on it directly.
pub fn open(account: &LegacyAccount, password: &[u8]) -> Result<RecoveredAccount> {
    let envelope = account.envelope.as_deref().ok_or_else(|| {
        anyhow!(
            "retired Mail account {:x} has no readable envelope",
            account.entity
        )
    })?;
    let json = unlock(password, envelope)
        .with_context(|| format!("open retired Mail account {:x}", account.entity))?;
    let body: AccountBody = serde_json::from_slice(&json)
        .with_context(|| format!("parse retired Mail account body {:x}", account.entity))?;
    Ok(RecoveredAccount {
        entity: account.entity,
        address: account.address.clone(),
        display_name: body.from_name,
        pop_endpoint: format!("{}:{}", body.pop3_host, body.pop3_port),
        smtp_endpoint: format!("{}:{}", body.smtp_host, body.smtp_port),
        password_len: body.pass.len(),
        password: SecretMaterial(body.pass),
    })
}

/// One file written by [`export`].
#[derive(Clone, Debug)]
pub struct ExportedFile {
    pub path: PathBuf,
    /// What the file is for, in words safe to print.
    pub purpose: &'static str,
    pub entity: Id,
}

/// Materialize one recovered mailbox password into `dir`.
///
/// The file is created `0600` and never overwritten: a stale export is a
/// credential lying around, and silently replacing one hides that. Returns
/// what was written; the caller prints the path, never the contents.
pub fn export(account: &RecoveredAccount, dir: &Path) -> Result<ExportedFile> {
    fs::create_dir_all(dir).with_context(|| format!("create export dir {}", dir.display()))?;
    let path = dir.join(format!("mail-password-{:x}.txt", account.entity));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("create {} (it must not already exist)", path.display()))?;
    file.write_all(account.password.0.as_bytes())
        .with_context(|| format!("write {}", path.display()))?;
    Ok(ExportedFile {
        path,
        purpose: "mailbox password, for `MAIL_PASS=\"$(cat <file>)\" mail account set …`",
        entity: account.entity,
    })
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use dryoc::rng::copy_randombytes;
    use dryoc::types::*;
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;
    use triblespace::macros::entity;

    use super::*;
    use crate::collection_cutover::test_support::{TestBranchSpec, TestDeltaSpec, TestSourceSpec};
    use faculties::storage::open_pile_strict;

    const PW: &[u8] = b"root-password";

    fn lock(password: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut salt = [0u8; SALT];
        copy_randombytes(&mut salt);
        let key = derive_key(password, &salt);
        let nonce = Nonce::gen();
        let ciphertext = DryocSecretBox::encrypt_to_vecbox(plaintext, &nonce, &key).to_vec();
        let mut out = Vec::with_capacity(SALT + NONCE + ciphertext.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ciphertext);
        out
    }

    struct Fixture {
        _directory: TempDir,
        pile: PathBuf,
        source: FrozenSource,
    }

    /// A legacy Secrets branch carrying an older and a newer account record,
    /// plus an active pointer naming the older one — so "newest" and "active"
    /// disagree and selection has something to decide.
    fn fixture() -> Fixture {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("mail.pile");
        File::create(&pile_path).unwrap();
        let mut deltas = Vec::new();

        for (index, day, address) in [(0u8, 1i64, "old@example.org"), (1, 5, "new@example.org")] {
            let account = Id::new([0x50 + index; 16]).unwrap();
            let at = Epoch::from_unix_seconds((1_700_000_000 + day * 86_400) as f64);
            let at_value = (at, at).try_to_inline().unwrap();
            let body = format!(
                r#"{{"pass":"mailbox-secret-{index}","from_name":"Toby Trible",
                    "pop3_host":"pop.example.org","pop3_port":995,
                    "smtp_host":"smtp.example.org","smtp_port":465}}"#
            );

            let mut fragment = Fragment::empty();
            let envelope = fragment.put::<RawBytes, _>(lock(PW, body.as_bytes()));
            fragment += entity! { ExclusiveId::force_ref(&account) @
                metadata::tag: &legacy::KIND_ACCOUNT,
                metadata::created_at: at_value,
                legacy::address: address,
                legacy::r#box: envelope,
            };
            deltas.push(TestDeltaSpec::authored(fragment, "legacy mail account"));
        }

        // The active pointer names the older address.
        let pointer = Id::new([0x60; 16]).unwrap();
        let at = Epoch::from_unix_seconds((1_700_000_000 + 6 * 86_400) as f64);
        let at_value = (at, at).try_to_inline().unwrap();
        deltas.push(TestDeltaSpec::authored(
            entity! { ExclusiveId::force_ref(&pointer) @
                metadata::tag: &legacy::KIND_ACTIVE,
                metadata::created_at: at_value,
                legacy::address: "old@example.org",
            },
            "legacy mail active",
        ));
        let source = TestSourceSpec::new(vec![TestBranchSpec::new(
            LEGACY_BRANCH_NAME,
            Id::new([0x71; 16]).unwrap(),
            SigningKey::from_bytes(&[0x71; 32]),
            deltas,
        )])
        .freeze(&pile_path)
        .unwrap()
        .source;

        Fixture {
            _directory: directory,
            pile: pile_path,
            source,
        }
    }

    #[test]
    fn plan_reports_every_account_without_writing_or_unsealing() {
        let fixture = fixture();
        let before = std::fs::metadata(&fixture.pile).unwrap().len();
        let report = plan_source(&fixture.source).unwrap();

        assert!(!report.legacy_branch_missing);
        assert_eq!(report.accounts.len(), 2);
        assert_eq!(report.unreadable_envelopes, 0);
        // Newest first…
        assert_eq!(report.accounts[0].address, "new@example.org");
        // …but the active pointer decides which one is recovered.
        assert_eq!(report.active_address.as_deref(), Some("old@example.org"));
        assert_eq!(report.selected().unwrap().address, "old@example.org");
        assert!(report.accounts.iter().all(|row| row.is_recoverable()));
        assert_eq!(std::fs::metadata(&fixture.pile).unwrap().len(), before);
    }

    #[test]
    fn open_recovers_the_sealed_settings_and_refuses_a_wrong_password() {
        let fixture = fixture();
        let report = plan_source(&fixture.source).unwrap();
        let selected = report.selected().unwrap();

        let recovered = open(selected, PW).unwrap();
        assert_eq!(recovered.address, "old@example.org");
        assert_eq!(recovered.display_name, "Toby Trible");
        assert_eq!(recovered.pop_endpoint, "pop.example.org:995");
        assert_eq!(recovered.smtp_endpoint, "smtp.example.org:465");
        assert_eq!(recovered.password_len, "mailbox-secret-0".len());

        assert!(open(selected, b"not-the-password").is_err());
    }

    #[test]
    fn export_writes_an_owner_only_file_and_refuses_to_overwrite() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = fixture();
        let report = plan_source(&fixture.source).unwrap();
        let recovered = open(report.selected().unwrap(), PW).unwrap();
        let out = fixture.pile.parent().unwrap().join("out");

        let written = export(&recovered, &out).unwrap();
        let mode = std::fs::metadata(&written.path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(
            std::fs::read_to_string(&written.path).unwrap(),
            "mailbox-secret-0"
        );

        // A second run must not silently replace a credential already lying
        // on disk.
        assert!(export(&recovered, &out).is_err());
    }

    #[test]
    fn a_recovered_account_never_renders_its_password() {
        let fixture = fixture();
        let report = plan_source(&fixture.source).unwrap();
        let recovered = open(report.selected().unwrap(), PW).unwrap();
        let rendered = format!("{recovered:?}");
        assert!(!rendered.contains("mailbox-secret"), "{rendered}");
    }

    #[test]
    fn a_pile_without_a_legacy_branch_reports_nothing_to_recover() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("empty.pile");
        File::create(&pile_path).unwrap();
        open_pile_strict(&pile_path).unwrap().close().unwrap();

        let report = plan(&pile_path).unwrap();
        assert!(report.legacy_branch_missing);
        assert!(report.accounts.is_empty());
    }
}
