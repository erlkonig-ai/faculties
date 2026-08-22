//! Recover the Teams credentials the collection cutover deliberately retired.
//!
//! `teams_cutover` treats the legacy Teams OAuth rows as a bounded retired
//! partition: they are verified as source evidence, but neither their facts
//! nor their plaintext payload blobs enter native Teams authority, because
//! native authority never holds a secret in the clear. Live authentication was
//! meant to restart at a source-scoped auth profile naming exact encrypted
//! Secrets versions.
//!
//! Nothing built that restart. On a migrated pile the native Teams collection
//! has no auth profile and the Secrets collection has no identity, so every
//! `teams` command fails with "Teams auth-profile source ... is missing" and
//! the legacy credentials sit unreferenced on the legacy branch.
//!
//! This module is the bridge, and it is deliberately **not** a pile writer.
//! Moving a credential into the current shape means sealing it to a Secrets
//! recipient, which requires an identity and its password — an interactive
//! act a migration cannot perform, and should not. So this reads the frozen
//! legacy branch, reports exactly which credential rows survive, and on
//! request materializes their plaintext into `0600` files shaped for the two
//! commands that do own that write: `teams login --client-secret @file` and
//! `secrets secret add ... @file`.
//!
//! It opens the pile read-only, appends nothing, and prints no secret.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use hifitime::Epoch;
use triblespace::core::metadata;
use triblespace::macros::{attributes, id_hex};
use triblespace::prelude::blobencodings::UTF8String;
use triblespace::prelude::inlineencodings::{GenId, Handle, NsTAIInterval};
use triblespace::prelude::*;

use crate::collection_cutover::{freeze_source, FrozenSource};
use faculties::schemas::teams::LEGACY_BRANCH_NAME;

/// The retired Teams OAuth vocabulary, repeated here rather than imported so
/// the recovery path stays readable next to `teams_cutover`'s own copy.
mod legacy {
    use super::*;

    attributes! {
        "5F10520477A04E5FB322C85CC78C6762" unsafe as pub local_kind: GenId;
        "438A29922F91F873A69C3856AA7A553F" unsafe as pub access_token: Handle<UTF8String>;
        "60C85DD37D09D3D27BC6BFA0E8040EA9" unsafe as pub refresh_token: Handle<UTF8String>;
        "0F7784BBDA2EE5B9009DE688472D6F24" unsafe as pub token_type: Handle<UTF8String>;
        "139B46989D7F56C7DFE6259FD74479AC" unsafe as pub scope: Handle<UTF8String>;
        "34ACCCECE281E1A0E191EEEBE7E47A23" unsafe as pub tenant: Handle<UTF8String>;
        "8C6CA6A45DCA9F78420BC216A83F4C22" unsafe as pub client_id: Handle<UTF8String>;
        "0E734F66EBBA45ED022D1EE539B11EBE" unsafe as pub client_secret: Handle<UTF8String>;
        // Teams published this expiry before the April 2026 timestamp
        // migration moved new writes to `metadata::expires_at`.
        "706CC590BF4684CA8FA00E4123C43124" unsafe as pub expires_at: NsTAIInterval;
        // Straddles the inline time-encoding migration; both are read, and a
        // row that carries neither simply has no recorded time.
        "0DA5DD275AA34F86B0297CC35F1B7395" unsafe as pub created_at_le: NsTAIInterval;
        "59FA7C04A43B96F31414D1B4544FAEC2" unsafe as pub created_at_ordered: NsTAIInterval;
    }

    pub const KIND_TOKEN: Id = id_hex!("7B6DBE9FD29182D97F1699437CF6627C");
    pub const KIND_CONFIG: Id = id_hex!("0D7F4BBE36BD0D6FF4E6C651110D6E8B");
}

/// Which of the two retired row shapes a credential is.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum LegacyKind {
    /// App registration: tenant, client id, client secret.
    Config,
    /// A delegated OAuth grant: access + refresh token and its scopes.
    Token,
}

impl LegacyKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Token => "token",
        }
    }
}

/// Plaintext held for export and never rendered.
///
/// `Debug` is implemented by hand: a derived one would put a live client
/// secret into any log line, backtrace, or panic message that touched a
/// report.
#[derive(Clone, Default)]
struct SecretMaterial {
    client_secret: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

impl std::fmt::Debug for SecretMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretMaterial")
            .field("client_secret", &self.client_secret.as_ref().map(|_| "…"))
            .field("access_token", &self.access_token.as_ref().map(|_| "…"))
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| "…"))
            .finish()
    }
}

/// One surviving legacy credential row.
#[derive(Clone, Debug)]
pub struct LegacyCredential {
    pub entity: Id,
    pub kind: LegacyKind,
    /// Earliest recorded creation time, across both historical encodings.
    pub created_at: Option<Epoch>,
    /// Recorded delegated-token expiry, when the row carries one.
    pub expires_at: Option<Epoch>,
    pub tenant: Option<String>,
    pub client_id: Option<String>,
    /// Space-delimited delegated scopes, as Microsoft returned them.
    pub scopes: Option<String>,
    pub token_type: Option<String>,
    /// Byte lengths of the secret-bearing payloads, for shape reporting.
    pub client_secret_len: Option<usize>,
    pub access_token_len: Option<usize>,
    pub refresh_token_len: Option<usize>,
    secret: SecretMaterial,
}

impl LegacyCredential {
    /// Whether this row still carries material worth exporting.
    pub fn is_exportable(&self) -> bool {
        match self.kind {
            LegacyKind::Config => self.secret.client_secret.is_some(),
            LegacyKind::Token => self.secret.access_token.is_some(),
        }
    }
}

/// Everything a run needs to decide what to do, with no secret in it.
#[derive(Clone, Debug, Default)]
pub struct TeamsCredentialReport {
    /// Legacy branch was absent (nothing to recover from).
    pub legacy_branch_missing: bool,
    /// Verified authored commits on the legacy Teams branch.
    pub authored_commits: usize,
    /// Credential rows in newest-first order.
    pub credentials: Vec<LegacyCredential>,
    /// Payload blobs a credential row names but the pile can no longer read.
    pub unreadable_payloads: usize,
    /// Distinct Microsoft user ids observed on the legacy branch. These are
    /// every chat participant, not the signed-in account.
    pub user_ids: Vec<String>,
    /// Directory object id of the account the newest delegated grant is for,
    /// read from its access token's `oid` claim.
    ///
    /// This is the value `teams auth set --user-id` wants, and the only place
    /// it can be recovered without a fresh login — the legacy rows record the
    /// participants of the chats, never which one signed in.
    pub signed_in_user_id: Option<String>,
}

/// One claim from an unverified JWT body.
///
/// Signature verification is Microsoft's job at the API boundary; here the
/// token is already-trusted local evidence and the claim is being read for a
/// directory object id, not for authorization.
fn jwt_claim(token: &str, claim: &str) -> Option<String> {
    use base64::Engine as _;

    let body = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    value
        .get(claim)?
        .as_str()
        .map(str::to_owned)
        .filter(|value| !value.is_empty())
}

impl TeamsCredentialReport {
    pub fn configs(&self) -> impl Iterator<Item = &LegacyCredential> {
        self.credentials
            .iter()
            .filter(|row| row.kind == LegacyKind::Config)
    }

    pub fn tokens(&self) -> impl Iterator<Item = &LegacyCredential> {
        self.credentials
            .iter()
            .filter(|row| row.kind == LegacyKind::Token)
    }

    /// The one tenant every legacy row agrees on, if they agree.
    pub fn tenant(&self) -> Option<&str> {
        let mut tenants = self
            .credentials
            .iter()
            .filter_map(|row| row.tenant.as_deref())
            .collect::<Vec<_>>();
        tenants.sort_unstable();
        tenants.dedup();
        match tenants.as_slice() {
            [tenant] => Some(tenant),
            _ => None,
        }
    }

    /// The one client id every legacy row agrees on, if they agree.
    pub fn client_id(&self) -> Option<&str> {
        let mut ids = self
            .credentials
            .iter()
            .filter_map(|row| row.client_id.as_deref())
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        match ids.as_slice() {
            [id] => Some(id),
            _ => None,
        }
    }

    /// Newest exportable app-registration row.
    pub fn newest_config(&self) -> Option<&LegacyCredential> {
        self.configs().find(|row| row.is_exportable())
    }

    /// Newest exportable delegated-grant row.
    pub fn newest_token(&self) -> Option<&LegacyCredential> {
        self.tokens().find(|row| row.is_exportable())
    }
}

/// Read the frozen legacy Teams branch and report every surviving credential.
///
/// The pile is opened read-only and never written. Branch-head and authored
/// commit signatures are verified by the freeze, so a row reported here is
/// evidence, not a guess.
pub fn plan(pile: &Path) -> Result<TeamsCredentialReport> {
    let source = freeze_source(pile).context("freeze legacy source for Teams credentials")?;
    plan_source(&source)
}

fn plan_source(source: &FrozenSource) -> Result<TeamsCredentialReport> {
    let Some(branch) = source
        .legacy_branch(LEGACY_BRANCH_NAME)
        .context("resolve legacy Teams branch")?
    else {
        return Ok(TeamsCredentialReport {
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
    let mut unreadable_payloads = 0;
    let mut text = |handle: Inline<Handle<UTF8String>>| -> Option<String> {
        match reader.get::<anybytes::View<str>, _>(handle) {
            Ok(view) => Some(view.as_ref().to_owned()),
            Err(_) => {
                unreadable_payloads += 1;
                None
            }
        }
    };

    let mut rows: BTreeMap<Id, LegacyKind> = BTreeMap::new();
    for (kind, label) in [
        (legacy::KIND_CONFIG, LegacyKind::Config),
        (legacy::KIND_TOKEN, LegacyKind::Token),
    ] {
        for entity in find!(
            entity: Id,
            pattern!(&facts, [{ ?entity @ legacy::local_kind: kind }])
        ) {
            rows.insert(entity, label);
        }
    }
    // A row written before the protocol-local kind attribute, or after it was
    // dropped, is still a credential. Classify it by what it carries rather
    // than skipping it: a missed client secret is the one thing here that
    // cannot be re-derived.
    for (attribute, label) in [
        (legacy::client_secret.id(), LegacyKind::Config),
        (legacy::access_token.id(), LegacyKind::Token),
    ] {
        for fact in facts.iter().filter(|fact| fact.a() == &attribute) {
            rows.entry(*fact.e()).or_insert(label);
        }
    }

    let single = |entity: &Id, attribute: Id| -> Option<Inline<Handle<UTF8String>>> {
        let mut values = facts
            .iter()
            .filter(|fact| fact.e() == entity && fact.a() == &attribute)
            .map(|fact| *fact.v::<Handle<UTF8String>>())
            .collect::<Vec<_>>();
        values.dedup();
        match values.as_slice() {
            [value] => Some(*value),
            _ => None,
        }
    };
    let instant = |entity: &Id, attribute: Id| -> Option<Epoch> {
        facts
            .iter()
            .filter(|fact| fact.e() == entity && fact.a() == &attribute)
            .filter_map(|fact| {
                fact.v::<NsTAIInterval>()
                    .try_from_inline::<(Epoch, Epoch)>()
                    .ok()
            })
            .map(|(start, _)| start)
            .min()
    };

    let mut credentials = Vec::new();
    for (entity, kind) in rows {
        let client_secret = single(&entity, legacy::client_secret.id()).and_then(&mut text);
        let access_token = single(&entity, legacy::access_token.id()).and_then(&mut text);
        let refresh_token = single(&entity, legacy::refresh_token.id()).and_then(&mut text);
        credentials.push(LegacyCredential {
            entity,
            kind,
            created_at: [
                metadata::created_at.id(),
                legacy::created_at_ordered.id(),
                legacy::created_at_le.id(),
            ]
            .into_iter()
            .filter_map(|attribute| instant(&entity, attribute))
            // The two retired encodings disagree by millennia on the same
            // row, so the plausible one is the one to show.
            .filter(|epoch| epoch.to_unix_seconds() > 0.0)
            .min(),
            expires_at: [metadata::expires_at.id(), legacy::expires_at.id()]
                .into_iter()
                .filter_map(|attribute| instant(&entity, attribute))
                .filter(|epoch| epoch.to_unix_seconds() > 0.0)
                .min(),
            tenant: single(&entity, legacy::tenant.id()).and_then(&mut text),
            client_id: single(&entity, legacy::client_id.id()).and_then(&mut text),
            scopes: single(&entity, legacy::scope.id()).and_then(&mut text),
            token_type: single(&entity, legacy::token_type.id()).and_then(&mut text),
            client_secret_len: client_secret.as_ref().map(String::len),
            access_token_len: access_token.as_ref().map(String::len),
            refresh_token_len: refresh_token.as_ref().map(String::len),
            secret: SecretMaterial {
                client_secret,
                access_token,
                refresh_token,
            },
        });
    }
    // Newest first: this is a rotation history, and the current credential is
    // the last one written.
    credentials.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then(left.entity.cmp(&right.entity))
    });

    let mut user_ids = facts
        .iter()
        .filter(|fact| fact.a() == &faculties::schemas::teams::teams::user_id.id())
        .map(|fact| *fact.v::<Handle<UTF8String>>())
        .collect::<Vec<_>>();
    user_ids.dedup();
    let user_ids = user_ids
        .into_iter()
        .filter_map(&mut text)
        .collect::<Vec<_>>();

    let signed_in_user_id = credentials
        .iter()
        .find(|row| row.kind == LegacyKind::Token && row.secret.access_token.is_some())
        .and_then(|row| {
            let token = row.secret.access_token.as_deref()?;
            jwt_claim(token, "oid").or_else(|| jwt_claim(token, "sub"))
        });

    Ok(TeamsCredentialReport {
        legacy_branch_missing: false,
        authored_commits,
        credentials,
        unreadable_payloads,
        user_ids,
        signed_in_user_id,
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

/// The shape `teams` seals into a delegated-token Secrets version.
///
/// Kept structurally identical to `bin/teams.rs`'s `DelegatedTokenBundle` so
/// an exported file can be handed straight to `secrets secret add`.
#[derive(serde::Serialize)]
struct DelegatedTokenBundle<'a> {
    access_token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<&'a str>,
    expires_at_unix: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_type: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
}

/// Materialize the newest exportable credential of each kind into `dir`.
///
/// Files are created `0600` and never overwritten: a stale export is a
/// credential lying around, and silently replacing one hides that. Returns
/// what was written; the caller prints paths, never contents.
pub fn export(report: &TeamsCredentialReport, dir: &Path) -> Result<Vec<ExportedFile>> {
    fs::create_dir_all(dir).with_context(|| format!("create export dir {}", dir.display()))?;

    let mut written = Vec::new();
    let mut write = |name: String, bytes: &[u8], purpose: &'static str, entity: Id| -> Result<()> {
        let path = dir.join(name);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("create {} (it must not already exist)", path.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write {}", path.display()))?;
        written.push(ExportedFile {
            path,
            purpose,
            entity,
        });
        Ok(())
    };

    if let Some(config) = report.newest_config() {
        let secret = config
            .secret
            .client_secret
            .as_deref()
            .expect("exportable config row has a client secret");
        write(
            format!("teams-client-secret-{:x}.txt", config.entity),
            secret.trim().as_bytes(),
            "app client secret, for `teams login --client-secret @<file>`",
            config.entity,
        )?;
    }

    if let Some(token) = report.newest_token() {
        let access_token = token
            .secret
            .access_token
            .as_deref()
            .expect("exportable token row has an access token");
        let bundle = DelegatedTokenBundle {
            access_token,
            refresh_token: token.secret.refresh_token.as_deref(),
            // The legacy row's own expiry, when it recorded a plausible one.
            // A bundle with a past expiry is exactly right: `teams` will then
            // refresh it rather than present a dead access token as live.
            expires_at_unix: token
                .expires_at
                .map(|epoch| epoch.to_unix_seconds() as i64)
                .unwrap_or(0),
            token_type: token.token_type.as_deref(),
            scope: token.scopes.as_deref(),
        };
        write(
            format!("teams-delegated-token-{:x}.json", token.entity),
            &serde_json::to_vec_pretty(&bundle).context("encode delegated-token bundle")?,
            "delegated token bundle, for `secrets secret add ... @<file>`",
            token.entity,
        )?;
    }

    if written.is_empty() {
        bail!("no exportable legacy credential rows; nothing written");
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;
    use triblespace::macros::entity;

    use super::*;
    use crate::collection_cutover::test_support::{TestBranchSpec, TestDeltaSpec, TestSourceSpec};
    use faculties::storage::open_pile_strict;

    struct Fixture {
        _directory: TempDir,
        pile: PathBuf,
        source: FrozenSource,
    }

    /// A legacy Teams branch carrying one older and one newer credential of
    /// each kind, so ordering and "newest" selection are both exercised.
    fn fixture() -> Fixture {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("teams.pile");
        File::create(&pile_path).unwrap();
        let mut deltas = Vec::new();

        for (index, day) in [(0u8, 1i64), (1, 5)] {
            let config = Id::new([0x30 + index; 16]).unwrap();
            let token = Id::new([0x40 + index; 16]).unwrap();
            let at = Epoch::from_unix_seconds((1_700_000_000 + day * 86_400) as f64);
            let expiry = Epoch::from_unix_seconds((1_700_003_600 + day * 86_400) as f64);
            let at_value = (at, at).try_to_inline().unwrap();
            let expiry_value = (expiry, expiry).try_to_inline().unwrap();

            let mut fragment = Fragment::empty();
            let tenant = fragment.put::<UTF8String, _>("tenant-guid".to_owned());
            let client_id = fragment.put::<UTF8String, _>("client-guid".to_owned());
            let client_secret = fragment.put::<UTF8String, _>(format!("client-secret-{index}"));
            let access = fragment.put::<UTF8String, _>(format!("access-{index}"));
            let refresh = fragment.put::<UTF8String, _>(format!("refresh-{index}"));
            let token_type = fragment.put::<UTF8String, _>("Bearer".to_owned());
            let scope = fragment.put::<UTF8String, _>("Chat.Read User.Read".to_owned());
            fragment += entity! { ExclusiveId::force_ref(&config) @
                legacy::local_kind: legacy::KIND_CONFIG,
                metadata::created_at: at_value,
                legacy::tenant: tenant,
                legacy::client_id: client_id,
                legacy::client_secret: client_secret,
            };
            fragment += entity! { ExclusiveId::force_ref(&token) @
                legacy::local_kind: legacy::KIND_TOKEN,
                metadata::created_at: at_value,
                legacy::expires_at: expiry_value,
                legacy::tenant: tenant,
                legacy::client_id: client_id,
                legacy::access_token: access,
                legacy::refresh_token: refresh,
                legacy::token_type: token_type,
                legacy::scope: scope,
            };
            deltas.push(TestDeltaSpec::authored(fragment, "legacy oauth"));
        }
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
    fn plan_reports_every_credential_newest_first_without_writing() {
        let fixture = fixture();
        let before = std::fs::metadata(&fixture.pile).unwrap().len();
        let report = plan_source(&fixture.source).unwrap();

        assert!(!report.legacy_branch_missing);
        assert_eq!(report.credentials.len(), 4);
        assert_eq!(report.unreadable_payloads, 0);
        assert_eq!(report.tenant(), Some("tenant-guid"));
        assert_eq!(report.client_id(), Some("client-guid"));
        // Newest first, and the newest of each kind is the day-5 pair.
        assert_eq!(report.credentials[0].entity, Id::new([0x31; 16]).unwrap());
        assert_eq!(
            report.newest_config().unwrap().entity,
            Id::new([0x31; 16]).unwrap()
        );
        assert_eq!(
            report.newest_token().unwrap().entity,
            Id::new([0x41; 16]).unwrap()
        );
        assert_eq!(report.newest_config().unwrap().client_secret_len, Some(15));
        assert_eq!(
            report.newest_token().unwrap().scopes.as_deref(),
            Some("Chat.Read User.Read")
        );
        assert_eq!(std::fs::metadata(&fixture.pile).unwrap().len(), before);
    }

    #[test]
    fn export_writes_owner_only_files_and_refuses_to_overwrite() {
        let fixture = fixture();
        let report = plan_source(&fixture.source).unwrap();
        let out = fixture.pile.parent().unwrap().join("out");

        let written = export(&report, &out).unwrap();
        assert_eq!(written.len(), 2);
        for file in &written {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&file.path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{}", file.path.display());
        }
        let bundle = written
            .iter()
            .find(|file| file.path.extension().is_some_and(|ext| ext == "json"))
            .unwrap();
        let decoded: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&bundle.path).unwrap()).unwrap();
        // Exactly the field names `bin/teams.rs` deserializes.
        assert!(decoded["access_token"].is_string());
        assert!(decoded["refresh_token"].is_string());
        assert!(decoded["expires_at_unix"].is_i64());
        assert_eq!(decoded["scope"], "Chat.Read User.Read");

        // A second run must not silently replace a credential already lying
        // on disk.
        assert!(export(&report, &out).is_err());
    }

    #[test]
    fn secret_material_never_renders_its_payload() {
        let material = SecretMaterial {
            client_secret: Some("live-secret".to_owned()),
            access_token: Some("live-token".to_owned()),
            refresh_token: None,
        };
        let rendered = format!("{material:?}");
        assert!(!rendered.contains("live-secret"), "{rendered}");
        assert!(!rendered.contains("live-token"), "{rendered}");
    }

    #[test]
    fn a_pile_without_a_legacy_branch_reports_nothing_to_recover() {
        let directory = TempDir::new().unwrap();
        let pile_path = directory.path().join("empty.pile");
        File::create(&pile_path).unwrap();
        open_pile_strict(&pile_path).unwrap().close().unwrap();

        let report = plan(&pile_path).unwrap();
        assert!(report.legacy_branch_missing);
        assert!(report.credentials.is_empty());
    }
}
