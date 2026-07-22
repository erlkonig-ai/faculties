//! secrets — an encrypted secret-store faculty (a 1Password replacement, owned,
//! pile-native). Admins distribute company secrets by sealing them to
//! recipients' keys; the pile gives storage, sync, and a signed audit trail for
//! free; authorization is signed relationship-tuples queried with the engine.
//! Design captured in the `authz`-tagged wiki (hub 4448d5fc).
//!
//! This binary is a THIN clap wrapper over the `secrets-core` crate: each `cmd_*`
//! parses args, resolves ids/names, calls the library, and prints. All of the
//! capability + envelope-encryption logic — schema, crypto, the effective-admin
//! fixpoint, the seal/open paths — lives in `secrets_core` so lean consumers
//! (playground/OAuth) can depend on it without the mary/GORBIE/egui stack.
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
//! Secrets are `(scope, name)` addressed, latest-wins (`secret add` of an
//! existing name is a new version, sealed to the *current* recipients).
//!
//! Removal is *operational, not cryptographic*: a removed user keeps the wrap
//! (= the value) they already held — the append-only pile cannot delete it, and
//! re-encrypting the same value protects nothing. So `secret rotate` is not a
//! crypto op; it is an *advisory* that lists every credential still readable by
//! a removed user, so you can change it at its source and `secret add` the new
//! value (which seals only to current recipients). The two-admin harness (in
//! `secrets-core`) shows the effective-admin fixpoint over the merged union
//! already defeats the duelling-admin / backdating / headless-group attacks (the
//! verdict is order-independent), so no epoch-finality layer is needed.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use dryoc::dryocbox::{DryocBox, KeyPair as BoxKeyPair};
use dryoc::dryocsecretbox::{DryocSecretBox, Key, Nonce};
use dryoc::types::*;

use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::Workspace;
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;

use faculties_secrets::schema::{KIND_IDENTITY, KIND_SCOPE};
use faculties_secrets::{fmt_id, MemberRole, SecretsRepo, DEFAULT_BRANCH};

type TextHandle = Inline<Handle<LongString>>;

fn read_text(ws: &mut Workspace<Pile>, h: TextHandle) -> Option<String> {
    ws.get::<View<str>, LongString>(h).ok().map(|v| v.to_string())
}

/// Resolve an entity id of a given KIND, accepting a full hex or a prefix.
fn resolve_kind_id(space: &TribleSet, kind: Id, input: &str) -> Result<Id> {
    let candidates = find!(e: Id, pattern!(space, [{ ?e @ metadata::tag: kind }]));
    faculties::resolve_id_prefix(input, candidates)
}

/// Resolve an entity of `kind` from an id (full hex or prefix) or, failing
/// that, its name (`metadata::name` — a scope's name, an identity's nickname).
/// Name resolution requires the name to be unambiguous.
fn resolve_named(ws: &mut Workspace<Pile>, space: &TribleSet, kind: Id, input: &str) -> Result<Id> {
    if let Ok(id) = resolve_kind_id(space, kind, input) {
        return Ok(id);
    }
    let named: Vec<Id> = find!(
        (e: Id, n: TextHandle),
        pattern!(space, [{ ?e @ metadata::tag: kind, metadata::name: ?n }])
    )
    .filter(|(_, n)| read_text(ws, *n).as_deref() == Some(input))
    .map(|(e, _)| e)
    .collect();
    match named.as_slice() {
        [one] => Ok(*one),
        [] => anyhow::bail!("no match for '{input}' (by id or name)"),
        many => anyhow::bail!("name '{input}' is ambiguous ({} matches — use the id)", many.len()),
    }
}

fn password() -> Result<Vec<u8>> {
    std::env::var("LIORA_SECRETS_PW")
        .map(|s| s.into_bytes())
        .map_err(|_| anyhow::anyhow!("set LIORA_SECRETS_PW to the identity password"))
}

// ── commands ──────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, name = "secrets", about = "Encrypted secret store (pile-native 1Password replacement)")]
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
    /// Show who can currently access a scope (the audit view).
    Members {
        #[arg(long)]
        scope: String,
    },
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
    /// Show which secrets are still readable by a removed user — the operational
    /// rotate worklist. Re-encrypting a stored value protects nothing (the
    /// removed user keeps their old wrap = the value), so the real fix is to
    /// change the credential at its source and `secret add` the new value. Bare
    /// `secret rotate` scans everything; `--scope` narrows it.
    Rotate {
        #[arg(long)]
        scope: Option<String>,
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

fn cmd_identity_init(repo: &SecretsRepo, nickname: String) -> Result<()> {
    let pw = password()?;
    let out = repo.identity_init(&pw, &nickname)?;
    println!("identity {} ({})", fmt_id(out.id), out.nickname);
    println!("  sign_pk {}", hex(&out.sign_pk));
    Ok(())
}

fn cmd_identity_list(repo: &SecretsRepo) -> Result<()> {
    let rows = repo.identity_list()?;
    if rows.is_empty() {
        println!("(no identities)");
    }
    for r in rows {
        println!("{}  {}", fmt_id(r.id), r.nickname);
    }
    Ok(())
}

fn cmd_scope_create(repo: &SecretsRepo, name: String, as_id: String) -> Result<()> {
    let creator = repo.read(|ws, space| resolve_named(ws, space, KIND_IDENTITY, &as_id))?;
    let out = repo.scope_create(&name, creator)?;
    println!(
        "scope {} ({})  root admin: {}",
        fmt_id(out.id),
        out.name,
        fmt_id(out.creator)
    );
    Ok(())
}

fn cmd_scope_list(repo: &SecretsRepo) -> Result<()> {
    let rows = repo.scope_list()?;
    if rows.is_empty() {
        println!("(no scopes)");
    }
    for s in rows {
        let mark = if s.rooted { "✓ rooted" } else { "✗ MISMATCH" };
        println!("{}  {}  root {}  [{}]", fmt_id(s.id), s.name, fmt_id(s.creator), mark);
    }
    Ok(())
}

fn cmd_scope_members(repo: &SecretsRepo, scope: String) -> Result<()> {
    let members = repo.read(|ws, space| {
        let scope_id = resolve_named(ws, space, KIND_SCOPE, &scope)?;
        Ok(repo.scope_members(space, ws, scope_id))
    })?;
    if members.is_empty() {
        println!("(no members)");
    }
    for m in members {
        let role = match m.role {
            MemberRole::RootAdmin => "root admin",
            MemberRole::Admin => "admin",
            MemberRole::Member => "member",
        };
        println!("{}  {}  [{}]", m.name, fmt_id(m.id), role);
    }
    Ok(())
}

fn cmd_grant(
    repo: &SecretsRepo,
    object: String,
    relation: String,
    subject: String,
    as_id: String,
) -> Result<()> {
    let (object_id, subject_id, issuer_id) = repo.read(|ws, space| {
        let object_id = resolve_named(ws, space, KIND_SCOPE, &object)?;
        let subject_id = resolve_named(ws, space, KIND_IDENTITY, &subject)?;
        let issuer_id = resolve_named(ws, space, KIND_IDENTITY, &as_id)?;
        Ok((object_id, subject_id, issuer_id))
    })?;
    let out = repo.grant(object_id, &relation, subject_id, issuer_id)?;
    println!(
        "grant {}  {} --{}--> {}  (by {})",
        fmt_id(out.grant_id),
        fmt_id(out.object),
        out.relation,
        fmt_id(out.subject),
        fmt_id(out.issuer)
    );
    Ok(())
}

fn cmd_revoke(repo: &SecretsRepo, object: String, subject: String) -> Result<()> {
    let (object_id, subject_id) = repo.read(|ws, space| {
        let object_id = resolve_named(ws, space, KIND_SCOPE, &object)?;
        let subject_id = resolve_named(ws, space, KIND_IDENTITY, &subject)?;
        Ok((object_id, subject_id))
    })?;
    let n = repo.revoke(object_id, subject_id)?;
    println!("revoked {} grant(s) for {} on {}", n, fmt_id(subject_id), fmt_id(object_id));
    Ok(())
}

fn cmd_secret_add(repo: &SecretsRepo, scope: String, name: String, value: String) -> Result<()> {
    let plaintext = load_value(&value)?;
    let scope_id = repo.read(|ws, space| resolve_named(ws, space, KIND_SCOPE, &scope))?;
    let out = repo.secret_add(scope_id, &name, &plaintext)?;
    println!(
        "secret {} ({}) sealed to {} recipient(s)",
        fmt_id(out.secret_id),
        out.name,
        out.recipients
    );
    Ok(())
}

fn cmd_secret_rotate(repo: &SecretsRepo, scope: Option<String>) -> Result<()> {
    let filter = match scope {
        Some(s) => Some(repo.read(|ws, space| resolve_named(ws, space, KIND_SCOPE, &s))?),
        None => None,
    };
    let findings = repo.rotate_worklist(filter)?;
    if findings.is_empty() {
        println!("✓ no secrets are exposed to removed users — nothing to rotate");
        return Ok(());
    }
    println!(
        "{} secret(s) still readable by a removed user. Re-encrypting them here\n\
         would change nothing (they keep their old wrap = the value). Change each\n\
         credential at its source, then `secret add` the new value:\n",
        findings.len()
    );
    // Resolve exposed-identity names for display.
    let named = repo.read(|ws, space| {
        Ok(findings
            .iter()
            .map(|f| {
                f.exposed
                    .iter()
                    .map(|e| faculties_secrets::entity_name(ws, space, *e))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>())
    })?;
    for (f, who) in findings.iter().zip(named) {
        println!("  {}/{}  →  exposed to: {}", f.scope_name, f.name, who.join(", "));
    }
    Ok(())
}

fn cmd_secret_get(repo: &SecretsRepo, scope: String, name: String, as_id: String) -> Result<()> {
    let pw = password()?;
    let (scope_id, me) = repo.read(|ws, space| {
        let scope_id = resolve_named(ws, space, KIND_SCOPE, &scope)?;
        let me = resolve_named(ws, space, KIND_IDENTITY, &as_id)?;
        Ok((scope_id, me))
    })?;
    let out = repo.secret_get(&pw, scope_id, &name, me)?;
    use std::io::Write;
    std::io::stdout().write_all(&out)?;
    Ok(())
}

fn cmd_secret_share(repo: &SecretsRepo, scope: String, name: String, as_id: String) -> Result<()> {
    let pw = password()?;
    let (scope_id, me) = repo.read(|ws, space| {
        let scope_id = resolve_named(ws, space, KIND_SCOPE, &scope)?;
        let me = resolve_named(ws, space, KIND_IDENTITY, &as_id)?;
        Ok((scope_id, me))
    })?;
    let n = repo.secret_share(&pw, scope_id, &name, me)?;
    if n == 0 {
        println!("already shared to all current recipients");
    } else {
        println!("shared to {} new recipient(s)", n);
    }
    Ok(())
}

fn cmd_secret_list(repo: &SecretsRepo) -> Result<()> {
    let rows = repo.secret_list()?;
    if rows.is_empty() {
        println!("(no secrets)");
    }
    for s in rows {
        println!(
            "{}  scope {}  (v{}, {} recipient(s))",
            s.name,
            fmt_id(s.scope),
            s.versions,
            s.recipients
        );
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let repo = SecretsRepo::open(&cli.pile, &cli.branch);
    match cli.command {
        Command::Selftest => cmd_selftest(),
        Command::Identity { cmd } => match cmd {
            IdentityCmd::Init { nickname } => cmd_identity_init(&repo, nickname),
            IdentityCmd::List => cmd_identity_list(&repo),
        },
        Command::Scope { cmd } => match cmd {
            ScopeCmd::Create { name, r#as } => cmd_scope_create(&repo, name, r#as),
            ScopeCmd::List => cmd_scope_list(&repo),
            ScopeCmd::Members { scope } => cmd_scope_members(&repo, scope),
        },
        Command::Grant { object, relation, subject, r#as } => {
            cmd_grant(&repo, object, relation, subject, r#as)
        }
        Command::Revoke { object, subject } => cmd_revoke(&repo, object, subject),
        Command::Secret { cmd } => match cmd {
            SecretCmd::Add { scope, name, value } => cmd_secret_add(&repo, scope, name, value),
            SecretCmd::Get { scope, name, r#as } => cmd_secret_get(&repo, scope, name, r#as),
            SecretCmd::Rotate { scope } => cmd_secret_rotate(&repo, scope),
            SecretCmd::Share { scope, name, r#as } => cmd_secret_share(&repo, scope, name, r#as),
            SecretCmd::List => cmd_secret_list(&repo),
        },
    }
}
