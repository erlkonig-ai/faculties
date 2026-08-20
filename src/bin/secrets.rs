//! `secrets` — collection-native encrypted secret storage.
//!
//! Every mutation publishes one independently signed fragment into the stable
//! Secrets union collection. The rooted grant fixpoint, OR-set grant identity,
//! strict record validation, crypto envelopes, and attachment validation live
//! in [`faculties::secrets`]; this binary owns only command workflow and I/O.
//!
//! An identity's private half rests either in a password-locked lockbox in its
//! record or in the node's durable pile signing key — one key for signing and
//! for sealing, so a node has one identity rather than two. `node list` reads
//! the roster of nodes the pile already attests, and `node adopt` names one.
//!
//! Naming a node entitles it to nothing: `grant` still decides who a scope's
//! recipients are, `secret add` still seals only to those recipients, and
//! `secret get` still needs a wrap addressed to the reader.

use std::collections::{BTreeSet, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use faculties::secrets::schema::DEFAULT_SCOPE_ID;
use faculties::secrets::{
    self as secrets_model, entity_name, grant_fragment, open_version, prepare_identity,
    prepare_node_identity, read_text, resolve_principal, resolve_scope,
    retraction_fragment, scope_by_creator_and_name, scope_fragment, seal_version, share_version,
    validate_candidate, IdentitySecret, SecretsCatalog,
};
use faculties::secrets_node;
use faculties::storage::{discover_nodes, load_signer, open_pile_strict};
use hifitime::Epoch;
use triblespace::core::collection::Collection;
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::BlobStore;
use triblespace::prelude::*;
use faculties::legacy_hint::open_scope;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "secrets",
    about = "Encrypted secret store (collection-native 1Password replacement)"
)]
struct Cli {
    /// Path to the pile file.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable collection signing-key file. Reads and writes never
    /// create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
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
    /// Scope management. A scope is intrinsic in creator+name; its creator is
    /// the implicit root admin.
    Scope {
        #[command(subcommand)]
        cmd: ScopeCmd,
    },
    /// Add one independent relation grant, issued by an effective admin.
    Grant {
        #[arg(long)]
        object: String,
        #[arg(long, default_value = "member")]
        relation: String,
        /// Identity or nested scope receiving the grant.
        #[arg(long)]
        subject: String,
        /// Issuing identity, which must be an effective admin of the object.
        /// Defaults to this node's own.
        #[arg(long)]
        r#as: Option<String>,
    },
    /// Monotonically retract every currently live grant for a subject on a
    /// scope. Rotate affected source credentials afterwards.
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
    /// Nodes that have written to this pile, and their Secrets names.
    Node {
        #[command(subcommand)]
        cmd: NodeCmd,
    },
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Create an identity (Ed25519 key, password-locked private key).
    Init {
        #[arg(long)]
        nickname: String,
    },
    /// List identities.
    List,
}

#[derive(Subcommand)]
enum NodeCmd {
    /// List every node whose verified commits appear in this pile, and the
    /// Secrets identity each is named as. Appearing here is not membership of
    /// anything: it says only that a secret *could* be sealed to that key.
    List,
    /// Name a node's signing key as a Secrets identity.
    ///
    /// The record carries only public material, so no password, private key,
    /// or ceremony with the named node is involved — and nothing is granted.
    /// Use `grant` to make the named identity a recipient of a scope.
    Adopt {
        #[arg(long)]
        nickname: String,
        /// Public key of a node from `node list`; a hex prefix is enough.
        /// Without it, this pile's own signing key.
        #[arg(long)]
        key: Option<String>,
    },
}

#[derive(Subcommand)]
enum ScopeCmd {
    /// Create the intrinsic `(creator, name)` scope.
    Create {
        #[arg(long)]
        name: String,
        /// Acting identity. Defaults to this node's own.
        #[arg(long)]
        r#as: Option<String>,
    },
    /// List rooted scopes.
    List,
    /// Show effective recipients of a scope.
    Members {
        #[arg(long)]
        scope: String,
    },
}

#[derive(Subcommand)]
enum SecretCmd {
    /// Add an immutable version, sealed to every current recipient.
    Add {
        #[arg(long)]
        scope: String,
        #[arg(long)]
        name: String,
        /// Literal value, @file, or @- for stdin.
        value: String,
    },
    /// Decrypt the latest unambiguous version as one identity.
    Get {
        #[arg(long)]
        scope: String,
        #[arg(long)]
        name: String,
        /// Reading identity. Defaults to this node's own.
        #[arg(long)]
        r#as: Option<String>,
    },
    /// List credentials whose current version is still wrapped to a removed
    /// user. This is an operational rotation worklist, not re-encryption.
    Rotate {
        #[arg(long)]
        scope: Option<String>,
    },
    /// Add wraps for recipients who joined after a version was created.
    Share {
        #[arg(long)]
        scope: String,
        #[arg(long)]
        name: String,
        /// Identity holding a wrap of the version, whose copy of the DEK is
        /// re-sealed to the new recipients. Defaults to this node's own.
        #[arg(long)]
        r#as: Option<String>,
    },
    /// List credentials grouped by `(scope, name)`.
    List,
}

#[derive(Clone, Copy)]
struct SecretsStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

struct CollectionView {
    facts: TribleSet,
    reader: PileReader,
}

struct LoadedSecrets {
    view: CollectionView,
    catalog: SecretsCatalog,
    /// This node's durable signing key: its pile authority and, once named,
    /// its Secrets identity.
    signer: SigningKey,
}

impl LoadedSecrets {
    /// The identity a command acts as, defaulting to this node's own.
    fn acting_identity(&self, explicit: Option<&str>) -> Result<Id> {
        secrets_node::acting_identity(&self.view.reader, &self.catalog, &self.signer, explicit)
    }

    /// What opens that identity: this node's signing key, or the password
    /// that opens the lockbox its record carries.
    fn identity_secret(&self, identity: Id) -> Result<IdentitySecret> {
        secrets_node::identity_secret(
            &self.catalog,
            identity,
            &self.signer,
            "the identity password",
        )
    }
}

impl SecretsStorage<'_> {
    fn with_collection<T>(
        &self,
        operation: impl FnOnce(&mut Collection<Pile>, &LoadedSecrets) -> Result<T>,
    ) -> Result<T> {
        let signer = load_signer(self.pile, self.key)?;
        let pile = open_pile_strict(self.pile)?;
        let mut collection = open_scope(pile, DEFAULT_SCOPE_ID, signer.clone());
        let result = (|| {
            let facts = collection
                .materialize()
                .context("materialize Secrets collection")?;
            let reader = collection
                .storage_mut()
                .reader()
                .context("open Secrets attachment reader")?;
            let catalog = secrets_model::validate_catalog(&reader, &facts)
                .context("validate Secrets collection")?;
            operation(
                &mut collection,
                &LoadedSecrets {
                    view: CollectionView { facts, reader },
                    catalog,
                    signer,
                },
            )
        })();
        finish_pile(collection.into_storage(), result)
    }

    fn with_view<T>(&self, operation: impl FnOnce(&LoadedSecrets) -> Result<T>) -> Result<T> {
        self.with_collection(|_, loaded| operation(loaded))
    }

    /// Run one mutation and publish its fragment, if it produced one.
    ///
    /// The operation also receives the open collection, because a mutation may
    /// legitimately need the pile's own records — `node adopt` resolves a key
    /// against the roster of nodes that have signed commits here.
    fn update<T>(
        &self,
        description: &'static str,
        operation: impl FnOnce(&mut Collection<Pile>, &LoadedSecrets) -> Result<(Option<Fragment>, T)>,
    ) -> Result<T> {
        self.with_collection(|collection, loaded| {
            let (fragment, value) = operation(collection, loaded)?;
            let Some(mut fragment) = fragment else {
                return Ok(value);
            };
            validate_candidate(&loaded.view.reader, &loaded.view.facts, &fragment)
                .context("validate Secrets mutation")?;
            fragment.describe_with(entity! { metadata::description: description });
            collection
                .commit(fragment)
                .context("commit Secrets fragment")?;
            Ok(value)
        })
    }
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context("close Secrets pile")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing Secrets pile also failed: {close_error}")))
        }
    }
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn now_epoch() -> Result<Epoch> {
    Epoch::now().map_err(|error| anyhow!("read current clock: {error:?}"))
}

fn point_interval(at: Epoch) -> secrets_model::IntervalValue {
    (at, at)
        .try_to_inline()
        .expect("a clock point is a valid interval")
}

fn load_value(raw: &str) -> Result<Vec<u8>> {
    if let Some(rest) = raw.strip_prefix('@') {
        if rest == "-" {
            let mut value = Vec::new();
            std::io::stdin()
                .read_to_end(&mut value)
                .context("read secret value from stdin")?;
            Ok(value)
        } else {
            std::fs::read(rest).with_context(|| format!("read {rest}"))
        }
    } else {
        Ok(raw.as_bytes().to_vec())
    }
}

// ── commands ───────────────────────────────────────────────────────────────

fn cmd_selftest() -> Result<()> {
    secrets_model::envelope_selftest()?;
    println!("✓ envelope round-trip: alice opened, bob refused");
    Ok(())
}

fn cmd_identity_init(storage: SecretsStorage<'_>, nickname: String) -> Result<()> {
    let password = faculties::secrets::password::read("the identity password")?;
    let (identity, public_key) = storage.update("secrets: identity init", |_, _| {
        let prepared = prepare_identity(&nickname, &password, point_interval(now_epoch()?))?;
        Ok((Some(prepared.fragment), (prepared.id, prepared.public_key)))
    })?;
    println!("identity {} ({nickname})", fmt_id(identity));
    println!("  sign_pk {}", hex(&public_key));
    Ok(())
}

fn cmd_identity_list(storage: SecretsStorage<'_>) -> Result<()> {
    storage.with_view(|loaded| {
        if loaded.catalog.identities.is_empty() {
            println!("(no identities)");
            return Ok(());
        }
        let node = secrets_node::node_identity(
            &loaded.view.reader,
            &loaded.catalog,
            &loaded.signer,
        )?;
        for row in loaded.catalog.identities.values() {
            let kind = if row.is_node_identity() {
                "node key"
            } else {
                "lockbox"
            };
            let here = if node == Some(row.id) { "  [this node]" } else { "" };
            println!(
                "{}  {}  [{kind}]{here}",
                fmt_id(row.id),
                read_text(&loaded.view.reader, row.name)?
            );
        }
        Ok(())
    })
}

/// The pile's own roster of writers.
///
/// Every commit carries the key that signed it, and discovery keeps only the
/// commits whose signature verifies, so this list needs no registry and no key
/// exchange. It reports who *can be named*, never who may read.
fn cmd_node_list(storage: SecretsStorage<'_>) -> Result<()> {
    storage.with_collection(|collection, loaded| {
        let nodes = discover_nodes(collection.storage_mut())?;
        if nodes.is_empty() {
            println!("(no signed commits in this pile)");
            return Ok(());
        }
        let this = loaded.signer.verifying_key().to_bytes();
        for node in &nodes {
            let named = secrets_model::identity_by_public_key(
                &loaded.view.reader,
                &loaded.catalog,
                &node.public_key(),
            )?;
            let name = match named {
                Some(id) => format!(
                    "{}  {}",
                    entity_name(&loaded.view.reader, &loaded.catalog, id)?,
                    fmt_id(id)
                ),
                None => "(unnamed — `secrets node adopt` names it)".to_owned(),
            };
            let here = if node.public_key() == this {
                "  [this node]"
            } else {
                ""
            };
            println!(
                "{}  {} commit(s) in {} collection(s)  {name}{here}",
                hex(&node.public_key()),
                node.commits(),
                node.collections()
            );
        }
        Ok(())
    })
}

fn cmd_node_adopt(storage: SecretsStorage<'_>, nickname: String, key: Option<String>) -> Result<()> {
    let (identity, name, public_key, existed) =
        storage.update("secrets: node adopt", |collection, loaded| {
            let public_key = match key.as_deref() {
                Some(selector) => resolve_node_key(collection.storage_mut(), selector)?,
                None => loaded.signer.verifying_key().to_bytes(),
            };
            if let Some(existing) = secrets_model::identity_by_public_key(
                &loaded.view.reader,
                &loaded.catalog,
                &public_key,
            )? {
                let name = entity_name(&loaded.view.reader, &loaded.catalog, existing)?;
                return Ok((None, (existing, name, public_key, true)));
            }
            let prepared =
                prepare_node_identity(&nickname, &public_key, point_interval(now_epoch()?))?;
            Ok((
                Some(prepared.fragment),
                (prepared.id, nickname.clone(), public_key, false),
            ))
        })?;
    if existed {
        println!(
            "node {} is already identity {} ({name})",
            hex(&public_key),
            fmt_id(identity)
        );
        return Ok(());
    }
    println!("identity {} ({name})", fmt_id(identity));
    println!("  node key {}", hex(&public_key));
    println!(
        "  named, not entitled — `secrets grant --object <scope> --subject {name}` makes it a recipient"
    );
    Ok(())
}

/// Resolve a node public key by exact hex or unambiguous prefix, against the
/// keys the pile itself attests. A key that has never written here cannot be
/// named this way; there is nothing to resolve it against.
fn resolve_node_key(
    store: &mut Pile,
    selector: &str,
) -> Result<[u8; 32]> {
    let selector = selector.trim().to_ascii_lowercase();
    if selector.is_empty() || !selector.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("a node key selector is hexadecimal");
    }
    let mut matches: Vec<[u8; 32]> = discover_nodes(store)?
        .into_iter()
        .map(|node| node.public_key())
        .filter(|key| hex(key).starts_with(&selector))
        .collect();
    matches.sort_unstable();
    matches.dedup();
    match matches.as_slice() {
        [key] => Ok(*key),
        [] => bail!("no node in this pile has a public key starting '{selector}'"),
        many => bail!("node key prefix '{selector}' is ambiguous ({} matches)", many.len()),
    }
}

fn cmd_scope_create(
    storage: SecretsStorage<'_>,
    name: String,
    as_identity: Option<String>,
) -> Result<()> {
    let (scope, creator, existed) = storage.update("secrets: scope create", |_, loaded| {
        let creator = loaded.acting_identity(as_identity.as_deref())?;
        if let Some(scope) =
            scope_by_creator_and_name(&loaded.view.reader, &loaded.catalog, creator, &name)?
        {
            return Ok((None, (scope, creator, true)));
        }
        let fragment = scope_fragment(creator, &name, point_interval(now_epoch()?))?;
        let scope = fragment.root().expect("scope fragment has one root");
        Ok((Some(fragment), (scope, creator, false)))
    })?;
    if existed {
        println!(
            "scope {} ({name}) already exists; root admin {}",
            fmt_id(scope),
            fmt_id(creator)
        );
        return Ok(());
    }
    println!(
        "scope {} ({name})  root admin: {}",
        fmt_id(scope),
        fmt_id(creator)
    );
    Ok(())
}

fn cmd_scope_list(storage: SecretsStorage<'_>) -> Result<()> {
    storage.with_view(|loaded| {
        if loaded.catalog.scopes.is_empty() {
            println!("(no scopes)");
            return Ok(());
        }
        for row in loaded.catalog.scopes.values() {
            let name = read_text(&loaded.view.reader, row.name)?;
            println!(
                "{}  {}  root {}  [✓ intrinsic]",
                fmt_id(row.id),
                name,
                fmt_id(row.creator)
            );
        }
        Ok(())
    })
}

fn cmd_scope_members(storage: SecretsStorage<'_>, scope: String) -> Result<()> {
    storage.with_view(|loaded| {
        let scope = resolve_scope(&loaded.view.reader, &loaded.catalog, &scope)?;
        let creator = loaded.catalog.scope_creator(scope);
        let admins = loaded.catalog.effective_admins(scope);
        let recipients = loaded.catalog.recipients_of(scope);
        if recipients.is_empty() {
            println!("(no members)");
            return Ok(());
        }
        for recipient in recipients {
            let name = entity_name(&loaded.view.reader, &loaded.catalog, recipient)?;
            let role = if creator == Some(recipient) {
                "root admin"
            } else if admins.contains(&recipient) {
                "admin"
            } else {
                "member"
            };
            println!("{}  {}  [{role}]", name, fmt_id(recipient));
        }
        Ok(())
    })
}

fn cmd_grant(
    storage: SecretsStorage<'_>,
    object: String,
    relation: String,
    subject: String,
    as_identity: Option<String>,
) -> Result<()> {
    let grant = genid().id;
    let (object, subject, issuer) = storage.update("secrets: grant", |_, loaded| {
        let object = resolve_scope(&loaded.view.reader, &loaded.catalog, &object)?;
        let subject = resolve_principal(&loaded.view.reader, &loaded.catalog, &subject)?;
        let issuer = loaded.acting_identity(as_identity.as_deref())?;
        if !loaded.catalog.effective_admins(object).contains(&issuer) {
            bail!(
                "{} is not an effective admin of {}; only an admin can grant",
                fmt_id(issuer),
                fmt_id(object)
            );
        }
        let fragment = grant_fragment(
            grant,
            object,
            &relation,
            subject,
            issuer,
            point_interval(now_epoch()?),
        )?;
        Ok((Some(fragment), (object, subject, issuer)))
    })?;
    println!(
        "grant {}  {} --{}--> {}  (by {})",
        fmt_id(grant),
        fmt_id(object),
        relation,
        fmt_id(subject),
        fmt_id(issuer)
    );
    Ok(())
}

fn cmd_revoke(storage: SecretsStorage<'_>, object: String, subject: String) -> Result<()> {
    let (object, subject, count) = storage.update("secrets: revoke", |_, loaded| {
        let object = resolve_scope(&loaded.view.reader, &loaded.catalog, &object)?;
        let subject = resolve_principal(&loaded.view.reader, &loaded.catalog, &subject)?;
        let grants: BTreeSet<Id> = loaded
            .catalog
            .grants
            .values()
            .filter(|grant| {
                grant.object == object && grant.subject == subject && grant.retracted_at.is_empty()
            })
            .map(|grant| grant.id)
            .collect();
        if grants.is_empty() {
            bail!(
                "no live grant for {} on {}",
                fmt_id(subject),
                fmt_id(object)
            );
        }
        let count = grants.len();
        let fragment = retraction_fragment(grants, point_interval(now_epoch()?))?;
        Ok((Some(fragment), (object, subject, count)))
    })?;
    println!(
        "revoked {count} grant(s) for {} on {}",
        fmt_id(subject),
        fmt_id(object)
    );
    Ok(())
}

fn cmd_secret_add(
    storage: SecretsStorage<'_>,
    scope: String,
    name: String,
    value: String,
) -> Result<()> {
    let plaintext = load_value(&value)?;
    let (secret, recipient_count) = storage.update("secrets: secret add", |_, loaded| {
        let scope = resolve_scope(&loaded.view.reader, &loaded.catalog, &scope)?;
        let sealed = seal_version(
            &loaded.view.reader,
            &loaded.catalog,
            scope,
            &name,
            &plaintext,
            point_interval(now_epoch()?),
        )?;
        Ok((
            Some(sealed.fragment),
            (sealed.secret, sealed.recipient_count),
        ))
    })?;
    println!(
        "secret {} ({name}) sealed to {} recipient(s)",
        fmt_id(secret),
        recipient_count
    );
    Ok(())
}

fn cmd_secret_get(
    storage: SecretsStorage<'_>,
    scope: String,
    name: String,
    as_identity: Option<String>,
) -> Result<()> {
    let plaintext = storage.with_view(|loaded| {
        let scope = resolve_scope(&loaded.view.reader, &loaded.catalog, &scope)?;
        let secret = loaded
            .catalog
            .latest_secret(scope, &name)?
            .ok_or_else(|| anyhow!("no secret named '{name}' in that scope"))?;
        let identity = loaded.acting_identity(as_identity.as_deref())?;
        let identity_secret = loaded.identity_secret(identity)?;
        open_version(
            &loaded.view.reader,
            &loaded.catalog,
            secret,
            identity,
            &identity_secret,
        )
    })?;
    std::io::stdout().write_all(&plaintext)?;
    Ok(())
}

fn cmd_secret_rotate(storage: SecretsStorage<'_>, scope: Option<String>) -> Result<()> {
    storage.with_view(|loaded| {
        let scope_filter = scope
            .as_deref()
            .map(|value| resolve_scope(&loaded.view.reader, &loaded.catalog, value))
            .transpose()?;
        let credentials: BTreeSet<(Id, String)> = loaded
            .catalog
            .secrets
            .values()
            .filter(|row| scope_filter.is_none_or(|scope| row.scope == scope))
            .map(|row| (row.scope, row.name.clone()))
            .collect();

        let mut findings = Vec::new();
        for (scope, name) in credentials {
            let Some(latest) = loaded.catalog.latest_secret(scope, &name)? else {
                continue;
            };
            let current: HashSet<Id> = loaded.catalog.recipients_of(scope).into_iter().collect();
            let exposed: Vec<Id> = loaded
                .catalog
                .wrap_holders(latest)
                .into_iter()
                .filter(|holder| !current.contains(holder))
                .collect();
            if !exposed.is_empty() {
                findings.push((scope, name, exposed));
            }
        }
        if findings.is_empty() {
            println!("✓ no secrets are exposed to removed users — nothing to rotate");
            return Ok(());
        }
        println!(
            "{} secret(s) remain readable by a removed user. Change each credential\n\
             at its source, then add the new value as another version:\n",
            findings.len()
        );
        for (scope, name, exposed) in findings {
            let scope_name = entity_name(&loaded.view.reader, &loaded.catalog, scope)?;
            let exposed = exposed
                .into_iter()
                .map(|id| entity_name(&loaded.view.reader, &loaded.catalog, id))
                .collect::<Result<Vec<_>>>()?;
            println!(
                "  {scope_name}/{name}  →  exposed to: {}",
                exposed.join(", ")
            );
        }
        Ok(())
    })
}

fn cmd_secret_share(
    storage: SecretsStorage<'_>,
    scope: String,
    name: String,
    as_identity: Option<String>,
) -> Result<()> {
    let new_recipient_count = storage.update("secrets: secret share", |_, loaded| {
        let scope = resolve_scope(&loaded.view.reader, &loaded.catalog, &scope)?;
        let secret = loaded
            .catalog
            .latest_secret(scope, &name)?
            .ok_or_else(|| anyhow!("no secret named '{name}' in that scope"))?;
        let identity = loaded.acting_identity(as_identity.as_deref())?;
        let identity_secret = loaded.identity_secret(identity)?;
        let shared = share_version(
            &loaded.view.reader,
            &loaded.catalog,
            secret,
            identity,
            &identity_secret,
            point_interval(now_epoch()?),
        )?;
        let fragment = (shared.new_recipient_count != 0).then_some(shared.fragment);
        Ok((fragment, shared.new_recipient_count))
    })?;
    if new_recipient_count == 0 {
        println!("already shared to all current recipients");
        return Ok(());
    }
    println!("shared to {new_recipient_count} new recipient(s)");
    Ok(())
}

fn cmd_secret_list(storage: SecretsStorage<'_>) -> Result<()> {
    storage.with_view(|loaded| {
        let credentials: BTreeSet<_> = loaded
            .catalog
            .secrets
            .values()
            .map(|row| (row.scope, row.name.clone()))
            .collect();
        if credentials.is_empty() {
            println!("(no secrets)");
            return Ok(());
        }
        for (scope, name) in credentials {
            let versions = loaded.catalog.secret_versions(scope, &name);
            let recipients = loaded.catalog.recipients_of(scope).len();
            println!(
                "{name}  scope {}  (v{versions}, {recipients} recipient(s))",
                fmt_id(scope)
            );
        }
        Ok(())
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let storage = SecretsStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
    };
    match cli.command {
        Command::Selftest => cmd_selftest(),
        Command::Identity { cmd } => match cmd {
            IdentityCmd::Init { nickname } => cmd_identity_init(storage, nickname),
            IdentityCmd::List => cmd_identity_list(storage),
        },
        Command::Scope { cmd } => match cmd {
            ScopeCmd::Create { name, r#as } => cmd_scope_create(storage, name, r#as),
            ScopeCmd::List => cmd_scope_list(storage),
            ScopeCmd::Members { scope } => cmd_scope_members(storage, scope),
        },
        Command::Grant {
            object,
            relation,
            subject,
            r#as,
        } => cmd_grant(storage, object, relation, subject, r#as),
        Command::Revoke { object, subject } => cmd_revoke(storage, object, subject),
        Command::Node { cmd } => match cmd {
            NodeCmd::List => cmd_node_list(storage),
            NodeCmd::Adopt { nickname, key } => cmd_node_adopt(storage, nickname, key),
        },
        Command::Secret { cmd } => match cmd {
            SecretCmd::Add { scope, name, value } => cmd_secret_add(storage, scope, name, value),
            SecretCmd::Get { scope, name, r#as } => cmd_secret_get(storage, scope, name, r#as),
            SecretCmd::Rotate { scope } => cmd_secret_rotate(storage, scope),
            SecretCmd::Share { scope, name, r#as } => cmd_secret_share(storage, scope, name, r#as),
            SecretCmd::List => cmd_secret_list(storage),
        },
    }
}
