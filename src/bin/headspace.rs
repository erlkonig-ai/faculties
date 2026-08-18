//! headspace — fork-visible agent configuration backed by exact Secrets versions.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use faculties::storage::{load_signer, open_pile_strict};
use faculties::headspace::{self, Catalog, ConfigValue, OpenedSecrets, ProfileValue, Resolution};
use faculties::schemas::headspace::DEFAULT_SCOPE_ID;
use faculties::secrets::{self as secrets_model, schema as secrets_schema, SecretsCatalog};
use hifitime::Epoch;
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::prelude::*;
use faculties::legacy_hint::open_scope;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "headspace",
    bin_name = "headspace",
    about = "Manage fork-visible Headspace configuration and model profiles."
)]
struct Cli {
    /// Existing pile file. Reads and writes never create it.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable collection signer. Ordinary commands never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Secrets identity used only when decrypting exact credential versions.
    #[arg(long, env = "SECRETS_IDENTITY")]
    secrets_identity: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Show the resolved active Headspace and available profiles.
    Show {
        /// Decrypt the exact referenced credential versions.
        #[arg(long, default_value_t = false)]
        show_secrets: bool,
    },
    /// List profile anchors and their current resolution.
    List,
    /// Switch the active profile by anchor id or settled profile name.
    Use {
        #[arg(value_name = "PROFILE")]
        profile: String,
    },
    /// Author a fresh profile anchor and activate it in one signed COMMIT.
    Add(AddArgs),
    /// Set one non-secret field on the resolved active profile.
    Set {
        #[arg(value_enum, value_name = "FIELD")]
        field: SetField,
        #[arg(value_name = "VALUE", help = "Literal value, @path, or @- for stdin.")]
        value: String,
    },
    /// Clear one optional non-secret field on the active profile.
    Unset {
        #[arg(value_enum, value_name = "FIELD")]
        field: UnsetField,
    },
    /// Manage an exact immutable Secrets reference.
    Secret {
        #[arg(value_enum)]
        role: SecretRole,
        #[command(subcommand)]
        command: SecretCommand,
    },
    /// Choose an existing complete snapshot and join every live head on its track.
    Reconcile {
        #[arg(value_name = "SNAPSHOT")]
        snapshot: String,
    },
}

#[derive(Args)]
struct AddArgs {
    #[arg(value_name = "NAME")]
    name: String,
    #[arg(long)]
    model: Option<String>,
    #[arg(long = "base-url")]
    base_url: Option<String>,
    /// Exact existing Secrets version for the new profile's model credential.
    #[arg(long)]
    model_secret_version: Option<String>,
    #[arg(long = "reasoning-effort")]
    reasoning_effort: Option<String>,
    #[arg(long)]
    stream: Option<bool>,
    #[arg(long = "context-window-tokens")]
    context_window_tokens: Option<u64>,
    #[arg(long = "max-output-tokens")]
    max_output_tokens: Option<u64>,
    #[arg(long = "prompt-safety-margin-tokens")]
    context_safety_margin_tokens: Option<u64>,
    #[arg(long = "prompt-chars-per-token")]
    chars_per_token: Option<u64>,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
#[value(rename_all = "kebab-case")]
enum SetField {
    Model,
    BaseUrl,
    ReasoningEffort,
    Stream,
    ContextWindowTokens,
    MaxOutputTokens,
    PromptSafetyMarginTokens,
    PromptCharsPerToken,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
#[value(rename_all = "kebab-case")]
enum UnsetField {
    ReasoningEffort,
}

#[derive(ValueEnum, Debug, Clone, Copy, Eq, PartialEq)]
#[value(rename_all = "kebab-case")]
enum SecretRole {
    Model,
    Tavily,
    Exa,
}

#[derive(Subcommand)]
enum SecretCommand {
    /// Point the role at an exact existing version, or seal one version first.
    Set(SecretSetArgs),
    /// Remove the role's exact credential reference in a complete successor.
    Unset,
}

#[derive(Args)]
struct SecretSetArgs {
    /// Plaintext credential as a literal, @path, or @-.
    #[arg(long, conflicts_with = "version", required_unless_present = "version")]
    value: Option<String>,
    /// Exact existing Secrets version. This repairs an interrupted Secrets-first update.
    #[arg(long, conflicts_with = "value", required_unless_present = "value")]
    version: Option<String>,
    /// Secrets scope receiving a newly sealed value. An existing unique
    /// reference defaults to its version's scope.
    #[arg(long, conflicts_with = "version")]
    secret_scope: Option<String>,
}

struct CollectionView {
    facts: TribleSet,
    reader: PileReader,
}

struct Views {
    headspace: CollectionView,
    catalog: Catalog,
    secrets: CollectionView,
    secrets_catalog: SecretsCatalog,
}

struct Storage<'a> {
    pile_path: &'a Path,
    pile: RefCell<Option<Pile>>,
    signer: SigningKey,
    secrets_identity: Option<&'a str>,
}

impl Storage<'_> {
    fn open<'a>(
        pile_path: &'a Path,
        key: Option<&Path>,
        secrets_identity: Option<&'a str>,
    ) -> Result<Storage<'a>> {
        // Authority is resolved before touching storage. A missing signer can
        // neither create a pile nor append a descriptor.
        let signer = load_signer(pile_path, key)?;
        let pile = open_pile_strict(pile_path)?;
        Ok(Storage {
            pile_path,
            pile: RefCell::new(Some(pile)),
            signer,
            secrets_identity,
        })
    }

    fn materialize(&self, scope: Id, label: &str) -> Result<CollectionView> {
        let mut pile = self.pile.borrow_mut();
        let pile = pile
            .as_mut()
            .ok_or_else(|| anyhow!("Headspace storage is already closed"))?;
        let facts = open_scope(&mut *pile, scope, self.signer.clone())
            .materialize()
            .with_context(|| format!("materialize {label} collection"))?;
        let reader = pile
            .reader()
            .with_context(|| format!("open {label} attachment reader"))?;
        Ok(CollectionView { facts, reader })
    }

    fn views(&self) -> Result<Views> {
        let secrets = self.materialize(secrets_schema::DEFAULT_SCOPE_ID, "Secrets")?;
        let secrets_catalog = secrets_model::validate_catalog(&secrets.reader, &secrets.facts)
            .context("validate Secrets collection")?;
        let headspace = self.materialize(DEFAULT_SCOPE_ID, "Headspace")?;
        let catalog = headspace::project_result(&headspace.reader, &headspace.facts)
            .context("validate Headspace collection")?;
        headspace::validate_secret_references(&catalog, &secrets_catalog)
            .context("validate exact Headspace credential references")?;
        Ok(Views {
            headspace,
            catalog,
            secrets,
            secrets_catalog,
        })
    }

    fn publish(&self, scope: Id, mut fragment: Fragment, description: &str) -> Result<()> {
        fragment.describe_with(entity! { metadata::description: description.to_owned() });
        let mut pile = self.pile.borrow_mut();
        let pile = pile
            .as_mut()
            .ok_or_else(|| anyhow!("Headspace storage is already closed"))?;
        open_scope(&mut *pile, scope, self.signer.clone())
            .commit(fragment)
            .with_context(|| format!("commit collection {scope:x}"))?;
        Ok(())
    }

    fn close(self) -> Result<()> {
        self.close_inner()
    }

    fn close_inner(&self) -> Result<()> {
        let Some(pile) = self.pile.borrow_mut().take() else {
            return Ok(());
        };
        pile.close()
            .with_context(|| format!("close Headspace pile {}", self.pile_path.display()))
    }
}

impl Drop for Storage<'_> {
    fn drop(&mut self) {
        let _ = self.close_inner();
    }
}

fn main() -> Result<()> {
    run(Cli::parse())
}

fn run(cli: Cli) -> Result<()> {
    let Some(command) = cli.command.as_ref() else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };

    let storage = Storage::open(
        &cli.pile,
        cli.key.as_deref(),
        cli.secrets_identity.as_deref(),
    )?;
    let result = dispatch(&storage, command);
    let close = storage.close();
    match (result, close) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing Headspace storage also failed: {close_error}"
        ))),
    }
}

fn dispatch(storage: &Storage<'_>, command: &Command) -> Result<()> {
    match command {
        Command::Show { show_secrets } => {
            let views = storage.views()?;
            let opened = if *show_secrets {
                open_display_secrets(storage, &views)?
            } else {
                None
            };
            print_headspace(&views.catalog, opened.as_ref())
        }
        Command::List => print_profile_list(&storage.views()?.catalog),
        Command::Use { profile } => use_profile(storage, profile),
        Command::Add(args) => add_profile(storage, args),
        Command::Set { field, value } => set_profile_field(storage, *field, value),
        Command::Unset { field } => unset_profile_field(storage, *field),
        Command::Secret { role, command } => match command {
            SecretCommand::Set(args) => set_secret(storage, *role, args),
            SecretCommand::Unset => unset_secret(storage, *role),
        },
        Command::Reconcile { snapshot } => reconcile(storage, snapshot),
    }
}

fn settled_config(catalog: &Catalog) -> Result<Option<&ConfigValue>> {
    catalog.config.settled_value("Headspace config")
}

fn require_profile(catalog: &Catalog, anchor: Id) -> Result<&ProfileValue> {
    catalog
        .profiles
        .get(&anchor)
        .ok_or_else(|| anyhow!("unknown profile {anchor:x}"))?
        .settled_value(&format!("profile {anchor:x}"))?
        .ok_or_else(|| anyhow!("profile {anchor:x} has no snapshot"))
}

fn resolve_profile_selector(catalog: &Catalog, raw: &str) -> Result<Id> {
    if let Some(id) = Id::from_hex(raw.trim()) {
        if catalog.profiles.contains_key(&id) {
            return Ok(id);
        }
        bail!("unknown profile {id:x}");
    }
    let needle = raw.trim().to_ascii_lowercase();
    let mut matches = Vec::new();
    for (&anchor, resolution) in &catalog.profiles {
        let profile = match resolution {
            Resolution::Unique(snapshot) => Some(&snapshot.value),
            Resolution::Agreed(snapshots) => snapshots.first().map(|snapshot| &snapshot.value),
            Resolution::Missing | Resolution::Forked(_) | Resolution::Invalid(_) => None,
        };
        if profile.is_some_and(|profile| profile.name.to_ascii_lowercase() == needle) {
            matches.push(anchor);
        }
    }
    match matches.as_slice() {
        [] => bail!("unknown profile {raw:?}"),
        [id] => Ok(*id),
        _ => bail!("profile name {raw:?} is ambiguous; use the full anchor id"),
    }
}

fn parse_exact_secret(views: &Views, raw: &str, label: &str) -> Result<Id> {
    let id = Id::from_hex(raw.trim())
        .ok_or_else(|| anyhow!("{label} requires one exact 32-hex Secrets version id"))?;
    if !views.secrets_catalog.secrets.contains_key(&id) {
        bail!("unknown exact Secrets version {id:x}");
    }
    Ok(id)
}

fn preflight_headspace(
    views: &Views,
    fragment: &Fragment,
    secrets: &SecretsCatalog,
) -> Result<Catalog> {
    let candidate = headspace::validate_catalog_union(
        &views.headspace.reader,
        &views.headspace.facts,
        fragment,
    )
    .context("validate Headspace successor")?;
    headspace::validate_secret_references(&candidate, secrets)
        .context("validate successor's exact Secrets references")?;
    Ok(candidate)
}

fn publish_headspace(
    storage: &Storage<'_>,
    views: &Views,
    fragment: Fragment,
    description: &str,
) -> Result<()> {
    preflight_headspace(views, &fragment, &views.secrets_catalog)?;
    storage.publish(DEFAULT_SCOPE_ID, fragment, description)
}

fn use_profile(storage: &Storage<'_>, selector: &str) -> Result<()> {
    let views = storage.views()?;
    let anchor = resolve_profile_selector(&views.catalog, selector)?;
    require_profile(&views.catalog, anchor)?;
    let existing = settled_config(&views.catalog)?;
    if existing.is_some_and(|config| config.active_profile == anchor) {
        return print_headspace(&views.catalog, None);
    }
    let mut config = existing
        .cloned()
        .unwrap_or_else(|| headspace::default_config(anchor));
    config.active_profile = anchor;
    let fragment =
        headspace::config_snapshot_fragment(&config, &views.catalog.config.head_ids())?.0;
    publish_headspace(
        storage,
        &views,
        fragment,
        "headspace: switch active profile",
    )?;
    print_reloaded(storage)
}

fn add_profile(storage: &Storage<'_>, args: &AddArgs) -> Result<()> {
    let views = storage.views()?;
    let anchor = genid().id;
    let mut profile = match settled_config(&views.catalog)? {
        Some(config) => require_profile(&views.catalog, config.active_profile)?.clone(),
        None => headspace::default_profile(anchor, args.name.clone()),
    };
    profile.anchor = anchor;
    profile.name = args.name.clone();
    if let Some(value) = args.model.as_deref() {
        profile.model = value.to_owned();
    }
    if let Some(value) = args.base_url.as_deref() {
        profile.base_url = value.to_owned();
    }
    if let Some(value) = args.model_secret_version.as_deref() {
        profile.model_secret_version =
            Some(parse_exact_secret(&views, value, "--model-secret-version")?);
    }
    if let Some(value) = args.reasoning_effort.as_deref() {
        profile.reasoning_effort = Some(value.trim().to_owned());
    }
    if let Some(value) = args.stream {
        profile.stream = value;
    }
    if let Some(value) = args.context_window_tokens {
        profile.context_window_tokens = value;
    }
    if let Some(value) = args.max_output_tokens {
        profile.max_output_tokens = value;
    }
    if let Some(value) = args.context_safety_margin_tokens {
        profile.context_safety_margin_tokens = value;
    }
    if let Some(value) = args.chars_per_token {
        profile.chars_per_token = value;
    }

    let mut config = settled_config(&views.catalog)?
        .cloned()
        .unwrap_or_else(|| headspace::default_config(anchor));
    config.active_profile = anchor;
    let fragment =
        headspace::add_profile_fragment(&profile, &config, &views.catalog.config.head_ids())?.0;
    publish_headspace(
        storage,
        &views,
        fragment,
        "headspace: add and activate profile",
    )?;
    print_reloaded(storage)
}

fn set_profile_field(storage: &Storage<'_>, field: SetField, raw: &str) -> Result<()> {
    let views = storage.views()?;
    let config = settled_config(&views.catalog)?
        .ok_or_else(|| anyhow!("Headspace has no active configuration; add a profile first"))?;
    let current = require_profile(&views.catalog, config.active_profile)?;
    let mut changed = current.clone();
    match field {
        SetField::Model => changed.model = faculties::text_arg(raw, "model name")?,
        SetField::BaseUrl => changed.base_url = faculties::text_arg(raw, "model base URL")?,
        SetField::ReasoningEffort => {
            changed.reasoning_effort = Some(
                faculties::text_arg(raw, "model reasoning effort")?
                    .trim()
                    .to_owned(),
            )
        }
        SetField::Stream => changed.stream = parse_bool(raw, "model_stream")?,
        SetField::ContextWindowTokens => {
            changed.context_window_tokens = parse_u64(raw, "model_context_window_tokens")?
        }
        SetField::MaxOutputTokens => {
            changed.max_output_tokens = parse_u64(raw, "model_max_output_tokens")?
        }
        SetField::PromptSafetyMarginTokens => {
            changed.context_safety_margin_tokens =
                parse_u64(raw, "model_context_safety_margin_tokens")?
        }
        SetField::PromptCharsPerToken => {
            changed.chars_per_token = parse_u64(raw, "model_chars_per_token")?
        }
    }
    if changed == *current {
        return print_headspace(&views.catalog, None);
    }
    let fragment = headspace::profile_snapshot_fragment(
        &changed,
        &views.catalog.profiles[&config.active_profile].head_ids(),
    )?
    .0;
    publish_headspace(storage, &views, fragment, "headspace: update profile")?;
    print_reloaded(storage)
}

fn unset_profile_field(storage: &Storage<'_>, field: UnsetField) -> Result<()> {
    let views = storage.views()?;
    let config = settled_config(&views.catalog)?
        .ok_or_else(|| anyhow!("Headspace has no active configuration; add a profile first"))?;
    let current = require_profile(&views.catalog, config.active_profile)?;
    let mut changed = current.clone();
    match field {
        UnsetField::ReasoningEffort => changed.reasoning_effort = None,
    }
    if changed == *current {
        return print_headspace(&views.catalog, None);
    }
    let fragment = headspace::profile_snapshot_fragment(
        &changed,
        &views.catalog.profiles[&config.active_profile].head_ids(),
    )?
    .0;
    publish_headspace(storage, &views, fragment, "headspace: unset profile field")?;
    print_reloaded(storage)
}

fn secret_label(role: SecretRole, profile: Id) -> String {
    match role {
        SecretRole::Model => format!("hs/model/{}", URL_SAFE_NO_PAD.encode(profile.raw())),
        SecretRole::Tavily => "hs/tavily".to_owned(),
        SecretRole::Exa => "hs/exa".to_owned(),
    }
}

fn point_now() -> Result<secrets_model::IntervalValue> {
    let now = Epoch::now().map_err(|error| anyhow!("read current clock: {error:?}"))?;
    (now, now)
        .try_to_inline()
        .map_err(|error| anyhow!("encode current clock: {error:?}"))
}

struct SecretSuccessor {
    fragment: Fragment,
    current: Option<Id>,
}

fn secret_successor(
    catalog: &Catalog,
    role: SecretRole,
    replacement: Option<Id>,
) -> Result<SecretSuccessor> {
    let (config, profile) = headspace::settled_active(catalog)?;
    match role {
        SecretRole::Model => {
            let mut changed = profile.clone();
            let current = changed.model_secret_version;
            changed.model_secret_version = replacement;
            Ok(SecretSuccessor {
                fragment: headspace::profile_snapshot_fragment(
                    &changed,
                    &catalog.profiles[&config.active_profile].head_ids(),
                )?
                .0,
                current,
            })
        }
        SecretRole::Tavily | SecretRole::Exa => {
            let mut changed = config.clone();
            let current = match role {
                SecretRole::Tavily => changed.tavily_secret_version,
                SecretRole::Exa => changed.exa_secret_version,
                SecretRole::Model => unreachable!(),
            };
            match role {
                SecretRole::Tavily => changed.tavily_secret_version = replacement,
                SecretRole::Exa => changed.exa_secret_version = replacement,
                SecretRole::Model => unreachable!(),
            }
            Ok(SecretSuccessor {
                fragment: headspace::config_snapshot_fragment(
                    &changed,
                    &catalog.config.head_ids(),
                )?
                .0,
                current,
            })
        }
    }
}

fn set_secret(storage: &Storage<'_>, role: SecretRole, args: &SecretSetArgs) -> Result<()> {
    let mut views = storage.views()?;
    let current = secret_successor(&views.catalog, role, None)?.current;
    let explicit = args
        .version
        .as_deref()
        .map(|value| parse_exact_secret(&views, value, "--version"))
        .transpose()?;

    let (secret, staged) = match (args.value.as_deref(), explicit) {
        (None, Some(secret)) => (secret, None),
        (Some(raw), None) => {
            let plaintext = faculties::text_arg(raw, "credential")?;
            let plaintext = plaintext.trim();
            if plaintext.is_empty() || plaintext.bytes().any(|byte| byte == 0) {
                bail!("credential is empty or contains NUL");
            }
            let scope = match args.secret_scope.as_deref() {
                Some(selector) => secrets_model::resolve_scope(
                    &views.secrets.reader,
                    &views.secrets_catalog,
                    selector,
                )?,
                None => current
                    .and_then(|id| views.secrets_catalog.secrets.get(&id))
                    .map(|row| row.scope)
                    .ok_or_else(|| {
                        anyhow!(
                            "--secret-scope is required when the role has no unique predecessor version"
                        )
                    })?,
            };
            let profile = headspace::settled_active(&views.catalog)?.0.active_profile;
            let sealed = secrets_model::seal_version(
                &views.secrets.reader,
                &views.secrets_catalog,
                scope,
                &secret_label(role, profile),
                plaintext.as_bytes(),
                point_now()?,
            )
            .context("seal Headspace credential version")?;
            let secret = sealed.secret;
            let candidate = secrets_model::validate_candidate(
                &views.secrets.reader,
                &views.secrets.facts,
                &sealed.fragment,
            )
            .context("validate staged Headspace credential")?;
            (secret, Some((sealed.fragment, candidate)))
        }
        _ => unreachable!("clap requires exactly one of --value or --version"),
    };

    if current == Some(secret) && staged.is_none() {
        println!("{role:?} already references exact Secrets version {secret:x}");
        return Ok(());
    }

    let successor = secret_successor(&views.catalog, role, Some(secret))?;
    let candidate_secrets = staged
        .as_ref()
        .map(|(_, catalog)| catalog)
        .unwrap_or(&views.secrets_catalog);
    preflight_headspace(&views, &successor.fragment, candidate_secrets)?;

    if let Some((secret_fragment, _)) = staged {
        storage.publish(
            secrets_schema::DEFAULT_SCOPE_ID,
            secret_fragment,
            "headspace: credential version",
        )?;
        eprintln!(
            "Published exact credential {secret:x}; if Headspace publication is interrupted, retry with: headspace secret {} set --version {secret:x}",
            role_name(role)
        );
        // Refresh through the same open pile before authoring the referencing
        // edge. Failure leaves a harmless orphan version, never a dangling
        // Headspace snapshot.
        views = storage.views()?;
        if !views.secrets_catalog.secrets.contains_key(&secret) {
            bail!("published exact Secrets version {secret:x} did not materialize");
        }
        let repaired = secret_successor(&views.catalog, role, Some(secret))?;
        preflight_headspace(&views, &repaired.fragment, &views.secrets_catalog)?;
        storage.publish(
            DEFAULT_SCOPE_ID,
            repaired.fragment,
            "headspace: exact credential reference",
        )?;
    } else {
        storage.publish(
            DEFAULT_SCOPE_ID,
            successor.fragment,
            "headspace: exact credential reference",
        )?;
    }
    println!("{role:?} credential version {secret:x}");
    Ok(())
}

fn unset_secret(storage: &Storage<'_>, role: SecretRole) -> Result<()> {
    let views = storage.views()?;
    let successor = secret_successor(&views.catalog, role, None)?;
    if successor.current.is_none() {
        println!("{role:?} credential is already unset");
        return Ok(());
    }
    publish_headspace(
        storage,
        &views,
        successor.fragment,
        "headspace: unset exact credential reference",
    )?;
    println!("{role:?} credential unset");
    Ok(())
}

fn role_name(role: SecretRole) -> &'static str {
    match role {
        SecretRole::Model => "model",
        SecretRole::Tavily => "tavily",
        SecretRole::Exa => "exa",
    }
}

fn reconcile(storage: &Storage<'_>, raw: &str) -> Result<()> {
    let views = storage.views()?;
    let chosen = faculties::resolve_id_prefix(raw, views.catalog.snapshot_ids())?;
    let Some((fragment, _)) = views.catalog.reconcile_fragment(chosen)? else {
        return print_headspace(&views.catalog, None);
    };
    publish_headspace(
        storage,
        &views,
        fragment,
        "headspace: reconcile snapshot track",
    )?;
    print_reloaded(storage)
}

fn resolve_secrets_identity(storage: &Storage<'_>, views: &Views) -> Result<Id> {
    let selector = match storage.secrets_identity {
        Some(value) => value.to_owned(),
        None => std::env::var("PERSONA")
            .context("set --secrets-identity/SECRETS_IDENTITY when it differs from PERSONA")?,
    };
    secrets_model::resolve_identity(&views.secrets.reader, &views.secrets_catalog, &selector)
        .with_context(|| format!("resolve Secrets identity {selector:?}"))
}

fn open_display_secrets(storage: &Storage<'_>, views: &Views) -> Result<Option<OpenedSecrets>> {
    let (config, profile) = match headspace::settled_active(&views.catalog) {
        Ok(value) => value,
        Err(_) if matches!(views.catalog.config, Resolution::Missing) => return Ok(None),
        Err(error) => return Err(error),
    };
    if profile.model_secret_version.is_none()
        && config.tavily_secret_version.is_none()
        && config.exa_secret_version.is_none()
    {
        return Ok(None);
    }
    let identity = resolve_secrets_identity(storage, views)?;
    let password = faculties::secrets::password::read("unlock the selected Secrets identity")?;
    headspace::open_active_secrets(
        &views.catalog,
        &views.secrets.reader,
        &views.secrets_catalog,
        identity,
        &password,
    )
    .map(Some)
}

fn print_reloaded(storage: &Storage<'_>) -> Result<()> {
    let views = storage.views()?;
    print_headspace(&views.catalog, None)
}

fn print_headspace(catalog: &Catalog, opened: Option<&OpenedSecrets>) -> Result<()> {
    println!("active:");
    let Some(config) = settled_config(catalog)? else {
        let profile = headspace::default_profile(Id::new([1; 16]).unwrap(), "default");
        print_profile(None, &profile, None);
        println!("  tavily_secret_version = null");
        println!("  tavily_api_key = null");
        println!("  exa_secret_version = null");
        println!("  exa_api_key = null");
        println!();
        println!("profiles:");
        return print_profile_list(catalog);
    };
    let profile = require_profile(catalog, config.active_profile)?;
    print_profile(
        Some(config.active_profile),
        profile,
        opened.and_then(|value| value.model_api_key.as_deref()),
    );
    print_secret_line(
        "tavily",
        config.tavily_secret_version,
        opened.and_then(|value| value.tavily_api_key.as_deref()),
    );
    print_secret_line(
        "exa",
        config.exa_secret_version,
        opened.and_then(|value| value.exa_api_key.as_deref()),
    );
    println!();
    println!("profiles:");
    print_profile_list(catalog)
}

fn print_profile(anchor: Option<Id>, profile: &ProfileValue, opened: Option<&str>) {
    println!(
        "  profile_id = {}",
        anchor
            .map(|id| format!("\"{id:x}\""))
            .unwrap_or_else(|| "null".to_owned())
    );
    println!("  profile_name = \"{}\"", profile.name);
    println!("  model = \"{}\"", profile.model);
    println!("  base_url = \"{}\"", profile.base_url);
    print_secret_line("model", profile.model_secret_version, opened);
    println!(
        "  reasoning_effort = {}",
        profile
            .reasoning_effort
            .as_deref()
            .map(|value| format!("\"{value}\""))
            .unwrap_or_else(|| "null".to_owned())
    );
    println!("  stream = {}", profile.stream);
    println!(
        "  context_window_tokens = {}",
        profile.context_window_tokens
    );
    println!("  max_output_tokens = {}", profile.max_output_tokens);
    println!(
        "  context_safety_margin_tokens = {}",
        profile.context_safety_margin_tokens
    );
    println!("  chars_per_token = {}", profile.chars_per_token);
}

fn print_secret_line(role: &str, version: Option<Id>, opened: Option<&str>) {
    println!(
        "  {role}_secret_version = {}",
        version
            .map(|id| format!("\"{id:x}\""))
            .unwrap_or_else(|| "null".to_owned())
    );
    println!(
        "  {role}_api_key = {}",
        match (version, opened) {
            (None, _) => "null".to_owned(),
            (Some(_), Some(value)) => format!("\"{value}\""),
            (Some(_), None) => "\"<redacted>\"".to_owned(),
        }
    );
}

fn print_profile_list(catalog: &Catalog) -> Result<()> {
    let active = match &catalog.config {
        Resolution::Unique(snapshot) => Some(snapshot.value.active_profile),
        Resolution::Agreed(snapshots) => snapshots
            .first()
            .map(|snapshot| snapshot.value.active_profile),
        Resolution::Missing | Resolution::Forked(_) | Resolution::Invalid(_) => None,
    };
    match &catalog.config {
        Resolution::Missing => println!("config\t<missing>"),
        Resolution::Unique(snapshot) => println!(
            "config\t{:x}\tactive={:x}",
            snapshot.id, snapshot.value.active_profile
        ),
        Resolution::Agreed(snapshots) => println!(
            "config\t<agreed:{}>\theads={}",
            snapshots.len(),
            format_snapshot_ids(snapshots.iter().map(|snapshot| snapshot.id))
        ),
        Resolution::Forked(snapshots) => {
            println!(
                "config\t<forked:{}>\theads={}",
                snapshots.len(),
                format_snapshot_ids(snapshots.iter().map(|snapshot| snapshot.id))
            );
            for snapshot in snapshots {
                println!(
                    "  head\t{:x}\tactive={:x}",
                    snapshot.id, snapshot.value.active_profile
                );
            }
        }
        Resolution::Invalid(error) => println!("config\t<invalid>\t{error}"),
    }

    let mut rows = Vec::new();
    for (&anchor, resolution) in &catalog.profiles {
        let marker = if active == Some(anchor) { '*' } else { ' ' };
        match resolution {
            Resolution::Unique(snapshot) => rows.push((
                snapshot.value.name.to_ascii_lowercase(),
                format!(
                    "{marker} {}\t{anchor:x}\tsnapshot={:x}",
                    snapshot.value.name, snapshot.id
                ),
            )),
            Resolution::Agreed(snapshots) => {
                let profile = &snapshots[0].value;
                rows.push((
                    profile.name.to_ascii_lowercase(),
                    format!(
                        "{marker} {}\t{anchor:x}\t[agreed:{}]\theads={}",
                        profile.name,
                        snapshots.len(),
                        format_snapshot_ids(snapshots.iter().map(|snapshot| snapshot.id))
                    ),
                ));
            }
            Resolution::Forked(snapshots) => {
                let names: BTreeSet<_> = snapshots
                    .iter()
                    .map(|snapshot| snapshot.value.name.as_str())
                    .collect();
                rows.push((
                    String::new(),
                    format!(
                        "! <forked:{}>\t{anchor:x}\theads={}\t{}",
                        snapshots.len(),
                        format_snapshot_ids(snapshots.iter().map(|snapshot| snapshot.id)),
                        names.into_iter().collect::<Vec<_>>().join(" | ")
                    ),
                ));
            }
            Resolution::Missing => rows.push((String::new(), format!("! <missing>\t{anchor:x}"))),
            Resolution::Invalid(error) => {
                rows.push((String::new(), format!("! <invalid>\t{anchor:x}\t{error}")))
            }
        }
    }
    rows.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    for (_, row) in rows {
        println!("{row}");
    }
    Ok(())
}

fn format_snapshot_ids(ids: impl IntoIterator<Item = Id>) -> String {
    ids.into_iter()
        .map(|id| format!("{id:x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn parse_u64(raw: &str, label: &str) -> Result<u64> {
    raw.parse::<u64>()
        .map_err(|_| anyhow!("invalid {label} {raw}"))
}

fn parse_bool(raw: &str, label: &str) -> Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => bail!("invalid {label} {raw} (expected true/false)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;

    use faculties::storage::{initialize_signer, open_pile_strict};
    use triblespace::core::repo::BlobStore;

    fn cli(pile: &Path, key: &Path, command: Command) -> Cli {
        Cli {
            pile: pile.to_owned(),
            key: Some(key.to_owned()),
            secrets_identity: None,
            command: Some(command),
        }
    }

    fn add(name: &str) -> Command {
        Command::Add(AddArgs {
            name: name.to_owned(),
            model: None,
            base_url: None,
            model_secret_version: None,
            reasoning_effort: None,
            stream: None,
            context_window_tokens: None,
            max_output_tokens: None,
            context_safety_margin_tokens: None,
            chars_per_token: None,
        })
    }

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("headspace.pile");
        let key = directory.path().join("headspace.key");
        File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        (directory, pile, key)
    }

    fn views<'a>(pile: &'a Path, key: &'a Path) -> (Storage<'a>, Views) {
        let storage = Storage::open(pile, Some(key), None).unwrap();
        let views = storage.views().unwrap();
        (storage, views)
    }

    #[test]
    fn missing_signer_does_not_grow_the_pile() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("headspace.pile");
        File::create(&pile).unwrap();
        let before = std::fs::metadata(&pile).unwrap().len();
        assert!(Storage::open(&pile, None, None).is_err());
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), before);
    }

    #[test]
    fn add_use_and_idempotent_profile_set_advance_only_intended_tracks() {
        let (_directory, pile, key) = fixture();
        run(cli(&pile, &key, add("first"))).unwrap();
        let (storage, first) = views(&pile, &key);
        let first_anchor = settled_config(&first.catalog)
            .unwrap()
            .unwrap()
            .active_profile;
        storage.close().unwrap();

        run(cli(&pile, &key, add("second"))).unwrap();
        run(cli(
            &pile,
            &key,
            Command::Use {
                profile: format!("{first_anchor:x}"),
            },
        ))
        .unwrap();
        run(cli(
            &pile,
            &key,
            Command::Set {
                field: SetField::Model,
                value: "changed".to_owned(),
            },
        ))
        .unwrap();
        let (storage, before) = views(&pile, &key);
        let snapshots = before.catalog.snapshot_ids().len();
        storage.close().unwrap();

        run(cli(
            &pile,
            &key,
            Command::Set {
                field: SetField::Model,
                value: "changed".to_owned(),
            },
        ))
        .unwrap();
        let (storage, after) = views(&pile, &key);
        assert_eq!(after.catalog.snapshot_ids().len(), snapshots);
        storage.close().unwrap();
    }

    #[test]
    fn interrupted_secrets_first_publication_repairs_by_exact_version_id() {
        let (_directory, pile, key) = fixture();
        run(cli(&pile, &key, add("default"))).unwrap();

        let signer = load_signer(&pile, Some(&key)).unwrap();
        let mut store = open_pile_strict(&pile).unwrap();
        let password = b"identity password";
        let identity =
            secrets_model::prepare_identity("me", password, point_now().unwrap()).unwrap();
        let scope_fragment =
            secrets_model::scope_fragment(identity.id, "headspace-test", point_now().unwrap())
                .unwrap();
        let scope = scope_fragment.root().unwrap();
        let mut foundation = identity.fragment;
        foundation += scope_fragment;
        Collection::new(&mut store, secrets_schema::DEFAULT_SCOPE_ID, signer.clone())
            .commit(foundation)
            .unwrap();
        let secrets_facts =
            Collection::new(&mut store, secrets_schema::DEFAULT_SCOPE_ID, signer.clone())
                .materialize()
                .unwrap();
        let reader = store.reader().unwrap();
        let catalog = secrets_model::validate_catalog(&reader, &secrets_facts).unwrap();
        let sealed = secrets_model::seal_version(
            &reader,
            &catalog,
            scope,
            "hs/model/interrupted",
            b"exact",
            point_now().unwrap(),
        )
        .unwrap();
        let version = sealed.secret;
        Collection::new(&mut store, secrets_schema::DEFAULT_SCOPE_ID, signer)
            .commit(sealed.fragment)
            .unwrap();
        store.close().unwrap();

        // Deterministic second half after a crash between collection commits.
        run(cli(
            &pile,
            &key,
            Command::Secret {
                role: SecretRole::Model,
                command: SecretCommand::Set(SecretSetArgs {
                    value: None,
                    version: Some(format!("{version:x}")),
                    secret_scope: None,
                }),
            },
        ))
        .unwrap();
        let (storage, repaired) = views(&pile, &key);
        assert_eq!(repaired.secrets_catalog.secrets.len(), 1);
        let (_, profile) = headspace::settled_active(&repaired.catalog).unwrap();
        assert_eq!(profile.model_secret_version, Some(version));
        storage.close().unwrap();

        run(cli(
            &pile,
            &key,
            Command::Secret {
                role: SecretRole::Model,
                command: SecretCommand::Set(SecretSetArgs {
                    value: None,
                    version: Some(format!("{version:x}")),
                    secret_scope: None,
                }),
            },
        ))
        .unwrap();
        let (storage, replay) = views(&pile, &key);
        assert_eq!(replay.secrets_catalog.secrets.len(), 1);
        assert_eq!(
            headspace::settled_active(&replay.catalog)
                .unwrap()
                .1
                .model_secret_version,
            Some(version)
        );
        storage.close().unwrap();
    }

    #[test]
    fn permanent_cli_exposes_no_collection_scope_branch_head_or_cas_knobs() {
        let command = Cli::command();
        for forbidden in ["scope", "branch", "branch_id", "head", "cas", "repair"] {
            assert!(!command
                .get_arguments()
                .any(|argument| argument.get_id() == forbidden));
        }
        assert!(command
            .get_arguments()
            .any(|argument| argument.get_id() == "key"));
    }
}
