use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration as StdDuration;

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
#[cfg(test)]
use faculties::storage::initialize_signer;
use faculties::storage::{load_signer, open_pile_strict};
use hifitime::{Epoch, TimeScale};
use reqwest::blocking::Client;
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use triblespace::core::blob::Bytes;
use triblespace::core::collection::{Collection, CollectionCommit};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::blobencodings::UTF8String;
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval, ShortString, U256BE};
use triblespace::prelude::*;

use faculties::clock;
use faculties::files as file_capability;
use faculties::legacy_hint::open_scope;
use faculties::schemas::archive::{archive, RawBytes};
use faculties::schemas::teams::{teams, DEFAULT_DELTA_URL, DEFAULT_SCOPE_ID};
use faculties::secrets::{self as secrets_model, storage as secrets_vaults};
use faculties::teams as teams_core;

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, name = "teams", about = "Ingest Microsoft Teams messages into TribleSpace")]
struct Cli {
    /// Path to the pile file.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it;
    /// initialize explicitly with `trible pile signing-key init <pile>`.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Concrete Microsoft Entra tenant used to select a collection auth
    /// profile. It may be omitted only when exactly one profile source exists.
    #[arg(long, env = "TEAMS_TENANT")]
    tenant: Option<String>,
    /// Microsoft Graph delta endpoint.
    #[arg(long, default_value = DEFAULT_DELTA_URL)]
    delta_url: String,
    /// Explicit external presentation identity for Teams mutations.
    #[arg(long = "as", global = true)]
    present_as: Option<String>,
    #[command(subcommand)]
    command: Option<CommandMode>,
}

#[derive(Subcommand)]
enum CommandMode {
    /// Sync from Graph and read messages from the local pile.
    Read {
        /// Teams chat id (external id).
        chat_id: Option<String>,
        /// Only show messages at or after this timestamp (RFC3339 or Graph format).
        #[arg(long)]
        since: Option<String>,
        /// Maximum number of messages to return (0 = no limit).
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Show newest messages first.
        #[arg(long)]
        descending: bool,
    },
    /// Send a message into a Teams chat.
    Send {
        chat_id: String,
        #[arg(help = "Message text. Use @path for file input or @- for stdin.")]
        text: String,
    },
    /// Users directory commands.
    Users {
        #[command(subcommand)]
        command: UsersCommand,
    },
    /// Presence commands.
    Presence {
        #[command(subcommand)]
        command: PresenceCommand,
    },
    /// Chat commands.
    Chat {
        #[command(subcommand)]
        command: ChatCommand,
    },
    /// Attachment commands.
    Attachments {
        #[command(subcommand)]
        command: AttachmentsCommand,
    },
    /// Configure or inspect the professional Teams presentation context.
    Context {
        #[command(subcommand)]
        command: ContextCommand,
    },
    /// Inspect Teams authentication state without printing credentials.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Interactive device-code login that publishes encrypted credential versions.
    Login {
        /// Tenant id or domain (default: common).
        #[arg(long, default_value = "common")]
        tenant: String,
        /// Azure app client id.
        #[arg(long)]
        client_id: String,
        /// Non-argv source for an Azure app client secret to encrypt as a new
        /// Secrets version. Use `@path` or `@-`; alternatively set
        /// `TEAMS_CLIENT_SECRET`.
        #[arg(
            long = "client-secret",
            value_name = "@PATH|@-",
            conflicts_with = "client_secret_version",
            help = "Read the Azure app client secret from @path or @- and encrypt it into the selected Secrets vault epoch. TEAMS_CLIENT_SECRET is the environment alternative."
        )]
        client_secret_source: Option<String>,
        /// Exact existing Secrets version for the app client secret.
        #[arg(long, value_parser = parse_id, conflicts_with = "client_secret_source")]
        client_secret_version: Option<Id>,
        /// Exact ready vault epoch receiving the new delegated-token version
        /// and any newly supplied client secret.
        #[arg(long, value_parser = parse_id)]
        vault: Id,
        /// Space-delimited scopes (defaults to chat + presence + user read + offline_access).
        #[arg(
            long,
            help = "Space-delimited scopes. Use @path for file input or @- for stdin."
        )]
        scopes: Option<String>,
    },
}

#[derive(Subcommand)]
enum ContextCommand {
    /// Set the identity and privacy boundary used for professional Teams work.
    Set {
        /// Name to present externally (for example, Bulti).
        present_as: String,
        /// Work-context reminder shown before Teams activity.
        #[arg(long)]
        boundary: String,
    },
    /// Show the current professional Teams presentation context.
    Show,
}

#[derive(Subcommand)]
enum AuthCommand {
    /// Show safe profile metadata and exact secret-version references.
    Status,
    /// Publish a complete profile from exact existing Secrets versions. This
    /// is also the repair/reconciliation path after an interrupted login.
    Set {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        user_id: String,
        #[arg(long)]
        scopes: String,
        #[arg(long, value_parser = parse_id)]
        client_secret_version: Option<Id>,
        #[arg(long, value_parser = parse_id)]
        delegated_token_version: Option<Id>,
    },
}

#[derive(Subcommand)]
enum UsersCommand {
    /// List directory users by display name prefix.
    List {
        /// Name/email prefix to search for.
        prefix: Option<String>,
        /// Maximum number of users to return (0 = no limit).
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

#[derive(Clone, Debug, ValueEnum)]
enum PresenceAvailability {
    #[value(name = "Available", alias = "available")]
    Available,
    #[value(name = "Busy", alias = "busy")]
    Busy,
    #[value(name = "Away", alias = "away")]
    Away,
    #[value(
        name = "DoNotDisturb",
        alias = "do-not-disturb",
        alias = "donotdisturb",
        alias = "dnd"
    )]
    DoNotDisturb,
}

impl PresenceAvailability {
    fn as_graph(&self) -> &'static str {
        match self {
            PresenceAvailability::Available => "Available",
            PresenceAvailability::Busy => "Busy",
            PresenceAvailability::Away => "Away",
            PresenceAvailability::DoNotDisturb => "DoNotDisturb",
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
enum PresenceActivity {
    #[value(name = "Available", alias = "available")]
    Available,
    #[value(
        name = "InACall",
        alias = "in-a-call",
        alias = "inacall",
        alias = "call"
    )]
    InACall,
    #[value(
        name = "InAConferenceCall",
        alias = "in-a-conference-call",
        alias = "inaconferencecall",
        alias = "conference"
    )]
    InAConferenceCall,
    #[value(name = "Away", alias = "away")]
    Away,
    #[value(name = "Presenting", alias = "presenting")]
    Presenting,
}

impl PresenceActivity {
    fn as_graph(&self) -> &'static str {
        match self {
            PresenceActivity::Available => "Available",
            PresenceActivity::InACall => "InACall",
            PresenceActivity::InAConferenceCall => "InAConferenceCall",
            PresenceActivity::Away => "Away",
            PresenceActivity::Presenting => "Presenting",
        }
    }
}

#[derive(Subcommand)]
enum PresenceCommand {
    /// Set the Teams presence for the logged-in user.
    Set {
        /// Availability (Available, Busy, Away, DoNotDisturb).
        availability: PresenceAvailability,
        /// Activity (Available, InACall, InAConferenceCall, Away, Presenting).
        #[arg(long)]
        activity: Option<PresenceActivity>,
        /// Expiration in minutes (5-240).
        #[arg(long, default_value_t = 60)]
        duration_mins: u32,
        /// Optional session id override (defaults to app client id).
        #[arg(long)]
        session_id: Option<String>,
    },
    /// Get presence for one or more users (by id).
    Get {
        /// One or more user ids to query.
        user_ids: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ChatCommand {
    /// Invite a user into an existing chat.
    Invite {
        chat_id: String,
        user_id: String,
        /// Add as owner.
        #[arg(long)]
        owner: bool,
    },
    /// Create a new chat with users (by id).
    Create {
        /// User ids to include (self is added automatically).
        user_ids: Vec<String>,
        /// Force a group chat even for 1:1.
        #[arg(long)]
        group: bool,
        /// Optional group chat topic.
        #[arg(
            long,
            help = "Optional group chat topic. Use @path for file input or @- for stdin."
        )]
        topic: Option<String>,
    },
}

#[derive(Subcommand)]
enum AttachmentsCommand {
    /// List attachments stored in the pile.
    List {
        /// Filter by Teams chat id (external id).
        #[arg(long)]
        chat_id: Option<String>,
        /// Filter by Teams message id (external id).
        #[arg(long)]
        message_id: Option<String>,
        /// Maximum number of attachments to return (0 = no limit).
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Show newest attachments first.
        #[arg(long)]
        descending: bool,
    },
    /// Export a stored attachment to a local file.
    Export {
        /// Attachment source id (as shown in attachments list).
        source_id: String,
        /// Filter by Teams chat id (external id).
        #[arg(long)]
        chat_id: Option<String>,
        /// Filter by Teams message id (external id).
        #[arg(long)]
        message_id: Option<String>,
        /// Output directory (created if missing).
        out_dir: Option<PathBuf>,
        /// Override filename (defaults to attachment name or source id).
        #[arg(long)]
        filename: Option<String>,
        /// Overwrite if the file already exists.
        #[arg(long)]
        overwrite: bool,
    },
}

#[derive(Clone, Debug)]
struct TeamsCommandConfig {
    pile_path: PathBuf,
    key_path: Option<PathBuf>,
    tenant_selector: Option<String>,
    delta_url: String,
}

#[derive(Clone, Debug)]
struct TeamsBridgeConfig {
    source_id: Id,
    tenant: String,
    client_id: String,
    user_id: String,
    scopes: String,
    profile: Id,
    client_secret_version: Option<Id>,
    delegated_token_version: Option<Id>,
    delta_url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DelegatedTokenBundle {
    access_token: String,
    refresh_token: Option<String>,
    expires_at_unix: i64,
    token_type: Option<String>,
    scope: Option<String>,
}

#[derive(Clone, Copy)]
struct TeamsStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

#[derive(Clone)]
struct CollectionView {
    facts: TribleSet,
    reader: PileReader,
}

struct TeamsSession<'a> {
    collection: &'a mut Collection<Pile>,
    facts: TribleSet,
    reader: PileReader,
    signer: ed25519_dalek::SigningKey,
    secrets: secrets_vaults::VaultDiscovery,
}

impl TeamsSession<'_> {
    fn view(&self) -> CollectionView {
        CollectionView {
            facts: self.facts.clone(),
            reader: self.reader.clone(),
        }
    }

    fn commit(
        &mut self,
        mut fragment: Fragment,
        description: &'static str,
    ) -> Result<Option<CollectionCommit>> {
        validate_candidate(&self.reader, &self.facts, &fragment)?;
        let mut candidate = self.facts.clone();
        candidate += fragment.facts().clone();
        teams_core::validate_auth_secret_references(&candidate, self.secrets.snapshot())?;
        if fragment.facts().difference(&self.facts).is_empty() {
            return Ok(None);
        }
        let added = fragment.facts().clone();
        fragment.describe_with(entity! { metadata::description: description });
        let commit = self
            .collection
            .commit(fragment)
            .context("commit Teams fragment")?;
        self.facts += added;
        self.reader = self
            .collection
            .storage_mut()
            .reader()
            .context("refresh Teams attachment snapshot")?;
        Ok(Some(commit))
    }

    fn refresh_secrets(&mut self) -> Result<()> {
        self.secrets =
            secrets_vaults::discover_local_vaults(self.collection.storage_mut(), &self.signer)
                .context("rediscover Secrets vaults for Teams")?;
        Ok(())
    }

    fn add_secret(
        &mut self,
        vault: Id,
        name: &str,
        plaintext: &[u8],
        observed_at: Inline<NsTAIInterval>,
    ) -> Result<Id> {
        let location = self
            .secrets
            .location(vault)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("vault {vault} is not ready for this node"))?;
        let secret = secrets_vaults::add_secret(
            self.collection.storage_mut(),
            &self.signer,
            &location,
            self.secrets.snapshot(),
            name,
            plaintext,
            observed_at,
        )
        .with_context(|| format!("publish Teams credential in vault {vault}"))?;
        self.refresh_secrets()?;
        if !self.secrets.snapshot().contains(secret) {
            bail!("published Teams Secrets version {secret} was not rediscovered");
        }
        Ok(secret)
    }
}

impl TeamsStorage<'_> {
    fn with_session<T>(
        &self,
        operation: impl FnOnce(&mut TeamsSession<'_>) -> Result<T>,
    ) -> Result<T> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let secrets = secrets_vaults::discover_local_vaults(&mut pile, &signer)
            .context("discover Secrets vaults for Teams")?;
        let mut collection = open_scope(pile, DEFAULT_SCOPE_ID, signer.clone());
        let result = (|| {
            let facts = collection
                .materialize()
                .context("materialize Teams collection")?;
            let reader = collection
                .storage_mut()
                .reader()
                .context("open Teams attachment reader")?;
            validate_catalog(&reader, &facts).context("validate Teams collection")?;
            teams_core::validate_auth_secret_references(&facts, secrets.snapshot())
                .context("validate Teams auth-profile Secrets references")?;
            operation(&mut TeamsSession {
                collection: &mut collection,
                facts,
                reader,
                signer,
                secrets,
            })
        })();
        finish_pile(collection.into_storage(), result)
    }

    #[cfg(test)]
    fn view(&self) -> Result<CollectionView> {
        self.with_session(|session| Ok(session.view()))
    }

    #[cfg(test)]
    fn publish(
        &self,
        fragment: Fragment,
        message: &'static str,
    ) -> Result<Option<CollectionCommit>> {
        self.with_session(|session| session.commit(fragment, message))
    }
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context("close Teams pile")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing Teams pile also failed: {close_error}")))
        }
    }
}

fn main() -> Result<()> {
    let mut cli = Cli::parse();
    let requested_as = cli.present_as.clone();
    let Some(mode) = cli.command.take() else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };

    match mode {
        CommandMode::Read {
            chat_id,
            since,
            limit,
            descending,
        } => {
            let config = build_config(&cli)?;
            with_teams_context(
                &config,
                requested_as.as_deref(),
                false,
                |runtime, session, _| {
                    read_messages(
                        runtime,
                        session,
                        ReadOptions {
                            chat_id,
                            since,
                            limit,
                            descending,
                        },
                    )
                },
            )
        }
        CommandMode::Send { chat_id, text } => {
            let config = build_config(&cli)?;
            let text = faculties::text_arg(&text, "message text")?;
            with_teams_context(
                &config,
                requested_as.as_deref(),
                true,
                |runtime, session, _| send_message(runtime, session, &chat_id, &text),
            )
        }
        CommandMode::Users { command } => {
            let config = build_config(&cli)?;
            with_teams_context(
                &config,
                requested_as.as_deref(),
                false,
                |runtime, session, _| match command {
                    UsersCommand::List { prefix, limit } => {
                        list_users(runtime, session, prefix.as_deref(), limit)
                    }
                },
            )
        }
        CommandMode::Presence { command } => {
            let config = build_config(&cli)?;
            match command {
                PresenceCommand::Set {
                    availability,
                    activity,
                    duration_mins,
                    session_id,
                } => with_teams_context(
                    &config,
                    requested_as.as_deref(),
                    true,
                    |runtime, session, _| {
                        set_presence_status(
                            runtime,
                            session,
                            availability,
                            activity,
                            duration_mins,
                            session_id,
                        )
                    },
                ),
                PresenceCommand::Get { user_ids } => with_teams_context(
                    &config,
                    requested_as.as_deref(),
                    false,
                    |runtime, session, _| get_presence(runtime, session, user_ids),
                ),
            }
        }
        CommandMode::Chat { command } => {
            let config = build_config(&cli)?;
            match command {
                ChatCommand::Invite {
                    chat_id,
                    user_id,
                    owner,
                } => with_teams_context(
                    &config,
                    requested_as.as_deref(),
                    true,
                    |runtime, session, _| {
                        invite_to_chat(runtime, session, &chat_id, &user_id, owner)
                    },
                ),
                ChatCommand::Create {
                    user_ids,
                    group,
                    topic,
                } => {
                    let topic = topic
                        .as_deref()
                        .map(|value| load_value_or_file(value, "chat topic"))
                        .transpose()?;
                    with_teams_context(
                        &config,
                        requested_as.as_deref(),
                        true,
                        |runtime, session, _| create_chat(runtime, session, user_ids, group, topic),
                    )
                }
            }
        }
        CommandMode::Attachments { command } => {
            let config = build_config(&cli)?;
            with_teams_context(
                &config,
                requested_as.as_deref(),
                false,
                |runtime, session, _| match command {
                    AttachmentsCommand::List {
                        chat_id,
                        message_id,
                        limit,
                        descending,
                    } => list_attachments(
                        runtime,
                        session,
                        AttachmentListOptions {
                            chat_id,
                            message_id,
                            limit,
                            descending,
                        },
                    ),
                    AttachmentsCommand::Export {
                        source_id,
                        chat_id,
                        message_id,
                        out_dir,
                        filename,
                        overwrite,
                    } => {
                        let out_dir = out_dir.unwrap_or_else(|| PathBuf::from("./attachments"));
                        export_attachment(
                            runtime,
                            session,
                            AttachmentExportOptions {
                                source_id,
                                chat_id,
                                message_id,
                                out_dir,
                                filename,
                                overwrite,
                            },
                        )
                    }
                },
            )
        }
        CommandMode::Context { command } => {
            let config = build_config(&cli)?;
            match command {
                ContextCommand::Set {
                    present_as,
                    boundary,
                } => storage(&config).with_session(|session| {
                    let source = selected_source(session, config.tenant_selector.as_deref())?;
                    let tenant = config.tenant_selector.as_deref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "`teams context set` requires --tenant for an explicit source identity"
                        )
                    })?;
                    let context = store_context(session, source, tenant, &present_as, &boundary)?;
                    show_context(&context)
                }),
                ContextCommand::Show => storage(&config).with_session(|session| {
                    let source = selected_source(session, config.tenant_selector.as_deref())?;
                    let context = load_context(&session.reader, &session.facts, source)?;
                    show_context(&context)
                }),
            }
        }
        CommandMode::Auth { command } => {
            let config = build_config(&cli)?;
            storage(&config).with_session(|session| match command {
                AuthCommand::Status => {
                    let banner_source = match config.tenant_selector.as_deref() {
                        Some(tenant) => Some(source_id_for_tenant(tenant)?),
                        None => {
                            let sources = teams_core::auth_profile_sources(&session.facts);
                            (sources.len() == 1).then(|| *sources.first().unwrap())
                        }
                    };
                    if let Some(source) = banner_source {
                        let context = load_context(&session.reader, &session.facts, source)?;
                        prepare_teams_context(&context, requested_as.as_deref(), false)?;
                    }
                    show_auth_status(session, config.tenant_selector.as_deref())
                }
                AuthCommand::Set {
                    tenant,
                    client_id,
                    user_id,
                    scopes,
                    client_secret_version,
                    delegated_token_version,
                } => set_auth_profile(
                    session,
                    &tenant,
                    &client_id,
                    &user_id,
                    &scopes,
                    client_secret_version,
                    delegated_token_version,
                ),
            })
        }
        CommandMode::Login {
            tenant,
            client_id,
            client_secret_source,
            client_secret_version,
            vault,
            scopes,
        } => {
            let config = build_config(&cli)?;
            prepare_teams_context(
                &TeamsPresentationContext::default(),
                requested_as.as_deref(),
                false,
            )?;
            let scopes = scopes
                .as_deref()
                .map(|value| load_value_or_file(value, "scopes"))
                .transpose()?
                .unwrap_or_else(default_scopes);
            let client_secret =
                load_client_secret(client_secret_source.as_deref(), client_secret_version)?;
            storage(&config).with_session(|session| {
                login_device_code_collection(
                    session,
                    &tenant,
                    &client_id,
                    client_secret.as_deref(),
                    client_secret_version,
                    vault,
                    &scopes,
                )
            })
        }
    }
}

fn build_config(cli: &Cli) -> Result<TeamsCommandConfig> {
    let delta_url = std::env::var("TEAMS_DELTA_URL")
        .ok()
        .unwrap_or_else(|| cli.delta_url.clone());
    Ok(TeamsCommandConfig {
        pile_path: cli.pile.clone(),
        key_path: cli.key.clone(),
        tenant_selector: cli.tenant.clone(),
        delta_url,
    })
}

fn parse_id(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim())
        .ok_or_else(|| format!("'{raw}' is not one exact nonzero 32-digit hexadecimal id"))
}

fn source_fragment(tenant: &str) -> Fragment {
    teams_core::source_fragment(tenant)
}

fn source_id_for_tenant(tenant: &str) -> Result<Id> {
    let tenant = tenant.trim();
    if tenant.is_empty() || is_generic_tenant(tenant) {
        bail!("Teams collection state requires one concrete tenant, got {tenant:?}");
    }
    Ok(source_fragment(tenant)
        .root()
        .expect("Teams source fragment has one root"))
}

fn selected_source(session: &TeamsSession<'_>, tenant_selector: Option<&str>) -> Result<Id> {
    if let Some(tenant) = tenant_selector {
        return source_id_for_tenant(tenant);
    }
    one_required(
        teams_core::auth_profile_sources(&session.facts),
        "Teams auth-profile source (set --tenant when more than one exists)",
    )
}

fn resolve_auth_config(
    session: &TeamsSession<'_>,
    config: &TeamsCommandConfig,
    source_id: Id,
) -> Result<TeamsBridgeConfig> {
    let profile = match teams_core::auth_profile_head(&session.facts, source_id) {
        teams_core::AuthProfileHead::Missing => {
            bail!("Teams source {source_id:x} has no auth profile; run `teams login`")
        }
        teams_core::AuthProfileHead::Unique(profile) => profile,
        teams_core::AuthProfileHead::Forked(heads) => bail!(
            "Teams source {source_id:x} has forked auth-profile heads {heads:?}; reconcile with `teams auth set`"
        ),
    };
    let record = teams_core::auth_profile(&session.facts, profile)?;
    let tenant = teams_core::source_label(&session.reader, &session.facts, source_id)?;
    Ok(TeamsBridgeConfig {
        source_id,
        tenant,
        client_id: read_utf8string(&session.reader, record.client_id, "Teams auth client id")?,
        user_id: read_utf8string(&session.reader, record.user_id, "Teams auth user id")?,
        scopes: read_utf8string(&session.reader, record.scopes, "Teams auth scopes")?,
        profile,
        client_secret_version: record.client_secret_version,
        delegated_token_version: record.delegated_token_version,
        delta_url: config.delta_url.clone(),
    })
}

fn require_exact_secret(session: &TeamsSession<'_>, id: Id, label: &str) -> Result<Id> {
    if !session.secrets.snapshot().contains(id) {
        bail!("unknown {label} {id:x}");
    }
    Ok(id)
}

fn open_exact_secret(session: &TeamsSession<'_>, secret: Id) -> Result<Vec<u8>> {
    session
        .secrets
        .snapshot()
        .open(secret, &session.signer)
        .with_context(|| format!("open exact Teams Secrets version {secret:x}"))
}

fn teams_secret_name(source: Id, kind: &str) -> String {
    format!(
        "teams/{kind}/{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(source.raw())
    )
}

fn storage(config: &TeamsCommandConfig) -> TeamsStorage<'_> {
    TeamsStorage {
        pile: &config.pile_path,
        key: config.key_path.as_deref(),
    }
}

fn with_teams_context<T>(
    config: &TeamsCommandConfig,
    requested_as: Option<&str>,
    require_explicit_identity: bool,
    operation: impl FnOnce(
        &TeamsBridgeConfig,
        &mut TeamsSession<'_>,
        &TeamsPresentationContext,
    ) -> Result<T>,
) -> Result<T> {
    storage(config).with_session(|session| {
        let source_id = selected_source(session, config.tenant_selector.as_deref())?;
        let context = load_context(&session.reader, &session.facts, source_id)?;
        let context = prepare_teams_context(&context, requested_as, require_explicit_identity)?;
        // The presentation gate deliberately precedes auth-profile resolution.
        // Outward mutations must fail on a missing/mismatched `--as` before
        // inspecting credentials or attempting any network operation.
        let runtime = resolve_auth_config(session, config, source_id)?;
        operation(&runtime, session, &context)
    })
}

fn default_scopes() -> String {
    [
        "openid",
        "offline_access",
        "User.Read.All",
        "Presence.ReadWrite",
        "Presence.Read.All",
        "Chat.ReadWrite",
        "ChatMessage.Send",
        "Chat.Create",
        "ChatMember.ReadWrite",
    ]
    .join(" ")
}

fn is_generic_tenant(tenant: &str) -> bool {
    teams_core::is_generic_tenant(tenant)
}

fn canonical_tenant(tenant: &str) -> String {
    teams_core::canonical_tenant(tenant)
}

fn jwt_tenant(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload))
        .ok()?;
    let claims: JsonValue = serde_json::from_slice(&bytes).ok()?;
    claims
        .get("tid")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|tenant| !tenant.is_empty() && !is_generic_tenant(tenant))
        .map(str::to_owned)
}

fn resolve_source_tenant(
    requested_authority: &str,
    id_token: Option<&str>,
    access_token: Option<&str>,
) -> Result<String> {
    if let Some(tenant) = id_token
        .and_then(jwt_tenant)
        .or_else(|| access_token.and_then(jwt_tenant))
    {
        return Ok(canonical_tenant(&tenant));
    }
    let requested = requested_authority.trim();
    if !requested.is_empty() && !is_generic_tenant(requested) {
        return Ok(canonical_tenant(requested));
    }
    bail!(
        "Microsoft did not return a concrete tenant identity for authority {requested_authority:?}; include `openid` in login scopes or login against the actual tenant id"
    )
}

fn pull_once_with_cache(
    config: &TeamsBridgeConfig,
    app_token_cache: &mut Option<AppTokenCache>,
    session: &mut TeamsSession<'_>,
) -> Result<()> {
    let (token, app_config) = get_app_token(config, app_token_cache, session)?;
    let mut known_messages =
        load_known_messages(&session.reader, &session.facts, config.source_id)?;
    let mut coverage = coverage_head(&session.reader, &session.facts, config.source_id)?;
    let base_url = resolve_delta_url(&config.delta_url, &app_config.user_id)?;
    let mut request_url = coverage
        .as_ref()
        .and_then(|coverage| coverage.cursor.clone())
        .unwrap_or_else(|| base_url.clone());
    let mut reset_expired = coverage
        .as_ref()
        .is_some_and(|coverage| coverage.cursor.is_some());
    loop {
        let page = match fetch_delta_page(&Client::new(), &token, &request_url) {
            Ok(page) => page,
            Err(error) if reset_expired && error.downcast_ref::<DeltaCursorExpired>().is_some() => {
                eprintln!(
                        "Teams delta cursor expired; beginning a new covered round from the base endpoint."
                    );
                request_url = base_url.clone();
                reset_expired = false;
                continue;
            }
            Err(error) => return Err(error),
        };
        reset_expired = false;

        let (cursor_kind, cursor) = match (page.next_link, page.delta_link) {
            (Some(next), None) => ("next", next),
            (None, Some(delta)) => ("delta", delta),
            _ => bail!("Teams delta page must contain exactly one nextLink or deltaLink"),
        };
        let incoming = parse_messages(page.messages)?;
        let generation = coverage
            .as_ref()
            .map(|coverage| coverage.generation + 1)
            .unwrap_or(1);
        let (mut fragment, observations, next_known_messages) = build_page_fragment(
            &app_config.tenant,
            config.source_id,
            incoming,
            &token,
            &known_messages,
        )?;
        let receipt = coverage_fragment(
            config.source_id,
            generation,
            coverage.as_ref().map(|coverage| coverage.id).into_iter(),
            &request_url,
            &cursor,
            cursor_kind,
            observations.iter().copied(),
        )?;
        let receipt_id = receipt.root().expect("coverage receipt has one root");
        fragment += receipt;
        session.commit(fragment, "teams delta page")?;
        known_messages = next_known_messages;

        coverage = Some(CoverageHead {
            id: receipt_id,
            generation,
            cursor: Some(cursor.clone()),
        });
        if cursor_kind == "delta" {
            return Ok(());
        }
        request_url = cursor;
    }
}

#[derive(Debug, Clone)]
struct AppTokenCache {
    access_token: String,
    expires_at_key: i128,
}

#[derive(Debug, Clone)]
struct AppConfig {
    tenant: String,
    client_id: String,
    client_secret: String,
    user_id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TeamsPresentationContext {
    name: Option<String>,
    boundary: Option<String>,
}

fn get_app_token(
    config: &TeamsBridgeConfig,
    app_token_cache: &mut Option<AppTokenCache>,
    session: &TeamsSession<'_>,
) -> Result<(String, AppConfig)> {
    let app_config = app_config(config, session)?;
    let now = clock::now()?;
    let now_key = interval_key(clock::point(now)?);

    if let Some(cache) = app_token_cache {
        if cache.expires_at_key > now_key + 30 * 1_000_000_000 {
            return Ok((cache.access_token.clone(), app_config));
        }
    }

    let token = request_client_credentials_token(
        &app_config.tenant,
        &app_config.client_id,
        &app_config.client_secret,
    )?;
    let expires_at = clock::point(epoch_after_seconds(clock::now()?, token.expires_in))?;
    let expires_at_key = interval_key(expires_at);
    let access_token = token.access_token;
    *app_token_cache = Some(AppTokenCache {
        access_token: access_token.clone(),
        expires_at_key,
    });
    Ok((access_token, app_config))
}

fn app_config(config: &TeamsBridgeConfig, session: &TeamsSession<'_>) -> Result<AppConfig> {
    let secret = config.client_secret_version.ok_or_else(|| {
        anyhow::anyhow!(
            "Teams auth profile {} has no app client-secret version; rotate with `teams login --client-secret ...` or `teams auth set`",
            config.profile
        )
    })?;
    let client_secret = String::from_utf8(open_exact_secret(session, secret)?)
        .context("Teams client secret is not UTF-8")?;

    Ok(AppConfig {
        tenant: config.tenant.clone(),
        client_id: config.client_id.clone(),
        client_secret,
        user_id: config.user_id.clone(),
    })
}

fn resolve_delta_url(template: &str, user_id: &str) -> Result<String> {
    if template.contains("{user_id}") {
        return Ok(template.replace("{user_id}", user_id));
    }
    if template.contains("/me/") {
        bail!("delta url uses /me; configure /users/{{user_id}}/chats/getAllMessages/delta");
    }
    Ok(template.to_owned())
}

fn get_delegated_token(
    config: &TeamsBridgeConfig,
    session: &mut TeamsSession<'_>,
) -> Result<String> {
    let secret = config.delegated_token_version.ok_or_else(|| {
        anyhow::anyhow!(
            "Teams auth profile {} has no delegated-token version; run `teams login`",
            config.profile
        )
    })?;
    let plaintext = open_exact_secret(session, secret)?;
    let bundle: DelegatedTokenBundle =
        serde_json::from_slice(&plaintext).context("decode Teams delegated-token bundle")?;
    if bundle.expires_at_unix > now_epoch_secs()? + 30 {
        return Ok(bundle.access_token);
    }
    let refresh = bundle.refresh_token.as_deref().ok_or_else(|| {
        anyhow::anyhow!("delegated token expired without a refresh token; run `teams login`")
    })?;
    let refreshed = refresh_token(
        &config.tenant,
        &config.client_id,
        refresh,
        bundle.scope.as_deref().or(Some(&config.scopes)),
    )?;
    let next_bundle = DelegatedTokenBundle {
        access_token: refreshed.access_token.clone(),
        refresh_token: refreshed
            .refresh_token
            .or_else(|| bundle.refresh_token.clone()),
        expires_at_unix: now_epoch_secs()? + refreshed.expires_in,
        token_type: refreshed.token_type.or(bundle.token_type),
        scope: refreshed
            .scope
            .or(bundle.scope)
            .or_else(|| Some(config.scopes.clone())),
    };
    let (vault, row) = session
        .secrets
        .snapshot()
        .lookup(secret)
        .ok_or_else(|| anyhow::anyhow!("exact delegated-token Secrets version disappeared"))?;
    let name = secrets_model::read_text(session.secrets.snapshot().reader(), row.name)
        .context("read delegated-token secret name")?;
    let encoded =
        serde_json::to_vec(&next_bundle).context("encode refreshed Teams token bundle")?;
    let next_secret = session.add_secret(vault, &name, &encoded, clock::point_now()?)?;
    let client_repair = config
        .client_secret_version
        .map(|id| format!(" --client-secret-version {id:x}"))
        .unwrap_or_default();
    eprintln!(
        "Published refreshed delegated-token version {next_secret:x}; if auth-profile publication is interrupted, repair with `teams auth set --tenant {} --client-id {} --user-id {} --scopes @SCOPES{client_repair} --delegated-token-version {next_secret:x}`.",
        config.tenant, config.client_id, config.user_id,
    );
    let mut fragment = source_fragment(&config.tenant);
    let (profile, _) = teams_core::auth_profile_fragment(
        config.source_id,
        &config.client_id,
        &config.user_id,
        next_bundle.scope.as_deref().unwrap_or(&config.scopes),
        config.client_secret_version,
        Some(next_secret),
        [config.profile],
    )?;
    fragment += profile;
    session.commit(fragment, "teams auth profile after token refresh")?;
    Ok(refreshed.access_token)
}

#[derive(Debug, Clone, Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: i64,
    interval: Option<i64>,
    message: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    expires_in: i64,
    scope: Option<String>,
    token_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ErrorResponse {
    error: String,
}

fn oauth_error_kind(body: &str) -> String {
    serde_json::from_str::<ErrorResponse>(body)
        .ok()
        .map(|error| error.error)
        .filter(|kind| {
            !kind.is_empty()
                && kind.len() <= 64
                && kind
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

fn now_epoch_secs() -> Result<i64> {
    Ok(clock::now()?.to_unix_seconds() as i64)
}

fn load_context(
    reader: &PileReader,
    catalog: &TribleSet,
    source_id: Id,
) -> Result<TeamsPresentationContext> {
    let heads = current_context_head_ids(catalog, source_id);
    let Some(context_id) = one_optional(heads, "Teams presentation-context head")? else {
        return Ok(TeamsPresentationContext::default());
    };
    let name = one_optional(
        find!(
            name: Inline<Handle<UTF8String>>,
            pattern!(catalog, [{ context_id @ metadata::name: ?name }])
        )
        .collect(),
        "Teams presentation name",
    )?
    .map(|handle| read_utf8string(reader, handle, "Teams presentation name"))
    .transpose()?;
    let boundary = one_optional(
        find!(
            boundary: Inline<Handle<UTF8String>>,
            pattern!(catalog, [{ context_id @ metadata::description: ?boundary }])
        )
        .collect(),
        "Teams presentation boundary",
    )?
    .map(|handle| read_utf8string(reader, handle, "Teams presentation boundary"))
    .transpose()?;
    Ok(TeamsPresentationContext { name, boundary })
}

fn store_context(
    session: &mut TeamsSession<'_>,
    source_id: Id,
    tenant: &str,
    presentation_name: &str,
    presentation_boundary: &str,
) -> Result<TeamsPresentationContext> {
    let presentation_name = presentation_name.trim();
    if presentation_name.is_empty() {
        bail!("Teams presentation name must not be empty");
    }
    let presentation_boundary = presentation_boundary.trim();
    if presentation_boundary.is_empty() {
        bail!("Teams presentation boundary must not be empty");
    }

    let supersedes = current_context_head_ids(&session.facts, source_id);
    let mut fragment = source_fragment(tenant);
    if fragment.root() != Some(source_id) {
        bail!("Teams context tenant/source identity mismatch");
    }
    fragment += teams_core::context_fragment(
        source_id,
        clock::point_now()?,
        supersedes,
        presentation_name,
        presentation_boundary,
    )?;
    session.commit(fragment, "teams professional context")?;
    Ok(TeamsPresentationContext {
        name: Some(presentation_name.to_owned()),
        boundary: Some(presentation_boundary.to_owned()),
    })
}

fn print_context_banner(context: &TeamsPresentationContext) {
    match context
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        Some(name) => eprintln!("TEAMS · PRESENT AS {name} · PROFESSIONAL WORK CONTEXT"),
        None => eprintln!("TEAMS · CONTEXT UNSET"),
    }
    match context
        .boundary
        .as_deref()
        .map(str::trim)
        .filter(|boundary| !boundary.is_empty())
    {
        Some(boundary) => eprintln!("BOUNDARY · {boundary}"),
        None => eprintln!("BOUNDARY · UNSET"),
    }
}

fn prepare_teams_context(
    context: &TeamsPresentationContext,
    requested_as: Option<&str>,
    require_explicit_identity: bool,
) -> Result<TeamsPresentationContext> {
    let context = context.clone();
    print_context_banner(&context);
    if !require_explicit_identity {
        return Ok(context);
    }

    let Some(configured_name) = context
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
    else {
        bail!("outward Teams mutations require a configured context; run `teams context set`");
    };
    if context
        .boundary
        .as_deref()
        .map(str::trim)
        .filter(|boundary| !boundary.is_empty())
        .is_none()
    {
        bail!("outward Teams mutations require a configured work boundary");
    }
    let Some(requested_as) = requested_as.map(str::trim).filter(|name| !name.is_empty()) else {
        bail!("outward Teams mutations require `--as {configured_name}`");
    };
    if requested_as != configured_name {
        bail!(
            "Teams presentation mismatch: configured as {configured_name}, requested --as {requested_as}"
        );
    }
    Ok(context)
}

fn show_context(context: &TeamsPresentationContext) -> Result<()> {
    match context.name.as_deref() {
        Some(name) => println!("present_as: {name}"),
        None => println!("present_as: (unset)"),
    }
    println!("context: professional/work-only");
    match context.boundary.as_deref() {
        Some(boundary) => println!("boundary: {boundary}"),
        None => println!("boundary: (unset)"),
    }
    Ok(())
}

fn show_auth_status(session: &TeamsSession<'_>, tenant: Option<&str>) -> Result<()> {
    let sources = match tenant {
        Some(tenant) => BTreeSet::from([source_id_for_tenant(tenant)?]),
        None => teams_core::auth_profile_sources(&session.facts),
    };
    if sources.is_empty() {
        println!("auth_profile: (unset)");
        return Ok(());
    }
    for source in sources {
        let tenant = teams_core::source_label(&session.reader, &session.facts, source)
            .unwrap_or_else(|_| format!("unknown-source-{source:x}"));
        println!("tenant: {tenant}");
        match teams_core::auth_profile_head(&session.facts, source) {
            teams_core::AuthProfileHead::Missing => println!("auth_profile: (unset)"),
            teams_core::AuthProfileHead::Forked(heads) => {
                println!("auth_profile: FORKED {heads:?}")
            }
            teams_core::AuthProfileHead::Unique(profile) => {
                let record = teams_core::auth_profile(&session.facts, profile)?;
                println!("auth_profile: {profile:x}");
                println!(
                    "client_id: {}",
                    read_utf8string(&session.reader, record.client_id, "Teams client id")?
                );
                println!(
                    "user_id: {}",
                    read_utf8string(&session.reader, record.user_id, "Teams user id")?
                );
                println!(
                    "scopes: {}",
                    read_utf8string(&session.reader, record.scopes, "Teams scopes")?
                );
                println!(
                    "client_secret_version: {}",
                    record
                        .client_secret_version
                        .map(|id| format!("{id:x}"))
                        .unwrap_or_else(|| "(unset)".to_owned())
                );
                println!(
                    "delegated_token_version: {}",
                    record
                        .delegated_token_version
                        .map(|id| format!("{id:x}"))
                        .unwrap_or_else(|| "(unset)".to_owned())
                );
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn set_auth_profile(
    session: &mut TeamsSession<'_>,
    tenant: &str,
    client_id: &str,
    user_id: &str,
    scopes: &str,
    client_secret_version: Option<Id>,
    delegated_token_version: Option<Id>,
) -> Result<()> {
    let source = source_id_for_tenant(tenant)?;
    let client_secret_version = client_secret_version
        .map(|id| require_exact_secret(session, id, "client-secret version"))
        .transpose()?;
    let delegated_token_version = delegated_token_version
        .map(|id| require_exact_secret(session, id, "delegated-token version"))
        .transpose()?;
    let predecessors = teams_core::auth_profile_head_ids(&session.facts, source);
    let scopes = load_value_or_file(scopes, "Teams scopes")?;
    let mut fragment = source_fragment(tenant);
    let (profile, profile_id) = teams_core::auth_profile_fragment(
        source,
        client_id,
        user_id,
        &scopes,
        client_secret_version,
        delegated_token_version,
        predecessors,
    )?;
    fragment += profile;
    session.commit(fragment, "teams auth profile")?;
    println!("auth_profile: {profile_id:x}");
    Ok(())
}

fn current_context_head_ids(catalog: &TribleSet, source_id: Id) -> BTreeSet<Id> {
    teams_core::context_head_ids(catalog, source_id)
}

fn load_chat_map(
    reader: &PileReader,
    catalog: &TribleSet,
    source_id: Id,
) -> Result<HashMap<Id, String>> {
    let mut map = HashMap::new();
    for (chat_id, handle) in find!(
        (chat: Id, chat_id: Inline<Handle<UTF8String>>),
        pattern!(catalog, [{
            ?chat @
            metadata::tag: teams::kind_chat,
            teams::source: source_id,
            teams::chat_id: ?chat_id,
        }])
    ) {
        let value = read_utf8string(reader, handle, "Teams chat id")?;
        map.insert(chat_id, value);
    }
    Ok(map)
}

fn load_message_external_map(
    reader: &PileReader,
    catalog: &TribleSet,
    source_id: Id,
) -> Result<HashMap<Id, String>> {
    let mut map = HashMap::new();
    for (message_id, handle) in find!(
        (message: Id, external: Inline<Handle<UTF8String>>),
        pattern!(catalog, [
            {
                ?message @
                metadata::tag: archive::kind_message,
                teams::chat: _?chat,
                teams::message_id: ?external,
            },
            {
                _?chat @
                metadata::tag: teams::kind_chat,
                teams::source: source_id,
            }
        ])
    ) {
        let value = read_utf8string(reader, handle, "Teams message id")?;
        map.insert(message_id, value);
    }
    Ok(map)
}

fn load_known_messages(
    reader: &PileReader,
    catalog: &TribleSet,
    source_id: Id,
) -> Result<Vec<KnownMessage>> {
    let mut known = BTreeSet::new();
    for (message_id, message_external, chat_id, chat_external) in find!(
        (
            message: Id,
            message_external: Inline<Handle<UTF8String>>,
            chat: Id,
            chat_external: Inline<Handle<UTF8String>>
        ),
        pattern!(catalog, [
            {
                ?message @
                metadata::tag: archive::kind_message,
                teams::chat: ?chat,
                teams::message_id: ?message_external,
            },
            {
                ?chat @
                metadata::tag: teams::kind_chat,
                teams::source: source_id,
                teams::chat_id: ?chat_external,
            }
        ])
    ) {
        known.insert(KnownMessage {
            message_id,
            message_external_id: read_utf8string(reader, message_external, "Teams message id")?,
            chat_id,
            chat_external_id: read_utf8string(reader, chat_external, "Teams chat id")?,
        });
    }
    Ok(known.into_iter().collect())
}

fn read_utf8string(
    reader: &PileReader,
    handle: Inline<Handle<UTF8String>>,
    field: &str,
) -> Result<String> {
    let view: anybytes::View<str> = reader
        .get(handle)
        .with_context(|| format!("read {field} payload {}", hex::encode_upper(handle.raw)))?;
    Ok(view.as_ref().to_owned())
}

fn epoch_after_seconds(base: Epoch, seconds: i64) -> Epoch {
    use hifitime::Duration as HifiDuration;
    base + HifiDuration::from_seconds(seconds as f64)
}

fn login_device_code_collection(
    session: &mut TeamsSession<'_>,
    tenant: &str,
    client_id: &str,
    client_secret: Option<&str>,
    client_secret_version: Option<Id>,
    vault: Id,
    scopes: &str,
) -> Result<()> {
    let tenant = tenant.trim();
    if tenant.is_empty() {
        bail!("Teams login tenant must not be empty");
    }
    let client_id = client_id.trim();
    if client_id.is_empty() {
        bail!("Teams login client id must not be empty");
    }
    if client_secret.is_some_and(str::is_empty) {
        bail!("Teams client secret must not be empty");
    }
    let scopes = teams_core::canonical_auth_scopes(scopes)?;
    // Validate every caller-supplied collection coordinate before starting an
    // interactive OAuth flow. Source-derived inheritance still has to wait
    // until Microsoft identifies the concrete tenant.
    let explicit_client_version = client_secret_version
        .map(|id| require_exact_secret(session, id, "client-secret version"))
        .transpose()?;
    if session.secrets.location(vault).is_none() {
        bail!("vault {vault} is not ready for this node");
    }

    let device = request_device_code(tenant, client_id, &scopes)?;
    if let Some(message) = &device.message {
        println!("{message}");
    } else if let Some(url) = &device.verification_uri_complete {
        println!("Open {} to authenticate.", url);
    } else {
        println!(
            "Visit {} and enter code {} to authenticate.",
            device.verification_uri, device.user_code
        );
    }

    let interval = device.interval.unwrap_or(5).max(1) as u64;
    let deadline = now_epoch_secs()? + device.expires_in;
    let token = poll_device_token(tenant, client_id, &device.device_code, interval, deadline)?;
    let user_id = fetch_me_id(&token.access_token)?;
    let source_tenant =
        resolve_source_tenant(tenant, token.id_token.as_deref(), Some(&token.access_token))?;
    let source = source_id_for_tenant(&source_tenant)?;
    let predecessors = teams_core::auth_profile_head_ids(&session.facts, source);
    let previous = match teams_core::auth_profile_head(&session.facts, source) {
        teams_core::AuthProfileHead::Unique(profile) => {
            Some(teams_core::auth_profile(&session.facts, profile)?)
        }
        teams_core::AuthProfileHead::Missing | teams_core::AuthProfileHead::Forked(_) => None,
    };
    let inherited_client_version = match previous.as_ref() {
        Some(profile)
            if read_utf8string(
                &session.reader,
                profile.client_id,
                "predecessor Teams auth client id",
            )? == client_id =>
        {
            profile.client_secret_version
        }
        Some(_) | None => None,
    };
    let canonical_scopes =
        teams_core::canonical_auth_scopes(token.scope.as_deref().unwrap_or(&scopes))?;
    let bundle = DelegatedTokenBundle {
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        expires_at_unix: now_epoch_secs()? + token.expires_in,
        token_type: token.token_type,
        scope: Some(canonical_scopes.clone()),
    };
    let encoded_bundle =
        serde_json::to_vec(&bundle).context("encode Teams delegated-token bundle")?;
    // Read chronology before the first durable append so a clock failure
    // cannot leave a partially published login.
    let observed_at = clock::point_now()?;
    let client_version = if let Some(client_secret) = client_secret {
        let client_version = session.add_secret(
            vault,
            &teams_secret_name(source, "client-secret"),
            client_secret.as_bytes(),
            observed_at,
        )?;
        eprintln!(
            "Published client-secret version {client_version:x} in vault {vault:x}; if later login publication is interrupted, repair with `teams auth set --tenant {source_tenant} --client-id {client_id} --user-id {user_id} --scopes @SCOPES --client-secret-version {client_version:x}`."
        );
        Some(client_version)
    } else {
        explicit_client_version.or(inherited_client_version)
    };

    let token_version = session.add_secret(
        vault,
        &teams_secret_name(source, "delegated-token"),
        &encoded_bundle,
        observed_at,
    )?;
    let client_repair = client_version
        .map(|id| format!(" --client-secret-version {id:x}"))
        .unwrap_or_default();
    eprintln!(
        "Published delegated-token version {token_version:x} in vault {vault:x}; if Teams profile publication is interrupted, repair with `teams auth set --tenant {source_tenant} --client-id {client_id} --user-id {user_id} --scopes @SCOPES{client_repair} --delegated-token-version {token_version:x}`."
    );
    let mut fragment = source_fragment(&source_tenant);
    let (profile, profile_id) = teams_core::auth_profile_fragment(
        source,
        client_id,
        &user_id,
        &canonical_scopes,
        client_version,
        Some(token_version),
        predecessors,
    )?;
    fragment += profile;
    session.commit(fragment, "teams login auth profile")?;
    println!("auth_profile: {profile_id:x}");
    println!("delegated_token_version: {token_version:x}");
    if let Some(client_version) = client_version {
        println!("client_secret_version: {client_version:x}");
    }
    Ok(())
}

fn request_device_code(tenant: &str, client_id: &str, scopes: &str) -> Result<DeviceCodeResponse> {
    let url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode");
    let params = [("client_id", client_id), ("scope", scopes)];
    let client = Client::new();
    let resp = client
        .post(url)
        .form(&params)
        .send()
        .context("request device code")?;
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    if !status.is_success() {
        bail!(
            "device code request failed: status={status} error={}",
            oauth_error_kind(&body)
        );
    }
    let parsed: DeviceCodeResponse =
        serde_json::from_str(&body).context("parse device code response")?;
    Ok(parsed)
}

fn fetch_me_id(access_token: &str) -> Result<String> {
    let client = Client::new();
    let resp = client
        .get("https://graph.microsoft.com/v1.0/me")
        .bearer_auth(access_token)
        .send()
        .context("GET /me")?;
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    if !status.is_success() {
        bail!("GET /me failed: status={status} body={body}");
    }
    let json: JsonValue = serde_json::from_str(&body).context("parse /me response")?;
    let Some(id) = json.get("id").and_then(JsonValue::as_str) else {
        bail!("GET /me response missing id");
    };
    Ok(id.to_owned())
}

fn poll_device_token(
    tenant: &str,
    client_id: &str,
    device_code: &str,
    interval_secs: u64,
    deadline: i64,
) -> Result<TokenResponse> {
    let url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
    let client = Client::new();
    let mut interval = interval_secs;

    loop {
        if now_epoch_secs()? >= deadline {
            bail!("device code expired before authorization completed");
        }

        let params = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", client_id),
            ("device_code", device_code),
        ];
        let resp = client
            .post(&url)
            .form(&params)
            .send()
            .context("poll device token")?;
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        if status.is_success() {
            let token: TokenResponse =
                serde_json::from_str(&body).context("parse token response")?;
            return Ok(token);
        }

        let error = oauth_error_kind(&body);
        match error.as_str() {
            "authorization_pending" => {
                thread::sleep(StdDuration::from_secs(interval));
            }
            "slow_down" => {
                interval += 5;
                thread::sleep(StdDuration::from_secs(interval));
            }
            "expired_token" => bail!("device code expired"),
            other => {
                bail!("device code authorization failed: status={status} error={other}")
            }
        }
    }
}

fn refresh_token(
    tenant: &str,
    client_id: &str,
    refresh_token: &str,
    scope: Option<&str>,
) -> Result<TokenResponse> {
    let url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
    let mut params = vec![
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", refresh_token),
    ];
    if let Some(scope) = scope {
        params.push(("scope", scope));
    }
    let client = Client::new();
    let resp = client
        .post(url)
        .form(&params)
        .send()
        .context("refresh token")?;
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    if !status.is_success() {
        bail!(
            "refresh token failed: status={status} error={}",
            oauth_error_kind(&body)
        );
    }
    let token: TokenResponse = serde_json::from_str(&body).context("parse refresh response")?;
    Ok(token)
}

fn request_client_credentials_token(
    tenant: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<TokenResponse> {
    let url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
    let params = [
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("scope", "https://graph.microsoft.com/.default"),
    ];
    let client = Client::new();
    let resp = client
        .post(url)
        .form(&params)
        .send()
        .context("request client credentials token")?;
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    if !status.is_success() {
        bail!(
            "client credentials token failed: status={status} error={}",
            oauth_error_kind(&body)
        );
    }
    let token: TokenResponse =
        serde_json::from_str(&body).context("parse client credentials response")?;
    Ok(token)
}

struct DeltaPage {
    messages: Vec<JsonValue>,
    next_link: Option<String>,
    delta_link: Option<String>,
}

#[derive(Debug)]
struct DeltaCursorExpired;

impl std::fmt::Display for DeltaCursorExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Teams delta cursor expired")
    }
}

impl std::error::Error for DeltaCursorExpired {}

fn fetch_delta_page(client: &Client, token: &str, url: &str) -> Result<DeltaPage> {
    let safe_url = url_without_query(url);
    let resp = client
        .get(url)
        .bearer_auth(token)
        .send()
        .map_err(|err| anyhow::anyhow!("GET {safe_url}: {}", err.without_url()))?;
    let status = resp.status();
    let body = resp.text().map_err(|err| {
        anyhow::anyhow!("read response body for {safe_url}: {}", err.without_url())
    })?;
    let graph_error_code = serde_json::from_str::<JsonValue>(&body)
        .ok()
        .and_then(|json| {
            json.pointer("/error/code")
                .and_then(JsonValue::as_str)
                .map(str::to_owned)
        });
    if status.as_u16() == 410
        || (status.is_client_error() && graph_error_code.as_deref() == Some("syncStateNotFound"))
    {
        return Err(DeltaCursorExpired.into());
    }
    if !status.is_success() {
        bail!(
            "GET {} failed: status={status} graph_error={}",
            url_without_query(url),
            graph_error_code.as_deref().unwrap_or("unknown"),
        );
    }

    let json: JsonValue = serde_json::from_str(&body).context("parse delta json")?;
    let messages = json
        .get("value")
        .and_then(JsonValue::as_array)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Teams delta response is missing its value array"))?;
    let next_link = json
        .get("@odata.nextLink")
        .and_then(JsonValue::as_str)
        .map(str::to_owned);
    let delta_link = json
        .get("@odata.deltaLink")
        .and_then(JsonValue::as_str)
        .map(str::to_owned);

    Ok(DeltaPage {
        messages,
        next_link,
        delta_link,
    })
}

fn url_without_query(url: &str) -> &str {
    url.split_once('?').map_or(url, |(base, _)| base)
}

fn send_message(
    config: &TeamsBridgeConfig,
    session: &mut TeamsSession<'_>,
    chat_id: &str,
    text: &str,
) -> Result<()> {
    let token = get_delegated_token(config, session)?;
    let url = format!("https://graph.microsoft.com/v1.0/chats/{chat_id}/messages");
    let body = json!({
        "body": {
            "contentType": "text",
            "content": text
        }
    });

    let client = Client::new();
    let resp = client
        .post(url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .context("POST chat message")?;
    let status = resp.status();
    let response_body = resp.text().unwrap_or_default();
    if !status.is_success() {
        bail!("send message failed: status={status} body={response_body}");
    }
    Ok(())
}

fn list_users(
    config: &TeamsBridgeConfig,
    session: &mut TeamsSession<'_>,
    prefix: Option<&str>,
    limit: usize,
) -> Result<()> {
    let token = get_delegated_token(config, session)?;
    let mut url =
        reqwest::Url::parse("https://graph.microsoft.com/v1.0/users").context("parse users url")?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("$select", "id,displayName,mail,userPrincipalName");
        if let Some(prefix) = prefix.map(str::trim).filter(|value| !value.is_empty()) {
            let escaped = escape_odata_literal(prefix);
            let filter = format!(
                "startswith(displayName,'{escaped}') or startswith(userPrincipalName,'{escaped}') or startswith(mail,'{escaped}')"
            );
            pairs.append_pair("$filter", &filter);
        }
        if limit > 0 {
            pairs.append_pair("$top", &limit.to_string());
        }
    }

    let client = Client::new();
    let resp = client
        .get(url)
        .bearer_auth(token)
        .send()
        .context("GET /users")?;
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    if !status.is_success() {
        bail!("list users failed: status={status} body={body}");
    }
    let json_body: JsonValue = serde_json::from_str(&body).context("parse users json")?;
    let users = json_body
        .get("value")
        .and_then(JsonValue::as_array)
        .cloned()
        .unwrap_or_default();

    for user in users {
        let id = user
            .get("id")
            .and_then(JsonValue::as_str)
            .unwrap_or("unknown");
        let name = user
            .get("displayName")
            .and_then(JsonValue::as_str)
            .unwrap_or("unknown");
        let mail = user.get("mail").and_then(JsonValue::as_str);
        let upn = user.get("userPrincipalName").and_then(JsonValue::as_str);
        let contact = mail.or(upn).unwrap_or("-");
        println!("{id}  {name}  {contact}");
    }
    Ok(())
}

fn set_presence_status(
    config: &TeamsBridgeConfig,
    session: &mut TeamsSession<'_>,
    availability: PresenceAvailability,
    activity: Option<PresenceActivity>,
    duration_mins: u32,
    session_id: Option<String>,
) -> Result<()> {
    let availability = availability.as_graph();
    let activity = activity
        .map(|value| value.as_graph().to_string())
        .unwrap_or_else(|| default_activity_for(availability).to_string());
    ensure_presence_combo(availability, &activity)?;
    if !(5..=240).contains(&duration_mins) {
        bail!("duration-mins must be between 5 and 240");
    }
    let user_id = config.user_id.clone();
    let default_session = config.client_id.clone();
    let session_id = session_id.unwrap_or(default_session);

    let token = get_delegated_token(config, session)?;
    let url = format!("https://graph.microsoft.com/v1.0/users/{user_id}/presence/setPresence");
    let expiration = format!("PT{}M", duration_mins);
    let body = json!({
        "sessionId": session_id,
        "availability": availability,
        "activity": activity,
        "expirationDuration": expiration,
    });

    let client = Client::new();
    let resp = client
        .post(url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .context("POST setPresence")?;
    let status = resp.status();
    let response_body = resp.text().unwrap_or_default();
    if !status.is_success() {
        bail!("set presence failed: status={status} body={response_body}");
    }
    Ok(())
}

fn get_presence(
    config: &TeamsBridgeConfig,
    session: &mut TeamsSession<'_>,
    user_ids: Vec<String>,
) -> Result<()> {
    if user_ids.is_empty() {
        bail!("presence-get requires at least one user id");
    }
    let token = get_delegated_token(config, session)?;
    let url = "https://graph.microsoft.com/v1.0/communications/getPresencesByUserId";
    let body = json!({
        "ids": user_ids,
    });

    let client = Client::new();
    let resp = client
        .post(url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .context("POST getPresencesByUserId")?;
    let status = resp.status();
    let response_body = resp.text().unwrap_or_default();
    if !status.is_success() {
        bail!("get presence failed: status={status} body={response_body}");
    }
    let json_body: JsonValue =
        serde_json::from_str(&response_body).context("parse presence json")?;
    let presences = json_body
        .get("value")
        .and_then(JsonValue::as_array)
        .cloned()
        .unwrap_or_default();

    for presence in presences {
        let id = presence
            .get("id")
            .and_then(JsonValue::as_str)
            .unwrap_or("unknown");
        let availability = presence
            .get("availability")
            .and_then(JsonValue::as_str)
            .unwrap_or("unknown");
        let activity = presence
            .get("activity")
            .and_then(JsonValue::as_str)
            .unwrap_or("unknown");
        println!("{id}  {availability}  {activity}");
    }
    Ok(())
}

fn default_activity_for(availability: &str) -> &'static str {
    match availability {
        "Available" => "Available",
        "Away" => "Away",
        "Busy" => "InACall",
        "DoNotDisturb" => "Presenting",
        _ => "Available",
    }
}

fn ensure_presence_combo(availability: &str, activity: &str) -> Result<()> {
    let ok = match (availability, activity) {
        ("Available", "Available") => true,
        ("Busy", "InACall") => true,
        ("Busy", "InAConferenceCall") => true,
        ("Away", "Away") => true,
        ("DoNotDisturb", "Presenting") => true,
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        bail!(
            "unsupported availability/activity combo: {availability}/{activity} (allowed: Available/Available, Busy/InACall, Busy/InAConferenceCall, Away/Away, DoNotDisturb/Presenting)"
        )
    }
}

fn invite_to_chat(
    config: &TeamsBridgeConfig,
    session: &mut TeamsSession<'_>,
    chat_id: &str,
    user_id: &str,
    owner: bool,
) -> Result<()> {
    let token = get_delegated_token(config, session)?;
    let url = format!("https://graph.microsoft.com/v1.0/chats/{chat_id}/members");
    let roles = if owner { vec!["owner"] } else { Vec::new() };
    let body = json!({
        "@odata.type": "#microsoft.graph.aadUserConversationMember",
        "roles": roles,
        "user@odata.bind": format!("https://graph.microsoft.com/v1.0/users('{user_id}')"),
    });

    let client = Client::new();
    let resp = client
        .post(url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .context("POST chat member")?;
    let status = resp.status();
    let response_body = resp.text().unwrap_or_default();
    if !status.is_success() {
        bail!("chat invite failed: status={status} body={response_body}");
    }
    Ok(())
}

fn create_chat(
    config: &TeamsBridgeConfig,
    session: &mut TeamsSession<'_>,
    mut user_ids: Vec<String>,
    force_group: bool,
    topic: Option<String>,
) -> Result<()> {
    if user_ids.is_empty() {
        bail!("chat-create requires at least one user id");
    }
    let self_id = config.user_id.clone();
    if !user_ids.iter().any(|id| id == &self_id) {
        user_ids.push(self_id.clone());
    }
    user_ids.sort();
    user_ids.dedup();
    let chat_type = if user_ids.len() == 2 && !force_group {
        "oneOnOne"
    } else {
        "group"
    };

    let members: Vec<JsonValue> = user_ids
        .iter()
        .map(|id| {
            let mut member = serde_json::Map::new();
            member.insert(
                "@odata.type".to_string(),
                json!("#microsoft.graph.aadUserConversationMember"),
            );
            member.insert(
                "user@odata.bind".to_string(),
                json!(format!("https://graph.microsoft.com/v1.0/users('{id}')")),
            );
            // Graph requires every member to have an explicit role (owner or guest).
            // Use owner for in-tenant users by default.
            member.insert("roles".to_string(), json!(["owner"]));
            JsonValue::Object(member)
        })
        .collect();

    let mut body = serde_json::Map::new();
    body.insert("chatType".to_string(), json!(chat_type));
    body.insert("members".to_string(), JsonValue::Array(members));
    if chat_type == "group" {
        if let Some(topic) = topic {
            let trimmed = topic.trim();
            if !trimmed.is_empty() {
                body.insert("topic".to_string(), json!(trimmed));
            }
        }
    }
    let token = get_delegated_token(config, session)?;
    let client = Client::new();
    let resp = client
        .post("https://graph.microsoft.com/v1.0/chats")
        .bearer_auth(token)
        .json(&body)
        .send()
        .context("POST create chat")?;
    let status = resp.status();
    let response_body = resp.text().unwrap_or_default();
    if !status.is_success() {
        bail!("chat create failed: status={status} body={response_body}");
    }
    let json_body: JsonValue =
        serde_json::from_str(&response_body).context("parse create chat response")?;
    let chat_id = json_body
        .get("id")
        .and_then(JsonValue::as_str)
        .unwrap_or("unknown");
    println!("{chat_id}");
    Ok(())
}

fn escape_odata_literal(value: &str) -> String {
    value.replace('\'', "''")
}

#[derive(Debug, Clone)]
struct ReadOptions {
    chat_id: Option<String>,
    since: Option<String>,
    limit: usize,
    descending: bool,
}

#[derive(Debug, Clone)]
struct ReadMessage {
    message_id: Id,
    chat_id: Id,
    author_names: BTreeSet<Inline<Handle<UTF8String>>>,
    deleted: bool,
    created_at: Inline<NsTAIInterval>,
    created_at_key: i128,
    content: Option<Inline<Handle<UTF8String>>>,
    attachments: BTreeSet<Id>,
}

#[derive(Debug, Clone)]
struct AttachmentListOptions {
    chat_id: Option<String>,
    message_id: Option<String>,
    limit: usize,
    descending: bool,
}

#[derive(Debug, Clone)]
struct AttachmentExportOptions {
    source_id: String,
    chat_id: Option<String>,
    message_id: Option<String>,
    out_dir: PathBuf,
    filename: Option<String>,
    overwrite: bool,
}

#[derive(Debug, Clone)]
struct AttachmentExportCandidate {
    message_id: Id,
    chat_id: Id,
    source_id: String,
    source_kind: Option<String>,
    data_handle: Inline<Handle<RawBytes>>,
    name: Option<Inline<Handle<UTF8String>>>,
    media_type: Option<Inline<Handle<UTF8String>>>,
}

#[derive(Debug, Clone)]
struct AttachmentRow {
    attachment_id: Id,
    message_id: Id,
    chat_id: Id,
    created_at: Inline<NsTAIInterval>,
    created_at_key: i128,
    source_id: Option<Inline<Handle<UTF8String>>>,
    source_kind: Option<Inline<ShortString>>,
    source_pointers: BTreeSet<Inline<Handle<UTF8String>>>,
    name: Option<Inline<Handle<UTF8String>>>,
    media_type: Option<Inline<Handle<UTF8String>>>,
    size: Option<Inline<U256BE>>,
}

fn attachment_reference(source_kind: Option<&str>, source_id: &str) -> String {
    match source_kind {
        Some(kind @ ("attachment" | "hosted-content")) => format!("{kind}:{source_id}"),
        _ => source_id.to_owned(),
    }
}

fn parse_attachment_reference(reference: &str) -> (Option<&str>, &str) {
    for kind in ["attachment", "hosted-content"] {
        if let Some(source_id) = reference
            .strip_prefix(kind)
            .and_then(|rest| rest.strip_prefix(':'))
        {
            return (Some(kind), source_id);
        }
    }
    (None, reference)
}

fn current_messages(catalog: &TribleSet, source_id: Id) -> Result<Vec<ReadMessage>> {
    let message_chats = find!(
        (message: Id, chat: Id),
        pattern!(catalog, [
            {
                ?message @
                metadata::tag: archive::kind_message,
                teams::chat: ?chat,
                teams::message_id: _?external,
            },
            {
                ?chat @
                metadata::tag: teams::kind_chat,
                teams::source: source_id,
            }
        ])
    )
    .collect::<BTreeMap<_, _>>();
    let mut result = Vec::new();
    for (message, state) in teams_core::current_message_states(catalog, source_id)? {
        let chat = message_chats.get(&message).copied().ok_or_else(|| {
            anyhow::anyhow!(
                "Teams causal state names message {message:x} outside source {source_id:x}"
            )
        })?;
        match state {
            teams_core::CurrentMessageState::Present(observation) => result.push(
                read_message_observation(catalog, message, chat, observation, false)?,
            ),
            teams_core::CurrentMessageState::Deleted(Some(observation)) => result.push(
                read_message_observation(catalog, message, chat, observation, true)?,
            ),
            teams_core::CurrentMessageState::Deleted(None) => {}
        }
    }
    Ok(result)
}

fn read_message_observation(
    catalog: &TribleSet,
    message_id: Id,
    chat_id: Id,
    observation_id: Id,
    deleted: bool,
) -> Result<ReadMessage> {
    let created_at = one_optional(
        find!(
            created: Inline<NsTAIInterval>,
            pattern!(catalog, [{ observation_id @ metadata::created_at: ?created }])
        )
        .collect(),
        "Teams message created time",
    )?;
    let content = one_optional(
        find!(
            content: Inline<Handle<UTF8String>>,
            pattern!(catalog, [{ observation_id @ archive::content: ?content }])
        )
        .collect(),
        "Teams message content",
    )?;
    let author_names = find!(
        name: Inline<Handle<UTF8String>>,
        pattern!(catalog, [{ observation_id @ teams::author_name: ?name }])
    )
    .collect::<BTreeSet<_>>();
    if !deleted && (created_at.is_none() || content.is_none()) {
        bail!("present Teams observation {observation_id:x} lacks created time or content");
    }
    let modified_at = one_required(
        find!(
            modified: Inline<NsTAIInterval>,
            pattern!(catalog, [{ observation_id @ teams::modified_at: ?modified }])
        )
        .collect(),
        "Teams message modified time",
    )?;
    let created_at = created_at.unwrap_or(modified_at);
    let attachments = find!(
        attachment: Id,
        pattern!(catalog, [{ observation_id @ archive::attachment: ?attachment }])
    )
    .collect::<BTreeSet<_>>();
    Ok(ReadMessage {
        message_id,
        chat_id,
        author_names,
        deleted,
        created_at,
        created_at_key: interval_key(created_at),
        content,
        attachments,
    })
}

fn read_messages(
    config: &TeamsBridgeConfig,
    session: &mut TeamsSession<'_>,
    options: ReadOptions,
) -> Result<()> {
    let mut app_token_cache = None;
    pull_once_with_cache(config, &mut app_token_cache, session)?;
    let view = session.view();
    let chat_map = load_chat_map(&view.reader, &view.facts, config.source_id)?;
    let chat_filter_ids = filter_external_ids(options.chat_id.as_deref(), &chat_map, "chat")?;
    let since_key = parse_since_key(options.since.as_deref())?;
    let mut messages = current_messages(&view.facts, config.source_id)?
        .into_iter()
        .filter(|message| !message.deleted)
        .filter(|message| {
            chat_filter_ids
                .as_ref()
                .is_none_or(|filter| filter.contains(&message.chat_id))
        })
        .filter(|message| since_key.is_none_or(|since| message.created_at_key >= since))
        .collect::<Vec<_>>();
    messages.sort_by(|left, right| {
        left.created_at_key
            .cmp(&right.created_at_key)
            .then_with(|| left.message_id.cmp(&right.message_id))
    });
    if options.limit > 0 && messages.len() > options.limit {
        messages = messages.split_off(messages.len() - options.limit);
    }
    if options.descending {
        messages.reverse();
    }
    for message in messages {
        let content = read_utf8string(
            &view.reader,
            message.content.expect("present observation has content"),
            "Teams message content",
        )?;
        let mut author_names = message
            .author_names
            .into_iter()
            .map(|handle| read_utf8string(&view.reader, handle, "Teams author display name"))
            .collect::<Result<Vec<_>>>()?;
        author_names.sort();
        author_names.dedup();
        let author = if author_names.is_empty() {
            "unknown".to_owned()
        } else {
            author_names.join(" / ")
        };
        let chat = chat_map
            .get(&message.chat_id)
            .cloned()
            .unwrap_or_else(|| format!("{}", message.chat_id));
        println!(
            "[{}] ({}) {}: {}",
            format_interval(message.created_at),
            chat,
            author,
            content
        );
    }
    Ok(())
}

fn filter_external_ids(
    requested: Option<&str>,
    map: &HashMap<Id, String>,
    kind: &str,
) -> Result<Option<HashSet<Id>>> {
    let Some(requested) = requested.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let ids = map
        .iter()
        .filter_map(|(id, external)| (external == requested).then_some(*id))
        .collect::<HashSet<_>>();
    if ids.is_empty() {
        bail!("No {kind} found for id {requested}");
    }
    Ok(Some(ids))
}

#[derive(Debug, Clone)]
struct IncomingMessage {
    chat_external_id: Option<String>,
    message_external_id: String,
    raw_json: String,
    author_external_id: Option<String>,
    author_display_name: Option<String>,
    content: Option<String>,
    created_at: Option<Inline<NsTAIInterval>>,
    modified_at: Option<Inline<NsTAIInterval>>,
    source_removed: bool,
    deleted: bool,
    deleted_at: Option<Inline<NsTAIInterval>>,
    etag: Option<String>,
    attachments: Vec<AttachmentSource>,
}

/// A source-local logical message identity already established by a previous
/// admitted page (or by a fully identified message in the page being built).
/// Graph's minimal `@removed` records contain only the source-local message id,
/// so they may be resolved only when that id names exactly one such record.
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
struct KnownMessage {
    message_id: Id,
    message_external_id: String,
    chat_id: Id,
    chat_external_id: String,
}

#[derive(Debug, Clone)]
struct AttachmentSource {
    source_kind: &'static str,
    source_id: String,
    source_url: Option<String>,
    fetch_required: bool,
    name: Option<String>,
    content_type: Option<String>,
    content_bytes: Option<Vec<u8>>,
}

fn list_attachments(
    config: &TeamsBridgeConfig,
    session: &mut TeamsSession<'_>,
    options: AttachmentListOptions,
) -> Result<()> {
    let mut app_token_cache = None;
    pull_once_with_cache(config, &mut app_token_cache, session)?;
    let view = session.view();
    let chat_map = load_chat_map(&view.reader, &view.facts, config.source_id)?;
    let message_map = load_message_external_map(&view.reader, &view.facts, config.source_id)?;
    let chat_filter = filter_external_ids(options.chat_id.as_deref(), &chat_map, "chat")?;
    let message_filter =
        filter_external_ids(options.message_id.as_deref(), &message_map, "message")?;
    let mut rows = attachment_rows(
        &view.reader,
        &view.facts,
        config.source_id,
        chat_filter.as_ref(),
        message_filter.as_ref(),
    )?;
    rows.sort_by(|left, right| {
        left.created_at_key
            .cmp(&right.created_at_key)
            .then_with(|| left.attachment_id.cmp(&right.attachment_id))
    });
    if options.limit > 0 && rows.len() > options.limit {
        rows = rows.split_off(rows.len() - options.limit);
    }
    if options.descending {
        rows.reverse();
    }
    for row in rows {
        let chat = chat_map
            .get(&row.chat_id)
            .cloned()
            .unwrap_or_else(|| format!("{}", row.chat_id));
        let message = message_map
            .get(&row.message_id)
            .cloned()
            .unwrap_or_else(|| format!("{}", row.message_id));
        let source_id = row
            .source_id
            .map(|handle| read_utf8string(&view.reader, handle, "Teams attachment source id"))
            .transpose()?
            .unwrap_or_default();
        let source_kind = row
            .source_kind
            .map(|value| String::try_from_inline(&value))
            .transpose()
            .map_err(|error| anyhow::anyhow!("decode attachment kind: {error:?}"))?;
        let mut source_pointers = row
            .source_pointers
            .into_iter()
            .map(|handle| read_utf8string(&view.reader, handle, "Teams attachment pointer"))
            .collect::<Result<Vec<_>>>()?;
        source_pointers.sort();
        source_pointers.dedup();
        let name = row
            .name
            .map(|handle| read_utf8string(&view.reader, handle, "Teams attachment name"))
            .transpose()?;
        let media_type = row
            .media_type
            .map(|handle| read_utf8string(&view.reader, handle, "Teams attachment media type"))
            .transpose()?;
        let size = row.size.map(inline_u256_to_u128).transpose()?;
        println!(
            "[{}] ({}) msg={} attachment={} name={} mime={} size={} source={}",
            format_interval(row.created_at),
            chat,
            message,
            attachment_reference(source_kind.as_deref(), &source_id),
            name.as_deref().unwrap_or("-"),
            media_type.as_deref().unwrap_or("-"),
            size.map(|size| size.to_string()).as_deref().unwrap_or("-"),
            if source_pointers.is_empty() {
                "-".to_owned()
            } else {
                source_pointers.join(" | ")
            },
        );
    }
    Ok(())
}

fn attachment_rows(
    _reader: &PileReader,
    catalog: &TribleSet,
    source_id: Id,
    chat_filter: Option<&HashSet<Id>>,
    message_filter: Option<&HashSet<Id>>,
) -> Result<Vec<AttachmentRow>> {
    let mut rows = Vec::new();
    for message in current_messages(catalog, source_id)?
        .into_iter()
        .filter(|message| !message.deleted)
    {
        if chat_filter.is_some_and(|filter| !filter.contains(&message.chat_id))
            || message_filter.is_some_and(|filter| !filter.contains(&message.message_id))
        {
            continue;
        }
        for attachment_id in message.attachments {
            let source_id = one_required(
                find!(
                    value: Inline<Handle<UTF8String>>,
                    pattern!(catalog, [{ attachment_id @ archive::attachment_source_id: ?value }])
                )
                .collect(),
                "Teams attachment source id",
            )?;
            let source_kind = one_required(
                find!(
                    value: Inline<ShortString>,
                    pattern!(catalog, [{ attachment_id @ teams::attachment_kind: ?value }])
                )
                .collect(),
                "Teams attachment kind",
            )?;
            let source_pointers = find!(
                value: Inline<Handle<UTF8String>>,
                pattern!(catalog, [{ attachment_id @ archive::attachment_source_pointer: ?value }])
            )
            .collect::<BTreeSet<_>>();
            let file_id = one_optional(
                find!(
                    value: Id,
                    pattern!(catalog, [{ attachment_id @ archive::attachment_file: ?value }])
                )
                .collect(),
                "Teams attachment file",
            )?;
            let occurrence_name = one_optional(
                find!(
                    value: Inline<Handle<UTF8String>>,
                    pattern!(catalog, [{ attachment_id @ archive::attachment_name: ?value }])
                )
                .collect(),
                "Teams attachment occurrence name",
            )?;
            let file_name = file_id
                .map(|id| file_capability::name_handle(catalog, id))
                .transpose()?
                .flatten();
            let media_type = file_id
                .map(|id| file_capability::media_type_name_handle_strict(catalog, id))
                .transpose()?
                .flatten();
            let size = one_optional(
                find!(
                    value: Inline<U256BE>,
                    pattern!(catalog, [{ attachment_id @ archive::attachment_size_bytes: ?value }])
                )
                .collect(),
                "Teams attachment size",
            )?;
            rows.push(AttachmentRow {
                attachment_id,
                message_id: message.message_id,
                chat_id: message.chat_id,
                created_at: message.created_at,
                created_at_key: message.created_at_key,
                source_id: Some(source_id),
                source_kind: Some(source_kind),
                source_pointers,
                name: occurrence_name.or(file_name),
                media_type,
                size,
            });
        }
    }
    Ok(rows)
}

fn export_attachment(
    config: &TeamsBridgeConfig,
    session: &mut TeamsSession<'_>,
    options: AttachmentExportOptions,
) -> Result<()> {
    let mut app_token_cache = None;
    pull_once_with_cache(config, &mut app_token_cache, session)?;
    let view = session.view();
    let chat_map = load_chat_map(&view.reader, &view.facts, config.source_id)?;
    let message_map = load_message_external_map(&view.reader, &view.facts, config.source_id)?;
    let chat_filter = filter_external_ids(options.chat_id.as_deref(), &chat_map, "chat")?;
    let message_filter =
        filter_external_ids(options.message_id.as_deref(), &message_map, "message")?;
    let wanted = options.source_id.trim();
    let (wanted_kind, wanted_source) = parse_attachment_reference(wanted);
    if wanted_source.is_empty() {
        bail!("attachment source id is empty");
    }
    let rows = attachment_rows(
        &view.reader,
        &view.facts,
        config.source_id,
        chat_filter.as_ref(),
        message_filter.as_ref(),
    )?;
    let mut candidates = Vec::new();
    for row in rows {
        let source = read_utf8string(
            &view.reader,
            row.source_id.expect("attachment row has source id"),
            "Teams attachment source id",
        )?;
        let kind_inline = row.source_kind.expect("attachment row has source kind");
        let kind = String::try_from_inline(&kind_inline)
            .map_err(|error| anyhow::anyhow!("decode attachment kind: {error:?}"))?;
        if source != wanted_source || wanted_kind.is_some_and(|wanted| wanted != kind) {
            continue;
        }
        let file_id = one_optional(
            find!(
                file: Id,
                pattern!(&view.facts, [{ row.attachment_id @ archive::attachment_file: ?file }])
            )
            .collect(),
            "Teams attachment file",
        )?;
        let Some(file_id) = file_id else {
            continue;
        };
        let data_handle = file_capability::content_handle(&view.facts, file_id)?
            .ok_or_else(|| anyhow::anyhow!("attachment file {file_id:x} has no content"))?;
        candidates.push(AttachmentExportCandidate {
            message_id: row.message_id,
            chat_id: row.chat_id,
            source_id: source,
            source_kind: Some(kind),
            data_handle,
            name: row.name,
            media_type: row.media_type,
        });
    }
    if candidates.is_empty() {
        println!("No stored attachment bytes found for {wanted}.");
        return Ok(());
    }
    if candidates.len() > 1 {
        println!("Multiple attachments matched; add --chat-id/--message-id:");
        for candidate in &candidates {
            println!(
                "- chat={} message={} attachment={}",
                chat_map
                    .get(&candidate.chat_id)
                    .map(String::as_str)
                    .unwrap_or("?"),
                message_map
                    .get(&candidate.message_id)
                    .map(String::as_str)
                    .unwrap_or("?"),
                attachment_reference(candidate.source_kind.as_deref(), &candidate.source_id),
            );
        }
        return Ok(());
    }
    let candidate = candidates.remove(0);
    let media_type = candidate
        .media_type
        .map(|handle| read_utf8string(&view.reader, handle, "attachment media type"))
        .transpose()?;
    let mut filename = options
        .filename
        .or_else(|| {
            candidate
                .name
                .map(|handle| read_utf8string(&view.reader, handle, "attachment name"))
                .transpose()
                .ok()
                .flatten()
        })
        .unwrap_or(candidate.source_id);
    filename = sanitize_filename(&filename);
    if !filename.contains('.') {
        if let Some(extension) = infer_extension(media_type.as_deref()) {
            filename.push('.');
            filename.push_str(extension);
        }
    }
    fs::create_dir_all(&options.out_dir)
        .with_context(|| format!("create output dir {}", options.out_dir.display()))?;
    let path = options.out_dir.join(filename);
    if path.exists() && !options.overwrite {
        bail!("output file exists: {} (use --overwrite)", path.display());
    }
    let bytes: Bytes = view
        .reader
        .get(candidate.data_handle)
        .context("load attachment bytes")?;
    fs::write(&path, bytes.as_ref())
        .with_context(|| format!("write attachment {}", path.display()))?;
    println!("{}", path.display());
    Ok(())
}

fn parse_messages(messages: Vec<JsonValue>) -> Result<Vec<IncomingMessage>> {
    // Preserve every distinct immutable source version. Full versions are
    // ordered only by Graph's lastModifiedDateTime and etag; neither field is
    // synthesized from another timestamp. Minimal @removed records carry no
    // usable version clock and are ordered causally by their page receipt.
    let mut parsed = BTreeMap::new();
    for message in messages {
        let message_external_id = message
            .get("id")
            .and_then(JsonValue::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("Teams delta message is missing id"))?;
        let chat_external_id = message
            .get("chatId")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let source_removed = message.get("@removed").is_some();
        let raw_json = serde_json::to_string(&message).context("serialize teams message json")?;

        if source_removed {
            let incoming = IncomingMessage {
                chat_external_id,
                message_external_id: message_external_id.to_owned(),
                raw_json: raw_json.clone(),
                author_external_id: None,
                author_display_name: None,
                content: None,
                created_at: None,
                modified_at: None,
                source_removed: true,
                deleted: true,
                deleted_at: None,
                etag: None,
                attachments: Vec::new(),
            };
            parsed.insert(
                (
                    incoming.chat_external_id.clone(),
                    incoming.message_external_id.clone(),
                    None,
                    None,
                    raw_json,
                ),
                incoming,
            );
            continue;
        }

        let chat_external_id = chat_external_id.ok_or_else(|| {
            anyhow::anyhow!("Teams delta message {message_external_id} is missing chatId")
        })?;
        let content = message
            .get("body")
            .and_then(|body| body.get("content"))
            .and_then(JsonValue::as_str)
            .map(str::to_owned);

        let created_at = message
            .get("createdDateTime")
            .and_then(JsonValue::as_str)
            .map(|value| {
                teams_core::parse_graph_datetime(value)
                    .map(epoch_interval)
                    .ok_or_else(|| anyhow::anyhow!("invalid Teams createdDateTime {value:?}"))
            })
            .transpose()?;
        let deleted_at = message
            .get("deletedDateTime")
            .and_then(JsonValue::as_str)
            .map(|value| {
                teams_core::parse_graph_datetime(value)
                    .map(epoch_interval)
                    .ok_or_else(|| anyhow::anyhow!("invalid Teams deletedDateTime {value:?}"))
            })
            .transpose()?;
        let deleted = deleted_at.is_some();
        if !deleted && content.is_none() {
            bail!("Teams delta message {message_external_id} is missing body.content");
        }
        let modified_at = message
            .get("lastModifiedDateTime")
            .and_then(JsonValue::as_str)
            .map(|value| {
                teams_core::parse_graph_datetime(value)
                    .map(epoch_interval)
                    .ok_or_else(|| anyhow::anyhow!("invalid Teams lastModifiedDateTime {value:?}"))
            })
            .transpose()?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Teams delta message {message_external_id} has no Graph lastModifiedDateTime; refusing to manufacture a source version"
                )
            })?;
        let modified_at_key = interval_key(modified_at);
        let etag = message
            .get("etag")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|etag| !etag.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Teams delta message {message_external_id} has no Graph etag; refusing to manufacture a source version"
                )
            })?;

        let from = message.get("from");
        let author_external_id = from
            .and_then(|from| from.get("user"))
            .and_then(|user| user.get("id"))
            .and_then(JsonValue::as_str)
            .map(str::to_owned);
        let author_display_name = from
            .and_then(|from| from.get("user"))
            .and_then(|user| user.get("displayName"))
            .and_then(JsonValue::as_str)
            .map(str::to_owned);

        let mut attachments = Vec::new();
        let mut seen_sources = HashSet::new();
        attachments.extend(parse_json_attachments(
            &message,
            &chat_external_id,
            message_external_id,
            &mut seen_sources,
        )?);
        if let Some(content) = content.as_deref() {
            attachments.extend(parse_hosted_content_attachments(
                content,
                &chat_external_id,
                message_external_id,
                &mut seen_sources,
            ));
        }

        let incoming = IncomingMessage {
            chat_external_id: Some(chat_external_id.clone()),
            message_external_id: message_external_id.to_owned(),
            raw_json: raw_json.clone(),
            author_external_id,
            author_display_name,
            content,
            created_at,
            modified_at: Some(modified_at),
            source_removed: false,
            deleted,
            deleted_at,
            etag: Some(etag.clone()),
            attachments,
        };
        parsed.insert(
            (
                incoming.chat_external_id.clone(),
                incoming.message_external_id.clone(),
                Some(modified_at_key),
                Some(etag),
                raw_json,
            ),
            incoming,
        );
    }

    Ok(parsed.into_values().collect())
}

fn parse_json_attachments(
    message: &JsonValue,
    chat_external_id: &str,
    message_external_id: &str,
    seen: &mut HashSet<String>,
) -> Result<Vec<AttachmentSource>> {
    let mut attachments = Vec::new();
    let Some(value) = message.get("attachments") else {
        return Ok(attachments);
    };
    if value.is_null() {
        return Ok(attachments);
    }
    let list = value.as_array().ok_or_else(|| {
        anyhow::anyhow!(
            "Teams delta message {message_external_id} has a non-array attachments field"
        )
    })?;
    for attachment in list {
        let source_id = attachment
            .get("id")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|source_id| !source_id.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Teams delta message {message_external_id} has an attachment without an id"
                )
            })?;
        if !seen.insert(format!("attachment:{source_id}")) {
            bail!("Teams delta message {message_external_id} repeats attachment id {source_id:?}");
        }

        let source_url = attachment
            .get("contentUrl")
            .and_then(JsonValue::as_str)
            .map(str::to_owned);
        let name = attachment
            .get("name")
            .and_then(JsonValue::as_str)
            .map(str::to_owned);
        let content_type = attachment
            .get("contentType")
            .and_then(JsonValue::as_str)
            .map(str::to_owned);
        let content_bytes = attachment
            .get("contentBytes")
            .and_then(JsonValue::as_str)
            .map(decode_base64)
            .transpose()?;

        attachments.push(AttachmentSource {
            source_kind: "attachment",
            source_id: source_id.to_owned(),
            source_url,
            fetch_required: false,
            name,
            content_type,
            content_bytes,
        });
    }

    let _ = (chat_external_id, message_external_id);
    Ok(attachments)
}

fn parse_hosted_content_attachments(
    content: &str,
    chat_external_id: &str,
    message_external_id: &str,
    seen: &mut HashSet<String>,
) -> Vec<AttachmentSource> {
    let mut attachments = Vec::new();
    for hosted_id in teams_core::extract_hosted_content_ids(content) {
        if !seen.insert(format!("hosted-content:{hosted_id}")) {
            continue;
        }
        let url = format!(
            "https://graph.microsoft.com/v1.0/chats/{chat_external_id}/messages/{message_external_id}/hostedContents/{hosted_id}/$value"
        );
        attachments.push(AttachmentSource {
            source_kind: "hosted-content",
            source_id: hosted_id,
            source_url: Some(url),
            fetch_required: true,
            name: None,
            content_type: None,
            content_bytes: None,
        });
    }
    attachments
}

fn decode_base64(value: &str) -> Result<Vec<u8>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|err| anyhow::anyhow!("base64 decode failed: {err:?}"))
}

type CoverageHead = teams_core::CoverageHead;

fn one_optional<T: Ord>(values: BTreeSet<T>, field: &str) -> Result<Option<T>> {
    match values.len() {
        0 => Ok(None),
        1 => Ok(values.into_iter().next()),
        count => bail!("{field} has {count} values; refusing arbitrary selection"),
    }
}

fn one_required<T: Ord>(values: BTreeSet<T>, field: &str) -> Result<T> {
    one_optional(values, field)?.ok_or_else(|| anyhow::anyhow!("{field} is missing"))
}

fn inline_u256_to_u128(value: Inline<U256BE>) -> Result<u128> {
    let raw = value.raw;
    if raw[..16].iter().any(|byte| *byte != 0) {
        bail!("Teams coverage generation exceeds u128");
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&raw[16..]);
    Ok(u128::from_be_bytes(bytes))
}

fn coverage_head(
    reader: &PileReader,
    catalog: &TribleSet,
    source_id: Id,
) -> Result<Option<CoverageHead>> {
    teams_core::coverage_head(reader, catalog, source_id)
}

fn coverage_fragment(
    source_id: Id,
    generation: u128,
    predecessors: impl IntoIterator<Item = Id>,
    request: &str,
    cursor: &str,
    kind: &str,
    observations: impl IntoIterator<Item = Id>,
) -> Result<Fragment> {
    teams_core::coverage_fragment(
        source_id,
        generation,
        predecessors,
        request,
        cursor,
        kind,
        observations,
    )
}

fn build_page_fragment(
    tenant: &str,
    source_id: Id,
    incoming: Vec<IncomingMessage>,
    token: &str,
    known: &[KnownMessage],
) -> Result<(Fragment, BTreeSet<Id>, Vec<KnownMessage>)> {
    let mut fragment = source_fragment(tenant);
    if fragment.root() != Some(source_id) {
        bail!("Teams tenant/source identity changed during one sync");
    }
    let mut events = BTreeSet::new();
    let mut identities = known.iter().cloned().collect::<BTreeSet<_>>();

    // Establish every fully identified logical message first. This lets a
    // minimal tombstone later in the same page resolve without depending on
    // Graph's response order.
    for message in &incoming {
        let Some(chat_external_id) = message.chat_external_id.as_deref() else {
            continue;
        };
        identities.insert(stage_message_identity(
            &mut fragment,
            source_id,
            chat_external_id,
            &message.message_external_id,
        ));
    }

    let mut by_external = BTreeMap::<String, BTreeSet<KnownMessage>>::new();
    for identity in &identities {
        by_external
            .entry(identity.message_external_id.clone())
            .or_default()
            .insert(identity.clone());
    }

    let mut page_kinds = BTreeMap::<Id, (bool, bool)>::new();
    for message in &incoming {
        let identity = resolve_message_identity(message, &identities, &by_external)?;
        let kinds = page_kinds.entry(identity.message_id).or_default();
        if message.source_removed {
            kinds.0 = true;
        } else {
            kinds.1 = true;
        }
    }
    if let Some((message, _)) = page_kinds
        .iter()
        .find(|(_, (removed, full))| *removed && *full)
    {
        bail!(
            "Teams delta page carries both an unversioned @removed marker and a full source version for message {message:x}; refusing to invent their order"
        );
    }

    for message in incoming {
        let identity = resolve_message_identity(&message, &identities, &by_external)?;
        // Every page COMMIT is independently inspectable: even a minimal
        // tombstone repeats the complete source/chat/message identity closure.
        let staged = stage_message_identity(
            &mut fragment,
            source_id,
            &identity.chat_external_id,
            &identity.message_external_id,
        );
        if staged.message_id != identity.message_id || staged.chat_id != identity.chat_id {
            bail!("Teams logical message identity changed while staging a page");
        }
        let message_id = identity.message_id;

        if message.source_removed {
            let tombstone = entity! {
                metadata::tag: teams::kind_message_tombstone,
                teams::message: message_id,
            };
            let tombstone_id = tombstone
                .root()
                .expect("Teams message tombstone has one root");
            fragment += tombstone;
            let raw = fragment.put::<UTF8String, _>(message.raw_json);
            fragment += entity! { ExclusiveId::force_ref(&tombstone_id) @
                teams::message_state: "deleted",
                teams::message_raw: raw,
            };
            events.insert(tombstone_id);
            continue;
        }

        let author_id = message
            .author_external_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|external| {
                let external = fragment.put::<UTF8String, _>(external.to_owned());
                let author = entity! {
                    metadata::tag: archive::kind_author,
                    teams::source: source_id,
                    teams::user_id: external,
                };
                let id = author.root().expect("Teams user fragment has one root");
                fragment += author;
                id
            });

        let mut attachment_ids = BTreeSet::new();
        for attachment in &message.attachments {
            let attachment = build_attachment_fragment(message_id, attachment, token)?;
            let id = attachment
                .root()
                .expect("Teams attachment fragment has one root");
            attachment_ids.insert(id);
            fragment += attachment;
        }

        let content = message
            .content
            .as_ref()
            .map(|content| fragment.put::<UTF8String, _>(content.to_owned()));
        let etag = fragment.put::<UTF8String, _>(
            message
                .etag
                .as_ref()
                .expect("full Teams source version has an etag")
                .to_owned(),
        );
        let author_name = message
            .author_display_name
            .as_ref()
            .map(|name| fragment.put::<UTF8String, _>(name.to_owned()));
        let state = if message.deleted {
            "deleted"
        } else {
            "present"
        };
        let observation = entity! {
            metadata::tag: teams::kind_message_observation,
            teams::message: message_id,
            teams::modified_at: message.modified_at.expect("full Teams source version has a timestamp"),
            teams::etag: etag,
        };
        let observation_id = observation
            .root()
            .expect("Teams message observation has one root");
        fragment += observation;
        let raw = fragment.put::<UTF8String, _>(message.raw_json);
        fragment += entity! { ExclusiveId::force_ref(&observation_id) @
            teams::message_state: state,
            metadata::created_at?: message.created_at,
            teams::deleted_at?: message.deleted_at,
            archive::author?: author_id,
            teams::author_name?: author_name,
            archive::content?: content,
            archive::attachment*: attachment_ids,
            teams::message_raw: raw,
        };
        events.insert(observation_id);
    }

    Ok((fragment, events, identities.into_iter().collect()))
}

fn stage_message_identity(
    fragment: &mut Fragment,
    source_id: Id,
    chat_external_id: &str,
    message_external_id: &str,
) -> KnownMessage {
    let chat_external = fragment.put::<UTF8String, _>(chat_external_id.to_owned());
    let chat = entity! {
        metadata::tag: teams::kind_chat,
        teams::source: source_id,
        teams::chat_id: chat_external,
    };
    let chat_id = chat.root().expect("Teams chat fragment has one root");
    *fragment += chat;

    let message_external = fragment.put::<UTF8String, _>(message_external_id.to_owned());
    let logical = entity! {
        metadata::tag: archive::kind_message,
        teams::chat: chat_id,
        teams::message_id: message_external,
    };
    let message_id = logical.root().expect("Teams message fragment has one root");
    *fragment += logical;

    KnownMessage {
        message_id,
        message_external_id: message_external_id.to_owned(),
        chat_id,
        chat_external_id: chat_external_id.to_owned(),
    }
}

fn resolve_message_identity(
    message: &IncomingMessage,
    identities: &BTreeSet<KnownMessage>,
    by_external: &BTreeMap<String, BTreeSet<KnownMessage>>,
) -> Result<KnownMessage> {
    if let Some(chat_external_id) = message.chat_external_id.as_deref() {
        return one_required(
            identities
                .iter()
                .filter(|known| {
                    known.chat_external_id == chat_external_id
                        && known.message_external_id == message.message_external_id
                })
                .cloned()
                .collect(),
            &format!(
                "Teams logical message identity for chat {chat_external_id:?}, message {:?}",
                message.message_external_id
            ),
        );
    }

    one_required(
        by_external
            .get(&message.message_external_id)
            .cloned()
            .unwrap_or_default(),
        &format!(
            "source-local Teams message id {:?} needed by minimal @removed record",
            message.message_external_id
        ),
    )
}

fn build_attachment_fragment(
    message_id: Id,
    source: &AttachmentSource,
    token: &str,
) -> Result<Fragment> {
    let source_id = source.source_id.trim();
    if source_id.is_empty() {
        bail!("Teams attachment has an empty source id");
    }
    let mut fragment = Fragment::empty();
    let source_handle = fragment.put::<UTF8String, _>(source_id.to_owned());
    let name = source
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| fragment.put::<UTF8String, _>(name.to_owned()));
    let source_pointer = source
        .source_url
        .as_ref()
        .map(|url| fragment.put::<UTF8String, _>(url.to_owned()));

    let mut content_type = source.content_type.clone();
    let bytes = match source.content_bytes.clone() {
        Some(bytes) => Some(bytes),
        None if source.fetch_required => {
            let url = source.source_url.as_deref().ok_or_else(|| {
                anyhow::anyhow!("required Teams attachment {source_id} has no fetch URL")
            })?;
            let (bytes, fetched_type) = fetch_attachment_bytes(token, url)?;
            if content_type.is_none() {
                content_type = fetched_type;
            }
            Some(bytes)
        }
        None => None,
    };
    let (file_id, size) = if let Some(bytes) = bytes {
        let size: Inline<U256BE> = (bytes.len() as u128).to_inline();
        let file_name = source
            .name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or(source_id);
        let media_type = file_capability::normalize_media_type_or_default(
            content_type
                .as_deref()
                .unwrap_or("application/octet-stream"),
        );
        let file = file_capability::stage(bytes, file_name, &media_type)?;
        let file_id = file.root().expect("canonical file fragment has one root");
        let (_, file_facts, file_metafacts, file_blobs) = file.into_parts();
        fragment += Fragment::from_parts(file_facts, file_metafacts, file_blobs);
        (Some(file_id), Some(size))
    } else {
        (None, None)
    };

    // The source occurrence is stable evidence. Materialized bytes are an
    // additive DERIVE of that evidence, not part of its identity: ordinary
    // Graph attachments often arrive pointer-only and may be fetched by a
    // separate process later without minting a second occurrence entity.
    let attachment = entity! {
        metadata::tag: archive::kind_attachment,
        archive::attachment_source_id: source_handle,
        teams::attachment_message: message_id,
        teams::attachment_kind: source.source_kind,
        archive::attachment_name?: name,
    };
    let attachment_id = attachment
        .root()
        .expect("Teams attachment fragment has one root");
    fragment += attachment;
    fragment += entity! { ExclusiveId::force_ref(&attachment_id) @
        archive::attachment_source_pointer?: source_pointer,
        archive::attachment_file?: file_id,
        archive::attachment_size_bytes?: size,
    };
    Ok(fragment)
}

/// Validate a page against the state it would create before any dependency or
/// signed COMMIT byte reaches the pile. This is deliberately stronger than
/// validating the isolated fragment: append-only storage cannot repair a
/// singular-field conflict or stale coverage fork after it has been signed.
fn validate_candidate(reader: &PileReader, catalog: &TribleSet, fragment: &Fragment) -> Result<()> {
    teams_core::validate_candidate(reader, catalog, fragment)
}

#[cfg(test)]
fn validate_commit_fragment(facts: &TribleSet) -> Result<()> {
    teams_core::validate_commit_fragment(facts)
}

fn validate_catalog(reader: &PileReader, catalog: &TribleSet) -> Result<()> {
    teams_core::validate_catalog(reader, catalog)
}

fn fetch_attachment_bytes(token: &str, url: &str) -> Result<(Vec<u8>, Option<String>)> {
    let client = Client::new();
    let safe_url = url_without_query(url);
    let resp = client
        .get(url)
        .bearer_auth(token)
        .send()
        .map_err(|err| anyhow::anyhow!("GET {safe_url}: {}", err.without_url()))?;
    let status = resp.status();
    if !status.is_success() {
        bail!("GET {} failed: status={status}", url_without_query(url));
    }
    let content_type = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    let bytes = resp
        .bytes()
        .map_err(|err| anyhow::anyhow!("read attachment bytes: {}", err.without_url()))?;
    Ok((bytes.to_vec(), content_type))
}

fn sanitize_filename(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "attachment".to_string();
    }

    let mut out = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        let cleaned = match ch {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ if ch.is_control() => '_',
            _ => ch,
        };
        out.push(cleaned);
    }

    let mut out = out.trim().trim_matches('.').to_string();
    if out.is_empty() || out == "." || out == ".." {
        out = "attachment".to_string();
    }
    out
}

fn infer_extension(media_type: Option<&str>) -> Option<&'static str> {
    match media_type? {
        "image/jpeg" | "image/jpg" | "image/pjpeg" => Some("jpg"),
        "image/png" => Some("png"),
        "image/gif" => Some("gif"),
        "image/webp" => Some("webp"),
        "image/bmp" => Some("bmp"),
        "image/tiff" => Some("tif"),
        "image/svg+xml" => Some("svg"),
        "application/pdf" => Some("pdf"),
        "text/plain" => Some("txt"),
        "text/markdown" => Some("md"),
        "text/html" => Some("html"),
        "application/json" => Some("json"),
        "application/zip" => Some("zip"),
        "application/msword" => Some("doc"),
        "application/vnd.ms-excel" => Some("xls"),
        "application/vnd.ms-powerpoint" => Some("ppt"),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => Some("docx"),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => Some("xlsx"),
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => Some("pptx"),
        "audio/mpeg" => Some("mp3"),
        "audio/mp4" | "audio/x-m4a" => Some("m4a"),
        "audio/wav" | "audio/x-wav" => Some("wav"),
        "video/mp4" => Some("mp4"),
        "video/quicktime" => Some("mov"),
        _ => None,
    }
}

fn epoch_interval(epoch: Epoch) -> Inline<NsTAIInterval> {
    (epoch, epoch).try_to_inline().unwrap()
}

fn interval_key(interval: Inline<NsTAIInterval>) -> i128 {
    let (lower, _): (Epoch, Epoch) = interval.try_from_inline().unwrap();
    lower.to_tai_duration().total_nanoseconds()
}

fn format_interval(interval: Inline<NsTAIInterval>) -> String {
    let (lower, _): (Epoch, Epoch) = interval.try_from_inline().unwrap();
    lower.to_gregorian_str(TimeScale::UTC)
}

fn parse_since_key(value: Option<&str>) -> Result<Option<i128>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let epoch = Epoch::from_gregorian_str(value)
        .ok()
        .or_else(|| teams_core::parse_graph_datetime(value))
        .ok_or_else(|| anyhow::anyhow!("invalid timestamp: {}", value))?;
    Ok(Some(interval_key(epoch_interval(epoch))))
}

fn load_value_or_file(raw: &str, label: &str) -> Result<String> {
    if let Some(path) = raw.strip_prefix('@') {
        if path == "-" {
            let mut value = String::new();
            std::io::stdin()
                .read_to_string(&mut value)
                .with_context(|| format!("read {label} from stdin"))?;
            return Ok(value);
        }
        return fs::read_to_string(path).with_context(|| format!("read {label} from {path}"));
    }
    Ok(raw.to_string())
}

fn load_value_or_file_trimmed(raw: &str, label: &str) -> Result<String> {
    Ok(load_value_or_file(raw, label)?.trim().to_string())
}

fn load_client_secret(
    source: Option<&str>,
    existing_version: Option<Id>,
) -> Result<Option<String>> {
    let sourced = source
        .map(|source| {
            if !source.starts_with('@') {
                bail!(
                    "--client-secret accepts only @path or @-; use TEAMS_CLIENT_SECRET for environment input"
                );
            }
            load_value_or_file_trimmed(source, "client secret")
        })
        .transpose()?;
    let environment = match std::env::var("TEAMS_CLIENT_SECRET") {
        Ok(value) => Some(value.trim().to_owned()),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("TEAMS_CLIENT_SECRET is not valid Unicode")
        }
    };

    if sourced.is_some() && environment.is_some() {
        bail!("provide the client secret through only one non-argv source");
    }
    let secret = sourced.or(environment);
    if existing_version.is_some() && secret.is_some() {
        bail!("an existing client-secret version conflicts with a new client secret");
    }
    if secret.as_deref().is_some_and(str::is_empty) {
        bail!("Teams client secret must not be empty");
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    const TEST_PILE: &str = "/tmp/never-opened-teams-cli-test.pile";
    const TEST_ID: &str = "01010101010101010101010101010101";

    #[test]
    fn v2_credential_surface_requires_exact_vault_and_rejects_legacy_selectors() {
        assert!(Cli::try_parse_from([
            "teams",
            "--pile",
            TEST_PILE,
            "login",
            "--tenant",
            "tenant.example",
            "--client-id",
            "client",
            "--vault",
            TEST_ID,
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "teams",
            "--pile",
            TEST_PILE,
            "login",
            "--tenant",
            "tenant.example",
            "--client-id",
            "client",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "teams",
            "--pile",
            TEST_PILE,
            "login",
            "--tenant",
            "tenant.example",
            "--client-id",
            "client",
            "--vault",
            "not-an-id",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "teams",
            "--pile",
            TEST_PILE,
            "--secrets-identity",
            "legacy",
            "auth",
            "status",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "teams",
            "--pile",
            TEST_PILE,
            "login",
            "--tenant",
            "tenant.example",
            "--client-id",
            "client",
            "--vault",
            TEST_ID,
            "--secret-scope",
            "legacy",
        ])
        .is_err());
    }

    #[test]
    fn oauth_error_kind_exposes_only_a_bounded_machine_kind() {
        let described = r#"{"error":"invalid_grant","error_description":"contains-secret"}"#;
        assert_eq!(oauth_error_kind(described), "invalid_grant");
        assert!(!oauth_error_kind(described).contains("contains-secret"));
        assert_eq!(
            oauth_error_kind(r#"{"error":"secret value with spaces"}"#),
            "unknown"
        );
        assert_eq!(oauth_error_kind("contains-secret"), "unknown");
    }

    struct Fixture {
        dir: PathBuf,
        pile: PathBuf,
        key: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "faculties-teams-collection-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let pile = dir.join("test.pile");
            fs::File::create(&pile).unwrap();
            let key = dir.join("test.key");
            initialize_signer(&pile, Some(&key)).unwrap();
            Self { dir, pile, key }
        }

        fn storage(&self) -> TeamsStorage<'_> {
            TeamsStorage {
                pile: &self.pile,
                key: Some(&self.key),
            }
        }

        fn publish(&self, fragment: Fragment) {
            self.storage().publish(fragment, "test Teams page").unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn graph_message(
        chat: &str,
        message: &str,
        created: &str,
        modified: &str,
        content: &str,
    ) -> JsonValue {
        json!({
            "chatId": chat,
            "id": message,
            "createdDateTime": created,
            "lastModifiedDateTime": modified,
            "etag": format!("{message}:{modified}:{content}"),
            "from": { "user": { "id": "user-1", "displayName": "Tester" } },
            "body": { "content": content },
            "attachments": [],
        })
    }

    fn page_fragment(
        tenant: &str,
        messages: Vec<JsonValue>,
        generation: u128,
        predecessors: impl IntoIterator<Item = Id>,
        cursor: &str,
    ) -> (Fragment, Id) {
        page_fragment_with_known(tenant, messages, generation, predecessors, cursor, &[])
    }

    fn page_fragment_with_known(
        tenant: &str,
        messages: Vec<JsonValue>,
        generation: u128,
        predecessors: impl IntoIterator<Item = Id>,
        cursor: &str,
        known: &[KnownMessage],
    ) -> (Fragment, Id) {
        let source = source_fragment(tenant);
        let source_id = source.root().unwrap();
        let incoming = parse_messages(messages).unwrap();
        let (mut fragment, observations, _) =
            build_page_fragment(tenant, source_id, incoming, "test-token", known).unwrap();
        let receipt = coverage_fragment(
            source_id,
            generation,
            predecessors,
            "https://graph.example/request",
            cursor,
            "delta",
            observations,
        )
        .unwrap();
        let receipt_id = receipt.root().unwrap();
        fragment += receipt;
        (fragment, receipt_id)
    }

    fn load_view(fixture: &Fixture) -> CollectionView {
        fixture.storage().view().unwrap()
    }

    fn initialize_test_secrets(fixture: &Fixture) -> (Id, Id, Id) {
        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        let vault = Id::new([0xE5; 16]).unwrap();
        secrets_vaults::create_vault(
            &mut pile,
            &signer,
            vault,
            "teams-test",
            clock::point_now().unwrap(),
        )
        .unwrap();
        let discovery = secrets_vaults::discover_local_vaults(&mut pile, &signer).unwrap();
        let location = *discovery.location(vault).unwrap();
        let client_id = secrets_vaults::add_secret(
            &mut pile,
            &signer,
            &location,
            discovery.snapshot(),
            "teams/client-secret/test",
            b"distinct-test-client-secret",
            clock::point_now().unwrap(),
        )
        .unwrap();
        drop(discovery);
        let token_bundle = DelegatedTokenBundle {
            access_token: "distinct-test-access-token".to_owned(),
            refresh_token: Some("distinct-test-refresh-token".to_owned()),
            expires_at_unix: now_epoch_secs().unwrap() + 3600,
            token_type: Some("Bearer".to_owned()),
            scope: Some("Chat.ReadWrite offline_access".to_owned()),
        };
        let discovery = secrets_vaults::discover_local_vaults(&mut pile, &signer).unwrap();
        let token_id = secrets_vaults::add_secret(
            &mut pile,
            &signer,
            &location,
            discovery.snapshot(),
            "teams/delegated-token/test",
            &serde_json::to_vec(&token_bundle).unwrap(),
            clock::point_now().unwrap(),
        )
        .unwrap();
        drop(discovery);
        pile.close().unwrap();
        (vault, client_id, token_id)
    }

    #[test]
    fn auth_profile_persists_only_exact_encrypted_secrets_references() {
        let fixture = Fixture::new();
        let (vault, client_secret, delegated_token) = initialize_test_secrets(&fixture);
        let tenant = "tenant.example";
        let source = source_fragment(tenant).root().unwrap();
        fixture
            .storage()
            .with_session(|session| {
                let mut fragment = source_fragment(tenant);
                let (profile, profile_id) = teams_core::auth_profile_fragment(
                    source,
                    "client-id",
                    "user-id",
                    "offline_access Chat.ReadWrite",
                    Some(client_secret),
                    Some(delegated_token),
                    [],
                )?;
                fragment += profile;
                session.commit(fragment, "test Teams auth profile")?;
                assert_eq!(
                    teams_core::auth_profile_head(&session.facts, source),
                    teams_core::AuthProfileHead::Unique(profile_id)
                );
                assert_eq!(
                    session.secrets.snapshot().lookup(client_secret).unwrap().0,
                    vault
                );
                let opened_client = session
                    .secrets
                    .snapshot()
                    .open(client_secret, &session.signer)?;
                assert_eq!(opened_client, b"distinct-test-client-secret");
                Ok(())
            })
            .unwrap();

        let bytes = fs::read(&fixture.pile).unwrap();
        for plaintext in [
            b"distinct-test-client-secret".as_slice(),
            b"distinct-test-access-token".as_slice(),
            b"distinct-test-refresh-token".as_slice(),
        ] {
            assert!(!bytes
                .windows(plaintext.len())
                .any(|window| window == plaintext));
        }
    }

    #[test]
    fn session_secret_creation_targets_one_exact_vault_and_refreshes_discovery() {
        let fixture = Fixture::new();
        let (vault, _, _) = initialize_test_secrets(&fixture);
        fixture
            .storage()
            .with_session(|session| {
                let observed_at = clock::point_now()?;
                let secret =
                    session.add_secret(vault, "teams/session-test", b"exact-vault", observed_at)?;
                assert_eq!(session.secrets.snapshot().lookup(secret).unwrap().0, vault);
                assert_eq!(
                    session.secrets.snapshot().open(secret, &session.signer)?,
                    b"exact-vault"
                );
                let missing = Id::new([0xE6; 16]).unwrap();
                let error = session
                    .add_secret(missing, "teams/session-test", b"wrong-vault", observed_at)
                    .unwrap_err();
                assert!(error.to_string().contains("not ready for this node"));
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn unknown_auth_secret_reference_is_rejected_before_append() {
        let fixture = Fixture::new();
        let source_identity = source_fragment("tenant.example");
        let source = source_identity.root().unwrap();
        let (profile, _) = teams_core::auth_profile_fragment(
            source,
            "client-id",
            "user-id",
            "offline_access",
            None,
            Some(Id::new([0xD7; 16]).unwrap()),
            [],
        )
        .unwrap();
        let mut fragment = source_identity;
        fragment += profile;
        let before = fs::read(&fixture.pile).unwrap();
        let error = fixture
            .storage()
            .publish(fragment, "dangling auth ref")
            .unwrap_err();
        assert!(error.to_string().contains("unknown delegated token bundle"));
        assert_eq!(fs::read(&fixture.pile).unwrap(), before);
    }

    #[test]
    fn source_chat_user_and_message_ids_are_tenant_scoped() {
        let a_source = source_fragment("tenant-a").root().unwrap();
        let b_source = source_fragment("tenant-b").root().unwrap();
        assert_eq!(a_source, source_fragment(" TENANT-A ").root().unwrap());
        assert_ne!(a_source, b_source);

        let a = build_page_fragment(
            "tenant-a",
            a_source,
            parse_messages(vec![graph_message(
                "chat",
                "message",
                "2026-08-01T10:00:00Z",
                "2026-08-01T10:00:00Z",
                "A",
            )])
            .unwrap(),
            "token",
            &[],
        )
        .unwrap()
        .0;
        let b = build_page_fragment(
            "tenant-b",
            b_source,
            parse_messages(vec![graph_message(
                "chat",
                "message",
                "2026-08-01T10:00:00Z",
                "2026-08-01T10:00:00Z",
                "A",
            )])
            .unwrap(),
            "token",
            &[],
        )
        .unwrap()
        .0;
        let a_chat = find!(
            chat: Id,
            pattern!(&a, [{ ?chat @ metadata::tag: teams::kind_chat }])
        )
        .collect::<BTreeSet<_>>();
        let b_chat = find!(
            chat: Id,
            pattern!(&b, [{ ?chat @ metadata::tag: teams::kind_chat }])
        )
        .collect::<BTreeSet<_>>();
        assert!(a_chat.is_disjoint(&b_chat));
        let a_messages = find!(
            message: Id,
            pattern!(&a, [{ ?message @ metadata::tag: archive::kind_message }])
        )
        .collect::<BTreeSet<_>>();
        let b_messages = find!(
            message: Id,
            pattern!(&b, [{ ?message @ metadata::tag: archive::kind_message }])
        )
        .collect::<BTreeSet<_>>();
        assert!(a_messages.is_disjoint(&b_messages));
    }

    #[test]
    fn edits_and_deletes_are_immutable_max_time_observations() {
        let fixture = Fixture::new();
        let (first, first_receipt) = page_fragment(
            "tenant-a",
            vec![graph_message(
                "chat",
                "message",
                "2026-08-01T10:00:00Z",
                "2026-08-01T10:00:00Z",
                "first",
            )],
            1,
            [],
            "https://graph.example/delta-1",
        );
        fixture.publish(first);
        let (edited, edited_receipt) = page_fragment(
            "tenant-a",
            vec![graph_message(
                "chat",
                "message",
                "2026-08-01T10:00:00Z",
                "2026-08-01T11:00:00Z",
                "edited",
            )],
            2,
            [first_receipt],
            "https://graph.example/delta-2",
        );
        fixture.publish(edited);
        let view = load_view(&fixture);
        let source = source_fragment("tenant-a").root().unwrap();
        let current = current_messages(&view.facts, source).unwrap();
        assert_eq!(current.len(), 1);
        assert!(!current[0].deleted);
        assert_eq!(
            read_utf8string(&view.reader, current[0].content.unwrap(), "test content").unwrap(),
            "edited"
        );
        assert_eq!(
            coverage_head(&view.reader, &view.facts, source)
                .unwrap()
                .unwrap()
                .id,
            edited_receipt
        );

        let mut deleted = graph_message(
            "chat",
            "message",
            "2026-08-01T10:00:00Z",
            "2026-08-01T12:00:00Z",
            "",
        );
        deleted["deletedDateTime"] = json!("2026-08-01T12:00:00Z");
        deleted["body"] = JsonValue::Null;
        let (tombstone, _) = page_fragment(
            "tenant-a",
            vec![deleted],
            3,
            [edited_receipt],
            "https://graph.example/delta-3",
        );
        fixture.publish(tombstone);
        let view = load_view(&fixture);
        let current = current_messages(&view.facts, source).unwrap();
        assert_eq!(current.len(), 1);
        assert!(current[0].deleted);
    }

    #[test]
    fn minimal_removed_is_causal_reversible_and_old_replay_cannot_restore() {
        let fixture = Fixture::new();
        let original = graph_message(
            "chat",
            "message",
            "2026-08-01T10:00:00Z",
            "2026-08-01T10:00:00Z",
            "original",
        );
        let (first, first_receipt) = page_fragment(
            "tenant-a",
            vec![original.clone()],
            1,
            [],
            "https://graph.example/delta-1",
        );
        fixture.publish(first);
        let first_view = load_view(&fixture);
        let source = source_fragment("tenant-a").root().unwrap();
        let known = load_known_messages(&first_view.reader, &first_view.facts, source).unwrap();

        let removed = json!({
            "id": "message",
            "@removed": { "reason": "deleted" }
        });
        let (tombstone, tombstone_receipt) = page_fragment_with_known(
            "tenant-a",
            vec![removed],
            2,
            [first_receipt],
            "https://graph.example/delta-2",
            &known,
        );
        fixture.publish(tombstone);
        let deleted_view = load_view(&fixture);
        assert!(current_messages(&deleted_view.facts, source)
            .unwrap()
            .is_empty());

        // A cursor reset can replay the exact pre-deletion source version in
        // a descendant receipt. Receipt recency alone must not resurrect it.
        let (replay, replay_receipt) = page_fragment(
            "tenant-a",
            vec![original],
            3,
            [tombstone_receipt],
            "https://graph.example/delta-3",
        );
        fixture.publish(replay);
        let replay_view = load_view(&fixture);
        assert!(current_messages(&replay_view.facts, source)
            .unwrap()
            .is_empty());

        let (restore, _) = page_fragment(
            "tenant-a",
            vec![graph_message(
                "chat",
                "message",
                "2026-08-01T10:00:00Z",
                "2026-08-01T11:00:00Z",
                "restored",
            )],
            4,
            [replay_receipt],
            "https://graph.example/delta-4",
        );
        fixture.publish(restore);
        let restored_view = load_view(&fixture);
        let current = current_messages(&restored_view.facts, source).unwrap();
        assert_eq!(current.len(), 1);
        assert_eq!(
            read_utf8string(
                &restored_view.reader,
                current[0].content.unwrap(),
                "restored content",
            )
            .unwrap(),
            "restored"
        );
    }

    #[test]
    fn minimal_removed_requires_unique_source_local_message_resolution() {
        let source = source_fragment("tenant-a").root().unwrap();
        let removed = parse_messages(vec![json!({
            "id": "message",
            "@removed": { "reason": "deleted" }
        })])
        .unwrap();
        assert!(
            build_page_fragment("tenant-a", source, removed.clone(), "token", &[])
                .unwrap_err()
                .to_string()
                .contains("is missing")
        );

        let mut scratch = source_fragment("tenant-a");
        let left = stage_message_identity(&mut scratch, source, "chat-left", "message");
        let right = stage_message_identity(&mut scratch, source, "chat-right", "message");
        let error =
            build_page_fragment("tenant-a", source, removed, "token", &[left, right]).unwrap_err();
        assert!(error.to_string().contains("has 2 values"));
    }

    #[test]
    fn graph_source_versions_require_modified_time_and_etag() {
        let mut missing_modified = graph_message(
            "chat",
            "message",
            "2026-08-01T10:00:00Z",
            "2026-08-01T10:00:00Z",
            "content",
        );
        missing_modified
            .as_object_mut()
            .unwrap()
            .remove("lastModifiedDateTime");
        assert!(parse_messages(vec![missing_modified])
            .unwrap_err()
            .to_string()
            .contains("lastModifiedDateTime"));

        let mut missing_etag = graph_message(
            "chat",
            "message",
            "2026-08-01T10:00:00Z",
            "2026-08-01T10:00:00Z",
            "content",
        );
        missing_etag.as_object_mut().unwrap().remove("etag");
        assert!(parse_messages(vec![missing_etag])
            .unwrap_err()
            .to_string()
            .contains("etag"));
    }
    #[test]
    fn repeated_partial_payload_for_one_source_version_converges() {
        let fixture = Fixture::new();
        let mut first = graph_message(
            "chat",
            "message",
            "2026-08-01T10:00:00Z",
            "2026-08-01T10:00:00Z",
            "content",
        );
        first["etag"] = json!("stable-etag");
        first["attachments"] = json!([{
            "id": "attachment-1",
            "name": "note.txt",
            "contentUrl": "https://graph.example/first",
        }]);
        let (first_page, first_receipt) = page_fragment(
            "tenant-a",
            vec![first],
            1,
            [],
            "https://graph.example/delta-1",
        );
        fixture.publish(first_page);

        let mut second = graph_message(
            "chat",
            "message",
            "2026-08-01T10:00:00Z",
            "2026-08-01T10:00:00Z",
            "content",
        );
        second["etag"] = json!("stable-etag");
        second["from"]["user"]["displayName"] = json!("Renamed Tester");
        second["attachments"] = json!([{
            "id": "attachment-1",
            "name": "note.txt",
            "contentUrl": "https://graph.example/second",
            "contentType": "text/plain",
            "contentBytes": base64::engine::general_purpose::STANDARD.encode(b"hello"),
        }]);
        let (second_page, _) = page_fragment(
            "tenant-a",
            vec![second],
            2,
            [first_receipt],
            "https://graph.example/delta-2",
        );
        fixture.publish(second_page);

        let view = load_view(&fixture);
        let observations = find!(
            value: Id,
            pattern!(&view.facts, [{
                ?value @ metadata::tag: teams::kind_message_observation
            }])
        )
        .collect::<BTreeSet<_>>();
        assert_eq!(observations.len(), 1);
        let observation = *observations.first().unwrap();
        assert_eq!(
            find!(
                value: Inline<Handle<UTF8String>>,
                pattern!(&view.facts, [{ observation @ teams::author_name: ?value }])
            )
            .collect::<BTreeSet<_>>()
            .len(),
            2
        );
        let attachment = one_required(
            find!(
                value: Id,
                pattern!(&view.facts, [{ observation @ archive::attachment: ?value }])
            )
            .collect(),
            "test attachment",
        )
        .unwrap();
        assert_eq!(
            find!(
                value: Inline<Handle<UTF8String>>,
                pattern!(&view.facts, [{ attachment @ archive::attachment_source_pointer: ?value }])
            )
            .collect::<BTreeSet<_>>()
            .len(),
            2
        );
        assert_eq!(
            find!(
                value: Id,
                pattern!(&view.facts, [{ attachment @ archive::attachment_file: ?value }])
            )
            .collect::<BTreeSet<_>>()
            .len(),
            1
        );
    }

    #[test]
    fn pointer_only_attachment_accepts_later_file_materialization() {
        let fixture = Fixture::new();
        let mut message = graph_message(
            "chat",
            "message",
            "2026-08-01T10:00:00Z",
            "2026-08-01T10:00:00Z",
            "content",
        );
        message["attachments"] = json!([{
            "id": "attachment-1",
            "name": "note.txt",
            "contentUrl": "https://graph.example/content",
        }]);
        let (page, _) = page_fragment(
            "tenant-a",
            vec![message],
            1,
            [],
            "https://graph.example/delta",
        );
        fixture.publish(page);
        let view = load_view(&fixture);
        let attachment = one_required(
            find!(
                value: Id,
                pattern!(&view.facts, [{
                    ?value @ metadata::tag: archive::kind_attachment
                }])
            )
            .collect(),
            "test attachment",
        )
        .unwrap();

        let mut derived =
            file_capability::stage(b"hello".to_vec(), "note.txt", "text/plain").unwrap();
        let file_id = derived.root().unwrap();
        let size: Inline<U256BE> = 5_u128.to_inline();
        derived += entity! { ExclusiveId::force_ref(&attachment) @
            archive::attachment_file: file_id,
            archive::attachment_size_bytes: size,
        };
        fixture
            .storage()
            .publish(derived, "materialize attachment")
            .unwrap();

        let materialized = load_view(&fixture);
        assert_eq!(
            one_required(
                find!(
                    value: Id,
                    pattern!(&materialized.facts, [{ attachment @ archive::attachment_file: ?value }])
                )
                .collect(),
                "materialized attachment file",
            )
            .unwrap(),
            file_id
        );
    }

    #[test]
    fn divergent_latest_message_ties_fail_closed() {
        let fixture = Fixture::new();
        let (first, first_receipt) = page_fragment(
            "tenant-a",
            vec![graph_message(
                "chat",
                "message",
                "2026-08-01T10:00:00Z",
                "2026-08-01T11:00:00Z",
                "left",
            )],
            1,
            [],
            "https://graph.example/delta-1",
        );
        fixture.publish(first);
        let (tie, _) = page_fragment(
            "tenant-a",
            vec![graph_message(
                "chat",
                "message",
                "2026-08-01T10:00:00Z",
                "2026-08-01T11:00:00Z",
                "right",
            )],
            2,
            [first_receipt],
            "https://graph.example/delta-2",
        );
        let before = fs::read(&fixture.pile).unwrap();
        let error = fixture.storage().publish(tie, "tie").unwrap_err();
        assert!(
            error.to_string().contains("causally ambiguous"),
            "unexpected rejection: {error:#}"
        );
        assert_eq!(fs::read(&fixture.pile).unwrap(), before);
        let view = load_view(&fixture);
        let source = source_fragment("tenant-a").root().unwrap();
        let current = current_messages(&view.facts, source).unwrap();
        assert_eq!(current.len(), 1);
        assert_eq!(
            read_utf8string(&view.reader, current[0].content.unwrap(), "test content").unwrap(),
            "left"
        );
    }

    #[test]
    fn causal_coverage_never_hides_a_stale_fork_behind_generation() {
        let fixture = Fixture::new();
        let (root, root_id) =
            page_fragment("tenant-a", vec![], 1, [], "https://graph.example/root");
        fixture.publish(root);
        let (main, main_id) = page_fragment(
            "tenant-a",
            vec![],
            2,
            [root_id],
            "https://graph.example/main",
        );
        fixture.publish(main);
        let (advanced, _) = page_fragment(
            "tenant-a",
            vec![],
            3,
            [main_id],
            "https://graph.example/advanced",
        );
        fixture.publish(advanced);
        let (stale_fork, _) = page_fragment(
            "tenant-a",
            vec![],
            2,
            [root_id],
            "https://graph.example/stale-fork",
        );
        let before = fs::read(&fixture.pile).unwrap();
        let error = fixture
            .storage()
            .publish(stale_fork, "stale fork")
            .unwrap_err();
        assert!(error.to_string().contains("coverage head has 2 values"));
        assert_eq!(fs::read(&fixture.pile).unwrap(), before);
    }

    #[test]
    fn inline_attachment_bytes_live_in_the_same_page_fragment() {
        let source = source_fragment("tenant-a").root().unwrap();
        let mut message = graph_message(
            "chat",
            "message",
            "2026-08-01T10:00:00Z",
            "2026-08-01T10:00:00Z",
            "file",
        );
        message["attachments"] = json!([{
            "id": "attachment-1",
            "name": "note.txt",
            "contentType": "text/plain; charset=utf-8",
            "contentBytes": base64::engine::general_purpose::STANDARD.encode(b"hello"),
        }]);
        let (fragment, _, _) = build_page_fragment(
            "tenant-a",
            source,
            parse_messages(vec![message]).unwrap(),
            "token",
            &[],
        )
        .unwrap();
        assert_eq!(
            find!(
                file: Id,
                pattern!(&fragment, [{ ?file @ metadata::tag: faculties::schemas::files::KIND_FILE }])
            )
            .count(),
            1
        );
        assert_eq!(
            find!(
                attachment: Id,
                pattern!(&fragment, [{
                    ?attachment @
                    metadata::tag: archive::kind_attachment,
                    archive::attachment_file: _?file,
                }])
            )
            .count(),
            1
        );
    }

    #[test]
    fn observations_without_their_page_receipt_are_rejected() {
        let source = source_fragment("tenant-a").root().unwrap();
        let (mut fragment, observations, _) = build_page_fragment(
            "tenant-a",
            source,
            parse_messages(vec![graph_message(
                "chat",
                "message",
                "2026-08-01T10:00:00Z",
                "2026-08-01T10:00:00Z",
                "atomic",
            )])
            .unwrap(),
            "token",
            &[],
        )
        .unwrap();
        assert!(validate_commit_fragment(fragment.facts()).is_err());

        fragment += coverage_fragment(
            source,
            1,
            [],
            "https://graph.example/request",
            "https://graph.example/delta",
            "delta",
            observations,
        )
        .unwrap();
        validate_commit_fragment(fragment.facts()).unwrap();
    }

    #[test]
    fn page_commit_cannot_borrow_identity_facts_from_the_catalog() {
        let fixture = Fixture::new();
        let (first, first_receipt) = page_fragment(
            "tenant-a",
            vec![graph_message(
                "chat",
                "message",
                "2026-08-01T10:00:00Z",
                "2026-08-01T10:00:00Z",
                "first",
            )],
            1,
            [],
            "https://graph.example/delta-1",
        );
        fixture.publish(first);

        let (second, _) = page_fragment(
            "tenant-a",
            vec![graph_message(
                "chat",
                "message",
                "2026-08-01T10:00:00Z",
                "2026-08-01T11:00:00Z",
                "second",
            )],
            2,
            [first_receipt],
            "https://graph.example/delta-2",
        );
        let chat = one_required(
            find!(
                value: Id,
                pattern!(&second, [{ ?value @ metadata::tag: teams::kind_chat }])
            )
            .collect(),
            "test chat",
        )
        .unwrap();
        let (_, facts, metafacts, blobs) = second.into_parts();
        let incomplete = facts
            .iter()
            .filter(|fact| fact.e() != &chat)
            .copied()
            .collect::<TribleSet>();
        let incomplete = Fragment::from_parts(incomplete, metafacts, blobs);
        let before = fs::read(&fixture.pile).unwrap();
        let error = fixture
            .storage()
            .publish(incomplete, "incomplete page")
            .unwrap_err();
        assert!(error.to_string().contains("names an unknown chat"));
        assert_eq!(fs::read(&fixture.pile).unwrap(), before);
    }

    #[test]
    fn malformed_inline_attachment_blocks_page_construction() {
        let mut message = graph_message(
            "chat",
            "message",
            "2026-08-01T10:00:00Z",
            "2026-08-01T10:00:00Z",
            "file",
        );
        message["attachments"] = json!([{
            "id": "attachment-1",
            "contentBytes": "not base64!",
        }]);
        assert!(parse_messages(vec![message]).is_err());

        let mut missing_id = graph_message(
            "chat",
            "message",
            "2026-08-01T10:00:00Z",
            "2026-08-01T10:00:00Z",
            "file",
        );
        missing_id["attachments"] = json!([{ "name": "orphan.bin" }]);
        assert!(parse_messages(vec![missing_id]).is_err());
    }

    #[test]
    fn exact_page_replay_is_idempotent() {
        let fixture = Fixture::new();
        let (page, _) = page_fragment(
            "tenant-a",
            vec![graph_message(
                "chat",
                "message",
                "2026-08-01T10:00:00Z",
                "2026-08-01T10:00:00Z",
                "same",
            )],
            1,
            [],
            "https://graph.example/delta",
        );
        fixture.publish(page.clone());
        let after_first = fs::metadata(&fixture.pile).unwrap().len();
        fixture.publish(page);
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), after_first);
    }

    #[test]
    fn login_resolves_generic_authority_to_token_tenant() {
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"tid":"tenant-guid"}"#);
        let token = format!("e30.{payload}.signature");
        assert_eq!(
            resolve_source_tenant("common", Some(&token), None).unwrap(),
            "tenant-guid"
        );
        assert!(resolve_source_tenant("common", None, None).is_err());
        assert_eq!(
            resolve_source_tenant("tenant.example", None, None).unwrap(),
            "tenant.example"
        );
    }

    #[test]
    fn attachment_references_preserve_collection_scope() {
        assert_eq!(
            attachment_reference(Some("hosted-content"), "42"),
            "hosted-content:42"
        );
        assert_eq!(
            parse_attachment_reference("attachment:42"),
            (Some("attachment"), "42")
        );
        assert_eq!(parse_attachment_reference("42"), (None, "42"));
    }
}
