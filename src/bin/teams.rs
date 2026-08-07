use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration as StdDuration;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use faculties::collection_access::{self, CollectionView, CollectionWriter};
use hifitime::{Epoch, TimeScale};
use reqwest::blocking::Client;
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::{Blob, Bytes, TryFromBlob};
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval, ShortString, U256BE};
use triblespace::prelude::*;

use faculties::files as file_capability;
use faculties::schemas::archive::{archive, RawBytes};
use faculties::schemas::files::{file, KIND_FILE, KIND_MEDIA_TYPE};
use faculties::schemas::teams::{teams, DEFAULT_DELTA_URL, DEFAULT_SCOPE_ID};

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
    /// Extrinsic Teams collection scope.
    #[arg(long, value_parser = parse_id_arg)]
    scope: Option<Id>,
    /// External 0600 JSON token/config cache. It is never copied into the pile.
    #[arg(long, env = "TEAMS_AUTH_FILE")]
    auth_file: Option<PathBuf>,
    /// Microsoft Entra tenant id (or domain).
    #[arg(long, env = "TEAMS_TENANT")]
    tenant: Option<String>,
    /// Microsoft application/client id.
    #[arg(long, env = "TEAMS_CLIENT_ID")]
    client_id: Option<String>,
    /// Microsoft application client secret. Use @path or @- for input.
    #[arg(long, env = "TEAMS_CLIENT_SECRET")]
    client_secret: Option<String>,
    /// User id whose chats are tracked by the application delta endpoint.
    #[arg(long, env = "TEAMS_USER_ID")]
    user_id: Option<String>,
    /// Microsoft Graph delta endpoint.
    #[arg(long, default_value = DEFAULT_DELTA_URL)]
    delta_url: String,
    /// OAuth bearer token (optional; otherwise use token command). Use @path for file input or @- for stdin.
    #[arg(long)]
    token: Option<String>,
    /// Command that outputs a bearer token. Use @path for file input or @- for stdin.
    #[arg(
        long,
        default_value = "az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv"
    )]
    token_command: String,
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
    /// Interactive device-code login to cache a delegated token.
    Login {
        /// Tenant id or domain (default: common).
        #[arg(long, default_value = "common")]
        tenant: String,
        /// Azure app client id.
        #[arg(long)]
        client_id: String,
        /// Azure app client secret (stored only in the external auth file).
        #[arg(
            long,
            help = "Azure app client secret (stored only in --auth-file). Use @path for file input or @- for stdin."
        )]
        client_secret: Option<String>,
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
    /// Show safe authentication metadata and token liveness (never secrets/tokens).
    Status,
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
struct TeamsBridgeConfig {
    pile_path: PathBuf,
    key_path: Option<PathBuf>,
    scope: Id,
    source_id: Id,
    presentation_context: TeamsPresentationContext,
    delta_url: String,
    token: Option<String>,
    token_command: String,
    auth_file: Option<PathBuf>,
    auth: ExternalAuth,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct ExternalAuth {
    tenant: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    user_id: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_at_unix: Option<i64>,
    token_type: Option<String>,
    scope: Option<String>,
}

#[derive(Clone, Copy)]
struct TeamsStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
    scope: Id,
}

impl TeamsStorage<'_> {
    fn view(&self) -> Result<CollectionView> {
        let signer = collection_access::load_signer(self.pile, self.key)?;
        let allowed = HashSet::from([signer.verifying_key()]);
        let view = collection_access::materialize_scope(self.pile, self.scope, &allowed)?;
        validate_commit_fragments(&view.reader, &view.commits)?;
        validate_catalog(&view.reader, &view.facts)?;
        Ok(view)
    }

    fn writer(&self) -> Result<CollectionWriter> {
        CollectionWriter::open(self.pile, self.key, self.scope)
    }

    fn publish(&self, fragment: Fragment, message: &str) -> Result<CollectionCommit> {
        let view = self.view()?;
        validate_candidate(&view.reader, &view.facts, &fragment)?;
        let metadata = entity! { metadata::description: message.to_owned() };
        collection_access::publish_fragment(self.pile, self.key, self.scope, fragment, metadata)
    }
}

fn parse_id_arg(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim()).ok_or_else(|| format!("invalid id '{raw}'"))
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
            read_messages(
                config,
                ReadOptions {
                    chat_id,
                    since,
                    limit,
                    descending,
                },
            )
        }
        CommandMode::Send { chat_id, text } => {
            let config = build_config(&cli)?;
            prepare_teams_context(&config, requested_as.as_deref(), true)?;
            let text = faculties::text_arg(&text, "message text")?;
            send_message(config, &chat_id, &text)
        }
        CommandMode::Users { command } => {
            let config = build_config(&cli)?;
            prepare_teams_context(&config, requested_as.as_deref(), false)?;
            match command {
                UsersCommand::List { prefix, limit } => {
                    list_users(config, prefix.as_deref(), limit)
                }
            }
        }
        CommandMode::Presence { command } => {
            let config = build_config(&cli)?;
            match command {
                PresenceCommand::Set {
                    availability,
                    activity,
                    duration_mins,
                    session_id,
                } => {
                    prepare_teams_context(&config, requested_as.as_deref(), true)?;
                    set_presence_status(config, availability, activity, duration_mins, session_id)
                }
                PresenceCommand::Get { user_ids } => {
                    prepare_teams_context(&config, requested_as.as_deref(), false)?;
                    get_presence(config, user_ids)
                }
            }
        }
        CommandMode::Chat { command } => {
            let config = build_config(&cli)?;
            match command {
                ChatCommand::Invite {
                    chat_id,
                    user_id,
                    owner,
                } => {
                    prepare_teams_context(&config, requested_as.as_deref(), true)?;
                    invite_to_chat(config, &chat_id, &user_id, owner)
                }
                ChatCommand::Create {
                    user_ids,
                    group,
                    topic,
                } => {
                    prepare_teams_context(&config, requested_as.as_deref(), true)?;
                    let topic = topic
                        .as_deref()
                        .map(|value| load_value_or_file(value, "chat topic"))
                        .transpose()?;
                    create_chat(config, user_ids, group, topic)
                }
            }
        }
        CommandMode::Attachments { command } => {
            let config = build_config(&cli)?;
            prepare_teams_context(&config, requested_as.as_deref(), false)?;
            match command {
                AttachmentsCommand::List {
                    chat_id,
                    message_id,
                    limit,
                    descending,
                } => list_attachments(
                    config,
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
                        config,
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
            }
        }
        CommandMode::Context { command } => {
            let config = build_config(&cli)?;
            match command {
                ContextCommand::Set {
                    present_as,
                    boundary,
                } => {
                    let context = store_context(&config, &present_as, &boundary)?;
                    show_context(&context)
                }
                ContextCommand::Show => show_context(&config.presentation_context),
            }
        }
        CommandMode::Auth { command } => {
            let config = build_config(&cli)?;
            prepare_teams_context(&config, requested_as.as_deref(), false)?;
            match command {
                AuthCommand::Status => show_auth_status(&config),
            }
        }
        CommandMode::Login {
            tenant,
            client_id,
            client_secret,
            scopes,
        } => {
            if cli.tenant.is_none() {
                cli.tenant = Some(tenant.clone());
            }
            let config = build_config_without_context(&cli)?;
            prepare_teams_context(&config, requested_as.as_deref(), false)?;
            let scopes = scopes
                .as_deref()
                .map(|value| load_value_or_file(value, "scopes"))
                .transpose()?
                .unwrap_or_else(default_scopes);
            let client_secret = client_secret
                .as_deref()
                .map(|value| load_value_or_file_trimmed(value, "client secret"))
                .transpose()?;
            login_device_code_external(
                &config,
                &tenant,
                &client_id,
                client_secret.as_deref(),
                &scopes,
            )
        }
    }
}

fn build_config(cli: &Cli) -> Result<TeamsBridgeConfig> {
    build_config_inner(cli, true)
}

fn build_config_without_context(cli: &Cli) -> Result<TeamsBridgeConfig> {
    build_config_inner(cli, false)
}

fn build_config_inner(cli: &Cli, read_context: bool) -> Result<TeamsBridgeConfig> {
    let pile_path = cli.pile.clone();
    let key_path = cli.key.clone();
    let scope = cli.scope.unwrap_or(DEFAULT_SCOPE_ID);
    let mut auth = cli
        .auth_file
        .as_deref()
        .map(load_external_auth)
        .transpose()?
        .flatten()
        .unwrap_or_default();
    override_nonempty(&mut auth.tenant, cli.tenant.clone());
    override_nonempty(&mut auth.client_id, cli.client_id.clone());
    override_nonempty(
        &mut auth.client_secret,
        cli.client_secret
            .as_deref()
            .map(|value| load_value_or_file_trimmed(value, "client secret"))
            .transpose()?,
    );
    override_nonempty(&mut auth.user_id, cli.user_id.clone());
    let tenant = auth
        .tenant
        .as_deref()
        .map(str::trim)
        .filter(|tenant| !tenant.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "missing Teams tenant; set --tenant/TEAMS_TENANT or configure --auth-file"
            )
        })?;
    if read_context && is_generic_tenant(tenant) {
        bail!(
            "Teams data needs a concrete tenant identity, not authority alias {tenant:?}; re-run `teams login` with --auth-file or set --tenant to the actual tenant id"
        );
    }
    let source = source_fragment(tenant);
    let source_id = source.root().expect("Teams source fragment has one root");
    let presentation_context = if read_context {
        let storage = TeamsStorage {
            pile: &pile_path,
            key: key_path.as_deref(),
            scope,
        };
        let view = storage.view()?;
        load_context(&view.reader, &view.facts, source_id)?
    } else {
        TeamsPresentationContext::default()
    };
    let delta_url = std::env::var("TEAMS_DELTA_URL")
        .ok()
        .unwrap_or_else(|| cli.delta_url.clone());
    let token = cli
        .token
        .clone()
        .or_else(|| std::env::var("TEAMS_TOKEN").ok());
    let token_command = std::env::var("TEAMS_TOKEN_COMMAND")
        .ok()
        .unwrap_or_else(|| cli.token_command.clone());
    Ok(TeamsBridgeConfig {
        pile_path,
        key_path,
        scope,
        source_id,
        presentation_context,
        delta_url,
        token,
        token_command,
        auth_file: cli.auth_file.clone(),
        auth,
    })
}

fn override_nonempty(target: &mut Option<String>, value: Option<String>) {
    if let Some(value) = value.map(|value| value.trim().to_owned()) {
        if !value.is_empty() {
            *target = Some(value);
        }
    }
}

fn source_fragment(tenant: &str) -> Fragment {
    let mut source = Fragment::empty();
    let tenant = source.put::<LongString, _>(canonical_tenant(tenant));
    source += entity! {
        metadata::tag: teams::kind_source,
        teams::tenant_id: tenant,
    };
    source
}

fn storage(config: &TeamsBridgeConfig) -> TeamsStorage<'_> {
    TeamsStorage {
        pile: &config.pile_path,
        key: config.key_path.as_deref(),
        scope: config.scope,
    }
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
    matches!(
        tenant.trim().to_ascii_lowercase().as_str(),
        "common" | "organizations" | "consumers"
    )
}

fn canonical_tenant(tenant: &str) -> String {
    tenant.trim().to_ascii_lowercase()
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
) -> Result<()> {
    let (token, app_config) = get_app_token(config, app_token_cache)?;
    let store = storage(config);
    let view = store.view()?;
    let mut known_messages = load_known_messages(&view.reader, &view.facts, config.source_id)?;
    let reader = view.reader;
    let mut catalog = view.facts;
    let mut coverage = coverage_head(&reader, &catalog, config.source_id)?;
    let base_url = resolve_delta_url(&config.delta_url, &app_config.user_id)?;
    let mut request_url = coverage
        .as_ref()
        .map(|coverage| coverage.cursor.clone())
        .unwrap_or_else(|| base_url.clone());
    let mut reset_expired = coverage.is_some();
    let mut writer = store.writer()?;

    let result = (|| loop {
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
        validate_candidate(&reader, &catalog, &fragment)?;

        let delta = fragment.facts().difference(&catalog);
        if !delta.is_empty() {
            writer.publish_fragment(
                fragment.clone(),
                entity! { metadata::description: "teams delta page".to_owned() },
            )?;
            catalog += fragment.into_facts();
        }
        known_messages = next_known_messages;

        coverage = Some(CoverageHead {
            id: receipt_id,
            generation,
            cursor: cursor.clone(),
        });
        if cursor_kind == "delta" {
            return Ok(());
        }
        request_url = cursor;
    })();
    writer.finish(result)
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
) -> Result<(String, AppConfig)> {
    let app_config = app_config(config)?;
    let now_key = interval_key(epoch_interval(now_epoch()));

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
    let expires_at = epoch_interval(epoch_after_seconds(now_epoch(), token.expires_in));
    let expires_at_key = interval_key(expires_at);
    let access_token = token.access_token;
    *app_token_cache = Some(AppTokenCache {
        access_token: access_token.clone(),
        expires_at_key,
    });
    Ok((access_token, app_config))
}

fn app_config(config: &TeamsBridgeConfig) -> Result<AppConfig> {
    let tenant =
        config.auth.tenant.clone().ok_or_else(|| {
            anyhow::anyhow!("missing tenant in Teams config; re-run teams.rs login")
        })?;
    let client_id = config.auth.client_id.clone().ok_or_else(|| {
        anyhow::anyhow!("missing client id in Teams config; re-run teams.rs login")
    })?;
    let client_secret = config.auth.client_secret.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "missing client secret; set --client-secret/TEAMS_CLIENT_SECRET or configure --auth-file"
        )
    })?;
    let user_id =
        config.auth.user_id.clone().ok_or_else(|| {
            anyhow::anyhow!("missing user id in Teams config; re-run teams.rs login")
        })?;

    Ok(AppConfig {
        tenant,
        client_id,
        client_secret,
        user_id,
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

fn get_delegated_token(config: &TeamsBridgeConfig) -> Result<String> {
    if let Some(token) = config
        .token
        .as_deref()
        .map(|value| load_value_or_file_trimmed(value, "token"))
        .transpose()?
    {
        let token = token.trim();
        if !token.is_empty() {
            return Ok(token.to_owned());
        }
    }

    if let Some(token) = external_cached_token(config)? {
        return Ok(token);
    }

    let token_command = load_value_or_file_trimmed(&config.token_command, "token command")?;
    let cmd = token_command
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    if cmd.is_empty() {
        bail!("token command is empty");
    }

    let mut command = Command::new(&cmd[0]);
    if cmd.len() > 1 {
        command.args(&cmd[1..]);
    }
    let output = command.output().context("run token command")?;
    if !output.status.success() {
        bail!(
            "token command failed: exit={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8(output.stdout).context("token command stdout not utf8")?;
    let token = stdout.trim();
    if token.is_empty() {
        bail!("token command returned empty token");
    }
    Ok(token.to_owned())
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
    error_description: Option<String>,
}

fn now_epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs() as i64
}

fn load_external_auth(path: &Path) -> Result<Option<ExternalAuth>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("parse Teams auth file {}", path.display()))
            .map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("read Teams auth file {}", path.display()))
        }
    }
}

fn store_external_auth(path: &Path, auth: &ExternalAuth) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("create Teams auth directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(auth).context("serialize Teams auth file")?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("teams-auth.json");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = path.with_file_name(format!(".{filename}.tmp-{}-{nonce}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("create temporary Teams auth file {}", temporary.display()))?;
    use std::io::Write as _;
    let write_result: Result<()> = (|| {
        file.write_all(&bytes)
            .with_context(|| format!("write Teams auth file {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("sync Teams auth file {}", temporary.display()))?;
        drop(file);
        fs::rename(&temporary, path).with_context(|| {
            format!(
                "atomically replace Teams auth file {} from {}",
                path.display(),
                temporary.display()
            )
        })?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restrict Teams auth file {}", path.display()))?;
    }
    Ok(())
}

fn external_cached_token(config: &TeamsBridgeConfig) -> Result<Option<String>> {
    let Some(access) = config.auth.access_token.as_deref() else {
        return Ok(None);
    };
    if config
        .auth
        .expires_at_unix
        .is_some_and(|expires| expires > now_epoch_secs() + 30)
    {
        return Ok(Some(access.to_owned()));
    }

    let (Some(path), Some(refresh), Some(tenant), Some(client_id)) = (
        config.auth_file.as_deref(),
        config.auth.refresh_token.as_deref(),
        config.auth.tenant.as_deref(),
        config.auth.client_id.as_deref(),
    ) else {
        return Ok(None);
    };
    let refreshed = refresh_token(tenant, client_id, refresh, config.auth.scope.as_deref())?;
    let mut auth = config.auth.clone();
    auth.access_token = Some(refreshed.access_token.clone());
    auth.refresh_token = refreshed
        .refresh_token
        .or_else(|| config.auth.refresh_token.clone());
    auth.expires_at_unix = Some(now_epoch_secs() + refreshed.expires_in);
    auth.scope = refreshed.scope.or_else(|| config.auth.scope.clone());
    auth.token_type = refreshed
        .token_type
        .or_else(|| config.auth.token_type.clone());
    store_external_auth(path, &auth)?;
    Ok(Some(refreshed.access_token))
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
            name: Inline<Handle<LongString>>,
            pattern!(catalog, [{ context_id @ metadata::name: ?name }])
        )
        .collect(),
        "Teams presentation name",
    )?
    .map(|handle| read_longstring(reader, handle, "Teams presentation name"))
    .transpose()?;
    let boundary = one_optional(
        find!(
            boundary: Inline<Handle<LongString>>,
            pattern!(catalog, [{ context_id @ metadata::description: ?boundary }])
        )
        .collect(),
        "Teams presentation boundary",
    )?
    .map(|handle| read_longstring(reader, handle, "Teams presentation boundary"))
    .transpose()?;
    Ok(TeamsPresentationContext { name, boundary })
}

fn store_context(
    config: &TeamsBridgeConfig,
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

    let store = storage(config);
    let view = store.view()?;
    let supersedes = current_context_head_ids(&view.facts, config.source_id);
    let mut fragment = source_fragment(
        config
            .auth
            .tenant
            .as_deref()
            .expect("build_config requires a tenant"),
    );
    let name_handle = fragment.put::<LongString, _>(presentation_name.to_owned());
    let boundary_handle = fragment.put::<LongString, _>(presentation_boundary.to_owned());
    fragment += entity! {
        metadata::tag: teams::kind_context,
        teams::source: config.source_id,
        metadata::created_at: epoch_interval(now_epoch()),
        metadata::supersedes*: supersedes,
        metadata::name: name_handle,
        metadata::description: boundary_handle,
    };
    if !fragment.facts().difference(&view.facts).is_empty() {
        store.publish(fragment, "teams professional context")?;
    }
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
    config: &TeamsBridgeConfig,
    requested_as: Option<&str>,
    require_explicit_identity: bool,
) -> Result<TeamsPresentationContext> {
    let context = config.presentation_context.clone();
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

fn show_auth_status(config: &TeamsBridgeConfig) -> Result<()> {
    println!(
        "auth_file: {}",
        config
            .auth_file
            .as_deref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "(none; environment/arguments only)".to_owned())
    );
    println!(
        "tenant: {}",
        config.auth.tenant.as_deref().unwrap_or("(unset)")
    );
    println!(
        "client_id: {}",
        config.auth.client_id.as_deref().unwrap_or("(unset)")
    );
    println!(
        "app_client_secret: {}",
        if config.auth.client_secret.is_some() {
            "configured externally (validity not checked)"
        } else {
            "not configured"
        }
    );
    println!(
        "user_identity: {}",
        if config.auth.user_id.is_some() {
            "configured"
        } else {
            "not configured"
        }
    );
    let access_state = match (
        config.auth.access_token.as_ref(),
        config.auth.expires_at_unix,
    ) {
        (Some(_), Some(expires)) if expires > now_epoch_secs() + 30 => "locally unexpired",
        (Some(_), _) => "locally expired or expiry unknown",
        _ => "not configured",
    };
    println!("delegated_access_token: {access_state}");
    println!(
        "delegated_refresh_token: {}",
        if config.auth.refresh_token.is_some() {
            "configured externally (validity not checked)"
        } else {
            "not configured"
        }
    );
    Ok(())
}

fn current_context_head_ids(catalog: &TribleSet, source_id: Id) -> BTreeSet<Id> {
    let mut context_ids = find!(
        (context: Id),
        pattern!(catalog, [{
            ?context @
            metadata::tag: teams::kind_context,
            teams::source: source_id,
        }])
    )
    .into_iter()
    .map(|(context_id,)| context_id)
    .collect::<BTreeSet<_>>();

    let superseded = find!(
        (predecessor: Id),
        pattern!(catalog, [{
            _?successor @
            metadata::tag: teams::kind_context,
            teams::source: source_id,
            metadata::supersedes: ?predecessor,
        }])
    )
    .into_iter()
    .map(|(predecessor,)| predecessor)
    .collect::<HashSet<_>>();
    context_ids.retain(|context_id| !superseded.contains(context_id));
    context_ids
}

fn load_chat_map(
    reader: &PileReader,
    catalog: &TribleSet,
    source_id: Id,
) -> Result<HashMap<Id, String>> {
    let mut map = HashMap::new();
    for (chat_id, handle) in find!(
        (chat: Id, chat_id: Inline<Handle<LongString>>),
        pattern!(catalog, [{
            ?chat @
            metadata::tag: teams::kind_chat,
            teams::source: source_id,
            teams::chat_id: ?chat_id,
        }])
    ) {
        let value = read_longstring(reader, handle, "Teams chat id")?;
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
        (message: Id, external: Inline<Handle<LongString>>),
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
        let value = read_longstring(reader, handle, "Teams message id")?;
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
            message_external: Inline<Handle<LongString>>,
            chat: Id,
            chat_external: Inline<Handle<LongString>>
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
            message_external_id: read_longstring(reader, message_external, "Teams message id")?,
            chat_id,
            chat_external_id: read_longstring(reader, chat_external, "Teams chat id")?,
        });
    }
    Ok(known.into_iter().collect())
}

fn read_longstring(
    reader: &PileReader,
    handle: Inline<Handle<LongString>>,
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

fn login_device_code_external(
    config: &TeamsBridgeConfig,
    tenant: &str,
    client_id: &str,
    client_secret: Option<&str>,
    scopes: &str,
) -> Result<()> {
    let auth_path = config.auth_file.as_deref().ok_or_else(|| {
        anyhow::anyhow!("Teams login requires --auth-file/TEAMS_AUTH_FILE; credentials are never stored in the pile")
    })?;
    let device = request_device_code(tenant, client_id, scopes)?;
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
    let deadline = now_epoch_secs() + device.expires_in;
    let token = poll_device_token(tenant, client_id, &device.device_code, interval, deadline)?;
    let user_id = fetch_me_id(&token.access_token)?;
    let source_tenant =
        resolve_source_tenant(tenant, token.id_token.as_deref(), Some(&token.access_token))?;
    let auth = ExternalAuth {
        tenant: Some(source_tenant),
        client_id: Some(client_id.to_owned()),
        client_secret: client_secret
            .map(str::to_owned)
            .or_else(|| config.auth.client_secret.clone()),
        user_id: Some(user_id),
        access_token: Some(token.access_token),
        refresh_token: token.refresh_token,
        expires_at_unix: Some(now_epoch_secs() + token.expires_in),
        token_type: token.token_type,
        scope: token.scope.or_else(|| Some(scopes.to_owned())),
    };
    store_external_auth(auth_path, &auth)?;
    println!(
        "Stored Teams credentials in {} (mode 0600).",
        auth_path.display()
    );
    println!("No authentication material was written to the pile.");
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
        bail!("device code request failed: status={status} body={body}");
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
        if now_epoch_secs() >= deadline {
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

        let err: ErrorResponse = serde_json::from_str(&body).unwrap_or(ErrorResponse {
            error: "unknown".to_owned(),
            error_description: Some(body.clone()),
        });

        match err.error.as_str() {
            "authorization_pending" => {
                thread::sleep(StdDuration::from_secs(interval));
            }
            "slow_down" => {
                interval += 5;
                thread::sleep(StdDuration::from_secs(interval));
            }
            "expired_token" => bail!("device code expired"),
            other => bail!(
                "device code authorization failed: {other} {}",
                err.error_description.unwrap_or_default()
            ),
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
        bail!("refresh token failed: status={status} body={body}");
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
        bail!("client credentials token failed: status={status} body={body}");
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

fn send_message(config: TeamsBridgeConfig, chat_id: &str, text: &str) -> Result<()> {
    let token = get_delegated_token(&config)?;
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

fn list_users(config: TeamsBridgeConfig, prefix: Option<&str>, limit: usize) -> Result<()> {
    let token = get_delegated_token(&config)?;
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
    config: TeamsBridgeConfig,
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
    let user_id = config
        .auth
        .user_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("missing user id; re-run teams.rs login"))?;
    let default_session = config
        .auth
        .client_id
        .clone()
        .unwrap_or_else(|| user_id.clone());
    let session_id = session_id.unwrap_or(default_session);

    let token = get_delegated_token(&config)?;
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

fn get_presence(config: TeamsBridgeConfig, user_ids: Vec<String>) -> Result<()> {
    if user_ids.is_empty() {
        bail!("presence-get requires at least one user id");
    }
    let token = get_delegated_token(&config)?;
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
    config: TeamsBridgeConfig,
    chat_id: &str,
    user_id: &str,
    owner: bool,
) -> Result<()> {
    let token = get_delegated_token(&config)?;
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
    config: TeamsBridgeConfig,
    mut user_ids: Vec<String>,
    force_group: bool,
    topic: Option<String>,
) -> Result<()> {
    if user_ids.is_empty() {
        bail!("chat-create requires at least one user id");
    }
    let self_id = config
        .auth
        .user_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("missing user id; re-run teams.rs login"))?;
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
    let token = get_delegated_token(&config)?;
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
    author_names: BTreeSet<Inline<Handle<LongString>>>,
    deleted: bool,
    created_at: Inline<NsTAIInterval>,
    created_at_key: i128,
    content: Option<Inline<Handle<LongString>>>,
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
    name: Option<Inline<Handle<LongString>>>,
    media_type: Option<Inline<Handle<LongString>>>,
}

#[derive(Debug, Clone)]
struct AttachmentRow {
    attachment_id: Id,
    message_id: Id,
    chat_id: Id,
    created_at: Inline<NsTAIInterval>,
    created_at_key: i128,
    source_id: Option<Inline<Handle<LongString>>>,
    source_kind: Option<Inline<ShortString>>,
    source_pointers: BTreeSet<Inline<Handle<LongString>>>,
    name: Option<Inline<Handle<LongString>>>,
    media_type: Option<Inline<Handle<LongString>>>,
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
    let logical_messages = find!(
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
    .collect::<BTreeSet<_>>();
    let message_chats = logical_messages.into_iter().collect::<BTreeMap<_, _>>();
    let heads = coverage_head_ids(catalog, source_id);
    if heads.is_empty() {
        return Ok(Vec::new());
    }
    let head = one_required(heads, "Teams coverage head")?;

    let mut observations = BTreeMap::new();
    for (observation, message, modified) in find!(
        (
            observation: Id,
            message: Id,
            modified: Inline<NsTAIInterval>
        ),
        pattern!(catalog, [{
            ?observation @
            metadata::tag: teams::kind_message_observation,
            teams::message: ?message,
            teams::modified_at: ?modified,
        }])
    ) {
        let state = one_required(
            find!(
                value: Inline<ShortString>,
                pattern!(catalog, [{ observation @ teams::message_state: ?value }])
            )
            .collect(),
            "Teams observation state",
        )?;
        let state = String::try_from_inline(&state)
            .map_err(|error| anyhow::anyhow!("decode Teams observation state: {error:?}"))?;
        observations.insert(
            observation,
            ObservationOrder {
                message,
                modified: interval_key(modified),
                deleted: state == "deleted",
            },
        );
    }
    let tombstones = find!(
        (tombstone: Id, message: Id),
        pattern!(catalog, [{
            ?tombstone @
            metadata::tag: teams::kind_message_tombstone,
            teams::message: ?message,
        }])
    )
    .collect::<BTreeMap<_, _>>();

    let mut receipts = Vec::new();
    for (receipt, generation) in find!(
        (receipt: Id, generation: Inline<U256BE>),
        pattern!(catalog, [{
            ?receipt @
            metadata::tag: teams::kind_coverage,
            teams::source: source_id,
            teams::coverage_generation: ?generation,
        }])
    ) {
        receipts.push(ReceiptOrder {
            id: receipt,
            generation: inline_u256_to_u128(generation)?,
            predecessors: find!(
                value: Id,
                pattern!(catalog, [{ receipt @ metadata::supersedes: ?value }])
            )
            .collect(),
            events: find!(
                value: Id,
                pattern!(catalog, [{ receipt @ teams::coverage_observation: ?value }])
            )
            .collect(),
        });
    }
    receipts.sort_by_key(|receipt| (receipt.generation, receipt.id));

    let mut remaining_children = BTreeMap::<Id, usize>::new();
    for receipt in &receipts {
        for predecessor in &receipt.predecessors {
            *remaining_children.entry(*predecessor).or_default() += 1;
        }
    }

    let mut states = BTreeMap::<Id, BTreeMap<Id, CausalMessageState>>::new();
    for receipt in receipts {
        // A normal delta history is a chain. Move its state forward instead
        // of cloning the complete message map for every page; branch points
        // retain snapshots only until their last child has consumed them.
        let mut state = if receipt.predecessors.len() == 1 {
            let predecessor = *receipt.predecessors.first().expect("one predecessor");
            let remaining = remaining_children
                .get_mut(&predecessor)
                .expect("predecessor child count was collected");
            let take_parent = *remaining == 1;
            *remaining -= 1;
            if take_parent {
                states.remove(&predecessor).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Teams coverage {:x} names an unavailable predecessor {predecessor:x}",
                        receipt.id
                    )
                })?
            } else {
                states.get(&predecessor).cloned().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Teams coverage {:x} names an unavailable predecessor {predecessor:x}",
                        receipt.id
                    )
                })?
            }
        } else {
            let mut merged = BTreeMap::new();
            for predecessor in &receipt.predecessors {
                let parent = states.get(predecessor).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Teams coverage {:x} names an unavailable predecessor {predecessor:x}",
                        receipt.id
                    )
                })?;
                merge_causal_states(&mut merged, parent, &observations)?;
                let remaining = remaining_children
                    .get_mut(predecessor)
                    .expect("predecessor child count was collected");
                *remaining -= 1;
            }
            for predecessor in &receipt.predecessors {
                if remaining_children.get(predecessor) == Some(&0) {
                    states.remove(predecessor);
                }
            }
            merged
        };

        let mut page_observations = BTreeMap::<Id, BTreeSet<Id>>::new();
        let mut page_tombstones = BTreeSet::new();
        for event in &receipt.events {
            if let Some(observation) = observations.get(event) {
                page_observations
                    .entry(observation.message)
                    .or_default()
                    .insert(*event);
            } else if let Some(message) = tombstones.get(event) {
                page_tombstones.insert(*message);
            } else {
                bail!(
                    "Teams coverage {:x} carries unknown event {event:x}",
                    receipt.id
                );
            }
        }
        if let Some(message) = page_tombstones
            .iter()
            .find(|message| page_observations.contains_key(*message))
        {
            bail!(
                "Teams coverage {:x} carries unordered full and @removed events for message {message:x}",
                receipt.id
            );
        }
        for (message, page_versions) in page_observations {
            apply_page_observations(&mut state, message, &page_versions, &observations)?;
        }
        for message in page_tombstones {
            let entry = state.entry(message).or_default();
            entry.visible = CausalVisible::Deleted(None);
        }
        states.insert(receipt.id, state);
    }

    let current = states
        .get(&head)
        .ok_or_else(|| anyhow::anyhow!("Teams coverage head {head:x} was not evaluable"))?;
    let mut result = Vec::new();
    for (message_id, state) in current {
        let Some(chat_id) = message_chats.get(message_id).copied() else {
            bail!("Teams causal state names message {message_id:x} outside source {source_id:x}");
        };
        match state.visible {
            CausalVisible::Unknown | CausalVisible::Deleted(None) => {}
            CausalVisible::Conflict => {
                bail!("current Teams state for message {message_id:x} is causally ambiguous")
            }
            CausalVisible::Present(observation) => result.push(read_message_observation(
                catalog,
                *message_id,
                chat_id,
                observation,
                false,
            )?),
            CausalVisible::Deleted(Some(observation)) => result.push(read_message_observation(
                catalog,
                *message_id,
                chat_id,
                observation,
                true,
            )?),
        }
    }
    Ok(result)
}

#[derive(Clone, Copy, Debug)]
struct ObservationOrder {
    message: Id,
    modified: i128,
    deleted: bool,
}

#[derive(Clone, Debug)]
struct ReceiptOrder {
    id: Id,
    generation: u128,
    predecessors: BTreeSet<Id>,
    events: BTreeSet<Id>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CausalVisible {
    Unknown,
    Present(Id),
    Deleted(Option<Id>),
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CausalMessageState {
    max_seen_modified: Option<i128>,
    visible: CausalVisible,
}

impl Default for CausalMessageState {
    fn default() -> Self {
        Self {
            max_seen_modified: None,
            visible: CausalVisible::Unknown,
        }
    }
}

fn merge_causal_states(
    target: &mut BTreeMap<Id, CausalMessageState>,
    parent: &BTreeMap<Id, CausalMessageState>,
    observations: &BTreeMap<Id, ObservationOrder>,
) -> Result<()> {
    for (message, incoming) in parent {
        let entry = target.entry(*message).or_default();
        let visible = merge_causal_visible(entry.visible, incoming.visible, observations)?;
        entry.max_seen_modified = entry.max_seen_modified.max(incoming.max_seen_modified);
        entry.visible = visible;
    }
    Ok(())
}

fn merge_causal_visible(
    left: CausalVisible,
    right: CausalVisible,
    observations: &BTreeMap<Id, ObservationOrder>,
) -> Result<CausalVisible> {
    use CausalVisible::{Conflict, Deleted, Present, Unknown};
    Ok(match (left, right) {
        (Unknown, value) | (value, Unknown) => value,
        (Conflict, _) | (_, Conflict) => Conflict,
        (Present(left), Present(right)) if left == right => Present(left),
        (Deleted(Some(left)), Deleted(Some(right))) if left == right => Deleted(Some(left)),
        (Present(left), Present(right)) => {
            newer_versioned_visible(Present(left), left, Present(right), right, observations)?
        }
        (Present(left), Deleted(Some(right))) => newer_versioned_visible(
            Present(left),
            left,
            Deleted(Some(right)),
            right,
            observations,
        )?,
        (Deleted(Some(left)), Present(right)) => newer_versioned_visible(
            Deleted(Some(left)),
            left,
            Present(right),
            right,
            observations,
        )?,
        (Deleted(Some(left)), Deleted(Some(right))) => newer_versioned_visible(
            Deleted(Some(left)),
            left,
            Deleted(Some(right)),
            right,
            observations,
        )?,
        (Deleted(None), Deleted(None)) => Deleted(None),
        (Deleted(None), Present(_) | Deleted(Some(_)))
        | (Present(_) | Deleted(Some(_)), Deleted(None)) => Conflict,
    })
}

fn newer_versioned_visible(
    left_visible: CausalVisible,
    left: Id,
    right_visible: CausalVisible,
    right: Id,
    observations: &BTreeMap<Id, ObservationOrder>,
) -> Result<CausalVisible> {
    let left_order = observations
        .get(&left)
        .ok_or_else(|| anyhow::anyhow!("missing Teams observation {left:x}"))?;
    let right_order = observations
        .get(&right)
        .ok_or_else(|| anyhow::anyhow!("missing Teams observation {right:x}"))?;
    Ok(match left_order.modified.cmp(&right_order.modified) {
        std::cmp::Ordering::Less => right_visible,
        std::cmp::Ordering::Greater => left_visible,
        std::cmp::Ordering::Equal => CausalVisible::Conflict,
    })
}

fn apply_page_observations(
    states: &mut BTreeMap<Id, CausalMessageState>,
    message: Id,
    page_versions: &BTreeSet<Id>,
    observations: &BTreeMap<Id, ObservationOrder>,
) -> Result<()> {
    let newest_time = page_versions
        .iter()
        .map(|id| {
            observations
                .get(id)
                .map(|observation| observation.modified)
                .ok_or_else(|| anyhow::anyhow!("missing Teams observation {id:x}"))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max()
        .expect("page observation group is nonempty");
    let newest = page_versions
        .iter()
        .filter(|id| {
            observations
                .get(*id)
                .is_some_and(|value| value.modified == newest_time)
        })
        .copied()
        .collect::<BTreeSet<_>>();
    let newest = one_required(
        newest,
        &format!("latest source version in one Teams page for message {message:x}"),
    )?;
    let order = observations
        .get(&newest)
        .expect("newest observation came from map");
    let state = states.entry(message).or_default();
    let before = state.max_seen_modified;
    state.max_seen_modified = Some(before.map_or(newest_time, |old| old.max(newest_time)));

    if before.is_none_or(|old| newest_time > old) {
        state.visible = if order.deleted {
            CausalVisible::Deleted(Some(newest))
        } else {
            CausalVisible::Present(newest)
        };
        return Ok(());
    }
    if newest_time < before.expect("checked Some above") {
        return Ok(());
    }
    state.visible = match state.visible {
        CausalVisible::Present(current) if current == newest && !order.deleted => {
            CausalVisible::Present(current)
        }
        CausalVisible::Deleted(Some(current)) if current == newest && order.deleted => {
            CausalVisible::Deleted(Some(current))
        }
        // An unversioned tombstone remains authoritative over an equal/old
        // replay after a cursor reset. Only a strictly newer source version
        // can restore it.
        CausalVisible::Deleted(None) => CausalVisible::Deleted(None),
        _ => CausalVisible::Conflict,
    };
    Ok(())
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
            content: Inline<Handle<LongString>>,
            pattern!(catalog, [{ observation_id @ archive::content: ?content }])
        )
        .collect(),
        "Teams message content",
    )?;
    let author_names = find!(
        name: Inline<Handle<LongString>>,
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

fn read_messages(config: TeamsBridgeConfig, options: ReadOptions) -> Result<()> {
    let mut app_token_cache = None;
    pull_once_with_cache(&config, &mut app_token_cache)?;
    let view = storage(&config).view()?;
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
        let content = read_longstring(
            &view.reader,
            message.content.expect("present observation has content"),
            "Teams message content",
        )?;
        let mut author_names = message
            .author_names
            .into_iter()
            .map(|handle| read_longstring(&view.reader, handle, "Teams author display name"))
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

fn list_attachments(config: TeamsBridgeConfig, options: AttachmentListOptions) -> Result<()> {
    let mut app_token_cache = None;
    pull_once_with_cache(&config, &mut app_token_cache)?;
    let view = storage(&config).view()?;
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
            .map(|handle| read_longstring(&view.reader, handle, "Teams attachment source id"))
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
            .map(|handle| read_longstring(&view.reader, handle, "Teams attachment pointer"))
            .collect::<Result<Vec<_>>>()?;
        source_pointers.sort();
        source_pointers.dedup();
        let name = row
            .name
            .map(|handle| read_longstring(&view.reader, handle, "Teams attachment name"))
            .transpose()?;
        let media_type = row
            .media_type
            .map(|handle| read_longstring(&view.reader, handle, "Teams attachment media type"))
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
                    value: Inline<Handle<LongString>>,
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
                value: Inline<Handle<LongString>>,
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
                    value: Inline<Handle<LongString>>,
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

fn export_attachment(config: TeamsBridgeConfig, options: AttachmentExportOptions) -> Result<()> {
    let mut app_token_cache = None;
    pull_once_with_cache(&config, &mut app_token_cache)?;
    let view = storage(&config).view()?;
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
        let source = read_longstring(
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
        .map(|handle| read_longstring(&view.reader, handle, "attachment media type"))
        .transpose()?;
    let mut filename = options
        .filename
        .or_else(|| {
            candidate
                .name
                .map(|handle| read_longstring(&view.reader, handle, "attachment name"))
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
                parse_graph_datetime(value)
                    .map(epoch_interval)
                    .ok_or_else(|| anyhow::anyhow!("invalid Teams createdDateTime {value:?}"))
            })
            .transpose()?;
        let deleted_at = message
            .get("deletedDateTime")
            .and_then(JsonValue::as_str)
            .map(|value| {
                parse_graph_datetime(value)
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
                parse_graph_datetime(value)
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
    for hosted_id in extract_hosted_content_ids(content) {
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

fn extract_hosted_content_ids(content: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut seen = HashSet::new();
    let needle = "/hostedContents/";
    let mut pos = 0;
    while let Some(idx) = content[pos..].find(needle) {
        let start = pos + idx + needle.len();
        let rest = &content[start..];
        let end = rest.find('/').unwrap_or(rest.len());
        let id = rest[..end].trim();
        if !id.is_empty() && seen.insert(id.to_string()) {
            ids.push(id.to_string());
        }
        pos = start + end;
    }
    ids
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct CoverageHead {
    id: Id,
    generation: u128,
    cursor: String,
}

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

fn coverage_head_ids(catalog: &TribleSet, source_id: Id) -> BTreeSet<Id> {
    let receipts = find!(
        receipt: Id,
        pattern!(catalog, [{
            ?receipt @
            metadata::tag: teams::kind_coverage,
            teams::source: source_id,
        }])
    )
    .collect::<BTreeSet<_>>();
    let superseded = find!(
        predecessor: Id,
        pattern!(catalog, [{
            _?successor @
            metadata::tag: teams::kind_coverage,
            teams::source: source_id,
            metadata::supersedes: ?predecessor,
        }])
    )
    .collect::<BTreeSet<_>>();
    receipts.difference(&superseded).copied().collect()
}

fn coverage_head(
    reader: &PileReader,
    catalog: &TribleSet,
    source_id: Id,
) -> Result<Option<CoverageHead>> {
    let receipts = find!(
        receipt: Id,
        pattern!(catalog, [{
            ?receipt @
            metadata::tag: teams::kind_coverage,
            teams::source: source_id,
        }])
    )
    .collect::<BTreeSet<_>>();
    if receipts.is_empty() {
        return Ok(None);
    }
    let heads = coverage_head_ids(catalog, source_id);
    let Some(id) = one_optional(heads, "Teams coverage head")? else {
        bail!("Teams coverage graph has records but no head (cycle or invalid predecessor)");
    };
    let generation = inline_u256_to_u128(one_required(
        find!(
            generation: Inline<U256BE>,
            pattern!(catalog, [{ id @ teams::coverage_generation: ?generation }])
        )
        .collect(),
        "Teams coverage generation",
    )?)?;
    let cursor = read_longstring(
        reader,
        one_required(
            find!(
                cursor: Inline<Handle<LongString>>,
                pattern!(catalog, [{ id @ teams::coverage_cursor: ?cursor }])
            )
            .collect(),
            "Teams coverage cursor",
        )?,
        "Teams coverage cursor",
    )?;
    let kind_inline = one_required(
        find!(
            kind: Inline<ShortString>,
            pattern!(catalog, [{ id @ teams::coverage_kind: ?kind }])
        )
        .collect(),
        "Teams coverage cursor kind",
    )?;
    let kind = String::try_from_inline(&kind_inline)
        .map_err(|error| anyhow::anyhow!("decode Teams coverage kind: {error:?}"))?;
    if kind != "next" && kind != "delta" {
        bail!("invalid Teams coverage cursor kind {kind:?}");
    }
    Ok(Some(CoverageHead {
        id,
        generation,
        cursor,
    }))
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
    if kind != "next" && kind != "delta" {
        bail!("invalid Teams coverage cursor kind {kind:?}");
    }
    let predecessors = predecessors.into_iter().collect::<BTreeSet<_>>();
    let observations = observations.into_iter().collect::<BTreeSet<_>>();
    let mut fragment = Fragment::empty();
    let request = fragment.put::<LongString, _>(request.to_owned());
    let cursor = fragment.put::<LongString, _>(cursor.to_owned());
    let generation: Inline<U256BE> = generation.to_inline();
    fragment += entity! {
        metadata::tag: teams::kind_coverage,
        teams::source: source_id,
        teams::coverage_generation: generation,
        teams::coverage_request: request,
        teams::coverage_cursor: cursor,
        teams::coverage_kind: kind,
        metadata::supersedes*: predecessors,
        teams::coverage_observation*: observations,
    };
    Ok(fragment)
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
            let raw = fragment.put::<LongString, _>(message.raw_json);
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
                let external = fragment.put::<LongString, _>(external.to_owned());
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
            .map(|content| fragment.put::<LongString, _>(content.to_owned()));
        let etag = fragment.put::<LongString, _>(
            message
                .etag
                .as_ref()
                .expect("full Teams source version has an etag")
                .to_owned(),
        );
        let author_name = message
            .author_display_name
            .as_ref()
            .map(|name| fragment.put::<LongString, _>(name.to_owned()));
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
        let raw = fragment.put::<LongString, _>(message.raw_json);
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
    let chat_external = fragment.put::<LongString, _>(chat_external_id.to_owned());
    let chat = entity! {
        metadata::tag: teams::kind_chat,
        teams::source: source_id,
        teams::chat_id: chat_external,
    };
    let chat_id = chat.root().expect("Teams chat fragment has one root");
    *fragment += chat;

    let message_external = fragment.put::<LongString, _>(message_external_id.to_owned());
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
    let source_handle = fragment.put::<LongString, _>(source_id.to_owned());
    let name = source
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| fragment.put::<LongString, _>(name.to_owned()));
    let source_pointer = source
        .source_url
        .as_ref()
        .map(|url| fragment.put::<LongString, _>(url.to_owned()));

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
        let file = file_capability::fragment(bytes, file_name, &media_type)?;
        let file_id = file.root().expect("canonical file fragment has one root");
        let (_, file_facts, file_blobs) = file.into_parts();
        fragment += Fragment::from_facts_and_blobs(file_facts, file_blobs);
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

fn validate_commit_fragments(reader: &PileReader, commits: &[CollectionCommit]) -> Result<()> {
    for commit in commits {
        let handle = Handle::<SimpleArchive>::from_hash(commit.data());
        let blob: Blob<SimpleArchive> = reader
            .get(handle)
            .with_context(|| format!("read Teams COMMIT data for {:x}", commit.id()))?;
        let facts = TribleSet::try_from_blob(blob)
            .with_context(|| format!("decode Teams COMMIT data for {:x}", commit.id()))?;
        validate_commit_fragment(&facts)
            .with_context(|| format!("validate Teams COMMIT {:x}", commit.id()))?;
    }
    Ok(())
}

/// Validate a page against the state it would create before any dependency or
/// signed COMMIT byte reaches the pile. This is deliberately stronger than
/// validating the isolated fragment: append-only storage cannot repair a
/// singular-field conflict or stale coverage fork after it has been signed.
fn validate_candidate(reader: &PileReader, catalog: &TribleSet, fragment: &Fragment) -> Result<()> {
    validate_commit_fragment(fragment.facts())?;
    validate_fragment_payloads(reader, fragment)?;
    let mut union = catalog.clone();
    union += fragment.facts().clone();
    validate_catalog_structure(&union)
}

fn validate_fragment_payloads(reader: &PileReader, fragment: &Fragment) -> Result<()> {
    let mut local = fragment.blobs().clone();
    let local = local.reader().context("snapshot Teams page payloads")?;
    let text_attributes = [
        teams::chat_id.id(),
        teams::message_id.id(),
        teams::message_raw.id(),
        teams::user_id.id(),
        teams::tenant_id.id(),
        teams::etag.id(),
        teams::author_name.id(),
        teams::coverage_request.id(),
        teams::coverage_cursor.id(),
        archive::content.id(),
        archive::attachment_source_id.id(),
        archive::attachment_source_pointer.id(),
        archive::attachment_name.id(),
        file::name.id(),
        metadata::name.id(),
        metadata::description.id(),
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    for fact in fragment.facts() {
        if text_attributes.contains(fact.a()) {
            let handle = *fact.v::<Handle<LongString>>();
            let text: anybytes::View<str> = if local
                .metadata(handle)
                .context("inspect staged Teams text payload")?
                .is_some()
            {
                local.get(handle).with_context(|| {
                    format!(
                        "decode staged Teams text payload {}",
                        hex::encode_upper(handle.raw)
                    )
                })?
            } else {
                reader.get(handle).with_context(|| {
                    format!(
                        "read existing Teams text payload {}",
                        hex::encode_upper(handle.raw)
                    )
                })?
            };
            if fact.a() == &teams::tenant_id.id()
                && (text.is_empty()
                    || text.as_ref() != canonical_tenant(text.as_ref())
                    || is_generic_tenant(text.as_ref()))
            {
                bail!("Teams page carries a non-canonical tenant identity");
            }
        } else if fact.a() == &file::content.id() {
            let handle = *fact.v::<Handle<RawBytes>>();
            if local
                .metadata(handle)
                .context("inspect staged attachment bytes")?
                .is_some()
            {
                let _: Bytes = local.get(handle).with_context(|| {
                    format!(
                        "decode staged attachment bytes {}",
                        hex::encode_upper(handle.raw)
                    )
                })?;
            } else {
                let _: Bytes = reader.get(handle).with_context(|| {
                    format!(
                        "read existing attachment bytes {}",
                        hex::encode_upper(handle.raw)
                    )
                })?;
            }
        }
    }
    Ok(())
}

/// Enforce the ingestion transaction boundary independently for every signed
/// member. A page receipt is useful only when the exact observations and their
/// required attachment records became durable in that same COMMIT.
fn validate_commit_fragment(facts: &TribleSet) -> Result<()> {
    let receipts = find!(
        receipt: Id,
        pattern!(facts, [{ ?receipt @ metadata::tag: teams::kind_coverage }])
    )
    .collect::<BTreeSet<_>>();
    let observations = find!(
        observation: Id,
        pattern!(facts, [{ ?observation @ metadata::tag: teams::kind_message_observation }])
    )
    .collect::<BTreeSet<_>>();
    let tombstones = find!(
        tombstone: Id,
        pattern!(facts, [{ ?tombstone @ metadata::tag: teams::kind_message_tombstone }])
    )
    .collect::<BTreeSet<_>>();

    if receipts.is_empty() && observations.is_empty() && tombstones.is_empty() {
        return Ok(());
    }
    let receipt = one_required(receipts, "Teams page receipt in one COMMIT")?;
    let covered = find!(
        observation: Id,
        pattern!(facts, [{ receipt @ teams::coverage_observation: ?observation }])
    )
    .collect::<BTreeSet<_>>();
    let mut events = observations.clone();
    events.extend(tombstones.iter().copied());
    if covered != events {
        bail!("Teams page COMMIT receipt coverage does not exactly match its message events");
    }

    let source = one_required(
        find!(
            source: Id,
            pattern!(facts, [{ receipt @ teams::source: ?source }])
        )
        .collect(),
        "Teams page receipt source",
    )?;
    let sources = find!(
        value: Id,
        pattern!(facts, [{ ?value @ metadata::tag: teams::kind_source }])
    )
    .collect::<BTreeSet<_>>();
    if sources != BTreeSet::from([source]) {
        bail!("Teams page COMMIT must contain exactly its receipt source identity {source:x}");
    }
    validate_source_identity(facts, source)?;

    let chats = find!(
        value: Id,
        pattern!(facts, [{ ?value @ metadata::tag: teams::kind_chat }])
    )
    .collect::<BTreeSet<_>>();
    for chat in &chats {
        validate_chat_identity(facts, *chat, &sources)?;
    }
    let authors = find!(
        value: Id,
        pattern!(facts, [{ ?value @ metadata::tag: archive::kind_author }])
    )
    .collect::<BTreeSet<_>>();
    for author in &authors {
        validate_author_identity(facts, *author, &sources)?;
    }
    let messages = find!(
        value: Id,
        pattern!(facts, [{ ?value @ metadata::tag: archive::kind_message }])
    )
    .collect::<BTreeSet<_>>();
    for message in &messages {
        validate_message_identity(facts, *message, &chats)?;
    }
    let attachments = find!(
        value: Id,
        pattern!(facts, [{ ?value @ metadata::tag: archive::kind_attachment }])
    )
    .collect::<BTreeSet<_>>();
    for attachment in &attachments {
        validate_attachment(facts, *attachment, &messages)?;
    }

    for observation in &observations {
        validate_observation(facts, *observation, &messages, &attachments, &authors)?;
    }
    for tombstone in &tombstones {
        validate_tombstone(facts, *tombstone, &messages)?;
    }

    validate_receipt_identity_local(facts, receipt, source, &events)?;
    validate_attachment_file_structure(facts, &attachments)?;
    Ok(())
}

fn validate_source_identity(facts: &TribleSet, source: Id) -> Result<()> {
    let tenant = one_required(
        find!(
            value: Inline<Handle<LongString>>,
            pattern!(facts, [{ source @ teams::tenant_id: ?value }])
        )
        .collect(),
        "Teams source tenant",
    )?;
    let expected = entity! {
        metadata::tag: teams::kind_source,
        teams::tenant_id: tenant,
    }
    .root()
    .expect("source identity has one root");
    if expected != source {
        bail!("Teams source {source:x} is not intrinsically tenant-scoped");
    }
    Ok(())
}

fn validate_chat_identity(facts: &TribleSet, chat: Id, sources: &BTreeSet<Id>) -> Result<()> {
    let source = one_required(
        find!(value: Id, pattern!(facts, [{ chat @ teams::source: ?value }])).collect(),
        "Teams chat source",
    )?;
    if !sources.contains(&source) {
        bail!("Teams chat {chat:x} names a source omitted from its COMMIT");
    }
    let external = one_required(
        find!(
            value: Inline<Handle<LongString>>,
            pattern!(facts, [{ chat @ teams::chat_id: ?value }])
        )
        .collect(),
        "Teams chat external id",
    )?;
    let expected = entity! {
        metadata::tag: teams::kind_chat,
        teams::source: source,
        teams::chat_id: external,
    }
    .root()
    .expect("chat identity has one root");
    if expected != chat {
        bail!("Teams chat {chat:x} is not intrinsically source-scoped");
    }
    Ok(())
}

fn validate_author_identity(facts: &TribleSet, author: Id, sources: &BTreeSet<Id>) -> Result<()> {
    let source = one_required(
        find!(value: Id, pattern!(facts, [{ author @ teams::source: ?value }])).collect(),
        "Teams user source",
    )?;
    if !sources.contains(&source) {
        bail!("Teams user {author:x} names a source omitted from its COMMIT");
    }
    let external = one_required(
        find!(
            value: Inline<Handle<LongString>>,
            pattern!(facts, [{ author @ teams::user_id: ?value }])
        )
        .collect(),
        "Teams user external id",
    )?;
    let expected = entity! {
        metadata::tag: archive::kind_author,
        teams::source: source,
        teams::user_id: external,
    }
    .root()
    .expect("user identity has one root");
    if expected != author {
        bail!("Teams user {author:x} is not intrinsically source-scoped");
    }
    Ok(())
}

fn validate_message_identity(facts: &TribleSet, message: Id, chats: &BTreeSet<Id>) -> Result<()> {
    let chat = one_required(
        find!(value: Id, pattern!(facts, [{ message @ teams::chat: ?value }])).collect(),
        "Teams message chat",
    )?;
    if !chats.contains(&chat) {
        bail!("Teams message {message:x} names a chat omitted from its COMMIT");
    }
    let external = one_required(
        find!(
            value: Inline<Handle<LongString>>,
            pattern!(facts, [{ message @ teams::message_id: ?value }])
        )
        .collect(),
        "Teams message external id",
    )?;
    let expected = entity! {
        metadata::tag: archive::kind_message,
        teams::chat: chat,
        teams::message_id: external,
    }
    .root()
    .expect("message identity has one root");
    if expected != message {
        bail!("Teams message {message:x} is not intrinsically chat-scoped");
    }
    Ok(())
}

fn validate_receipt_identity_local(
    facts: &TribleSet,
    receipt: Id,
    source: Id,
    events: &BTreeSet<Id>,
) -> Result<()> {
    let generation = one_required(
        find!(
            value: Inline<U256BE>,
            pattern!(facts, [{ receipt @ teams::coverage_generation: ?value }])
        )
        .collect(),
        "Teams coverage generation",
    )?;
    let _ = inline_u256_to_u128(generation)?;
    let request = one_required(
        find!(
            value: Inline<Handle<LongString>>,
            pattern!(facts, [{ receipt @ teams::coverage_request: ?value }])
        )
        .collect(),
        "Teams coverage request",
    )?;
    let cursor = one_required(
        find!(
            value: Inline<Handle<LongString>>,
            pattern!(facts, [{ receipt @ teams::coverage_cursor: ?value }])
        )
        .collect(),
        "Teams coverage cursor",
    )?;
    let kind = one_required(
        find!(
            value: Inline<ShortString>,
            pattern!(facts, [{ receipt @ teams::coverage_kind: ?value }])
        )
        .collect(),
        "Teams coverage kind",
    )?;
    let kind_text = String::try_from_inline(&kind)
        .map_err(|error| anyhow::anyhow!("decode Teams coverage kind: {error:?}"))?;
    if kind_text != "next" && kind_text != "delta" {
        bail!("invalid Teams coverage kind {kind_text:?}");
    }
    let predecessors = find!(
        value: Id,
        pattern!(facts, [{ receipt @ metadata::supersedes: ?value }])
    )
    .collect::<BTreeSet<_>>();
    let expected = entity! {
        metadata::tag: teams::kind_coverage,
        teams::source: source,
        teams::coverage_generation: generation,
        teams::coverage_request: request,
        teams::coverage_cursor: cursor,
        teams::coverage_kind: kind,
        metadata::supersedes*: predecessors,
        teams::coverage_observation*: events.clone(),
    }
    .root()
    .expect("coverage identity has one root");
    if expected != receipt {
        bail!("Teams coverage receipt {receipt:x} is not intrinsic");
    }
    Ok(())
}

fn validate_attachment_file_structure(facts: &TribleSet, attachments: &BTreeSet<Id>) -> Result<()> {
    let referenced_files = attachments
        .iter()
        .flat_map(|attachment| {
            find!(
                value: Id,
                pattern!(facts, [{ *attachment @ archive::attachment_file: ?value }])
            )
        })
        .collect::<BTreeSet<_>>();
    let files = find!(
        value: Id,
        pattern!(facts, [{ ?value @ metadata::tag: KIND_FILE }])
    )
    .collect::<BTreeSet<_>>();
    let media_types = find!(
        value: Id,
        pattern!(facts, [{ ?value @ metadata::tag: KIND_MEDIA_TYPE }])
    )
    .collect::<BTreeSet<_>>();
    for media_type in &media_types {
        let media_name = one_required(
            find!(
                value: Inline<Handle<LongString>>,
                pattern!(facts, [{ *media_type @ metadata::name: ?value }])
            )
            .collect(),
            "attachment media type name",
        )?;
        let expected_media = entity! {
            metadata::tag: KIND_MEDIA_TYPE,
            metadata::name: media_name,
        }
        .root()
        .expect("media type identity has one root");
        if expected_media != *media_type {
            bail!("attachment media type {media_type:x} is not intrinsic");
        }
    }
    if !referenced_files.is_subset(&files) {
        if let Some(file_id) = referenced_files.difference(&files).next() {
            bail!("Teams facts omit attachment file {file_id:x}");
        }
    }
    for file_id in files {
        let content = one_required(
            find!(
                value: Inline<Handle<RawBytes>>,
                pattern!(facts, [{ file_id @ file::content: ?value }])
            )
            .collect(),
            "attachment file content",
        )?;
        let name = one_required(
            find!(
                value: Inline<Handle<LongString>>,
                pattern!(facts, [{ file_id @ file::name: ?value }])
            )
            .collect(),
            "attachment file name",
        )?;
        let media_type = one_required(
            find!(
                value: Id,
                pattern!(facts, [{ file_id @ file::media_type: ?value }])
            )
            .collect(),
            "attachment file media type",
        )?;
        if !media_types.contains(&media_type) {
            bail!("Teams facts omit media-type identity {media_type:x}");
        }
        let media_name = one_required(
            find!(
                value: Inline<Handle<LongString>>,
                pattern!(facts, [{ media_type @ metadata::name: ?value }])
            )
            .collect(),
            "attachment media type name",
        )?;
        let expected_media = entity! {
            metadata::tag: KIND_MEDIA_TYPE,
            metadata::name: media_name,
        }
        .root()
        .expect("media type identity has one root");
        if expected_media != media_type {
            bail!("attachment media type {media_type:x} is not intrinsic");
        }
        let expected_file = entity! {
            metadata::tag: KIND_FILE,
            file::content: content,
            file::name: name,
            file::media_type: media_type,
        }
        .root()
        .expect("file identity has one root");
        if expected_file != file_id {
            bail!("attachment file {file_id:x} is not canonical");
        }
    }
    Ok(())
}

fn validate_catalog(reader: &PileReader, catalog: &TribleSet) -> Result<()> {
    validate_known_payloads(reader, catalog)?;
    file_capability::validate_catalog(reader, catalog)?;
    validate_catalog_structure(catalog)?;

    let sources = find!(
        source: Id,
        pattern!(catalog, [{ ?source @ metadata::tag: teams::kind_source }])
    )
    .collect::<BTreeSet<_>>();
    for source_id in &sources {
        let tenant = one_required(
            find!(
                value: Inline<Handle<LongString>>,
                pattern!(catalog, [{ *source_id @ teams::tenant_id: ?value }])
            )
            .collect(),
            "Teams source tenant",
        )?;
        let tenant_text = read_longstring(reader, tenant, "Teams source tenant")?;
        if tenant_text.is_empty()
            || tenant_text != canonical_tenant(&tenant_text)
            || is_generic_tenant(&tenant_text)
        {
            bail!("Teams source {source_id:x} has a non-canonical tenant identity");
        }
    }
    Ok(())
}

fn validate_catalog_structure(catalog: &TribleSet) -> Result<()> {
    let sources = find!(
        source: Id,
        pattern!(catalog, [{ ?source @ metadata::tag: teams::kind_source }])
    )
    .collect::<BTreeSet<_>>();
    for source in &sources {
        validate_source_identity(catalog, *source)?;
    }
    let chats = find!(
        chat: Id,
        pattern!(catalog, [{ ?chat @ metadata::tag: teams::kind_chat }])
    )
    .collect::<BTreeSet<_>>();
    for chat in &chats {
        validate_chat_identity(catalog, *chat, &sources)?;
    }

    let authors = find!(
        author: Id,
        pattern!(catalog, [{ ?author @ metadata::tag: archive::kind_author }])
    )
    .collect::<BTreeSet<_>>();
    for author in &authors {
        validate_author_identity(catalog, *author, &sources)?;
    }

    let messages = find!(
        message: Id,
        pattern!(catalog, [{ ?message @ metadata::tag: archive::kind_message }])
    )
    .collect::<BTreeSet<_>>();
    for message in &messages {
        validate_message_identity(catalog, *message, &chats)?;
    }

    let attachments = find!(
        attachment: Id,
        pattern!(catalog, [{ ?attachment @ metadata::tag: archive::kind_attachment }])
    )
    .collect::<BTreeSet<_>>();
    for attachment_id in &attachments {
        validate_attachment(catalog, *attachment_id, &messages)?;
    }
    validate_attachment_file_structure(catalog, &attachments)?;

    let observations = find!(
        observation: Id,
        pattern!(catalog, [{
            ?observation @ metadata::tag: teams::kind_message_observation
        }])
    )
    .collect::<BTreeSet<_>>();
    for observation_id in &observations {
        validate_observation(catalog, *observation_id, &messages, &attachments, &authors)?;
    }
    let tombstones = find!(
        tombstone: Id,
        pattern!(catalog, [{ ?tombstone @ metadata::tag: teams::kind_message_tombstone }])
    )
    .collect::<BTreeSet<_>>();
    for tombstone_id in &tombstones {
        validate_tombstone(catalog, *tombstone_id, &messages)?;
    }
    let mut events = observations.clone();
    events.extend(tombstones);
    validate_coverage(catalog, &sources, &events)?;
    validate_contexts(catalog, &sources)?;
    for source in &sources {
        let source_id = *source;
        let heads = coverage_head_ids(catalog, source_id);
        let has_coverage = find!(
            (),
            pattern!(catalog, [{
                _?receipt @
                metadata::tag: teams::kind_coverage,
                teams::source: source_id,
            }])
        )
        .next()
        .is_some();
        if has_coverage {
            let _ = one_required(heads, "Teams coverage head")?;
        }
        let context_heads = current_context_head_ids(catalog, source_id);
        let has_context = find!(
            (),
            pattern!(catalog, [{
                _?context @
                metadata::tag: teams::kind_context,
                teams::source: source_id,
            }])
        )
        .next()
        .is_some();
        if has_context {
            let _ = one_required(context_heads, "Teams context head")?;
        }
        let _ = current_messages(catalog, source_id)?;
    }
    Ok(())
}

fn validate_known_payloads(reader: &PileReader, catalog: &TribleSet) -> Result<()> {
    let text_attributes = [
        teams::chat_id.id(),
        teams::message_id.id(),
        teams::message_raw.id(),
        teams::user_id.id(),
        teams::tenant_id.id(),
        teams::etag.id(),
        teams::author_name.id(),
        teams::coverage_request.id(),
        teams::coverage_cursor.id(),
        archive::content.id(),
        archive::attachment_source_id.id(),
        archive::attachment_source_pointer.id(),
        archive::attachment_name.id(),
        metadata::name.id(),
        metadata::description.id(),
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    for fact in catalog {
        if text_attributes.contains(fact.a()) {
            let handle = *fact.v::<Handle<LongString>>();
            let _: anybytes::View<str> = reader.get(handle).with_context(|| {
                format!("read Teams text payload {}", hex::encode_upper(handle.raw))
            })?;
        }
    }
    Ok(())
}

fn validate_attachment(
    catalog: &TribleSet,
    attachment_id: Id,
    messages: &BTreeSet<Id>,
) -> Result<()> {
    let message = one_required(
        find!(
            value: Id,
            pattern!(catalog, [{ attachment_id @ teams::attachment_message: ?value }])
        )
        .collect(),
        "Teams attachment message",
    )?;
    if !messages.contains(&message) {
        bail!("Teams attachment {attachment_id:x} names an unknown message {message:x}");
    }
    let source = one_required(
        find!(
            value: Inline<Handle<LongString>>,
            pattern!(catalog, [{ attachment_id @ archive::attachment_source_id: ?value }])
        )
        .collect(),
        "Teams attachment source id",
    )?;
    let kind = one_required(
        find!(
            value: Inline<ShortString>,
            pattern!(catalog, [{ attachment_id @ teams::attachment_kind: ?value }])
        )
        .collect(),
        "Teams attachment kind",
    )?;
    let kind_text = String::try_from_inline(&kind)
        .map_err(|error| anyhow::anyhow!("decode Teams attachment kind: {error:?}"))?;
    if kind_text != "attachment" && kind_text != "hosted-content" {
        bail!("invalid Teams attachment kind {kind_text:?}");
    }
    let name = one_optional(
        find!(
            value: Inline<Handle<LongString>>,
            pattern!(catalog, [{ attachment_id @ archive::attachment_name: ?value }])
        )
        .collect(),
        "Teams attachment name",
    )?;
    let _pointers = find!(
        value: Inline<Handle<LongString>>,
        pattern!(catalog, [{ attachment_id @ archive::attachment_source_pointer: ?value }])
    )
    .collect::<BTreeSet<_>>();
    let file = one_optional(
        find!(
            value: Id,
            pattern!(catalog, [{ attachment_id @ archive::attachment_file: ?value }])
        )
        .collect(),
        "Teams attachment file",
    )?;
    let size = one_optional(
        find!(
            value: Inline<U256BE>,
            pattern!(catalog, [{ attachment_id @ archive::attachment_size_bytes: ?value }])
        )
        .collect(),
        "Teams attachment size",
    )?;
    if kind_text == "hosted-content" && file.is_none() {
        bail!("hosted Teams attachment {attachment_id:x} lacks required bytes");
    }
    if file.is_some() != size.is_some() {
        bail!("Teams attachment {attachment_id:x} must carry file and byte size together");
    }
    let expected = entity! {
        metadata::tag: archive::kind_attachment,
        archive::attachment_source_id: source,
        teams::attachment_message: message,
        teams::attachment_kind: kind,
        archive::attachment_name?: name,
    }
    .root()
    .expect("attachment identity has one root");
    if expected != attachment_id {
        bail!("Teams attachment {attachment_id:x} is not an intrinsic source occurrence");
    }
    Ok(())
}

fn validate_observation(
    catalog: &TribleSet,
    observation_id: Id,
    messages: &BTreeSet<Id>,
    attachments: &BTreeSet<Id>,
    authors: &BTreeSet<Id>,
) -> Result<()> {
    let message = one_required(
        find!(
            value: Id,
            pattern!(catalog, [{ observation_id @ teams::message: ?value }])
        )
        .collect(),
        "Teams observation message",
    )?;
    if !messages.contains(&message) {
        bail!("Teams observation {observation_id:x} names an unknown message {message:x}");
    }
    let state = one_required(
        find!(
            value: Inline<ShortString>,
            pattern!(catalog, [{ observation_id @ teams::message_state: ?value }])
        )
        .collect(),
        "Teams observation state",
    )?;
    let state_text = String::try_from_inline(&state)
        .map_err(|error| anyhow::anyhow!("decode Teams observation state: {error:?}"))?;
    if state_text != "present" && state_text != "deleted" {
        bail!("invalid Teams observation state {state_text:?}");
    }
    let created = one_optional(
        find!(
            value: Inline<NsTAIInterval>,
            pattern!(catalog, [{ observation_id @ metadata::created_at: ?value }])
        )
        .collect(),
        "Teams observation created time",
    )?;
    let modified = one_required(
        find!(
            value: Inline<NsTAIInterval>,
            pattern!(catalog, [{ observation_id @ teams::modified_at: ?value }])
        )
        .collect(),
        "Teams observation modified time",
    )?;
    let deleted = one_optional(
        find!(
            value: Inline<NsTAIInterval>,
            pattern!(catalog, [{ observation_id @ teams::deleted_at: ?value }])
        )
        .collect(),
        "Teams observation deleted time",
    )?;
    let author = one_optional(
        find!(
            value: Id,
            pattern!(catalog, [{ observation_id @ archive::author: ?value }])
        )
        .collect(),
        "Teams observation author",
    )?;
    if author.is_some_and(|author| !authors.contains(&author)) {
        bail!("Teams observation {observation_id:x} names an unknown author");
    }
    let _author_names = find!(
        value: Inline<Handle<LongString>>,
        pattern!(catalog, [{ observation_id @ teams::author_name: ?value }])
    )
    .collect::<BTreeSet<_>>();
    let content = one_optional(
        find!(
            value: Inline<Handle<LongString>>,
            pattern!(catalog, [{ observation_id @ archive::content: ?value }])
        )
        .collect(),
        "Teams observation content",
    )?;
    let etag = one_required(
        find!(
            value: Inline<Handle<LongString>>,
            pattern!(catalog, [{ observation_id @ teams::etag: ?value }])
        )
        .collect(),
        "Teams observation etag",
    )?;
    let observation_attachments = find!(
        value: Id,
        pattern!(catalog, [{ observation_id @ archive::attachment: ?value }])
    )
    .collect::<BTreeSet<_>>();
    if !observation_attachments.is_subset(attachments) {
        bail!("Teams observation {observation_id:x} names an unknown attachment");
    }
    for attachment in &observation_attachments {
        let owner = one_required(
            find!(
                value: Id,
                pattern!(catalog, [{ *attachment @ teams::attachment_message: ?value }])
            )
            .collect(),
            "Teams attachment owner",
        )?;
        if owner != message {
            bail!(
                "Teams observation {observation_id:x} links attachment {attachment:x} owned by another message"
            );
        }
    }
    let raw = find!(
        value: Inline<Handle<LongString>>,
        pattern!(catalog, [{ observation_id @ teams::message_raw: ?value }])
    )
    .collect::<BTreeSet<_>>();
    if raw.is_empty() {
        bail!("Teams observation {observation_id:x} has no raw source representation");
    }
    if state_text == "present" && (created.is_none() || content.is_none()) {
        bail!("present Teams observation {observation_id:x} lacks created time or content");
    }
    if state_text == "present" && deleted.is_some() {
        bail!("present Teams observation {observation_id:x} carries a deletion time");
    }
    if state_text == "deleted" && deleted.is_none() {
        bail!("versioned deleted Teams observation {observation_id:x} lacks deletedDateTime");
    }
    let expected = entity! {
        metadata::tag: teams::kind_message_observation,
        teams::message: message,
        teams::modified_at: modified,
        teams::etag: etag,
    }
    .root()
    .expect("observation identity has one root");
    if expected != observation_id {
        bail!("Teams observation {observation_id:x} is not an intrinsic source version");
    }
    Ok(())
}

fn validate_tombstone(
    catalog: &TribleSet,
    tombstone_id: Id,
    messages: &BTreeSet<Id>,
) -> Result<()> {
    let message = one_required(
        find!(
            value: Id,
            pattern!(catalog, [{ tombstone_id @ teams::message: ?value }])
        )
        .collect(),
        "Teams tombstone message",
    )?;
    if !messages.contains(&message) {
        bail!("Teams tombstone {tombstone_id:x} names an unknown message {message:x}");
    }
    let state = one_required(
        find!(
            value: Inline<ShortString>,
            pattern!(catalog, [{ tombstone_id @ teams::message_state: ?value }])
        )
        .collect(),
        "Teams tombstone state",
    )?;
    let state_text = String::try_from_inline(&state)
        .map_err(|error| anyhow::anyhow!("decode Teams tombstone state: {error:?}"))?;
    if state_text != "deleted" {
        bail!("invalid Teams tombstone state {state_text:?}");
    }
    let raw = find!(
        value: Inline<Handle<LongString>>,
        pattern!(catalog, [{ tombstone_id @ teams::message_raw: ?value }])
    )
    .collect::<BTreeSet<_>>();
    if raw.is_empty() {
        bail!("Teams tombstone {tombstone_id:x} has no raw source representation");
    }
    let expected = entity! {
        metadata::tag: teams::kind_message_tombstone,
        teams::message: message,
    }
    .root()
    .expect("tombstone identity has one root");
    if expected != tombstone_id {
        bail!("Teams tombstone {tombstone_id:x} is not intrinsic");
    }
    Ok(())
}

fn validate_coverage(
    catalog: &TribleSet,
    sources: &BTreeSet<Id>,
    events: &BTreeSet<Id>,
) -> Result<()> {
    let receipts = find!(
        receipt: Id,
        pattern!(catalog, [{ ?receipt @ metadata::tag: teams::kind_coverage }])
    )
    .collect::<BTreeSet<_>>();
    let mut generations = BTreeMap::new();
    for receipt in &receipts {
        let source = one_required(
            find!(value: Id, pattern!(catalog, [{ *receipt @ teams::source: ?value }])).collect(),
            "Teams coverage source",
        )?;
        if !sources.contains(&source) {
            bail!("Teams coverage {receipt:x} names an unknown source {source:x}");
        }
        let generation_inline = one_required(
            find!(
                value: Inline<U256BE>,
                pattern!(catalog, [{ *receipt @ teams::coverage_generation: ?value }])
            )
            .collect(),
            "Teams coverage generation",
        )?;
        let generation = inline_u256_to_u128(generation_inline)?;
        let request = one_required(
            find!(
                value: Inline<Handle<LongString>>,
                pattern!(catalog, [{ *receipt @ teams::coverage_request: ?value }])
            )
            .collect(),
            "Teams coverage request",
        )?;
        let cursor = one_required(
            find!(
                value: Inline<Handle<LongString>>,
                pattern!(catalog, [{ *receipt @ teams::coverage_cursor: ?value }])
            )
            .collect(),
            "Teams coverage cursor",
        )?;
        let kind = one_required(
            find!(
                value: Inline<ShortString>,
                pattern!(catalog, [{ *receipt @ teams::coverage_kind: ?value }])
            )
            .collect(),
            "Teams coverage kind",
        )?;
        let kind_text = String::try_from_inline(&kind)
            .map_err(|error| anyhow::anyhow!("decode Teams coverage kind: {error:?}"))?;
        if kind_text != "next" && kind_text != "delta" {
            bail!("invalid Teams coverage kind {kind_text:?}");
        }
        let predecessors = find!(
            value: Id,
            pattern!(catalog, [{ *receipt @ metadata::supersedes: ?value }])
        )
        .collect::<BTreeSet<_>>();
        let covered = find!(
            value: Id,
            pattern!(catalog, [{ *receipt @ teams::coverage_observation: ?value }])
        )
        .collect::<BTreeSet<_>>();
        if !covered.is_subset(events) {
            bail!("Teams coverage {receipt:x} names an unknown message event");
        }
        for event in &covered {
            let message = one_required(
                find!(
                    value: Id,
                    pattern!(catalog, [{ *event @ teams::message: ?value }])
                )
                .collect(),
                "Teams covered event message",
            )?;
            let chat = one_required(
                find!(
                    value: Id,
                    pattern!(catalog, [{ message @ teams::chat: ?value }])
                )
                .collect(),
                "Teams covered event chat",
            )?;
            let event_source = one_required(
                find!(
                    value: Id,
                    pattern!(catalog, [{ chat @ teams::source: ?value }])
                )
                .collect(),
                "Teams covered event source",
            )?;
            if event_source != source {
                bail!("Teams coverage {receipt:x} carries event {event:x} from another source");
            }
        }
        let expected = entity! {
            metadata::tag: teams::kind_coverage,
            teams::source: source,
            teams::coverage_generation: generation_inline,
            teams::coverage_request: request,
            teams::coverage_cursor: cursor,
            teams::coverage_kind: kind,
            metadata::supersedes*: predecessors.clone(),
            teams::coverage_observation*: covered,
        }
        .root()
        .expect("coverage identity has one root");
        if expected != *receipt {
            bail!("Teams coverage receipt {receipt:x} is not intrinsic");
        }
        generations.insert(*receipt, (source, generation, predecessors));
    }
    for (receipt, (source, generation, predecessors)) in &generations {
        if predecessors.is_empty() {
            if *generation != 1 {
                bail!("root Teams coverage {receipt:x} has generation {generation}, not 1");
            }
            continue;
        }
        let mut parent_generation = None;
        for predecessor in predecessors {
            let Some((parent_source, parent, _)) = generations.get(predecessor) else {
                bail!("Teams coverage {receipt:x} names unknown predecessor {predecessor:x}");
            };
            if parent_source != source {
                bail!("Teams coverage {receipt:x} crosses source boundaries");
            }
            parent_generation =
                Some(parent_generation.map_or(*parent, |old: u128| old.max(*parent)));
        }
        if parent_generation.and_then(|parent| parent.checked_add(1)) != Some(*generation) {
            bail!("Teams coverage {receipt:x} generation is not max(parent)+1");
        }
    }
    Ok(())
}

fn validate_contexts(catalog: &TribleSet, sources: &BTreeSet<Id>) -> Result<()> {
    let contexts = find!(
        context: Id,
        pattern!(catalog, [{ ?context @ metadata::tag: teams::kind_context }])
    )
    .collect::<BTreeSet<_>>();
    for context in &contexts {
        let source = one_required(
            find!(value: Id, pattern!(catalog, [{ *context @ teams::source: ?value }])).collect(),
            "Teams context source",
        )?;
        if !sources.contains(&source) {
            bail!("Teams context {context:x} names unknown source {source:x}");
        }
        let created = one_required(
            find!(
                value: Inline<NsTAIInterval>,
                pattern!(catalog, [{ *context @ metadata::created_at: ?value }])
            )
            .collect(),
            "Teams context created time",
        )?;
        let name = one_required(
            find!(
                value: Inline<Handle<LongString>>,
                pattern!(catalog, [{ *context @ metadata::name: ?value }])
            )
            .collect(),
            "Teams context name",
        )?;
        let description = one_required(
            find!(
                value: Inline<Handle<LongString>>,
                pattern!(catalog, [{ *context @ metadata::description: ?value }])
            )
            .collect(),
            "Teams context boundary",
        )?;
        let predecessors = find!(
            value: Id,
            pattern!(catalog, [{ *context @ metadata::supersedes: ?value }])
        )
        .collect::<BTreeSet<_>>();
        for predecessor in &predecessors {
            if !contexts.contains(predecessor) {
                bail!("Teams context {context:x} names unknown predecessor {predecessor:x}");
            }
            let predecessor_source = one_required(
                find!(
                    value: Id,
                    pattern!(catalog, [{ *predecessor @ teams::source: ?value }])
                )
                .collect(),
                "Teams predecessor context source",
            )?;
            if predecessor_source != source {
                bail!("Teams context {context:x} crosses source boundaries");
            }
        }
        let expected = entity! {
            metadata::tag: teams::kind_context,
            teams::source: source,
            metadata::created_at: created,
            metadata::supersedes*: predecessors,
            metadata::name: name,
            metadata::description: description,
        }
        .root()
        .expect("context identity has one root");
        if expected != *context {
            bail!("Teams context {context:x} is not an immutable snapshot");
        }
    }
    Ok(())
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

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
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
        .or_else(|| parse_graph_datetime(value))
        .ok_or_else(|| anyhow::anyhow!("invalid timestamp: {}", value))?;
    Ok(Some(interval_key(epoch_interval(epoch))))
}

fn parse_graph_datetime(value: &str) -> Option<Epoch> {
    // Accept common Graph formats:
    // - 2025-01-01T12:34:56Z
    // - 2025-01-01T12:34:56.1234567Z
    // - 2025-01-01T12:34:56+00:00
    let value = value.trim();
    let (date, time) = value.split_once('T')?;
    let (year, month, day) = {
        let mut parts = date.splitn(3, '-');
        let year = parts.next()?.parse::<i32>().ok()?;
        let month = parts.next()?.parse::<u8>().ok()?;
        let day = parts.next()?.parse::<u8>().ok()?;
        (year, month, day)
    };

    let (time, offset_secs) = parse_time_and_offset(time)?;
    let (hour, minute, second, nanos) = time;

    let mut epoch = Epoch::from_gregorian_utc(
        year,
        month as u8,
        day as u8,
        hour as u8,
        minute as u8,
        second as u8,
        nanos as u32,
    );
    if offset_secs != 0 {
        use hifitime::Duration as HifiDuration;
        epoch -= HifiDuration::from_seconds(offset_secs as f64);
    }
    Some(epoch)
}

fn parse_time_and_offset(value: &str) -> Option<((u8, u8, u8, u32), i32)> {
    // Returns ((hour, min, sec, nanos), offset_secs)
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if let Some(stripped) = value.strip_suffix('Z') {
        let time = parse_hms_fraction(stripped)?;
        return Some((time, 0));
    }

    if let Some((time, offset)) = split_timezone_offset(value) {
        let time = parse_hms_fraction(time)?;
        let offset_secs = parse_offset_seconds(offset)?;
        return Some((time, offset_secs));
    }

    let time = parse_hms_fraction(value)?;
    Some((time, 0))
}

fn split_timezone_offset(value: &str) -> Option<(&str, &str)> {
    // Find the last '+' or '-' which starts the offset (after HH:MM:SS(.nanos)).
    // This handles negative offsets without confusing the date part (already split).
    let bytes = value.as_bytes();
    for idx in (0..bytes.len()).rev() {
        let b = bytes[idx];
        if b == b'+' || b == b'-' {
            let (time, offset) = value.split_at(idx);
            if offset.len() >= 3 {
                return Some((time, offset));
            }
            return None;
        }
    }
    None
}

fn parse_offset_seconds(offset: &str) -> Option<i32> {
    let offset = offset.trim();
    let sign = if offset.starts_with('+') {
        1i32
    } else if offset.starts_with('-') {
        -1i32
    } else {
        return None;
    };
    let rest = &offset[1..];
    let (hh, mm) = rest.split_once(':')?;
    let hours = hh.parse::<i32>().ok()?;
    let mins = mm.parse::<i32>().ok()?;
    Some(sign * (hours * 3600 + mins * 60))
}

fn parse_hms_fraction(value: &str) -> Option<(u8, u8, u8, u32)> {
    let value = value.trim();
    let (hms, frac) = value.split_once('.').unwrap_or((value, ""));
    let mut parts = hms.splitn(3, ':');
    let hour = parts.next()?.parse::<u8>().ok()?;
    let minute = parts.next()?.parse::<u8>().ok()?;
    let second = parts.next()?.parse::<u8>().ok()?;

    let nanos = if frac.is_empty() {
        0
    } else {
        // Pad/truncate to nanoseconds.
        let mut digits = frac
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .collect::<String>();
        if digits.is_empty() {
            0
        } else {
            if digits.len() > 9 {
                digits.truncate(9);
            } else {
                while digits.len() < 9 {
                    digits.push('0');
                }
            }
            digits.parse::<u32>().ok()?
        }
    };

    Some((hour, minute, second, nanos))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

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
            collection_access::initialize_signer(&pile, Some(&key)).unwrap();
            Self { dir, pile, key }
        }

        fn storage(&self) -> TeamsStorage<'_> {
            TeamsStorage {
                pile: &self.pile,
                key: Some(&self.key),
                scope: DEFAULT_SCOPE_ID,
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
            read_longstring(&view.reader, current[0].content.unwrap(), "test content").unwrap(),
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
            read_longstring(
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
    fn causal_merge_orders_full_versions_but_not_unversioned_tombstones() {
        let message = Id::new([9; 16]).unwrap();
        let present = Id::new([1; 16]).unwrap();
        let deleted = Id::new([2; 16]).unwrap();
        let observations = BTreeMap::from([
            (
                present,
                ObservationOrder {
                    message,
                    modified: 10,
                    deleted: false,
                },
            ),
            (
                deleted,
                ObservationOrder {
                    message,
                    modified: 11,
                    deleted: true,
                },
            ),
        ]);
        assert_eq!(
            merge_causal_visible(
                CausalVisible::Present(present),
                CausalVisible::Deleted(Some(deleted)),
                &observations,
            )
            .unwrap(),
            CausalVisible::Deleted(Some(deleted))
        );
        assert_eq!(
            merge_causal_visible(
                CausalVisible::Deleted(None),
                CausalVisible::Present(present),
                &observations,
            )
            .unwrap(),
            CausalVisible::Conflict
        );
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
                value: Inline<Handle<LongString>>,
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
                value: Inline<Handle<LongString>>,
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
            file_capability::fragment(b"hello".to_vec(), "note.txt", "text/plain").unwrap();
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
            read_longstring(&view.reader, current[0].content.unwrap(), "test content").unwrap(),
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
        let (_, facts, blobs) = second.into_parts();
        let incomplete = facts
            .iter()
            .filter(|fact| fact.e() != &chat)
            .copied()
            .collect::<TribleSet>();
        let incomplete = Fragment::from_facts_and_blobs(incomplete, blobs);
        let before = fs::read(&fixture.pile).unwrap();
        let error = fixture
            .storage()
            .publish(incomplete, "incomplete page")
            .unwrap_err();
        assert!(error.to_string().contains("omitted from its COMMIT"));
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
        fixture.publish(page);
        let view = load_view(&fixture);
        assert_eq!(view.commits.len(), 1);
    }

    #[test]
    fn external_auth_file_is_not_a_pile_record() {
        let fixture = Fixture::new();
        let auth_path = fixture.dir.join("teams-auth.json");
        let before = fs::metadata(&fixture.pile).unwrap().len();
        let auth = ExternalAuth {
            tenant: Some("tenant-a".into()),
            client_secret: Some("secret".into()),
            ..ExternalAuth::default()
        };
        store_external_auth(&auth_path, &auth).unwrap();
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), before);
        assert_eq!(
            load_external_auth(&auth_path).unwrap().unwrap().tenant,
            auth.tenant
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&auth_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let replacement = ExternalAuth {
            tenant: Some("tenant-b".into()),
            ..ExternalAuth::default()
        };
        store_external_auth(&auth_path, &replacement).unwrap();
        assert_eq!(
            load_external_auth(&auth_path).unwrap().unwrap().tenant,
            replacement.tenant
        );
        assert!(fs::read_dir(&fixture.dir).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".teams-auth.json.tmp-")));
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
