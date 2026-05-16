
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration as StdDuration;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use hifitime::{Epoch, TimeScale};
use rand_core::OsRng;
use reqwest::blocking::Client;
use reqwest::header::CONTENT_TYPE;
use serde_json::{Value as JsonValue, json};
use serde::Deserialize;
use triblespace::core::metadata;
use triblespace::core::blob::Bytes;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval, ShortString, U256BE};
use triblespace::prelude::*;

/// Author entity used by the teams faculty when writing its own log entries.
/// Singleton — same id across every faculty run.
const TEAMS_LOG_AUTHOR_ID: Id = id_hex!("5E9B01A9D7C9BB6D765F8C96A83D2E60");
/// Author entity used for attachment backfill rows (there is no real author
/// for these; the attachments-only backfill is a faculty action, not a user
/// message). Singleton.
const TEAMS_BACKFILL_AUTHOR_ID: Id = id_hex!("64A9492F3B2368A0DAB5FAF3277132C2");
/// Fallback author id used when Teams delivers a message with no `from.user.id`.
/// Mapping every anonymous message to the same id keeps the graph small and
/// lets us eventually merge/correct them later if the upstream data improves.
#[allow(dead_code)]
const TEAMS_UNKNOWN_AUTHOR_ID: Id = id_hex!("04217F0E5F75F57B8A7CBFD824D5FF31");

use faculties::schemas::archive::{RawBytes, archive};
use faculties::schemas::teams::{
    DEFAULT_BRANCH, DEFAULT_DELTA_URL, DEFAULT_LOG_BRANCH, FILES_BRANCH_NAME, file_schema, teams,
};
use file_schema::KIND_FILE;
use file_schema::file;

#[derive(Parser)]
#[command(name = "teams", about = "Ingest Microsoft Teams messages into TribleSpace")]
struct Cli {
    /// Path to the pile file to write into.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Branch name to write into (created if missing).
    #[arg(long, default_value = DEFAULT_BRANCH)]
    branch: String,
    /// Branch id to write into (hex). Overrides config/env branch id.
    #[arg(long)]
    branch_id: Option<String>,
    /// Microsoft Graph delta endpoint.
    #[arg(long, default_value = DEFAULT_DELTA_URL)]
    delta_url: String,
    /// OAuth bearer token (optional; otherwise use token command). Use @path for file input or @- for stdin.
    #[arg(long)]
    token: Option<String>,
    /// Command that outputs a bearer token. Use @path for file input or @- for stdin.
    #[arg(
        long,
        default_value =
            "az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv"
    )]
    token_command: String,
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
    /// Interactive device-code login to cache a delegated token.
    Login {
        /// Tenant id or domain (default: common).
        #[arg(long, default_value = "common")]
        tenant: String,
        /// Azure app client id.
        #[arg(long)]
        client_id: String,
        /// Azure app client secret (stored in the pile).
        #[arg(long, help = "Azure app client secret (stored in the pile). Use @path for file input or @- for stdin.")]
        client_secret: Option<String>,
        /// Space-delimited scopes (defaults to chat + presence + user read + offline_access).
        #[arg(long, help = "Space-delimited scopes. Use @path for file input or @- for stdin.")]
        scopes: Option<String>,
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
    #[value(name = "InACall", alias = "in-a-call", alias = "inacall", alias = "call")]
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
        #[arg(long, help = "Optional group chat topic. Use @path for file input or @- for stdin.")]
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
    /// Backfill attachments for existing messages.
    Backfill {
        /// Filter by Teams chat id (external id).
        #[arg(long)]
        chat_id: Option<String>,
        /// Filter by Teams message id (external id).
        #[arg(long)]
        message_id: Option<String>,
        /// Maximum number of messages to scan (0 = no limit).
        #[arg(long, default_value_t = 0)]
        limit: usize,
        /// Scan newest messages first.
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
    branch: String,
    branch_id: Id,
    log_branch_id: Id,
    delta_url: String,
    token: Option<String>,
    token_command: String,
}

fn main() -> Result<()> {
    let mut cli = Cli::parse();
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
            let text = load_value_or_file(&text, "message text")?;
            send_message(config, &chat_id, &text)
        }
        CommandMode::Users { command } => {
            let config = build_config(&cli)?;
            match command {
                UsersCommand::List { prefix, limit } => list_users(config, prefix.as_deref(), limit),
            }
        }
        CommandMode::Presence { command } => {
            let config = build_config(&cli)?;
            match command {
                PresenceCommand::Set { availability, activity, duration_mins, session_id } => {
                    set_presence_status(config, availability, activity, duration_mins, session_id)
                }
                PresenceCommand::Get { user_ids } => get_presence(config, user_ids),
            }
        }
        CommandMode::Chat { command } => {
            let config = build_config(&cli)?;
            match command {
                ChatCommand::Invite { chat_id, user_id, owner } => invite_to_chat(config, &chat_id, &user_id, owner),
                ChatCommand::Create { user_ids, group, topic } => {
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
            match command {
                AttachmentsCommand::List { chat_id, message_id, limit, descending } => {
                    list_attachments(config, AttachmentListOptions { chat_id, message_id, limit, descending })
                }
                AttachmentsCommand::Backfill { chat_id, message_id, limit, descending } => {
                    backfill_attachments(config, AttachmentBackfillOptions { chat_id, message_id, limit, descending })
                }
                AttachmentsCommand::Export { source_id, chat_id, message_id, out_dir, filename, overwrite } => {
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
        CommandMode::Login {
            tenant,
            client_id,
            client_secret,
            scopes,
        } => {
            let config = build_config(&cli)?;
            let scopes = scopes
                .as_deref()
                .map(|value| load_value_or_file(value, "scopes"))
                .transpose()?
                .unwrap_or_else(default_scopes);
            let client_secret = client_secret
                .as_deref()
                .map(|value| load_value_or_file_trimmed(value, "client secret"))
                .transpose()?;
            login_device_code(&config, &tenant, &client_id, client_secret.as_deref(), &scopes)
        }
    }
}

fn with_repo<T>(
    pile_path: &PathBuf,
    f: impl FnOnce(&mut Repository<Pile>) -> Result<T>,
) -> Result<T> {
    let pile = open_pile(pile_path)?;
    let repo = Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
        .map_err(|err| anyhow::anyhow!("create repository: {err:?}"))?;
    with_repo_close(repo, f)
}

fn build_config(cli: &Cli) -> Result<TeamsBridgeConfig> {
    let pile_path = cli.pile.clone();
    let branch = std::env::var("TRIBLESPACE_BRANCH").ok().unwrap_or_else(|| cli.branch.clone());
    let log_branch = std::env::var("TRIBLESPACE_LOG_BRANCH")
        .ok()
        .unwrap_or_else(|| DEFAULT_LOG_BRANCH.to_string());
    let branch_id = with_repo(&pile_path, |repo| {
        if let Some(hex) = cli.branch_id.as_deref() {
            return Id::from_hex(hex.trim())
                .ok_or_else(|| anyhow::anyhow!("invalid branch id '{hex}'"));
        }
        repo.ensure_branch(&branch, None)
            .map_err(|e| anyhow::anyhow!("ensure teams branch: {e:?}"))
    })?;
    let log_branch_id = with_repo(&pile_path, |repo| {
        repo.ensure_branch(&log_branch, None)
            .map_err(|e| anyhow::anyhow!("ensure logs branch: {e:?}"))
    })?;
    let delta_url = std::env::var("TEAMS_DELTA_URL")
        .ok()
        .unwrap_or_else(|| cli.delta_url.clone());
    let token = cli
        .token
        .as_deref()
        .map(|value| load_value_or_file_trimmed(value, "token"))
        .transpose()?
        .or_else(|| std::env::var("TEAMS_TOKEN").ok());
    let token_command = std::env::var("TEAMS_TOKEN_COMMAND")
        .ok()
        .unwrap_or_else(|| cli.token_command.clone());
    let token_command = load_value_or_file_trimmed(&token_command, "token command")?;
    Ok(TeamsBridgeConfig {
        pile_path,
        branch,
        branch_id,
        log_branch_id,
        delta_url,
        token,
        token_command,
    })
}

fn default_scopes() -> String {
    [
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

fn with_repo_close<T, F>(repo: Repository<Pile>, f: F) -> Result<T>
where
    F: FnOnce(&mut Repository<Pile>) -> Result<T>,
{
    let mut repo = repo;
    let result = f(&mut repo);
    let pile = repo.into_storage();
    let close_res = pile.close().map_err(|e| anyhow::anyhow!("close pile: {e:?}"));
    if let Err(err) = close_res {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }
    result
}

fn log_event(config: &TeamsBridgeConfig, level: &str, message: &str) -> Result<()> {
    let (repo, branch_id) = open_repo_for_branch_id(&config.pile_path, config.log_branch_id, "logs")?;
    with_repo_close(repo, |repo| {
        let mut ws = map_err_debug(repo.pull(branch_id), "pull workspace")?;
        let catalog = map_err_debug(ws.checkout(..), "checkout workspace")?.into_facts();

        let mut change = TribleSet::new();
        let author_name = ws.put("teams".to_string());
        let author_role = ws.put("faculty".to_string());
        change += entity! { ExclusiveId::force_ref(&TEAMS_LOG_AUTHOR_ID) @
            metadata::tag: archive::kind_author,
            archive::author_name: author_name,
            archive::author_role: author_role,
        };

        let log_id = ufoid();
        let content = format!("[{}] {}", level.trim(), message.trim());
        let content_handle = ws.put(content);
        let created_at = epoch_interval(now_epoch());
        change += entity! { &log_id @
            metadata::tag: teams::kind_log,
            archive::author: TEAMS_LOG_AUTHOR_ID,
            metadata::created_at: created_at,
            archive::content: content_handle,
        };

        let change = change.difference(&catalog);
        if change.is_empty() {
            return Ok(());
        }
        ws.commit(change, "teams log");
        map_err_debug(repo.push(&mut ws), "push workspace")?;
        Ok(())
    })
}

fn pull_once_with_cache(
    config: &TeamsBridgeConfig,
    app_token_cache: &mut Option<AppTokenCache>,
) -> Result<()> {
    let (token, app_config) = get_app_token(config, app_token_cache)?;
    let (repo, branch_id) =
        open_repo_for_branch_id(&config.pile_path, config.branch_id, &config.branch)?;
    with_repo_close(repo, |repo| {
        let mut ws = map_err_debug(repo.pull(branch_id), "pull workspace")?;
        let catalog = map_err_debug(ws.checkout(..), "checkout workspace")?.into_facts();
        let cursor_state = load_cursor_from_space(&mut ws, &catalog)?;
        let start_url = match cursor_state.as_ref() {
            Some(cursor) if cursor.url.contains("/me/") => {
                resolve_delta_url(&config.delta_url, &app_config.user_id)?
            }
            Some(cursor) => cursor.url.clone(),
            None => resolve_delta_url(&config.delta_url, &app_config.user_id)?,
        };

        let (messages, new_cursor) = fetch_delta_messages(&token, &start_url)?;
        let index = CatalogIndex::build(&catalog);
    let incoming = parse_messages(messages)?;
    let (mut change, files_change) = build_ingest_change(&mut ws, &catalog, &index, incoming, &token, config)?;
        if let Some(cursor_change) =
            build_cursor_change(&mut ws, &catalog, cursor_state.as_ref(), new_cursor)?
        {
            change += cursor_change;
        }

        if !change.is_empty() {
            ws.commit(change, "teams ingest");
            map_err_debug(repo.push(&mut ws), "push workspace")?;
        }

        // Commit file entities to the files branch.
        if !files_change.is_empty() {
            let files_branch_id = repo.ensure_branch(FILES_BRANCH_NAME, None)
                .map_err(|e| anyhow::anyhow!("ensure files branch: {e:?}"))?;
            let mut files_ws = map_err_debug(repo.pull(files_branch_id), "pull files workspace")?;
            files_ws.commit(files_change, "teams attachment files");
            map_err_debug(repo.push(&mut files_ws), "push files workspace")?;
        }

        Ok(())
    })
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

#[derive(Debug, Clone, Default)]
struct TeamsConfigData {
    tenant: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    user_id: Option<String>,
}

fn get_app_token(
    config: &TeamsBridgeConfig,
    app_token_cache: &mut Option<AppTokenCache>,
) -> Result<(String, AppConfig)> {
    let app_config = load_app_config_from_pile(config)?;
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

fn load_app_config_from_pile(config: &TeamsBridgeConfig) -> Result<AppConfig> {
    let Some(config_data) = load_config_from_pile(config)? else {
        bail!(
            "missing Teams app config; run teams.rs login --client-id <app-id> --tenant <tenant-id> --client-secret <secret>"
        );
    };

    let tenant = config_data.tenant.ok_or_else(|| {
        anyhow::anyhow!("missing tenant in Teams config; re-run teams.rs login")
    })?;
    let client_id = config_data.client_id.ok_or_else(|| {
        anyhow::anyhow!("missing client id in Teams config; re-run teams.rs login")
    })?;
    let client_secret = config_data.client_secret.ok_or_else(|| {
        anyhow::anyhow!(
            "missing client secret in Teams config; re-run teams.rs login with --client-secret"
        )
    })?;
    let user_id = config_data.user_id.ok_or_else(|| {
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
    if let Some(token) = config.token.as_ref() {
        let token = token.trim();
        if !token.is_empty() {
            return Ok(token.to_owned());
        }
    }

    if let Some(token) = load_cached_token_from_pile(config)? {
        return Ok(token);
    }

    let cmd = config
        .token_command
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
    expires_in: i64,
    scope: Option<String>,
    token_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ErrorResponse {
    error: String,
    error_description: Option<String>,
}

#[derive(Debug, Clone)]
struct TokenState {
    token_id: Id,
    created_at_key: i128,
    expires_at_key: i128,
    access_token: Inline<Handle<LongString>>,
    refresh_token: Option<Inline<Handle<LongString>>>,
    scope: Option<Inline<Handle<LongString>>>,
    tenant: Option<Inline<Handle<LongString>>>,
    client_id: Option<Inline<Handle<LongString>>>,
}

#[derive(Debug, Clone)]
struct ConfigState {
    config_id: Id,
    created_at_key: i128,
    tenant: Option<Inline<Handle<LongString>>>,
    client_id: Option<Inline<Handle<LongString>>>,
    client_secret: Option<Inline<Handle<LongString>>>,
    user_id: Option<Inline<Handle<LongString>>>,
}

#[derive(Debug, Clone)]
struct TokenData {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Inline<NsTAIInterval>,
    token_type: Option<String>,
    scope: Option<String>,
    tenant: String,
    client_id: String,
}

fn now_epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs() as i64
}

fn load_cached_token_from_pile(config: &TeamsBridgeConfig) -> Result<Option<String>> {
    let (repo, branch_id) =
        open_repo_for_branch_id(&config.pile_path, config.branch_id, &config.branch)?;
    with_repo_close(repo, |repo| {
        let mut ws = map_err_debug(repo.pull(branch_id), "pull workspace")?;
        let catalog = map_err_debug(ws.checkout(..), "checkout workspace")?.into_facts();
        let Some(state) = latest_token_state(&catalog) else {
            return Ok(None);
        };

        let now_key = interval_key(epoch_interval(now_epoch()));
        if state.expires_at_key > now_key + 30 * 1_000_000_000 {
            let token = load_longstring(&mut ws, state.access_token)?;
            return Ok(Some(token));
        }

        let refresh_handle = state.refresh_token.clone();
        let tenant_handle = state.tenant.clone();
        let client_handle = state.client_id.clone();
        let Some(refresh_handle) = refresh_handle else {
            return Ok(None);
        };
        let Some(tenant_handle) = tenant_handle else {
            return Ok(None);
        };
        let Some(client_handle) = client_handle else {
            return Ok(None);
        };

        let refresh = load_longstring(&mut ws, refresh_handle)?;
        let tenant = load_longstring(&mut ws, tenant_handle)?;
        let client_id = load_longstring(&mut ws, client_handle)?;
        let scope = match state.scope.clone() {
            Some(scope) => Some(load_longstring(&mut ws, scope)?),
            None => None,
        };

        let refreshed = refresh_token(&tenant, &client_id, &refresh, scope.as_deref())?;
        let expires_at = epoch_interval(epoch_after_seconds(now_epoch(), refreshed.expires_in));
        let token = TokenData {
            access_token: refreshed.access_token.clone(),
            refresh_token: refreshed.refresh_token.or(Some(refresh)),
            expires_at,
            token_type: refreshed.token_type,
            scope: refreshed.scope.or(scope),
            tenant,
            client_id,
        };
        store_token_in_repo(repo, branch_id, &token)?;
        Ok(Some(token.access_token))
    })
}

fn load_config_from_pile(config: &TeamsBridgeConfig) -> Result<Option<TeamsConfigData>> {
    let (repo, branch_id) =
        open_repo_for_branch_id(&config.pile_path, config.branch_id, &config.branch)?;
    with_repo_close(repo, |repo| {
        let mut ws = map_err_debug(repo.pull(branch_id), "pull workspace")?;
        let catalog = map_err_debug(ws.checkout(..), "checkout workspace")?.into_facts();
        let Some(state) = latest_config_state(&catalog) else {
            return Ok(None);
        };

        let tenant = match state.tenant {
            Some(handle) => Some(load_longstring(&mut ws, handle)?),
            None => None,
        };
        let client_id = match state.client_id {
            Some(handle) => Some(load_longstring(&mut ws, handle)?),
            None => None,
        };
        let client_secret = match state.client_secret {
            Some(handle) => Some(load_longstring(&mut ws, handle)?),
            None => None,
        };
        let user_id = match state.user_id {
            Some(handle) => Some(load_longstring(&mut ws, handle)?),
            None => None,
        };

        Ok(Some(TeamsConfigData {
            tenant,
            client_id,
            client_secret,
            user_id,
        }))
    })
}

fn latest_token_state(catalog: &TribleSet) -> Option<TokenState> {
    let mut best: Option<TokenState> = None;
    for (token_id, access_token, expires_at, created_at) in find!(
        (
            token: Id,
            access: Inline<Handle<LongString>>,
            expires_at: Inline<NsTAIInterval>,
            created_at: Inline<NsTAIInterval>
        ),
        pattern!(catalog, [{
            ?token @
            metadata::tag: teams::kind_token,
            teams::access_token: ?access,
            metadata::expires_at: ?expires_at,
            metadata::created_at: ?created_at,
        }])
    ) {
        let created_key = interval_key(created_at);
        let expires_key = interval_key(expires_at);
        let replace = match &best {
            None => true,
            Some(current) => {
                created_key > current.created_at_key
                    || (created_key == current.created_at_key && token_id > current.token_id)
            }
        };
        if replace {
            best = Some(TokenState {
                token_id,
                created_at_key: created_key,
                expires_at_key: expires_key,
                access_token,
                refresh_token: find_optional_handle(catalog, token_id, &teams::refresh_token),
                scope: find_optional_handle(catalog, token_id, &teams::scope),
                tenant: find_optional_handle(catalog, token_id, &teams::tenant),
                client_id: find_optional_handle(catalog, token_id, &teams::client_id),
            });
        }
    }
    best
}

fn latest_config_state(catalog: &TribleSet) -> Option<ConfigState> {
    let mut best: Option<ConfigState> = None;
    for (config_id, created_at) in find!(
        (config: Id, created_at: Inline<NsTAIInterval>),
        pattern!(catalog, [{
            ?config @
            metadata::tag: teams::kind_config,
            metadata::created_at: ?created_at,
        }])
    ) {
        let created_key = interval_key(created_at);
        let replace = match &best {
            None => true,
            Some(current) => {
                created_key > current.created_at_key
                    || (created_key == current.created_at_key && config_id > current.config_id)
            }
        };
        if replace {
            best = Some(ConfigState {
                config_id,
                created_at_key: created_key,
                tenant: find_optional_handle(catalog, config_id, &teams::tenant),
                client_id: find_optional_handle(catalog, config_id, &teams::client_id),
                client_secret: find_optional_handle(catalog, config_id, &teams::client_secret),
                user_id: find_optional_handle(catalog, config_id, &teams::user_id),
            });
        }
    }
    best
}

fn find_optional_handle(
    catalog: &TribleSet,
    entity: Id,
    attribute: &Attribute<Handle<LongString>>,
) -> Option<Inline<Handle<LongString>>> {
    find!(
        (handle: Inline<Handle<LongString>>),
        pattern!(catalog, [{ entity @ attribute: ?handle }])
    )
    .into_iter()
    .next()
    .map(|(handle,)| handle)
}

fn find_optional_value<S: InlineEncoding>(
    catalog: &TribleSet,
    entity: Id,
    attribute: &Attribute<S>,
) -> Option<Inline<S>> {
    find!(
        (value: Inline<S>),
        pattern!(catalog, [{ entity @ attribute: ?value }])
    )
    .into_iter()
    .next()
    .map(|(value,)| value)
}

fn load_chat_map(
    ws: &mut Workspace<Pile>,
    catalog: &TribleSet,
) -> Result<HashMap<Id, String>> {
    let mut map = HashMap::new();
    for (chat_id, handle) in find!(
        (chat: Id, chat_id: Inline<Handle<LongString>>),
        pattern!(catalog, [{
            ?chat @ teams::chat_id: ?chat_id,
        }])
    ) {
        let value = load_longstring(ws, handle)?;
        map.insert(chat_id, value);
    }
    Ok(map)
}

fn load_message_external_map(
    ws: &mut Workspace<Pile>,
    catalog: &TribleSet,
) -> Result<HashMap<Id, String>> {
    let mut map = HashMap::new();
    for (message_id, handle) in find!(
        (message: Id, message_id: Inline<Handle<LongString>>),
        pattern!(catalog, [{
            ?message @ teams::message_id: ?message_id,
        }])
    ) {
        let value = load_longstring(ws, handle)?;
        map.insert(message_id, value);
    }
    Ok(map)
}

fn load_author_map(
    ws: &mut Workspace<Pile>,
    catalog: &TribleSet,
) -> Result<HashMap<Id, String>> {
    let mut map = HashMap::new();
    for (author_id, handle) in find!(
        (author: Id, name: Inline<Handle<LongString>>),
        pattern!(catalog, [{
            ?author @ archive::author_name: ?name,
        }])
    ) {
        let value = load_longstring(ws, handle)?;
        map.insert(author_id, value);
    }
    Ok(map)
}

fn store_token_in_repo(
    repo: &mut Repository<Pile>,
    branch_id: Id,
    token: &TokenData,
) -> Result<()> {
    let mut ws = map_err_debug(repo.pull(branch_id), "pull workspace")?;
    let catalog = map_err_debug(ws.checkout(..), "checkout workspace")?.into_facts();
    let change = build_token_change(&mut ws, &catalog, token)?;
    if change.is_empty() {
        return Ok(());
    }
    ws.commit(change, "teams token cache");
    map_err_debug(repo.push(&mut ws), "push workspace")?;
    Ok(())
}

fn store_token_in_pile(config: &TeamsBridgeConfig, token: &TokenData) -> Result<()> {
    let (repo, branch_id) =
        open_repo_for_branch_id(&config.pile_path, config.branch_id, &config.branch)?;
    with_repo_close(repo, |repo| store_token_in_repo(repo, branch_id, token))
}

fn store_config_in_pile(config: &TeamsBridgeConfig, data: &TeamsConfigData) -> Result<()> {
    let (repo, branch_id) =
        open_repo_for_branch_id(&config.pile_path, config.branch_id, &config.branch)?;
    with_repo_close(repo, |repo| store_config_in_repo(repo, branch_id, data))
}

fn build_token_change(
    ws: &mut Workspace<Pile>,
    catalog: &TribleSet,
    token: &TokenData,
) -> Result<TribleSet> {
    let mut change = TribleSet::new();
    let token_id = ufoid();
    let access_handle = ws.put(token.access_token.clone());
    let expires_at = token.expires_at;
    let created_at = epoch_interval(now_epoch());
    let tenant_handle = ws.put(token.tenant.clone());
    let client_handle = ws.put(token.client_id.clone());
    let refresh_handle = token
        .refresh_token
        .as_ref()
        .map(|refresh| ws.put(refresh.to_owned()));
    let token_type_handle = token
        .token_type
        .as_ref()
        .map(|token_type| ws.put(token_type.to_owned()));
    let scope_handle = token
        .scope
        .as_ref()
        .map(|scope| ws.put(scope.to_owned()));

    change += entity! { &token_id @
        metadata::tag: teams::kind_token,
        metadata::created_at: created_at,
        teams::access_token: access_handle,
        metadata::expires_at: expires_at,
        teams::tenant: tenant_handle,
        teams::client_id: client_handle,
        teams::refresh_token?: refresh_handle,
        teams::token_type?: token_type_handle,
        teams::scope?: scope_handle,
    };

    Ok(change.difference(catalog))
}

fn store_config_in_repo(
    repo: &mut Repository<Pile>,
    branch_id: Id,
    data: &TeamsConfigData,
) -> Result<()> {
    let mut ws = map_err_debug(repo.pull(branch_id), "pull workspace")?;
    let catalog = map_err_debug(ws.checkout(..), "checkout workspace")?.into_facts();
    let change = build_config_change(&mut ws, &catalog, data)?;
    if change.is_empty() {
        return Ok(());
    }
    ws.commit(change, "teams config cache");
    map_err_debug(repo.push(&mut ws), "push workspace")?;
    Ok(())
}

fn build_config_change(
    ws: &mut Workspace<Pile>,
    catalog: &TribleSet,
    data: &TeamsConfigData,
) -> Result<TribleSet> {
    let mut change = TribleSet::new();
    let config_id = ufoid();
    let created_at = epoch_interval(now_epoch());
    let tenant_handle = data.tenant.as_ref().map(|value| ws.put(value.to_owned()));
    let client_id_handle = data
        .client_id
        .as_ref()
        .map(|value| ws.put(value.to_owned()));
    let client_secret_handle = data
        .client_secret
        .as_ref()
        .map(|value| ws.put(value.to_owned()));
    let user_id_handle = data.user_id.as_ref().map(|value| ws.put(value.to_owned()));

    change += entity! { &config_id @
        metadata::tag: teams::kind_config,
        metadata::created_at: created_at,
        teams::tenant?: tenant_handle,
        teams::client_id?: client_id_handle,
        teams::client_secret?: client_secret_handle,
        teams::user_id?: user_id_handle,
    };

    Ok(change.difference(catalog))
}

fn load_longstring(
    ws: &mut Workspace<Pile>,
    handle: Inline<Handle<LongString>>,
) -> Result<String> {
    let view: View<str> = map_err_debug(ws.get(handle), "load longstring")?;
    Ok(view.to_string())
}

fn epoch_after_seconds(base: Epoch, seconds: i64) -> Epoch {
    use hifitime::Duration as HifiDuration;
    base + HifiDuration::from_seconds(seconds as f64)
}

fn login_device_code(
    config: &TeamsBridgeConfig,
    tenant: &str,
    client_id: &str,
    client_secret: Option<&str>,
    scopes: &str,
) -> Result<()> {
    let device = request_device_code(tenant, client_id, scopes)?;
    if let Some(message) = &device.message {
        println!("{message}");
    } else if let Some(url) = &device.verification_uri_complete {
        println!("Open {} to authenticate.", url);
    } else {
        println!(
            "Visit {} and enter code {} to authenticate.",
            device.verification_uri,
            device.user_code
        );
    }

    let interval = device.interval.unwrap_or(5).max(1) as u64;
    let deadline = now_epoch_secs() + device.expires_in;
    let token = poll_device_token(tenant, client_id, &device.device_code, interval, deadline)?;
    let user_id = fetch_me_id(&token.access_token)?;
    let expires_at = epoch_interval(epoch_after_seconds(now_epoch(), token.expires_in));
    let token = TokenData {
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        expires_at,
        token_type: token.token_type,
        scope: token.scope.or_else(|| Some(scopes.to_owned())),
        tenant: tenant.to_owned(),
        client_id: client_id.to_owned(),
    };
    store_token_in_pile(config, &token)?;
    let existing = load_config_from_pile(config)?.unwrap_or_default();
    let merged_secret = client_secret
        .map(str::to_owned)
        .or(existing.client_secret);
    let config_data = TeamsConfigData {
        tenant: Some(tenant.to_owned()),
        client_id: Some(client_id.to_owned()),
        client_secret: merged_secret,
        user_id: Some(user_id),
    };
    store_config_in_pile(config, &config_data)?;
    println!(
        "Stored token cache in {} (branch {})",
        config.pile_path.display(),
        config.branch
    );
    println!(
        "Stored Teams config in {} (branch {})",
        config.pile_path.display(),
        config.branch
    );
    Ok(())
}

fn request_device_code(tenant: &str, client_id: &str, scopes: &str) -> Result<DeviceCodeResponse> {
    let url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode");
    let params = [
        ("client_id", client_id),
        ("scope", scopes),
    ];
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
    let parsed: DeviceCodeResponse = serde_json::from_str(&body).context("parse device code response")?;
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
            let token: TokenResponse = serde_json::from_str(&body).context("parse token response")?;
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

fn fetch_delta_messages(token: &str, start_url: &str) -> Result<(Vec<JsonValue>, Option<String>)> {
    let client = Client::new();
    let mut url = start_url.to_owned();

    let mut messages = Vec::new();
    let cursor = loop {
        let delta = fetch_delta_page(&client, token, &url)?;
        messages.extend(delta.messages);

        if let Some(next) = delta.next_link {
            url = next;
            continue;
        }

        break delta.delta_link;
    };

    Ok((messages, cursor))
}

struct DeltaPage {
    messages: Vec<JsonValue>,
    next_link: Option<String>,
    delta_link: Option<String>,
}

fn fetch_delta_page(client: &Client, token: &str, url: &str) -> Result<DeltaPage> {
    let resp = client
        .get(url)
        .bearer_auth(token)
        .send()
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .with_context(|| format!("read response body for {url}"))?;
    if !status.is_success() {
        bail!("GET {url} failed: status={status} body={body}");
    }

    let json: JsonValue = serde_json::from_str(&body).context("parse delta json")?;
    let messages = json
        .get("value")
        .and_then(JsonValue::as_array)
        .cloned()
        .unwrap_or_default();
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
    let mut url = reqwest::Url::parse("https://graph.microsoft.com/v1.0/users")
        .context("parse users url")?;
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
        let id = user.get("id").and_then(JsonValue::as_str).unwrap_or("unknown");
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
    let config_data = load_config_from_pile(&config)?.ok_or_else(|| {
        anyhow::anyhow!("missing Teams config; run teams.rs login --client-id <app-id> --tenant <tenant-id>")
    })?;
    let user_id = config_data
        .user_id
        .ok_or_else(|| anyhow::anyhow!("missing user id; re-run teams.rs login"))?;
    let default_session = config_data.client_id.unwrap_or_else(|| user_id.clone());
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
    let json_body: JsonValue = serde_json::from_str(&response_body).context("parse presence json")?;
    let presences = json_body
        .get("value")
        .and_then(JsonValue::as_array)
        .cloned()
        .unwrap_or_default();

    for presence in presences {
        let id = presence.get("id").and_then(JsonValue::as_str).unwrap_or("unknown");
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

fn invite_to_chat(config: TeamsBridgeConfig, chat_id: &str, user_id: &str, owner: bool) -> Result<()> {
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
    let config_data = load_config_from_pile(&config)?.ok_or_else(|| {
        anyhow::anyhow!("missing Teams config; run teams.rs login --client-id <app-id> --tenant <tenant-id>")
    })?;
    let self_id = config_data
        .user_id
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
    let chat_id = json_body.get("id").and_then(JsonValue::as_str).unwrap_or("unknown");
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
    author_id: Id,
    created_at: Inline<NsTAIInterval>,
    created_at_key: i128,
    content: Inline<Handle<LongString>>,
}

#[derive(Debug, Clone)]
struct AttachmentListOptions {
    chat_id: Option<String>,
    message_id: Option<String>,
    limit: usize,
    descending: bool,
}

#[derive(Debug, Clone)]
struct AttachmentBackfillOptions {
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
    data_handle: Inline<Handle<RawBytes>>,
    name: Option<Inline<Handle<LongString>>>,
    mime: Option<Inline<ShortString>>,
}

#[derive(Debug, Clone)]
struct AttachmentRow {
    attachment_id: Id,
    message_id: Id,
    chat_id: Id,
    created_at: Inline<NsTAIInterval>,
    created_at_key: i128,
    source_id: Option<Inline<Handle<LongString>>>,
    source_pointer: Option<Inline<Handle<LongString>>>,
    name: Option<Inline<Handle<LongString>>>,
    mime: Option<Inline<ShortString>>,
    size: Option<Inline<U256BE>>,
}

fn read_messages(config: TeamsBridgeConfig, options: ReadOptions) -> Result<()> {
    let mut app_token_cache = None;
    pull_once_with_cache(&config, &mut app_token_cache)?;

    let (repo, branch_id) =
        open_repo_for_branch_id(&config.pile_path, config.branch_id, &config.branch)?;
    with_repo_close(repo, |repo| {
        let mut ws = map_err_debug(repo.pull(branch_id), "pull workspace")?;
        let catalog = map_err_debug(ws.checkout(..), "checkout workspace")?.into_facts();

        let chat_map = load_chat_map(&mut ws, &catalog)?;
        let author_map = load_author_map(&mut ws, &catalog)?;
        let chat_filter_ids = match options.chat_id.as_ref().map(|value| value.trim()) {
            Some(value) if !value.is_empty() => {
                let mut ids = HashSet::new();
                for (chat_id, external) in &chat_map {
                    if external == value {
                        ids.insert(*chat_id);
                    }
                }
                if ids.is_empty() {
                    println!("No chat found for id {}", value);
                    return Ok(());
                }
                Some(ids)
            }
            _ => None,
        };

        let since_key = parse_since_key(options.since.as_deref())?;
        let mut messages = Vec::new();
        for (message_id, content, author_id, created_at, chat_id) in find!(
            (
                message: Id,
                content: Inline<Handle<LongString>>,
                author: Id,
                created_at: Inline<NsTAIInterval>,
                chat: Id
            ),
            pattern!(&catalog, [{
                ?message @
                metadata::tag: archive::kind_message,
                archive::content: ?content,
                archive::author: ?author,
                metadata::created_at: ?created_at,
                teams::chat: ?chat,
            }])
        ) {
            if let Some(filter) = &chat_filter_ids {
                if !filter.contains(&chat_id) {
                    continue;
                }
            }
            let created_key = interval_key(created_at);
            if let Some(since_key) = since_key {
                if created_key < since_key {
                    continue;
                }
            }
            messages.push(ReadMessage {
                message_id,
                chat_id,
                author_id,
                created_at,
                created_at_key: created_key,
                content,
            });
        }

        messages.sort_by(|left, right| {
            left.created_at_key
                .cmp(&right.created_at_key)
                .then_with(|| left.message_id.cmp(&right.message_id))
        });

        if options.limit > 0 && messages.len() > options.limit {
            let start = messages.len() - options.limit;
            messages = messages.split_off(start);
        }

        if options.descending {
            messages.reverse();
        }

        for message in messages {
            let content = load_longstring(&mut ws, message.content)?;
            let author = author_map
                .get(&message.author_id)
                .cloned()
                .unwrap_or_else(|| format!("{}", message.author_id));
            let chat = chat_map
                .get(&message.chat_id)
                .cloned()
                .unwrap_or_else(|| format!("{}", message.chat_id));
            let timestamp = format_interval(message.created_at);

            println!("[{}] ({}) {}: {}", timestamp, chat, author, content);
        }

        Ok(())
    })
}

#[derive(Debug, Clone)]
struct IncomingMessage {
    chat_external_id: String,
    message_external_id: String,
    raw_json: String,
    author_external_id: Option<String>,
    author_display_name: Option<String>,
    content: String,
    created_at: Inline<NsTAIInterval>,
    created_at_key: i128,
    attachments: Vec<AttachmentSource>,
}

#[derive(Debug, Clone)]
struct AttachmentSource {
    source_id: String,
    source_url: Option<String>,
    name: Option<String>,
    content_type: Option<String>,
    content_bytes: Option<Vec<u8>>,
}

fn open_pile(path: &PathBuf) -> Result<Pile> {
    let mut pile = Pile::open(path).with_context(|| format!("open pile {}", path.display()))?;
    if let Err(err) = pile.restore().context("restore pile") {
        // Avoid Drop warnings on early errors.
        let _ = pile.close();
        return Err(err);
    }
    Ok(pile)
}


fn list_attachments(config: TeamsBridgeConfig, options: AttachmentListOptions) -> Result<()> {
    let mut app_token_cache = None;
    pull_once_with_cache(&config, &mut app_token_cache)?;

    let (repo, branch_id) =
        open_repo_for_branch_id(&config.pile_path, config.branch_id, &config.branch)?;
    with_repo_close(repo, |repo| {
        let mut ws = map_err_debug(repo.pull(branch_id), "pull workspace")?;
        let catalog = map_err_debug(ws.checkout(..), "checkout workspace")?.into_facts();

        let chat_map = load_chat_map(&mut ws, &catalog)?;
        let message_map = load_message_external_map(&mut ws, &catalog)?;

        let chat_filter_ids = match options.chat_id.as_ref().map(|value| value.trim()) {
            Some(value) if !value.is_empty() => {
                let mut ids = HashSet::new();
                for (chat_id, external) in &chat_map {
                    if external == value {
                        ids.insert(*chat_id);
                    }
                }
                if ids.is_empty() {
                    println!("No chat found for id {}", value);
                    return Ok(());
                }
                Some(ids)
            }
            _ => None,
        };

        let message_filter_ids = match options.message_id.as_ref().map(|value| value.trim()) {
            Some(value) if !value.is_empty() => {
                let mut ids = HashSet::new();
                for (message_id, external) in &message_map {
                    if external == value {
                        ids.insert(*message_id);
                    }
                }
                if ids.is_empty() {
                    println!("No message found for id {}", value);
                    return Ok(());
                }
                Some(ids)
            }
            _ => None,
        };

        let mut rows = Vec::new();
        for (message_id, attachment_id, created_at, chat_id) in find!(
            (
                message: Id,
                attachment: Id,
                created_at: Inline<NsTAIInterval>,
                chat: Id
            ),
            pattern!(&catalog, [{
                ?message @
                archive::attachment: ?attachment,
                metadata::created_at: ?created_at,
                teams::chat: ?chat,
            }])
        ) {
            if let Some(filter) = &chat_filter_ids {
                if !filter.contains(&chat_id) {
                    continue;
                }
            }
            if let Some(filter) = &message_filter_ids {
                if !filter.contains(&message_id) {
                    continue;
                }
            }
            rows.push(AttachmentRow {
                attachment_id,
                message_id,
                chat_id,
                created_at,
                created_at_key: interval_key(created_at),
                source_id: find_optional_handle(&catalog, attachment_id, &archive::attachment_source_id),
                source_pointer: find_optional_handle(
                    &catalog,
                    attachment_id,
                    &archive::attachment_source_pointer,
                ),
                name: find_optional_handle(&catalog, attachment_id, &archive::attachment_name),
                mime: find_optional_value(&catalog, attachment_id, &archive::attachment_mime),
                size: find_optional_value(&catalog, attachment_id, &archive::attachment_size_bytes),
            });
        }

        rows.sort_by(|left, right| {
            left.created_at_key
                .cmp(&right.created_at_key)
                .then_with(|| left.attachment_id.cmp(&right.attachment_id))
        });

        if options.limit > 0 && rows.len() > options.limit {
            let start = rows.len() - options.limit;
            rows = rows.split_off(start);
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
                .map(|handle| load_longstring(&mut ws, handle))
                .transpose()?
                .unwrap_or_default();
            let source_pointer = row
                .source_pointer
                .map(|handle| load_longstring(&mut ws, handle))
                .transpose()?;
            let name = row
                .name
                .map(|handle| load_longstring(&mut ws, handle))
                .transpose()?;
            let mime = row.mime.map(|value| String::try_from_inline(&value).unwrap());
            let size = row.size.and_then(u256_to_u128).map(|value| value.to_string());
            let timestamp = format_interval(row.created_at);

            let size_display = size.unwrap_or_else(|| "-".to_string());
            let name_display = name.unwrap_or_else(|| "-".to_string());
            let mime_display = mime.unwrap_or_else(|| "-".to_string());
            let pointer_display = source_pointer.unwrap_or_else(|| "-".to_string());
            println!(
                "[{}] ({}) msg={} attachment={} name={} mime={} size={} source={}",
                timestamp,
                chat,
                message,
                source_id,
                name_display,
                mime_display,
                size_display,
                pointer_display
            );
        }

        Ok(())
    })
}

fn backfill_attachments(config: TeamsBridgeConfig, options: AttachmentBackfillOptions) -> Result<()> {
    let mut app_token_cache = None;
    let (token, _app_config) = get_app_token(&config, &mut app_token_cache)?;
    pull_once_with_cache(&config, &mut app_token_cache)?;

    let (repo, branch_id) =
        open_repo_for_branch_id(&config.pile_path, config.branch_id, &config.branch)?;
    with_repo_close(repo, |repo| {
        let mut ws = map_err_debug(repo.pull(branch_id), "pull workspace")?;
        let catalog = map_err_debug(ws.checkout(..), "checkout workspace")?.into_facts();
        let index = CatalogIndex::build(&catalog);

        let chat_map = load_chat_map(&mut ws, &catalog)?;
        let message_map = load_message_external_map(&mut ws, &catalog)?;
        let mut files_change = TribleSet::new();

        let chat_filter_ids = match options.chat_id.as_ref().map(|value| value.trim()) {
            Some(value) if !value.is_empty() => {
                let mut ids = HashSet::new();
                for (chat_id, external) in &chat_map {
                    if external == value {
                        ids.insert(*chat_id);
                    }
                }
                if ids.is_empty() {
                    println!("No chat found for id {}", value);
                    return Ok(());
                }
                Some(ids)
            }
            _ => None,
        };

        let message_filter_ids = match options.message_id.as_ref().map(|value| value.trim()) {
            Some(value) if !value.is_empty() => {
                let mut ids = HashSet::new();
                for (message_id, external) in &message_map {
                    if external == value {
                        ids.insert(*message_id);
                    }
                }
                if ids.is_empty() {
                    println!("No message found for id {}", value);
                    return Ok(());
                }
                Some(ids)
            }
            _ => None,
        };

        let mut content_map = HashMap::new();
        let mut chat_by_message = HashMap::new();
        let mut created_by_message = HashMap::new();
        for (message_id, chat_id, created_at, content) in find!(
            (
                message: Id,
                chat: Id,
                created_at: Inline<NsTAIInterval>,
                content: Inline<Handle<LongString>>
            ),
            pattern!(&catalog, [{
                ?message @
                metadata::tag: archive::kind_message,
                teams::chat: ?chat,
                metadata::created_at: ?created_at,
                archive::content: ?content,
            }])
        ) {
            content_map.insert(message_id, content);
            chat_by_message.insert(message_id, chat_id);
            created_by_message.insert(message_id, created_at);
        }

        let mut raw_map = HashMap::new();
        for (message_id, raw) in find!(
            (message: Id, raw: Inline<Handle<LongString>>),
            pattern!(&catalog, [{ ?message @ teams::message_raw: ?raw }])
        ) {
            raw_map.insert(message_id, raw);
        }

        let mut message_rows = Vec::new();
        for (message_id, content_handle) in &content_map {
            let chat_id = match chat_by_message.get(message_id) {
                Some(chat_id) => *chat_id,
                None => continue,
            };
            if let Some(filter) = &chat_filter_ids {
                if !filter.contains(&chat_id) {
                    continue;
                }
            }
            if let Some(filter) = &message_filter_ids {
                if !filter.contains(message_id) {
                    continue;
                }
            }
            let created_at = match created_by_message.get(message_id) {
                Some(created_at) => *created_at,
                None => continue,
            };
            message_rows.push((
                *message_id,
                chat_id,
                created_at,
                interval_key(created_at),
                *content_handle,
            ));
        }

        message_rows.sort_by(|left, right| left.3.cmp(&right.3).then_with(|| left.0.cmp(&right.0)));
        if options.descending {
            message_rows.reverse();
        }
        if options.limit > 0 && message_rows.len() > options.limit {
            message_rows.truncate(options.limit);
        }

        let mut change = TribleSet::new();
        let mut added_attachments = HashSet::new();
        let mut scanned = 0usize;
        let mut created = 0usize;
        for (message_id, chat_id, created_at, _created_key, content_handle) in message_rows {
            let chat_external_id = match chat_map.get(&chat_id) {
                Some(value) => value.clone(),
                None => continue,
            };
            let message_external_id = match message_map.get(&message_id) {
                Some(value) => value.clone(),
                None => continue,
            };

            let content = load_longstring(&mut ws, content_handle)?;
            let raw_json = raw_map
                .get(&message_id)
                .map(|handle| load_longstring(&mut ws, *handle))
                .transpose()?;

            let mut seen = HashSet::new();
            let mut attachments = Vec::new();
            if let Some(raw_str) = raw_json.as_deref() {
                if let Ok(parsed) = serde_json::from_str::<JsonValue>(raw_str) {
                    attachments.extend(parse_json_attachments(
                        &parsed,
                        &chat_external_id,
                        &message_external_id,
                        &mut seen,
                    ));
                }
            }
            attachments.extend(parse_hosted_content_attachments(
                &content,
                &chat_external_id,
                &message_external_id,
                &mut seen,
            ));

            if attachments.is_empty() {
                continue;
            }

            // `created_at`, `content`, `chat_external_id`, `message_external_id`,
            // and `raw_json` are not used by the new `ensure_attachments` —
            // they were kept in the stub only to satisfy the old IncomingMessage
            // shape. The backfill only needs `message_id` + the attachments list.
            let _ = (created_at, &content, &chat_external_id, &message_external_id, &raw_json);
            let before = change.len();
            ensure_attachments(
                &mut ws,
                &mut change,
                &mut files_change,
                &index,
                message_id,
                &attachments,
                &token,
                &config,
                &mut added_attachments,
            )?;
            if change.len() > before {
                created += 1;
            }
            scanned += 1;
        }

        if change.is_empty() {
            println!("No attachments to backfill.");
            return Ok(());
        }

        ws.commit(change, "teams attachments backfill");
        map_err_debug(repo.push(&mut ws), "push workspace")?;
        println!("Backfilled attachments for {created} messages (scanned {scanned}).");
        Ok(())
    })
}

fn export_attachment(config: TeamsBridgeConfig, options: AttachmentExportOptions) -> Result<()> {
    let mut app_token_cache = None;
    pull_once_with_cache(&config, &mut app_token_cache)?;

    let (repo, branch_id) =
        open_repo_for_branch_id(&config.pile_path, config.branch_id, &config.branch)?;
    with_repo_close(repo, |repo| {
        let mut ws = map_err_debug(repo.pull(branch_id), "pull workspace")?;
        let catalog = map_err_debug(ws.checkout(..), "checkout workspace")?.into_facts();

        let chat_map = load_chat_map(&mut ws, &catalog)?;
        let message_map = load_message_external_map(&mut ws, &catalog)?;

        let chat_filter_ids = match options.chat_id.as_ref().map(|value| value.trim()) {
            Some(value) if !value.is_empty() => {
                let mut ids = HashSet::new();
                for (chat_id, external) in &chat_map {
                    if external == value {
                        ids.insert(*chat_id);
                    }
                }
                if ids.is_empty() {
                    println!("No chat found for id {}", value);
                    return Ok(());
                }
                Some(ids)
            }
            _ => None,
        };

        let message_filter_ids = match options.message_id.as_ref().map(|value| value.trim()) {
            Some(value) if !value.is_empty() => {
                let mut ids = HashSet::new();
                for (message_id, external) in &message_map {
                    if external == value {
                        ids.insert(*message_id);
                    }
                }
                if ids.is_empty() {
                    println!("No message found for id {}", value);
                    return Ok(());
                }
                Some(ids)
            }
            _ => None,
        };

        let wanted_source = options.source_id.trim();
        if wanted_source.is_empty() {
            bail!("attachment source id is empty");
        }

        let mut candidates = Vec::new();
        for (message_id, attachment_id, chat_id, source_id_handle, data_handle) in find!(
            (
                message: Id,
                attachment: Id,
                chat: Id,
                source_id: Inline<Handle<LongString>>,
                data: Inline<Handle<RawBytes>>
            ),
            pattern!(&catalog, [
                { ?message @ archive::attachment: ?attachment, teams::chat: ?chat },
                { ?attachment @ archive::attachment_source_id: ?source_id, archive::attachment_data: ?data }
            ])
        ) {
            if let Some(filter) = &chat_filter_ids {
                if !filter.contains(&chat_id) {
                    continue;
                }
            }
            if let Some(filter) = &message_filter_ids {
                if !filter.contains(&message_id) {
                    continue;
                }
            }
            let source_id = load_longstring(&mut ws, source_id_handle)?;
            if source_id != wanted_source {
                continue;
            }

            candidates.push(AttachmentExportCandidate {
                message_id,
                chat_id,
                source_id,
                data_handle,
                name: find_optional_handle(&catalog, attachment_id, &archive::attachment_name),
                mime: find_optional_value(&catalog, attachment_id, &archive::attachment_mime),
            });
        }

        if candidates.is_empty() {
            println!("No attachment found for source id {wanted_source}.");
            return Ok(());
        }

        if candidates.len() > 1 {
            println!("Multiple attachments matched. Use --chat-id or --message-id to disambiguate:");
            for candidate in &candidates {
                let chat = chat_map
                    .get(&candidate.chat_id)
                    .cloned()
                    .unwrap_or_else(|| format!("{}", candidate.chat_id));
                let message = message_map
                    .get(&candidate.message_id)
                    .cloned()
                    .unwrap_or_else(|| format!("{}", candidate.message_id));
                println!("- chat={chat} message={message} attachment={}", candidate.source_id);
            }
            return Ok(());
        }

        let candidate = candidates.remove(0);
        let mut filename = options
            .filename
            .clone()
            .or_else(|| {
                candidate
                    .name
                    .map(|handle| load_longstring(&mut ws, handle))
                    .transpose()
                    .ok()
                    .flatten()
            })
            .unwrap_or_else(|| candidate.source_id.clone());

        filename = sanitize_filename(&filename);
        if !filename.contains('.') {
            if let Some(ext) = infer_extension(candidate.mime.as_ref()) {
                filename.push('.');
                filename.push_str(ext);
            }
        }

        let out_dir = options.out_dir.clone();
        fs::create_dir_all(&out_dir)
            .with_context(|| format!("create output dir {}", out_dir.display()))?;
        let path = out_dir.join(&filename);
        if path.exists() && !options.overwrite {
            bail!("output file exists: {} (use --overwrite)", path.display());
        }

        let bytes: Bytes =
            map_err_debug(ws.get::<Bytes, RawBytes>(candidate.data_handle), "load attachment bytes")?;
        fs::write(&path, bytes.as_ref())
            .with_context(|| format!("write attachment {}", path.display()))?;
        println!("{}", path.display());
        Ok(())
    })
}

fn open_repo_for_branch_id(
    path: &PathBuf,
    branch_id: Id,
    branch_name: &str,
) -> Result<(Repository<Pile>, Id)> {
    let mut pile = open_pile(path)?;
    if pile
        .head(branch_id)
        .map_err(|err| anyhow::anyhow!("branch head {branch_name}: {err:?}"))?
        .is_none()
    {
        let _ = pile.close();
        return Err(anyhow::anyhow!(
            "unknown branch {branch_name} ({branch_id:x})"
        ));
    }
    let repo = Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
        .map_err(|err| anyhow::anyhow!("create repository: {err:?}"))?;
    Ok((repo, branch_id))
}

#[derive(Debug, Clone)]
struct CursorState {
    url: String,
}

fn load_cursor_from_space(
    ws: &mut Workspace<Pile>,
    catalog: &TribleSet,
) -> Result<Option<CursorState>> {
    let mut best: Option<(i128, Id, Inline<Handle<LongString>>)> = None;
    for (cursor_id, delta_link, created_at) in find!(
        (cursor: Id, delta_link: Inline<Handle<LongString>>, created_at: Inline<NsTAIInterval>),
        pattern!(catalog, [{
            ?cursor @
            metadata::tag: teams::kind_cursor,
            teams::delta_link: ?delta_link,
            metadata::created_at: ?created_at,
        }])
    ) {
        let key = interval_key(created_at);
        let replace = match &best {
            None => true,
            Some((best_key, best_id, _)) => {
                key > *best_key || (key == *best_key && cursor_id > *best_id)
            }
        };
        if replace {
            best = Some((key, cursor_id, delta_link));
        }
    }

    let Some((_key, _cursor_id, handle)) = best else {
        return Ok(None);
    };

    let view: View<str> = map_err_debug(
        ws.get::<View<str>, LongString>(handle),
        "load teams delta cursor",
    )?;
    Ok(Some(CursorState {
        url: view.to_string(),
    }))
}

fn build_cursor_change(
    ws: &mut Workspace<Pile>,
    catalog: &TribleSet,
    current: Option<&CursorState>,
    new_cursor: Option<String>,
) -> Result<Option<TribleSet>> {
    let Some(cursor) = new_cursor else {
        return Ok(None);
    };
    let cursor = cursor.trim().to_owned();
    if cursor.is_empty() {
        return Ok(None);
    }
    if current.is_some_and(|state| state.url == cursor) {
        return Ok(None);
    }

    let handle = ws.put(cursor);
    let now = epoch_interval(now_epoch());
    let cursor_id = ufoid();
    let mut change = TribleSet::new();
    change += entity! { &cursor_id @
        metadata::tag: teams::kind_cursor,
        teams::delta_link: handle,
        metadata::created_at: now,
    };
    Ok(Some(change.difference(catalog)))
}

fn parse_messages(messages: Vec<JsonValue>) -> Result<Vec<IncomingMessage>> {
    let mut parsed = Vec::new();
    for message in messages {
        if message.get("@removed").is_some() {
            continue;
        }

        let Some(chat_external_id) = message.get("chatId").and_then(JsonValue::as_str) else {
            continue;
        };
        let Some(message_external_id) = message.get("id").and_then(JsonValue::as_str) else {
            continue;
        };
        let Some(created_at_str) = message.get("createdDateTime").and_then(JsonValue::as_str)
        else {
            continue;
        };
        let Some(content) = message
            .get("body")
            .and_then(|body| body.get("content"))
            .and_then(JsonValue::as_str)
        else {
            continue;
        };

        let epoch = parse_graph_datetime(created_at_str).unwrap_or_else(now_epoch);
        let created_at = epoch_interval(epoch);
        let created_at_key = interval_key(created_at);

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

        let raw_json = serde_json::to_string(&message).context("serialize teams message json")?;

        let mut attachments = Vec::new();
        let mut seen_sources = HashSet::new();
        attachments.extend(parse_json_attachments(
            &message,
            chat_external_id,
            message_external_id,
            &mut seen_sources,
        ));
        attachments.extend(parse_hosted_content_attachments(
            &content,
            chat_external_id,
            message_external_id,
            &mut seen_sources,
        ));

        parsed.push(IncomingMessage {
            chat_external_id: chat_external_id.to_owned(),
            message_external_id: message_external_id.to_owned(),
            raw_json,
            author_external_id,
            author_display_name,
            content: content.to_owned(),
            created_at,
            created_at_key,
            attachments,
        });
    }

    Ok(parsed)
}

fn parse_json_attachments(
    message: &JsonValue,
    chat_external_id: &str,
    message_external_id: &str,
    seen: &mut HashSet<String>,
) -> Vec<AttachmentSource> {
    let mut attachments = Vec::new();
    let Some(list) = message.get("attachments").and_then(JsonValue::as_array) else {
        return attachments;
    };
    for attachment in list {
        let Some(source_id) = attachment.get("id").and_then(JsonValue::as_str) else {
            continue;
        };
        if !seen.insert(source_id.to_string()) {
            continue;
        }

        let mut source_url = attachment
            .get("contentUrl")
            .and_then(JsonValue::as_str)
            .map(str::to_owned);
        if source_url.is_none() {
            source_url = Some(format!(
                "https://graph.microsoft.com/v1.0/chats/{chat_external_id}/messages/{message_external_id}/attachments/{source_id}/$value"
            ));
        }
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
            .and_then(|value| decode_base64(value).ok());

        attachments.push(AttachmentSource {
            source_id: source_id.to_owned(),
            source_url,
            name,
            content_type,
            content_bytes,
        });
    }

    attachments
}

fn parse_hosted_content_attachments(
    content: &str,
    chat_external_id: &str,
    message_external_id: &str,
    seen: &mut HashSet<String>,
) -> Vec<AttachmentSource> {
    let mut attachments = Vec::new();
    for hosted_id in extract_hosted_content_ids(content) {
        if !seen.insert(hosted_id.clone()) {
            continue;
        }
        let url = format!(
            "https://graph.microsoft.com/v1.0/chats/{chat_external_id}/messages/{message_external_id}/hostedContents/{hosted_id}/$value"
        );
        attachments.push(AttachmentSource {
            source_id: hosted_id,
            source_url: Some(url),
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

struct CatalogIndex {
    messages: HashSet<Id>,
    reply_to_set: HashSet<Id>,
    authors: HashSet<Id>,
    chats: HashSet<Id>,
    attachments: HashSet<Id>,
    message_attachment_set: HashSet<(Id, Id)>,
    last_message_by_chat: HashMap<Id, (i128, Id)>,
    author_name_set: HashSet<Id>,
    message_raw_set: HashSet<Id>,
    message_chat_set: HashSet<Id>,
    message_content_set: HashSet<Id>,
    message_created_at_set: HashSet<Id>,
}

impl CatalogIndex {
    fn build(catalog: &TribleSet) -> Self {
        let messages = find!(
            (message: Id),
            pattern!(catalog, [{
                ?message @
                metadata::tag: archive::kind_message,
            }])
        )
        .into_iter()
        .map(|(message,)| message)
        .collect::<HashSet<_>>();

        let reply_to_set = find!(
            (message: Id, reply_to: Id),
            pattern!(catalog, [{ ?message @ archive::reply_to: ?reply_to }])
        )
        .into_iter()
        .map(|(message, _)| message)
        .collect::<HashSet<_>>();

        let authors = find!(
            (author: Id),
            pattern!(catalog, [{
                ?author @
                metadata::tag: archive::kind_author,
            }])
        )
        .into_iter()
        .map(|(author,)| author)
        .collect::<HashSet<_>>();

        let chats = find!(
            (chat: Id),
            pattern!(catalog, [{ ?chat @ metadata::tag: teams::kind_chat }])
        )
        .into_iter()
        .map(|(chat,)| chat)
        .collect::<HashSet<_>>();

        let attachments = find!(
            (attachment: Id),
            pattern!(catalog, [{
                ?attachment @
                metadata::tag: archive::kind_attachment,
            }])
        )
        .into_iter()
        .map(|(attachment,)| attachment)
        .collect::<HashSet<_>>();

        let message_attachment_set = find!(
            (message: Id, attachment: Id),
            pattern!(catalog, [{ ?message @ archive::attachment: ?attachment }])
        )
        .into_iter()
        .collect::<HashSet<_>>();

        let author_name_set = find!(
            (author: Id, name: Inline<Handle<LongString>>),
            pattern!(catalog, [{ ?author @ archive::author_name: ?name }])
        )
        .into_iter()
        .map(|(author, _)| author)
        .collect::<HashSet<_>>();

        let message_raw_set = find!(
            (message: Id, raw: Inline<Handle<LongString>>),
            pattern!(catalog, [{ ?message @ teams::message_raw: ?raw }])
        )
        .into_iter()
        .map(|(message, _)| message)
        .collect::<HashSet<_>>();

        let message_chat_set = find!(
            (message: Id, chat: Id),
            pattern!(catalog, [{ ?message @ teams::chat: ?chat }])
        )
        .into_iter()
        .map(|(message, _)| message)
        .collect::<HashSet<_>>();

        let message_content_set = find!(
            (message: Id, content: Inline<Handle<LongString>>),
            pattern!(catalog, [{ ?message @ archive::content: ?content }])
        )
        .into_iter()
        .map(|(message, _)| message)
        .collect::<HashSet<_>>();

        let message_created_at_set = find!(
            (message: Id, created_at: Inline<NsTAIInterval>),
            pattern!(catalog, [{ ?message @ metadata::created_at: ?created_at }])
        )
        .into_iter()
        .map(|(message, _)| message)
        .collect::<HashSet<_>>();

        let mut last_message_by_chat: HashMap<Id, (i128, Id)> = HashMap::new();
        for (message_id, chat_id, created_at) in find!(
            (message: Id, chat: Id, created_at: Inline<NsTAIInterval>),
            pattern!(catalog, [{
                ?message @
                metadata::tag: archive::kind_message,
                teams::chat: ?chat,
                metadata::created_at: ?created_at,
            }])
        ) {
            let key = interval_key(created_at);
            match last_message_by_chat.get(&chat_id) {
                None => {
                    last_message_by_chat.insert(chat_id, (key, message_id));
                }
                Some((current_key, current_id))
                    if key > *current_key || (key == *current_key && message_id > *current_id) =>
                {
                    last_message_by_chat.insert(chat_id, (key, message_id));
                }
                _ => {}
            }
        }

        Self {
            messages,
            reply_to_set,
            authors,
            chats,
            attachments,
            message_attachment_set,
            last_message_by_chat,
            author_name_set,
            message_raw_set,
            message_chat_set,
            message_content_set,
            message_created_at_set,
        }
    }
}

fn build_ingest_change(
    ws: &mut Workspace<Pile>,
    catalog: &TribleSet,
    index: &CatalogIndex,
    incoming: Vec<IncomingMessage>,
    token: &str,
    config: &TeamsBridgeConfig,
) -> Result<(TribleSet, TribleSet)> {
    let mut by_chat: HashMap<String, Vec<IncomingMessage>> = HashMap::new();
    for message in incoming {
        by_chat
            .entry(message.chat_external_id.clone())
            .or_default()
            .push(message);
    }

    let mut change = TribleSet::new();
    let mut files_change = TribleSet::new();
    let mut added_attachments = HashSet::new();
    for (chat_external_id, mut messages) in by_chat {
        // Derive chat_id intrinsically from the external id.
        let chat_external_handle = ws.put(chat_external_id.clone());
        let chat_id_frag = entity! { _ @
            teams::chat_id: chat_external_handle,
        };
        let chat_id = chat_id_frag
            .root()
            .ok_or_else(|| anyhow::anyhow!("chat id rooted"))?;
        change += chat_id_frag;

        let missing_chat_kind = !index.chats.contains(&chat_id);
        if missing_chat_kind {
            change += entity! { ExclusiveId::force_ref(&chat_id) @
                metadata::tag: teams::kind_chat,
            };
        }

        // Sort by created_at (stable across runs; no derived-id tiebreak yet
        // because message_ids are per-message below).
        messages.sort_by(|left, right| {
            left.created_at_key
                .cmp(&right.created_at_key)
                .then_with(|| left.message_external_id.cmp(&right.message_external_id))
        });

        let mut predecessor = index
            .last_message_by_chat
            .get(&chat_id)
            .map(|(_, message_id)| *message_id);

        for message in messages {
            // Derive author_id intrinsically from the author's external id,
            // or fall back to the unknown-author singleton if Teams did not
            // provide one.
            let author_id = match message.author_external_id.as_deref() {
                Some(ext) if !ext.trim().is_empty() => {
                    ensure_author(
                        ws,
                        &mut change,
                        index,
                        ext,
                        message.author_display_name.as_deref(),
                    )?
                }
                _ => TEAMS_UNKNOWN_AUTHOR_ID,
            };

            // Derive message_id intrinsically from the message's external id.
            let message_external_handle = ws.put(message.message_external_id.clone());
            let message_id_frag = entity! { _ @
                teams::message_id: message_external_handle,
            };
            let message_id = message_id_frag
                .root()
                .ok_or_else(|| anyhow::anyhow!("message id rooted"))?;
            change += message_id_frag;

            ensure_attachments(
                ws,
                &mut change,
                &mut files_change,
                index,
                message_id,
                &message.attachments,
                token,
                config,
                &mut added_attachments,
            )?;

            if !index.messages.contains(&message_id) {
                // New message entity.
                let content_handle = ws.put(message.content);
                let raw_handle = ws.put(message.raw_json);
                change += entity! { ExclusiveId::force_ref(&message_id) @
                    metadata::tag: archive::kind_message,
                    archive::author: author_id,
                    metadata::created_at: message.created_at,
                    archive::content: content_handle,
                    teams::chat: chat_id,
                    teams::message_raw: raw_handle,
                    archive::reply_to?: predecessor,
                };
            } else {
                // Fill in missing metadata for existing messages when possible.
                let message_chat = (!index.message_chat_set.contains(&message_id))
                    .then_some(chat_id);
                let message_raw = (!index.message_raw_set.contains(&message_id))
                    .then(|| ws.put(message.raw_json.clone()));
                let message_created_at = (!index.message_created_at_set.contains(&message_id))
                    .then_some(message.created_at);
                let message_content = (!index.message_content_set.contains(&message_id))
                    .then(|| ws.put(message.content.clone()));
                let message_reply_to = (predecessor.is_some()
                    && !index.reply_to_set.contains(&message_id))
                    .then_some(predecessor.unwrap());

                if message_chat.is_some()
                    || message_raw.is_some()
                    || message_created_at.is_some()
                    || message_content.is_some()
                    || message_reply_to.is_some()
                {
                    change += entity! { ExclusiveId::force_ref(&message_id) @
                        teams::chat?: message_chat,
                        teams::message_raw?: message_raw,
                        metadata::created_at?: message_created_at,
                        archive::content?: message_content,
                        archive::reply_to?: message_reply_to,
                    };
                }
            }

            predecessor = Some(message_id);
        }
    }

    Ok((change.difference(catalog), files_change))
}

fn ensure_author(
    ws: &mut Workspace<Pile>,
    change: &mut TribleSet,
    index: &CatalogIndex,
    author_external_id: &str,
    author_display_name: Option<&str>,
) -> Result<Id> {
    // Derive author_id intrinsically from the external id via the
    // identity-only-fragment idiom.
    let external_handle = ws.put(author_external_id.to_owned());
    let id_frag = entity! { _ @
        teams::user_id: external_handle,
    };
    let author_id = id_frag
        .root()
        .ok_or_else(|| anyhow::anyhow!("author id rooted"))?;
    *change += id_frag;

    let missing_author_kind = !index.authors.contains(&author_id);
    let author_name = (!index.author_name_set.contains(&author_id)).then(|| {
        let name = author_display_name
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(author_external_id);
        ws.put(name.to_string())
    });

    if missing_author_kind || author_name.is_some() {
        *change += entity! { ExclusiveId::force_ref(&author_id) @
            metadata::tag?: missing_author_kind.then_some(&archive::kind_author),
            archive::author_name?: author_name,
        };
    }

    Ok(author_id)
}

fn ensure_attachments(
    ws: &mut Workspace<Pile>,
    change: &mut TribleSet,
    files_change: &mut TribleSet,
    index: &CatalogIndex,
    message_id: Id,
    attachments: &[AttachmentSource],
    token: &str,
    config: &TeamsBridgeConfig,
    added: &mut HashSet<Id>,
) -> Result<()> {
    for source in attachments {
        let source_id = source.source_id.trim();
        if source_id.is_empty() {
            continue;
        }
        // Derive attachment_id intrinsically from the source id via the
        // shared archive::attachment_source_id attribute.
        let source_handle = ws.put(source_id.to_owned());
        let att_id_frag = entity! { _ @
            archive::attachment_source_id: source_handle,
        };
        let attachment_id = att_id_frag
            .root()
            .ok_or_else(|| anyhow::anyhow!("attachment id rooted"))?;

        if !index
            .message_attachment_set
            .contains(&(message_id, attachment_id))
        {
            *change += entity! { ExclusiveId::force_ref(&message_id) @
                archive::attachment: attachment_id,
            };
        }
        *change += att_id_frag;

        if index.attachments.contains(&attachment_id) || !added.insert(attachment_id) {
            continue;
        }

        let mut content_type = source.content_type.clone();
        let bytes = match &source.content_bytes {
            Some(bytes) => bytes.clone(),
            None => {
                let Some(url) = source.source_url.as_deref() else {
                    continue;
                };
                match fetch_attachment_bytes(token, url) {
                    Ok((bytes, fetched_type)) => {
                        if content_type.is_none() {
                            content_type = fetched_type;
                        }
                        bytes
                    }
                    Err(err) => {
                        let _ = log_event(
                            config,
                            "error",
                            &format!("attachment fetch failed ({url}): {err:?}"),
                        );
                        continue;
                    }
                }
            }
        };

        // Store as a file entity on the files branch.
        let content_handle: Inline<inlineencodings::Handle<blobencodings::RawBytes>> =
            ws.put::<blobencodings::RawBytes, _>(bytes);
        let name_str = source
            .name
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("attachment");
        let name_handle: Inline<inlineencodings::Handle<blobencodings::LongString>> =
            ws.put(name_str.to_owned());
        let mime = content_type.as_deref().unwrap_or("application/octet-stream");

        *files_change += entity! { ExclusiveId::force_ref(&attachment_id) @
            metadata::tag: &KIND_FILE,
            file::content: content_handle,
            file::name: name_handle,
            file::mime: mime
        };
    }
    Ok(())
}

fn fetch_attachment_bytes(token: &str, url: &str) -> Result<(Vec<u8>, Option<String>)> {
    let client = Client::new();
    let resp = client
        .get(url)
        .bearer_auth(token)
        .send()
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        bail!("GET {url} failed: status={status} body={body}");
    }
    let content_type = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    let bytes = resp.bytes().context("read attachment bytes")?;
    Ok((bytes.to_vec(), content_type))
}

fn shortstring_value(value: Option<&str>) -> Option<Inline<ShortString>> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }
    let value = value.split(';').next().unwrap_or(value).trim();
    if value.is_empty() {
        return None;
    }
    let trimmed = truncate_utf8(value, 32);
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_inline())
    }
}

fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut len = 0;
    for ch in value.chars() {
        let ch_len = ch.len_utf8();
        if len + ch_len > max_bytes {
            break;
        }
        len += ch_len;
    }
    &value[..len]
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

fn infer_extension(mime: Option<&Inline<ShortString>>) -> Option<&'static str> {
    let mut mime = String::try_from_inline(mime?).ok()?;
    mime.make_ascii_lowercase();
    let mime = mime.split(';').next().unwrap_or("").trim();
    match mime {
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

fn map_err_debug<T, E: std::fmt::Debug>(
    result: std::result::Result<T, E>,
    context: &str,
) -> Result<T> {
    result.map_err(|err| anyhow::anyhow!("{context}: {err:?}"))
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



fn u256_to_u128(value: Inline<U256BE>) -> Option<u128> {
    let raw = value.raw;
    if raw[..16].iter().any(|&b| b != 0) {
        return None;
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&raw[16..]);
    Some(u128::from_be_bytes(buf))
}
