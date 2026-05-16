//!
//! # Discord faculty
//!
//! Ingests Discord channel messages into a TribleSpace pile and
//! posts new messages on request. Bot-token only — no OAuth2 dance.
//! Paste the token once (`discord login @token.txt`); it's cached
//! in the pile under a `kind_token` entity and reused on every
//! subsequent call.
//!
//! Messages land on the `discord` branch using the generic
//! `archive::*` schema (author / content / reply_to / kind_message)
//! so downstream consumers don't care which protocol they came
//! from. Discord-specific context (guild, channel, external
//! snowflakes, raw JSON) lives under the `discord::*` attributes.
//!
//! Entity ids are derived intrinsically from the external
//! snowflake via the identity-only-fragment idiom — re-ingesting
//! the same message collapses to the same entity, so edits and
//! re-runs are idempotent.
//!
//! ## MVP scope
//!
//! - `discord login <token>` — cache bot token in the pile.
//! - `discord send <channel_id> <text>` — POST a message.
//! - `discord read <channel_id>` — GET recent messages, ingest
//!   into the pile (per-channel cursor stored as
//!   `discord::cursor_last_message_id` so successive calls are
//!   incremental).
//!
//! Not yet implemented: attachments, gateway websocket for
//! real-time events, guild/channel listing. All straightforward
//! follow-ups; kept out of the MVP so the first working cut is
//! small.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::{CommandFactory, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use hifitime::{Epoch, TimeScale};
use rand_core::OsRng;
use reqwest::blocking::Client;
use serde_json::{Value as JsonValue, json};

use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::prelude::blobencodings::{self, LongString};
use triblespace::prelude::inlineencodings::{Blake3, Handle, NsTAIInterval};
use triblespace::prelude::*;

use faculties::schemas::archive::archive;
use faculties::schemas::discord::{DEFAULT_BRANCH, DEFAULT_LOG_BRANCH, discord};
use faculties::schemas::teams::{FILES_BRANCH_NAME, file_schema};
use file_schema::KIND_FILE;
use file_schema::file;

const DISCORD_API_BASE: &str = "https://discord.com/api/v10";

#[derive(Parser)]
#[command(
    name = "discord",
    about = "Post to and ingest Discord channels into TribleSpace"
)]
struct Cli {
    /// Path to the pile file to write into.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Branch name to write into (created if missing).
    #[arg(long, default_value = DEFAULT_BRANCH)]
    branch: String,
    /// Branch id (hex). Overrides `--branch`.
    #[arg(long)]
    branch_id: Option<String>,
    #[command(subcommand)]
    command: Option<CommandMode>,
}

#[derive(Subcommand)]
enum CommandMode {
    /// Cache a Discord bot token in the pile. Subsequent calls
    /// read it from the pile — no need to re-pass it.
    Login {
        /// Bot token (from the Discord developer portal). Use
        /// `@path` to read from a file or `@-` for stdin.
        token: String,
    },
    /// Post a message to a Discord channel.
    Send {
        /// Channel id (external Discord snowflake).
        channel_id: String,
        /// Message body. Use `@path` / `@-` for file / stdin.
        text: String,
    },
    /// Pull recent messages into the pile, then print the newest
    /// ones. If no channel is specified, polls every channel the
    /// bot can see (iterating via `/users/@me/guilds` +
    /// `/guilds/{id}/channels`) — Discord has no cross-channel
    /// delta stream the way Graph does, so the faculty does the
    /// fan-out itself. Successive runs are incremental: each
    /// channel has its own cursor.
    Read {
        /// Channel id (external Discord snowflake). If omitted,
        /// polls every text-capable channel the bot can see.
        channel_id: Option<String>,
        /// Only show messages at or after this timestamp
        /// (RFC3339: e.g. `2026-04-24T12:00:00Z`).
        #[arg(long)]
        since: Option<String>,
        /// Max messages to print from the pile after ingest
        /// (0 = no limit).
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Print newest first (default: oldest first).
        #[arg(long)]
        descending: bool,
        /// Max messages to fetch *per channel call* (1–100,
        /// Discord's API cap).
        #[arg(long, default_value_t = 50)]
        fetch_limit: u32,
    },
    /// List guilds (servers) + their text channels visible to the
    /// bot. Answers the "what can the bot see?" diagnostic — if a
    /// channel you expect isn't listed, the bot needs to be
    /// invited / granted access on Discord's side first.
    Channels {
        #[command(subcommand)]
        command: ChannelsCommand,
    },
}

#[derive(Subcommand)]
enum ChannelsCommand {
    /// Print guilds + channels.
    List {
        /// Only show channels in this guild (snowflake id).
        #[arg(long)]
        guild: Option<String>,
    },
}

#[derive(Clone, Debug)]
struct DiscordConfig {
    pile_path: PathBuf,
    #[allow(dead_code)]
    branch: String,
    branch_id: Id,
    log_branch_id: Id,
    files_branch_id: Id,
}

fn main() -> Result<()> {
    let mut cli = Cli::parse();
    let Some(mode) = cli.command.take() else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };
    let config = build_config(&cli)?;

    match mode {
        CommandMode::Login { token } => login(config, token),
        CommandMode::Send { channel_id, text } => send(config, channel_id, text),
        CommandMode::Read {
            channel_id,
            since,
            limit,
            descending,
            fetch_limit,
        } => read(
            config,
            ReadOptions {
                channel_id,
                since,
                limit,
                descending,
                fetch_limit,
            },
        ),
        CommandMode::Channels { command } => match command {
            ChannelsCommand::List { guild } => list_channels(config, guild),
        },
    }
}

// ── config / pile plumbing ───────────────────────────────────────

fn build_config(cli: &Cli) -> Result<DiscordConfig> {
    let pile_path = cli.pile.clone();
    let branch = cli.branch.clone();
    let log_branch = DEFAULT_LOG_BRANCH.to_string();
    let branch_id = with_repo(&pile_path, |repo| {
        if let Some(hex) = cli.branch_id.as_deref() {
            return Id::from_hex(hex.trim())
                .ok_or_else(|| anyhow!("invalid branch id '{hex}'"));
        }
        repo.ensure_branch(&branch, None)
            .map_err(|e| anyhow!("ensure discord branch: {e:?}"))
    })?;
    let log_branch_id = with_repo(&pile_path, |repo| {
        repo.ensure_branch(&log_branch, None)
            .map_err(|e| anyhow!("ensure logs branch: {e:?}"))
    })?;
    let files_branch_id = with_repo(&pile_path, |repo| {
        repo.ensure_branch(FILES_BRANCH_NAME, None)
            .map_err(|e| anyhow!("ensure files branch: {e:?}"))
    })?;
    Ok(DiscordConfig {
        pile_path,
        branch,
        branch_id,
        log_branch_id,
        files_branch_id,
    })
}

fn open_pile(path: &PathBuf) -> Result<Pile> {
    Pile::open(path).with_context(|| format!("open pile {}", path.display()))
}

fn with_repo<T>(
    pile_path: &PathBuf,
    f: impl FnOnce(&mut Repository<Pile>) -> Result<T>,
) -> Result<T> {
    let pile = open_pile(pile_path)?;
    let repo = Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
        .map_err(|e| anyhow!("create repository: {e:?}"))?;
    with_repo_close(repo, f)
}

fn with_repo_close<T, F>(repo: Repository<Pile>, f: F) -> Result<T>
where
    F: FnOnce(&mut Repository<Pile>) -> Result<T>,
{
    let mut repo = repo;
    let result = f(&mut repo);
    let pile = repo.into_storage();
    let close_res = pile.close().map_err(|e| anyhow!("close pile: {e:?}"));
    if let Err(err) = close_res {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }
    result
}

fn log_event(config: &DiscordConfig, level: &str, message: &str) -> Result<()> {
    with_repo(&config.pile_path, |repo| {
        let mut ws = repo
            .pull(config.log_branch_id)
            .map_err(|e| anyhow!("pull logs: {e:?}"))?;
        let level_handle = ws.put(level.to_string());
        let message_handle = ws.put(message.to_string());
        let change = entity! { _ @
            metadata::tag: discord::kind_log,
            metadata::created_at: epoch_interval(now_epoch()),
            archive::author_role: level_handle,
            archive::content: message_handle,
        };
        ws.commit(change, &format!("discord {level}"));
        repo.push(&mut ws).map_err(|e| anyhow!("push logs: {e:?}"))?;
        Ok(())
    })
}

// ── token cache ──────────────────────────────────────────────────

fn login(config: DiscordConfig, raw_token: String) -> Result<()> {
    let token = load_value_or_file_trimmed(&raw_token, "token")?;
    if token.is_empty() {
        bail!("empty token");
    }

    with_repo(&config.pile_path, |repo| {
        let mut ws = repo
            .pull(config.branch_id)
            .map_err(|e| anyhow!("pull discord: {e:?}"))?;
        let catalog = ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout discord: {e:?}"))?
            .into_facts();

        // Identity fragment for the bot-token entity — keyed on
        // `kind_token` alone, so there's exactly one token entity
        // per pile. Re-running `login` updates the token on the
        // same entity rather than minting a new one.
        let id_frag = entity! { _ @ metadata::tag: discord::kind_token };
        let token_id = id_frag.root().ok_or_else(|| anyhow!("token id rooted"))?;

        let token_handle = ws.put(token);
        let mut change = id_frag;
        change += entity! { ExclusiveId::force_ref(&token_id) @
            discord::bot_token: token_handle,
        };

        let delta = change.difference(&catalog);
        if !delta.is_empty() {
            ws.commit(delta, "discord: store bot token");
            repo.push(&mut ws)
                .map_err(|e| anyhow!("push discord: {e:?}"))?;
        }
        Ok(())
    })?;

    log_event(&config, "info", "bot token cached")?;
    println!("Token cached in pile.");
    Ok(())
}

fn load_bot_token(config: &DiscordConfig) -> Result<String> {
    let token: Result<Option<String>> = with_repo(&config.pile_path, |repo| {
        let mut ws = repo
            .pull(config.branch_id)
            .map_err(|e| anyhow!("pull discord: {e:?}"))?;
        let catalog = ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout discord: {e:?}"))?
            .into_facts();
        // Find any (entity, bot_token-handle) pair. There's at
        // most one by construction (kind_token is intrinsic-id'd
        // from just the tag).
        for (_tok, handle) in find!(
            (tok: Id, handle: Inline<Handle<LongString>>),
            pattern!(&catalog, [{
                ?tok @
                metadata::tag: discord::kind_token,
                discord::bot_token: ?handle,
            }])
        ) {
            let view: View<str> = ws
                .get(handle)
                .map_err(|e| anyhow!("get token bytes: {e:?}"))?;
            return Ok(Some(view.to_string()));
        }
        Ok(None)
    });
    token?.ok_or_else(|| anyhow!("no bot token cached; run `discord login <token>` first"))
}

// ── send ─────────────────────────────────────────────────────────

fn send(config: DiscordConfig, channel_id: String, raw_text: String) -> Result<()> {
    let token = load_bot_token(&config)?;
    let text = load_value_or_file(&raw_text, "message text")?;
    if text.trim().is_empty() {
        bail!("empty message body");
    }

    let client = build_client()?;
    let url = format!("{DISCORD_API_BASE}/channels/{channel_id}/messages");
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bot {token}"))
        .header("Content-Type", "application/json")
        .body(json!({ "content": text }).to_string())
        .send()
        .with_context(|| format!("POST {url}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        bail!("discord send failed ({status}): {body}");
    }

    let json: JsonValue = resp.json().context("parse send response")?;
    let message_id = json
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>");
    log_event(
        &config,
        "info",
        &format!("sent message {message_id} to channel {channel_id}"),
    )?;
    println!("Sent message {message_id} to channel {channel_id}");
    Ok(())
}

// ── read ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct IncomingMessage {
    external_id: String,
    raw_json: String,
    channel_external_id: String,
    author_external_id: String,
    author_display_name: String,
    content: String,
    created_at: Inline<NsTAIInterval>,
    /// Present only on edited messages. Re-ingesting an edited
    /// message updates this attribute on the existing entity.
    edited_at: Option<Inline<NsTAIInterval>>,
    reply_to_external_id: Option<String>,
    attachments: Vec<AttachmentSource>,
}

#[derive(Debug, Clone)]
struct AttachmentSource {
    /// Discord attachment snowflake — the external identity used
    /// to derive the attachment entity's intrinsic id via
    /// `archive::attachment_source_id`.
    source_id: String,
    /// CDN URL Discord serves the file from. Open (no auth) for
    /// discord.com attachments; we still user-agent the request.
    url: String,
    /// Original filename as uploaded.
    filename: String,
    /// MIME type Discord reports. May be missing for legacy
    /// attachments; caller falls back to "application/octet-stream".
    content_type: Option<String>,
}

#[derive(Debug, Clone)]
struct ReadOptions {
    channel_id: Option<String>,
    since: Option<String>,
    limit: usize,
    descending: bool,
    fetch_limit: u32,
}

fn read(config: DiscordConfig, options: ReadOptions) -> Result<()> {
    let token = load_bot_token(&config)?;
    let fetch_limit = options.fetch_limit.clamp(1, 100);

    match options.channel_id.as_deref() {
        Some(id) => {
            pull_channel(&config, &token, id, fetch_limit)?;
        }
        None => {
            let channels = list_visible_text_channels(&token)?;
            if channels.is_empty() {
                println!("Bot is not in any guilds (or has no text-capable channels).");
                return Ok(());
            }
            println!(
                "Polling {} channels across {} guilds…",
                channels.len(),
                channels
                    .iter()
                    .map(|c| c.guild_id.as_str())
                    .collect::<std::collections::HashSet<_>>()
                    .len()
            );
            for ch in &channels {
                if let Err(err) = pull_channel(&config, &token, &ch.id, fetch_limit) {
                    let _ = log_event(
                        &config,
                        "warn",
                        &format!("poll failed for channel {} ({}): {err:?}", ch.id, ch.name),
                    );
                    eprintln!("  ! {}: {err}", ch.id);
                }
            }
        }
    }

    print_history(&config, &options)?;
    Ok(())
}

/// Sync one channel from Discord into the pile: fetch via REST
/// using the stored cursor (if any), ingest messages +
/// attachments, advance the cursor to the newest snowflake seen.
fn pull_channel(
    config: &DiscordConfig,
    token: &str,
    channel_id: &str,
    fetch_limit: u32,
) -> Result<()> {
    let cursor = load_channel_cursor(config, channel_id)?;

    // `after=<id>` returns messages newer than `id`. Without a
    // cursor we get the most-recent `fetch_limit` messages (in
    // reverse order), which we normalise below.
    let client = build_client()?;
    let mut url =
        format!("{DISCORD_API_BASE}/channels/{channel_id}/messages?limit={fetch_limit}");
    if let Some(c) = cursor.as_deref() {
        url.push_str(&format!("&after={c}"));
    }
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bot {token}"))
        .send()
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        bail!("discord read failed ({status}): {body}");
    }
    let messages: Vec<JsonValue> = resp.json().context("parse read response")?;
    if messages.is_empty() {
        return Ok(());
    }

    let incoming = parse_messages(messages, channel_id)?;
    let ingested = incoming.len();
    let newest_snowflake = incoming
        .iter()
        .map(|m| m.external_id.clone())
        .max_by(|a, b| compare_snowflakes(a, b));

    with_repo(&config.pile_path, |repo| {
        let mut ws = repo
            .pull(config.branch_id)
            .map_err(|e| anyhow!("pull discord: {e:?}"))?;
        let mut files_ws = repo
            .pull(config.files_branch_id)
            .map_err(|e| anyhow!("pull files: {e:?}"))?;
        let catalog = ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout discord: {e:?}"))?
            .into_facts();
        let files_catalog = files_ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout files: {e:?}"))?
            .into_facts();

        let (change, files_change) =
            build_ingest_change(&mut ws, &mut files_ws, &catalog, incoming, config)?;

        let delta = change.difference(&catalog);
        if !delta.is_empty() {
            ws.commit(
                delta,
                &format!("discord: ingest {ingested} messages from {channel_id}"),
            );
            repo.push(&mut ws)
                .map_err(|e| anyhow!("push discord: {e:?}"))?;
        }

        let files_delta = files_change.difference(&files_catalog);
        if !files_delta.is_empty() {
            files_ws.commit(
                files_delta,
                &format!("discord: attachments from channel {channel_id}"),
            );
            repo.push(&mut files_ws)
                .map_err(|e| anyhow!("push files: {e:?}"))?;
        }
        Ok(())
    })?;

    if let Some(snowflake) = newest_snowflake {
        store_channel_cursor(config, channel_id, &snowflake)?;
    }

    log_event(
        config,
        "info",
        &format!("ingested {ingested} messages from channel {channel_id}"),
    )?;
    println!("  {channel_id}: +{ingested}");
    Ok(())
}

/// Describe one visible channel for the all-channels poll loop.
struct VisibleChannel {
    id: String,
    name: String,
    guild_id: String,
}

/// Enumerate every text-capable channel the bot can see. Text
/// channels are types 0 (GUILD_TEXT), 5 (GUILD_ANNOUNCEMENT), and
/// 15 (GUILD_FORUM); voice / stage / category / thread types are
/// skipped. Mirrors the shape `channels list` uses for display.
fn list_visible_text_channels(token: &str) -> Result<Vec<VisibleChannel>> {
    let client = build_client()?;
    let guilds: Vec<JsonValue> = client
        .get(format!("{DISCORD_API_BASE}/users/@me/guilds"))
        .header("Authorization", format!("Bot {token}"))
        .send()
        .context("GET /users/@me/guilds")?
        .error_for_status()
        .context("guilds request failed")?
        .json()
        .context("parse guilds response")?;

    let mut out = Vec::new();
    for guild in guilds {
        let guild_id = guild
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if guild_id.is_empty() {
            continue;
        }
        let channels: Vec<JsonValue> = client
            .get(format!("{DISCORD_API_BASE}/guilds/{guild_id}/channels"))
            .header("Authorization", format!("Bot {token}"))
            .send()
            .with_context(|| format!("GET /guilds/{guild_id}/channels"))?
            .error_for_status()
            .with_context(|| format!("channels request for guild {guild_id} failed"))?
            .json()
            .with_context(|| format!("parse channels for guild {guild_id}"))?;
        for ch in channels {
            let kind = ch.get("type").and_then(|v| v.as_i64()).unwrap_or(-1);
            if !matches!(kind, 0 | 5 | 15) {
                continue;
            }
            let id = ch.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let name = ch.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if id.is_empty() {
                continue;
            }
            out.push(VisibleChannel {
                id: id.to_string(),
                name: name.to_string(),
                guild_id: guild_id.clone(),
            });
        }
    }
    Ok(out)
}

/// Query the pile for messages — filtered by channel if
/// `options.channel_id` is set, otherwise pooled across every
/// channel — and print them. Channel identity comes from the
/// same identity-only-fragment idiom `build_ingest_change` uses,
/// so the filter is by intrinsic id.
fn print_history(config: &DiscordConfig, options: &ReadOptions) -> Result<()> {
    let since_key = match options.since.as_deref() {
        Some(s) => Some(interval_key(parse_iso8601(s.trim())?)),
        None => None,
    };

    with_repo(&config.pile_path, |repo| {
        let mut ws = repo
            .pull(config.branch_id)
            .map_err(|e| anyhow!("pull discord: {e:?}"))?;
        let catalog = ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout discord: {e:?}"))?
            .into_facts();

        // Re-derive the channel id from the external snowflake,
        // if filtering.
        let channel_filter: Option<Id> = match options.channel_id.as_deref() {
            Some(id_str) => {
                let external_handle = ws.put(id_str.to_string());
                let id_frag = entity! { _ @ discord::channel_id: external_handle };
                Some(
                    id_frag
                        .root()
                        .ok_or_else(|| anyhow!("channel id rooted"))?,
                )
            }
            None => None,
        };

        // Channel id → external snowflake, for display when the
        // filter is off.
        let mut channel_externals: HashMap<Id, String> = HashMap::new();
        for (ch_id, ext_handle) in find!(
            (channel: Id, ext: Inline<Handle<LongString>>),
            pattern!(&catalog, [{
                ?channel @
                metadata::tag: discord::kind_channel,
                discord::channel_id: ?ext,
            }])
        ) {
            let view: View<str> = ws
                .get(ext_handle)
                .map_err(|e| anyhow!("load channel external: {e:?}"))?;
            channel_externals.insert(ch_id, view.to_string());
        }

        // First pass: required attributes.
        let mut messages: Vec<HistoryRow> = Vec::new();
        for (msg, content, author_id, created_at, ch) in find!(
            (
                message: Id,
                content: Inline<Handle<LongString>>,
                author: Id,
                created_at: Inline<NsTAIInterval>,
                channel: Id,
            ),
            pattern!(&catalog, [{
                ?message @
                metadata::tag: archive::kind_message,
                archive::content: ?content,
                archive::author: ?author,
                metadata::created_at: ?created_at,
                discord::channel: ?channel,
            }])
        ) {
            if let Some(filter) = channel_filter {
                if ch != filter {
                    continue;
                }
            }
            let key = interval_key(created_at);
            if let Some(s) = since_key {
                if key < s {
                    continue;
                }
            }
            messages.push(HistoryRow {
                message_id: msg,
                channel_id: ch,
                content,
                author_id,
                created_at,
                created_at_key: key,
                edited_at: None,
            });
        }

        let edited: std::collections::HashMap<Id, Inline<NsTAIInterval>> = find!(
            (message: Id, edited: Inline<NsTAIInterval>),
            pattern!(&catalog, [{
                ?message @
                metadata::tag: archive::kind_message,
                archive::edited_at: ?edited,
            }])
        )
        .into_iter()
        .collect();
        for row in messages.iter_mut() {
            row.edited_at = edited.get(&row.message_id).copied();
        }

        // Resolve author display names in one pass.
        let mut author_names: HashMap<Id, String> = HashMap::new();
        for (author, name_handle) in find!(
            (author: Id, name: Inline<Handle<LongString>>),
            pattern!(&catalog, [{
                ?author @
                metadata::tag: archive::kind_author,
                archive::author_name: ?name,
            }])
        ) {
            let view: View<str> = ws
                .get(name_handle)
                .map_err(|e| anyhow!("load author name: {e:?}"))?;
            author_names.insert(author, view.to_string());
        }

        messages.sort_by_key(|m| m.created_at_key);
        if options.limit > 0 && messages.len() > options.limit {
            let start = messages.len() - options.limit;
            messages = messages.split_off(start);
        }
        if options.descending {
            messages.reverse();
        }

        if messages.is_empty() {
            match options.channel_id.as_deref() {
                Some(id) => println!("(no messages in pile for channel {id})"),
                None => println!("(no messages in pile)"),
            }
            return Ok(());
        }
        for message in messages {
            let view: View<str> = ws
                .get(message.content)
                .map_err(|e| anyhow!("load content: {e:?}"))?;
            let content = view.to_string();
            let author = author_names
                .get(&message.author_id)
                .cloned()
                .unwrap_or_else(|| format!("{}", message.author_id));
            let timestamp = format_interval(message.created_at);
            let edited_marker = match message.edited_at {
                Some(edit_interval) => format!(" (edited {})", format_interval(edit_interval)),
                None => String::new(),
            };
            // Prefix with the channel snowflake when showing
            // pooled history across channels.
            let channel_prefix = if channel_filter.is_some() {
                String::new()
            } else {
                match channel_externals.get(&message.channel_id) {
                    Some(ext) => format!(" #{ext}"),
                    None => String::new(),
                }
            };
            println!("[{timestamp}]{channel_prefix}{edited_marker} {author}: {content}");
        }
        Ok(())
    })
}

struct HistoryRow {
    message_id: Id,
    channel_id: Id,
    content: Inline<Handle<LongString>>,
    author_id: Id,
    created_at: Inline<NsTAIInterval>,
    created_at_key: i128,
    edited_at: Option<Inline<NsTAIInterval>>,
}

fn parse_messages(messages: Vec<JsonValue>, channel_external_id: &str) -> Result<Vec<IncomingMessage>> {
    let mut out = Vec::with_capacity(messages.len());
    for message in messages {
        let raw_json = serde_json::to_string(&message).context("serialize message json")?;
        let external_id = message
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("message missing id"))?
            .to_string();
        let content = message
            .get("content")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let author = message
            .get("author")
            .cloned()
            .unwrap_or(JsonValue::Null);
        let author_external_id = author
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let author_display_name = author
            .get("global_name")
            .and_then(|v| v.as_str())
            .or_else(|| author.get("username").and_then(|v| v.as_str()))
            .unwrap_or("")
            .to_string();
        let timestamp_str = message
            .get("timestamp")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("message {external_id} missing timestamp"))?;
        let created_at = parse_iso8601(timestamp_str)
            .with_context(|| format!("parse timestamp {timestamp_str}"))?;
        // `edited_timestamp` is null on unedited messages and an
        // ISO-8601 string otherwise. Skip silently on parse
        // failure — a malformed edit stamp shouldn't block ingest.
        let edited_at = message
            .get("edited_timestamp")
            .and_then(|v| v.as_str())
            .and_then(|s| parse_iso8601(s).ok());
        let reply_to_external_id = message
            .get("referenced_message")
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Discord attachments live in `attachments[]` on the
        // message body; shape documented at
        // https://discord.com/developers/docs/resources/channel#attachment-object
        let attachments = message
            .get("attachments")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|a| {
                        let source_id = a.get("id").and_then(|v| v.as_str())?.to_string();
                        let url = a.get("url").and_then(|v| v.as_str())?.to_string();
                        let filename = a
                            .get("filename")
                            .and_then(|v| v.as_str())
                            .unwrap_or("attachment")
                            .to_string();
                        let content_type = a
                            .get("content_type")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        Some(AttachmentSource {
                            source_id,
                            url,
                            filename,
                            content_type,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        out.push(IncomingMessage {
            external_id,
            raw_json,
            channel_external_id: channel_external_id.to_string(),
            author_external_id,
            author_display_name,
            content,
            created_at,
            edited_at,
            reply_to_external_id,
            attachments,
        });
    }
    // Normalise to oldest-first for stable `reply_to` resolution.
    out.sort_by(|a, b| compare_snowflakes(&a.external_id, &b.external_id));
    Ok(out)
}

fn build_ingest_change(
    ws: &mut Workspace<Pile>,
    files_ws: &mut Workspace<Pile>,
    _catalog: &TribleSet,
    messages: Vec<IncomingMessage>,
    config: &DiscordConfig,
) -> Result<(TribleSet, TribleSet)> {
    let mut change = TribleSet::new();
    let mut files_change = TribleSet::new();
    let mut added_attachment_files: std::collections::HashSet<Id> =
        std::collections::HashSet::new();

    // Resolve each external id (channel, author, message) to an
    // intrinsic Id via the identity-only-fragment idiom. Cached
    // across this batch so repeated references hit the same id.
    let mut channel_ids: HashMap<String, Id> = HashMap::new();
    let mut author_ids: HashMap<String, Id> = HashMap::new();
    let mut message_ids: HashMap<String, Id> = HashMap::new();

    for message in &messages {
        // ── channel ──
        if !channel_ids.contains_key(&message.channel_external_id) {
            let external_handle = ws.put(message.channel_external_id.clone());
            let id_frag = entity! { _ @
                discord::channel_id: external_handle,
            };
            let channel_id = id_frag
                .root()
                .ok_or_else(|| anyhow!("channel id rooted"))?;
            change += id_frag;
            change += entity! { ExclusiveId::force_ref(&channel_id) @
                metadata::tag: discord::kind_channel,
            };
            channel_ids.insert(message.channel_external_id.clone(), channel_id);
        }
        // ── author ──
        if !author_ids.contains_key(&message.author_external_id) {
            let external_handle = ws.put(message.author_external_id.clone());
            let id_frag = entity! { _ @
                discord::user_id: external_handle,
            };
            let author_id = id_frag
                .root()
                .ok_or_else(|| anyhow!("author id rooted"))?;
            change += id_frag;
            let mut author_facts = entity! { ExclusiveId::force_ref(&author_id) @
                metadata::tag: archive::kind_author,
            };
            if !message.author_display_name.is_empty() {
                let name_handle = ws.put(message.author_display_name.clone());
                author_facts += entity! { ExclusiveId::force_ref(&author_id) @
                    archive::author_name: name_handle,
                };
            }
            change += author_facts;
            author_ids.insert(message.author_external_id.clone(), author_id);
        }
    }

    // ── messages (second pass, so reply_to can resolve predecessors from this batch) ──
    for message in &messages {
        let external_handle = ws.put(message.external_id.clone());
        let id_frag = entity! { _ @
            discord::message_id: external_handle,
        };
        let message_id = id_frag
            .root()
            .ok_or_else(|| anyhow!("message id rooted"))?;
        message_ids.insert(message.external_id.clone(), message_id);

        let content_handle = ws.put(message.content.clone());
        let raw_handle = ws.put(message.raw_json.clone());
        let channel_id = channel_ids[&message.channel_external_id];
        let author_id = author_ids[&message.author_external_id];
        let reply_to = message
            .reply_to_external_id
            .as_ref()
            .and_then(|ext| message_ids.get(ext).copied());

        change += id_frag;
        change += entity! { ExclusiveId::force_ref(&message_id) @
            metadata::tag: archive::kind_message,
            archive::author: author_id,
            archive::content: content_handle,
            metadata::created_at: message.created_at,
            discord::channel: channel_id,
            discord::message_raw: raw_handle,
            archive::reply_to?: reply_to,
            archive::edited_at?: message.edited_at,
        };

        // ── attachments ──
        // For each attachment on this message, derive an intrinsic
        // id from `archive::attachment_source_id`, link the
        // message → attachment, and put the file on the shared
        // files branch tagged KIND_FILE. Deduped across this
        // batch so the same attachment seen twice only fetches
        // once.
        for source in &message.attachments {
            let source_handle = ws.put(source.source_id.clone());
            let att_id_frag = entity! { _ @
                archive::attachment_source_id: source_handle,
            };
            let attachment_id = att_id_frag
                .root()
                .ok_or_else(|| anyhow!("attachment id rooted"))?;

            // Link message → attachment. Safe to re-emit; trible
            // de-duplicates against the catalog at commit time.
            change += entity! { ExclusiveId::force_ref(&message_id) @
                archive::attachment: attachment_id,
            };
            change += att_id_frag;

            if !added_attachment_files.insert(attachment_id) {
                continue;
            }

            // Download the bytes from Discord's CDN. No bot auth
            // required — CDN URLs are open. If the fetch fails,
            // log and skip the file entity; the message and the
            // `archive::attachment_source_id` entity still land,
            // so a later backfill can pick it up.
            let (bytes, fetched_type) = match fetch_attachment_bytes(&source.url) {
                Ok(pair) => pair,
                Err(err) => {
                    let _ = log_event(
                        config,
                        "error",
                        &format!(
                            "attachment fetch failed ({}): {err:?}",
                            source.url
                        ),
                    );
                    continue;
                }
            };

            let mime = source
                .content_type
                .clone()
                .or(fetched_type)
                .unwrap_or_else(|| "application/octet-stream".to_string());
            let content_handle = files_ws.put::<blobencodings::RawBytes, _>(bytes);
            let name_handle = files_ws.put(source.filename.clone());

            files_change += entity! { ExclusiveId::force_ref(&attachment_id) @
                metadata::tag: &KIND_FILE,
                file::content: content_handle,
                file::name: name_handle,
                file::mime: mime.as_str(),
            };
        }
    }

    Ok((change, files_change))
}

// ── per-channel cursor ───────────────────────────────────────────

fn load_channel_cursor(config: &DiscordConfig, channel_external_id: &str) -> Result<Option<String>> {
    with_repo(&config.pile_path, |repo| {
        let mut ws = repo
            .pull(config.branch_id)
            .map_err(|e| anyhow!("pull discord: {e:?}"))?;
        let catalog = ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout discord: {e:?}"))?
            .into_facts();

        // Cursor id is the root of `{kind_cursor, channel_id=X}`.
        let external_handle = ws.put(channel_external_id.to_string());
        let id_frag = entity! { _ @
            metadata::tag: discord::kind_cursor,
            discord::channel_id: external_handle,
        };
        let cursor_id = id_frag
            .root()
            .ok_or_else(|| anyhow!("cursor id rooted"))?;

        for (_cur, handle) in find!(
            (cur: Id, handle: Inline<Handle<LongString>>),
            pattern!(&catalog, [{
                ?cur @
                metadata::tag: discord::kind_cursor,
                discord::cursor_last_message_id: ?handle,
            }])
        ) {
            // find! doesn't let us filter by cursor_id in-macro
            // without rebinding, so check match manually:
            if _cur == cursor_id {
                let view: View<str> = ws
                    .get(handle)
                    .map_err(|e| anyhow!("get cursor: {e:?}"))?;
                return Ok(Some(view.to_string()));
            }
        }
        Ok(None)
    })
}

fn store_channel_cursor(
    config: &DiscordConfig,
    channel_external_id: &str,
    snowflake: &str,
) -> Result<()> {
    with_repo(&config.pile_path, |repo| {
        let mut ws = repo
            .pull(config.branch_id)
            .map_err(|e| anyhow!("pull discord: {e:?}"))?;
        let catalog = ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout discord: {e:?}"))?
            .into_facts();

        let external_handle = ws.put(channel_external_id.to_string());
        let id_frag = entity! { _ @
            metadata::tag: discord::kind_cursor,
            discord::channel_id: external_handle,
        };
        let cursor_id = id_frag
            .root()
            .ok_or_else(|| anyhow!("cursor id rooted"))?;

        let snowflake_handle = ws.put(snowflake.to_string());
        let mut change = id_frag;
        change += entity! { ExclusiveId::force_ref(&cursor_id) @
            discord::cursor_last_message_id: snowflake_handle,
        };

        let delta = change.difference(&catalog);
        if !delta.is_empty() {
            ws.commit(
                delta,
                &format!("discord: update cursor for {channel_external_id}"),
            );
            repo.push(&mut ws)
                .map_err(|e| anyhow!("push discord: {e:?}"))?;
        }
        Ok(())
    })
}

// ── channels list ────────────────────────────────────────────────

fn list_channels(config: DiscordConfig, guild_filter: Option<String>) -> Result<()> {
    let token = load_bot_token(&config)?;
    let client = build_client()?;

    // 1. guilds the bot is in.
    let guilds: Vec<JsonValue> = client
        .get(format!("{DISCORD_API_BASE}/users/@me/guilds"))
        .header("Authorization", format!("Bot {token}"))
        .send()
        .context("GET /users/@me/guilds")?
        .error_for_status()
        .context("guilds request failed")?
        .json()
        .context("parse guilds response")?;

    if guilds.is_empty() {
        println!("Bot is not a member of any guilds. Invite it to a server first.");
        return Ok(());
    }

    let filter = guild_filter.as_deref().map(str::trim);

    for guild in guilds {
        let guild_id = guild
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("<missing>");
        let guild_name = guild
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("<unnamed>");
        if filter.map_or(false, |f| !f.is_empty() && f != guild_id) {
            continue;
        }

        println!("{guild_name}  ({guild_id})");

        // 2. channels in this guild.
        let channels: Vec<JsonValue> = client
            .get(format!("{DISCORD_API_BASE}/guilds/{guild_id}/channels"))
            .header("Authorization", format!("Bot {token}"))
            .send()
            .with_context(|| format!("GET /guilds/{guild_id}/channels"))?
            .error_for_status()
            .with_context(|| format!("channels request for guild {guild_id} failed"))?
            .json()
            .with_context(|| format!("parse channels for guild {guild_id}"))?;

        // Discord channel types: 0 = GUILD_TEXT, 2 = GUILD_VOICE,
        // 4 = GUILD_CATEGORY, 5 = GUILD_ANNOUNCEMENT, 15 = GUILD_FORUM.
        // Group by category; show text-ish ones first.
        let mut rows: Vec<(i64, &str, &str, &str)> = Vec::new();
        for channel in &channels {
            let id = channel
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("<missing>");
            let name = channel
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("<unnamed>");
            let kind = channel.get("type").and_then(|v| v.as_i64()).unwrap_or(-1);
            let kind_label = channel_type_label(kind);
            rows.push((kind, id, name, kind_label));
        }
        // Stable order: categories first, then text/announce/forum, then voice.
        rows.sort_by_key(|(kind, _, _, _)| match kind {
            4 => 0,   // category
            0 | 5 => 1, // text / announcement
            15 => 2,  // forum
            _ => 3,   // voice, stage, thread, ...
        });

        for (_, id, name, kind_label) in rows {
            println!("  {kind_label:<12} #{name:<30} {id}");
        }
        println!();
    }
    Ok(())
}

fn channel_type_label(kind: i64) -> &'static str {
    match kind {
        0 => "text",
        1 => "dm",
        2 => "voice",
        3 => "group-dm",
        4 => "category",
        5 => "announcement",
        10 => "announce-thread",
        11 => "public-thread",
        12 => "private-thread",
        13 => "stage",
        14 => "directory",
        15 => "forum",
        16 => "media",
        _ => "other",
    }
}

// ── attachment bytes ─────────────────────────────────────────────

/// Fetch attachment bytes from Discord's CDN. Unlike teams'
/// `fetch_attachment_bytes`, no bearer token is needed — Discord
/// CDN URLs are open. Returns `(bytes, response_content_type)`
/// so a missing `content_type` on the JSON attachment object can
/// fall back to whatever the CDN reports.
fn fetch_attachment_bytes(url: &str) -> Result<(Vec<u8>, Option<String>)> {
    let client = build_client()?;
    let resp = client
        .get(url)
        .send()
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        bail!("GET {url} failed: status={status} body={body}");
    }
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let bytes = resp.bytes().context("read attachment body")?;
    Ok((bytes.to_vec(), content_type))
}

// ── helpers ──────────────────────────────────────────────────────

fn build_client() -> Result<Client> {
    Client::builder()
        .user_agent("triblespace-discord/0.1")
        .timeout(Duration::from_secs(30))
        .build()
        .context("build reqwest client")
}

/// Compare two Discord snowflakes numerically without parsing —
/// they're fixed-width u64 strings, so lexicographic works as long
/// as the strings are equal-length. Discord snowflakes are all
/// 17–19 digits; compare by (length, string) to get numeric order.
fn compare_snowflakes(a: &str, b: &str) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn parse_iso8601(value: &str) -> Result<Inline<NsTAIInterval>> {
    // Discord timestamps look like `2026-04-22T09:12:34.567000+00:00`.
    // hifitime's Epoch::from_gregorian_str handles RFC3339.
    let epoch = Epoch::from_gregorian_str(value)
        .map_err(|e| anyhow!("parse iso8601 '{value}': {e}"))?;
    Ok(epoch_interval(epoch))
}

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or(Epoch::from_gregorian_tai_at_midnight(2026, 1, 1))
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

fn load_value_or_file(raw: &str, label: &str) -> Result<String> {
    if let Some(path) = raw.strip_prefix('@') {
        if path == "-" {
            let mut value = String::new();
            std::io::stdin()
                .read_to_string(&mut value)
                .with_context(|| format!("read {label} from stdin"))?;
            return Ok(value);
        }
        return fs::read_to_string(path)
            .with_context(|| format!("read {label} from {path}"));
    }
    Ok(raw.to_string())
}

fn load_value_or_file_trimmed(raw: &str, label: &str) -> Result<String> {
    Ok(load_value_or_file(raw, label)?.trim().to_string())
}
