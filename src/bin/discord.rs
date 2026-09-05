//! Discord observation faculty.
//!
//! The faculty stores complete, immutable message observations in one
//! SimpleArchive-union collection. Discord snowflakes identify stable anchors;
//! mutable payloads never accumulate conflicting values on those anchors.
//! Replaying an identical REST payload converges on the same intrinsic
//! observation, while an edit creates a new observation linked to the same
//! message anchor.
//!
//! Forward progress is represented by immutable numeric intervals. The first
//! bounded import establishes an explicit baseline immediately before its
//! oldest returned message. Later reads backpaginate to the connected frontier
//! before publishing one interval in the same signed COMMIT as every message
//! and attachment it covers. A bounded recent-window fetch also reconciles
//! edits. The REST API cannot prove deletions or edits outside that window;
//! future Gateway tombstones can be modeled as another immutable observation
//! kind.
//!
//! Bot credentials are deliberately external input. This faculty neither
//! claims the historical shared logs branch nor stores mutable secrets in the
//! logical Discord dataset.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hifitime::{Epoch, TimeScale};
use reqwest::blocking::Client;
use serde_json::{json, Value as JsonValue};

use faculties::collection_names::{open_configured, open_exact_in};
use faculties::discord as discord_model;
use faculties::files as file_capability;
use faculties::schemas::archive::archive;
use faculties::schemas::discord::{discord, DEFAULT_SCOPE_ID};
use faculties::storage::{load_signer, open_pile_strict, FactArchive, FactCollection};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::collection::{
    records::CollectionHandle, Collection, CollectionCommit, CollectionSnapshotExt,
    CollectionStoreExt,
};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::prelude::inlineencodings::NsTAIInterval;
use triblespace::prelude::*;

const DISCORD_API_BASE: &str = "https://discord.com/api/v10";

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "discord",
    about = "Post to and ingest Discord channels into TribleSpace"
)]
struct Cli {
    /// Path to the pile file to use.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it;
    /// initialize explicitly with trible pile signing-key init.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Discord bot token. Use @path or @- to avoid exposing it in argv.
    #[arg(long, env = "DISCORD_TOKEN")]
    token: Option<String>,
    #[command(subcommand)]
    command: Option<CommandMode>,
}

#[derive(Subcommand)]
enum CommandMode {
    /// Post a message and persist the returned Discord observation.
    Send {
        /// Channel id (global Discord snowflake).
        channel_id: String,
        /// Message body. Use @path for file input or @- for stdin.
        text: String,
    },
    /// Pull one complete forward interval plus a bounded recent window.
    Read {
        /// Channel id (global Discord snowflake). If omitted, poll every
        /// visible text-capable channel.
        channel_id: Option<String>,
        /// Only display messages at or after this RFC3339 timestamp.
        #[arg(long)]
        since: Option<String>,
        /// Maximum messages to display after ingestion (0 = no limit).
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Display newest first.
        #[arg(long)]
        descending: bool,
        /// Maximum messages per forward page (Discord caps this at 100).
        #[arg(long, default_value_t = 100)]
        fetch_limit: u32,
        /// Recent messages re-fetched to observe bounded-window edits.
        #[arg(long, default_value_t = 50)]
        reconcile_limit: u32,
    },
    /// List guilds and channels visible to the bot.
    Channels {
        #[command(subcommand)]
        command: ChannelsCommand,
    },
}

#[derive(Subcommand)]
enum ChannelsCommand {
    /// Print guilds and channels.
    List {
        /// Only show channels in this guild (global Discord snowflake).
        #[arg(long)]
        guild: Option<String>,
    },
}

#[derive(Clone, Copy)]
struct DiscordStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
    collection: Option<CollectionHandle>,
}

#[derive(Clone)]
struct CollectionView {
    facts: FactArchive,
    reader: PileSnapshot,
}

struct DiscordSession<'a> {
    pile: &'a mut Pile,
    collection: Collection<SimpleArchive>,
    maintained: FactCollection,
    signer: SigningKey,
    facts: FactArchive,
    reader: PileSnapshot,
}

impl DiscordSession<'_> {
    fn view(&self) -> CollectionView {
        CollectionView {
            facts: self.facts.clone(),
            reader: self.reader.clone(),
        }
    }

    fn commit(&mut self, mut fragment: Fragment, description: String) -> Result<CollectionCommit> {
        fragment.describe_with(entity! { metadata::description: description });
        let commit = self
            .pile
            .commit(self.collection, &self.signer, fragment)
            .context("publish Discord collection fragment")?;
        self.reader = pollster::block_on(self.maintained.maintain(self.pile))
            .context("maintain Discord fact collection after commit")?;
        self.facts = self
            .reader
            .collection(self.maintained.rank9())
            .context("observe maintained Discord fact collection after commit")?
            .view::<FactArchive>()
            .context("read maintained Discord fact collection after commit")?;
        Ok(commit)
    }
}

impl DiscordStorage<'_> {
    fn open_collection(
        &self,
        pile: &mut Pile,
        authority: VerifyingKey,
    ) -> Result<Collection<SimpleArchive>> {
        let Some(handle) = self.collection else {
            return open_configured(pile, DEFAULT_SCOPE_ID, authority);
        };
        let snapshot = pile
            .snapshot()
            .context("freeze store while opening exact Discord collection")?;
        open_exact_in(&snapshot, DEFAULT_SCOPE_ID, handle)
    }

    /// Prove that this process can publish to the selected collection before
    /// an outbound Discord side effect occurs.
    fn preflight_write(&self) -> Result<()> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = (|| {
            let collection = self.open_collection(&mut pile, signer.verifying_key())?;
            let snapshot = pile
                .snapshot()
                .context("freeze Discord WRITE-admission preflight")?;
            if !collection
                .writer_is_admitted(&snapshot, signer.verifying_key())
                .context("check Discord collection WRITE admission")?
            {
                bail!("durable signer is not admitted to WRITE the Discord collection");
            }
            Ok(())
        })();
        finish_pile(pile, result)
    }

    fn with_session<T>(
        &self,
        operation: impl FnOnce(&mut DiscordSession<'_>) -> Result<T>,
    ) -> Result<T> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = (|| {
            let collection = self.open_collection(&mut pile, signer.verifying_key())?;
            let maintained = FactCollection::new(&mut pile, collection)
                .context("register maintained Discord fact collection")?;
            let store_snapshot = pollster::block_on(maintained.maintain(&mut pile))
                .context("maintain Discord fact collection")?;
            let facts = store_snapshot
                .collection(maintained.rank9())
                .context("observe maintained Discord fact collection")?
                .view::<FactArchive>()
                .context("read maintained Discord fact collection")?;
            operation(&mut DiscordSession {
                pile: &mut pile,
                collection,
                maintained,
                signer,
                facts,
                reader: store_snapshot,
            })
        })();
        finish_pile(pile, result)
    }

    #[cfg(test)]
    fn view(&self) -> Result<CollectionView> {
        self.with_session(|session| Ok(session.view()))
    }

    fn publish(&self, fragment: Fragment, description: String) -> Result<CollectionCommit> {
        self.with_session(|session| session.commit(fragment, description))
    }
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context("close Discord pile")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing Discord pile also failed: {close_error}")))
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command.as_ref() else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };
    let storage = DiscordStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
        collection: None,
    };

    match command {
        CommandMode::Send { channel_id, text } => {
            let token = require_token(&cli)?;
            send(storage, &token, channel_id, text)
        }
        CommandMode::Read {
            channel_id,
            since,
            limit,
            descending,
            fetch_limit,
            reconcile_limit,
        } => {
            let token = require_token(&cli)?;
            read(
                storage,
                &token,
                ReadOptions {
                    channel_id: channel_id.clone(),
                    since: since.clone(),
                    limit: *limit,
                    descending: *descending,
                    fetch_limit: (*fetch_limit).clamp(1, 100),
                    reconcile_limit: (*reconcile_limit).clamp(1, 100),
                },
            )
        }
        CommandMode::Channels { command } => match command {
            ChannelsCommand::List { guild } => {
                let token = require_token(&cli)?;
                list_channels(&token, guild.as_deref())
            }
        },
    }
}

fn require_token(cli: &Cli) -> Result<String> {
    let token = cli
        .token
        .as_deref()
        .ok_or_else(|| anyhow!("missing Discord token; pass --token, DISCORD_TOKEN, @path, or @-"))
        .and_then(|raw| load_value_or_file_trimmed(raw, "Discord token"))?;
    if token.is_empty() {
        bail!("empty Discord token");
    }
    Ok(token)
}

fn send(storage: DiscordStorage<'_>, token: &str, channel_id: &str, raw_text: &str) -> Result<()> {
    send_with(storage, token, channel_id, raw_text, post_message)
}

fn send_with(
    storage: DiscordStorage<'_>,
    token: &str,
    channel_id: &str,
    raw_text: &str,
    post: impl FnOnce(&str, &str, &str) -> Result<JsonValue>,
) -> Result<()> {
    discord_model::validate_snowflake(channel_id).context("invalid channel id")?;
    let text = faculties::text_arg(raw_text, "message text")?;
    if text.trim().is_empty() {
        bail!("empty message body");
    }

    storage
        .preflight_write()
        .context("preflight Discord collection WRITE admission")?;
    let payload = post(token, channel_id, &text)?;
    let messages = parse_messages(vec![payload], channel_id)?;
    let message_id = messages
        .first()
        .map(|message| message.external_id.as_str())
        .ok_or_else(|| anyhow!("Discord send response contained no message"))?;
    let fragment = build_ingest_fragment(&messages, None, fetch_attachment_bytes)?;
    storage.publish(
        fragment,
        format!("discord: sent and observed message {message_id} in channel {channel_id}"),
    )?;
    println!("Sent and stored message {message_id} in channel {channel_id}");
    Ok(())
}

fn post_message(token: &str, channel_id: &str, text: &str) -> Result<JsonValue> {
    let client = build_client()?;
    let url = format!("{DISCORD_API_BASE}/channels/{channel_id}/messages");
    let response = client
        .post(&url)
        .header("Authorization", format!("Bot {token}"))
        .header("Content-Type", "application/json")
        .body(json!({ "content": text }).to_string())
        .send()
        .with_context(|| format!("POST {url}"))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        bail!("discord send failed ({status}): {body}");
    }
    response.json().context("parse send response")
}

#[derive(Debug, Clone)]
struct ReadOptions {
    channel_id: Option<String>,
    since: Option<String>,
    limit: usize,
    descending: bool,
    fetch_limit: u32,
    reconcile_limit: u32,
}

fn read(storage: DiscordStorage<'_>, token: &str, options: ReadOptions) -> Result<()> {
    storage.with_session(|session| {
        match options.channel_id.as_deref() {
            Some(channel_id) => {
                pull_channel(
                    session,
                    token,
                    channel_id,
                    options.fetch_limit,
                    options.reconcile_limit,
                )?;
            }
            None => {
                let channels = list_visible_text_channels(token)?;
                if channels.is_empty() {
                    println!("Bot is not in any guilds or has no text-capable channels.");
                    return Ok(());
                }
                println!(
                    "Polling {} channels across {} guilds…",
                    channels.len(),
                    channels
                        .iter()
                        .map(|channel| channel.guild_id.as_str())
                        .collect::<BTreeSet<_>>()
                        .len()
                );
                for channel in &channels {
                    if let Err(error) = pull_channel(
                        session,
                        token,
                        &channel.id,
                        options.fetch_limit,
                        options.reconcile_limit,
                    ) {
                        eprintln!("  ! {} ({}): {error:#}", channel.id, channel.name);
                    }
                }
            }
        }
        print_history(&session.view(), &options)
    })
}

/// Fetch a complete forward interval and one bounded recent reconciliation
/// window. The interval is appended only after every semantic payload and file
/// has been staged successfully.
fn pull_channel(
    session: &mut DiscordSession<'_>,
    token: &str,
    channel_id: &str,
    fetch_limit: u32,
    reconcile_limit: u32,
) -> Result<()> {
    discord_model::validate_snowflake(channel_id).context("invalid channel id")?;
    let channel = discord_model::channel_fragment(channel_id)?
        .root()
        .expect("intrinsic channel has one root");
    let prior = discord_model::channel_coverage(&session.facts, channel)?;
    let forward = fetch_complete_forward(
        prior.map(|coverage| coverage.through_inclusive),
        fetch_limit,
        |request| fetch_message_page(token, channel_id, request),
    )?;
    let recent_payloads = if prior.is_some() {
        fetch_message_page(
            token,
            channel_id,
            PageRequest {
                after: None,
                before: None,
                limit: reconcile_limit,
            },
        )?
    } else {
        Vec::new()
    };

    let mut payloads = forward.payloads;
    payloads.extend(recent_payloads);
    let messages = parse_messages(payloads, channel_id)?;
    if messages.is_empty() {
        println!("  {channel_id}: no observations");
        return Ok(());
    }

    let fragment = build_ingest_fragment(&messages, forward.coverage, fetch_attachment_bytes)?;
    let description = match forward.coverage {
        Some(interval) => format!(
            "discord: observed {} payloads in channel {channel_id}, covered ({}, {}]{}",
            messages.len(),
            interval.after_exclusive,
            interval.through_inclusive,
            if interval.baseline {
                " from bounded baseline"
            } else {
                ""
            },
        ),
        None => format!(
            "discord: reconciled {} recent payloads in channel {channel_id}",
            messages.len()
        ),
    };
    session.commit(fragment, description)?;
    match forward.coverage {
        Some(interval) => println!(
            "  {channel_id}: {} observations; covered ({}, {}]{}",
            messages.len(),
            interval.after_exclusive,
            interval.through_inclusive,
            if interval.baseline {
                " (bounded baseline)"
            } else {
                ""
            },
        ),
        None => println!("  {channel_id}: {} reconciled observations", messages.len()),
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PageRequest {
    after: Option<u64>,
    before: Option<u64>,
    limit: u32,
}

#[derive(Debug)]
struct ForwardBatch {
    payloads: Vec<JsonValue>,
    coverage: Option<discord_model::CoverageInterval>,
}

fn fetch_message_page(
    token: &str,
    channel_id: &str,
    request: PageRequest,
) -> Result<Vec<JsonValue>> {
    let mut url = format!(
        "{DISCORD_API_BASE}/channels/{channel_id}/messages?limit={}",
        request.limit.clamp(1, 100)
    );
    if let Some(after) = request.after {
        url.push_str("&after=");
        url.push_str(&after.to_string());
    }
    if let Some(before) = request.before {
        url.push_str("&before=");
        url.push_str(&before.to_string());
    }
    let response = build_client()?
        .get(&url)
        .header("Authorization", format!("Bot {token}"))
        .send()
        .with_context(|| format!("GET {url}"))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        bail!("discord read failed ({status}): {body}");
    }
    response.json().context("parse Discord message page")
}

/// Discord returns message pages newest first. When a forward page is full we
/// must walk backwards from its smallest id until crossing the prior frontier;
/// otherwise a burst larger than `limit` would publish a cursor past messages
/// it never ingested.
fn fetch_complete_forward<F>(
    prior_frontier: Option<u64>,
    limit: u32,
    mut fetch: F,
) -> Result<ForwardBatch>
where
    F: FnMut(PageRequest) -> Result<Vec<JsonValue>>,
{
    let limit = limit.clamp(1, 100);
    let first_request = PageRequest {
        after: prior_frontier,
        before: None,
        limit,
    };
    let mut payloads = fetch(first_request)?;
    let mut ids = checked_page_ids(&payloads, limit)?;
    if ids.is_empty() {
        return Ok(ForwardBatch {
            payloads,
            coverage: None,
        });
    }

    if let Some(frontier) = prior_frontier {
        if ids.iter().any(|id| *id <= frontier) {
            bail!("Discord after={frontier} page returned a non-forward message");
        }
    }
    let through = *ids.iter().max().expect("non-empty id page");

    if let Some(frontier) = prior_frontier {
        let mut before = *ids.iter().min().expect("non-empty id page");
        while ids.len() == limit as usize {
            let page = fetch(PageRequest {
                after: None,
                before: Some(before),
                limit,
            })?;
            let page_ids = checked_page_ids(&page, limit)?;
            if page_ids.is_empty() {
                break;
            }
            if page_ids.iter().any(|id| *id >= before) {
                bail!("Discord before={before} page did not move backwards");
            }
            let reached_frontier = page_ids.iter().any(|id| *id <= frontier);
            let short_page = page_ids.len() < limit as usize;
            payloads.extend(
                page.into_iter()
                    .zip(page_ids.iter().copied())
                    .filter_map(|(payload, id)| {
                        (id > frontier && id <= through).then_some(payload)
                    }),
            );
            before = *page_ids.iter().min().expect("non-empty id page");
            if reached_frontier || short_page {
                break;
            }
            ids = page_ids;
        }
        Ok(ForwardBatch {
            payloads,
            coverage: Some(discord_model::CoverageInterval::new(
                frontier, through, false,
            )?),
        })
    } else {
        let minimum = *ids.iter().min().expect("non-empty baseline page");
        Ok(ForwardBatch {
            payloads,
            coverage: Some(discord_model::CoverageInterval::new(
                minimum.saturating_sub(1),
                through,
                true,
            )?),
        })
    }
}

fn checked_page_ids(payloads: &[JsonValue], limit: u32) -> Result<Vec<u64>> {
    if payloads.len() > limit as usize {
        bail!(
            "Discord returned {} messages for a page limited to {limit}",
            payloads.len()
        );
    }
    let ids = payload_ids(payloads)?;
    if ids.iter().copied().collect::<BTreeSet<_>>().len() != ids.len() {
        bail!("Discord returned duplicate message ids within one page");
    }
    Ok(ids)
}

fn payload_ids(payloads: &[JsonValue]) -> Result<Vec<u64>> {
    payloads
        .iter()
        .map(|payload| {
            let raw = payload
                .get("id")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| anyhow!("Discord message payload missing id"))?;
            discord_model::validate_snowflake(raw)
                .with_context(|| format!("invalid Discord message id '{raw}'"))
        })
        .collect()
}

#[derive(Debug, Clone)]
struct IncomingMessage {
    external_id: String,
    channel_external_id: String,
    author_external_id: String,
    author_display_name: Option<String>,
    content: String,
    created_at: Inline<NsTAIInterval>,
    edited_at: Option<Inline<NsTAIInterval>>,
    reply_to_external_id: Option<String>,
    attachments: Vec<AttachmentSource>,
}

#[derive(Debug, Clone)]
struct AttachmentSource {
    source_id: String,
    /// Ephemeral transport locator. Discord signs and refreshes this value; it
    /// must never participate in semantic identity or equality.
    url: String,
    filename: String,
    content_type: Option<String>,
}

fn parse_messages(
    payloads: Vec<JsonValue>,
    expected_channel_id: &str,
) -> Result<Vec<IncomingMessage>> {
    discord_model::validate_snowflake(expected_channel_id)
        .context("invalid expected channel id")?;
    let mut messages = Vec::with_capacity(payloads.len());
    for payload in payloads {
        let external_id = required_snowflake(&payload, "id", "message")?;
        if let Some(actual_channel) = payload.get("channel_id").and_then(JsonValue::as_str) {
            discord_model::validate_snowflake(actual_channel)
                .context("invalid message channel_id")?;
            if actual_channel != expected_channel_id {
                bail!(
                    "Discord returned message {external_id} for channel {actual_channel}, expected {expected_channel_id}"
                );
            }
        }
        let content = payload
            .get("content")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_owned();
        let author = payload
            .get("author")
            .ok_or_else(|| anyhow!("message {external_id} missing author"))?;
        let author_external_id = required_snowflake(author, "id", "message author")?;
        let author_display_name = author
            .get("global_name")
            .and_then(JsonValue::as_str)
            .or_else(|| author.get("username").and_then(JsonValue::as_str))
            .filter(|name| !name.is_empty())
            .map(str::to_owned);
        let timestamp = payload
            .get("timestamp")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| anyhow!("message {external_id} missing timestamp"))?;
        let created_at =
            parse_iso8601(timestamp).with_context(|| format!("parse timestamp '{timestamp}'"))?;
        let edited_at = payload
            .get("edited_timestamp")
            .and_then(JsonValue::as_str)
            .map(parse_iso8601)
            .transpose()
            .with_context(|| format!("parse edited timestamp for message {external_id}"))?;
        let reply_to_external_id = payload
            .get("referenced_message")
            .and_then(|value| value.get("id"))
            .and_then(JsonValue::as_str)
            .map(|raw| {
                discord_model::validate_snowflake(raw)
                    .with_context(|| format!("invalid reply target id '{raw}'"))
                    .map(|_| raw.to_owned())
            })
            .transpose()?;

        let attachments = match payload.get("attachments") {
            None | Some(JsonValue::Null) => Vec::new(),
            Some(JsonValue::Array(values)) => values
                .iter()
                .map(|attachment| {
                    let source_id = required_snowflake(attachment, "id", "attachment")?;
                    let url = attachment
                        .get("url")
                        .and_then(JsonValue::as_str)
                        .filter(|url| !url.is_empty())
                        .ok_or_else(|| anyhow!("attachment {source_id} missing URL"))?
                        .to_owned();
                    let filename = attachment
                        .get("filename")
                        .and_then(JsonValue::as_str)
                        .filter(|name| !name.is_empty())
                        .ok_or_else(|| anyhow!("attachment {source_id} missing filename"))?
                        .to_owned();
                    let content_type = attachment
                        .get("content_type")
                        .and_then(JsonValue::as_str)
                        .map(str::to_owned);
                    Ok(AttachmentSource {
                        source_id,
                        url,
                        filename,
                        content_type,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            Some(_) => bail!("message {external_id} attachments field is not an array"),
        };

        messages.push(IncomingMessage {
            external_id,
            channel_external_id: expected_channel_id.to_owned(),
            author_external_id,
            author_display_name,
            content,
            created_at,
            edited_at,
            reply_to_external_id,
            attachments,
        });
    }
    messages
        .sort_by_key(|message| discord_model::validate_snowflake(&message.external_id).unwrap());
    Ok(messages)
}

fn required_snowflake(value: &JsonValue, field: &str, subject: &str) -> Result<String> {
    let raw = value
        .get(field)
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("{subject} missing {field}"))?;
    discord_model::validate_snowflake(raw)
        .with_context(|| format!("invalid {subject} {field} '{raw}'"))?;
    Ok(raw.to_owned())
}

/// Construct one complete self-contained collection fragment.
///
/// The fetch callback makes the validation-before-publication boundary
/// directly testable. Any attachment error aborts construction; callers have
/// not opened a writer yet and therefore cannot publish a receipt.
fn build_ingest_fragment<F>(
    messages: &[IncomingMessage],
    coverage: Option<discord_model::CoverageInterval>,
    mut fetch: F,
) -> Result<Fragment>
where
    F: FnMut(&str) -> Result<Vec<u8>>,
{
    if messages.is_empty() {
        if coverage.is_some() {
            bail!("an ingestion receipt requires at least one observed message");
        }
        return Ok(Fragment::empty());
    }

    let expected_channel = messages[0].channel_external_id.as_str();
    for message in messages {
        if message.channel_external_id != expected_channel {
            bail!("one Discord ingestion COMMIT cannot span channels");
        }
    }
    if let Some(interval) = coverage {
        let covers_observation = messages.iter().any(|message| {
            let id = discord_model::validate_snowflake(&message.external_id)
                .expect("parsed messages have valid ids");
            id > interval.after_exclusive && id <= interval.through_inclusive
        });
        if !covers_observation {
            bail!("an ingestion interval must cover at least one staged message");
        }
    }

    let mut fragment = Fragment::empty();
    let channel = discord_model::channel_fragment(expected_channel)?;
    let channel_id = channel.root().expect("intrinsic channel has one root");
    fragment += channel;

    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    struct AttachmentKey {
        source_id: String,
        filename: String,
        content_type: Option<String>,
    }

    #[derive(Debug)]
    struct AttachmentTransport {
        urls: BTreeSet<String>,
    }

    // Aggregate by stable Discord attachment id. Signed CDN URLs are merely
    // retryable transports and are intentionally absent from equality and
    // intrinsic identity.
    let mut transports: BTreeMap<AttachmentKey, AttachmentTransport> = BTreeMap::new();
    for source in messages.iter().flat_map(|message| &message.attachments) {
        let key = AttachmentKey {
            source_id: source.source_id.clone(),
            filename: file_capability::leaf_name(&source.filename),
            content_type: source.content_type.clone(),
        };
        transports
            .entry(key)
            .or_insert_with(|| AttachmentTransport {
                urls: BTreeSet::new(),
            })
            .urls
            .insert(source.url.clone());
    }

    let mut prepared_attachments: BTreeMap<AttachmentKey, (Id, Fragment)> = BTreeMap::new();
    for (key, transport) in transports {
        let mut failures = Vec::new();
        let mut bytes = None;
        for url in &transport.urls {
            match fetch(url) {
                Ok(value) => {
                    bytes = Some(value);
                    break;
                }
                Err(error) => failures.push(format!("{url}: {error:#}")),
            }
        }
        let bytes = bytes.ok_or_else(|| {
            anyhow!(
                "fetch Discord attachment {} failed via every observed URL: {}",
                key.source_id,
                failures.join("; ")
            )
        })?;
        let media_type = key
            .content_type
            .as_deref()
            .unwrap_or_else(|| file_capability::infer_media_type(Path::new(&key.filename)));
        let file_fragment =
            file_capability::stage(bytes, &key.filename, media_type).with_context(|| {
                format!("construct canonical file for attachment {}", key.source_id)
            })?;
        let file_id = file_fragment
            .root()
            .expect("canonical file fragment has one root");
        let mut attachment = entity! { _ @
            metadata::tag: archive::kind_attachment,
            archive::attachment_source_id: key.source_id.clone(),
            archive::attachment_name: key.filename.clone(),
            archive::attachment_file: file_id,
        };
        let attachment_id = attachment
            .root()
            .expect("attachment occurrence has one exported root");
        attachment += file_fragment;
        prepared_attachments.insert(key, (attachment_id, attachment));
    }

    for message in messages {
        let message_anchor = discord_model::message_anchor_fragment(&message.external_id)?;
        let message_anchor_id = message_anchor
            .root()
            .expect("intrinsic message anchor has one root");
        fragment += message_anchor;

        let author = discord_model::user_fragment(&message.author_external_id)?;
        let author_id = author.root().expect("intrinsic user anchor has one root");
        fragment += author;
        if let Some(display_name) = &message.author_display_name {
            fragment += entity! { _ @
                metadata::tag: discord::kind_user_profile,
                discord::user: author_id,
                archive::author_name: display_name.clone(),
            };
        }

        let reply_to = match message.reply_to_external_id.as_deref() {
            Some(external) => {
                let anchor = discord_model::message_anchor_fragment(external)?;
                let id = anchor.root().expect("intrinsic reply anchor has one root");
                fragment += anchor;
                Some(id)
            }
            None => None,
        };

        let mut attachment_ids = Vec::with_capacity(message.attachments.len());
        for source in &message.attachments {
            let key = AttachmentKey {
                source_id: source.source_id.clone(),
                filename: file_capability::leaf_name(&source.filename),
                content_type: source.content_type.clone(),
            };
            let (id, attachment) = prepared_attachments
                .get(&key)
                .expect("every parsed attachment was prepared");
            attachment_ids.push(*id);
            fragment += attachment.clone();
        }

        fragment += entity! { _ @
            metadata::tag: archive::kind_message,
            discord::message: message_anchor_id,
            discord::channel: channel_id,
            archive::author: author_id,
            archive::content: message.content.clone(),
            metadata::created_at: message.created_at,
            archive::edited_at?: message.edited_at,
            archive::reply_to?: reply_to,
            archive::attachment*: attachment_ids,
        };
    }

    // Keep this last: no receipt fragment exists until every semantic payload
    // and attachment above has validated and staged successfully.
    if let Some(interval) = coverage {
        fragment += discord_model::coverage_fragment(channel_id, interval);
    }
    Ok(fragment)
}

fn print_history(view: &CollectionView, options: &ReadOptions) -> Result<()> {
    let since = options
        .since
        .as_deref()
        .map(|value| parse_iso8601(value.trim()))
        .transpose()?;
    let channel_filter = options
        .channel_id
        .as_deref()
        .map(discord_model::channel_fragment)
        .transpose()?
        .map(|fragment| fragment.root().expect("intrinsic channel has one root"));
    let mut messages = discord_model::select_messages(&view.facts, channel_filter, since)?;

    if options.limit > 0 && messages.len() > options.limit {
        messages = messages.split_off(messages.len() - options.limit);
    }
    if options.descending {
        messages.reverse();
    }
    if messages.is_empty() {
        match options.channel_id.as_deref() {
            Some(channel) => println!("(no messages in collection for channel {channel})"),
            None => println!("(no messages in collection)"),
        }
        return Ok(());
    }

    let channel_names = discord_model::channel_labels(&view.facts, &view.reader)?;
    let author_names = discord_model::user_labels(&view.facts, &view.reader)?;
    for message in messages {
        let content =
            discord_model::read_text(&view.reader, message.content, "Discord message content")?;
        let author = author_names
            .get(&message.author)
            .cloned()
            .unwrap_or_else(|| format!("{}", message.author));
        let edited = message
            .edited_at
            .map(|edited| format!(" (edited {})", format_interval(edited)))
            .unwrap_or_default();
        let channel = if options.channel_id.is_some() {
            String::new()
        } else {
            channel_names
                .get(&message.channel)
                .map(|external| format!(" #{external}"))
                .unwrap_or_default()
        };
        let conflict = if message.variant_count > 1 {
            format!(
                " [DIVERGENT {}/{}]",
                message.variant_index + 1,
                message.variant_count
            )
        } else {
            String::new()
        };
        println!(
            "[{}]{channel}{edited}{conflict} {author}: {content}",
            format_interval(message.created_at)
        );
    }
    Ok(())
}

struct VisibleChannel {
    id: String,
    name: String,
    guild_id: String,
}

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
        let guild_id = guild.get("id").and_then(JsonValue::as_str).unwrap_or("");
        if discord_model::validate_snowflake(guild_id).is_err() {
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
        for channel in channels {
            let kind = channel
                .get("type")
                .and_then(JsonValue::as_i64)
                .unwrap_or(-1);
            if !matches!(kind, 0 | 5 | 15) {
                continue;
            }
            let id = channel.get("id").and_then(JsonValue::as_str).unwrap_or("");
            if discord_model::validate_snowflake(id).is_err() {
                continue;
            }
            out.push(VisibleChannel {
                id: id.to_owned(),
                name: channel
                    .get("name")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("")
                    .to_owned(),
                guild_id: guild_id.to_owned(),
            });
        }
    }
    Ok(out)
}

fn list_channels(token: &str, guild_filter: Option<&str>) -> Result<()> {
    if let Some(filter) = guild_filter {
        discord_model::validate_snowflake(filter).context("invalid guild filter")?;
    }
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
    if guilds.is_empty() {
        println!("Bot is not a member of any guilds. Invite it to a server first.");
        return Ok(());
    }

    for guild in guilds {
        let guild_id = guild
            .get("id")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| anyhow!("Discord guild missing id"))?;
        discord_model::validate_snowflake(guild_id).context("invalid Discord guild id")?;
        if guild_filter.is_some_and(|filter| filter != guild_id) {
            continue;
        }
        let guild_name = guild
            .get("name")
            .and_then(JsonValue::as_str)
            .unwrap_or("<unnamed>");
        println!("{guild_name}  ({guild_id})");

        let channels: Vec<JsonValue> = client
            .get(format!("{DISCORD_API_BASE}/guilds/{guild_id}/channels"))
            .header("Authorization", format!("Bot {token}"))
            .send()
            .with_context(|| format!("GET /guilds/{guild_id}/channels"))?
            .error_for_status()
            .with_context(|| format!("channels request for guild {guild_id} failed"))?
            .json()
            .with_context(|| format!("parse channels for guild {guild_id}"))?;
        let mut rows = Vec::new();
        for channel in &channels {
            let id = channel
                .get("id")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| anyhow!("Discord channel missing id"))?;
            discord_model::validate_snowflake(id).context("invalid Discord channel id")?;
            let name = channel
                .get("name")
                .and_then(JsonValue::as_str)
                .unwrap_or("<unnamed>");
            let kind = channel
                .get("type")
                .and_then(JsonValue::as_i64)
                .unwrap_or(-1);
            rows.push((kind, id, name, channel_type_label(kind)));
        }
        rows.sort_by_key(|(kind, _, _, _)| match kind {
            4 => 0,
            0 | 5 => 1,
            15 => 2,
            _ => 3,
        });
        for (_, id, name, kind) in rows {
            println!("  {kind:<12} #{name:<30} {id}");
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

fn fetch_attachment_bytes(url: &str) -> Result<Vec<u8>> {
    let response = build_client()?
        .get(url)
        .send()
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        bail!("GET {url} failed: status={status} body={body}");
    }
    let bytes = response.bytes().context("read attachment body")?;
    Ok(bytes.to_vec())
}

fn build_client() -> Result<Client> {
    Client::builder()
        .user_agent("triblespace-discord/0.2")
        .timeout(Duration::from_secs(30))
        .build()
        .context("build reqwest client")
}

fn parse_iso8601(value: &str) -> Result<Inline<NsTAIInterval>> {
    let epoch = Epoch::from_gregorian_str(value)
        .map_err(|error| anyhow!("parse ISO8601 '{value}': {error}"))?;
    Ok(epoch_interval(epoch))
}

fn epoch_interval(epoch: Epoch) -> Inline<NsTAIInterval> {
    (epoch, epoch)
        .try_to_inline()
        .expect("point interval encodes")
}

fn format_interval(interval: Inline<NsTAIInterval>) -> String {
    let (lower, _): (Epoch, Epoch) = interval.try_from_inline().expect("valid TAI interval");
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
        return fs::read_to_string(path).with_context(|| format!("read {label} from {path}"));
    }
    Ok(raw.to_owned())
}

fn load_value_or_file_trimmed(raw: &str, label: &str) -> Result<String> {
    Ok(load_value_or_file(raw, label)?.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use faculties::schemas::files::KIND_FILE;
    use std::fs::File;
    fn message_json(
        id: &str,
        channel: &str,
        content: &str,
        edited: Option<&str>,
        attachments: JsonValue,
    ) -> JsonValue {
        json!({
            "id": id,
            "channel_id": channel,
            "content": content,
            "author": {
                "id": "100000000000000010",
                "username": "Ada",
                "global_name": "Ada Lovelace"
            },
            "timestamp": "2026-08-07T08:00:00Z",
            "edited_timestamp": edited,
            "attachments": attachments,
            "referenced_message": null
        })
    }

    fn fresh_storage(directory: &tempfile::TempDir) -> (PathBuf, PathBuf) {
        let pile = directory.path().join("discord.pile");
        let key = directory.path().join("discord.key");
        File::create(&pile).unwrap();
        faculties::storage::initialize_signer(&pile, Some(&key)).unwrap();
        (pile, key)
    }

    fn test_storage<'a>(pile: &'a Path, key: &'a Path) -> DiscordStorage<'a> {
        DiscordStorage {
            pile,
            key: Some(key),
            collection: None,
        }
    }

    #[test]
    fn unauthorized_collection_fails_before_remote_post() {
        let directory = tempfile::tempdir().unwrap();
        let (pile_path, key) = fresh_storage(&directory);
        let root = SigningKey::from_bytes(&[0x41; 32]);
        let mut pile = Pile::open(&pile_path).unwrap();
        let collection = pile
            .collection(
                "discord",
                faculties::collection_names::private_policy(root.verifying_key()),
            )
            .unwrap();
        pile.close().unwrap();

        let mut posts = 0;
        let result = send_with(
            DiscordStorage {
                pile: &pile_path,
                key: Some(&key),
                collection: Some(collection.handle()),
            },
            "unused-token",
            "100000000000000002",
            "must not leave this process",
            |_, _, _| {
                posts += 1;
                Ok(json!({}))
            },
        );
        let error = result.unwrap_err();
        assert!(error.to_string().contains("WRITE admission"), "{error:#}");
        assert_eq!(posts, 0, "authorization failure must precede HTTP POST");
    }

    #[test]
    fn replayed_payload_has_identical_intrinsic_observation() {
        let payload = message_json(
            "100000000000000001",
            "100000000000000002",
            "hello",
            None,
            json!([]),
        );
        let first = parse_messages(vec![payload.clone()], "100000000000000002").unwrap();
        let second = parse_messages(vec![payload], "100000000000000002").unwrap();
        let interval =
            discord_model::CoverageInterval::new(100000000000000000, 100000000000000001, true)
                .unwrap();
        let first =
            build_ingest_fragment(&first, Some(interval), |_| unreachable!("no attachments"))
                .unwrap();
        let second =
            build_ingest_fragment(&second, Some(interval), |_| unreachable!("no attachments"))
                .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn volatile_payload_and_profile_changes_do_not_fork_message_semantics() {
        let directory = tempfile::tempdir().unwrap();
        let (pile, key) = fresh_storage(&directory);
        let storage = test_storage(&pile, &key);
        let channel = "100000000000000004";
        let first = message_json(
            "100000000000000003",
            channel,
            "stable meaning",
            None,
            json!([]),
        );
        let mut second = first.clone();
        second["pinned"] = json!(true);
        second["reactions"] = json!([{"count": 42, "emoji": {"name": "✨"}}]);
        second["author"]["global_name"] = json!("Countess Lovelace");
        let messages = parse_messages(vec![first, second], channel).unwrap();
        storage
            .publish(
                build_ingest_fragment(&messages, None, |_| unreachable!("no attachments")).unwrap(),
                "volatile replay".to_owned(),
            )
            .unwrap();
        let view = storage.view().unwrap();
        let selected = discord_model::select_messages(
            &view.facts,
            Some(
                discord_model::channel_fragment(channel)
                    .unwrap()
                    .root()
                    .unwrap(),
            ),
            None,
        )
        .unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].variant_count, 1);
        let observations = find!(
            observation: Id,
            pattern!(&view.facts, [{
                ?observation @
                metadata::tag: archive::kind_message,
                discord::message: _?anchor,
            }])
        )
        .collect::<BTreeSet<_>>();
        assert_eq!(observations.len(), 1);

        let users = find!(
            user: Id,
            pattern!(&view.facts, [{
                ?user @ metadata::tag: discord::kind_user
            }])
        )
        .collect::<BTreeSet<_>>();
        let profiles = find!(
            profile: Id,
            pattern!(&view.facts, [{
                ?profile @ metadata::tag: discord::kind_user_profile
            }])
        )
        .collect::<BTreeSet<_>>();
        assert_eq!(users.len(), 1);
        assert_eq!(profiles.len(), 2);
        let label = discord_model::user_labels(&view.facts, &view.reader)
            .unwrap()
            .remove(users.first().unwrap())
            .unwrap();
        assert!(label.contains("Ada Lovelace"));
        assert!(label.contains("Countess Lovelace"));
    }

    #[test]
    fn refreshed_signed_attachment_urls_are_retryable_transport_only() {
        let directory = tempfile::tempdir().unwrap();
        let (pile, key) = fresh_storage(&directory);
        let storage = test_storage(&pile, &key);
        let channel = "100000000000000006";
        let mut old = message_json(
            "100000000000000005",
            channel,
            "with file",
            None,
            json!([{
                "id": "100000000000000007",
                "url": "https://cdn.example/a-expired.bin?ex=old&hm=old",
                "filename": "folder/file.bin",
                "content_type": "application/octet-stream"
            }]),
        );
        let mut refreshed = old.clone();
        refreshed["attachments"][0]["url"] = json!("https://cdn.example/b-fresh.bin?ex=new&hm=new");
        // A volatile field changes too; neither change belongs to message
        // semantics.
        old["pinned"] = json!(false);
        refreshed["pinned"] = json!(true);

        let old_fragment = build_ingest_fragment(
            &parse_messages(vec![old.clone()], channel).unwrap(),
            None,
            |_| Ok(b"bytes".to_vec()),
        )
        .unwrap();
        let refreshed_fragment = build_ingest_fragment(
            &parse_messages(vec![refreshed.clone()], channel).unwrap(),
            None,
            |_| Ok(b"bytes".to_vec()),
        )
        .unwrap();
        assert_eq!(old_fragment, refreshed_fragment);

        let messages = parse_messages(vec![old, refreshed], channel).unwrap();
        let mut attempts = Vec::new();
        let fragment = build_ingest_fragment(&messages, None, |url| {
            attempts.push(url.to_owned());
            if url.contains("expired") {
                bail!("expired signature");
            }
            Ok(b"bytes".to_vec())
        })
        .unwrap();
        assert_eq!(attempts.len(), 2);
        storage
            .publish(fragment, "refreshed attachment URL".to_owned())
            .unwrap();
        let view = storage.view().unwrap();
        assert_eq!(
            discord_model::select_messages(&view.facts, None, None)
                .unwrap()
                .len(),
            1
        );
        let attachments = find!(
            attachment: Id,
            pattern!(&view.facts, [{
                ?attachment @ metadata::tag: archive::kind_attachment
            }])
        )
        .collect::<BTreeSet<_>>();
        assert_eq!(attachments.len(), 1);
        assert!(exists!(pattern!(&view.facts, [{
            _?file @ metadata::tag: &KIND_FILE
        }])));
    }

    #[test]
    fn attachment_failure_cannot_publish_coverage() {
        let directory = tempfile::tempdir().unwrap();
        let (pile, key) = fresh_storage(&directory);
        let storage = test_storage(&pile, &key);
        let channel = "100000000000000009";
        let payload = message_json(
            "100000000000000008",
            channel,
            "with file",
            None,
            json!([{
                "id": "100000000000000010",
                "url": "https://cdn.example/file.bin",
                "filename": "file.bin",
                "content_type": "application/octet-stream"
            }]),
        );
        let messages = parse_messages(vec![payload], channel).unwrap();
        let interval =
            discord_model::CoverageInterval::new(100000000000000007, 100000000000000008, true)
                .unwrap();
        assert!(build_ingest_fragment(&messages, Some(interval), |_| bail!("offline")).is_err());
        assert!(storage.view().unwrap().facts.iter().next().is_none());

        let fragment =
            build_ingest_fragment(&messages, Some(interval), |_| Ok(b"bytes".to_vec())).unwrap();
        storage
            .publish(fragment, "complete test page".to_owned())
            .unwrap();
        let view = storage.view().unwrap();
        let channel_id = discord_model::channel_fragment(channel)
            .unwrap()
            .root()
            .unwrap();
        assert_eq!(
            discord_model::channel_coverage(&view.facts, channel_id)
                .unwrap()
                .unwrap()
                .through_inclusive,
            100000000000000008
        );
    }

    #[test]
    fn newest_first_pagination_closes_a_150_message_gap_before_advancing() {
        let frontier = 100_000_u64;
        let available = ((frontier - 100)..=(frontier + 150)).collect::<Vec<_>>();
        let mut requests = Vec::new();
        let batch = fetch_complete_forward(Some(frontier), 100, |request| {
            requests.push(request);
            let mut ids = available
                .iter()
                .copied()
                .filter(|id| request.after.is_none_or(|after| *id > after))
                .filter(|id| request.before.is_none_or(|before| *id < before))
                .collect::<Vec<_>>();
            ids.sort_unstable_by(|left, right| right.cmp(left));
            ids.truncate(request.limit as usize);
            Ok(ids
                .into_iter()
                .map(|id| json!({"id": id.to_string()}))
                .collect())
        })
        .unwrap();
        let ingested = payload_ids(&batch.payloads)
            .unwrap()
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert_eq!(ingested, ((frontier + 1)..=(frontier + 150)).collect());
        assert_eq!(
            batch.coverage,
            Some(discord_model::CoverageInterval::new(frontier, frontier + 150, false).unwrap())
        );
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].after, Some(frontier));
        assert_eq!(requests[1].before, Some(frontier + 51));
    }

    #[test]
    fn first_page_is_an_explicit_bounded_baseline() {
        let available = (1_u64..=150).collect::<Vec<_>>();
        let batch = fetch_complete_forward(None, 100, |request| {
            let mut ids = available.clone();
            ids.sort_unstable_by(|left, right| right.cmp(left));
            ids.truncate(request.limit as usize);
            Ok(ids
                .into_iter()
                .map(|id| json!({"id": id.to_string()}))
                .collect())
        })
        .unwrap();
        assert_eq!(batch.payloads.len(), 100);
        assert_eq!(
            batch.coverage,
            Some(discord_model::CoverageInterval::new(50, 150, true).unwrap())
        );
    }

    #[test]
    fn latest_official_edit_wins_and_divergent_maxima_are_exposed() {
        let directory = tempfile::tempdir().unwrap();
        let (pile, key) = fresh_storage(&directory);
        let storage = test_storage(&pile, &key);
        let channel = "100000000000000007";
        let original = message_json("100000000000000008", channel, "original", None, json!([]));
        let edited = message_json(
            "100000000000000008",
            channel,
            "edited",
            Some("2026-08-07T09:00:00Z"),
            json!([]),
        );
        let messages = parse_messages(vec![original, edited], channel).unwrap();
        storage
            .publish(
                build_ingest_fragment(&messages, None, |_| unreachable!("no attachments")).unwrap(),
                "original and edit".to_owned(),
            )
            .unwrap();
        let view = storage.view().unwrap();
        let channel_id = discord_model::channel_fragment(channel)
            .unwrap()
            .root()
            .unwrap();
        let rows = discord_model::select_messages(&view.facts, Some(channel_id), None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            discord_model::read_text(&view.reader, rows[0].content, "content").unwrap(),
            "edited"
        );

        let divergent = message_json(
            "100000000000000008",
            channel,
            "different at same edit time",
            Some("2026-08-07T09:00:00Z"),
            json!([]),
        );
        let messages = parse_messages(vec![divergent], channel).unwrap();
        storage
            .publish(
                build_ingest_fragment(&messages, None, |_| unreachable!("no attachments")).unwrap(),
                "divergent edit".to_owned(),
            )
            .unwrap();
        let view = storage.view().unwrap();
        let rows = discord_model::select_messages(&view.facts, Some(channel_id), None).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.variant_count == 2));
        let contents = rows
            .iter()
            .map(|row| discord_model::read_text(&view.reader, row.content, "content").unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            contents,
            BTreeSet::from([
                "different at same edit time".to_owned(),
                "edited".to_owned(),
            ])
        );
    }

    #[test]
    fn malformed_locally_supplied_ids_are_rejected() {
        assert!(discord_model::validate_snowflake("01").is_err());
        assert!(discord_model::validate_snowflake("not-an-id").is_err());
        assert!(discord_model::validate_snowflake("18446744073709551616").is_err());
    }

    #[test]
    fn permanent_cli_has_one_fixed_collection_identity() {
        let command = Cli::command();
        for forbidden in ["scope", "branch", "branch_id", "head", "repair"] {
            assert!(!command
                .get_arguments()
                .any(|argument| argument.get_id() == forbidden));
        }
    }
}
