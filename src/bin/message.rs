//! Collection-native local messaging CLI.
//!
//! The reusable Message ontology, validation, recipient resolution, and
//! frozen-snapshot delivery semantics live in [`faculties::message`]. This
//! binary only orchestrates collection access and presents commands.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use faculties::clock;
use faculties::collection_names::open_configured;
use faculties::message::{self, IntervalValue, MessageRow};
use faculties::relations::{self, IdentityComponents};
use faculties::schemas::message::DEFAULT_SCOPE_ID;
use faculties::schemas::relations::DEFAULT_SCOPE_ID as DEFAULT_RELATIONS_SCOPE_ID;
use faculties::storage::{load_signer, open_pile_strict, FactArchive, FactCollection};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::collection::{Collection, CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::prelude::*;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "message",
    about = "Local messaging faculty for the agent"
)]
struct Cli {
    /// Path to the pile file.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Send a message as $PERSONA (override the sender with --from).
    Send {
        /// Recipient label, id, or id prefix (person or group).
        to: String,
        /// Message text. Use @path for file input or @- for stdin.
        text: String,
        /// Sender label, id, or id prefix. Defaults to $PERSONA.
        #[arg(long, env = "PERSONA", value_name = "PERSON")]
        from: Option<String>,
    },
    /// List recent inbox and outbox messages (latest first).
    List {
        /// Reader label, id, or id prefix.
        reader: String,
        /// Only show unread inbox messages.
        #[arg(long)]
        unread: bool,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Mark one inbox message as read.
    Ack {
        /// Message id or unambiguous id prefix.
        id: String,
        /// Reader label, id, or id prefix.
        by: String,
    },
    /// Mark every currently unread inbox message as read in one commit.
    AckAll {
        /// Reader label, id, or id prefix.
        by: String,
        /// Restrict to one sender label, id, or id prefix.
        #[arg(long)]
        from: Option<String>,
    },
}

struct MessageStorage<'a> {
    pile: &'a mut Pile,
    signer: &'a SigningKey,
    collection: Collection<SimpleArchive>,
    messages: &'a FactArchive,
    relations: &'a FactArchive,
    reader: &'a PileSnapshot,
}

impl MessageStorage<'_> {
    fn with_views<T>(
        &self,
        operation: impl FnOnce(&FactArchive, &FactArchive, &PileSnapshot) -> Result<T>,
    ) -> Result<T> {
        operation(self.messages, self.relations, self.reader)
    }

    fn with_view<T>(
        &self,
        operation: impl FnOnce(&FactArchive, &FactArchive, &PileSnapshot) -> Result<T>,
    ) -> Result<T> {
        self.with_views(operation)
    }

    /// Publish at most one locally constructed typed fragment.
    fn update<T>(
        &mut self,
        description: &'static str,
        operation: impl FnOnce(
            &FactArchive,
            &FactArchive,
            &PileSnapshot,
        ) -> Result<(Option<Fragment>, T)>,
    ) -> Result<T> {
        let (fragment, value) = operation(self.messages, self.relations, self.reader)?;
        if let Some(mut fragment) = fragment {
            fragment.describe_with(entity! { metadata::description: description });
            self.pile
                .commit(self.collection, self.signer, fragment)
                .context("commit authored Message fragment")?;
        }
        Ok(value)
    }
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context("close Message pile")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing Message pile also failed: {close_error}")))
        }
    }
}

fn interval_key(interval: IntervalValue) -> i128 {
    let (lower, _): (i128, i128) = interval
        .try_from_inline()
        .expect("stored Message timestamp is a valid interval");
    lower
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn format_age(now_key: i128, past_key: i128) -> String {
    let seconds = (now_key.saturating_sub(past_key) / 1_000_000_000).max(0);
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3_600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h", seconds / 3_600)
    } else {
        format!("{}d", seconds / 86_400)
    }
}

fn truncate_single_line(text: &str, max: usize) -> String {
    let mut output = String::with_capacity(max);
    for character in text.chars() {
        if output.len() >= max {
            output.push_str("...");
            break;
        }
        if matches!(character, '\n' | '\r') {
            output.push(' ');
        } else {
            output.push(character);
        }
    }
    output
}

fn render_list_body(text: &str) -> String {
    text.replace('\r', "").replace('\n', "\\n")
}

fn person_label(reader: &PileSnapshot, facts: &FactArchive, person: Id) -> Result<String> {
    let profile = relations::current_profile(facts, person)?;
    Ok(relations::profile_input(reader, &profile)?.label)
}

fn recipient_label(reader: &PileSnapshot, facts: &FactArchive, row: &MessageRow) -> Result<String> {
    match row.group_snapshot {
        None => person_label(reader, facts, row.to),
        Some(snapshot) => {
            let snapshot = relations::group_snapshot(facts, snapshot)?;
            relations::read_text(reader, snapshot.name)
        }
    }
}

fn cmd_send(
    storage: &mut MessageStorage<'_>,
    text: String,
    from: String,
    to: String,
) -> Result<()> {
    if text.trim().is_empty() {
        bail!("message text is empty");
    }
    let (message_id, from_id, to_id) =
        storage.update("local message", |_, relation_facts, reader| {
            let from_id = message::resolve_person(reader, relation_facts, &from)?
                .require_unique("active person", &from)?;
            let recipient =
                message::resolve_recipient(reader, relation_facts, &to)?.require_unique(&to)?;
            let (fragment, message_id) =
                message::message_fragment(from_id, &recipient, &text, clock::point_now()?);
            Ok((Some(fragment), (message_id, from_id, recipient.anchor())))
        })?;
    println!(
        "[{}] {} -> {}: {}",
        fmt_id(message_id),
        fmt_id(from_id),
        fmt_id(to_id),
        truncate_single_line(&text, 120)
    );
    Ok(())
}

fn cmd_ack(storage: &mut MessageStorage<'_>, id: String, by: String) -> Result<()> {
    let (message_id, reader_id, already_read) = storage.update(
        "local message read",
        |message_facts, relation_facts, reader| {
            let reader_id = message::resolve_person(reader, relation_facts, &by)?
                .require_unique("active person", &by)?;
            let message_id = message::resolve_message_id(message_facts, &id)?;
            let row = message::row_by_id(message_facts, message_id)?;
            let identities = IdentityComponents::from_facts(relation_facts)?;
            if !message::is_inbox_message(&row, reader_id, relation_facts, &identities)? {
                bail!(
                    "message {} is not in {}'s inbox",
                    fmt_id(message_id),
                    fmt_id(reader_id)
                );
            }
            let reads = message::load_read_rows(message_facts)?;
            if message::is_read_by(&reads, message_id, reader_id, &identities)? {
                return Ok((None, (message_id, reader_id, true)));
            }
            let (fragment, _) =
                message::read_fragment(message_id, reader_id, Some(clock::point_now()?));
            Ok((Some(fragment), (message_id, reader_id, false)))
        },
    )?;
    if already_read {
        println!(
            "Message {} was already read by {}.",
            fmt_id(message_id),
            fmt_id(reader_id)
        );
        return Ok(());
    }
    println!(
        "Marked {} as read by {}.",
        fmt_id(message_id),
        fmt_id(reader_id)
    );
    Ok(())
}

fn cmd_ack_all(storage: &mut MessageStorage<'_>, by: String, from: Option<String>) -> Result<()> {
    let (reader_id, count) = storage.update(
        "local messages bulk read",
        |message_facts, relation_facts, reader| {
            let reader_id = message::resolve_person(reader, relation_facts, &by)?
                .require_unique("active person", &by)?;
            let from = from
                .as_deref()
                .map(|selector| {
                    message::resolve_person(reader, relation_facts, selector)?
                        .require_unique("active person", selector)
                })
                .transpose()?;
            let identities = IdentityComponents::from_facts(relation_facts)?;
            let reads = message::load_read_rows(message_facts)?;
            let observed_at = clock::point_now()?;
            let mut fragment = Fragment::empty();
            let mut count = 0usize;
            for row in message::load_message_rows(message_facts)? {
                if !message::is_inbox_message(&row, reader_id, relation_facts, &identities)?
                    || message::is_read_by(&reads, row.id, reader_id, &identities)?
                {
                    continue;
                }
                if let Some(from) = from {
                    if !identities.equivalent(row.from, from)? {
                        continue;
                    }
                }
                fragment += message::read_fragment(row.id, reader_id, Some(observed_at)).0;
                count += 1;
            }
            Ok(((count > 0).then_some(fragment), (reader_id, count)))
        },
    )?;
    if count == 0 {
        println!("No unread messages for {}.", fmt_id(reader_id));
        return Ok(());
    }
    println!(
        "Marked {count} message(s) as read by {}.",
        fmt_id(reader_id)
    );
    Ok(())
}

fn cmd_list(
    storage: &mut MessageStorage<'_>,
    reader: String,
    unread: bool,
    limit: usize,
) -> Result<()> {
    storage.with_view(|message_facts, relation_facts, blob_reader| {
        let reader_id = message::resolve_person(blob_reader, relation_facts, &reader)?
            .require_unique("active person", &reader)?;
        let identities = IdentityComponents::from_facts(relation_facts)?;
        let reads = message::load_read_rows(message_facts)?;
        let mut messages = message::load_message_rows(message_facts)?;
        messages.sort_by(|left, right| {
            interval_key(right.created_at)
                .cmp(&interval_key(left.created_at))
                .then_with(|| left.id.cmp(&right.id))
        });

        let now = interval_key(clock::point_now()?);
        let mut shown = 0usize;
        for row in messages {
            let incoming = message::is_inbox_message(&row, reader_id, relation_facts, &identities)?;
            let outgoing = message::is_outgoing_message(&row, reader_id, &identities)?;
            if !incoming && !outgoing {
                continue;
            }
            let read = message::is_read_by(&reads, row.id, reader_id, &identities)?;
            if unread && !(incoming && !read) {
                continue;
            }

            let from_label = person_label(blob_reader, relation_facts, row.from)?;
            let to_label = recipient_label(blob_reader, relation_facts, &row)?;
            let status = if incoming {
                if read { "read" } else { "unread" }.to_owned()
            } else if row.group_snapshot.is_none()
                && message::is_read_by(&reads, row.id, row.to, &identities)?
            {
                format!("read-by:{to_label}")
            } else {
                "sent".to_owned()
            };
            let body = message::read_body(blob_reader, row.body)?;
            println!(
                "[{}] {} {} -> {} ({}) {}",
                fmt_id(row.id),
                format_age(now, interval_key(row.created_at)),
                from_label,
                to_label,
                status,
                render_list_body(&body)
            );
            shown += 1;
            if shown >= limit {
                break;
            }
        }
        if shown == 0 {
            println!("No messages.");
        }
        Ok(())
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };
    let signer = load_signer(&cli.pile, cli.key.as_deref())?;
    let mut pile = open_pile_strict(&cli.pile)?;
    let result = pollster::block_on(async {
        // Register every descriptor before freezing the one shared source
        // boundary used by both maintenance operations.
        let relations_source = open_configured(
            &mut pile,
            DEFAULT_RELATIONS_SCOPE_ID,
            signer.verifying_key(),
        )?;
        let message_source = open_configured(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
        let relations = FactCollection::new(&mut pile, relations_source)
            .context("register maintained Relations fact collection")?;
        let messages = FactCollection::new(&mut pile, message_source)
            .context("register maintained Message fact collection")?;
        let before = pile
            .snapshot()
            .context("freeze shared Message pre-maintenance snapshot")?;
        let instant = clock::now()?;
        drop(
            relations
                .maintain_at(&mut pile, &before, instant)
                .await
                .context("maintain Relations fact collection")?,
        );
        drop(
            messages
                .maintain_at(&mut pile, &before, instant)
                .await
                .context("maintain Message fact collection")?,
        );

        // Both query views and every attachment read share this one later
        // immutable boundary.
        let reader = pile
            .snapshot()
            .context("freeze maintained Message snapshot")?;
        let relation_collection = reader
            .collection_at(relations.rank9(), instant)
            .context("observe Relations Rank9 projection")?;
        let relation_facts = relation_collection
            .view::<FactArchive>()
            .context("read Relations Rank9 projection")?;
        let message_collection = reader
            .collection_at(messages.rank9(), instant)
            .context("observe Message Rank9 projection")?;
        let message_facts = message_collection
            .view::<FactArchive>()
            .context("read Message Rank9 projection")?;
        let mut storage = MessageStorage {
            pile: &mut pile,
            signer: &signer,
            collection: messages.source(),
            messages: &message_facts,
            relations: &relation_facts,
            reader: &reader,
        };

        match command {
            Command::Send { to, text, from } => {
                let Some(from) = from
                    .map(|value| value.trim().to_owned())
                    .filter(|value| !value.is_empty())
                else {
                    bail!(
                        "no sender: set $PERSONA or pass --from <person>\n\
                         usage: message send <TO> <TEXT> [--from <PERSON>]"
                    );
                };
                let text = faculties::text_arg(&text, "message text")?;
                cmd_send(&mut storage, text, from, to)
            }
            Command::List {
                reader,
                unread,
                limit,
            } => cmd_list(&mut storage, reader, unread, limit),
            Command::Ack { id, by } => cmd_ack(&mut storage, id, by),
            Command::AckAll { by, from } => cmd_ack_all(&mut storage, by, from),
        }
    });
    finish_pile(pile, result)
}
