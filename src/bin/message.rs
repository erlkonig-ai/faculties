//! Collection-native local messaging CLI.
//!
//! The reusable Message ontology, validation, recipient resolution, and
//! frozen-snapshot delivery semantics live in [`faculties::message`]. This
//! binary only orchestrates collection access and presents commands.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::collection_access::{self, CollectionSnapshot, CollectionView};
use faculties::message::{self, IntervalValue, MessageRow};
use faculties::relations::{self, IdentityComponents};
use faculties::schemas::message::DEFAULT_SCOPE_ID;
use faculties::schemas::relations::DEFAULT_SCOPE_ID as DEFAULT_RELATIONS_SCOPE_ID;
use hifitime::Epoch;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
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
    /// Extrinsic Message collection scope.
    #[arg(long, value_parser = parse_id_arg)]
    scope: Option<Id>,
    /// Extrinsic Relations collection scope used for names, identity, and
    /// frozen group snapshots.
    #[arg(long, value_parser = parse_id_arg)]
    relations_scope: Option<Id>,
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

#[derive(Clone, Copy)]
struct MessageStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
    scope: Id,
    relations_scope: Id,
}

struct MessageViews {
    messages: CollectionView,
    relations: CollectionView,
}

impl MessageStorage<'_> {
    fn views(&self) -> Result<MessageViews> {
        let signer = collection_access::load_signer(self.pile, self.key)?;
        let allowed = HashSet::from([signer.verifying_key()]);
        let snapshot = CollectionSnapshot::open(self.pile)?;
        let relations = snapshot
            .materialize_scope(self.relations_scope, &allowed)
            .context("materialize Relations collection")?;
        relations::validate_catalog(&relations.reader, &relations.facts)
            .context("validate Relations collection")?;
        let messages = snapshot
            .materialize_scope(self.scope, &allowed)
            .context("materialize Message collection")?;
        message::validate_catalog(&messages.reader, &messages.facts, &relations.facts)
            .context("validate Message collection")?;
        Ok(MessageViews {
            messages,
            relations,
        })
    }

    fn publish(
        &self,
        views: &MessageViews,
        fragment: Fragment,
        description: &str,
    ) -> Result<CollectionCommit> {
        message::validate_catalog_union(
            &views.messages.reader,
            &views.messages.facts,
            &fragment,
            &views.relations.facts,
        )?;
        let metadata = entity! { metadata::description: description.to_owned() };
        collection_access::publish_fragment(self.pile, self.key, self.scope, fragment, metadata)
    }
}

fn parse_id_arg(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim()).ok_or_else(|| format!("invalid id '{raw}'"))
}

fn now_epoch() -> Result<Epoch> {
    Epoch::now().map_err(|error| anyhow!("read current clock: {error:?}"))
}

fn epoch_interval(epoch: Epoch) -> IntervalValue {
    (epoch, epoch)
        .try_to_inline()
        .expect("a point in time is a valid interval")
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

fn person_label(view: &CollectionView, person: Id) -> Result<String> {
    let profile = relations::current_profile(&view.facts, person)?;
    Ok(relations::profile_input(&view.reader, &profile)?.label)
}

fn recipient_label(view: &CollectionView, row: &MessageRow) -> Result<String> {
    match row.group_snapshot {
        None => person_label(view, row.to),
        Some(snapshot) => {
            let snapshot = relations::group_snapshot(&view.facts, snapshot)?;
            relations::read_text(&view.reader, snapshot.name)
        }
    }
}

fn cmd_send(storage: MessageStorage<'_>, text: String, from: String, to: String) -> Result<()> {
    if text.trim().is_empty() {
        bail!("message text is empty");
    }
    let views = storage.views()?;
    let from_id = message::resolve_person(&views.relations.reader, &views.relations.facts, &from)?
        .require_unique("active person", &from)?;
    let recipient =
        message::resolve_recipient(&views.relations.reader, &views.relations.facts, &to)?
            .require_unique(&to)?;
    let message_id = genid().id;
    let fragment = message::message_fragment(
        message_id,
        from_id,
        &recipient,
        &text,
        epoch_interval(now_epoch()?),
    );
    storage.publish(&views, fragment, "local message")?;
    println!(
        "[{}] {} -> {}: {}",
        fmt_id(message_id),
        fmt_id(from_id),
        fmt_id(recipient.anchor()),
        truncate_single_line(&text, 120)
    );
    Ok(())
}

fn cmd_ack(storage: MessageStorage<'_>, id: String, by: String) -> Result<()> {
    let views = storage.views()?;
    let reader = message::resolve_person(&views.relations.reader, &views.relations.facts, &by)?
        .require_unique("active person", &by)?;
    let message_id = message::resolve_message_id(&views.messages.facts, &id)?;
    let row = message::row_by_id(&views.messages.facts, message_id)?;
    let identities = IdentityComponents::from_facts(&views.relations.facts)?;
    if !message::is_inbox_message(&row, reader, &views.relations.facts, &identities)? {
        bail!(
            "message {} is not in {}'s inbox",
            fmt_id(message_id),
            fmt_id(reader)
        );
    }
    let reads = message::load_read_rows(&views.messages.facts)?;
    if message::is_read_by(&reads, message_id, reader, &identities)? {
        println!(
            "Message {} was already read by {}.",
            fmt_id(message_id),
            fmt_id(reader)
        );
        return Ok(());
    }
    let (fragment, _) =
        message::read_fragment(message_id, reader, Some(epoch_interval(now_epoch()?)));
    storage.publish(&views, fragment, "local message read")?;
    println!(
        "Marked {} as read by {}.",
        fmt_id(message_id),
        fmt_id(reader)
    );
    Ok(())
}

fn cmd_ack_all(storage: MessageStorage<'_>, by: String, from: Option<String>) -> Result<()> {
    let views = storage.views()?;
    let reader = message::resolve_person(&views.relations.reader, &views.relations.facts, &by)?
        .require_unique("active person", &by)?;
    let from = from
        .as_deref()
        .map(|selector| {
            message::resolve_person(&views.relations.reader, &views.relations.facts, selector)?
                .require_unique("active person", selector)
        })
        .transpose()?;
    let identities = IdentityComponents::from_facts(&views.relations.facts)?;
    let reads = message::load_read_rows(&views.messages.facts)?;
    let observed_at = epoch_interval(now_epoch()?);
    let mut fragment = Fragment::empty();
    let mut count = 0usize;
    for row in message::load_message_rows(&views.messages.facts)? {
        if !message::is_inbox_message(&row, reader, &views.relations.facts, &identities)?
            || message::is_read_by(&reads, row.id, reader, &identities)?
        {
            continue;
        }
        if let Some(from) = from {
            if !identities.equivalent(row.from, from)? {
                continue;
            }
        }
        fragment += message::read_fragment(row.id, reader, Some(observed_at)).0;
        count += 1;
    }
    if count == 0 {
        println!("No unread messages for {}.", fmt_id(reader));
        return Ok(());
    }
    storage.publish(&views, fragment, "local messages bulk read")?;
    println!("Marked {count} message(s) as read by {}.", fmt_id(reader));
    Ok(())
}

fn cmd_list(storage: MessageStorage<'_>, reader: String, unread: bool, limit: usize) -> Result<()> {
    let views = storage.views()?;
    let reader_id =
        message::resolve_person(&views.relations.reader, &views.relations.facts, &reader)?
            .require_unique("active person", &reader)?;
    let identities = IdentityComponents::from_facts(&views.relations.facts)?;
    let reads = message::load_read_rows(&views.messages.facts)?;
    let mut messages = message::load_message_rows(&views.messages.facts)?;
    messages.sort_by(|left, right| {
        interval_key(right.created_at)
            .cmp(&interval_key(left.created_at))
            .then_with(|| left.id.cmp(&right.id))
    });

    let now = interval_key(epoch_interval(now_epoch()?));
    let mut shown = 0usize;
    for row in messages {
        let incoming =
            message::is_inbox_message(&row, reader_id, &views.relations.facts, &identities)?;
        let outgoing = message::is_outgoing_message(&row, reader_id, &identities)?;
        if !incoming && !outgoing {
            continue;
        }
        let read = message::is_read_by(&reads, row.id, reader_id, &identities)?;
        if unread && !(incoming && !read) {
            continue;
        }

        let from_label = person_label(&views.relations, row.from)?;
        let to_label = recipient_label(&views.relations, &row)?;
        let status = if incoming {
            if read { "read" } else { "unread" }.to_owned()
        } else if row.group_snapshot.is_none()
            && message::is_read_by(&reads, row.id, row.to, &identities)?
        {
            format!("read-by:{to_label}")
        } else {
            "sent".to_owned()
        };
        let body = message::read_body(&views.messages.reader, row.body)?;
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };
    let storage = MessageStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
        scope: cli.scope.unwrap_or(DEFAULT_SCOPE_ID),
        relations_scope: cli.relations_scope.unwrap_or(DEFAULT_RELATIONS_SCOPE_ID),
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
            cmd_send(storage, text, from, to)
        }
        Command::List {
            reader,
            unread,
            limit,
        } => cmd_list(storage, reader, unread, limit),
        Command::Ack { id, by } => cmd_ack(storage, id, by),
        Command::AckAll { by, from } => cmd_ack_all(storage, by, from),
    }
}
