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
use faculties::collection_names::{configured_handle, open_configured, open_exact_in};
use faculties::message::{self, IntervalValue, MessageRow};
use faculties::relations::{self, IdentityComponents, TextHandle};
use faculties::schemas::message::DEFAULT_SCOPE_ID;
use faculties::schemas::relations::DEFAULT_SCOPE_ID as DEFAULT_RELATIONS_SCOPE_ID;
use faculties::storage::{self, load_signer, open_store, runtime, FactArchive, FacultyStore};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::{Collection, CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::async_store::AsyncBlobStoreAcquire;
use triblespace::core::repo::StorageClose;
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
    pile: &'a mut FacultyStore,
    signer: &'a SigningKey,
    collection: Collection<SimpleArchive>,
    reader: &'a PileSnapshot,
    messages: &'a FactArchive,
    relations: &'a FactArchive,
}

impl MessageStorage<'_> {
    /// Publish at most one locally constructed typed fragment.
    fn update<T>(
        &mut self,
        description: &'static str,
        operation: impl FnOnce(&FactArchive, &FactArchive) -> Result<(Option<Fragment>, T)>,
    ) -> Result<T> {
        let (fragment, value) = operation(self.messages, self.relations)?;
        if let Some(mut fragment) = fragment {
            fragment.describe_with(entity! { metadata::description: description });
            self.pile
                .commit(self.collection, self.signer, fragment)
                .context("commit authored Message fragment")?;
        }
        Ok(value)
    }
}

fn finish_pile<T>(pile: FacultyStore, result: Result<T>) -> Result<T> {
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

async fn acquire_text<S>(store: &mut S, handle: TextHandle) -> Result<String>
where
    S: AsyncBlobStoreAcquire,
{
    let bytes = store
        .acquire(handle.transmute())
        .await
        .context("acquire Message text")?
        .context("Message text is unavailable")?;
    Ok(std::str::from_utf8(&bytes)
        .context("decode Message text")?
        .to_owned())
}

async fn person_label<S, P>(store: &mut S, facts: &P, person: Id) -> Result<String>
where
    S: AsyncBlobStoreAcquire,
    P: TriblePattern,
{
    let profile = relations::current_profile(facts, person)?;
    acquire_text(store, profile.label).await
}

async fn recipient_label<S, P>(store: &mut S, facts: &P, row: &MessageRow) -> Result<String>
where
    S: AsyncBlobStoreAcquire,
    P: TriblePattern,
{
    match row.group_snapshot {
        None => person_label(store, facts, row.to).await,
        Some(snapshot) => {
            let snapshot = relations::group_snapshot(facts, snapshot)?;
            acquire_text(store, snapshot.name).await
        }
    }
}

async fn cmd_send(
    storage: &mut MessageStorage<'_>,
    text: String,
    from: String,
    to: String,
) -> Result<()> {
    if text.trim().is_empty() {
        bail!("message text is empty");
    }
    let relation_facts = storage.relations;
    let (from_id, recipient) = storage::read(storage.pile, storage.reader, |reader| {
        let from_id = message::resolve_person(reader, relation_facts, &from)?
            .require_unique("active person", &from)?;
        let recipient =
            message::resolve_recipient(reader, relation_facts, &to)?.require_unique(&to)?;
        Ok((from_id, recipient))
    })
    .await?;
    let (message_id, from_id, to_id) = storage.update("local message", |_, _| {
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

async fn cmd_ack(storage: &mut MessageStorage<'_>, id: String, by: String) -> Result<()> {
    let relation_facts = storage.relations;
    let reader_id = storage::read(storage.pile, storage.reader, |reader| {
        message::resolve_person(reader, relation_facts, &by)?.require_unique("active person", &by)
    })
    .await?;
    let (message_id, reader_id, already_read) =
        storage.update("local message read", |message_facts, relation_facts| {
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
        })?;
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

async fn cmd_ack_all(
    storage: &mut MessageStorage<'_>,
    by: String,
    from: Option<String>,
) -> Result<()> {
    let relation_facts = storage.relations;
    let (reader_id, from) = storage::read(storage.pile, storage.reader, |reader| {
        let reader_id = message::resolve_person(reader, relation_facts, &by)?
            .require_unique("active person", &by)?;
        let from = from
            .as_deref()
            .map(|selector| {
                message::resolve_person(reader, relation_facts, selector)?
                    .require_unique("active person", selector)
            })
            .transpose()?;
        Ok((reader_id, from))
    })
    .await?;
    let (reader_id, count) = storage.update(
        "local messages bulk read",
        |message_facts, relation_facts| {
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

async fn cmd_list(
    storage: &mut MessageStorage<'_>,
    reader: String,
    unread: bool,
    limit: usize,
) -> Result<()> {
    let message_facts = storage.messages;
    let relation_facts = storage.relations;
    let reader_id = storage::read(storage.pile, storage.reader, |blob_reader| {
        message::resolve_person(blob_reader, relation_facts, &reader)?
            .require_unique("active person", &reader)
    })
    .await?;
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

        let from_label = person_label(storage.pile, relation_facts, row.from).await?;
        let to_label = recipient_label(storage.pile, relation_facts, &row).await?;
        let status = if incoming {
            if read { "read" } else { "unread" }.to_owned()
        } else if row.group_snapshot.is_none()
            && message::is_read_by(&reads, row.id, row.to, &identities)?
        {
            format!("read-by:{to_label}")
        } else {
            "sent".to_owned()
        };
        let body = acquire_text(storage.pile, row.body).await?;
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
    let signer = load_signer(&cli.pile, cli.key.as_deref())?;
    let runtime = runtime()?;
    let mut pile = open_store(&cli.pile)?;
    let result = runtime.block_on(async {
        // An explicit descriptor may itself have arrived as only an exact
        // handle. Acquire it and the name needed by open_configured, not its
        // arbitrary attachment closure.
        for scope in [DEFAULT_RELATIONS_SCOPE_ID, DEFAULT_SCOPE_ID] {
            if let Some(handle) = configured_handle(scope)? {
                let reader = pile
                    .snapshot()
                    .context("freeze configured Message collection descriptor")?;
                storage::read(&mut pile, &reader, |reader| {
                    open_exact_in(reader, scope, handle)
                })
                .await?;
            }
        }
        // Register the representations, then maintain each edge from its
        // realized immediate source. Both reads use one final snapshot.
        let relations_source = open_configured(
            &mut pile,
            DEFAULT_RELATIONS_SCOPE_ID,
            signer.verifying_key(),
        )?;
        let message_source = open_configured(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
        let descriptors = pile.snapshot().context("freeze Message source policies")?;
        let relations_policy = relations_source
            .policy(&descriptors)
            .context("read Relations source policy")?;
        let message_policy = message_source
            .policy(&descriptors)
            .context("read Message source policy")?;
        drop(descriptors);
        let relations_succinct = pile
            .derive::<SuccinctArchiveBlob>(relations_source, (), relations_policy.clone())
            .context("register Relations Succinct collection")?;
        let relations_rank9 = pile
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(relations_succinct, (), relations_policy)
            .context("register Relations Rank9 collection")?;
        let message_succinct = pile
            .derive::<SuccinctArchiveBlob>(message_source, (), message_policy.clone())
            .context("register Message Succinct collection")?;
        let message_rank9 = pile
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(message_succinct, (), message_policy)
            .context("register Message Rank9 collection")?;
        drop(
            pile.ensure(relations_source)
                .await
                .context("ensure Relations source collection")?,
        );
        drop(
            pile.ensure(message_source)
                .await
                .context("ensure Message source collection")?,
        );
        drop(
            pile.maintain(relations_succinct)
                .await
                .context("maintain Relations Succinct collection")?,
        );
        drop(
            pile.maintain(relations_rank9)
                .await
                .context("maintain Relations Rank9 collection")?,
        );
        drop(
            pile.maintain(message_succinct)
                .await
                .context("maintain Message Succinct collection")?,
        );
        drop(
            pile.maintain(message_rank9)
                .await
                .context("maintain Message Rank9 collection")?,
        );

        // Both query views retain their selected support. Later selected-text
        // acquisition may add bytes, but never replaces these frozen facts.
        let reader = pile
            .snapshot()
            .context("freeze maintained Message snapshot")?;
        let relation_collection = reader
            .collection(relations_rank9)
            .context("observe Relations Rank9 projection")?;
        let relation_facts = relation_collection
            .view::<FactArchive>()
            .context("read Relations Rank9 projection")?;
        let message_collection = reader
            .collection(message_rank9)
            .context("observe Message Rank9 projection")?;
        let message_facts = message_collection
            .view::<FactArchive>()
            .context("read Message Rank9 projection")?;
        let mut storage = MessageStorage {
            pile: &mut pile,
            signer: &signer,
            collection: message_source,
            reader: &reader,
            messages: &message_facts,
            relations: &relation_facts,
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
                cmd_send(&mut storage, text, from, to).await
            }
            Command::List {
                reader,
                unread,
                limit,
            } => cmd_list(&mut storage, reader, unread, limit).await,
            Command::Ack { id, by } => cmd_ack(&mut storage, id, by).await,
            Command::AckAll { by, from } => cmd_ack_all(&mut storage, by, from).await,
        }
    });
    finish_pile(pile, result)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::Infallible;
    use std::future::{ready, Future};

    use anybytes::Bytes;
    use hifitime::Epoch;
    use triblespace::core::blob::encodings::UnknownBlob;
    use triblespace::core::blob::MemoryBlobStoreSnapshot;
    use triblespace::core::repo::pile::ReadError;

    /// A real resident-only pile with a deterministic remote blob fixture.
    struct AcquiringPile {
        pile: Pile,
        remote: MemoryBlobStoreSnapshot,
        requested: Vec<Inline<inlineencodings::Handle<UnknownBlob>>>,
        arriving: Option<(Collection<SimpleArchive>, SigningKey, Fragment)>,
        _file: tempfile::NamedTempFile,
    }

    impl AcquiringPile {
        fn new(mut remote: MemoryBlobStore) -> Self {
            let file = tempfile::NamedTempFile::new().unwrap();
            Self {
                pile: Pile::open(file.path()).unwrap(),
                remote: remote.snapshot().unwrap(),
                requested: Vec::new(),
                arriving: None,
                _file: file,
            }
        }
    }

    impl SnapshotSource for AcquiringPile {
        type Snapshot = PileSnapshot;
        type SnapshotError = ReadError;

        fn snapshot_at(&mut self, instant: Epoch) -> Result<PileSnapshot, ReadError> {
            self.pile.snapshot_at(instant)
        }
    }

    impl AsyncBlobStoreAcquire for AcquiringPile {
        type AcquireError = Infallible;

        fn acquire(
            &mut self,
            handle: Inline<inlineencodings::Handle<UnknownBlob>>,
        ) -> impl Future<Output = Result<Option<Bytes>, Infallible>> + Send {
            let resident = self.pile.snapshot().unwrap();
            if resident.contains_blob(handle).unwrap() {
                return ready(Ok(Some(resident.get(handle).unwrap())));
            }
            self.requested.push(handle);
            if let Some((collection, signer, fragment)) = self.arriving.take() {
                self.pile.commit(collection, &signer, fragment).unwrap();
            }
            if !self.remote.contains_blob(handle).unwrap() {
                return ready(Ok(None));
            }
            let bytes: Bytes = self.remote.get(handle).unwrap();
            let cached: Inline<inlineencodings::Handle<UnknownBlob>> =
                self.pile.put(bytes.clone()).unwrap();
            assert_eq!(cached, handle);
            ready(Ok(Some(bytes)))
        }
    }

    fn test_id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    #[test]
    fn configured_descriptor_read_acquires_its_descriptor_and_name_only() {
        let mut remote = MemoryRepo::default();
        let signer = SigningKey::from_bytes(&[8; 32]);
        let source = faculties::collection_names::open(
            &mut remote,
            DEFAULT_SCOPE_ID,
            signer.verifying_key(),
        )
        .unwrap();
        let descriptor: TribleSet = remote.snapshot().unwrap().get(source.handle()).unwrap();
        let name = triblespace::core::collection::descriptor::name(&descriptor)
            .unwrap()
            .unwrap();
        let mut store = AcquiringPile::new(remote.blobs);
        let before = store.snapshot().unwrap();

        let opened = pollster::block_on(storage::read(&mut store, &before, |reader| {
            open_exact_in(reader, DEFAULT_SCOPE_ID, source.handle())
        }))
        .unwrap();

        assert_eq!(opened, source);
        assert_eq!(
            store.requested,
            vec![source.handle().transmute(), name.transmute()]
        );
        assert!(!before.contains_blob(source.handle()).unwrap());
    }

    #[test]
    fn exact_person_and_group_selectors_do_not_acquire_text() {
        let person = test_id(1);
        let group = test_id(2);
        let (mut fragment, _, _) = relations::person_fragment(
            person,
            relations::ProfileInput {
                label: "person".to_owned(),
                ..Default::default()
            },
        )
        .unwrap();
        fragment += relations::group_create_fragment(group, "group").unwrap().0;
        let mut store = AcquiringPile::new(MemoryBlobStore::new());
        let before = store.snapshot().unwrap();

        let (actual_person, actual_group) =
            pollster::block_on(storage::read(&mut store, &before, |reader| {
                Ok((
                    message::resolve_person(reader, fragment.facts(), &fmt_id(person))?,
                    message::resolve_recipient(reader, fragment.facts(), &fmt_id(group))?,
                ))
            }))
            .unwrap();

        assert_eq!(actual_person, relations::SelectorOutcome::Unique(person));
        assert_eq!(
            actual_group.require_unique("group").unwrap().anchor(),
            group
        );
        assert!(store.requested.is_empty());
    }

    #[test]
    fn label_and_alias_selection_acquire_only_current_selector_text() {
        let person = test_id(3);
        let (mut fragment, predecessor, _) = relations::person_fragment(
            person,
            relations::ProfileInput {
                label: "superseded label".to_owned(),
                aliases: vec!["superseded alias".to_owned()],
                ..Default::default()
            },
        )
        .unwrap();
        fragment += relations::profile_fragment(
            person,
            relations::ProfileInput {
                label: "current label".to_owned(),
                aliases: vec!["current alias".to_owned()],
                note: Some("not a selector input".to_owned()),
                emails: vec!["not-a-selector@example.test".to_owned()],
                ..Default::default()
            },
            &[predecessor],
        )
        .unwrap();
        let profile = relations::current_profile(fragment.facts(), person).unwrap();

        for (input, expected) in [
            ("current label", vec![profile.label.transmute()]),
            (
                "current alias",
                vec![profile.label.transmute(), profile.aliases[0].transmute()],
            ),
        ] {
            let mut store = AcquiringPile::new(fragment.blobs().clone());
            let before = store.snapshot().unwrap();
            let outcome = pollster::block_on(storage::read(&mut store, &before, |reader| {
                message::resolve_person(reader, fragment.facts(), input)
            }))
            .unwrap();

            assert_eq!(outcome, relations::SelectorOutcome::Unique(person));
            assert_eq!(store.requested, expected);
            assert!(!before.contains_blob(profile.label).unwrap());
            assert_eq!(store.snapshot().unwrap().wants().unwrap().count(), 0);
        }
    }

    #[test]
    fn person_display_acquires_only_the_selected_label() {
        let person = test_id(4);
        let (fragment, _, _) = relations::person_fragment(
            person,
            relations::ProfileInput {
                label: "display label".to_owned(),
                aliases: vec!["unneeded alias".to_owned()],
                note: Some("unneeded note".to_owned()),
                ..Default::default()
            },
        )
        .unwrap();
        let profile = relations::current_profile(fragment.facts(), person).unwrap();
        let mut store = AcquiringPile::new(fragment.blobs().clone());

        assert_eq!(
            pollster::block_on(person_label(&mut store, fragment.facts(), person)).unwrap(),
            "display label"
        );
        assert_eq!(store.requested, vec![profile.label.transmute()]);
    }

    #[test]
    fn recipient_display_uses_the_messages_frozen_group_snapshot() {
        let group = test_id(5);
        let (mut fragment, original) =
            relations::group_create_fragment(group, "original group").unwrap();
        let original_name = relations::group_snapshot(fragment.facts(), original)
            .unwrap()
            .name;
        let (message, id) = message::message_fragment(
            test_id(6),
            &message::Recipient::Group {
                anchor: group,
                snapshot: original,
                basis: faculties::schemas::message::GROUP_SNAPSHOT_BASIS_WITNESSED,
            },
            "unneeded message body",
            (Epoch::from_tai_seconds(0.0), Epoch::from_tai_seconds(0.0))
                .try_to_inline()
                .unwrap(),
        );
        let row = message::row_by_id(message.facts(), id).unwrap();
        fragment += message;
        fragment +=
            relations::group_snapshot_fragment(group, "renamed group", &[], &[original]).unwrap();
        let mut store = AcquiringPile::new(fragment.blobs().clone());

        assert_eq!(
            pollster::block_on(recipient_label(&mut store, fragment.facts(), &row)).unwrap(),
            "original group"
        );
        assert_eq!(store.requested, vec![original_name.transmute()]);
    }

    #[test]
    fn acquiring_a_selected_body_leaves_other_bodies_and_old_snapshot_untouched() {
        let mut remote = MemoryBlobStore::new();
        let selected: TextHandle = remote.put("selected body").unwrap();
        let unrelated: TextHandle = remote.put("unselected body").unwrap();
        let mut store = AcquiringPile::new(remote);
        let before = store.snapshot().unwrap();

        assert_eq!(
            pollster::block_on(acquire_text(&mut store, selected)).unwrap(),
            "selected body"
        );
        assert_eq!(store.requested, vec![selected.transmute()]);
        assert!(!before.contains_blob(selected).unwrap());
        let after = store.snapshot().unwrap();
        assert!(after.contains_blob(selected).unwrap());
        assert!(!after.contains_blob(unrelated).unwrap());
        assert_eq!(after.wants().unwrap().count(), 0);
    }

    #[test]
    fn acquisition_does_not_turn_missing_or_invalid_text_into_empty_text() {
        let mut remote = MemoryBlobStore::new();
        let invalid = remote.insert(Blob::<blobencodings::UTF8String>::new(Bytes::from_source(
            vec![0xff_u8],
        )));
        let absent: TextHandle = "absent".to_blob().get_handle();
        let mut store = AcquiringPile::new(remote);

        let missing = pollster::block_on(acquire_text(&mut store, absent)).unwrap_err();
        assert!(missing.to_string().contains("unavailable"));
        let malformed = pollster::block_on(acquire_text(&mut store, invalid)).unwrap_err();
        assert!(malformed.to_string().contains("decode Message text"));
    }

    #[test]
    fn selector_retry_keeps_frozen_support_when_a_commit_arrives_during_acquisition() {
        let person = test_id(7);
        let (mut fragment, predecessor, _) = relations::person_fragment(
            person,
            relations::ProfileInput {
                label: "original label".to_owned(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut store = AcquiringPile::new(fragment.blobs().clone());
        fragment.blobs_mut().keep([]);
        let signer = SigningKey::from_bytes(&[7; 32]);
        let source = faculties::collection_names::open(
            &mut store.pile,
            DEFAULT_RELATIONS_SCOPE_ID,
            signer.verifying_key(),
        )
        .unwrap();
        store.pile.commit(source, &signer, fragment).unwrap();
        let policy = source.policy(&store.pile.snapshot().unwrap()).unwrap();
        let succinct = store
            .pile
            .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
            .unwrap();
        let rank9 = store
            .pile
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
            .unwrap();
        let before = pollster::block_on(async {
            drop(store.pile.ensure(source).await.unwrap());
            drop(store.pile.maintain(succinct).await.unwrap());
            store.pile.maintain(rank9).await.unwrap()
        });
        let observed = before.collection(rank9).unwrap();
        let facts = observed.view::<FactArchive>().unwrap();
        let original_support = observed.support().clone();
        let successor = relations::profile_fragment(
            person,
            relations::ProfileInput {
                label: "later label".to_owned(),
                ..Default::default()
            },
            &[predecessor],
        )
        .unwrap();
        store.arriving = Some((source, signer, successor));

        let outcome = pollster::block_on(storage::read(&mut store, &before, |reader| {
            assert_eq!(reader.instant(), before.instant());
            message::resolve_person(reader, &facts, "original label")
        }))
        .unwrap();

        assert_eq!(outcome, relations::SelectorOutcome::Unique(person));
        assert_eq!(store.requested.len(), 1);
        assert_eq!(observed.support(), &original_support);
        assert_eq!(original_support.len(), 1);
        let after = store.snapshot().unwrap();
        assert_eq!(source.admitted(&after).unwrap().len(), 2);
        assert_eq!(after.wants().unwrap().count(), 0);
    }
}
