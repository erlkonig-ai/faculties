//! Typed finite Message operations over one frozen Message/Relations observation.
//! Text is literal; sender selection and output routing belong to the caller.

use std::path::PathBuf;

use crate::clock;
use crate::collection_names::{configured_handle, open_configured, open_exact_in};
use crate::message::{self, IntervalValue, MessageRow};
use crate::relations::{self, IdentityComponents, TextHandle};
use crate::schemas::message::DEFAULT_SCOPE_ID;
use crate::schemas::relations::DEFAULT_SCOPE_ID as DEFAULT_RELATIONS_SCOPE_ID;
use crate::storage::{
    self, load_signer, open_store, runtime, FactArchive, FacultySnapshot, FacultyStore,
};
use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
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

/// A configured Message capability. Every call observes one newly maintained,
/// frozen Message/Relations view and closes storage before returning its value.
/// No transport, sender environment, or text-file convention is consulted.
#[derive(Clone, Debug)]
pub struct Message {
    pile: PathBuf,
    key: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug)]
pub struct SendOptions<'a> {
    pub from: &'a str,
    pub to: &'a str,
    /// Literal text, including strings beginning with `@`.
    pub text: &'a str,
}

impl SendOptions<'_> {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(!self.from.trim().is_empty(), "message sender is empty");
        anyhow::ensure!(!self.to.trim().is_empty(), "message recipient is empty");
        anyhow::ensure!(!self.text.trim().is_empty(), "message text is empty");
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ListOptions<'a> {
    pub reader: &'a str,
    pub unread: bool,
    pub limit: usize,
}

impl<'a> ListOptions<'a> {
    pub fn new(reader: &'a str) -> Self {
        Self {
            reader,
            unread: false,
            limit: 20,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AckAllOptions<'a> {
    pub by: &'a str,
    pub from: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SentMessage {
    pub id: Id,
    pub from: Id,
    /// The exact recipient, including a group's witnessed delivery snapshot.
    pub recipient: message::Recipient,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageStatus {
    Unread,
    Read,
    Sent,
    ReadByRecipient,
}

/// An owned observation, not a second catalog. Its envelope preserves exact
/// attribution even when delivery/receipts use settled identity equivalence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageObservation {
    pub row: MessageRow,
    pub body: String,
    pub from_label: String,
    pub to_label: String,
    pub incoming: bool,
    pub outgoing: bool,
    pub status: MessageStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageList {
    pub reader: Id,
    pub observed_at: IntervalValue,
    pub entries: Vec<MessageObservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Acknowledgement {
    pub message: Id,
    pub reader: Id,
    pub already_read: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcknowledgedMessages {
    pub reader: Id,
    /// Envelopes acknowledged by this operation, empty for an idempotent replay.
    pub message_ids: Vec<Id>,
}

impl Message {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self { pile, key }
    }

    pub fn send(&self, options: &SendOptions<'_>) -> Result<SentMessage> {
        options.validate()?;
        with_storage(self, |storage, runtime| {
            runtime.block_on(send(storage, options))
        })
    }

    pub fn list(&self, options: &ListOptions<'_>) -> Result<MessageList> {
        with_storage(self, |storage, runtime| {
            runtime.block_on(list(storage, options))
        })
    }

    pub fn ack(&self, id: &str, by: &str) -> Result<Acknowledgement> {
        with_storage(self, |storage, runtime| {
            runtime.block_on(ack(storage, id, by))
        })
    }

    pub fn ack_all(&self, options: &AckAllOptions<'_>) -> Result<AcknowledgedMessages> {
        with_storage(self, |storage, runtime| {
            runtime.block_on(ack_all(storage, options))
        })
    }
}

struct MessageStorage<'a> {
    pile: &'a mut FacultyStore,
    signer: &'a SigningKey,
    collection: Collection<SimpleArchive>,
    reader: &'a FacultySnapshot,
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

pub(super) fn interval_key(interval: IntervalValue) -> i128 {
    let (lower, _): (i128, i128) = interval
        .try_from_inline()
        .expect("stored Message timestamp is a valid interval");
    lower
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
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
    if matches!(
        relations::profile_head(facts, person)?,
        relations::Head::Missing
    ) {
        return Ok(format!("{person:x} [profile unavailable]"));
    }
    let profile = relations::current_profile(facts, person)?;
    let Some(bytes) = store
        .acquire(profile.label.transmute())
        .await
        .context("acquire Message person label")?
    else {
        return Ok(format!("{person:x} [label unavailable]"));
    };
    Ok(std::str::from_utf8(&bytes)
        .context("decode Message person label")?
        .to_owned())
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

async fn send(storage: &mut MessageStorage<'_>, options: &SendOptions<'_>) -> Result<SentMessage> {
    let relation_facts = storage.relations;
    let (from_id, recipient) = storage::read(storage.pile, storage.reader, |reader| {
        let from_id = message::resolve_person(reader, relation_facts, options.from)?
            .require_unique("active person", options.from)?;
        let recipient = message::resolve_recipient(reader, relation_facts, options.to)?
            .require_unique(options.to)?;
        Ok((from_id, recipient))
    })
    .await?;
    storage.update("local message", |_, _| {
        let (fragment, id) =
            message::message_fragment(from_id, &recipient, options.text, clock::point_now()?);
        Ok((
            Some(fragment),
            SentMessage {
                id,
                from: from_id,
                recipient,
            },
        ))
    })
}

async fn ack(storage: &mut MessageStorage<'_>, id: &str, by: &str) -> Result<Acknowledgement> {
    let relation_facts = storage.relations;
    let reader_id = storage::read(storage.pile, storage.reader, |reader| {
        message::resolve_person(reader, relation_facts, by)?.require_unique("active person", by)
    })
    .await?;
    storage.update("local message read", |message_facts, relation_facts| {
        let message_id = message::resolve_message_id(message_facts, id)?;
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
        let already_read = message::is_read_by(&reads, message_id, reader_id, &identities)?;
        let fragment = if already_read {
            None
        } else {
            Some(message::read_fragment(message_id, reader_id, Some(clock::point_now()?)).0)
        };
        Ok((
            fragment,
            Acknowledgement {
                message: message_id,
                reader: reader_id,
                already_read,
            },
        ))
    })
}

async fn ack_all(
    storage: &mut MessageStorage<'_>,
    options: &AckAllOptions<'_>,
) -> Result<AcknowledgedMessages> {
    let relation_facts = storage.relations;
    let (reader_id, from) = storage::read(storage.pile, storage.reader, |reader| {
        let reader_id = message::resolve_person(reader, relation_facts, options.by)?
            .require_unique("active person", options.by)?;
        let from = options
            .from
            .map(|selector| {
                message::resolve_person(reader, relation_facts, selector)?
                    .require_unique("active person", selector)
            })
            .transpose()?;
        Ok((reader_id, from))
    })
    .await?;
    storage.update(
        "local messages bulk read",
        |message_facts, relation_facts| {
            let identities = IdentityComponents::from_facts(relation_facts)?;
            let reads = message::load_read_rows(message_facts)?;
            let observed_at = clock::point_now()?;
            let mut fragment = Fragment::empty();
            let mut message_ids = Vec::new();
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
                message_ids.push(row.id);
            }
            Ok((
                (!message_ids.is_empty()).then_some(fragment),
                AcknowledgedMessages {
                    reader: reader_id,
                    message_ids,
                },
            ))
        },
    )
}

async fn list(storage: &mut MessageStorage<'_>, options: &ListOptions<'_>) -> Result<MessageList> {
    let message_facts = storage.messages;
    let relation_facts = storage.relations;
    let reader_id = storage::read(storage.pile, storage.reader, |reader| {
        message::resolve_person(reader, relation_facts, options.reader)?
            .require_unique("active person", options.reader)
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

    let observed_at = clock::point_now()?;
    let mut entries = Vec::new();
    for row in messages {
        if entries.len() >= options.limit {
            break;
        }
        let incoming = message::is_inbox_message(&row, reader_id, relation_facts, &identities)?;
        let outgoing = message::is_outgoing_message(&row, reader_id, &identities)?;
        if !incoming && !outgoing {
            continue;
        }
        let read = message::is_read_by(&reads, row.id, reader_id, &identities)?;
        if options.unread && !(incoming && !read) {
            continue;
        }
        let from_label = person_label(storage.pile, relation_facts, row.from).await?;
        let to_label = recipient_label(storage.pile, relation_facts, &row).await?;
        let status = if incoming {
            if read {
                MessageStatus::Read
            } else {
                MessageStatus::Unread
            }
        } else if row.group_snapshot.is_none()
            && message::is_read_by(&reads, row.id, row.to, &identities)?
        {
            MessageStatus::ReadByRecipient
        } else {
            MessageStatus::Sent
        };
        let body = acquire_text(storage.pile, row.body).await?;
        entries.push(MessageObservation {
            row,
            body,
            from_label,
            to_label,
            incoming,
            outgoing,
            status,
        });
    }
    Ok(MessageList {
        reader: reader_id,
        observed_at,
        entries,
    })
}

fn with_storage<T>(
    capability: &Message,
    operation: impl FnOnce(&mut MessageStorage<'_>, &tokio::runtime::Runtime) -> Result<T>,
) -> Result<T> {
    let signer = load_signer(&capability.pile, capability.key.as_deref())?;
    let runtime = runtime()?;
    let mut pile = open_store(&capability.pile)?;
    let result = (|| {
        let (message_source, reader, relation_facts, message_facts) = runtime.block_on(async {
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
            let message_source =
                open_configured(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
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
                .derive::<Rank9AcceleratedSuccinctArchiveBlob>(
                    relations_succinct,
                    (),
                    relations_policy,
                )
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

            Ok::<_, anyhow::Error>((message_source, reader, relation_facts, message_facts))
        })?;
        let mut storage = MessageStorage {
            pile: &mut pile,
            signer: &signer,
            collection: message_source,
            reader: &reader,
            messages: &message_facts,
            relations: &relation_facts,
        };
        operation(&mut storage, &runtime)
    })();
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
        let source =
            crate::collection_names::open(&mut remote, DEFAULT_SCOPE_ID, signer.verifying_key())
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
            message::resolve_person(&before, fragment.facts(), &fmt_id(test_id(3))).unwrap(),
            relations::SelectorOutcome::Missing
        );
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
    fn exact_inbox_message_keeps_an_unobserved_senders_anchor_and_body() {
        let sender = test_id(8);
        let reader = test_id(9);
        let (relations, _, _) = relations::person_fragment(
            reader,
            relations::ProfileInput {
                label: "reader".to_owned(),
                ..Default::default()
            },
        )
        .unwrap();
        let (envelope, id) = message::message_fragment(
            sender,
            &message::Recipient::Person(reader),
            "visible inbox body",
            (Epoch::from_tai_seconds(0.0), Epoch::from_tai_seconds(0.0))
                .try_to_inline()
                .unwrap(),
        );
        let row = message::row_by_id(envelope.facts(), id).unwrap();
        let identities = IdentityComponents::from_facts(relations.facts()).unwrap();
        assert!(message::is_inbox_message(&row, reader, relations.facts(), &identities).unwrap());
        assert!(!message::is_outgoing_message(&row, reader, &identities).unwrap());
        let mut store = AcquiringPile::new(envelope.blobs().clone());

        assert_eq!(
            pollster::block_on(person_label(&mut store, relations.facts(), row.from)).unwrap(),
            format!("{sender:x} [profile unavailable]")
        );
        assert!(store.requested.is_empty());
        assert_eq!(
            pollster::block_on(acquire_text(&mut store, row.body)).unwrap(),
            "visible inbox body"
        );
        assert_eq!((row.from, row.to), (sender, reader));
        assert_eq!(store.requested, vec![row.body.transmute()]);
    }

    #[test]
    fn person_display_distinguishes_absent_profile_from_unavailable_label() {
        let person = test_id(10);
        let (fragment, _, _) = relations::person_fragment(
            person,
            relations::ProfileInput {
                label: "unavailable label".to_owned(),
                ..Default::default()
            },
        )
        .unwrap();
        let profile = relations::current_profile(fragment.facts(), person).unwrap();
        let mut store = AcquiringPile::new(MemoryBlobStore::new());
        let anchor_only = entity! {
            ExclusiveId::force_ref(&person) @
            metadata::tag: &crate::schemas::relations::KIND_PERSON_ID
        };

        assert_eq!(
            pollster::block_on(person_label(&mut store, anchor_only.facts(), person)).unwrap(),
            format!("{person:x} [profile unavailable]")
        );
        assert!(store.requested.is_empty());

        assert_eq!(
            pollster::block_on(person_label(&mut store, fragment.facts(), person)).unwrap(),
            format!("{person:x} [label unavailable]")
        );
        assert_eq!(store.requested, vec![profile.label.transmute()]);
        assert_eq!(store.snapshot().unwrap().wants().unwrap().count(), 0);
    }

    #[test]
    fn person_display_does_not_hide_a_profile_fork() {
        let person = test_id(11);
        let (mut fragment, _, _) = relations::person_fragment(
            person,
            relations::ProfileInput {
                label: "first head".to_owned(),
                ..Default::default()
            },
        )
        .unwrap();
        fragment += relations::profile_fragment(
            person,
            relations::ProfileInput {
                label: "second head".to_owned(),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let mut store = AcquiringPile::new(fragment.blobs().clone());

        let error =
            pollster::block_on(person_label(&mut store, fragment.facts(), person)).unwrap_err();
        assert!(error.to_string().contains("profile is forked"));
        assert!(store.requested.is_empty());
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
                basis: crate::schemas::message::GROUP_SNAPSHOT_BASIS_WITNESSED,
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

        let person = test_id(12);
        let profile = entity! {
            metadata::tag: &crate::schemas::relations::KIND_PERSON_PROFILE,
            crate::schemas::relations::profile::of: &person,
            metadata::name: invalid,
        };
        let malformed =
            pollster::block_on(person_label(&mut store, profile.facts(), person)).unwrap_err();
        assert!(malformed
            .to_string()
            .contains("decode Message person label"));
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
        let source = crate::collection_names::open(
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
