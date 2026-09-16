//! Typed finite Message operations over one frozen Message/Relations observation.
//! Text is literal; sender selection and output routing belong to the caller.

use std::path::PathBuf;

use crate::clock;
use crate::collection_names::{configured_handle, open_configured, open_exact_in};
use crate::message::{self, IntervalValue, MessageRow};
use crate::relations::{self, IdentityComponents, TextHandle};
use crate::schemas::message::DEFAULT_SCOPE_ID;
use crate::schemas::relations::DEFAULT_SCOPE_ID as DEFAULT_RELATIONS_SCOPE_ID;
use crate::storage::{self, FactArchive, FacultySnapshot, FacultyStore, Storage};
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
use triblespace::prelude::*;

/// A configured Message capability. Every call observes one frozen
/// Message/Relations view through its storage handle. A read attaches the
/// replicated views as they stand; an edit first requests maintenance of the
/// Message chain when its signer may write it, then queries the same indexed
/// views. There is no hybrid view: a locally unindexed COMMIT waits for
/// maintenance exactly as an unsynced one does.
/// No transport, sender environment, or text-file convention is consulted.
#[derive(Clone, Debug)]
pub struct Message {
    storage: Storage,
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
        Self::with_storage(Storage::new(pile, key))
    }

    pub fn with_storage(storage: Storage) -> Self {
        Self { storage }
    }

    pub fn send(&self, options: &SendOptions<'_>) -> Result<SentMessage> {
        options.validate()?;
        with_storage(self, ViewIntent::Edit, |storage, runtime| {
            runtime.block_on(send(storage, options))
        })
    }

    pub fn list(&self, options: &ListOptions<'_>) -> Result<MessageList> {
        with_storage(self, ViewIntent::Read, |storage, runtime| {
            runtime.block_on(list(storage, options))
        })
    }

    pub fn ack(&self, id: &str, by: &str) -> Result<Acknowledgement> {
        with_storage(self, ViewIntent::Edit, |storage, runtime| {
            runtime.block_on(ack(storage, id, by))
        })
    }

    pub fn ack_all(&self, options: &AckAllOptions<'_>) -> Result<AcknowledgedMessages> {
        with_storage(self, ViewIntent::Edit, |storage, runtime| {
            runtime.block_on(ack_all(storage, options))
        })
    }
}

/// The facts one operation queries: the resident Rank9 view, for reads and
/// edits alike. There are no hybrid views: a locally unindexed COMMIT waits
/// for maintenance exactly as an unsynced one does.
type MessageFacts = FactArchive;

/// The one explicit boundary between reading and writing. A read attaches
/// the replicated views as they stand and never maintains; measured
/// 2026-09-16 on sky, Fac 92308e55 / Core 256898f2, one process, `message
/// list --unread` cost 42.39 s wall and 171.24 s combined CPU with inline
/// maintenance, 6.10 s and 6.40 s without. An edit first requests
/// maintenance of the Message chain under the existing permission-aware
/// contract: when its signer is admitted to write the derived Succinct and
/// Rank9 targets they are carried one edge from their resident inputs,
/// otherwise the views are attached as they stand; the signer's source WRITE
/// still gates publication, and no derived grant is invented. Persona lookup
/// through Relations is a read for every operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ViewIntent {
    Read,
    Edit,
}

struct MessageStorage<'a> {
    pile: &'a mut FacultyStore,
    signer: &'a SigningKey,
    collection: Collection<SimpleArchive>,
    reader: &'a FacultySnapshot,
    messages: &'a MessageFacts,
    relations: &'a MessageFacts,
}

impl MessageStorage<'_> {
    /// Publish at most one locally constructed typed fragment.
    fn update<T>(
        &mut self,
        description: &'static str,
        operation: impl FnOnce(&MessageFacts, &MessageFacts) -> Result<(Option<Fragment>, T)>,
    ) -> Result<T> {
        let (fragment, value) = operation(self.messages, self.relations)?;
        if let Some(mut fragment) = fragment {
            let snapshot = self
                .pile
                .snapshot()
                .context("freeze Message publication authority")?;
            anyhow::ensure!(
                self.collection
                    .writer_is_admitted(&snapshot, self.signer.verifying_key())
                    .map_err(|error| {
                        anyhow::anyhow!("check Message source WRITE admission: {error}")
                    })?,
                "publishing a Message fragment requires source collection WRITE"
            );
            drop(snapshot);
            fragment.describe_with(entity! { metadata::description: description });
            self.pile
                .commit(self.collection, self.signer, fragment)
                .context("commit authored Message fragment")?;
        }
        Ok(value)
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
        .with_context(|| format!("acquire Message text blake3:{}", hex::encode(handle.raw)))?
        .with_context(|| {
            format!(
                "Message text is unavailable (blake3:{})",
                hex::encode(handle.raw)
            )
        })?;
    Ok(std::str::from_utf8(&bytes)
        .with_context(|| format!("decode Message text blake3:{}", hex::encode(handle.raw)))?
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
            acquire_text(store, snapshot.name).await.with_context(|| {
                format!(
                    "read name of group snapshot {:x} for Message {:x}",
                    snapshot.id, row.id
                )
            })
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
        let body = acquire_text(storage.pile, row.body)
            .await
            .with_context(|| format!("read body of Message {:x}", row.id))?;
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
    intent: ViewIntent,
    operation: impl FnOnce(&mut MessageStorage<'_>, &tokio::runtime::Runtime) -> Result<T>,
) -> Result<T> {
    capability.storage.with_store(|pile, signer, runtime| {
        let (message_source, reader, relation_facts, message_facts) = runtime.block_on(async {
            // An explicit descriptor may itself have arrived as only an exact
            // handle. Acquire it and the name needed by open_configured, not its
            // arbitrary attachment closure.
            for scope in [DEFAULT_RELATIONS_SCOPE_ID, DEFAULT_SCOPE_ID] {
                if let Some(handle) = configured_handle(scope)? {
                    let reader = pile
                        .snapshot()
                        .context("freeze configured Message collection descriptor")?;
                    storage::read(pile, &reader, |reader| open_exact_in(reader, scope, handle))
                        .await?;
                }
            }
            let relations_source =
                open_configured(pile, DEFAULT_RELATIONS_SCOPE_ID, signer.verifying_key())?;
            let message_source = open_configured(pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
            let (reader, relation_facts, message_facts) =
                message_views(pile, signer, relations_source, message_source, intent).await?;
            Ok::<_, anyhow::Error>((message_source, reader, relation_facts, message_facts))
        })?;
        let mut storage = MessageStorage {
            pile,
            signer,
            collection: message_source,
            reader: &reader,
            messages: &message_facts,
            relations: &relation_facts,
        };
        operation(&mut storage, runtime)
    })
}

async fn message_views(
    pile: &mut FacultyStore,
    signer: &SigningKey,
    relations_source: Collection<SimpleArchive>,
    message_source: Collection<SimpleArchive>,
    intent: ViewIntent,
) -> Result<(FacultySnapshot, MessageFacts, MessageFacts)> {
    let trace = std::env::var_os("MESSAGE_RESIDUAL_TRACE").is_some();
    let started = std::time::Instant::now();
    // A read reuses the chains as the maintenance worker left them. An edit
    // requests one edge of maintenance on the Message chain first, when its
    // signer may write those targets. Publication checks source WRITE
    // independently.
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
    let registered_at = started.elapsed();
    if intent == ViewIntent::Edit {
        let admitted = {
            let snapshot = pile.snapshot().context("freeze Message WRITE admission")?;
            let subject = signer.verifying_key();
            message_succinct
                .writer_is_admitted(&snapshot, subject)
                .map_err(|error| {
                    anyhow::anyhow!("check Message Succinct WRITE admission: {error}")
                })?
                && message_rank9
                    .writer_is_admitted(&snapshot, subject)
                    .map_err(|error| {
                        anyhow::anyhow!("check Message Rank9 WRITE admission: {error}")
                    })?
        };
        // One-edge maintenance selects resident immediate-source inputs and
        // never acquires a root just to read the target. A signer without
        // derived WRITE queries the views as they stand: that admission check
        // is the seam, since a refused maintenance would surface as an error
        // and not as a typed outcome.
        if admitted {
            drop(
                pile.maintain(message_succinct, signer)
                    .await
                    .context("maintain Message Succinct collection")?,
            );
            drop(
                pile.maintain(message_rank9, signer)
                    .await
                    .context("maintain Message Rank9 collection")?,
            );
        }
    }
    let maintained_at = started.elapsed();
    // Both query views retain their selected support. Later selected-text
    // acquisition may add bytes, but never replaces these frozen facts.
    let reader = pile.snapshot().context("freeze Message observation")?;
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
    let attached_at = started.elapsed();
    if trace {
        eprintln!(
            "views: registered in {:.2?}, maintained in {:.2?}, attached in {:.2?}",
            registered_at,
            maintained_at - registered_at,
            attached_at - maintained_at
        );
    }
    Ok((reader, relation_facts, message_facts))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;
    use std::future::{ready, Future};
    use std::io;

    use anybytes::Bytes;
    use hifitime::Epoch;
    use triblespace::core::blob::encodings::UnknownBlob;
    use triblespace::core::blob::MemoryBlobStoreSnapshot;
    use triblespace::core::collection::{
        empty_metadata_handle, grant_collection_write, CollectionCommit, CollectionRead,
        CollectionRecord, CollectionRecordSelector,
    };
    use triblespace::core::repo::pile::ReadError;
    use triblespace::core::repo::StorageClose;

    /// A real resident-only pile with a deterministic remote blob fixture.
    struct AcquiringPile {
        pile: Pile,
        remote: MemoryBlobStoreSnapshot,
        requested: Vec<Inline<inlineencodings::Handle<UnknownBlob>>>,
        failure: Option<io::ErrorKind>,
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
                failure: None,
                arriving: None,
                _file: file,
            }
        }
    }

    impl SnapshotSource for AcquiringPile {
        type Snapshot = PileSnapshot;
        type SnapshotError = ReadError;

        fn snapshot(&mut self) -> Result<PileSnapshot, ReadError> {
            self.pile.snapshot()
        }
    }

    impl AsyncBlobStoreAcquire for AcquiringPile {
        type AcquireError = io::Error;

        fn acquire(
            &mut self,
            handle: Inline<inlineencodings::Handle<UnknownBlob>>,
        ) -> impl Future<Output = Result<Option<Bytes>, io::Error>> + Send {
            let resident = self.pile.snapshot().unwrap();
            if resident.contains_blob(handle).unwrap() {
                return ready(Ok(Some(resident.get(handle).unwrap())));
            }
            self.requested.push(handle);
            if let Some(kind) = self.failure {
                return ready(Err(io::Error::new(
                    kind,
                    "injected Message acquisition failure",
                )));
            }
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

    /// Stand-in for the maintenance worker: carry one source's Succinct and
    /// Rank9 targets, exactly what no operation does any more by itself.
    fn carry(
        pile: &mut FacultyStore,
        runtime: &tokio::runtime::Runtime,
        source: Collection<SimpleArchive>,
        signer: &SigningKey,
    ) {
        let policy = source.policy(&pile.snapshot().unwrap()).unwrap();
        let succinct = pile
            .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
            .unwrap();
        let rank9 = pile
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
            .unwrap();
        drop(runtime.block_on(pile.maintain(succinct, signer)).unwrap());
        drop(runtime.block_on(pile.maintain(rank9, signer)).unwrap());
    }

    #[test]
    fn non_writer_lists_resident_messages_but_cannot_publish() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut pile = storage::open_store(file.path()).unwrap();
        let runtime = storage::runtime().unwrap();
        let owner = SigningKey::from_bytes(&[91; 32]);
        let observer = SigningKey::from_bytes(&[92; 32]);
        let relations_source = crate::collection_names::open(
            &mut pile,
            DEFAULT_RELATIONS_SCOPE_ID,
            owner.verifying_key(),
        )
        .unwrap();
        let message_source =
            crate::collection_names::open(&mut pile, DEFAULT_SCOPE_ID, owner.verifying_key())
                .unwrap();
        let mut selectors = BTreeSet::new();
        for source in [relations_source, message_source] {
            let policy = source.policy(&pile.snapshot().unwrap()).unwrap();
            let succinct = pile
                .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
                .unwrap();
            let rank9 = pile
                .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
                .unwrap();
            for handle in [source.handle(), succinct.handle(), rank9.handle()] {
                selectors.insert(CollectionRecordSelector::Collection(handle));
            }
        }
        let sender = test_id(61);
        let recipient = test_id(62);
        let mut people = relations::person_fragment(
            sender,
            relations::ProfileInput {
                label: "sender".to_owned(),
                ..Default::default()
            },
        )
        .unwrap()
        .0;
        people += relations::person_fragment(
            recipient,
            relations::ProfileInput {
                label: "reader".to_owned(),
                ..Default::default()
            },
        )
        .unwrap()
        .0;
        pile.commit(relations_source, &owner, people).unwrap();
        let (first, first_id) = message::message_fragment(
            sender,
            &message::Recipient::Person(recipient),
            "first message",
            clock::point_now().unwrap(),
        );
        pile.commit(message_source, &owner, first).unwrap();
        // The maintenance worker carries both chains; operations never do.
        carry(&mut pile, &runtime, relations_source, &owner);
        carry(&mut pile, &runtime, message_source, &owner);

        let (second, second_id) = message::message_fragment(
            sender,
            &message::Recipient::Person(recipient),
            "second message",
            clock::point_now().unwrap(),
        );
        let later_person = test_id(63);
        let later = relations::person_fragment(
            later_person,
            relations::ProfileInput {
                label: "later person".to_owned(),
                ..Default::default()
            },
        )
        .unwrap()
        .0;
        let options = ListOptions::new("reader");
        for growth in [None, Some((later, second))] {
            if let Some((person, message)) = growth {
                pile.commit(relations_source, &owner, person).unwrap();
                pile.commit(message_source, &owner, message).unwrap();
            }
            let before = pile.snapshot().unwrap().select_records(&selectors).unwrap();
            // A listing is a read: it sees the carried views as they stand,
            // not the raw records the worker has not carried yet.
            let (snapshot, relation_facts, message_facts) = runtime
                .block_on(message_views(
                    &mut pile,
                    &observer,
                    relations_source,
                    message_source,
                    ViewIntent::Read,
                ))
                .unwrap();
            assert!(!relations::person_anchors(&relation_facts).contains(&later_person));
            let mut input = MessageStorage {
                pile: &mut pile,
                signer: &observer,
                collection: message_source,
                reader: &snapshot,
                messages: &message_facts,
                relations: &relation_facts,
            };
            let result = runtime.block_on(list(&mut input, &options)).unwrap();
            assert_eq!(result.reader, recipient);
            assert_eq!(result.entries.len(), 1);
            assert_eq!(result.entries[0].row.id, first_id);
            assert_eq!(result.entries[0].body, "first message");
            assert_eq!(result.entries[0].status, MessageStatus::Unread);
            assert_eq!(
                pile.snapshot().unwrap().select_records(&selectors).unwrap(),
                before
            );
        }

        let before = pile.snapshot().unwrap().select_records(&selectors).unwrap();
        let (snapshot, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &observer,
                relations_source,
                message_source,
                ViewIntent::Edit,
            ))
            .unwrap();
        let mut input = MessageStorage {
            pile: &mut pile,
            signer: &observer,
            collection: message_source,
            reader: &snapshot,
            messages: &message_facts,
            relations: &relation_facts,
        };
        let error = runtime
            .block_on(send(
                &mut input,
                &SendOptions {
                    from: "sender",
                    to: "reader",
                    text: "unauthorized message",
                },
            ))
            .unwrap_err();
        assert!(format!("{error:#}").contains("requires source collection WRITE"));
        let error = runtime
            .block_on(ack(&mut input, &fmt_id(first_id), "reader"))
            .unwrap_err();
        assert!(format!("{error:#}").contains("requires source collection WRITE"));
        input.update("no-op", |_, _| Ok((None, ()))).unwrap();
        assert_eq!(
            pile.snapshot().unwrap().select_records(&selectors).unwrap(),
            before
        );

        let (snapshot, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &owner,
                relations_source,
                message_source,
                ViewIntent::Edit,
            ))
            .unwrap();
        let mut input = MessageStorage {
            pile: &mut pile,
            signer: &owner,
            collection: message_source,
            reader: &snapshot,
            messages: &message_facts,
            relations: &relation_facts,
        };
        let acknowledgement = runtime
            .block_on(ack(&mut input, &fmt_id(first_id), "reader"))
            .unwrap();
        assert!(!acknowledgement.already_read);
        // The read receipt is a raw COMMIT the worker has not carried; an
        // edit by the owner maintains the chain first, so the receipt is
        // carried and acknowledging again is a no-op that publishes nothing.
        let (snapshot, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &owner,
                relations_source,
                message_source,
                ViewIntent::Edit,
            ))
            .unwrap();
        let before_noop = pile.snapshot().unwrap().select_records(&selectors).unwrap();
        let mut input = MessageStorage {
            pile: &mut pile,
            signer: &owner,
            collection: message_source,
            reader: &snapshot,
            messages: &message_facts,
            relations: &relation_facts,
        };
        assert!(
            runtime
                .block_on(ack(&mut input, &fmt_id(first_id), "reader"))
                .unwrap()
                .already_read
        );
        assert_eq!(
            pile.snapshot().unwrap().select_records(&selectors).unwrap(),
            before_noop
        );
        let (snapshot, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &owner,
                relations_source,
                message_source,
                ViewIntent::Edit,
            ))
            .unwrap();
        let mut input = MessageStorage {
            pile: &mut pile,
            signer: &owner,
            collection: message_source,
            reader: &snapshot,
            messages: &message_facts,
            relations: &relation_facts,
        };
        let result = runtime.block_on(list(&mut input, &options)).unwrap();
        assert_eq!(result.entries.len(), 2);
        assert_eq!(
            result
                .entries
                .iter()
                .find(|entry| entry.row.id == first_id)
                .unwrap()
                .status,
            MessageStatus::Read
        );
        assert_eq!(
            result
                .entries
                .iter()
                .find(|entry| entry.row.id == second_id)
                .unwrap()
                .status,
            MessageStatus::Unread
        );
        pile.close().unwrap();
    }

    #[test]
    fn source_only_writer_sends_and_acknowledges_without_derived_write() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut pile = storage::open_store(file.path()).unwrap();
        let runtime = storage::runtime().unwrap();
        let owner = SigningKey::from_bytes(&[95; 32]);
        let sender = SigningKey::from_bytes(&[96; 32]);
        let relations_source = crate::collection_names::open(
            &mut pile,
            DEFAULT_RELATIONS_SCOPE_ID,
            owner.verifying_key(),
        )
        .unwrap();
        let message_source =
            crate::collection_names::open(&mut pile, DEFAULT_SCOPE_ID, owner.verifying_key())
                .unwrap();
        let person = test_id(66);
        pile.commit(
            relations_source,
            &owner,
            relations::person_fragment(
                person,
                relations::ProfileInput {
                    label: "sender".to_owned(),
                    ..Default::default()
                },
            )
            .unwrap()
            .0,
        )
        .unwrap();
        let (first, first_id) = message::message_fragment(
            test_id(68),
            &message::Recipient::Person(person),
            "already readable",
            clock::point_now().unwrap(),
        );
        pile.commit(message_source, &owner, first).unwrap();
        // Persona lookup is a read, and a writer without derived WRITE sees
        // only what the maintainer carried: the owner carries both chains
        // before the sender can address anyone or acknowledge anything.
        carry(&mut pile, &runtime, relations_source, &owner);
        carry(&mut pile, &runtime, message_source, &owner);
        drop(
            runtime
                .block_on(message_views(
                    &mut pile,
                    &sender,
                    relations_source,
                    message_source,
                    ViewIntent::Edit,
                ))
                .unwrap(),
        );
        grant_collection_write(
            &mut pile,
            message_source.handle(),
            &owner,
            sender.verifying_key(),
        )
        .unwrap();
        for source in [relations_source, message_source] {
            let policy = source.policy(&pile.snapshot().unwrap()).unwrap();
            let succinct = pile
                .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
                .unwrap();
            let rank9 = pile
                .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
                .unwrap();
            let snapshot = pile.snapshot().unwrap();
            assert!(!succinct
                .writer_is_admitted(&snapshot, sender.verifying_key())
                .unwrap());
            assert!(!rank9
                .writer_is_admitted(&snapshot, sender.verifying_key())
                .unwrap());
        }
        let before = pile
            .snapshot()
            .unwrap()
            .records()
            .unwrap()
            .map(|record| record.unwrap())
            .collect::<BTreeSet<_>>();
        let (snapshot, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &sender,
                relations_source,
                message_source,
                ViewIntent::Edit,
            ))
            .unwrap();
        assert!(message_source
            .writer_is_admitted(&snapshot, sender.verifying_key())
            .unwrap());
        let mut input = MessageStorage {
            pile: &mut pile,
            signer: &sender,
            collection: message_source,
            reader: &snapshot,
            messages: &message_facts,
            relations: &relation_facts,
        };
        let sent = runtime
            .block_on(send(
                &mut input,
                &SendOptions {
                    from: "sender",
                    to: "sender",
                    text: "published without index WRITE",
                },
            ))
            .unwrap();
        assert!(
            !runtime
                .block_on(ack(&mut input, &fmt_id(first_id), "sender"))
                .unwrap()
                .already_read
        );
        let after = pile
            .snapshot()
            .unwrap()
            .records()
            .unwrap()
            .map(|record| record.unwrap())
            .collect::<BTreeSet<_>>();
        let added: Vec<_> = after.difference(&before).copied().collect();
        assert_eq!(added.len(), 2);
        assert!(added.iter().all(|record| matches!(
            record,
            CollectionRecord::Commit(commit) if commit.collection() == message_source.handle()
        )));

        // The owner can subsequently maintain these admitted source writes.
        let (snapshot, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &owner,
                relations_source,
                message_source,
                ViewIntent::Edit,
            ))
            .unwrap();
        let mut input = MessageStorage {
            pile: &mut pile,
            signer: &owner,
            collection: message_source,
            reader: &snapshot,
            messages: &message_facts,
            relations: &relation_facts,
        };
        let listed = runtime
            .block_on(list(&mut input, &ListOptions::new("sender")))
            .unwrap();
        assert_eq!(listed.entries.len(), 2);
        assert_eq!(
            listed
                .entries
                .iter()
                .find(|entry| entry.row.id == sent.id)
                .unwrap()
                .body,
            "published without index WRITE"
        );
        assert!(pile.health().started_at.is_none());
        pile.close().unwrap();
    }

    #[test]
    fn owner_reads_warm_targets_without_acquiring_cold_root_members() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut pile = storage::open_store(file.path()).unwrap();
        let runtime = storage::runtime().unwrap();
        let owner = SigningKey::from_bytes(&[97; 32]);
        let relations_source = crate::collection_names::open(
            &mut pile,
            DEFAULT_RELATIONS_SCOPE_ID,
            owner.verifying_key(),
        )
        .unwrap();
        let message_source =
            crate::collection_names::open(&mut pile, DEFAULT_SCOPE_ID, owner.verifying_key())
                .unwrap();
        let person = test_id(67);
        pile.commit(
            relations_source,
            &owner,
            relations::person_fragment(
                person,
                relations::ProfileInput {
                    label: "reader".to_owned(),
                    ..Default::default()
                },
            )
            .unwrap()
            .0,
        )
        .unwrap();
        let (first, first_id) = message::message_fragment(
            person,
            &message::Recipient::Person(person),
            "the resident message",
            clock::point_now().unwrap(),
        );
        pile.commit(message_source, &owner, first).unwrap();
        // The worker carries both chains once, so the targets are warm.
        carry(&mut pile, &runtime, relations_source, &owner);
        carry(&mut pile, &runtime, message_source, &owner);
        assert!(pile.health().started_at.is_none());

        let mut missing = Vec::new();
        for (source, name) in [
            (relations_source, "cold Relations member"),
            (message_source, "cold Message member"),
        ] {
            // Model record-first repair: the real signed member arrives, but
            // its archive does not. Its bytes exist only in this local value.
            let blob = IntoBlob::<SimpleArchive>::to_blob(
                entity! { metadata::name: name }.facts().clone(),
            );
            let handle = blob.get_handle();
            pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
                &owner,
                source.handle(),
                inlineencodings::Handle::<SimpleArchive>::to_hash(handle),
                empty_metadata_handle(),
            )))
            .unwrap();
            let snapshot = pile.snapshot().unwrap();
            assert!(source.admitted(&snapshot).unwrap().contains(handle));
            assert!(!snapshot.contains_blob(handle).unwrap());
            missing.push(handle);
        }
        let before = pile
            .snapshot()
            .unwrap()
            .records()
            .unwrap()
            .map(|record| record.unwrap())
            .collect::<Vec<_>>();
        let (snapshot, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &owner,
                relations_source,
                message_source,
                ViewIntent::Edit,
            ))
            .unwrap();
        let mut input = MessageStorage {
            pile: &mut pile,
            signer: &owner,
            collection: message_source,
            reader: &snapshot,
            messages: &message_facts,
            relations: &relation_facts,
        };
        let listed = runtime
            .block_on(list(&mut input, &ListOptions::new("reader")))
            .unwrap();
        assert_eq!(listed.entries.len(), 1);
        assert_eq!(listed.entries[0].row.id, first_id);
        assert_eq!(listed.entries[0].body, "the resident message");
        let after = pile.snapshot().unwrap();
        assert_eq!(
            after
                .records()
                .unwrap()
                .map(|record| record.unwrap())
                .collect::<Vec<_>>(),
            before
        );
        for handle in missing {
            assert!(!after.contains_blob(handle).unwrap());
        }
        // A foreground Peer starts only when an unavailable blob is acquired.
        assert!(pile.health().started_at.is_none());
        pile.close().unwrap();
    }

    #[test]
    fn edits_see_the_carried_views_and_fresh_records_once_the_worker_carries_them() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut pile = storage::open_store(file.path()).unwrap();
        let runtime = storage::runtime().unwrap();
        let relations_owner = SigningKey::from_bytes(&[93; 32]);
        let message_owner = SigningKey::from_bytes(&[94; 32]);
        let relations_source = crate::collection_names::open(
            &mut pile,
            DEFAULT_RELATIONS_SCOPE_ID,
            relations_owner.verifying_key(),
        )
        .unwrap();
        let message_source = crate::collection_names::open(
            &mut pile,
            DEFAULT_SCOPE_ID,
            message_owner.verifying_key(),
        )
        .unwrap();
        let first_person = test_id(64);
        let second_person = test_id(65);
        pile.commit(
            relations_source,
            &relations_owner,
            relations::person_fragment(
                first_person,
                relations::ProfileInput {
                    label: "first".to_owned(),
                    ..Default::default()
                },
            )
            .unwrap()
            .0,
        )
        .unwrap();
        let (first, first_message) = message::message_fragment(
            first_person,
            &message::Recipient::Person(first_person),
            "first message",
            clock::point_now().unwrap(),
        );
        pile.commit(message_source, &message_owner, first).unwrap();
        // Each chain's own maintainer carries it, as the worker would.
        carry(&mut pile, &runtime, relations_source, &relations_owner);
        carry(&mut pile, &runtime, message_source, &message_owner);
        // Fresh raw records in both chains that nobody has carried yet.
        pile.commit(
            relations_source,
            &relations_owner,
            relations::person_fragment(
                second_person,
                relations::ProfileInput {
                    label: "second".to_owned(),
                    ..Default::default()
                },
            )
            .unwrap()
            .0,
        )
        .unwrap();
        let (second, second_message) = message::message_fragment(
            first_person,
            &message::Recipient::Person(first_person),
            "second message",
            clock::point_now().unwrap(),
        );
        pile.commit(message_source, &message_owner, second).unwrap();
        let records = |pile: &mut FacultyStore| {
            pile.snapshot()
                .unwrap()
                .records()
                .unwrap()
                .map(|record| record.unwrap())
                .collect::<BTreeSet<_>>()
        };
        let before = records(&mut pile);

        // A read sees only what was carried, in both chains.
        let (_, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &message_owner,
                relations_source,
                message_source,
                ViewIntent::Read,
            ))
            .unwrap();
        assert_eq!(
            relations::person_anchors(&relation_facts),
            BTreeSet::from([first_person])
        );
        assert_eq!(
            message::load_message_rows(&message_facts)
                .unwrap()
                .iter()
                .map(|row| row.id)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([first_message])
        );
        assert_eq!(records(&mut pile), before, "a read publishes nothing");

        // An edit by the Message owner maintains the Message chain first, so
        // it sees the fresh message; persona lookup is a read for every
        // operation, so the fresh person waits for the Relations maintainer.
        let (_, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &message_owner,
                relations_source,
                message_source,
                ViewIntent::Edit,
            ))
            .unwrap();
        assert_eq!(
            relations::person_anchors(&relation_facts),
            BTreeSet::from([first_person])
        );
        assert_eq!(
            message::load_message_rows(&message_facts)
                .unwrap()
                .iter()
                .map(|row| row.id)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([first_message, second_message])
        );
        assert!(
            records(&mut pile) != before,
            "an edit maintains the Message chain"
        );
        // Once the Relations maintainer carries the fresh person, the same
        // read sees it.
        carry(&mut pile, &runtime, relations_source, &relations_owner);
        let (_, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &message_owner,
                relations_source,
                message_source,
                ViewIntent::Read,
            ))
            .unwrap();
        assert_eq!(
            relations::person_anchors(&relation_facts),
            BTreeSet::from([first_person, second_person])
        );
        assert_eq!(
            message::load_message_rows(&message_facts)
                .unwrap()
                .iter()
                .map(|row| row.id)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([first_message, second_message])
        );
        pile.close().unwrap();
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
    fn group_name_acquisition_errors_identify_snapshot_message_and_handle() {
        let group = test_id(13);
        let (relations, snapshot) =
            relations::group_create_fragment(group, "unavailable group name").unwrap();
        let name = relations::group_snapshot(relations.facts(), snapshot)
            .unwrap()
            .name;
        let (envelope, id) = message::message_fragment(
            test_id(14),
            &message::Recipient::Group {
                anchor: group,
                snapshot,
                basis: crate::schemas::message::GROUP_SNAPSHOT_BASIS_WITNESSED,
            },
            "not the unavailable attachment",
            (Epoch::from_tai_seconds(0.0), Epoch::from_tai_seconds(0.0))
                .try_to_inline()
                .unwrap(),
        );
        let row = message::row_by_id(envelope.facts(), id).unwrap();
        for failure in [None, Some(io::ErrorKind::TimedOut)] {
            let mut store = AcquiringPile::new(MemoryBlobStore::new());
            store.failure = failure;
            let error = pollster::block_on(recipient_label(&mut store, relations.facts(), &row))
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("read name of group snapshot {snapshot:x} for Message {id:x}")
            );
            let report = format!("{error:#}");
            assert!(report.contains(&format!("blake3:{}", hex::encode(name.raw))));
            assert!(!report.contains("read body of Message"));
            match failure {
                None => {
                    assert!(report.contains("Message text is unavailable"));
                    assert!(error.downcast_ref::<io::Error>().is_none());
                }
                Some(kind) => {
                    assert!(report.contains("acquire Message text"));
                    assert!(!report.contains("Message text is unavailable"));
                    assert_eq!(error.downcast_ref::<io::Error>().unwrap().kind(), kind);
                }
            }
            assert_eq!(store.requested, vec![name.transmute()]);
        }
    }

    #[test]
    fn list_body_decode_error_identifies_message_and_handle() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut pile = storage::open_store(file.path()).unwrap();
        let runtime = storage::runtime().unwrap();
        let owner = SigningKey::from_bytes(&[98; 32]);
        let relations_source = crate::collection_names::open(
            &mut pile,
            DEFAULT_RELATIONS_SCOPE_ID,
            owner.verifying_key(),
        )
        .unwrap();
        let message_source =
            crate::collection_names::open(&mut pile, DEFAULT_SCOPE_ID, owner.verifying_key())
                .unwrap();
        let person = test_id(15);
        pile.commit(
            relations_source,
            &owner,
            relations::person_fragment(
                person,
                relations::ProfileInput {
                    label: "reader".to_owned(),
                    ..Default::default()
                },
            )
            .unwrap()
            .0,
        )
        .unwrap();
        // Keep the malformed body resident: this exercises the real list
        // caller without starting the lazy network host or changing visibility.
        let bytes: Inline<inlineencodings::Handle<UnknownBlob>> =
            pile.put(Bytes::from_source(vec![0xff_u8])).unwrap();
        let body: TextHandle = bytes.transmute();
        let envelope = message::envelope_fragment(
            person,
            person,
            body,
            clock::point_now().unwrap(),
            None,
            None,
        );
        let id = envelope.root().unwrap();
        pile.commit(message_source, &owner, envelope).unwrap();
        carry(&mut pile, &runtime, relations_source, &owner);
        let (snapshot, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &owner,
                relations_source,
                message_source,
                ViewIntent::Edit,
            ))
            .unwrap();
        let mut input = MessageStorage {
            pile: &mut pile,
            signer: &owner,
            collection: message_source,
            reader: &snapshot,
            messages: &message_facts,
            relations: &relation_facts,
        };
        let error = runtime
            .block_on(list(&mut input, &ListOptions::new("reader")))
            .unwrap_err();
        assert_eq!(error.to_string(), format!("read body of Message {id:x}"));
        let report = format!("{error:#}");
        assert!(report.contains(&format!(
            "decode Message text blake3:{}",
            hex::encode(body.raw)
        )));
        assert!(!report.contains("Message text is unavailable"));
        assert!(!report.contains("group snapshot"));
        assert!(error.downcast_ref::<std::str::Utf8Error>().is_some());
        assert!(pile.health().started_at.is_none());
        pile.close().unwrap();
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
    fn acquisition_distinguishes_missing_failed_and_invalid_text() {
        let mut remote = MemoryBlobStore::new();
        let invalid = remote.insert(Blob::<blobencodings::UTF8String>::new(Bytes::from_source(
            vec![0xff_u8],
        )));
        let absent: TextHandle = "absent".to_blob().get_handle();
        let mut store = AcquiringPile::new(remote);

        let missing = pollster::block_on(acquire_text(&mut store, absent)).unwrap_err();
        assert_eq!(
            missing.to_string(),
            format!(
                "Message text is unavailable (blake3:{})",
                hex::encode(absent.raw)
            )
        );
        assert!(missing.downcast_ref::<io::Error>().is_none());

        store.failure = Some(io::ErrorKind::PermissionDenied);
        let failed = pollster::block_on(acquire_text(&mut store, absent)).unwrap_err();
        assert_eq!(
            failed.to_string(),
            format!("acquire Message text blake3:{}", hex::encode(absent.raw))
        );
        assert_eq!(
            failed.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            failed.root_cause().to_string(),
            "injected Message acquisition failure"
        );
        assert!(!format!("{failed:#}").contains("Message text is unavailable"));

        store.failure = None;
        let malformed = pollster::block_on(acquire_text(&mut store, invalid)).unwrap_err();
        assert_eq!(
            malformed.to_string(),
            format!("decode Message text blake3:{}", hex::encode(invalid.raw))
        );
        assert!(malformed.downcast_ref::<std::str::Utf8Error>().is_some());

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
            drop(store.pile.ensure(source, &signer).await.unwrap());
            drop(store.pile.maintain(succinct, &signer).await.unwrap());
            store.pile.maintain(rank9, &signer).await.unwrap()
        });
        let observed = before.collection(rank9).unwrap();
        let facts = observed.view::<FactArchive>().unwrap();
        let original_support = observed.support().unwrap().clone();
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
            message::resolve_person(reader, &facts, "original label")
        }))
        .unwrap();

        assert_eq!(outcome, relations::SelectorOutcome::Unique(person));
        assert_eq!(store.requested.len(), 1);
        assert_eq!(observed.support().unwrap(), &original_support);
        assert_eq!(original_support.len(), 1);
        let after = store.snapshot().unwrap();
        assert_eq!(source.admitted(&after).unwrap().len(), 2);
        assert_eq!(after.wants().unwrap().count(), 0);
    }

    #[test]
    fn reads_attach_the_resident_views_without_maintaining() {
        // A pure read never publishes maintenance records, even when a raw
        // COMMIT the maintenance worker has not carried yet is resident.
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut pile = storage::open_store(file.path()).unwrap();
        let runtime = storage::runtime().unwrap();
        let owner = SigningKey::from_bytes(&[93; 32]);
        let relations_source = crate::collection_names::open(
            &mut pile,
            DEFAULT_RELATIONS_SCOPE_ID,
            owner.verifying_key(),
        )
        .unwrap();
        let message_source =
            crate::collection_names::open(&mut pile, DEFAULT_SCOPE_ID, owner.verifying_key())
                .unwrap();
        let mut selectors = BTreeSet::new();
        for source in [relations_source, message_source] {
            let policy = source.policy(&pile.snapshot().unwrap()).unwrap();
            let succinct = pile
                .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
                .unwrap();
            let rank9 = pile
                .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
                .unwrap();
            for handle in [source.handle(), succinct.handle(), rank9.handle()] {
                selectors.insert(CollectionRecordSelector::Collection(handle));
            }
        }
        let sender = test_id(63);
        let recipient = test_id(64);
        let mut people = relations::person_fragment(
            sender,
            relations::ProfileInput {
                label: "sender".to_owned(),
                ..Default::default()
            },
        )
        .unwrap()
        .0;
        people += relations::person_fragment(
            recipient,
            relations::ProfileInput {
                label: "reader".to_owned(),
                ..Default::default()
            },
        )
        .unwrap()
        .0;
        pile.commit(relations_source, &owner, people).unwrap();
        let (first, first_id) = message::message_fragment(
            sender,
            &message::Recipient::Person(recipient),
            "maintained message",
            clock::point_now().unwrap(),
        );
        pile.commit(message_source, &owner, first).unwrap();
        // The worker carries both chains once.
        carry(&mut pile, &runtime, relations_source, &owner);
        carry(&mut pile, &runtime, message_source, &owner);
        // A raw COMMIT nobody has carried yet.
        let (second, second_id) = message::message_fragment(
            sender,
            &message::Recipient::Person(recipient),
            "fresh raw message",
            clock::point_now().unwrap(),
        );
        pile.commit(message_source, &owner, second).unwrap();
        let before = pile
            .snapshot()
            .unwrap()
            .select_records(&selectors)
            .unwrap()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let bytes_before = std::fs::metadata(file.path()).unwrap().len();
        let (_, _relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &owner,
                relations_source,
                message_source,
                ViewIntent::Read,
            ))
            .unwrap();
        let after = pile
            .snapshot()
            .unwrap()
            .select_records(&selectors)
            .unwrap()
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            before, after,
            "a read must publish no DERIVE or MERGE record"
        );
        // Descriptor registration is idempotent: with the descriptors already
        // resident, a read appends nothing to the pile at all.
        assert_eq!(
            std::fs::metadata(file.path()).unwrap().len(),
            bytes_before,
            "a read after registration must not append to the pile"
        );
        assert!(
            message::row_by_id(&message_facts, first_id).is_ok(),
            "the maintained message stays readable"
        );
        // The pure read sees the rollup as it stands; the fresh raw COMMIT
        // waits for the maintenance worker, for an edit exactly as for a read.
        assert!(message::row_by_id(&message_facts, second_id).is_err());
        carry(&mut pile, &runtime, message_source, &owner);
        let (_, _relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &owner,
                relations_source,
                message_source,
                ViewIntent::Edit,
            ))
            .unwrap();
        assert!(message::row_by_id(&message_facts, first_id).is_ok());
        assert!(
            message::row_by_id(&message_facts, second_id).is_ok(),
            "the carried message is readable by the same view"
        );
        pile.close().unwrap();
    }
}
