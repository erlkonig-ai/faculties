//! Typed finite Message operations over one frozen Message/Relations observation.
//! Text is literal; sender selection and output routing belong to the caller.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::clock;
use crate::collection_names::{configured_handle, open_configured, open_exact_in};
use crate::message::{self, IntervalValue};
use crate::relations::{self, IdentityComponents, TextHandle};
use crate::schemas::message::{local, DEFAULT_SCOPE_ID, KIND_MESSAGE_ID, KIND_READ_ID};
use crate::schemas::relations::{
    group as relation_group, DEFAULT_SCOPE_ID as DEFAULT_RELATIONS_SCOPE_ID,
};
use crate::storage::{self, FactArchive, FacultySnapshot, FacultyStore, Storage};
use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use itertools::Itertools;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::{Collection, CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::query::intersectionconstraint::and;
use triblespace::core::query::sortedsliceconstraint::SortedSlice;
use triblespace::core::query::temp;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::async_store::AsyncBlobStoreAcquire;
use triblespace::macros::{exists, find, pattern};
use triblespace::prelude::*;

/// A configured Message capability. Every call observes one frozen
/// Message/Relations view through its storage handle. Authorized operations
/// maintain both chains before selecting that view and carry newly published
/// Message facts before returning. A principal without derived WRITE still
/// reads the resident targets and may publish when it has source WRITE; no
/// operation manufactures a grant or mixes raw facts into an indexed view.
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

/// One envelope as this reader saw it. Every field is a column of the query
/// that selected it: nothing is loaded before a question is asked, and the
/// exact sender and recipient anchors stay as written even when delivery and
/// receipts use settled identity equivalence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageObservation {
    pub id: Id,
    pub from: Id,
    pub to: Id,
    pub created_at: IntervalValue,
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

/// The facts one operation queries: its frozen Rank9 view, for reads and
/// edits alike. Maintenance happens before selection and after publication,
/// never by mixing a later raw COMMIT into these facts.
type MessageFacts = FactArchive;

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
    async fn update<T>(
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
            maintain_fact_chain(self.pile, self.signer, self.collection, "Message")
                .await
                .context(
                    "Message fragment was committed, but maintaining its query views failed",
                )?;
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

/// The columns of one envelope these operations read. Nothing else is
/// selected, so a record carrying fields this reader does not model still
/// answers, and one that is missing a field it does model simply does not.
/// The columns of one envelope these operations read, including the exact
/// group snapshot that delivered it to this reader — `None` for a direct
/// send. The delivering snapshot is a column of the join that selected the
/// envelope, not a second lookup: an envelope naming two snapshots is
/// delivered by the one that names the reader, and only that one may name
/// the audience a listing shows.
pub(crate) type Envelope = (Id, Id, Id, message::TextHandle, IntervalValue, Option<Id>);

pub(crate) fn envelope_id(envelope: &Envelope) -> Id {
    envelope.0
}

/// Every anchor Relations has settled as this same person, ordered so a query
/// can join on it directly. An unobserved or contradictory component still
/// identifies its own anchor: settlement may widen who a reader is, but a
/// stranger's unsettled verdict never erases them.
pub(crate) fn settled_identity(identities: &IdentityComponents, person: Id) -> Vec<Id> {
    identities
        .component(person)
        .map(|component| component.into_iter().collect())
        .unwrap_or_else(|_| vec![person])
}

/// Envelopes delivered to one settled identity: addressed to it directly, or
/// carried by the Relations group snapshot frozen at send time that names it as
/// a member. Each arm is one join — the second across both views, on the
/// snapshot — and a sender's own envelope is outgoing, never inbox.
pub(crate) fn inbox<M, R>(message_facts: &M, relation_facts: &R, mine: &[Id]) -> Vec<Envelope>
where
    M: TriblePattern,
    R: TriblePattern,
{
    let direct = find!(
        (id: Id, from: Id, to: Id, body: message::TextHandle, created_at: IntervalValue),
        and!(
            SortedSlice::new_unchecked(mine).has(to),
            pattern!(message_facts, [{ ?id @
                metadata::tag: &KIND_MESSAGE_ID,
                local::from: ?from,
                local::to: ?to,
                local::body: ?body,
                metadata::created_at: ?created_at,
            }])
        )
    )
    .map(|(id, from, to, body, created_at)| (id, from, to, body, created_at, None));
    let delivered = find!(
        (
            id: Id,
            from: Id,
            to: Id,
            body: message::TextHandle,
            created_at: IntervalValue,
            snapshot: Id
        ),
        temp!(
            (member),
            and!(
                SortedSlice::new_unchecked(mine).has(member),
                pattern!(message_facts, [{ ?id @
                    metadata::tag: &KIND_MESSAGE_ID,
                    local::from: ?from,
                    local::to: ?to,
                    local::body: ?body,
                    metadata::created_at: ?created_at,
                    local::group_snapshot: ?snapshot,
                }]),
                pattern!(relation_facts, [{ ?snapshot @ relation_group::member: ?member }])
            )
        )
    )
    .map(|(id, from, to, body, created_at, snapshot)| {
        (id, from, to, body, created_at, Some(snapshot))
    });
    // Sending is a property of the envelope, not of one witness of it: if any
    // witness names this identity as the sender the envelope is outgoing, so
    // inbox and outbox stay disjoint by id however many senders are asserted.
    let sent: BTreeSet<Id> = outbox(message_facts, mine)
        .iter()
        .map(envelope_id)
        .collect();
    direct
        .chain(delivered)
        .filter(|envelope| !sent.contains(&envelope_id(envelope)))
        .collect()
}

/// Envelopes one settled identity sent.
pub(crate) fn outbox<M>(message_facts: &M, mine: &[Id]) -> Vec<Envelope>
where
    M: TriblePattern,
{
    find!(
        (id: Id, from: Id, to: Id, body: message::TextHandle, created_at: IntervalValue),
        and!(
            SortedSlice::new_unchecked(mine).has(from),
            pattern!(message_facts, [{ ?id @
                metadata::tag: &KIND_MESSAGE_ID,
                local::from: ?from,
                local::to: ?to,
                local::body: ?body,
                metadata::created_at: ?created_at,
            }])
        )
    )
    .map(|(id, from, to, body, created_at)| {
        // A sender's own envelope was not delivered *to* them, so its audience
        // is whatever snapshot it names.
        let snapshot = delivery_snapshot(message_facts, id);
        (id, from, to, body, created_at, snapshot)
    })
    .collect()
}

/// The exact audience an envelope was delivered to, when it was a group send.
fn delivery_snapshot<M>(message_facts: &M, message: Id) -> Option<Id>
where
    M: TriblePattern,
{
    find!(
        snapshot: Id,
        pattern!(message_facts, [{ message @ local::group_snapshot: ?snapshot }])
    )
    .next()
}

/// The envelopes among these witnesses that a sender selector accepts, reduced
/// to one id each. Witnesses are filtered *before* the reduction: an envelope
/// asserting two senders is selected when any of its witnesses matches, and
/// reducing first would let an unmatched witness hide it.
pub(crate) fn envelopes_from(envelopes: Vec<Envelope>, senders: Option<&[Id]>) -> Vec<Id> {
    envelopes
        .into_iter()
        .filter(|(_, sender, ..)| {
            senders.map_or(true, |senders| senders.binary_search(sender).is_ok())
        })
        .map(|envelope| envelope_id(&envelope))
        .unique()
        .collect()
}

/// Whether any canonical read marker about this envelope belongs to one of
/// these settled anchors. The first witness answers.
pub(crate) fn read_by<M>(message_facts: &M, message: Id, readers: &[Id]) -> bool
where
    M: TriblePattern,
{
    exists!(
        (reader: Id),
        and!(
            SortedSlice::new_unchecked(readers).has(reader),
            pattern!(message_facts, [{ _?marker @
                metadata::tag: &KIND_READ_ID,
                local::about_message: &message,
                local::reader: ?reader,
            }])
        )
    )
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

async fn recipient_label<S, P>(
    store: &mut S,
    facts: &P,
    message: Id,
    to: Id,
    delivered_through: Option<Id>,
) -> Result<String>
where
    S: AsyncBlobStoreAcquire,
    P: TriblePattern,
{
    match delivered_through {
        None => person_label(store, facts, to).await,
        Some(snapshot) => {
            let snapshot = relations::group_snapshot(facts, snapshot)?;
            acquire_text(store, snapshot.name).await.with_context(|| {
                format!(
                    "read name of group snapshot {:x} for Message {:x}",
                    snapshot.id, message
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
    storage
        .update("local message", |_, _| {
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
        .await
}

async fn ack(storage: &mut MessageStorage<'_>, id: &str, by: &str) -> Result<Acknowledgement> {
    let relation_facts = storage.relations;
    let reader_id = storage::read(storage.pile, storage.reader, |reader| {
        message::resolve_person(reader, relation_facts, by)?.require_unique("active person", by)
    })
    .await?;
    storage
        .update("local message read", |message_facts, relation_facts| {
            let identities = IdentityComponents::from_facts(relation_facts)?;
            let mine = settled_identity(&identities, reader_id);
            // The prefix resolves against exactly what this reader may
            // acknowledge, so an id outside that inbox never names a message.
            let delivered = inbox(message_facts, relation_facts, &mine);
            let message_id = crate::resolve_id_prefix(id, delivered.iter().map(envelope_id))?;
            if !delivered
                .iter()
                .any(|envelope| envelope_id(envelope) == message_id)
            {
                bail!(
                    "message {} is not in {}'s inbox",
                    fmt_id(message_id),
                    fmt_id(reader_id)
                );
            }
            let already_read = read_by(message_facts, message_id, &mine);
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
        .await
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
    storage
        .update(
            "local messages bulk read",
            |message_facts, relation_facts| {
                let identities = IdentityComponents::from_facts(relation_facts)?;
                let mine = settled_identity(&identities, reader_id);
                let senders = from.map(|sender| settled_identity(&identities, sender));
                let observed_at = clock::point_now()?;
                let mut fragment = Fragment::empty();
                let mut message_ids = Vec::new();
                for id in envelopes_from(
                    inbox(message_facts, relation_facts, &mine),
                    senders.as_deref(),
                ) {
                    if read_by(message_facts, id, &mine) {
                        continue;
                    }
                    fragment += message::read_fragment(id, reader_id, Some(observed_at)).0;
                    message_ids.push(id);
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
        .await
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
    let mine = settled_identity(&identities, reader_id);

    // Newest first, one entry per envelope: both views answer with a bag, so a
    // repeated field or a person settled across two anchors is one more witness
    // of the same envelope rather than another message. Inbox and outbox are
    // disjoint, because an envelope this reader sent is never delivered to it.
    let candidates: Vec<(bool, Envelope)> = inbox(message_facts, relation_facts, &mine)
        .into_iter()
        .map(|envelope| (true, envelope))
        .chain(
            outbox(message_facts, &mine)
                .into_iter()
                .map(|envelope| (false, envelope)),
        )
        .sorted_by(|(_, left), (_, right)| {
            interval_key(right.4)
                .cmp(&interval_key(left.4))
                .then_with(|| left.0.cmp(&right.0))
        })
        .unique_by(|(_, envelope)| envelope_id(envelope))
        .collect();

    let observed_at = clock::point_now()?;
    let mut entries = Vec::new();
    for (incoming, (id, from, to, body, created_at, delivered_through)) in candidates {
        if entries.len() >= options.limit {
            break;
        }
        let read = read_by(message_facts, id, &mine);
        if options.unread && !(incoming && !read) {
            continue;
        }
        let from_label = person_label(storage.pile, relation_facts, from).await?;
        let to_label =
            recipient_label(storage.pile, relation_facts, id, to, delivered_through).await?;
        let status = if incoming {
            if read {
                MessageStatus::Read
            } else {
                MessageStatus::Unread
            }
        } else if delivered_through.is_none()
            && read_by(message_facts, id, &settled_identity(&identities, to))
        {
            MessageStatus::ReadByRecipient
        } else {
            MessageStatus::Sent
        };
        let body = acquire_text(storage.pile, body)
            .await
            .with_context(|| format!("read body of Message {id:x}"))?;
        entries.push(MessageObservation {
            id,
            from,
            to,
            created_at,
            body,
            from_label,
            to_label,
            incoming,
            outgoing: !incoming,
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
                message_views(pile, signer, relations_source, message_source).await?;
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
) -> Result<(FacultySnapshot, MessageFacts, MessageFacts)> {
    let trace = std::env::var_os("MESSAGE_RESIDUAL_TRACE").is_some();
    let started = std::time::Instant::now();
    // Persona lookup needs the same eager observation as Message itself.
    // Each chain checks its own derived WRITE; neither inherits the other's
    // authority and source publication still checks source WRITE separately.
    let relations_rank9 = maintain_fact_chain(pile, signer, relations_source, "Relations").await?;
    let message_rank9 = maintain_fact_chain(pile, signer, message_source, "Message").await?;
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
            "views: prepared in {:.2?}, attached in {:.2?}",
            maintained_at,
            attached_at - maintained_at
        );
    }
    Ok((reader, relation_facts, message_facts))
}

async fn maintain_fact_chain(
    pile: &mut FacultyStore,
    signer: &SigningKey,
    source: Collection<SimpleArchive>,
    name: &'static str,
) -> Result<Collection<Rank9AcceleratedSuccinctArchiveBlob>> {
    let descriptors = pile
        .snapshot()
        .with_context(|| format!("freeze {name} source policy"))?;
    let policy = source
        .policy(&descriptors)
        .with_context(|| format!("read {name} source policy"))?;
    drop(descriptors);
    let succinct = pile
        .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
        .with_context(|| format!("register {name} Succinct collection"))?;
    let rank9 = pile
        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
        .with_context(|| format!("register {name} Rank9 collection"))?;
    let admitted = {
        let snapshot = pile
            .snapshot()
            .with_context(|| format!("freeze {name} WRITE admission"))?;
        let subject = signer.verifying_key();
        succinct
            .writer_is_admitted(&snapshot, subject)
            .map_err(|error| anyhow::anyhow!("check {name} Succinct WRITE admission: {error}"))?
            && rank9
                .writer_is_admitted(&snapshot, subject)
                .map_err(|error| anyhow::anyhow!("check {name} Rank9 WRITE admission: {error}"))?
    };
    // One-edge maintenance uses resident immediate-source inputs, never an
    // acquisition of a cold root just to read a warm target. A signer without
    // derived WRITE keeps the resident-view/source-publication fallback.
    if admitted {
        drop(
            pile.maintain(succinct, signer)
                .await
                .with_context(|| format!("maintain {name} Succinct collection"))?,
        );
        drop(
            pile.maintain(rank9, signer)
                .await
                .with_context(|| format!("maintain {name} Rank9 collection"))?,
        );
    }
    Ok(rank9)
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

    /// Every envelope this view answers with, asked the way the operations ask:
    /// a typed pattern over the attributes, never a catalog.
    fn visible<M>(message_facts: &M) -> BTreeSet<Id>
    where
        M: TriblePattern,
    {
        find!(
            id: Id,
            pattern!(message_facts, [{ ?id @ metadata::tag: &KIND_MESSAGE_ID }])
        )
        .collect()
    }

    /// Fixture preparation by a principal admitted to both derived targets.
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
        // Prepare the resident views before the non-writer observes them.
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
            // The observer lacks derived WRITE, so it sees resident views,
            // not the newer raw records it is not authorized to carry.
            let (snapshot, relation_facts, message_facts) = runtime
                .block_on(message_views(
                    &mut pile,
                    &observer,
                    relations_source,
                    message_source,
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
            assert_eq!(result.entries[0].id, first_id);
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
        runtime
            .block_on(input.update("no-op", |_, _| Ok((None, ()))))
            .unwrap();
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
        // The owner carries its receipt before returning; acknowledging the
        // same observed receipt again is a no-op that publishes nothing.
        let (snapshot, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &owner,
                relations_source,
                message_source,
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
                .find(|entry| entry.id == first_id)
                .unwrap()
                .status,
            MessageStatus::Read
        );
        assert_eq!(
            result
                .entries
                .iter()
                .find(|entry| entry.id == second_id)
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
                .find(|entry| entry.id == sent.id)
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
        assert_eq!(listed.entries[0].id, first_id);
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
    fn reads_maintain_each_chain_only_with_its_own_write_authority() {
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

        // The Message owner eagerly carries Message even for a read, but
        // cannot carry Relations using its unrelated Message authority.
        let (_, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &message_owner,
                relations_source,
                message_source,
            ))
            .unwrap();
        assert_eq!(
            relations::person_anchors(&relation_facts),
            BTreeSet::from([first_person])
        );
        assert_eq!(
            visible(&message_facts),
            BTreeSet::from([first_message, second_message])
        );
        let maintained = records(&mut pile);
        assert_ne!(maintained, before, "the read maintains Message");

        // Repeating the same read is idempotent; Relations still waits for a
        // principal authorized to carry that chain.
        let (_, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &message_owner,
                relations_source,
                message_source,
            ))
            .unwrap();
        assert_eq!(
            relations::person_anchors(&relation_facts),
            BTreeSet::from([first_person])
        );
        assert_eq!(
            visible(&message_facts),
            BTreeSet::from([first_message, second_message])
        );
        assert_eq!(records(&mut pile), maintained);
        // Once the Relations maintainer carries the fresh person, the same
        // read sees it.
        carry(&mut pile, &runtime, relations_source, &relations_owner);
        let (_, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &message_owner,
                relations_source,
                message_source,
            ))
            .unwrap();
        assert_eq!(
            relations::person_anchors(&relation_facts),
            BTreeSet::from([first_person, second_person])
        );
        assert_eq!(
            visible(&message_facts),
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
        let mut store = AcquiringPile::new(remote.into_inner().blobs);
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
        let identities = IdentityComponents::from_facts(relations.facts()).unwrap();
        let mine = settled_identity(&identities, reader);
        let delivered = inbox(envelope.facts(), relations.facts(), &mine);
        assert_eq!(
            delivered.iter().map(envelope_id).collect::<Vec<_>>(),
            vec![id]
        );
        assert!(outbox(envelope.facts(), &mine).is_empty());
        let (_, from, to, body, _, snapshot) = delivered[0];
        assert_eq!(snapshot, None, "a direct send is delivered by no snapshot");
        let mut store = AcquiringPile::new(envelope.blobs().clone());

        assert_eq!(
            pollster::block_on(person_label(&mut store, relations.facts(), from)).unwrap(),
            format!("{sender:x} [profile unavailable]")
        );
        assert!(store.requested.is_empty());
        assert_eq!(
            pollster::block_on(acquire_text(&mut store, body)).unwrap(),
            "visible inbox body"
        );
        // The unobserved sender keeps its exact anchor; delivery equivalence
        // never rewrites attribution.
        assert_eq!((from, to), (sender, reader));
        assert_eq!(store.requested, vec![body.transmute()]);
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
        fragment += message;
        fragment +=
            relations::group_snapshot_fragment(group, "renamed group", &[], &[original]).unwrap();
        let mut store = AcquiringPile::new(fragment.blobs().clone());

        assert_eq!(
            pollster::block_on(recipient_label(
                &mut store,
                fragment.facts(),
                id,
                group,
                Some(original)
            ))
            .unwrap(),
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
        let (_envelope, id) = message::message_fragment(
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
        for failure in [None, Some(io::ErrorKind::TimedOut)] {
            let mut store = AcquiringPile::new(MemoryBlobStore::new());
            store.failure = failure;
            let error = pollster::block_on(recipient_label(
                &mut store,
                relations.facts(),
                id,
                group,
                Some(snapshot),
            ))
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
    fn reads_eagerly_maintain_authorized_message_and_relations_chains() {
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
        // Start with a carried view, then append facts no worker has seen.
        carry(&mut pile, &runtime, relations_source, &owner);
        carry(&mut pile, &runtime, message_source, &owner);
        let (_old_reader, old_relations, old_messages) = runtime
            .block_on(message_views(
                &mut pile,
                &owner,
                relations_source,
                message_source,
            ))
            .unwrap();
        let later_person = test_id(65);
        pile.commit(
            relations_source,
            &owner,
            relations::person_fragment(
                later_person,
                relations::ProfileInput {
                    label: "new person".to_owned(),
                    ..Default::default()
                },
            )
            .unwrap()
            .0,
        )
        .unwrap();
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
        let (_, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &owner,
                relations_source,
                message_source,
            ))
            .unwrap();
        let after = pile
            .snapshot()
            .unwrap()
            .select_records(&selectors)
            .unwrap()
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert_ne!(before, after, "the read carries the resident source writes");
        assert!(after.difference(&before).all(|record| matches!(
            record,
            CollectionRecord::Derive(_) | CollectionRecord::Merge(_)
        )));
        assert_eq!(
            visible(&message_facts),
            BTreeSet::from([first_id, second_id])
        );
        assert!(relations::person_anchors(&relation_facts).contains(&later_person));
        assert_eq!(visible(&old_messages), BTreeSet::from([first_id]));
        assert!(!relations::person_anchors(&old_relations).contains(&later_person));
        assert_eq!(pile.snapshot().unwrap().wants().unwrap().count(), 0);
        assert!(pile.health().started_at.is_none());

        // Repeating the same authorized read has no new work to publish.
        let bytes_after = std::fs::metadata(file.path()).unwrap().len();
        let (_, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &owner,
                relations_source,
                message_source,
            ))
            .unwrap();
        assert_eq!(
            visible(&message_facts),
            BTreeSet::from([first_id, second_id])
        );
        assert!(relations::person_anchors(&relation_facts).contains(&later_person));
        assert_eq!(
            pile.snapshot()
                .unwrap()
                .select_records(&selectors)
                .unwrap()
                .into_iter()
                .collect::<BTreeSet<_>>(),
            after
        );
        assert_eq!(std::fs::metadata(file.path()).unwrap().len(), bytes_after);
        pile.close().unwrap();
    }

    #[test]
    fn sends_and_acknowledgements_finish_their_views_before_returning() {
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
        let policy = message_source.policy(&pile.snapshot().unwrap()).unwrap();
        let succinct = pile
            .derive::<SuccinctArchiveBlob>(message_source, (), policy.clone())
            .unwrap();
        let rank9 = pile
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
            .unwrap();
        let sender = test_id(81);
        let recipient = test_id(82);
        let mut people = Fragment::empty();
        for (person, label) in [(sender, "sender"), (recipient, "reader")] {
            people += relations::person_fragment(
                person,
                relations::ProfileInput {
                    label: label.to_owned(),
                    ..Default::default()
                },
            )
            .unwrap()
            .0;
        }
        pile.commit(relations_source, &owner, people).unwrap();
        // No external worker or fixture carry: preparing the operation must
        // first make the raw Relations names available to sender resolution.
        let (snapshot, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &owner,
                relations_source,
                message_source,
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
        let mut sent = Vec::new();
        for text in ["first eager message", "second eager message"] {
            sent.push(
                runtime
                    .block_on(send(
                        &mut input,
                        &SendOptions {
                            from: "sender",
                            to: "reader",
                            text,
                        },
                    ))
                    .unwrap()
                    .id,
            );
            // This is a passive target query, not another faculty call that
            // could repair an incomplete send before the assertion.
            let after = input.pile.snapshot().unwrap();
            let selected = after.collection(rank9).unwrap();
            let facts = selected.view::<FactArchive>().unwrap();
            assert_eq!(visible(&facts), sent.iter().copied().collect());
            assert_eq!(message_source.admitted(&after).unwrap().len(), sent.len());
        }
        assert!(
            visible(&message_facts).is_empty(),
            "the operation view stays frozen"
        );

        let (snapshot, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &owner,
                relations_source,
                message_source,
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
        let acknowledged = runtime
            .block_on(ack(&mut input, &fmt_id(sent[0]), "reader"))
            .unwrap();
        assert!(!acknowledged.already_read);
        let after = input.pile.snapshot().unwrap();
        let selected = after.collection(rank9).unwrap();
        let facts = selected.view::<FactArchive>().unwrap();
        assert!(read_by(&facts, sent[0], &[recipient]));
        assert!(!read_by(&facts, sent[1], &[recipient]));
        assert!(!read_by(&message_facts, sent[0], &[recipient]));

        let (snapshot, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &owner,
                relations_source,
                message_source,
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
        let acknowledged = runtime
            .block_on(ack_all(
                &mut input,
                &AckAllOptions {
                    by: "reader",
                    from: None,
                },
            ))
            .unwrap();
        assert_eq!(acknowledged.message_ids, vec![sent[1]]);
        let after = input.pile.snapshot().unwrap();
        let selected = after.collection(rank9).unwrap();
        let facts = selected.view::<FactArchive>().unwrap();
        assert!(sent.iter().all(|id| read_by(&facts, *id, &[recipient])));
        assert!(!read_by(&message_facts, sent[1], &[recipient]));
        assert_eq!(after.wants().unwrap().count(), 0);
        assert!(pile.health().started_at.is_none());
        pile.close().unwrap();
    }

    #[test]
    fn post_commit_maintenance_failure_names_the_already_published_fragment() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut pile = storage::open_store(file.path()).unwrap();
        let runtime = storage::runtime().unwrap();
        let owner = SigningKey::from_bytes(&[99; 32]);
        let relations_source = crate::collection_names::open(
            &mut pile,
            DEFAULT_RELATIONS_SCOPE_ID,
            owner.verifying_key(),
        )
        .unwrap();
        let message_source =
            crate::collection_names::open(&mut pile, DEFAULT_SCOPE_ID, owner.verifying_key())
                .unwrap();
        let (snapshot, relation_facts, message_facts) = runtime
            .block_on(message_views(
                &mut pile,
                &owner,
                relations_source,
                message_source,
            ))
            .unwrap();
        // This admitted but malformed input arrives after the operation's
        // frozen view. It cannot prevent the raw COMMIT; it does prevent
        // completing the subsequent Succinct maintenance.
        let raw: Inline<inlineencodings::Handle<UnknownBlob>> =
            pile.put(Bytes::from_source(vec![0_u8])).unwrap();
        let malformed: Inline<inlineencodings::Handle<SimpleArchive>> = raw.transmute();
        pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
            &owner,
            message_source.handle(),
            inlineencodings::Handle::<SimpleArchive>::to_hash(malformed),
            empty_metadata_handle(),
        )))
        .unwrap();
        let before = message_source.admitted(&pile.snapshot().unwrap()).unwrap();
        assert_eq!(before.len(), 1);
        let (fragment, id) = message::message_fragment(
            test_id(83),
            &message::Recipient::Person(test_id(84)),
            "the committed message survives its maintenance failure",
            clock::point_now().unwrap(),
        );
        let mut input = MessageStorage {
            pile: &mut pile,
            signer: &owner,
            collection: message_source,
            reader: &snapshot,
            messages: &message_facts,
            relations: &relation_facts,
        };
        let error = runtime
            .block_on(input.update("failure witness", |_, _| Ok((Some(fragment), id))))
            .unwrap_err();
        let text = format!("{error:#}");
        assert!(
            text.contains("Message fragment was committed, but maintaining its query views failed")
        );
        assert!(text.contains("maintain Message Succinct collection"));
        let after = pile.snapshot().unwrap();
        let admitted = message_source.admitted(&after).unwrap();
        assert_eq!(admitted.len(), before.len() + 1);
        assert!(admitted.contains(malformed));
        assert!(visible(&message_facts).is_empty());
        pile.close().unwrap();
    }

    fn at(seconds: f64) -> IntervalValue {
        let epoch = Epoch::from_tai_seconds(seconds);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn person_anchor(person: Id) -> TribleSet {
        entity! { ExclusiveId::force_ref(&person) @
            metadata::tag: &crate::schemas::relations::KIND_PERSON_ID
        }
        .into_facts()
    }

    fn test_body() -> message::TextHandle {
        "body".to_owned().to_blob().get_handle()
    }

    fn delivered_ids<M, R>(message_facts: &M, relation_facts: &R, mine: &[Id]) -> Vec<Id>
    where
        M: TriblePattern,
        R: TriblePattern,
    {
        inbox(message_facts, relation_facts, mine)
            .iter()
            .map(envelope_id)
            .collect()
    }

    /// Delivery is decided by the audience frozen into the envelope at send
    /// time, never by the group's later head.
    #[test]
    fn group_delivery_uses_the_frozen_snapshot_not_a_later_head() {
        let sender = test_id(0x31);
        let original_member = test_id(0x32);
        let later_member = test_id(0x33);
        let group = test_id(0x34);

        let mut relation_facts = TribleSet::new();
        for person in [sender, original_member, later_member] {
            relation_facts += person_anchor(person);
        }
        relation_facts += entity! { ExclusiveId::force_ref(&group) @
            metadata::tag: &crate::schemas::relations::KIND_GROUP
        }
        .into_facts();
        let old =
            relations::group_snapshot_fragment(group, "group", &[original_member], &[]).unwrap();
        let old_id = old.root().unwrap();
        relation_facts += old.into_facts();
        relation_facts +=
            relations::group_snapshot_fragment(group, "group", &[later_member], &[old_id])
                .unwrap()
                .into_facts();

        let envelope = message::envelope_fragment(
            sender,
            group,
            test_body(),
            at(13.0),
            Some(old_id),
            Some(crate::schemas::message::GROUP_SNAPSHOT_BASIS_WITNESSED),
        );
        let id = envelope.root().unwrap();
        let message_facts = envelope.into_facts();

        let identities = IdentityComponents::from_facts(&relation_facts).unwrap();
        assert_eq!(
            delivered_ids(
                &message_facts,
                &relation_facts,
                &settled_identity(&identities, original_member)
            ),
            vec![id]
        );
        assert!(delivered_ids(
            &message_facts,
            &relation_facts,
            &settled_identity(&identities, later_member)
        )
        .is_empty());
        assert_eq!(delivery_snapshot(&message_facts, id), Some(old_id));
    }

    /// People Relations has never observed still address each other. Their
    /// envelopes are simply not this reader's, and none of them is an error.
    #[test]
    fn unobserved_senders_do_not_poison_exact_inbox_membership() {
        let reader = test_id(0x70);
        let unknown_sender = test_id(0x71);
        let unknown_recipient = test_id(0x72);
        let relation_facts = person_anchor(reader);

        let mut message_facts = TribleSet::new();
        let mut ids = Vec::new();
        for (from, to, seconds) in [
            (unknown_sender, unknown_recipient, 15.0),
            (unknown_sender, reader, 14.0),
            (reader, unknown_recipient, 13.0),
        ] {
            let envelope =
                message::envelope_fragment(from, to, test_body(), at(seconds), None, None);
            ids.push(envelope.root().unwrap());
            message_facts += envelope.into_facts();
        }

        let identities = IdentityComponents::from_facts(&relation_facts).unwrap();
        let mine = settled_identity(&identities, reader);
        assert_eq!(
            delivered_ids(&message_facts, &relation_facts, &mine),
            vec![ids[1]]
        );
        assert_eq!(
            outbox(&message_facts, &mine)
                .iter()
                .map(envelope_id)
                .collect::<Vec<_>>(),
            vec![ids[2]]
        );
    }

    /// A receipt written by someone Relations has not observed neither marks
    /// the message read for another reader nor hides that reader's own receipt.
    #[test]
    fn unobserved_receipt_readers_neither_acknowledge_nor_hide_an_exact_reader() {
        let reader = test_id(0x73);
        let absent = test_id(0x74);
        let message = test_id(0x75);
        let relation_facts = person_anchor(reader);
        let identities = IdentityComponents::from_facts(&relation_facts).unwrap();
        let mine = settled_identity(&identities, reader);
        // An anchor with no Relations evidence still identifies itself.
        let theirs = settled_identity(&identities, absent);
        assert_eq!(theirs, vec![absent]);

        let mut message_facts = message::read_fragment(message, absent, None).0.into_facts();
        assert!(!read_by(&message_facts, message, &mine));
        assert!(read_by(&message_facts, message, &theirs));
        message_facts += message::read_fragment(message, reader, None).0.into_facts();
        assert!(read_by(&message_facts, message, &mine));
    }

    /// Settled same-person evidence widens who may read and acknowledge an
    /// envelope; it never rewrites the anchors the envelope names.
    #[test]
    fn settled_same_identity_delivers_without_rewriting_attribution() {
        let sender = test_id(0x36);
        let addressed = test_id(0x37);
        let equivalent_reader = test_id(0x38);
        let mut relation_facts = TribleSet::new();
        for person in [sender, addressed, equivalent_reader] {
            relation_facts += person_anchor(person);
        }
        relation_facts +=
            relations::identity_verdict_fragment(addressed, equivalent_reader, true, &[])
                .unwrap()
                .into_facts();

        let envelope =
            message::envelope_fragment(sender, addressed, test_body(), at(13.5), None, None);
        let id = envelope.root().unwrap();
        let message_facts = envelope.into_facts();

        let identities = IdentityComponents::from_facts(&relation_facts).unwrap();
        let mine = settled_identity(&identities, equivalent_reader);
        let delivered = inbox(&message_facts, &relation_facts, &mine);
        assert_eq!(
            delivered.iter().map(envelope_id).collect::<Vec<_>>(),
            vec![id]
        );
        let (_, from, to, ..) = delivered[0];
        assert_eq!((from, to), (sender, addressed));

        // The receipt one anchor writes answers for the whole settled person.
        let acknowledged = message::read_fragment(id, equivalent_reader, None)
            .0
            .into_facts();
        assert!(read_by(
            &acknowledged,
            id,
            &settled_identity(&identities, addressed)
        ));
    }

    /// The sender's own envelope is outgoing, so `ack` has nothing to mark and
    /// an unrelated person sees neither side of it.
    #[test]
    fn a_sender_never_finds_their_own_envelope_in_their_inbox() {
        let sender = test_id(0x45);
        let recipient = test_id(0x46);
        let unrelated = test_id(0x47);
        let mut relation_facts = TribleSet::new();
        for person in [sender, recipient, unrelated] {
            relation_facts += person_anchor(person);
        }
        let envelope =
            message::envelope_fragment(sender, recipient, test_body(), at(13.75), None, None);
        let id = envelope.root().unwrap();
        let message_facts = envelope.into_facts();

        let identities = IdentityComponents::from_facts(&relation_facts).unwrap();
        let mine = settled_identity(&identities, sender);
        assert!(delivered_ids(&message_facts, &relation_facts, &mine).is_empty());
        assert_eq!(
            outbox(&message_facts, &mine)
                .iter()
                .map(envelope_id)
                .collect::<Vec<_>>(),
            vec![id]
        );

        let stranger = settled_identity(&identities, unrelated);
        assert!(delivered_ids(&message_facts, &relation_facts, &stranger).is_empty());
        assert!(outbox(&message_facts, &stranger).is_empty());
    }

    /// Sending is a property of the envelope, not of one witness: an envelope
    /// that names this reader as a sender anywhere is outgoing, even when
    /// another witness names someone else, so inbox and outbox stay disjoint.
    #[test]
    fn a_second_sender_witness_does_not_put_my_own_envelope_in_my_inbox() {
        let me = test_id(0x50);
        let other_sender = test_id(0x51);
        let relation_facts = person_anchor(me) + person_anchor(other_sender);

        let envelope = message::envelope_fragment(me, me, test_body(), at(17.0), None, None);
        let id = envelope.root().unwrap();
        let mut message_facts = envelope.into_facts();
        message_facts +=
            entity! { ExclusiveId::force_ref(&id) @ local::from: other_sender }.into_facts();

        let identities = IdentityComponents::from_facts(&relation_facts).unwrap();
        let mine = settled_identity(&identities, me);
        assert!(
            delivered_ids(&message_facts, &relation_facts, &mine).is_empty(),
            "an envelope I am a sender of is never in my inbox"
        );
        assert_eq!(
            outbox(&message_facts, &mine)
                .iter()
                .map(envelope_id)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([id])
        );
    }

    /// An envelope naming two snapshots is delivered by the one that names the
    /// reader, and the row carries that snapshot so the audience a listing
    /// shows cannot come from the other one.
    #[test]
    fn the_delivering_snapshot_is_the_one_that_names_the_reader() {
        let sender = test_id(0x52);
        let member = test_id(0x53);
        let stranger = test_id(0x54);
        let group = test_id(0x55);
        let mut relation_facts =
            person_anchor(sender) + person_anchor(member) + person_anchor(stranger);
        relation_facts += entity! { ExclusiveId::force_ref(&group) @
            metadata::tag: &crate::schemas::relations::KIND_GROUP
        }
        .into_facts();
        let without =
            relations::group_snapshot_fragment(group, "without", &[stranger], &[]).unwrap();
        let without_id = without.root().unwrap();
        relation_facts += without.into_facts();
        let with =
            relations::group_snapshot_fragment(group, "with", &[member], &[without_id]).unwrap();
        let with_id = with.root().unwrap();
        relation_facts += with.into_facts();

        let envelope = message::envelope_fragment(
            sender,
            group,
            test_body(),
            at(18.0),
            Some(without_id),
            Some(crate::schemas::message::GROUP_SNAPSHOT_BASIS_WITNESSED),
        );
        let id = envelope.root().unwrap();
        let mut message_facts = envelope.into_facts();
        message_facts += entity! { ExclusiveId::force_ref(&id) @
            local::group_snapshot: with_id,
        }
        .into_facts();

        let identities = IdentityComponents::from_facts(&relation_facts).unwrap();
        let mine = settled_identity(&identities, member);
        let delivered = inbox(&message_facts, &relation_facts, &mine);
        assert_eq!(
            delivered.iter().map(envelope_id).collect::<Vec<_>>(),
            vec![id]
        );
        assert_eq!(
            delivered[0].5,
            Some(with_id),
            "the snapshot that delivered it, not the one it also names"
        );
    }

    /// `--from` selects an envelope when any witness names that sender, so a
    /// second sender witness cannot hide it behind the reduction.
    #[test]
    fn a_sender_selector_matches_any_witness_of_the_envelope() {
        let first = test_id(0x56);
        let second = test_id(0x57);
        let reader = test_id(0x58);
        let relation_facts = person_anchor(first) + person_anchor(second) + person_anchor(reader);

        let envelope = message::envelope_fragment(first, reader, test_body(), at(19.0), None, None);
        let id = envelope.root().unwrap();
        let mut message_facts = envelope.into_facts();
        message_facts += entity! { ExclusiveId::force_ref(&id) @ local::from: second }.into_facts();

        let identities = IdentityComponents::from_facts(&relation_facts).unwrap();
        let mine = settled_identity(&identities, reader);
        let delivered = inbox(&message_facts, &relation_facts, &mine);
        assert_eq!(delivered.len(), 2, "both senders witness the envelope");
        assert_eq!(envelopes_from(delivered.clone(), None), vec![id]);
        for sender in [first, second] {
            assert_eq!(
                envelopes_from(
                    delivered.clone(),
                    Some(&settled_identity(&identities, sender))
                ),
                vec![id],
                "selecting {sender:x} must find the envelope"
            );
        }
        let absent = settled_identity(&identities, test_id(0x59));
        assert!(envelopes_from(delivered, Some(&absent)).is_empty());
    }

    /// A second recipient naming another anchor of the same settled person is
    /// one more witness of one envelope. The query answers with a bag and the
    /// listing collapses it; nothing is rejected as malformed.
    #[test]
    fn a_repeated_recipient_is_one_more_witness_not_one_more_message() {
        let sender = test_id(0x39);
        let addressed = test_id(0x3A);
        let also_addressed = test_id(0x3B);
        let mut relation_facts = TribleSet::new();
        for person in [sender, addressed, also_addressed] {
            relation_facts += person_anchor(person);
        }
        relation_facts +=
            relations::identity_verdict_fragment(addressed, also_addressed, true, &[])
                .unwrap()
                .into_facts();

        let envelope =
            message::envelope_fragment(sender, addressed, test_body(), at(16.0), None, None);
        let id = envelope.root().unwrap();
        let mut message_facts = envelope.into_facts();
        message_facts +=
            entity! { ExclusiveId::force_ref(&id) @ local::to: also_addressed }.into_facts();

        let identities = IdentityComponents::from_facts(&relation_facts).unwrap();
        let mine = settled_identity(&identities, addressed);
        let delivered = inbox(&message_facts, &relation_facts, &mine);
        assert_eq!(delivered.len(), 2, "both recipients witness the envelope");
        assert_eq!(
            delivered
                .iter()
                .unique_by(|envelope| envelope_id(envelope))
                .count(),
            1,
            "and they are one message"
        );
    }
}
