//! Shared collection-native Message model and semantics.
//!
//! This module owns what the Message vocabulary *is*: the intrinsic identity
//! of one immutable envelope, the intrinsic `(message, reader)` acknowledgement,
//! and recipient selection against frozen Relations group snapshots. It holds no
//! catalog, no row type and no import validator: every question about the
//! collection is asked where it is used, as a `find!` over the typed attributes
//! in [`crate::schemas::message`]. Typed finite workflows live in [`operations`],
//! with explicit [`cli`] and [`mcp`] frontends.

pub mod cli;
pub mod mcp;
pub mod operations;
mod render;

pub use operations::{
    AckAllOptions, AcknowledgedMessages, Acknowledgement, ListOptions, Message, MessageList,
    MessageObservation, MessageStatus, SendOptions, SentMessage,
};

use anyhow::{bail, Context, Result};
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::*;

use crate::relations::{self, SelectorOutcome};
use crate::schemas::message::{
    local, GROUP_SNAPSHOT_BASIS_WITNESSED, KIND_MESSAGE_ID, KIND_READ_ID,
};

pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;
pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

/// One exact address selected from Relations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Recipient {
    Person(Id),
    Group { anchor: Id, snapshot: Id, basis: Id },
}

impl Recipient {
    pub fn anchor(&self) -> Id {
        match self {
            Self::Person(id) => *id,
            Self::Group { anchor, .. } => *anchor,
        }
    }

    pub fn group_snapshot(&self) -> Option<Id> {
        match self {
            Self::Person(_) => None,
            Self::Group { snapshot, .. } => Some(*snapshot),
        }
    }

    pub fn group_snapshot_basis(&self) -> Option<Id> {
        match self {
            Self::Person(_) => None,
            Self::Group { basis, .. } => Some(*basis),
        }
    }
}

/// Typed outcome of resolving a selector across people and groups.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecipientOutcome {
    Missing,
    Unique(Recipient),
    Ambiguous(Vec<Id>),
    /// At least one live candidate has an unsettled snapshot track. The two
    /// sides stay separate so the error can name the blocker and its kind
    /// instead of listing the union and leaving the reader to guess which of
    /// the two is actually broken.
    Forked {
        people: Vec<Id>,
        groups: Vec<Id>,
    },
    Invalid(String),
}

impl RecipientOutcome {
    /// Render an exact-selection requirement at a command boundary.
    pub fn require_unique(self, input: &str) -> Result<Recipient> {
        match self {
            Self::Unique(recipient) => Ok(recipient),
            Self::Missing => bail!("no person or group matches '{input}'"),
            Self::Ambiguous(ids) => {
                bail!("multiple recipients match '{input}': {}", format_ids(&ids))
            }
            Self::Forked { people, groups } => {
                let mut blockers = Vec::new();
                if !people.is_empty() {
                    blockers.push(format!(
                        "person {} (reconcile with `relations reconcile`)",
                        format_ids(&people)
                    ));
                }
                if !groups.is_empty() {
                    blockers.push(format!(
                        "group {} (reconcile with `relations group reconcile`)",
                        format_ids(&groups)
                    ));
                }
                bail!(
                    "cannot resolve recipient '{input}': unreconciled state on {}",
                    blockers.join("; ")
                )
            }
            Self::Invalid(reason) => bail!("invalid recipient selector '{input}': {reason}"),
        }
    }
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn format_ids(ids: &[Id]) -> String {
    ids.iter()
        .map(|id| fmt_id(*id))
        .collect::<Vec<_>>()
        .join(", ")
}

fn sorted_ids(values: impl IntoIterator<Item = Id>) -> Vec<Id> {
    let mut values: Vec<Id> = values.into_iter().collect();
    values.sort_unstable();
    values.dedup();
    values
}

/// The anchors of one side that actually block resolution, if any.
fn blocking_ids(outcome: &SelectorOutcome) -> Vec<Id> {
    match outcome {
        SelectorOutcome::Forked { forked, .. } => forked.clone(),
        _ => Vec::new(),
    }
}

pub fn resolve_person<Store, P>(reader: &Store, facts: &P, input: &str) -> Result<SelectorOutcome>
where
    Store: BlobStoreGet + ?Sized,
    P: TriblePattern,
{
    relations::resolve_person(reader, facts, input, false)
}

/// Resolve a recipient without erasing diagnostic state.
///
/// A label shared by a settled person and group is ambiguous: neither storage
/// kind gets an imperative tie-break. Any matching fork remains visible — but
/// only on a candidate that is genuinely in the running. `relations`
/// disqualifies retired people before it reports their fork state, so a dead
/// legacy anchor sharing a group's name can no longer veto the group.
pub fn resolve_recipient<Store, P>(
    reader: &Store,
    facts: &P,
    input: &str,
) -> Result<RecipientOutcome>
where
    Store: BlobStoreGet + ?Sized,
    P: TriblePattern,
{
    let person = relations::resolve_person(reader, facts, input, false)?;
    let group = relations::resolve_group(reader, facts, input)?;

    let forked_people = blocking_ids(&person);
    let forked_groups = blocking_ids(&group);
    if !forked_people.is_empty() || !forked_groups.is_empty() {
        return Ok(RecipientOutcome::Forked {
            people: forked_people,
            groups: forked_groups,
        });
    }

    if let SelectorOutcome::Unique(group_id) = group {
        match &person {
            SelectorOutcome::Unique(person_id) => {
                return Ok(RecipientOutcome::Ambiguous(sorted_ids([
                    *person_id, group_id,
                ])));
            }
            SelectorOutcome::Ambiguous(person_ids) => {
                let mut candidates = person_ids.clone();
                candidates.push(group_id);
                return Ok(RecipientOutcome::Ambiguous(sorted_ids(candidates)));
            }
            SelectorOutcome::Missing | SelectorOutcome::Invalid(_) => {}
            SelectorOutcome::Forked { .. } => unreachable!("handled above"),
        }
        let snapshot = relations::current_group(facts, group_id)?;
        return Ok(RecipientOutcome::Unique(Recipient::Group {
            anchor: group_id,
            snapshot: snapshot.id,
            basis: GROUP_SNAPSHOT_BASIS_WITNESSED,
        }));
    }

    if matches!(group, SelectorOutcome::Ambiguous(_)) {
        let mut candidates = group.candidates();
        candidates.extend(person.candidates());
        return Ok(RecipientOutcome::Ambiguous(sorted_ids(candidates)));
    }

    match person {
        SelectorOutcome::Unique(id) => Ok(RecipientOutcome::Unique(Recipient::Person(id))),
        SelectorOutcome::Ambiguous(ids) => Ok(RecipientOutcome::Ambiguous(ids)),
        SelectorOutcome::Missing => match group {
            SelectorOutcome::Missing => Ok(RecipientOutcome::Missing),
            SelectorOutcome::Invalid(reason) => Ok(RecipientOutcome::Invalid(reason)),
            SelectorOutcome::Ambiguous(_)
            | SelectorOutcome::Forked { .. }
            | SelectorOutcome::Unique(_) => unreachable!("handled above"),
        },
        SelectorOutcome::Invalid(reason) => match group {
            SelectorOutcome::Missing | SelectorOutcome::Invalid(_) => {
                Ok(RecipientOutcome::Invalid(reason))
            }
            SelectorOutcome::Ambiguous(_)
            | SelectorOutcome::Forked { .. }
            | SelectorOutcome::Unique(_) => unreachable!("handled above"),
        },
        SelectorOutcome::Forked { .. } => unreachable!("handled above"),
    }
}

/// Reconstruct one exact envelope over an already-staged body handle.
///
/// Migration may use a non-witnessed recognized basis; ordinary sends should
/// use [`message_fragment`] with a resolved [`Recipient`].
pub fn envelope_fragment(
    from: Id,
    to: Id,
    body: TextHandle,
    created_at: IntervalValue,
    group_snapshot: Option<Id>,
    group_snapshot_basis: Option<Id>,
) -> Fragment {
    entity! { _ @
        metadata::tag: &KIND_MESSAGE_ID,
        local::from: from,
        local::to: to,
        local::body: body,
        metadata::created_at: created_at,
        local::group_snapshot?: group_snapshot,
        local::group_snapshot_basis?: group_snapshot_basis,
    }
}

/// Build a complete envelope and stage its body attachment.
pub fn message_fragment(
    from: Id,
    recipient: &Recipient,
    body: &str,
    created_at: IntervalValue,
) -> (Fragment, Id) {
    let mut fragment = Fragment::empty();
    let body = fragment.put(body.to_owned());
    let envelope = envelope_fragment(
        from,
        recipient.anchor(),
        body,
        created_at,
        recipient.group_snapshot(),
        recipient.group_snapshot_basis(),
    );
    let id = envelope
        .root()
        .expect("canonical Message envelope has exactly one intrinsic root");
    fragment += envelope;
    (fragment, id)
}

fn read_core(message: Id, reader: Id) -> (Fragment, Id) {
    let fragment = entity! {
        metadata::tag: &KIND_READ_ID,
        local::about_message: message,
        local::reader: reader,
    };
    let id = fragment
        .root()
        .expect("canonical read fact has exactly one intrinsic root");
    (fragment, id)
}

/// Canonical intrinsic identity of the monotone `(message, reader)` fact.
pub fn read_id(message: Id, reader: Id) -> Id {
    read_core(message, reader).1
}

/// Build one canonical read fact with optional additive timestamp evidence.
pub fn read_fragment(
    message: Id,
    reader: Id,
    observed_at: Option<IntervalValue>,
) -> (Fragment, Id) {
    let (mut fragment, id) = read_core(message, reader);
    if let Some(observed_at) = observed_at {
        fragment += entity! { ExclusiveId::force_ref(&id) @
            local::read_at: observed_at,
        };
    }
    (fragment, id)
}

/// Read one message body from the snapshot that observed its handle.
pub fn read_body(reader: &PileSnapshot, handle: TextHandle) -> Result<String> {
    let view: anybytes::View<str> = reader
        .get(handle)
        .with_context(|| format!("read Message body {}", hex::encode(handle.raw)))?;
    Ok(view.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::fs::{self, File};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::collection_names::open_configured;
    use crate::schemas::message::DEFAULT_SCOPE_ID;
    use crate::schemas::relations::DEFAULT_SCOPE_ID as DEFAULT_RELATIONS_SCOPE_ID;
    use crate::storage::{discover_target, open_pile_strict, FactArchive};
    use crate::test_support::initialize_open_collection_fixture;
    use hifitime::Epoch;
    use triblespace::core::blob::encodings::succinctarchive::{
        Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
    };
    use triblespace::core::collection::{CollectionSnapshotExt, CollectionStoreExt};
    use triblespace::macros::{find, pattern};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "faculties-message-native-{}-{serial}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn at_unix(seconds: f64) -> IntervalValue {
        let epoch = Epoch::from_unix_seconds(seconds);
        (epoch, epoch).try_to_inline().unwrap()
    }

    #[test]
    fn identical_envelopes_have_one_intrinsic_identity() {
        let from = test_id(0x11);
        let to = Recipient::Person(test_id(0x12));
        let (first, first_id) = message_fragment(from, &to, "same", at_unix(10.0));
        let (second, second_id) = message_fragment(from, &to, "same", at_unix(10.0));
        assert_eq!(first_id, second_id);
        assert_eq!(first, second);

        let (_, later_id) = message_fragment(from, &to, "same", at_unix(11.0));
        assert_ne!(first_id, later_id);
    }

    #[test]
    fn settled_person_group_label_collision_is_ambiguous() {
        let person = test_id(0x15);
        let group = test_id(0x16);
        let (mut fragment, _, _) = relations::person_fragment(
            person,
            relations::ProfileInput {
                label: "shared".to_owned(),
                ..relations::ProfileInput::default()
            },
        )
        .unwrap();
        fragment += relations::group_create_fragment(group, "shared").unwrap().0;
        let facts = fragment.facts().clone();
        let reader = fragment.blobs_mut().snapshot().unwrap();
        relations::validate_catalog_union(&reader, &TribleSet::new(), &fragment).unwrap();
        assert_eq!(
            resolve_recipient(&reader, &facts, "shared").unwrap(),
            RecipientOutcome::Ambiguous(sorted_ids([person, group]))
        );
    }

    /// Regression for a broadcast outage: a shared selector died with a fork
    /// error naming the perfectly settled group because a retired person with
    /// the same label had a forked profile.
    #[test]
    fn a_retired_namesake_fork_does_not_veto_a_live_group() {
        let legacy = test_id(0x21);
        let group = test_id(0x22);

        let mut input = relations::ProfileInput {
            label: "legacy shared".to_owned(),
            ..relations::ProfileInput::default()
        };
        input.aliases = vec!["shared".to_owned()];
        let (mut fragment, profile_id, lifecycle_id) =
            relations::person_fragment(legacy, input).unwrap();

        // Two un-superseded profile heads, both still answering to the selector.
        for note in ["left", "right"] {
            fragment += relations::profile_fragment(
                legacy,
                relations::ProfileInput {
                    label: "legacy shared".to_owned(),
                    aliases: vec!["shared".to_owned()],
                    note: Some(note.to_owned()),
                    ..relations::ProfileInput::default()
                },
                &[profile_id],
            )
            .unwrap();
        }
        fragment += relations::lifecycle_fragment(legacy, true, &[lifecycle_id]);
        fragment += relations::group_create_fragment(group, "shared").unwrap().0;

        let facts = fragment.facts().clone();
        let reader = fragment.blobs_mut().snapshot().unwrap();
        relations::validate_catalog_union(&reader, &TribleSet::new(), &fragment).unwrap();
        assert!(matches!(
            relations::profile_head(&facts, legacy).unwrap(),
            relations::Head::Forked(_)
        ));

        let recipient = resolve_recipient(&reader, &facts, "shared")
            .unwrap()
            .require_unique("shared")
            .unwrap();
        assert_eq!(recipient.anchor(), group);
        assert_eq!(
            recipient.group_snapshot(),
            Some(relations::current_group(&facts, group).unwrap().id)
        );
    }

    /// The other half: a fork on a LIVE candidate must still fail closed, and
    /// the error must name that candidate and its kind rather than listing the
    /// union of both sides and leaving the reader to guess.
    #[test]
    fn a_live_forked_namesake_still_blocks_and_names_itself() {
        let person = test_id(0x23);
        let group = test_id(0x24);

        let (mut fragment, profile_id, _) = relations::person_fragment(
            person,
            relations::ProfileInput {
                label: "crew".to_owned(),
                ..relations::ProfileInput::default()
            },
        )
        .unwrap();
        for note in ["left", "right"] {
            fragment += relations::profile_fragment(
                person,
                relations::ProfileInput {
                    label: "crew".to_owned(),
                    note: Some(note.to_owned()),
                    ..relations::ProfileInput::default()
                },
                &[profile_id],
            )
            .unwrap();
        }
        fragment += relations::group_create_fragment(group, "crew").unwrap().0;

        let facts = fragment.facts().clone();
        let reader = fragment.blobs_mut().snapshot().unwrap();
        relations::validate_catalog_union(&reader, &TribleSet::new(), &fragment).unwrap();

        assert_eq!(
            resolve_recipient(&reader, &facts, "crew").unwrap(),
            RecipientOutcome::Forked {
                people: vec![person],
                groups: Vec::new(),
            }
        );
        let message = resolve_recipient(&reader, &facts, "crew")
            .unwrap()
            .require_unique("crew")
            .unwrap_err()
            .to_string();
        assert!(message.contains(&format!("person {person:x}")), "{message}");
        assert!(!message.contains(&format!("{group:x}")), "{message}");
    }

    #[test]
    fn repeated_reads_converge_on_one_intrinsic_marker() {
        let message = test_id(0x21);
        let reader = test_id(0x22);
        let (first, first_id) = read_fragment(message, reader, Some(at_unix(11.0)));
        let (second, second_id) = read_fragment(message, reader, Some(at_unix(12.0)));
        assert_eq!(first_id, second_id);
        assert_eq!(first_id, read_id(message, reader));

        let mut union = first;
        union += second;
        let markers: BTreeSet<Id> = find!(
            id: Id,
            pattern!(union.facts(), [{ ?id @ metadata::tag: &KIND_READ_ID }])
        )
        .collect();
        assert_eq!(markers, BTreeSet::from([first_id]));
        // Both observations survive as additive evidence about the one fact;
        // neither is selected as a winner.
        let observed: BTreeSet<[u8; 32]> = find!(
            at: IntervalValue,
            pattern!(union.facts(), [{ first_id @ local::read_at: ?at }])
        )
        .map(|at| at.raw)
        .collect();
        assert_eq!(observed.len(), 2);
    }

    /// Ids are opaque. A typed pattern selects every entity that carries the
    /// fields this reader models, including a legacy random-id envelope whose
    /// id authenticates nothing, and ignores facts it does not model.
    #[test]
    fn a_typed_pattern_keeps_opaque_ids_and_ignores_unrelated_facts() {
        let sender = test_id(0x48);
        let recipient = test_id(0x49);
        let body = "body".to_owned().to_blob().get_handle();
        let envelope = envelope_fragment(sender, recipient, body, at_unix(14.25), None, None);
        let intrinsic = envelope.root().unwrap();
        let legacy = test_id(0x4A);
        let unrelated = test_id(0x4C);

        let mut facts = envelope.into_facts();
        facts += entity! { ExclusiveId::force_ref(&legacy) @
            metadata::tag: &KIND_MESSAGE_ID,
            local::from: sender,
            local::to: recipient,
            local::body: body,
            metadata::created_at: at_unix(14.25),
        }
        .into_facts();
        facts += entity! { ExclusiveId::force_ref(&unrelated) @
            metadata::tag: &test_id(0x4D),
        }
        .into_facts();
        // An annotation nobody models must not hide the entity that carries it.
        facts += entity! { ExclusiveId::force_ref(&intrinsic) @
            metadata::description: "annotated after the fact",
        }
        .into_facts();

        let envelopes: BTreeSet<Id> = find!(
            (id: Id, from: Id, to: Id, body: TextHandle, created_at: IntervalValue),
            pattern!(&facts, [{ ?id @
                metadata::tag: &KIND_MESSAGE_ID,
                local::from: ?from,
                local::to: ?to,
                local::body: ?body,
                metadata::created_at: ?created_at,
            }])
        )
        .map(|(id, _, _, _, _)| id)
        .collect();
        assert_eq!(envelopes, BTreeSet::from([intrinsic, legacy]));
    }

    /// The schema cannot express cardinality and neither does the reader: a
    /// second `from` is one more witness, not a malformed record to reject.
    /// The consumer decides what to do with a bag; nothing fails here.
    #[test]
    fn a_repeated_field_yields_every_witness_instead_of_failing() {
        let sender = test_id(0x41);
        let other_sender = test_id(0x42);
        let recipient = test_id(0x43);
        let body = "body".to_owned().to_blob().get_handle();
        let envelope = envelope_fragment(sender, recipient, body, at_unix(14.0), None, None);
        let message = envelope.root().unwrap();
        let mut facts = envelope.into_facts();
        facts +=
            entity! { ExclusiveId::force_ref(&message) @ local::from: other_sender }.into_facts();

        let senders: BTreeSet<Id> = find!(
            (id: Id, from: Id),
            pattern!(&facts, [{ ?id @
                metadata::tag: &KIND_MESSAGE_ID,
                local::from: ?from,
            }])
        )
        .map(|(_, from)| from)
        .collect();
        assert_eq!(senders, BTreeSet::from([sender, other_sender]));
    }

    #[test]
    fn native_pile_publication_is_idempotent() {
        let directory = TestDirectory::new();
        let pile_path = directory.0.join("messages.pile");
        let key_path = directory.0.join("messages.key");
        File::create(&pile_path).unwrap();
        let signer = initialize_open_collection_fixture(&pile_path, Some(&key_path));

        let sender = test_id(0x51);
        let recipient = test_id(0x52);
        let (mut relations_fragment, _, _) = relations::person_fragment(
            sender,
            relations::ProfileInput {
                label: "sender".to_owned(),
                ..relations::ProfileInput::default()
            },
        )
        .unwrap();
        relations_fragment += relations::person_fragment(
            recipient,
            relations::ProfileInput {
                label: "recipient".to_owned(),
                ..relations::ProfileInput::default()
            },
        )
        .unwrap()
        .0;

        let mut pile = open_pile_strict(&pile_path).unwrap();
        let relations_collection = open_configured(
            &mut pile,
            DEFAULT_RELATIONS_SCOPE_ID,
            signer.verifying_key(),
        )
        .unwrap();
        pile.commit(relations_collection, &signer, relations_fragment)
            .unwrap();

        let team = signer.verifying_key();
        let messages =
            open_configured(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key()).unwrap();
        let policy = messages.policy(&pile.snapshot().unwrap()).unwrap();
        let succinct = pile
            .derive::<SuccinctArchiveBlob>(messages, (), policy.clone())
            .unwrap();
        let rank9 = pile
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
            .unwrap();
        let (fragment, message_id) = message_fragment(
            sender,
            &Recipient::Person(recipient),
            "one immutable envelope",
            at_unix(15.0),
        );

        let first = pile.commit(messages, &signer, fragment.clone()).unwrap();
        let second = pile.commit(messages, &signer, fragment).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            discover_target(&mut pile, DEFAULT_SCOPE_ID, team)
                .unwrap()
                .commits()
                .len(),
            1
        );
        let store_snapshot = pollster::block_on(async {
            drop(pile.ensure(messages, &signer).await.unwrap());
            drop(pile.maintain(succinct, &signer).await.unwrap());
            pile.maintain(rank9, &signer).await.unwrap()
        });
        let observed = store_snapshot.collection(rank9).unwrap();
        let message_facts = observed.view::<FactArchive>().unwrap();
        let published: BTreeSet<Id> = find!(
            id: Id,
            pattern!(&message_facts, [{ ?id @ metadata::tag: &KIND_MESSAGE_ID }])
        )
        .collect();
        assert_eq!(published, BTreeSet::from([message_id]));
        drop(message_facts);
        drop(observed);
        drop(store_snapshot);
        pile.close().unwrap();
    }
}
