//! Shared collection-native Message model and semantics.
//!
//! This module is the single semantic boundary used by the Message CLI and by
//! observers such as Orient. It owns exact envelope/read validation, typed
//! recipient selection, intrinsic read identity, and delivery against frozen
//! Relations group snapshots. Presentation and command workflows stay in the
//! binaries.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
use triblespace::macros::{find, pattern};
use triblespace::prelude::*;

use crate::relations::{self, IdentityComponents, SelectorOutcome};
use crate::schemas::message::{
    local, GROUP_SNAPSHOT_BASES, GROUP_SNAPSHOT_BASIS_WITNESSED, KIND_MESSAGE_ID, KIND_READ_ID,
};
use crate::schemas::relations::KIND_GROUP_SNAPSHOT;

pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
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
    Forked(Vec<Id>),
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
            Self::Forked(ids) => bail!(
                "recipient selector '{input}' touches forked state on: {}",
                format_ids(&ids)
            ),
            Self::Invalid(reason) => bail!("invalid recipient selector '{input}': {reason}"),
        }
    }
}

/// One complete immutable message envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageRow {
    pub id: Id,
    pub from: Id,
    pub to: Id,
    pub body: TextHandle,
    pub created_at: IntervalValue,
    pub group_snapshot: Option<Id>,
    pub group_snapshot_basis: Option<Id>,
}

/// One canonical intrinsic `(message, reader)` acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadRow {
    pub id: Id,
    pub message: Id,
    pub reader: Id,
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

fn exactly_one<T>(entity: Id, field: &str, values: Vec<T>) -> Result<T> {
    let count = values.len();
    let mut values = values.into_iter();
    match (values.next(), count) {
        (Some(value), 1) => Ok(value),
        _ => bail!(
            "Message entity {} has {count} values for {field}; expected exactly one",
            fmt_id(entity)
        ),
    }
}

fn at_most_one<T>(entity: Id, field: &str, values: Vec<T>) -> Result<Option<T>> {
    let count = values.len();
    let mut values = values.into_iter();
    match (values.next(), count) {
        (None, 0) => Ok(None),
        (Some(value), 1) => Ok(Some(value)),
        _ => bail!(
            "Message entity {} has {count} values for {field}; expected at most one",
            fmt_id(entity)
        ),
    }
}

fn point_interval(value: IntervalValue, entity: Id, field: &str) -> Result<()> {
    let (lower, upper): (i128, i128) = value
        .try_from_inline()
        .map_err(|error| anyhow!("decode {field} on Message entity {entity:x}: {error:?}"))?;
    if lower != upper {
        bail!("{field} on Message entity {entity:x} must be a point interval");
    }
    Ok(())
}

fn sorted_ids(values: impl IntoIterator<Item = Id>) -> Vec<Id> {
    let mut values: Vec<Id> = values.into_iter().collect();
    values.sort_unstable();
    values.dedup();
    values
}

fn selector_ids(outcome: &SelectorOutcome) -> Vec<Id> {
    match outcome {
        SelectorOutcome::Unique(id) => vec![*id],
        SelectorOutcome::Ambiguous(ids) | SelectorOutcome::Forked(ids) => ids.clone(),
        SelectorOutcome::Missing | SelectorOutcome::Invalid(_) => Vec::new(),
    }
}

pub fn resolve_person(
    reader: &PileReader,
    facts: &TribleSet,
    input: &str,
) -> Result<SelectorOutcome> {
    relations::resolve_person(reader, facts, input, false)
}

/// Resolve a recipient without erasing diagnostic state.
///
/// A label shared by a settled person and group is ambiguous: neither storage
/// kind gets an imperative tie-break. Any matching fork remains visible.
pub fn resolve_recipient(
    reader: &PileReader,
    facts: &TribleSet,
    input: &str,
) -> Result<RecipientOutcome> {
    let person = relations::resolve_person(reader, facts, input, false)?;
    let group = relations::resolve_group(reader, facts, input)?;

    if matches!(person, SelectorOutcome::Forked(_)) || matches!(group, SelectorOutcome::Forked(_)) {
        let mut candidates = selector_ids(&person);
        candidates.extend(selector_ids(&group));
        return Ok(RecipientOutcome::Forked(sorted_ids(candidates)));
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
            SelectorOutcome::Forked(_) => unreachable!("handled above"),
        }
        let snapshot = relations::current_group(facts, group_id)?;
        return Ok(RecipientOutcome::Unique(Recipient::Group {
            anchor: group_id,
            snapshot: snapshot.id,
            basis: GROUP_SNAPSHOT_BASIS_WITNESSED,
        }));
    }

    if matches!(group, SelectorOutcome::Ambiguous(_)) {
        let mut candidates = selector_ids(&group);
        candidates.extend(selector_ids(&person));
        return Ok(RecipientOutcome::Ambiguous(sorted_ids(candidates)));
    }

    match person {
        SelectorOutcome::Unique(id) => Ok(RecipientOutcome::Unique(Recipient::Person(id))),
        SelectorOutcome::Ambiguous(ids) => Ok(RecipientOutcome::Ambiguous(ids)),
        SelectorOutcome::Missing => match group {
            SelectorOutcome::Missing => Ok(RecipientOutcome::Missing),
            SelectorOutcome::Invalid(reason) => Ok(RecipientOutcome::Invalid(reason)),
            SelectorOutcome::Ambiguous(_)
            | SelectorOutcome::Forked(_)
            | SelectorOutcome::Unique(_) => unreachable!("handled above"),
        },
        SelectorOutcome::Invalid(reason) => match group {
            SelectorOutcome::Missing | SelectorOutcome::Invalid(_) => {
                Ok(RecipientOutcome::Invalid(reason))
            }
            SelectorOutcome::Ambiguous(_)
            | SelectorOutcome::Forked(_)
            | SelectorOutcome::Unique(_) => unreachable!("handled above"),
        },
        SelectorOutcome::Forked(_) => unreachable!("handled above"),
    }
}

/// Reconstruct one exact envelope over an already-staged body handle.
///
/// Migration may use a non-witnessed recognized basis; ordinary sends should
/// use [`message_fragment`] with a resolved [`Recipient`].
pub fn envelope_fragment(
    id: Id,
    from: Id,
    to: Id,
    body: TextHandle,
    created_at: IntervalValue,
    group_snapshot: Option<Id>,
    group_snapshot_basis: Option<Id>,
) -> Fragment {
    let mut fragment = entity! { ExclusiveId::force_ref(&id) @
        metadata::tag: &KIND_MESSAGE_ID,
        local::from: from,
        local::to: to,
        local::body: body,
        metadata::created_at: created_at,
    };
    if let Some(snapshot) = group_snapshot {
        fragment += entity! { ExclusiveId::force_ref(&id) @
            local::group_snapshot: snapshot,
        };
    }
    if let Some(basis) = group_snapshot_basis {
        fragment += entity! { ExclusiveId::force_ref(&id) @
            local::group_snapshot_basis: basis,
        };
    }
    fragment
}

/// Build a complete envelope and stage its body attachment.
pub fn message_fragment(
    id: Id,
    from: Id,
    recipient: &Recipient,
    body: &str,
    created_at: IntervalValue,
) -> Fragment {
    let mut fragment = Fragment::empty();
    let body = fragment.put(body.to_owned());
    fragment += envelope_fragment(
        id,
        from,
        recipient.anchor(),
        body,
        created_at,
        recipient.group_snapshot(),
        recipient.group_snapshot_basis(),
    );
    fragment
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

pub fn load_message_rows(facts: &TribleSet) -> Result<Vec<MessageRow>> {
    let ids = sorted_ids(find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_MESSAGE_ID }])
    ));
    ids.into_iter()
        .map(|id| {
            Ok(MessageRow {
                id,
                from: exactly_one(
                    id,
                    "local::from",
                    find!(value: Id, pattern!(facts, [{ id @ local::from: ?value }])).collect(),
                )?,
                to: exactly_one(
                    id,
                    "local::to",
                    find!(value: Id, pattern!(facts, [{ id @ local::to: ?value }])).collect(),
                )?,
                body: exactly_one(
                    id,
                    "local::body",
                    find!(value: TextHandle, pattern!(facts, [{ id @ local::body: ?value }]))
                        .collect(),
                )?,
                created_at: exactly_one(
                    id,
                    "metadata::created_at",
                    find!(value: IntervalValue, pattern!(facts, [{ id @ metadata::created_at: ?value }]))
                        .collect(),
                )?,
                group_snapshot: at_most_one(
                    id,
                    "local::group_snapshot",
                    find!(value: Id, pattern!(facts, [{ id @ local::group_snapshot: ?value }]))
                        .collect(),
                )?,
                group_snapshot_basis: at_most_one(
                    id,
                    "local::group_snapshot_basis",
                    find!(value: Id, pattern!(facts, [{ id @ local::group_snapshot_basis: ?value }]))
                        .collect(),
                )?,
            })
        })
        .collect()
}

pub fn load_read_rows(facts: &TribleSet) -> Result<Vec<ReadRow>> {
    let ids = sorted_ids(find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_READ_ID }])
    ));
    ids.into_iter()
        .map(|id| {
            Ok(ReadRow {
                id,
                message: exactly_one(
                    id,
                    "local::about_message",
                    find!(value: Id, pattern!(facts, [{ id @ local::about_message: ?value }]))
                        .collect(),
                )?,
                reader: exactly_one(
                    id,
                    "local::reader",
                    find!(value: Id, pattern!(facts, [{ id @ local::reader: ?value }])).collect(),
                )?,
            })
        })
        .collect()
}

fn validate_structure(facts: &TribleSet, relation_facts: &TribleSet) -> Result<Vec<TextHandle>> {
    let messages = load_message_rows(facts)?;
    let reads = load_read_rows(facts)?;
    let message_rows: BTreeMap<Id, MessageRow> =
        messages.iter().map(|row| (row.id, *row)).collect();
    let people = relations::person_anchors(relation_facts);
    let groups = relations::group_anchors(relation_facts);
    let group_snapshots: BTreeSet<Id> = find!(
        id: Id,
        pattern!(relation_facts, [{ ?id @ metadata::tag: &KIND_GROUP_SNAPSHOT }])
    )
    .collect();

    let mut expected = TribleSet::new();
    let mut bodies = Vec::with_capacity(messages.len());
    for row in messages {
        point_interval(row.created_at, row.id, "metadata::created_at")?;
        if !people.contains(&row.from) {
            bail!(
                "message {} names undeclared sender {}",
                fmt_id(row.id),
                fmt_id(row.from)
            );
        }
        let recipient_is_person = people.contains(&row.to);
        let recipient_is_group = groups.contains(&row.to);
        if recipient_is_person == recipient_is_group {
            bail!(
                "message {} recipient {} is not exactly one declared person or group",
                fmt_id(row.id),
                fmt_id(row.to)
            );
        }
        match (
            recipient_is_group,
            row.group_snapshot,
            row.group_snapshot_basis,
        ) {
            (false, None, None) => {}
            (false, _, _) => bail!(
                "direct message {} carries group-snapshot provenance",
                fmt_id(row.id)
            ),
            (true, None, _) | (true, _, None) => bail!(
                "group message {} requires both a frozen snapshot and its basis",
                fmt_id(row.id)
            ),
            (true, Some(snapshot), Some(basis)) => {
                if !GROUP_SNAPSHOT_BASES.contains(&basis) {
                    bail!(
                        "group message {} has unrecognized snapshot basis {}",
                        fmt_id(row.id),
                        fmt_id(basis)
                    );
                }
                if !group_snapshots.contains(&snapshot) {
                    bail!(
                        "group message {} names unknown Relations snapshot {}",
                        fmt_id(row.id),
                        fmt_id(snapshot)
                    );
                }
                let group = relations::group_snapshot(relation_facts, snapshot)?;
                if group.group != row.to {
                    bail!(
                        "group message {} snapshot {} belongs to group {}, not {}",
                        fmt_id(row.id),
                        fmt_id(snapshot),
                        fmt_id(group.group),
                        fmt_id(row.to)
                    );
                }
            }
        }
        expected += envelope_fragment(
            row.id,
            row.from,
            row.to,
            row.body,
            row.created_at,
            row.group_snapshot,
            row.group_snapshot_basis,
        )
        .facts()
        .clone();
        bodies.push(row.body);
    }

    let identities = IdentityComponents::from_facts(relation_facts)?;
    for row in reads {
        let message = message_rows.get(&row.message).ok_or_else(|| {
            anyhow!(
                "read marker {} names unknown message {}",
                fmt_id(row.id),
                fmt_id(row.message)
            )
        })?;
        if !people.contains(&row.reader) {
            bail!(
                "read marker {} names undeclared reader {}",
                fmt_id(row.id),
                fmt_id(row.reader)
            );
        }
        if !is_inbox_message(message, row.reader, relation_facts, &identities)? {
            bail!(
                "read marker {} reader {} is not eligible for message {} under its frozen inbox semantics",
                fmt_id(row.id),
                fmt_id(row.reader),
                fmt_id(row.message)
            );
        }
        let (core, expected_id) = read_core(row.message, row.reader);
        if expected_id != row.id {
            bail!(
                "read marker {} is not the intrinsic identity of message {} and reader {}",
                fmt_id(row.id),
                fmt_id(row.message),
                fmt_id(row.reader)
            );
        }
        expected += core.facts().clone();
        for observed_at in find!(
            value: IntervalValue,
            pattern!(facts, [{ row.id @ local::read_at: ?value }])
        ) {
            point_interval(observed_at, row.id, "local::read_at")?;
            expected += entity! { ExclusiveId::force_ref(&row.id) @
                local::read_at: observed_at,
            }
            .facts()
            .clone();
        }
    }

    if expected != *facts {
        let missing = expected.difference(facts).len();
        let unexpected = facts.difference(&expected).len();
        bail!(
            "Message catalog is not an exact canonical ontology ({missing} missing, {unexpected} unexpected facts)"
        );
    }
    Ok(bodies)
}

fn load_text_overlay<Overlay>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    handle: TextHandle,
) -> Result<String>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    if let Some(overlay) = overlay {
        if overlay
            .metadata(handle)
            .expect("memory metadata lookup is infallible")
            .is_some()
        {
            let view: anybytes::View<str> = overlay
                .get(handle)
                .with_context(|| format!("read staged Message body {}", hex::encode(handle.raw)))?;
            return Ok(view.to_string());
        }
    }
    let view: anybytes::View<str> = reader
        .get(handle)
        .with_context(|| format!("read Message body {}", hex::encode(handle.raw)))?;
    Ok(view.to_string())
}

fn validate_bodies<Overlay>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    bodies: Vec<TextHandle>,
) -> Result<()>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    let mut seen = HashSet::new();
    for handle in bodies {
        if seen.insert(handle.raw) {
            let _ = load_text_overlay(reader, overlay, handle)?;
        }
    }
    Ok(())
}

/// Read one validated message body.
pub fn read_body(reader: &PileReader, handle: TextHandle) -> Result<String> {
    load_text_overlay(reader, None::<&PileReader>, handle)
}

/// Validate a complete materialized Message catalog against the exact
/// Relations catalog from the same immutable pile snapshot.
pub fn validate_catalog(
    reader: &PileReader,
    facts: &TribleSet,
    relation_facts: &TribleSet,
) -> Result<()> {
    let bodies = validate_structure(facts, relation_facts)?;
    validate_bodies(reader, None::<&PileReader>, bodies)
}

/// Validate the exact would-be union before any staged body or signed COMMIT
/// byte is appended.
pub fn validate_catalog_union(
    reader: &PileReader,
    current: &TribleSet,
    fragment: &Fragment,
    relation_facts: &TribleSet,
) -> Result<TribleSet> {
    let mut union = current.clone();
    union += fragment.facts().clone();
    let bodies = validate_structure(&union, relation_facts)?;
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .reader()
        .expect("MemoryBlobStore reader creation is infallible");
    validate_bodies(reader, Some(&overlay), bodies)?;
    Ok(union)
}

pub fn resolve_message_id(facts: &TribleSet, prefix: &str) -> Result<Id> {
    let candidates = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_MESSAGE_ID }])
    );
    crate::resolve_id_prefix(prefix, candidates)
}

pub fn row_by_id(facts: &TribleSet, id: Id) -> Result<MessageRow> {
    load_message_rows(facts)?
        .into_iter()
        .find(|row| row.id == id)
        .ok_or_else(|| anyhow!("message {} disappeared from validated catalog", fmt_id(id)))
}

/// Decide frozen-snapshot inbox membership with settled same-person equality.
/// The exact sender and recipient anchors remain untouched for attribution.
pub fn is_inbox_message(
    row: &MessageRow,
    reader: Id,
    relation_facts: &TribleSet,
    identities: &IdentityComponents,
) -> Result<bool> {
    if identities.equivalent(row.from, reader)? {
        return Ok(false);
    }
    match row.group_snapshot {
        None => identities.equivalent(row.to, reader),
        Some(snapshot) => {
            let group = relations::group_snapshot(relation_facts, snapshot)?;
            for member in group.members {
                if identities.equivalent(member, reader)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

pub fn is_outgoing_message(
    row: &MessageRow,
    reader: Id,
    identities: &IdentityComponents,
) -> Result<bool> {
    identities.equivalent(row.from, reader)
}

/// Whether any canonical read marker belongs to the settled identity of
/// `reader` for this message.
pub fn is_read_by(
    reads: &[ReadRow],
    message: Id,
    reader: Id,
    identities: &IdentityComponents,
) -> Result<bool> {
    for read in reads.iter().filter(|read| read.message == message) {
        if identities.equivalent(read.reader, reader)? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    use crate::collection_access;
    use crate::schemas::relations::{
        DEFAULT_SCOPE_ID as DEFAULT_RELATIONS_SCOPE_ID, KIND_GROUP, KIND_PERSON_ID,
    };
    use hifitime::Epoch;

    fn test_id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn at_unix(seconds: f64) -> IntervalValue {
        let epoch = Epoch::from_unix_seconds(seconds);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn between_unix(lower: f64, upper: f64) -> IntervalValue {
        (
            Epoch::from_unix_seconds(lower),
            Epoch::from_unix_seconds(upper),
        )
            .try_to_inline()
            .unwrap()
    }

    fn person_anchor(person: Id) -> Fragment {
        entity! { ExclusiveId::force_ref(&person) @ metadata::tag: &KIND_PERSON_ID }
    }

    fn group_anchor(group: Id) -> Fragment {
        entity! { ExclusiveId::force_ref(&group) @ metadata::tag: &KIND_GROUP }
    }

    #[test]
    fn duplicate_identical_sends_are_distinct_occurrences() {
        let from = test_id(0x11);
        let to = Recipient::Person(test_id(0x12));
        let first = genid().id;
        let second = genid().id;
        assert_ne!(first, second);

        let first_fragment = message_fragment(first, from, &to, "same", at_unix(10.0));
        let second_fragment = message_fragment(second, from, &to, "same", at_unix(10.0));
        assert!(find!(
            id: Id,
            pattern!(first_fragment.facts(), [{ ?id @ metadata::tag: &KIND_MESSAGE_ID }])
        )
        .any(|id| id == first));
        assert!(find!(
            id: Id,
            pattern!(second_fragment.facts(), [{ ?id @ metadata::tag: &KIND_MESSAGE_ID }])
        )
        .any(|id| id == second));
        assert_ne!(first_fragment.facts(), second_fragment.facts());
    }

    #[test]
    fn settled_person_group_label_collision_is_ambiguous() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("messages.pile");
        let key = directory.path().join("messages.key");
        File::create(&pile).unwrap();
        collection_access::initialize_signer(&pile, Some(&key)).unwrap();

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
        collection_access::publish_fragment(
            &pile,
            Some(&key),
            DEFAULT_RELATIONS_SCOPE_ID,
            fragment,
            Fragment::empty(),
        )
        .unwrap();

        let signer = collection_access::load_signer(&pile, Some(&key)).unwrap();
        let allowed = HashSet::from([signer.verifying_key()]);
        let view =
            collection_access::materialize_scope(&pile, DEFAULT_RELATIONS_SCOPE_ID, &allowed)
                .unwrap();
        relations::validate_catalog(&view.reader, &view.facts).unwrap();
        assert_eq!(
            resolve_recipient(&view.reader, &view.facts, "shared").unwrap(),
            RecipientOutcome::Ambiguous(sorted_ids([person, group]))
        );
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
        assert_eq!(
            find!(
                at: IntervalValue,
                pattern!(union.facts(), [{ first_id @ local::read_at: ?at }])
            )
            .count(),
            2
        );
    }

    #[test]
    fn group_delivery_uses_frozen_snapshot_not_later_head() {
        let sender = test_id(0x31);
        let original_member = test_id(0x32);
        let later_member = test_id(0x33);
        let group = test_id(0x34);
        let mut relation_facts = TribleSet::new();
        for person in [sender, original_member, later_member] {
            relation_facts += person_anchor(person).facts().clone();
        }
        relation_facts += group_anchor(group).facts().clone();
        let old =
            relations::group_snapshot_fragment(group, "group", &[original_member], &[]).unwrap();
        let old_id = old.root().unwrap();
        relation_facts += old.facts().clone();
        let new =
            relations::group_snapshot_fragment(group, "group", &[later_member], &[old_id]).unwrap();
        relation_facts += new.facts().clone();

        let row = MessageRow {
            id: test_id(0x35),
            from: sender,
            to: group,
            body: "body".to_owned().to_blob().get_handle(),
            created_at: at_unix(13.0),
            group_snapshot: Some(old_id),
            group_snapshot_basis: Some(GROUP_SNAPSHOT_BASIS_WITNESSED),
        };
        let identities = IdentityComponents::from_facts(&relation_facts).unwrap();
        assert!(is_inbox_message(&row, original_member, &relation_facts, &identities).unwrap());
        assert!(!is_inbox_message(&row, later_member, &relation_facts, &identities).unwrap());

        let valid = envelope_fragment(
            row.id,
            row.from,
            row.to,
            row.body,
            row.created_at,
            row.group_snapshot,
            row.group_snapshot_basis,
        )
        .into_facts();
        validate_structure(&valid, &relation_facts).unwrap();
        let mut valid_read = valid.clone();
        valid_read += read_fragment(row.id, original_member, None)
            .0
            .facts()
            .clone();
        validate_structure(&valid_read, &relation_facts).unwrap();

        let mut stale_head_read = valid.clone();
        stale_head_read += read_fragment(row.id, later_member, None).0.facts().clone();
        let error = validate_structure(&stale_head_read, &relation_facts)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not eligible"), "{error}");

        let missing_basis = envelope_fragment(
            row.id,
            row.from,
            row.to,
            row.body,
            row.created_at,
            row.group_snapshot,
            None,
        )
        .into_facts();
        let error = validate_structure(&missing_basis, &relation_facts)
            .unwrap_err()
            .to_string();
        assert!(error.contains("requires both"), "{error}");

        let unknown_basis = envelope_fragment(
            row.id,
            row.from,
            row.to,
            row.body,
            row.created_at,
            row.group_snapshot,
            Some(test_id(0xFF)),
        )
        .into_facts();
        let error = validate_structure(&unknown_basis, &relation_facts)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unrecognized snapshot basis"), "{error}");
    }

    #[test]
    fn settled_same_identity_delivers_without_rewriting_attribution() {
        let sender = test_id(0x36);
        let addressed = test_id(0x37);
        let equivalent_reader = test_id(0x38);
        let mut relation_facts = TribleSet::new();
        for person in [sender, addressed, equivalent_reader] {
            relation_facts += person_anchor(person).facts().clone();
        }
        relation_facts +=
            relations::identity_verdict_fragment(addressed, equivalent_reader, true, &[])
                .unwrap()
                .facts()
                .clone();
        let row = MessageRow {
            id: test_id(0x39),
            from: sender,
            to: addressed,
            body: "body".to_owned().to_blob().get_handle(),
            created_at: at_unix(13.5),
            group_snapshot: None,
            group_snapshot_basis: None,
        };
        let identities = IdentityComponents::from_facts(&relation_facts).unwrap();
        assert!(is_inbox_message(&row, equivalent_reader, &relation_facts, &identities).unwrap());
        assert_eq!(row.from, sender);
        assert_eq!(row.to, addressed);

        let mut facts = envelope_fragment(
            row.id,
            row.from,
            row.to,
            row.body,
            row.created_at,
            None,
            None,
        )
        .into_facts();
        facts += read_fragment(row.id, equivalent_reader, None)
            .0
            .facts()
            .clone();
        validate_structure(&facts, &relation_facts).unwrap();
    }

    #[test]
    fn read_markers_reject_unrelated_readers_and_the_sender() {
        let sender = test_id(0x45);
        let recipient = test_id(0x46);
        let unrelated = test_id(0x47);
        let message = test_id(0x48);
        let mut relation_facts = TribleSet::new();
        for person in [sender, recipient, unrelated] {
            relation_facts += person_anchor(person).facts().clone();
        }
        let envelope = envelope_fragment(
            message,
            sender,
            recipient,
            "body".to_owned().to_blob().get_handle(),
            at_unix(13.75),
            None,
            None,
        )
        .into_facts();

        for reader in [unrelated, sender] {
            let mut facts = envelope.clone();
            facts += read_fragment(message, reader, None).0.facts().clone();
            let error = validate_structure(&facts, &relation_facts)
                .unwrap_err()
                .to_string();
            assert!(error.contains("not eligible"), "{error}");
        }
    }

    #[test]
    fn malformed_envelope_fails_instead_of_selecting_a_value() {
        let sender = test_id(0x41);
        let other_sender = test_id(0x42);
        let recipient = test_id(0x43);
        let message = test_id(0x44);
        let mut relation_facts = TribleSet::new();
        for person in [sender, other_sender, recipient] {
            relation_facts += person_anchor(person).facts().clone();
        }
        let body = "body".to_owned().to_blob().get_handle();
        let mut facts =
            envelope_fragment(message, sender, recipient, body, at_unix(14.0), None, None)
                .facts()
                .clone();
        facts += entity! { ExclusiveId::force_ref(&message) @ local::from: other_sender }
            .facts()
            .clone();

        let error = validate_structure(&facts, &relation_facts)
            .unwrap_err()
            .to_string();
        assert!(error.contains("local::from"), "{error}");
        assert!(error.contains("expected exactly one"), "{error}");
    }

    #[test]
    fn authored_chronology_requires_point_intervals() {
        let sender = test_id(0x51);
        let recipient = test_id(0x52);
        let message = test_id(0x53);
        let mut relation_facts = TribleSet::new();
        for person in [sender, recipient] {
            relation_facts += person_anchor(person).facts().clone();
        }

        let body = "body".to_owned().to_blob().get_handle();
        let envelope = envelope_fragment(
            message,
            sender,
            recipient,
            body,
            between_unix(15.0, 16.0),
            None,
            None,
        )
        .into_facts();
        let error = validate_structure(&envelope, &relation_facts)
            .unwrap_err()
            .to_string();
        assert!(error.contains("metadata::created_at"), "{error}");
        assert!(error.contains("point interval"), "{error}");

        let mut facts =
            envelope_fragment(message, sender, recipient, body, at_unix(15.0), None, None)
                .into_facts();
        facts += read_fragment(message, recipient, Some(between_unix(16.0, 17.0)))
            .0
            .facts()
            .clone();
        let error = validate_structure(&facts, &relation_facts)
            .unwrap_err()
            .to_string();
        assert!(error.contains("local::read_at"), "{error}");
        assert!(error.contains("point interval"), "{error}");
    }
}
