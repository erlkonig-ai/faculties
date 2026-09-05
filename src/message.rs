//! Shared collection-native Message model and semantics.
//!
//! This module is the single semantic boundary used by the Message CLI and by
//! observers such as Orient. It owns typed envelope/read queries, explicit
//! import validation, recipient selection, intrinsic write construction, and
//! delivery against frozen Relations group snapshots. Presentation and command
//! workflows stay in the binaries.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::core::repo::{BlobStoreGet, BlobStoreMeta};
use triblespace::macros::{find, pattern};
use triblespace::prelude::*;

use crate::relations::{self, IdentityComponents, SelectorOutcome};
use crate::schemas::message::{
    local, GROUP_SNAPSHOT_BASES, GROUP_SNAPSHOT_BASIS_WITNESSED, KIND_MESSAGE_ID, KIND_READ_ID,
};
use crate::schemas::relations::KIND_GROUP_SNAPSHOT;

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

/// One canonical read marker together with all additive timestamp evidence.
///
/// Observations are a set, not competing scalar state. Consumers may summarize
/// them for presentation, but none is selected as the semantic winner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadReceiptRow {
    pub marker: ReadRow,
    pub observed_at: Vec<IntervalValue>,
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

fn message_identity_matches(facts: &TribleSet, id: Id) -> bool {
    let froms: Vec<Id> =
        find!(value: Id, pattern!(facts, [{ id @ local::from: ?value }])).collect();
    let tos: Vec<Id> = find!(value: Id, pattern!(facts, [{ id @ local::to: ?value }])).collect();
    let bodies: Vec<TextHandle> =
        find!(value: TextHandle, pattern!(facts, [{ id @ local::body: ?value }])).collect();
    let created_at: Vec<IntervalValue> = find!(
        value: IntervalValue,
        pattern!(facts, [{ id @ metadata::created_at: ?value }])
    )
    .collect();
    if froms.is_empty() || tos.is_empty() || bodies.is_empty() || created_at.is_empty() {
        return false;
    }

    // Include absence as a candidate even when an optional field is present.
    // This lets validation recognize an otherwise-canonical direct envelope
    // whose intrinsic id has been polluted with an appended optional fact,
    // and reject it as inexact instead of making the damaged entity vanish.
    let mut snapshots = vec![None];
    snapshots.extend(
        find!(value: Id, pattern!(facts, [{ id @ local::group_snapshot: ?value }])).map(Some),
    );
    let mut bases = vec![None];
    bases.extend(
        find!(value: Id, pattern!(facts, [{ id @ local::group_snapshot_basis: ?value }])).map(Some),
    );

    froms.iter().copied().any(|from| {
        tos.iter().copied().any(|to| {
            bodies.iter().copied().any(|body| {
                created_at.iter().copied().any(|created_at| {
                    snapshots.iter().copied().any(|snapshot| {
                        bases.iter().copied().any(|basis| {
                            envelope_fragment(from, to, body, created_at, snapshot, basis).root()
                                == Some(id)
                        })
                    })
                })
            })
        })
    })
}

fn read_identity_matches(facts: &TribleSet, id: Id) -> bool {
    let messages: Vec<Id> = find!(
        value: Id,
        pattern!(facts, [{ id @ local::about_message: ?value }])
    )
    .collect();
    let readers: Vec<Id> =
        find!(value: Id, pattern!(facts, [{ id @ local::reader: ?value }])).collect();
    messages.iter().copied().any(|message| {
        readers
            .iter()
            .copied()
            .any(|reader| read_id(message, reader) == id)
    })
}

fn entity_facts(facts: &TribleSet, id: Id) -> TribleSet {
    find!(
        (attribute: Id, value: Inline<UnknownInline>),
        pattern!(facts, [{ id @ ?attribute: ?value }])
    )
    .map(|(attribute, value)| {
        let mut raw = [0; 64];
        raw[..16].copy_from_slice(&id.raw());
        raw[16..32].copy_from_slice(&attribute.raw());
        raw[32..].copy_from_slice(&value.raw);
        Trible::force_raw(raw).expect("queried Message fact remains structurally valid")
    })
    .collect()
}

fn require_exact_native_entity(
    facts: &TribleSet,
    id: Id,
    expected: &TribleSet,
    label: &str,
) -> Result<()> {
    let actual = entity_facts(facts, id);
    if actual != *expected {
        let missing = expected.difference(&actual).len();
        let unexpected = actual.difference(expected).len();
        bail!(
            "canonical Message {label} {} is not exact ({missing} missing, {unexpected} unexpected facts)",
            fmt_id(id)
        );
    }
    Ok(())
}

/// Query every decodable Message envelope projection.
///
/// Entity ids are opaque and additional facts are open-world annotations. A
/// typed pattern therefore selects the fields this reader understands without
/// reconstructing an intrinsic id or scanning the entity's complete fact set.
pub fn load_message_rows<P>(facts: &P) -> Result<Vec<MessageRow>>
where
    P: TriblePattern,
{
    let mut cores: Vec<(Id, Id, Id, TextHandle, IntervalValue)> = find!(
        (id: Id, from: Id, to: Id, body: TextHandle, created_at: IntervalValue),
        pattern!(facts, [{ ?id @
            metadata::tag: &KIND_MESSAGE_ID,
            local::from: ?from,
            local::to: ?to,
            local::body: ?body,
            metadata::created_at: ?created_at,
        }])
    )
    .collect();
    cores.sort_unstable_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
            .then_with(|| left.3.raw.cmp(&right.3.raw))
            .then_with(|| left.4.raw.cmp(&right.4.raw))
    });
    cores.dedup();

    let mut rows = Vec::new();
    for (id, from, to, body, created_at) in cores {
        let mut snapshots: Vec<Option<Id>> = find!(
            snapshot: Id,
            pattern!(facts, [{ id @ local::group_snapshot: ?snapshot }])
        )
        .map(Some)
        .collect();
        if snapshots.is_empty() {
            snapshots.push(None);
        } else {
            snapshots.sort_unstable();
            snapshots.dedup();
        }
        let mut bases: Vec<Option<Id>> = find!(
            basis: Id,
            pattern!(facts, [{ id @ local::group_snapshot_basis: ?basis }])
        )
        .map(Some)
        .collect();
        if bases.is_empty() {
            bases.push(None);
        } else {
            bases.sort_unstable();
            bases.dedup();
        }
        for group_snapshot in &snapshots {
            for group_snapshot_basis in &bases {
                rows.push(MessageRow {
                    id,
                    from,
                    to,
                    body,
                    created_at,
                    group_snapshot: *group_snapshot,
                    group_snapshot_basis: *group_snapshot_basis,
                });
            }
        }
    }
    rows.sort_unstable_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.from.cmp(&right.from))
            .then_with(|| left.to.cmp(&right.to))
            .then_with(|| left.body.raw.cmp(&right.body.raw))
            .then_with(|| left.created_at.raw.cmp(&right.created_at.raw))
            .then_with(|| left.group_snapshot.cmp(&right.group_snapshot))
            .then_with(|| left.group_snapshot_basis.cmp(&right.group_snapshot_basis))
    });
    rows.dedup();
    Ok(rows)
}

/// Query every decodable `(message, reader)` acknowledgement projection.
pub fn load_read_rows<P>(facts: &P) -> Result<Vec<ReadRow>>
where
    P: TriblePattern,
{
    let rows: BTreeSet<(Id, Id, Id)> = find!(
        (id: Id, message: Id, reader: Id),
        pattern!(facts, [{ ?id @
            metadata::tag: &KIND_READ_ID,
            local::about_message: ?message,
            local::reader: ?reader,
        }])
    )
    .collect();
    Ok(rows
        .into_iter()
        .map(|(id, message, reader)| ReadRow {
            id,
            message,
            reader,
        })
        .collect())
}

/// Validate only self-authenticating intrinsic Message envelopes.
///
/// A native collection may also retain arbitrary authored legacy facts. A
/// random-id legacy entity can carry the same tag and field vocabulary, but it
/// is not a native envelope unless its id authenticates one complete canonical
/// projection. Once selected, its complete entity fact set must be the exact
/// immutable envelope.
fn validated_message_rows(facts: &TribleSet) -> Result<Vec<MessageRow>> {
    let ids = sorted_ids(find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_MESSAGE_ID }])
    ))
    .into_iter()
    .filter(|id| message_identity_matches(facts, *id));
    ids.into_iter()
        .map(|id| {
            let row = MessageRow {
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
            };
            let expected = envelope_fragment(
                row.from,
                row.to,
                row.body,
                row.created_at,
                row.group_snapshot,
                row.group_snapshot_basis,
            );
            let expected_id = expected
                .root()
                .expect("canonical Message envelope has exactly one intrinsic root");
            if expected_id != row.id {
                bail!(
                    "message {} is not the intrinsic identity of its immutable envelope (expected {})",
                    fmt_id(row.id),
                    fmt_id(expected_id)
                );
            }
            require_exact_native_entity(facts, id, expected.facts(), "envelope")?;
            Ok(row)
        })
        .collect()
}

/// Validate only self-authenticating intrinsic `(message, reader)` markers.
///
/// Historical random-id read occurrences remain inert even though their tag
/// and relationship attributes are retained in the same generic collection.
/// A selected marker must contain exactly its intrinsic core plus any number
/// of additive `read_at` observations.
fn validated_read_rows(facts: &TribleSet) -> Result<Vec<ReadRow>> {
    let ids = sorted_ids(find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_READ_ID }])
    ))
    .into_iter()
    .filter(|id| read_identity_matches(facts, *id));
    ids.into_iter()
        .map(|id| {
            let row = ReadRow {
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
            };
            let (mut expected, expected_id) = read_core(row.message, row.reader);
            if expected_id != row.id {
                bail!(
                    "read marker {} is not the intrinsic identity of message {} and reader {}",
                    fmt_id(row.id),
                    fmt_id(row.message),
                    fmt_id(row.reader)
                );
            }
            for observed_at in find!(
                value: IntervalValue,
                pattern!(facts, [{ row.id @ local::read_at: ?value }])
            ) {
                expected += entity! { ExclusiveId::force_ref(&row.id) @
                    local::read_at: observed_at,
                };
            }
            require_exact_native_entity(facts, id, expected.facts(), "read marker")?;
            Ok(row)
        })
        .collect()
}

/// Project decodable read markers with their complete additive observations.
pub fn load_read_receipts<P>(facts: &P) -> Result<Vec<ReadReceiptRow>>
where
    P: TriblePattern,
{
    load_read_rows(facts)?
        .into_iter()
        .map(|marker| {
            let mut observed_at: Vec<IntervalValue> = find!(
                value: IntervalValue,
                pattern!(facts, [{ marker.id @ local::read_at: ?value }])
            )
            .collect();
            observed_at.sort_unstable_by_key(|value| value.raw);
            observed_at.dedup();
            Ok(ReadReceiptRow {
                marker,
                observed_at,
            })
        })
        .collect()
}

fn validate_structure(facts: &TribleSet, relation_facts: &TribleSet) -> Result<Vec<TextHandle>> {
    let messages = validated_message_rows(facts)?;
    let reads = validated_read_rows(facts)?;
    let message_rows: BTreeMap<Id, MessageRow> =
        messages.iter().map(|row| (row.id, *row)).collect();
    let people = relations::person_anchors(relation_facts);
    let groups = relations::group_anchors(relation_facts);
    let group_snapshots: BTreeSet<Id> = find!(
        id: Id,
        pattern!(relation_facts, [{ ?id @ metadata::tag: &KIND_GROUP_SNAPSHOT }])
    )
    .collect();

    let mut bodies = Vec::with_capacity(messages.len());
    for row in messages {
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
        bodies.push(row.body);
    }

    let identities = IdentityComponents::from_facts(relation_facts)?;
    for row in &reads {
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
    }
    Ok(bodies)
}

fn load_text_overlay<Overlay>(
    reader: &PileSnapshot,
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
    reader: &PileSnapshot,
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
pub fn read_body(reader: &PileSnapshot, handle: TextHandle) -> Result<String> {
    load_text_overlay(reader, None::<&PileSnapshot>, handle)
}

/// Validate the native Message view inside a complete materialized collection
/// against the exact Relations catalog from the same immutable pile snapshot.
pub fn validate_catalog(
    reader: &PileSnapshot,
    facts: &TribleSet,
    relation_facts: &TribleSet,
) -> Result<()> {
    let bodies = validate_structure(facts, relation_facts)?;
    validate_bodies(reader, None::<&PileSnapshot>, bodies)
}

/// Validate the native Message view of the exact would-be generic union before
/// any staged body or signed COMMIT byte is appended.
pub fn validate_catalog_union(
    reader: &PileSnapshot,
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
        .snapshot()
        .expect("MemoryBlobStore reader creation is infallible");
    validate_bodies(reader, Some(&overlay), bodies)?;
    Ok(union)
}

pub fn resolve_message_id<P>(facts: &P, prefix: &str) -> Result<Id>
where
    P: TriblePattern,
{
    let candidates: BTreeSet<Id> = load_message_rows(facts)?
        .into_iter()
        .map(|row| row.id)
        .collect();
    let id = crate::resolve_id_prefix(prefix, candidates.iter().copied())?;
    if !candidates.contains(&id) {
        bail!("no native Message has id {}", fmt_id(id));
    }
    Ok(id)
}

pub fn row_by_id<P>(facts: &P, id: Id) -> Result<MessageRow>
where
    P: TriblePattern,
{
    load_message_rows(facts)?
        .into_iter()
        .find(|row| row.id == id)
        .ok_or_else(|| {
            anyhow!(
                "message {} has no decodable envelope projection",
                fmt_id(id)
            )
        })
}

/// Decide frozen-snapshot inbox membership with settled same-person equality.
/// The exact sender and recipient anchors remain untouched for attribution.
pub fn is_inbox_message<P>(
    row: &MessageRow,
    reader: Id,
    relation_facts: &P,
    identities: &IdentityComponents,
) -> Result<bool>
where
    P: TriblePattern,
{
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
    use std::fs::{self, File};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::collection_names::open_configured;
    use crate::schemas::message::DEFAULT_SCOPE_ID;
    use crate::schemas::relations::{
        DEFAULT_SCOPE_ID as DEFAULT_RELATIONS_SCOPE_ID, KIND_GROUP, KIND_PERSON_ID,
    };
    use crate::storage::{discover_target, open_pile_strict, FactArchive};
    use crate::test_support::initialize_open_collection_fixture;
    use hifitime::Epoch;
    use triblespace::core::blob::encodings::succinctarchive::{
        Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
    };
    use triblespace::core::collection::{CollectionSnapshotExt, CollectionStoreExt};

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

    fn person_anchor(person: Id) -> Fragment {
        entity! { ExclusiveId::force_ref(&person) @ metadata::tag: &KIND_PERSON_ID }
    }

    fn group_anchor(group: Id) -> Fragment {
        entity! { ExclusiveId::force_ref(&group) @ metadata::tag: &KIND_GROUP }
    }

    fn row(
        from: Id,
        to: Id,
        body: TextHandle,
        created_at: IntervalValue,
        group_snapshot: Option<Id>,
        group_snapshot_basis: Option<Id>,
    ) -> (MessageRow, Fragment) {
        let fragment = envelope_fragment(
            from,
            to,
            body,
            created_at,
            group_snapshot,
            group_snapshot_basis,
        );
        let id = fragment.root().unwrap();
        (
            MessageRow {
                id,
                from,
                to,
                body,
                created_at,
                group_snapshot,
                group_snapshot_basis,
            },
            fragment,
        )
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
        assert_eq!(
            find!(
                at: IntervalValue,
                pattern!(union.facts(), [{ first_id @ local::read_at: ?at }])
            )
            .count(),
            2
        );
        let receipts = load_read_receipts(union.facts()).unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].marker.id, first_id);
        assert_eq!(receipts[0].observed_at.len(), 2);
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

        let (row, envelope) = row(
            sender,
            group,
            "body".to_owned().to_blob().get_handle(),
            at_unix(13.0),
            Some(old_id),
            Some(GROUP_SNAPSHOT_BASIS_WITNESSED),
        );
        let identities = IdentityComponents::from_facts(&relation_facts).unwrap();
        assert!(is_inbox_message(&row, original_member, &relation_facts, &identities).unwrap());
        assert!(!is_inbox_message(&row, later_member, &relation_facts, &identities).unwrap());

        let valid = envelope.into_facts();
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
        let (row, envelope) = row(
            sender,
            addressed,
            "body".to_owned().to_blob().get_handle(),
            at_unix(13.5),
            None,
            None,
        );
        let identities = IdentityComponents::from_facts(&relation_facts).unwrap();
        assert!(is_inbox_message(&row, equivalent_reader, &relation_facts, &identities).unwrap());
        assert_eq!(row.from, sender);
        assert_eq!(row.to, addressed);

        let mut facts = envelope.into_facts();
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
        let mut relation_facts = TribleSet::new();
        for person in [sender, recipient, unrelated] {
            relation_facts += person_anchor(person).facts().clone();
        }
        let envelope = envelope_fragment(
            sender,
            recipient,
            "body".to_owned().to_blob().get_handle(),
            at_unix(13.75),
            None,
            None,
        );
        let message = envelope.root().unwrap();
        let envelope = envelope.into_facts();

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
    fn typed_views_accept_opaque_ids_and_ignore_unrelated_facts() {
        let sender = test_id(0x48);
        let recipient = test_id(0x49);
        let mut relation_facts = TribleSet::new();
        for person in [sender, recipient] {
            relation_facts += person_anchor(person).facts().clone();
        }

        let body = "body".to_owned().to_blob().get_handle();
        let envelope = envelope_fragment(sender, recipient, body, at_unix(14.25), None, None);
        let message = envelope.root().unwrap();
        let (first_read, read) = read_fragment(message, recipient, Some(at_unix(14.5)));
        let (second_read, repeated_read) = read_fragment(message, recipient, Some(at_unix(14.75)));
        assert_eq!(read, repeated_read);

        let legacy_message = test_id(0x4A);
        let legacy_read = test_id(0x4B);
        let unrelated = test_id(0x4C);
        let mut facts = envelope.into_facts();
        facts += first_read.into_facts();
        facts += second_read.into_facts();
        facts += entity! { ExclusiveId::force_ref(&legacy_message) @
            metadata::tag: &KIND_MESSAGE_ID,
            local::from: sender,
            local::to: recipient,
            local::body: body,
            metadata::created_at: at_unix(14.25),
        }
        .into_facts();
        facts += entity! { ExclusiveId::force_ref(&legacy_read) @
            metadata::tag: &KIND_READ_ID,
            local::about_message: legacy_message,
            local::reader: recipient,
            local::read_at: at_unix(15.0),
        }
        .into_facts();
        facts += entity! { ExclusiveId::force_ref(&unrelated) @
            metadata::tag: &test_id(0x4D),
        }
        .into_facts();

        assert_eq!(
            load_message_rows(&facts)
                .unwrap()
                .into_iter()
                .map(|row| row.id)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([message, legacy_message])
        );
        assert_eq!(
            load_read_rows(&facts)
                .unwrap()
                .into_iter()
                .map(|row| row.id)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([read, legacy_read])
        );
        assert_eq!(
            resolve_message_id(&facts, &fmt_id(message)).unwrap(),
            message
        );
        assert_eq!(
            resolve_message_id(&facts, &fmt_id(legacy_message)).unwrap(),
            legacy_message
        );
        validate_structure(&facts, &relation_facts).unwrap();

        facts += entity! { ExclusiveId::force_ref(&read) @
            metadata::tag: &test_id(0x4E),
        }
        .into_facts();
        let error = validate_structure(&facts, &relation_facts)
            .unwrap_err()
            .to_string();
        assert!(error.contains("canonical Message read marker"));
        assert!(error.contains("is not exact"));
    }

    #[test]
    fn body_validation_is_strict_for_native_shadows_but_not_legacy_noise() {
        let directory = TestDirectory::new();
        let pile_path = directory.0.join("bodies.pile");
        File::create(&pile_path).unwrap();
        let mut pile = open_pile_strict(&pile_path).unwrap();

        let sender = test_id(0x53);
        let recipient = test_id(0x54);
        let mut relation_facts = TribleSet::new();
        for person in [sender, recipient] {
            relation_facts += person_anchor(person).facts().clone();
        }
        let (mut fragment, _) = message_fragment(
            sender,
            &Recipient::Person(recipient),
            "resident canonical body",
            at_unix(15.25),
        );
        let missing_body: TextHandle = Inline::new([0xEE; 32]);
        let legacy_message = test_id(0x55);
        fragment += entity! { ExclusiveId::force_ref(&legacy_message) @
            metadata::tag: &KIND_MESSAGE_ID,
            local::from: sender,
            local::to: recipient,
            local::body: missing_body,
            metadata::created_at: at_unix(15.5),
        };

        let reader = pile.snapshot().unwrap();
        validate_catalog_union(&reader, &TribleSet::new(), &fragment, &relation_facts).unwrap();

        let invalid_native =
            envelope_fragment(sender, recipient, missing_body, at_unix(15.75), None, None);
        let error =
            validate_catalog_union(&reader, &TribleSet::new(), &invalid_native, &relation_facts)
                .unwrap_err()
                .to_string();
        assert!(error.contains("read Message body"), "{error}");
        drop(reader);
        pile.close().unwrap();
    }

    #[test]
    fn native_pile_publication_is_idempotent_and_self_validating() {
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
        let relation_facts = relations_fragment.facts().clone();

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
        let reader = pile.snapshot().unwrap();
        validate_catalog_union(&reader, &TribleSet::new(), &fragment, &relation_facts).unwrap();
        drop(reader);

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
            drop(pile.ensure(messages).await.unwrap());
            drop(pile.maintain(succinct).await.unwrap());
            pile.maintain(rank9).await.unwrap()
        });
        let observed = store_snapshot.collection(rank9).unwrap();
        let message_facts = observed.view::<FactArchive>().unwrap();
        assert_eq!(load_message_rows(&message_facts).unwrap()[0].id, message_id);
        drop(message_facts);
        drop(observed);
        drop(store_snapshot);
        pile.close().unwrap();
    }

    #[test]
    fn malformed_envelope_fails_instead_of_selecting_a_value() {
        let sender = test_id(0x41);
        let other_sender = test_id(0x42);
        let recipient = test_id(0x43);
        let mut relation_facts = TribleSet::new();
        for person in [sender, other_sender, recipient] {
            relation_facts += person_anchor(person).facts().clone();
        }
        let body = "body".to_owned().to_blob().get_handle();
        let envelope = envelope_fragment(sender, recipient, body, at_unix(14.0), None, None);
        let message = envelope.root().unwrap();
        let mut facts = envelope.facts().clone();
        facts += entity! { ExclusiveId::force_ref(&message) @ local::from: other_sender }
            .facts()
            .clone();

        let error = validate_structure(&facts, &relation_facts)
            .unwrap_err()
            .to_string();
        assert!(error.contains("local::from"), "{error}");
        assert!(error.contains("expected exactly one"), "{error}");
    }
}
