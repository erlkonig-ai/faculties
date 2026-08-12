//! Collection-native Compass values and semantic views.
//!
//! Compass is deliberately a small event algebra, not a mutable board
//! snapshot protocol. Goals and notes are stable occurrence anchors; status
//! and priority changes are immutable events. The collection value is their
//! set union. Reads derive the current view with one deterministic rule:
//! timestamp first, event id second. Replica merge therefore cannot make the
//! visible board depend on insertion or iteration order.

use std::collections::{BTreeMap, BTreeSet};

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use triblespace::core::collection::{Collection, CollectionCommit};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet};
use triblespace::macros::{entity, find, pattern};
use triblespace::prelude::*;

use crate::schemas::compass::{
    board, interval_key, DEFAULT_SCOPE_ID, KIND_DEPRIORITIZE_ID, KIND_GOAL_ID, KIND_NOTE_ID,
    KIND_PRIORITIZE_ID, KIND_SPECS, KIND_STATUS_ID,
};

pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

fn validate_short(label: &str, value: &str) -> Result<()> {
    if value.len() > 32 {
        bail!("{label} exceeds 32 UTF-8 bytes: {value}");
    }
    if value.bytes().any(|byte| byte == 0) {
        bail!("{label} contains a NUL byte: {value}");
    }
    Ok(())
}

pub fn canonical_status(value: impl Into<String>) -> Result<String> {
    let value = value.into().trim().to_ascii_lowercase();
    validate_short("status", &value)?;
    Ok(value)
}

pub fn canonical_tags(values: impl IntoIterator<Item = String>) -> Result<Vec<String>> {
    let mut values: Vec<String> = values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .collect();
    for value in &values {
        validate_short("tag", value)?;
    }
    values.sort();
    values.dedup();
    Ok(values)
}

fn sorted_ids(values: impl IntoIterator<Item = Id>) -> Vec<Id> {
    let mut values: Vec<Id> = values.into_iter().collect();
    values.sort_unstable();
    values.dedup();
    values
}

fn sorted_strings(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut values: Vec<String> = values.into_iter().collect();
    values.sort();
    values.dedup();
    values
}

fn exactly_one<T>(entity: Id, field: &str, mut values: Vec<T>) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "Compass entity {entity:x} has {} values for {field}; expected exactly one",
            values.len()
        );
    }
    Ok(values.pop().expect("one Compass value"))
}

fn at_most_one<T>(entity: Id, field: &str, mut values: Vec<T>) -> Result<Option<T>> {
    if values.len() > 1 {
        bail!(
            "Compass entity {entity:x} has {} values for {field}; expected at most one",
            values.len()
        );
    }
    Ok(values.pop())
}

fn require_point(entity: Id, field: &str, value: IntervalValue) -> Result<()> {
    let (lower, upper): (i128, i128) = value
        .try_from_inline()
        .map_err(|error| anyhow!("decode Compass {field} on {entity:x}: {error:?}"))?;
    if lower != upper {
        bail!("Compass {field} on {entity:x} must be a point interval");
    }
    Ok(())
}

/// Self-contained descriptions of Compass's published event kinds.
///
/// Adding these same facts to every authored action is harmless set
/// duplication and lets a fresh collection explain itself without a special
/// bootstrap transaction.
pub fn kind_catalog_fragment() -> Fragment {
    let mut fragment = Fragment::empty();
    for (id, label) in KIND_SPECS {
        let name = fragment.put::<blobencodings::LongString, _>(label.to_owned());
        fragment += entity! { ExclusiveId::force_ref(&id) @ metadata::name: name };
    }
    fragment
}

/// One immutable goal anchor. Its random id is the goal's durable identity;
/// the descriptive facts are authored once and thereafter only accumulated.
pub fn goal_fragment(
    goal: Id,
    title: impl Into<String>,
    tags: Vec<String>,
    parent: Option<Id>,
    created_at: IntervalValue,
) -> Result<Fragment> {
    let tags = canonical_tags(tags)?;
    let mut fragment = Fragment::empty();
    let title = fragment.put::<blobencodings::LongString, _>(title.into());
    fragment += entity! { ExclusiveId::force_ref(&goal) @
        metadata::tag: &KIND_GOAL_ID,
        board::title: title,
        metadata::created_at: created_at,
        board::parent?: parent.as_ref(),
        board::tag*: tags.iter().map(String::as_str),
    };
    Ok(fragment)
}

/// One intrinsic status event. Exact replay has the same entity id; two
/// independently timed actions remain distinct events.
pub fn status_fragment(
    goal: Id,
    status: impl Into<String>,
    by: Option<Id>,
    created_at: IntervalValue,
) -> Result<Fragment> {
    let status = canonical_status(status)?;
    Ok(entity! {
        metadata::tag: &KIND_STATUS_ID,
        board::task: &goal,
        board::status: status.as_str(),
        board::by?: by.as_ref(),
        metadata::created_at: created_at,
    })
}

/// One independent note occurrence. The explicit random id is intentional:
/// identical prose entered twice represents two ledger occurrences, and the
/// id is also the stable target of `metadata::supersedes` links.
#[allow(clippy::too_many_arguments)]
pub fn note_fragment(
    note: Id,
    goal: Id,
    body: impl Into<String>,
    tags: Vec<String>,
    references: Vec<String>,
    supersedes: Vec<Id>,
    by: Option<Id>,
    created_at: IntervalValue,
) -> Result<Fragment> {
    let tags = canonical_tags(tags)?;
    let references = sorted_strings(references);
    let supersedes = sorted_ids(supersedes);
    let mut fragment = Fragment::empty();
    let body = fragment.put::<blobencodings::LongString, _>(body.into());
    let references: Vec<TextHandle> = references
        .into_iter()
        .map(|value| fragment.put::<blobencodings::LongString, _>(value))
        .collect();
    fragment += entity! { ExclusiveId::force_ref(&note) @
        metadata::tag: &KIND_NOTE_ID,
        board::task: &goal,
        board::note: body,
        board::by?: by.as_ref(),
        board::tag*: tags.iter().map(String::as_str),
        board::reference*: references.iter(),
        metadata::supersedes*: supersedes.iter(),
        metadata::created_at: created_at,
    };
    Ok(fragment)
}

/// One intrinsic priority assertion or retraction event.
pub fn priority_fragment(
    higher: Id,
    lower: Id,
    active: bool,
    created_at: IntervalValue,
) -> Fragment {
    let kind = if active {
        KIND_PRIORITIZE_ID
    } else {
        KIND_DEPRIORITIZE_ID
    };
    entity! {
        metadata::tag: &kind,
        board::higher: &higher,
        board::lower: &lower,
        metadata::created_at: created_at,
    }
}

pub fn goal_ids(facts: &TribleSet) -> BTreeSet<Id> {
    find!(
        goal: Id,
        pattern!(facts, [{ ?goal @ metadata::tag: &KIND_GOAL_ID }])
    )
    .collect()
}

pub fn note_ids(facts: &TribleSet) -> BTreeSet<Id> {
    find!(
        note: Id,
        pattern!(facts, [{ ?note @
            metadata::tag: &KIND_NOTE_ID,
            board::task: _?goal,
            board::note: _?body,
        }])
    )
    .collect()
}

fn ids_of_kind(facts: &TribleSet, kind: Id) -> BTreeSet<Id> {
    find!(id: Id, pattern!(facts, [{ ?id @ metadata::tag: &kind }])).collect()
}

fn is_compass_kind(kind: Id) -> bool {
    KIND_SPECS.iter().any(|(candidate, _)| *candidate == kind)
}

fn is_compass_attribute(attribute: Id) -> bool {
    [
        board::title.id(),
        board::tag.id(),
        board::parent.id(),
        board::task.id(),
        board::status.id(),
        board::by.id(),
        board::note.id(),
        board::reference.id(),
        board::higher.id(),
        board::lower.id(),
        metadata::created_at.id(),
        metadata::supersedes.id(),
    ]
    .contains(&attribute)
}

fn is_compass_signal_attribute(attribute: Id) -> bool {
    [
        board::title.id(),
        board::tag.id(),
        board::parent.id(),
        board::task.id(),
        board::status.id(),
        board::by.id(),
        board::note.id(),
        board::reference.id(),
        board::higher.id(),
        board::lower.id(),
    ]
    .contains(&attribute)
}

fn allowed_attribute(kind: Id, attribute: Id) -> bool {
    if attribute == metadata::created_at.id() {
        return true;
    }
    if kind == KIND_GOAL_ID {
        [board::title.id(), board::tag.id(), board::parent.id()].contains(&attribute)
    } else if kind == KIND_NOTE_ID {
        [
            board::task.id(),
            board::note.id(),
            board::by.id(),
            board::tag.id(),
            board::reference.id(),
            metadata::supersedes.id(),
        ]
        .contains(&attribute)
    } else if kind == KIND_STATUS_ID {
        [board::task.id(), board::status.id(), board::by.id()].contains(&attribute)
    } else if kind == KIND_PRIORITIZE_ID || kind == KIND_DEPRIORITIZE_ID {
        [board::higher.id(), board::lower.id()].contains(&attribute)
    } else {
        false
    }
}

fn validate_open_entity(facts: &TribleSet, entity: Id, kind: Id) -> Result<()> {
    for fact in facts {
        if fact.a() == &metadata::tag.id() {
            let observed: Id = (*fact.v::<inlineencodings::GenId>())
                .try_from_inline()
                .expect("GenId metadata tag decodes as Id");
            if is_compass_kind(observed) && observed != kind {
                bail!(
                    "Compass entity {entity:x} carries both {kind:x} and {observed:x} kind markers"
                );
            }
        } else if is_compass_attribute(*fact.a()) && !allowed_attribute(kind, *fact.a()) {
            bail!(
                "Compass entity {entity:x} carries attribute {:x}, which is not part of its {kind:x} core",
                fact.a()
            );
        }
    }
    Ok(())
}

/// Project the fields Compass owns for one event kind. Unknown attributes and
/// non-Compass metadata tags are deliberately absent: Trible entities are open
/// world, and preserved history may carry earlier timestamp encodings or
/// domain annotations beside the current Compass core.
fn core_projection(facts: &TribleSet, entity: Id, kind: Id) -> TribleSet {
    let mut projected = TribleSet::new();
    for fact in facts {
        if fact.e() != &entity {
            continue;
        }
        let include = if fact.a() == &metadata::tag.id() {
            let observed: Id = (*fact.v::<inlineencodings::GenId>())
                .try_from_inline()
                .expect("GenId metadata tag decodes as Id");
            is_compass_kind(observed)
        } else {
            allowed_attribute(kind, *fact.a())
        };
        if include {
            projected.insert(fact);
        }
    }
    projected
}

fn validate_goal(facts: &TribleSet, goal: Id) -> Result<()> {
    validate_open_entity(facts, goal, KIND_GOAL_ID)?;
    let _title = exactly_one(
        goal,
        "board::title",
        find!(value: TextHandle, pattern!(facts, [{ goal @ board::title: ?value }])).collect(),
    )?;
    let created_at = at_most_one(
        goal,
        "metadata::created_at",
        find!(
            value: IntervalValue,
            pattern!(facts, [{ goal @ metadata::created_at: ?value }])
        )
        .collect(),
    )?;
    if let Some(created_at) = created_at {
        require_point(goal, "metadata::created_at", created_at)?;
    }
    let _parent = at_most_one(
        goal,
        "board::parent",
        find!(value: Id, pattern!(facts, [{ goal @ board::parent: ?value }])).collect(),
    )?;
    Ok(())
}

fn validate_note(facts: &TribleSet, note: Id) -> Result<()> {
    validate_open_entity(facts, note, KIND_NOTE_ID)?;
    let _task = exactly_one(
        note,
        "board::task",
        find!(value: Id, pattern!(facts, [{ note @ board::task: ?value }])).collect(),
    )?;
    let _body = exactly_one(
        note,
        "board::note",
        find!(value: TextHandle, pattern!(facts, [{ note @ board::note: ?value }])).collect(),
    )?;
    let created_at = at_most_one(
        note,
        "metadata::created_at",
        find!(
            value: IntervalValue,
            pattern!(facts, [{ note @ metadata::created_at: ?value }])
        )
        .collect(),
    )?;
    if let Some(created_at) = created_at {
        require_point(note, "metadata::created_at", created_at)?;
    }
    let _by = at_most_one(
        note,
        "board::by",
        find!(value: Id, pattern!(facts, [{ note @ board::by: ?value }])).collect(),
    )?;
    Ok(())
}

fn validate_status(facts: &TribleSet, event: Id) -> Result<()> {
    validate_open_entity(facts, event, KIND_STATUS_ID)?;
    let _task = exactly_one(
        event,
        "board::task",
        find!(value: Id, pattern!(facts, [{ event @ board::task: ?value }])).collect(),
    )?;
    let _status = exactly_one(
        event,
        "board::status",
        find!(value: String, pattern!(facts, [{ event @ board::status: ?value }])).collect(),
    )?;
    let _by = at_most_one(
        event,
        "board::by",
        find!(value: Id, pattern!(facts, [{ event @ board::by: ?value }])).collect(),
    )?;
    let created_at = at_most_one(
        event,
        "metadata::created_at",
        find!(
            value: IntervalValue,
            pattern!(facts, [{ event @ metadata::created_at: ?value }])
        )
        .collect(),
    )?;
    if let Some(created_at) = created_at {
        require_point(event, "metadata::created_at", created_at)?;
    }
    Ok(())
}

fn validate_priority(facts: &TribleSet, event: Id, kind: Id, label: &str) -> Result<()> {
    validate_open_entity(facts, event, kind)?;
    let higher = exactly_one(
        event,
        "board::higher",
        find!(value: Id, pattern!(facts, [{ event @ board::higher: ?value }])).collect(),
    )?;
    let lower = exactly_one(
        event,
        "board::lower",
        find!(value: Id, pattern!(facts, [{ event @ board::lower: ?value }])).collect(),
    )?;
    if higher == lower {
        bail!("Compass {label} {event:x} relates one goal to itself");
    }
    let created_at = at_most_one(
        event,
        "metadata::created_at",
        find!(
            value: IntervalValue,
            pattern!(facts, [{ event @ metadata::created_at: ?value }])
        )
        .collect(),
    )?;
    if let Some(created_at) = created_at {
        require_point(event, "metadata::created_at", created_at)?;
    }
    Ok(())
}

/// Validate the complete Compass event algebra without imposing intrinsic ids
/// on preserved legacy events. Random goal and note anchors remain valid;
/// Compass-owned scalar fields retain their cardinalities while orthogonal
/// facts on the same open-world entity remain intact.
pub fn validate_structure(facts: &TribleSet) -> Result<()> {
    let mut by_entity: BTreeMap<Id, TribleSet> = BTreeMap::new();
    for fact in facts {
        by_entity.entry(*fact.e()).or_default().insert(fact);
    }
    for goal in ids_of_kind(facts, KIND_GOAL_ID) {
        validate_goal(&by_entity[&goal], goal)?;
    }
    for note in ids_of_kind(facts, KIND_NOTE_ID) {
        validate_note(&by_entity[&note], note)?;
    }
    for event in ids_of_kind(facts, KIND_STATUS_ID) {
        validate_status(&by_entity[&event], event)?;
    }
    for event in ids_of_kind(facts, KIND_PRIORITIZE_ID) {
        validate_priority(
            &by_entity[&event],
            event,
            KIND_PRIORITIZE_ID,
            "priority event",
        )?;
    }
    for event in ids_of_kind(facts, KIND_DEPRIORITIZE_ID) {
        validate_priority(
            &by_entity[&event],
            event,
            KIND_DEPRIORITIZE_ID,
            "depriority event",
        )?;
    }
    Ok(())
}

/// Reject newly introduced Compass fields that have no current Compass event
/// kind. Full-view validation intentionally preserves retired event kinds and
/// earlier cross-domain uses of shared attributes; exact replay of those facts
/// therefore remains harmless. New facts must use the current algebra.
fn validate_candidate_kind_ownership(
    current: &TribleSet,
    candidate: &TribleSet,
    union: &TribleSet,
) -> Result<()> {
    let touched: BTreeSet<Id> = candidate
        .iter()
        .filter(|fact| is_compass_signal_attribute(*fact.a()))
        .map(|fact| *fact.e())
        .collect();
    for entity in touched {
        let kinds: BTreeSet<Id> = union
            .iter()
            .filter(|fact| fact.e() == &entity && fact.a() == &metadata::tag.id())
            .filter_map(|fact| {
                let kind: Id = (*fact.v::<inlineencodings::GenId>())
                    .try_from_inline()
                    .expect("GenId metadata tag decodes as Id");
                is_compass_kind(kind).then_some(kind)
            })
            .collect();
        if kinds.len() == 1 {
            continue;
        }
        let introduces_field = candidate.iter().any(|fact| {
            fact.e() == &entity && is_compass_signal_attribute(*fact.a()) && !current.contains(fact)
        });
        if introduces_field {
            bail!(
                "new Compass-owned fields on entity {entity:x} require exactly one Compass kind; found {}",
                kinds.len()
            );
        }
    }
    Ok(())
}

fn require_canonical_status(facts: &TribleSet, event: Id) -> Result<()> {
    let task = exactly_one(
        event,
        "board::task",
        find!(value: Id, pattern!(facts, [{ event @ board::task: ?value }])).collect(),
    )?;
    let status = exactly_one(
        event,
        "board::status",
        find!(value: String, pattern!(facts, [{ event @ board::status: ?value }])).collect(),
    )?;
    let by = at_most_one(
        event,
        "board::by",
        find!(value: Id, pattern!(facts, [{ event @ board::by: ?value }])).collect(),
    )?;
    let created_at = exactly_one(
        event,
        "metadata::created_at",
        find!(
            value: IntervalValue,
            pattern!(facts, [{ event @ metadata::created_at: ?value }])
        )
        .collect(),
    )?;
    let canonical = status_fragment(task, status, by, created_at)?
        .root()
        .unwrap();
    if canonical != event {
        bail!(
            "new Compass status event {event:x} is non-canonical; canonical identity is {canonical:x}"
        );
    }
    Ok(())
}

fn require_complete_extrinsic(facts: &TribleSet, entity: Id, label: &str) -> Result<()> {
    let created_at = exactly_one(
        entity,
        "metadata::created_at",
        find!(
            value: IntervalValue,
            pattern!(facts, [{ entity @ metadata::created_at: ?value }])
        )
        .collect(),
    )?;
    require_point(entity, "metadata::created_at", created_at)
        .with_context(|| format!("validate new Compass {label} {entity:x}"))
}

fn require_canonical_priority(facts: &TribleSet, event: Id, active: bool) -> Result<()> {
    let higher = exactly_one(
        event,
        "board::higher",
        find!(value: Id, pattern!(facts, [{ event @ board::higher: ?value }])).collect(),
    )?;
    let lower = exactly_one(
        event,
        "board::lower",
        find!(value: Id, pattern!(facts, [{ event @ board::lower: ?value }])).collect(),
    )?;
    let created_at = exactly_one(
        event,
        "metadata::created_at",
        find!(
            value: IntervalValue,
            pattern!(facts, [{ event @ metadata::created_at: ?value }])
        )
        .collect(),
    )?;
    let canonical = priority_fragment(higher, lower, active, created_at)
        .root()
        .unwrap();
    if canonical != event {
        bail!(
            "new Compass priority event {event:x} is non-canonical; canonical identity is {canonical:x}"
        );
    }
    Ok(())
}

fn validate_candidate_structure(current: &TribleSet, candidate: &TribleSet) -> Result<TribleSet> {
    let mut union = current.clone();
    union += candidate.clone();
    validate_structure(&union)?;
    validate_candidate_kind_ownership(current, candidate, &union)?;

    let touched: BTreeSet<Id> = candidate.iter().map(|fact| *fact.e()).collect();
    for (kind, label) in [
        (KIND_GOAL_ID, "goal"),
        (KIND_NOTE_ID, "note"),
        (KIND_STATUS_ID, "status event"),
        (KIND_PRIORITIZE_ID, "priority event"),
        (KIND_DEPRIORITIZE_ID, "depriority event"),
    ] {
        let existing = ids_of_kind(current, kind);
        for entity in existing.intersection(&touched).copied() {
            let proposed = core_projection(candidate, entity, kind);
            if proposed.is_empty() {
                continue;
            }
            let prior = core_projection(current, entity, kind);
            if proposed != prior {
                bail!("Compass candidate divergently reuses existing {label} anchor {entity:x}");
            }
        }
    }

    for goal in ids_of_kind(candidate, KIND_GOAL_ID)
        .difference(&ids_of_kind(current, KIND_GOAL_ID))
        .copied()
    {
        require_complete_extrinsic(&union, goal, "goal")?;
    }
    for note in ids_of_kind(candidate, KIND_NOTE_ID)
        .difference(&ids_of_kind(current, KIND_NOTE_ID))
        .copied()
    {
        require_complete_extrinsic(&union, note, "note")?;
    }

    for event in ids_of_kind(candidate, KIND_STATUS_ID)
        .difference(&ids_of_kind(current, KIND_STATUS_ID))
        .copied()
    {
        require_canonical_status(&union, event)?;
    }
    for (kind, active) in [(KIND_PRIORITIZE_ID, true), (KIND_DEPRIORITIZE_ID, false)] {
        for event in ids_of_kind(candidate, kind)
            .difference(&ids_of_kind(current, kind))
            .copied()
        {
            require_canonical_priority(&union, event, active)?;
        }
    }
    Ok(union)
}

/// Active explicit priority edges after deterministic last-event reduction.
pub fn active_priority_edges(facts: &TribleSet) -> BTreeSet<(Id, Id)> {
    let mut latest: BTreeMap<(Id, Id), ((i128, Id), bool)> = BTreeMap::new();
    let mut absorb = |event: Id, higher: Id, lower: Id, at: IntervalValue, active: bool| {
        let order = (interval_key(at), event);
        latest
            .entry((higher, lower))
            .and_modify(|(current, value)| {
                if order > *current {
                    *current = order;
                    *value = active;
                }
            })
            .or_insert((order, active));
    };

    for (event, higher, lower, at) in find!(
        (event: Id, higher: Id, lower: Id, at: IntervalValue),
        pattern!(facts, [{ ?event @
            metadata::tag: &KIND_PRIORITIZE_ID,
            board::higher: ?higher,
            board::lower: ?lower,
            metadata::created_at: ?at,
        }])
    ) {
        absorb(event, higher, lower, at, true);
    }
    for (event, higher, lower, at) in find!(
        (event: Id, higher: Id, lower: Id, at: IntervalValue),
        pattern!(facts, [{ ?event @
            metadata::tag: &KIND_DEPRIORITIZE_ID,
            board::higher: ?higher,
            board::lower: ?lower,
            metadata::created_at: ?at,
        }])
    ) {
        absorb(event, higher, lower, at, false);
    }

    latest
        .into_iter()
        .filter_map(|(edge, (_, active))| active.then_some(edge))
        .collect()
}

pub fn read_text(reader: &PileReader, handle: TextHandle) -> Result<String> {
    let value: View<str> = reader
        .get(handle)
        .map_err(|error| anyhow!("load Compass text: {error:?}"))?;
    Ok(value.to_string())
}

/// Strictly load every direct text attachment required by Compass semantics.
/// Kind names are descriptive catalog sugar and are deliberately excluded:
/// the legacy CLI emitted some of those handles without retaining their blob,
/// and a missing label must not make otherwise-complete board data unreadable.
pub fn validate_known_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    validate_structure(facts)?;
    for fact in facts {
        if fact.a() == &board::title.id()
            || fact.a() == &board::note.id()
            || fact.a() == &board::reference.id()
        {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::LongString>>();
            let _: View<str> = reader.get(handle).with_context(|| {
                format!(
                    "read Compass text payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

/// Validate the exact union and text-attachment closure of an additive Compass
/// publication.
///
/// Existing facts must remain readable from the pile snapshot; newly staged
/// title, note, and reference handles must be owned by the candidate fragment.
/// This is the pre-publication boundary used by compound importers such as the
/// portable bootstrap, so a late missing attachment cannot strand an earlier
/// collection COMMIT.
pub fn validate_candidate(
    reader: &PileReader,
    current: &TribleSet,
    fragment: &Fragment,
) -> Result<()> {
    validate_known_payloads(reader, current)?;
    validate_candidate_structure(current, fragment.facts())?;
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .reader()
        .context("snapshot staged Compass attachments")?;
    for fact in fragment.facts() {
        if fact.a() == &board::title.id()
            || fact.a() == &board::note.id()
            || fact.a() == &board::reference.id()
        {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::LongString>>();
            let _: View<str> = overlay.get(handle).with_context(|| {
                format!(
                    "read staged Compass text payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

/// Materialize the complete signer-owned Compass collection through an
/// already-open pile.
pub fn materialize_collection(
    pile: &mut Pile,
    signer: &SigningKey,
) -> Result<(TribleSet, PileReader)> {
    let facts = Collection::new(&mut *pile, DEFAULT_SCOPE_ID, signer.clone())
        .materialize()
        .map_err(|error| anyhow!("materialize Compass collection: {error}"))?;
    let reader = pile
        .reader()
        .map_err(|error| anyhow!("open Compass attachment reader: {error}"))?;
    validate_known_payloads(&reader, &facts)?;
    Ok((facts, reader))
}

/// Publish one complete Compass action through an already-open pile.
pub fn commit_collection(
    pile: &mut Pile,
    signer: &SigningKey,
    fragment: Fragment,
) -> Result<CollectionCommit> {
    Collection::new(pile, DEFAULT_SCOPE_ID, signer.clone())
        .commit(fragment)
        .map_err(|error| anyhow!("commit Compass collection fragment: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hifitime::Epoch;

    fn at(value: i128) -> IntervalValue {
        let value = Epoch::from_unix_seconds(value as f64);
        (value, value).try_to_inline().unwrap()
    }

    #[test]
    fn equal_time_priority_events_use_entity_id_not_insertion_order() {
        let high = genid().id;
        let low = genid().id;
        let activate = priority_fragment(high, low, true, at(7));
        let deactivate = priority_fragment(high, low, false, at(7));
        let activate_id = activate.root().unwrap();
        let deactivate_id = deactivate.root().unwrap();

        let mut left = TribleSet::new();
        left += activate.clone();
        left += deactivate.clone();
        let mut right = TribleSet::new();
        right += deactivate;
        right += activate;

        assert_eq!(active_priority_edges(&left), active_priority_edges(&right));
        assert_eq!(
            active_priority_edges(&left).contains(&(high, low)),
            activate_id > deactivate_id
        );
    }

    #[test]
    fn exact_status_replay_has_one_intrinsic_identity() {
        let goal = genid().id;
        let first = status_fragment(goal, "Doing", None, at(11)).unwrap();
        let second = status_fragment(goal, "doing", None, at(11)).unwrap();
        assert_eq!(first.root(), second.root());
        assert_eq!(first.facts(), second.facts());
    }

    #[test]
    fn equal_notes_remain_distinct_occurrences() {
        let goal = genid().id;
        let first = note_fragment(
            genid().id,
            goal,
            "same",
            vec![],
            vec![],
            vec![],
            None,
            at(4),
        )
        .unwrap();
        let second = note_fragment(
            genid().id,
            goal,
            "same",
            vec![],
            vec![],
            vec![],
            None,
            at(4),
        )
        .unwrap();
        assert_ne!(first.root(), second.root());
    }

    #[test]
    fn additive_union_rejects_a_reused_goal_anchor_with_divergent_shape() {
        let goal = genid().id;
        let first = goal_fragment(goal, "first", vec!["one".into()], None, at(4)).unwrap();
        let second = goal_fragment(goal, "second", vec!["two".into()], None, at(5)).unwrap();
        let mut union = first.facts().clone();
        union += second.facts().clone();

        let error = validate_structure(&union).unwrap_err().to_string();
        assert!(error.contains("values for board::title"));
    }

    #[test]
    fn exact_replay_of_an_extrinsic_anchor_remains_valid() {
        let goal = genid().id;
        let fragment = goal_fragment(goal, "same", vec!["one".into()], None, at(4)).unwrap();
        let mut union = fragment.facts().clone();
        union += fragment.facts().clone();

        validate_structure(&union).unwrap();
    }

    #[test]
    fn preserved_goal_accepts_orthogonal_annotations_and_legacy_time() {
        let goal = genid().id;
        let mut fragment = goal_fragment(goal, "same", vec!["one".into()], None, at(4)).unwrap();
        fragment += entity! { ExclusiveId::force_ref(&goal) @ metadata::updated_at: at(5) };

        validate_structure(fragment.facts()).unwrap();

        let replay = goal_fragment(goal, "same", vec!["one".into()], None, at(4)).unwrap();
        validate_candidate_structure(fragment.facts(), replay.facts()).unwrap();
    }

    #[test]
    fn candidate_rejects_tag_removal_hidden_by_additive_union() {
        let goal = genid().id;
        let current =
            goal_fragment(goal, "same", vec!["one".into(), "two".into()], None, at(4)).unwrap();
        let candidate = goal_fragment(goal, "same", vec!["one".into()], None, at(4)).unwrap();

        let error = validate_candidate_structure(current.facts(), candidate.facts())
            .unwrap_err()
            .to_string();
        assert!(error.contains("divergently reuses existing goal anchor"));
    }

    #[test]
    fn orthogonal_candidate_fact_does_not_mutate_goal_core() {
        let goal = genid().id;
        let current = goal_fragment(goal, "same", vec!["one".into()], None, at(4)).unwrap();
        let candidate = entity! { ExclusiveId::force_ref(&goal) @ metadata::updated_at: at(5) };

        validate_candidate_structure(current.facts(), candidate.facts()).unwrap();
    }

    #[test]
    fn new_status_must_have_its_intrinsic_core_identity() {
        let goal = genid().id;
        let canonical = status_fragment(goal, "doing", None, at(7)).unwrap();
        validate_candidate_structure(&TribleSet::new(), canonical.facts()).unwrap();

        let forged_id = genid().id;
        let forged = entity! { ExclusiveId::force_ref(&forged_id) @
            metadata::tag: &KIND_STATUS_ID,
            board::task: &goal,
            board::status: "doing",
            metadata::created_at: at(7),
        };
        let error = validate_candidate_structure(&TribleSet::new(), forged.facts())
            .unwrap_err()
            .to_string();
        assert!(error.contains("status event") && error.contains("non-canonical"));
    }

    #[test]
    fn new_priority_must_have_its_intrinsic_core_identity() {
        let higher = genid().id;
        let lower = genid().id;
        let canonical = priority_fragment(higher, lower, true, at(7));
        validate_candidate_structure(&TribleSet::new(), canonical.facts()).unwrap();

        let forged_id = genid().id;
        let forged = entity! { ExclusiveId::force_ref(&forged_id) @
            metadata::tag: &KIND_PRIORITIZE_ID,
            board::higher: &higher,
            board::lower: &lower,
            metadata::created_at: at(7),
        };
        let error = validate_candidate_structure(&TribleSet::new(), forged.facts())
            .unwrap_err()
            .to_string();
        assert!(error.contains("priority event") && error.contains("non-canonical"));
    }

    #[test]
    fn new_extrinsic_goal_requires_complete_occurrence_time() {
        let goal = genid().id;
        let mut incomplete = Fragment::empty();
        let title = incomplete.put::<blobencodings::LongString, _>("incomplete".to_owned());
        incomplete += entity! { ExclusiveId::force_ref(&goal) @
            metadata::tag: &KIND_GOAL_ID,
            board::title: title,
        };

        let error = validate_candidate_structure(&TribleSet::new(), incomplete.facts())
            .unwrap_err()
            .to_string();
        assert!(error.contains("metadata::created_at"));
    }

    #[test]
    fn exact_replay_preserves_a_noncanonical_legacy_status_id() {
        let goal = genid().id;
        let legacy_id = genid().id;
        let legacy = entity! { ExclusiveId::force_ref(&legacy_id) @
            metadata::tag: &KIND_STATUS_ID,
            board::task: &goal,
            board::status: "doing",
        };

        validate_structure(legacy.facts()).unwrap();
        validate_candidate_structure(legacy.facts(), legacy.facts()).unwrap();
    }

    #[test]
    fn newly_introduced_compass_owned_field_requires_exactly_one_compass_kind() {
        let entity = genid().id;
        let mut orphan = Fragment::empty();
        let title = orphan.put::<blobencodings::LongString, _>("orphan".to_owned());
        orphan += entity! { ExclusiveId::force_ref(&entity) @ board::title: title };

        // A frozen legacy view remains inspectable, but no writer may add this
        // untyped field to an empty collection.
        validate_structure(orphan.facts()).unwrap();
        let error = validate_candidate_structure(&TribleSet::new(), orphan.facts())
            .unwrap_err()
            .to_string();
        assert!(error.contains("require exactly one Compass kind"));
    }
}
