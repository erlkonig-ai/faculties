//! Collection-native Relations values and read semantics.
//!
//! Stable person/group anchors define the addressable native subjects. A
//! materialized collection may also retain historical mutable facts on those
//! same anchors, but native state reads only exact intrinsic snapshots whose
//! predecessor sets record domain lineage. Replica union may therefore expose
//! a fork, but it can never silently pick a scalar winner. Persisted normalized
//! labels are deliberately absent: lookup is a pure view over the current
//! profile text and can later be accelerated by a derived collection without
//! changing truth.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::metadata;
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreList};
use triblespace::macros::{entity, find, pattern};
use triblespace::prelude::*;

use crate::schemas::relations::{
    group, identity, lifecycle, profile, relations as legacy, KIND_GROUP, KIND_GROUP_SNAPSHOT,
    KIND_IDENTITY_VERDICT, KIND_PERSON_ID, KIND_PERSON_LIFECYCLE, KIND_PERSON_PROFILE,
};

pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;
/// One queryable observation of when a stable person or group anchor was
/// created in a source system.
pub type ObservedAt = Inline<inlineencodings::NsTAIInterval>;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProfileInput {
    pub label: String,
    pub aliases: Vec<String>,
    pub affinities: Vec<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: Option<String>,
    pub note: Option<String>,
    pub teams_user_ids: Vec<String>,
    pub emails: Vec<String>,
    pub phones: Vec<String>,
    pub company: Option<String>,
    pub position: Option<String>,
    pub profile_urls: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileSnapshot {
    pub id: Id,
    pub person: Id,
    pub label: TextHandle,
    pub aliases: Vec<TextHandle>,
    pub affinities: Vec<TextHandle>,
    pub first_name: Option<TextHandle>,
    pub last_name: Option<TextHandle>,
    pub display_name: Option<TextHandle>,
    pub note: Option<TextHandle>,
    pub teams_user_ids: Vec<TextHandle>,
    pub emails: Vec<TextHandle>,
    pub phones: Vec<TextHandle>,
    pub company: Option<TextHandle>,
    pub position: Option<TextHandle>,
    pub profile_urls: Vec<TextHandle>,
    pub predecessors: Vec<Id>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleSnapshot {
    pub id: Id,
    pub person: Id,
    pub retired: bool,
    pub predecessors: Vec<Id>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupSnapshot {
    pub id: Id,
    pub group: Id,
    pub name: TextHandle,
    pub members: Vec<Id>,
    pub predecessors: Vec<Id>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityVerdict {
    pub id: Id,
    pub low: Id,
    pub high: Id,
    pub same: bool,
    pub predecessors: Vec<Id>,
}

/// Current state of one snapshot track. A fork is legitimate grow-only
/// evidence and is therefore a value, not catalog corruption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Head {
    Missing,
    Unique(Id),
    Forked(Vec<Id>),
}

/// Typed result of resolving a human-facing person or group selector.
///
/// `Forked` keeps the two kinds of candidate apart: `forked` are the anchors
/// whose own snapshot track is unsettled — the actual blockers — and `settled`
/// are the other matches, retained so a caller sees the whole candidate set.
/// Flattening the two into one list is what made a fork on an irrelevant
/// anchor read as a fork on the anchor the user asked for. Callers can inspect
/// the corresponding `*_head` values for detail without scraping an error
/// string.
///
/// Only candidates that survive disqualification appear here at all: a
/// selector never reports a fork on an anchor it has already ruled out (see
/// [`resolve_person`]).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectorOutcome {
    Missing,
    Unique(Id),
    Ambiguous(Vec<Id>),
    Forked { forked: Vec<Id>, settled: Vec<Id> },
    Invalid(String),
}

impl SelectorOutcome {
    /// Every anchor this outcome matched, blockers and settled alike.
    pub fn candidates(&self) -> Vec<Id> {
        match self {
            Self::Unique(id) => vec![*id],
            Self::Ambiguous(ids) => ids.clone(),
            Self::Forked { forked, settled } => {
                sorted_ids(forked.iter().copied().chain(settled.iter().copied()))
            }
            Self::Missing | Self::Invalid(_) => Vec::new(),
        }
    }

    /// Render the typed outcome at a command boundary that requires one exact
    /// anchor. Library consumers should normally retain the enum.
    pub fn require_unique(self, kind: &str, input: &str) -> Result<Id> {
        match self {
            Self::Unique(id) => Ok(id),
            Self::Missing => bail!("no {kind} matches '{input}'"),
            Self::Ambiguous(ids) => bail!(
                "multiple {kind}s match '{input}': {}",
                ids.iter()
                    .map(|id| format!("{id:x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::Forked { forked, settled } => {
                let mut message = format!(
                    "cannot resolve {kind} '{input}': unreconciled {kind} state on {}",
                    forked
                        .iter()
                        .map(|id| format!("{id:x}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                if !settled.is_empty() {
                    message.push_str(&format!(
                        " (also matched, but not selectable while the fork stands: {})",
                        settled
                            .iter()
                            .map(|id| format!("{id:x}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                bail!("{message}")
            }
            Self::Invalid(reason) => bail!("invalid {kind} selector '{input}': {reason}"),
        }
    }
}

fn sorted_ids(values: impl IntoIterator<Item = Id>) -> Vec<Id> {
    let mut values: Vec<Id> = values.into_iter().collect();
    values.sort_unstable();
    values.dedup();
    values
}

fn sorted_handles(values: impl IntoIterator<Item = TextHandle>) -> Vec<TextHandle> {
    let mut values: Vec<TextHandle> = values.into_iter().collect();
    values.sort_unstable_by_key(|value| value.raw);
    values.dedup();
    values
}

fn required_text(value: impl Into<String>, field: &str) -> Result<String> {
    let value = value.into();
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{field} is empty");
    }
    if trimmed.bytes().any(|byte| byte == 0) {
        bail!("{field} contains a NUL byte");
    }
    Ok(trimmed.to_owned())
}

fn optional_text(value: Option<String>, field: &str) -> Result<Option<String>> {
    value.map(|value| required_text(value, field)).transpose()
}

fn text_set(values: Vec<String>, field: &str) -> Result<Vec<String>> {
    let mut values: Vec<String> = values
        .into_iter()
        .map(|value| required_text(value, field))
        .collect::<Result<_>>()?;
    values.sort();
    values.dedup();
    Ok(values)
}

fn source_set(mut values: Vec<String>) -> Result<Vec<String>> {
    for value in &values {
        if value.len() > 32 {
            bail!(
                "source is {} bytes but the published ShortString schema holds at most 32",
                value.len()
            );
        }
        if value.bytes().any(|byte| byte == 0) {
            bail!("source contains a NUL byte");
        }
    }
    values.sort();
    values.dedup();
    Ok(values)
}

fn sorted_observations(values: impl IntoIterator<Item = ObservedAt>) -> Vec<ObservedAt> {
    let mut values: Vec<_> = values.into_iter().collect();
    values.sort_unstable_by_key(|value| value.raw);
    values.dedup();
    values
}

fn provenance_record(anchor: Id, sources: &[String], observed_at: &[ObservedAt]) -> Fragment {
    entity! { ExclusiveId::force_ref(&anchor) @
        legacy::source*: sources.iter().map(String::as_str),
        metadata::created_at*: observed_at.iter(),
    }
}

/// Build additive provenance for a stable person anchor.
///
/// Source labels and creation observations are deliberately outside profile
/// snapshot identity: learning another immutable source fact neither forks nor
/// rewrites mutable person state.
pub fn person_provenance_fragment(
    person: Id,
    sources: Vec<String>,
    observed_at: &[ObservedAt],
) -> Result<Fragment> {
    let sources = source_set(sources)?;
    let observed_at = sorted_observations(observed_at.iter().copied());
    Ok(provenance_record(person, &sources, &observed_at))
}

/// Build additive creation observations for a stable group anchor.
pub fn group_provenance_fragment(group: Id, observed_at: &[ObservedAt]) -> Fragment {
    provenance_record(
        group,
        &[],
        &sorted_observations(observed_at.iter().copied()),
    )
}

fn anchor_fragment(anchor: Id, kind: Id) -> Fragment {
    entity! { ExclusiveId::force_ref(&anchor) @ metadata::tag: &kind }
}

fn profile_record(snapshot: &ProfileSnapshot) -> Fragment {
    entity! {
        metadata::tag: &KIND_PERSON_PROFILE,
        profile::of: &snapshot.person,
        metadata::name: snapshot.label,
        profile::alias*: snapshot.aliases.iter(),
        profile::affinity*: snapshot.affinities.iter(),
        profile::first_name?: snapshot.first_name,
        profile::last_name?: snapshot.last_name,
        profile::display_name?: snapshot.display_name,
        metadata::description?: snapshot.note,
        profile::teams_user_id*: snapshot.teams_user_ids.iter(),
        profile::email*: snapshot.emails.iter(),
        profile::phone*: snapshot.phones.iter(),
        profile::company?: snapshot.company,
        profile::position?: snapshot.position,
        profile::profile_url*: snapshot.profile_urls.iter(),
        metadata::supersedes*: snapshot.predecessors.iter(),
    }
}

fn lifecycle_record(snapshot: &LifecycleSnapshot) -> Fragment {
    entity! {
        metadata::tag: &KIND_PERSON_LIFECYCLE,
        lifecycle::of: &snapshot.person,
        lifecycle::retired: snapshot.retired,
        metadata::supersedes*: snapshot.predecessors.iter(),
    }
}

fn group_record(snapshot: &GroupSnapshot) -> Fragment {
    entity! {
        metadata::tag: &KIND_GROUP_SNAPSHOT,
        group::snapshot_of: &snapshot.group,
        metadata::name: snapshot.name,
        group::member*: snapshot.members.iter(),
        metadata::supersedes*: snapshot.predecessors.iter(),
    }
}

fn identity_record(snapshot: &IdentityVerdict) -> Fragment {
    entity! {
        metadata::tag: &KIND_IDENTITY_VERDICT,
        identity::low: &snapshot.low,
        identity::high: &snapshot.high,
        identity::same: snapshot.same,
        metadata::supersedes*: snapshot.predecessors.iter(),
    }
}

/// Build an initial person declaration, full profile, and active lifecycle as
/// one self-contained publication fragment.
pub fn person_fragment(person: Id, input: ProfileInput) -> Result<(Fragment, Id, Id)> {
    let mut fragment = anchor_fragment(person, KIND_PERSON_ID);
    let profile = profile_fragment(person, input, &[])?;
    let profile_id = profile
        .root()
        .expect("profile fragment has one intrinsic root");
    fragment += profile;
    let lifecycle = lifecycle_fragment(person, false, &[]);
    let lifecycle_id = lifecycle
        .root()
        .expect("lifecycle fragment has one intrinsic root");
    fragment += lifecycle;
    Ok((fragment, profile_id, lifecycle_id))
}

/// Build one exact intrinsic profile successor.
pub fn profile_fragment(person: Id, input: ProfileInput, predecessors: &[Id]) -> Result<Fragment> {
    let label = required_text(input.label, "label")?;
    let aliases = text_set(input.aliases, "alias")?;
    let affinities = text_set(input.affinities, "affinity")?;
    let teams_user_ids = text_set(input.teams_user_ids, "Teams user id")?;
    let emails = text_set(input.emails, "email")?;
    let phones = text_set(input.phones, "phone")?;
    let profile_urls = text_set(input.profile_urls, "profile URL")?;
    let first_name = optional_text(input.first_name, "first name")?;
    let last_name = optional_text(input.last_name, "last name")?;
    let display_name = optional_text(input.display_name, "display name")?;
    let company = optional_text(input.company, "company")?;
    let position = optional_text(input.position, "position")?;

    let mut fragment = Fragment::empty();
    let snapshot = ProfileSnapshot {
        id: person,
        person,
        label: fragment.put(label),
        aliases: aliases
            .into_iter()
            .map(|value| fragment.put(value))
            .collect(),
        affinities: affinities
            .into_iter()
            .map(|value| fragment.put(value))
            .collect(),
        first_name: first_name.map(|value| fragment.put(value)),
        last_name: last_name.map(|value| fragment.put(value)),
        display_name: display_name.map(|value| fragment.put(value)),
        note: input.note.map(|value| fragment.put(value)),
        teams_user_ids: teams_user_ids
            .into_iter()
            .map(|value| fragment.put(value))
            .collect(),
        emails: emails
            .into_iter()
            .map(|value| fragment.put(value))
            .collect(),
        phones: phones
            .into_iter()
            .map(|value| fragment.put(value))
            .collect(),
        company: company.map(|value| fragment.put(value)),
        position: position.map(|value| fragment.put(value)),
        profile_urls: profile_urls
            .into_iter()
            .map(|value| fragment.put(value))
            .collect(),
        predecessors: sorted_ids(predecessors.iter().copied()),
    };
    fragment += profile_record(&snapshot);
    Ok(fragment)
}

pub fn lifecycle_fragment(person: Id, retired: bool, predecessors: &[Id]) -> Fragment {
    lifecycle_record(&LifecycleSnapshot {
        id: person,
        person,
        retired,
        predecessors: sorted_ids(predecessors.iter().copied()),
    })
}

pub fn group_create_fragment(group_id: Id, name: impl Into<String>) -> Result<(Fragment, Id)> {
    let mut fragment = anchor_fragment(group_id, KIND_GROUP);
    let snapshot = group_snapshot_fragment(group_id, name, &[], &[])?;
    let snapshot_id = snapshot
        .root()
        .expect("group snapshot fragment has one intrinsic root");
    fragment += snapshot;
    Ok((fragment, snapshot_id))
}

pub fn group_snapshot_fragment(
    group_id: Id,
    name: impl Into<String>,
    members: &[Id],
    predecessors: &[Id],
) -> Result<Fragment> {
    let name = required_text(name, "group name")?;
    let mut fragment = Fragment::empty();
    let snapshot = GroupSnapshot {
        id: group_id,
        group: group_id,
        name: fragment.put(name),
        members: sorted_ids(members.iter().copied()),
        predecessors: sorted_ids(predecessors.iter().copied()),
    };
    fragment += group_record(&snapshot);
    Ok(fragment)
}

/// Reconcile concurrent group snapshots without losing any asserted member.
///
/// A normal single-parent successor is an authored full-state edit and may
/// add or remove members. A multi-parent successor has different semantics:
/// it closes a fork, so membership is the join (set union) of the snapshots it
/// names. The group name remains an explicit human choice because names do not
/// themselves form a useful join-semilattice.
pub fn reconcile_group_fragment(
    facts: &TribleSet,
    group_id: Id,
    name: impl Into<String>,
    predecessors: &[Id],
) -> Result<Fragment> {
    let predecessors = sorted_ids(predecessors.iter().copied());
    if predecessors.len() < 2 {
        bail!("group reconciliation requires at least two distinct predecessors");
    }

    let mut members = BTreeSet::new();
    for predecessor in &predecessors {
        let snapshot = group_snapshot(facts, *predecessor)
            .with_context(|| format!("read group reconciliation predecessor {predecessor:x}"))?;
        if snapshot.group != group_id {
            bail!(
                "group reconciliation predecessor {predecessor:x} belongs to group {:x}, not {group_id:x}",
                snapshot.group
            );
        }
        members.extend(snapshot.members);
    }
    let members: Vec<_> = members.into_iter().collect();
    group_snapshot_fragment(group_id, name, &members, &predecessors)
}

pub fn identity_verdict_fragment(
    first: Id,
    second: Id,
    same: bool,
    predecessors: &[Id],
) -> Result<Fragment> {
    if first == second {
        bail!("identity verdict endpoints must be different people");
    }
    let (low, high) = if first < second {
        (first, second)
    } else {
        (second, first)
    };
    Ok(identity_record(&IdentityVerdict {
        id: low,
        low,
        high,
        same,
        predecessors: sorted_ids(predecessors.iter().copied()),
    }))
}

fn exactly_one<T>(values: Vec<T>, entity: Id, field: &str) -> Result<T> {
    let count = values.len();
    if count != 1 {
        bail!("Relations entity {entity:x} has {count} values for {field}; expected exactly one");
    }
    Ok(values.into_iter().next().unwrap())
}

fn at_most_one<T>(values: Vec<T>, entity: Id, field: &str) -> Result<Option<T>> {
    let count = values.len();
    if count > 1 {
        bail!("Relations entity {entity:x} has {count} values for {field}; expected at most one");
    }
    Ok(values.into_iter().next())
}

/// Read one exact self-authenticating native profile snapshot. Historical
/// anchor-shaped rows may share field attributes, but without the intrinsic
/// identity and complete native record they cannot enter this view.
pub fn profile_snapshot(facts: &TribleSet, id: Id) -> Result<ProfileSnapshot> {
    let snapshot = ProfileSnapshot {
        id,
        person: exactly_one(
            find!(v: Id, pattern!(facts, [{ id @ profile::of: ?v }])).collect(),
            id,
            "profile::of",
        )?,
        label: exactly_one(
            find!(v: TextHandle, pattern!(facts, [{ id @ metadata::name: ?v }])).collect(),
            id,
            "metadata::name",
        )?,
        aliases: sorted_handles(
            find!(v: TextHandle, pattern!(facts, [{ id @ profile::alias: ?v }])),
        ),
        affinities: sorted_handles(find!(
            v: TextHandle,
            pattern!(facts, [{ id @ profile::affinity: ?v }])
        )),
        first_name: at_most_one(
            find!(v: TextHandle, pattern!(facts, [{ id @ profile::first_name: ?v }])).collect(),
            id,
            "profile::first_name",
        )?,
        last_name: at_most_one(
            find!(v: TextHandle, pattern!(facts, [{ id @ profile::last_name: ?v }])).collect(),
            id,
            "profile::last_name",
        )?,
        display_name: at_most_one(
            find!(v: TextHandle, pattern!(facts, [{ id @ profile::display_name: ?v }])).collect(),
            id,
            "profile::display_name",
        )?,
        note: at_most_one(
            find!(v: TextHandle, pattern!(facts, [{ id @ metadata::description: ?v }])).collect(),
            id,
            "metadata::description",
        )?,
        teams_user_ids: sorted_handles(find!(
            v: TextHandle,
            pattern!(facts, [{ id @ profile::teams_user_id: ?v }])
        )),
        emails: sorted_handles(find!(
            v: TextHandle,
            pattern!(facts, [{ id @ profile::email: ?v }])
        )),
        phones: sorted_handles(find!(
            v: TextHandle,
            pattern!(facts, [{ id @ profile::phone: ?v }])
        )),
        company: at_most_one(
            find!(v: TextHandle, pattern!(facts, [{ id @ profile::company: ?v }])).collect(),
            id,
            "profile::company",
        )?,
        position: at_most_one(
            find!(v: TextHandle, pattern!(facts, [{ id @ profile::position: ?v }])).collect(),
            id,
            "profile::position",
        )?,
        profile_urls: sorted_handles(find!(
            v: TextHandle,
            pattern!(facts, [{ id @ profile::profile_url: ?v }])
        )),
        predecessors: sorted_ids(find!(
            v: Id,
            pattern!(facts, [{ id @ metadata::supersedes: ?v }])
        )),
    };
    let expected = ensure_intrinsic(id, profile_record(&snapshot), "profile")?;
    require_exact_native_entity(facts, id, &expected, "profile")?;
    Ok(snapshot)
}

pub fn lifecycle_snapshot(facts: &TribleSet, id: Id) -> Result<LifecycleSnapshot> {
    let snapshot = LifecycleSnapshot {
        id,
        person: exactly_one(
            find!(v: Id, pattern!(facts, [{ id @ lifecycle::of: ?v }])).collect(),
            id,
            "lifecycle::of",
        )?,
        retired: exactly_one(
            find!(v: bool, pattern!(facts, [{ id @ lifecycle::retired: ?v }])).collect(),
            id,
            "lifecycle::retired",
        )?,
        predecessors: sorted_ids(find!(
            v: Id,
            pattern!(facts, [{ id @ metadata::supersedes: ?v }])
        )),
    };
    let expected = ensure_intrinsic(id, lifecycle_record(&snapshot), "lifecycle")?;
    require_exact_native_entity(facts, id, &expected, "lifecycle")?;
    Ok(snapshot)
}

pub fn group_snapshot(facts: &TribleSet, id: Id) -> Result<GroupSnapshot> {
    let snapshot = GroupSnapshot {
        id,
        group: exactly_one(
            find!(v: Id, pattern!(facts, [{ id @ group::snapshot_of: ?v }])).collect(),
            id,
            "group::snapshot_of",
        )?,
        name: exactly_one(
            find!(v: TextHandle, pattern!(facts, [{ id @ metadata::name: ?v }])).collect(),
            id,
            "metadata::name",
        )?,
        members: sorted_ids(find!(v: Id, pattern!(facts, [{ id @ group::member: ?v }]))),
        predecessors: sorted_ids(find!(
            v: Id,
            pattern!(facts, [{ id @ metadata::supersedes: ?v }])
        )),
    };
    let expected = ensure_intrinsic(id, group_record(&snapshot), "group snapshot")?;
    require_exact_native_entity(facts, id, &expected, "group snapshot")?;
    Ok(snapshot)
}

pub fn identity_verdict(facts: &TribleSet, id: Id) -> Result<IdentityVerdict> {
    let snapshot = IdentityVerdict {
        id,
        low: exactly_one(
            find!(v: Id, pattern!(facts, [{ id @ identity::low: ?v }])).collect(),
            id,
            "identity::low",
        )?,
        high: exactly_one(
            find!(v: Id, pattern!(facts, [{ id @ identity::high: ?v }])).collect(),
            id,
            "identity::high",
        )?,
        same: exactly_one(
            find!(v: bool, pattern!(facts, [{ id @ identity::same: ?v }])).collect(),
            id,
            "identity::same",
        )?,
        predecessors: sorted_ids(find!(
            v: Id,
            pattern!(facts, [{ id @ metadata::supersedes: ?v }])
        )),
    };
    let expected = ensure_intrinsic(id, identity_record(&snapshot), "identity verdict")?;
    require_exact_native_entity(facts, id, &expected, "identity verdict")?;
    Ok(snapshot)
}

pub fn person_anchors(facts: &TribleSet) -> BTreeSet<Id> {
    find!(id: Id, pattern!(facts, [{ ?id @ metadata::tag: &KIND_PERSON_ID }])).collect()
}

pub fn group_anchors(facts: &TribleSet) -> BTreeSet<Id> {
    find!(id: Id, pattern!(facts, [{ ?id @ metadata::tag: &KIND_GROUP }])).collect()
}

/// Every exact source label asserted for a stable person anchor, sorted and
/// deduplicated. No scalar winner is selected when several systems observed
/// the same person.
pub fn person_sources(facts: &TribleSet, person: Id) -> Result<Vec<String>> {
    source_set(
        find!(value: String, pattern!(facts, [{ person @ legacy::source: ?value }])).collect(),
    )
}

/// Every creation-time observation attached to a stable person or group
/// anchor, in chronological order. Repeated observations collapse by set
/// semantics.
pub fn creation_observations(facts: &TribleSet, anchor: Id) -> Vec<ObservedAt> {
    sorted_observations(find!(
        value: ObservedAt,
        pattern!(facts, [{ anchor @ metadata::created_at: ?value }])
    ))
}

/// Deterministic lower bound of the known creation observations.
///
/// This is a projection, not a stored scalar fact: later union may reveal an
/// earlier observation without invalidating any existing assertion.
pub fn earliest_creation_observation(facts: &TribleSet, anchor: Id) -> Option<ObservedAt> {
    creation_observations(facts, anchor).into_iter().next()
}

fn ids_of_kind(facts: &TribleSet, kind: Id) -> BTreeSet<Id> {
    find!(id: Id, pattern!(facts, [{ ?id @ metadata::tag: kind }])).collect()
}

fn track_head(
    ids: BTreeSet<Id>,
    predecessors: impl Fn(Id) -> Result<Vec<Id>>,
    label: &str,
) -> Result<Head> {
    if ids.is_empty() {
        return Ok(Head::Missing);
    }
    let mut superseded = BTreeSet::new();
    for &id in &ids {
        for predecessor in predecessors(id)? {
            if !ids.contains(&predecessor) {
                bail!(
                    "{label} snapshot {id:x} supersedes missing or wrong-track predecessor {predecessor:x}"
                );
            }
            superseded.insert(predecessor);
        }
    }
    let heads: Vec<Id> = ids.difference(&superseded).copied().collect();
    match heads.as_slice() {
        [] => bail!("{label} snapshot track has no head"),
        [head] => Ok(Head::Unique(*head)),
        _ => Ok(Head::Forked(heads)),
    }
}

pub fn profile_head(facts: &TribleSet, person: Id) -> Result<Head> {
    let ids = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_PERSON_PROFILE, profile::of: person }])
    )
    .collect();
    track_head(
        ids,
        |id| Ok(profile_snapshot(facts, id)?.predecessors),
        "profile",
    )
}

pub fn lifecycle_head(facts: &TribleSet, person: Id) -> Result<Head> {
    let ids = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_PERSON_LIFECYCLE, lifecycle::of: person }])
    )
    .collect();
    track_head(
        ids,
        |id| Ok(lifecycle_snapshot(facts, id)?.predecessors),
        "lifecycle",
    )
}

pub fn group_head(facts: &TribleSet, group_id: Id) -> Result<Head> {
    let ids = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_GROUP_SNAPSHOT, group::snapshot_of: group_id }])
    )
    .collect();
    track_head(
        ids,
        |id| Ok(group_snapshot(facts, id)?.predecessors),
        "group",
    )
}

fn pair(first: Id, second: Id) -> Result<(Id, Id)> {
    if first == second {
        bail!("identity pair endpoints are equal");
    }
    Ok(if first < second {
        (first, second)
    } else {
        (second, first)
    })
}

pub fn identity_head(facts: &TribleSet, first: Id, second: Id) -> Result<Head> {
    let (low, high) = pair(first, second)?;
    let ids = find!(
        id: Id,
        pattern!(facts, [{ ?id @
            metadata::tag: &KIND_IDENTITY_VERDICT,
            identity::low: low,
            identity::high: high,
        }])
    )
    .collect();
    track_head(
        ids,
        |id| Ok(identity_verdict(facts, id)?.predecessors),
        "identity verdict",
    )
}

fn ensure_intrinsic(id: Id, record: Fragment, label: &str) -> Result<TribleSet> {
    let expected = record
        .root()
        .ok_or_else(|| anyhow!("{label} record has no unique intrinsic root"))?;
    if id != expected {
        bail!("{label} {id:x} does not match intrinsic root {expected:x}");
    }
    Ok(record.into_facts())
}

fn entity_facts(facts: &TribleSet, id: Id) -> TribleSet {
    facts
        .iter()
        .filter(|fact| fact.e() == &id)
        .copied()
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
            "canonical Relations {label} {id:x} is not exact ({missing} missing, {unexpected} unexpected facts)"
        );
    }
    Ok(())
}

fn validate_structure(facts: &TribleSet) -> Result<Vec<(TextHandle, bool)>> {
    let people = person_anchors(facts);
    let groups = group_anchors(facts);
    if let Some(id) = people.intersection(&groups).next() {
        bail!("Relations anchor {id:x} is both a person and a group");
    }

    let profile_ids = ids_of_kind(facts, KIND_PERSON_PROFILE);
    let lifecycle_ids = ids_of_kind(facts, KIND_PERSON_LIFECYCLE);
    let group_ids = ids_of_kind(facts, KIND_GROUP_SNAPSHOT);
    let verdict_ids = ids_of_kind(facts, KIND_IDENTITY_VERDICT);

    for &person in &people {
        let _ = person_sources(facts, person)?;
    }

    let mut text_handles = Vec::new();
    for &id in &profile_ids {
        let snapshot = profile_snapshot(facts, id)?;
        if !people.contains(&snapshot.person) {
            bail!(
                "profile {id:x} names undeclared person {:x}",
                snapshot.person
            );
        }
        text_handles.push((snapshot.label, true));
        text_handles.extend(
            snapshot
                .aliases
                .iter()
                .copied()
                .map(|handle| (handle, true)),
        );
        text_handles.extend(
            snapshot
                .affinities
                .iter()
                .copied()
                .map(|handle| (handle, true)),
        );
        text_handles.extend(snapshot.first_name.into_iter().map(|handle| (handle, true)));
        text_handles.extend(snapshot.last_name.into_iter().map(|handle| (handle, true)));
        text_handles.extend(
            snapshot
                .display_name
                .into_iter()
                .map(|handle| (handle, true)),
        );
        text_handles.extend(snapshot.note.into_iter().map(|handle| (handle, false)));
        text_handles.extend(
            snapshot
                .teams_user_ids
                .iter()
                .copied()
                .map(|handle| (handle, true)),
        );
        text_handles.extend(snapshot.emails.iter().copied().map(|handle| (handle, true)));
        text_handles.extend(snapshot.phones.iter().copied().map(|handle| (handle, true)));
        text_handles.extend(snapshot.company.into_iter().map(|handle| (handle, true)));
        text_handles.extend(snapshot.position.into_iter().map(|handle| (handle, true)));
        text_handles.extend(
            snapshot
                .profile_urls
                .iter()
                .copied()
                .map(|handle| (handle, true)),
        );
    }
    for &id in &lifecycle_ids {
        let snapshot = lifecycle_snapshot(facts, id)?;
        if !people.contains(&snapshot.person) {
            bail!(
                "lifecycle {id:x} names undeclared person {:x}",
                snapshot.person
            );
        }
    }
    for &id in &group_ids {
        let snapshot = group_snapshot(facts, id)?;
        if !groups.contains(&snapshot.group) {
            bail!(
                "group snapshot {id:x} names undeclared group {:x}",
                snapshot.group
            );
        }
        for member in &snapshot.members {
            if !people.contains(member) {
                bail!("group snapshot {id:x} names undeclared person {member:x}");
            }
        }
        if snapshot.predecessors.len() > 1 {
            let mut inherited_members = BTreeSet::new();
            for predecessor in &snapshot.predecessors {
                let parent = group_snapshot(facts, *predecessor).with_context(|| {
                    format!("read group reconciliation predecessor {predecessor:x}")
                })?;
                if parent.group != snapshot.group {
                    bail!(
                        "group snapshot {id:x} reconciles predecessor {predecessor:x} from another group"
                    );
                }
                inherited_members.extend(parent.members);
            }
            let actual_members: BTreeSet<_> = snapshot.members.iter().copied().collect();
            if actual_members != inherited_members {
                bail!(
                    "group reconciliation {id:x} has {} members; the predecessor union has {}",
                    actual_members.len(),
                    inherited_members.len()
                );
            }
        }
        text_handles.push((snapshot.name, true));
    }
    for &id in &verdict_ids {
        let snapshot = identity_verdict(facts, id)?;
        if snapshot.low >= snapshot.high {
            bail!("identity verdict {id:x} does not use canonical ordered endpoints");
        }
        if !people.contains(&snapshot.low) || !people.contains(&snapshot.high) {
            bail!("identity verdict {id:x} names an undeclared person");
        }
    }

    for &person in &people {
        if matches!(profile_head(facts, person)?, Head::Missing) {
            bail!("person {person:x} has no profile snapshot");
        }
        if matches!(lifecycle_head(facts, person)?, Head::Missing) {
            bail!("person {person:x} has no lifecycle snapshot");
        }
    }
    for &group_id in &groups {
        if matches!(group_head(facts, group_id)?, Head::Missing) {
            bail!("group {group_id:x} has no group snapshot");
        }
    }
    for &id in &verdict_ids {
        let verdict = identity_verdict(facts, id)?;
        let _ = identity_head(facts, verdict.low, verdict.high)?;
    }

    Ok(text_handles)
}

fn load_text_from<Store>(reader: &Store, handle: TextHandle) -> Result<String>
where
    Store: BlobStoreGet + ?Sized,
{
    let view: View<str> = reader
        .get(handle)
        .with_context(|| format!("read Relations text payload {}", hex::encode(handle.raw)))?;
    Ok(view.to_string())
}

fn load_text_overlay<Store, Overlay>(
    reader: &Store,
    overlay: &Overlay,
    handle: TextHandle,
) -> Result<String>
where
    Store: BlobStoreGet + ?Sized,
    Overlay: BlobStoreGet + BlobStoreList,
{
    if overlay
        .contains_blob(handle)
        .context("inspect staged Relations text payloads")?
    {
        let view: View<str> = overlay.get(handle).with_context(|| {
            format!(
                "read staged Relations text payload {}",
                hex::encode(handle.raw)
            )
        })?;
        return Ok(view.to_string());
    }
    load_text_from(reader, handle)
}

fn validate_texts(
    handles: Vec<(TextHandle, bool)>,
    mut load: impl FnMut(TextHandle) -> Result<String>,
) -> Result<()> {
    let mut seen = HashSet::new();
    for (handle, trimmed) in handles {
        if !seen.insert(handle.raw) {
            continue;
        }
        let value = load(handle)?;
        if value.bytes().any(|byte| byte == 0) {
            bail!("Relations text payload contains a NUL byte");
        }
        if trimmed && (value.is_empty() || value.trim() != value) {
            bail!("Relations canonical text payload is empty or has surrounding whitespace");
        }
    }
    Ok(())
}

/// Validate the native Relations view inside a complete materialized
/// collection. Structural forks remain valid; malformed intrinsic records and
/// their missing attachments do not. Retained legacy facts outside intrinsic
/// snapshot entities remain inert.
pub fn validate_catalog<Store>(reader: &Store, facts: &TribleSet) -> Result<()>
where
    Store: BlobStoreGet + ?Sized,
{
    let handles = validate_structure(facts)?;
    validate_texts(handles, |handle| load_text_from(reader, handle))
}

/// Preflight the native Relations view of the exact generic union that would
/// result from publishing `fragment`. Staged native attachments are read from
/// the fragment overlay; no pile bytes are written by this function.
pub fn validate_catalog_union<Store>(
    reader: &Store,
    current: &TribleSet,
    fragment: &Fragment,
) -> Result<TribleSet>
where
    Store: BlobStoreGet + ?Sized,
{
    let mut expected = current.clone();
    expected += fragment.facts().clone();
    let handles = validate_structure(&expected)?;
    // `BlobStore::reader` freezes a snapshot through `&mut self`.  Cloning a
    // Fragment is O(1) over its PATCH-backed stores, so preflight can do that
    // without mutating the caller's candidate.
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .reader()
        .expect("MemoryBlobStore reader creation is infallible");
    validate_texts(handles, |handle| {
        load_text_overlay(reader, &overlay, handle)
    })?;
    Ok(expected)
}

pub fn read_text<Store>(reader: &Store, handle: TextHandle) -> Result<String>
where
    Store: BlobStoreGet + ?Sized,
{
    load_text_from(reader, handle)
}

pub fn profile_input<Store>(reader: &Store, snapshot: &ProfileSnapshot) -> Result<ProfileInput>
where
    Store: BlobStoreGet + ?Sized,
{
    let read_all = |handles: &[TextHandle]| -> Result<Vec<String>> {
        handles
            .iter()
            .map(|&handle| load_text_from(reader, handle))
            .collect()
    };
    Ok(ProfileInput {
        label: load_text_from(reader, snapshot.label)?,
        aliases: read_all(&snapshot.aliases)?,
        affinities: read_all(&snapshot.affinities)?,
        first_name: snapshot
            .first_name
            .map(|handle| load_text_from(reader, handle))
            .transpose()?,
        last_name: snapshot
            .last_name
            .map(|handle| load_text_from(reader, handle))
            .transpose()?,
        display_name: snapshot
            .display_name
            .map(|handle| load_text_from(reader, handle))
            .transpose()?,
        note: snapshot
            .note
            .map(|handle| load_text_from(reader, handle))
            .transpose()?,
        teams_user_ids: read_all(&snapshot.teams_user_ids)?,
        emails: read_all(&snapshot.emails)?,
        phones: read_all(&snapshot.phones)?,
        company: snapshot
            .company
            .map(|handle| load_text_from(reader, handle))
            .transpose()?,
        position: snapshot
            .position
            .map(|handle| load_text_from(reader, handle))
            .transpose()?,
        profile_urls: read_all(&snapshot.profile_urls)?,
    })
}

pub fn current_profile(facts: &TribleSet, person: Id) -> Result<ProfileSnapshot> {
    match profile_head(facts, person)? {
        Head::Unique(id) => profile_snapshot(facts, id),
        Head::Missing => bail!("person {person:x} has no profile"),
        Head::Forked(heads) => bail!(
            "person {person:x} profile is forked across {} heads: {}",
            heads.len(),
            heads
                .iter()
                .map(|id| format!("{id:x}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

pub fn person_is_retired(facts: &TribleSet, person: Id) -> Result<bool> {
    match lifecycle_head(facts, person)? {
        Head::Unique(id) => Ok(lifecycle_snapshot(facts, id)?.retired),
        Head::Missing => bail!("person {person:x} has no lifecycle"),
        Head::Forked(heads) => bail!(
            "person {person:x} lifecycle is forked across {} heads",
            heads.len()
        ),
    }
}

pub fn current_group(facts: &TribleSet, group_id: Id) -> Result<GroupSnapshot> {
    match group_head(facts, group_id)? {
        Head::Unique(id) => group_snapshot(facts, id),
        Head::Missing => bail!("group {group_id:x} has no snapshot"),
        Head::Forked(heads) => bail!(
            "group {group_id:x} is forked across {} heads: {}",
            heads.len(),
            heads
                .iter()
                .map(|id| format!("{id:x}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

pub fn lookup_key(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn profile_matches<Store>(reader: &Store, snapshot: &ProfileSnapshot, key: &str) -> Result<bool>
where
    Store: BlobStoreGet + ?Sized,
{
    if lookup_key(&load_text_from(reader, snapshot.label)?) == key {
        return Ok(true);
    }
    for &alias in &snapshot.aliases {
        if lookup_key(&load_text_from(reader, alias)?) == key {
            return Ok(true);
        }
    }
    Ok(false)
}

fn id_candidates(input: &str, anchors: &BTreeSet<Id>) -> (bool, BTreeSet<Id>) {
    if !input.is_empty() && input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        if input.len() == 32 {
            let exact = Id::from_hex(input)
                .filter(|id| anchors.contains(id))
                .into_iter()
                .collect();
            return (true, exact);
        }
        if input.len() < 32 {
            return (
                false,
                anchors
                    .iter()
                    .copied()
                    .filter(|id| format!("{id:x}").starts_with(input))
                    .collect(),
            );
        }
    }
    (false, BTreeSet::new())
}

fn selector_outcome(
    settled: BTreeSet<Id>,
    forked: BTreeSet<Id>,
    retired: BTreeSet<Id>,
) -> SelectorOutcome {
    if !forked.is_empty() {
        return SelectorOutcome::Forked {
            forked: forked.into_iter().collect(),
            settled: settled.into_iter().collect(),
        };
    }
    match settled.into_iter().collect::<Vec<_>>().as_slice() {
        [] if !retired.is_empty() => SelectorOutcome::Invalid(format!(
            "the only match is retired and therefore not addressable: {} (`relations unretire` \
             to restore it)",
            retired
                .iter()
                .map(|id| format!("{id:x}"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        [] => SelectorOutcome::Missing,
        [id] => SelectorOutcome::Unique(*id),
        ids => SelectorOutcome::Ambiguous(ids.to_vec()),
    }
}

/// Whether a lifecycle track disqualifies its anchor from selection.
///
/// A fork is only indeterminate when its heads disagree. When every head says
/// the same thing, the answer is settled no matter which head eventually wins,
/// so the fork cannot change the verdict — the same reasoning
/// [`IdentityComponents::from_facts`] already applies to agreement-only
/// verdict forks. `None` means genuinely indeterminate.
fn retired_verdict(facts: &TribleSet, person: Id, state: &Head) -> Result<Option<bool>> {
    match state {
        Head::Unique(id) => Ok(Some(lifecycle_snapshot(facts, *id)?.retired)),
        Head::Forked(heads) => {
            let values: BTreeSet<bool> = heads
                .iter()
                .map(|id| Ok(lifecycle_snapshot(facts, *id)?.retired))
                .collect::<Result<_>>()?;
            Ok(match values.len() {
                1 => values.into_iter().next(),
                _ => None,
            })
        }
        Head::Missing => bail!("person {person:x} has no lifecycle snapshot"),
    }
}

/// Resolve a person selector against current profile and lifecycle state.
///
/// Two rules keep an unreconciled anchor from vetoing an unrelated one:
///
/// 1. **Disqualification precedes fork reporting.** Unless `include_retired`,
///    a retired anchor is dropped outright and never contributes a fork —
///    whether its own state is settled is simply not a question the selector
///    asks about a candidate it has already ruled out.
/// 2. **A fork blocks only when it could change the answer.** The only thing
///    lifecycle decides here is addressability, so a lifecycle fork whose
///    heads all agree is settled for this purpose regardless of which head
///    eventually wins. Heads that disagree are indeterminate and do block.
///
/// A profile fork always blocks a surviving candidate: the label match itself
/// is then head-dependent.
pub fn resolve_person<Store>(
    reader: &Store,
    facts: &TribleSet,
    input: &str,
    include_retired: bool,
) -> Result<SelectorOutcome>
where
    Store: BlobStoreGet + ?Sized,
{
    let input = input.trim();
    if input.is_empty() {
        return Ok(SelectorOutcome::Invalid("empty selector".to_owned()));
    }
    let anchors = person_anchors(facts);
    let normalized = input.to_ascii_lowercase();
    let (exact_id, id_matches) = id_candidates(&normalized, &anchors);
    if exact_id && id_matches.is_empty() {
        return Ok(SelectorOutcome::Missing);
    }

    let key = lookup_key(input);
    let mut settled = BTreeSet::new();
    let mut forked = BTreeSet::new();
    let mut retired = BTreeSet::new();
    for person in anchors {
        let profile_state = profile_head(facts, person)?;
        let label_matches = match &profile_state {
            Head::Unique(id) => profile_matches(reader, &profile_snapshot(facts, *id)?, &key)?,
            Head::Forked(heads) => {
                let mut matches = false;
                for head in heads {
                    let snapshot = profile_snapshot(facts, *head)?;
                    if profile_matches(reader, &snapshot, &key)? {
                        matches = true;
                        break;
                    }
                }
                matches
            }
            Head::Missing => bail!("person {person:x} has no profile snapshot"),
        };
        if !id_matches.contains(&person) && (exact_id || !label_matches) {
            continue;
        }

        // Disqualification comes BEFORE fork reporting. A retired anchor is
        // not a candidate, so its internal consistency cannot bear on whether
        // the selector resolves — otherwise a fork on a retired legacy anchor
        // vetoes a live, perfectly settled match that merely shares its name.
        // A retired person carrying a multi-head profile fork must not poison a
        // live group that happens to share its selector.
        let lifecycle_state = lifecycle_head(facts, person)?;
        let retired_state = retired_verdict(facts, person, &lifecycle_state)?;
        if !include_retired && retired_state == Some(true) {
            retired.insert(person);
            continue;
        }

        // Past this point the anchor really is in the running, so an unsettled
        // track on it genuinely blocks: fail closed rather than pick a head.
        if matches!(profile_state, Head::Forked(_)) || retired_state.is_none() {
            forked.insert(person);
            continue;
        }
        settled.insert(person);
    }
    Ok(selector_outcome(settled, forked, retired))
}

pub fn resolve_group<Store>(
    reader: &Store,
    facts: &TribleSet,
    input: &str,
) -> Result<SelectorOutcome>
where
    Store: BlobStoreGet + ?Sized,
{
    let input = input.trim();
    if input.is_empty() {
        return Ok(SelectorOutcome::Invalid("empty selector".to_owned()));
    }
    let anchors = group_anchors(facts);
    let normalized = input.to_ascii_lowercase();
    let (exact_id, id_matches) = id_candidates(&normalized, &anchors);
    if exact_id && id_matches.is_empty() {
        return Ok(SelectorOutcome::Missing);
    }
    let key = lookup_key(input);
    let mut settled = BTreeSet::new();
    let mut forked = BTreeSet::new();
    for group_id in anchors {
        let state = group_head(facts, group_id)?;
        let label_matches = match &state {
            Head::Unique(id) => {
                let snapshot = group_snapshot(facts, *id)?;
                lookup_key(&load_text_from(reader, snapshot.name)?) == key
            }
            Head::Forked(heads) => {
                let mut matches = false;
                for head in heads {
                    let snapshot = group_snapshot(facts, *head)?;
                    if lookup_key(&load_text_from(reader, snapshot.name)?) == key {
                        matches = true;
                        break;
                    }
                }
                matches
            }
            Head::Missing => bail!("group {group_id:x} has no snapshot"),
        };
        if !id_matches.contains(&group_id) && (exact_id || !label_matches) {
            continue;
        }
        match state {
            Head::Unique(_) => {
                settled.insert(group_id);
            }
            Head::Forked(_) => {
                forked.insert(group_id);
            }
            Head::Missing => unreachable!("handled above"),
        }
    }
    Ok(selector_outcome(settled, forked, BTreeSet::new()))
}

/// Settled semantic relation between two exact person anchors.
///
/// `Unknown` means there is no settled path proving either outcome. Mixed
/// verdict forks and contradictions are errors rather than a fourth value:
/// callers must keep that evidence visible instead of silently treating it as
/// absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityRelation {
    Same,
    Distinct,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct IdentityComponents {
    parent: HashMap<Id, Id>,
    distinct_components: BTreeSet<(Id, Id)>,
    contradictions: BTreeSet<Id>,
    poisoned_components: BTreeSet<Id>,
    forked_pairs: BTreeSet<(Id, Id)>,
    mixed_forked_pairs: BTreeSet<(Id, Id)>,
}

fn find_root(parent: &HashMap<Id, Id>, mut id: Id) -> Id {
    while let Some(&next) = parent.get(&id) {
        if next == id {
            break;
        }
        id = next;
    }
    id
}

fn union_roots(parent: &mut HashMap<Id, Id>, first: Id, second: Id) {
    let first = find_root(parent, first);
    let second = find_root(parent, second);
    if first == second {
        return;
    }
    let (low, high) = if first < second {
        (first, second)
    } else {
        (second, first)
    };
    parent.insert(high, low);
}

impl IdentityComponents {
    pub fn from_facts(facts: &TribleSet) -> Result<Self> {
        let people = person_anchors(facts);
        let mut parent: HashMap<Id, Id> = people.iter().map(|&id| (id, id)).collect();
        let verdict_ids = ids_of_kind(facts, KIND_IDENTITY_VERDICT);
        let mut pairs = BTreeSet::new();
        for id in verdict_ids {
            let verdict = identity_verdict(facts, id)?;
            pairs.insert((verdict.low, verdict.high));
        }

        let mut same = Vec::new();
        let mut distinct = Vec::new();
        let mut forked_pairs = BTreeSet::new();
        let mut mixed_forked_pairs = BTreeSet::new();
        for (low, high) in pairs {
            match identity_head(facts, low, high)? {
                Head::Unique(id) => {
                    let verdict = identity_verdict(facts, id)?;
                    if verdict.same {
                        same.push((low, high));
                    } else {
                        distinct.push((low, high));
                    }
                }
                Head::Forked(heads) => {
                    forked_pairs.insert((low, high));
                    let values: BTreeSet<bool> = heads
                        .into_iter()
                        .map(|id| Ok(identity_verdict(facts, id)?.same))
                        .collect::<Result<_>>()?;
                    if values.len() == 1 && values.contains(&true) {
                        same.push((low, high));
                    } else if values.len() == 1 && values.contains(&false) {
                        distinct.push((low, high));
                    } else {
                        mixed_forked_pairs.insert((low, high));
                    }
                }
                Head::Missing => unreachable!("pair came from a verdict"),
            }
        }

        // Agreement-only lineage forks are still reported through
        // `forked_pairs`, but their semantic value is settled and may safely
        // participate in equality. Only mixed same/distinct forks are
        // semantically indeterminate.
        for (low, high) in same {
            union_roots(&mut parent, low, high);
        }

        let mut contradictions = BTreeSet::new();
        let mut distinct_components = BTreeSet::new();
        for (low, high) in distinct {
            let low_root = find_root(&parent, low);
            let high_root = find_root(&parent, high);
            if low_root == high_root {
                contradictions.insert(low_root);
            } else if low_root < high_root {
                distinct_components.insert((low_root, high_root));
            } else {
                distinct_components.insert((high_root, low_root));
            }
        }
        let mut poisoned_components = BTreeSet::new();
        for &(low, high) in &mixed_forked_pairs {
            let low_root = find_root(&parent, low);
            let high_root = find_root(&parent, high);
            if low_root == high_root {
                poisoned_components.insert(low_root);
            }
        }
        Ok(Self {
            parent,
            distinct_components,
            contradictions,
            poisoned_components,
            forked_pairs,
            mixed_forked_pairs,
        })
    }

    fn root(&self, person: Id) -> Result<Id> {
        if !self.parent.contains_key(&person) {
            bail!("unknown person anchor {person:x}");
        }
        Ok(find_root(&self.parent, person))
    }

    pub fn component(&self, person: Id) -> Result<BTreeSet<Id>> {
        let root = self.root(person)?;
        if self.contradictions.contains(&root) || self.poisoned_components.contains(&root) {
            bail!("identity component containing {person:x} is contradictory or unsettled");
        }
        Ok(self
            .parent
            .keys()
            .copied()
            .filter(|&candidate| find_root(&self.parent, candidate) == root)
            .collect())
    }

    /// Resolve the settled semantic relation without replacing either exact
    /// anchor with a canonical representative. Distinctness is lifted through
    /// settled same-person components in the same way as equality.
    pub fn relation(&self, first: Id, second: Id) -> Result<IdentityRelation> {
        let first_root = self.root(first)?;
        let second_root = self.root(second)?;
        if self.contradictions.contains(&first_root)
            || self.contradictions.contains(&second_root)
            || self.poisoned_components.contains(&first_root)
            || self.poisoned_components.contains(&second_root)
        {
            bail!("identity comparison touches a contradictory or unsettled component");
        }
        if first_root == second_root {
            return Ok(IdentityRelation::Same);
        }
        let roots = if first_root < second_root {
            (first_root, second_root)
        } else {
            (second_root, first_root)
        };
        if self.mixed_forked_pairs.iter().any(|&(low, high)| {
            let pair_roots = {
                let low = find_root(&self.parent, low);
                let high = find_root(&self.parent, high);
                if low < high {
                    (low, high)
                } else {
                    (high, low)
                }
            };
            pair_roots == roots
        }) {
            bail!("identity comparison is unsettled by a forked pair verdict");
        }
        if self.distinct_components.contains(&roots) {
            Ok(IdentityRelation::Distinct)
        } else {
            Ok(IdentityRelation::Unknown)
        }
    }

    /// Boolean projection for callers that only care whether identity is
    /// settled as the same person.
    pub fn equivalent(&self, first: Id, second: Id) -> Result<bool> {
        Ok(self.relation(first, second)? == IdentityRelation::Same)
    }

    pub fn forked_pairs(&self) -> &BTreeSet<(Id, Id)> {
        &self.forked_pairs
    }

    pub fn mixed_forked_pairs(&self) -> &BTreeSet<(Id, Id)> {
        &self.mixed_forked_pairs
    }
}

/// Addressable groups containing `person`, where settled same-person
/// components participate in equality but the exact input anchor remains the
/// caller's attribution identity.
pub fn groups_for_member(facts: &TribleSet, person: Id) -> Result<BTreeSet<Id>> {
    let identities = IdentityComponents::from_facts(facts)?;
    let mut groups = BTreeSet::new();
    for group_id in group_anchors(facts) {
        let snapshot = current_group(facts, group_id)?;
        for member in snapshot.members {
            if identities.equivalent(person, member)? {
                groups.insert(group_id);
                break;
            }
        }
    }
    Ok(groups)
}

/// Pure, fork-visible profile projection for read-only consumers such as the
/// GORBIE widgets. One malformed anchor cannot erase the rest of a roster:
/// its failure is retained as an explicit row value instead.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileView {
    Current { snapshot: Id, value: ProfileInput },
    Forked(Vec<Id>),
    Invalid(String),
}

pub fn person_profile_views<Store>(reader: &Store, facts: &TribleSet) -> Vec<(Id, ProfileView)>
where
    Store: BlobStoreGet + ?Sized,
{
    person_anchors(facts)
        .into_iter()
        .map(|person| {
            let state = match profile_head(facts, person) {
                Ok(Head::Unique(snapshot)) => profile_snapshot(facts, snapshot)
                    .and_then(|profile| profile_input(reader, &profile))
                    .map(|value| ProfileView::Current { snapshot, value })
                    .unwrap_or_else(|error| ProfileView::Invalid(error.to_string())),
                Ok(Head::Forked(heads)) => ProfileView::Forked(heads),
                Ok(Head::Missing) => {
                    ProfileView::Invalid(format!("person {person:x} has no profile snapshot"))
                }
                Err(error) => ProfileView::Invalid(error.to_string()),
            };
            (person, state)
        })
        .collect()
}

/// Every current person profile, preserving exact anchor identity. Retired
/// people are included or excluded explicitly; a fork remains an error.
pub fn current_people<Store>(
    reader: &Store,
    facts: &TribleSet,
    include_retired: bool,
) -> Result<Vec<(Id, ProfileInput)>>
where
    Store: BlobStoreGet + ?Sized,
{
    let mut people = Vec::new();
    for person in person_anchors(facts) {
        if !include_retired && person_is_retired(facts, person)? {
            continue;
        }
        let profile = current_profile(facts, person)?;
        people.push((person, profile_input(reader, &profile)?));
    }
    people.sort_by(|(left_id, left), (right_id, right)| {
        lookup_key(&left.label)
            .cmp(&lookup_key(&right.label))
            .then_with(|| left_id.cmp(right_id))
    });
    Ok(people)
}

/// Return all canonical identity pairs and their fork-visible heads.
pub fn identity_heads(facts: &TribleSet) -> Result<BTreeMap<(Id, Id), Head>> {
    let mut pairs = BTreeSet::new();
    for id in ids_of_kind(facts, KIND_IDENTITY_VERDICT) {
        let verdict = identity_verdict(facts, id)?;
        pairs.insert((verdict.low, verdict.high));
    }
    pairs
        .into_iter()
        .map(|pair| Ok((pair, identity_head(facts, pair.0, pair.1)?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Fixture {
        facts: RefCell<TribleSet>,
        blobs: RefCell<MemoryBlobStore>,
    }

    struct FixtureView {
        facts: TribleSet,
        reader: <MemoryBlobStore as BlobStore>::Reader,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                facts: RefCell::new(TribleSet::new()),
                blobs: RefCell::new(MemoryBlobStore::new()),
            }
        }

        fn publish(&self, fragment: Fragment) {
            let (facts, blobs) = fragment.into_facts_and_blobs();
            *self.facts.borrow_mut() += facts;
            self.blobs.borrow_mut().union(blobs);
        }

        fn view(&self) -> FixtureView {
            FixtureView {
                facts: self.facts.borrow().clone(),
                reader: self.blobs.borrow_mut().reader().unwrap(),
            }
        }
    }

    fn profile(label: &str) -> ProfileInput {
        ProfileInput {
            label: label.to_owned(),
            ..ProfileInput::default()
        }
    }

    fn publish_person(fixture: &Fixture, person: Id, label: &str) {
        let (fragment, _, _) = person_fragment(person, profile(label)).unwrap();
        fixture.publish(fragment);
    }

    fn observed_at(day: u8) -> ObservedAt {
        let epoch = hifitime::Epoch::from_gregorian_utc(2026, 8, day, 12, 0, 0, 0);
        (epoch, epoch).try_to_inline().unwrap()
    }

    #[test]
    fn profile_identity_is_order_independent_and_semantic() {
        let person = genid().id;
        let predecessor_a = genid().id;
        let predecessor_b = genid().id;
        let mut first = profile(" Ada ");
        first.aliases = vec!["Countess".into(), "Ada".into(), "Countess".into()];
        first.emails = vec!["ada@example.test".into(), "a@example.test".into()];
        let mut second = profile("Ada");
        second.aliases = vec!["Ada".into(), "Countess".into()];
        second.emails = vec!["a@example.test".into(), "ada@example.test".into()];

        let a = profile_fragment(person, first, &[predecessor_b, predecessor_a]).unwrap();
        let b = profile_fragment(person, second, &[predecessor_a, predecessor_b]).unwrap();
        assert_eq!(a.root(), b.root());

        let mut changed = profile("Ada Lovelace");
        changed.aliases = vec!["Ada".into(), "Countess".into()];
        changed.emails = vec!["a@example.test".into(), "ada@example.test".into()];
        let changed = profile_fragment(person, changed, &[predecessor_a, predecessor_b]).unwrap();
        assert_ne!(a.root(), changed.root());
    }

    #[test]
    fn later_provenance_union_does_not_move_or_fork_snapshot_heads() {
        let fixture = Fixture::new();
        let person = genid().id;
        let group = genid().id;
        publish_person(&fixture, person, "Ada");
        let (group_fragment, _) = group_create_fragment(group, "crew").unwrap();
        fixture.publish(group_fragment);

        let before = fixture.view();
        let profile_before = profile_head(&before.facts, person).unwrap();
        let lifecycle_before = lifecycle_head(&before.facts, person).unwrap();
        let group_before = group_head(&before.facts, group).unwrap();

        fixture.publish(
            person_provenance_fragment(
                person,
                vec!["linkedin".into(), "mail".into()],
                &[observed_at(9)],
            )
            .unwrap(),
        );
        fixture.publish(
            person_provenance_fragment(
                person,
                vec!["mail".into(), "crm".into()],
                &[observed_at(8)],
            )
            .unwrap(),
        );
        fixture.publish(group_provenance_fragment(group, &[observed_at(10)]));

        let after = fixture.view();
        validate_catalog(&after.reader, &after.facts).unwrap();
        assert_eq!(profile_head(&after.facts, person).unwrap(), profile_before);
        assert_eq!(
            lifecycle_head(&after.facts, person).unwrap(),
            lifecycle_before
        );
        assert_eq!(group_head(&after.facts, group).unwrap(), group_before);
        assert_eq!(
            person_sources(&after.facts, person).unwrap(),
            vec!["crm", "linkedin", "mail"]
        );
    }

    #[test]
    fn creation_observation_minimum_is_order_and_duplicate_independent() {
        let person = genid().id;
        let early = observed_at(8);
        let late = observed_at(10);
        let first = person_provenance_fragment(
            person,
            vec!["mail".into(), "crm".into(), "mail".into()],
            &[late, early, late],
        )
        .unwrap();
        let second =
            person_provenance_fragment(person, vec!["crm".into(), "mail".into()], &[early, late])
                .unwrap();
        assert_eq!(first.facts(), second.facts());

        let facts = first.into_facts();
        assert_eq!(creation_observations(&facts, person), vec![early, late]);
        assert_eq!(earliest_creation_observation(&facts, person), Some(early));
    }

    #[test]
    fn same_identity_verdict_is_symmetric_and_fork_visible() {
        let a = genid().id;
        let b = genid().id;
        let same_ab = identity_verdict_fragment(a, b, true, &[]).unwrap();
        let same_ba = identity_verdict_fragment(b, a, true, &[]).unwrap();
        assert_eq!(same_ab.root(), same_ba.root());

        let distinct = identity_verdict_fragment(a, b, false, &[]).unwrap();
        let mut facts = same_ab.into_facts();
        facts += distinct;
        assert!(matches!(
            identity_head(&facts, a, b).unwrap(),
            Head::Forked(_)
        ));
    }

    #[test]
    fn catalog_accepts_forks_but_rejects_extra_snapshot_facts() {
        let fixture = Fixture::new();
        let person = genid().id;
        publish_person(&fixture, person, "Ada");
        let view = fixture.view();
        let first_head = match profile_head(&view.facts, person).unwrap() {
            Head::Unique(id) => id,
            other => panic!("expected unique profile, got {other:?}"),
        };
        fixture.publish(profile_fragment(person, profile("Ada One"), &[first_head]).unwrap());
        fixture.publish(profile_fragment(person, profile("Ada Two"), &[first_head]).unwrap());
        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        assert!(matches!(
            profile_head(&view.facts, person).unwrap(),
            Head::Forked(_)
        ));
        assert!(matches!(
            person_profile_views(&view.reader, &view.facts).as_slice(),
            [(id, ProfileView::Forked(heads))] if *id == person && heads.len() == 2
        ));

        let fork_head = match profile_head(&view.facts, person).unwrap() {
            Head::Forked(heads) => heads[0],
            _ => unreachable!(),
        };
        let mut malformed = view.facts.clone();
        let existing_handle = profile_snapshot(&view.facts, fork_head).unwrap().label;
        malformed +=
            entity! { ExclusiveId::force_ref(&fork_head) @ profile::email: existing_handle };
        assert!(validate_catalog(&view.reader, &malformed).is_err());
    }

    #[test]
    fn native_views_ignore_preserved_legacy_rows_and_unrelated_facts() {
        let fixture = Fixture::new();
        let person = genid().id;
        let other = genid().id;
        publish_person(&fixture, person, "Ada");
        publish_person(&fixture, other, "Other");
        let group = genid().id;
        let (group_fragment, initial_group) = group_create_fragment(group, "crew").unwrap();
        fixture.publish(group_fragment);
        fixture
            .publish(group_snapshot_fragment(group, "crew", &[person], &[initial_group]).unwrap());

        let before = fixture.view();
        let profile_before = profile_head(&before.facts, person).unwrap();
        let lifecycle_before = lifecycle_head(&before.facts, person).unwrap();
        let group_before = group_head(&before.facts, group).unwrap();

        let old_group_snapshot = genid().id;
        let unrelated = genid().id;
        let missing_legacy_note: TextHandle = Inline::new([0xEE; 32]);
        let mut legacy = Fragment::empty();
        let old_group_name = legacy.put("historical crew".to_owned());
        legacy += entity! { ExclusiveId::force_ref(&person) @
            metadata::name: old_group_name,
            metadata::description: missing_legacy_note,
            legacy::alias: "countess",
            legacy::same_as: &other,
        };
        legacy += entity! { ExclusiveId::force_ref(&old_group_snapshot) @
            group::snapshot_of: &group,
            metadata::name: old_group_name,
            group::member: &other,
        };
        legacy += entity! {
            metadata::tag: &crate::schemas::relations::KIND_RETIRE_ID,
            legacy::subject: &person,
            metadata::created_at: observed_at(11),
        };
        legacy += entity! { ExclusiveId::force_ref(&unrelated) @
            metadata::tag: &genid().id,
        };
        fixture.publish(legacy);

        let after = fixture.view();
        validate_catalog(&after.reader, &after.facts).unwrap();
        assert_eq!(profile_head(&after.facts, person).unwrap(), profile_before);
        assert_eq!(
            lifecycle_head(&after.facts, person).unwrap(),
            lifecycle_before
        );
        assert_eq!(group_head(&after.facts, group).unwrap(), group_before);
        assert_eq!(
            profile_input(
                &after.reader,
                &current_profile(&after.facts, person).unwrap()
            )
            .unwrap()
            .label,
            "Ada"
        );
        assert!(!person_is_retired(&after.facts, person).unwrap());
        assert_eq!(
            current_group(&after.facts, group).unwrap().members,
            vec![person]
        );
        assert_eq!(
            groups_for_member(&after.facts, person).unwrap(),
            [group].into()
        );
        assert!(identity_heads(&after.facts).unwrap().is_empty());
        assert!(group_snapshot(&after.facts, old_group_snapshot).is_err());
        assert!(profile_snapshot(&after.facts, person).is_err());
    }

    #[test]
    fn preflight_reads_staged_payloads_without_writing() {
        let fixture = Fixture::new();
        let view = fixture.view();
        let person = genid().id;
        let mut input = profile("Ada");
        input.emails =
            vec!["a-very-long-address-that-exceeds-thirty-two-bytes@example.test".into()];
        input.teams_user_ids = vec!["00000000-0000-0000-0000-000000000000".into()];
        let (fragment, _, _) = person_fragment(person, input).unwrap();
        let expected = validate_catalog_union(&view.reader, &view.facts, &fragment).unwrap();
        assert!(person_anchors(&expected).contains(&person));
        assert!(person_anchors(&view.facts).is_empty());
    }

    #[test]
    fn lookup_is_computed_and_ambiguity_is_visible() {
        let fixture = Fixture::new();
        let ada = genid().id;
        let other = genid().id;
        let mut first = profile("Ada");
        first.aliases = vec!["Countess".into()];
        let (fragment, _, _) = person_fragment(ada, first).unwrap();
        fixture.publish(fragment);
        publish_person(&fixture, other, "Other");
        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        assert_eq!(
            resolve_person(&view.reader, &view.facts, "  COUNTESS ", false).unwrap(),
            SelectorOutcome::Unique(ada)
        );

        let third = genid().id;
        publish_person(&fixture, third, "countess");
        let view = fixture.view();
        assert_eq!(
            resolve_person(&view.reader, &view.facts, "countess", false).unwrap(),
            SelectorOutcome::Ambiguous(vec![ada.min(third), ada.max(third)])
        );
    }

    /// Fork one person's profile track into two un-superseded heads that both
    /// still answer to `alias`.
    fn fork_profile(fixture: &Fixture, person: Id, label: &str, alias: &str, base: Id) {
        for note in ["left", "right"] {
            let mut input = profile(label);
            input.aliases = vec![alias.to_owned()];
            input.note = Some(note.to_owned());
            fixture.publish(profile_fragment(person, input, &[base]).unwrap());
        }
    }

    /// A broadcast outage in miniature. A retired legacy anchor answering to a
    /// shared selector carried a profile fork, and that fork vetoed the live,
    /// entirely settled candidate.
    #[test]
    fn a_retired_anchor_is_dropped_before_its_fork_can_block_the_selector() {
        let fixture = Fixture::new();
        let legacy = genid().id;
        let live = genid().id;

        let mut input = profile("legacy shared");
        input.aliases = vec!["shared".into()];
        let (fragment, profile_id, lifecycle_id) = person_fragment(legacy, input).unwrap();
        fixture.publish(fragment);
        fork_profile(&fixture, legacy, "legacy shared", "shared", profile_id);
        fixture.publish(lifecycle_fragment(legacy, true, &[lifecycle_id]));

        publish_person(&fixture, live, "shared");
        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        assert!(matches!(
            profile_head(&view.facts, legacy).unwrap(),
            Head::Forked(_)
        ));
        assert!(person_is_retired(&view.facts, legacy).unwrap());

        // Retirement disqualifies before the fork is ever consulted.
        assert_eq!(
            resolve_person(&view.reader, &view.facts, "shared", false).unwrap(),
            SelectorOutcome::Unique(live)
        );
        // An operator who explicitly asks for retired anchors still sees the
        // fork, and sees which side of the tie is the blocker.
        assert_eq!(
            resolve_person(&view.reader, &view.facts, "shared", true).unwrap(),
            SelectorOutcome::Forked {
                forked: vec![legacy],
                settled: vec![live],
            }
        );
    }

    /// The fail-closed half of the rule: a fork on a candidate that really is
    /// in the running must keep blocking, and must be named as the blocker.
    #[test]
    fn a_forked_live_anchor_still_blocks_and_is_named_as_the_blocker() {
        let fixture = Fixture::new();
        let forked_person = genid().id;
        let settled_person = genid().id;

        let mut input = profile("ada");
        input.aliases = vec!["countess".into()];
        let (fragment, profile_id, _) = person_fragment(forked_person, input).unwrap();
        fixture.publish(fragment);
        fork_profile(&fixture, forked_person, "ada", "countess", profile_id);
        publish_person(&fixture, settled_person, "countess");

        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        let outcome = resolve_person(&view.reader, &view.facts, "countess", false).unwrap();
        assert_eq!(
            outcome,
            SelectorOutcome::Forked {
                forked: vec![forked_person],
                settled: vec![settled_person],
            }
        );
        assert_eq!(
            outcome.candidates(),
            sorted_ids([forked_person, settled_person])
        );

        let message = resolve_person(&view.reader, &view.facts, "countess", false)
            .unwrap()
            .require_unique("person", "countess")
            .unwrap_err()
            .to_string();
        // The blocker is named as the blocker, and the innocent match is not
        // listed as though it were one.
        assert!(
            message.contains(&format!("state on {forked_person:x}")),
            "{message}"
        );
        assert!(
            message.contains(&format!(
                "not selectable while the fork stands: {settled_person:x}"
            )),
            "{message}"
        );
    }

    /// A fork only blocks when it could change the answer. The one thing a
    /// lifecycle track decides for a selector is addressability, so heads that
    /// agree are settled for that purpose however the fork later resolves.
    #[test]
    fn a_lifecycle_fork_blocks_only_when_its_heads_disagree() {
        let fixture = Fixture::new();
        let person = genid().id;
        let (fragment, _, active) = person_fragment(person, profile("ada")).unwrap();
        fixture.publish(fragment);

        let resolve = |view: &FixtureView| resolve_person(&view.reader, &view.facts, "ada", false);
        // The two un-superseded lifecycle heads, split by what they claim.
        let split = |fixture: &Fixture| -> (Vec<Id>, Vec<Id>) {
            let facts = fixture.view().facts;
            let heads = match lifecycle_head(&facts, person).unwrap() {
                Head::Forked(heads) => heads,
                other => panic!("expected a fork, got {other:?}"),
            };
            heads
                .into_iter()
                .partition(|id| lifecycle_snapshot(&facts, *id).unwrap().retired)
        };

        // Two windows disagree about whether Ada is retired: indeterminate.
        fixture.publish(lifecycle_fragment(person, true, &[active]));
        fixture.publish(lifecycle_fragment(person, false, &[active]));
        let (says_retired, says_active) = split(&fixture);
        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        assert!(matches!(
            resolve(&view).unwrap(),
            SelectorOutcome::Forked { .. }
        ));

        // Still two heads, but now both say active: Ada is addressable.
        fixture.publish(lifecycle_fragment(person, false, &says_retired));
        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        assert!(matches!(
            lifecycle_head(&view.facts, person).unwrap(),
            Head::Forked(_)
        ));
        assert_eq!(resolve(&view).unwrap(), SelectorOutcome::Unique(person));

        // Disagreement returns: indeterminate again.
        fixture.publish(lifecycle_fragment(person, true, &says_active));
        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        assert!(matches!(
            resolve(&view).unwrap(),
            SelectorOutcome::Forked { .. }
        ));

        // Both heads now say retired: disqualified, and reported as retired
        // rather than as a fork.
        let (_, still_active) = split(&fixture);
        fixture.publish(lifecycle_fragment(person, true, &still_active));
        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        assert!(matches!(
            lifecycle_head(&view.facts, person).unwrap(),
            Head::Forked(_)
        ));
        match resolve(&view).unwrap() {
            SelectorOutcome::Invalid(reason) => {
                assert!(reason.contains("retired"), "{reason}");
                assert!(reason.contains(&format!("{person:x}")), "{reason}");
            }
            other => panic!("expected a retired verdict, got {other:?}"),
        }
        assert_eq!(
            resolve_person(&view.reader, &view.facts, "ada", true).unwrap(),
            SelectorOutcome::Unique(person)
        );
    }

    #[test]
    fn lifecycle_has_no_clock_arbitration() {
        let fixture = Fixture::new();
        let person = genid().id;
        publish_person(&fixture, person, "Ada");
        let view = fixture.view();
        let initial = match lifecycle_head(&view.facts, person).unwrap() {
            Head::Unique(id) => id,
            _ => panic!("expected lifecycle head"),
        };
        fixture.publish(lifecycle_fragment(person, true, &[initial]));
        fixture.publish(lifecycle_fragment(person, false, &[initial]));
        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        assert!(matches!(
            lifecycle_head(&view.facts, person).unwrap(),
            Head::Forked(_)
        ));
        assert!(person_is_retired(&view.facts, person).is_err());
    }

    #[test]
    fn group_reconciliation_is_exactly_the_predecessor_member_union() {
        let fixture = Fixture::new();
        let first = genid().id;
        let second = genid().id;
        publish_person(&fixture, first, "First");
        publish_person(&fixture, second, "Second");

        let group = genid().id;
        let (initial, initial_id) = group_create_fragment(group, "crew").unwrap();
        fixture.publish(initial);
        let left = group_snapshot_fragment(group, "crew", &[first], &[initial_id]).unwrap();
        let left_id = left.root().unwrap();
        fixture.publish(left);
        let right = group_snapshot_fragment(group, "crew", &[second], &[initial_id]).unwrap();
        let right_id = right.root().unwrap();
        fixture.publish(right);

        let fork = fixture.view();
        assert!(matches!(
            group_head(&fork.facts, group).unwrap(),
            Head::Forked(_)
        ));

        let lossy = group_snapshot_fragment(group, "crew", &[], &[left_id, right_id]).unwrap();
        assert!(validate_catalog_union(&fork.reader, &fork.facts, &lossy).is_err());

        let reconciled =
            reconcile_group_fragment(&fork.facts, group, "crew", &[right_id, left_id]).unwrap();
        let settled = validate_catalog_union(&fork.reader, &fork.facts, &reconciled).unwrap();
        let head = match group_head(&settled, group).unwrap() {
            Head::Unique(head) => head,
            other => panic!("expected reconciled group head, got {other:?}"),
        };
        assert_eq!(
            group_snapshot(&settled, head).unwrap().members,
            vec![first.min(second), first.max(second)]
        );
    }

    #[test]
    fn settled_same_components_apply_to_group_membership_without_rewriting_persona() {
        let fixture = Fixture::new();
        let configured_persona = genid().id;
        let equivalent_anchor = genid().id;
        publish_person(&fixture, configured_persona, "Configured");
        publish_person(&fixture, equivalent_anchor, "Imported");
        let group_id = genid().id;
        let (group_fragment, _) = group_create_fragment(group_id, "crew").unwrap();
        fixture.publish(group_fragment);
        let view = fixture.view();
        let group_head = match group_head(&view.facts, group_id).unwrap() {
            Head::Unique(id) => id,
            _ => panic!("expected group head"),
        };
        fixture.publish(
            group_snapshot_fragment(group_id, "crew", &[equivalent_anchor], &[group_head]).unwrap(),
        );
        fixture.publish(
            identity_verdict_fragment(configured_persona, equivalent_anchor, true, &[]).unwrap(),
        );
        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        let identities = IdentityComponents::from_facts(&view.facts).unwrap();
        assert!(identities
            .equivalent(configured_persona, equivalent_anchor)
            .unwrap());
        assert_eq!(
            groups_for_member(&view.facts, configured_persona).unwrap(),
            BTreeSet::from([group_id])
        );
        assert_eq!(configured_persona, configured_persona);
    }

    #[test]
    fn distinctness_propagates_through_settled_same_components() {
        let fixture = Fixture::new();
        let a = genid().id;
        let b = genid().id;
        let c = genid().id;
        let unknown = genid().id;
        publish_person(&fixture, a, "A");
        publish_person(&fixture, b, "B");
        publish_person(&fixture, c, "C");
        publish_person(&fixture, unknown, "Unknown");
        fixture.publish(identity_verdict_fragment(a, b, false, &[]).unwrap());
        fixture.publish(identity_verdict_fragment(b, c, true, &[]).unwrap());

        let view = fixture.view();
        let identities = IdentityComponents::from_facts(&view.facts).unwrap();
        assert_eq!(identities.relation(b, c).unwrap(), IdentityRelation::Same);
        assert_eq!(
            identities.relation(a, c).unwrap(),
            IdentityRelation::Distinct
        );
        assert_eq!(
            identities.relation(a, unknown).unwrap(),
            IdentityRelation::Unknown
        );
        assert!(!identities.equivalent(a, c).unwrap());
    }

    #[test]
    fn transitive_same_and_distinct_is_a_visible_contradiction() {
        let fixture = Fixture::new();
        let a = genid().id;
        let b = genid().id;
        let c = genid().id;
        publish_person(&fixture, a, "A");
        publish_person(&fixture, b, "B");
        publish_person(&fixture, c, "C");
        fixture.publish(identity_verdict_fragment(a, b, true, &[]).unwrap());
        fixture.publish(identity_verdict_fragment(b, c, true, &[]).unwrap());
        fixture.publish(identity_verdict_fragment(a, c, false, &[]).unwrap());
        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        let identities = IdentityComponents::from_facts(&view.facts).unwrap();
        assert!(identities.equivalent(a, c).is_err());
    }

    #[test]
    fn mixed_fork_inside_a_settled_component_poisons_that_component() {
        let fixture = Fixture::new();
        let a = genid().id;
        let b = genid().id;
        let c = genid().id;
        publish_person(&fixture, a, "A");
        publish_person(&fixture, b, "B");
        publish_person(&fixture, c, "C");
        fixture.publish(identity_verdict_fragment(a, b, true, &[]).unwrap());
        fixture.publish(identity_verdict_fragment(b, c, true, &[]).unwrap());
        fixture.publish(identity_verdict_fragment(a, c, true, &[]).unwrap());
        fixture.publish(identity_verdict_fragment(a, c, false, &[]).unwrap());

        let view = fixture.view();
        validate_catalog(&view.reader, &view.facts).unwrap();
        let identities = IdentityComponents::from_facts(&view.facts).unwrap();
        let pair = if a < c { (a, c) } else { (c, a) };
        assert!(identities.mixed_forked_pairs().contains(&pair));
        assert!(identities.equivalent(a, b).is_err());
        assert!(identities.component(c).is_err());
    }

    #[test]
    fn mixed_fork_wins_over_distinctness_between_the_same_components() {
        let fixture = Fixture::new();
        let a = genid().id;
        let b = genid().id;
        let c = genid().id;
        publish_person(&fixture, a, "A");
        publish_person(&fixture, b, "B");
        publish_person(&fixture, c, "C");
        fixture.publish(identity_verdict_fragment(a, b, false, &[]).unwrap());
        fixture.publish(identity_verdict_fragment(b, c, true, &[]).unwrap());
        fixture.publish(identity_verdict_fragment(a, c, true, &[]).unwrap());
        fixture.publish(identity_verdict_fragment(a, c, false, &[]).unwrap());

        let view = fixture.view();
        let identities = IdentityComponents::from_facts(&view.facts).unwrap();
        assert!(identities.relation(a, b).is_err());
        assert!(identities.relation(a, c).is_err());
    }

    #[test]
    fn agreement_only_verdict_fork_is_semantically_settled_but_diagnostic() {
        let fixture = Fixture::new();
        let a = genid().id;
        let b = genid().id;
        publish_person(&fixture, a, "A");
        publish_person(&fixture, b, "B");
        let initial = identity_verdict_fragment(a, b, true, &[]).unwrap();
        let initial_id = initial.root().unwrap();
        fixture.publish(initial);
        fixture.publish(identity_verdict_fragment(a, b, true, &[initial_id]).unwrap());
        let detour = identity_verdict_fragment(a, b, false, &[initial_id]).unwrap();
        let detour_id = detour.root().unwrap();
        fixture.publish(detour);
        fixture.publish(identity_verdict_fragment(a, b, true, &[detour_id]).unwrap());

        let view = fixture.view();
        let identities = IdentityComponents::from_facts(&view.facts).unwrap();
        let pair = if a < b { (a, b) } else { (b, a) };
        assert!(identities.forked_pairs().contains(&pair));
        assert!(!identities.mixed_forked_pairs().contains(&pair));
        assert!(identities.equivalent(a, b).unwrap());
    }
}
