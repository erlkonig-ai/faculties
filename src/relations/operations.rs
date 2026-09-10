//! `relations` — authored people, addressable groups, and explicit identity
//! adjudication in one union-only native collection.
//!
//! Stable person/group anchors never accumulate mutable scalar facts. Every
//! change publishes one intrinsic full-state snapshot with explicit
//! predecessors. Concurrent publications therefore become visible forks;
//! reconciliation is another monotonic child, never deletion, a mutable head,
//! or clock-based arbitration.

use std::collections::{BTreeSet, HashSet};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use crate::clock;
use crate::collection_names::{configured_handle, open_configured, open_exact_in};
use crate::relations::{
    self, GroupSnapshot, Head, IdentityComponents, ProfileInput, ProfileSnapshot, SelectorOutcome,
};
use crate::schemas::relations::DEFAULT_SCOPE_ID;
use crate::storage::{FactArchive, FacultyStore, Storage};
use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::{Collection, CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::repo::async_store::Blocking;
use triblespace::core::repo::SnapshotSource;
use triblespace::prelude::*;

type RelationsReader = Blocking<<FacultyStore as SnapshotSource>::Snapshot>;

struct RelationsStorage<'a> {
    pile: &'a mut FacultyStore,
    signer: &'a SigningKey,
    collection: Collection<SimpleArchive>,
    facts: &'a FactArchive,
    reader: &'a RelationsReader,
}

impl RelationsStorage<'_> {
    fn with_view<T>(
        &self,
        f: impl FnOnce(&FactArchive, &RelationsReader) -> Result<T>,
    ) -> Result<T> {
        f(self.facts, self.reader)
    }

    /// Build one typed local update. `None` is a genuine no-op and writes no
    /// collection record.
    fn update<T>(
        &mut self,
        f: impl FnOnce(&FactArchive, &RelationsReader) -> Result<(Option<Fragment>, T)>,
    ) -> Result<T> {
        let (fragment, result) = f(self.facts, self.reader)?;
        if let Some(fragment) = fragment {
            self.pile
                .commit(self.collection, self.signer, fragment)
                .context("commit authored Relations fragment")?;
        }
        Ok(result)
    }
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn now_observation() -> Result<relations::ObservedAt> {
    clock::point_now()
}

fn resolve_person_anchor(
    reader: &RelationsReader,
    facts: &FactArchive,
    selector: &str,
    include_retired: bool,
) -> Result<Id> {
    match relations::resolve_person(reader, facts, selector, include_retired)? {
        SelectorOutcome::Unique(id) => Ok(id),
        // Reconciliation operations may deliberately address the one stable
        // anchor whose profile/lifecycle happens to have several heads — but
        // only when it is the sole claimant, so no settled match is displaced.
        SelectorOutcome::Forked {
            ref forked,
            ref settled,
        } if forked.len() == 1 && settled.is_empty() => Ok(forked[0]),
        outcome => outcome.require_unique("person", selector),
    }
}

fn resolve_group_anchor(
    reader: &RelationsReader,
    facts: &FactArchive,
    selector: &str,
) -> Result<Id> {
    match relations::resolve_group(reader, facts, selector)? {
        SelectorOutcome::Unique(id) => Ok(id),
        SelectorOutcome::Forked {
            ref forked,
            ref settled,
        } if forked.len() == 1 && settled.is_empty() => Ok(forked[0]),
        outcome => outcome.require_unique("group", selector),
    }
}

fn head_ids(head: Head, subject: &str) -> Result<Vec<Id>> {
    match head {
        Head::Missing => bail!("{subject} has no snapshot"),
        Head::Unique(id) => Ok(vec![id]),
        Head::Forked(ids) => Ok(ids),
    }
}

fn resolve_head_selector(raw: &str, heads: &[Id], label: &str) -> Result<Id> {
    let raw = raw.trim().to_ascii_lowercase();
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) || raw.len() > 32 {
        bail!("invalid {label} head selector '{raw}'");
    }
    let matches: Vec<Id> = heads
        .iter()
        .copied()
        .filter(|id| format!("{id:x}").starts_with(&raw))
        .collect();
    match matches.as_slice() {
        [] => bail!("'{raw}' is not a current {label} head"),
        [id] => Ok(*id),
        _ => bail!("'{raw}' matches multiple current {label} heads"),
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProfileField {
    Aliases,
    Affinities,
    FirstName,
    LastName,
    DisplayName,
    Note,
    TeamsUserIds,
    Emails,
    Phones,
    Company,
    Position,
    ProfileUrls,
}

/// Fields absent from a patch remain untouched. A present repeated field
/// replaces the whole set, including an explicitly empty set. Clear applies
/// only to optional/repeated fields and conflicts with a simultaneous replacement.
#[derive(Clone, Debug, Default)]
pub struct ProfilePatch {
    pub label: Option<String>,
    pub aliases: Option<Vec<String>>,
    pub affinities: Option<Vec<String>>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: Option<String>,
    pub note: Option<String>,
    pub teams_user_ids: Option<Vec<String>>,
    pub emails: Option<Vec<String>>,
    pub phones: Option<Vec<String>>,
    pub company: Option<String>,
    pub position: Option<String>,
    pub profile_urls: Option<Vec<String>>,
    pub clear: Vec<ProfileField>,
}

fn replacement_conflict(
    clears: &HashSet<ProfileField>,
    field: ProfileField,
    replacement_present: bool,
) -> Result<()> {
    if clears.contains(&field) && replacement_present {
        bail!("clearing {field:?} conflicts with its replacement");
    }
    Ok(())
}

fn apply_profile_patch(input: &mut ProfileInput, patch: ProfilePatch) -> Result<bool> {
    let before = input.clone();
    let clears: HashSet<ProfileField> = patch.clear.into_iter().collect();
    if let Some(label) = patch.label {
        input.label = label;
    }
    macro_rules! scalar {
        ($field:ident, $variant:ident) => {
            replacement_conflict(&clears, ProfileField::$variant, patch.$field.is_some())?;
            if clears.contains(&ProfileField::$variant) {
                input.$field = None;
            } else if let Some(value) = patch.$field {
                input.$field = Some(value);
            }
        };
    }
    macro_rules! repeated {
        ($field:ident, $variant:ident) => {
            replacement_conflict(&clears, ProfileField::$variant, patch.$field.is_some())?;
            if clears.contains(&ProfileField::$variant) {
                input.$field.clear();
            } else if let Some(value) = patch.$field {
                input.$field = value;
            }
        };
    }
    repeated!(aliases, Aliases);
    repeated!(affinities, Affinities);
    scalar!(first_name, FirstName);
    scalar!(last_name, LastName);
    scalar!(display_name, DisplayName);
    scalar!(note, Note);
    repeated!(teams_user_ids, TeamsUserIds);
    repeated!(emails, Emails);
    repeated!(phones, Phones);
    scalar!(company, Company);
    scalar!(position, Position);
    repeated!(profile_urls, ProfileUrls);
    Ok(*input != before)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PeopleFilter {
    #[default]
    Active,
    All,
    Retired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddedPerson {
    pub person: Id,
    pub profile: Id,
    pub lifecycle: Id,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileUpdate {
    pub person: Id,
    pub previous: Id,
    pub current: Option<Id>,
    pub provenance_added: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddedGroup {
    pub group: Id,
    pub snapshot: Id,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileReconciliation {
    Settled(Id),
    Reconciled { heads: usize, successor: Id },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleChange {
    Unchanged(Id),
    Changed { person: Id, successor: Id },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupAddition {
    Already(Id),
    Changed { old: Id, new: Id },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupRemoval {
    Absent(Id),
    Changed { old: Id, new: Id },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupRename {
    Unchanged(String),
    Changed { old: Id, new: Id },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupReconciliation {
    Settled(Id),
    Reconciled { heads: usize, successor: Id },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityChange {
    Settled(Id),
    Changed {
        first: Id,
        second: Id,
        successor: Id,
    },
}

fn add_person(
    storage: &mut RelationsStorage<'_>,
    profile: ProfileInput,
    id: Option<Id>,
    source: Vec<String>,
) -> Result<AddedPerson> {
    let person = id.unwrap_or_else(|| genid().id);
    let (mut fragment, profile_id, lifecycle_id) = relations::person_fragment(person, profile)?;
    fragment += relations::person_provenance_fragment(person, source, &[now_observation()?])?;
    storage.update(|_, _| {
        Ok((
            Some(fragment),
            AddedPerson {
                person,
                profile: profile_id,
                lifecycle: lifecycle_id,
            },
        ))
    })
}

fn set_profile(
    storage: &mut RelationsStorage<'_>,
    person: String,
    source: Vec<String>,
    patch: ProfilePatch,
) -> Result<ProfileUpdate> {
    storage.update(|facts, reader| {
        let person = resolve_person_anchor(reader, facts, &person, true)?;
        let current = relations::current_profile(facts, person)?;
        let mut value = relations::profile_input(reader, &current)?;
        let changed = apply_profile_patch(&mut value, patch)?;

        let mut fragment = Fragment::empty();
        let new = if changed {
            let profile = relations::profile_fragment(person, value, &[current.id])?;
            let id = profile.root().expect("profile snapshot root");
            fragment += profile;
            Some(id)
        } else {
            None
        };
        let provenance_added = !source.is_empty();
        if provenance_added {
            fragment += relations::person_provenance_fragment(person, source, &[])?;
        }
        let publish = (!fragment.facts().is_empty()).then_some(fragment);
        Ok((
            publish,
            ProfileUpdate {
                person,
                previous: current.id,
                current: new,
                provenance_added,
            },
        ))
    })
}

fn reconcile_profile(
    storage: &mut RelationsStorage<'_>,
    person_selector: String,
    base: Option<String>,
    patch: ProfilePatch,
) -> Result<ProfileReconciliation> {
    storage.update(|facts, reader| {
        let person = resolve_person_anchor(reader, facts, &person_selector, true)?;
        let heads = head_ids(relations::profile_head(facts, person)?, "person profile")?;
        let snapshots: Vec<(ProfileSnapshot, ProfileInput)> = heads
            .iter()
            .map(|&id| {
                let snapshot = relations::profile_snapshot(facts, id)?;
                let input = relations::profile_input(reader, &snapshot)?;
                Ok((snapshot, input))
            })
            .collect::<Result<_>>()?;
        let base_id = if let Some(base) = base {
            resolve_head_selector(&base, &heads, "profile")?
        } else {
            let first = &snapshots[0].1;
            if snapshots.iter().skip(1).any(|(_, value)| value != first) {
                bail!("profile heads disagree; choose the intended value with --base <head>");
            }
            snapshots[0].0.id
        };
        let mut value = snapshots
            .iter()
            .find(|(snapshot, _)| snapshot.id == base_id)
            .map(|(_, value)| value.clone())
            .expect("selected current head");
        let changed = apply_profile_patch(&mut value, patch)?;
        if heads.len() == 1 && !changed {
            return Ok((None, ProfileReconciliation::Settled(base_id)));
        }
        let fragment = relations::profile_fragment(person, value, &heads)?;
        let successor = fragment.root().expect("profile snapshot root");
        Ok((
            Some(fragment),
            ProfileReconciliation::Reconciled {
                heads: heads.len(),
                successor,
            },
        ))
    })
}

fn lifecycle_state(facts: &FactArchive, person: Id) -> Result<(Vec<Id>, Option<bool>)> {
    match relations::lifecycle_head(facts, person)? {
        Head::Missing => bail!("person {} has no lifecycle", fmt_id(person)),
        Head::Unique(id) => Ok((
            vec![id],
            Some(relations::lifecycle_snapshot(facts, id)?.retired),
        )),
        Head::Forked(ids) => Ok((ids, None)),
    }
}

fn set_retired(
    storage: &mut RelationsStorage<'_>,
    selector: String,
    retired: bool,
) -> Result<LifecycleChange> {
    storage.update(|facts, reader| {
        let person = resolve_person_anchor(reader, facts, &selector, true)?;
        let (heads, current) = lifecycle_state(facts, person)?;
        if current == Some(retired) {
            return Ok((None, LifecycleChange::Unchanged(person)));
        }
        let fragment = relations::lifecycle_fragment(person, retired, &heads);
        let successor = fragment.root().expect("lifecycle snapshot root");
        Ok((
            Some(fragment),
            LifecycleChange::Changed { person, successor },
        ))
    })
}

fn print_values(mut output: &mut String, label: &str, values: &[String]) -> Result<()> {
    for value in values {
        writeln!(&mut output, "{label}: {value}")?;
    }
    Ok(())
}

fn print_profile(mut output: &mut String, id: Id, input: &ProfileInput) -> Result<()> {
    writeln!(&mut output, "profile: {}", fmt_id(id))?;
    writeln!(&mut output, "label: {}", input.label)?;
    print_values(&mut output, "alias", &input.aliases)?;
    print_values(&mut output, "affinity", &input.affinities)?;
    if let Some(value) = &input.first_name {
        writeln!(&mut output, "first_name: {value}")?;
    }
    if let Some(value) = &input.last_name {
        writeln!(&mut output, "last_name: {value}")?;
    }
    if let Some(value) = &input.display_name {
        writeln!(&mut output, "display_name: {value}")?;
    }
    if let Some(value) = &input.company {
        writeln!(&mut output, "company: {value}")?;
    }
    if let Some(value) = &input.position {
        writeln!(&mut output, "position: {value}")?;
    }
    print_values(&mut output, "teams_user_id", &input.teams_user_ids)?;
    print_values(&mut output, "email", &input.emails)?;
    print_values(&mut output, "phone", &input.phones)?;
    print_values(&mut output, "profile_url", &input.profile_urls)?;
    if let Some(value) = &input.note {
        writeln!(&mut output, "note:\n{value}")?;
    }
    Ok(())
}

fn show_person(storage: &mut RelationsStorage<'_>, selector: String) -> Result<String> {
    let mut output = String::new();
    storage.with_view(|facts, reader| {
        let person = resolve_person_anchor(reader, facts, &selector, true)?;
        writeln!(&mut output, "person: {}", fmt_id(person))?;
        print_values(
            &mut output,
            "source",
            &relations::person_sources(facts, person)?,
        )?;
        let observations = relations::creation_observations(facts, person);
        if !observations.is_empty() {
            writeln!(&mut output, "creation_observations: {}", observations.len())?;
        }
        match relations::profile_head(facts, person)? {
            Head::Missing => writeln!(&mut output, "profile: missing")?,
            Head::Unique(id) => {
                let snapshot = relations::profile_snapshot(facts, id)?;
                print_profile(
                    &mut output,
                    id,
                    &relations::profile_input(reader, &snapshot)?,
                )?;
            }
            Head::Forked(ids) => {
                writeln!(&mut output, "profile_fork: {} heads", ids.len())?;
                for id in ids {
                    let snapshot = relations::profile_snapshot(facts, id)?;
                    print_profile(
                        &mut output,
                        id,
                        &relations::profile_input(reader, &snapshot)?,
                    )?;
                }
            }
        }
        match relations::lifecycle_head(facts, person)? {
            Head::Missing => writeln!(&mut output, "lifecycle: missing")?,
            Head::Unique(id) => writeln!(
                &mut output,
                "retired: {}\nlifecycle: {}",
                relations::lifecycle_snapshot(facts, id)?.retired,
                fmt_id(id)
            )?,
            Head::Forked(ids) => {
                writeln!(&mut output, "lifecycle_fork: {} heads", ids.len())?;
                for id in ids {
                    writeln!(
                        &mut output,
                        "- {} retired={}",
                        fmt_id(id),
                        relations::lifecycle_snapshot(facts, id)?.retired
                    )?;
                }
            }
        }
        Ok(output)
    })
}

fn list_people(
    storage: &mut RelationsStorage<'_>,
    limit: usize,
    all: bool,
    retired_only: bool,
) -> Result<String> {
    let mut output = String::new();
    storage.with_view(|facts, reader| {
        let mut rows = Vec::new();
        for person in relations::person_anchors(facts) {
            let lifecycle = relations::lifecycle_head(facts, person)?;
            let retired = match &lifecycle {
                Head::Unique(id) => Some(relations::lifecycle_snapshot(facts, *id)?.retired),
                Head::Missing | Head::Forked(_) => None,
            };
            if retired_only && retired != Some(true) {
                continue;
            }
            if !all && !retired_only && retired == Some(true) {
                continue;
            }
            let profile = relations::profile_head(facts, person)?;
            let (label, marker) = match profile {
                Head::Unique(id) => {
                    let snapshot = relations::profile_snapshot(facts, id)?;
                    (relations::read_text(reader, snapshot.label)?, String::new())
                }
                Head::Forked(ids) => (
                    "<forked profile>".to_owned(),
                    format!(" [profile fork: {} heads]", ids.len()),
                ),
                Head::Missing => ("<missing profile>".to_owned(), " [invalid]".to_owned()),
            };
            let lifecycle_marker = match lifecycle {
                Head::Forked(ids) => format!(" [lifecycle fork: {} heads]", ids.len()),
                _ if retired == Some(true) => " [retired]".to_owned(),
                _ => String::new(),
            };
            rows.push((
                relations::lookup_key(&label),
                person,
                label,
                marker,
                lifecycle_marker,
            ));
        }
        rows.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        if rows.is_empty() {
            writeln!(&mut output, "No people.")?;
        }
        for (_, person, label, marker, lifecycle) in rows.into_iter().take(limit) {
            writeln!(
                &mut output,
                "[{}] {label}{marker}{lifecycle}",
                fmt_id(person)
            )?;
        }
        Ok(output)
    })
}

fn create_group(storage: &mut RelationsStorage<'_>, name: String) -> Result<AddedGroup> {
    storage.update(|facts, reader| {
        match relations::resolve_group(reader, facts, &name)? {
            SelectorOutcome::Missing => {}
            outcome => {
                let existing = outcome.require_unique("group", &name)?;
                bail!("group '{}' already resolves to {}", name, fmt_id(existing));
            }
        }
        let group = genid().id;
        let (mut fragment, snapshot) = relations::group_create_fragment(group, name)?;
        fragment += relations::group_provenance_fragment(group, &[now_observation()?]);
        Ok((Some(fragment), AddedGroup { group, snapshot }))
    })
}

fn add_group_member(
    storage: &mut RelationsStorage<'_>,
    group_selector: String,
    person_selector: String,
) -> Result<GroupAddition> {
    storage.update(|facts, reader| {
        let group = resolve_group_anchor(reader, facts, &group_selector)?;
        let person = resolve_person_anchor(reader, facts, &person_selector, true)?;
        let current = relations::current_group(facts, group)?;
        let identities = IdentityComponents::from_facts(facts)?;
        for &member in &current.members {
            if identities.equivalent(person, member)? {
                return Ok((None, GroupAddition::Already(person)));
            }
        }
        let mut members = current.members.clone();
        members.push(person);
        let name = relations::read_text(reader, current.name)?;
        let old = current.id;
        let fragment = relations::group_snapshot_fragment(group, name, &members, &[old])?;
        let new = fragment.root().expect("group snapshot root");
        Ok((Some(fragment), GroupAddition::Changed { old, new }))
    })
}

fn remove_group_member(
    storage: &mut RelationsStorage<'_>,
    group_selector: String,
    person_selector: String,
) -> Result<GroupRemoval> {
    storage.update(|facts, reader| {
        let group = resolve_group_anchor(reader, facts, &group_selector)?;
        let person = resolve_person_anchor(reader, facts, &person_selector, true)?;
        let current = relations::current_group(facts, group)?;
        let identities = IdentityComponents::from_facts(facts)?;
        let mut members = Vec::new();
        for member in current.members.iter().copied() {
            if !identities.equivalent(person, member)? {
                members.push(member);
            }
        }
        if members.len() == current.members.len() {
            return Ok((None, GroupRemoval::Absent(person)));
        }
        let name = relations::read_text(reader, current.name)?;
        let old = current.id;
        let fragment = relations::group_snapshot_fragment(group, name, &members, &[old])?;
        let new = fragment.root().expect("group snapshot root");
        Ok((Some(fragment), GroupRemoval::Changed { old, new }))
    })
}

fn rename_group(
    storage: &mut RelationsStorage<'_>,
    group_selector: String,
    name: String,
) -> Result<GroupRename> {
    storage.update(|facts, reader| {
        let group = resolve_group_anchor(reader, facts, &group_selector)?;
        let current = relations::current_group(facts, group)?;
        let old_name = relations::read_text(reader, current.name)?;
        if old_name.trim() == name.trim() {
            return Ok((None, GroupRename::Unchanged(old_name)));
        }
        let old = current.id;
        let fragment = relations::group_snapshot_fragment(group, name, &current.members, &[old])?;
        let new = fragment.root().expect("group snapshot root");
        Ok((Some(fragment), GroupRename::Changed { old, new }))
    })
}

fn reconcile_group(
    storage: &mut RelationsStorage<'_>,
    selector: String,
    explicit_name: Option<String>,
) -> Result<GroupReconciliation> {
    storage.update(|facts, reader| {
        let group = resolve_group_anchor(reader, facts, &selector)?;
        let heads = head_ids(relations::group_head(facts, group)?, "group")?;
        if heads.len() == 1 && explicit_name.is_none() {
            return Ok((None, GroupReconciliation::Settled(heads[0])));
        }
        if heads.len() == 1 {
            bail!("group has one head; use `relations group rename` to change its name");
        }
        let snapshots: Vec<GroupSnapshot> = heads
            .iter()
            .map(|&id| relations::group_snapshot(facts, id))
            .collect::<Result<_>>()?;
        let name = if let Some(name) = explicit_name {
            name
        } else {
            let names: BTreeSet<String> = snapshots
                .iter()
                .map(|snapshot| relations::read_text(reader, snapshot.name))
                .collect::<Result<_>>()?;
            if names.len() != 1 {
                bail!("group heads disagree on the name; provide --name");
            }
            names.into_iter().next().expect("one name")
        };
        // The core helper is the single authority for the multi-parent join:
        // every immediate predecessor member is retained.
        let fragment = relations::reconcile_group_fragment(facts, group, name, &heads)?;
        let successor = fragment.root().expect("group snapshot root");
        Ok((
            Some(fragment),
            GroupReconciliation::Reconciled {
                heads: heads.len(),
                successor,
            },
        ))
    })
}

fn print_group_snapshot(
    mut output: &mut String,
    reader: &RelationsReader,
    facts: &FactArchive,
    snapshot: GroupSnapshot,
) -> Result<()> {
    writeln!(&mut output, "snapshot: {}", fmt_id(snapshot.id))?;
    writeln!(
        &mut output,
        "name: {}",
        relations::read_text(reader, snapshot.name)?
    )?;
    for member in snapshot.members {
        let label = relations::current_profile(facts, member)
            .and_then(|profile| relations::read_text(reader, profile.label))
            .unwrap_or_else(|_| "<unsettled profile>".to_owned());
        writeln!(&mut output, "member: {} {label}", fmt_id(member))?;
    }
    Ok(())
}

fn show_group(storage: &mut RelationsStorage<'_>, selector: String) -> Result<String> {
    let mut output = String::new();
    storage.with_view(|facts, reader| {
        let group = resolve_group_anchor(reader, facts, &selector)?;
        writeln!(&mut output, "group: {}", fmt_id(group))?;
        match relations::group_head(facts, group)? {
            Head::Missing => writeln!(&mut output, "snapshot: missing")?,
            Head::Unique(id) => print_group_snapshot(
                &mut output,
                reader,
                facts,
                relations::group_snapshot(facts, id)?,
            )?,
            Head::Forked(ids) => {
                writeln!(&mut output, "group_fork: {} heads", ids.len())?;
                for id in ids {
                    print_group_snapshot(
                        &mut output,
                        reader,
                        facts,
                        relations::group_snapshot(facts, id)?,
                    )?;
                }
            }
        }
        Ok(output)
    })
}

fn list_groups(storage: &mut RelationsStorage<'_>) -> Result<String> {
    let mut output = String::new();
    storage.with_view(|facts, reader| {
        let mut rows = Vec::new();
        for group in relations::group_anchors(facts) {
            match relations::group_head(facts, group)? {
                Head::Unique(id) => {
                    let snapshot = relations::group_snapshot(facts, id)?;
                    rows.push((
                        relations::read_text(reader, snapshot.name)?,
                        group,
                        format!("{} members", snapshot.members.len()),
                    ));
                }
                Head::Forked(ids) => rows.push((
                    "<forked group>".to_owned(),
                    group,
                    format!("fork: {} heads", ids.len()),
                )),
                Head::Missing => {
                    rows.push(("<missing group>".to_owned(), group, "invalid".to_owned()))
                }
            }
        }
        rows.sort_by(|left, right| {
            relations::lookup_key(&left.0)
                .cmp(&relations::lookup_key(&right.0))
                .then_with(|| left.1.cmp(&right.1))
        });
        if rows.is_empty() {
            writeln!(&mut output, "No groups.")?;
        }
        for (name, group, state) in rows {
            writeln!(&mut output, "[{}] {name} ({state})", fmt_id(group))?;
        }
        Ok(output)
    })
}

fn resolve_identity(
    storage: &mut RelationsStorage<'_>,
    first: String,
    second: String,
    same: bool,
) -> Result<IdentityChange> {
    storage.update(|facts, reader| {
        let first = resolve_person_anchor(reader, facts, &first, true)?;
        let second = resolve_person_anchor(reader, facts, &second, true)?;
        if first == second {
            bail!("an identity verdict requires two different person anchors");
        }
        let predecessors = match relations::identity_head(facts, first, second)? {
            Head::Missing => Vec::new(),
            Head::Unique(id) => {
                if relations::identity_verdict(facts, id)?.same == same {
                    return Ok((None, IdentityChange::Settled(id)));
                }
                vec![id]
            }
            Head::Forked(ids) => ids,
        };
        let fragment = relations::identity_verdict_fragment(first, second, same, &predecessors)?;
        let successor = fragment.root().expect("identity verdict root");
        Ok((
            Some(fragment),
            IdentityChange::Changed {
                first,
                second,
                successor,
            },
        ))
    })
}

fn list_identities(storage: &mut RelationsStorage<'_>) -> Result<String> {
    let mut output = String::new();
    storage.with_view(|facts, _| {
        let heads = relations::identity_heads(facts)?;
        if heads.is_empty() {
            writeln!(&mut output, "No identity verdicts.")?;
        }
        for ((low, high), head) in heads {
            match head {
                Head::Missing => unreachable!("listed pair has a verdict"),
                Head::Unique(id) => writeln!(
                    &mut output,
                    "{} {} {} [{}]",
                    fmt_id(low),
                    if relations::identity_verdict(facts, id)?.same {
                        "same-as"
                    } else {
                        "distinct-from"
                    },
                    fmt_id(high),
                    fmt_id(id)
                )?,
                Head::Forked(ids) => {
                    writeln!(
                        &mut output,
                        "{} ? {} [fork: {} heads]",
                        fmt_id(low),
                        fmt_id(high),
                        ids.len()
                    )?;
                    for id in ids {
                        writeln!(
                            &mut output,
                            "- {} {}",
                            fmt_id(id),
                            if relations::identity_verdict(facts, id)?.same {
                                "same-as"
                            } else {
                                "distinct-from"
                            }
                        )?;
                    }
                }
            }
        }
        Ok(output)
    })
}

/// Configured Relations operations. Each call maintains the exact configured
/// collection then observes one immutable fact/payload boundary.
#[derive(Clone, Debug)]
pub struct Relations {
    storage: Storage,
}

impl Relations {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(Storage::new(pile, key))
    }

    pub fn with_storage(storage: Storage) -> Self {
        Self { storage }
    }

    fn with_relations<T>(
        &self,
        execute: impl FnOnce(&mut RelationsStorage<'_>) -> Result<T>,
    ) -> Result<T> {
        self.storage.with_store(|pile, signer, runtime| {
            let collection = if let Some(handle) = configured_handle(DEFAULT_SCOPE_ID)? {
                let reader = Blocking::with_runtime(pile.snapshot()?, Arc::clone(runtime));
                open_exact_in(&reader, DEFAULT_SCOPE_ID, handle)?
            } else {
                open_configured(pile, DEFAULT_SCOPE_ID, signer.verifying_key())?
            };
            let descriptor_snapshot = pile.snapshot()?;
            let policy = collection.policy(&descriptor_snapshot)?;
            drop(descriptor_snapshot);
            let facts_succinct =
                pile.derive::<SuccinctArchiveBlob>(collection, (), policy.clone())?;
            let facts_rank9 =
                pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(facts_succinct, (), policy)?;
            let reader = runtime
                .block_on(async {
                    drop(pile.ensure(collection).await?);
                    drop(pile.maintain(facts_succinct).await?);
                    pile.maintain(facts_rank9).await
                })
                .context("maintain Relations fact collection")?;
            let observed = reader
                .collection(facts_rank9)
                .context("observe Relations Rank9 projection")?;
            let view = observed
                .view::<FactArchive>()
                .context("read Relations Rank9 projection")?;
            // Only exact payload gets may acquire here. Facts, records, proofs,
            // and their interpretation instant remain those of this observation.
            // Dispatch stays outside block_on: Blocking owns the one CLI boundary.
            let payload_reader = Blocking::with_runtime(reader.clone(), Arc::clone(runtime));
            let mut storage = RelationsStorage {
                pile,
                signer,
                collection,
                facts: &view,
                reader: &payload_reader,
            };

            execute(&mut storage)
        })
    }

    pub fn add(
        &self,
        profile: ProfileInput,
        id: Option<Id>,
        sources: &[String],
    ) -> Result<AddedPerson> {
        self.with_relations(|storage| add_person(storage, profile, id, sources.to_vec()))
    }
    pub fn set(
        &self,
        person: &str,
        patch: ProfilePatch,
        sources: &[String],
    ) -> Result<ProfileUpdate> {
        self.with_relations(|storage| {
            set_profile(storage, person.to_owned(), sources.to_vec(), patch)
        })
    }
    pub fn reconcile(
        &self,
        person: &str,
        base: Option<&str>,
        patch: ProfilePatch,
    ) -> Result<ProfileReconciliation> {
        self.with_relations(|storage| {
            reconcile_profile(storage, person.to_owned(), base.map(str::to_owned), patch)
        })
    }
    pub fn list(&self, limit: usize, filter: PeopleFilter) -> Result<String> {
        self.with_relations(|storage| {
            list_people(
                storage,
                limit,
                filter == PeopleFilter::All,
                filter == PeopleFilter::Retired,
            )
        })
    }
    pub fn show(&self, person: &str) -> Result<String> {
        self.with_relations(|storage| show_person(storage, person.to_owned()))
    }
    pub fn retire(&self, person: &str) -> Result<LifecycleChange> {
        self.with_relations(|storage| set_retired(storage, person.to_owned(), true))
    }
    pub fn unretire(&self, person: &str) -> Result<LifecycleChange> {
        self.with_relations(|storage| set_retired(storage, person.to_owned(), false))
    }
    pub fn group_create(&self, name: &str) -> Result<AddedGroup> {
        self.with_relations(|storage| create_group(storage, name.to_owned()))
    }
    pub fn group_add(&self, group: &str, person: &str) -> Result<GroupAddition> {
        self.with_relations(|storage| {
            add_group_member(storage, group.to_owned(), person.to_owned())
        })
    }
    pub fn group_remove(&self, group: &str, person: &str) -> Result<GroupRemoval> {
        self.with_relations(|storage| {
            remove_group_member(storage, group.to_owned(), person.to_owned())
        })
    }
    pub fn group_rename(&self, group: &str, name: &str) -> Result<GroupRename> {
        self.with_relations(|storage| rename_group(storage, group.to_owned(), name.to_owned()))
    }
    pub fn group_reconcile(&self, group: &str, name: Option<&str>) -> Result<GroupReconciliation> {
        self.with_relations(|storage| {
            reconcile_group(storage, group.to_owned(), name.map(str::to_owned))
        })
    }
    pub fn group_list(&self) -> Result<String> {
        self.with_relations(list_groups)
    }
    pub fn group_show(&self, group: &str) -> Result<String> {
        self.with_relations(|storage| show_group(storage, group.to_owned()))
    }
    pub fn identity_resolve(
        &self,
        first: &str,
        second: &str,
        same: bool,
    ) -> Result<IdentityChange> {
        self.with_relations(|storage| {
            resolve_identity(storage, first.to_owned(), second.to_owned(), same)
        })
    }
    pub fn identity_list(&self) -> Result<String> {
        self.with_relations(list_identities)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{initialize_signer, load_signer, open_pile_strict, open_store, runtime};
    use std::fs;
    use triblespace::core::blob::encodings::UnknownBlob;
    use triblespace::core::blob::Bytes;
    use triblespace::core::collection::{
        CollectionRead, CollectionRecord, CollectionRecordSelector,
    };
    use triblespace::core::repo::StorageClose;

    fn profile(label: &str) -> ProfileInput {
        ProfileInput {
            label: label.to_owned(),
            aliases: vec!["old alias".to_owned()],
            emails: vec!["old@example.test".to_owned()],
            first_name: Some("Ada".to_owned()),
            ..ProfileInput::default()
        }
    }

    #[test]
    fn profile_patch_preserves_unspecified_and_replaces_sets() {
        let mut value = profile("ada");
        let changed = apply_profile_patch(
            &mut value,
            ProfilePatch {
                aliases: Some(vec!["Countess".to_owned(), "Enchantress".to_owned()]),
                company: Some("Analytical Engines".to_owned()),
                ..ProfilePatch::default()
            },
        )
        .unwrap();
        assert!(changed);
        assert_eq!(value.first_name.as_deref(), Some("Ada"));
        assert_eq!(value.emails, vec!["old@example.test"]);
        assert_eq!(value.aliases, vec!["Countess", "Enchantress"]);
        assert_eq!(value.company.as_deref(), Some("Analytical Engines"));
    }

    #[test]
    fn profile_patch_clear_is_explicit_and_conflicts_with_replacement() {
        let mut value = profile("ada");
        apply_profile_patch(
            &mut value,
            ProfilePatch {
                clear: vec![ProfileField::FirstName, ProfileField::Emails],
                ..ProfilePatch::default()
            },
        )
        .unwrap();
        assert_eq!(value.first_name, None);
        assert!(value.emails.is_empty());

        let error = apply_profile_patch(
            &mut value,
            ProfilePatch {
                emails: Some(vec!["new@example.test".to_owned()]),
                clear: vec![ProfileField::Emails],
                ..ProfilePatch::default()
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("conflicts"));
    }

    #[test]
    fn native_collection_updates_expose_profile_forks() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("relations.pile");
        let key = directory.path().join("relations.key");
        fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        let signer = load_signer(&pile, Some(&key)).unwrap();
        let mut store = open_pile_strict(&pile).unwrap();
        let collection =
            open_configured(&mut store, DEFAULT_SCOPE_ID, signer.verifying_key()).unwrap();
        let descriptor_snapshot = store.snapshot().unwrap();
        let policy = collection.policy(&descriptor_snapshot).unwrap();
        drop(descriptor_snapshot);
        let facts_succinct = store
            .derive::<SuccinctArchiveBlob>(collection, (), policy.clone())
            .unwrap();
        let facts_rank9 = store
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(facts_succinct, (), policy)
            .unwrap();

        let person = genid().id;
        let (fragment, initial, _) = relations::person_fragment(person, profile("Ada")).unwrap();
        store.commit(collection, &signer, fragment).unwrap();

        let left = relations::profile_fragment(person, profile("Ada Left"), &[initial]).unwrap();
        let right = relations::profile_fragment(person, profile("Ada Right"), &[initial]).unwrap();
        store.commit(collection, &signer, left).unwrap();
        store.commit(collection, &signer, right).unwrap();

        let reader = pollster::block_on(async {
            drop(store.ensure(collection).await?);
            drop(store.maintain(facts_succinct).await?);
            store.maintain(facts_rank9).await
        })
        .unwrap();
        let observed = reader.collection(facts_rank9).unwrap();
        let view = observed.view::<FactArchive>().unwrap();
        match relations::profile_head(&view, person).unwrap() {
            Head::Forked(heads) => assert_eq!(heads.len(), 2),
            other => panic!("expected visible fork, got {other:?}"),
        }
        drop(view);
        drop(observed);
        drop(reader);
        store.close().unwrap();
    }

    #[test]
    fn snapshot_payload_reads_keep_relations_facts_frozen_and_publish_once() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relations.pile");
        let key = directory.path().join("relations.key");
        fs::File::create(&path).unwrap();
        let signer = initialize_signer(&path, Some(&key)).unwrap();
        let runtime = Arc::new(runtime().unwrap());
        let mut pile = open_store(&path).unwrap();
        let collection =
            crate::collection_names::open(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())
                .unwrap();
        let policy = collection.policy(&pile.snapshot().unwrap()).unwrap();
        let succinct = pile
            .derive::<SuccinctArchiveBlob>(collection, (), policy.clone())
            .unwrap();
        let rank9 = pile
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
            .unwrap();

        let person = genid().id;
        let (fragment, initial_profile, _) =
            relations::person_fragment(person, profile("Ada")).unwrap();
        let (facts, mut payloads) = fragment.into_facts_and_blobs();
        let label = relations::profile_snapshot(&facts, initial_profile)
            .unwrap()
            .label;
        // The source archive is present, but its text attachments are cold.
        let initial = pile.commit(collection, &signer, facts.into()).unwrap();
        let frozen = runtime
            .block_on(async {
                drop(pile.ensure(collection).await?);
                drop(pile.maintain(succinct).await?);
                pile.maintain(rank9).await
            })
            .unwrap();
        let instant = frozen.instant();
        assert!(!frozen.contains_blob(label).unwrap());
        let observed = frozen.collection(rank9).unwrap();
        let view = observed.view::<FactArchive>().unwrap();
        let reader = Blocking::with_runtime(frozen.clone(), Arc::clone(&runtime));

        // Model bytes arriving in shared backing after the semantic snapshot.
        // Exact get may use them; it must not adopt the later person's facts.
        let payloads = payloads.snapshot().unwrap();
        for blob in payloads.blobs() {
            let blob = blob.unwrap();
            let bytes: Bytes = payloads.get(blob.handle).unwrap();
            pile.put::<UnknownBlob, _>(bytes).unwrap();
        }
        let later_person = genid().id;
        let (later, _, _) = relations::person_fragment(later_person, profile("Ada")).unwrap();
        pile.commit(collection, &signer, later).unwrap();

        let mut storage = RelationsStorage {
            pile: &mut pile,
            signer: &signer,
            collection,
            facts: &view,
            reader: &reader,
        };
        storage
            .with_view(|facts, reader| {
                assert_eq!(resolve_person_anchor(reader, facts, "Ada", false)?, person);
                assert_eq!(
                    resolve_person_anchor(reader, facts, "old alias", false)?,
                    person
                );
                assert_eq!(relations::person_anchors(facts), BTreeSet::from([person]));
                let current = relations::current_profile(facts, person)?;
                assert_eq!(relations::profile_input(reader, &current)?, profile("Ada"));
                Ok(())
            })
            .unwrap();
        let successor = storage
            .update(|facts, reader| {
                let current = relations::current_profile(facts, person)?;
                let mut input = relations::profile_input(reader, &current)?;
                input.note = Some("one snapshot-backed publication".to_owned());
                let fragment = relations::profile_fragment(person, input, &[current.id])?;
                let successor = fragment.root().unwrap();
                Ok((Some(fragment), successor))
            })
            .unwrap();
        assert_ne!(successor, initial_profile);
        drop(storage);

        let selectors = BTreeSet::from([CollectionRecordSelector::Collection(collection.handle())]);
        assert_eq!(frozen.instant(), instant);
        assert!(!frozen.contains_blob(label).unwrap());
        assert_eq!(
            frozen.select_records(&selectors).unwrap(),
            vec![CollectionRecord::Commit(initial)],
        );
        assert_eq!(
            relations::profile_head(&view, person).unwrap(),
            Head::Unique(initial_profile)
        );
        let after = pile.snapshot().unwrap();
        assert_eq!(after.select_records(&selectors).unwrap().len(), 3);
        assert_eq!(after.wants().unwrap().count(), 0);
        drop(after);
        drop(reader);
        drop(view);
        drop(observed);
        drop(frozen);
        pile.close().unwrap();
    }
}
