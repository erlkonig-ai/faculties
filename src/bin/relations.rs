//! `relations` — authored people, addressable groups, and explicit identity
//! adjudication in one union-only collection.
//!
//! Stable person/group anchors never accumulate mutable scalar facts. Every
//! change publishes one intrinsic full-state snapshot with explicit
//! predecessors. Concurrent publications therefore become visible forks;
//! reconciliation is another monotonic child, never deletion or clock-based
//! arbitration.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use faculties::collection_access::{self, CollectionView};
use faculties::relations::{
    self, GroupSnapshot, Head, IdentityComponents, ProfileInput, ProfileSnapshot, SelectorOutcome,
};
use faculties::schemas::relations::DEFAULT_SCOPE_ID;
use triblespace::core::metadata;
use triblespace::macros::entity;
use triblespace::prelude::*;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "relations",
    about = "Authored people, groups, and identity verdicts"
)]
struct Cli {
    /// Path to the pile file.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Extrinsic collection scope. Defaults to the stable Relations scope.
    #[arg(long, value_parser = parse_id_arg)]
    scope: Option<Id>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Add a stable person anchor with an initial profile and active lifecycle.
    Add {
        /// Canonical human-facing label.
        label: String,
        /// Exact stable person id. Omit to mint a fresh anchor.
        #[arg(long, value_parser = parse_id_arg)]
        id: Option<Id>,
        #[command(flatten)]
        profile: NewProfileArgs,
    },
    /// Replace selected fields of one current profile snapshot.
    Set {
        /// Person label, alias, exact id, or id prefix.
        person: String,
        #[command(flatten)]
        patch: ProfilePatchArgs,
    },
    /// Collapse concurrent profile heads into one explicit successor.
    Reconcile {
        /// Person label, alias, exact id, or id prefix.
        person: String,
        /// Fork head whose full profile is the base. Optional only when every
        /// current head has the same semantic profile value.
        #[arg(long)]
        base: Option<String>,
        #[command(flatten)]
        patch: ProfilePatchArgs,
    },
    /// List person anchors and their current state.
    List {
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Include settled retired people.
        #[arg(long)]
        all: bool,
        /// Show only settled retired people.
        #[arg(long, conflicts_with = "all")]
        retired: bool,
    },
    /// Show one person, including all heads when a track is forked.
    Show {
        /// Person label, alias, exact id, or id prefix.
        person: String,
    },
    /// Publish a retired lifecycle successor (also reconciles a lifecycle fork).
    Retire { person: String },
    /// Publish an active lifecycle successor (also reconciles a lifecycle fork).
    #[command(alias = "restore")]
    Unretire { person: String },
    /// Manage addressable exact-member groups.
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
    /// Record and inspect explicit same-person/distinct-person verdicts.
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
}

#[derive(Args, Clone, Default)]
struct NewProfileArgs {
    #[arg(long)]
    alias: Vec<String>,
    #[arg(long)]
    affinity: Vec<String>,
    #[arg(long)]
    first_name: Option<String>,
    #[arg(long)]
    last_name: Option<String>,
    #[arg(long)]
    display_name: Option<String>,
    #[arg(long)]
    note: Option<String>,
    #[arg(long)]
    teams_user_id: Vec<String>,
    #[arg(long)]
    email: Vec<String>,
    #[arg(long)]
    phone: Vec<String>,
    #[arg(long)]
    company: Option<String>,
    #[arg(long)]
    position: Option<String>,
    #[arg(long)]
    profile_url: Vec<String>,
}

impl NewProfileArgs {
    fn into_profile(self, label: String) -> ProfileInput {
        ProfileInput {
            label,
            aliases: self.alias,
            affinities: self.affinity,
            first_name: self.first_name,
            last_name: self.last_name,
            display_name: self.display_name,
            note: self.note,
            teams_user_ids: self.teams_user_id,
            emails: self.email,
            phones: self.phone,
            company: self.company,
            position: self.position,
            profile_urls: self.profile_url,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, ValueEnum)]
enum ProfileField {
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

#[derive(Args, Clone, Default)]
struct ProfilePatchArgs {
    #[arg(long)]
    label: Option<String>,
    /// Replace the complete alias set (repeat for multiple values).
    #[arg(long)]
    alias: Vec<String>,
    /// Replace the complete affinity set (repeat for multiple values).
    #[arg(long)]
    affinity: Vec<String>,
    #[arg(long)]
    first_name: Option<String>,
    #[arg(long)]
    last_name: Option<String>,
    #[arg(long)]
    display_name: Option<String>,
    #[arg(long)]
    note: Option<String>,
    /// Replace the complete Teams-id set (repeat for multiple values).
    #[arg(long)]
    teams_user_id: Vec<String>,
    /// Replace the complete email set (repeat for multiple values).
    #[arg(long)]
    email: Vec<String>,
    /// Replace the complete phone set (repeat for multiple values).
    #[arg(long)]
    phone: Vec<String>,
    #[arg(long)]
    company: Option<String>,
    #[arg(long)]
    position: Option<String>,
    /// Replace the complete profile-URL set (repeat for multiple values).
    #[arg(long)]
    profile_url: Vec<String>,
    /// Clear one field or complete repeated field. Repeat as needed.
    #[arg(long, value_enum)]
    clear: Vec<ProfileField>,
}

#[derive(Subcommand)]
enum GroupCommand {
    Create {
        name: String,
    },
    Add {
        group: String,
        person: String,
    },
    Remove {
        group: String,
        person: String,
    },
    Rename {
        group: String,
        name: String,
    },
    /// Collapse all heads, taking the union of their exact member anchors.
    Reconcile {
        group: String,
        /// Required only when concurrent heads disagree on the name.
        #[arg(long)]
        name: Option<String>,
    },
    List,
    Show {
        group: String,
    },
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Resolve the current verdict for an unordered person pair.
    Resolve {
        first: String,
        second: String,
        #[arg(
            long,
            conflicts_with = "distinct",
            required_unless_present = "distinct"
        )]
        same: bool,
        #[arg(long, conflicts_with = "same", required_unless_present = "same")]
        distinct: bool,
    },
    /// List canonical person pairs and every live verdict head.
    List,
}

#[derive(Clone, Copy)]
struct RelationsStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
    scope: Id,
}

impl RelationsStorage<'_> {
    fn view(&self) -> Result<CollectionView> {
        let signer = collection_access::load_signer(self.pile, self.key)?;
        let allowed = HashSet::from([signer.verifying_key()]);
        let view = collection_access::materialize_scope(self.pile, self.scope, &allowed)?;
        relations::validate_catalog(&view.reader, &view.facts)
            .context("validate authored Relations collection")?;
        Ok(view)
    }

    fn publish(&self, fragment: Fragment, description: &str) -> Result<()> {
        // Validate the exact would-be union, including staged text blobs,
        // before opening an append writer.
        let view = self.view()?;
        relations::validate_catalog_union(&view.reader, &view.facts, &fragment)
            .context("preflight authored Relations union")?;

        let mut metadata_fragment = Fragment::empty();
        let description = metadata_fragment.put(description.to_owned());
        metadata_fragment += entity! { metadata::description: description };
        collection_access::publish_fragment(
            self.pile,
            self.key,
            self.scope,
            fragment,
            metadata_fragment,
        )?;
        Ok(())
    }
}

fn parse_id_arg(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim()).ok_or_else(|| format!("invalid id '{raw}'"))
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn resolve_person_anchor(
    view: &CollectionView,
    selector: &str,
    include_retired: bool,
) -> Result<Id> {
    match relations::resolve_person(&view.reader, &view.facts, selector, include_retired)? {
        SelectorOutcome::Unique(id) => Ok(id),
        // Some operations deliberately reconcile one forked anchor. The typed
        // outcome still prevents a fork from being mistaken for settled state.
        SelectorOutcome::Forked(ids) if ids.len() == 1 => Ok(ids[0]),
        outcome => outcome.require_unique("person", selector),
    }
}

fn resolve_group_anchor(view: &CollectionView, selector: &str) -> Result<Id> {
    match relations::resolve_group(&view.reader, &view.facts, selector)? {
        SelectorOutcome::Unique(id) => Ok(id),
        SelectorOutcome::Forked(ids) if ids.len() == 1 => Ok(ids[0]),
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

fn replacement_conflict(
    clears: &HashSet<ProfileField>,
    field: ProfileField,
    replacement_present: bool,
) -> Result<()> {
    if clears.contains(&field) && replacement_present {
        bail!(
            "--clear {} conflicts with its replacement option",
            field.to_possible_value().expect("value enum").get_name()
        );
    }
    Ok(())
}

fn apply_profile_patch(input: &mut ProfileInput, patch: ProfilePatchArgs) -> Result<bool> {
    let before = input.clone();
    let clears: HashSet<ProfileField> = patch.clear.into_iter().collect();

    replacement_conflict(&clears, ProfileField::Aliases, !patch.alias.is_empty())?;
    replacement_conflict(
        &clears,
        ProfileField::Affinities,
        !patch.affinity.is_empty(),
    )?;
    replacement_conflict(&clears, ProfileField::FirstName, patch.first_name.is_some())?;
    replacement_conflict(&clears, ProfileField::LastName, patch.last_name.is_some())?;
    replacement_conflict(
        &clears,
        ProfileField::DisplayName,
        patch.display_name.is_some(),
    )?;
    replacement_conflict(&clears, ProfileField::Note, patch.note.is_some())?;
    replacement_conflict(
        &clears,
        ProfileField::TeamsUserIds,
        !patch.teams_user_id.is_empty(),
    )?;
    replacement_conflict(&clears, ProfileField::Emails, !patch.email.is_empty())?;
    replacement_conflict(&clears, ProfileField::Phones, !patch.phone.is_empty())?;
    replacement_conflict(&clears, ProfileField::Company, patch.company.is_some())?;
    replacement_conflict(&clears, ProfileField::Position, patch.position.is_some())?;
    replacement_conflict(
        &clears,
        ProfileField::ProfileUrls,
        !patch.profile_url.is_empty(),
    )?;

    if let Some(value) = patch.label {
        input.label = value;
    }
    if clears.contains(&ProfileField::Aliases) {
        input.aliases.clear();
    } else if !patch.alias.is_empty() {
        input.aliases = patch.alias;
    }
    if clears.contains(&ProfileField::Affinities) {
        input.affinities.clear();
    } else if !patch.affinity.is_empty() {
        input.affinities = patch.affinity;
    }

    macro_rules! scalar {
        ($field:ident, $variant:ident, $value:expr) => {
            if clears.contains(&ProfileField::$variant) {
                input.$field = None;
            } else if let Some(value) = $value {
                input.$field = Some(value);
            }
        };
    }
    scalar!(first_name, FirstName, patch.first_name);
    scalar!(last_name, LastName, patch.last_name);
    scalar!(display_name, DisplayName, patch.display_name);
    scalar!(note, Note, patch.note);
    scalar!(company, Company, patch.company);
    scalar!(position, Position, patch.position);

    macro_rules! repeated {
        ($field:ident, $variant:ident, $value:expr) => {
            if clears.contains(&ProfileField::$variant) {
                input.$field.clear();
            } else if !$value.is_empty() {
                input.$field = $value;
            }
        };
    }
    repeated!(teams_user_ids, TeamsUserIds, patch.teams_user_id);
    repeated!(emails, Emails, patch.email);
    repeated!(phones, Phones, patch.phone);
    repeated!(profile_urls, ProfileUrls, patch.profile_url);
    Ok(*input != before)
}

fn cmd_add(
    storage: RelationsStorage<'_>,
    label: String,
    id: Option<Id>,
    profile: NewProfileArgs,
) -> Result<()> {
    let person = id.unwrap_or_else(|| genid().id);
    let (fragment, profile_id, lifecycle_id) =
        relations::person_fragment(person, profile.into_profile(label))?;
    storage.publish(fragment, "relations add person")?;
    println!("person: {}", fmt_id(person));
    println!("profile: {}", fmt_id(profile_id));
    println!("lifecycle: {}", fmt_id(lifecycle_id));
    Ok(())
}

fn cmd_set(storage: RelationsStorage<'_>, person: String, patch: ProfilePatchArgs) -> Result<()> {
    let view = storage.view()?;
    let person = resolve_person_anchor(&view, &person, true)?;
    let current = relations::current_profile(&view.facts, person)?;
    let mut value = relations::profile_input(&view.reader, &current)?;
    if !apply_profile_patch(&mut value, patch)? {
        println!("No profile change for {}.", fmt_id(person));
        return Ok(());
    }
    let fragment = relations::profile_fragment(person, value, &[current.id])?;
    let snapshot = fragment.root().expect("profile snapshot root");
    storage.publish(fragment, "relations replace profile")?;
    println!("profile: {} -> {}", fmt_id(current.id), fmt_id(snapshot));
    Ok(())
}

fn cmd_reconcile_profile(
    storage: RelationsStorage<'_>,
    person_selector: String,
    base: Option<String>,
    patch: ProfilePatchArgs,
) -> Result<()> {
    let view = storage.view()?;
    let person = resolve_person_anchor(&view, &person_selector, true)?;
    let heads = head_ids(
        relations::profile_head(&view.facts, person)?,
        "person profile",
    )?;
    let snapshots: Vec<(ProfileSnapshot, ProfileInput)> = heads
        .iter()
        .map(|&id| {
            let snapshot = relations::profile_snapshot(&view.facts, id)?;
            let input = relations::profile_input(&view.reader, &snapshot)?;
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
        println!("Profile {} is already settled.", fmt_id(base_id));
        return Ok(());
    }
    let fragment = relations::profile_fragment(person, value, &heads)?;
    let successor = fragment.root().expect("profile snapshot root");
    storage.publish(fragment, "relations reconcile profile")?;
    println!("profile: {} heads -> {}", heads.len(), fmt_id(successor));
    Ok(())
}

fn lifecycle_state(view: &CollectionView, person: Id) -> Result<(Vec<Id>, Option<bool>)> {
    match relations::lifecycle_head(&view.facts, person)? {
        Head::Missing => bail!("person {} has no lifecycle", fmt_id(person)),
        Head::Unique(id) => Ok((
            vec![id],
            Some(relations::lifecycle_snapshot(&view.facts, id)?.retired),
        )),
        Head::Forked(ids) => Ok((ids, None)),
    }
}

fn cmd_set_retired(storage: RelationsStorage<'_>, selector: String, retired: bool) -> Result<()> {
    let view = storage.view()?;
    let person = resolve_person_anchor(&view, &selector, true)?;
    let (heads, current) = lifecycle_state(&view, person)?;
    if current == Some(retired) {
        println!(
            "{} is already {}.",
            fmt_id(person),
            if retired { "retired" } else { "active" }
        );
        return Ok(());
    }
    let fragment = relations::lifecycle_fragment(person, retired, &heads);
    let successor = fragment.root().expect("lifecycle snapshot root");
    storage.publish(
        fragment,
        if retired {
            "relations retire person"
        } else {
            "relations restore person"
        },
    )?;
    println!(
        "{}: {} ({})",
        if retired { "retired" } else { "active" },
        fmt_id(person),
        fmt_id(successor)
    );
    Ok(())
}

fn print_values(label: &str, values: &[String]) {
    for value in values {
        println!("{label}: {value}");
    }
}

fn print_profile(id: Id, input: &ProfileInput) {
    println!("profile: {}", fmt_id(id));
    println!("label: {}", input.label);
    print_values("alias", &input.aliases);
    print_values("affinity", &input.affinities);
    if let Some(value) = &input.first_name {
        println!("first_name: {value}");
    }
    if let Some(value) = &input.last_name {
        println!("last_name: {value}");
    }
    if let Some(value) = &input.display_name {
        println!("display_name: {value}");
    }
    if let Some(value) = &input.company {
        println!("company: {value}");
    }
    if let Some(value) = &input.position {
        println!("position: {value}");
    }
    print_values("teams_user_id", &input.teams_user_ids);
    print_values("email", &input.emails);
    print_values("phone", &input.phones);
    print_values("profile_url", &input.profile_urls);
    if let Some(value) = &input.note {
        println!("note:\n{value}");
    }
}

fn cmd_show(storage: RelationsStorage<'_>, selector: String) -> Result<()> {
    let view = storage.view()?;
    let person = resolve_person_anchor(&view, &selector, true)?;
    println!("person: {}", fmt_id(person));
    match relations::profile_head(&view.facts, person)? {
        Head::Missing => println!("profile: missing"),
        Head::Unique(id) => {
            let snapshot = relations::profile_snapshot(&view.facts, id)?;
            print_profile(id, &relations::profile_input(&view.reader, &snapshot)?);
        }
        Head::Forked(ids) => {
            println!("profile_fork: {} heads", ids.len());
            for id in ids {
                let snapshot = relations::profile_snapshot(&view.facts, id)?;
                print_profile(id, &relations::profile_input(&view.reader, &snapshot)?);
            }
        }
    }
    match relations::lifecycle_head(&view.facts, person)? {
        Head::Missing => println!("lifecycle: missing"),
        Head::Unique(id) => println!(
            "retired: {}\nlifecycle: {}",
            relations::lifecycle_snapshot(&view.facts, id)?.retired,
            fmt_id(id)
        ),
        Head::Forked(ids) => {
            println!("lifecycle_fork: {} heads", ids.len());
            for id in ids {
                println!(
                    "- {} retired={}",
                    fmt_id(id),
                    relations::lifecycle_snapshot(&view.facts, id)?.retired
                );
            }
        }
    }
    Ok(())
}

fn cmd_list(
    storage: RelationsStorage<'_>,
    limit: usize,
    all: bool,
    retired_only: bool,
) -> Result<()> {
    let view = storage.view()?;
    let mut rows = Vec::new();
    for person in relations::person_anchors(&view.facts) {
        let lifecycle = relations::lifecycle_head(&view.facts, person)?;
        let retired = match lifecycle {
            Head::Unique(id) => Some(relations::lifecycle_snapshot(&view.facts, id)?.retired),
            Head::Missing => None,
            Head::Forked(_) => None,
        };
        if retired_only && retired != Some(true) {
            continue;
        }
        if !all && !retired_only && retired == Some(true) {
            continue;
        }
        let profile = relations::profile_head(&view.facts, person)?;
        let (label, marker) = match profile {
            Head::Unique(id) => {
                let snapshot = relations::profile_snapshot(&view.facts, id)?;
                (
                    relations::read_text(&view.reader, snapshot.label)?,
                    String::new(),
                )
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
        println!("No people.");
    }
    for (_, person, label, marker, lifecycle) in rows.into_iter().take(limit) {
        println!("[{}] {label}{marker}{lifecycle}", fmt_id(person));
    }
    Ok(())
}

fn cmd_group_create(storage: RelationsStorage<'_>, name: String) -> Result<()> {
    let view = storage.view()?;
    match relations::resolve_group(&view.reader, &view.facts, &name)? {
        SelectorOutcome::Missing => {}
        outcome => {
            let existing = outcome.require_unique("group", &name)?;
            bail!("group '{}' already resolves to {}", name, fmt_id(existing));
        }
    }
    let group = genid().id;
    let (fragment, snapshot) = relations::group_create_fragment(group, name)?;
    storage.publish(fragment, "relations create group")?;
    println!("group: {}\nsnapshot: {}", fmt_id(group), fmt_id(snapshot));
    Ok(())
}

fn group_successor(
    storage: RelationsStorage<'_>,
    current: GroupSnapshot,
    name: String,
    members: Vec<Id>,
    description: &str,
) -> Result<()> {
    let fragment =
        relations::group_snapshot_fragment(current.group, name, &members, &[current.id])?;
    let successor = fragment.root().expect("group snapshot root");
    storage.publish(fragment, description)?;
    println!("snapshot: {} -> {}", fmt_id(current.id), fmt_id(successor));
    Ok(())
}

fn cmd_group_add(
    storage: RelationsStorage<'_>,
    group_selector: String,
    person_selector: String,
) -> Result<()> {
    let view = storage.view()?;
    let group = resolve_group_anchor(&view, &group_selector)?;
    let person = resolve_person_anchor(&view, &person_selector, true)?;
    let current = relations::current_group(&view.facts, group)?;
    let identities = IdentityComponents::from_facts(&view.facts)?;
    for &member in &current.members {
        if identities.equivalent(person, member)? {
            println!("{} is already represented in the group.", fmt_id(person));
            return Ok(());
        }
    }
    let mut members = current.members.clone();
    members.push(person);
    let name = relations::read_text(&view.reader, current.name)?;
    group_successor(
        storage,
        current,
        name,
        members,
        "relations add group member",
    )
}

fn cmd_group_remove(
    storage: RelationsStorage<'_>,
    group_selector: String,
    person_selector: String,
) -> Result<()> {
    let view = storage.view()?;
    let group = resolve_group_anchor(&view, &group_selector)?;
    let person = resolve_person_anchor(&view, &person_selector, true)?;
    let current = relations::current_group(&view.facts, group)?;
    let identities = IdentityComponents::from_facts(&view.facts)?;
    let mut members = Vec::new();
    for member in current.members.iter().copied() {
        if !identities.equivalent(person, member)? {
            members.push(member);
        }
    }
    if members.len() == current.members.len() {
        println!("{} is not represented in the group.", fmt_id(person));
        return Ok(());
    }
    let name = relations::read_text(&view.reader, current.name)?;
    group_successor(
        storage,
        current,
        name,
        members,
        "relations remove group member",
    )
}

fn cmd_group_rename(
    storage: RelationsStorage<'_>,
    group_selector: String,
    name: String,
) -> Result<()> {
    let view = storage.view()?;
    let group = resolve_group_anchor(&view, &group_selector)?;
    let current = relations::current_group(&view.facts, group)?;
    let old = relations::read_text(&view.reader, current.name)?;
    if old.trim() == name.trim() {
        println!("Group is already named {old}.");
        return Ok(());
    }
    let members = current.members.clone();
    group_successor(storage, current, name, members, "relations rename group")
}

fn cmd_group_reconcile(
    storage: RelationsStorage<'_>,
    selector: String,
    explicit_name: Option<String>,
) -> Result<()> {
    let view = storage.view()?;
    let group = resolve_group_anchor(&view, &selector)?;
    let heads = head_ids(relations::group_head(&view.facts, group)?, "group")?;
    if heads.len() == 1 && explicit_name.is_none() {
        println!("Group is already settled at {}.", fmt_id(heads[0]));
        return Ok(());
    }
    let snapshots: Vec<GroupSnapshot> = heads
        .iter()
        .map(|&id| relations::group_snapshot(&view.facts, id))
        .collect::<Result<_>>()?;
    let members: BTreeSet<Id> = snapshots
        .iter()
        .flat_map(|snapshot| snapshot.members.iter().copied())
        .collect();
    let name = if let Some(name) = explicit_name {
        name
    } else {
        let names: BTreeSet<String> = snapshots
            .iter()
            .map(|snapshot| relations::read_text(&view.reader, snapshot.name))
            .collect::<Result<_>>()?;
        if names.len() != 1 {
            bail!("group heads disagree on the name; provide --name");
        }
        names.into_iter().next().expect("one name")
    };
    let fragment = relations::group_snapshot_fragment(
        group,
        name,
        &members.into_iter().collect::<Vec<_>>(),
        &heads,
    )?;
    let successor = fragment.root().expect("group snapshot root");
    storage.publish(fragment, "relations reconcile group")?;
    println!("group: {} heads -> {}", heads.len(), fmt_id(successor));
    Ok(())
}

fn print_group_snapshot(view: &CollectionView, snapshot: GroupSnapshot) -> Result<()> {
    println!("snapshot: {}", fmt_id(snapshot.id));
    println!(
        "name: {}",
        relations::read_text(&view.reader, snapshot.name)?
    );
    for member in snapshot.members {
        let label = relations::current_profile(&view.facts, member)
            .and_then(|profile| relations::read_text(&view.reader, profile.label))
            .unwrap_or_else(|_| "<unsettled profile>".to_owned());
        println!("member: {} {label}", fmt_id(member));
    }
    Ok(())
}

fn cmd_group_show(storage: RelationsStorage<'_>, selector: String) -> Result<()> {
    let view = storage.view()?;
    let group = resolve_group_anchor(&view, &selector)?;
    println!("group: {}", fmt_id(group));
    match relations::group_head(&view.facts, group)? {
        Head::Missing => println!("snapshot: missing"),
        Head::Unique(id) => {
            print_group_snapshot(&view, relations::group_snapshot(&view.facts, id)?)?
        }
        Head::Forked(ids) => {
            println!("group_fork: {} heads", ids.len());
            for id in ids {
                print_group_snapshot(&view, relations::group_snapshot(&view.facts, id)?)?;
            }
        }
    }
    Ok(())
}

fn cmd_group_list(storage: RelationsStorage<'_>) -> Result<()> {
    let view = storage.view()?;
    let mut rows = Vec::new();
    for group in relations::group_anchors(&view.facts) {
        match relations::group_head(&view.facts, group)? {
            Head::Unique(id) => {
                let snapshot = relations::group_snapshot(&view.facts, id)?;
                rows.push((
                    relations::read_text(&view.reader, snapshot.name)?,
                    group,
                    format!("{} members", snapshot.members.len()),
                ));
            }
            Head::Forked(ids) => rows.push((
                "<forked group>".to_owned(),
                group,
                format!("fork: {} heads", ids.len()),
            )),
            Head::Missing => rows.push(("<missing group>".to_owned(), group, "invalid".to_owned())),
        }
    }
    rows.sort_by(|left, right| {
        relations::lookup_key(&left.0)
            .cmp(&relations::lookup_key(&right.0))
            .then_with(|| left.1.cmp(&right.1))
    });
    if rows.is_empty() {
        println!("No groups.");
    }
    for (name, group, state) in rows {
        println!("[{}] {name} ({state})", fmt_id(group));
    }
    Ok(())
}

fn cmd_identity_resolve(
    storage: RelationsStorage<'_>,
    first: String,
    second: String,
    same: bool,
) -> Result<()> {
    let view = storage.view()?;
    let first = resolve_person_anchor(&view, &first, true)?;
    let second = resolve_person_anchor(&view, &second, true)?;
    if first == second {
        bail!("an identity verdict requires two different person anchors");
    }
    let head = relations::identity_head(&view.facts, first, second)?;
    let predecessors = match head {
        Head::Missing => Vec::new(),
        Head::Unique(id) => {
            if relations::identity_verdict(&view.facts, id)?.same == same {
                println!("Identity verdict is already settled at {}.", fmt_id(id));
                return Ok(());
            }
            vec![id]
        }
        Head::Forked(ids) => ids,
    };
    let fragment = relations::identity_verdict_fragment(first, second, same, &predecessors)?;
    let successor = fragment.root().expect("identity verdict root");
    storage.publish(fragment, "relations resolve identity verdict")?;
    println!(
        "identity: {} {} {} ({})",
        fmt_id(first),
        if same { "same-as" } else { "distinct-from" },
        fmt_id(second),
        fmt_id(successor)
    );
    Ok(())
}

fn cmd_identity_list(storage: RelationsStorage<'_>) -> Result<()> {
    let view = storage.view()?;
    let heads = relations::identity_heads(&view.facts)?;
    if heads.is_empty() {
        println!("No identity verdicts.");
    }
    for ((low, high), head) in heads {
        match head {
            Head::Missing => unreachable!("listed pair has a verdict"),
            Head::Unique(id) => println!(
                "{} {} {} [{}]",
                fmt_id(low),
                if relations::identity_verdict(&view.facts, id)?.same {
                    "same-as"
                } else {
                    "distinct-from"
                },
                fmt_id(high),
                fmt_id(id)
            ),
            Head::Forked(ids) => {
                println!(
                    "{} ? {} [fork: {} heads]",
                    fmt_id(low),
                    fmt_id(high),
                    ids.len()
                );
                for id in ids {
                    println!(
                        "- {} {}",
                        fmt_id(id),
                        if relations::identity_verdict(&view.facts, id)?.same {
                            "same-as"
                        } else {
                            "distinct-from"
                        }
                    );
                }
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let storage = RelationsStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
        scope: cli.scope.unwrap_or(DEFAULT_SCOPE_ID),
    };

    match cli.command {
        None => {
            Cli::command().print_help().ok();
            println!();
        }
        Some(Command::Add { label, id, profile }) => cmd_add(storage, label, id, profile)?,
        Some(Command::Set { person, patch }) => cmd_set(storage, person, patch)?,
        Some(Command::Reconcile {
            person,
            base,
            patch,
        }) => cmd_reconcile_profile(storage, person, base, patch)?,
        Some(Command::List {
            limit,
            all,
            retired,
        }) => cmd_list(storage, limit, all, retired)?,
        Some(Command::Show { person }) => cmd_show(storage, person)?,
        Some(Command::Retire { person }) => cmd_set_retired(storage, person, true)?,
        Some(Command::Unretire { person }) => cmd_set_retired(storage, person, false)?,
        Some(Command::Group { command }) => match command {
            GroupCommand::Create { name } => cmd_group_create(storage, name)?,
            GroupCommand::Add { group, person } => cmd_group_add(storage, group, person)?,
            GroupCommand::Remove { group, person } => cmd_group_remove(storage, group, person)?,
            GroupCommand::Rename { group, name } => cmd_group_rename(storage, group, name)?,
            GroupCommand::Reconcile { group, name } => cmd_group_reconcile(storage, group, name)?,
            GroupCommand::List => cmd_group_list(storage)?,
            GroupCommand::Show { group } => cmd_group_show(storage, group)?,
        },
        Some(Command::Identity { command }) => match command {
            IdentityCommand::Resolve {
                first,
                second,
                same,
                distinct: _,
            } => cmd_identity_resolve(storage, first, second, same)?,
            IdentityCommand::List => cmd_identity_list(storage)?,
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            ProfilePatchArgs {
                alias: vec!["Countess".to_owned(), "Enchantress".to_owned()],
                company: Some("Analytical Engines".to_owned()),
                ..ProfilePatchArgs::default()
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
            ProfilePatchArgs {
                clear: vec![ProfileField::FirstName, ProfileField::Emails],
                ..ProfilePatchArgs::default()
            },
        )
        .unwrap();
        assert_eq!(value.first_name, None);
        assert!(value.emails.is_empty());

        let error = apply_profile_patch(
            &mut value,
            ProfilePatchArgs {
                email: vec!["new@example.test".to_owned()],
                clear: vec![ProfileField::Emails],
                ..ProfilePatchArgs::default()
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("conflicts"));
    }
}
