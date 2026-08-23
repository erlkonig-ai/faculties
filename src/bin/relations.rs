//! `relations` — authored people, addressable groups, and explicit identity
//! adjudication in one union-only native collection.
//!
//! Stable person/group anchors never accumulate mutable scalar facts. Every
//! change publishes one intrinsic full-state snapshot with explicit
//! predecessors. Concurrent publications therefore become visible forks;
//! reconciliation is another monotonic child, never deletion, a mutable head,
//! or clock-based arbitration.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use faculties::legacy_hint::open_scope;
use faculties::relations::{
    self, GroupSnapshot, Head, IdentityComponents, ProfileInput, ProfileSnapshot, SelectorOutcome,
};
use faculties::schemas::relations::DEFAULT_SCOPE_ID;
use faculties::storage::{load_signer, open_pile_strict};
use hifitime::Epoch;
use triblespace::core::collection::Collection;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::BlobStore;
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
        /// Additive provenance label (repeatable).
        #[arg(long)]
        source: Vec<String>,
        #[command(flatten)]
        profile: NewProfileArgs,
    },
    /// Replace selected fields of one current profile snapshot.
    Set {
        /// Person label, alias, exact id, or id prefix.
        person: String,
        /// Additive provenance label (repeatable; does not alter profile identity).
        #[arg(long)]
        source: Vec<String>,
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
}

impl RelationsStorage<'_> {
    fn with_collection<T>(&self, f: impl FnOnce(&mut Collection<Pile>) -> Result<T>) -> Result<T> {
        // Reads and writes share the same durable authority. Ordinary CLI
        // commands never mint a key or substitute an ephemeral identity.
        let signer = load_signer(self.pile, self.key)?;
        let pile = open_pile_strict(self.pile)?;
        let mut collection = open_scope(pile, DEFAULT_SCOPE_ID, signer);
        let result = f(&mut collection);
        let close = collection.into_storage().close();
        match (result, close) {
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(error)) => Err(anyhow::anyhow!("close pile: {error}")),
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(close_error)) => {
                Err(error.context(format!("closing pile also failed: {close_error}")))
            }
        }
    }

    fn with_view<T>(&self, f: impl FnOnce(&TribleSet, &PileReader) -> Result<T>) -> Result<T> {
        self.with_collection(|collection| {
            let facts = collection
                .materialize()
                .context("materialize authored Relations collection")?;
            let reader = collection
                .storage_mut()
                .reader()
                .context("open Relations blob reader")?;
            relations::validate_catalog(&reader, &facts)
                .context("validate authored Relations collection")?;
            f(&facts, &reader)
        })
    }

    /// Build and preflight one update against the exact known collection
    /// union. `None` is a genuine no-op and writes no collection record.
    fn update<T>(
        &self,
        f: impl FnOnce(&TribleSet, &PileReader) -> Result<(Option<Fragment>, T)>,
    ) -> Result<T> {
        self.with_collection(|collection| {
            let facts = collection
                .materialize()
                .context("materialize authored Relations collection")?;
            let reader = collection
                .storage_mut()
                .reader()
                .context("open Relations blob reader")?;
            relations::validate_catalog(&reader, &facts)
                .context("validate authored Relations collection")?;
            let (fragment, result) = f(&facts, &reader)?;
            if let Some(fragment) = fragment {
                relations::validate_catalog_union(&reader, &facts, &fragment)
                    .context("preflight authored Relations union")?;
                collection
                    .commit(fragment)
                    .context("commit authored Relations fragment")?;
            }
            Ok(result)
        })
    }
}

fn parse_id_arg(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim()).ok_or_else(|| format!("invalid id '{raw}'"))
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn now_observation() -> relations::ObservedAt {
    let now = Epoch::now().unwrap_or(Epoch::from_unix_seconds(0.0));
    (now, now).try_to_inline().expect("current epoch is inline")
}

fn resolve_person_anchor(
    reader: &PileReader,
    facts: &TribleSet,
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

fn resolve_group_anchor(reader: &PileReader, facts: &TribleSet, selector: &str) -> Result<Id> {
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
    source: Vec<String>,
    profile: NewProfileArgs,
) -> Result<()> {
    let person = id.unwrap_or_else(|| genid().id);
    let (mut fragment, profile_id, lifecycle_id) =
        relations::person_fragment(person, profile.into_profile(label))?;
    fragment += relations::person_provenance_fragment(person, source, &[now_observation()])?;
    storage.update(|_, _| Ok((Some(fragment), ())))?;
    println!("person: {}", fmt_id(person));
    println!("profile: {}", fmt_id(profile_id));
    println!("lifecycle: {}", fmt_id(lifecycle_id));
    Ok(())
}

fn cmd_set(
    storage: RelationsStorage<'_>,
    person: String,
    source: Vec<String>,
    patch: ProfilePatchArgs,
) -> Result<()> {
    let (person, old, new, provenance_added) = storage.update(|facts, reader| {
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
        Ok((publish, (person, current.id, new, provenance_added)))
    })?;
    match new {
        Some(new) => {
            println!("profile: {} -> {}", fmt_id(old), fmt_id(new));
            if provenance_added {
                println!("Added provenance for {}.", fmt_id(person));
            }
        }
        None if provenance_added => println!("Added provenance for {}.", fmt_id(person)),
        None => println!("No profile change for {}.", fmt_id(person)),
    }
    Ok(())
}

fn cmd_reconcile_profile(
    storage: RelationsStorage<'_>,
    person_selector: String,
    base: Option<String>,
    patch: ProfilePatchArgs,
) -> Result<()> {
    enum Outcome {
        Settled(Id),
        Reconciled { heads: usize, successor: Id },
    }
    let outcome = storage.update(|facts, reader| {
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
            return Ok((None, Outcome::Settled(base_id)));
        }
        let fragment = relations::profile_fragment(person, value, &heads)?;
        let successor = fragment.root().expect("profile snapshot root");
        Ok((
            Some(fragment),
            Outcome::Reconciled {
                heads: heads.len(),
                successor,
            },
        ))
    })?;
    match outcome {
        Outcome::Settled(id) => println!("Profile {} is already settled.", fmt_id(id)),
        Outcome::Reconciled { heads, successor } => {
            println!("profile: {heads} heads -> {}", fmt_id(successor))
        }
    }
    Ok(())
}

fn lifecycle_state(facts: &TribleSet, person: Id) -> Result<(Vec<Id>, Option<bool>)> {
    match relations::lifecycle_head(facts, person)? {
        Head::Missing => bail!("person {} has no lifecycle", fmt_id(person)),
        Head::Unique(id) => Ok((
            vec![id],
            Some(relations::lifecycle_snapshot(facts, id)?.retired),
        )),
        Head::Forked(ids) => Ok((ids, None)),
    }
}

fn cmd_set_retired(storage: RelationsStorage<'_>, selector: String, retired: bool) -> Result<()> {
    enum Outcome {
        Unchanged(Id),
        Changed { person: Id, successor: Id },
    }
    let outcome = storage.update(|facts, reader| {
        let person = resolve_person_anchor(reader, facts, &selector, true)?;
        let (heads, current) = lifecycle_state(facts, person)?;
        if current == Some(retired) {
            return Ok((None, Outcome::Unchanged(person)));
        }
        let fragment = relations::lifecycle_fragment(person, retired, &heads);
        let successor = fragment.root().expect("lifecycle snapshot root");
        Ok((Some(fragment), Outcome::Changed { person, successor }))
    })?;
    match outcome {
        Outcome::Unchanged(person) => println!(
            "{} is already {}.",
            fmt_id(person),
            if retired { "retired" } else { "active" }
        ),
        Outcome::Changed { person, successor } => println!(
            "{}: {} ({})",
            if retired { "retired" } else { "active" },
            fmt_id(person),
            fmt_id(successor)
        ),
    }
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
    storage.with_view(|facts, reader| {
        let person = resolve_person_anchor(reader, facts, &selector, true)?;
        println!("person: {}", fmt_id(person));
        print_values("source", &relations::person_sources(facts, person)?);
        let observations = relations::creation_observations(facts, person);
        if !observations.is_empty() {
            println!("creation_observations: {}", observations.len());
        }
        match relations::profile_head(facts, person)? {
            Head::Missing => println!("profile: missing"),
            Head::Unique(id) => {
                let snapshot = relations::profile_snapshot(facts, id)?;
                print_profile(id, &relations::profile_input(reader, &snapshot)?);
            }
            Head::Forked(ids) => {
                println!("profile_fork: {} heads", ids.len());
                for id in ids {
                    let snapshot = relations::profile_snapshot(facts, id)?;
                    print_profile(id, &relations::profile_input(reader, &snapshot)?);
                }
            }
        }
        match relations::lifecycle_head(facts, person)? {
            Head::Missing => println!("lifecycle: missing"),
            Head::Unique(id) => println!(
                "retired: {}\nlifecycle: {}",
                relations::lifecycle_snapshot(facts, id)?.retired,
                fmt_id(id)
            ),
            Head::Forked(ids) => {
                println!("lifecycle_fork: {} heads", ids.len());
                for id in ids {
                    println!(
                        "- {} retired={}",
                        fmt_id(id),
                        relations::lifecycle_snapshot(facts, id)?.retired
                    );
                }
            }
        }
        Ok(())
    })
}

fn cmd_list(
    storage: RelationsStorage<'_>,
    limit: usize,
    all: bool,
    retired_only: bool,
) -> Result<()> {
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
            println!("No people.");
        }
        for (_, person, label, marker, lifecycle) in rows.into_iter().take(limit) {
            println!("[{}] {label}{marker}{lifecycle}", fmt_id(person));
        }
        Ok(())
    })
}

fn cmd_group_create(storage: RelationsStorage<'_>, name: String) -> Result<()> {
    let (group, snapshot) = storage.update(|facts, reader| {
        match relations::resolve_group(reader, facts, &name)? {
            SelectorOutcome::Missing => {}
            outcome => {
                let existing = outcome.require_unique("group", &name)?;
                bail!("group '{}' already resolves to {}", name, fmt_id(existing));
            }
        }
        let group = genid().id;
        let (mut fragment, snapshot) = relations::group_create_fragment(group, name)?;
        fragment += relations::group_provenance_fragment(group, &[now_observation()]);
        Ok((Some(fragment), (group, snapshot)))
    })?;
    println!("group: {}\nsnapshot: {}", fmt_id(group), fmt_id(snapshot));
    Ok(())
}

fn cmd_group_add(
    storage: RelationsStorage<'_>,
    group_selector: String,
    person_selector: String,
) -> Result<()> {
    enum Outcome {
        Already(Id),
        Changed { old: Id, new: Id },
    }
    let outcome = storage.update(|facts, reader| {
        let group = resolve_group_anchor(reader, facts, &group_selector)?;
        let person = resolve_person_anchor(reader, facts, &person_selector, true)?;
        let current = relations::current_group(facts, group)?;
        let identities = IdentityComponents::from_facts(facts)?;
        for &member in &current.members {
            if identities.equivalent(person, member)? {
                return Ok((None, Outcome::Already(person)));
            }
        }
        let mut members = current.members.clone();
        members.push(person);
        let name = relations::read_text(reader, current.name)?;
        let old = current.id;
        let fragment = relations::group_snapshot_fragment(group, name, &members, &[old])?;
        let new = fragment.root().expect("group snapshot root");
        Ok((Some(fragment), Outcome::Changed { old, new }))
    })?;
    match outcome {
        Outcome::Already(person) => {
            println!("{} is already represented in the group.", fmt_id(person))
        }
        Outcome::Changed { old, new } => {
            println!("snapshot: {} -> {}", fmt_id(old), fmt_id(new))
        }
    }
    Ok(())
}

fn cmd_group_remove(
    storage: RelationsStorage<'_>,
    group_selector: String,
    person_selector: String,
) -> Result<()> {
    enum Outcome {
        Absent(Id),
        Changed { old: Id, new: Id },
    }
    let outcome = storage.update(|facts, reader| {
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
            return Ok((None, Outcome::Absent(person)));
        }
        let name = relations::read_text(reader, current.name)?;
        let old = current.id;
        let fragment = relations::group_snapshot_fragment(group, name, &members, &[old])?;
        let new = fragment.root().expect("group snapshot root");
        Ok((Some(fragment), Outcome::Changed { old, new }))
    })?;
    match outcome {
        Outcome::Absent(person) => {
            println!("{} is not represented in the group.", fmt_id(person))
        }
        Outcome::Changed { old, new } => {
            println!("snapshot: {} -> {}", fmt_id(old), fmt_id(new))
        }
    }
    Ok(())
}

fn cmd_group_rename(
    storage: RelationsStorage<'_>,
    group_selector: String,
    name: String,
) -> Result<()> {
    enum Outcome {
        Unchanged(String),
        Changed { old: Id, new: Id },
    }
    let outcome = storage.update(|facts, reader| {
        let group = resolve_group_anchor(reader, facts, &group_selector)?;
        let current = relations::current_group(facts, group)?;
        let old_name = relations::read_text(reader, current.name)?;
        if old_name.trim() == name.trim() {
            return Ok((None, Outcome::Unchanged(old_name)));
        }
        let old = current.id;
        let fragment = relations::group_snapshot_fragment(group, name, &current.members, &[old])?;
        let new = fragment.root().expect("group snapshot root");
        Ok((Some(fragment), Outcome::Changed { old, new }))
    })?;
    match outcome {
        Outcome::Unchanged(name) => println!("Group is already named {name}."),
        Outcome::Changed { old, new } => {
            println!("snapshot: {} -> {}", fmt_id(old), fmt_id(new))
        }
    }
    Ok(())
}

fn cmd_group_reconcile(
    storage: RelationsStorage<'_>,
    selector: String,
    explicit_name: Option<String>,
) -> Result<()> {
    enum Outcome {
        Settled(Id),
        Reconciled { heads: usize, successor: Id },
    }
    let outcome = storage.update(|facts, reader| {
        let group = resolve_group_anchor(reader, facts, &selector)?;
        let heads = head_ids(relations::group_head(facts, group)?, "group")?;
        if heads.len() == 1 && explicit_name.is_none() {
            return Ok((None, Outcome::Settled(heads[0])));
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
            Outcome::Reconciled {
                heads: heads.len(),
                successor,
            },
        ))
    })?;
    match outcome {
        Outcome::Settled(id) => println!("Group is already settled at {}.", fmt_id(id)),
        Outcome::Reconciled { heads, successor } => {
            println!("group: {heads} heads -> {}", fmt_id(successor))
        }
    }
    Ok(())
}

fn print_group_snapshot(
    reader: &PileReader,
    facts: &TribleSet,
    snapshot: GroupSnapshot,
) -> Result<()> {
    println!("snapshot: {}", fmt_id(snapshot.id));
    println!("name: {}", relations::read_text(reader, snapshot.name)?);
    for member in snapshot.members {
        let label = relations::current_profile(facts, member)
            .and_then(|profile| relations::read_text(reader, profile.label))
            .unwrap_or_else(|_| "<unsettled profile>".to_owned());
        println!("member: {} {label}", fmt_id(member));
    }
    Ok(())
}

fn cmd_group_show(storage: RelationsStorage<'_>, selector: String) -> Result<()> {
    storage.with_view(|facts, reader| {
        let group = resolve_group_anchor(reader, facts, &selector)?;
        println!("group: {}", fmt_id(group));
        match relations::group_head(facts, group)? {
            Head::Missing => println!("snapshot: missing"),
            Head::Unique(id) => {
                print_group_snapshot(reader, facts, relations::group_snapshot(facts, id)?)?
            }
            Head::Forked(ids) => {
                println!("group_fork: {} heads", ids.len());
                for id in ids {
                    print_group_snapshot(reader, facts, relations::group_snapshot(facts, id)?)?;
                }
            }
        }
        Ok(())
    })
}

fn cmd_group_list(storage: RelationsStorage<'_>) -> Result<()> {
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
            println!("No groups.");
        }
        for (name, group, state) in rows {
            println!("[{}] {name} ({state})", fmt_id(group));
        }
        Ok(())
    })
}

fn cmd_identity_resolve(
    storage: RelationsStorage<'_>,
    first: String,
    second: String,
    same: bool,
) -> Result<()> {
    enum Outcome {
        Settled(Id),
        Changed {
            first: Id,
            second: Id,
            successor: Id,
        },
    }
    let outcome = storage.update(|facts, reader| {
        let first = resolve_person_anchor(reader, facts, &first, true)?;
        let second = resolve_person_anchor(reader, facts, &second, true)?;
        if first == second {
            bail!("an identity verdict requires two different person anchors");
        }
        let predecessors = match relations::identity_head(facts, first, second)? {
            Head::Missing => Vec::new(),
            Head::Unique(id) => {
                if relations::identity_verdict(facts, id)?.same == same {
                    return Ok((None, Outcome::Settled(id)));
                }
                vec![id]
            }
            Head::Forked(ids) => ids,
        };
        let fragment = relations::identity_verdict_fragment(first, second, same, &predecessors)?;
        let successor = fragment.root().expect("identity verdict root");
        Ok((
            Some(fragment),
            Outcome::Changed {
                first,
                second,
                successor,
            },
        ))
    })?;
    match outcome {
        Outcome::Settled(id) => println!("Identity verdict is already settled at {}.", fmt_id(id)),
        Outcome::Changed {
            first,
            second,
            successor,
        } => println!(
            "identity: {} {} {} ({})",
            fmt_id(first),
            if same { "same-as" } else { "distinct-from" },
            fmt_id(second),
            fmt_id(successor)
        ),
    }
    Ok(())
}

fn cmd_identity_list(storage: RelationsStorage<'_>) -> Result<()> {
    storage.with_view(|facts, _| {
        let heads = relations::identity_heads(facts)?;
        if heads.is_empty() {
            println!("No identity verdicts.");
        }
        for ((low, high), head) in heads {
            match head {
                Head::Missing => unreachable!("listed pair has a verdict"),
                Head::Unique(id) => println!(
                    "{} {} {} [{}]",
                    fmt_id(low),
                    if relations::identity_verdict(facts, id)?.same {
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
                            if relations::identity_verdict(facts, id)?.same {
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
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let storage = RelationsStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
    };

    match cli.command {
        None => {
            Cli::command().print_help().ok();
            println!();
        }
        Some(Command::Add {
            label,
            id,
            source,
            profile,
        }) => cmd_add(storage, label, id, source, profile)?,
        Some(Command::Set {
            person,
            source,
            patch,
        }) => cmd_set(storage, person, source, patch)?,
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
    use faculties::storage::{
        ensure_team_of_one_write_authority, initialize_signer, open_pile_strict,
    };
    use std::fs;

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

    #[test]
    fn native_collection_updates_expose_profile_forks() {
        let nonce = format!("{}-{}", std::process::id(), genid().id);
        let directory = std::env::temp_dir().join(format!("faculties-relations-{nonce}"));
        fs::create_dir_all(&directory).unwrap();
        let pile = directory.join("relations.pile");
        let key = directory.join("relations.key");
        fs::File::create(&pile).unwrap();
        let signer = initialize_signer(&pile, Some(&key)).unwrap();
        let mut store = open_pile_strict(&pile).unwrap();
        ensure_team_of_one_write_authority(&mut store, &signer).unwrap();
        store.close().unwrap();
        let storage = RelationsStorage {
            pile: &pile,
            key: Some(&key),
        };

        let person = genid().id;
        let (fragment, initial, _) = relations::person_fragment(person, profile("Ada")).unwrap();
        storage.update(|_, _| Ok((Some(fragment), ()))).unwrap();

        let left = relations::profile_fragment(person, profile("Ada Left"), &[initial]).unwrap();
        let right = relations::profile_fragment(person, profile("Ada Right"), &[initial]).unwrap();
        storage.update(|_, _| Ok((Some(left), ()))).unwrap();
        storage.update(|_, _| Ok((Some(right), ()))).unwrap();

        storage
            .with_view(|facts, _| {
                match relations::profile_head(facts, person)? {
                    Head::Forked(heads) => assert_eq!(heads.len(), 2),
                    other => panic!("expected visible fork, got {other:?}"),
                }
                Ok(())
            })
            .unwrap();
        fs::remove_dir_all(directory).unwrap();
    }
}
