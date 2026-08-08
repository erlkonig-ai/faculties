//! `compass` — a fork-visible goal ledger over one union-only collection.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::collection_access::{self, CollectionSnapshot, CollectionView};
use faculties::compass::{self, IntervalValue, NoteRecord, PriorityResolution, StatusResolution};
use faculties::relations::{self, SelectorOutcome};
use faculties::schemas::compass::{DEFAULT_SCOPE_ID, DEFAULT_STATUSES, KIND_NOTE};
use faculties::schemas::relations::DEFAULT_SCOPE_ID as RELATIONS_SCOPE_ID;
use hifitime::Epoch;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
use triblespace::prelude::*;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "compass",
    about = "A fork-visible TribleSpace goal ledger"
)]
struct Cli {
    /// Path to the pile file.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Extrinsic collection scope. Defaults to the stable Compass scope.
    #[arg(long, value_parser = parse_id_arg)]
    scope: Option<Id>,
    /// Acting Relations persona (label, alias, exact id, or id prefix).
    #[arg(long, env = "PERSONA")]
    persona: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Add a stable goal with immutable genesis and an initial status.
    Add {
        #[arg(help = "Goal title. Use @path for file input or @- for stdin.")]
        title: String,
        #[arg(long, default_value = "todo")]
        status: String,
        /// Parent goal id or unambiguous id prefix.
        #[arg(long)]
        parent: Option<String>,
        #[arg(long)]
        tag: Vec<String>,
        #[arg(long, help = "Initial note. Use @path for file input or @- for stdin.")]
        note: Option<String>,
    },
    /// List goals in status columns. Forked and invalid state is never hidden.
    List {
        /// Show settled done goals too.
        #[arg(long)]
        all: bool,
        /// Filter by goal tag (repeatable, matches any).
        #[arg(long)]
        tag: Vec<String>,
        /// Filter by status, or by the special diagnostic values `agreed`,
        /// `forked`, `missing`, and `invalid`.
        #[arg(value_name = "STATUS")]
        status: Vec<String>,
    },
    /// Publish a complete scalar status successor, joining every live head.
    Move {
        /// Goal id or unambiguous id prefix.
        id: String,
        status: String,
    },
    /// Add an independent ledger note to a goal.
    Note {
        /// Goal id or unambiguous id prefix.
        id: String,
        #[arg(help = "Note text. Use @path for file input or @- for stdin.")]
        note: String,
        #[arg(long)]
        tag: Vec<String>,
        /// Opaque exact reference (repeatable). Markdown faculty links in the
        /// body are also recorded automatically.
        #[arg(long = "ref", value_name = "REFERENCE")]
        reference: Vec<String>,
        /// Existing note id superseded for provenance. Notes remain visible.
        #[arg(long, value_name = "NOTE_ID")]
        supersedes: Vec<String>,
    },
    /// Show one goal, its fork-visible status history, and every note.
    Show {
        /// Goal id or unambiguous id prefix.
        id: String,
    },
    /// Add one edge to the complete current board-priority snapshot.
    Prioritize {
        /// The more important goal.
        higher: String,
        #[arg(long)]
        over: String,
    },
    /// Remove one edge from the complete current board-priority snapshot.
    Deprioritize {
        /// The more important goal.
        higher: String,
        #[arg(long)]
        over: String,
    },
    /// Resolve a priority fork by supplying the complete intended edge set.
    /// Repeat `--edge HIGHER:LOWER`; omit it for an empty explicit order.
    PriorityResolve {
        #[arg(long, value_name = "HIGHER:LOWER")]
        edge: Vec<String>,
    },
    /// Resolve a goal id prefix to its full 32-character id.
    Resolve { prefix: String },
}

#[derive(Clone, Copy)]
struct CompassStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
    scope: Id,
}

impl CompassStorage<'_> {
    fn view(&self) -> Result<CollectionView> {
        let signer = collection_access::load_signer(self.pile, self.key)?;
        let allowed = HashSet::from([signer.verifying_key()]);
        let view = CollectionSnapshot::open(self.pile)?.materialize_scope(self.scope, &allowed)?;
        compass::validate_catalog(&view.reader, &view.facts)
            .context("validate authored Compass collection")?;
        Ok(view)
    }

    fn publish(&self, fragment: Fragment, description: &str) -> Result<CollectionCommit> {
        let view = self.view()?;
        compass::validate_catalog_union(&view.reader, &view.facts, &fragment)
            .context("preflight authored Compass union")?;

        let mut commit_metadata = Fragment::empty();
        let description = commit_metadata.put(description.to_owned());
        commit_metadata += entity! { metadata::description: description };
        collection_access::publish_fragment(
            self.pile,
            self.key,
            self.scope,
            fragment,
            commit_metadata,
        )
    }
}

fn parse_id_arg(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim()).ok_or_else(|| format!("invalid id '{raw}'"))
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn now_epoch() -> Result<Epoch> {
    Epoch::now().map_err(|error| anyhow!("read current clock: {error:?}"))
}

fn epoch_interval(epoch: Epoch) -> IntervalValue {
    (epoch, epoch)
        .try_to_inline()
        .expect("valid point interval")
}

fn interval_key(interval: IntervalValue) -> i128 {
    let (lower, _): (i128, i128) = interval.try_from_inline().expect("valid point interval");
    lower
}

fn format_interval(interval: IntervalValue) -> String {
    let (lower, _): (Epoch, Epoch) = interval.try_from_inline().expect("valid point interval");
    format!("{lower}")
}

fn resolve_goal(input: &str, facts: &TribleSet) -> Result<Id> {
    faculties::resolve_id_prefix(input, compass::goal_anchors(facts))
}

fn all_note_ids(facts: &TribleSet) -> BTreeSet<Id> {
    find!(id: Id, pattern!(facts, [{ ?id @ metadata::tag: &KIND_NOTE }])).collect()
}

fn resolve_note(input: &str, facts: &TribleSet) -> Result<Id> {
    faculties::resolve_id_prefix(input, all_note_ids(facts))
}

fn resolve_persona(storage: CompassStorage<'_>, input: Option<&str>) -> Result<Option<Id>> {
    let Some(input) = input else {
        return Ok(None);
    };
    let signer = collection_access::load_signer(storage.pile, storage.key)?;
    let allowed = HashSet::from([signer.verifying_key()]);
    let view = CollectionSnapshot::open(storage.pile)?
        .materialize_scope(RELATIONS_SCOPE_ID, &allowed)
        .context("materialize Relations collection for persona attribution")?;
    relations::validate_catalog(&view.reader, &view.facts)
        .context("validate Relations collection for persona attribution")?;
    let outcome = relations::resolve_person(&view.reader, &view.facts, input, false)?;
    match outcome {
        SelectorOutcome::Unique(id) => Ok(Some(id)),
        other => other
            .require_unique("active Relations person", input)
            .map(Some),
    }
}

/// Extract `[text](faculty:<hex>)` links as exact opaque references.
fn extract_reference_values(text: &str) -> Vec<String> {
    let mut references = Vec::new();
    let mut rest = text;
    while let Some(paren) = rest.find("](") {
        let after = &rest[paren + 2..];
        let Some(end) = after.find(')') else {
            break;
        };
        let link = &after[..end];
        if let Some(colon) = link.find(':') {
            let faculty = &link[..colon];
            let hex: String = link[colon + 1..]
                .chars()
                .take_while(char::is_ascii_hexdigit)
                .collect();
            if hex.len() >= 4
                && !faculty.is_empty()
                && faculty
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
            {
                references.push(format!("{faculty}:{hex}"));
            }
        }
        rest = &after[end + 1..];
    }
    references.sort();
    references.dedup();
    references
}

fn cmd_add(
    storage: CompassStorage<'_>,
    title: String,
    status: String,
    parent: Option<String>,
    tags: Vec<String>,
    note_body: Option<String>,
    persona: Option<&str>,
) -> Result<()> {
    let view = storage.view()?;
    let parent = parent
        .as_deref()
        .map(|input| resolve_goal(input, &view.facts))
        .transpose()?;
    let by = resolve_persona(storage, persona)?;
    let goal_id = genid().id;
    let created_at = epoch_interval(now_epoch()?);
    let (mut fragment, _, _) =
        compass::goal_fragment(goal_id, title, tags, parent, status, by, created_at)?;

    if let Some(body) = note_body {
        let references = extract_reference_values(&body);
        fragment += compass::note_fragment(
            genid().id,
            goal_id,
            body,
            Vec::new(),
            references,
            &[],
            by,
            created_at,
        )?
        .0;
    }

    if matches!(
        compass::priority_resolution(&view.facts),
        PriorityResolution::Missing
    ) {
        fragment += compass::priority_snapshot_fragment([], &[])?.0;
    }
    storage.publish(fragment, "add Compass goal")?;
    println!("Added goal {goal_id:x}");
    Ok(())
}

fn status_predecessors(facts: &TribleSet, goal_id: Id) -> Result<Vec<Id>> {
    match compass::status_resolution(facts, goal_id) {
        StatusResolution::Missing => Ok(Vec::new()),
        StatusResolution::Unique(snapshot) => Ok(vec![snapshot.id]),
        StatusResolution::Agreed(snapshots) | StatusResolution::Forked(snapshots) => {
            Ok(snapshots.into_iter().map(|snapshot| snapshot.id).collect())
        }
        StatusResolution::Invalid(reason) => {
            bail!("status state for goal {goal_id:x} is invalid: {reason}")
        }
    }
}

fn cmd_move(
    storage: CompassStorage<'_>,
    input: String,
    value: String,
    persona: Option<&str>,
) -> Result<()> {
    let view = storage.view()?;
    let goal_id = resolve_goal(&input, &view.facts)?;
    let predecessors = status_predecessors(&view.facts, goal_id)?;
    let joined = predecessors.len();
    let by = resolve_persona(storage, persona)?;
    let value = compass::canonical_status(value)?;
    let fragment = compass::status_fragment(
        goal_id,
        value.clone(),
        &predecessors,
        by,
        epoch_interval(now_epoch()?),
    )?;
    storage.publish(fragment, "move Compass goal")?;
    println!("Moved goal {goal_id:x} to {value}");
    if joined > 1 {
        println!("Joined {joined} concurrent status heads");
    }
    Ok(())
}

fn cmd_note(
    storage: CompassStorage<'_>,
    input: String,
    body: String,
    tags: Vec<String>,
    mut references: Vec<String>,
    supersedes: Vec<String>,
    persona: Option<&str>,
) -> Result<()> {
    let view = storage.view()?;
    let goal_id = resolve_goal(&input, &view.facts)?;
    let predecessors: Vec<Id> = supersedes
        .iter()
        .map(|input| resolve_note(input, &view.facts))
        .collect::<Result<_>>()?;
    for predecessor in &predecessors {
        let record = compass::note_record(&view.facts, *predecessor)?;
        if record.goal != goal_id {
            bail!("superseded note {predecessor:x} belongs to another goal");
        }
    }
    references.extend(extract_reference_values(&body));
    references.sort();
    references.dedup();
    let by = resolve_persona(storage, persona)?;
    let (fragment, note_id) = compass::note_fragment(
        genid().id,
        goal_id,
        body,
        tags,
        references,
        &predecessors,
        by,
        epoch_interval(now_epoch()?),
    )?;
    storage.publish(fragment, "add Compass note")?;
    println!("Added note {note_id:x} to goal {goal_id:x}");
    Ok(())
}

fn unique_priority_base(facts: &TribleSet) -> Result<(BTreeSet<(Id, Id)>, Vec<Id>)> {
    match compass::priority_resolution(facts) {
        PriorityResolution::Missing => Ok((BTreeSet::new(), Vec::new())),
        PriorityResolution::Unique(snapshot) => {
            let id = snapshot.id;
            Ok((snapshot.edges, vec![id]))
        }
        PriorityResolution::Agreed(snapshots) => {
            let edges = snapshots
                .first()
                .expect("agreed priority has at least two heads")
                .edges
                .clone();
            let heads = snapshots.into_iter().map(|snapshot| snapshot.id).collect();
            Ok((edges, heads))
        }
        PriorityResolution::Forked(snapshots) => bail!(
            "priority state is forked at heads {}; use `compass priority-resolve` with the complete intended edge set",
            snapshots
                .iter()
                .map(|snapshot| fmt_id(snapshot.id))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        PriorityResolution::Invalid(reason) => bail!("priority state is invalid: {reason}"),
    }
}

fn cmd_prioritize(storage: CompassStorage<'_>, higher: String, lower: String) -> Result<()> {
    let view = storage.view()?;
    let higher = resolve_goal(&higher, &view.facts)?;
    let lower = resolve_goal(&lower, &view.facts)?;
    if higher == lower {
        bail!("cannot prioritize a goal over itself");
    }
    if compass::parent_edges(&view.facts)?.contains(&(higher, lower)) {
        bail!("children are already implicitly prioritized over their parents");
    }
    let (mut edges, predecessors) = unique_priority_base(&view.facts)?;
    let joined = predecessors.len();
    if !edges.insert((higher, lower)) {
        bail!("that explicit priority edge is already present");
    }
    compass::validate_priority_edges(&view.facts, &edges)?;
    let fragment = compass::priority_snapshot_fragment(edges, &predecessors)?.0;
    storage.publish(fragment, "prioritize Compass goal")?;
    println!("{higher:x} > {lower:x}");
    if joined > 1 {
        println!("Joined {joined} agreeing priority heads");
    }
    Ok(())
}

fn cmd_deprioritize(storage: CompassStorage<'_>, higher: String, lower: String) -> Result<()> {
    let view = storage.view()?;
    let higher = resolve_goal(&higher, &view.facts)?;
    let lower = resolve_goal(&lower, &view.facts)?;
    let (mut edges, predecessors) = unique_priority_base(&view.facts)?;
    let joined = predecessors.len();
    if !edges.remove(&(higher, lower)) {
        if compass::parent_edges(&view.facts)?.contains(&(higher, lower)) {
            bail!("child-over-parent priority is structural and cannot be removed");
        }
        bail!("no explicit priority edge {higher:x}>{lower:x}");
    }
    compass::validate_priority_edges(&view.facts, &edges)?;
    let fragment = compass::priority_snapshot_fragment(edges, &predecessors)?.0;
    storage.publish(fragment, "deprioritize Compass goal")?;
    println!("Removed: {higher:x} > {lower:x}");
    if joined > 1 {
        println!("Joined {joined} agreeing priority heads");
    }
    Ok(())
}

fn parse_priority_edge(raw: &str, facts: &TribleSet) -> Result<(Id, Id)> {
    let (higher, lower) = raw
        .split_once(':')
        .ok_or_else(|| anyhow!("priority edge must be HIGHER:LOWER, got '{raw}'"))?;
    Ok((resolve_goal(higher, facts)?, resolve_goal(lower, facts)?))
}

fn cmd_priority_resolve(storage: CompassStorage<'_>, edges: Vec<String>) -> Result<()> {
    let view = storage.view()?;
    let predecessors = match compass::priority_resolution(&view.facts) {
        PriorityResolution::Missing => Vec::new(),
        PriorityResolution::Unique(snapshot) => vec![snapshot.id],
        PriorityResolution::Agreed(snapshots) | PriorityResolution::Forked(snapshots) => {
            snapshots.into_iter().map(|snapshot| snapshot.id).collect()
        }
        PriorityResolution::Invalid(reason) => bail!("priority state is invalid: {reason}"),
    };
    let edges: BTreeSet<(Id, Id)> = edges
        .iter()
        .map(|edge| parse_priority_edge(edge, &view.facts))
        .collect::<Result<_>>()?;
    compass::validate_priority_edges(&view.facts, &edges)?;
    let joined = predecessors.len();
    let (fragment, snapshot_id) = compass::priority_snapshot_fragment(edges, &predecessors)?;
    storage.publish(fragment, "resolve Compass priority state")?;
    println!("Published exact priority snapshot {snapshot_id:x}");
    if joined > 1 {
        println!("Joined {joined} concurrent priority heads");
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct TaskRow {
    id: Id,
    title: String,
    tags: Vec<String>,
    parent: Option<Id>,
    sort_key: Option<i128>,
    notes: usize,
    state_note: Option<String>,
}

fn priority_ranks(ids: &BTreeSet<Id>, edges: &BTreeSet<(Id, Id)>) -> HashMap<Id, usize> {
    let mut outgoing: BTreeMap<Id, Vec<Id>> = BTreeMap::new();
    let mut indegree: BTreeMap<Id, usize> = ids.iter().map(|id| (*id, 0)).collect();
    for &(higher, lower) in edges {
        if ids.contains(&higher) && ids.contains(&lower) {
            outgoing.entry(higher).or_default().push(lower);
            *indegree.entry(lower).or_default() += 1;
        }
    }
    let mut ready: BTreeSet<Id> = indegree
        .iter()
        .filter_map(|(&id, &degree)| (degree == 0).then_some(id))
        .collect();
    let mut rank = 0;
    let mut ranks = HashMap::new();
    while let Some(id) = ready.pop_first() {
        ranks.insert(id, rank);
        rank += 1;
        for lower in outgoing.get(&id).into_iter().flatten() {
            let degree = indegree.get_mut(lower).unwrap();
            *degree -= 1;
            if *degree == 0 {
                ready.insert(*lower);
            }
        }
    }
    for &id in ids {
        ranks.entry(id).or_insert(rank);
    }
    ranks
}

fn order_rows(rows: Vec<TaskRow>, edges: &BTreeSet<(Id, Id)>) -> Vec<(TaskRow, usize)> {
    let mut by_id: BTreeMap<Id, TaskRow> = rows.into_iter().map(|row| (row.id, row)).collect();
    let ids: BTreeSet<Id> = by_id.keys().copied().collect();
    let ranks = priority_ranks(&ids, edges);
    let mut children: BTreeMap<Id, Vec<Id>> = BTreeMap::new();
    let mut roots = Vec::new();
    for (&id, row) in &by_id {
        if let Some(parent) = row.parent {
            if ids.contains(&parent) {
                children.entry(parent).or_default().push(id);
                continue;
            }
        }
        roots.push(id);
    }
    let sort = |items: &mut Vec<Id>| {
        items.sort_by(|a, b| {
            ranks[a]
                .cmp(&ranks[b])
                .then_with(|| by_id[b].sort_key.cmp(&by_id[a].sort_key))
                .then_with(|| a.cmp(b))
        });
    };
    sort(&mut roots);
    for values in children.values_mut() {
        sort(values);
    }

    fn walk(
        id: Id,
        depth: usize,
        by_id: &mut BTreeMap<Id, TaskRow>,
        children: &BTreeMap<Id, Vec<Id>>,
        output: &mut Vec<(TaskRow, usize)>,
    ) {
        let Some(row) = by_id.remove(&id) else {
            return;
        };
        output.push((row, depth));
        for child in children.get(&id).into_iter().flatten() {
            walk(*child, depth + 1, by_id, children, output);
        }
    }

    let mut output = Vec::new();
    for root in roots {
        walk(root, 0, &mut by_id, &children, &mut output);
    }
    for id in by_id.keys().copied().collect::<Vec<_>>() {
        walk(id, 0, &mut by_id, &children, &mut output);
    }
    output
}

fn current_priority_for_render(facts: &TribleSet) -> Result<BTreeSet<(Id, Id)>> {
    let explicit = match compass::priority_resolution(facts) {
        PriorityResolution::Missing => {
            eprintln!("warning: priority state is missing");
            BTreeSet::new()
        }
        PriorityResolution::Unique(snapshot) => snapshot.edges,
        PriorityResolution::Agreed(snapshots) => {
            eprintln!(
                "notice: priority state has {} agreeing concurrent heads: {}",
                snapshots.len(),
                snapshots
                    .iter()
                    .map(|snapshot| fmt_id(snapshot.id))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            snapshots
                .into_iter()
                .next()
                .expect("agreed priority has at least two heads")
                .edges
        }
        PriorityResolution::Forked(snapshots) => {
            eprintln!(
                "warning: priority state is forked at {}; explicit priorities are not arbitrated",
                snapshots
                    .iter()
                    .map(|snapshot| fmt_id(snapshot.id))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            BTreeSet::new()
        }
        PriorityResolution::Invalid(reason) => {
            eprintln!("warning: priority state is invalid: {reason}");
            BTreeSet::new()
        }
    };
    compass::effective_priority_edges(facts, &explicit)
}

fn status_column(
    resolution: StatusResolution,
) -> (String, Option<i128>, Option<String>, BTreeSet<String>) {
    match resolution {
        StatusResolution::Missing => (
            "!missing".into(),
            None,
            Some("status missing".into()),
            BTreeSet::from(["missing".into()]),
        ),
        StatusResolution::Invalid(reason) => (
            "!invalid".into(),
            None,
            Some(format!("status invalid: {reason}")),
            BTreeSet::from(["invalid".into()]),
        ),
        StatusResolution::Unique(snapshot) => {
            let value = snapshot.value;
            (
                value.clone(),
                Some(interval_key(snapshot.created_at)),
                None,
                BTreeSet::from([value]),
            )
        }
        StatusResolution::Agreed(snapshots) => {
            let value = snapshots
                .first()
                .expect("agreed status has at least two heads")
                .value
                .clone();
            let sort_key = snapshots
                .iter()
                .map(|snapshot| interval_key(snapshot.created_at))
                .max()
                .expect("agreed status has at least two heads");
            let heads = snapshots
                .iter()
                .map(|snapshot| fmt_id(snapshot.id))
                .collect::<Vec<_>>()
                .join(", ");
            (
                value.clone(),
                Some(sort_key),
                Some(format!(
                    "{} agreeing concurrent heads: {heads}",
                    snapshots.len()
                )),
                BTreeSet::from([value, "agreed".into()]),
            )
        }
        StatusResolution::Forked(snapshots) => {
            let statuses: BTreeSet<String> = snapshots
                .iter()
                .map(|snapshot| snapshot.value.clone())
                .collect();
            let detail = snapshots
                .iter()
                .map(|snapshot| format!("{}@{}", snapshot.value, fmt_id(snapshot.id)))
                .collect::<Vec<_>>()
                .join(", ");
            let sort_key = snapshots
                .iter()
                .map(|snapshot| interval_key(snapshot.created_at))
                .max()
                .expect("forked status has at least two heads");
            let mut filter_values = statuses;
            filter_values.insert("forked".into());
            (
                "!forked".into(),
                Some(sort_key),
                Some(format!("status fork: {detail}")),
                filter_values,
            )
        }
    }
}

fn cmd_list(
    storage: CompassStorage<'_>,
    status_filter: Vec<String>,
    tag_filter: Vec<String>,
    show_done: bool,
) -> Result<()> {
    let view = storage.view()?;
    let status_filter: BTreeSet<String> = status_filter
        .into_iter()
        .map(compass::canonical_status)
        .collect::<Result<_>>()?;
    let tag_filter: BTreeSet<String> = tag_filter
        .into_iter()
        .map(compass::canonical_tag)
        .collect::<Result<_>>()?;
    let priority = current_priority_for_render(&view.facts)?;
    let mut columns: BTreeMap<String, Vec<TaskRow>> = BTreeMap::new();

    for goal_id in compass::goal_anchors(&view.facts) {
        let genesis = compass::genesis_for_goal(&view.facts, goal_id)?
            .ok_or_else(|| anyhow!("goal {goal_id:x} has no genesis"))?;
        let tags = compass::tag_labels(&view.reader, &view.facts, &genesis.tags)?;
        if !tag_filter.is_empty() && !tags.iter().any(|tag| tag_filter.contains(tag)) {
            continue;
        }
        let (column, sort_key, state_note, filter_values) =
            status_column(compass::status_resolution(&view.facts, goal_id));
        if !status_filter.is_empty() && status_filter.is_disjoint(&filter_values) {
            continue;
        }
        if status_filter.is_empty() && !show_done && column == "done" {
            continue;
        }
        columns.entry(column).or_default().push(TaskRow {
            id: goal_id,
            title: compass::read_text(&view.reader, genesis.title)?,
            tags,
            parent: genesis.parent,
            sort_key,
            notes: compass::notes_for_goal(&view.facts, goal_id)?.len(),
            state_note,
        });
    }

    let mut order: Vec<String> = DEFAULT_STATUSES
        .iter()
        .filter(|status| columns.contains_key(**status))
        .map(|status| (*status).to_owned())
        .collect();
    for special in ["!forked", "!missing", "!invalid"] {
        if columns.contains_key(special) {
            order.push(special.to_owned());
        }
    }
    let mut extras: Vec<String> = columns
        .keys()
        .filter(|status| !order.contains(status))
        .cloned()
        .collect();
    extras.sort();
    order.extend(extras);

    if order.is_empty() {
        println!("No goals yet.");
        return Ok(());
    }
    for status in order {
        let rows = columns.remove(&status).unwrap_or_default();
        println!();
        let heading = match status.as_str() {
            "!forked" => "STATUS FORKED",
            "!missing" => "STATUS MISSING",
            "!invalid" => "STATUS INVALID",
            _ => status.as_str(),
        };
        println!("== {} ({}) ==", heading.to_uppercase(), rows.len());
        for (row, depth) in order_rows(rows, &priority) {
            let tags = if row.tags.is_empty() {
                String::new()
            } else {
                format!(
                    " {}",
                    row.tags
                        .iter()
                        .map(|tag| format!("#{tag}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            };
            let notes = match row.notes {
                0 => String::new(),
                1 => " (1 note)".into(),
                count => format!(" ({count} notes)"),
            };
            let state = row
                .state_note
                .map(|state| format!(" [{state}]"))
                .unwrap_or_default();
            println!(
                "{}- [{}] {}{}{}{}",
                "  ".repeat(depth),
                fmt_id(row.id),
                row.title,
                tags,
                notes,
                state
            );
        }
    }
    println!();
    Ok(())
}

fn print_status_resolution(resolution: StatusResolution) {
    match resolution {
        StatusResolution::Missing => println!("Status: MISSING"),
        StatusResolution::Invalid(reason) => println!("Status: INVALID ({reason})"),
        StatusResolution::Unique(snapshot) => println!(
            "Status: {} ({}; head {})",
            snapshot.value,
            format_interval(snapshot.created_at),
            fmt_id(snapshot.id)
        ),
        StatusResolution::Agreed(snapshots) => {
            let value = &snapshots[0].value;
            println!(
                "Status: {value} (AGREED; {} concurrent heads)",
                snapshots.len()
            );
            for snapshot in snapshots {
                println!(
                    "  - {} at {}{}",
                    fmt_id(snapshot.id),
                    format_interval(snapshot.created_at),
                    snapshot
                        .by
                        .map(|by| format!(" by {}", fmt_id(by)))
                        .unwrap_or_default()
                );
            }
        }
        StatusResolution::Forked(snapshots) => {
            println!("Status: FORKED ({} heads)", snapshots.len());
            for snapshot in snapshots {
                println!(
                    "  - {} {} at {}{}",
                    fmt_id(snapshot.id),
                    snapshot.value,
                    format_interval(snapshot.created_at),
                    snapshot
                        .by
                        .map(|by| format!(" by {}", fmt_id(by)))
                        .unwrap_or_default()
                );
            }
        }
    }
}

fn print_priority_for_goal(facts: &TribleSet, goal_id: Id) {
    match compass::priority_resolution(facts) {
        PriorityResolution::Missing => println!("Priority: MISSING"),
        PriorityResolution::Invalid(reason) => println!("Priority: INVALID ({reason})"),
        PriorityResolution::Unique(snapshot) => {
            println!("Priority head: {}", fmt_id(snapshot.id));
            print_incident_edges(goal_id, &snapshot.edges, "  ");
        }
        PriorityResolution::Agreed(snapshots) => {
            println!(
                "Priority: AGREED ({} concurrent heads: {})",
                snapshots.len(),
                snapshots
                    .iter()
                    .map(|snapshot| fmt_id(snapshot.id))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            print_incident_edges(goal_id, &snapshots[0].edges, "  ");
        }
        PriorityResolution::Forked(snapshots) => {
            println!("Priority: FORKED ({} heads)", snapshots.len());
            for snapshot in snapshots {
                println!("  head {}:", fmt_id(snapshot.id));
                print_incident_edges(goal_id, &snapshot.edges, "    ");
            }
        }
    }
}

fn print_incident_edges(goal_id: Id, edges: &BTreeSet<(Id, Id)>, indent: &str) {
    let incident: Vec<_> = edges
        .iter()
        .filter(|(higher, lower)| *higher == goal_id || *lower == goal_id)
        .collect();
    if incident.is_empty() {
        println!("{indent}(no explicit incident edges)");
    } else {
        for (higher, lower) in incident {
            println!("{indent}{higher:x} > {lower:x}");
        }
    }
}

fn cmd_show(storage: CompassStorage<'_>, input: String) -> Result<()> {
    let view = storage.view()?;
    let goal_id = resolve_goal(&input, &view.facts)?;
    let genesis = compass::genesis_for_goal(&view.facts, goal_id)?
        .ok_or_else(|| anyhow!("goal {goal_id:x} has no genesis"))?;
    println!("Goal {goal_id:x}");
    println!(
        "Title: {}",
        compass::read_text(&view.reader, genesis.title)?
    );
    println!("Created: {}", format_interval(genesis.created_at));
    let tags = compass::tag_labels(&view.reader, &view.facts, &genesis.tags)?;
    if !tags.is_empty() {
        println!("Tags: {}", tags.join(", "));
    }
    if let Some(parent) = genesis.parent {
        println!("Parent: {parent:x}");
    }
    print_status_resolution(compass::status_resolution(&view.facts, goal_id));
    print_priority_for_goal(&view.facts, goal_id);

    let mut status_ids: Vec<Id> = find!(
        id: Id,
        pattern!(&view.facts, [{ ?id @
            metadata::tag: &faculties::schemas::compass::KIND_STATUS_SNAPSHOT,
            faculties::schemas::compass::status::of: &goal_id,
        }])
    )
    .collect();
    status_ids.sort_unstable();
    let mut history = status_ids
        .into_iter()
        .map(|id| compass::status_snapshot(&view.facts, id))
        .collect::<Result<Vec<_>>>()?;
    history.sort_by_key(|snapshot| (interval_key(snapshot.created_at), snapshot.id));
    if !history.is_empty() {
        println!();
        println!("Status history:");
        for snapshot in history {
            println!(
                "- [{}] {} {}{}{}",
                fmt_id(snapshot.id),
                format_interval(snapshot.created_at),
                snapshot.value,
                snapshot
                    .by
                    .map(|by| format!(" by {}", fmt_id(by)))
                    .unwrap_or_default(),
                if snapshot.predecessors.is_empty() {
                    String::new()
                } else {
                    format!(
                        " <- {}",
                        snapshot
                            .predecessors
                            .iter()
                            .map(|id| fmt_id(*id))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            );
        }
    }

    let mut notes = compass::notes_for_goal(&view.facts, goal_id)?;
    notes.sort_by_key(|record| (interval_key(record.created_at), record.id));
    if !notes.is_empty() {
        println!();
        println!("Notes:");
        for record in notes {
            print_note(&view, record)?;
        }
    }
    Ok(())
}

fn print_note(view: &CollectionView, record: NoteRecord) -> Result<()> {
    println!(
        "- [{}] {}{}",
        fmt_id(record.id),
        format_interval(record.created_at),
        record
            .by
            .map(|by| format!(" by {}", fmt_id(by)))
            .unwrap_or_default()
    );
    let body = compass::read_text(&view.reader, record.body)?;
    if body.is_empty() {
        println!("  (empty)");
    } else {
        for line in body.lines() {
            println!("  {line}");
        }
    }
    if !record.tags.is_empty() {
        let tags = compass::tag_labels(&view.reader, &view.facts, &record.tags)?;
        println!(
            "  tags: {}",
            tags.iter()
                .map(|tag| format!("#{tag}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    if !record.references.is_empty() {
        let references = record
            .references
            .iter()
            .map(|handle| compass::read_text(&view.reader, *handle))
            .collect::<Result<Vec<_>>>()?;
        println!("  refs: {}", references.join(", "));
    }
    if !record.supersedes.is_empty() {
        println!(
            "  supersedes: {}",
            record
                .supersedes
                .iter()
                .map(|id| fmt_id(*id))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

fn cmd_resolve(storage: CompassStorage<'_>, prefix: String) -> Result<()> {
    let view = storage.view()?;
    println!("{:x}", resolve_goal(&prefix, &view.facts)?);
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    };
    let storage = CompassStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
        scope: cli.scope.unwrap_or(DEFAULT_SCOPE_ID),
    };

    match command {
        Command::Add {
            title,
            status,
            parent,
            tag,
            note,
        } => cmd_add(
            storage,
            faculties::text_arg(&title, "goal title")?,
            status,
            parent,
            tag,
            note.as_deref()
                .map(|value| faculties::text_arg(value, "goal note"))
                .transpose()?,
            cli.persona.as_deref(),
        ),
        Command::List { all, tag, status } => cmd_list(storage, status, tag, all),
        Command::Move { id, status } => cmd_move(storage, id, status, cli.persona.as_deref()),
        Command::Note {
            id,
            note,
            tag,
            reference,
            supersedes,
        } => cmd_note(
            storage,
            id,
            faculties::text_arg(&note, "goal note")?,
            tag,
            reference,
            supersedes,
            cli.persona.as_deref(),
        ),
        Command::Show { id } => cmd_show(storage, id),
        Command::Prioritize { higher, over } => cmd_prioritize(storage, higher, over),
        Command::Deprioritize { higher, over } => cmd_deprioritize(storage, higher, over),
        Command::PriorityResolve { edge } => cmd_priority_resolve(storage, edge),
        Command::Resolve { prefix } => cmd_resolve(storage, prefix),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_references_are_exact_sorted_and_deduplicated() {
        assert_eq!(
            extract_reference_values(
                "[wiki](wiki:ABcd1234) [again](wiki:ABcd1234) [git](git:DEADBEEF)"
            ),
            ["git:DEADBEEF", "wiki:ABcd1234"]
        );
    }

    #[test]
    fn dangling_markdown_link_is_not_a_reference_or_a_panic() {
        assert!(extract_reference_values("unfinished ](").is_empty());
    }

    #[test]
    fn priority_edge_syntax_is_unambiguous() {
        assert!("abc:def".split_once(':').is_some());
        assert!("abcdef".split_once(':').is_none());
    }
}
