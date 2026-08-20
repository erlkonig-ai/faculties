use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::legacy_hint::open_scope;
use faculties::schemas::compass::{
    board, latest_status_event, DEFAULT_STATUSES, KIND_GOAL_ID, KIND_NOTE_ID, KIND_STATUS_ID,
};
use faculties::schemas::relations::DEFAULT_SCOPE_ID as RELATIONS_SCOPE_ID;
use faculties::storage::{load_signer, open_pile_strict};
use faculties::{compass, relations};
use hifitime::Epoch;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::prelude::*;
use triblespace_paths::{PathExpr, PathIndex, Step};

type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, name = "compass", about = "A small TribleSpace kanban faculty")]
struct Cli {
    /// Path to the pile file to use
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Acting persona (relations label or 32-char hex id). When set,
    /// status and note events record who made them — the audit trail gains the
    /// actor, and `orient wait` watchers can absorb their own edits.
    #[arg(long, env = "PERSONA")]
    persona: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Add a new goal
    Add {
        #[arg(help = "Goal title. Use @path for file input or @- for stdin.")]
        title: String,
        #[arg(long, default_value = "todo")]
        status: String,
        /// Parent goal id (full 32-char hex id; use `compass resolve` to look up by prefix)
        #[arg(long)]
        parent: Option<String>,
        #[arg(long)]
        tag: Vec<String>,
        #[arg(long, help = "Initial note. Use @path for file input or @- for stdin.")]
        note: Option<String>,
    },
    /// List goals in kanban columns (hides done by default)
    List {
        /// Show done goals too
        #[arg(long)]
        all: bool,
        /// Filter by tag (repeatable, shows goals matching any)
        #[arg(long)]
        tag: Vec<String>,
        #[arg(value_name = "STATUS")]
        status: Vec<String>,
    },
    /// Move a goal to a new status
    Move {
        /// Full 32-char hex id
        id: String,
        status: String,
    },
    /// Add a note to a goal
    Note {
        /// Full 32-char hex id
        id: String,
        #[arg(help = "Note text. Use @path for file input or @- for stdin.")]
        note: String,
        /// Short note tag (repeatable). Relations person or group tags request
        /// attention through Orient without assigning workflow semantics.
        #[arg(long)]
        tag: Vec<String>,
        /// Opaque exact reference stored on the note (repeatable). Recognized
        /// inline `[text](faculty:hex)` links are stored automatically too.
        #[arg(long = "ref", value_name = "REFERENCE")]
        reference: Vec<String>,
        /// Existing note this note supersedes (repeatable). The edge is
        /// provenance only: Compass keeps and displays every note.
        #[arg(long, value_name = "NOTE_ID")]
        supersedes: Vec<String>,
    },
    /// Show a goal with history and notes
    Show {
        /// Full 32-char hex id
        id: String,
    },
    /// Mark a goal as more important than another
    Prioritize {
        /// The more important goal (full 32-char hex id)
        higher: String,
        /// The less important goal (full 32-char hex id)
        #[arg(long)]
        over: String,
    },
    /// Remove a priority relationship
    Deprioritize {
        /// The goal that was marked more important (full 32-char hex id)
        higher: String,
        /// The goal it was prioritized over (full 32-char hex id)
        #[arg(long)]
        over: String,
    },
    /// Resolve a hex prefix to a full 32-char goal id
    Resolve {
        /// Hex prefix to search for
        prefix: String,
    },
}

// ── on-demand board queries ───────────────────────────────────────────
// All data lives in the TribleSet; we query directly via find!() instead
// of pre-materializing into Rust structs.

/// Query helpers that operate directly on the checked-out TribleSet + workspace.

type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn epoch_interval(epoch: Epoch) -> IntervalValue {
    (epoch, epoch).try_to_inline().unwrap()
}

fn interval_key(interval: IntervalValue) -> i128 {
    let (lower, _): (i128, i128) = interval.try_from_inline().unwrap();
    lower
}

fn format_interval(interval: IntervalValue) -> String {
    let (lower, _): (Epoch, Epoch) = interval.try_from_inline().unwrap();
    format!("{}", lower)
}

fn validate_short(label: &str, value: &str) -> Result<()> {
    if value.as_bytes().len() > 32 {
        bail!("{label} exceeds 32 bytes: {value}");
    }
    if value.as_bytes().iter().any(|b| *b == 0) {
        bail!("{label} contains NUL bytes: {value}");
    }
    Ok(())
}

fn normalize_status(status: String) -> String {
    status.trim().to_lowercase()
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

/// Extract `[text](faculty:<hex>)` markdown link references from text.
/// Returns (faculty, hex_string) pairs.
fn extract_references(text: &str) -> Vec<(String, String)> {
    let mut refs = Vec::new();
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
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
            if hex.len() >= 4
                && !faculty.is_empty()
                && faculty
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                refs.push((faculty.to_string(), hex));
            }
        }
        rest = &after[end + 1..];
    }
    refs.sort();
    refs.dedup();
    refs
}

fn extract_reference_values(text: &str) -> Vec<String> {
    extract_references(text)
        .into_iter()
        .map(|(faculty, hex)| format!("{faculty}:{hex}"))
        .collect()
}

fn load_value_or_file(raw: &str, label: &str) -> Result<String> {
    if let Some(path) = raw.strip_prefix('@') {
        if path == "-" {
            let mut value = String::new();
            std::io::stdin()
                .read_to_string(&mut value)
                .with_context(|| format!("read {label} from stdin"))?;
            return Ok(value);
        }
        return fs::read_to_string(path).with_context(|| format!("read {label} from {path}"));
    }
    Ok(raw.to_string())
}

#[derive(Clone, Copy)]
struct CompassStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

impl CompassStorage<'_> {
    fn with_pile<T>(
        &self,
        f: impl FnOnce(&mut Pile, &ed25519_dalek::SigningKey) -> Result<T>,
    ) -> Result<T> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = f(&mut pile, &signer);
        let close = pile.close();
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
        self.with_pile(|pile, signer| {
            let (facts, reader) = compass::materialize_collection(pile, signer)?;
            f(&facts, &reader)
        })
    }

    /// Build and publish one complete user action against one known-prefix
    /// view. `None` is a genuine no-op and writes no collection record.
    fn update<T>(
        &self,
        persona: Option<&str>,
        f: impl FnOnce(&TribleSet, &PileReader, Option<Id>) -> Result<(Option<Fragment>, T)>,
    ) -> Result<T> {
        self.with_pile(|pile, signer| {
            let (facts, reader) = compass::materialize_collection(pile, signer)?;
            let by = if let Some(persona) = persona {
                let relation_facts = open_scope(&mut *pile, RELATIONS_SCOPE_ID, signer.clone())
                    .materialize()
                    .context("materialize Relations collection for Compass persona")?;
                relations::validate_catalog(&reader, &relation_facts)
                    .context("validate Relations collection for Compass persona")?;
                Some(resolve_persona_id(&relation_facts, &reader, persona)?)
            } else {
                None
            };
            let (fragment, value) = f(&facts, &reader, by)?;
            if let Some(fragment) = fragment {
                compass::validate_candidate(&reader, &facts, &fragment)
                    .context("validate Compass action before publication")?;
                compass::commit_collection(pile, signer, fragment)?;
            }
            Ok(value)
        })
    }
}

fn task_title(reader: &PileReader, space: &TribleSet, task_id: Id) -> String {
    find!(h: TextHandle, pattern!(space, [{ task_id @ board::title: ?h }]))
        .next()
        .and_then(|h| read_text(reader, h).ok())
        .unwrap_or_default()
}

fn task_tags(space: &TribleSet, task_id: Id) -> Vec<String> {
    let mut tags: Vec<String> = find!(
        tag: String,
        pattern!(space, [{ task_id @ metadata::tag: &KIND_GOAL_ID, board::tag: ?tag }])
    )
    .collect();
    tags.sort();
    tags.dedup();
    tags
}

fn task_parent(space: &TribleSet, task_id: Id) -> Option<Id> {
    find!(p: Id, pattern!(space, [{ task_id @ board::parent: ?p }])).next()
}

fn task_created_at(space: &TribleSet, task_id: Id) -> Option<IntervalValue> {
    find!(s: IntervalValue, pattern!(space, [{ task_id @ metadata::created_at: ?s }])).next()
}

/// Latest status for a task.
fn task_latest_status(space: &TribleSet, task_id: Id) -> Option<(String, IntervalValue)> {
    latest_status_event(space, task_id).map(|(_, status, at)| (status, at))
}

/// All goal IDs.
fn all_goal_ids(space: &TribleSet) -> Vec<Id> {
    find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: &KIND_GOAL_ID }])).collect()
}

/// All note event IDs.
fn all_note_ids(space: &TribleSet) -> Vec<Id> {
    find!(
        id: Id,
        pattern!(space, [
            {
                ?id @
                metadata::tag: &KIND_NOTE_ID,
                board::task: _?goal,
                board::note: _?body,
            },
            { _?goal @ metadata::tag: &KIND_GOAL_ID },
        ])
    )
    .collect()
}

fn read_text(reader: &PileReader, handle: TextHandle) -> Result<String> {
    compass::read_text(reader, handle)
}

/// Parse a full 32-char hex ID. Returns a helpful error pointing to `compass resolve` on failure.
fn resolve_task_id(input: &str, space: &TribleSet) -> Result<Id> {
    faculties::resolve_id_prefix(input, all_goal_ids(space))
}

fn resolve_note_id(input: &str, space: &TribleSet) -> Result<Id> {
    let trimmed = input.trim();
    if trimmed.len() != 32 {
        bail!("supersedes requires a full 32-char note id: '{trimmed}'");
    }
    let note_id =
        Id::from_hex(trimmed).ok_or_else(|| anyhow::anyhow!("invalid note id '{trimmed}'"))?;
    if !all_note_ids(space).contains(&note_id) {
        bail!("supersedes target is not an existing note: '{trimmed}'");
    }
    Ok(note_id)
}

fn parent_paths(space: &TribleSet) -> Result<PathIndex> {
    let parent_plus = PathExpr::from(Step::Forward(board::parent.id().into()))
        .plus()
        .compile();
    PathIndex::from_tribles(parent_plus, space.iter())
        .map_err(|error| anyhow::anyhow!("materialize goal-parent ancestry: {error}"))
}

/// Check if `to` is an ancestor of `from` (or `from` itself) in the parent tree.
fn is_ancestor(paths: &PathIndex, from: Id, to: Id) -> bool {
    if from == to {
        return true;
    }
    let from: Inline<inlineencodings::GenId> = from.to_inline();
    let to: Inline<inlineencodings::GenId> = to.to_inline();
    paths.contains(&from.raw, &to.raw)
}

/// Count notes for a task.
fn note_count(space: &TribleSet, task_id: Id) -> usize {
    find!(
        _n: TextHandle,
        pattern!(space, [{ _?evt @ metadata::tag: &KIND_NOTE_ID, board::task: &task_id, board::note: ?_n }])
    ).count()
}

fn event_actor(space: &TribleSet, event_id: Id) -> Option<Id> {
    find!(by: Id, pattern!(space, [{ event_id @ board::by: ?by }])).next()
}

fn note_tags(space: &TribleSet, note_id: Id) -> Vec<String> {
    let mut tags: Vec<String> =
        find!(tag: String, pattern!(space, [{ note_id @ board::tag: ?tag }])).collect();
    tags.sort();
    tags.dedup();
    tags
}

fn note_references(reader: &PileReader, space: &TribleSet, note_id: Id) -> Vec<String> {
    let mut references: Vec<String> = find!(
        handle: TextHandle,
        pattern!(space, [{ note_id @ board::reference: ?handle }])
    )
    .filter_map(|handle| read_text(reader, handle).ok())
    .collect();
    references.sort();
    references.dedup();
    references
}

fn note_supersedes(space: &TribleSet, note_id: Id) -> Vec<Id> {
    let mut predecessors: Vec<Id> = find!(
        predecessor: Id,
        pattern!(space, [{ note_id @ metadata::supersedes: ?predecessor }])
    )
    .collect();
    predecessors.sort();
    predecessors.dedup();
    predecessors
}

fn render_board(
    reader: &PileReader,
    space: &TribleSet,
    status_filter: &[String],
    tag_filter: &[String],
    show_done: bool,
) {
    let goal_ids = all_goal_ids(space);
    let priority_ranks = compass::priority_ranks(
        goal_ids.iter().copied(),
        &compass::goal_priority_edges(space),
    );

    let mut columns: HashMap<String, Vec<TaskRow>> = HashMap::new();

    for &task_id in &goal_ids {
        let (status, status_at) = task_latest_status(space, task_id)
            .map(|(s, at)| (s, Some(at)))
            .unwrap_or_else(|| ("todo".to_string(), None));

        if status_filter.is_empty() {
            if !show_done && status == "done" {
                continue;
            }
        } else if !status_filter.iter().any(|s| s == &status) {
            continue;
        }

        let tags = task_tags(space, task_id);
        if !tag_filter.is_empty() && !tags.iter().any(|t| tag_filter.contains(t)) {
            continue;
        }

        let title = task_title(reader, space, task_id);
        let created_at = task_created_at(space, task_id);
        let notes = note_count(space, task_id);
        let parent = task_parent(space, task_id);

        let sort_key = status_at
            .map(interval_key)
            .or(created_at.map(interval_key))
            .unwrap_or(0);
        columns.entry(status).or_default().push(TaskRow {
            id: task_id,
            id_hex: fmt_id(task_id),
            title,
            tags,
            sort_key,
            note_count: notes,
            parent,
        });
    }

    let mut ordered_statuses = Vec::new();
    for status in DEFAULT_STATUSES {
        if columns.contains_key(status) {
            ordered_statuses.push(status.to_string());
        }
    }
    let mut extras: Vec<String> = columns
        .keys()
        .filter(|s| !DEFAULT_STATUSES.contains(&s.as_str()))
        .cloned()
        .collect();
    extras.sort();
    ordered_statuses.extend(extras);

    if ordered_statuses.is_empty() {
        println!("No goals yet.");
        return;
    }

    for status in ordered_statuses {
        let rows = columns.remove(&status).unwrap_or_default();
        println!();
        println!("== {} ({}) ==", status.to_uppercase(), rows.len());
        let ordered = order_rows(rows, &priority_ranks);
        for (row, depth) in ordered {
            let indent = "  ".repeat(depth);
            println!(
                "{}- [{}] {}{}{}",
                indent,
                row.id_hex,
                row.title,
                row.tag_suffix(),
                row.note_suffix()
            );
        }
    }
    println!();
}

#[derive(Debug, Clone)]
struct TaskRow {
    id: Id,
    id_hex: String,
    title: String,
    tags: Vec<String>,
    sort_key: i128,
    note_count: usize,
    parent: Option<Id>,
}

#[derive(Debug)]
struct NoteRow {
    id: Id,
    text: String,
    sort_key: i128,
    at: String,
    by: Option<Id>,
    tags: Vec<String>,
    references: Vec<String>,
    supersedes: Vec<Id>,
}

impl TaskRow {
    fn tag_suffix(&self) -> String {
        if self.tags.is_empty() {
            String::new()
        } else {
            format!(
                " {}",
                self.tags
                    .iter()
                    .map(|t| format!("#{t}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        }
    }

    fn note_suffix(&self) -> String {
        if self.note_count == 0 {
            String::new()
        } else if self.note_count == 1 {
            " (1 note)".to_string()
        } else {
            format!(" ({} notes)", self.note_count)
        }
    }
}

fn order_rows(rows: Vec<TaskRow>, ranks: &BTreeMap<Id, usize>) -> Vec<(TaskRow, usize)> {
    let mut by_id: HashMap<Id, TaskRow> = HashMap::new();
    for row in rows {
        by_id.insert(row.id, row);
    }
    let ids: HashSet<Id> = by_id.keys().copied().collect();
    let mut children: HashMap<Id, Vec<Id>> = HashMap::new();
    let mut roots = Vec::new();

    for (id, row) in &by_id {
        if let Some(parent) = row.parent {
            if ids.contains(&parent) {
                children.entry(parent).or_default().push(*id);
                continue;
            }
        }
        roots.push(*id);
    }

    let sort_ids = |items: &mut Vec<Id>| {
        items.sort_by(|a, b| {
            let a_rank = ranks.get(a).copied().unwrap_or(usize::MAX);
            let b_rank = ranks.get(b).copied().unwrap_or(usize::MAX);
            match a_rank.cmp(&b_rank) {
                std::cmp::Ordering::Equal => {
                    // Fall back to timestamp (most recent first)
                    let a_key = by_id.get(a).map(|row| row.sort_key).unwrap_or(0);
                    let b_key = by_id.get(b).map(|row| row.sort_key).unwrap_or(0);
                    b_key.cmp(&a_key).then_with(|| a.cmp(b))
                }
                other => other,
            }
        });
    };

    sort_ids(&mut roots);
    for kids in children.values_mut() {
        sort_ids(kids);
    }

    let mut ordered = Vec::new();
    let mut visited = HashSet::new();

    fn walk(
        id: Id,
        depth: usize,
        by_id: &HashMap<Id, TaskRow>,
        children: &HashMap<Id, Vec<Id>>,
        visited: &mut HashSet<Id>,
        out: &mut Vec<(TaskRow, usize)>,
    ) {
        if !visited.insert(id) {
            return;
        }
        let Some(row) = by_id.get(&id) else {
            return;
        };
        out.push((row.clone(), depth));
        if let Some(kids) = children.get(&id) {
            for kid in kids {
                walk(*kid, depth + 1, by_id, children, visited, out);
            }
        }
    }

    for root in roots {
        walk(root, 0, &by_id, &children, &mut visited, &mut ordered);
    }

    for id in by_id.keys() {
        if !visited.contains(id) {
            walk(*id, 0, &by_id, &children, &mut visited, &mut ordered);
        }
    }

    ordered
}

/// Resolve one active Relations person for attribution. The flag remains a
/// cooperative authorship claim, but it cannot name an unknown or retired
/// anchor.
fn resolve_persona_id(space: &TribleSet, reader: &PileReader, input: &str) -> Result<Id> {
    relations::resolve_person(reader, space, input, false)?.require_unique("persona", input)
}

fn cmd_add(
    storage: CompassStorage<'_>,
    title: String,
    status: String,
    parent: Option<String>,
    tags: Vec<String>,
    note: Option<String>,
    persona: Option<&str>,
) -> Result<()> {
    let status = compass::canonical_status(status)?;
    let tags = compass::canonical_tags(tags)?;
    let (task_ref, note_ref) = storage.update(persona, |space, _reader, by_id| {
        let parent_id = match parent.as_deref() {
            Some(parent) => Some(resolve_task_id(parent, space)?),
            None => None,
        };
        let task_ref = genid().id;
        let now = epoch_interval(now_epoch());
        let mut change = compass::kind_catalog_fragment();
        change += compass::goal_fragment(task_ref, title, tags, parent_id, now)?;
        change += compass::status_fragment(task_ref, status, by_id, now)?;

        let mut note_ref = None;
        if let Some(note) = note {
            let note_id = genid().id;
            let references = extract_reference_values(&note);
            change += compass::note_fragment(
                note_id,
                task_ref,
                note,
                vec![],
                references,
                vec![],
                by_id,
                now,
            )?;
            note_ref = Some(note_id);
        }
        Ok((Some(change), (task_ref, note_ref)))
    })?;
    println!("Added goal {:x}", task_ref);
    if let Some(note_ref) = note_ref {
        println!("Added note {:x} to goal {:x}", note_ref, task_ref);
    }
    Ok(())
}

fn cmd_list(
    storage: CompassStorage<'_>,
    status_filter: Vec<String>,
    tag_filter: Vec<String>,
    show_done: bool,
) -> Result<()> {
    let status_filter: Vec<String> = status_filter.into_iter().map(normalize_status).collect();
    for status in &status_filter {
        validate_short("status", status)?;
    }

    storage.with_view(|space, reader| {
        render_board(reader, space, &status_filter, &tag_filter, show_done);
        Ok(())
    })
}

fn cmd_move(
    storage: CompassStorage<'_>,
    id: String,
    status: String,
    persona: Option<&str>,
) -> Result<()> {
    let status = compass::canonical_status(status)?;
    let rendered_status = status.clone();
    let resolved = storage.update(persona, |space, _reader, by_id| {
        let task_id = resolve_task_id(&id, space)?;
        let mut change = compass::kind_catalog_fragment();
        change += compass::status_fragment(task_id, status, by_id, epoch_interval(now_epoch()))?;
        Ok((Some(change), task_id))
    })?;
    println!("Moved goal {:x} to {}", resolved, rendered_status);
    Ok(())
}

fn cmd_note(
    storage: CompassStorage<'_>,
    id: String,
    note: String,
    tags: Vec<String>,
    mut references: Vec<String>,
    supersedes: Vec<String>,
    persona: Option<&str>,
) -> Result<()> {
    let tags = compass::canonical_tags(tags)?;
    if let Some(reference) = references
        .iter()
        .find(|reference| reference.trim().is_empty())
    {
        bail!("reference must not be empty: {reference:?}");
    }
    references.extend(extract_reference_values(&note));
    references.sort();
    references.dedup();

    let (task_id, note_id) = storage.update(persona, |space, _reader, by_id| {
        let task_id = resolve_task_id(&id, space)?;
        let superseded_ids: Vec<Id> = supersedes
            .iter()
            .map(|input| resolve_note_id(input, space))
            .collect::<Result<_>>()?;
        let now = epoch_interval(now_epoch());
        let note_id = genid().id;
        let mut change = compass::kind_catalog_fragment();
        change += compass::note_fragment(
            note_id,
            task_id,
            note,
            tags,
            references,
            superseded_ids,
            by_id,
            now,
        )?;
        Ok((Some(change), (task_id, note_id)))
    })?;
    println!("Added note {:x} to goal {:x}", note_id, task_id);
    Ok(())
}

fn cmd_show(storage: CompassStorage<'_>, id: String) -> Result<()> {
    storage.with_view(|space, reader| {
        let task_id = resolve_task_id(&id, space)?;

        let title = task_title(reader, space, task_id);
        if title.is_empty() {
            bail!("goal missing");
        }

        println!("Goal {:x}", task_id);
        println!("Title: {}", title);
        if let Some(created) = task_created_at(space, task_id) {
            println!("Created: {}", format_interval(created));
        }

        if let Some((status, at)) = task_latest_status(space, task_id) {
            println!("Status: {} (since {})", status, format_interval(at));
        }

        let tags = task_tags(space, task_id);
        if !tags.is_empty() {
            println!("Tags: {}", tags.join(", "));
        }

        if let Some(parent_id) = task_parent(space, task_id) {
            let parent_hex = fmt_id(parent_id);
            let parent_title = task_title(reader, space, parent_id);
            if parent_title.is_empty() {
                println!("Parent: {parent_hex}");
            } else {
                println!("Parent: {parent_title} ({parent_hex})");
            }
        }

        // Status history for this task.
        let mut history: Vec<(i128, Id, String, String, Option<Id>)> = find!(
            (event: Id, status: String, at: IntervalValue),
            pattern!(space, [{
                ?event @
                metadata::tag: &KIND_STATUS_ID,
                board::status_of: &task_id,
                board::status: ?status,
                metadata::created_at: ?at,
            }])
        )
        .map(|(event, status, at)| {
            (
                interval_key(at),
                event,
                format_interval(at),
                status,
                event_actor(space, event),
            )
        })
        .collect();
        if !history.is_empty() {
            history.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
            println!();
            println!("Status history:");
            for (_, _, at, status, by) in &history {
                match by {
                    Some(by) => println!("- {at} {status} by {by:x}"),
                    None => println!("- {at} {status}"),
                }
            }
        }

        // Notes for this task.
        let mut notes: Vec<NoteRow> = find!(
            (note_id: Id, note_handle: TextHandle, at: IntervalValue),
            pattern!(space, [{
                ?note_id @
                metadata::tag: &KIND_NOTE_ID,
                board::task: &task_id,
                board::note: ?note_handle,
                metadata::created_at: ?at,
            }])
        )
        .filter_map(|(note_id, handle, at)| {
            read_text(reader, handle).ok().map(|text| NoteRow {
                id: note_id,
                text,
                sort_key: interval_key(at),
                at: format_interval(at),
                by: event_actor(space, note_id),
                tags: note_tags(space, note_id),
                references: note_references(reader, space, note_id),
                supersedes: note_supersedes(space, note_id),
            })
        })
        .collect();
        if !notes.is_empty() {
            notes.sort_by(|a, b| (a.sort_key, a.id).cmp(&(b.sort_key, b.id)));
            println!();
            println!("Notes:");
            for note in &notes {
                match note.by {
                    Some(by) => println!("- [{}] {} by {by:x}", fmt_id(note.id), note.at),
                    None => println!("- [{}] {}", fmt_id(note.id), note.at),
                }
                if note.text.is_empty() {
                    println!("  (empty)");
                } else {
                    for line in note.text.lines() {
                        println!("  {line}");
                    }
                }
                if !note.tags.is_empty() {
                    println!(
                        "  tags: {}",
                        note.tags
                            .iter()
                            .map(|tag| format!("#{tag}"))
                            .collect::<Vec<_>>()
                            .join(" ")
                    );
                }
                if !note.references.is_empty() {
                    println!("  refs: {}", note.references.join(", "));
                }
                if !note.supersedes.is_empty() {
                    println!(
                        "  supersedes: {}",
                        note.supersedes
                            .iter()
                            .map(|id| fmt_id(*id))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
            }

            let mut all_refs = Vec::new();
            for note in &notes {
                all_refs.extend(extract_references(&note.text));
            }
            all_refs.sort();
            all_refs.dedup();
            if !all_refs.is_empty() {
                println!();
                println!("References:");
                for (faculty, hex) in &all_refs {
                    println!("  ⇢ {faculty}:{hex}");
                }
            }
        }
        Ok(())
    })
}

fn cmd_prioritize(
    storage: CompassStorage<'_>,
    higher_input: String,
    lower_input: String,
) -> Result<()> {
    let (higher_title, lower_title) = storage.update(None, |space, reader, _| {
        let higher_id = resolve_task_id(&higher_input, space)?;
        let lower_id = resolve_task_id(&lower_input, space)?;

        if higher_id == lower_id {
            bail!("cannot prioritize a goal over itself");
        }

        // Build full edge set (explicit + implicit child→parent)
        let edges = compass::goal_priority_edges(space);

        if compass::would_create_priority_cycle(&edges, higher_id, lower_id) {
            let paths = parent_paths(space)?;
            if is_ancestor(&paths, higher_id, lower_id) || is_ancestor(&paths, lower_id, higher_id)
            {
                bail!("children are implicitly prioritized over their parents");
            }
            bail!("would create a priority cycle");
        }

        let mut change = compass::kind_catalog_fragment();
        change +=
            compass::priority_fragment(higher_id, lower_id, true, epoch_interval(now_epoch()));
        Ok((
            Some(change),
            (
                task_title(reader, space, higher_id),
                task_title(reader, space, lower_id),
            ),
        ))
    })?;
    println!(
        "{} > {}",
        if higher_title.is_empty() {
            "?"
        } else {
            &higher_title
        },
        if lower_title.is_empty() {
            "?"
        } else {
            &lower_title
        }
    );
    Ok(())
}

fn cmd_deprioritize(
    storage: CompassStorage<'_>,
    higher_input: String,
    lower_input: String,
) -> Result<()> {
    let (higher_title, lower_title) = storage.update(None, |space, reader, _| {
        let higher_id = resolve_task_id(&higher_input, space)?;
        let lower_id = resolve_task_id(&lower_input, space)?;

        let edges = compass::active_priority_edges(space);
        if !edges.contains(&(higher_id, lower_id)) {
            bail!("no active priority relationship between these goals");
        }

        let mut change = compass::kind_catalog_fragment();
        change +=
            compass::priority_fragment(higher_id, lower_id, false, epoch_interval(now_epoch()));
        Ok((
            Some(change),
            (
                task_title(reader, space, higher_id),
                task_title(reader, space, lower_id),
            ),
        ))
    })?;
    println!(
        "Removed: {} > {}",
        if higher_title.is_empty() {
            "?"
        } else {
            &higher_title
        },
        if lower_title.is_empty() {
            "?"
        } else {
            &lower_title
        }
    );
    Ok(())
}

fn cmd_resolve(storage: CompassStorage<'_>, prefix: String) -> Result<()> {
    storage.with_view(|space, _reader| {
        let id = resolve_task_id(&prefix, space)?;
        println!("{:x}", id);
        Ok(())
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(cmd) = cli.command else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };
    let storage = CompassStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
    };

    match cmd {
        Command::Add {
            title,
            status,
            parent,
            tag,
            note,
        } => {
            let title = load_value_or_file(&title, "goal title")?;
            let note = note
                .as_deref()
                .map(|value| faculties::text_arg(value, "goal note"))
                .transpose()?;
            cmd_add(
                storage,
                title,
                status,
                parent,
                tag,
                note,
                cli.persona.as_deref(),
            )
        }
        Command::List { status, tag, all } => cmd_list(storage, status, tag, all),
        Command::Move { id, status } => cmd_move(storage, id, status, cli.persona.as_deref()),
        Command::Note {
            id,
            note,
            tag,
            reference,
            supersedes,
        } => {
            let note = faculties::text_arg(&note, "goal note")?;
            cmd_note(
                storage,
                id,
                note,
                tag,
                reference,
                supersedes,
                cli.persona.as_deref(),
            )
        }
        Command::Show { id } => cmd_show(storage, id),
        Command::Prioritize { higher, over } => cmd_prioritize(storage, higher, over),
        Command::Deprioritize { higher, over } => cmd_deprioritize(storage, higher, over),
        Command::Resolve { prefix } => cmd_resolve(storage, prefix),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use faculties::storage::initialize_signer;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "faculties-compass-cli-{}-{serial}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn parent_paths_preserve_reflexive_and_transitive_ancestry() {
        let root = Id::new([1; 16]).unwrap();
        let child = Id::new([2; 16]).unwrap();
        let grandchild = Id::new([3; 16]).unwrap();
        let unrelated = Id::new([4; 16]).unwrap();
        let mut space = TribleSet::new();
        space += entity! { ExclusiveId::force_ref(&child) @ board::parent: &root };
        space += entity! { ExclusiveId::force_ref(&grandchild) @ board::parent: &child };

        let paths = parent_paths(&space).unwrap();
        assert!(is_ancestor(&paths, grandchild, root));
        assert!(is_ancestor(&paths, child, root));
        assert!(is_ancestor(&paths, root, root));
        assert!(!is_ancestor(&paths, root, grandchild));
        assert!(!is_ancestor(&paths, grandchild, unrelated));
    }

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
    fn native_actions_accumulate_and_reads_do_not_write() {
        let directory = TestDirectory::new();
        let pile = directory.0.join("compass.pile");
        let key = directory.0.join("compass.key");
        std::fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        let storage = CompassStorage {
            pile: &pile,
            key: Some(&key),
        };

        cmd_add(
            storage,
            "A native goal".to_owned(),
            "todo".to_owned(),
            None,
            vec!["test".to_owned()],
            Some("first note".to_owned()),
            None,
        )
        .unwrap();
        let goal = storage
            .with_view(|facts, _| Ok(*compass::goal_ids(facts).iter().next().unwrap()))
            .unwrap();

        let before = std::fs::metadata(&pile).unwrap().len();
        cmd_list(storage, vec![], vec![], true).unwrap();
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), before);

        cmd_move(storage, format!("{goal:x}"), "doing".to_owned(), None).unwrap();
        storage
            .with_view(|facts, _| {
                assert_eq!(
                    latest_status_event(facts, goal)
                        .map(|(_, value, _)| value)
                        .as_deref(),
                    Some("doing")
                );
                Ok(())
            })
            .unwrap();
    }
}
