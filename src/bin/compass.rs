use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::collection_names::{configured_handle, open_configured, open_exact_in};
use faculties::schemas::compass::{
    board, latest_status_event, DEFAULT_SCOPE_ID as COMPASS_SCOPE_ID, DEFAULT_STATUSES,
    KIND_GOAL_ID, KIND_NOTE_ID, KIND_STATUS_ID,
};
use faculties::schemas::relations::DEFAULT_SCOPE_ID as RELATIONS_SCOPE_ID;
use faculties::storage::{
    self, load_signer, open_store, runtime, FactArchive, FactCollection, FacultyStore,
};
use faculties::{clock, compass, relations};
use hifitime::Epoch;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use triblespace::core::collection::lww_register::LwwIndex;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::core::repo::StorageClose;
use triblespace::prelude::*;
use triblespace_paths::{PathExpr, PathIndex, Step};

type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;

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
// All data stays in the maintained Succinct view; query it directly instead
// of pre-materializing Rust catalogs.

/// Query helpers that operate directly on one immutable fact view + workspace.

type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

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
        f: impl FnOnce(
            &mut FacultyStore,
            &ed25519_dalek::SigningKey,
            &tokio::runtime::Runtime,
        ) -> Result<T>,
    ) -> Result<T> {
        let signer = load_signer(self.pile, self.key)?;
        let runtime = runtime()?;
        let mut pile = open_store(self.pile)?;
        let result = (|| {
            if let Some(handle) = configured_handle(COMPASS_SCOPE_ID)? {
                let reader = pile
                    .snapshot()
                    .context("freeze configured Compass descriptor")?;
                runtime.block_on(storage::read(&mut pile, &reader, |reader| {
                    open_exact_in(reader, COMPASS_SCOPE_ID, handle)
                }))?;
            }
            f(&mut pile, &signer, &runtime)
        })();
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

    /// Prepare a pure read against fixed facts/status and an acquiring blob
    /// reader. Printing and other effects belong after this returns.
    fn with_view<T>(
        &self,
        mut f: impl FnMut(&FactArchive, &PileSnapshot, &LwwIndex) -> Result<T>,
    ) -> Result<T> {
        self.with_pile(|pile, signer, runtime| {
            runtime.block_on(async {
                let view = compass::materialize_indexed_collection(pile, signer).await?;
                storage::read(pile, view.store_snapshot(), |reader| {
                    f(view.facts(), reader, view.status_register())
                })
                .await
            })
        })
    }

    /// Prepare reads against one frozen view, then author and publish once.
    /// The author runs outside retries, so event clocks and publication cannot
    /// be repeated by a missing attachment. `None` is a genuine no-op.
    fn update<P, T>(
        &self,
        persona: Option<&str>,
        mut prepare: impl FnMut(&FactArchive, &PileSnapshot, Option<Id>) -> Result<P>,
        author: impl FnOnce(P) -> Result<(Option<Fragment>, T)>,
    ) -> Result<T> {
        self.with_pile(|pile, signer, runtime| {
            // Register every descriptor before fixing the one shared source
            // boundary used by this action.
            let compass_source = open_configured(pile, COMPASS_SCOPE_ID, signer.verifying_key())?;
            let compass_facts = FactCollection::new(pile, compass_source)
                .context("register maintained Compass fact collection")?;
            let relation_facts = if persona.is_some() {
                if let Some(handle) = configured_handle(RELATIONS_SCOPE_ID)? {
                    let reader = pile
                        .snapshot()
                        .context("freeze configured Relations descriptor for Compass")?;
                    runtime.block_on(storage::read(pile, &reader, |reader| {
                        open_exact_in(reader, RELATIONS_SCOPE_ID, handle)
                    }))?;
                }
                let source = open_configured(pile, RELATIONS_SCOPE_ID, signer.verifying_key())?;
                Some(
                    FactCollection::new(pile, source)
                        .context("register maintained Relations fact collection")?,
                )
            } else {
                None
            };

            let (compass_support, relation_support, instant) = runtime.block_on(async {
                drop(
                    pile.ensure(compass_facts.source())
                        .await
                        .context("ensure Compass source collection")?,
                );
                if let Some(relation_facts) = relation_facts {
                    drop(
                        pile.ensure(relation_facts.source())
                            .await
                            .context("ensure Relations source collection for Compass persona")?,
                    );
                }
                let before = pile
                    .snapshot()
                    .context("freeze shared Compass/Relations source snapshot")?;
                let compass_support = compass_facts
                    .source()
                    .admitted(&before)
                    .context("admit Compass support")?;
                let relation_support = match relation_facts {
                    Some(relation_facts) => Some(
                        relation_facts
                            .source()
                            .admitted(&before)
                            .context("admit Relations support for Compass persona")?,
                    ),
                    None => None,
                };
                let instant = before.instant();
                drop(before);
                drop(
                    compass_facts
                        .maintain_exact(pile, &compass_support)
                        .await
                        .context("maintain Compass fact collection")?,
                );
                if let (Some(relation_facts), Some(relation_support)) =
                    (relation_facts, relation_support.as_ref())
                {
                    drop(
                        relation_facts
                            .maintain_exact(pile, relation_support)
                            .await
                            .context("maintain Relations fact collection for Compass persona")?,
                    );
                }
                Ok::<_, anyhow::Error>((compass_support, relation_support, instant))
            })?;
            // Attach every view through one immutable post-maintenance store
            // boundary, so validation and persona resolution cannot mix
            // collection watermarks.
            let reader = pile
                .snapshot_at(instant)
                .context("freeze maintained Compass/Relations snapshot")?;
            let facts = reader
                .collection_exact(compass_facts.rank9(), &compass_support)
                .context("observe Compass fact collection")?
                .view::<FactArchive>()
                .context("read Compass fact collection")?;
            let by = if let (Some(persona), Some(relation_facts), Some(relation_support)) =
                (persona, relation_facts, relation_support.as_ref())
            {
                let relations = reader
                    .collection_exact(relation_facts.rank9(), relation_support)
                    .context("observe Relations fact collection for Compass persona")?
                    .view::<FactArchive>()
                    .context("read Relations fact collection for Compass persona")?;
                Some(
                    runtime.block_on(storage::read(pile, &reader, |blob_reader| {
                        resolve_persona_id(&relations, blob_reader, persona)
                    }))?,
                )
            } else {
                None
            };
            let prepared = runtime.block_on(storage::read(pile, &reader, |blob_reader| {
                prepare(&facts, blob_reader, by)
            }))?;
            let (fragment, value) = author(prepared)?;
            if let Some(fragment) = fragment {
                compass::commit_collection(pile, signer, fragment)?;
            }
            Ok(value)
        })
    }
}

fn task_title<P: TriblePattern>(reader: &PileSnapshot, space: &P, task_id: Id) -> Result<String> {
    find!(h: TextHandle, pattern!(space, [{ task_id @ board::title: ?h }]))
        .next()
        .map(|handle| read_text(reader, handle))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn task_tags<P: TriblePattern>(space: &P, task_id: Id) -> Vec<String> {
    let mut tags: Vec<String> = find!(
        tag: String,
        pattern!(space, [{ task_id @ metadata::tag: &KIND_GOAL_ID, board::tag: ?tag }])
    )
    .collect();
    tags.sort();
    tags.dedup();
    tags
}

fn task_parent<P: TriblePattern>(space: &P, task_id: Id) -> Option<Id> {
    find!(p: Id, pattern!(space, [{ task_id @ board::parent: ?p }])).next()
}

fn task_created_at<P: TriblePattern>(space: &P, task_id: Id) -> Option<IntervalValue> {
    find!(s: IntervalValue, pattern!(space, [{ task_id @ metadata::created_at: ?s }])).next()
}

/// Latest status for a task.
fn task_latest_status<P: TriblePattern>(
    space: &P,
    status_register: &LwwIndex,
    task_id: Id,
) -> Option<(String, IntervalValue)> {
    latest_status_event(space, status_register, task_id).map(|(_, status, at)| (status, at))
}

/// All goal IDs.
fn all_goal_ids<P: TriblePattern>(space: &P) -> Vec<Id> {
    find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: &KIND_GOAL_ID }])).collect()
}

/// All note event IDs.
fn all_note_ids<P: TriblePattern>(space: &P) -> Vec<Id> {
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

fn read_text(reader: &PileSnapshot, handle: TextHandle) -> Result<String> {
    compass::read_text(reader, handle)
}

/// Parse a full 32-char hex ID. Returns a helpful error pointing to `compass resolve` on failure.
fn resolve_task_id<P: TriblePattern>(input: &str, space: &P) -> Result<Id> {
    faculties::resolve_id_prefix(input, all_goal_ids(space))
}

fn resolve_note_id<P: TriblePattern>(input: &str, space: &P) -> Result<Id> {
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

fn parent_paths<P: TriblePattern>(space: &P) -> Result<PathIndex> {
    let parent_plus = PathExpr::from(Step::Forward(board::parent.id().into()))
        .plus()
        .compile();
    let edges: TribleSet = find!(
        (child: Id, parent: Id),
        pattern!(space, [{ ?child @ board::parent: ?parent }])
    )
    .map(|(child, parent)| {
        let parent: Inline<inlineencodings::GenId> = parent.to_inline();
        Trible::force(&child, &board::parent.id(), &parent)
    })
    .collect();
    PathIndex::from_tribles(parent_plus, edges.iter())
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
fn note_count<P: TriblePattern>(space: &P, task_id: Id) -> usize {
    find!(
        _n: TextHandle,
        pattern!(space, [{ _?evt @ metadata::tag: &KIND_NOTE_ID, board::task: &task_id, board::note: ?_n }])
    ).count()
}

fn event_actor<P: TriblePattern>(space: &P, event_id: Id) -> Option<Id> {
    find!(by: Id, pattern!(space, [{ event_id @ board::by: ?by }])).next()
}

fn note_tags<P: TriblePattern>(space: &P, note_id: Id) -> Vec<String> {
    let mut tags: Vec<String> =
        find!(tag: String, pattern!(space, [{ note_id @ board::tag: ?tag }])).collect();
    tags.sort();
    tags.dedup();
    tags
}

fn note_references<P: TriblePattern>(
    reader: &PileSnapshot,
    space: &P,
    note_id: Id,
) -> Result<Vec<String>> {
    let mut references: Vec<String> = find!(
        handle: TextHandle,
        pattern!(space, [{ note_id @ board::reference: ?handle }])
    )
    .map(|handle| read_text(reader, handle))
    .collect::<Result<_>>()?;
    references.sort();
    references.dedup();
    Ok(references)
}

fn note_supersedes<P: TriblePattern>(space: &P, note_id: Id) -> Vec<Id> {
    let mut predecessors: Vec<Id> = find!(
        predecessor: Id,
        pattern!(space, [{ note_id @ metadata::supersedes: ?predecessor }])
    )
    .collect();
    predecessors.sort();
    predecessors.dedup();
    predecessors
}

fn render_board<P: TriblePattern>(
    reader: &PileSnapshot,
    space: &P,
    status_register: &LwwIndex,
    status_filter: &[String],
    tag_filter: &[String],
    show_done: bool,
) -> Result<String> {
    let goal_ids = all_goal_ids(space);
    let priority_ranks = compass::priority_ranks(
        goal_ids.iter().copied(),
        &compass::goal_priority_edges(space),
    );

    let mut columns: HashMap<String, Vec<TaskRow>> = HashMap::new();

    for &task_id in &goal_ids {
        let (status, status_at) = task_latest_status(space, status_register, task_id)
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

        let title = task_title(reader, space, task_id)?;
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
        return Ok("No goals yet.\n".to_owned());
    }

    let mut output = String::new();
    for status in ordered_statuses {
        let rows = columns.remove(&status).unwrap_or_default();
        writeln!(output)?;
        writeln!(output, "== {} ({}) ==", status.to_uppercase(), rows.len())?;
        let ordered = order_rows(rows, &priority_ranks);
        for (row, depth) in ordered {
            let indent = "  ".repeat(depth);
            writeln!(
                output,
                "{}- [{}] {}{}{}",
                indent,
                row.id_hex,
                row.title,
                row.tag_suffix(),
                row.note_suffix()
            )?;
        }
    }
    writeln!(output)?;
    Ok(output)
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
fn resolve_persona_id<P: TriblePattern>(
    space: &P,
    reader: &PileSnapshot,
    input: &str,
) -> Result<Id> {
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
    let (task_ref, note_ref) = storage.update(
        persona,
        |space, _reader, by_id| {
            let parent_id = parent
                .as_deref()
                .map(|parent| resolve_task_id(parent, space))
                .transpose()?;
            Ok((parent_id, by_id))
        },
        |(parent_id, by_id)| {
            let now = clock::point_now()?;
            let mut change = compass::kind_catalog_fragment();
            let (goal, task_ref) = compass::goal_fragment(title, tags, parent_id, now)?;
            change += goal;
            change += compass::status_fragment(task_ref, status, by_id, now)?;

            let mut note_ref = None;
            if let Some(note) = note {
                let references = extract_reference_values(&note);
                let (record, note_id) =
                    compass::note_fragment(task_ref, note, vec![], references, vec![], by_id, now)?;
                change += record;
                note_ref = Some(note_id);
            }
            Ok((Some(change), (task_ref, note_ref)))
        },
    )?;
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

    let output = storage.with_view(|space, reader, status_register| {
        render_board(
            reader,
            space,
            status_register,
            &status_filter,
            &tag_filter,
            show_done,
        )
    })?;
    print!("{output}");
    Ok(())
}

fn cmd_move(
    storage: CompassStorage<'_>,
    id: String,
    status: String,
    persona: Option<&str>,
) -> Result<()> {
    let status = compass::canonical_status(status)?;
    let rendered_status = status.clone();
    let resolved = storage.update(
        persona,
        |space, _reader, by_id| Ok((resolve_task_id(&id, space)?, by_id)),
        |(task_id, by_id)| {
            let mut change = compass::kind_catalog_fragment();
            change += compass::status_fragment(task_id, status, by_id, clock::point_now()?)?;
            Ok((Some(change), task_id))
        },
    )?;
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

    let (task_id, note_id) = storage.update(
        persona,
        |space, _reader, by_id| {
            let task_id = resolve_task_id(&id, space)?;
            let superseded_ids: Vec<Id> = supersedes
                .iter()
                .map(|input| resolve_note_id(input, space))
                .collect::<Result<_>>()?;
            Ok((task_id, superseded_ids, by_id))
        },
        |(task_id, superseded_ids, by_id)| {
            let now = clock::point_now()?;
            let mut change = compass::kind_catalog_fragment();
            let (record, note_id) = compass::note_fragment(
                task_id,
                note,
                tags,
                references,
                superseded_ids,
                by_id,
                now,
            )?;
            change += record;
            Ok((Some(change), (task_id, note_id)))
        },
    )?;
    println!("Added note {:x} to goal {:x}", note_id, task_id);
    Ok(())
}

fn render_goal<P: TriblePattern>(
    reader: &PileSnapshot,
    space: &P,
    status_register: &LwwIndex,
    task_id: Id,
) -> Result<String> {
    let mut output = String::new();
    let title = task_title(reader, space, task_id)?;
    if title.is_empty() {
        bail!("goal missing");
    }

    writeln!(output, "Goal {:x}", task_id)?;
    writeln!(output, "Title: {}", title)?;
    if let Some(created) = task_created_at(space, task_id) {
        writeln!(output, "Created: {}", format_interval(created))?;
    }

    if let Some((status, at)) = task_latest_status(space, status_register, task_id) {
        writeln!(output, "Status: {} (since {})", status, format_interval(at))?;
    }

    let tags = task_tags(space, task_id);
    if !tags.is_empty() {
        writeln!(output, "Tags: {}", tags.join(", "))?;
    }

    if let Some(parent_id) = task_parent(space, task_id) {
        let parent_hex = fmt_id(parent_id);
        let parent_title = task_title(reader, space, parent_id)?;
        if parent_title.is_empty() {
            writeln!(output, "Parent: {parent_hex}")?;
        } else {
            writeln!(output, "Parent: {parent_title} ({parent_hex})")?;
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
        writeln!(output)?;
        writeln!(output, "Status history:")?;
        for (_, _, at, status, by) in &history {
            match by {
                Some(by) => writeln!(output, "- {at} {status} by {by:x}")?,
                None => writeln!(output, "- {at} {status}")?,
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
    .map(|(note_id, handle, at)| {
        Ok(NoteRow {
            id: note_id,
            text: read_text(reader, handle)?,
            sort_key: interval_key(at),
            at: format_interval(at),
            by: event_actor(space, note_id),
            tags: note_tags(space, note_id),
            references: note_references(reader, space, note_id)?,
            supersedes: note_supersedes(space, note_id),
        })
    })
    .collect::<Result<_>>()?;
    if !notes.is_empty() {
        notes.sort_by(|a, b| (a.sort_key, a.id).cmp(&(b.sort_key, b.id)));
        writeln!(output)?;
        writeln!(output, "Notes:")?;
        for note in &notes {
            match note.by {
                Some(by) => writeln!(output, "- [{}] {} by {by:x}", fmt_id(note.id), note.at)?,
                None => writeln!(output, "- [{}] {}", fmt_id(note.id), note.at)?,
            }
            if note.text.is_empty() {
                writeln!(output, "  (empty)")?;
            } else {
                for line in note.text.lines() {
                    writeln!(output, "  {line}")?;
                }
            }
            if !note.tags.is_empty() {
                writeln!(
                    output,
                    "  tags: {}",
                    note.tags
                        .iter()
                        .map(|tag| format!("#{tag}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                )?;
            }
            if !note.references.is_empty() {
                writeln!(output, "  refs: {}", note.references.join(", "))?;
            }
            if !note.supersedes.is_empty() {
                writeln!(
                    output,
                    "  supersedes: {}",
                    note.supersedes
                        .iter()
                        .map(|id| fmt_id(*id))
                        .collect::<Vec<_>>()
                        .join(", ")
                )?;
            }
        }

        let mut all_refs = Vec::new();
        for note in &notes {
            all_refs.extend(extract_references(&note.text));
        }
        all_refs.sort();
        all_refs.dedup();
        if !all_refs.is_empty() {
            writeln!(output)?;
            writeln!(output, "References:")?;
            for (faculty, hex) in &all_refs {
                writeln!(output, "  ⇢ {faculty}:{hex}")?;
            }
        }
    }
    Ok(output)
}

fn cmd_show(storage: CompassStorage<'_>, id: String) -> Result<()> {
    let output = storage.with_view(|space, reader, status_register| {
        let task_id = resolve_task_id(&id, space)?;
        render_goal(reader, space, status_register, task_id)
    })?;
    print!("{output}");
    Ok(())
}

fn cmd_prioritize(
    storage: CompassStorage<'_>,
    higher_input: String,
    lower_input: String,
) -> Result<()> {
    let (higher_title, lower_title) = storage.update(
        None,
        |space, reader, _| {
            let higher_id = resolve_task_id(&higher_input, space)?;
            let lower_id = resolve_task_id(&lower_input, space)?;

            if higher_id == lower_id {
                bail!("cannot prioritize a goal over itself");
            }

            // Build full edge set (explicit + implicit child→parent)
            let edges = compass::goal_priority_edges(space);

            if compass::would_create_priority_cycle(&edges, higher_id, lower_id) {
                let paths = parent_paths(space)?;
                if is_ancestor(&paths, higher_id, lower_id)
                    || is_ancestor(&paths, lower_id, higher_id)
                {
                    bail!("children are implicitly prioritized over their parents");
                }
                bail!("would create a priority cycle");
            }

            Ok((
                higher_id,
                lower_id,
                task_title(reader, space, higher_id)?,
                task_title(reader, space, lower_id)?,
            ))
        },
        |(higher_id, lower_id, higher_title, lower_title)| {
            let mut change = compass::kind_catalog_fragment();
            change += compass::priority_fragment(higher_id, lower_id, true, clock::point_now()?);
            Ok((Some(change), (higher_title, lower_title)))
        },
    )?;
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
    let (higher_title, lower_title) = storage.update(
        None,
        |space, reader, _| {
            let higher_id = resolve_task_id(&higher_input, space)?;
            let lower_id = resolve_task_id(&lower_input, space)?;

            let edges = compass::active_priority_edges(space);
            if !edges.contains(&(higher_id, lower_id)) {
                bail!("no active priority relationship between these goals");
            }

            Ok((
                higher_id,
                lower_id,
                task_title(reader, space, higher_id)?,
                task_title(reader, space, lower_id)?,
            ))
        },
        |(higher_id, lower_id, higher_title, lower_title)| {
            let mut change = compass::kind_catalog_fragment();
            change += compass::priority_fragment(higher_id, lower_id, false, clock::point_now()?);
            Ok((Some(change), (higher_title, lower_title)))
        },
    )?;
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
    let id =
        storage.with_view(|space, _reader, _status_register| resolve_task_id(&prefix, space))?;
    println!("{id:x}");
    Ok(())
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
    use anybytes::Bytes;
    use ed25519_dalek::SigningKey;
    use faculties::storage::initialize_signer;
    use std::convert::Infallible;
    use std::future::{ready, Future};
    use std::sync::atomic::{AtomicU64, Ordering};
    use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace::core::blob::encodings::UnknownBlob;
    use triblespace::core::blob::MemoryBlobStoreSnapshot;
    use triblespace::core::repo::async_store::AsyncBlobStoreAcquire;
    use triblespace::core::repo::pile::ReadError;
    use triblespace::core::repo::MissingBlob;

    type BlobHandle = Inline<inlineencodings::Handle<UnknownBlob>>;

    /// A real resident-only pile with an exact-handle remote byte fixture.
    struct AcquiringPile {
        pile: Pile,
        remote: MemoryBlobStoreSnapshot,
        requested: Vec<BlobHandle>,
        arriving: Option<(Collection<SimpleArchive>, SigningKey, Fragment)>,
        _file: tempfile::NamedTempFile,
    }

    impl AcquiringPile {
        fn new(mut remote: MemoryBlobStore) -> Self {
            let file = tempfile::NamedTempFile::new().unwrap();
            Self {
                pile: Pile::open(file.path()).unwrap(),
                remote: remote.snapshot().unwrap(),
                requested: Vec::new(),
                arriving: None,
                _file: file,
            }
        }
    }

    impl SnapshotSource for AcquiringPile {
        type Snapshot = PileSnapshot;
        type SnapshotError = ReadError;

        fn snapshot_at(&mut self, instant: Epoch) -> Result<PileSnapshot, ReadError> {
            self.pile.snapshot_at(instant)
        }
    }

    impl AsyncBlobStoreAcquire for AcquiringPile {
        type AcquireError = Infallible;

        fn acquire(
            &mut self,
            handle: BlobHandle,
        ) -> impl Future<Output = Result<Option<Bytes>, Infallible>> + Send {
            let resident = self.pile.snapshot().unwrap();
            if resident.contains_blob(handle).unwrap() {
                return ready(Ok(Some(resident.get(handle).unwrap())));
            }
            self.requested.push(handle);
            if let Some((collection, signer, fragment)) = self.arriving.take() {
                self.pile.commit(collection, &signer, fragment).unwrap();
            }
            if !self.remote.contains_blob(handle).unwrap() {
                return ready(Ok(None));
            }
            let bytes: Bytes = self.remote.get(handle).unwrap();
            let cached: BlobHandle = self.pile.put(bytes.clone()).unwrap();
            assert_eq!(cached, handle);
            ready(Ok(Some(bytes)))
        }
    }

    fn sparse_view(
        mut fragment: Fragment,
    ) -> (
        AcquiringPile,
        compass::CompassSnapshot,
        Collection<SimpleArchive>,
        SigningKey,
    ) {
        let mut store = AcquiringPile::new(fragment.blobs().clone());
        fragment.blobs_mut().keep([]);
        let signer = SigningKey::from_bytes(&[7; 32]);
        let source = faculties::collection_names::open(
            &mut store.pile,
            COMPASS_SCOPE_ID,
            signer.verifying_key(),
        )
        .unwrap();
        store.pile.commit(source, &signer, fragment).unwrap();
        let view = pollster::block_on(compass::materialize_indexed_collection(
            &mut store.pile,
            &signer,
        ))
        .unwrap();
        (store, view, source, signer)
    }

    #[test]
    fn configured_descriptor_read_acquires_descriptor_and_name_only() {
        let mut remote = MemoryRepo::default();
        let signer = SigningKey::from_bytes(&[8; 32]);
        let source = faculties::collection_names::open(
            &mut remote,
            COMPASS_SCOPE_ID,
            signer.verifying_key(),
        )
        .unwrap();
        let descriptor: TribleSet = remote.snapshot().unwrap().get(source.handle()).unwrap();
        let name = triblespace::core::collection::descriptor::name(&descriptor)
            .unwrap()
            .unwrap();
        let mut store = AcquiringPile::new(remote.blobs);
        let before = store.snapshot().unwrap();

        let opened = pollster::block_on(storage::read(&mut store, &before, |reader| {
            open_exact_in(reader, COMPASS_SCOPE_ID, source.handle())
        }))
        .unwrap();

        assert_eq!(opened, source);
        assert_eq!(
            store.requested,
            vec![source.handle().transmute(), name.transmute()]
        );
        assert!(!before.contains_blob(source.handle()).unwrap());
        assert_eq!(store.snapshot().unwrap().wants().unwrap().count(), 0);
    }

    #[test]
    fn missing_title_and_reference_keep_the_typed_missing_blob_error() {
        let at: IntervalValue = (Epoch::from_tai_seconds(0.0), Epoch::from_tai_seconds(0.0))
            .try_to_inline()
            .unwrap();
        let (mut fragment, goal) =
            compass::goal_fragment("selected goal", vec![], None, at).unwrap();
        let (note, note_id) = compass::note_fragment(
            goal,
            "selected note",
            vec![],
            vec!["git:DEADBEEF".to_owned()],
            vec![],
            None,
            at,
        )
        .unwrap();
        fragment += note;
        let title = find!(handle: TextHandle, pattern!(fragment.facts(), [{ goal @ board::title: ?handle }]))
            .next().unwrap();
        let reference = find!(handle: TextHandle, pattern!(fragment.facts(), [{ note_id @ board::reference: ?handle }]))
            .next().unwrap();
        let (_, view, _, _) = sparse_view(fragment);

        let missing_title = task_title(view.store_snapshot(), view.facts(), goal).unwrap_err();
        let missing_reference =
            note_references(view.store_snapshot(), view.facts(), note_id).unwrap_err();
        for (error, expected) in [(missing_title, title), (missing_reference, reference)] {
            assert_eq!(
                error
                    .chain()
                    .find_map(|source| source.downcast_ref::<MissingBlob>())
                    .unwrap()
                    .handle,
                expected.transmute()
            );
        }
        // An absent title fact retains its existing open-world meaning.
        assert_eq!(
            task_title(view.store_snapshot(), &TribleSet::new(), goal).unwrap(),
            ""
        );
    }

    #[test]
    fn board_fetches_only_titles_surviving_status_and_tag_filters() {
        let at: IntervalValue = (Epoch::from_tai_seconds(0.0), Epoch::from_tai_seconds(0.0))
            .try_to_inline()
            .unwrap();
        let (mut fragment, selected) =
            compass::goal_fragment("selected goal", vec!["shown".to_owned()], None, at).unwrap();
        fragment += compass::status_fragment(selected, "doing", None, at).unwrap();
        let (hidden, _) =
            compass::goal_fragment("other tag goal", vec!["other".to_owned()], None, at).unwrap();
        fragment += hidden;
        let (done, done_id) =
            compass::goal_fragment("done goal", vec!["shown".to_owned()], None, at).unwrap();
        fragment += done;
        fragment += compass::status_fragment(done_id, "done", None, at).unwrap();
        fragment += compass::note_fragment(
            selected,
            "note not needed by list",
            vec![],
            vec!["git:DEADBEEF".to_owned()],
            vec![],
            None,
            at,
        )
        .unwrap()
        .0;
        let title = find!(handle: TextHandle, pattern!(fragment.facts(), [{ selected @ board::title: ?handle }]))
            .next().unwrap();
        let (mut store, view, _, _) = sparse_view(fragment);

        let output =
            pollster::block_on(storage::read(&mut store, view.store_snapshot(), |reader| {
                render_board(
                    reader,
                    view.facts(),
                    view.status_register(),
                    &[],
                    &["shown".to_owned()],
                    false,
                )
            }))
            .unwrap();

        assert!(output.contains("selected goal"));
        assert!(output.contains("DOING (1)"));
        assert!(!output.contains("other tag goal"));
        assert!(!output.contains("done goal"));
        assert_eq!(store.requested, vec![title.transmute()]);
        assert!(!view.store_snapshot().contains_blob(title).unwrap());
        assert_eq!(store.snapshot().unwrap().wants().unwrap().count(), 0);
    }

    #[test]
    fn show_fetches_selected_goal_parent_note_and_reference_only() {
        let at: IntervalValue = (Epoch::from_tai_seconds(0.0), Epoch::from_tai_seconds(0.0))
            .try_to_inline()
            .unwrap();
        let (mut fragment, parent) =
            compass::goal_fragment("parent goal", vec![], None, at).unwrap();
        let (child, goal) =
            compass::goal_fragment("selected goal", vec![], Some(parent), at).unwrap();
        fragment += child;
        let (note, note_id) = compass::note_fragment(
            goal,
            "selected note",
            vec!["review".to_owned()],
            vec!["git:DEADBEEF".to_owned()],
            vec![],
            None,
            at,
        )
        .unwrap();
        fragment += note;
        let (unrelated, unrelated_goal) =
            compass::goal_fragment("unrelated goal", vec![], None, at).unwrap();
        fragment += unrelated;
        fragment += compass::note_fragment(
            unrelated_goal,
            "unrelated note",
            vec![],
            vec![],
            vec![],
            None,
            at,
        )
        .unwrap()
        .0;
        let mut expected: Vec<BlobHandle> = find!(handle: TextHandle,
            pattern!(fragment.facts(), [{ goal @ board::title: ?handle }]))
        .map(|handle| handle.transmute())
        .collect();
        expected.extend(
            find!(handle: TextHandle,
            pattern!(fragment.facts(), [{ parent @ board::title: ?handle }]))
            .map(|handle| handle.transmute()),
        );
        expected.extend(
            find!(handle: TextHandle,
            pattern!(fragment.facts(), [{ note_id @ board::note: ?handle }]))
            .map(|handle| handle.transmute()),
        );
        expected.extend(
            find!(handle: TextHandle,
            pattern!(fragment.facts(), [{ note_id @ board::reference: ?handle }]))
            .map(|handle| handle.transmute()),
        );
        let (mut store, view, _, _) = sparse_view(fragment);

        let output =
            pollster::block_on(storage::read(&mut store, view.store_snapshot(), |reader| {
                render_goal(reader, view.facts(), view.status_register(), goal)
            }))
            .unwrap();

        assert!(output.contains("Title: selected goal"));
        assert!(output.contains("Parent: parent goal"));
        assert!(output.contains("selected note"));
        assert!(output.contains("refs: git:DEADBEEF"));
        assert!(!output.contains("unrelated"));
        assert_eq!(store.requested, expected);
        assert_eq!(store.snapshot().unwrap().wants().unwrap().count(), 0);
    }

    #[test]
    fn unavailable_note_or_reference_fails_the_whole_prepared_show() {
        let at: IntervalValue = (Epoch::from_tai_seconds(0.0), Epoch::from_tai_seconds(0.0))
            .try_to_inline()
            .unwrap();
        let (mut fragment, goal) =
            compass::goal_fragment("selected goal", vec![], None, at).unwrap();
        let (note, note_id) = compass::note_fragment(
            goal,
            "selected note",
            vec![],
            vec!["git:DEADBEEF".to_owned()],
            vec![],
            None,
            at,
        )
        .unwrap();
        fragment += note;
        let title = find!(handle: TextHandle, pattern!(fragment.facts(), [{ goal @ board::title: ?handle }]))
            .next().unwrap();
        let body = find!(handle: TextHandle, pattern!(fragment.facts(), [{ note_id @ board::note: ?handle }]))
            .next().unwrap();
        let reference = find!(handle: TextHandle, pattern!(fragment.facts(), [{ note_id @ board::reference: ?handle }]))
            .next().unwrap();

        for missing in [body, reference] {
            let (mut store, view, _, _) = sparse_view(fragment.clone());
            let mut remote = fragment.blobs().clone();
            remote.keep(
                [title, body, reference]
                    .into_iter()
                    .filter(|handle| *handle != missing)
                    .map(|handle| handle.transmute()),
            );
            store.remote = remote.snapshot().unwrap();
            let error =
                pollster::block_on(storage::read(&mut store, view.store_snapshot(), |reader| {
                    render_goal(reader, view.facts(), view.status_register(), goal)
                }))
                .unwrap_err();
            assert_eq!(
                error
                    .chain()
                    .find_map(|source| source.downcast_ref::<MissingBlob>())
                    .unwrap()
                    .handle,
                missing.transmute()
            );
            assert_eq!(store.requested.last(), Some(&missing.transmute()));
        }
    }

    #[test]
    fn render_retry_keeps_frozen_facts_status_support_and_instant() {
        let at: IntervalValue = (Epoch::from_tai_seconds(0.0), Epoch::from_tai_seconds(0.0))
            .try_to_inline()
            .unwrap();
        let later: IntervalValue = (Epoch::from_tai_seconds(1.0), Epoch::from_tai_seconds(1.0))
            .try_to_inline()
            .unwrap();
        let (mut fragment, goal) =
            compass::goal_fragment("original goal", vec![], None, at).unwrap();
        fragment += compass::status_fragment(goal, "todo", None, at).unwrap();
        let (mut store, view, source, signer) = sparse_view(fragment);
        let original_support = source.admitted(view.store_snapshot()).unwrap();
        let (mut arrival, arrived_goal) =
            compass::goal_fragment("later goal", vec![], None, later).unwrap();
        arrival += compass::status_fragment(goal, "done", None, later).unwrap();
        store.arriving = Some((source, signer, arrival));

        let output =
            pollster::block_on(storage::read(&mut store, view.store_snapshot(), |reader| {
                assert_eq!(reader.instant(), view.store_snapshot().instant());
                render_board(
                    reader,
                    view.facts(),
                    view.status_register(),
                    &[],
                    &[],
                    false,
                )
            }))
            .unwrap();

        assert!(output.contains("original goal"));
        assert!(output.contains("TODO (1)"));
        assert!(!output.contains("later goal"));
        assert!(!compass::goal_ids(view.facts()).contains(&arrived_goal));
        assert_eq!(
            source.admitted(view.store_snapshot()).unwrap(),
            original_support
        );
        assert_eq!(original_support.len(), 1);
        assert_eq!(store.requested.len(), 1);
        let after = store.snapshot().unwrap();
        assert_eq!(source.admitted(&after).unwrap().len(), 2);
        assert_eq!(after.wants().unwrap().count(), 0);
    }

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
            .with_view(|facts, _, _| Ok(*compass::goal_ids(facts).iter().next().unwrap()))
            .unwrap();

        // Compass preserves unrelated open-world facts. Multiple values on
        // the order attribute alone do not form a status coordinate and must
        // not make the maintained register reject the exact cover.
        let unrelated = ufoid();
        let first: IntervalValue = {
            let value = Epoch::from_unix_seconds(1.0);
            (value, value).try_to_inline().unwrap()
        };
        let second: IntervalValue = {
            let value = Epoch::from_unix_seconds(2.0);
            (value, value).try_to_inline().unwrap()
        };
        let mut fragment = entity! { &unrelated @ metadata::created_at: first };
        fragment += entity! { &unrelated @ metadata::created_at: second };
        storage
            .with_pile(|pile, signer, _runtime| {
                compass::commit_collection(pile, signer, fragment)?;
                Ok(())
            })
            .unwrap();
        storage
            .with_view(|facts, _, status_register| {
                assert_eq!(
                    latest_status_event(facts, status_register, goal)
                        .map(|(_, value, _)| value)
                        .as_deref(),
                    Some("todo")
                );
                Ok(())
            })
            .unwrap();

        let before = std::fs::metadata(&pile).unwrap().len();
        cmd_list(storage, vec![], vec![], true).unwrap();
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), before);

        cmd_move(storage, format!("{goal:x}"), "doing".to_owned(), None).unwrap();
        storage
            .with_view(|facts, _, status_register| {
                assert_eq!(
                    latest_status_event(facts, status_register, goal)
                        .map(|(_, value, _)| value)
                        .as_deref(),
                    Some("doing")
                );
                Ok(())
            })
            .unwrap();
    }
}
