use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use faculties::schemas::compass::{
    active_attestation_ids_for_reviewer, active_request_ids_for_goal,
    all_attestation_ids_for_reviewer, all_request_ids_for_goal, board, evaluate_goal,
    evaluate_request_live, latest_status_event, review, review_attestation_fragment,
    review_attestation_settlement_fragment, review_override_fragment,
    review_override_settlement_fragment, review_request, review_request_fragment,
    review_roster_successor_fragment, ReviewEvaluation, ReviewGateState, ReviewProjection,
    SettlementMode, DEFAULT_STATUSES, KIND_DEPRIORITIZE_ID, KIND_GOAL_ID, KIND_NOTE_ID,
    KIND_PRIORITIZE_ID, KIND_REVIEW_REQUEST_ID, KIND_SPECS, KIND_STATUS_ID, REVIEW_STATUS,
    VERDICT_ABSTAIN, VERDICT_APPROVE, VERDICT_REQUEST_CHANGES,
};
use faculties::schemas::relations::{
    active_person_ids, head_members, head_snapshot_of, person_ids, relations as rel_attrs,
    KIND_GROUP, KIND_PERSON_ID,
};
use faculties::schemas::orient::{orient_state, KIND_REVIEW_WATERMARK_ID};
use hifitime::Epoch;
use rand_core::OsRng;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use triblespace::core::metadata;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::prelude::*;

type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, name = "compass", about = "A small TribleSpace kanban faculty")]
struct Cli {
    /// Path to the pile file to use
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Branch name for the board
    #[arg(long, default_value = "compass")]
    branch: String,
    /// Branch id for the board (hex). Overrides config.
    #[arg(long)]
    branch_id: Option<String>,
    /// Acting persona (relations label or 32-char hex id). When set,
    /// status events record who made them — the audit trail gains the
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
    /// Open, attest, inspect, and settle an exact review candidate.
    Review {
        #[command(subcommand)]
        command: ReviewCommand,
    },
}

#[derive(Subcommand)]
enum ReviewCommand {
    /// Bind a goal to one immutable target and atomically enter review.
    Open {
        /// Goal id or unique prefix.
        goal: String,
        /// Immutable artifact revision IRI (for example git+https://...@<full-oid>).
        #[arg(long)]
        target: String,
        /// Accept an opaque IRI whose immutability Compass cannot verify.
        /// The normal path only accepts validated content-addressed schemes.
        #[arg(long)]
        unsafe_opaque_target: bool,
        /// Relations group whose active members are frozen as the roster.
        /// It must include the author and at least one distinct reviewer.
        #[arg(long, default_value = "review-triad")]
        review_group: String,
        /// Optional independent person allowed to record a reasoned break-glass settlement.
        #[arg(long)]
        override_authority: Vec<String>,
    },
    /// Replace one current request's roster without changing its exact candidate.
    Supersede {
        /// Exact request id or unique prefix (not a goal id).
        request: String,
        /// Relations group whose active members become the successor's frozen roster.
        #[arg(long)]
        review_group: String,
    },
    /// Submit or replace this persona's attestation for one exact request.
    Submit {
        /// Exact request id or unique prefix (not a goal id).
        request: String,
        #[arg(value_enum)]
        verdict: VerdictArg,
        /// Review report. Use @path for file input or @- for stdin.
        #[arg(long)]
        report: String,
    },
    /// Acknowledge an exact request: stop your watcher waking on it until its
    /// state (your attestation head-set) changes, or a new request supersedes it.
    Ack {
        /// Exact request id or unique prefix (not a goal id).
        request: String,
    },
    /// Snooze an exact request: acknowledge it AND set a deadline that
    /// deliberately re-surfaces it (e.g. `--for 2h`, `--for 30m`, `--for 1d`).
    Snooze {
        /// Exact request id or unique prefix (not a goal id).
        request: String,
        /// Re-enqueue after this long (e.g. 90m, 2h, 1d).
        #[arg(long = "for")]
        duration: String,
    },
    /// Show the settlement projection for a goal or exact request.
    Status {
        id: String,
        /// Include every historical request for the goal.
        #[arg(long)]
        history: bool,
    },
    /// Exit successfully only when this exact active request may settle.
    Gate { request: String },
    /// Record the exact attestation proof and atomically move the goal to done.
    Settle { request: String },
    /// Record a reasoned break-glass proof and atomically move the goal to done.
    Override {
        request: String,
        /// Non-empty reason. Use @path for file input or @- for stdin.
        #[arg(long)]
        reason: String,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum VerdictArg {
    Approve,
    RequestChanges,
    Abstain,
}

impl VerdictArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Approve => VERDICT_APPROVE,
            Self::RequestChanges => VERDICT_REQUEST_CHANGES,
            Self::Abstain => VERDICT_ABSTAIN,
        }
    }
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
        let end = after.find(')').unwrap_or(after.len());
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
        rest = &after[end.min(after.len()).max(1)..];
    }
    refs.sort();
    refs.dedup();
    refs
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

fn open_repo(path: &Path) -> Result<Repository<Pile>> {
    let mut pile =
        Pile::open(path).map_err(|e| anyhow::anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.refresh() {
        // Avoid Drop warnings on early errors.
        let _ = pile.close();
        return Err(match err {
            triblespace::core::repo::pile::ReadError::CorruptPile { valid_length } => anyhow::anyhow!(
                "pile corrupt at byte {valid_length}: refusing to auto-repair (a stale binary \
                 could truncate newer data). If, and only if, the tail is a genuinely torn write, truncate it explicitly (DESTRUCTIVE) with: trible pile amputate {}",
                path.display()
            ),
            other => anyhow::anyhow!("refresh pile {}: {other:?}", path.display()),
        });
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|err| anyhow::anyhow!("create repository: {err:?}"))
}

fn with_repo<T>(pile: &Path, f: impl FnOnce(&mut Repository<Pile>) -> Result<T>) -> Result<T> {
    let mut repo = open_repo(pile)?;
    let result = f(&mut repo);
    let close_res = repo
        .close()
        .map_err(|e| anyhow::anyhow!("close pile: {e:?}"));
    if let Err(err) = close_res {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }
    result
}

fn task_title(ws: &mut Workspace<Pile>, space: &TribleSet, task_id: Id) -> String {
    find!(h: TextHandle, pattern!(space, [{ task_id @ board::title: ?h }]))
        .next()
        .and_then(|h| read_text(ws, h).ok())
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

fn read_text(ws: &mut Workspace<Pile>, handle: TextHandle) -> Result<String> {
    let view: View<str> = ws
        .get::<View<str>, blobencodings::LongString>(handle)
        .map_err(|e| anyhow::anyhow!("load longstring: {e:?}"))?;
    Ok(view.to_string())
}

/// Parse a full 32-char hex ID. Returns a helpful error pointing to `compass resolve` on failure.
fn resolve_task_id(input: &str, space: &TribleSet) -> Result<Id> {
    faculties::resolve_id_prefix(input, all_goal_ids(space))
}

/// Compute active priority edges from the space.
fn active_priority_edges(space: &TribleSet) -> HashSet<(Id, Id)> {
    let mut latest: HashMap<(Id, Id), (i128, bool)> = HashMap::new();
    for (higher, lower, at) in find!(
        (higher: Id, lower: Id, at: IntervalValue),
        pattern!(space, [{
            _?evt @
            metadata::tag: &KIND_PRIORITIZE_ID,
            board::higher: ?higher,
            board::lower: ?lower,
            metadata::created_at: ?at,
        }])
    ) {
        let key = interval_key(at);
        latest
            .entry((higher, lower))
            .and_modify(|(cur_key, cur_active)| {
                if key > *cur_key {
                    *cur_key = key;
                    *cur_active = true;
                }
            })
            .or_insert((key, true));
    }
    for (higher, lower, at) in find!(
        (higher: Id, lower: Id, at: IntervalValue),
        pattern!(space, [{
            _?evt @
            metadata::tag: &KIND_DEPRIORITIZE_ID,
            board::higher: ?higher,
            board::lower: ?lower,
            metadata::created_at: ?at,
        }])
    ) {
        let key = interval_key(at);
        latest
            .entry((higher, lower))
            .and_modify(|(cur_key, cur_active)| {
                if key > *cur_key {
                    *cur_key = key;
                    *cur_active = false;
                }
            })
            .or_insert((key, false));
    }
    latest
        .into_iter()
        .filter(|(_, (_, active))| *active)
        .map(|(k, _)| k)
        .collect()
}

/// Check if `to` is an ancestor of `from` (or `from` itself) in the parent tree.
fn is_ancestor(space: &TribleSet, from: Id, to: Id) -> bool {
    from == to
        || exists!(
            (_start: Id, _end: Id),
            and!(
                _start.is(from.to_inline()),
                _end.is(to.to_inline()),
                path!(space, _start board::parent+ _end)
            )
        )
}

/// Count notes for a task.
fn note_count(space: &TribleSet, task_id: Id) -> usize {
    find!(
        _n: TextHandle,
        pattern!(space, [{ _?evt @ metadata::tag: &KIND_NOTE_ID, board::task: &task_id, board::note: ?_n }])
    ).count()
}

/// Check if adding (higher, lower) would create a cycle in the priority DAG.
fn would_create_cycle(edges: &HashSet<(Id, Id)>, higher: Id, lower: Id) -> bool {
    let mut visited = HashSet::new();
    let mut queue = vec![lower];
    while let Some(node) = queue.pop() {
        if node == higher {
            return true;
        }
        if !visited.insert(node) {
            continue;
        }
        for &(h, l) in edges {
            if h == node && !visited.contains(&l) {
                queue.push(l);
            }
        }
    }
    false
}

/// Topological rank of tasks by priority edges (lower rank = more important).
fn priority_ranks(task_ids: &[Id], edges: &HashSet<(Id, Id)>) -> HashMap<Id, usize> {
    let id_set: HashSet<Id> = task_ids.iter().copied().collect();
    let mut adj: HashMap<Id, Vec<Id>> = HashMap::new();
    let mut in_degree: HashMap<Id, usize> = HashMap::new();
    for &id in task_ids {
        in_degree.entry(id).or_insert(0);
    }
    for &(h, l) in edges {
        if id_set.contains(&h) && id_set.contains(&l) {
            adj.entry(h).or_default().push(l);
            *in_degree.entry(l).or_insert(0) += 1;
        }
    }
    let mut queue: Vec<Id> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(&id, _)| id)
        .collect();
    queue.sort_by(|a, b| a.cmp(b));
    let mut ranks = HashMap::new();
    let mut rank = 0;
    while let Some(node) = queue.pop() {
        ranks.insert(node, rank);
        rank += 1;
        if let Some(neighbors) = adj.get(&node) {
            for &next in neighbors {
                if let Some(deg) = in_degree.get_mut(&next) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push(next);
                        queue.sort_by(|a, b| a.cmp(b));
                    }
                }
            }
        }
    }
    for &id in task_ids {
        ranks.entry(id).or_insert(rank);
    }
    ranks
}

fn render_board(
    ws: &mut Workspace<Pile>,
    space: &TribleSet,
    status_filter: &[String],
    tag_filter: &[String],
    show_done: bool,
) {
    let goal_ids = all_goal_ids(space);
    let mut priority_edges = active_priority_edges(space);
    // Implicit: children must be done before parents → child > parent
    for &id in &goal_ids {
        if let Some(parent) = task_parent(space, id) {
            priority_edges.insert((id, parent));
        }
    }

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

        let title = task_title(ws, space, task_id);
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
        let ordered = order_rows(rows, &priority_edges);
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

fn order_rows(rows: Vec<TaskRow>, priority_edges: &HashSet<(Id, Id)>) -> Vec<(TaskRow, usize)> {
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

    let all_ids: Vec<Id> = by_id.keys().copied().collect();
    let ranks = priority_ranks(&all_ids, priority_edges);

    let sort_ids = |items: &mut Vec<Id>| {
        items.sort_by(|a, b| {
            let a_rank = ranks.get(a).copied().unwrap_or(usize::MAX);
            let b_rank = ranks.get(b).copied().unwrap_or(usize::MAX);
            match a_rank.cmp(&b_rank) {
                std::cmp::Ordering::Equal => {
                    // Fall back to timestamp (most recent first)
                    let a_key = by_id.get(a).map(|row| row.sort_key).unwrap_or(0);
                    let b_key = by_id.get(b).map(|row| row.sort_key).unwrap_or(0);
                    b_key.cmp(&a_key)
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

fn ensure_kind_entities(ws: &mut Workspace<Pile>) -> Result<TribleSet> {
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow::anyhow!("checkout board: {e:?}"))?;
    let existing: HashSet<Id> = find!(
        (kind: Id),
        pattern!(&space, [{ ?kind @ metadata::name: _?handle }])
    )
    .map(|(kind,)| kind)
    .collect();

    let mut change = TribleSet::new();
    for (id, label) in KIND_SPECS {
        if existing.contains(&id) {
            continue;
        }
        let name_handle = label.to_owned().to_blob().get_handle();
        change += entity! { ExclusiveId::force_ref(&id) @ metadata::name: name_handle };
    }
    Ok(change)
}

fn relations_workspace(repo: &mut Repository<Pile>) -> Result<Workspace<Pile>> {
    let relations_branch_id = repo
        .ensure_branch("relations", None)
        .map_err(|e| anyhow::anyhow!("ensure relations branch: {e:?}"))?;
    repo.pull(relations_branch_id)
        .map_err(|e| anyhow::anyhow!("pull relations workspace: {e:?}"))
}

/// Resolve a relations person inside an explicit eligibility set. Review
/// identity is cooperative (the persona flag is still a claim), but it may
/// not be an arbitrary Id.
fn resolve_person_in(
    space: &TribleSet,
    eligible_people: &HashSet<Id>,
    input: &str,
    eligibility: &str,
) -> Result<Id> {
    let trimmed = input.trim();
    if let Some(id) = Id::from_hex(trimmed) {
        if eligible_people.contains(&id) {
            return Ok(id);
        }
        bail!("persona '{trimmed}' is not {eligibility}");
    }
    let key = trimmed.to_ascii_lowercase();
    let matches: Vec<Id> = find!(
        person_id: Id,
        pattern!(space, [{ ?person_id @ metadata::tag: &KIND_PERSON_ID }])
    )
    .filter(|&person_id| {
        eligible_people.contains(&person_id)
            && (exists!(pattern!(space, [{ person_id @ rel_attrs::label_norm: key.as_str() }]))
                || exists!(pattern!(space, [{ person_id @ rel_attrs::alias_norm: key.as_str() }])))
    })
    .collect();
    match matches.len() {
        0 => bail!("unknown persona label '{trimmed}' ({eligibility}; try the hex id)"),
        1 => Ok(matches[0]),
        _ => bail!("multiple relations entries match persona label '{trimmed}'"),
    }
}

/// Strictly resolve a live relations person for a new action or assignment.
fn resolve_active_person(
    space: &TribleSet,
    active_people: &HashSet<Id>,
    input: &str,
) -> Result<Id> {
    resolve_person_in(space, active_people, input, "an active relations person")
}

/// Resolve an existing relations person, including a soft-retired identity.
/// A review request freezes its actors, so retirement removes future roster
/// eligibility without revoking an already-assigned submit/settle/override
/// role or rewriting historical proof.
fn resolve_frozen_person(
    space: &TribleSet,
    known_people: &HashSet<Id>,
    input: &str,
) -> Result<Id> {
    resolve_person_in(space, known_people, input, "a relations person")
}

/// Resolve the acting persona (relations label or 32-char hex id).
fn resolve_persona_id(repo: &mut Repository<Pile>, input: &str) -> Result<Id> {
    let mut ws = relations_workspace(repo)?;
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow::anyhow!("checkout relations: {e:?}"))?;
    let active = active_person_ids(&space);
    resolve_active_person(&space, &active, input)
}

fn resolve_group_id(space: &TribleSet, input: &str) -> Result<Id> {
    let trimmed = input.trim();
    if let Some(id) = Id::from_hex(trimmed) {
        if exists!(pattern!(space, [{ id @ metadata::tag: &KIND_GROUP }])) {
            return Ok(id);
        }
        bail!("'{trimmed}' is not a relations group");
    }
    let key = trimmed.to_ascii_lowercase();
    // Name resolves through the head snapshot (a rename supersedes the old name).
    let mut matches: Vec<Id> = find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: &KIND_GROUP }]))
        .filter(|&id| {
            head_snapshot_of(space, id).is_some_and(|head| {
                exists!(pattern!(space, [{ head @ rel_attrs::label_norm: key.as_str() }]))
            })
        })
        .collect();
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [] => bail!("unknown relations group '{trimmed}'"),
        [id] => Ok(*id),
        _ => bail!("multiple relations groups match '{trimmed}'"),
    }
}

fn validate_frozen_review_roster(
    required: &[Id],
    author: Id,
    active_people: &HashSet<Id>,
) -> Result<()> {
    if !required.contains(&author) {
        bail!("review roster must include the author persona {author:x}");
    }
    if !required.iter().any(|reviewer| *reviewer != author) {
        bail!("review roster must include at least one distinct non-author reviewer");
    }
    if required.iter().any(|id| !active_people.contains(id)) {
        bail!("review group contains inactive or non-person members");
    }
    Ok(())
}

fn resolve_request_id(input: &str, space: &TribleSet) -> Result<Id> {
    let ids: Vec<Id> = find!(
        id: Id,
        pattern!(space, [{ ?id @ metadata::tag: &KIND_REVIEW_REQUEST_ID }])
    )
    .collect();
    faculties::resolve_id_prefix(input, ids)
}

fn person_label(ws: &mut Workspace<Pile>, space: &TribleSet, id: Id) -> String {
    find!(h: TextHandle, pattern!(space, [{ id @ metadata::name: ?h }]))
        .next()
        .and_then(|handle| read_text(ws, handle).ok())
        .unwrap_or_else(|| fmt_id(id))
}

fn request_target(
    ws: &mut Workspace<Pile>,
    request: &faculties::schemas::compass::ReviewRequest,
) -> String {
    request
        .target()
        .and_then(|handle| read_text(ws, handle).ok())
        .unwrap_or_else(|| "<malformed target>".to_string())
}

fn request_is_active(space: &TribleSet, request_id: Id) -> bool {
    review_request(space, request_id)
        .and_then(|request| request.goal())
        .is_some_and(|goal| active_request_ids_for_goal(space, goal).as_slice() == [request_id])
}

fn cmd_add(
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    title: String,
    status: String,
    parent: Option<String>,
    tags: Vec<String>,
    note: Option<String>,
    persona: Option<&str>,
) -> Result<()> {
    let status = normalize_status(status);
    if status == REVIEW_STATUS {
        bail!("review is a bound workflow state; use `compass review open <goal> --target ...`");
    }
    let tags: Vec<String> = tags.into_iter().map(|t| t.trim().to_string()).collect();
    validate_short("status", &status)?;
    for tag in &tags {
        validate_short("tag", tag)?;
    }

    let task_ref = with_repo(pile, |repo| {
        let by_id = persona.map(|p| resolve_persona_id(repo, p)).transpose()?;
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let parent_id = match parent.as_deref() {
            Some(p) => {
                let space = ws
                    .checkout(..)
                    .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
                Some(resolve_task_id(p, &space)?)
            }
            None => None,
        };
        let task_id = ufoid();
        let task_ref = task_id.id;
        let now = epoch_interval(now_epoch());
        let title_handle = ws.put(title);

        let mut change = TribleSet::new();
        change += ensure_kind_entities(&mut ws)?;
        change += entity! { &task_id @
            metadata::tag: &KIND_GOAL_ID,
            board::title: title_handle,
            metadata::created_at: now,
            board::parent?: parent_id.as_ref(),
            board::tag*: tags.iter().map(|tag| tag.as_str()),
        };

        let status_id = ufoid();
        change += entity! { &status_id @
            metadata::tag: &KIND_STATUS_ID,
            board::task: &task_ref,
            board::status: status.as_str(),
            board::by?: by_id.as_ref(),
            metadata::created_at: now,
        };

        if let Some(note) = note {
            let note_id = ufoid();
            change += entity! { &note_id @
                metadata::tag: &KIND_NOTE_ID,
                board::task: &task_ref,
                board::note: ws.put(note),
                metadata::created_at: now,
            };
        }

        ws.commit(change, "add goal");
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push goal: {e:?}"))?;
        Ok(task_ref)
    })?;
    println!("Added goal {:x}", task_ref);
    Ok(())
}

fn cmd_list(
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    status_filter: Vec<String>,
    tag_filter: Vec<String>,
    show_done: bool,
) -> Result<()> {
    let status_filter: Vec<String> = status_filter.into_iter().map(normalize_status).collect();
    for status in &status_filter {
        validate_short("status", status)?;
    }

    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        render_board(&mut ws, &space, &status_filter, &tag_filter, show_done);
        Ok(())
    })
}

fn cmd_move(
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    id: String,
    status: String,
    persona: Option<&str>,
) -> Result<()> {
    let status = normalize_status(status);
    validate_short("status", &status)?;
    if status == REVIEW_STATUS {
        bail!("review requires an exact candidate; use `compass review open <goal> --target ...`");
    }

    let resolved = with_repo(pile, |repo| {
        let by_id = persona.map(|p| resolve_persona_id(repo, p)).transpose()?;
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        loop {
            let space = ws
                .checkout(..)
                .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
            let task_id = resolve_task_id(&id, &space)?;
            if !all_request_ids_for_goal(&space, task_id).is_empty() {
                bail!(
                    "goal {:x} is in the structured review lifecycle; raw status moves would detach its exact proof. Open a successor candidate with `compass review open`, settle/override the active request, or create a new goal after settlement",
                    task_id
                );
            }
            let now = epoch_interval(now_epoch());

            let status_id = ufoid();
            let mut change = TribleSet::new();
            change += ensure_kind_entities(&mut ws)?;
            change += entity! { &status_id @
                metadata::tag: &KIND_STATUS_ID,
                board::task: &task_id,
                board::status: status.as_str(),
                board::by?: by_id.as_ref(),
                metadata::created_at: now,
            };

            ws.commit(change, "move goal");
            match repo
                .try_push(&mut ws)
                .map_err(|e| anyhow::anyhow!("push status: {e:?}"))?
            {
                None => return Ok(task_id),
                Some(conflict) => ws = conflict,
            }
        }
    })?;
    println!("Moved goal {:x} to {}", resolved, status);
    Ok(())
}

fn cmd_note(
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    id: String,
    note: String,
) -> Result<()> {
    let task_id = with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let task_id = resolve_task_id(&id, &space)?;
        let now = epoch_interval(now_epoch());

        let note_id = ufoid();
        let mut change = TribleSet::new();
        change += ensure_kind_entities(&mut ws)?;
        change += entity! { &note_id @
            metadata::tag: &KIND_NOTE_ID,
            board::task: &task_id,
            board::note: ws.put(note),
            metadata::created_at: now,
        };

        ws.commit(change, "add goal note");
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push note: {e:?}"))?;
        Ok(task_id)
    })?;
    println!("Noted goal {:x}", task_id);
    Ok(())
}

fn cmd_show(pile: &Path, _branch_name: &str, branch_id: Id, id: String) -> Result<()> {
    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let task_id = resolve_task_id(&id, &space)?;

        let title = task_title(&mut ws, &space, task_id);
        if title.is_empty() {
            bail!("goal missing");
        }

        println!("Goal {:x}", task_id);
        println!("Title: {}", title);
        if let Some(created) = task_created_at(&space, task_id) {
            println!("Created: {}", format_interval(created));
        }

        if let Some((status, at)) = task_latest_status(&space, task_id) {
            println!("Status: {} (since {})", status, format_interval(at));
        }

        let tags = task_tags(&space, task_id);
        if !tags.is_empty() {
            println!("Tags: {}", tags.join(", "));
        }

        if let Some(parent_id) = task_parent(&space, task_id) {
            let parent_hex = fmt_id(parent_id);
            let parent_title = task_title(&mut ws, &space, parent_id);
            if parent_title.is_empty() {
                println!("Parent: {parent_hex}");
            } else {
                println!("Parent: {parent_title} ({parent_hex})");
            }
        }

        // Status history for this task.
        let mut history: Vec<(String, i128, String)> = find!(
            (status: String, at: IntervalValue),
            pattern!(&space, [{
                _?evt @
                metadata::tag: &KIND_STATUS_ID,
                board::task: &task_id,
                board::status: ?status,
                metadata::created_at: ?at,
            }])
        )
        .map(|(status, at)| (status, interval_key(at), format_interval(at)))
        .collect();
        if !history.is_empty() {
            history.sort_by(|a, b| a.1.cmp(&b.1));
            println!();
            println!("Status history:");
            for (status, _, at_str) in &history {
                println!("- {at_str} {status}");
            }
        }

        // Notes for this task.
        let mut notes: Vec<(String, i128, String)> = find!(
            (note_handle: TextHandle, at: IntervalValue),
            pattern!(&space, [{
                _?evt @
                metadata::tag: &KIND_NOTE_ID,
                board::task: &task_id,
                board::note: ?note_handle,
                metadata::created_at: ?at,
            }])
        )
        .filter_map(|(h, at)| {
            read_text(&mut ws, h)
                .ok()
                .map(|text| (text, interval_key(at), format_interval(at)))
        })
        .collect();
        if !notes.is_empty() {
            notes.sort_by(|a, b| a.1.cmp(&b.1));
            println!();
            println!("Notes:");
            for (text, _, at_str) in &notes {
                println!("- {at_str} {text}");
            }

            let mut all_refs = Vec::new();
            for (text, _, _) in &notes {
                all_refs.extend(extract_references(text));
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
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    higher_input: String,
    lower_input: String,
) -> Result<()> {
    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let higher_id = resolve_task_id(&higher_input, &space)?;
        let lower_id = resolve_task_id(&lower_input, &space)?;

        if higher_id == lower_id {
            bail!("cannot prioritize a goal over itself");
        }

        // Build full edge set (explicit + implicit child→parent)
        let mut edges = active_priority_edges(&space);
        for id in all_goal_ids(&space) {
            if let Some(parent) = task_parent(&space, id) {
                edges.insert((id, parent));
            }
        }

        if would_create_cycle(&edges, higher_id, lower_id) {
            if is_ancestor(&space, higher_id, lower_id) || is_ancestor(&space, lower_id, higher_id)
            {
                bail!("children are implicitly prioritized over their parents");
            }
            bail!("would create a priority cycle");
        }

        let now = epoch_interval(now_epoch());
        let evt_id = ufoid();
        let mut change = TribleSet::new();
        change += ensure_kind_entities(&mut ws)?;
        change += entity! { &evt_id @
            metadata::tag: &KIND_PRIORITIZE_ID,
            board::higher: &higher_id,
            board::lower: &lower_id,
            metadata::created_at: now,
        };

        ws.commit(change, "prioritize goal");
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push: {e:?}"))?;

        let h_title = task_title(&mut ws, &space, higher_id);
        let l_title = task_title(&mut ws, &space, lower_id);
        println!(
            "{} > {}",
            if h_title.is_empty() { "?" } else { &h_title },
            if l_title.is_empty() { "?" } else { &l_title }
        );
        Ok(())
    })
}

fn cmd_deprioritize(
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    higher_input: String,
    lower_input: String,
) -> Result<()> {
    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let higher_id = resolve_task_id(&higher_input, &space)?;
        let lower_id = resolve_task_id(&lower_input, &space)?;

        let edges = active_priority_edges(&space);
        if !edges.contains(&(higher_id, lower_id)) {
            bail!("no active priority relationship between these goals");
        }

        let now = epoch_interval(now_epoch());
        let evt_id = ufoid();
        let mut change = TribleSet::new();
        change += ensure_kind_entities(&mut ws)?;
        change += entity! { &evt_id @
            metadata::tag: &KIND_DEPRIORITIZE_ID,
            board::higher: &higher_id,
            board::lower: &lower_id,
            metadata::created_at: now,
        };

        ws.commit(change, "deprioritize goal");
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push: {e:?}"))?;

        let h_title = task_title(&mut ws, &space, higher_id);
        let l_title = task_title(&mut ws, &space, lower_id);
        println!(
            "Removed: {} > {}",
            if h_title.is_empty() { "?" } else { &h_title },
            if l_title.is_empty() { "?" } else { &l_title }
        );
        Ok(())
    })
}

fn is_hex_of_len(value: &str, lengths: &[usize]) -> bool {
    lengths.contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_review_target(raw: &str, unsafe_opaque: bool) -> Result<String> {
    let target = raw.trim();
    if target.is_empty() {
        bail!("review target is empty");
    }
    if target.chars().any(char::is_whitespace) {
        bail!("review target must be one immutable IRI without whitespace");
    }
    if !target.contains(':') {
        bail!("review target must be an immutable IRI (for example git+https://...@<full-oid>)");
    }
    let validated = if target.starts_with("git:") || target.starts_with("git+") {
        let revision = target.rsplit_once('@').map(|(_, revision)| revision);
        let full_oid = revision.is_some_and(|revision| is_hex_of_len(revision, &[40, 64]));
        if !full_oid {
            bail!(
                "git review targets must end in @<full-40-or-64-hex-object-id>; mutable refs and short SHAs are not exact"
            );
        }
        true
    } else if let Some(hash) = target.strip_prefix("files:") {
        is_hex_of_len(hash, &[64])
    } else if let Some(hash) = target.strip_prefix("urn:blake3:") {
        is_hex_of_len(hash, &[64])
    } else if let Some(hash) = target.strip_prefix("urn:sha256:") {
        is_hex_of_len(hash, &[64])
    } else if let Some(hash) = target.strip_prefix("urn:sha512:") {
        is_hex_of_len(hash, &[128])
    } else {
        false
    };
    if !validated && !unsafe_opaque {
        bail!(
            "review target scheme is not verifiably content-addressed; use a full Git object IRI, files:<64-hex>, urn:blake3:<64-hex>, urn:sha256:<64-hex>, or explicitly acknowledge the risk with --unsafe-opaque-target"
        );
    }
    Ok(target.to_string())
}

fn cmd_review_open(
    pile: &Path,
    branch_id: Id,
    goal_input: String,
    target: String,
    unsafe_opaque_target: bool,
    review_group: String,
    override_inputs: Vec<String>,
    persona: Option<&str>,
) -> Result<()> {
    let persona = persona.ok_or_else(|| {
        anyhow::anyhow!("review open requires --persona <label-or-hex> or $PERSONA")
    })?;
    let target = validate_review_target(&target, unsafe_opaque_target)?;

    let (request_id, created) = with_repo(pile, |repo| {
        let mut relations_ws = relations_workspace(repo)?;
        let relations_space = relations_ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout relations: {e:?}"))?;
        let active_people = active_person_ids(&relations_space);
        let known_people = person_ids(&relations_space);
        let author = resolve_active_person(&relations_space, &active_people, persona)?;

        let group_id = resolve_group_id(&relations_space, &review_group)?;
        // Freeze the CURRENT roster: the members of the group's head snapshot
        // (not stale anchor-direct edges).
        let mut required: Vec<Id> = head_members(&relations_space, group_id).into_iter().collect();
        required.sort();
        required.dedup();
        validate_frozen_review_roster(&required, author, &active_people)?;

        let mut override_authorities = Vec::new();
        for input in &override_inputs {
            override_authorities.push(resolve_active_person(
                &relations_space,
                &active_people,
                input,
            )?);
        }
        override_authorities.sort();
        override_authorities.dedup();
        if override_authorities.len() > 1 {
            bail!("review may freeze at most one break-glass authority");
        }
        if override_authorities.contains(&author) {
            bail!("the review author cannot appoint themselves as break-glass authority");
        }

        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        loop {
            let space = ws
                .checkout(..)
                .map_err(|e| anyhow::anyhow!("checkout board: {e:?}"))?;
            let goal_id = resolve_task_id(&goal_input, &space)?;
            let heads = active_request_ids_for_goal(&space, goal_id);

            let sealed_target = target.clone().to_blob().get_handle();
            let mut parsed_heads = Vec::with_capacity(heads.len());
            let mut same_target_heads = Vec::new();
            for head in &heads {
                let existing = review_request(&space, *head).ok_or_else(|| {
                    anyhow::anyhow!("current review head {head:x} is not a readable request")
                })?;
                if existing.targets.contains(&sealed_target) {
                    same_target_heads.push(*head);
                }
                parsed_heads.push(existing);
            }

            if !same_target_heads.is_empty() {
                if let ([head], [existing]) = (heads.as_slice(), parsed_heads.as_slice()) {
                    let structurally_current = evaluate_request_live(&space, *head, &known_people, &relations_space)
                        .is_some_and(|evaluation| {
                            !matches!(evaluation.state, ReviewGateState::Invalid { .. })
                        });
                    let same_frozen_fields = existing.author() == Some(author)
                        && existing.required == required
                        && existing.override_authorities == override_authorities;
                    if structurally_current && same_frozen_fields {
                        return Ok((*head, false));
                    }
                    if !structurally_current {
                        bail!(
                            "current review head {head:x} is malformed; same-target rewriting is forbidden. A repair with a genuinely changed immutable target must preserve its frozen author/roster/override fields, or use a new goal"
                        );
                    }
                    bail!(
                        "same-target review fields cannot be rewritten through `review open`; use `compass review supersede {head:x} --review-group <group>` from the frozen author to replace only the roster safely"
                    );
                }
                let ids = same_target_heads
                    .iter()
                    .map(|id| format!("{id:x}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                bail!(
                    "same-target fork repair is deliberately unsupported: target already occurs on current head(s) {ids}. Use a genuinely changed immutable target absent from every current head (or a future explicit same-target repair protocol)"
                );
            }

            if let ([head], [existing]) = (heads.as_slice(), parsed_heads.as_slice()) {
                let structurally_current = evaluate_request_live(&space, *head, &known_people, &relations_space)
                    .is_some_and(|evaluation| {
                        !matches!(evaluation.state, ReviewGateState::Invalid { .. })
                    });
                let same_frozen_fields = existing.author() == Some(author)
                    && existing.required == required
                    && existing.override_authorities == override_authorities;
                if !structurally_current && !same_frozen_fields {
                    bail!(
                        "current review head {head:x} is malformed; a changed-target repair must preserve its frozen author/roster/override fields"
                    );
                }
            }

            let now = epoch_interval(now_epoch());
            let target_handle = ws.put(target.clone());
            let request = review_request_fragment(
                goal_id,
                author,
                target_handle,
                &required,
                &override_authorities,
                &heads,
                now,
            );
            let request_id = request
                .root()
                .expect("a review request fragment has one intrinsic root");
            let mut change = TribleSet::new();
            change += ensure_kind_entities(&mut ws)?;
            change += request;
            // Level B: record the live-roster group anchor as an extra fact
            // (outside the sealed fragment) so the gate resolves the group's
            // CURRENT members at eval time. Removing a member then unblocks
            // this request with no supersede-for-reroster.
            change += entity! { ExclusiveId::force_ref(&request_id) @ review::group: &group_id };
            ws.commit(change, "open review request");
            match repo
                .try_push(&mut ws)
                .map_err(|e| anyhow::anyhow!("push review request: {e:?}"))?
            {
                None => return Ok((request_id, true)),
                Some(conflict) => ws = conflict,
            }
        }
    })?;

    if created {
        println!("Opened review request {request_id:x}");
        println!("Target: {target}");
    } else {
        println!("Review request {request_id:x} is already current for that exact target");
    }
    Ok(())
}

fn cmd_review_supersede(
    pile: &Path,
    branch_id: Id,
    request_input: String,
    review_group: String,
    persona: Option<&str>,
) -> Result<()> {
    let persona = persona.ok_or_else(|| {
        anyhow::anyhow!("review supersede requires --persona <label-or-hex> or $PERSONA")
    })?;

    let (successor_id, predecessor_id) = with_repo(pile, |repo| {
        let mut relations_ws = relations_workspace(repo)?;
        let relations_space = relations_ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout relations: {e:?}"))?;
        let active_people = active_person_ids(&relations_space);
        let known_people = person_ids(&relations_space);
        let actor = resolve_active_person(&relations_space, &active_people, persona)?;
        let group_id = resolve_group_id(&relations_space, &review_group)?;
        let mut required: Vec<Id> = head_members(&relations_space, group_id).into_iter().collect();
        required.sort();
        required.dedup();

        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        loop {
            let space = ws
                .checkout(..)
                .map_err(|e| anyhow::anyhow!("checkout board: {e:?}"))?;
            let predecessor_id = resolve_request_id(&request_input, &space)?;
            let predecessor = review_request(&space, predecessor_id)
                .ok_or_else(|| anyhow::anyhow!("review request {predecessor_id:x} is malformed"))?;
            let goal = predecessor.goal().ok_or_else(|| {
                anyhow::anyhow!("review request {predecessor_id:x} does not name one goal")
            })?;
            if active_request_ids_for_goal(&space, goal).as_slice() != [predecessor_id] {
                bail!(
                    "review request {predecessor_id:x} is not the unique current review head"
                );
            }
            let evaluation = evaluate_request_live(&space, predecessor_id, &known_people, &relations_space)
                .ok_or_else(|| anyhow::anyhow!("review request {predecessor_id:x} is malformed"))?;
            match &evaluation.state {
                ReviewGateState::Invalid { reasons } => bail!(
                    "cannot supersede malformed review request {predecessor_id:x}: {}",
                    reasons.join("; ")
                ),
                ReviewGateState::Settled { .. } => {
                    bail!("cannot supersede settled review request {predecessor_id:x}")
                }
                ReviewGateState::Pending { .. }
                | ReviewGateState::Blocked { .. }
                | ReviewGateState::Ready => {}
            }
            let author = evaluation
                .request
                .author()
                .expect("non-invalid review request has one author");
            if actor != author {
                bail!(
                    "only frozen request author {author:x} may supersede review request {predecessor_id:x}"
                );
            }
            validate_frozen_review_roster(&required, author, &active_people)?;
            if required == evaluation.request.required {
                bail!("selected review group freezes the existing roster; no successor is needed");
            }

            for removed in evaluation
                .request
                .required
                .iter()
                .filter(|reviewer| !required.contains(reviewer))
            {
                let submitted = all_attestation_ids_for_reviewer(
                    &space,
                    predecessor_id,
                    *removed,
                );
                if !submitted.is_empty() {
                    let evidence = submitted
                        .iter()
                        .map(|id| format!("{id:x}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    bail!(
                        "cannot remove reviewer {removed:x}: request {predecessor_id:x} has {} submitted attestation record(s) by that reviewer ({evidence})",
                        submitted.len()
                    );
                }
            }

            let target = evaluation
                .request
                .target()
                .expect("non-invalid review request has one target");
            let now = epoch_interval(now_epoch());
            let successor = review_roster_successor_fragment(
                goal,
                author,
                target,
                &required,
                &evaluation.request.override_authorities,
                predecessor_id,
                now,
            );
            let successor_id = successor
                .root()
                .expect("a review request fragment has one intrinsic root");
            let mut candidate_space = space.clone().into_facts();
            candidate_space += successor;
            let candidate = evaluate_request_live(&candidate_space, successor_id, &known_people, &relations_space)
                .ok_or_else(|| anyhow::anyhow!("prospective roster successor is malformed"))?;
            if let ReviewGateState::Invalid { reasons } = candidate.state {
                bail!(
                    "cannot create unsafe roster successor {successor_id:x}: {}",
                    reasons.join("; ")
                );
            }
            let successor = review_roster_successor_fragment(
                goal,
                author,
                target,
                &required,
                &evaluation.request.override_authorities,
                predecessor_id,
                now,
            );
            let mut change = TribleSet::new();
            change += ensure_kind_entities(&mut ws)?;
            change += successor;
            change += entity! { ExclusiveId::force_ref(&successor_id) @ review::group: &group_id };
            ws.commit(change, "supersede review roster");
            match repo
                .try_push(&mut ws)
                .map_err(|e| anyhow::anyhow!("push review roster successor: {e:?}"))?
            {
                None => return Ok((successor_id, predecessor_id)),
                Some(conflict) => ws = conflict,
            }
        }
    })?;

    println!("Superseded review request {predecessor_id:x} with {successor_id:x}");
    println!("Target and frozen author are unchanged; every successor reviewer must attest anew");
    Ok(())
}

fn cmd_review_submit(
    pile: &Path,
    branch_id: Id,
    request_input: String,
    verdict: VerdictArg,
    report: String,
    persona: Option<&str>,
) -> Result<()> {
    let persona = persona.ok_or_else(|| {
        anyhow::anyhow!("review submit requires --persona <label-or-hex> or $PERSONA")
    })?;
    let report = report.trim().to_string();
    if report.is_empty() {
        bail!("review report is empty; settlement records evidence, not ceremonial votes");
    }
    let verdict = verdict.as_str();

    let (attestation_id, request_id) = with_repo(pile, |repo| {
        let mut relations_ws = relations_workspace(repo)?;
        let relations_space = relations_ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout relations: {e:?}"))?;
        let known_people = person_ids(&relations_space);
        let reviewer = resolve_frozen_person(&relations_space, &known_people, persona)?;
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        loop {
            let space = ws
                .checkout(..)
                .map_err(|e| anyhow::anyhow!("checkout board: {e:?}"))?;
            let request_id = resolve_request_id(&request_input, &space)?;
            let request = review_request(&space, request_id)
                .ok_or_else(|| anyhow::anyhow!("review request {request_id:x} is malformed"))?;
            if !request_is_active(&space, request_id) {
                bail!(
                    "review request {request_id:x} is stale or forked; attest the sole current exact request instead"
                );
            }
            if !request.required.contains(&reviewer) {
                bail!("persona {reviewer:x} is not in request {request_id:x}'s frozen reviewer roster");
            }
            if !matches!(
                evaluate_request_live(&space, request_id, &known_people, &relations_space),
                Some(ReviewEvaluation {
                    state: ReviewGateState::Pending { .. }
                        | ReviewGateState::Blocked { .. }
                        | ReviewGateState::Ready,
                    ..
                })
            ) {
                bail!("review request {request_id:x} is invalid or already settled");
            }

            let heads = active_attestation_ids_for_reviewer(&space, request_id, reviewer);
            let report_handle = ws.put(report.clone());
            let now = epoch_interval(now_epoch());
            let attestation = review_attestation_fragment(
                request_id,
                reviewer,
                verdict,
                report_handle,
                &heads,
                now,
            );
            let attestation_id = attestation
                .root()
                .expect("a review attestation fragment has one intrinsic root");
            let mut change = TribleSet::new();
            change += ensure_kind_entities(&mut ws)?;
            change += attestation;
            ws.commit(change, "submit review attestation");
            match repo
                .try_push(&mut ws)
                .map_err(|e| anyhow::anyhow!("push review attestation: {e:?}"))?
            {
                None => return Ok((attestation_id, request_id)),
                Some(conflict) => ws = conflict,
            }
        }
    })?;
    println!("Attested {verdict} on request {request_id:x} ({attestation_id:x})");
    Ok(())
}

/// Parse a snooze duration ("90m", "2h", "1d") into an absolute deadline.
fn parse_snooze_deadline(duration: &str) -> Result<Epoch> {
    let dur = humantime::parse_duration(duration.trim())
        .with_context(|| format!("invalid --for duration '{duration}' (try 90m, 2h, 1d)"))?;
    Ok(now_epoch() + hifitime::Duration::from_total_nanoseconds(dur.as_nanos() as i128))
}

/// Write a per-persona review watermark onto the private `orient-state` branch:
/// `deadline == None` is a plain ACK (quiet until state/roster/target changes),
/// `Some` is a SNOOZE (also re-enqueues after the deadline). Validates the
/// request is active and the persona is in its frozen roster, then snapshots the
/// reviewer's current attestation head-set so a later head change re-surfaces it.
/// Returns the resolved request id.
fn write_review_watermark(
    pile: &Path,
    branch_id: Id,
    request_input: String,
    persona: Option<&str>,
    deadline: Option<Epoch>,
) -> Result<Id> {
    let persona = persona.ok_or_else(|| {
        anyhow::anyhow!("review ack/snooze requires --persona <label-or-hex> or $PERSONA")
    })?;
    with_repo(pile, |repo| {
        // Resolve the reviewer against the frozen roster (soft-retired ok).
        let mut relations_ws = relations_workspace(repo)?;
        let relations_space = relations_ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout relations: {e:?}"))?;
        let known_people = person_ids(&relations_space);
        let reviewer = resolve_frozen_person(&relations_space, &known_people, persona)?;

        // Read the compass board to validate the request and snapshot the
        // reviewer's current attestation head-set.
        let mut board_ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull board: {e:?}"))?;
        let space = board_ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout board: {e:?}"))?;
        let request_id = resolve_request_id(&request_input, &space)?;
        let request = review_request(&space, request_id)
            .ok_or_else(|| anyhow::anyhow!("review request {request_id:x} is malformed"))?;
        if !request_is_active(&space, request_id) {
            bail!(
                "review request {request_id:x} is stale or forked; ack/snooze the sole current exact request instead"
            );
        }
        if !request.required.contains(&reviewer) {
            bail!("persona {reviewer:x} is not in request {request_id:x}'s frozen reviewer roster");
        }
        let heads = active_attestation_ids_for_reviewer(&space, request_id, reviewer);

        // Append the watermark on the private orient-state branch (CAS loop).
        let orient_state_branch = repo
            .ensure_branch("orient-state", None)
            .map_err(|e| anyhow::anyhow!("ensure orient-state branch: {e:?}"))?;
        let mut ws = repo
            .pull(orient_state_branch)
            .map_err(|e| anyhow::anyhow!("pull orient-state: {e:?}"))?;
        loop {
            let now = epoch_interval(now_epoch());
            let wm_id = ufoid();
            let mut change = TribleSet::new();
            change += entity! { &wm_id @
                metadata::tag: &KIND_REVIEW_WATERMARK_ID,
                orient_state::persona: &reviewer,
                orient_state::wm_request: &request_id,
                orient_state::wm_head*: heads.iter(),
                orient_state::at: now,
            };
            if let Some(deadline) = deadline {
                change += entity! { &wm_id @
                    orient_state::wm_deadline: epoch_interval(deadline),
                };
            }
            let verb = if deadline.is_some() {
                "snooze review"
            } else {
                "ack review"
            };
            ws.commit(change, verb);
            match repo
                .try_push(&mut ws)
                .map_err(|e| anyhow::anyhow!("push review watermark: {e:?}"))?
            {
                None => return Ok(request_id),
                Some(conflict) => ws = conflict,
            }
        }
    })
}

fn cmd_review_ack(pile: &Path, branch_id: Id, request: String, persona: Option<&str>) -> Result<()> {
    let request_id = write_review_watermark(pile, branch_id, request, persona, None)?;
    println!(
        "Acknowledged review request {request_id:x} — your watcher stays quiet on it until its state changes, a successor supersedes it, or you attest."
    );
    Ok(())
}

fn cmd_review_snooze(
    pile: &Path,
    branch_id: Id,
    request: String,
    duration: String,
    persona: Option<&str>,
) -> Result<()> {
    let deadline = parse_snooze_deadline(&duration)?;
    let request_id = write_review_watermark(pile, branch_id, request, persona, Some(deadline))?;
    println!(
        "Snoozed review request {request_id:x} for {} — it re-surfaces after that (or sooner if its state changes).",
        duration.trim()
    );
    Ok(())
}

fn render_review_evaluation(
    board_ws: &mut Workspace<Pile>,
    relations_ws: &mut Workspace<Pile>,
    relations_space: &TribleSet,
    evaluation: &ReviewEvaluation,
    active_binding: bool,
) {
    println!("Request: {:x}", evaluation.request.id);
    println!("Target: {}", request_target(board_ws, &evaluation.request));
    if let Some(author) = evaluation.request.author() {
        println!(
            "Author: {} ({:x})",
            person_label(relations_ws, relations_space, author),
            author
        );
    }
    if !active_binding {
        println!("Binding: HISTORICAL OR FORKED — exact gate commands are closed");
    }
    let gate = match &evaluation.state {
        ReviewGateState::Invalid { reasons } => format!("INVALID — {}", reasons.join("; ")),
        ReviewGateState::Pending {
            submitted,
            required,
        } => {
            format!("PENDING — {submitted}/{required} submitted")
        }
        ReviewGateState::Blocked { submitted, reasons } => {
            format!(
                "BLOCKED — {submitted}/{} submitted — {}",
                evaluation.request.required.len(),
                reasons.join("; ")
            )
        }
        ReviewGateState::Ready if active_binding => {
            "READY — exact candidate may settle".to_string()
        }
        ReviewGateState::Ready => {
            "HISTORICAL READY EVIDENCE — request is not the sole active head".to_string()
        }
        ReviewGateState::Settled { settlements } => {
            let override_count = settlements
                .iter()
                .filter(|s| s.mode == SettlementMode::Override)
                .count();
            if override_count == 0 {
                "SETTLED — exact attestation proof recorded".to_string()
            } else {
                "OVERRIDDEN — reasoned break-glass proof recorded".to_string()
            }
        }
    };
    println!("Gate: {gate}");
    if let ReviewGateState::Settled { settlements } = &evaluation.state {
        println!("Certificates:");
        for settlement in settlements {
            match settlement.mode {
                SettlementMode::Attestations => {
                    println!(
                        "- {:x} ({} reviewers)",
                        settlement.id,
                        evaluation.request.required.len()
                    );
                    for evidence in &settlement.attestations {
                        println!("    sealed attestation {:x}", evidence);
                    }
                }
                SettlementMode::Override => {
                    println!("- {:x} (break-glass)", settlement.id);
                    if let Some(event) = settlement.override_event {
                        println!("    sealed override event {:x}", event);
                    }
                }
            }
        }
    }
    println!("Reviewers:");
    let author = evaluation.request.author();
    for slot in &evaluation.slots {
        let name = person_label(relations_ws, relations_space, slot.reviewer);
        let role = if Some(slot.reviewer) == author {
            " (author)"
        } else {
            ""
        };
        match slot.heads.as_slice() {
            [] => println!("- {name}{role}: pending [{:x}]", slot.reviewer),
            [head] => {
                let verdict = head.verdict().unwrap_or("malformed");
                println!("- {name}{role}: {verdict} [{:x}]", head.id);
                if let Some(report) = head.report().and_then(|h| read_text(board_ws, h).ok()) {
                    for line in report.lines() {
                        println!("    {line}");
                    }
                }
            }
            heads => println!(
                "- {name}{role}: FORKED ({} active attestations)",
                heads.len()
            ),
        }
    }
}

fn render_review_projection(
    board_ws: &mut Workspace<Pile>,
    board_space: &TribleSet,
    relations_ws: &mut Workspace<Pile>,
    relations_space: &TribleSet,
    projection: ReviewProjection,
) {
    match projection {
        ReviewProjection::Unbound => println!("Gate: UNBOUND — no exact review request"),
        ReviewProjection::Forked { request_ids } => {
            println!(
                "Gate: FORKED — {} concurrent request heads; gate closed",
                request_ids.len()
            );
            for id in request_ids {
                if let Some(request) = review_request(board_space, id) {
                    println!("- [{id:x}] {}", request_target(board_ws, &request));
                } else {
                    println!("- [{id:x}] malformed");
                }
            }
        }
        ReviewProjection::Bound(evaluation) => {
            render_review_evaluation(board_ws, relations_ws, relations_space, &evaluation, true)
        }
    }
}

fn cmd_review_status(pile: &Path, branch_id: Id, input: String, history: bool) -> Result<()> {
    with_repo(pile, |repo| {
        let mut relations_ws = relations_workspace(repo)?;
        let relations_space = relations_ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout relations: {e:?}"))?;
        let known_people = person_ids(&relations_space);
        let mut board_ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let board_space = board_ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout board: {e:?}"))?;

        let request_matches: Vec<Id> = find!(
            id: Id,
            pattern!(&board_space, [{ ?id @ metadata::tag: &KIND_REVIEW_REQUEST_ID }])
        )
        .filter(|id| fmt_id(*id).starts_with(&input.to_ascii_lowercase()))
        .collect();
        let goal_id = match request_matches.as_slice() {
            [request_id] => {
                let evaluation = evaluate_request_live(&board_space, *request_id, &known_people, &relations_space)
                    .ok_or_else(|| anyhow::anyhow!("malformed review request {request_id:x}"))?;
                let goal = evaluation.request.goal();
                let active_binding = request_is_active(&board_space, *request_id);
                render_review_evaluation(
                    &mut board_ws,
                    &mut relations_ws,
                    &relations_space,
                    &evaluation,
                    active_binding,
                );
                goal
            }
            [] => {
                let goal_id = resolve_task_id(&input, &board_space)?;
                println!("Goal: {goal_id:x}");
                render_review_projection(
                    &mut board_ws,
                    &board_space,
                    &mut relations_ws,
                    &relations_space,
                    evaluate_goal(&board_space, goal_id, &known_people),
                );
                Some(goal_id)
            }
            _ => bail!("review request prefix '{input}' is ambiguous"),
        };

        if history {
            if let Some(goal_id) = goal_id {
                let active: HashSet<Id> = active_request_ids_for_goal(&board_space, goal_id)
                    .into_iter()
                    .collect();
                let ids = all_request_ids_for_goal(&board_space, goal_id);
                println!("History:");
                if ids.is_empty() {
                    println!("- None");
                }
                for id in ids {
                    let state = if active.contains(&id) {
                        "ACTIVE"
                    } else {
                        "STALE"
                    };
                    let target = review_request(&board_space, id)
                        .map(|request| request_target(&mut board_ws, &request))
                        .unwrap_or_else(|| "<malformed target>".to_string());
                    println!("- {state} [{id:x}] {target}");
                }
            }
        }
        Ok(())
    })
}

fn load_exact_active_evaluation(
    space: &TribleSet,
    request_input: &str,
    known_people: &HashSet<Id>,
    relations_space: &TribleSet,
) -> Result<ReviewEvaluation> {
    let request_id = resolve_request_id(request_input, space)?;
    if !request_is_active(space, request_id) {
        bail!("review request {request_id:x} is stale or fork-superseded");
    }
    evaluate_request_live(space, request_id, known_people, relations_space)
        .ok_or_else(|| anyhow::anyhow!("malformed review request {request_id:x}"))
}

fn cmd_review_gate(pile: &Path, branch_id: Id, request_input: String) -> Result<()> {
    with_repo(pile, |repo| {
        let mut relations_ws = relations_workspace(repo)?;
        let relations_space = relations_ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout relations: {e:?}"))?;
        let known_people = person_ids(&relations_space);
        let mut board_ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let board_space = board_ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout board: {e:?}"))?;
        let evaluation =
            load_exact_active_evaluation(&board_space, &request_input, &known_people, &relations_space)?;
        let passes = matches!(
            evaluation.state,
            ReviewGateState::Ready | ReviewGateState::Settled { .. }
        );
        render_review_evaluation(
            &mut board_ws,
            &mut relations_ws,
            &relations_space,
            &evaluation,
            true,
        );
        if !passes {
            bail!(
                "review gate is closed for request {:x}",
                evaluation.request.id
            );
        }
        Ok(())
    })
}

fn cmd_review_settle(
    pile: &Path,
    branch_id: Id,
    request_input: String,
    persona: Option<&str>,
) -> Result<()> {
    let persona = persona.ok_or_else(|| {
        anyhow::anyhow!("review settle requires --persona <label-or-hex> or $PERSONA")
    })?;
    let (settlement_id, created) = with_repo(pile, |repo| {
        let mut relations_ws = relations_workspace(repo)?;
        let relations_space = relations_ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout relations: {e:?}"))?;
        let known_people = person_ids(&relations_space);
        let settler = resolve_frozen_person(&relations_space, &known_people, persona)?;
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        loop {
            let space = ws
                .checkout(..)
                .map_err(|e| anyhow::anyhow!("checkout board: {e:?}"))?;
            let evaluation =
                load_exact_active_evaluation(&space, &request_input, &known_people, &relations_space)?;
            if let ReviewGateState::Settled { settlements } = &evaluation.state {
                return Ok((settlements[0].id, false));
            }
            if !matches!(evaluation.state, ReviewGateState::Ready) {
                bail!(
                    "review gate is not ready for request {:x}",
                    evaluation.request.id
                );
            }
            if evaluation.request.author() != Some(settler) {
                bail!(
                    "only request author {:x} may record the final settlement",
                    evaluation.request.author().expect("ready request has one author")
                );
            }
            let goal = evaluation
                .request
                .goal()
                .ok_or_else(|| anyhow::anyhow!("review request has no unique goal"))?;
            let evidence: Vec<Id> = evaluation
                .slots
                .iter()
                .map(|slot| slot.heads[0].id)
                .collect();
            let now = epoch_interval(now_epoch());
            let settlement = review_attestation_settlement_fragment(
                evaluation.request.id,
                goal,
                settler,
                &evidence,
                now,
            );
            let settlement_id = settlement
                .root()
                .expect("a review settlement fragment has one intrinsic root");
            let mut change = TribleSet::new();
            change += ensure_kind_entities(&mut ws)?;
            change += settlement;
            ws.commit(change, "settle reviewed goal");
            match repo
                .try_push(&mut ws)
                .map_err(|e| anyhow::anyhow!("push review settlement: {e:?}"))?
            {
                None => return Ok((settlement_id, true)),
                Some(conflict) => ws = conflict,
            }
        }
    })?;
    if created {
        println!("Settled review with exact attestation proof {settlement_id:x}");
    } else {
        println!("Review is already settled by {settlement_id:x}");
    }
    Ok(())
}

fn cmd_review_override(
    pile: &Path,
    branch_id: Id,
    request_input: String,
    reason: String,
    persona: Option<&str>,
) -> Result<()> {
    let persona = persona.ok_or_else(|| {
        anyhow::anyhow!("review override requires --persona <label-or-hex> or $PERSONA")
    })?;
    let reason = reason.trim().to_string();
    if reason.is_empty() {
        bail!("break-glass override requires a non-empty reason");
    }
    let (settlement_id, created) = with_repo(pile, |repo| {
        let mut relations_ws = relations_workspace(repo)?;
        let relations_space = relations_ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout relations: {e:?}"))?;
        let known_people = person_ids(&relations_space);
        let actor = resolve_frozen_person(&relations_space, &known_people, persona)?;
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        loop {
            let space = ws
                .checkout(..)
                .map_err(|e| anyhow::anyhow!("checkout board: {e:?}"))?;
            let evaluation =
                load_exact_active_evaluation(&space, &request_input, &known_people, &relations_space)?;
            if let ReviewGateState::Settled { settlements } = &evaluation.state {
                return Ok((settlements[0].id, false));
            }
            if matches!(evaluation.state, ReviewGateState::Invalid { .. }) {
                bail!(
                    "break-glass cannot override malformed candidate integrity for request {:x}",
                    evaluation.request.id
                );
            }
            if !evaluation.request.override_authorities.contains(&actor) {
                bail!("persona {actor:x} is not a frozen override authority for this request");
            }
            let goal = evaluation
                .request
                .goal()
                .ok_or_else(|| anyhow::anyhow!("review request has no unique goal"))?;
            let now = epoch_interval(now_epoch());
            let reason_handle = ws.put(reason.clone());
            let override_event =
                review_override_fragment(evaluation.request.id, actor, reason_handle, now);
            let override_id = override_event
                .root()
                .expect("a review override fragment has one intrinsic root");
            let settlement = review_override_settlement_fragment(
                evaluation.request.id,
                goal,
                actor,
                override_id,
                now,
            );
            let settlement_id = settlement
                .root()
                .expect("a review settlement fragment has one intrinsic root");
            let mut change = TribleSet::new();
            change += ensure_kind_entities(&mut ws)?;
            change += override_event;
            change += settlement;
            ws.commit(change, "override and settle reviewed goal");
            match repo
                .try_push(&mut ws)
                .map_err(|e| anyhow::anyhow!("push review override: {e:?}"))?
            {
                None => return Ok((settlement_id, true)),
                Some(conflict) => ws = conflict,
            }
        }
    })?;
    if created {
        println!("Recorded break-glass settlement {settlement_id:x}");
    } else {
        println!("Review is already settled by {settlement_id:x}");
    }
    Ok(())
}

fn cmd_resolve(pile: &Path, _branch_name: &str, branch_id: Id, prefix: String) -> Result<()> {
    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let id = resolve_task_id(&prefix, &space)?;
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
    let branch_id = with_repo(&cli.pile, |repo| {
        if let Some(hex) = cli.branch_id.as_deref() {
            return Id::from_hex(hex.trim())
                .ok_or_else(|| anyhow::anyhow!("invalid branch id '{hex}'"));
        }
        repo.ensure_branch(&cli.branch, None)
            .map_err(|e| anyhow::anyhow!("ensure branch '{}': {e:?}", cli.branch))
    })?;

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
                .map(|value| load_value_or_file(value, "goal note"))
                .transpose()?;
            cmd_add(
                &cli.pile,
                &cli.branch,
                branch_id,
                title,
                status,
                parent,
                tag,
                note,
                cli.persona.as_deref(),
            )
        }
        Command::List { status, tag, all } => {
            cmd_list(&cli.pile, &cli.branch, branch_id, status, tag, all)
        }
        Command::Move { id, status } => cmd_move(
            &cli.pile,
            &cli.branch,
            branch_id,
            id,
            status,
            cli.persona.as_deref(),
        ),
        Command::Note { id, note } => {
            let note = load_value_or_file(&note, "goal note")?;
            cmd_note(&cli.pile, &cli.branch, branch_id, id, note)
        }
        Command::Show { id } => cmd_show(&cli.pile, &cli.branch, branch_id, id),
        Command::Prioritize { higher, over } => {
            cmd_prioritize(&cli.pile, &cli.branch, branch_id, higher, over)
        }
        Command::Deprioritize { higher, over } => {
            cmd_deprioritize(&cli.pile, &cli.branch, branch_id, higher, over)
        }
        Command::Resolve { prefix } => cmd_resolve(&cli.pile, &cli.branch, branch_id, prefix),
        Command::Review { command } => match command {
            ReviewCommand::Open {
                goal,
                target,
                unsafe_opaque_target,
                review_group,
                override_authority,
            } => cmd_review_open(
                &cli.pile,
                branch_id,
                goal,
                target,
                unsafe_opaque_target,
                review_group,
                override_authority,
                cli.persona.as_deref(),
            ),
            ReviewCommand::Supersede {
                request,
                review_group,
            } => cmd_review_supersede(
                &cli.pile,
                branch_id,
                request,
                review_group,
                cli.persona.as_deref(),
            ),
            ReviewCommand::Submit {
                request,
                verdict,
                report,
            } => cmd_review_submit(
                &cli.pile,
                branch_id,
                request,
                verdict,
                load_value_or_file(&report, "review report")?,
                cli.persona.as_deref(),
            ),
            ReviewCommand::Ack { request } => {
                cmd_review_ack(&cli.pile, branch_id, request, cli.persona.as_deref())
            }
            ReviewCommand::Snooze { request, duration } => {
                cmd_review_snooze(&cli.pile, branch_id, request, duration, cli.persona.as_deref())
            }
            ReviewCommand::Status { id, history } => {
                cmd_review_status(&cli.pile, branch_id, id, history)
            }
            ReviewCommand::Gate { request } => cmd_review_gate(&cli.pile, branch_id, request),
            ReviewCommand::Settle { request } => {
                cmd_review_settle(&cli.pile, branch_id, request, cli.persona.as_deref())
            }
            ReviewCommand::Override { request, reason } => cmd_review_override(
                &cli.pile,
                branch_id,
                request,
                load_value_or_file(&reason, "override reason")?,
                cli.persona.as_deref(),
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use faculties::schemas::relations::group;
    use faculties::schemas::compass::review;
    use faculties::schemas::relations::KIND_RETIRE_ID;
    use std::fs::File;

    const TEST_TARGET: &str =
        "urn:blake3:1111111111111111111111111111111111111111111111111111111111111111";

    struct TestPile(PathBuf);

    impl TestPile {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "faculties-compass-review-{}.pile",
                ufoid().id
            ));
            File::create(&path).expect("create test pile");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestPile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn seed_cli_review(pile: &Path, reviewer_count: usize) -> Result<(Id, Id, Vec<Id>, Id)> {
        with_repo(pile, |repo| {
            let reviewers: Vec<Id> = (0..reviewer_count).map(|_| ufoid().id).collect();
            let group_id = ufoid().id;
            let relations_branch = repo
                .ensure_branch("relations", None)
                .map_err(|e| anyhow::anyhow!("ensure relations branch: {e:?}"))?;
            let mut relations_ws = repo
                .pull(relations_branch)
                .map_err(|e| anyhow::anyhow!("pull relations: {e:?}"))?;
            let mut relations_change = TribleSet::new();
            for reviewer in &reviewers {
                relations_change += entity! { ExclusiveId::force_ref(reviewer) @
                    metadata::tag: &KIND_PERSON_ID,
                };
            }
            let snapshot_id = ufoid().id;
            relations_change += entity! { ExclusiveId::force_ref(&group_id) @
                metadata::tag: &KIND_GROUP,
            };
            relations_change += entity! { ExclusiveId::force_ref(&snapshot_id) @
                group::snapshot_of: &group_id,
                group::member*: reviewers.iter(),
            };
            relations_ws.commit(relations_change, "seed review roster");
            repo.push(&mut relations_ws)
                .map_err(|e| anyhow::anyhow!("push relations fixture: {e:?}"))?;

            let board_branch = repo
                .ensure_branch("compass", None)
                .map_err(|e| anyhow::anyhow!("ensure compass branch: {e:?}"))?;
            let mut board_ws = repo
                .pull(board_branch)
                .map_err(|e| anyhow::anyhow!("pull compass: {e:?}"))?;
            let goal = ufoid().id;
            let goal_fragment = entity! { ExclusiveId::force_ref(&goal) @
                metadata::tag: &KIND_GOAL_ID,
            };
            board_ws.commit(goal_fragment, "seed review goal");
            repo.push(&mut board_ws)
                .map_err(|e| anyhow::anyhow!("push goal fixture: {e:?}"))?;
            Ok((board_branch, goal, reviewers, group_id))
        })
    }

    fn cli_evaluation(pile: &Path, branch_id: Id, goal: Id) -> ReviewEvaluation {
        with_repo(pile, |repo| {
            let mut relations_ws = relations_workspace(repo)?;
            let relations_space = relations_ws
                .checkout(..)
                .map_err(|e| anyhow::anyhow!("checkout relations: {e:?}"))?;
            let known = person_ids(&relations_space);
            let mut board_ws = repo
                .pull(branch_id)
                .map_err(|e| anyhow::anyhow!("pull compass: {e:?}"))?;
            let board_space = board_ws
                .checkout(..)
                .map_err(|e| anyhow::anyhow!("checkout compass: {e:?}"))?;
            match evaluate_goal(&board_space, goal, &known) {
                ReviewProjection::Bound(evaluation) => Ok(evaluation),
                other => bail!("expected bound review, got {other:?}"),
            }
        })
        .expect("evaluate CLI review fixture")
    }

    fn active_request_ids_for_goal_in_pile(pile: &Path, branch_id: Id, goal: Id) -> Vec<Id> {
        with_repo(pile, |repo| {
            let mut ws = repo
                .pull(branch_id)
                .map_err(|e| anyhow::anyhow!("pull compass: {e:?}"))?;
            let space = ws
                .checkout(..)
                .map_err(|e| anyhow::anyhow!("checkout compass: {e:?}"))?;
            Ok(active_request_ids_for_goal(&space, goal))
        })
        .expect("load active CLI request heads")
    }

    fn add_active_cli_person(pile: &Path) -> Id {
        with_repo(pile, |repo| {
            let branch = repo
                .ensure_branch("relations", None)
                .map_err(|e| anyhow::anyhow!("ensure relations branch: {e:?}"))?;
            let mut ws = repo
                .pull(branch)
                .map_err(|e| anyhow::anyhow!("pull relations: {e:?}"))?;
            let person = ufoid().id;
            let fragment = entity! { ExclusiveId::force_ref(&person) @
                metadata::tag: &KIND_PERSON_ID,
            };
            ws.commit(fragment, "seed active outsider");
            repo.push(&mut ws)
                .map_err(|e| anyhow::anyhow!("push active outsider: {e:?}"))?;
            Ok(person)
        })
        .expect("add active CLI person")
    }

    fn add_cli_group(pile: &Path, members: &[Id]) -> Id {
        with_repo(pile, |repo| {
            let branch = repo
                .ensure_branch("relations", None)
                .map_err(|e| anyhow::anyhow!("ensure relations branch: {e:?}"))?;
            let mut ws = repo
                .pull(branch)
                .map_err(|e| anyhow::anyhow!("pull relations: {e:?}"))?;
            let group_id = ufoid().id;
            let snapshot_id = ufoid().id;
            let mut fragment = TribleSet::new();
            fragment += entity! { ExclusiveId::force_ref(&group_id) @
                metadata::tag: &KIND_GROUP,
            };
            fragment += entity! { ExclusiveId::force_ref(&snapshot_id) @
                group::snapshot_of: &group_id,
                group::member*: members.iter(),
            };
            ws.commit(fragment, "seed alternate review roster");
            repo.push(&mut ws)
                .map_err(|e| anyhow::anyhow!("push alternate review roster: {e:?}"))?;
            Ok(group_id)
        })
        .expect("add CLI group")
    }

    fn retire_cli_person(pile: &Path, person: Id) {
        with_repo(pile, |repo| {
            let branch = repo
                .ensure_branch("relations", None)
                .map_err(|e| anyhow::anyhow!("ensure relations branch: {e:?}"))?;
            let mut ws = repo
                .pull(branch)
                .map_err(|e| anyhow::anyhow!("pull relations: {e:?}"))?;
            let event = ufoid();
            let fragment = entity! { &event @
                metadata::tag: &KIND_RETIRE_ID,
                rel_attrs::subject: &person,
                metadata::created_at: epoch_interval(now_epoch()),
            };
            ws.commit(fragment, "retire review fixture person");
            repo.push(&mut ws)
                .map_err(|e| anyhow::anyhow!("push retirement: {e:?}"))?;
            Ok(())
        })
        .expect("retire CLI person")
    }

    fn inject_cli_attestation(
        pile: &Path,
        branch_id: Id,
        request: Id,
        reviewer: Id,
        verdict: &str,
        supersedes: &[Id],
    ) -> Id {
        with_repo(pile, |repo| {
            let mut ws = repo
                .pull(branch_id)
                .map_err(|e| anyhow::anyhow!("pull compass: {e:?}"))?;
            let report = ws.put(format!("fixture evidence {}", ufoid().id));
            let fragment = review_attestation_fragment(
                request,
                reviewer,
                verdict,
                report,
                supersedes,
                epoch_interval(now_epoch()),
            );
            let id = fragment.root().expect("intrinsic fixture attestation");
            ws.commit(fragment, "inject review evidence fixture");
            repo.push(&mut ws)
                .map_err(|e| anyhow::anyhow!("push review evidence fixture: {e:?}"))?;
            Ok(id)
        })
        .expect("inject CLI attestation")
    }

    fn inject_cli_request_successor(
        pile: &Path,
        branch_id: Id,
        predecessor_id: Id,
        target: &str,
    ) -> Id {
        with_repo(pile, |repo| {
            let mut ws = repo
                .pull(branch_id)
                .map_err(|e| anyhow::anyhow!("pull compass: {e:?}"))?;
            let space = ws
                .checkout(..)
                .map_err(|e| anyhow::anyhow!("checkout compass: {e:?}"))?;
            let predecessor = review_request(&space, predecessor_id)
                .ok_or_else(|| anyhow::anyhow!("missing predecessor fixture"))?;
            let fragment = review_request_fragment(
                predecessor.goal().expect("fixture goal"),
                predecessor.author().expect("fixture author"),
                ws.put(target.to_string()),
                &predecessor.required,
                &predecessor.override_authorities,
                &[predecessor_id],
                epoch_interval(now_epoch()),
            );
            let id = fragment.root().expect("intrinsic fixture successor");
            ws.commit(fragment, "inject review successor fixture");
            repo.push(&mut ws)
                .map_err(|e| anyhow::anyhow!("push review successor fixture: {e:?}"))?;
            Ok(id)
        })
        .expect("inject CLI request successor")
    }

    fn backpatch_cli_entity(pile: &Path, branch_id: Id, fragment: Fragment) {
        with_repo(pile, |repo| {
            let mut ws = repo
                .pull(branch_id)
                .map_err(|e| anyhow::anyhow!("pull compass: {e:?}"))?;
            ws.commit(fragment, "backpatch malformed review fixture");
            repo.push(&mut ws)
                .map_err(|e| anyhow::anyhow!("push malformed review fixture: {e:?}"))?;
            Ok(())
        })
        .expect("backpatch CLI entity")
    }

    fn open_cli_review_as(
        pile: &Path,
        branch_id: Id,
        goal: Id,
        author: Id,
        group_id: Id,
    ) -> Result<Id> {
        let author = format!("{author:x}");
        cmd_review_open(
            pile,
            branch_id,
            format!("{goal:x}"),
            TEST_TARGET.to_string(),
            false,
            format!("{group_id:x}"),
            Vec::new(),
            Some(&author),
        )?;
        Ok(cli_evaluation(pile, branch_id, goal).request.id)
    }

    fn open_cli_review(
        pile: &Path,
        branch_id: Id,
        goal: Id,
        reviewers: &[Id],
        group_id: Id,
    ) -> Result<Id> {
        open_cli_review_as(pile, branch_id, goal, reviewers[0], group_id)
    }

    #[test]
    fn cli_pair_gate_runs_from_open_through_exact_settlement() {
        let pile = TestPile::new();
        let (branch, goal, reviewers, group) = seed_cli_review(pile.path(), 2).unwrap();
        let request = open_cli_review(pile.path(), branch, goal, &reviewers, group).unwrap();

        cmd_review_submit(
            pile.path(),
            branch,
            format!("{request:x}"),
            VerdictArg::Abstain,
            "author inspected the exact candidate".to_string(),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap();
        assert!(matches!(
            cli_evaluation(pile.path(), branch, goal).state,
            ReviewGateState::Pending {
                submitted: 1,
                required: 2
            }
        ));

        cmd_review_submit(
            pile.path(),
            branch,
            format!("{request:x}"),
            VerdictArg::Approve,
            "independent reviewer approves".to_string(),
            Some(&format!("{:x}", reviewers[1])),
        )
        .unwrap();
        cmd_review_gate(pile.path(), branch, format!("{request:x}")).unwrap();
        cmd_review_settle(
            pile.path(),
            branch,
            format!("{request:x}"),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap();

        match cli_evaluation(pile.path(), branch, goal).state {
            ReviewGateState::Settled { settlements } => {
                assert_eq!(settlements.len(), 1);
                assert_eq!(settlements[0].attestations.len(), 2);
            }
            other => panic!("expected exact pair settlement, got {other:?}"),
        }
    }

    #[test]
    fn cli_pair_change_request_blocks_the_gate() {
        let pile = TestPile::new();
        let (branch, goal, reviewers, group) = seed_cli_review(pile.path(), 2).unwrap();
        let request = open_cli_review(pile.path(), branch, goal, &reviewers, group).unwrap();
        cmd_review_submit(
            pile.path(),
            branch,
            format!("{request:x}"),
            VerdictArg::Abstain,
            "author abstains".to_string(),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap();
        cmd_review_submit(
            pile.path(),
            branch,
            format!("{request:x}"),
            VerdictArg::RequestChanges,
            "independent reviewer found a blocker".to_string(),
            Some(&format!("{:x}", reviewers[1])),
        )
        .unwrap();

        assert!(matches!(
            cli_evaluation(pile.path(), branch, goal).state,
            ReviewGateState::Blocked { submitted: 2, .. }
        ));
        assert!(cmd_review_gate(pile.path(), branch, format!("{request:x}")).is_err());
    }

    #[test]
    fn cli_open_rejects_author_only_and_missing_author_rosters() {
        let author_only_pile = TestPile::new();
        let (branch, goal, reviewers, group) = seed_cli_review(author_only_pile.path(), 1).unwrap();
        let err =
            open_cli_review(author_only_pile.path(), branch, goal, &reviewers, group).unwrap_err();
        assert!(format!("{err:#}").contains("at least one distinct non-author reviewer"));

        let missing_author_pile = TestPile::new();
        let (branch, goal, _reviewers, group) =
            seed_cli_review(missing_author_pile.path(), 2).unwrap();
        let outsider = add_active_cli_person(missing_author_pile.path());
        let err = open_cli_review_as(missing_author_pile.path(), branch, goal, outsider, group)
            .unwrap_err();
        assert!(format!("{err:#}").contains("must include the author persona"));
    }

    #[test]
    fn cli_safe_roster_supersession_preserves_target_history_and_override() {
        let pile = TestPile::new();
        let (branch, goal, reviewers, triad) = seed_cli_review(pile.path(), 3).unwrap();
        let authority = add_active_cli_person(pile.path());
        cmd_review_open(
            pile.path(),
            branch,
            format!("{goal:x}"),
            TEST_TARGET.to_string(),
            false,
            format!("{triad:x}"),
            vec![format!("{authority:x}")],
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap();
        let predecessor = cli_evaluation(pile.path(), branch, goal).request.id;
        for (reviewer, verdict) in [
            (reviewers[0], VerdictArg::Abstain),
            (reviewers[1], VerdictArg::Approve),
        ] {
            cmd_review_submit(
                pile.path(),
                branch,
                format!("{predecessor:x}"),
                verdict,
                "evidence on the frozen triad".to_string(),
                Some(&format!("{reviewer:x}")),
            )
            .unwrap();
        }
        assert!(matches!(
            cli_evaluation(pile.path(), branch, goal).state,
            ReviewGateState::Pending {
                submitted: 2,
                required: 3
            }
        ));

        retire_cli_person(pile.path(), reviewers[2]);
        let pair = add_cli_group(pile.path(), &reviewers[..2]);

        let bypass = cmd_review_open(
            pile.path(),
            branch,
            format!("{goal:x}"),
            TEST_TARGET.to_string(),
            false,
            format!("{pair:x}"),
            vec![format!("{authority:x}")],
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap_err();
        assert!(format!("{bypass:#}").contains("same-target review fields cannot be rewritten"));

        cmd_review_supersede(
            pile.path(),
            branch,
            format!("{predecessor:x}"),
            format!("{pair:x}"),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap();
        let successor = cli_evaluation(pile.path(), branch, goal).request.id;
        assert_ne!(successor, predecessor);

        with_repo(pile.path(), |repo| {
            let mut board_ws = repo
                .pull(branch)
                .map_err(|e| anyhow::anyhow!("pull compass: {e:?}"))?;
            let board_space = board_ws
                .checkout(..)
                .map_err(|e| anyhow::anyhow!("checkout compass: {e:?}"))?;
            let old = review_request(&board_space, predecessor).expect("historical request");
            let new = review_request(&board_space, successor).expect("successor request");
            let mut expected_pair = reviewers[..2].to_vec();
            expected_pair.sort();
            assert!(old.is_canonical());
            assert!(new.is_canonical());
            assert_eq!(old.required.len(), 3);
            assert_eq!(new.required, expected_pair);
            assert_eq!(new.goal(), old.goal());
            assert_eq!(new.author(), old.author());
            assert_eq!(new.target(), old.target());
            assert_eq!(new.override_authorities, vec![authority]);
            assert_eq!(new.supersedes, vec![predecessor]);
            assert_eq!(new.roster_predecessors, vec![predecessor]);
            assert_eq!(request_target(&mut board_ws, &old), TEST_TARGET);
            assert_eq!(request_target(&mut board_ws, &new), TEST_TARGET);
            assert_eq!(
                active_request_ids_for_goal(&board_space, goal),
                vec![successor]
            );
            assert_eq!(all_request_ids_for_goal(&board_space, goal).len(), 2);
            assert_eq!(
                all_attestation_ids_for_reviewer(
                    &board_space,
                    predecessor,
                    reviewers[0]
                )
                .len(),
                1
            );
            assert_eq!(
                all_attestation_ids_for_reviewer(
                    &board_space,
                    predecessor,
                    reviewers[1]
                )
                .len(),
                1
            );
            Ok(())
        })
        .unwrap();
        assert!(matches!(
            cli_evaluation(pile.path(), branch, goal).state,
            ReviewGateState::Pending {
                submitted: 0,
                required: 2
            }
        ));

        cmd_review_submit(
            pile.path(),
            branch,
            format!("{successor:x}"),
            VerdictArg::Abstain,
            "fresh author attestation".to_string(),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap();
        cmd_review_submit(
            pile.path(),
            branch,
            format!("{successor:x}"),
            VerdictArg::Approve,
            "fresh independent attestation".to_string(),
            Some(&format!("{:x}", reviewers[1])),
        )
        .unwrap();
        cmd_review_settle(
            pile.path(),
            branch,
            format!("{successor:x}"),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap();
        assert!(matches!(
            cli_evaluation(pile.path(), branch, goal).state,
            ReviewGateState::Settled { .. }
        ));

        assert!(Cli::try_parse_from([
            "compass",
            "--pile",
            "fixture.pile",
            "review",
            "supersede",
            "abcd",
            "--review-group",
            "review-pair",
            "--target",
            TEST_TARGET,
        ])
        .is_err());
    }

    #[test]
    fn cli_open_rejects_all_same_target_rewrites_and_same_target_fork_repair() {
        let pile = TestPile::new();
        let (branch, goal, reviewers, triad) = seed_cli_review(pile.path(), 3).unwrap();
        let base = open_cli_review(pile.path(), branch, goal, &reviewers, triad).unwrap();

        let idempotent = open_cli_review(pile.path(), branch, goal, &reviewers, triad).unwrap();
        assert_eq!(idempotent, base);
        with_repo(pile.path(), |repo| {
            let mut ws = repo
                .pull(branch)
                .map_err(|e| anyhow::anyhow!("pull compass: {e:?}"))?;
            let space = ws
                .checkout(..)
                .map_err(|e| anyhow::anyhow!("checkout compass: {e:?}"))?;
            assert_eq!(all_request_ids_for_goal(&space, goal), vec![base]);
            Ok(())
        })
        .unwrap();

        let author_rewrite = cmd_review_open(
            pile.path(),
            branch,
            format!("{goal:x}"),
            TEST_TARGET.to_string(),
            false,
            format!("{triad:x}"),
            Vec::new(),
            Some(&format!("{:x}", reviewers[1])),
        )
        .unwrap_err();
        assert!(format!("{author_rewrite:#}").contains("same-target review fields"));

        let pair = add_cli_group(pile.path(), &reviewers[..2]);
        let roster_rewrite = cmd_review_open(
            pile.path(),
            branch,
            format!("{goal:x}"),
            TEST_TARGET.to_string(),
            false,
            format!("{pair:x}"),
            Vec::new(),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap_err();
        assert!(format!("{roster_rewrite:#}").contains("same-target review fields"));

        let override_rewrite = cmd_review_open(
            pile.path(),
            branch,
            format!("{goal:x}"),
            TEST_TARGET.to_string(),
            false,
            format!("{triad:x}"),
            vec![format!("{:x}", reviewers[2])],
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap_err();
        assert!(format!("{override_rewrite:#}").contains("same-target review fields"));
        assert_eq!(
            active_request_ids_for_goal_in_pile(pile.path(), branch, goal),
            vec![base]
        );

        let left_target =
            "urn:blake3:7777777777777777777777777777777777777777777777777777777777777777";
        let right_target =
            "urn:blake3:8888888888888888888888888888888888888888888888888888888888888888";
        let repair_target =
            "urn:blake3:9999999999999999999999999999999999999999999999999999999999999999";
        let left = inject_cli_request_successor(pile.path(), branch, base, left_target);
        let right = inject_cli_request_successor(pile.path(), branch, base, right_target);
        let same_target_fork_repair = cmd_review_open(
            pile.path(),
            branch,
            format!("{goal:x}"),
            left_target.to_string(),
            false,
            format!("{triad:x}"),
            Vec::new(),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap_err();
        assert!(format!("{same_target_fork_repair:#}")
            .contains("same-target fork repair is deliberately unsupported"));
        let mut fork = vec![left, right];
        fork.sort();
        assert_eq!(
            active_request_ids_for_goal_in_pile(pile.path(), branch, goal),
            fork
        );

        cmd_review_open(
            pile.path(),
            branch,
            format!("{goal:x}"),
            repair_target.to_string(),
            false,
            format!("{triad:x}"),
            Vec::new(),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap();
        let repaired = active_request_ids_for_goal_in_pile(pile.path(), branch, goal);
        assert_eq!(repaired.len(), 1);
        assert!(!repaired.contains(&left));
        assert!(!repaired.contains(&right));
    }

    #[test]
    fn cli_supersede_rejects_transitive_add_then_remove_evidence_laundering() {
        let pile = TestPile::new();
        let (branch, goal, reviewers, all_four) = seed_cli_review(pile.path(), 4).unwrap();
        let triad = add_cli_group(pile.path(), &reviewers[..3]);
        let grandparent =
            open_cli_review(pile.path(), branch, goal, &reviewers[..3], triad).unwrap();
        inject_cli_attestation(
            pile.path(),
            branch,
            grandparent,
            reviewers[2],
            VERDICT_REQUEST_CHANGES,
            &[],
        );

        cmd_review_supersede(
            pile.path(),
            branch,
            format!("{grandparent:x}"),
            format!("{all_four:x}"),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap();
        let parent = active_request_ids_for_goal_in_pile(pile.path(), branch, goal)[0];
        let without_dissenter =
            add_cli_group(pile.path(), &[reviewers[0], reviewers[1], reviewers[3]]);
        let err = cmd_review_supersede(
            pile.path(),
            branch,
            format!("{parent:x}"),
            format!("{without_dissenter:x}"),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap_err();
        let rendered = format!("{err:#}");
        assert!(rendered.contains("cannot create unsafe roster successor"));
        assert!(rendered.contains(&format!("{grandparent:x}")));
        assert_eq!(
            active_request_ids_for_goal_in_pile(pile.path(), branch, goal),
            vec![parent]
        );
    }

    #[test]
    fn cli_supersede_never_drops_any_submitted_evidence() {
        for case in [
            "approve",
            "dissent",
            "abstain",
            "unknown",
            "malformed",
            "fork",
            "historical-stale",
        ] {
            let pile = TestPile::new();
            let (branch, goal, reviewers, triad) = seed_cli_review(pile.path(), 3).unwrap();
            let predecessor =
                open_cli_review(pile.path(), branch, goal, &reviewers, triad).unwrap();
            let removed = reviewers[2];
            let expected_records = match case {
                "approve" => {
                    inject_cli_attestation(
                        pile.path(),
                        branch,
                        predecessor,
                        removed,
                        VERDICT_APPROVE,
                        &[],
                    );
                    1
                }
                "dissent" => {
                    inject_cli_attestation(
                        pile.path(),
                        branch,
                        predecessor,
                        removed,
                        VERDICT_REQUEST_CHANGES,
                        &[],
                    );
                    1
                }
                "abstain" => {
                    inject_cli_attestation(
                        pile.path(),
                        branch,
                        predecessor,
                        removed,
                        VERDICT_ABSTAIN,
                        &[],
                    );
                    1
                }
                "unknown" => {
                    inject_cli_attestation(
                        pile.path(),
                        branch,
                        predecessor,
                        removed,
                        "shrug",
                        &[],
                    );
                    1
                }
                "malformed" => {
                    let id = inject_cli_attestation(
                        pile.path(),
                        branch,
                        predecessor,
                        removed,
                        VERDICT_APPROVE,
                        &[],
                    );
                    backpatch_cli_entity(
                        pile.path(),
                        branch,
                        entity! { ExclusiveId::force_ref(&id) @ review::verdict: "also" },
                    );
                    1
                }
                "fork" => {
                    inject_cli_attestation(
                        pile.path(),
                        branch,
                        predecessor,
                        removed,
                        VERDICT_APPROVE,
                        &[],
                    );
                    inject_cli_attestation(
                        pile.path(),
                        branch,
                        predecessor,
                        removed,
                        VERDICT_REQUEST_CHANGES,
                        &[],
                    );
                    2
                }
                "historical-stale" => {
                    let old = inject_cli_attestation(
                        pile.path(),
                        branch,
                        predecessor,
                        removed,
                        VERDICT_APPROVE,
                        &[],
                    );
                    inject_cli_attestation(
                        pile.path(),
                        branch,
                        predecessor,
                        removed,
                        VERDICT_APPROVE,
                        &[old],
                    );
                    2
                }
                _ => unreachable!(),
            };
            let pair = add_cli_group(pile.path(), &reviewers[..2]);
            with_repo(pile.path(), |repo| {
                let mut ws = repo
                    .pull(branch)
                    .map_err(|e| anyhow::anyhow!("pull compass: {e:?}"))?;
                let space = ws
                    .checkout(..)
                    .map_err(|e| anyhow::anyhow!("checkout compass: {e:?}"))?;
                assert_eq!(
                    all_attestation_ids_for_reviewer(&space, predecessor, removed).len(),
                    expected_records,
                    "case {case}"
                );
                Ok(())
            })
            .unwrap();
            let err = cmd_review_supersede(
                pile.path(),
                branch,
                format!("{predecessor:x}"),
                format!("{pair:x}"),
                Some(&format!("{:x}", reviewers[0])),
            )
            .unwrap_err();
            let message = format!("{err:#}");
            assert!(message.contains("cannot remove reviewer"), "case {case}: {message}");
            assert!(
                message.contains(&format!("{expected_records} submitted attestation record")),
                "case {case}: {message}"
            );
            assert_eq!(
                active_request_ids_for_goal_in_pile(pile.path(), branch, goal),
                vec![predecessor],
                "case {case}"
            );
        }
    }

    #[test]
    fn cli_supersede_requires_a_valid_active_roster_and_the_frozen_author() {
        let author_only_pile = TestPile::new();
        let (branch, goal, reviewers, triad) =
            seed_cli_review(author_only_pile.path(), 3).unwrap();
        let predecessor = open_cli_review(
            author_only_pile.path(),
            branch,
            goal,
            &reviewers,
            triad,
        )
        .unwrap();
        let author_only = add_cli_group(author_only_pile.path(), &reviewers[..1]);
        let err = cmd_review_supersede(
            author_only_pile.path(),
            branch,
            format!("{predecessor:x}"),
            format!("{author_only:x}"),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("at least one distinct non-author reviewer"));

        let missing_author_pile = TestPile::new();
        let (branch, goal, reviewers, triad) =
            seed_cli_review(missing_author_pile.path(), 3).unwrap();
        let predecessor = open_cli_review(
            missing_author_pile.path(),
            branch,
            goal,
            &reviewers,
            triad,
        )
        .unwrap();
        let missing_author = add_cli_group(missing_author_pile.path(), &reviewers[1..]);
        let err = cmd_review_supersede(
            missing_author_pile.path(),
            branch,
            format!("{predecessor:x}"),
            format!("{missing_author:x}"),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("must include the author persona"));

        let inactive_pile = TestPile::new();
        let (branch, goal, reviewers, triad) = seed_cli_review(inactive_pile.path(), 3).unwrap();
        let predecessor =
            open_cli_review(inactive_pile.path(), branch, goal, &reviewers, triad).unwrap();
        let inactive_group = add_cli_group(inactive_pile.path(), &reviewers[..2]);
        retire_cli_person(inactive_pile.path(), reviewers[1]);
        let err = cmd_review_supersede(
            inactive_pile.path(),
            branch,
            format!("{predecessor:x}"),
            format!("{inactive_group:x}"),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("inactive or non-person members"));

        let wrong_author_pile = TestPile::new();
        let (branch, goal, reviewers, triad) =
            seed_cli_review(wrong_author_pile.path(), 3).unwrap();
        let predecessor = open_cli_review(
            wrong_author_pile.path(),
            branch,
            goal,
            &reviewers,
            triad,
        )
        .unwrap();
        let pair = add_cli_group(wrong_author_pile.path(), &reviewers[..2]);
        let outsider = add_active_cli_person(wrong_author_pile.path());
        let err = cmd_review_supersede(
            wrong_author_pile.path(),
            branch,
            format!("{predecessor:x}"),
            format!("{pair:x}"),
            Some(&format!("{outsider:x}")),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("only frozen request author"));
    }

    #[test]
    fn cli_supersede_refuses_settled_stale_forked_and_malformed_requests() {
        let settled_pile = TestPile::new();
        let (branch, goal, reviewers, pair) = seed_cli_review(settled_pile.path(), 2).unwrap();
        let request =
            open_cli_review(settled_pile.path(), branch, goal, &reviewers, pair).unwrap();
        for (reviewer, verdict) in [
            (reviewers[0], VerdictArg::Abstain),
            (reviewers[1], VerdictArg::Approve),
        ] {
            cmd_review_submit(
                settled_pile.path(),
                branch,
                format!("{request:x}"),
                verdict,
                "settlement fixture".to_string(),
                Some(&format!("{reviewer:x}")),
            )
            .unwrap();
        }
        cmd_review_settle(
            settled_pile.path(),
            branch,
            format!("{request:x}"),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap();
        let third = add_active_cli_person(settled_pile.path());
        let larger = add_cli_group(
            settled_pile.path(),
            &[reviewers[0], reviewers[1], third],
        );
        let err = cmd_review_supersede(
            settled_pile.path(),
            branch,
            format!("{request:x}"),
            format!("{larger:x}"),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("cannot supersede settled"));

        let stale_pile = TestPile::new();
        let (branch, goal, reviewers, triad) = seed_cli_review(stale_pile.path(), 3).unwrap();
        let stale = open_cli_review(stale_pile.path(), branch, goal, &reviewers, triad).unwrap();
        let current = inject_cli_request_successor(
            stale_pile.path(),
            branch,
            stale,
            "urn:blake3:2222222222222222222222222222222222222222222222222222222222222222",
        );
        let pair = add_cli_group(stale_pile.path(), &reviewers[..2]);
        let err = cmd_review_supersede(
            stale_pile.path(),
            branch,
            format!("{stale:x}"),
            format!("{pair:x}"),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("not the unique current review head"));
        assert_eq!(
            active_request_ids_for_goal_in_pile(stale_pile.path(), branch, goal),
            vec![current]
        );

        let forked_pile = TestPile::new();
        let (branch, goal, reviewers, triad) = seed_cli_review(forked_pile.path(), 3).unwrap();
        let base = open_cli_review(forked_pile.path(), branch, goal, &reviewers, triad).unwrap();
        let left = inject_cli_request_successor(
            forked_pile.path(),
            branch,
            base,
            "urn:blake3:3333333333333333333333333333333333333333333333333333333333333333",
        );
        let right = inject_cli_request_successor(
            forked_pile.path(),
            branch,
            base,
            "urn:blake3:4444444444444444444444444444444444444444444444444444444444444444",
        );
        let pair = add_cli_group(forked_pile.path(), &reviewers[..2]);
        let err = cmd_review_supersede(
            forked_pile.path(),
            branch,
            format!("{left:x}"),
            format!("{pair:x}"),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("not the unique current review head"));
        let mut expected = vec![left, right];
        expected.sort();
        assert_eq!(
            active_request_ids_for_goal_in_pile(forked_pile.path(), branch, goal),
            expected
        );

        let malformed_pile = TestPile::new();
        let (branch, goal, reviewers, triad) = seed_cli_review(malformed_pile.path(), 3).unwrap();
        let malformed =
            open_cli_review(malformed_pile.path(), branch, goal, &reviewers, triad).unwrap();
        let injected_target =
            "urn:blake3:5555555555555555555555555555555555555555555555555555555555555555"
                .to_string()
                .to_blob()
                .get_handle();
        backpatch_cli_entity(
            malformed_pile.path(),
            branch,
            entity! { ExclusiveId::force_ref(&malformed) @ metadata::iri: injected_target },
        );
        let pair = add_cli_group(malformed_pile.path(), &reviewers[..2]);
        let err = cmd_review_supersede(
            malformed_pile.path(),
            branch,
            format!("{malformed:x}"),
            format!("{pair:x}"),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("cannot supersede malformed"));
        assert_eq!(
            active_request_ids_for_goal_in_pile(malformed_pile.path(), branch, goal),
            vec![malformed]
        );

        let bypass = cmd_review_open(
            malformed_pile.path(),
            branch,
            format!("{goal:x}"),
            TEST_TARGET.to_string(),
            false,
            format!("{pair:x}"),
            Vec::new(),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap_err();
        assert!(format!("{bypass:#}").contains("must preserve its frozen author/roster/override"));

        cmd_review_open(
            malformed_pile.path(),
            branch,
            format!("{goal:x}"),
            "urn:blake3:6666666666666666666666666666666666666666666666666666666666666666"
                .to_string(),
            false,
            format!("{triad:x}"),
            Vec::new(),
            Some(&format!("{:x}", reviewers[0])),
        )
        .unwrap();
        assert_ne!(
            active_request_ids_for_goal_in_pile(malformed_pile.path(), branch, goal),
            vec![malformed]
        );
    }

    #[test]
    fn cli_triad_gate_remains_all_required() {
        let pile = TestPile::new();
        let (branch, goal, reviewers, group) = seed_cli_review(pile.path(), 3).unwrap();
        let request = open_cli_review(pile.path(), branch, goal, &reviewers, group).unwrap();
        for (reviewer, verdict) in [
            (reviewers[0], VerdictArg::Abstain),
            (reviewers[1], VerdictArg::Approve),
        ] {
            cmd_review_submit(
                pile.path(),
                branch,
                format!("{request:x}"),
                verdict,
                "triad review evidence".to_string(),
                Some(&format!("{reviewer:x}")),
            )
            .unwrap();
        }
        assert!(matches!(
            cli_evaluation(pile.path(), branch, goal).state,
            ReviewGateState::Pending {
                submitted: 2,
                required: 3
            }
        ));
        assert!(cmd_review_gate(pile.path(), branch, format!("{request:x}")).is_err());

        cmd_review_submit(
            pile.path(),
            branch,
            format!("{request:x}"),
            VerdictArg::Approve,
            "second peer approves".to_string(),
            Some(&format!("{:x}", reviewers[2])),
        )
        .unwrap();
        assert!(matches!(
            cli_evaluation(pile.path(), branch, goal).state,
            ReviewGateState::Ready
        ));
    }

    #[test]
    fn cli_five_person_gate_has_no_cardinality_cutoff() {
        let pile = TestPile::new();
        let (branch, goal, reviewers, group) = seed_cli_review(pile.path(), 5).unwrap();
        let request = open_cli_review(pile.path(), branch, goal, &reviewers, group).unwrap();
        for (index, reviewer) in reviewers.iter().enumerate().take(4) {
            let verdict = if index == 0 {
                VerdictArg::Abstain
            } else {
                VerdictArg::Approve
            };
            cmd_review_submit(
                pile.path(),
                branch,
                format!("{request:x}"),
                verdict,
                "large-council review evidence".to_string(),
                Some(&format!("{reviewer:x}")),
            )
            .unwrap();
        }
        assert!(matches!(
            cli_evaluation(pile.path(), branch, goal).state,
            ReviewGateState::Pending {
                submitted: 4,
                required: 5
            }
        ));
        assert!(cmd_review_gate(pile.path(), branch, format!("{request:x}")).is_err());

        cmd_review_submit(
            pile.path(),
            branch,
            format!("{request:x}"),
            VerdictArg::Approve,
            "final council member approves".to_string(),
            Some(&format!("{:x}", reviewers[4])),
        )
        .unwrap();
        assert!(matches!(
            cli_evaluation(pile.path(), branch, goal).state,
            ReviewGateState::Ready
        ));
    }

    #[test]
    fn cli_roster_validator_preserves_active_external_requirement() {
        let author = ufoid().id;
        let peer = ufoid().id;
        let third = ufoid().id;
        let fourth = ufoid().id;
        let fifth = ufoid().id;
        let active = HashSet::from([author, peer, third, fourth, fifth]);

        assert!(validate_frozen_review_roster(&[author, peer], author, &active).is_ok());
        assert!(validate_frozen_review_roster(&[author, peer, third], author, &active).is_ok());
        assert!(validate_frozen_review_roster(
            &[author, peer, third, fourth, fifth],
            author,
            &active
        )
        .is_ok());
        assert!(validate_frozen_review_roster(&[author], author, &active).is_err());
        assert!(validate_frozen_review_roster(&[peer, third], author, &active).is_err());
        assert!(validate_frozen_review_roster(&[author, ufoid().id], author, &active).is_err());
    }

    #[test]
    fn git_review_target_requires_a_full_object_id() {
        assert!(validate_review_target(
            "git+https://example.test/repo@1111111111111111111111111111111111111111",
            false,
        )
        .is_ok());
        assert!(validate_review_target("git+https://example.test/repo@main", false).is_err());
        assert!(validate_review_target("git+https://example.test/repo@1234abcd", false).is_err());
        assert!(validate_review_target("https://example.test/repo/main", false).is_err());
        assert!(validate_review_target("https://example.test/repo/main", true).is_ok());
        assert!(validate_review_target(
            "files:1111111111111111111111111111111111111111111111111111111111111111",
            false,
        )
        .is_ok());
    }

    #[test]
    fn exact_request_commands_reject_each_head_of_a_fork() {
        let goal = ufoid().id;
        let author = ufoid().id;
        let reviewers = [author, ufoid().id, ufoid().id];
        let target = "urn:blake3:1111111111111111111111111111111111111111111111111111111111111111"
            .to_blob()
            .get_handle();
        let now = epoch_interval(Epoch::from_gregorian_utc(2026, 7, 13, 12, 0, 0, 0));
        let base = review_request_fragment(goal, author, target, &reviewers, &[], &[], now);
        let base_id = base.root().unwrap();
        let left = review_request_fragment(
            goal,
            author,
            target,
            &reviewers,
            &[],
            &[base_id],
            now,
        );
        let left_id = left.root().unwrap();
        let right = review_request_fragment(
            goal,
            author,
            target,
            &reviewers,
            &[],
            &[base_id],
            later_interval_for_test(),
        );
        let right_id = right.root().unwrap();
        let mut space = TribleSet::new();
        space += entity! { ExclusiveId::force_ref(&goal) @ metadata::tag: &KIND_GOAL_ID };
        space += base;
        space += left;
        space += right;

        assert!(!request_is_active(&space, left_id));
        assert!(!request_is_active(&space, right_id));
    }

    #[test]
    fn frozen_review_role_survives_soft_retirement() {
        let person = ufoid().id;
        let mut space = TribleSet::new();
        space += entity! { ExclusiveId::force_ref(&person) @
            metadata::tag: &KIND_PERSON_ID,
        };
        let known = HashSet::from([person]);
        let active = HashSet::new();
        let input = format!("{person:x}");

        assert!(resolve_active_person(&space, &active, &input).is_err());
        assert_eq!(
            resolve_frozen_person(&space, &known, &input).unwrap(),
            person
        );
    }

    fn later_interval_for_test() -> IntervalValue {
        epoch_interval(Epoch::from_gregorian_utc(2026, 7, 13, 12, 0, 1, 0))
    }
}
