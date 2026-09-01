//! Read-only diagnostics over one immutable collection snapshot.
//!
//! Triage intentionally owns no branch, chain, repair protocol, or mutable
//! workspace. Every command freezes the pile once and projects the canonical
//! faculty collections it needs from that same snapshot under each
//! collection's explicit admission policy.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::PathBuf;

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use faculties::cognition as cognition_model;
use faculties::memory::{self as memory_model};
use faculties::memory_cover::{
    all_chunk_ids, chunk_about_archive_message, chunk_about_exec_result, chunk_aliases,
    chunk_end_at, chunk_image_handle, chunk_lens_handle, chunk_observed_at, chunk_references,
    chunk_start_at, chunk_summary_handle,
};
use faculties::message as message_model;
use faculties::relations as relations_model;
use faculties::schemas::cognition::DEFAULT_SCOPE_ID as COGNITION_SCOPE_ID;
use faculties::schemas::headspace::DEFAULT_SCOPE_ID as HEADSPACE_SCOPE_ID;
use faculties::schemas::memory::DEFAULT_SCOPE_ID as MEMORY_SCOPE_ID;
use faculties::schemas::message::DEFAULT_SCOPE_ID as MESSAGE_SCOPE_ID;
use faculties::schemas::relations::DEFAULT_SCOPE_ID as RELATIONS_SCOPE_ID;
use faculties::schemas::triage::cog;
use faculties::secrets::storage::{self as vaults, VaultDiscovery};
use faculties::storage::{load_signer, open_pile_strict};
use faculties::triage::{
    self as triage_model, build_loop_report, collect_exec_state, collect_model_chat_state,
    collect_reason_state, ExecRequestRow, ExecState, ModelChatState, ModelResultRow,
    ReasonEventRow, ScanOptions, ScanSources, SourceView, TriageHeadspace, UnreadMessages,
    UnreadUnavailable,
};
use hifitime::Epoch;
use serde::{Deserialize, Serialize};
use triblespace::core::repo::memoryrepo::MemoryRepo;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::{BlobStoreGet, BlobStoreMeta};
use triblespace::macros::{find, pattern};
use triblespace::prelude::blobencodings::SimpleArchive;
use triblespace::prelude::*;

type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;
type Interval = Inline<inlineencodings::NsTAIInterval>;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "triage",
    about = "Doctor-style diagnostics over canonical faculty collections"
)]
struct Cli {
    /// Path to the pile file to inspect.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Full health scan with queue and loop heuristics.
    Scan {
        /// Max recent exec attempts used for loop diagnostics.
        #[arg(long, default_value_t = 40)]
        recent: usize,
        /// Minimum repeated attempts to report as a probable loop.
        #[arg(long, default_value_t = 3)]
        loop_min: usize,
        /// Mark in-progress requests older than this as stale.
        #[arg(long, default_value_t = 15)]
        stale_min: i64,
    },
    /// Show recent exec attempts and repeated failure patterns.
    Loops {
        #[arg(long, default_value_t = 40)]
        recent: usize,
        #[arg(long, default_value_t = 3)]
        min_repeat: usize,
    },
    /// Show an interleaved recent activity timeline (exec/model/reason).
    Timeline {
        /// Max events to print (newest first).
        #[arg(long, default_value_t = 80)]
        recent: usize,
    },
    /// Show every canonical Memory chunk and the context budget.
    Cover {
        /// Show complete text instead of a one-line preview.
        #[arg(long)]
        full: bool,
    },
    /// Inspect every canonical Memory chunk or alias matching an ID prefix.
    Chunk {
        /// Intrinsic node ID or historical alias prefix.
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Inspect a full turn cycle: context in, model output, command, exec result.
    Turn {
        /// Nth most recent exec request (1 = latest).
        #[arg(long, default_value_t = 1)]
        turn: usize,
        /// Show full content (context messages, stdout, reasoning).
        #[arg(long)]
        full: bool,
    },
    /// Show every assembled context recorded for a recent turn.
    Context {
        /// Nth most recent exec request (1 = latest).
        #[arg(long, default_value_t = 1)]
        turn: usize,
        /// Show full message content.
        #[arg(long)]
        full: bool,
        /// Dump raw JSON, retaining every context candidate.
        #[arg(long)]
        raw: bool,
    },
}

/// One canonical collection value observed through the frozen pile prefix.
struct CollectionView {
    facts: TribleSet,
    reader: PileSnapshot,
}

impl CollectionView {
    fn source(&self) -> SourceView<'_> {
        SourceView {
            facts: &self.facts,
            reader: &self.reader,
        }
    }
}

/// One immutable pile world plus one explicit local signing identity.
struct TriageSnapshot {
    pile_path: PathBuf,
    pile: RefCell<Option<Pile>>,
    signer: SigningKey,
    store_snapshot: PileSnapshot,
    collections: std::collections::BTreeMap<Id, Collection<SimpleArchive>>,
}

impl TriageSnapshot {
    fn open(cli: &Cli) -> Result<Self> {
        // Loading is deliberately strict: a diagnostic read must never mint a
        // new identity, create a pile, or admit somebody else's COMMITs.
        let signer = load_signer(&cli.pile, cli.key.as_deref())?;
        let mut pile = open_pile_strict(&cli.pile)?;
        let store_snapshot = pile
            .snapshot()
            .context("freeze Triage native store snapshot")?;
        let mut registry = MemoryRepo::default();
        let mut collections = std::collections::BTreeMap::new();
        for scope in [
            COGNITION_SCOPE_ID,
            HEADSPACE_SCOPE_ID,
            MEMORY_SCOPE_ID,
            RELATIONS_SCOPE_ID,
            MESSAGE_SCOPE_ID,
        ] {
            let collection = match faculties::collection_names::configured_handle(scope)? {
                Some(handle) => faculties::collection_names::open_exact_in(
                    &store_snapshot,
                    scope,
                    signer.verifying_key(),
                    handle,
                )?,
                None => {
                    faculties::collection_names::open(&mut registry, scope, signer.verifying_key())
                        .with_context(|| {
                            format!(
                                "register {} collection",
                                faculties::collection_names::require_name(scope)
                            )
                        })?
                }
            };
            collections.insert(scope, collection);
        }
        Ok(Self {
            pile_path: cli.pile.clone(),
            pile: RefCell::new(Some(pile)),
            signer,
            store_snapshot,
            collections,
        })
    }

    fn view(&self, scope: Id, label: &str) -> Result<CollectionView> {
        let collection = self
            .collections
            .get(&scope)
            .copied()
            .with_context(|| format!("{label} collection was not registered in snapshot"))?;
        let facts = if self
            .store_snapshot
            .metadata(collection.handle())
            .with_context(|| format!("inspect {label} collection descriptor"))?
            .is_some()
        {
            faculties::storage::read_fact_collection(collection, &self.store_snapshot)
                .map(|(facts, _)| facts)
                .with_context(|| format!("materialize {label} collection"))?
        } else {
            TribleSet::new()
        };
        Ok(CollectionView {
            facts,
            reader: self.store_snapshot.clone(),
        })
    }

    fn cognition(&self) -> Result<CollectionView> {
        let view = self.view(COGNITION_SCOPE_ID, "Cognition")?;
        cognition_model::validate_catalog(&view.reader, &view.facts)
            .context("validate Cognition collection")?;
        Ok(view)
    }

    fn headspace(&self) -> Result<(CollectionView, TriageHeadspace)> {
        let secrets = self.secrets()?;
        let view = self.view(HEADSPACE_SCOPE_ID, "Headspace")?;
        let projected = triage_model::project_headspace(view.source(), secrets.snapshot())?;
        Ok((view, projected))
    }

    fn secrets(&self) -> Result<VaultDiscovery> {
        let mut pile = self.pile.borrow_mut();
        let pile = pile
            .as_mut()
            .ok_or_else(|| anyhow!("Triage snapshot is already closed"))?;
        vaults::discover_local_vaults(pile, &self.signer)
            .context("discover readable Secrets vaults")
    }

    fn memory(&self) -> Result<CollectionView> {
        let view = self.view(MEMORY_SCOPE_ID, "Memory")?;
        memory_model::validate_catalog(&view.reader, &view.facts)
            .context("validate Memory collection")?;
        Ok(view)
    }

    fn relations(&self) -> Result<CollectionView> {
        let view = self.view(RELATIONS_SCOPE_ID, "Relations")?;
        relations_model::validate_catalog(&view.reader, &view.facts)
            .context("validate Relations collection")?;
        Ok(view)
    }

    fn messages(&self, relations: &CollectionView) -> Result<CollectionView> {
        let view = self.view(MESSAGE_SCOPE_ID, "Message")?;
        message_model::validate_catalog(&view.reader, &view.facts, &relations.facts)
            .context("validate Message collection")?;
        Ok(view)
    }

    fn close(self, result: Result<()>) -> Result<()> {
        let close = self.close_inner();
        match (result, close) {
            (Ok(()), Ok(())) => Ok(()),
            (Ok(()), Err(error)) | (Err(error), Ok(())) => Err(error),
            (Err(error), Err(close_error)) => {
                Err(error.context(format!("also failed to close Triage pile: {close_error}")))
            }
        }
    }

    fn close_inner(&self) -> Result<()> {
        let Some(pile) = self.pile.borrow_mut().take() else {
            return Ok(());
        };
        pile.close()
            .with_context(|| format!("close Triage pile {}", self.pile_path.display()))
    }
}

impl Drop for TriageSnapshot {
    fn drop(&mut self) {
        let _ = self.close_inner();
    }
}

#[derive(Debug, Clone)]
struct TimelineRow {
    at: i128,
    source: &'static str,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ChatRole {
    System,
    User,
    Assistant,
}

impl std::fmt::Display for ChatRole {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::System => formatter.write_str("system"),
            Self::User => formatter.write_str("user"),
            Self::Assistant => formatter.write_str("assistant"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatMessage {
    role: ChatRole,
    content: String,
}

#[derive(Debug, Clone)]
struct ContextCandidate {
    result: Id,
    thought: Id,
    messages: Vec<ChatMessage>,
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn now_key() -> Result<i128> {
    triage_model::now_tai_ns()
}

fn interval_key(interval: Interval) -> i128 {
    triage_model::interval_key(interval)
}

fn format_tai_ns(ns: i128) -> String {
    let ns = ns.clamp(i64::MIN as i128, i64::MAX as i128) as i64;
    let epoch = Epoch::from_tai_duration(hifitime::Duration::from_truncated_nanoseconds(ns));
    let (year, month, day, hour, minute, second, _) = epoch.to_gregorian_utc();
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}")
}

fn format_age(now: i128, past: i128) -> String {
    let seconds = (now.saturating_sub(past) / 1_000_000_000).max(0) as i64;
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3_600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h", seconds / 3_600)
    } else {
        format!("{}d", seconds / 86_400)
    }
}

fn format_duration_ns(ns: i128) -> String {
    let ns = ns.max(0);
    let milliseconds = ns / 1_000_000;
    if milliseconds < 1_000 {
        format!("{milliseconds}ms")
    } else if milliseconds < 60_000 {
        format!("{:.2}s", milliseconds as f64 / 1_000.0)
    } else {
        format!("{:.1}m", milliseconds as f64 / 60_000.0)
    }
}

fn format_exit_code(code: Option<u64>) -> String {
    code.map(|code| code.to_string())
        .unwrap_or_else(|| "-".to_owned())
}

fn truncate_single_line(text: &str, max: usize) -> String {
    let mut out = String::with_capacity(max + 3);
    for ch in text.chars() {
        if out.chars().count() >= max {
            out.push_str("...");
            break;
        }
        out.push(if ch == '\n' || ch == '\r' { ' ' } else { ch });
    }
    out
}

fn first_line(text: &str) -> String {
    text.lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or(text)
        .trim()
        .to_owned()
}

fn read_text(reader: &PileSnapshot, handle: TextHandle) -> Result<String> {
    let view: View<str> = reader
        .get(handle)
        .with_context(|| format!("read UTF8String {}", hex::encode(handle.raw)))?;
    Ok(view.to_string())
}

fn at_most_one<T>(entity: Id, field: &str, values: Vec<T>) -> Result<Option<T>> {
    let count = values.len();
    let mut values = values.into_iter();
    match (values.next(), count) {
        (None, 0) => Ok(None),
        (Some(value), 1) => Ok(Some(value)),
        _ => bail!(
            "Cognition entity {entity:x} has {count} values for {field}; expected at most one"
        ),
    }
}

fn cmd_scan(
    cli: &Cli,
    snapshot: &TriageSnapshot,
    recent: usize,
    loop_min: usize,
    stale_min: i64,
) -> Result<()> {
    let cognition = snapshot.cognition()?;
    let headspace_view = snapshot.view(HEADSPACE_SCOPE_ID, "Headspace")?;
    let secrets = snapshot.secrets()?;
    let relations = snapshot.relations()?;
    let messages = snapshot.messages(&relations)?;
    let now = now_key()?;
    let stale_ns = stale_min.max(0) as i128 * 60 * 1_000_000_000;
    let report = triage_model::project_scan(
        ScanSources {
            cognition: cognition.source(),
            headspace: headspace_view.source(),
            secrets: secrets.snapshot(),
            relations: relations.source(),
            messages: messages.source(),
        },
        ScanOptions {
            now: Some(now),
            stale_after_ns: stale_ns,
            recent_attempts: recent,
            loop_min,
        },
    )?;

    println!("Triage scan");
    println!("- pile: {}", cli.pile.display());
    println!("- Cognition facts: {}", cognition.facts.len());
    let config_heads = report.headspace.config_heads();
    let active_profile_heads = report.headspace.active_profile_heads();
    if let Some(error) = report.headspace.unsettled_reason() {
        println!("- Headspace active state: unresolved ({error})");
    } else {
        let state = if config_heads.len() > 1 || active_profile_heads.len() > 1 {
            "agreed"
        } else {
            "unique"
        };
        println!(
            "- Headspace active state: {state} (config heads={}, profile heads={})",
            config_heads.len(),
            active_profile_heads.len()
        );
    }
    if let Some(persona) = report.headspace.persona_id {
        println!("- persona id: {persona:x}");
    }
    if !report.relations.forked_profiles.is_empty() {
        println!(
            "- Relations profile forks: {}",
            report.relations.forked_profiles.len()
        );
    }
    println!();
    println!("Queues");
    println!(
        "- exec: requests={} pending={} running={} age_unknown={} stale={} forked={} invalid={} done={}",
        report.exec_queue.requests,
        report.exec_queue.pending,
        report.exec_queue.running,
        report.exec_queue.age_unknown,
        report.exec_queue.stale,
        report.exec_queue.forked,
        report.exec_queue.invalid,
        report.exec_queue.done
    );
    println!(
        "- model: requests={} pending={} running={} age_unknown={} stale={} forked={} invalid={} done={}",
        report.model_queue.requests,
        report.model_queue.pending,
        report.model_queue.running,
        report.model_queue.age_unknown,
        report.model_queue.stale,
        report.model_queue.forked,
        report.model_queue.invalid,
        report.model_queue.done
    );
    match report.unread_messages {
        UnreadMessages::Available { count, .. } => {
            println!("- unread canonical inbox messages: {count}")
        }
        UnreadMessages::Unavailable(reason) => {
            let reason = match reason {
                UnreadUnavailable::HeadspaceUnsettled => "Headspace is unsettled",
                UnreadUnavailable::PersonaNotConfigured => "no persona is configured",
            };
            println!("- unread canonical inbox messages: unavailable ({reason})");
        }
    }

    println!();
    println!("Loop heuristics");
    if let Some(pattern) = report.probable_loop.as_ref() {
        println!(
            "- probable loop: {} repeated {}x (exit={}): {}",
            truncate_single_line(&pattern.command, 80),
            pattern.count,
            pattern
                .exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            truncate_single_line(&pattern.fingerprint, 120)
        );
    } else {
        println!("- no repeated failure loop >= {loop_min} in recent exec results");
    }

    let mut model_failures: Vec<_> = report
        .model_state
        .results
        .iter()
        .filter(|row| row.error.is_some())
        .collect();
    model_failures.sort_by_key(|row| (row.finished_at, row.id));
    model_failures.reverse();
    println!();
    println!("Recent model failures");
    if model_failures.is_empty() {
        println!("- none");
    }
    for row in model_failures.into_iter().take(recent.min(5)) {
        println!(
            "- {} | {}",
            format_age(now, row.finished_at),
            truncate_single_line(row.error.as_deref().unwrap_or("<missing error>"), 140)
        );
    }

    println!();
    println!("Suggested next checks");
    for suggestion in &report.suggestions {
        println!("- {suggestion}");
    }
    Ok(())
}

fn cmd_loops(snapshot: &TriageSnapshot, recent: usize, min_repeat: usize) -> Result<()> {
    let cognition = snapshot.cognition()?;
    let state = collect_exec_state(&cognition.reader, &cognition.facts)?;
    let report = build_loop_report(&state, recent, min_repeat);
    let now = now_key()?;
    println!("Triage loops");
    println!("- Cognition facts: {}", cognition.facts.len());
    println!("- recent attempts: {}", report.recent.len());
    if let Some(head) = &report.contiguous_head {
        println!(
            "- contiguous head loop: {}x, exit={}, command={}",
            head.count,
            head.exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            truncate_single_line(&head.command, 90)
        );
    } else {
        println!("- contiguous head loop: none (threshold {min_repeat})");
    }
    println!();
    println!("Top patterns");
    for pattern in report.top_patterns.iter().take(5) {
        println!(
            "- {}x | exit={} | {} | {}",
            pattern.count,
            pattern
                .exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            truncate_single_line(&pattern.command, 70),
            truncate_single_line(&pattern.fingerprint, 80)
        );
    }
    println!();
    println!("Recent attempts");
    for row in report.recent {
        println!(
            "- [{}:{}] {} | exit={} | {} | {}",
            fmt_id(row.request_id),
            fmt_id(row.result_id),
            format_age(now, row.finished_at),
            row.exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            truncate_single_line(&row.command, 70),
            truncate_single_line(&row.fingerprint, 90)
        );
    }
    Ok(())
}

fn build_timeline_rows(
    exec_state: &ExecState,
    model_state: &ModelChatState,
    reason_rows: &[ReasonEventRow],
    recent: usize,
) -> Vec<TimelineRow> {
    let mut rows = Vec::new();
    for request in exec_state.requests.values() {
        rows.push(TimelineRow {
            at: request.requested_at,
            source: "exec",
            detail: format!(
                "[{}] {}",
                fmt_id(request.id),
                truncate_single_line(&request.command, 120)
            ),
        });
    }
    for result in &exec_state.results {
        let command = exec_state
            .requests
            .get(&result.about_request)
            .map(|request| request.command.as_str())
            .unwrap_or("<missing request>");
        let status = result
            .error
            .as_deref()
            .map(|error| format!("error {}", truncate_single_line(error, 72)))
            .or_else(|| {
                result.stderr_text.as_deref().map(|stderr| {
                    format!(
                        "exit {} stderr {}",
                        format_exit_code(result.exit_code),
                        truncate_single_line(&first_line(stderr), 72)
                    )
                })
            })
            .unwrap_or_else(|| format!("exit {}", format_exit_code(result.exit_code)));
        rows.push(TimelineRow {
            at: result.finished_at,
            source: "exec-result",
            detail: format!(
                "[{}:{}] {} | {status}",
                fmt_id(result.about_request),
                fmt_id(result.id),
                truncate_single_line(command, 100)
            ),
        });
    }
    for request in model_state.requests.values() {
        rows.push(TimelineRow {
            at: request.requested_at,
            source: "model",
            detail: format!("[{}] request", fmt_id(request.id)),
        });
    }
    for result in &model_state.results {
        if let Some(error) = &result.error {
            rows.push(TimelineRow {
                at: result.finished_at,
                source: "model-error",
                detail: format!(
                    "[{}] {}",
                    fmt_id(result.id),
                    truncate_single_line(error, 130)
                ),
            });
        }
    }
    for row in reason_rows {
        let mut detail = format!("[{}] ", fmt_id(row.id));
        if let Some(turn) = row.about_turn {
            detail.push_str(&format!("[turn {}] ", fmt_id(turn)));
        }
        detail.push_str(&truncate_single_line(
            row.text.as_deref().unwrap_or("<missing>"),
            120,
        ));
        if let Some(command) = &row.command_text {
            detail.push_str(" | ");
            detail.push_str(&truncate_single_line(command, 96));
        }
        rows.push(TimelineRow {
            at: row.created_at.unwrap_or(i128::MIN),
            source: "reason",
            detail,
        });
    }
    rows.sort_by_key(|row| row.at);
    rows.reverse();
    rows.truncate(recent);
    rows
}

fn cmd_timeline(snapshot: &TriageSnapshot, recent: usize) -> Result<()> {
    let cognition = snapshot.cognition()?;
    let exec_state = collect_exec_state(&cognition.reader, &cognition.facts)?;
    let model_state = collect_model_chat_state(&cognition.reader, &cognition.facts)?;
    let reason_state = collect_reason_state(&cognition.reader, &cognition.facts)?;
    let rows = build_timeline_rows(&exec_state, &model_state, &reason_state, recent);
    let now = now_key()?;
    println!("Triage timeline");
    println!("- Cognition facts: {}", cognition.facts.len());
    println!("- rows: {}", rows.len());
    println!();
    for row in rows {
        println!(
            "- {:>5} {:>11} | {}",
            format_age(now, row.at),
            row.source,
            row.detail
        );
    }
    Ok(())
}

fn chunk_text(reader: &PileSnapshot, space: &TribleSet, id: Id) -> Result<String> {
    if let Some(handle) = chunk_summary_handle(space, id) {
        return memory_model::read_text(reader, handle);
    }
    if let Some(handle) = chunk_image_handle(space, id) {
        return Ok(format!(
            "<image: {} bytes>",
            memory_model::read_image(reader, handle)?.len()
        ));
    }
    Ok(String::new())
}

fn format_span(space: &TribleSet, id: Id) -> String {
    let (Some(s), Some(e)) = (chunk_start_at(space, id), chunk_end_at(space, id)) else {
        return "?".to_string();
    };
    let start = interval_key(s);
    let end = interval_key(e);
    format!(
        "{}..{} ({})",
        format_tai_ns(start),
        format_tai_ns(end),
        format_duration_ns(end.saturating_sub(start))
    )
}

fn cmd_cover(snapshot: &TriageSnapshot, full: bool) -> Result<()> {
    let memory = snapshot.memory()?;
    let (_, headspace) = snapshot.headspace()?;
    let space = &memory.facts;
    let mut chunk_ids = all_chunk_ids(space);
    chunk_ids.sort();
    let mut all_chunk_chars = 0usize;
    for id in &chunk_ids {
        all_chunk_chars += chunk_text(&memory.reader, space, *id)?.len();
    }
    let budget = headspace.budget()?;
    let fill = if budget.body_budget_chars > 0 {
        all_chunk_chars as f64 / budget.body_budget_chars as f64 * 100.0
    } else {
        0.0
    };
    println!("Memory cover");
    println!("- Memory facts: {}", memory.facts.len());
    println!("- chunks: {}", chunk_ids.len());
    println!();
    println!("Budget");
    println!(
        "- context={} output={} safety={} chars/token={}",
        budget.context_window_tokens,
        budget.max_output_tokens,
        budget.safety_margin_tokens,
        budget.chars_per_token
    );
    println!(
        "- system={} chars body={} chars all-chunks={} chars ratio={fill:.1}%",
        budget.system_prompt_chars, budget.body_budget_chars, all_chunk_chars
    );
    println!();
    println!("Chunks (canonical ID order; every episode coexists)");
    if chunk_ids.is_empty() {
        println!("- empty");
    }
    for id in chunk_ids {
        let text = chunk_text(&memory.reader, space, id)?;
        println!(
            "- chunk {} | {} | {}",
            fmt_id(id),
            format_span(space, id),
            if full {
                text
            } else {
                truncate_single_line(&text, 100)
            }
        );
    }
    Ok(())
}

fn matching_memory_nodes(space: &TribleSet, prefix: &str) -> BTreeSet<Id> {
    let prefix = prefix.trim().to_ascii_uppercase();
    let mut matches: BTreeSet<Id> = BTreeSet::new();
    for id in all_chunk_ids(space) {
        if format!("{id:X}").starts_with(&prefix)
            || chunk_aliases(space, id)
                .iter()
                .any(|alias| format!("{alias:X}").starts_with(&prefix))
        {
            matches.insert(id);
        }
    }
    matches
}

fn print_ids(label: &str, ids: impl IntoIterator<Item = Id>) {
    let ids: Vec<_> = ids.into_iter().collect();
    if !ids.is_empty() {
        println!(
            "  {label}: {}",
            ids.iter()
                .map(|id| fmt_id(*id))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

fn print_observations(observations: &[Interval]) {
    if !observations.is_empty() {
        println!("  observations:");
        for observation in observations {
            println!("    - {}", format_tai_ns(interval_key(*observation)));
        }
    }
}

fn cmd_chunk(snapshot: &TriageSnapshot, prefix: &str) -> Result<()> {
    let memory = snapshot.memory()?;
    let matches = matching_memory_nodes(&memory.facts, prefix);
    if matches.is_empty() {
        bail!("no canonical Memory chunk or alias matches prefix '{prefix}'");
    }
    println!(
        "Memory match set for '{prefix}' ({} chunk(s))",
        matches.len()
    );
    for (index, id) in matches.into_iter().enumerate() {
        if index > 0 {
            println!();
        }
        let space = &memory.facts;
        println!("Chunk {}", fmt_id(id));
        println!("  span: {}", format_span(space, id));
        print_ids("references", chunk_references(space, id).into_iter());
        print_ids("aliases", chunk_aliases(space, id).into_iter());
        if let Some(exec) = chunk_about_exec_result(space, id) {
            println!("  about exec result: {}", fmt_id(exec));
        }
        if let Some(message) = chunk_about_archive_message(space, id) {
            println!("  about archive message: {}", fmt_id(message));
        }
        if let Some(lens) = chunk_lens_handle(space, id) {
            println!("  lens: {}", memory_model::read_text(&memory.reader, lens)?);
        }
        print_observations(&chunk_observed_at(space, id));
        println!("  content:");
        for line in chunk_text(&memory.reader, space, id)?.lines() {
            println!("    {line}");
        }
    }
    Ok(())
}

fn select_request(state: &ExecState, turn: usize) -> Result<&ExecRequestRow> {
    if turn == 0 {
        bail!("turn is one-based");
    }
    let mut requests: Vec<_> = state.requests.values().collect();
    requests.sort_by_key(|request| (request.requested_at, request.id));
    requests.reverse();
    requests.get(turn - 1).copied().ok_or_else(|| {
        anyhow!(
            "turn #{turn} not found; only {} request(s) exist",
            requests.len()
        )
    })
}

fn contexts_for_turn(
    reader: &PileSnapshot,
    space: &TribleSet,
    exec_state: &ExecState,
    request: Id,
) -> Result<Vec<ContextCandidate>> {
    let mut pairs = BTreeSet::new();
    for result in exec_state
        .results
        .iter()
        .filter(|result| result.about_request == request)
    {
        if let Some(thought) = result.about_thought {
            pairs.insert((result.id, thought));
        }
    }
    let mut contexts = Vec::new();
    for (result, thought) in pairs {
        let handle = at_most_one(
            thought,
            "cog::context",
            find!(value: TextHandle, pattern!(space, [{ thought @ cog::context: ?value }]))
                .collect(),
        )?;
        if let Some(handle) = handle {
            let json = read_text(reader, handle)?;
            let messages = serde_json::from_str(&json)
                .with_context(|| format!("parse context JSON for thought {thought:x}"))?;
            contexts.push(ContextCandidate {
                result,
                thought,
                messages,
            });
        }
    }
    Ok(contexts)
}

fn print_model_result(row: &ModelResultRow, full: bool) {
    println!("  Model result {}", fmt_id(row.id));
    println!("    finished: {}", format_tai_ns(row.finished_at));
    if let Some(error) = &row.error {
        println!(
            "    error: {}",
            if full {
                error.clone()
            } else {
                truncate_single_line(error, 120)
            }
        );
    }
    if row.input_tokens.is_some() || row.output_tokens.is_some() {
        let token = |value: Option<u64>| value.map_or_else(|| "-".to_owned(), |n| n.to_string());
        println!(
            "    tokens: in={} out={} cache_create={} cache_read={}",
            token(row.input_tokens),
            token(row.output_tokens),
            token(row.cache_creation_input_tokens),
            token(row.cache_read_input_tokens)
        );
    }
    for (label, text) in [
        ("reasoning", row.reasoning_text.as_ref()),
        ("output", row.output_text.as_ref()),
    ] {
        if let Some(text) = text {
            if full {
                println!("    {label} ({} chars):", text.len());
                for line in text.lines() {
                    println!("      {line}");
                }
            } else {
                println!(
                    "    {label}: {} chars \"{}\"",
                    text.len(),
                    truncate_single_line(text, 80)
                );
            }
        }
    }
}

fn cmd_turn(snapshot: &TriageSnapshot, turn: usize, full: bool) -> Result<()> {
    let cognition = snapshot.cognition()?;
    let exec_state = collect_exec_state(&cognition.reader, &cognition.facts)?;
    let model_state = collect_model_chat_state(&cognition.reader, &cognition.facts)?;
    let request = select_request(&exec_state, turn)?;
    let now = now_key()?;
    println!("Turn #{turn}");
    println!("- Cognition facts: {}", cognition.facts.len());
    println!("- request: {}", fmt_id(request.id));
    println!(
        "- requested: {} ({})",
        format_tai_ns(request.requested_at),
        format_age(now, request.requested_at)
    );
    println!(
        "- command: {}",
        if full {
            request.command.clone()
        } else {
            truncate_single_line(&request.command, 100)
        }
    );

    let mut results: Vec<_> = exec_state
        .results
        .iter()
        .filter(|result| result.about_request == request.id)
        .collect();
    results.sort_by_key(|result| (result.finished_at, result.id));
    if results.is_empty() {
        println!();
        println!("Exec results: none (turn may still be in progress)");
        return Ok(());
    }
    println!();
    println!("Exec results ({})", results.len());
    for result in results {
        println!("- result {}", fmt_id(result.id));
        println!(
            "  exit: {}",
            result
                .exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "-".to_owned())
        );
        println!(
            "  finished: {} (latency {})",
            format_tai_ns(result.finished_at),
            format_duration_ns(result.finished_at.saturating_sub(request.requested_at))
        );
        for (label, text) in [
            ("error", result.error.as_ref()),
            ("stderr", result.stderr_text.as_ref()),
            ("stdout", result.stdout_text.as_ref()),
        ] {
            if let Some(text) = text {
                if full {
                    println!("  {label} ({} chars):", text.len());
                    for line in text.lines() {
                        println!("    {line}");
                    }
                } else {
                    println!("  {label}: {}", truncate_single_line(text, 120));
                }
            }
        }
        if let Some(thought) = result.about_thought {
            println!("  thought: {}", fmt_id(thought));
            let mut model_requests: Vec<_> = model_state
                .requests
                .values()
                .filter(|candidate| candidate.about_thought == Some(thought))
                .collect();
            model_requests.sort_by_key(|candidate| (candidate.requested_at, candidate.id));
            for model_request in model_requests {
                println!("  Model request {}", fmt_id(model_request.id));
                let mut model_results: Vec<_> = model_state
                    .results
                    .iter()
                    .filter(|candidate| candidate.about_request == model_request.id)
                    .collect();
                model_results.sort_by_key(|candidate| (candidate.finished_at, candidate.id));
                for model_result in model_results {
                    print_model_result(model_result, full);
                }
            }
        }
    }

    let contexts = contexts_for_turn(&cognition.reader, &cognition.facts, &exec_state, request.id)?;
    println!();
    println!("Context candidates ({})", contexts.len());
    for candidate in contexts {
        let chars: usize = candidate
            .messages
            .iter()
            .map(|message| message.content.len())
            .sum();
        println!(
            "- result {} thought {}: {} messages, {} chars",
            fmt_id(candidate.result),
            fmt_id(candidate.thought),
            candidate.messages.len(),
            chars
        );
        for (index, message) in candidate.messages.iter().enumerate() {
            if full {
                println!(
                    "  #{index} [{}] ({} chars)",
                    message.role,
                    message.content.len()
                );
                for line in message.content.lines() {
                    println!("    {line}");
                }
            } else {
                println!(
                    "  #{index} [{:<9}] ({:>5} chars) \"{}\"",
                    message.role.to_string(),
                    message.content.len(),
                    truncate_single_line(&message.content, 60)
                );
            }
        }
    }
    Ok(())
}

fn cmd_context(snapshot: &TriageSnapshot, turn: usize, full: bool, raw: bool) -> Result<()> {
    let cognition = snapshot.cognition()?;
    let (_, headspace) = snapshot.headspace()?;
    let exec_state = collect_exec_state(&cognition.reader, &cognition.facts)?;
    let request = select_request(&exec_state, turn)?;
    let contexts = contexts_for_turn(&cognition.reader, &cognition.facts, &exec_state, request.id)?;
    if contexts.is_empty() {
        bail!("turn #{turn} has no recorded context candidate");
    }
    if raw {
        let values: Vec<_> = contexts
            .iter()
            .map(|candidate| {
                serde_json::json!({
                    "result": fmt_id(candidate.result),
                    "thought": fmt_id(candidate.thought),
                    "messages": candidate.messages,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&values)?);
        return Ok(());
    }
    println!("Contexts for turn #{turn} [{}]", fmt_id(request.id));
    println!("- Cognition facts: {}", cognition.facts.len());
    println!("- command: {}", truncate_single_line(&request.command, 60));
    println!("- candidates: {}", contexts.len());
    for candidate in contexts {
        let chars: usize = candidate
            .messages
            .iter()
            .map(|message| message.content.len())
            .sum();
        let budget = headspace.budget()?;
        let fill = if budget.body_budget_chars > 0 {
            chars as f64 / budget.body_budget_chars as f64 * 100.0
        } else {
            0.0
        };
        println!();
        println!(
            "Result {} / thought {}: {} messages, {} chars, fill={fill:.1}%",
            fmt_id(candidate.result),
            fmt_id(candidate.thought),
            candidate.messages.len(),
            chars
        );
        for (index, message) in candidate.messages.iter().enumerate() {
            if full {
                println!(
                    "  #{index} [{}] ({} chars)",
                    message.role,
                    message.content.len()
                );
                for line in message.content.lines() {
                    println!("    {line}");
                }
            } else {
                println!(
                    "  #{index} [{:<9}] ({:>5} chars) \"{}\"",
                    message.role.to_string(),
                    message.content.len(),
                    truncate_single_line(&message.content, 70)
                );
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = &cli.command else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };
    let snapshot = TriageSnapshot::open(&cli)?;
    let result = match command {
        Command::Scan {
            recent,
            loop_min,
            stale_min,
        } => cmd_scan(&cli, &snapshot, *recent, *loop_min, *stale_min),
        Command::Loops { recent, min_repeat } => cmd_loops(&snapshot, *recent, *min_repeat),
        Command::Timeline { recent } => cmd_timeline(&snapshot, *recent),
        Command::Cover { full } => cmd_cover(&snapshot, *full),
        Command::Chunk { id } => cmd_chunk(&snapshot, id),
        Command::Turn { turn, full } => cmd_turn(&snapshot, *turn, *full),
        Command::Context { turn, full, raw } => cmd_context(&snapshot, *turn, *full, *raw),
    };
    snapshot.close(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::path::PathBuf;

    use faculties::headspace::{self, Resolution};
    use faculties::memory::{ChunkDraft, ChunkDraftContent};
    use faculties::schemas::triage::{exec, KIND_EXEC_REQUEST_ID};
    use faculties::storage::initialize_signer;
    use triblespace::core::metadata;
    use triblespace::macros::entity;

    fn test_id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn point(seconds: f64) -> Interval {
        let at = Epoch::from_tai_seconds(seconds);
        (at, at).try_to_inline().unwrap()
    }

    fn exec_request(id: Id, command: &str, at: f64) -> Fragment {
        entity! { ExclusiveId::force_ref(&id) @
            metadata::tag: &KIND_EXEC_REQUEST_ID,
            exec::command_text: command.to_owned(),
            metadata::created_at: point(at),
        }
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        pile: PathBuf,
        key: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let pile = directory.path().join("triage.pile");
            let key = directory.path().join("triage.key");
            File::create(&pile).unwrap();
            initialize_signer(&pile, Some(&key)).unwrap();
            Self {
                _directory: directory,
                pile,
                key,
            }
        }

        fn publish(&self, scope: Id, fragment: Fragment) {
            let signer = load_signer(&self.pile, Some(&self.key)).unwrap();
            let mut pile = open_pile_strict(&self.pile).unwrap();
            let collection =
                faculties::collection_names::open(&mut pile, scope, signer.verifying_key())
                    .unwrap();
            pile.commit(collection, &signer, fragment).unwrap();
            pile.close().unwrap();
        }

        fn cli(&self, command: Command) -> Cli {
            Cli {
                pile: self.pile.clone(),
                key: Some(self.key.clone()),
                command: Some(command),
            }
        }

        fn snapshot(&self) -> TriageSnapshot {
            TriageSnapshot::open(&self.cli(Command::Loops {
                recent: 1,
                min_repeat: 1,
            }))
            .unwrap()
        }
    }

    fn chunk(text: &str, start: f64) -> (Fragment, Id) {
        memory_model::chunk_fragment(ChunkDraft {
            content: ChunkDraftContent::Text(text.to_owned()),
            start_at: point(start),
            end_at: point(start + 1.0),
            lens: None,
            references: BTreeSet::new(),
            about_exec_result: None,
            about_archive_message: None,
            observed_at: BTreeSet::from([point(start + 2.0)]),
            aliases: BTreeSet::new(),
        })
        .unwrap()
    }

    #[test]
    fn memory_chunks_coexist() {
        let fixture = Fixture::new();
        let (left, left_id) = chunk("one telling", 10.0);
        let (right, right_id) = chunk("another telling", 10.0);
        fixture.publish(MEMORY_SCOPE_ID, left);
        fixture.publish(MEMORY_SCOPE_ID, right);

        let view = fixture.snapshot().memory().unwrap();
        assert!(!view.facts.is_empty());
        let ids: BTreeSet<Id> = all_chunk_ids(&view.facts).into_iter().collect();
        assert_eq!(ids, BTreeSet::from([left_id, right_id]));
    }

    #[test]
    fn headspace_profile_fork_is_reported_instead_of_arbitrated() {
        let fixture = Fixture::new();
        let anchor = test_id(0x51);
        let profile = headspace::default_profile(anchor, "triage");
        let config = headspace::default_config(anchor);
        let (genesis, profile_head, _) =
            headspace::add_profile_fragment(&profile, &config, &[]).unwrap();
        fixture.publish(HEADSPACE_SCOPE_ID, genesis);

        let mut left = profile.clone();
        left.model = "left".to_owned();
        let mut right = profile;
        right.model = "right".to_owned();
        fixture.publish(
            HEADSPACE_SCOPE_ID,
            headspace::profile_snapshot_fragment(&left, &[profile_head])
                .unwrap()
                .0,
        );
        fixture.publish(
            HEADSPACE_SCOPE_ID,
            headspace::profile_snapshot_fragment(&right, &[profile_head])
                .unwrap()
                .0,
        );

        let (_, projected) = fixture.snapshot().headspace().unwrap();
        assert!(projected.budget.is_none());
        assert!(matches!(
            projected.active_profile,
            Some(Resolution::Forked(_))
        ));
        assert!(projected.unsettled_reason().unwrap().contains("forked"));
    }

    #[test]
    fn missing_exact_headspace_secret_is_a_visible_catalog_error() {
        let fixture = Fixture::new();
        let anchor = test_id(0x61);
        let mut profile = headspace::default_profile(anchor, "private");
        profile.model_secret_version = Some(test_id(0x62));
        let config = headspace::default_config(anchor);
        fixture.publish(
            HEADSPACE_SCOPE_ID,
            headspace::add_profile_fragment(&profile, &config, &[])
                .unwrap()
                .0,
        );

        let error = match fixture.snapshot().headspace() {
            Ok(_) => panic!("missing exact secret unexpectedly validated"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("missing exact model Secrets version"));
    }

    #[test]
    fn read_snapshot_never_appends_to_the_pile() {
        let fixture = Fixture::new();
        fixture.publish(
            COGNITION_SCOPE_ID,
            exec_request(test_id(0x71), "read only", 10.0),
        );
        let before = std::fs::metadata(&fixture.pile).unwrap().len();
        let snapshot = fixture.snapshot();
        snapshot.cognition().unwrap();
        snapshot.close(Ok(())).unwrap();
        let after = std::fs::metadata(&fixture.pile).unwrap().len();
        assert_eq!(after, before);
    }

    #[test]
    fn retired_branch_commands_and_selector_are_not_cli_surface() {
        assert!(
            Cli::try_parse_from(["triage", "--pile", "x", "--branch", "cognition", "scan"])
                .is_err()
        );
        assert!(Cli::try_parse_from(["triage", "--pile", "x", "chain"]).is_err());
        assert!(Cli::try_parse_from(["triage", "--pile", "x", "repair"]).is_err());
        assert!(Cli::try_parse_from(["triage", "--pile", "x", "migrate-legacy"]).is_err());
    }
}
