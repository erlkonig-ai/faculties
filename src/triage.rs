//! Canonical read model for Triage diagnostics.
//!
//! Triage observes several immutable collection values at once. Cognition is
//! an event ledger, so queue state is a causal reduction over request,
//! in-progress, and result entities joined by `about_request`; event time is
//! taken from the native `created_at`, `started_at`, and `finished_at` fields
//! according to each event kind. Headspace and Relations retain every current
//! DAG head. No timestamp winner or mutable branch head participates here.
//!
//! This module is the shared semantic boundary for both the `triage` CLI and
//! the GORBIE widget. Callers own storage and presentation only.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use hifitime::Epoch;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::BlobStoreGet;
use triblespace::macros::{find, pattern};
use triblespace::prelude::*;

use crate::cognition as cognition_model;
use crate::headspace::{self, Catalog, ConfigValue, ProfileValue, Resolution};
use crate::message as message_model;
use crate::relations::{self as relations_model, IdentityComponents, ProfileView};
use crate::schemas::triage::{
    exec, model_chat, reason, KIND_EXEC_IN_PROGRESS_ID, KIND_EXEC_REQUEST_ID, KIND_EXEC_RESULT_ID,
    KIND_MODEL_IN_PROGRESS_ID, KIND_MODEL_REQUEST_ID, KIND_MODEL_RESULT_ID, KIND_REASON_EVENT_ID,
};
use crate::secrets::{self as secrets_model};

pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
pub type Interval = Inline<inlineencodings::NsTAIInterval>;

/// One immutable collection value from a single frozen pile prefix.
#[derive(Clone, Copy, Debug)]
pub struct SourceView<'a> {
    pub facts: &'a TribleSet,
    pub reader: &'a PileReader,
}

#[derive(Clone, Copy, Debug)]
pub struct ScanSources<'a> {
    pub cognition: SourceView<'a>,
    pub headspace: SourceView<'a>,
    pub secrets: SourceView<'a>,
    pub relations: SourceView<'a>,
    pub messages: SourceView<'a>,
}

#[derive(Clone, Copy, Debug)]
pub struct ScanOptions {
    pub now: i128,
    pub stale_after_ns: i128,
    pub recent_attempts: usize,
    pub loop_min: usize,
}

#[derive(Debug, Clone)]
pub struct ExecRequestRow {
    pub id: Id,
    pub command: String,
    pub requested_at: i128,
}

#[derive(Debug, Clone)]
pub struct ExecInProgressRow {
    pub id: Id,
    pub about_request: Id,
    pub attempt: Option<u64>,
    pub started_at: i128,
}

#[derive(Debug, Clone)]
pub struct ExecResultRow {
    pub id: Id,
    pub about_request: Id,
    pub attempt: Option<u64>,
    pub finished_at: i128,
    pub exit_code: Option<u64>,
    pub stdout_text: Option<String>,
    pub stderr_text: Option<String>,
    pub error: Option<String>,
    pub about_thought: Option<Id>,
}

#[derive(Debug, Clone, Default)]
pub struct ExecState {
    pub requests: HashMap<Id, ExecRequestRow>,
    pub in_progress: Vec<ExecInProgressRow>,
    pub results: Vec<ExecResultRow>,
}

#[derive(Debug, Clone)]
pub struct ModelRequestRow {
    pub id: Id,
    pub requested_at: i128,
    pub about_thought: Option<Id>,
}

#[derive(Debug, Clone)]
pub struct ModelInProgressRow {
    pub id: Id,
    pub about_request: Id,
    pub attempt: Option<u64>,
    pub started_at: i128,
}

#[derive(Debug, Clone)]
pub struct ModelResultRow {
    pub id: Id,
    pub about_request: Id,
    pub attempt: Option<u64>,
    pub finished_at: i128,
    pub error: Option<String>,
    pub output_text: Option<String>,
    pub reasoning_text: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cache_creation_input_tokens: Option<u64>,
    pub cache_read_input_tokens: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct ModelChatState {
    pub requests: HashMap<Id, ModelRequestRow>,
    pub in_progress: Vec<ModelInProgressRow>,
    pub results: Vec<ModelResultRow>,
}

#[derive(Debug, Clone)]
pub struct ReasonEventRow {
    pub id: Id,
    pub created_at: Option<i128>,
    pub text: Option<String>,
    pub about_turn: Option<Id>,
    pub command_text: Option<String>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct QueueCounts {
    pub requests: usize,
    pub pending: usize,
    pub running: usize,
    pub stale: usize,
    pub done: usize,
    /// Attempt slots with competing in-progress or result event identities.
    pub forked: usize,
    /// Requests whose lifecycle mixes incompatible attempt protocols.
    pub invalid: usize,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AttemptFork {
    pub request_id: Id,
    pub attempt: Option<u64>,
    pub in_progress_ids: Vec<Id>,
    pub result_ids: Vec<Id>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct QueueProjection {
    pub counts: QueueCounts,
    pub forks: Vec<AttemptFork>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ExecAttempt {
    pub request_id: Id,
    pub result_id: Id,
    pub finished_at: i128,
    pub command: String,
    pub exit_code: Option<u64>,
    pub fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct PatternSummary {
    pub command: String,
    pub exit_code: Option<u64>,
    pub fingerprint: String,
    pub count: usize,
    pub latest: i128,
}

#[derive(Debug, Clone)]
pub struct LoopReport {
    pub recent: Vec<ExecAttempt>,
    pub top_patterns: Vec<PatternSummary>,
    pub contiguous_head: Option<PatternSummary>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BudgetInfo {
    pub context_window_tokens: u64,
    pub max_output_tokens: u64,
    pub safety_margin_tokens: u64,
    pub chars_per_token: u64,
    pub system_prompt_chars: usize,
    pub body_budget_chars: i64,
}

/// Active Headspace projection without erasing resolution state or concurrent
/// provenance heads.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TriageHeadspace {
    pub config: Resolution<ConfigValue>,
    pub active_profile: Option<Resolution<ProfileValue>>,
    pub persona_id: Option<Id>,
    pub budget: Option<BudgetInfo>,
}

impl TriageHeadspace {
    pub fn budget(&self) -> Result<&BudgetInfo> {
        self.budget.as_ref().ok_or_else(|| {
            anyhow!(
                "Headspace has no settled active budget: {}",
                self.unsettled_reason()
                    .unwrap_or_else(|| "unknown failure".to_owned())
            )
        })
    }

    pub fn is_settled(&self) -> bool {
        self.budget.is_some()
    }

    pub fn config_heads(&self) -> Vec<Id> {
        self.config.head_ids()
    }

    pub fn active_profile_heads(&self) -> Vec<Id> {
        self.active_profile
            .as_ref()
            .map(Resolution::head_ids)
            .unwrap_or_default()
    }

    /// Human-readable explanation derived from the typed resolutions. The
    /// read model retains the variants above; strings exist only at the
    /// presentation boundary.
    pub fn unsettled_reason(&self) -> Option<String> {
        let config = match self.config.settled_value("Headspace config") {
            Ok(Some(config)) => config,
            Ok(None) => return Some("Headspace has no active configuration".to_owned()),
            Err(error) => return Some(format!("{error:#}")),
        };
        let Some(profile) = self.active_profile.as_ref() else {
            return Some(format!(
                "active profile {:x} is missing",
                config.active_profile
            ));
        };
        match profile.settled_value(&format!("profile {:x}", config.active_profile)) {
            Ok(Some(_)) => None,
            Ok(None) => Some(format!(
                "active profile {:x} has no snapshot",
                config.active_profile
            )),
            Err(error) => Some(format!("{error:#}")),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UnreadUnavailable {
    HeadspaceUnsettled,
    PersonaNotConfigured,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UnreadMessages {
    Available { reader: Id, count: usize },
    Unavailable(UnreadUnavailable),
}

#[derive(Debug, Clone, Default)]
pub struct RelationState {
    pub terms: Vec<String>,
    /// Every forked person profile and all of its current heads.
    pub forked_profiles: Vec<(Id, Vec<Id>)>,
}

#[derive(Debug, Clone)]
pub struct ScanReport {
    pub exec_state: ExecState,
    pub model_state: ModelChatState,
    pub reason_events: Vec<ReasonEventRow>,
    pub exec_queue: QueueCounts,
    pub model_queue: QueueCounts,
    pub exec_attempt_forks: Vec<AttemptFork>,
    pub model_attempt_forks: Vec<AttemptFork>,
    pub lifecycle_diagnostics: Vec<String>,
    pub headspace: TriageHeadspace,
    pub relations: RelationState,
    pub unread_messages: UnreadMessages,
    pub loops: LoopReport,
    pub probable_loop: Option<PatternSummary>,
    pub suggestions: Vec<String>,
}

pub fn now_tai_ns() -> i128 {
    Epoch::now()
        .unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
        .to_tai_duration()
        .total_nanoseconds()
}

pub fn interval_key(interval: Interval) -> i128 {
    let (lower, _): (Epoch, Epoch) = interval
        .try_from_inline()
        .expect("NsTAIInterval values decode as epochs");
    lower.to_tai_duration().total_nanoseconds()
}

fn u256be_to_u64(entity: Id, field: &str, value: Inline<inlineencodings::U256BE>) -> Result<u64> {
    let bytes = value.raw;
    if bytes[..24].iter().any(|byte| *byte != 0) {
        bail!("Cognition entity {entity:x} has a {field} value larger than u64");
    }
    let mut lower = [0; 8];
    lower.copy_from_slice(&bytes[24..]);
    Ok(u64::from_be_bytes(lower))
}

fn optional_u64(
    entity: Id,
    field: &str,
    values: Vec<Inline<inlineencodings::U256BE>>,
) -> Result<Option<u64>> {
    at_most_one(entity, field, values)?
        .map(|value| u256be_to_u64(entity, field, value))
        .transpose()
}

fn optional_attempt(
    entity: Id,
    field: &str,
    values: Vec<Inline<inlineencodings::U256BE>>,
) -> Result<Option<u64>> {
    optional_u64(entity, field, values)
}

fn read_text<Store>(reader: &Store, handle: TextHandle) -> Result<String>
where
    Store: BlobStoreGet + ?Sized,
{
    let view: View<str> = reader
        .get(handle)
        .with_context(|| format!("read LongString {}", hex::encode(handle.raw)))?;
    Ok(view.to_string())
}

fn tagged_entities(space: &TribleSet, kind: Id) -> BTreeSet<Id> {
    find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: kind }])).collect()
}

fn exactly_one<T>(entity: Id, field: &str, values: Vec<T>) -> Result<T> {
    let count = values.len();
    let mut values = values.into_iter();
    match (values.next(), count) {
        (Some(value), 1) => Ok(value),
        _ => bail!(
            "Cognition entity {entity:x} has {count} values for {field}; expected exactly one"
        ),
    }
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

fn one_text<Store>(
    reader: &Store,
    entity: Id,
    field: &str,
    values: Vec<TextHandle>,
) -> Result<Option<String>>
where
    Store: BlobStoreGet + ?Sized,
{
    at_most_one(entity, field, values)?
        .map(|handle| read_text(reader, handle))
        .transpose()
}

/// Project every native Exec event exactly once by entity id.
pub fn collect_exec_state<Store>(reader: &Store, space: &TribleSet) -> Result<ExecState>
where
    Store: BlobStoreGet + ?Sized,
{
    let mut state = ExecState::default();
    for id in tagged_entities(space, KIND_EXEC_REQUEST_ID) {
        let command = exactly_one(
            id,
            "exec::command_text",
            find!(value: TextHandle, pattern!(space, [{ id @ exec::command_text: ?value }]))
                .collect(),
        )?;
        let requested_at = exactly_one(
            id,
            "metadata::created_at",
            find!(value: Interval, pattern!(space, [{ id @ metadata::created_at: ?value }]))
                .collect(),
        )?;
        state.requests.insert(
            id,
            ExecRequestRow {
                id,
                command: read_text(reader, command)?,
                requested_at: interval_key(requested_at),
            },
        );
    }
    for id in tagged_entities(space, KIND_EXEC_IN_PROGRESS_ID) {
        let about_request = exactly_one(
            id,
            "exec::about_request",
            find!(value: Id, pattern!(space, [{ id @ exec::about_request: ?value }])).collect(),
        )?;
        let started_at = exactly_one(
            id,
            "metadata::started_at",
            find!(value: Interval, pattern!(space, [{ id @ metadata::started_at: ?value }]))
                .collect(),
        )?;
        state.in_progress.push(ExecInProgressRow {
            id,
            about_request,
            attempt: optional_attempt(
                id,
                "exec::attempt",
                find!(value: Inline<inlineencodings::U256BE>, pattern!(space, [{ id @ exec::attempt: ?value }]))
                    .collect(),
            )?,
            started_at: interval_key(started_at),
        });
    }
    for id in tagged_entities(space, KIND_EXEC_RESULT_ID) {
        let about_request = exactly_one(
            id,
            "exec::about_request",
            find!(value: Id, pattern!(space, [{ id @ exec::about_request: ?value }])).collect(),
        )?;
        let finished_at = exactly_one(
            id,
            "metadata::finished_at",
            find!(value: Interval, pattern!(space, [{ id @ metadata::finished_at: ?value }]))
                .collect(),
        )?;
        let exit_code = optional_u64(
            id,
            "exec::exit_code",
            find!(value: Inline<inlineencodings::U256BE>, pattern!(space, [{ id @ exec::exit_code: ?value }]))
                .collect(),
        )?;
        state.results.push(ExecResultRow {
            id,
            about_request,
            attempt: optional_attempt(
                id,
                "exec::attempt",
                find!(value: Inline<inlineencodings::U256BE>, pattern!(space, [{ id @ exec::attempt: ?value }]))
                    .collect(),
            )?,
            finished_at: interval_key(finished_at),
            exit_code,
            stdout_text: one_text(
                reader,
                id,
                "exec::stdout_text",
                find!(value: TextHandle, pattern!(space, [{ id @ exec::stdout_text: ?value }]))
                    .collect(),
            )?,
            stderr_text: one_text(
                reader,
                id,
                "exec::stderr_text",
                find!(value: TextHandle, pattern!(space, [{ id @ exec::stderr_text: ?value }]))
                    .collect(),
            )?,
            error: one_text(
                reader,
                id,
                "exec::error",
                find!(value: TextHandle, pattern!(space, [{ id @ exec::error: ?value }]))
                    .collect(),
            )?,
            about_thought: at_most_one(
                id,
                "exec::about_thought",
                find!(value: Id, pattern!(space, [{ id @ exec::about_thought: ?value }]))
                    .collect(),
            )?,
        });
    }
    Ok(state)
}

/// Project every native model-chat event exactly once by entity id.
pub fn collect_model_chat_state<Store>(reader: &Store, space: &TribleSet) -> Result<ModelChatState>
where
    Store: BlobStoreGet + ?Sized,
{
    let mut state = ModelChatState::default();
    for id in tagged_entities(space, KIND_MODEL_REQUEST_ID) {
        let requested_at = exactly_one(
            id,
            "metadata::created_at",
            find!(value: Interval, pattern!(space, [{ id @ metadata::created_at: ?value }]))
                .collect(),
        )?;
        let about_thought = at_most_one(
            id,
            "model_chat::about_thought",
            find!(value: Id, pattern!(space, [{ id @ model_chat::about_thought: ?value }]))
                .collect(),
        )?;
        state.requests.insert(
            id,
            ModelRequestRow {
                id,
                requested_at: interval_key(requested_at),
                about_thought,
            },
        );
    }
    for id in tagged_entities(space, KIND_MODEL_IN_PROGRESS_ID) {
        let about_request = exactly_one(
            id,
            "model_chat::about_request",
            find!(value: Id, pattern!(space, [{ id @ model_chat::about_request: ?value }]))
                .collect(),
        )?;
        let started_at = exactly_one(
            id,
            "metadata::started_at",
            find!(value: Interval, pattern!(space, [{ id @ metadata::started_at: ?value }]))
                .collect(),
        )?;
        state.in_progress.push(ModelInProgressRow {
            id,
            about_request,
            attempt: optional_attempt(
                id,
                "model_chat::attempt",
                find!(value: Inline<inlineencodings::U256BE>, pattern!(space, [{ id @ model_chat::attempt: ?value }]))
                    .collect(),
            )?,
            started_at: interval_key(started_at),
        });
    }
    for id in tagged_entities(space, KIND_MODEL_RESULT_ID) {
        let about_request = exactly_one(
            id,
            "model_chat::about_request",
            find!(value: Id, pattern!(space, [{ id @ model_chat::about_request: ?value }]))
                .collect(),
        )?;
        let finished_at = exactly_one(
            id,
            "metadata::finished_at",
            find!(value: Interval, pattern!(space, [{ id @ metadata::finished_at: ?value }]))
                .collect(),
        )?;
        let token = |field: &str,
                     attribute: &triblespace::core::attribute::Attribute<
            inlineencodings::U256BE,
        >| {
            optional_u64(
                id,
                field,
                find!(value: Inline<inlineencodings::U256BE>, pattern!(space, [{ id @ attribute: ?value }]))
                    .collect(),
            )
        };
        state.results.push(ModelResultRow {
            id,
            about_request,
            attempt: optional_attempt(
                id,
                "model_chat::attempt",
                find!(value: Inline<inlineencodings::U256BE>, pattern!(space, [{ id @ model_chat::attempt: ?value }]))
                    .collect(),
            )?,
            finished_at: interval_key(finished_at),
            error: one_text(
                reader,
                id,
                "model_chat::error",
                find!(value: TextHandle, pattern!(space, [{ id @ model_chat::error: ?value }]))
                    .collect(),
            )?,
            output_text: one_text(
                reader,
                id,
                "model_chat::output_text",
                find!(value: TextHandle, pattern!(space, [{ id @ model_chat::output_text: ?value }]))
                    .collect(),
            )?,
            reasoning_text: one_text(
                reader,
                id,
                "model_chat::reasoning_text",
                find!(value: TextHandle, pattern!(space, [{ id @ model_chat::reasoning_text: ?value }]))
                    .collect(),
            )?,
            input_tokens: token("model_chat::input_tokens", &model_chat::input_tokens)?,
            output_tokens: token("model_chat::output_tokens", &model_chat::output_tokens)?,
            cache_creation_input_tokens: token(
                "model_chat::cache_creation_input_tokens",
                &model_chat::cache_creation_input_tokens,
            )?,
            cache_read_input_tokens: token(
                "model_chat::cache_read_input_tokens",
                &model_chat::cache_read_input_tokens,
            )?,
        });
    }
    Ok(state)
}

pub fn collect_reason_state<Store>(reader: &Store, space: &TribleSet) -> Result<Vec<ReasonEventRow>>
where
    Store: BlobStoreGet + ?Sized,
{
    let mut rows = Vec::new();
    for id in tagged_entities(space, KIND_REASON_EVENT_ID) {
        let created_at = at_most_one(
            id,
            "metadata::created_at",
            find!(value: Interval, pattern!(space, [{ id @ metadata::created_at: ?value }]))
                .collect(),
        )?
        .map(interval_key);
        rows.push(ReasonEventRow {
            id,
            created_at,
            text: one_text(
                reader,
                id,
                "reason::text",
                find!(value: TextHandle, pattern!(space, [{ id @ reason::text: ?value }]))
                    .collect(),
            )?,
            about_turn: at_most_one(
                id,
                "reason::about_turn",
                find!(value: Id, pattern!(space, [{ id @ reason::about_turn: ?value }])).collect(),
            )?,
            command_text: one_text(
                reader,
                id,
                "reason::command_text",
                find!(value: TextHandle, pattern!(space, [{ id @ reason::command_text: ?value }]))
                    .collect(),
            )?,
        });
    }
    rows.sort_by_key(|row| (row.created_at.unwrap_or(i128::MIN), row.id));
    rows.reverse();
    Ok(rows)
}

pub fn exec_queue_counts(
    state: &ExecState,
    now: i128,
    stale_after_ns: i128,
) -> Result<QueueProjection> {
    queue_counts(
        state.requests.keys().copied(),
        state
            .in_progress
            .iter()
            .map(|row| (row.id, row.about_request, row.attempt, row.started_at)),
        state
            .results
            .iter()
            .map(|row| (row.id, row.about_request, row.attempt)),
        now,
        stale_after_ns,
        "Exec",
    )
}

pub fn model_queue_counts(
    state: &ModelChatState,
    now: i128,
    stale_after_ns: i128,
) -> Result<QueueProjection> {
    queue_counts(
        state.requests.keys().copied(),
        state
            .in_progress
            .iter()
            .map(|row| (row.id, row.about_request, row.attempt, row.started_at)),
        state
            .results
            .iter()
            .map(|row| (row.id, row.about_request, row.attempt)),
        now,
        stale_after_ns,
        "Model",
    )
}

#[derive(Default)]
struct AttemptEvidence {
    in_progress: Vec<(Id, i128)>,
    results: Vec<Id>,
}

fn queue_counts(
    requests: impl IntoIterator<Item = Id>,
    in_progress: impl IntoIterator<Item = (Id, Id, Option<u64>, i128)>,
    results: impl IntoIterator<Item = (Id, Id, Option<u64>)>,
    now: i128,
    stale_after_ns: i128,
    label: &str,
) -> Result<QueueProjection> {
    let requests: BTreeSet<_> = requests.into_iter().collect();
    let in_progress: Vec<_> = in_progress.into_iter().collect();
    let results: Vec<_> = results.into_iter().collect();
    let mut numbering = BTreeMap::<Id, (bool, bool)>::new();
    let mut slots = BTreeMap::<(Id, Option<u64>), AttemptEvidence>::new();
    let mut diagnostics = Vec::new();

    for (event, request, attempt, started_at) in in_progress {
        if !requests.contains(&request) {
            diagnostics.push(format!(
                "{label} in-progress event {event:x} references missing request {request:x}"
            ));
            continue;
        }
        let flags = numbering.entry(request).or_default();
        if attempt.is_some() {
            flags.1 = true;
        } else {
            flags.0 = true;
        }
        slots
            .entry((request, attempt))
            .or_default()
            .in_progress
            .push((event, started_at));
    }
    for (event, request, attempt) in results {
        if !requests.contains(&request) {
            diagnostics.push(format!(
                "{label} result {event:x} references missing request {request:x}"
            ));
            continue;
        }
        let flags = numbering.entry(request).or_default();
        if attempt.is_some() {
            flags.1 = true;
        } else {
            flags.0 = true;
        }
        slots
            .entry((request, attempt))
            .or_default()
            .results
            .push(event);
    }
    let invalid_requests: BTreeSet<_> = numbering
        .iter()
        .filter_map(|(request, (unnumbered, numbered))| {
            (*unnumbered && *numbered).then_some(*request)
        })
        .collect();
    for request in &invalid_requests {
        diagnostics.push(format!(
            "{label} request {request:x} mixes numbered and unnumbered lifecycle evidence; attempt identity is ambiguous"
        ));
    }

    let mut counts = QueueCounts {
        requests: requests.len(),
        ..QueueCounts::default()
    };
    let mut forks = Vec::new();
    for ((request_id, attempt), evidence) in &mut slots {
        evidence.in_progress.sort_by_key(|(event, _)| *event);
        evidence.results.sort_unstable();
        if evidence.in_progress.len() > 1 || evidence.results.len() > 1 {
            forks.push(AttemptFork {
                request_id: *request_id,
                attempt: *attempt,
                in_progress_ids: evidence
                    .in_progress
                    .iter()
                    .map(|(event, _)| *event)
                    .collect(),
                result_ids: evidence.results.clone(),
            });
        }
    }

    for request in &requests {
        if invalid_requests.contains(request) {
            counts.invalid += 1;
            continue;
        }
        let current_attempt = slots
            .keys()
            .filter_map(|(candidate, attempt)| (*candidate == *request).then_some(*attempt))
            .max();
        let Some(current_attempt) = current_attempt else {
            counts.pending += 1;
            continue;
        };
        let evidence = &slots[&(*request, current_attempt)];
        if evidence.in_progress.len() > 1 || evidence.results.len() > 1 {
            counts.forked += 1;
        } else if evidence.results.len() == 1 {
            counts.done += 1;
        } else if let Some((_, started_at)) = evidence.in_progress.first() {
            if now.saturating_sub(*started_at) >= stale_after_ns.max(0) {
                counts.stale += 1;
            } else {
                counts.running += 1;
            }
        } else {
            counts.pending += 1;
        }
    }
    debug_assert_eq!(
        counts.pending
            + counts.running
            + counts.stale
            + counts.done
            + counts.forked
            + counts.invalid,
        counts.requests
    );
    Ok(QueueProjection {
        counts,
        forks,
        diagnostics,
    })
}

fn first_line(text: &str) -> String {
    text.lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or(text)
        .trim()
        .to_owned()
}

pub fn collect_exec_attempts(state: &ExecState, recent: usize) -> Vec<ExecAttempt> {
    let mut numbering = BTreeMap::<Id, (bool, bool)>::new();
    for (request, attempt) in state
        .in_progress
        .iter()
        .map(|row| (row.about_request, row.attempt))
        .chain(
            state
                .results
                .iter()
                .map(|row| (row.about_request, row.attempt)),
        )
    {
        if !state.requests.contains_key(&request) {
            continue;
        }
        let flags = numbering.entry(request).or_default();
        if attempt.is_some() {
            flags.1 = true;
        } else {
            flags.0 = true;
        }
    }
    let invalid_requests: BTreeSet<_> = numbering
        .into_iter()
        .filter_map(|(request, (unnumbered, numbered))| (unnumbered && numbered).then_some(request))
        .collect();

    let mut by_attempt = BTreeMap::<(Id, Option<u64>), Vec<&ExecResultRow>>::new();
    let mut start_counts = BTreeMap::<(Id, Option<u64>), usize>::new();
    for start in &state.in_progress {
        *start_counts
            .entry((start.about_request, start.attempt))
            .or_default() += 1;
    }
    for result in &state.results {
        by_attempt
            .entry((result.about_request, result.attempt))
            .or_default()
            .push(result);
    }
    let mut rows = Vec::new();
    for ((request_id, attempt), results) in by_attempt {
        if invalid_requests.contains(&request_id) {
            continue;
        }
        // Competing results in one semantic attempt slot are a fork. They stay
        // visible in QueueProjection and the event timeline, but cannot be
        // chosen as one loop fingerprint without inventing an arbiter.
        let [result] = results.as_slice() else {
            continue;
        };
        if start_counts
            .get(&(request_id, attempt))
            .copied()
            .unwrap_or(0)
            > 1
        {
            continue;
        }
        let Some(request) = state.requests.get(&request_id) else {
            continue;
        };
        let fingerprint = result
            .error
            .as_deref()
            .map(first_line)
            .or_else(|| result.stderr_text.as_deref().map(first_line))
            .unwrap_or_else(|| {
                if result.exit_code == Some(0) {
                    "<ok>".to_owned()
                } else {
                    "<no stderr text>".to_owned()
                }
            });
        rows.push(ExecAttempt {
            request_id: request.id,
            result_id: result.id,
            finished_at: result.finished_at,
            command: request.command.clone(),
            exit_code: result.exit_code,
            fingerprint,
        });
    }
    rows.sort_by_key(|row| (row.finished_at, row.result_id));
    rows.reverse();
    rows.truncate(recent);
    rows
}

pub fn build_loop_report(state: &ExecState, recent: usize, min_repeat: usize) -> LoopReport {
    let recent_rows = collect_exec_attempts(state, recent);
    let mut patterns: HashMap<(String, Option<u64>, String), PatternSummary> = HashMap::new();
    for row in &recent_rows {
        let entry = patterns
            .entry((row.command.clone(), row.exit_code, row.fingerprint.clone()))
            .or_insert_with(|| PatternSummary {
                command: row.command.clone(),
                exit_code: row.exit_code,
                fingerprint: row.fingerprint.clone(),
                count: 0,
                latest: row.finished_at,
            });
        entry.count += 1;
        entry.latest = entry.latest.max(row.finished_at);
    }
    let mut top_patterns: Vec<_> = patterns.into_values().collect();
    top_patterns.sort_by_key(|pattern| (pattern.count, pattern.latest));
    top_patterns.reverse();
    let contiguous_head = recent_rows.first().and_then(|head| {
        let count = recent_rows
            .iter()
            .take_while(|row| {
                row.command == head.command
                    && row.exit_code == head.exit_code
                    && row.fingerprint == head.fingerprint
            })
            .count();
        (count >= min_repeat).then_some(PatternSummary {
            command: head.command.clone(),
            exit_code: head.exit_code,
            fingerprint: head.fingerprint.clone(),
            count,
            latest: head.finished_at,
        })
    });
    LoopReport {
        recent: recent_rows,
        top_patterns,
        contiguous_head,
    }
}

fn pattern_is_failure(pattern: &PatternSummary) -> bool {
    pattern.exit_code.unwrap_or(1) != 0 || !matches!(pattern.fingerprint.trim(), "" | "<ok>")
}

fn probable_loop(report: &LoopReport, loop_min: usize) -> Option<PatternSummary> {
    report.contiguous_head.clone().or_else(|| {
        report
            .top_patterns
            .iter()
            .find(|pattern| pattern.count >= loop_min && pattern_is_failure(pattern))
            .cloned()
    })
}

fn budget_info(
    context_window_tokens: u64,
    max_output_tokens: u64,
    safety_margin_tokens: u64,
    chars_per_token: u64,
    system_prompt_chars: usize,
) -> BudgetInfo {
    let chars_per_token = chars_per_token.max(1);
    let body_budget_chars = ((context_window_tokens as i64)
        - (max_output_tokens as i64)
        - (safety_margin_tokens as i64))
        * chars_per_token as i64
        - system_prompt_chars as i64;
    BudgetInfo {
        context_window_tokens,
        max_output_tokens,
        safety_margin_tokens,
        chars_per_token,
        system_prompt_chars,
        body_budget_chars,
    }
}

pub fn project_triage_headspace(catalog: &Catalog) -> TriageHeadspace {
    let active_profile = catalog
        .config
        .settled_value("Headspace config")
        .ok()
        .flatten()
        .and_then(|config| catalog.profiles.get(&config.active_profile))
        .cloned();
    match headspace::settled_active(catalog) {
        Ok((config, profile)) => TriageHeadspace {
            config: catalog.config.clone(),
            active_profile,
            persona_id: config.persona,
            budget: Some(budget_info(
                profile.context_window_tokens,
                profile.max_output_tokens,
                profile.context_safety_margin_tokens,
                profile.chars_per_token,
                config.system_prompt.len(),
            )),
        },
        Err(_) => TriageHeadspace {
            config: catalog.config.clone(),
            active_profile,
            persona_id: None,
            budget: None,
        },
    }
}

pub fn project_headspace(
    headspace_view: SourceView<'_>,
    secrets_view: SourceView<'_>,
) -> Result<TriageHeadspace> {
    let secrets = secrets_model::validate_catalog(secrets_view.reader, secrets_view.facts)
        .context("validate Secrets collection")?;
    let catalog = headspace::project_result(headspace_view.reader, headspace_view.facts)
        .context("validate Headspace collection")?;
    headspace::validate_secret_references(&catalog, &secrets)
        .context("validate exact Headspace Secrets references")?;
    Ok(project_triage_headspace(&catalog))
}

pub fn relation_state(view: SourceView<'_>) -> Result<RelationState> {
    let mut terms = BTreeSet::new();
    let mut forked_profiles = Vec::new();
    for (person, profile) in relations_model::person_profile_views(view.reader, view.facts) {
        match profile {
            ProfileView::Current { value, .. } => {
                terms.insert(value.label);
                terms.extend(value.aliases);
            }
            ProfileView::Forked(heads) => {
                forked_profiles.push((person, heads.clone()));
                for head in heads {
                    let profile = relations_model::profile_snapshot(view.facts, head)?;
                    let value = relations_model::profile_input(view.reader, &profile)
                        .with_context(|| format!("read forked profile {head:x} for {person:x}"))?;
                    terms.insert(value.label);
                    terms.extend(value.aliases);
                }
            }
            ProfileView::Invalid(error) => {
                bail!("Relations profile {person:x} is invalid after validation: {error}")
            }
        }
    }
    forked_profiles.sort_by_key(|(person, _)| *person);
    Ok(RelationState {
        terms: terms.into_iter().collect(),
        forked_profiles,
    })
}

pub fn count_unread_messages(
    messages: SourceView<'_>,
    relations: SourceView<'_>,
    reader: Id,
) -> Result<usize> {
    let identities = IdentityComponents::from_facts(relations.facts)?;
    let rows = message_model::load_message_rows(messages.facts)?;
    let reads = message_model::load_read_rows(messages.facts)?;
    let mut count = 0;
    for row in rows {
        if message_model::is_inbox_message(&row, reader, relations.facts, &identities)?
            && !message_model::is_read_by(&reads, row.id, reader, &identities)?
        {
            count += 1;
        }
    }
    Ok(count)
}

fn extract_unknown_person_label(text: &str) -> Option<String> {
    let marker = "unknown person label '";
    let rest = &text[text.find(marker)? + marker.len()..];
    Some(rest[..rest.find('\'')?].to_owned())
}

fn scan_suggestions(
    exec_queue: &QueueCounts,
    model_queue: &QueueCounts,
    probable_loop: Option<&PatternSummary>,
    relations: &RelationState,
    headspace: &TriageHeadspace,
    unread_messages: UnreadMessages,
    lifecycle_diagnostics: &[String],
) -> Vec<String> {
    let mut suggestions = Vec::new();
    if model_queue.pending > 0
        && model_queue.running == 0
        && model_queue.stale == 0
        && model_queue.forked == 0
    {
        suggestions
            .push("Model worker may be down: pending requests have no active attempt.".into());
    }
    if exec_queue.pending > 0
        && exec_queue.running == 0
        && exec_queue.stale == 0
        && exec_queue.forked == 0
    {
        suggestions
            .push("Exec worker may be down: pending requests have no active attempt.".into());
    }
    if exec_queue.stale > 0 || model_queue.stale > 0 {
        suggestions
            .push("One or more workers appear stale; inspect service and process health.".into());
    }
    if let Some(pattern) = probable_loop {
        if let Some(label) = extract_unknown_person_label(&pattern.fingerprint) {
            if let Some(candidate) = relations
                .terms
                .iter()
                .find(|term| term.eq_ignore_ascii_case(&label) && **term != label)
            {
                suggestions.push(format!(
                    "message label mismatch: '{label}' failed; try '{candidate}'."
                ));
            } else {
                suggestions.push(format!(
                    "unknown message label '{label}': add it to Relations or use an ID."
                ));
            }
        }
        if pattern.fingerprint.contains("rust-script")
            && pattern.fingerprint.contains("No such file or directory")
        {
            suggestions.push("rust-script is missing in the execution environment.".into());
        }
        if pattern.fingerprint.contains("commentary: not found") {
            suggestions.push(
                "command extraction appears to retain a markdown wrapper or preamble.".into(),
            );
        }
    }
    if model_queue.pending == 0
        && exec_queue.pending == 0
        && exec_queue.running == 0
        && model_queue.running == 0
        && exec_queue.stale == 0
        && model_queue.stale == 0
        && exec_queue.forked == 0
        && model_queue.forked == 0
        && exec_queue.invalid == 0
        && model_queue.invalid == 0
        && lifecycle_diagnostics.is_empty()
        && relations.forked_profiles.is_empty()
        && headspace.is_settled()
        && matches!(unread_messages, UnreadMessages::Available { count: 0, .. })
    {
        suggestions.push("system looks healthy; no obvious blockers detected.".into());
    }
    suggestions
}

impl ScanReport {
    /// Re-derive all wall-clock-dependent request states without reprojecting
    /// immutable collection data. Widgets call this on every render so an
    /// unchanged start event can cross the Running→Stale boundary.
    pub fn refresh_time(&mut self, now: i128, stale_after_ns: i128) -> Result<()> {
        let exec = exec_queue_counts(&self.exec_state, now, stale_after_ns)?;
        let model = model_queue_counts(&self.model_state, now, stale_after_ns)?;
        let mut diagnostics = exec.diagnostics;
        diagnostics.extend(model.diagnostics);
        self.exec_queue = exec.counts;
        self.model_queue = model.counts;
        self.exec_attempt_forks = exec.forks;
        self.model_attempt_forks = model.forks;
        self.lifecycle_diagnostics = diagnostics;
        self.suggestions = scan_suggestions(
            &self.exec_queue,
            &self.model_queue,
            self.probable_loop.as_ref(),
            &self.relations,
            &self.headspace,
            self.unread_messages,
            &self.lifecycle_diagnostics,
        );
        Ok(())
    }
}

/// Project the complete native `triage scan` semantic state.
pub fn project_scan(sources: ScanSources<'_>, options: ScanOptions) -> Result<ScanReport> {
    cognition_model::validate_catalog(sources.cognition.reader, sources.cognition.facts)
        .context("validate Cognition collection")?;
    relations_model::validate_catalog(sources.relations.reader, sources.relations.facts)
        .context("validate Relations collection")?;
    message_model::validate_catalog(
        sources.messages.reader,
        sources.messages.facts,
        sources.relations.facts,
    )
    .context("validate Message collection")?;

    let exec_state = collect_exec_state(sources.cognition.reader, sources.cognition.facts)?;
    let model_state = collect_model_chat_state(sources.cognition.reader, sources.cognition.facts)?;
    let reason_events = collect_reason_state(sources.cognition.reader, sources.cognition.facts)?;
    let exec_projection = exec_queue_counts(&exec_state, options.now, options.stale_after_ns)?;
    let model_projection = model_queue_counts(&model_state, options.now, options.stale_after_ns)?;
    let exec_queue = exec_projection.counts;
    let model_queue = model_projection.counts;
    let mut lifecycle_diagnostics = exec_projection.diagnostics;
    lifecycle_diagnostics.extend(model_projection.diagnostics);
    let headspace = project_headspace(sources.headspace, sources.secrets)?;
    let relations = relation_state(sources.relations)?;
    let unread_messages = if !headspace.is_settled() {
        UnreadMessages::Unavailable(UnreadUnavailable::HeadspaceUnsettled)
    } else if let Some(persona) = headspace.persona_id {
        UnreadMessages::Available {
            reader: persona,
            count: count_unread_messages(sources.messages, sources.relations, persona)?,
        }
    } else {
        UnreadMessages::Unavailable(UnreadUnavailable::PersonaNotConfigured)
    };
    let loops = build_loop_report(&exec_state, options.recent_attempts, options.loop_min);
    let probable_loop = probable_loop(&loops, options.loop_min);

    let suggestions = scan_suggestions(
        &exec_queue,
        &model_queue,
        probable_loop.as_ref(),
        &relations,
        &headspace,
        unread_messages,
        &lifecycle_diagnostics,
    );

    Ok(ScanReport {
        exec_state,
        model_state,
        reason_events,
        exec_queue,
        model_queue,
        exec_attempt_forks: exec_projection.forks,
        model_attempt_forks: model_projection.forks,
        lifecycle_diagnostics,
        headspace,
        relations,
        unread_messages,
        loops,
        probable_loop,
        suggestions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use triblespace::core::repo::BlobStore;
    use triblespace::macros::entity;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn request(byte: u8, command: &str) -> ExecRequestRow {
        ExecRequestRow {
            id: id(byte),
            command: command.to_owned(),
            requested_at: 0,
        }
    }

    fn start(byte: u8, request: Id, attempt: Option<u64>, started_at: i128) -> ExecInProgressRow {
        ExecInProgressRow {
            id: id(byte),
            about_request: request,
            attempt,
            started_at,
        }
    }

    fn result(byte: u8, request: Id, attempt: Option<u64>, finished_at: i128) -> ExecResultRow {
        ExecResultRow {
            id: id(byte),
            about_request: request,
            attempt,
            finished_at,
            exit_code: Some(1),
            stdout_text: None,
            stderr_text: Some("same failure".to_owned()),
            error: None,
            about_thought: None,
        }
    }

    fn assert_partition(counts: &QueueCounts) {
        assert_eq!(
            counts.pending
                + counts.running
                + counts.stale
                + counts.done
                + counts.forked
                + counts.invalid,
            counts.requests
        );
    }

    #[test]
    fn queue_states_are_disjoint_and_staleness_rederives_from_now() {
        let mut state = ExecState::default();
        for byte in 1..=4 {
            let row = request(byte, "command");
            state.requests.insert(row.id, row);
        }
        state.in_progress.push(start(11, id(2), None, 950));
        state.in_progress.push(start(12, id(3), None, 100));
        state.results.push(result(13, id(4), None, 900));

        let first = exec_queue_counts(&state, 1_000, 100).unwrap();
        assert_eq!(
            first.counts,
            QueueCounts {
                requests: 4,
                pending: 1,
                running: 1,
                stale: 1,
                done: 1,
                forked: 0,
                invalid: 0,
            }
        );
        assert_partition(&first.counts);

        let later = exec_queue_counts(&state, 1_050, 100).unwrap();
        assert_eq!(later.counts.running, 0);
        assert_eq!(later.counts.stale, 2);
        assert_partition(&later.counts);
    }

    #[test]
    fn highest_numbered_attempt_is_current_but_older_terminal_attempts_remain_history() {
        let request = request(1, "retrying command");
        let mut state = ExecState::default();
        state.requests.insert(request.id, request.clone());
        state.results.push(result(11, request.id, Some(1), 100));
        state.in_progress.push(start(12, request.id, Some(2), 190));

        let queue = exec_queue_counts(&state, 200, 100).unwrap();
        assert_eq!(queue.counts.running, 1);
        assert_eq!(queue.counts.done, 0);
        assert_eq!(collect_exec_attempts(&state, 10).len(), 1);
    }

    #[test]
    fn result_without_start_is_done_for_legacy_and_numbered_protocols() {
        let mut state = ModelChatState::default();
        for byte in 1..=2 {
            let request = ModelRequestRow {
                id: id(byte),
                requested_at: 0,
                about_thought: None,
            };
            state.requests.insert(request.id, request);
        }
        for (byte, request, attempt) in [(11, id(1), None), (12, id(2), Some(4))] {
            state.results.push(ModelResultRow {
                id: id(byte),
                about_request: request,
                attempt,
                finished_at: 10,
                error: None,
                output_text: None,
                reasoning_text: None,
                input_tokens: None,
                output_tokens: None,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            });
        }

        let queue = model_queue_counts(&state, 20, 100).unwrap();
        assert_eq!(queue.counts.done, 2);
        assert_partition(&queue.counts);
    }

    #[test]
    fn attempt_forks_are_never_timestamp_arbitrated_and_history_stays_visible() {
        let current_fork = request(1, "current fork");
        let historical_fork = request(2, "historical fork");
        let mut state = ExecState::default();
        state.requests.insert(current_fork.id, current_fork.clone());
        state
            .requests
            .insert(historical_fork.id, historical_fork.clone());
        state
            .in_progress
            .push(start(11, current_fork.id, Some(1), 10));
        state
            .in_progress
            .push(start(12, current_fork.id, Some(1), 20));
        state
            .results
            .push(result(13, historical_fork.id, Some(1), 30));
        state
            .results
            .push(result(14, historical_fork.id, Some(1), 40));
        state
            .results
            .push(result(15, historical_fork.id, Some(2), 50));

        let queue = exec_queue_counts(&state, 100, 1_000).unwrap();
        assert_eq!(queue.counts.forked, 1);
        assert_eq!(queue.counts.done, 1);
        assert_eq!(queue.forks.len(), 2);
        assert!(queue
            .forks
            .iter()
            .any(|fork| fork.request_id == historical_fork.id && fork.attempt == Some(1)));
        assert_partition(&queue.counts);

        let attempts = collect_exec_attempts(&state, 10);
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].result_id, id(15));
    }

    #[test]
    fn mixed_attempt_protocol_is_invalid_and_orphans_are_diagnostic_only() {
        let request = request(1, "ambiguous");
        let mut state = ExecState::default();
        state.requests.insert(request.id, request.clone());
        state.results.push(result(11, request.id, None, 10));
        state.results.push(result(12, request.id, Some(1), 20));
        state.results.push(result(13, id(99), Some(1), 30));

        let queue = exec_queue_counts(&state, 100, 10).unwrap();
        assert_eq!(queue.counts.invalid, 1);
        assert_eq!(queue.counts.requests, 1);
        assert_eq!(queue.diagnostics.len(), 2);
        assert!(queue
            .diagnostics
            .iter()
            .any(|line| line.contains("mixes numbered and unnumbered")));
        assert!(queue
            .diagnostics
            .iter()
            .any(|line| line.contains("references missing request")));
        assert!(collect_exec_attempts(&state, 10).is_empty());
        assert_partition(&queue.counts);
    }

    #[test]
    fn loop_reduction_uses_only_settled_terminal_attempt_slots() {
        let settled = request(1, "same command");
        let forked = request(2, "same command");
        let mixed = request(3, "same command");
        let mut state = ExecState::default();
        for request in [&settled, &forked, &mixed] {
            state.requests.insert(request.id, request.clone());
        }
        state.results.push(result(11, settled.id, Some(1), 10));
        state.results.push(result(12, settled.id, Some(2), 20));
        state.results.push(result(13, forked.id, Some(1), 30));
        state.results.push(result(14, forked.id, Some(1), 40));
        state.results.push(result(15, mixed.id, None, 50));
        state.results.push(result(16, mixed.id, Some(1), 60));

        let report = build_loop_report(&state, 20, 2);
        assert_eq!(report.recent.len(), 2);
        assert_eq!(report.top_patterns[0].count, 2);
        assert_eq!(report.contiguous_head.as_ref().unwrap().count, 2);
    }

    fn point(seconds: f64) -> Interval {
        let at = Epoch::from_tai_seconds(seconds);
        (at, at).try_to_inline().unwrap()
    }

    fn native_exec_fragment(exit_code: Inline<inlineencodings::U256BE>) -> Fragment {
        let request = id(1);
        let start = id(2);
        let result = id(3);
        let mut fragment = Fragment::empty();
        let command = fragment.put("native timestamps".to_owned());
        fragment += entity! { ExclusiveId::force_ref(&request) @
            metadata::tag: &KIND_EXEC_REQUEST_ID,
            exec::command_text: command,
            metadata::created_at: point(10.0),
        };
        fragment += entity! { ExclusiveId::force_ref(&start) @
            metadata::tag: &KIND_EXEC_IN_PROGRESS_ID,
            exec::about_request: &request,
            exec::attempt: 1u64,
            metadata::started_at: point(20.0),
        };
        fragment += entity! { ExclusiveId::force_ref(&result) @
            metadata::tag: &KIND_EXEC_RESULT_ID,
            exec::about_request: &request,
            exec::attempt: 1u64,
            exec::exit_code: exit_code,
            metadata::finished_at: point(30.0),
        };
        fragment
    }

    #[test]
    fn collector_uses_each_native_lifecycle_timestamp() {
        let exit_code: Inline<inlineencodings::U256BE> = 7u64.to_inline();
        let mut fragment = native_exec_fragment(exit_code);
        let facts = fragment.facts().clone();
        let reader = fragment.blobs_mut().reader().unwrap();

        let state = collect_exec_state(&reader, &facts).unwrap();
        assert_eq!(
            state.requests[&id(1)].requested_at,
            interval_key(point(10.0))
        );
        assert_eq!(state.in_progress[0].started_at, interval_key(point(20.0)));
        assert_eq!(state.results[0].finished_at, interval_key(point(30.0)));
        assert_eq!(state.results[0].exit_code, Some(7));
    }

    #[test]
    fn oversized_u256_values_are_invalid_instead_of_dropped_or_wrapped() {
        let mut raw = [0; 32];
        raw[0] = 1;
        let mut fragment = native_exec_fragment(Inline::<inlineencodings::U256BE>::new(raw));
        let facts = fragment.facts().clone();
        let reader = fragment.blobs_mut().reader().unwrap();

        let error = collect_exec_state(&reader, &facts).unwrap_err();
        assert!(format!("{error:#}").contains("exec::exit_code value larger than u64"));
    }

    #[test]
    fn unavailable_inbox_never_satisfies_the_healthy_heuristic() {
        let anchor = id(1);
        let config = headspace::default_config(anchor);
        let profile = headspace::default_profile(anchor, "test");
        let headspace = TriageHeadspace {
            config: Resolution::Unique(headspace::Snapshot {
                id: id(2),
                value: config.clone(),
                predecessors: Vec::new(),
            }),
            active_profile: Some(Resolution::Unique(headspace::Snapshot {
                id: id(3),
                value: profile.clone(),
                predecessors: Vec::new(),
            })),
            persona_id: None,
            budget: Some(budget_info(
                profile.context_window_tokens,
                profile.max_output_tokens,
                profile.context_safety_margin_tokens,
                profile.chars_per_token,
                config.system_prompt.len(),
            )),
        };
        let queues = QueueCounts::default();
        let relations = RelationState::default();

        let unavailable = scan_suggestions(
            &queues,
            &queues,
            None,
            &relations,
            &headspace,
            UnreadMessages::Unavailable(UnreadUnavailable::PersonaNotConfigured),
            &[],
        );
        assert!(!unavailable.iter().any(|line| line.contains("healthy")));

        let available = scan_suggestions(
            &queues,
            &queues,
            None,
            &relations,
            &headspace,
            UnreadMessages::Available {
                reader: id(4),
                count: 0,
            },
            &[],
        );
        assert!(available.iter().any(|line| line.contains("healthy")));
    }
}
