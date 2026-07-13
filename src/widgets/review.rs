//! Read-only GORBIE-embeddable review bench.
//!
//! Renders both active review goals and goals with structured review history
//! as collapsed-by-default sections. Keeping closed reviews on the bench makes
//! exact settlements and break-glass reasons auditable after the atomic
//! settlement event moves a goal to `"done"`. The gate is the same
//! heterogeneous, revision-bound settlement projection used by the Compass
//! CLI and Orient; the widget never reimplements quorum semantics. Per goal it
//! gathers:
//!
//! - title, tags, latest-status age, and time since creation;
//! - the goal's notes, newest-first;
//! - wiki fragments REFERENCED from the notes — extracted by regexing
//!   32-hex ids out of the note text (pragmatic v0: a real link edge
//!   arrives with the Great Unification epic later) — each rendered
//!   with its title and full typst prose via the wiki widget's
//!   rendering path;
//! - decide entries whose `decide::about` edge points at the goal,
//!   rendered as pros / cons / outcome.
//!
//! Strictly READ-ONLY: the widget never commits or pushes — auditing
//! posture. All state is queried on demand from cached `TribleSet`
//! snapshots (no shadow datamodels); the snapshots refresh whenever a
//! workspace head advances.
//!
//! ```ignore
//! let mut panel = ReviewPanel::default();
//! panel.render(ctx, compass_ws, wiki_ws, decide_ws, relations_ws);
//! ```

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::Inline;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{CommitHandle, Workspace};
use triblespace::core::trible::TribleSet;
use triblespace::macros::{find, pattern};
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::View;

use crate::schemas::compass::{
    active_request_ids_for_goal, all_request_ids_for_goal, board as compass, evaluate_goal,
    latest_status_event, review_attestation, review_request, ReviewGateState, ReviewProjection,
    SettlementMode, KIND_GOAL_ID, KIND_NOTE_ID, REVIEW_STATUS,
};
use crate::schemas::decide::{decide as decide_attrs, factor, KIND_CON, KIND_DECISION, KIND_PRO};
use crate::schemas::relations::{person_ids, retired_person_ids};
use crate::schemas::wiki::{attrs as wiki, KIND_VERSION_ID};
use crate::widgets::wiki::render_wiki_content;

type TextHandle = Inline<Handle<LongString>>;

// ── Palette (shared idiom across the dashboard widgets) ─────────────

fn color_muted(ui: &egui::Ui) -> egui::Color32 {
    if ui.visuals().dark_mode {
        egui::Color32::from_rgb(0x9a, 0x9a, 0x9a)
    } else {
        egui::Color32::from_rgb(0x6a, 0x6a, 0x6a)
    }
}

fn color_frame(ui: &egui::Ui) -> egui::Color32 {
    if ui.visuals().dark_mode {
        egui::Color32::from_rgb(0x29, 0x32, 0x36)
    } else {
        egui::Color32::from_rgb(0xec, 0xec, 0xec)
    }
}

/// RAL 6018 yellow green — "PRO" accent (decide-widget idiom).
fn color_pro() -> egui::Color32 {
    egui::Color32::from_rgb(0x57, 0xa6, 0x39)
}

/// RAL 3020 traffic red — "CON" accent.
fn color_con() -> egui::Color32 {
    egui::Color32::from_rgb(0xcc, 0x0a, 0x17)
}

/// RAL 1003 signal yellow — outcome / resolved accent.
fn color_resolved() -> egui::Color32 {
    egui::Color32::from_rgb(0xf7, 0xba, 0x0b)
}

fn gate_color(ui: &egui::Ui, tone: GateTone) -> egui::Color32 {
    match tone {
        GateTone::Good => color_pro(),
        GateTone::Warn => color_resolved(),
        GateTone::Bad => color_con(),
        GateTone::Muted => color_muted(ui),
    }
}

/// "Paper" frame recipe — matches the compass/decide card chrome.
fn paper_frame(ui: &egui::Ui) -> egui::Frame {
    egui::Frame::NONE
        .fill(ui.visuals().window_fill)
        .stroke(egui::Stroke::new(1.0, color_frame(ui)))
        .shadow(egui::epaint::Shadow {
            offset: [2, 2],
            blur: 0,
            spread: 0,
            color: egui::Color32::from_black_alpha(48),
        })
        .corner_radius(egui::CornerRadius::ZERO)
}

fn render_chip(ui: &mut egui::Ui, label: &str, fill: egui::Color32) {
    let text_color = colorhash::text_color_on(fill);
    let font = egui::TextStyle::Small.resolve(ui.style());
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_string(), font, text_color);
    const PAD_X: f32 = 5.0;
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(galley.size().x + PAD_X * 2.0, galley.size().y),
        egui::Sense::hover(),
    );
    let painter = ui.painter();
    painter.rect_filled(rect, egui::CornerRadius::ZERO, fill);
    painter.galley(
        egui::pos2(rect.left() + PAD_X, rect.top()),
        galley,
        text_color,
    );
}

// ── Time helpers ─────────────────────────────────────────────────────

fn now_tai_ns() -> i128 {
    hifitime::Epoch::now()
        .map(|e| e.to_tai_duration().total_nanoseconds())
        .unwrap_or(0)
}

fn format_age(now_key: i128, maybe_key: Option<i128>) -> String {
    let Some(key) = maybe_key else {
        return "-".to_string();
    };
    let delta_s = (now_key.saturating_sub(key) / 1_000_000_000).max(0) as i64;
    if delta_s < 60 {
        format!("{delta_s}s")
    } else if delta_s < 60 * 60 {
        format!("{}m", delta_s / 60)
    } else if delta_s < 24 * 60 * 60 {
        format!("{}h", delta_s / 3600)
    } else {
        format!("{}d", delta_s / 86_400)
    }
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

/// 32-hex-id matcher for note text. `\b` on both ends keeps a 64-char
/// content hash from yielding a bogus half-match. Pragmatic v0 — the
/// note→fragment relationship should become a real link edge (queried
/// via `pattern!`, no text scraping) with the Great Unification epic;
/// this regex is the bridge until then.
fn hex32_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[0-9a-fA-F]{32}\b").expect("static regex"))
}

// ── Cached snapshots ─────────────────────────────────────────────────

/// Cached fact spaces + head markers for the four branches the bench
/// reads. Queries run against the `TribleSet`s on demand; text blobs
/// are dereffed through the owning branch's workspace at render time.
struct ReviewLive {
    compass_space: TribleSet,
    wiki_space: TribleSet,
    decide_space: TribleSet,
    relations_space: TribleSet,
    compass_head: Option<CommitHandle>,
    wiki_head: Option<CommitHandle>,
    decide_head: Option<CommitHandle>,
    relations_head: Option<CommitHandle>,
}

fn checkout_space(ws: &mut Workspace<Pile>, label: &str) -> TribleSet {
    ws.checkout(..)
        .map(|co| co.into_facts())
        .unwrap_or_else(|e| {
            eprintln!("[review] {label} checkout: {e:?}");
            TribleSet::new()
        })
}

impl ReviewLive {
    fn refresh(
        compass_ws: &mut Workspace<Pile>,
        wiki_ws: Option<&mut Workspace<Pile>>,
        decide_ws: Option<&mut Workspace<Pile>>,
        relations_ws: Option<&mut Workspace<Pile>>,
    ) -> Self {
        let compass_space = checkout_space(compass_ws, "compass");
        let compass_head = compass_ws.head();
        let (wiki_space, wiki_head) = match wiki_ws {
            Some(ws) => (checkout_space(ws, "wiki"), ws.head()),
            None => (TribleSet::new(), None),
        };
        let (decide_space, decide_head) = match decide_ws {
            Some(ws) => (checkout_space(ws, "decide"), ws.head()),
            None => (TribleSet::new(), None),
        };
        let (relations_space, relations_head) = match relations_ws {
            Some(ws) => (checkout_space(ws, "relations"), ws.head()),
            None => (TribleSet::new(), None),
        };
        ReviewLive {
            compass_space,
            wiki_space,
            decide_space,
            relations_space,
            compass_head,
            wiki_head,
            decide_head,
            relations_head,
        }
    }
}

fn read_text(ws: &mut Workspace<Pile>, h: TextHandle) -> Option<String> {
    ws.get::<View<str>, LongString>(h).ok().map(|v| {
        let s: &str = v.as_ref();
        s.to_string()
    })
}

#[derive(Clone, Copy)]
enum GateTone {
    Good,
    Warn,
    Bad,
    Muted,
}

#[derive(Clone)]
struct AttestationView {
    id: Id,
    verdict: String,
    report: String,
}

#[derive(Clone)]
struct ReviewerView {
    id: Id,
    name: String,
    author: bool,
    retired: bool,
    heads: Vec<AttestationView>,
}

#[derive(Clone)]
struct CertificateView {
    id: Id,
    mode: SettlementMode,
    attestations: Vec<Id>,
    override_event: Option<Id>,
}

#[derive(Clone)]
struct CandidateView {
    id: Id,
    target: String,
}

#[derive(Clone)]
struct SettlementView {
    label: String,
    progress: String,
    tone: GateTone,
    request_id: Option<Id>,
    target: Option<String>,
    author: Option<String>,
    requested_at: Option<i128>,
    reasons: Vec<String>,
    reviewers: Vec<ReviewerView>,
    certificates: Vec<CertificateView>,
    candidates: Vec<CandidateView>,
    stale: Vec<CandidateView>,
    override_reason: Option<String>,
}

impl SettlementView {
    fn header_target(&self) -> String {
        let Some(target) = self.target.as_deref() else {
            return if self.candidates.is_empty() {
                "—".to_string()
            } else {
                format!("{} candidates", self.candidates.len())
            };
        };
        let revision = target.rsplit('@').next().unwrap_or(target);
        revision.chars().take(8).collect()
    }
}

fn interval_key(interval: crate::schemas::compass::IntervalValue) -> Option<i128> {
    let (lower, _): (i128, i128) = interval.try_from_inline().ok()?;
    Some(lower)
}

fn person_name(space: &TribleSet, ws: Option<&mut Workspace<Pile>>, id: Id) -> String {
    let handle = find!(h: TextHandle, pattern!(space, [{ id @ metadata::name: ?h }])).next();
    match (ws, handle) {
        (Some(ws), Some(handle)) => read_text(ws, handle).unwrap_or_else(|| fmt_id(id)),
        _ => fmt_id(id),
    }
}

fn candidate_view(space: &TribleSet, ws: &mut Workspace<Pile>, request_id: Id) -> CandidateView {
    let target = review_request(space, request_id)
        .and_then(|request| request.target())
        .and_then(|handle| read_text(ws, handle))
        .unwrap_or_else(|| "<malformed target>".to_string());
    CandidateView {
        id: request_id,
        target,
    }
}

fn build_settlement_view(
    live: &ReviewLive,
    goal_id: Id,
    compass_ws: &mut Workspace<Pile>,
    mut relations_ws: Option<&mut Workspace<Pile>>,
) -> SettlementView {
    let known_people = person_ids(&live.relations_space);
    let projection = evaluate_goal(&live.compass_space, goal_id, &known_people);
    let active_requests: HashSet<Id> = active_request_ids_for_goal(&live.compass_space, goal_id)
        .into_iter()
        .collect();
    let stale = all_request_ids_for_goal(&live.compass_space, goal_id)
        .into_iter()
        .filter(|id| !active_requests.contains(id))
        .map(|id| candidate_view(&live.compass_space, compass_ws, id))
        .collect();

    match projection {
        ReviewProjection::Unbound => SettlementView {
            label: "UNBOUND".to_string(),
            progress: "0/3".to_string(),
            tone: GateTone::Muted,
            request_id: None,
            target: None,
            author: None,
            requested_at: None,
            reasons: vec![
                "No immutable candidate is bound to this legacy review goal.".to_string(),
            ],
            reviewers: Vec::new(),
            certificates: Vec::new(),
            candidates: Vec::new(),
            stale,
            override_reason: None,
        },
        ReviewProjection::Forked { request_ids } => SettlementView {
            label: "FORKED · GATE CLOSED".to_string(),
            progress: "0/3".to_string(),
            tone: GateTone::Bad,
            request_id: None,
            target: None,
            author: None,
            requested_at: None,
            reasons: vec![
                "Concurrent successor requests must be superseded by one new request.".to_string(),
            ],
            reviewers: Vec::new(),
            certificates: Vec::new(),
            candidates: request_ids
                .into_iter()
                .map(|id| candidate_view(&live.compass_space, compass_ws, id))
                .collect(),
            stale,
            override_reason: None,
        },
        ReviewProjection::Bound(evaluation) => {
            let author_id = evaluation.request.author();
            let target = evaluation
                .request
                .target()
                .and_then(|handle| read_text(compass_ws, handle));
            let author = author_id
                .map(|id| person_name(&live.relations_space, relations_ws.as_deref_mut(), id));
            let requested_at = evaluation
                .request
                .created_at
                .first()
                .copied()
                .and_then(interval_key);
            let mut reasons = Vec::new();
            let (label, progress, tone, settlements) = match &evaluation.state {
                ReviewGateState::Invalid { reasons: why } => {
                    reasons.extend(why.iter().cloned());
                    (
                        "INVALID".to_string(),
                        "0/3".to_string(),
                        GateTone::Bad,
                        Vec::new(),
                    )
                }
                ReviewGateState::Pending {
                    submitted,
                    required,
                } => (
                    "PENDING".to_string(),
                    format!("{submitted}/{required}"),
                    GateTone::Warn,
                    Vec::new(),
                ),
                ReviewGateState::Blocked {
                    submitted,
                    reasons: why,
                } => {
                    reasons.extend(why.iter().cloned());
                    (
                        "BLOCKED".to_string(),
                        format!("{submitted}/3"),
                        GateTone::Bad,
                        Vec::new(),
                    )
                }
                ReviewGateState::Ready => (
                    "READY".to_string(),
                    "3/3".to_string(),
                    GateTone::Good,
                    Vec::new(),
                ),
                ReviewGateState::Settled { settlements } => {
                    let overridden = settlements
                        .iter()
                        .any(|settlement| settlement.mode == SettlementMode::Override);
                    (
                        if overridden { "OVERRIDDEN" } else { "SETTLED" }.to_string(),
                        if overridden { "OVERRIDE" } else { "3/3" }.to_string(),
                        if overridden {
                            GateTone::Warn
                        } else {
                            GateTone::Good
                        },
                        settlements.clone(),
                    )
                }
            };
            let override_reason = settlements
                .iter()
                .find(|settlement| settlement.mode == SettlementMode::Override)
                .and_then(|settlement| settlement.override_event)
                .and_then(|event| {
                    find!(h: TextHandle, pattern!(&live.compass_space, [{ event @ metadata::description: ?h }])).next()
                })
                .and_then(|handle| read_text(compass_ws, handle));
            let sealed_evidence = settlements
                .iter()
                .find(|settlement| settlement.mode == SettlementMode::Attestations)
                .map(|settlement| settlement.attestations.as_slice());
            let retired = retired_person_ids(&live.relations_space);
            let reviewers = evaluation
                .request
                .required
                .iter()
                .copied()
                .map(|reviewer| {
                    let name = person_name(
                        &live.relations_space,
                        relations_ws.as_deref_mut(),
                        reviewer,
                    );
                    // A green ordinary settlement renders its immutable proof
                    // evidence, never a later/current reviewer frontier. An
                    // override has no attestation proof, so its reviewer cards
                    // deliberately preserve the live blockers it bypassed.
                    let heads = if let Some(evidence) = sealed_evidence {
                        evidence
                            .iter()
                            .filter_map(|id| review_attestation(&live.compass_space, *id))
                            .filter(|head| head.reviewer() == Some(reviewer))
                            .collect::<Vec<_>>()
                    } else {
                        evaluation
                            .slots
                            .iter()
                            .find(|slot| slot.reviewer == reviewer)
                            .map(|slot| slot.heads.clone())
                            .unwrap_or_default()
                    }
                    .into_iter()
                    .map(|head| AttestationView {
                        id: head.id,
                        verdict: head.verdict().unwrap_or("malformed").to_string(),
                        report: head
                            .report()
                            .and_then(|handle| read_text(compass_ws, handle))
                            .unwrap_or_default(),
                    })
                    .collect();
                    ReviewerView {
                        id: reviewer,
                        name,
                        author: author_id == Some(reviewer),
                        retired: retired.contains(&reviewer),
                        heads,
                    }
                })
                .collect();
            let certificates = settlements
                .into_iter()
                .map(|settlement| CertificateView {
                    id: settlement.id,
                    mode: settlement.mode,
                    attestations: settlement.attestations,
                    override_event: settlement.override_event,
                })
                .collect();
            SettlementView {
                label,
                progress,
                tone,
                request_id: Some(evaluation.request.id),
                target,
                author,
                requested_at,
                reasons,
                reviewers,
                certificates,
                candidates: Vec::new(),
                stale,
                override_reason,
            }
        }
    }
}

// ── On-demand queries ────────────────────────────────────────────────

/// Active review goals plus every goal carrying structured review history.
/// Active work sorts first, then each group is newest-status-first. Returns
/// `(goal_id, latest_status, latest_status_at)`.
fn review_goals(space: &TribleSet) -> Vec<(Id, String, i128)> {
    // Reuse the schema's timestamp + event-id tie-break so every projection
    // agrees after equal-time events merge.
    let mut goals: Vec<(Id, String, i128)> = find!(
        gid: Id,
        pattern!(space, [{ ?gid @ metadata::tag: &KIND_GOAL_ID }])
    )
    .filter_map(|gid| {
        latest_status_event(space, gid)
            .and_then(|(_, status, at)| interval_key(at).map(|ts| (gid, status, ts)))
    })
    .filter(|(gid, status, _)| {
        status == REVIEW_STATUS || !all_request_ids_for_goal(space, *gid).is_empty()
    })
    .collect();
    goals.sort_by(|a, b| {
        let a_active = a.1 == REVIEW_STATUS;
        let b_active = b.1 == REVIEW_STATUS;
        b_active
            .cmp(&a_active)
            .then_with(|| b.2.cmp(&a.2))
            .then_with(|| a.0.cmp(&b.0))
    });
    goals
}

fn goal_title(space: &TribleSet, ws: &mut Workspace<Pile>, goal_id: Id) -> String {
    find!(
        h: TextHandle,
        pattern!(space, [{
            goal_id @
            metadata::tag: &KIND_GOAL_ID,
            compass::title: ?h,
        }])
    )
    .next()
    .and_then(|h| read_text(ws, h))
    .unwrap_or_else(|| "(untitled)".to_string())
}

fn goal_tags(space: &TribleSet, goal_id: Id) -> Vec<String> {
    let mut tags: Vec<String> = find!(
        tag: String,
        pattern!(space, [{
            goal_id @
            metadata::tag: &KIND_GOAL_ID,
            compass::tag: ?tag,
        }])
    )
    .collect();
    tags.sort();
    tags
}

fn goal_created_at(space: &TribleSet, goal_id: Id) -> Option<i128> {
    find!(
        ts: (i128, i128),
        pattern!(space, [{
            goal_id @
            metadata::tag: &KIND_GOAL_ID,
            metadata::created_at: ?ts,
        }])
    )
    .next()
    .map(|ts| ts.0)
}

/// Notes on a goal, newest-first: (created_at, body).
fn goal_notes(
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
    goal_id: Id,
) -> Vec<(Option<i128>, String)> {
    let raw: Vec<(TextHandle, (i128, i128))> = find!(
        (h: TextHandle, ts: (i128, i128)),
        pattern!(space, [{
            _?event @
            metadata::tag: &KIND_NOTE_ID,
            compass::task: &goal_id,
            compass::note: ?h,
            metadata::created_at: ?ts,
        }])
    )
    .collect();
    let mut notes: Vec<(Option<i128>, String)> = raw
        .into_iter()
        .map(|(h, ts)| (Some(ts.0), read_text(ws, h).unwrap_or_default()))
        .collect();
    notes.sort_by(|a, b| b.0.cmp(&a.0));
    notes
}

/// Extract candidate fragment references from note bodies: every
/// 32-hex id, in order of first appearance, deduped, minus the goal's
/// own id. See [`hex32_regex`] for why this is a regex and not an edge.
fn referenced_ids(notes: &[(Option<i128>, String)], goal_id: Id) -> Vec<Id> {
    let mut seen: HashSet<Id> = HashSet::new();
    let mut out = Vec::new();
    for (_, body) in notes {
        for m in hex32_regex().find_iter(body) {
            if let Some(id) = Id::from_hex(m.as_str()) {
                if id != goal_id && seen.insert(id) {
                    out.push(id);
                }
            }
        }
    }
    out
}

/// Resolve a referenced id against the wiki: the id may be a fragment
/// id or one of its version ids. Returns (fragment_id, latest_version).
fn resolve_wiki_fragment(wiki_space: &TribleSet, id: Id) -> Option<(Id, Id)> {
    // Fragment id? (has at least one version pointing at it)
    let is_fragment = find!(
        vid: Id,
        pattern!(wiki_space, [{
            ?vid @
            metadata::tag: &KIND_VERSION_ID,
            wiki::fragment: &id,
        }])
    )
    .next()
    .is_some();
    let frag = if is_fragment {
        id
    } else {
        // Version id? — hop to its fragment.
        find!(frag: Id, pattern!(wiki_space, [{ id @ wiki::fragment: ?frag }])).next()?
    };
    let latest = find!(
        (vid: Id, ts: (i128, i128)),
        pattern!(wiki_space, [{
            ?vid @
            metadata::tag: &KIND_VERSION_ID,
            wiki::fragment: &frag,
            metadata::created_at: ?ts,
        }])
    )
    .max_by_key(|(_, ts)| ts.0)
    .map(|(vid, _)| vid)?;
    Some((frag, latest))
}

/// Decisions whose about-edge points at the goal (see
/// `schemas/decide.rs` + `src/bin/decide.rs`: `decide propose --about
/// <goal-id>` writes `decide::about`).
fn decisions_about(space: &TribleSet, goal_id: Id) -> Vec<Id> {
    let mut ids: Vec<Id> = find!(
        d: Id,
        pattern!(space, [{
            ?d @
            metadata::tag: &KIND_DECISION,
            decide_attrs::about: &goal_id,
        }])
    )
    .collect();
    ids.sort();
    ids
}

/// One-liner texts of a decision's factors of `kind`, oldest-first.
fn decision_factors(
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
    decision_id: Id,
    kind: Id,
) -> Vec<String> {
    let rows: Vec<(TextHandle, (i128, i128))> = find!(
        (h: TextHandle, ts: (i128, i128)),
        pattern!(space, [{
            _?f @
            metadata::tag: &kind,
            factor::about_decision: &decision_id,
            metadata::name: ?h,
            metadata::created_at: ?ts,
        }])
    )
    .collect();
    let mut rows = rows;
    rows.sort_by_key(|(_, ts)| ts.0);
    rows.into_iter()
        .map(|(h, _)| read_text(ws, h).unwrap_or_else(|| "(unnamed)".into()))
        .collect()
}

// ── Widget ───────────────────────────────────────────────────────────

/// GORBIE-embeddable review bench. See the module docs.
pub struct ReviewPanel {
    live: Option<ReviewLive>,
}

impl Default for ReviewPanel {
    fn default() -> Self {
        Self { live: None }
    }
}

impl ReviewPanel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Render the bench. `compass_ws` and `relations_ws` are required because
    /// exact gate validation needs the frozen identities; `wiki_ws` and
    /// `decide_ws` are optional, in which case linked context simply does not
    /// resolve. READ-ONLY: no commits, no pushes.
    pub fn render(
        &mut self,
        ctx: &mut CardCtx<'_>,
        compass_ws: &mut Workspace<Pile>,
        mut wiki_ws: Option<&mut Workspace<Pile>>,
        decide_ws: Option<&mut Workspace<Pile>>,
        relations_ws: &mut Workspace<Pile>,
    ) {
        let mut decide_ws = decide_ws;
        let compass_head = compass_ws.head();
        let wiki_head = wiki_ws.as_ref().and_then(|ws| ws.head());
        let decide_head = decide_ws.as_ref().and_then(|ws| ws.head());
        let relations_head = relations_ws.head();
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => {
                l.compass_head != compass_head
                    || l.wiki_head != wiki_head
                    || l.decide_head != decide_head
                    || l.relations_head != relations_head
            }
        };
        if need_refresh {
            self.live = Some(ReviewLive::refresh(
                compass_ws,
                wiki_ws.as_deref_mut(),
                decide_ws.as_deref_mut(),
                Some(&mut *relations_ws),
            ));
        }
        let Some(live) = self.live.as_ref() else {
            return;
        };

        let goals = review_goals(&live.compass_space);
        let active_count = goals
            .iter()
            .filter(|(_, status, _)| status == REVIEW_STATUS)
            .count();
        let history_count = goals.len().saturating_sub(active_count);
        let now = now_tai_ns();

        ctx.section("Review", |ctx| {
            // Header count line.
            {
                let ui = ctx.ui_mut();
                ui.label(
                    egui::RichText::new(format!(
                        "{active_count} ACTIVE · {history_count} HISTORICAL"
                    ))
                    .monospace()
                    .strong()
                    .small()
                    .color(color_muted(ui)),
                );
            }

            if goals.is_empty() {
                let ui = ctx.ui_mut();
                ui.add_space(16.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        egui::RichText::new("\u{2705}") // ✅
                            .size(28.0)
                            .color(color_muted(ui)),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new("No review activity yet.")
                            .monospace()
                            .small()
                            .strong()
                            .color(color_muted(ui)),
                    );
                    ui.add_space(2.0);
                    ui.label(
                        egui::RichText::new(
                            "`compass review open` binds an exact candidate and assigns its frozen triad.",
                        )
                        .small()
                        .color(color_muted(ui)),
                    );
                });
                ui.add_space(16.0);
                return;
            }

            for (goal_id, latest_status, status_at) in &goals {
                let goal_id = *goal_id;
                let title = goal_title(&live.compass_space, compass_ws, goal_id);
                let settlement = build_settlement_view(
                    live,
                    goal_id,
                    compass_ws,
                    Some(&mut *relations_ws),
                );
                let title_line = title.lines().next().unwrap_or("").trim();
                // Include the id prefix in the section title so two
                // same-titled goals don't share a persisted fold state.
                let header = format!(
                    "{} · {} · {} · {} · {}",
                    if title_line.is_empty() {
                        "(untitled)"
                    } else {
                        title_line
                    },
                    &fmt_id(goal_id)[..8],
                    settlement.header_target(),
                    settlement.progress,
                    settlement.label,
                );
                // Per-goal collapsed-by-default section — inherits the
                // notebook-wide `set_default_section_open(false)`
                // dashboard default (headless captures force open).
                ctx.section(&header, |ctx| {
                    render_goal(
                        ctx,
                        live,
                        goal_id,
                        latest_status,
                        *status_at,
                        now,
                        compass_ws,
                        wiki_ws.as_deref_mut(),
                        decide_ws.as_deref_mut(),
                        &settlement,
                    );
                });
            }
        });
    }
}

// ── Per-goal rendering ───────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn render_goal(
    ctx: &mut CardCtx<'_>,
    live: &ReviewLive,
    goal_id: Id,
    latest_status: &str,
    status_at: i128,
    now: i128,
    compass_ws: &mut Workspace<Pile>,
    mut wiki_ws: Option<&mut Workspace<Pile>>,
    mut decide_ws: Option<&mut Workspace<Pile>>,
    settlement: &SettlementView,
) {
    let tags = goal_tags(&live.compass_space, goal_id);
    let created_at = goal_created_at(&live.compass_space, goal_id);
    let notes = goal_notes(&live.compass_space, compass_ws, goal_id);
    let refs = referenced_ids(&notes, goal_id);
    let decisions = decisions_about(&live.decide_space, goal_id);

    ctx.grid(|g| {
        // Meta row: id · ages · tags.
        g.full(|ctx| {
            let ui = ctx.ui_mut();
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = egui::vec2(6.0, 4.0);
                ui.label(
                    egui::RichText::new(fmt_id(goal_id))
                        .monospace()
                        .small()
                        .color(color_muted(ui)),
                );
                let status_label = if latest_status == REVIEW_STATUS {
                    "IN REVIEW".to_string()
                } else {
                    latest_status.to_uppercase()
                };
                ui.label(
                    egui::RichText::new(format!(
                        "{} {} · CREATED {}",
                        status_label,
                        format_age(now, Some(status_at)),
                        format_age(now, created_at),
                    ))
                    .monospace()
                    .small()
                    .strong()
                    .color(color_muted(ui)),
                );
                for tag in &tags {
                    render_chip(
                        ui,
                        &format!("#{tag}"),
                        colorhash::ral_categorical(tag.as_bytes()),
                    );
                }
            });
        });

        // ── Revision-bound settlement ──
        let state_label = settlement.label.clone();
        let progress = settlement.progress.clone();
        let tone = settlement.tone;
        let request_id = settlement.request_id;
        let target = settlement.target.clone();
        let author = settlement.author.clone();
        let requested_at = settlement.requested_at;
        g.full(move |ctx| {
            let ui = ctx.ui_mut();
            ui.add_space(4.0);
            paper_frame(ui)
                .inner_margin(egui::Margin {
                    left: 8,
                    right: 8,
                    top: 7,
                    bottom: 7,
                })
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal_wrapped(|ui| {
                        render_chip(ui, &state_label, gate_color(ui, tone));
                        ui.label(egui::RichText::new(&progress).monospace().strong().small());
                        if let Some(request_id) = request_id {
                            ui.label(
                                egui::RichText::new(format!("request {}", fmt_id(request_id)))
                                    .monospace()
                                    .small()
                                    .color(color_muted(ui)),
                            );
                        }
                        if let Some(author) = author.as_deref() {
                            ui.label(
                                egui::RichText::new(format!("author {author}"))
                                    .small()
                                    .color(color_muted(ui)),
                            );
                        }
                        if requested_at.is_some() {
                            ui.label(
                                egui::RichText::new(format!(
                                    "requested {}",
                                    format_age(now, requested_at)
                                ))
                                .small()
                                .color(color_muted(ui)),
                            );
                        }
                    });
                    if let Some(target) = target.as_deref() {
                        ui.add_space(5.0);
                        ui.label(
                            egui::RichText::new("EXACT CANDIDATE")
                                .monospace()
                                .strong()
                                .small()
                                .color(color_muted(ui)),
                        );
                        ui.add(
                            egui::Label::new(egui::RichText::new(target).monospace().small())
                                .wrap_mode(egui::TextWrapMode::Wrap),
                        );
                    }
                });
        });

        for reason in &settlement.reasons {
            let reason = reason.clone();
            g.full(move |ctx| {
                let ui = ctx.ui_mut();
                ui.label(
                    egui::RichText::new(reason)
                        .small()
                        .strong()
                        .color(color_con()),
                );
            });
        }

        for certificate in &settlement.certificates {
            let certificate = certificate.clone();
            g.full(move |ctx| {
                let ui = ctx.ui_mut();
                paper_frame(ui)
                    .inner_margin(egui::Margin::same(7))
                    .show(ui, |ui| {
                        let mode = match certificate.mode {
                            SettlementMode::Attestations => "TRIADIC CERTIFICATE",
                            SettlementMode::Override => "BREAK-GLASS CERTIFICATE",
                        };
                        ui.horizontal_wrapped(|ui| {
                            render_chip(ui, mode, color_resolved());
                            ui.label(
                                egui::RichText::new(fmt_id(certificate.id))
                                    .monospace()
                                    .small()
                                    .color(color_muted(ui)),
                            );
                        });
                        for evidence in &certificate.attestations {
                            ui.label(
                                egui::RichText::new(format!(
                                    "SEALED ATTESTATION {}",
                                    fmt_id(*evidence)
                                ))
                                .monospace()
                                .small(),
                            );
                        }
                        if let Some(event) = certificate.override_event {
                            ui.label(
                                egui::RichText::new(format!(
                                    "SEALED OVERRIDE EVENT {}",
                                    fmt_id(event)
                                ))
                                .monospace()
                                .small(),
                            );
                        }
                    });
            });
        }

        if let Some(reason) = settlement.override_reason.clone() {
            g.full(move |ctx| {
                let ui = ctx.ui_mut();
                ui.label(
                    egui::RichText::new("BREAK-GLASS REASON")
                        .monospace()
                        .strong()
                        .small()
                        .color(color_resolved()),
                );
                ui.add(
                    egui::Label::new(egui::RichText::new(reason).small())
                        .wrap_mode(egui::TextWrapMode::Wrap),
                );
            });
        }

        for candidate in &settlement.candidates {
            let candidate = candidate.clone();
            g.full(move |ctx| {
                let ui = ctx.ui_mut();
                paper_frame(ui)
                    .inner_margin(egui::Margin::same(7))
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(format!("FORK HEAD {}", fmt_id(candidate.id)))
                                .monospace()
                                .strong()
                                .small()
                                .color(color_con()),
                        );
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(candidate.target).monospace().small(),
                            )
                            .wrap_mode(egui::TextWrapMode::Wrap),
                        );
                    });
            });
        }

        for reviewer in &settlement.reviewers {
            let reviewer = reviewer.clone();
            g.full(move |ctx| {
                let ui = ctx.ui_mut();
                paper_frame(ui)
                    .inner_margin(egui::Margin::same(7))
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(egui::RichText::new(&reviewer.name).strong());
                            if reviewer.author {
                                render_chip(ui, "AUTHOR", color_resolved());
                            }
                            if reviewer.retired {
                                let retired_color = color_muted(ui);
                                render_chip(ui, "RETIRED", retired_color);
                            }
                            ui.label(
                                egui::RichText::new(fmt_id(reviewer.id))
                                    .monospace()
                                    .small()
                                    .color(color_muted(ui)),
                            );
                        });
                        match reviewer.heads.as_slice() {
                            [] => {
                                ui.label(
                                    egui::RichText::new("PENDING")
                                        .monospace()
                                        .strong()
                                        .small()
                                        .color(color_muted(ui)),
                                );
                            }
                            [head] => {
                                let fill = match head.verdict.as_str() {
                                    "approve" => color_pro(),
                                    "request-changes" => color_con(),
                                    _ => color_resolved(),
                                };
                                ui.horizontal_wrapped(|ui| {
                                    render_chip(ui, &head.verdict.to_uppercase(), fill);
                                    ui.label(
                                        egui::RichText::new(fmt_id(head.id))
                                            .monospace()
                                            .small()
                                            .color(color_muted(ui)),
                                    );
                                });
                                if !head.report.is_empty() {
                                    ui.add(
                                        egui::Label::new(egui::RichText::new(&head.report).small())
                                            .wrap_mode(egui::TextWrapMode::Wrap),
                                    );
                                }
                            }
                            heads => {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "FORKED — {} ACTIVE ATTESTATIONS",
                                        heads.len()
                                    ))
                                    .monospace()
                                    .strong()
                                    .small()
                                    .color(color_con()),
                                );
                                for head in heads {
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "{} · {}",
                                            fmt_id(head.id),
                                            head.verdict
                                        ))
                                        .monospace()
                                        .small(),
                                    );
                                }
                            }
                        }
                    });
                ui.add_space(3.0);
            });
        }

        if !settlement.stale.is_empty() {
            let stale = settlement.stale.clone();
            g.full(move |ctx| {
                let ui = ctx.ui_mut();
                ui.label(
                    egui::RichText::new(format!("STALE CANDIDATES ({})", stale.len()))
                        .monospace()
                        .strong()
                        .small()
                        .color(color_muted(ui)),
                );
                for candidate in stale {
                    ui.label(
                        egui::RichText::new(format!(
                            "{} · {}",
                            fmt_id(candidate.id),
                            candidate.target
                        ))
                        .monospace()
                        .small()
                        .color(color_muted(ui)),
                    );
                }
            });
        }

        // ── Notes ──
        g.full(|ctx| {
            let ui = ctx.ui_mut();
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(format!("NOTES ({})", notes.len()))
                    .monospace()
                    .strong()
                    .small()
                    .color(color_muted(ui)),
            );
        });
        if notes.is_empty() {
            g.full(|ctx| {
                let ui = ctx.ui_mut();
                ui.label(
                    egui::RichText::new("no notes")
                        .small()
                        .color(color_muted(ui)),
                );
            });
        }
        for (at, body) in &notes {
            let at = *at;
            g.full(|ctx| {
                let ui = ctx.ui_mut();
                paper_frame(ui)
                    .inner_margin(egui::Margin {
                        left: 8,
                        right: 6,
                        top: 4,
                        bottom: 4,
                    })
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(
                            egui::RichText::new(format_age(now, at))
                                .small()
                                .monospace()
                                .color(color_muted(ui)),
                        );
                        ui.add(
                            egui::Label::new(egui::RichText::new(body).small())
                                .wrap_mode(egui::TextWrapMode::Wrap),
                        );
                    });
                ui.add_space(3.0);
            });
        }

        // ── Referenced wiki fragments ──
        if !refs.is_empty() {
            g.full(|ctx| {
                let ui = ctx.ui_mut();
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(format!("REFERENCES ({})", refs.len()))
                        .monospace()
                        .strong()
                        .small()
                        .color(color_muted(ui)),
                );
            });
        }
        for rid in &refs {
            let rid = *rid;
            match resolve_wiki_fragment(&live.wiki_space, rid) {
                Some((frag_id, vid)) => {
                    let title = find!(
                        h: TextHandle,
                        pattern!(&live.wiki_space, [{ vid @ wiki::title: ?h }])
                    )
                    .next()
                    .and_then(|h| wiki_ws.as_deref_mut().and_then(|ws| read_text(ws, h)))
                    .unwrap_or_default();
                    let content = find!(
                        h: TextHandle,
                        pattern!(&live.wiki_space, [{ vid @ wiki::content: ?h }])
                    )
                    .next()
                    .and_then(|h| wiki_ws.as_deref_mut().and_then(|ws| read_text(ws, h)))
                    .unwrap_or_default();
                    g.full(move |ctx| {
                        let frag_col = colorhash::ral_categorical(frag_id.as_ref());
                        {
                            let ui = ctx.ui_mut();
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 8.0;
                                let (dot_rect, _) = ui.allocate_exact_size(
                                    egui::vec2(10.0, 10.0),
                                    egui::Sense::hover(),
                                );
                                ui.painter().circle_filled(dot_rect.center(), 5.0, frag_col);
                                ui.add(
                                    egui::Label::new(egui::RichText::new(&title).strong()).wrap(),
                                );
                                ui.label(
                                    egui::RichText::new(format!("wiki:{}", fmt_id(frag_id)))
                                        .monospace()
                                        .small()
                                        .color(frag_col),
                                );
                            });
                        }
                        // Reuse the wiki widget's typst rendering path
                        // (incl. wiki:/files: link interception so egui
                        // doesn't try to shell-open them). The bench is
                        // an auditing surface — clicks are swallowed;
                        // open the wiki section to navigate.
                        let _ = render_wiki_content(ctx, &content);
                        ctx.ui_mut().add_space(6.0);
                    });
                }
                None => {
                    g.full(move |ctx| {
                        let ui = ctx.ui_mut();
                        ui.label(
                            egui::RichText::new(format!(
                                "{} — not a wiki fragment (goal/decision id or dangling)",
                                fmt_id(rid)
                            ))
                            .monospace()
                            .small()
                            .color(color_muted(ui)),
                        );
                    });
                }
            }
        }

        // ── Linked decisions ──
        if !decisions.is_empty() {
            g.full(|ctx| {
                let ui = ctx.ui_mut();
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(format!("DECISIONS ({})", decisions.len()))
                        .monospace()
                        .strong()
                        .small()
                        .color(color_muted(ui)),
                );
            });
        }
        for did in &decisions {
            let did = *did;
            let title = find!(
                h: TextHandle,
                pattern!(&live.decide_space, [{
                    did @ metadata::tag: &KIND_DECISION, metadata::name: ?h,
                }])
            )
            .next()
            .and_then(|h| decide_ws.as_deref_mut().and_then(|ws| read_text(ws, h)))
            .unwrap_or_else(|| "(untitled)".to_string());
            let outcome = find!(
                h: TextHandle,
                pattern!(&live.decide_space, [{
                    did @ metadata::tag: &KIND_DECISION, decide_attrs::outcome: ?h,
                }])
            )
            .next()
            .and_then(|h| decide_ws.as_deref_mut().and_then(|ws| read_text(ws, h)));
            let finished = find!(
                ts: (i128, i128),
                pattern!(&live.decide_space, [{
                    did @ metadata::tag: &KIND_DECISION, metadata::finished_at: ?ts,
                }])
            )
            .next()
            .is_some();
            let pros = match decide_ws.as_deref_mut() {
                Some(ws) => decision_factors(&live.decide_space, ws, did, KIND_PRO),
                None => Vec::new(),
            };
            let cons = match decide_ws.as_deref_mut() {
                Some(ws) => decision_factors(&live.decide_space, ws, did, KIND_CON),
                None => Vec::new(),
            };
            let resolved = finished && outcome.as_deref().map_or(false, |o| !o.trim().is_empty());

            g.full(move |ctx| {
                let ui = ctx.ui_mut();
                paper_frame(ui)
                    .inner_margin(egui::Margin {
                        left: 8,
                        right: 8,
                        top: 6,
                        bottom: 6,
                    })
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing.x = 6.0;
                            ui.label(egui::RichText::new(&title).strong());
                            let (label, fill) = if resolved {
                                ("RESOLVED", color_resolved())
                            } else {
                                ("PROPOSED", color_muted(ui))
                            };
                            render_chip(ui, label, fill);
                            ui.label(
                                egui::RichText::new(fmt_id(did))
                                    .monospace()
                                    .small()
                                    .color(color_muted(ui)),
                            );
                        });
                        ui.add_space(4.0);
                        ui.columns(2, |cols| {
                            render_factor_column(&mut cols[0], "PROS", color_pro(), &pros);
                            render_factor_column(&mut cols[1], "CONS", color_con(), &cons);
                        });
                        if let Some(outcome) = outcome.as_deref() {
                            if !outcome.trim().is_empty() {
                                ui.add_space(4.0);
                                ui.separator();
                                ui.label(
                                    egui::RichText::new("OUTCOME")
                                        .monospace()
                                        .small()
                                        .strong()
                                        .color(color_resolved()),
                                );
                                ui.add(
                                    egui::Label::new(egui::RichText::new(outcome).small())
                                        .wrap_mode(egui::TextWrapMode::Wrap),
                                );
                            }
                        }
                    });
                ui.add_space(3.0);
            });
        }
    });
}

fn render_factor_column(
    ui: &mut egui::Ui,
    heading: &str,
    accent: egui::Color32,
    factors: &[String],
) {
    ui.vertical(|ui| {
        ui.label(
            egui::RichText::new(heading)
                .monospace()
                .strong()
                .small()
                .color(accent),
        );
        if factors.is_empty() {
            ui.label(
                egui::RichText::new("\u{2014}") // em dash
                    .small()
                    .color(color_muted(ui)),
            );
            return;
        }
        for f in factors {
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                ui.label(egui::RichText::new("\u{2022}").small().color(accent));
                ui.add(
                    egui::Label::new(egui::RichText::new(f).small())
                        .wrap_mode(egui::TextWrapMode::Wrap),
                );
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schemas::compass::KIND_STATUS_ID;
    use hifitime::Epoch;
    use triblespace::macros::entity;
    use triblespace::prelude::*;

    fn at(second: u8) -> crate::schemas::compass::IntervalValue {
        let epoch = Epoch::from_gregorian_utc(2026, 7, 13, 12, 0, second, 0);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn add_goal(space: &mut TribleSet, goal: Id) {
        *space += entity! { ExclusiveId::force_ref(&goal) @
            metadata::tag: &KIND_GOAL_ID,
        };
    }

    fn add_status(space: &mut TribleSet, goal: Id, status: &str, second: u8) {
        let event = ufoid();
        *space += entity! { &event @
            metadata::tag: &KIND_STATUS_ID,
            compass::task: &goal,
            compass::status: status,
            metadata::created_at: at(second),
        };
    }

    #[test]
    fn bench_retains_structured_history_after_settlement() {
        let mut space = TribleSet::new();
        let active = ufoid().id;
        let settled = ufoid().id;
        let ordinary_done = ufoid().id;
        for goal in [active, settled, ordinary_done] {
            add_goal(&mut space, goal);
        }

        add_status(&mut space, active, REVIEW_STATUS, 1);

        let request = ufoid();
        space += entity! { &request @
            metadata::tag: &crate::schemas::compass::KIND_REVIEW_REQUEST_ID,
            metadata::tag: &KIND_STATUS_ID,
            compass::task: &settled,
            compass::status: REVIEW_STATUS,
            metadata::created_at: at(2),
        };
        add_status(&mut space, settled, crate::schemas::compass::DONE_STATUS, 3);
        add_status(
            &mut space,
            ordinary_done,
            crate::schemas::compass::DONE_STATUS,
            4,
        );

        let rows = review_goals(&space);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, active, "active reviews sort before history");
        assert_eq!(rows[0].1, REVIEW_STATUS);
        assert_eq!(rows[1].0, settled);
        assert_eq!(rows[1].1, crate::schemas::compass::DONE_STATUS);
    }
}
