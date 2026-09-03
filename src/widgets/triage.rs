//! Read-only GORBIE-embeddable viewer for the `triage` faculty.
//!
//! Triage is the diagnostic faculty: it cross-references canonical Cognition,
//! Headspace, Secrets, Relations, and Messages collection snapshots to surface
//! "what is the agent doing right now and what recently went wrong". The
//! widget consumes the same library read model as `triage scan`; it does not
//! maintain a second event projector.
//!
//! Card shape:
//! - Top: dashboard card with disjoint EXEC and MODEL request states plus
//!   Headspace, inbox, Relations, attempt-fork, and loop diagnostics.
//! - Below: a chronological feed of recent activity, newest first.
//!   Each event renders as a small card with a kind-coloured header
//!   (EXEC / MODEL / REASON), a short summary line, and the
//!   canonical entity id at the bottom.
//!
//! v1 limits: no turn-level drill-down and no live token-usage histogram
//! (just totals per event when present).
//!
//! ```ignore
//! let mut panel = TriageViewer::default();
//! panel.render(ctx, cognition, headspace, secrets, relations, messages);
//! ```

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use crate::storage::FactArchive;
use crate::triage::{
    self as triage_model, PatternSummary, QueueCounts, ScanOptions, ScanReport, ScanSources,
    SourceView, UnreadMessages, UnreadUnavailable,
};
use crate::widgets::storage::{DatasetRevision, DatasetView, SecretsView};
use triblespace::core::id::Id;

/// How many timeline events to keep in the live snapshot. Older
/// entries are still in the pile — `triage timeline` is the right
/// tool for full history.
const MAX_EVENTS: usize = 40;

/// "Stale" threshold for in-progress entries — entries older than
/// this without resolving are flagged in the scan dashboard.
const STALE_SECONDS: i64 = 15 * 60;

// ── Palette ──────────────────────────────────────────────────────────

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

/// RAL 6018 yellow-green — exec activity (commands running).
fn color_exec() -> egui::Color32 {
    egui::Color32::from_rgb(0x57, 0xa6, 0x39)
}

/// RAL 5012 light blue — model activity (LLM calls).
fn color_model() -> egui::Color32 {
    egui::Color32::from_rgb(0x3b, 0x83, 0xbd)
}

/// RAL 1003 signal yellow — reason events (explicit thoughts).
fn color_reason() -> egui::Color32 {
    egui::Color32::from_rgb(0xf7, 0xba, 0x0b)
}

/// RAL 3020 traffic red — error / non-zero exit.
fn color_error() -> egui::Color32 {
    egui::Color32::from_rgb(0xcc, 0x0a, 0x17)
}

fn mix(a: egui::Color32, b: egui::Color32, t: f32) -> egui::Color32 {
    let t = t.clamp(0.0, 1.0);
    let lerp = |x: u8, y: u8| {
        ((x as f32) * (1.0 - t) + (y as f32) * t)
            .round()
            .clamp(0.0, 255.0) as u8
    };
    egui::Color32::from_rgb(lerp(a.r(), b.r()), lerp(a.g(), b.g()), lerp(a.b(), b.b()))
}

// ── Data ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EventKind {
    ExecResult,
    ModelResult,
    Reason,
}

impl EventKind {
    fn color(self) -> egui::Color32 {
        match self {
            EventKind::ExecResult => color_exec(),
            EventKind::ModelResult => color_model(),
            EventKind::Reason => color_reason(),
        }
    }

    fn label(self) -> &'static str {
        match self {
            EventKind::ExecResult => "EXEC",
            EventKind::ModelResult => "MODEL",
            EventKind::Reason => "REASON",
        }
    }
}

#[derive(Clone, Debug)]
struct EventRow {
    id: Id,
    kind: EventKind,
    at: Option<i128>,
    /// One-line summary used as the card heading. Exec: command
    /// (or error). Model: first 80 chars of output_text (or error).
    /// Reason: first 80 chars of text.
    summary: String,
    /// Optional secondary text — typically the exec exit code,
    /// model token usage, or a longer error stub.
    detail: Option<String>,
    /// True when this event represents a failure (non-zero exec
    /// exit, or model.error set). Renders with the error accent.
    is_error: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TriageRevisions {
    cognition: DatasetRevision,
    headspace: DatasetRevision,
    secrets: DatasetRevision,
    relations: DatasetRevision,
    messages: DatasetRevision,
}

struct TriageLive {
    cached_revisions: TriageRevisions,
    report: Option<ScanReport>,
    exec: QueueCounts,
    model: QueueCounts,
    events: Vec<EventRow>,
    total_events: usize,
    diagnostic: Option<String>,
    headspace_error: Option<String>,
    config_heads: usize,
    active_profile_heads: usize,
    persona_id: Option<Id>,
    relation_forks: usize,
    exec_fork_history: usize,
    model_fork_history: usize,
    lifecycle_diagnostics: Vec<String>,
    unread_messages: UnreadMessages,
    probable_loop: Option<PatternSummary>,
    suggestions: Vec<String>,
}

fn source_view<'a>(view: DatasetView<'a>) -> SourceView<'a, FactArchive> {
    SourceView {
        facts: view.facts,
        reader: view.reader,
    }
}

// ── Live snapshot ────────────────────────────────────────────────────

impl TriageLive {
    fn refresh(
        cognition: DatasetView<'_>,
        headspace: DatasetView<'_>,
        secrets: SecretsView<'_>,
        relations: DatasetView<'_>,
        messages: DatasetView<'_>,
    ) -> Self {
        let cached_revisions = TriageRevisions {
            cognition: cognition.revision,
            headspace: headspace.revision,
            secrets: secrets.revision,
            relations: relations.revision,
            messages: messages.revision,
        };
        let report = triage_model::project_scan(
            ScanSources {
                cognition: source_view(cognition),
                headspace: source_view(headspace),
                secrets: secrets.snapshot,
                relations: source_view(relations),
                messages: source_view(messages),
            },
            ScanOptions {
                now: triage_model::now_tai_ns().ok(),
                stale_after_ns: STALE_SECONDS as i128 * 1_000_000_000,
                recent_attempts: MAX_EVENTS,
                loop_min: 3,
            },
        );
        match report {
            Ok(report) => Self::from_report(cached_revisions, report),
            Err(error) => Self {
                cached_revisions,
                report: None,
                exec: QueueCounts::default(),
                model: QueueCounts::default(),
                events: Vec::new(),
                total_events: 0,
                diagnostic: Some(format!("{error:#}")),
                headspace_error: None,
                config_heads: 0,
                active_profile_heads: 0,
                persona_id: None,
                relation_forks: 0,
                exec_fork_history: 0,
                model_fork_history: 0,
                lifecycle_diagnostics: Vec::new(),
                unread_messages: UnreadMessages::Unavailable(UnreadUnavailable::HeadspaceUnsettled),
                probable_loop: None,
                suggestions: Vec::new(),
            },
        }
    }
    fn from_report(cached_revisions: TriageRevisions, report: ScanReport) -> Self {
        let mut events = Vec::new();
        for result in &report.exec_state.results {
            let command = report
                .exec_state
                .requests
                .get(&result.about_request)
                .map(|request| request.command.as_str());
            let summary = command
                .map(|command| first_line(command, 80))
                .or_else(|| {
                    result
                        .error
                        .as_deref()
                        .map(|error| format!("error: {}", first_line(error, 60)))
                })
                .unwrap_or_else(|| "(exec result with missing request)".to_owned());
            let mut details = Vec::new();
            if let Some(exit) = result.exit_code {
                details.push(format!("exit {exit}"));
            }
            if let Some(error) = result.error.as_deref() {
                details.push(first_line(error, 80));
            } else if result.exit_code.unwrap_or(0) != 0 {
                if let Some(stderr) = result.stderr_text.as_deref() {
                    details.push(first_line(stderr, 80));
                }
            }
            events.push(EventRow {
                id: result.id,
                kind: EventKind::ExecResult,
                at: Some(result.finished_at),
                summary,
                detail: (!details.is_empty()).then(|| details.join(" · ")),
                is_error: result.error.is_some() || result.exit_code.is_some_and(|code| code != 0),
            });
        }
        for result in &report.model_state.results {
            let summary = result
                .output_text
                .as_deref()
                .map(|output| first_line(output, 80))
                .or_else(|| {
                    result
                        .error
                        .as_deref()
                        .map(|error| format!("error: {}", first_line(error, 60)))
                })
                .unwrap_or_else(|| "(model result)".to_owned());
            let mut details = Vec::new();
            if let Some(input) = result.input_tokens {
                details.push(format!("{} in", format_count(input)));
            }
            if let Some(output) = result.output_tokens {
                details.push(format!("{} out", format_count(output)));
            }
            if let Some(error) = result.error.as_deref() {
                details.push(first_line(error, 80));
            }
            events.push(EventRow {
                id: result.id,
                kind: EventKind::ModelResult,
                at: Some(result.finished_at),
                summary,
                detail: (!details.is_empty()).then(|| details.join(" · ")),
                is_error: result.error.is_some(),
            });
        }
        for reason in &report.reason_events {
            events.push(EventRow {
                id: reason.id,
                kind: EventKind::Reason,
                at: reason.created_at,
                summary: reason
                    .text
                    .as_deref()
                    .map(|text| first_line(text, 80))
                    .unwrap_or_else(|| "(reason event without text)".to_owned()),
                detail: reason
                    .command_text
                    .as_deref()
                    .map(|command| format!("→ {}", first_line(command, 60))),
                is_error: false,
            });
        }
        events.sort_by_key(|event| (event.at.unwrap_or(i128::MIN), event.id));
        events.reverse();
        let total_events = events.len();
        events.truncate(MAX_EVENTS);

        let live = Self {
            cached_revisions,
            report: None,
            exec: report.exec_queue.clone(),
            model: report.model_queue.clone(),
            events,
            total_events,
            diagnostic: None,
            headspace_error: report.headspace.unsettled_reason(),
            config_heads: report.headspace.config_heads().len(),
            active_profile_heads: report.headspace.active_profile_heads().len(),
            persona_id: report.headspace.persona_id,
            relation_forks: report.relations.forked_profiles.len(),
            exec_fork_history: report.exec_attempt_forks.len(),
            model_fork_history: report.model_attempt_forks.len(),
            lifecycle_diagnostics: report.lifecycle_diagnostics.clone(),
            unread_messages: report.unread_messages,
            probable_loop: report.probable_loop.clone(),
            suggestions: report.suggestions.clone(),
        };
        Self {
            report: Some(report),
            ..live
        }
    }

    fn refresh_time(&mut self, now: Option<i128>) {
        let Some(report) = self.report.as_mut() else {
            return;
        };
        if let Err(error) = report.refresh_time(now, STALE_SECONDS as i128 * 1_000_000_000) {
            self.diagnostic = Some(format!("{error:#}"));
            return;
        }
        self.exec = report.exec_queue.clone();
        self.model = report.model_queue.clone();
        self.exec_fork_history = report.exec_attempt_forks.len();
        self.model_fork_history = report.model_attempt_forks.len();
        self.lifecycle_diagnostics = report.lifecycle_diagnostics.clone();
        self.suggestions = report.suggestions.clone();
    }
}

fn first_line(text: &str, max: usize) -> String {
    let line = text.lines().next().unwrap_or("").trim();
    if line.chars().count() > max {
        let truncated: String = line.chars().take(max.saturating_sub(1)).collect();
        format!("{truncated}…")
    } else {
        line.to_string()
    }
}

fn format_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f32 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f32 / 1_000.0)
    } else {
        format!("{n}")
    }
}

fn format_time(at: Option<i128>) -> String {
    let Some(at) = at else {
        return "--:--:--".to_owned();
    };
    let ns = at.clamp(i64::MIN as i128, i64::MAX as i128) as i64;
    let epoch =
        hifitime::Epoch::from_tai_duration(hifitime::Duration::from_truncated_nanoseconds(ns));
    let (_, _, _, hour, minute, second, _) = epoch.to_gregorian_utc();
    format!("{hour:02}:{minute:02}:{second:02}")
}

fn age_label(now: Option<i128>, at: Option<i128>) -> String {
    let Some(at) = at else {
        return "TIME UNKNOWN".to_owned();
    };
    let Some(now) = now else {
        return "AGE UNKNOWN".to_owned();
    };
    let secs = (now.saturating_sub(at) / 1_000_000_000).max(0) as i64;
    if secs < 60 {
        format!("{secs}S AGO")
    } else if secs < 3_600 {
        format!("{}M AGO", secs / 60)
    } else if secs < 86_400 {
        format!("{}H AGO", secs / 3_600)
    } else {
        format!("{}D AGO", secs / 86_400)
    }
}

fn id_hex(id: Id) -> String {
    format!("{id:x}")
}

// ── Widget ───────────────────────────────────────────────────────────

pub struct TriageViewer {
    live: Option<TriageLive>,
}

impl Default for TriageViewer {
    fn default() -> Self {
        Self { live: None }
    }
}

impl TriageViewer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn render(
        &mut self,
        ctx: &mut CardCtx<'_>,
        cognition: DatasetView<'_>,
        headspace: DatasetView<'_>,
        secrets: SecretsView<'_>,
        relations: DatasetView<'_>,
        messages: DatasetView<'_>,
    ) {
        let revisions = TriageRevisions {
            cognition: cognition.revision,
            headspace: headspace.revision,
            secrets: secrets.revision,
            relations: relations.revision,
            messages: messages.revision,
        };
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(live) => live.cached_revisions != revisions,
        };
        if need_refresh {
            self.live = Some(TriageLive::refresh(
                cognition, headspace, secrets, relations, messages,
            ));
        }
        let now = triage_model::now_tai_ns().ok();
        if let Some(live) = self.live.as_mut() {
            live.refresh_time(now);
        }

        ctx.section("Triage", |ctx| {
            let Some(live) = self.live.as_ref() else { return };

            ctx.grid(|g| {
                if let Some(error) = live.diagnostic.as_deref() {
                    g.full(|ctx| render_diagnostic_card(ctx.ui_mut(), error));
                    return;
                }

                // Queue counts dashboard.
                g.full(|ctx| {
                    render_queues_card(ctx.ui_mut(), live);
                });

                if !live.suggestions.is_empty() {
                    g.full(|ctx| render_suggestions_card(ctx.ui_mut(), &live.suggestions));
                }

                if live.events.is_empty() {
                    g.full(|ctx| {
                        let ui = ctx.ui_mut();
                        ui.add_space(16.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                egui::RichText::new("\u{1FA7A}") // 🩺
                                    .size(28.0)
                                    .color(color_muted(ui)),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new("No canonical agent activity yet.")
                                    .monospace()
                                    .small()
                                    .strong()
                                    .color(color_muted(ui)),
                            );
                            ui.add_space(2.0);
                            ui.label(
                                egui::RichText::new(
                                    "exec results, model calls and reason events will appear here when the agent runs."
                                )
                                .monospace()
                                .small()
                                .color(color_muted(ui)),
                            );
                        });
                        ui.add_space(16.0);
                    });
                    return;
                }

                g.full(|ctx| {
                    let ui = ctx.ui_mut();
                    let shown = live.events.len();
                    let label = if shown < live.total_events {
                        format!(
                            "SHOWING {shown} OF {} EVENTS (NEWEST FIRST)",
                            live.total_events
                        )
                    } else {
                        format!(
                            "{shown} EVENT{}",
                            if shown == 1 { "" } else { "S" }
                        )
                    };
                    ui.label(
                        egui::RichText::new(label)
                            .monospace()
                            .strong()
                            .small()
                            .color(color_muted(ui)),
                    );
                });

                for ev in &live.events {
                    g.full(|ctx| {
                        render_event_card(ctx.ui_mut(), ev, now);
                    });
                }
            });
        });
    }
}

// ── Queue-counts dashboard ──────────────────────────────────────────

fn render_diagnostic_card(ui: &mut egui::Ui, error: &str) {
    let color = color_error();
    egui::Frame::NONE
        .fill(egui::Color32::from_rgba_unmultiplied(
            color.r(),
            color.g(),
            color.b(),
            32,
        ))
        .stroke(egui::Stroke::new(1.0, color))
        .corner_radius(egui::CornerRadius::ZERO)
        .inner_margin(egui::Margin::same(10))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(
                egui::RichText::new("INVALID TRIAGE SNAPSHOT")
                    .monospace()
                    .small()
                    .strong()
                    .color(color),
            );
            ui.label(egui::RichText::new(error).monospace().small().color(color));
        });
}

fn render_suggestions_card(ui: &mut egui::Ui, suggestions: &[String]) {
    let fill = ui.visuals().window_fill;
    egui::Frame::NONE
        .fill(fill)
        .stroke(egui::Stroke::new(1.0, color_frame(ui)))
        .corner_radius(egui::CornerRadius::ZERO)
        .inner_margin(egui::Margin::same(10))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(
                egui::RichText::new("SUGGESTED NEXT CHECKS")
                    .monospace()
                    .small()
                    .strong()
                    .color(color_reason()),
            );
            for suggestion in suggestions {
                ui.label(
                    egui::RichText::new(format!("· {suggestion}"))
                        .monospace()
                        .small()
                        .color(color_muted(ui)),
                );
            }
        });
}

fn render_queues_card(ui: &mut egui::Ui, live: &TriageLive) {
    let bubble_fill = ui.visuals().window_fill;
    let body_text = colorhash::text_color_on(bubble_fill);
    let body_muted = mix(body_text, bubble_fill, 0.30);

    egui::Frame::NONE
        .fill(bubble_fill)
        .stroke(egui::Stroke::new(1.0, color_frame(ui)))
        .shadow(egui::epaint::Shadow {
            offset: [2, 2],
            blur: 0,
            spread: 0,
            color: egui::Color32::from_black_alpha(48),
        })
        .corner_radius(egui::CornerRadius::ZERO)
        .inner_margin(egui::Margin {
            left: 12,
            right: 12,
            top: 10,
            bottom: 10,
        })
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 4.0;

            render_queue_row(ui, "EXEC", color_exec(), &live.exec, body_text, body_muted);
            render_queue_row(
                ui,
                "MODEL",
                color_model(),
                &live.model,
                body_text,
                body_muted,
            );
            ui.separator();

            if let Some(error) = live.headspace_error.as_deref() {
                render_status_line(
                    ui,
                    "HEADSPACE UNRESOLVED",
                    &first_line(error, 140),
                    color_error(),
                );
            } else {
                let agreement = if live.config_heads > 1 || live.active_profile_heads > 1 {
                    "AGREED"
                } else {
                    "SETTLED"
                };
                let persona = live
                    .persona_id
                    .map(|id| format!("persona {}", &id_hex(id)[..8]))
                    .unwrap_or_else(|| "no persona".to_owned());
                render_status_line(
                    ui,
                    &format!("HEADSPACE {agreement}"),
                    &format!(
                        "config heads {} · profile heads {} · {persona}",
                        live.config_heads, live.active_profile_heads
                    ),
                    color_exec(),
                );
            }

            match live.unread_messages {
                UnreadMessages::Available { count: unread, .. } => render_status_line(
                    ui,
                    "INBOX",
                    &format!(
                        "{unread} unread canonical message{}",
                        if unread == 1 { "" } else { "s" }
                    ),
                    if unread == 0 {
                        body_muted
                    } else {
                        color_reason()
                    },
                ),
                UnreadMessages::Unavailable(reason) => {
                    let detail = match reason {
                        UnreadUnavailable::HeadspaceUnsettled => {
                            "Headspace active state is unsettled"
                        }
                        UnreadUnavailable::PersonaNotConfigured => {
                            "Headspace has no configured persona"
                        }
                    };
                    render_status_line(ui, "INBOX UNAVAILABLE", detail, color_reason())
                }
            }
            if live.relation_forks > 0 {
                render_status_line(
                    ui,
                    "RELATIONS FORK",
                    &format!(
                        "{} person profile{} have competing heads",
                        live.relation_forks,
                        if live.relation_forks == 1 { "" } else { "s" }
                    ),
                    color_reason(),
                );
            }
            if live.exec_fork_history > 0 || live.model_fork_history > 0 {
                render_status_line(
                    ui,
                    "ATTEMPT FORKS",
                    &format!(
                        "exec {} · model {} (historical and current)",
                        live.exec_fork_history, live.model_fork_history
                    ),
                    color_reason(),
                );
            }
            for diagnostic in &live.lifecycle_diagnostics {
                render_status_line(
                    ui,
                    "INVALID LIFECYCLE",
                    &first_line(diagnostic, 140),
                    color_error(),
                );
            }
            if let Some(pattern) = live.probable_loop.as_ref() {
                render_status_line(
                    ui,
                    "PROBABLE LOOP",
                    &format!(
                        "{}× · exit {} · {}",
                        pattern.count,
                        pattern
                            .exit_code
                            .map(|code| code.to_string())
                            .unwrap_or_else(|| "-".to_owned()),
                        first_line(&pattern.command, 80)
                    ),
                    color_error(),
                );
            }
        });
}

fn render_status_line(ui: &mut egui::Ui, label: &str, detail: &str, color: egui::Color32) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        ui.label(
            egui::RichText::new(label)
                .monospace()
                .small()
                .strong()
                .color(color),
        );
        ui.label(
            egui::RichText::new(detail)
                .monospace()
                .small()
                .color(color_muted(ui)),
        );
    });
}

fn render_queue_row(
    ui: &mut egui::Ui,
    label: &str,
    accent: egui::Color32,
    counts: &QueueCounts,
    text: egui::Color32,
    muted: egui::Color32,
) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = egui::vec2(8.0, 4.0);
        // Coloured label tag — same accent the corresponding event
        // cards use, so EXEC rows in the timeline match the EXEC
        // row in this dashboard at a glance.
        egui::Frame::NONE
            .fill(accent)
            .corner_radius(egui::CornerRadius::ZERO)
            .inner_margin(egui::Margin::symmetric(6, 1))
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new(label)
                        .monospace()
                        .strong()
                        .small()
                        .color(colorhash::text_color_on(accent)),
                );
            });

        render_count(ui, "REQ", counts.requests, text, muted);
        render_count(ui, "PEND", counts.pending, text, muted);
        render_count(ui, "RUN", counts.running, text, muted);
        if counts.age_unknown > 0 {
            render_count_colored(ui, "AGE?", counts.age_unknown, color_reason());
        }
        if counts.stale > 0 {
            // Stale items are surfaced in error red so they catch
            // the eye — the user probably wants to triage them.
            render_count_colored(ui, "STALE", counts.stale, color_error());
        }
        if counts.forked > 0 {
            render_count_colored(ui, "FORK", counts.forked, color_reason());
        }
        if counts.invalid > 0 {
            render_count_colored(ui, "INVALID", counts.invalid, color_error());
        }
        render_count(ui, "DONE", counts.done, text, muted);
    });
}

fn render_count(
    ui: &mut egui::Ui,
    label: &str,
    n: usize,
    text: egui::Color32,
    muted: egui::Color32,
) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 3.0;
        ui.label(egui::RichText::new(label).monospace().small().color(muted));
        ui.label(
            egui::RichText::new(format!("{n}"))
                .monospace()
                .strong()
                .color(text),
        );
    });
}

fn render_count_colored(ui: &mut egui::Ui, label: &str, n: usize, color: egui::Color32) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 3.0;
        ui.label(
            egui::RichText::new(label)
                .monospace()
                .small()
                .strong()
                .color(color),
        );
        ui.label(
            egui::RichText::new(format!("{n}"))
                .monospace()
                .strong()
                .color(color),
        );
    });
}

// ── Event card ──────────────────────────────────────────────────────

fn render_event_card(ui: &mut egui::Ui, ev: &EventRow, now: Option<i128>) {
    let bubble_fill = ui.visuals().window_fill;
    let accent = if ev.is_error {
        color_error()
    } else {
        ev.kind.color()
    };
    let text_on_accent = colorhash::text_color_on(accent);
    let body_muted = {
        let body_text = colorhash::text_color_on(bubble_fill);
        mix(body_text, bubble_fill, 0.22)
    };

    egui::Frame::NONE
        .fill(bubble_fill)
        .stroke(egui::Stroke::new(1.0, color_frame(ui)))
        .shadow(egui::epaint::Shadow {
            offset: [2, 2],
            blur: 0,
            spread: 0,
            color: egui::Color32::from_black_alpha(48),
        })
        .corner_radius(egui::CornerRadius::ZERO)
        .inner_margin(egui::Margin::ZERO)
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 0.0;

            // ── Header: KIND · time · ERROR badge (when present) ──
            egui::Frame::NONE
                .fill(accent)
                .corner_radius(egui::CornerRadius::ZERO)
                .inner_margin(egui::Margin {
                    left: 10,
                    right: 10,
                    top: 6,
                    bottom: 6,
                })
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 2.0;

                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(ev.kind.label())
                                .monospace()
                                .strong()
                                .small()
                                .color(text_on_accent),
                        );
                        ui.label(
                            egui::RichText::new(format!(
                                "· {} · {}",
                                format_time(ev.at),
                                age_label(now, ev.at),
                            ))
                            .monospace()
                            .small()
                            .color(text_on_accent),
                        );
                        if ev.is_error {
                            ui.label(
                                egui::RichText::new("· ERROR")
                                    .monospace()
                                    .strong()
                                    .small()
                                    .color(text_on_accent),
                            );
                        }
                        if let Some(d) = ev.detail.as_ref() {
                            ui.label(
                                egui::RichText::new(format!("· {d}"))
                                    .monospace()
                                    .small()
                                    .color(text_on_accent),
                            );
                        }
                    });

                    ui.label(
                        egui::RichText::new(&ev.summary)
                            .monospace()
                            .size(13.0)
                            .color(text_on_accent),
                    );
                });

            // ── Body: just the canonical id (terse — these are
            //         debug-style events; the CLI is the right tool
            //         for full drill-down). ──
            egui::Frame::NONE
                .fill(bubble_fill)
                .corner_radius(egui::CornerRadius::ZERO)
                .inner_margin(egui::Margin {
                    left: 10,
                    right: 10,
                    top: 4,
                    bottom: 6,
                })
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.label(
                        egui::RichText::new(id_hex(ev.id))
                            .monospace()
                            .small()
                            .color(body_muted),
                    );
                });
        });
}
