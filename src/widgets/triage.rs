//! Read-only GORBIE-embeddable viewer for the `triage` faculty.
//!
//! Triage is the diagnostic faculty: it cross-references exec
//! requests / model requests / reason events on the cognition
//! branch to surface "what is the agent doing right now and what
//! recently went wrong". This widget renders the same information
//! the `triage scan` and `triage timeline` CLI commands print, as
//! a queue-counts dashboard plus a chronological feed of the most
//! recent exec / model / reason events.
//!
//! Card shape:
//! - Top: dashboard card with EXEC and MODEL queue counts (requests,
//!   pending, running, completed) and the number of stale
//!   in-progress entries (> 15 min).
//! - Below: a chronological feed of recent activity, newest first.
//!   Each event renders as a small card with a kind-coloured header
//!   (EXEC / MODEL / REASON), a short summary line, and the
//!   canonical entity id at the bottom.
//!
//! v1 limits: no failure-pattern grouping (the `triage loops`
//! command is the right tool for that), no turn-level drill-down,
//! no live token-usage histogram (just totals per event when
//! present).
//!
//! ```ignore
//! let mut panel = TriageViewer::default();
//! panel.render(ctx, cognition_ws);
//! ```

use chrono::{DateTime, TimeZone, Timelike, Utc};
use hifitime::Epoch;

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::Inline;
use triblespace::core::metadata;
use triblespace::core::repo::BlobStoreGet;
use triblespace::core::trible::TribleSet;
use triblespace::macros::{find, pattern};
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::U256BE;
use triblespace::prelude::View;

use crate::schemas::triage::{
    exec as exec_attrs, model_chat as model_attrs, reason as reason_attrs,
    KIND_EXEC_IN_PROGRESS_ID, KIND_EXEC_REQUEST_ID, KIND_EXEC_RESULT_ID, KIND_MODEL_IN_PROGRESS_ID,
    KIND_MODEL_REQUEST_ID, KIND_MODEL_RESULT_ID, KIND_REASON_EVENT_ID,
};
use crate::widgets::storage::{DatasetRevision, DatasetView};

type TextHandle = Inline<Handle<LongString>>;

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
    at: DateTime<Utc>,
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

#[derive(Clone, Debug, Default)]
struct QueueCounts {
    requests: usize,
    in_progress: usize,
    stale_in_progress: usize,
    results: usize,
}

struct TriageLive {
    cached_revision: DatasetRevision,
    exec: QueueCounts,
    model: QueueCounts,
    events: Vec<EventRow>,
    total_events: usize,
}

// ── Live snapshot ────────────────────────────────────────────────────

impl TriageLive {
    fn refresh(dataset: DatasetView<'_>) -> Self {
        let space = dataset.facts;

        let now_ns = now_tai_ns();
        let stale_cutoff_ns = now_ns - (STALE_SECONDS as i128) * 1_000_000_000;

        let exec = collect_queue(
            space,
            KIND_EXEC_REQUEST_ID,
            KIND_EXEC_IN_PROGRESS_ID,
            KIND_EXEC_RESULT_ID,
            stale_cutoff_ns,
        );
        let model = collect_queue(
            space,
            KIND_MODEL_REQUEST_ID,
            KIND_MODEL_IN_PROGRESS_ID,
            KIND_MODEL_RESULT_ID,
            stale_cutoff_ns,
        );

        let mut events: Vec<EventRow> = Vec::new();
        collect_exec_results(dataset, space, &mut events);
        collect_model_results(dataset, space, &mut events);
        collect_reason_events(dataset, space, &mut events);

        events.sort_by(|a, b| b.at.cmp(&a.at));
        let total_events = events.len();
        events.truncate(MAX_EVENTS);

        TriageLive {
            cached_revision: dataset.revision,
            exec,
            model,
            events,
            total_events,
        }
    }
}

fn collect_queue(
    space: &TribleSet,
    request_kind: Id,
    in_progress_kind: Id,
    result_kind: Id,
    stale_cutoff_ns: i128,
) -> QueueCounts {
    let mut counts = QueueCounts::default();
    for (_id,) in find!(
        (id: Id,),
        pattern!(space, [{ ?id @ metadata::tag: request_kind }])
    ) {
        counts.requests += 1;
    }
    for (_id, _ts) in find!(
        (id: Id, ts: (i128, i128)),
        pattern!(space, [{
            ?id @
            metadata::tag: in_progress_kind,
            metadata::created_at: ?ts,
        }])
    ) {
        counts.in_progress += 1;
        if _ts.0 < stale_cutoff_ns {
            counts.stale_in_progress += 1;
        }
    }
    for (_id,) in find!(
        (id: Id,),
        pattern!(space, [{ ?id @ metadata::tag: result_kind }])
    ) {
        counts.results += 1;
    }
    counts
}

fn collect_exec_results(dataset: DatasetView<'_>, space: &TribleSet, out: &mut Vec<EventRow>) {
    // Each exec result has: about_request → command_text,
    // exit_code, stdout/stderr/error handles, created_at.
    // For the timeline we just need the result entity + its
    // created_at + summary fields.
    for (id, ts) in find!(
        (id: Id, ts: (i128, i128)),
        pattern!(space, [{
            ?id @
            metadata::tag: KIND_EXEC_RESULT_ID,
            metadata::created_at: ?ts,
        }])
    ) {
        let at = ns_to_chrono(ts.0);
        let exit = find_u64(space, id, |id| {
            find!(
                v: Inline<U256BE>,
                pattern!(space, [{ id @ exec_attrs::exit_code: ?v }])
            )
            .next()
        });
        let is_error = exit.map_or(false, |c| c != 0);
        // Pull the originating request's command_text for context.
        let about_request = find!(
            r: Id,
            pattern!(space, [{ id @ exec_attrs::about_request: ?r }])
        )
        .next();
        let command_handle = about_request.and_then(|req| {
            find!(
                h: TextHandle,
                pattern!(space, [{ req @ exec_attrs::command_text: ?h }])
            )
            .next()
        });
        let command = command_handle.and_then(|h| read_text(dataset, h));
        let error_handle = find!(
            h: TextHandle,
            pattern!(space, [{ id @ exec_attrs::error: ?h }])
        )
        .next();
        let error_text = error_handle.and_then(|h| read_text(dataset, h));

        let summary = command
            .clone()
            .map(|c| first_line(&c, 80))
            .or(error_text
                .clone()
                .map(|e| format!("error: {}", first_line(&e, 60))))
            .unwrap_or_else(|| "(exec result)".to_string());

        let detail = match exit {
            Some(c) if c != 0 => Some(format!("exit {c}")),
            Some(_) => None,
            None => None,
        };

        out.push(EventRow {
            id,
            kind: EventKind::ExecResult,
            at,
            summary,
            detail,
            is_error,
        });
    }
}

fn collect_model_results(dataset: DatasetView<'_>, space: &TribleSet, out: &mut Vec<EventRow>) {
    for (id, ts) in find!(
        (id: Id, ts: (i128, i128)),
        pattern!(space, [{
            ?id @
            metadata::tag: KIND_MODEL_RESULT_ID,
            metadata::created_at: ?ts,
        }])
    ) {
        let at = ns_to_chrono(ts.0);
        let error_handle = find!(
            h: TextHandle,
            pattern!(space, [{ id @ model_attrs::error: ?h }])
        )
        .next();
        let error_text = error_handle.and_then(|h| read_text(dataset, h));
        let is_error = error_text.is_some();

        let output_handle = find!(
            h: TextHandle,
            pattern!(space, [{ id @ model_attrs::output_text: ?h }])
        )
        .next();
        let output_text = output_handle.and_then(|h| read_text(dataset, h));

        let input_tokens = find_u64(space, id, |id| {
            find!(
                v: Inline<U256BE>,
                pattern!(space, [{ id @ model_attrs::input_tokens: ?v }])
            )
            .next()
        });
        let output_tokens = find_u64(space, id, |id| {
            find!(
                v: Inline<U256BE>,
                pattern!(space, [{ id @ model_attrs::output_tokens: ?v }])
            )
            .next()
        });

        let summary = output_text
            .as_ref()
            .map(|t| first_line(t, 80))
            .or(error_text
                .clone()
                .map(|e| format!("error: {}", first_line(&e, 60))))
            .unwrap_or_else(|| "(model result)".to_string());

        let detail = match (input_tokens, output_tokens) {
            (Some(i), Some(o)) => Some(format!("{} in · {} out", format_count(i), format_count(o))),
            (Some(i), None) => Some(format!("{} in", format_count(i))),
            (None, Some(o)) => Some(format!("{} out", format_count(o))),
            (None, None) => None,
        };

        out.push(EventRow {
            id,
            kind: EventKind::ModelResult,
            at,
            summary,
            detail,
            is_error,
        });
    }
}

fn collect_reason_events(dataset: DatasetView<'_>, space: &TribleSet, out: &mut Vec<EventRow>) {
    for (id, ts) in find!(
        (id: Id, ts: (i128, i128)),
        pattern!(space, [{
            ?id @
            metadata::tag: KIND_REASON_EVENT_ID,
            metadata::created_at: ?ts,
        }])
    ) {
        let at = ns_to_chrono(ts.0);
        let text_handle = find!(
            h: TextHandle,
            pattern!(space, [{ id @ reason_attrs::text: ?h }])
        )
        .next();
        let text = text_handle.and_then(|h| read_text(dataset, h));
        let cmd_handle = find!(
            h: TextHandle,
            pattern!(space, [{ id @ reason_attrs::command_text: ?h }])
        )
        .next();
        let cmd = cmd_handle.and_then(|h| read_text(dataset, h));

        let summary = text
            .as_ref()
            .map(|t| first_line(t, 80))
            .unwrap_or_else(|| "(reason event)".to_string());
        let detail = cmd.map(|c| format!("→ {}", first_line(&c, 60)));

        out.push(EventRow {
            id,
            kind: EventKind::Reason,
            at,
            summary,
            detail,
            is_error: false,
        });
    }
}

fn read_text(dataset: DatasetView<'_>, h: TextHandle) -> Option<String> {
    dataset
        .reader
        .get::<View<str>, LongString>(h)
        .ok()
        .map(|v| {
            let s: &str = v.as_ref();
            s.to_string()
        })
}

fn ns_to_chrono(ns: i128) -> DateTime<Utc> {
    let secs = (ns / 1_000_000_000) as i64;
    let nanos = ((ns % 1_000_000_000) as u32).min(999_999_999);
    Utc.timestamp_opt(secs, nanos)
        .single()
        .unwrap_or_else(Utc::now)
}

fn now_tai_ns() -> i128 {
    Epoch::now()
        .map(|e| e.to_tai_duration().total_nanoseconds())
        .unwrap_or(0)
}

fn find_u64<F>(_space: &TribleSet, entity_id: Id, query: F) -> Option<u64>
where
    F: FnOnce(Id) -> Option<Inline<U256BE>>,
{
    let raw = query(entity_id)?;
    if raw.raw[..24].iter().any(|b| *b != 0) {
        return None;
    }
    let bytes: [u8; 8] = raw.raw[24..32].try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
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

fn format_time(t: DateTime<Utc>) -> String {
    format!("{:02}:{:02}:{:02}", t.hour(), t.minute(), t.second())
}

fn age_label(now: DateTime<Utc>, at: DateTime<Utc>) -> String {
    let secs = (now - at).num_seconds().max(0);
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

    pub fn render(&mut self, ctx: &mut CardCtx<'_>, dataset: DatasetView<'_>) {
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => l.cached_revision != dataset.revision,
        };
        if need_refresh {
            self.live = Some(TriageLive::refresh(dataset));
        }

        ctx.section("Triage", |ctx| {
            let Some(live) = self.live.as_ref() else { return };
            let now = Utc::now();

            ctx.grid(|g| {
                // Queue counts dashboard.
                g.full(|ctx| {
                    render_queues_card(ctx.ui_mut(), &live.exec, &live.model);
                });

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
                                egui::RichText::new("No agent activity on this branch yet.")
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

fn render_queues_card(ui: &mut egui::Ui, exec: &QueueCounts, model: &QueueCounts) {
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

            render_queue_row(ui, "EXEC", color_exec(), exec, body_text, body_muted);
            render_queue_row(ui, "MODEL", color_model(), model, body_text, body_muted);
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
        render_count(ui, "RUN", counts.in_progress, text, muted);
        if counts.stale_in_progress > 0 {
            // Stale items are surfaced in error red so they catch
            // the eye — the user probably wants to triage them.
            render_count_colored(ui, "STALE", counts.stale_in_progress, color_error());
        }
        render_count(ui, "DONE", counts.results, text, muted);
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

fn render_event_card(ui: &mut egui::Ui, ev: &EventRow, now: DateTime<Utc>) {
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
