//! Read-only GORBIE-embeddable viewer for the `decide` faculty.
//!
//! Renders each decision as a paper card: status stripe (PROPOSED /
//! RESOLVED / FORCED) on the left, title + context across the top,
//! pros + cons in two columns (RAL signal green / traffic red), and
//! the outcome at the bottom when resolved.
//!
//! The widget holds UI + cached-query state only; the host supplies
//! the `decide` workspace at render time. Decisions sort newest-first.
//!
//! ```ignore
//! let mut panel = DecidePanel::default();
//! panel.render(ctx, decide_ws);
//! ```

use std::collections::HashMap;

use GORBIE::prelude::CardCtx;

use triblespace::core::id::Id;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{CommitHandle, Workspace};
use triblespace::core::trible::TribleSet;
use triblespace::core::inline::encodings::hash::{Blake3, Handle};
use triblespace::core::inline::Inline;
use triblespace::macros::{find, pattern};
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::View;

use crate::schemas::decide::{
    decide as decide_attrs, factor, KIND_CON, KIND_DECISION, KIND_PRO,
};

type TextHandle = Inline<Handle<LongString>>;

// ── Color palette ────────────────────────────────────────────────────

/// RAL 6018 yellow green — "PRO" accent.
fn color_pro() -> egui::Color32 {
    egui::Color32::from_rgb(0x57, 0xa6, 0x39)
}

/// RAL 3020 traffic red — "CON" accent.
fn color_con() -> egui::Color32 {
    egui::Color32::from_rgb(0xcc, 0x0a, 0x17)
}

/// RAL 1003 signal yellow — RESOLVED status (matches search highlight).
fn color_resolved() -> egui::Color32 {
    egui::Color32::from_rgb(0xf7, 0xba, 0x0b)
}

/// RAL 2004 pure orange — FORCED status (override, attention).
fn color_forced() -> egui::Color32 {
    egui::Color32::from_rgb(0xe2, 0x5b, 0x12)
}

fn color_proposed(ui: &egui::Ui) -> egui::Color32 {
    if ui.visuals().dark_mode {
        egui::Color32::from_rgb(0x6a, 0x6a, 0x6a)
    } else {
        egui::Color32::from_rgb(0xa0, 0xa0, 0xa0)
    }
}

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

// ── Row structs ──────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct DecisionRow {
    id: Id,
    title: String,
    context: Option<String>,
    about: Option<Id>,
    created_at: Option<i128>,
    finished_at: Option<i128>,
    outcome: Option<String>,
    pros: Vec<FactorRow>,
    cons: Vec<FactorRow>,
}

#[derive(Clone, Debug)]
struct FactorRow {
    text: String,
    detail: Option<String>,
    created_at: Option<i128>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Proposed,
    Resolved,
    Forced,
}

impl DecisionRow {
    fn status(&self) -> Status {
        let resolved = self.finished_at.is_some()
            && self.outcome.as_ref().map_or(false, |s| !s.trim().is_empty());
        if !resolved {
            Status::Proposed
        } else if self.pros.is_empty() && self.cons.is_empty() {
            Status::Forced
        } else {
            Status::Resolved
        }
    }

    fn sort_key(&self) -> i128 {
        // Newest first — negate, treat missing as far-old.
        -(self.created_at.unwrap_or(i128::MIN))
    }
}

// ── Live snapshot ────────────────────────────────────────────────────

struct DecideLive {
    cached_head: Option<CommitHandle>,
    decisions: Vec<DecisionRow>,
}

impl DecideLive {
    fn refresh(ws: &mut Workspace<Pile>) -> Self {
        let space = ws
            .checkout(..)
            .map(|co| co.into_facts())
            .unwrap_or_else(|e| {
                eprintln!("[decide] checkout: {e:?}");
                TribleSet::new()
            });
        let cached_head = ws.head();

        // Per-decision rollups — title / description / outcome handles,
        // about pointer, created/finished timestamps.
        let mut decisions: HashMap<Id, DecisionRow> = HashMap::new();

        for (id,) in find!(
            (d: Id,),
            pattern!(&space, [{ ?d @ metadata::tag: KIND_DECISION }])
        ) {
            decisions.insert(
                id,
                DecisionRow {
                    id,
                    title: String::from("(untitled)"),
                    context: None,
                    about: None,
                    created_at: None,
                    finished_at: None,
                    outcome: None,
                    pros: Vec::new(),
                    cons: Vec::new(),
                },
            );
        }

        // Title.
        let title_rows: Vec<(Id, TextHandle)> = find!(
            (d: Id, h: TextHandle),
            pattern!(&space, [{
                ?d @
                metadata::tag: KIND_DECISION,
                metadata::name: ?h,
            }])
        )
        .collect();
        for (id, h) in title_rows {
            if let Some(row) = decisions.get_mut(&id) {
                if let Some(text) = read_text(ws, h) {
                    row.title = text;
                }
            }
        }

        // Context (description).
        let ctx_rows: Vec<(Id, TextHandle)> = find!(
            (d: Id, h: TextHandle),
            pattern!(&space, [{
                ?d @
                metadata::tag: KIND_DECISION,
                metadata::description: ?h,
            }])
        )
        .collect();
        for (id, h) in ctx_rows {
            if let Some(row) = decisions.get_mut(&id) {
                row.context = read_text(ws, h);
            }
        }

        // Outcome (only set on resolved).
        let outcome_rows: Vec<(Id, TextHandle)> = find!(
            (d: Id, h: TextHandle),
            pattern!(&space, [{
                ?d @
                metadata::tag: KIND_DECISION,
                decide_attrs::outcome: ?h,
            }])
        )
        .collect();
        for (id, h) in outcome_rows {
            if let Some(row) = decisions.get_mut(&id) {
                row.outcome = read_text(ws, h);
            }
        }

        // About pointer.
        for (id, target) in find!(
            (d: Id, a: Id),
            pattern!(&space, [{
                ?d @
                metadata::tag: KIND_DECISION,
                decide_attrs::about: ?a,
            }])
        ) {
            if let Some(row) = decisions.get_mut(&id) {
                row.about = Some(target);
            }
        }

        // Timestamps (intervals — take the start ns).
        for (id, ts) in find!(
            (d: Id, ts: (i128, i128)),
            pattern!(&space, [{
                ?d @
                metadata::tag: KIND_DECISION,
                metadata::created_at: ?ts,
            }])
        ) {
            if let Some(row) = decisions.get_mut(&id) {
                row.created_at = Some(ts.0);
            }
        }
        for (id, ts) in find!(
            (d: Id, ts: (i128, i128)),
            pattern!(&space, [{
                ?d @
                metadata::tag: KIND_DECISION,
                metadata::finished_at: ?ts,
            }])
        ) {
            if let Some(row) = decisions.get_mut(&id) {
                row.finished_at = Some(ts.0);
            }
        }

        // Pros / cons. Each factor has metadata::name (one-liner),
        // optional metadata::description (long form), and a
        // factor::about_decision pointer back to its parent.
        collect_factors(ws, &space, KIND_PRO, &mut decisions, |row, f| {
            row.pros.push(f);
        });
        collect_factors(ws, &space, KIND_CON, &mut decisions, |row, f| {
            row.cons.push(f);
        });

        // Stable factor ordering: oldest-first within each column.
        for row in decisions.values_mut() {
            row.pros.sort_by_key(|f| f.created_at.unwrap_or(i128::MAX));
            row.cons.sort_by_key(|f| f.created_at.unwrap_or(i128::MAX));
        }

        let mut decisions: Vec<DecisionRow> = decisions.into_values().collect();
        decisions.sort_by_key(|d| d.sort_key());

        DecideLive {
            cached_head,
            decisions,
        }
    }
}

fn collect_factors(
    ws: &mut Workspace<Pile>,
    space: &TribleSet,
    kind: Id,
    decisions: &mut HashMap<Id, DecisionRow>,
    mut push: impl FnMut(&mut DecisionRow, FactorRow),
) {
    // Pull the (factor_id, decision_id, name_handle) triple in one
    // pass; description and created_at are looked up per-factor since
    // they're optional.
    let rows: Vec<(Id, Id, TextHandle)> = find!(
        (f: Id, d: Id, name: TextHandle),
        pattern!(space, [{
            ?f @
                metadata::tag: kind,
                metadata::name: ?name,
                factor::about_decision: ?d,
        }])
    )
    .collect();
    for (factor_id, decision_id, name) in rows {
        let text = read_text(ws, name).unwrap_or_else(|| "(unnamed)".into());
        let detail = find!(
            (h: TextHandle,),
            pattern!(space, [{ factor_id @ metadata::description: ?h }])
        )
        .next()
        .and_then(|(h,)| read_text(ws, h));
        let created_at = find!(
            (ts: (i128, i128),),
            pattern!(space, [{ factor_id @ metadata::created_at: ?ts }])
        )
        .next()
        .map(|(ts,)| ts.0);
        if let Some(row) = decisions.get_mut(&decision_id) {
            push(
                row,
                FactorRow {
                    text,
                    detail,
                    created_at,
                },
            );
        }
    }
}

fn read_text(ws: &mut Workspace<Pile>, h: TextHandle) -> Option<String> {
    ws.get::<View<str>, LongString>(h)
        .ok()
        .map(|v| {
            let s: &str = v.as_ref();
            s.to_string()
        })
}

// ── Widget ───────────────────────────────────────────────────────────

pub struct DecidePanel {
    live: Option<DecideLive>,
}

impl Default for DecidePanel {
    fn default() -> Self {
        Self { live: None }
    }
}

impl DecidePanel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn render(
        &mut self,
        ctx: &mut CardCtx<'_>,
        ws: &mut Workspace<Pile>,
    ) {
        let head = ws.head();
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => l.cached_head != head,
        };
        if need_refresh {
            self.live = Some(DecideLive::refresh(ws));
        }

        ctx.section("Decisions", |ctx| {
            let Some(live) = self.live.as_ref() else {
                return;
            };
            let count = live.decisions.len();
            let resolved = live
                .decisions
                .iter()
                .filter(|d| {
                    matches!(d.status(), Status::Resolved | Status::Forced)
                })
                .count();
            let open = count - resolved;

            let mut search = ctx.search();
            let needle = search.query().to_lowercase();
            let search_active = !needle.is_empty();

            ctx.grid(|g| {
                // Header counts.
                g.full(|ctx| {
                    let ui = ctx.ui_mut();
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 12.0;
                        ui.label(
                            egui::RichText::new(format!("{count} DECISIONS"))
                                .monospace()
                                .strong()
                                .small()
                                .color(color_muted(ui)),
                        );
                        ui.label(
                            egui::RichText::new(format!("{open} OPEN"))
                                .monospace()
                                .small()
                                .color(color_proposed(ui)),
                        );
                        ui.label(
                            egui::RichText::new(format!("{resolved} RESOLVED"))
                                .monospace()
                                .small()
                                .color(color_resolved()),
                        );
                    });
                });

                if live.decisions.is_empty() {
                    g.full(|ctx| {
                        let ui = ctx.ui_mut();
                        ui.add_space(16.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                egui::RichText::new("\u{2696}")
                                    .size(28.0)
                                    .color(color_muted(ui)),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new("No decisions yet.")
                                    .monospace()
                                    .small()
                                    .strong()
                                    .color(color_muted(ui)),
                            );
                        });
                        ui.add_space(16.0);
                    });
                    return;
                }

                for dec in &live.decisions {
                    if search_active && !decision_matches_search(dec, &needle) {
                        continue;
                    }
                    let match_info = if search_active {
                        Some(
                            search.report(egui::Id::new(("decide_match", dec.id))),
                        )
                    } else {
                        None
                    };
                    let is_focused =
                        match_info.as_ref().map_or(false, |i| i.is_focused);
                    g.full(|ctx| {
                        let ui = ctx.ui_mut();
                        let pre_y = ui.cursor().min.y;
                        render_decision(ui, dec, &needle, is_focused);
                        if let Some(info) = match_info {
                            if info.should_scroll_to {
                                let post_y = ui.cursor().min.y;
                                let rect = egui::Rect::from_min_max(
                                    egui::pos2(ui.min_rect().left(), pre_y),
                                    egui::pos2(ui.min_rect().right(), post_y),
                                );
                                ui.scroll_to_rect(
                                    rect,
                                    Some(egui::Align::Center),
                                );
                            }
                        }
                    });
                }
            });
        });
    }
}

fn decision_matches_search(dec: &DecisionRow, needle: &str) -> bool {
    if dec.title.to_lowercase().contains(needle) {
        return true;
    }
    if let Some(c) = &dec.context {
        if c.to_lowercase().contains(needle) {
            return true;
        }
    }
    if let Some(outcome) = &dec.outcome {
        if outcome.to_lowercase().contains(needle) {
            return true;
        }
    }
    for f in dec.pros.iter().chain(dec.cons.iter()) {
        if f.text.to_lowercase().contains(needle) {
            return true;
        }
        if let Some(d) = &f.detail {
            if d.to_lowercase().contains(needle) {
                return true;
            }
        }
    }
    false
}

// ── Rendering ────────────────────────────────────────────────────────

const STATUS_STRIPE_WIDTH: f32 = 18.0;
const STROKE_INSET: f32 = 1.0;

fn status_color(status: Status, ui: &egui::Ui) -> egui::Color32 {
    match status {
        Status::Proposed => color_proposed(ui),
        Status::Resolved => color_resolved(),
        Status::Forced => color_forced(),
    }
}

fn status_label(status: Status) -> &'static str {
    match status {
        Status::Proposed => "PROPOSED",
        Status::Resolved => "RESOLVED",
        Status::Forced => "FORCED",
    }
}

fn render_decision(
    ui: &mut egui::Ui,
    dec: &DecisionRow,
    search_needle: &str,
    focused: bool,
) {
    let frame_fill = ui.visuals().window_fill;
    let stroke_color = color_frame(ui);
    let status = dec.status();
    let stripe_color = status_color(status, ui);
    let stripe_label = status_label(status);

    let inner_margin = egui::Margin {
        left: (STROKE_INSET + STATUS_STRIPE_WIDTH + 8.0) as i8,
        right: 12,
        top: 8,
        bottom: 8,
    };

    ui.vertical(|ui| {
    let frame_resp = egui::Frame::NONE
        .fill(frame_fill)
        .stroke(egui::Stroke::new(STROKE_INSET, stroke_color))
        .shadow(egui::epaint::Shadow {
            offset: [2, 2],
            blur: 0,
            spread: 0,
            color: egui::Color32::from_black_alpha(48),
        })
        .corner_radius(egui::CornerRadius::ZERO)
        .inner_margin(inner_margin)
        .show(ui, |ui| {
            // Title row: title on the left, optional about → and age
            // on the right (`Align::Min` cross-axis to avoid the
            // frame-delayed cell sizing feedback loop).
            ui.with_layout(
                egui::Layout::right_to_left(egui::Align::Min),
                |ui| {
                    if let Some(age) = format_relative_age(dec.created_at) {
                        ui.label(
                            egui::RichText::new(age)
                                .monospace()
                                .small()
                                .color(color_muted(ui)),
                        );
                    }
                    if let Some(about) = dec.about {
                        ui.label(
                            egui::RichText::new(format!(
                                "\u{2192} {}",
                                id_hex(about)
                            ))
                            .monospace()
                            .small()
                            .color(color_muted(ui)),
                        );
                    }
                    ui.with_layout(
                        egui::Layout::left_to_right(egui::Align::Min),
                        |ui| {
                            GORBIE::search::highlight_label(
                                ui,
                                &dec.title,
                                search_needle,
                                title_format(ui),
                                focused,
                            );
                        },
                    );
                },
            );

            if let Some(context_text) = &dec.context {
                ui.add_space(2.0);
                GORBIE::search::highlight_label(
                    ui,
                    context_text,
                    search_needle,
                    body_format(ui, color_muted(ui)),
                    focused,
                );
            }

            ui.add_space(6.0);

            ui.columns(2, |cols| {
                render_factor_column(
                    &mut cols[0],
                    "PROS",
                    color_pro(),
                    &dec.pros,
                    search_needle,
                    focused,
                );
                render_factor_column(
                    &mut cols[1],
                    "CONS",
                    color_con(),
                    &dec.cons,
                    search_needle,
                    focused,
                );
            });

            if let Some(outcome) = &dec.outcome {
                if !outcome.trim().is_empty() {
                    ui.add_space(6.0);
                    ui.separator();
                    ui.add_space(2.0);
                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::Min),
                        |ui| {
                            if let Some(age) = format_relative_age(dec.finished_at) {
                                ui.label(
                                    egui::RichText::new(age)
                                        .monospace()
                                        .small()
                                        .color(color_muted(ui)),
                                );
                            }
                            ui.with_layout(
                                egui::Layout::left_to_right(egui::Align::Min),
                                |ui| {
                                    ui.label(
                                        egui::RichText::new("OUTCOME")
                                            .monospace()
                                            .small()
                                            .strong()
                                            .color(color_resolved()),
                                    );
                                },
                            );
                        },
                    );
                    GORBIE::search::highlight_label(
                        ui,
                        outcome,
                        search_needle,
                        body_format(ui, ui.visuals().text_color()),
                        focused,
                    );
                }
            }
        });

    // Left status stripe, compass-card idiom.
    let outer = frame_resp.response.rect;
    paint_status_stripe(ui.painter(), outer, stripe_color, stripe_label);
    });
}

fn render_factor_column(
    ui: &mut egui::Ui,
    heading: &str,
    accent: egui::Color32,
    factors: &[FactorRow],
    search_needle: &str,
    focused: bool,
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
            ui.add_space(2.0);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                ui.label(
                    egui::RichText::new("\u{2022}") // bullet
                        .small()
                        .color(accent),
                );
                GORBIE::search::highlight_label(
                    ui,
                    &f.text,
                    search_needle,
                    body_format(ui, ui.visuals().text_color()),
                    focused,
                );
            });
            if let Some(detail) = &f.detail {
                GORBIE::search::highlight_label(
                    ui,
                    detail,
                    search_needle,
                    body_format(ui, color_muted(ui)),
                    focused,
                );
            }
        }
    });
}

fn paint_status_stripe(
    painter: &egui::Painter,
    outer: egui::Rect,
    color: egui::Color32,
    label: &str,
) {
    let stripe_rect = egui::Rect::from_min_size(
        outer.min + egui::vec2(STROKE_INSET, STROKE_INSET),
        egui::vec2(STATUS_STRIPE_WIDTH, outer.height() - 2.0 * STROKE_INSET),
    );
    painter.rect_filled(stripe_rect, egui::CornerRadius::ZERO, color);
    let font = egui::FontId::monospace(9.0);
    let text_color = GORBIE::themes::colorhash::text_color_on(color);
    let galley = painter.layout_no_wrap(label.to_string(), font, text_color);
    if galley.size().x + 6.0 > stripe_rect.height() {
        return;
    }
    let gh = galley.size().y;
    let pos = egui::pos2(
        stripe_rect.left() + (STATUS_STRIPE_WIDTH + gh) * 0.5,
        stripe_rect.top() + 5.0,
    );
    let mut text_shape = egui::epaint::TextShape::new(pos, galley, text_color);
    text_shape.angle = std::f32::consts::FRAC_PI_2;
    text_shape.fallback_color = text_color;
    painter.add(text_shape);
}

fn title_format(ui: &egui::Ui) -> egui::TextFormat {
    egui::TextFormat {
        font_id: egui::TextStyle::Heading.resolve(ui.style()),
        color: ui.visuals().text_color(),
        ..Default::default()
    }
}

fn body_format(ui: &egui::Ui, color: egui::Color32) -> egui::TextFormat {
    egui::TextFormat {
        font_id: egui::TextStyle::Body.resolve(ui.style()),
        color,
        ..Default::default()
    }
}

fn id_hex(id: Id) -> String {
    format!("{id:x}")
}

fn format_relative_age(ts: Option<i128>) -> Option<String> {
    let ts = ts?;
    let now = now_tai_ns();
    let secs = ((now - ts) / 1_000_000_000).max(0) as i64;
    Some(format_age_secs(secs))
}

fn format_age_secs(secs: i64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else if secs < 86400 * 30 {
        format!("{}d", secs / 86400)
    } else if secs < 86400 * 365 {
        format!("{}mo", secs / (86400 * 30))
    } else {
        format!("{}y", secs / (86400 * 365))
    }
}

fn now_tai_ns() -> i128 {
    use hifitime::Epoch;
    let now = Epoch::now().unwrap_or_else(|_| Epoch::from_tai_seconds(0.0));
    now.to_tai_duration().total_nanoseconds()
}
