//! Read-only GORBIE-embeddable viewer for the `decide` faculty.
//!
//! Renders each decision as a paper card: status stripe (PROPOSED /
//! RESOLVED / FORCED) on the left, title + context across the top,
//! pros + cons in two columns (RAL signal green / traffic red), and
//! the outcome at the bottom when resolved.
//!
//! The widget consumes Decide's canonical genesis/factor/resolution read
//! model. Concurrent resolution heads remain visible as agreed or divergent
//! state; no timestamp winner is recreated here.
//!
//! ```ignore
//! let mut panel = DecidePanel::default();
//! panel.render(ctx, decide_ws);
//! ```

use GORBIE::prelude::CardCtx;

use triblespace::core::id::Id;

use crate::decide::{self, FactorSide, Resolution};
use crate::widgets::storage::{DatasetRevision, DatasetView};

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
    resolution: ResolutionRow,
    pros: Vec<FactorRow>,
    cons: Vec<FactorRow>,
}

#[derive(Clone, Debug)]
struct FactorRow {
    text: String,
    created_at: Option<i128>,
}

#[derive(Clone, Debug)]
enum ResolutionRow {
    Proposed,
    Unique {
        id: Id,
        outcome: String,
        forced: bool,
        finished_at: i128,
    },
    Agreed {
        heads: Vec<Id>,
        outcome: String,
        forced: bool,
    },
    Forked(Vec<ForkRow>),
    Invalid(String),
}

#[derive(Clone, Debug)]
struct ForkRow {
    id: Id,
    outcome: String,
    forced: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Proposed,
    Resolved,
    Forced,
    Agreed,
    Forked,
    Invalid,
}

impl DecisionRow {
    fn status(&self) -> Status {
        match &self.resolution {
            ResolutionRow::Proposed => Status::Proposed,
            ResolutionRow::Unique { forced: true, .. } => Status::Forced,
            ResolutionRow::Unique { .. } => Status::Resolved,
            ResolutionRow::Agreed { .. } => Status::Agreed,
            ResolutionRow::Forked(_) => Status::Forked,
            ResolutionRow::Invalid(_) => Status::Invalid,
        }
    }

    /// Raw chronological key: created timestamp, missing → `i128::MIN`
    /// ("oldest"). Sorted with `Reverse` for newest-first — negating
    /// would overflow on `i128::MIN` (debug-build panic when a decision
    /// has no created_at).
    fn sort_key(&self) -> i128 {
        self.created_at.unwrap_or(i128::MIN)
    }
}

// ── Live snapshot ────────────────────────────────────────────────────

struct DecideLive {
    cached_revision: DatasetRevision,
    decisions: Vec<DecisionRow>,
}

impl DecideLive {
    fn refresh(dataset: DatasetView<'_>) -> Self {
        let mut decisions = decide::decision_anchors(dataset.facts)
            .into_iter()
            .map(|id| {
                load_decision(dataset, id).unwrap_or_else(|error| invalid_decision(id, error))
            })
            .collect::<Vec<_>>();
        decisions.sort_by_key(|d| std::cmp::Reverse(d.sort_key()));

        DecideLive {
            cached_revision: dataset.revision,
            decisions,
        }
    }
}

fn invalid_decision(id: Id, error: anyhow::Error) -> DecisionRow {
    DecisionRow {
        id,
        title: format!("Invalid decision {}", id_hex(id)),
        context: None,
        about: None,
        created_at: None,
        resolution: ResolutionRow::Invalid(format!("{error:#}")),
        pros: Vec::new(),
        cons: Vec::new(),
    }
}

fn load_decision(dataset: DatasetView<'_>, id: Id) -> anyhow::Result<DecisionRow> {
    let genesis = decide::genesis_for_decision(dataset.facts, id)?
        .ok_or_else(|| anyhow::anyhow!("decision {id:x} has no canonical genesis"))?;
    let mut pros = Vec::new();
    let mut cons = Vec::new();
    for factor in decide::factors_for_decision(dataset.facts, id)? {
        let row = FactorRow {
            text: decide::read_text(dataset.reader, factor.text)?,
            created_at: Some(interval_ns(factor.created_at)?),
        };
        match factor.side {
            FactorSide::Pro => pros.push(row),
            FactorSide::Con => cons.push(row),
        }
    }
    pros.sort_by_key(|factor| factor.created_at.unwrap_or(i128::MAX));
    cons.sort_by_key(|factor| factor.created_at.unwrap_or(i128::MAX));
    Ok(DecisionRow {
        id,
        title: decide::read_text(dataset.reader, genesis.title)?,
        context: genesis
            .context
            .map(|handle| decide::read_text(dataset.reader, handle))
            .transpose()?,
        about: genesis.about,
        created_at: Some(interval_ns(genesis.created_at)?),
        resolution: load_resolution(dataset, id)?,
        pros,
        cons,
    })
}

fn load_resolution(dataset: DatasetView<'_>, decision: Id) -> anyhow::Result<ResolutionRow> {
    Ok(match decide::resolution(dataset.facts, decision) {
        Resolution::Missing => ResolutionRow::Proposed,
        Resolution::Unique(snapshot) => ResolutionRow::Unique {
            id: snapshot.id,
            outcome: decide::read_text(dataset.reader, snapshot.outcome)?,
            forced: snapshot.forced,
            finished_at: interval_ns(snapshot.finished_at)?,
        },
        Resolution::Agreed(snapshots) => {
            let first = snapshots
                .first()
                .ok_or_else(|| anyhow::anyhow!("agreed resolution frontier is empty"))?;
            ResolutionRow::Agreed {
                heads: snapshots.iter().map(|snapshot| snapshot.id).collect(),
                outcome: decide::read_text(dataset.reader, first.outcome)?,
                forced: first.forced,
            }
        }
        Resolution::Forked(snapshots) => ResolutionRow::Forked(
            snapshots
                .into_iter()
                .map(|snapshot| {
                    Ok(ForkRow {
                        id: snapshot.id,
                        outcome: decide::read_text(dataset.reader, snapshot.outcome)?,
                        forced: snapshot.forced,
                    })
                })
                .collect::<anyhow::Result<_>>()?,
        ),
        Resolution::Invalid(error) => ResolutionRow::Invalid(error),
    })
}

fn interval_ns(value: decide::IntervalValue) -> anyhow::Result<i128> {
    let (lower, _upper): (i128, i128) = value
        .try_from_inline()
        .map_err(|error| anyhow::anyhow!("decode Decide timestamp: {error:?}"))?;
    Ok(lower)
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

    pub fn render(&mut self, ctx: &mut CardCtx<'_>, dataset: DatasetView<'_>) {
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => l.cached_revision != dataset.revision,
        };
        if need_refresh {
            self.live = Some(DecideLive::refresh(dataset));
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
                    matches!(
                        d.status(),
                        Status::Resolved | Status::Forced | Status::Agreed
                    )
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
                        Some(search.report(egui::Id::new(("decide_match", dec.id))))
                    } else {
                        None
                    };
                    let is_focused = match_info.as_ref().map_or(false, |i| i.is_focused);
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
                                ui.scroll_to_rect(rect, Some(egui::Align::Center));
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
    match &dec.resolution {
        ResolutionRow::Unique { outcome, .. } | ResolutionRow::Agreed { outcome, .. } => {
            if outcome.to_lowercase().contains(needle) {
                return true;
            }
        }
        ResolutionRow::Forked(heads) => {
            if heads.iter().any(|head| outcome_matches(head, needle)) {
                return true;
            }
        }
        ResolutionRow::Invalid(error) if error.to_lowercase().contains(needle) => return true,
        _ => {}
    }
    for f in dec.pros.iter().chain(dec.cons.iter()) {
        if f.text.to_lowercase().contains(needle) {
            return true;
        }
    }
    false
}

fn outcome_matches(head: &ForkRow, needle: &str) -> bool {
    head.outcome.to_lowercase().contains(needle) || id_hex(head.id).to_lowercase().contains(needle)
}

// ── Rendering ────────────────────────────────────────────────────────

const STATUS_STRIPE_WIDTH: f32 = 18.0;
const STROKE_INSET: f32 = 1.0;

fn status_color(status: Status, ui: &egui::Ui) -> egui::Color32 {
    match status {
        Status::Proposed => color_proposed(ui),
        Status::Resolved => color_resolved(),
        Status::Forced => color_forced(),
        Status::Agreed => color_pro(),
        Status::Forked => color_forced(),
        Status::Invalid => color_con(),
    }
}

fn status_label(status: Status) -> &'static str {
    match status {
        Status::Proposed => "PROPOSED",
        Status::Resolved => "RESOLVED",
        Status::Forced => "FORCED",
        Status::Agreed => "AGREED",
        Status::Forked => "FORKED",
        Status::Invalid => "INVALID",
    }
}

fn render_decision(ui: &mut egui::Ui, dec: &DecisionRow, search_needle: &str, focused: bool) {
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
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
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
                            egui::RichText::new(format!("\u{2192} {}", id_hex(about)))
                                .monospace()
                                .small()
                                .color(color_muted(ui)),
                        );
                    }
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Min), |ui| {
                        GORBIE::search::highlight_label(
                            ui,
                            &dec.title,
                            search_needle,
                            title_format(ui),
                            focused,
                        );
                    });
                });

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

                render_resolution(ui, &dec.resolution, search_needle, focused);
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
        }
    });
}

fn render_resolution(
    ui: &mut egui::Ui,
    resolution: &ResolutionRow,
    search_needle: &str,
    focused: bool,
) {
    let (outcome, finished_at, note) = match resolution {
        ResolutionRow::Proposed => return,
        ResolutionRow::Unique {
            id,
            outcome,
            finished_at,
            ..
        } => (
            Some(outcome.as_str()),
            Some(*finished_at),
            Some(format!("HEAD {}", id_hex(*id))),
        ),
        ResolutionRow::Agreed {
            heads,
            outcome,
            forced,
        } => (
            Some(outcome.as_str()),
            None,
            Some(format!(
                "{} AGREED HEADS{}",
                heads.len(),
                if *forced { " · FORCED" } else { "" }
            )),
        ),
        ResolutionRow::Forked(heads) => {
            ui.add_space(6.0);
            ui.separator();
            ui.label(
                egui::RichText::new(format!("{} DIVERGENT RESOLUTION HEADS", heads.len()))
                    .monospace()
                    .small()
                    .strong()
                    .color(color_forced()),
            );
            for head in heads {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        egui::RichText::new(format!(
                            "{}{}",
                            if head.forced { "FORCED · " } else { "" },
                            id_hex(head.id)
                        ))
                        .monospace()
                        .small()
                        .color(color_muted(ui)),
                    );
                    GORBIE::search::highlight_label(
                        ui,
                        &head.outcome,
                        search_needle,
                        body_format(ui, ui.visuals().text_color()),
                        focused,
                    );
                });
            }
            return;
        }
        ResolutionRow::Invalid(error) => {
            ui.add_space(6.0);
            ui.separator();
            ui.label(
                egui::RichText::new("INVALID RESOLUTION GRAPH")
                    .monospace()
                    .small()
                    .strong()
                    .color(color_con()),
            );
            ui.label(egui::RichText::new(error).monospace().small());
            return;
        }
    };

    ui.add_space(6.0);
    ui.separator();
    ui.add_space(2.0);
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
        if let Some(age) = format_relative_age(finished_at) {
            ui.label(
                egui::RichText::new(age)
                    .monospace()
                    .small()
                    .color(color_muted(ui)),
            );
        }
        if let Some(note) = note {
            ui.label(
                egui::RichText::new(note)
                    .monospace()
                    .small()
                    .color(color_muted(ui)),
            );
        }
        ui.with_layout(egui::Layout::left_to_right(egui::Align::Min), |ui| {
            ui.label(
                egui::RichText::new("OUTCOME")
                    .monospace()
                    .small()
                    .strong()
                    .color(color_resolved()),
            );
        });
    });
    if let Some(outcome) = outcome {
        GORBIE::search::highlight_label(
            ui,
            outcome,
            search_needle,
            body_format(ui, ui.visuals().text_color()),
            focused,
        );
    }
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
    let now = crate::clock::tai_nanoseconds_now().ok()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(resolution: ResolutionRow) -> DecisionRow {
        DecisionRow {
            id: Id::new([1; 16]).unwrap(),
            title: "test".to_owned(),
            context: None,
            about: None,
            created_at: None,
            resolution,
            pros: Vec::new(),
            cons: Vec::new(),
        }
    }

    #[test]
    fn fork_and_agreement_are_distinct_visible_states() {
        let first = Id::new([2; 16]).unwrap();
        let second = Id::new([3; 16]).unwrap();
        let forked = decision(ResolutionRow::Forked(vec![
            ForkRow {
                id: first,
                outcome: "left".to_owned(),
                forced: false,
            },
            ForkRow {
                id: second,
                outcome: "right".to_owned(),
                forced: true,
            },
        ]));
        assert_eq!(forked.status(), Status::Forked);
        assert!(decision_matches_search(&forked, "right"));

        let agreed = decision(ResolutionRow::Agreed {
            heads: vec![first, second],
            outcome: "same".to_owned(),
            forced: false,
        });
        assert_eq!(agreed.status(), Status::Agreed);
        assert!(decision_matches_search(&agreed, "same"));
    }
}
