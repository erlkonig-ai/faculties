//! Read-only GORBIE viewer for the collection-native Decide ledger.
//!
//! Resolution state is projected through the shared fork-visible model. The
//! widget never infers forcedness from the current factor set and never picks
//! one divergent outcome. Every live head retains its own evidence, time, and
//! predecessor history in the card.

use GORBIE::prelude::CardCtx;

use triblespace::core::id::Id;

use crate::decide::{self, FactorSide, Resolution, ResolutionSnapshot};
use crate::widgets::storage::{DatasetRevision, DatasetView};

// ── Color palette ────────────────────────────────────────────────────

fn color_pro() -> egui::Color32 {
    egui::Color32::from_rgb(0x57, 0xa6, 0x39)
}

fn color_con() -> egui::Color32 {
    egui::Color32::from_rgb(0xcc, 0x0a, 0x17)
}

fn color_resolved() -> egui::Color32 {
    egui::Color32::from_rgb(0xf7, 0xba, 0x0b)
}

fn color_forced() -> egui::Color32 {
    egui::Color32::from_rgb(0xe2, 0x5b, 0x12)
}

fn color_agreed() -> egui::Color32 {
    egui::Color32::from_rgb(0x2f, 0x78, 0xc4)
}

fn color_forked() -> egui::Color32 {
    egui::Color32::from_rgb(0xb0, 0x55, 0xc9)
}

fn color_invalid() -> egui::Color32 {
    egui::Color32::from_rgb(0xcc, 0x0a, 0x17)
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

// ── Projection ───────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct DecisionRow {
    id: Id,
    title: String,
    context: Option<String>,
    about: Option<Id>,
    created_at: Option<i128>,
    pros: Vec<FactorRow>,
    cons: Vec<FactorRow>,
    resolution: ResolutionView,
}

#[derive(Clone, Debug)]
struct FactorRow {
    id: Id,
    text: String,
    created_at: Option<i128>,
}

#[derive(Clone, Debug)]
struct ResolutionHeadRow {
    id: Id,
    outcome: String,
    forced: bool,
    evidence: Vec<Id>,
    predecessors: Vec<Id>,
    finished_at: Option<i128>,
}

#[derive(Clone, Debug)]
enum ResolutionView {
    Missing,
    Unique(ResolutionHeadRow),
    Agreed(Vec<ResolutionHeadRow>),
    Forked(Vec<ResolutionHeadRow>),
    Invalid(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Status {
    Proposed,
    Resolved,
    Forced,
    Agreed,
    ForcedAgreed,
    Forked,
    Invalid,
}

impl DecisionRow {
    fn status(&self) -> Status {
        status_of(&self.resolution)
    }

    fn sort_key(&self) -> i128 {
        self.created_at.unwrap_or(i128::MIN)
    }
}

fn status_of(resolution: &ResolutionView) -> Status {
    match resolution {
        ResolutionView::Missing => Status::Proposed,
        ResolutionView::Unique(head) if head.forced => Status::Forced,
        ResolutionView::Unique(_) => Status::Resolved,
        ResolutionView::Agreed(heads) if heads.first().is_some_and(|head| head.forced) => {
            Status::ForcedAgreed
        }
        ResolutionView::Agreed(_) => Status::Agreed,
        ResolutionView::Forked(_) => Status::Forked,
        ResolutionView::Invalid(_) => Status::Invalid,
    }
}

fn interval_key(value: decide::IntervalValue) -> Option<i128> {
    let (lower, _): (i128, i128) = value.try_from_inline().ok()?;
    Some(lower)
}

fn head_row(
    dataset: DatasetView<'_>,
    snapshot: ResolutionSnapshot,
) -> Result<ResolutionHeadRow, String> {
    let outcome = decide::read_text(dataset.reader, snapshot.outcome)
        .map_err(|error| format!("read resolution {} outcome: {error:#}", id_hex(snapshot.id)))?;
    Ok(ResolutionHeadRow {
        id: snapshot.id,
        outcome,
        forced: snapshot.forced,
        evidence: snapshot.evidence,
        predecessors: snapshot.predecessors,
        finished_at: interval_key(snapshot.finished_at),
    })
}

fn resolution_view(dataset: DatasetView<'_>, resolution: Resolution) -> ResolutionView {
    let convert = |snapshots: Vec<ResolutionSnapshot>| {
        snapshots
            .into_iter()
            .map(|snapshot| head_row(dataset, snapshot))
            .collect::<Result<Vec<_>, _>>()
    };
    match resolution {
        Resolution::Missing => ResolutionView::Missing,
        Resolution::Unique(snapshot) => match head_row(dataset, snapshot) {
            Ok(head) => ResolutionView::Unique(head),
            Err(error) => ResolutionView::Invalid(error),
        },
        Resolution::Agreed(snapshots) => match convert(snapshots) {
            Ok(heads) => ResolutionView::Agreed(heads),
            Err(error) => ResolutionView::Invalid(error),
        },
        Resolution::Forked(snapshots) => match convert(snapshots) {
            Ok(heads) => ResolutionView::Forked(heads),
            Err(error) => ResolutionView::Invalid(error),
        },
        Resolution::Invalid(error) => ResolutionView::Invalid(error),
    }
}

struct DecideLive {
    cached_revision: DatasetRevision,
    decisions: Vec<DecisionRow>,
}

impl DecideLive {
    fn refresh(dataset: DatasetView<'_>) -> Self {
        let mut decisions = Vec::new();
        for id in decide::decision_anchors(dataset.facts) {
            let genesis = match decide::genesis_for_decision(dataset.facts, id) {
                Ok(Some(genesis)) => genesis,
                Ok(None) => {
                    decisions.push(invalid_row(id, "decision has no genesis"));
                    continue;
                }
                Err(error) => {
                    decisions.push(invalid_row(id, format!("invalid genesis: {error:#}")));
                    continue;
                }
            };
            let title = match decide::read_text(dataset.reader, genesis.title) {
                Ok(title) => title,
                Err(error) => {
                    decisions.push(invalid_row(id, format!("read title: {error:#}")));
                    continue;
                }
            };
            let context = match genesis.context {
                Some(handle) => match decide::read_text(dataset.reader, handle) {
                    Ok(context) => Some(context),
                    Err(error) => {
                        decisions.push(invalid_row(id, format!("read context: {error:#}")));
                        continue;
                    }
                },
                None => None,
            };
            let factors = match decide::factors_for_decision(dataset.facts, id) {
                Ok(factors) => factors,
                Err(error) => {
                    decisions.push(invalid_row(id, format!("invalid factors: {error:#}")));
                    continue;
                }
            };
            let mut pros = Vec::new();
            let mut cons = Vec::new();
            let mut factor_error = None;
            for factor in factors {
                let text = match decide::read_text(dataset.reader, factor.text) {
                    Ok(text) => text,
                    Err(error) => {
                        factor_error =
                            Some(format!("read factor {}: {error:#}", id_hex(factor.id)));
                        break;
                    }
                };
                let row = FactorRow {
                    id: factor.id,
                    text,
                    created_at: interval_key(factor.created_at),
                };
                match factor.side {
                    FactorSide::Pro => pros.push(row),
                    FactorSide::Con => cons.push(row),
                }
            }
            if let Some(error) = factor_error {
                decisions.push(invalid_row(id, error));
                continue;
            }
            pros.sort_by_key(|factor| (factor.created_at.unwrap_or(i128::MAX), factor.id));
            cons.sort_by_key(|factor| (factor.created_at.unwrap_or(i128::MAX), factor.id));
            decisions.push(DecisionRow {
                id,
                title,
                context,
                about: genesis.about,
                created_at: interval_key(genesis.created_at),
                pros,
                cons,
                resolution: resolution_view(dataset, decide::resolution(dataset.facts, id)),
            });
        }
        decisions.sort_by_key(|decision| std::cmp::Reverse((decision.sort_key(), decision.id)));
        Self {
            cached_revision: dataset.revision,
            decisions,
        }
    }
}

fn invalid_row(id: Id, error: impl Into<String>) -> DecisionRow {
    DecisionRow {
        id,
        title: "(invalid decision)".to_owned(),
        context: None,
        about: None,
        created_at: None,
        pros: Vec::new(),
        cons: Vec::new(),
        resolution: ResolutionView::Invalid(error.into()),
    }
}

// ── Widget ───────────────────────────────────────────────────────────

#[derive(Default)]
pub struct DecidePanel {
    live: Option<DecideLive>,
}

impl DecidePanel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn render(&mut self, ctx: &mut CardCtx<'_>, dataset: DatasetView<'_>) {
        if self
            .live
            .as_ref()
            .is_none_or(|live| live.cached_revision != dataset.revision)
        {
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
                .filter(|decision| {
                    matches!(
                        decision.status(),
                        Status::Resolved | Status::Forced | Status::Agreed | Status::ForcedAgreed
                    )
                })
                .count();
            let forked = live
                .decisions
                .iter()
                .filter(|decision| decision.status() == Status::Forked)
                .count();
            let open = count.saturating_sub(resolved);
            let mut search = ctx.search();
            let needle = search.query().to_lowercase();
            let search_active = !needle.is_empty();

            ctx.grid(|grid| {
                grid.full(|ctx| {
                    let ui = ctx.ui_mut();
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 12.0;
                        count_label(ui, format!("{count} DECISIONS"), color_muted(ui), true);
                        count_label(
                            ui,
                            format!("{open} OPEN/UNSETTLED"),
                            color_proposed(ui),
                            false,
                        );
                        count_label(ui, format!("{resolved} RESOLVED"), color_resolved(), false);
                        if forked > 0 {
                            count_label(ui, format!("{forked} FORKED"), color_forked(), false);
                        }
                    });
                });

                if live.decisions.is_empty() {
                    grid.full(|ctx| {
                        let ui = ctx.ui_mut();
                        ui.add_space(16.0);
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new("⚖").size(28.0).color(color_muted(ui)));
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

                for decision in &live.decisions {
                    if search_active && !decision_matches_search(decision, &needle) {
                        continue;
                    }
                    let match_info = search_active
                        .then(|| search.report(egui::Id::new(("decide_match", decision.id))));
                    let focused = match_info.as_ref().is_some_and(|info| info.is_focused);
                    grid.full(|ctx| {
                        let ui = ctx.ui_mut();
                        let pre_y = ui.cursor().min.y;
                        render_decision(ui, decision, &needle, focused);
                        if let Some(info) = match_info {
                            if info.should_scroll_to {
                                let rect = egui::Rect::from_min_max(
                                    egui::pos2(ui.min_rect().left(), pre_y),
                                    egui::pos2(ui.min_rect().right(), ui.cursor().min.y),
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

fn count_label(ui: &mut egui::Ui, text: String, color: egui::Color32, strong: bool) {
    let mut text = egui::RichText::new(text).monospace().small().color(color);
    if strong {
        text = text.strong();
    }
    ui.label(text);
}

fn decision_matches_search(decision: &DecisionRow, needle: &str) -> bool {
    decision.title.to_lowercase().contains(needle)
        || decision
            .context
            .as_ref()
            .is_some_and(|context| context.to_lowercase().contains(needle))
        || decision
            .pros
            .iter()
            .chain(&decision.cons)
            .any(|factor| factor.text.to_lowercase().contains(needle))
        || match &decision.resolution {
            ResolutionView::Unique(head) => head.outcome.to_lowercase().contains(needle),
            ResolutionView::Agreed(heads) | ResolutionView::Forked(heads) => heads
                .iter()
                .any(|head| head.outcome.to_lowercase().contains(needle)),
            ResolutionView::Invalid(error) => error.to_lowercase().contains(needle),
            ResolutionView::Missing => false,
        }
}

// ── Rendering ────────────────────────────────────────────────────────

const STATUS_STRIPE_WIDTH: f32 = 18.0;
const STROKE_INSET: f32 = 1.0;

fn status_color(status: Status, ui: &egui::Ui) -> egui::Color32 {
    match status {
        Status::Proposed => color_proposed(ui),
        Status::Resolved => color_resolved(),
        Status::Forced => color_forced(),
        Status::Agreed => color_agreed(),
        Status::ForcedAgreed => color_forced(),
        Status::Forked => color_forked(),
        Status::Invalid => color_invalid(),
    }
}

fn status_label(status: Status) -> &'static str {
    match status {
        Status::Proposed => "PROPOSED",
        Status::Resolved => "RESOLVED",
        Status::Forced => "FORCED",
        Status::Agreed => "AGREED",
        Status::ForcedAgreed => "FORCED AGREEMENT",
        Status::Forked => "FORKED",
        Status::Invalid => "INVALID",
    }
}

fn render_decision(ui: &mut egui::Ui, decision: &DecisionRow, needle: &str, focused: bool) {
    let status = decision.status();
    let inner_margin = egui::Margin {
        left: (STROKE_INSET + STATUS_STRIPE_WIDTH + 8.0) as i8,
        right: 12,
        top: 8,
        bottom: 8,
    };
    ui.vertical(|ui| {
        let frame = egui::Frame::NONE
            .fill(ui.visuals().window_fill)
            .stroke(egui::Stroke::new(STROKE_INSET, color_frame(ui)))
            .shadow(egui::epaint::Shadow {
                offset: [2, 2],
                blur: 0,
                spread: 0,
                color: egui::Color32::from_black_alpha(48),
            })
            .corner_radius(egui::CornerRadius::ZERO)
            .inner_margin(inner_margin)
            .show(ui, |ui| {
                render_title(ui, decision, needle, focused);
                if let Some(context) = &decision.context {
                    ui.add_space(2.0);
                    GORBIE::search::highlight_label(
                        ui,
                        context,
                        needle,
                        body_format(ui, color_muted(ui)),
                        focused,
                    );
                }
                ui.add_space(6.0);
                ui.columns(2, |columns| {
                    render_factor_column(
                        &mut columns[0],
                        "PROS",
                        color_pro(),
                        &decision.pros,
                        needle,
                        focused,
                    );
                    render_factor_column(
                        &mut columns[1],
                        "CONS",
                        color_con(),
                        &decision.cons,
                        needle,
                        focused,
                    );
                });
                render_resolution(ui, &decision.resolution, needle, focused);
            });
        paint_status_stripe(
            ui.painter(),
            frame.response.rect,
            status_color(status, ui),
            status_label(status),
        );
    });
}

fn render_title(ui: &mut egui::Ui, decision: &DecisionRow, needle: &str, focused: bool) {
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
        if let Some(age) = format_relative_age(decision.created_at) {
            ui.label(
                egui::RichText::new(age)
                    .monospace()
                    .small()
                    .color(color_muted(ui)),
            );
        }
        if let Some(about) = decision.about {
            ui.label(
                egui::RichText::new(format!("→ {}", short_id(about)))
                    .monospace()
                    .small()
                    .color(color_muted(ui)),
            )
            .on_hover_text(id_hex(about));
        }
        ui.with_layout(egui::Layout::left_to_right(egui::Align::Min), |ui| {
            GORBIE::search::highlight_label(ui, &decision.title, needle, title_format(ui), focused);
        });
    });
}

fn render_factor_column(
    ui: &mut egui::Ui,
    heading: &str,
    accent: egui::Color32,
    factors: &[FactorRow],
    needle: &str,
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
            ui.label(egui::RichText::new("—").small().color(color_muted(ui)));
            return;
        }
        for factor in factors {
            ui.add_space(2.0);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                ui.label(egui::RichText::new("•").small().color(accent));
                GORBIE::search::highlight_label(
                    ui,
                    &factor.text,
                    needle,
                    body_format(ui, ui.visuals().text_color()),
                    focused,
                );
                ui.label(
                    egui::RichText::new(short_id(factor.id))
                        .monospace()
                        .small()
                        .color(color_muted(ui)),
                )
                .on_hover_text(id_hex(factor.id));
            });
        }
    });
}

fn render_resolution(ui: &mut egui::Ui, resolution: &ResolutionView, needle: &str, focused: bool) {
    match resolution {
        ResolutionView::Missing => {}
        ResolutionView::Unique(head) => {
            resolution_separator(
                ui,
                if head.forced {
                    "FORCED OUTCOME"
                } else {
                    "OUTCOME"
                },
                status_color(status_of(resolution), ui),
            );
            render_head(ui, head, true, needle, focused);
        }
        ResolutionView::Agreed(heads) => {
            resolution_separator(
                ui,
                &format!("AGREED OUTCOME · {} HEADS", heads.len()),
                status_color(status_of(resolution), ui),
            );
            if let Some(first) = heads.first() {
                GORBIE::search::highlight_label(
                    ui,
                    &first.outcome,
                    needle,
                    body_format(ui, ui.visuals().text_color()),
                    focused,
                );
            }
            for head in heads {
                render_head(ui, head, false, needle, focused);
            }
        }
        ResolutionView::Forked(heads) => {
            resolution_separator(ui, &fork_label(heads), color_forked());
            for head in heads {
                render_head(ui, head, true, needle, focused);
            }
        }
        ResolutionView::Invalid(error) => {
            resolution_separator(ui, "INVALID RESOLUTION", color_invalid());
            ui.label(
                egui::RichText::new(error)
                    .monospace()
                    .small()
                    .color(color_invalid()),
            );
        }
    }
}

fn fork_label(heads: &[ResolutionHeadRow]) -> String {
    format!(
        "DIVERGENT RESOLUTIONS · {} HEADS · NONE SELECTED",
        heads.len()
    )
}

fn resolution_separator(ui: &mut egui::Ui, label: &str, color: egui::Color32) {
    ui.add_space(6.0);
    ui.separator();
    ui.add_space(2.0);
    ui.label(
        egui::RichText::new(label)
            .monospace()
            .small()
            .strong()
            .color(color),
    );
}

fn render_head(
    ui: &mut egui::Ui,
    head: &ResolutionHeadRow,
    show_outcome: bool,
    needle: &str,
    focused: bool,
) {
    ui.add_space(3.0);
    ui.horizontal_wrapped(|ui| {
        ui.label(
            egui::RichText::new(format!("HEAD {}", short_id(head.id)))
                .monospace()
                .small()
                .strong()
                .color(color_muted(ui)),
        )
        .on_hover_text(id_hex(head.id));
        ui.label(
            egui::RichText::new(format!("forced={}", head.forced))
                .monospace()
                .small()
                .color(if head.forced {
                    color_forced()
                } else {
                    color_muted(ui)
                }),
        );
        if let Some(age) = format_relative_age(head.finished_at) {
            ui.label(
                egui::RichText::new(age)
                    .monospace()
                    .small()
                    .color(color_muted(ui)),
            );
        }
    });
    render_id_set(ui, "evidence", &head.evidence);
    if !head.predecessors.is_empty() {
        render_id_set(ui, "supersedes", &head.predecessors);
    }
    if show_outcome {
        GORBIE::search::highlight_label(
            ui,
            &head.outcome,
            needle,
            body_format(ui, ui.visuals().text_color()),
            focused,
        );
    }
}

fn render_id_set(ui: &mut egui::Ui, label: &str, ids: &[Id]) {
    let display = if ids.is_empty() {
        "(none)".to_owned()
    } else {
        ids.iter()
            .map(|id| short_id(*id))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let full = ids
        .iter()
        .map(|id| id_hex(*id))
        .collect::<Vec<_>>()
        .join("\n");
    ui.label(
        egui::RichText::new(format!("{label}: {display}"))
            .monospace()
            .small()
            .color(color_muted(ui)),
    )
    .on_hover_text(full);
}

fn paint_status_stripe(
    painter: &egui::Painter,
    outer: egui::Rect,
    color: egui::Color32,
    label: &str,
) {
    let stripe = egui::Rect::from_min_size(
        outer.min + egui::vec2(STROKE_INSET, STROKE_INSET),
        egui::vec2(STATUS_STRIPE_WIDTH, outer.height() - 2.0 * STROKE_INSET),
    );
    painter.rect_filled(stripe, egui::CornerRadius::ZERO, color);
    let text_color = GORBIE::themes::colorhash::text_color_on(color);
    let galley = painter.layout_no_wrap(label.to_owned(), egui::FontId::monospace(9.0), text_color);
    if galley.size().x + 6.0 > stripe.height() {
        return;
    }
    let position = egui::pos2(
        stripe.left() + (STATUS_STRIPE_WIDTH + galley.size().y) * 0.5,
        stripe.top() + 5.0,
    );
    let mut text = egui::epaint::TextShape::new(position, galley, text_color);
    text.angle = std::f32::consts::FRAC_PI_2;
    text.fallback_color = text_color;
    painter.add(text);
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

fn short_id(id: Id) -> String {
    id_hex(id)[..8].to_owned()
}

fn format_relative_age(timestamp: Option<i128>) -> Option<String> {
    let timestamp = timestamp?;
    let now = hifitime::Epoch::now()
        .ok()?
        .to_tai_duration()
        .total_nanoseconds();
    let seconds = ((now - timestamp) / 1_000_000_000).max(0) as i64;
    Some(format_age_secs(seconds))
}

fn format_age_secs(seconds: i64) -> String {
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3_600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h", seconds / 3_600)
    } else if seconds < 86_400 * 30 {
        format!("{}d", seconds / 86_400)
    } else if seconds < 86_400 * 365 {
        format!("{}mo", seconds / (86_400 * 30))
    } else {
        format!("{}y", seconds / (86_400 * 365))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn head(byte: u8, outcome: &str, forced: bool, evidence: Vec<Id>) -> ResolutionHeadRow {
        ResolutionHeadRow {
            id: id(byte),
            outcome: outcome.to_owned(),
            forced,
            evidence,
            predecessors: Vec::new(),
            finished_at: Some(byte.into()),
        }
    }

    #[test]
    fn forcedness_comes_only_from_the_explicit_head_bit() {
        let forced = ResolutionView::Unique(head(1, "yes", true, vec![id(3), id(4)]));
        assert_eq!(status_of(&forced), Status::Forced);
        let not_forced = ResolutionView::Unique(head(2, "yes", false, Vec::new()));
        assert_eq!(status_of(&not_forced), Status::Resolved);
    }

    #[test]
    fn agreement_keeps_head_local_evidence() {
        let view = ResolutionView::Agreed(vec![
            head(1, "yes", false, vec![id(3), id(4)]),
            head(2, "yes", false, vec![id(3), id(5)]),
        ]);
        assert_eq!(status_of(&view), Status::Agreed);
        let ResolutionView::Agreed(heads) = view else {
            unreachable!()
        };
        assert_ne!(heads[0].evidence, heads[1].evidence);
    }

    #[test]
    fn divergent_heads_are_never_projected_as_resolved() {
        let view = ResolutionView::Forked(vec![
            head(1, "yes", false, Vec::new()),
            head(2, "no", false, Vec::new()),
        ]);
        assert_eq!(status_of(&view), Status::Forked);
    }

    #[test]
    fn forced_bit_only_fork_is_not_labelled_as_divergent_outcomes() {
        let heads = vec![
            head(1, "yes", false, Vec::new()),
            head(2, "yes", true, Vec::new()),
        ];
        assert_eq!(
            fork_label(&heads),
            "DIVERGENT RESOLUTIONS · 2 HEADS · NONE SELECTED"
        );
    }
}
