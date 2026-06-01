//! Read-only GORBIE-embeddable viewer for the `gauge` faculty.
//!
//! Gauge is a research-quality lens on the wiki branch — it doesn't
//! define its own attributes, it just walks the latest version of
//! every fragment and counts tags (epistemic status / content
//! type) plus outgoing-link densities. This widget renders the same
//! numbers the `gauge health` CLI command prints, as a single
//! dashboard card grouped into two tag categories with horizontal
//! count bars and a few derived health metrics underneath.
//!
//! ```ignore
//! let mut panel = GaugeViewer::default();
//! panel.render(ctx, wiki_ws);
//! ```

use std::collections::HashMap;

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

use crate::schemas::gauge::wiki;

type TextHandle = Inline<Handle<LongString>>;

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

fn mix(a: egui::Color32, b: egui::Color32, t: f32) -> egui::Color32 {
    let t = t.clamp(0.0, 1.0);
    let lerp = |x: u8, y: u8| {
        ((x as f32) * (1.0 - t) + (y as f32) * t).round().clamp(0.0, 255.0) as u8
    };
    egui::Color32::from_rgb(
        lerp(a.r(), b.r()),
        lerp(a.g(), b.g()),
        lerp(a.b(), b.b()),
    )
}

// ── Tag taxonomy ─────────────────────────────────────────────────────

/// Tag names the dashboard surfaces under "Epistemic Status". Order
/// is the rendering order top-to-bottom, so the most-load-bearing
/// (published) is first.
const STATUS_TAGS: &[&str] = &[
    "published",
    "refuted",
    "preprint",
    "audit-warning",
];

/// Tag names surfaced under "Content Type", same ordering policy:
/// foundational claims first, derived/process tags after.
const CONTENT_TAGS: &[&str] = &[
    "synthesis",
    "hypothesis",
    "evidence",
    "finding",
    "review",
    "prediction",
];

// ── Live snapshot ────────────────────────────────────────────────────

struct GaugeLive {
    cached_head: Option<CommitHandle>,
    /// Total count of distinct fragments (= number of latest versions
    /// found). Drives the orphan-rate percentage and the bar scales.
    total_versions: usize,
    /// Fragments with zero outgoing `wiki::links_to` edges. They're
    /// "leaf" entries — useful to keep an eye on as a connection
    /// debt indicator.
    orphans: usize,
    /// Sum of outgoing-link counts across every latest version. The
    /// average ratio is the "links per version" metric the CLI
    /// reports.
    total_links: usize,
    /// Per-tag-name → fragment count, keyed by tag name (resolved
    /// from the tag entity's `metadata::name` long-string).
    tag_counts: HashMap<String, usize>,
}

impl GaugeLive {
    fn refresh(ws: &mut Workspace<Pile>) -> Self {
        let space = ws
            .checkout(..)
            .map(|co| co.into_facts())
            .unwrap_or_else(|e| {
                eprintln!("[gauge] checkout: {e:?}");
                TribleSet::new()
            });
        let cached_head = ws.head();

        // For every fragment id, find the version with the latest
        // `metadata::created_at` (lower bound of the interval). This
        // mirrors what `gauge.rs::latest_versions` does in the CLI.
        let mut latest: HashMap<Id, (Id, i128)> = HashMap::new();
        for (vid, frag, ts) in find!(
            (vid: Id, frag: Id, ts: (i128, i128)),
            pattern!(&space, [{
                ?vid @
                wiki::fragment: ?frag,
                metadata::created_at: ?ts,
            }])
        ) {
            let key = ts.0;
            latest
                .entry(frag)
                .and_modify(|slot| {
                    if key > slot.1 {
                        *slot = (vid, key);
                    }
                })
                .or_insert((vid, key));
        }
        let total_versions = latest.len();

        // Cache tag-name lookups across the whole snapshot pass —
        // tag entities are shared across many fragments, so a name
        // cache keyed by tag id saves a lot of redundant blob reads.
        let mut name_cache: HashMap<Id, Option<String>> = HashMap::new();
        let mut tag_counts: HashMap<String, usize> = HashMap::new();
        let mut orphans = 0usize;
        let mut total_links = 0usize;

        for (_frag, (vid, _ts)) in &latest {
            // Tags attached to this version.
            for tag_id in find!(
                tag: Id,
                pattern!(&space, [{ vid @ metadata::tag: ?tag }])
            ) {
                let name = name_cache
                    .entry(tag_id)
                    .or_insert_with(|| resolve_tag_name(ws, &space, tag_id))
                    .clone();
                if let Some(name) = name {
                    *tag_counts.entry(name).or_insert(0) += 1;
                }
            }

            // Outgoing link count (orphan = zero out-links).
            let link_count = find!(
                target: Id,
                pattern!(&space, [{ vid @ wiki::links_to: ?target }])
            )
            .count();
            if link_count == 0 {
                orphans += 1;
            }
            total_links += link_count;
        }

        GaugeLive {
            cached_head,
            total_versions,
            orphans,
            total_links,
            tag_counts,
        }
    }

    fn count(&self, name: &str) -> usize {
        self.tag_counts.get(name).copied().unwrap_or(0)
    }
}

fn resolve_tag_name(
    ws: &mut Workspace<Pile>,
    space: &TribleSet,
    tag_id: Id,
) -> Option<String> {
    let handle = find!(
        h: TextHandle,
        pattern!(space, [{ tag_id @ metadata::name: ?h }])
    )
    .next()?;
    let view: View<str> = ws.get(handle).ok()?;
    Some(view.as_ref().to_string())
}

// ── Widget ───────────────────────────────────────────────────────────

pub struct GaugeViewer {
    live: Option<GaugeLive>,
}

impl Default for GaugeViewer {
    fn default() -> Self {
        Self { live: None }
    }
}

impl GaugeViewer {
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
            self.live = Some(GaugeLive::refresh(ws));
        }

        ctx.section("Gauge", |ctx| {
            let Some(live) = self.live.as_ref() else { return };

            ctx.grid(|g| {
                g.full(|ctx| {
                    render_summary_line(ctx.ui_mut(), live);
                });
                g.full(|ctx| {
                    render_dashboard_card(ctx.ui_mut(), live);
                });
            });
        });
    }
}

fn render_summary_line(ui: &mut egui::Ui, live: &GaugeLive) {
    let total = live.total_versions;
    let orphan_pct = if total > 0 {
        (live.orphans as f32 / total as f32) * 100.0
    } else {
        0.0
    };
    let links_per = if total > 0 {
        live.total_links as f32 / total as f32
    } else {
        0.0
    };
    ui.label(
        egui::RichText::new(format!(
            "{total} FRAGMENT{} · {:.1} LINKS/VERSION · {} ORPHAN{} ({:.0}%)",
            if total == 1 { "" } else { "S" },
            links_per,
            live.orphans,
            if live.orphans == 1 { "" } else { "S" },
            orphan_pct,
        ))
        .monospace()
        .strong()
        .small()
        .color(color_muted(ui)),
    );
}

fn render_dashboard_card(ui: &mut egui::Ui, live: &GaugeLive) {
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

            // Epistemic-status section.
            render_section_header(ui, "EPISTEMIC STATUS", body_muted);
            let status_max = STATUS_TAGS
                .iter()
                .map(|t| live.count(t))
                .max()
                .unwrap_or(0)
                .max(1);
            for tag in STATUS_TAGS {
                render_tag_row(ui, tag, live.count(tag), status_max, body_text);
            }

            ui.add_space(6.0);

            // Content-type section.
            render_section_header(ui, "CONTENT TYPE", body_muted);
            let content_max = CONTENT_TAGS
                .iter()
                .map(|t| live.count(t))
                .max()
                .unwrap_or(0)
                .max(1);
            for tag in CONTENT_TAGS {
                render_tag_row(ui, tag, live.count(tag), content_max, body_text);
            }

            // Derived metrics — the "what does the count actually
            // mean" line. Survival = published / (pub + refuted),
            // theory-grounding = published / synthesis. Only render
            // when the denominators are non-zero so we don't print
            // div-by-zero placeholders.
            let published = live.count("published");
            let refuted = live.count("refuted");
            let synthesis = live.count("synthesis");
            let review = live.count("review");

            let mut derived: Vec<String> = Vec::new();
            if published + refuted > 0 {
                derived.push(format!(
                    "SURVIVAL {:.0}%",
                    100.0 * published as f32 / (published + refuted) as f32
                ));
            }
            if synthesis > 0 {
                derived.push(format!(
                    "THEORY→EVIDENCE {:.1}%",
                    100.0 * published as f32 / synthesis as f32
                ));
            }
            if published > 0 {
                derived.push(format!(
                    "REVIEW DENSITY {:.1}",
                    review as f32 / published as f32
                ));
            }
            if !derived.is_empty() {
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(4.0, 4.0);
                    for d in derived {
                        render_metric_chip(ui, &d);
                    }
                });
            }
        });
}

fn render_section_header(ui: &mut egui::Ui, label: &str, color: egui::Color32) {
    ui.add_space(2.0);
    ui.label(
        egui::RichText::new(label)
            .monospace()
            .strong()
            .small()
            .color(color),
    );
}

/// Single tag row: a 90-px label column on the left, a count on the
/// right, and a horizontal bar in between sized by `count / max_in_section`.
/// Bar colour is hashed from the tag name so e.g. "published" is the
/// same hue everywhere it appears across the viewer.
fn render_tag_row(
    ui: &mut egui::Ui,
    label: &str,
    count: usize,
    max_in_section: usize,
    text_color: egui::Color32,
) {
    let bar_color = colorhash::ral_categorical(label.as_bytes());
    let frame = color_frame(ui);
    let label_w = 96.0;
    let count_w = 50.0;
    let row_h = 14.0;
    let total_w = ui.available_width();
    let bar_w = (total_w - label_w - count_w - 12.0).max(20.0);

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        // Label.
        ui.add_sized(
            egui::vec2(label_w, row_h),
            egui::Label::new(
                egui::RichText::new(label.to_uppercase())
                    .monospace()
                    .small()
                    .color(text_color),
            ),
        );
        // Bar.
        let (bar_rect, _) = ui.allocate_exact_size(
            egui::vec2(bar_w, row_h),
            egui::Sense::hover(),
        );
        let painter = ui.painter();
        painter.rect_filled(bar_rect, egui::CornerRadius::ZERO, frame);
        let fill_w =
            (count as f32 / max_in_section as f32).clamp(0.0, 1.0) * bar_rect.width();
        let fill_rect = egui::Rect::from_min_size(
            bar_rect.min,
            egui::vec2(fill_w, bar_rect.height()),
        );
        painter.rect_filled(fill_rect, egui::CornerRadius::ZERO, bar_color);
        // Count.
        ui.add_sized(
            egui::vec2(count_w, row_h),
            egui::Label::new(
                egui::RichText::new(format!("{count:>5}"))
                    .monospace()
                    .strong()
                    .small()
                    .color(text_color),
            ),
        );
    });
}

fn render_metric_chip(ui: &mut egui::Ui, label: &str) {
    let fill = colorhash::ral_categorical(label.as_bytes());
    let text = colorhash::text_color_on(fill);
    egui::Frame::NONE
        .fill(fill)
        .corner_radius(egui::CornerRadius::ZERO)
        .inner_margin(egui::Margin::symmetric(5, 1))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(label)
                    .monospace()
                    .small()
                    .strong()
                    .color(text),
            );
        });
}
