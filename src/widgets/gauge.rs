//! Read-only GORBIE-embeddable viewer for the `gauge` faculty.
//!
//! Gauge is a research-quality lens on the canonical Wiki revision DAG. It
//! counts tags and content-derived link density across every visible frontier
//! head. Concurrent heads remain separate observations and the summary calls
//! out forks explicitly; no timestamp winner is selected. This widget renders a
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

use crate::schemas::wiki::{extract_link_targets, TAG_SPECS};
use crate::widgets::storage::{DatasetRevision, DatasetView};
use crate::wiki::{self, WikiCatalog};

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
        ((x as f32) * (1.0 - t) + (y as f32) * t)
            .round()
            .clamp(0.0, 255.0) as u8
    };
    egui::Color32::from_rgb(lerp(a.r(), b.r()), lerp(a.g(), b.g()), lerp(a.b(), b.b()))
}

// ── Tag taxonomy ─────────────────────────────────────────────────────

/// Tag names the dashboard surfaces under "Epistemic Status". Order
/// is the rendering order top-to-bottom, so the most-load-bearing
/// (published) is first.
const STATUS_TAGS: &[&str] = &["published", "refuted", "preprint", "audit-warning"];

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
    cached_revision: DatasetRevision,
    /// Logical entries on the default (not wholly archived) Wiki surface.
    total_entries: usize,
    /// Every visible maximal revision. This may exceed `total_entries` when
    /// one or more entry DAGs have unresolved concurrent heads.
    total_heads: usize,
    forked_entries: usize,
    /// Frontier heads whose immutable content contains no outgoing Wiki link.
    orphans: usize,
    /// Sum of content-derived outgoing links across every frontier head.
    total_links: usize,
    /// Per-tag-name → frontier-head count.
    tag_counts: HashMap<String, usize>,
}

impl GaugeLive {
    fn refresh(dataset: DatasetView<'_>) -> Result<Self, String> {
        let catalog = wiki::validate_catalog(dataset.reader, dataset.facts)
            .map_err(|error| format!("validate Wiki collection for Gauge: {error:#}"))?;
        let entries = catalog.revisions.list_entries();
        let total_entries = entries.len();
        let total_heads = entries.iter().map(|entry| entry.frontier.len()).sum();
        let forked_entries = entries
            .iter()
            .filter(|entry| entry.frontier.len() > 1)
            .count();

        let mut tag_counts: HashMap<String, usize> = HashMap::new();
        let mut orphans = 0usize;
        let mut total_links = 0usize;

        for head in entries.iter().flat_map(|entry| &entry.frontier) {
            for tag in &head.tags {
                if let Some(name) = resolve_tag_name(&catalog, dataset, *tag) {
                    *tag_counts.entry(name).or_insert(0) += 1;
                }
            }

            let content = wiki::read_text(dataset.reader, head.content)
                .map_err(|error| format!("read Wiki revision {:x}: {error:#}", head.id))?;
            let link_count = extract_link_targets(&content).len();
            if link_count == 0 {
                orphans += 1;
            }
            total_links += link_count;
        }

        Ok(GaugeLive {
            cached_revision: dataset.revision,
            total_entries,
            total_heads,
            forked_entries,
            orphans,
            total_links,
            tag_counts,
        })
    }

    fn count(&self, name: &str) -> usize {
        self.tag_counts.get(name).copied().unwrap_or(0)
    }
}

fn resolve_tag_name(
    catalog: &WikiCatalog,
    dataset: DatasetView<'_>,
    tag: triblespace::core::id::Id,
) -> Option<String> {
    if let Some(handle) = catalog.tag_names.get(&tag) {
        return wiki::read_text(dataset.reader, *handle).ok();
    }
    TAG_SPECS
        .iter()
        .find_map(|(known, name)| (*known == tag).then(|| (*name).to_owned()))
}

// ── Widget ───────────────────────────────────────────────────────────

pub struct GaugeViewer {
    live: Option<GaugeLive>,
    error: Option<(DatasetRevision, String)>,
}

impl Default for GaugeViewer {
    fn default() -> Self {
        Self {
            live: None,
            error: None,
        }
    }
}

impl GaugeViewer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn render(&mut self, ctx: &mut CardCtx<'_>, dataset: DatasetView<'_>) {
        let need_refresh = match self.live.as_ref() {
            None => self
                .error
                .as_ref()
                .is_none_or(|(revision, _)| *revision != dataset.revision),
            Some(l) => l.cached_revision != dataset.revision,
        };
        if need_refresh {
            match GaugeLive::refresh(dataset) {
                Ok(live) => {
                    self.live = Some(live);
                    self.error = None;
                }
                Err(error) => {
                    self.live = None;
                    self.error = Some((dataset.revision, error));
                }
            }
        }

        ctx.section("Gauge", |ctx| {
            if let Some((_, error)) = self.error.as_ref() {
                ctx.grid(|g| {
                    g.full(|ctx| {
                        let color = egui::Color32::from_rgb(0xcc, 0x0a, 0x17);
                        ctx.label(
                            egui::RichText::new(format!("INVALID WIKI SNAPSHOT · {error}"))
                                .monospace()
                                .small()
                                .strong()
                                .color(color),
                        );
                    });
                });
                return;
            }
            let Some(live) = self.live.as_ref() else {
                return;
            };

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
    let heads = live.total_heads;
    let orphan_pct = if heads > 0 {
        (live.orphans as f32 / heads as f32) * 100.0
    } else {
        0.0
    };
    let links_per = if heads > 0 {
        live.total_links as f32 / heads as f32
    } else {
        0.0
    };
    ui.label(
        egui::RichText::new(format!(
            "{} ENTR{} · {heads} HEAD{} · {} FORK{} · {:.1} LINKS/HEAD · {} ORPHAN{} ({:.0}%)",
            live.total_entries,
            if live.total_entries == 1 { "Y" } else { "IES" },
            if heads == 1 { "" } else { "S" },
            live.forked_entries,
            if live.forked_entries == 1 { "" } else { "S" },
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
        let (bar_rect, _) = ui.allocate_exact_size(egui::vec2(bar_w, row_h), egui::Sense::hover());
        let painter = ui.painter();
        painter.rect_filled(bar_rect, egui::CornerRadius::ZERO, frame);
        let fill_w = (count as f32 / max_in_section as f32).clamp(0.0, 1.0) * bar_rect.width();
        let fill_rect =
            egui::Rect::from_min_size(bar_rect.min, egui::vec2(fill_w, bar_rect.height()));
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;

    use crate::storage::{initialize_signer, open_pile_strict};
    use crate::widgets::storage::{SourceKey, StorageState};
    use crate::wiki::{self, RevisionDraft};
    use hifitime::Epoch;
    use triblespace::prelude::*;

    fn at(seconds: f64) -> wiki::IntervalValue {
        let instant = Epoch::from_tai_seconds(seconds);
        (instant, instant).try_to_inline().unwrap()
    }

    fn revision(
        output: &mut Fragment,
        author: Id,
        title: &str,
        content: &str,
        tags: &[Id],
        predecessors: &[Id],
        seconds: f64,
    ) -> Id {
        let (record, id) = wiki::revision_record(RevisionDraft {
            title: title.to_owned(),
            content: content.to_owned(),
            tags: tags.iter().copied().collect(),
            predecessors: predecessors.iter().copied().collect(),
            author,
            authored_at: at(seconds),
        })
        .unwrap();
        *output += record;
        id
    }

    #[test]
    fn gauge_counts_every_frontier_head_without_a_timestamp_winner() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("gauge.pile");
        File::create(&pile_path).unwrap();
        let signer = initialize_signer(&pile_path, None).unwrap();
        let (mut fragment, author) = wiki::author_record(&signer.verifying_key());
        let tag = TAG_SPECS[1].0;
        let root = revision(&mut fragment, author, "root", "root", &[], &[], 1.0);
        let linked = revision(
            &mut fragment,
            author,
            "linked",
            &format!(r#"#link("wiki:{root:x}")[root]"#),
            &[tag],
            &[root],
            2.0,
        );
        let unlinked = revision(
            &mut fragment,
            author,
            "unlinked",
            "no links",
            &[tag],
            &[root],
            3.0,
        );
        assert_ne!(linked, unlinked);

        let mut pile = open_pile_strict(&pile_path).unwrap();
        wiki::commit_collection(&mut pile, &signer, fragment).unwrap();
        pile.close().unwrap();

        let mut storage = StorageState::new(&pile_path);
        let context = storage.context();
        let dataset = context.dataset(SourceKey::Wiki).unwrap();
        let live = GaugeLive::refresh(dataset).unwrap();
        assert_eq!(live.total_entries, 1);
        assert_eq!(live.total_heads, 2);
        assert_eq!(live.forked_entries, 1);
        assert_eq!(live.total_links, 1);
        assert_eq!(live.orphans, 1);
        assert_eq!(live.count(TAG_SPECS[1].1), 2);
    }
}
