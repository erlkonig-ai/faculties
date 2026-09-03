//! Read-only GORBIE-embeddable viewer for the `atlas` faculty.
//!
//! Atlas is a schema-metadata catalog: every entity in the pile
//! that carries a `metadata::name` (and usually a
//! `metadata::description`) — kinds, tag constants, protocol roots,
//! attribute groupings. This widget lets the user browse the
//! catalog as a searchable list, with description + tag chips +
//! group/member counts.
//!
//! Card shape per entry:
//! - hashed-accent header with the entity name + tag count + group
//!   member count;
//! - paper body with the description text and tag chips (each tag
//!   resolved through the same catalog so a tag whose name lives
//!   in the catalog shows as its name; otherwise the short id);
//! - canonical entity id mono-small at the bottom.
//!
//! ```ignore
//! let mut panel = AtlasViewer::default();
//! panel.render(ctx, atlas_ws);
//! ```

use std::collections::BTreeMap;

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use crate::atlas::AtlasEntry;
use crate::widgets::storage::{DatasetRevision, DatasetView};
use triblespace::core::id::Id;

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

fn entry_color(id: Id) -> egui::Color32 {
    colorhash::ral_categorical(id.as_ref())
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

// ── Row struct ───────────────────────────────────────────────────────

struct AtlasLive {
    cached_revision: DatasetRevision,
    entries: Vec<AtlasEntry>,
    /// All name variants keyed by entity id, used to resolve tag chips
    /// without manufacturing a preferred label.
    names_by_id: BTreeMap<Id, Vec<String>>,
    diagnostic: Option<String>,
}

// ── Live snapshot ────────────────────────────────────────────────────

impl AtlasLive {
    fn refresh(dataset: DatasetView<'_>) -> Self {
        match crate::atlas::named_entries(dataset.reader, dataset.facts) {
            Ok(mut entries) => {
                entries.sort_by(|left, right| {
                    atlas_sort_key(left)
                        .cmp(&atlas_sort_key(right))
                        .then_with(|| left.id.cmp(&right.id))
                });
                let names_by_id = entries
                    .iter()
                    .map(|entry| (entry.id, entry.names.clone()))
                    .collect();
                AtlasLive {
                    cached_revision: dataset.revision,
                    entries,
                    names_by_id,
                    diagnostic: None,
                }
            }
            Err(error) => AtlasLive {
                cached_revision: dataset.revision,
                entries: Vec::new(),
                names_by_id: BTreeMap::new(),
                diagnostic: Some(format!("Atlas query failed: {error:#}")),
            },
        }
    }
}

fn atlas_sort_key(entry: &AtlasEntry) -> Vec<String> {
    entry.names.iter().map(|name| name.to_lowercase()).collect()
}

fn id_hex(id: Id) -> String {
    format!("{id:x}")
}

fn short_id(id: Id) -> String {
    let s = format!("{id:x}");
    s.chars().take(8).collect()
}

fn entry_matches_search(entry: &AtlasEntry, needle: &str) -> bool {
    if entry
        .names
        .iter()
        .any(|name| name.to_lowercase().contains(needle))
    {
        return true;
    }
    if entry
        .descriptions
        .iter()
        .any(|description| description.to_lowercase().contains(needle))
    {
        return true;
    }
    if id_hex(entry.id).contains(needle) {
        return true;
    }
    false
}

// ── Widget ───────────────────────────────────────────────────────────

pub struct AtlasViewer {
    live: Option<AtlasLive>,
}

impl Default for AtlasViewer {
    fn default() -> Self {
        Self { live: None }
    }
}

impl AtlasViewer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn render(&mut self, ctx: &mut CardCtx<'_>, dataset: DatasetView<'_>) {
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => l.cached_revision != dataset.revision,
        };
        if need_refresh {
            self.live = Some(AtlasLive::refresh(dataset));
        }

        ctx.section("Atlas", |ctx| {
            let Some(live) = self.live.as_ref() else {
                return;
            };

            let mut search = ctx.search();
            let needle = search.query().to_lowercase();
            let search_active = !needle.is_empty();
            let visible: Vec<&AtlasEntry> = if search_active {
                live.entries
                    .iter()
                    .filter(|e| entry_matches_search(e, &needle))
                    .collect()
            } else {
                live.entries.iter().collect()
            };

            ctx.grid(|g| {
                if let Some(diagnostic) = &live.diagnostic {
                    g.full(|ctx| render_diagnostic(ctx.ui_mut(), diagnostic));
                    return;
                }
                g.full(|ctx| {
                    let ui = ctx.ui_mut();
                    let total = live.entries.len();
                    let shown = visible.len();
                    let label = if search_active {
                        format!("{shown} / {total} NAMED ENTITIES")
                    } else {
                        format!(
                            "{total} NAMED ENTIT{}",
                            if total == 1 { "Y" } else { "IES" }
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

                if live.entries.is_empty() {
                    g.full(|ctx| {
                        let ui = ctx.ui_mut();
                        ui.add_space(16.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                egui::RichText::new("\u{1F5FA}") // 🗺
                                    .size(28.0)
                                    .color(color_muted(ui)),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new("No named entities in this branch.")
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

                for entry in visible {
                    let match_info = if search_active {
                        Some(search.report(egui::Id::new(("atlas_match", entry.id))))
                    } else {
                        None
                    };
                    let is_focused = match_info.as_ref().map_or(false, |i| i.is_focused);
                    g.full(|ctx| {
                        let ui = ctx.ui_mut();
                        let pre_y = ui.cursor().min.y;
                        render_entry_card(ui, entry, &live.names_by_id, &needle, is_focused);
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

// ── Entry card ──────────────────────────────────────────────────────

fn render_entry_card(
    ui: &mut egui::Ui,
    entry: &AtlasEntry,
    names_by_id: &BTreeMap<Id, Vec<String>>,
    search_needle: &str,
    focused: bool,
) {
    let bubble_fill = ui.visuals().window_fill;
    let accent = entry_color(entry.id);
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

            // ── Header: name + tag count + member count ──
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

                    for name in &entry.names {
                        GORBIE::search::highlight_label(
                            ui,
                            name,
                            search_needle,
                            egui::TextFormat {
                                font_id: egui::FontId::new(16.0, egui::FontFamily::Proportional),
                                color: text_on_accent,
                                ..Default::default()
                            },
                            focused,
                        );
                    }

                    let mut meta = Vec::new();
                    if entry.names.len() > 1 {
                        meta.push(format!("{} NAME VARIANTS", entry.names.len()));
                    }
                    if entry.descriptions.len() > 1 {
                        meta.push(format!("{} DESCRIPTION VARIANTS", entry.descriptions.len()));
                    }
                    if !entry.tags.is_empty() {
                        meta.push(format!(
                            "{} TAG{}",
                            entry.tags.len(),
                            if entry.tags.len() == 1 { "" } else { "S" }
                        ));
                    }
                    if !entry.members.is_empty() {
                        meta.push(format!(
                            "{} MEMBER{}",
                            entry.members.len(),
                            if entry.members.len() == 1 { "" } else { "S" }
                        ));
                    }
                    if !meta.is_empty() {
                        ui.label(
                            egui::RichText::new(meta.join(" · "))
                                .monospace()
                                .small()
                                .color(text_on_accent),
                        );
                    }
                });

            // ── Body: description + tag chips + id ──
            egui::Frame::NONE
                .fill(bubble_fill)
                .corner_radius(egui::CornerRadius::ZERO)
                .inner_margin(egui::Margin {
                    left: 10,
                    right: 10,
                    top: 6,
                    bottom: 8,
                })
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 4.0;

                    for (index, description) in entry.descriptions.iter().enumerate() {
                        if entry.descriptions.len() > 1 {
                            ui.label(
                                egui::RichText::new(format!(
                                    "DESCRIPTION VARIANT {} / {}",
                                    index + 1,
                                    entry.descriptions.len()
                                ))
                                .monospace()
                                .small()
                                .strong()
                                .color(body_muted),
                            );
                        }
                        GORBIE::search::highlight_label(
                            ui,
                            description,
                            search_needle,
                            egui::TextFormat {
                                font_id: egui::TextStyle::Body.resolve(ui.style()),
                                color: body_muted,
                                ..Default::default()
                            },
                            focused,
                        );
                    }

                    if !entry.tags.is_empty() {
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing = egui::vec2(4.0, 4.0);
                            for tag_id in &entry.tags {
                                let label = names_by_id
                                    .get(tag_id)
                                    .map(|names| names.join(" / "))
                                    .unwrap_or_else(|| short_id(*tag_id));
                                render_tag_chip(ui, &label);
                            }
                        });
                    }

                    ui.label(
                        egui::RichText::new(id_hex(entry.id))
                            .monospace()
                            .small()
                            .color(body_muted),
                    );
                });
        });
}

fn render_tag_chip(ui: &mut egui::Ui, label: &str) {
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

fn render_diagnostic(ui: &mut egui::Ui, diagnostic: &str) {
    let color = ui.visuals().error_fg_color;
    egui::Frame::NONE
        .fill(egui::Color32::from_rgba_unmultiplied(
            color.r(),
            color.g(),
            color.b(),
            28,
        ))
        .stroke(egui::Stroke::new(1.0, color))
        .inner_margin(egui::Margin::symmetric(8, 6))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(diagnostic)
                    .monospace()
                    .small()
                    .color(color),
            );
        });
}
