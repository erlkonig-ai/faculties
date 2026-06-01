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

fn entry_color(id: Id) -> egui::Color32 {
    colorhash::ral_categorical(id.as_ref())
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

// ── Row struct ───────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct AtlasRow {
    id: Id,
    name: String,
    description: Option<String>,
    /// Tag ids attached to this entity. Each is itself a catalog
    /// entry — resolved at render time so the chip shows the
    /// tag's name (or the short id when the tag has no name).
    tags: Vec<Id>,
    /// Number of other entities that carry this entity as a tag.
    /// Roughly "how many things am I a category for".
    member_count: usize,
}

impl AtlasRow {
    fn sort_key(&self) -> String {
        self.name.to_lowercase()
    }
}

struct AtlasLive {
    cached_head: Option<CommitHandle>,
    entries: Vec<AtlasRow>,
    /// Name lookup keyed by entity id — used to resolve tag chips.
    /// Same data as `entries` but indexed for O(1) chip rendering.
    name_by_id: HashMap<Id, String>,
}

// ── Live snapshot ────────────────────────────────────────────────────

impl AtlasLive {
    fn refresh(ws: &mut Workspace<Pile>) -> Self {
        let space = ws
            .checkout(..)
            .map(|co| co.into_facts())
            .unwrap_or_else(|e| {
                eprintln!("[atlas] checkout: {e:?}");
                TribleSet::new()
            });
        let cached_head = ws.head();

        // All entities with a metadata::name. The query gives us
        // (entity_id, name_handle) pairs; we deref the handle to a
        // string on demand. metadata::name is the catalog's
        // discriminator — anything named is a catalog entry.
        let name_rows: Vec<(Id, TextHandle)> = find!(
            (id: Id, h: TextHandle),
            pattern!(&space, [{ ?id @ metadata::name: ?h }])
        )
        .collect();

        let mut entries: HashMap<Id, AtlasRow> = HashMap::new();
        let mut name_by_id: HashMap<Id, String> = HashMap::new();
        for (id, h) in name_rows {
            let name = read_text(ws, h).unwrap_or_else(|| short_id(id));
            name_by_id.insert(id, name.clone());
            entries.insert(
                id,
                AtlasRow {
                    id,
                    name,
                    description: None,
                    tags: Vec::new(),
                    member_count: 0,
                },
            );
        }

        // Descriptions for the same entries.
        let desc_rows: Vec<(Id, TextHandle)> = find!(
            (id: Id, h: TextHandle),
            pattern!(&space, [{ ?id @ metadata::description: ?h }])
        )
        .collect();
        for (id, h) in desc_rows {
            if let Some(row) = entries.get_mut(&id) {
                row.description = read_text(ws, h);
            }
        }

        // Tag attachments — entity carries `metadata::tag: tag_id`.
        // We collect both (so each entry knows its own tags) and
        // count the reverse: how many entities reference this
        // entity as a tag.
        let mut member_counts: HashMap<Id, usize> = HashMap::new();
        for (entity_id, tag_id) in find!(
            (id: Id, t: Id),
            pattern!(&space, [{ ?id @ metadata::tag: ?t }])
        ) {
            if let Some(row) = entries.get_mut(&entity_id) {
                row.tags.push(tag_id);
            }
            *member_counts.entry(tag_id).or_insert(0) += 1;
        }
        for row in entries.values_mut() {
            row.tags.sort_by_key(|t| {
                let bytes: &[u8] = t.as_ref();
                bytes.to_vec()
            });
            row.tags.dedup();
            row.member_count = member_counts.get(&row.id).copied().unwrap_or(0);
        }

        let mut entries: Vec<AtlasRow> = entries.into_values().collect();
        entries.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

        AtlasLive {
            cached_head,
            entries,
            name_by_id,
        }
    }
}

fn read_text(ws: &mut Workspace<Pile>, h: TextHandle) -> Option<String> {
    ws.get::<View<str>, LongString>(h).ok().map(|v| {
        let s: &str = v.as_ref();
        s.to_string()
    })
}

fn id_hex(id: Id) -> String {
    format!("{id:x}")
}

fn short_id(id: Id) -> String {
    let s = format!("{id:x}");
    s.chars().take(8).collect()
}

fn entry_matches_search(entry: &AtlasRow, needle: &str) -> bool {
    if entry.name.to_lowercase().contains(needle) {
        return true;
    }
    if entry
        .description
        .as_deref()
        .map_or(false, |d| d.to_lowercase().contains(needle))
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
            self.live = Some(AtlasLive::refresh(ws));
        }

        ctx.section("Atlas", |ctx| {
            let Some(live) = self.live.as_ref() else { return };

            let mut search = ctx.search();
            let needle = search.query().to_lowercase();
            let search_active = !needle.is_empty();
            let visible: Vec<&AtlasRow> = if search_active {
                live.entries
                    .iter()
                    .filter(|e| entry_matches_search(e, &needle))
                    .collect()
            } else {
                live.entries.iter().collect()
            };

            ctx.grid(|g| {
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
                        Some(
                            search.report(egui::Id::new((
                                "atlas_match",
                                entry.id,
                            ))),
                        )
                    } else {
                        None
                    };
                    let is_focused =
                        match_info.as_ref().map_or(false, |i| i.is_focused);
                    g.full(|ctx| {
                        let ui = ctx.ui_mut();
                        let pre_y = ui.cursor().min.y;
                        render_entry_card(ui, entry, &live.name_by_id, &needle, is_focused);
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

// ── Entry card ──────────────────────────────────────────────────────

fn render_entry_card(
    ui: &mut egui::Ui,
    entry: &AtlasRow,
    name_by_id: &HashMap<Id, String>,
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

                    ui.horizontal(|ui| {
                        GORBIE::search::highlight_label(
                            ui,
                            &entry.name,
                            search_needle,
                            egui::TextFormat {
                                font_id: egui::FontId::new(
                                    16.0,
                                    egui::FontFamily::Proportional,
                                ),
                                color: text_on_accent,
                                ..Default::default()
                            },
                            focused,
                        );
                    });

                    let mut meta = Vec::new();
                    if !entry.tags.is_empty() {
                        meta.push(format!(
                            "{} TAG{}",
                            entry.tags.len(),
                            if entry.tags.len() == 1 { "" } else { "S" }
                        ));
                    }
                    if entry.member_count > 0 {
                        meta.push(format!(
                            "{} MEMBER{}",
                            entry.member_count,
                            if entry.member_count == 1 { "" } else { "S" }
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

                    if let Some(desc) = entry.description.as_ref() {
                        GORBIE::search::highlight_label(
                            ui,
                            desc,
                            search_needle,
                            egui::TextFormat {
                                font_id: egui::TextStyle::Body
                                    .resolve(ui.style()),
                                color: body_muted,
                                ..Default::default()
                            },
                            focused,
                        );
                    }

                    if !entry.tags.is_empty() {
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing =
                                egui::vec2(4.0, 4.0);
                            for tag_id in &entry.tags {
                                let label = name_by_id
                                    .get(tag_id)
                                    .cloned()
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
