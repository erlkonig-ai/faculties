//! Read-only GORBIE-embeddable viewer for the `relations` faculty.
//!
//! Each person renders as a half-width card with two flush sections: a
//! colored header carrying the canonical identity (alias/name on top,
//! full id underneath, both in contrast text on the person's hashed
//! colour) and a paper body carrying the human-readable info (full
//! name when distinct from the alias, email, and affinity chips). The
//! coloured header is the recognition handle you carry between widgets
//! — wherever a stripe or chip uses the same person colour you can
//! match it back here at a glance.
//!
//! ```ignore
//! let mut panel = RelationsViewer::default();
//! panel.render(ctx, relations_ws);
//! ```

use std::collections::HashMap;

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

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

use crate::schemas::relations::{relations as rel, KIND_PERSON_ID};

type TextHandle = Inline<Handle<LongString>>;

// ── Color palette ────────────────────────────────────────────────────

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

fn person_color(id: Id) -> egui::Color32 {
    colorhash::ral_categorical(id.as_ref())
}

// ── Row structs ──────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct PersonRow {
    id: Id,
    alias: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    display_name: Option<String>,
    email: Option<String>,
    affinities: Vec<String>,
}

impl PersonRow {
    fn empty(id: Id) -> Self {
        Self {
            id,
            alias: None,
            first_name: None,
            last_name: None,
            display_name: None,
            email: None,
            affinities: Vec::new(),
        }
    }
}

impl PersonRow {
    /// Primary heading: alias preferred, falls back to first+last,
    /// then display_name, finally an 8-char hex prefix.
    fn primary(&self) -> String {
        if let Some(a) = self.alias.as_ref() {
            if !a.is_empty() {
                return a.clone();
            }
        }
        match (self.first_name.as_ref(), self.last_name.as_ref()) {
            (Some(f), Some(l)) if !f.is_empty() && !l.is_empty() => {
                return format!("{f} {l}");
            }
            (Some(f), _) if !f.is_empty() => return f.clone(),
            (_, Some(l)) if !l.is_empty() => return l.clone(),
            _ => {}
        }
        if let Some(d) = self.display_name.as_ref() {
            if !d.is_empty() {
                return d.clone();
            }
        }
        id_hex(self.id)
    }

    /// Secondary: full display name, when distinct from `primary()`.
    fn secondary(&self) -> Option<String> {
        let primary = self.primary();
        let full = match (self.first_name.as_ref(), self.last_name.as_ref()) {
            (Some(f), Some(l)) if !f.is_empty() && !l.is_empty() => {
                Some(format!("{f} {l}"))
            }
            _ => self.display_name.clone(),
        };
        match full {
            Some(f) if f != primary && !f.is_empty() => Some(f),
            _ => None,
        }
    }

    fn sort_key(&self) -> String {
        self.alias
            .clone()
            .unwrap_or_else(|| self.primary())
            .to_lowercase()
    }
}

fn id_hex(id: Id) -> String {
    format!("{id:x}")
}

// ── Live snapshot ────────────────────────────────────────────────────

struct RelationsLive {
    cached_head: Option<CommitHandle>,
    people: Vec<PersonRow>,
}

impl RelationsLive {
    fn refresh(ws: &mut Workspace<Pile>) -> Self {
        let space = ws
            .checkout(..)
            .map(|co| co.into_facts())
            .unwrap_or_else(|e| {
                eprintln!("[relations] checkout: {e:?}");
                TribleSet::new()
            });
        let cached_head = ws.head();

        let mut by_id: HashMap<Id, PersonRow> = HashMap::new();
        for (id,) in find!(
            (p: Id,),
            pattern!(&space, [{ ?p @ metadata::tag: KIND_PERSON_ID }])
        ) {
            by_id.insert(id, PersonRow::empty(id));
        }

        let alias_rows: Vec<(Id, String)> = find!(
            (p: Id, a: String),
            pattern!(&space, [{ ?p @ rel::alias: ?a }])
        )
        .collect();
        for (pid, alias) in alias_rows {
            if let Some(row) = by_id.get_mut(&pid) {
                row.alias = Some(alias);
            }
        }
        let first_rows: Vec<(Id, TextHandle)> = find!(
            (p: Id, h: TextHandle),
            pattern!(&space, [{ ?p @ rel::first_name: ?h }])
        )
        .collect();
        for (pid, h) in first_rows {
            if let Some(row) = by_id.get_mut(&pid) {
                row.first_name = read_text(ws, h);
            }
        }
        let last_rows: Vec<(Id, TextHandle)> = find!(
            (p: Id, h: TextHandle),
            pattern!(&space, [{ ?p @ rel::last_name: ?h }])
        )
        .collect();
        for (pid, h) in last_rows {
            if let Some(row) = by_id.get_mut(&pid) {
                row.last_name = read_text(ws, h);
            }
        }
        let display_rows: Vec<(Id, TextHandle)> = find!(
            (p: Id, h: TextHandle),
            pattern!(&space, [{ ?p @ rel::display_name: ?h }])
        )
        .collect();
        for (pid, h) in display_rows {
            if let Some(row) = by_id.get_mut(&pid) {
                row.display_name = read_text(ws, h);
            }
        }
        let email_rows: Vec<(Id, String)> = find!(
            (p: Id, e: String),
            pattern!(&space, [{ ?p @ rel::email: ?e }])
        )
        .collect();
        for (pid, e) in email_rows {
            if let Some(row) = by_id.get_mut(&pid) {
                row.email = Some(e);
            }
        }
        // Affinities — multi-valued tag-like attribute.
        let affinity_rows: Vec<(Id, String)> = find!(
            (p: Id, a: String),
            pattern!(&space, [{ ?p @ rel::affinity: ?a }])
        )
        .collect();
        for (pid, aff) in affinity_rows {
            if let Some(row) = by_id.get_mut(&pid) {
                row.affinities.push(aff);
            }
        }
        for row in by_id.values_mut() {
            row.affinities.sort();
            row.affinities.dedup();
        }

        let mut people: Vec<PersonRow> = by_id.into_values().collect();
        people.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

        RelationsLive {
            cached_head,
            people,
        }
    }
}

fn read_text(ws: &mut Workspace<Pile>, h: TextHandle) -> Option<String> {
    ws.get::<View<str>, LongString>(h).ok().map(|v| {
        let s: &str = v.as_ref();
        s.to_string()
    })
}

// ── Widget ───────────────────────────────────────────────────────────

pub struct RelationsViewer {
    live: Option<RelationsLive>,
}

impl Default for RelationsViewer {
    fn default() -> Self {
        Self { live: None }
    }
}

impl RelationsViewer {
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
            self.live = Some(RelationsLive::refresh(ws));
        }

        ctx.section("Relations", |ctx| {
            let Some(live) = self.live.as_ref() else { return };

            let mut search = ctx.search();
            let needle = search.query().to_lowercase();
            let search_active = !needle.is_empty();

            let visible_count = live
                .people
                .iter()
                .filter(|p| !search_active || person_matches_search(p, &needle))
                .count();

            ctx.grid(|g| {
                // Header.
                g.full(|ctx| {
                    let ui = ctx.ui_mut();
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 12.0;
                        ui.label(
                            egui::RichText::new(format!(
                                "{visible_count} / {} PEOPLE",
                                live.people.len()
                            ))
                            .monospace()
                            .strong()
                            .small()
                            .color(color_muted(ui)),
                        );
                    });
                });

                if live.people.is_empty() {
                    g.full(|ctx| {
                        let ui = ctx.ui_mut();
                        ui.add_space(16.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                egui::RichText::new("\u{1F465}") // 👥
                                    .size(28.0)
                                    .color(color_muted(ui)),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new("No relations yet.")
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

                // Two-per-row layout via `g.half`. People are sorted
                // by alias / name lowercase so the grid reads as an
                // alphabetic directory.
                for person in &live.people {
                    if search_active && !person_matches_search(person, &needle) {
                        continue;
                    }
                    let match_info = if search_active {
                        Some(search.report(egui::Id::new(("relations_match", person.id))))
                    } else {
                        None
                    };
                    let is_focused =
                        match_info.as_ref().map_or(false, |i| i.is_focused);
                    g.half(|ctx| {
                        let ui = ctx.ui_mut();
                        let pre_y = ui.cursor().min.y;
                        render_person(ui, person, &needle, is_focused);
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

fn person_matches_search(p: &PersonRow, needle: &str) -> bool {
    let candidates = [
        p.alias.as_deref(),
        p.first_name.as_deref(),
        p.last_name.as_deref(),
        p.display_name.as_deref(),
        p.email.as_deref(),
    ];
    for c in candidates.iter().flatten() {
        if c.to_lowercase().contains(needle) {
            return true;
        }
    }
    for aff in &p.affinities {
        if aff.to_lowercase().contains(needle) {
            return true;
        }
    }
    false
}

// ── Rendering ────────────────────────────────────────────────────────

const STROKE_INSET: f32 = 1.0;
const NAME_FONT_SIZE: f32 = 18.0;

fn render_person(
    ui: &mut egui::Ui,
    person: &PersonRow,
    search_needle: &str,
    focused: bool,
) {
    let bubble_fill = ui.visuals().window_fill;
    let accent = person_color(person.id);
    let text_on_accent = colorhash::text_color_on(accent);
    let muted = color_muted(ui);

    // The card is two stacked sections inside a single bordered/shadowed
    // outer frame: a colored header carrying the person's identity (name
    // and id) and a paper body carrying the human-friendly info beneath.
    // `inner_margin = 0` and `item_spacing.y = 0` on the outer frame
    // make the two sections flush, edge-to-edge.
    egui::Frame::NONE
        .fill(bubble_fill)
        .stroke(egui::Stroke::new(STROKE_INSET, color_frame(ui)))
        .shadow(egui::epaint::Shadow {
            offset: [2, 2],
            blur: 0,
            spread: 0,
            color: egui::Color32::from_black_alpha(48),
        })
        .corner_radius(egui::CornerRadius::ZERO)
        .inner_margin(egui::Margin::ZERO)
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;

            // ── Header: name + id on the person's color ──
            egui::Frame::NONE
                .fill(accent)
                .corner_radius(egui::CornerRadius::ZERO)
                .inner_margin(egui::Margin {
                    left: 10,
                    right: 10,
                    top: 8,
                    bottom: 8,
                })
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;

                    let name_format = egui::TextFormat {
                        font_id: egui::FontId::new(
                            NAME_FONT_SIZE,
                            egui::FontFamily::Proportional,
                        ),
                        color: text_on_accent,
                        ..Default::default()
                    };
                    GORBIE::search::highlight_label(
                        ui,
                        &person.primary(),
                        search_needle,
                        name_format,
                        focused,
                    );

                    // ID directly under the name — same colored band,
                    // so the canonical handle is paired with the name.
                    ui.label(
                        egui::RichText::new(id_hex(person.id))
                            .monospace()
                            .small()
                            .color(text_on_accent),
                    );
                });

            // ── Body: secondary, email, affinities on paper ──
            egui::Frame::NONE
                .fill(bubble_fill)
                .corner_radius(egui::CornerRadius::ZERO)
                .inner_margin(egui::Margin {
                    left: 10,
                    right: 10,
                    top: 8,
                    bottom: 10,
                })
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;

                    if let Some(secondary) = person.secondary() {
                        GORBIE::search::highlight_label(
                            ui,
                            &secondary,
                            search_needle,
                            body_format(ui, ui.visuals().text_color()),
                            focused,
                        );
                    }

                    if let Some(email) = person.email.as_ref() {
                        GORBIE::search::highlight_label(
                            ui,
                            email,
                            search_needle,
                            mono_small_format(ui, muted),
                            focused,
                        );
                    }

                    if !person.affinities.is_empty() {
                        ui.add_space(2.0);
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing = egui::vec2(4.0, 4.0);
                            for aff in &person.affinities {
                                render_tag_chip(ui, aff, accent);
                            }
                        });
                    }
                });
        });
}

fn render_tag_chip(ui: &mut egui::Ui, label: &str, accent: egui::Color32) {
    let text = colorhash::text_color_on(accent);
    egui::Frame::NONE
        .fill(accent)
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

fn body_format(ui: &egui::Ui, color: egui::Color32) -> egui::TextFormat {
    egui::TextFormat {
        font_id: egui::TextStyle::Body.resolve(ui.style()),
        color,
        ..Default::default()
    }
}

fn mono_small_format(ui: &egui::Ui, color: egui::Color32) -> egui::TextFormat {
    egui::TextFormat {
        font_id: egui::TextStyle::Monospace.resolve(ui.style()),
        color,
        ..Default::default()
    }
}
