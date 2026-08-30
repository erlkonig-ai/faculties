//! Read-only GORBIE-embeddable viewer for the `status` faculty.
//!
//! A "window status board": the latest present-tense status per window
//! (`status set "<text>"`), rendered as a compact roster — one row
//! per window, most-recently-updated first, so the active windows
//! float to the top. This is the team seeing itself at a glance,
//! the GUI counterpart to `status list` / orient's Window status section.
//!
//! Filtering is by *has-a-status*, not by a separate affinity: any window
//! that has ever filed a status update appears here. That keeps the
//! board open to other windows — a future Teams/Discord user with
//! a presence status drops in with no widget change, resolving their
//! name from `relations` (or showing a hex id until they're known).
//!
//! Identity is carried by the NAME (the window's star / alias); the
//! persona colour is decorative reinforcement only, never the handle
//! one must rely on (the palette is full-hue RAL, not colorblind-safe).
//!
//! ```ignore
//! let mut panel = StatusViewer::default();
//! panel.render(ctx, status_view, relations_view);
//! ```

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use triblespace::core::id::Id;
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::core::trible::TribleSet;

use crate::relations::{self as native_relations, Head};
use crate::status as native_status;
use crate::widgets::storage::{DatasetRevision, DatasetView};

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

fn window_color(id: Id) -> egui::Color32 {
    colorhash::ral_categorical(id.as_ref())
}

// ── Row struct ───────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct WindowStatus {
    window: Id,
    /// Resolved display name (star/alias), or hex id when the window
    /// isn't in the relations branch yet.
    name: String,
    text: String,
    /// TAI-ns lower bound of the status event's `created_at` interval.
    at_ns: i128,
}

struct StatusLive {
    cached_revision: DatasetRevision,
    relations_cached_revision: Option<DatasetRevision>,
    windows: Vec<WindowStatus>,
}

// ── Live snapshot ────────────────────────────────────────────────────

impl StatusLive {
    fn refresh(view: DatasetView<'_>, relations: Option<DatasetView<'_>>) -> Self {
        let relations_cached_revision = relations.map(|relations| relations.revision);
        let empty_relations = TribleSet::new();
        let relations_facts = relations
            .map(|relations| relations.facts)
            .unwrap_or(&empty_relations);
        let latest = native_status::latest_per_window(
            native_status::load_status_rows(view.facts)
                .expect("Viewer storage exposed an invalid Status collection"),
        )
        .expect("Viewer storage exposed ambiguous Status identities");
        let mut keyed = latest
            .into_values()
            .map(|row| {
                let at_ns = native_status::point_timestamp(row.at)
                    .expect("validated Status time is a point interval");
                (
                    (at_ns, row.event),
                    WindowStatus {
                        window: row.window,
                        name: native_window_label(view.reader, relations_facts, row.window),
                        text: native_status::read_text(view.reader, row.text)
                            .expect("validated Status text is resident"),
                        at_ns,
                    },
                )
            })
            .collect::<Vec<_>>();

        // Match the Status domain's `(point timestamp, intrinsic event id)`
        // arbitration exactly, including deterministic equal-time ties.
        keyed.sort_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then_with(|| left.1.name.cmp(&right.1.name))
        });
        let windows = keyed.into_iter().map(|(_, window)| window).collect();

        StatusLive {
            cached_revision: view.revision,
            relations_cached_revision,
            windows,
        }
    }
}

fn native_window_label(reader: &PileSnapshot, facts: &TribleSet, window: Id) -> String {
    if !native_relations::person_anchors(facts).contains(&window) {
        return id_hex(window);
    }
    let mut label = match native_relations::profile_head(facts, window)
        .expect("Viewer storage exposed invalid Relations profile state")
    {
        Head::Unique(profile) => {
            let snapshot = native_relations::profile_snapshot(facts, profile)
                .expect("validated Relations profile is readable");
            native_relations::read_text(reader, snapshot.label)
                .expect("validated Relations label is resident")
        }
        Head::Forked(heads) => {
            return format!("{} [profile fork: {} heads]", id_hex(window), heads.len());
        }
        Head::Missing => return format!("{} [missing profile]", id_hex(window)),
    };
    match native_relations::lifecycle_head(facts, window)
        .expect("Viewer storage exposed invalid Relations lifecycle state")
    {
        Head::Forked(heads) => label.push_str(&format!(" [lifecycle fork: {} heads]", heads.len())),
        Head::Missing => label.push_str(" [missing lifecycle]"),
        Head::Unique(_) => {}
    }
    label
}

fn id_hex(id: Id) -> String {
    format!("{id:x}")
}

fn now_tai_ns() -> Option<i128> {
    crate::clock::tai_nanoseconds_now().ok()
}

fn age_label(now: Option<i128>, at: i128) -> String {
    let Some(now) = now else {
        return "unknown".to_owned();
    };
    let secs = ((now - at) / 1_000_000_000).max(0);
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3_600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3_600)
    } else if secs < 7 * 86_400 {
        format!("{}d", secs / 86_400)
    } else if secs < 30 * 86_400 {
        format!("{}w", secs / (7 * 86_400))
    } else {
        format!("{}mo", secs / (30 * 86_400))
    }
}

// ── Widget ───────────────────────────────────────────────────────────

pub struct StatusViewer {
    live: Option<StatusLive>,
}

impl Default for StatusViewer {
    fn default() -> Self {
        Self { live: None }
    }
}

impl StatusViewer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn render(
        &mut self,
        ctx: &mut CardCtx<'_>,
        view: DatasetView<'_>,
        relations: Option<DatasetView<'_>>,
    ) {
        let revision = view.revision;
        let relations_revision = relations.map(|view| view.revision);
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => {
                l.cached_revision != revision || l.relations_cached_revision != relations_revision
            }
        };
        if need_refresh {
            self.live = Some(StatusLive::refresh(view, relations));
        }

        ctx.section("Status", |ctx| {
            let Some(live) = self.live.as_ref() else {
                return;
            };
            let now = now_tai_ns();

            ctx.grid(|g| {
                g.full(|ctx| {
                    let ui = ctx.ui_mut();
                    let n = live.windows.len();
                    let newest = live
                        .windows
                        .first()
                        .map(|w| age_label(now, w.at_ns))
                        .unwrap_or_else(|| "-".to_string());
                    ui.label(
                        egui::RichText::new(format!(
                            "{n} WINDOW{} · NEWEST {}",
                            if n == 1 { "" } else { "S" },
                            newest.to_uppercase(),
                        ))
                        .monospace()
                        .strong()
                        .small()
                        .color(color_muted(ui)),
                    );
                });

                if live.windows.is_empty() {
                    g.full(|ctx| {
                        let ui = ctx.ui_mut();
                        ui.add_space(16.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                egui::RichText::new("\u{1F4CD}") // 📍
                                    .size(28.0)
                                    .color(color_muted(ui)),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new("No status set yet.")
                                    .monospace()
                                    .small()
                                    .strong()
                                    .color(color_muted(ui)),
                            );
                            ui.add_space(2.0);
                            ui.label(
                                egui::RichText::new(
                                    "windows appear here when they `status set \"<text>\"`.",
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

                for w in &live.windows {
                    g.full(|ctx| {
                        render_status_row(ctx.ui_mut(), w, now);
                    });
                }
            });
        });
    }
}

// ── Row rendering ────────────────────────────────────────────────────

/// One window's current status as a low-chrome roster row:
/// `[dot] NAME            <age>` on top, the status text wrapping
/// beneath. Matches orient's Window status section — a glance, not a card.
fn render_status_row(ui: &mut egui::Ui, w: &WindowStatus, now: Option<i128>) {
    let accent = window_color(w.window);
    let muted = color_muted(ui);

    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        // Decorative identity dot (NOT the handle — the name is).
        let (dot, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
        ui.painter()
            .rect_filled(dot, egui::CornerRadius::ZERO, accent);
        ui.label(
            egui::RichText::new(&w.name)
                .monospace()
                .strong()
                .size(13.0)
                .color(ui.visuals().text_color()),
        );
        // Age, right-aligned.
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                egui::RichText::new(age_label(now, w.at_ns))
                    .monospace()
                    .small()
                    .color(muted),
            );
        });
    });

    // Status text, indented under the name. Must WRAP to the row
    // width — rendering it in a bare `horizontal` gives the label
    // infinite width and clips at the card edge, so nest a `vertical`
    // (which bounds width to what's left after the indent) and let the
    // Label wrap inside it.
    let text = if w.text.trim().is_empty() {
        "(empty status)".to_string()
    } else {
        w.text.clone()
    };
    ui.horizontal_top(|ui| {
        ui.add_space(16.0); // align under the name (past the dot)
        ui.vertical(|ui| {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(text)
                        .size(13.0)
                        .color(ui.visuals().text_color()),
                )
                .wrap(),
            );
        });
    });

    // Hairline separator between windows.
    ui.add_space(4.0);
    let sep_y = ui.cursor().min.y;
    let x = ui.min_rect().x_range();
    ui.painter()
        .hline(x, sep_y, egui::Stroke::new(1.0, color_frame(ui)));
}
