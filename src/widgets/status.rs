//! Read-only GORBIE-embeddable viewer for the `status` faculty.
//!
//! A "colony board": the latest present-tense status per window
//! (`status set "<text>"`), rendered as a compact roster — one row
//! per window, most-recently-updated first, so the active windows
//! float to the top. This is the colony seeing itself at a glance,
//! the GUI counterpart to `status list` / orient's Colony section.
//!
//! Filtering is by *has-a-status*, not by zooid affinity: any window
//! that has ever filed a status update appears here. That keeps the
//! board open to non-zooid windows — a future Teams/Discord user with
//! a presence status drops in with no widget change, resolving their
//! name from `relations` (or showing a hex id until they're known).
//!
//! Identity is carried by the NAME (the window's star / alias); the
//! persona colour is decorative reinforcement only, never the handle
//! one must rely on (the palette is full-hue RAL, not colorblind-safe).
//!
//! ```ignore
//! let mut panel = StatusViewer::default();
//! panel.render(ctx, status_ws, relations_ws.as_mut());
//! ```

use std::collections::HashMap;

use hifitime::Epoch;

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

use crate::schemas::relations::{relations as rel, KIND_PERSON_ID};
use crate::schemas::status::{status as status_attrs, KIND_STATUS_UPDATE};

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
    cached_head: Option<CommitHandle>,
    relations_cached_head: Option<CommitHandle>,
    windows: Vec<WindowStatus>,
}

// ── Live snapshot ────────────────────────────────────────────────────

impl StatusLive {
    fn refresh(ws: &mut Workspace<Pile>, relations_ws: Option<&mut Workspace<Pile>>) -> Self {
        let space = ws
            .checkout(..)
            .map(|co| co.into_facts())
            .unwrap_or_else(|e| {
                eprintln!("[status] checkout: {e:?}");
                TribleSet::new()
            });
        let cached_head = ws.head();

        // Resolve window names from the relations branch (optional).
        let (relations_cached_head, names) = match relations_ws {
            Some(rws) => {
                let head = rws.head();
                let rspace = rws
                    .checkout(..)
                    .map(|co| co.into_facts())
                    .unwrap_or_else(|e| {
                        eprintln!("[status] relations checkout: {e:?}");
                        TribleSet::new()
                    });
                (head, build_names(&rspace, rws))
            }
            None => (None, HashMap::new()),
        };

        // Every status event: (window, text-handle, created_at). Keep
        // the latest per window by the interval's lower bound — same
        // latest-per-window semantics as the `status list` CLI.
        let mut latest: HashMap<Id, (TextHandle, i128)> = HashMap::new();
        for (window, text_h, at) in find!(
            (window: Id, text: TextHandle, at: (i128, i128)),
            pattern!(&space, [{
                _?sid @
                metadata::tag: KIND_STATUS_UPDATE,
                status_attrs::window: ?window,
                status_attrs::text: ?text,
                metadata::created_at: ?at,
            }])
        ) {
            latest
                .entry(window)
                .and_modify(|slot| {
                    if at.0 > slot.1 {
                        *slot = (text_h, at.0);
                    }
                })
                .or_insert((text_h, at.0));
        }

        let mut windows: Vec<WindowStatus> = Vec::with_capacity(latest.len());
        for (window, (text_h, at_ns)) in latest {
            let text = read_text(ws, text_h).unwrap_or_default();
            let name = names
                .get(&window)
                .cloned()
                .unwrap_or_else(|| id_hex(window));
            windows.push(WindowStatus {
                window,
                name,
                text,
                at_ns,
            });
        }

        // Most-recently-updated first — the live glance.
        windows.sort_by(|a, b| b.at_ns.cmp(&a.at_ns).then(a.name.cmp(&b.name)));

        StatusLive {
            cached_head,
            relations_cached_head,
            windows,
        }
    }
}

/// Display-name map for relations persons: alias > first+last >
/// display_name > (caller falls back to hex id). Only persons are
/// enumerated; windows absent here render by hex id.
fn build_names(rspace: &TribleSet, rws: &mut Workspace<Pile>) -> HashMap<Id, String> {
    #[derive(Default)]
    struct N {
        alias: Option<String>,
        first: Option<String>,
        last: Option<String>,
        display: Option<String>,
    }
    let mut acc: HashMap<Id, N> = HashMap::new();
    for (pid,) in find!(
        (p: Id,),
        pattern!(rspace, [{ ?p @ metadata::tag: KIND_PERSON_ID }])
    ) {
        acc.entry(pid).or_default();
    }
    for (pid, a) in find!(
        (p: Id, a: String),
        pattern!(rspace, [{ ?p @ rel::alias: ?a }])
    ) {
        if let Some(n) = acc.get_mut(&pid) {
            // Prefer the shortest alias as the canonical short handle
            // (e.g. "Zeta" over "Zeta Lyrae") — matches the star-as-label feel.
            match n.alias.as_ref() {
                Some(existing) if existing.len() <= a.len() => {}
                _ => n.alias = Some(a),
            }
        }
    }
    let first_rows: Vec<(Id, TextHandle)> = find!(
        (p: Id, h: TextHandle),
        pattern!(rspace, [{ ?p @ rel::first_name: ?h }])
    )
    .collect();
    for (pid, h) in first_rows {
        if acc.contains_key(&pid) {
            if let Some(v) = read_text(rws, h) {
                if let Some(n) = acc.get_mut(&pid) {
                    n.first.get_or_insert(v);
                }
            }
        }
    }
    let last_rows: Vec<(Id, TextHandle)> = find!(
        (p: Id, h: TextHandle),
        pattern!(rspace, [{ ?p @ rel::last_name: ?h }])
    )
    .collect();
    for (pid, h) in last_rows {
        if acc.contains_key(&pid) {
            if let Some(v) = read_text(rws, h) {
                if let Some(n) = acc.get_mut(&pid) {
                    n.last.get_or_insert(v);
                }
            }
        }
    }
    let display_rows: Vec<(Id, TextHandle)> = find!(
        (p: Id, h: TextHandle),
        pattern!(rspace, [{ ?p @ rel::display_name: ?h }])
    )
    .collect();
    for (pid, h) in display_rows {
        if acc.contains_key(&pid) {
            if let Some(v) = read_text(rws, h) {
                if let Some(n) = acc.get_mut(&pid) {
                    n.display.get_or_insert(v);
                }
            }
        }
    }

    acc.into_iter()
        .map(|(id, n)| {
            let name = n
                .alias
                .filter(|s| !s.trim().is_empty())
                .or_else(|| match (n.first.as_ref(), n.last.as_ref()) {
                    (Some(f), Some(l)) if !f.trim().is_empty() && !l.trim().is_empty() => {
                        Some(format!("{f} {l}"))
                    }
                    (Some(f), _) if !f.trim().is_empty() => Some(f.clone()),
                    (_, Some(l)) if !l.trim().is_empty() => Some(l.clone()),
                    _ => None,
                })
                .or_else(|| n.display.filter(|s| !s.trim().is_empty()))
                .unwrap_or_else(|| id_hex(id));
            (id, name)
        })
        .collect()
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

fn now_tai_ns() -> i128 {
    Epoch::now()
        .map(|e| e.to_tai_duration().total_nanoseconds())
        .unwrap_or(0)
}

fn age_label(now: i128, at: i128) -> String {
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
        ws: &mut Workspace<Pile>,
        mut relations_ws: Option<&mut Workspace<Pile>>,
    ) {
        let head = ws.head();
        let rhead = relations_ws.as_ref().and_then(|w| w.head());
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => l.cached_head != head || l.relations_cached_head != rhead,
        };
        if need_refresh {
            self.live = Some(StatusLive::refresh(
                ws,
                relations_ws.as_mut().map(|w| &mut **w),
            ));
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
/// beneath. Matches orient's Colony section — a glance, not a card.
fn render_status_row(ui: &mut egui::Ui, w: &WindowStatus, now: i128) {
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
