//! Read-only GORBIE-embeddable viewer for the `memory` faculty.
//!
//! Memory chunks are compacted context summaries with a time span,
//! a long-string body, and a tree shape (multi-valued `child` plus
//! binary `left`/`right` partition pointers). The full faculty CLI
//! is the way to navigate by precise time range; this widget shows
//! the most-recent N chunks as cards so the user can scan recent
//! agent activity at a glance.
//!
//! Each card:
//! - colored header with the time range (start → end), span chip,
//!   and a `· N CHILDREN` count when present;
//! - paper body with the chunk's summary text (first lines visible,
//!   the rest scrollable in-card);
//! - footer line with the canonical chunk id and provenance markers
//!   (`☞ exec` / `☞ msg`) when the chunk is anchored to an exec
//!   result or archived message.
//!
//! v1 limits: no tree drill-down (children render in their own
//! card by virtue of being chunks too — the relationship isn't
//! drawn), no archive-message blob resolution (only the link is
//! shown), no live time-range filter.
//!
//! ```ignore
//! let mut panel = MemoryViewer::default();
//! panel.render(ctx, memory_ws);
//! ```

use std::collections::HashMap;

use chrono::{DateTime, Datelike, NaiveDate, TimeZone, Timelike, Utc};
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

use crate::schemas::memory::{ctx as memctx, KIND_CHUNK_ID};

type TextHandle = Inline<Handle<LongString>>;

/// How many of the most-recent chunks to keep in the live snapshot.
/// Bounded so the widget stays responsive when a long-running agent
/// has accumulated thousands of chunks — older ones are still in the
/// pile, but the CLI is the right tool for time-range archeology.
const MAX_CHUNKS: usize = 40;

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

fn chunk_color(id: Id) -> egui::Color32 {
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
struct ChunkRow {
    id: Id,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    summary: String,
    child_count: usize,
    about_exec_result: Option<Id>,
    about_archive_message: Option<Id>,
}

impl ChunkRow {
    fn span_seconds(&self) -> i64 {
        (self.end - self.start).num_seconds().max(0)
    }
}

struct MemoryLive {
    cached_head: Option<CommitHandle>,
    chunks: Vec<ChunkRow>,
    /// Total chunk count regardless of MAX_CHUNKS clamp — surfaced in
    /// the section header so the user can tell when they're seeing a
    /// truncated window.
    total: usize,
}

// ── Live snapshot ────────────────────────────────────────────────────

impl MemoryLive {
    fn refresh(ws: &mut Workspace<Pile>) -> Self {
        let space = ws
            .checkout(..)
            .map(|co| co.into_facts())
            .unwrap_or_else(|e| {
                eprintln!("[memory] checkout: {e:?}");
                TribleSet::new()
            });
        let cached_head = ws.head();

        let mut by_id: HashMap<Id, ChunkRow> = HashMap::new();

        // Retracted/superseded chunks must leave EVERY view, the board
        // included — same exclusion the CLI read paths apply (tag-agnostic:
        // anything something else supersedes is invisible).
        let superseded: std::collections::HashSet<Id> =
            find!(old: Id, pattern!(&space, [{ _ @ memctx::supersedes: ?old }])).collect();

        // Enumerate every chunk + its time-range bounds in one query.
        // start_at and end_at are NsTAIInterval values, projected as
        // hifitime Epoch tuples (start, end). For the bounds we only
        // need the lower bound of each interval.
        for (id, start_iv, end_iv) in find!(
            (id: Id, s: (Epoch, Epoch), e: (Epoch, Epoch)),
            pattern!(&space, [{
                ?id @
                metadata::tag: KIND_CHUNK_ID,
                memctx::start_at: ?s,
                memctx::end_at: ?e,
            }])
        ) {
            if superseded.contains(&id) {
                continue;
            }
            by_id.insert(
                id,
                ChunkRow {
                    id,
                    start: epoch_to_chrono(start_iv.0),
                    end: epoch_to_chrono(end_iv.0),
                    summary: String::new(),
                    child_count: 0,
                    about_exec_result: None,
                    about_archive_message: None,
                },
            );
        }
        let total = by_id.len();

        // Summary text — Handle<LongString>, dereffed on demand. Doing
        // it after the main enumeration so we can skip chunks that
        // didn't match the time-bounded find!() above.
        let summary_rows: Vec<(Id, TextHandle)> = find!(
            (id: Id, h: TextHandle),
            pattern!(&space, [{ ?id @ memctx::summary: ?h }])
        )
        .collect();
        for (id, h) in summary_rows {
            if let Some(row) = by_id.get_mut(&id) {
                if let Some(text) = read_text(ws, h) {
                    row.summary = text;
                }
            }
        }

        // Provenance pointers — exec-result or archive-message anchor
        // surfaced in the card footer.
        for (id, pid) in find!(
            (id: Id, pid: Id),
            pattern!(&space, [{ ?id @ memctx::about_exec_result: ?pid }])
        ) {
            if let Some(row) = by_id.get_mut(&id) {
                row.about_exec_result = Some(pid);
            }
        }
        for (id, pid) in find!(
            (id: Id, pid: Id),
            pattern!(&space, [{ ?id @ memctx::about_archive_message: ?pid }])
        ) {
            if let Some(row) = by_id.get_mut(&id) {
                row.about_archive_message = Some(pid);
            }
        }

        // Reference count — multi-valued `reference` attribute (renamed from `child`), one row per
        // edge. We just need the count for the badge.
        for (id, _child) in find!(
            (id: Id, c: Id),
            pattern!(&space, [{ ?id @ memctx::reference: ?c }])
        ) {
            if let Some(row) = by_id.get_mut(&id) {
                row.child_count += 1;
            }
        }

        // Sort newest-first by start time, then clamp to MAX_CHUNKS so
        // very long-running piles don't render thousands of cards.
        let mut chunks: Vec<ChunkRow> = by_id.into_values().collect();
        chunks.sort_by(|a, b| b.start.cmp(&a.start));
        chunks.truncate(MAX_CHUNKS);

        MemoryLive {
            cached_head,
            chunks,
            total,
        }
    }
}

fn epoch_to_chrono(e: Epoch) -> DateTime<Utc> {
    let secs = e.to_unix_seconds();
    Utc.timestamp_opt(secs as i64, ((secs.fract() * 1e9) as u32).min(999_999_999))
        .single()
        .unwrap_or_else(Utc::now)
}

fn read_text(ws: &mut Workspace<Pile>, h: TextHandle) -> Option<String> {
    ws.get::<View<str>, LongString>(h).ok().map(|v| {
        let s: &str = v.as_ref();
        s.to_string()
    })
}

// ── Time / span formatting ──────────────────────────────────────────

fn format_chunk_range(start: DateTime<Utc>, end: DateTime<Utc>) -> String {
    if start.date_naive() == end.date_naive() {
        format!(
            "{} {:02}:{:02} → {:02}:{:02}",
            short_date(start.date_naive()),
            start.hour(),
            start.minute(),
            end.hour(),
            end.minute(),
        )
    } else {
        format!(
            "{} {:02}:{:02} → {} {:02}:{:02}",
            short_date(start.date_naive()),
            start.hour(),
            start.minute(),
            short_date(end.date_naive()),
            end.hour(),
            end.minute(),
        )
    }
}

fn short_date(d: NaiveDate) -> String {
    let weekday = d.format("%a").to_string().to_uppercase();
    let month = d.format("%b").to_string().to_uppercase();
    format!("{weekday} {} {month}", d.day())
}

fn format_span(secs: i64) -> String {
    let s = secs.max(1);
    if s >= 86_400 {
        let d = s as f32 / 86_400.0;
        if d >= 10.0 {
            format!("{d:.0}D")
        } else {
            format!("{d:.1}D")
        }
    } else if s >= 3_600 {
        let h = s as f32 / 3_600.0;
        if h >= 10.0 {
            format!("{h:.0}H")
        } else {
            format!("{h:.1}H")
        }
    } else if s >= 60 {
        format!("{}M", s / 60)
    } else {
        format!("{s}S")
    }
}

fn id_hex(id: Id) -> String {
    format!("{id:x}")
}

fn first_line(text: &str, max_chars: usize) -> String {
    let line = text.lines().next().unwrap_or("").trim_start();
    if line.chars().count() > max_chars {
        let truncated: String = line.chars().take(max_chars.saturating_sub(1)).collect();
        format!("{truncated}…")
    } else {
        line.to_string()
    }
}

// ── Widget ───────────────────────────────────────────────────────────

pub struct MemoryViewer {
    live: Option<MemoryLive>,
}

impl Default for MemoryViewer {
    fn default() -> Self {
        Self { live: None }
    }
}

impl MemoryViewer {
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
            self.live = Some(MemoryLive::refresh(ws));
        }

        ctx.section("Memory", |ctx| {
            let Some(live) = self.live.as_ref() else { return };

            ctx.grid(|g| {
                g.full(|ctx| {
                    let ui = ctx.ui_mut();
                    let shown = live.chunks.len();
                    let label = if shown < live.total {
                        format!(
                            "SHOWING {shown} OF {} CHUNKS (NEWEST FIRST)",
                            live.total
                        )
                    } else {
                        format!(
                            "{shown} CHUNK{}",
                            if shown == 1 { "" } else { "S" }
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

                if live.chunks.is_empty() {
                    g.full(|ctx| {
                        let ui = ctx.ui_mut();
                        ui.add_space(16.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                egui::RichText::new("\u{1F9E0}") // 🧠
                                    .size(28.0)
                                    .color(color_muted(ui)),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new("No memory chunks yet.")
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

                for chunk in &live.chunks {
                    g.full(|ctx| {
                        render_chunk_card(ctx.ui_mut(), chunk);
                    });
                }
            });
        });
    }
}

// ── Chunk card ───────────────────────────────────────────────────────

fn render_chunk_card(ui: &mut egui::Ui, chunk: &ChunkRow) {
    let bubble_fill = ui.visuals().window_fill;
    let accent = chunk_color(chunk.id);
    let text_on_accent = colorhash::text_color_on(accent);
    let body_text = colorhash::text_color_on(bubble_fill);
    let body_muted = mix(body_text, bubble_fill, 0.22);

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

            // ── Header: time range + span + child count ──
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
                        ui.label(
                            egui::RichText::new(format_chunk_range(chunk.start, chunk.end))
                                .monospace()
                                .strong()
                                .color(text_on_accent),
                        );
                        ui.label(
                            egui::RichText::new(format!("· {}", format_span(chunk.span_seconds())))
                                .monospace()
                                .small()
                                .strong()
                                .color(text_on_accent),
                        );
                        if chunk.child_count > 0 {
                            ui.label(
                                egui::RichText::new(format!(
                                    "· {} CHILD{}",
                                    chunk.child_count,
                                    if chunk.child_count == 1 { "" } else { "REN" }
                                ))
                                .monospace()
                                .small()
                                .color(text_on_accent),
                            );
                        }
                    });

                    // First line of the summary as the card subtitle —
                    // a quick "what is this chunk about" before the
                    // body unrolls the full text.
                    let preview = first_line(&chunk.summary, 90);
                    if !preview.is_empty() {
                        ui.label(
                            egui::RichText::new(preview)
                                .size(14.0)
                                .color(text_on_accent),
                        );
                    }
                });

            // ── Body: summary text + provenance footer ──
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

                    // Show the body text after the first-line preview
                    // already in the header — so the body shows the
                    // SECOND line onwards. Long bodies are truncated
                    // at ~180 chars (≈3 lines at this width); the CLI
                    // is the right tool for full reads.
                    let rest = body_rest(&chunk.summary, 180);
                    if !rest.is_empty() {
                        ui.label(
                            egui::RichText::new(rest)
                                .size(13.0)
                                .color(body_text),
                        );
                    }

                    // Provenance row — small mono chips for any
                    // anchored exec-result / archive-message ids.
                    let has_provenance = chunk.about_exec_result.is_some()
                        || chunk.about_archive_message.is_some();
                    if has_provenance {
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing = egui::vec2(4.0, 4.0);
                            if let Some(eid) = chunk.about_exec_result {
                                render_provenance_chip(ui, "EXEC", eid);
                            }
                            if let Some(mid) = chunk.about_archive_message {
                                render_provenance_chip(ui, "MSG", mid);
                            }
                        });
                    }

                    // Canonical chunk id at the bottom — quiet but
                    // always reachable for cross-referencing with
                    // `memory <id-prefix>` on the CLI.
                    ui.label(
                        egui::RichText::new(id_hex(chunk.id))
                            .monospace()
                            .small()
                            .color(body_muted),
                    );
                });
        });
}

fn render_provenance_chip(ui: &mut egui::Ui, label: &str, id: Id) {
    let fill = colorhash::ral_categorical(label.as_bytes());
    let text = colorhash::text_color_on(fill);
    egui::Frame::NONE
        .fill(fill)
        .corner_radius(egui::CornerRadius::ZERO)
        .inner_margin(egui::Margin::symmetric(5, 1))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(format!("\u{261E} {label} {}", id_hex(id))) // ☞
                    .monospace()
                    .small()
                    .strong()
                    .color(text),
            );
        });
}

/// Return the rest of `text` after the first newline, truncated to
/// `max_chars` with an ellipsis. Empty when the chunk's summary is
/// just a single line — that line is already in the header preview.
fn body_rest(text: &str, max_chars: usize) -> String {
    let after_first = text.split_once('\n').map(|(_, rest)| rest).unwrap_or("");
    let trimmed = after_first.trim_start_matches(['\n', ' ']);
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.chars().count() > max_chars {
        let truncated: String =
            trimmed.chars().take(max_chars.saturating_sub(1)).collect();
        format!("{truncated}…")
    } else {
        trimmed.to_string()
    }
}
