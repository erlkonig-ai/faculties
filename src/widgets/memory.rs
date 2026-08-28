//! Read-only GORBIE-embeddable viewer for the `memory` faculty.
//!
//! Memory chunks are immutable episodes. This widget projects the canonical
//! Memory collection and shows the most-recent N chunks as cards. Multiple
//! tellings of the same moment coexist; presentation order does not choose a
//! current truth.
//!
//! Each card:
//! - colored header with the time range (start → end), span chip,
//!   and a `· N REFS` count when present;
//! - paper body with the chunk's summary text (first lines visible,
//!   the rest scrollable in-card);
//! - footer line with the canonical chunk id and provenance markers
//!   (`☞ exec` / `☞ msg`) when the chunk is anchored to an exec
//!   result or archived message.
//!
//! v1 limits: no archive-message blob resolution (only the link is shown), no
//! time-range filter.
//!
//! ```ignore
//! let mut panel = MemoryViewer::default();
//! panel.render(ctx, memory_ws);
//! ```

use chrono::{DateTime, Datelike, NaiveDate, TimeZone, Timelike, Utc};
use hifitime::Epoch;

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use crate::memory::{self, ChunkContent};
use crate::widgets::storage::{DatasetRevision, DatasetView};
use triblespace::core::id::Id;

/// How many of the most-recent chunks to keep in the rendered snapshot.
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
        ((x as f32) * (1.0 - t) + (y as f32) * t)
            .round()
            .clamp(0.0, 255.0) as u8
    };
    egui::Color32::from_rgb(lerp(a.r(), b.r()), lerp(a.g(), b.g()), lerp(a.b(), b.b()))
}

// ── Row struct ───────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct ChunkRow {
    id: Id,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    summary: String,
    reference_count: usize,
    about_exec_result: Option<Id>,
    about_archive_message: Option<Id>,
}

impl ChunkRow {
    fn span_seconds(&self) -> i64 {
        (self.end - self.start).num_seconds().max(0)
    }
}

struct MemorySnapshot {
    cached_revision: DatasetRevision,
    chunks: Vec<ChunkRow>,
    /// Total chunk count regardless of MAX_CHUNKS clamp — surfaced in
    /// the section header so the user can tell when they're seeing a
    /// truncated window.
    total: usize,
}

// ── Snapshot ─────────────────────────────────────────────────────────

impl MemorySnapshot {
    fn refresh(dataset: DatasetView<'_>) -> Result<Self, String> {
        // Use the domain validator even though StorageState normally admitted
        // this exact snapshot already.  Keeping the widget boundary strict
        // makes a directly embedded viewer surface malformed structure or
        // missing payloads as a diagnostic instead of partially rendering it.
        let catalog = memory::validate_catalog(dataset.reader, dataset.facts)
            .map_err(|error| format!("validate Memory collection: {error:#}"))?;
        let mut chunks = Vec::new();
        for id in catalog.chunk_ids() {
            let row = &catalog.chunks[&id];
            let (start, _): (Epoch, Epoch) = row
                .start_at
                .try_from_inline()
                .map_err(|error| format!("decode Memory chunk {id:x} start: {error:?}"))?;
            let (end, _): (Epoch, Epoch) = row
                .end_at
                .try_from_inline()
                .map_err(|error| format!("decode Memory chunk {id:x} end: {error:?}"))?;
            let summary = match row.content {
                ChunkContent::Text(handle) => memory::read_text(dataset.reader, handle)
                    .map_err(|error| format!("read Memory chunk {id:x}: {error:#}"))?,
                ChunkContent::Image(_) => "Image memory".to_owned(),
            };
            chunks.push(ChunkRow {
                id,
                start: epoch_to_chrono(start)
                    .ok_or_else(|| format!("Memory chunk {id:x} start is outside viewer range"))?,
                end: epoch_to_chrono(end)
                    .ok_or_else(|| format!("Memory chunk {id:x} end is outside viewer range"))?,
                summary,
                reference_count: row.references.len(),
                about_exec_result: row.about_exec_result,
                about_archive_message: row.about_archive_message,
            });
        }
        let total = chunks.len();

        // Newest-first is presentation only. The id tie-break makes equal
        // spans deterministic without choosing between coexisting episodes.
        chunks.sort_by(|a, b| b.start.cmp(&a.start).then_with(|| a.id.cmp(&b.id)));
        chunks.truncate(MAX_CHUNKS);

        Ok(MemorySnapshot {
            cached_revision: dataset.revision,
            chunks,
            total,
        })
    }
}

fn epoch_to_chrono(e: Epoch) -> Option<DateTime<Utc>> {
    let secs = e.to_unix_seconds();
    if !secs.is_finite() {
        return None;
    }
    let whole = secs.floor();
    if whole < i64::MIN as f64 || whole > i64::MAX as f64 {
        return None;
    }
    let nanos = ((secs - whole) * 1e9).round().clamp(0.0, 999_999_999.0) as u32;
    Utc.timestamp_opt(whole as i64, nanos).single()
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
    snapshot: Option<MemorySnapshot>,
    error: Option<(DatasetRevision, String)>,
}

impl Default for MemoryViewer {
    fn default() -> Self {
        Self {
            snapshot: None,
            error: None,
        }
    }
}

impl MemoryViewer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn render(&mut self, ctx: &mut CardCtx<'_>, dataset: DatasetView<'_>) {
        let need_refresh = match self.snapshot.as_ref() {
            None => self
                .error
                .as_ref()
                .is_none_or(|(revision, _)| *revision != dataset.revision),
            Some(l) => l.cached_revision != dataset.revision,
        };
        if need_refresh {
            match MemorySnapshot::refresh(dataset) {
                Ok(snapshot) => {
                    self.snapshot = Some(snapshot);
                    self.error = None;
                }
                Err(error) => {
                    self.snapshot = None;
                    self.error = Some((dataset.revision, error));
                }
            }
        }

        ctx.section("Memory", |ctx| {
            if let Some((_, error)) = self.error.as_ref() {
                ctx.grid(|g| {
                    g.full(|ctx| {
                        ctx.ui_mut().label(
                            egui::RichText::new(error)
                                .monospace()
                                .small()
                                .color(egui::Color32::from_rgb(0xcc, 0x0a, 0x17)),
                        );
                    });
                });
                return;
            }
            let Some(snapshot) = self.snapshot.as_ref() else {
                return;
            };

            ctx.grid(|g| {
                g.full(|ctx| {
                    let ui = ctx.ui_mut();
                    let shown = snapshot.chunks.len();
                    let label = if shown < snapshot.total {
                        format!(
                            "SHOWING {shown} OF {} MEMORY CHUNKS (NEWEST FIRST)",
                            snapshot.total,
                        )
                    } else {
                        format!("{shown} MEMORY CHUNK{}", if shown == 1 { "" } else { "S" },)
                    };
                    ui.label(
                        egui::RichText::new(label)
                            .monospace()
                            .strong()
                            .small()
                            .color(color_muted(ui)),
                    );
                });

                if snapshot.chunks.is_empty() {
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

                for chunk in &snapshot.chunks {
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
        .stroke(egui::Stroke::new(1.0_f32, color_frame(ui)))
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

            // ── Header: time range + span + reference count ──
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
                        if chunk.reference_count > 0 {
                            ui.label(
                                egui::RichText::new(format!(
                                    "· {} REF{}",
                                    chunk.reference_count,
                                    if chunk.reference_count == 1 { "" } else { "S" }
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
                        ui.label(egui::RichText::new(rest).size(13.0).color(body_text));
                    }

                    // Provenance row — small mono chips for any
                    // anchored exec-result / archive-message ids.
                    let has_provenance =
                        chunk.about_exec_result.is_some() || chunk.about_archive_message.is_some();
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
        let truncated: String = trimmed.chars().take(max_chars.saturating_sub(1)).collect();
        format!("{truncated}…")
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use triblespace::prelude::{Fragment, TryToInline};

    fn point(seconds: f64) -> memory::IntervalValue {
        let at = Epoch::from_tai_seconds(seconds);
        (at, at).try_to_inline().unwrap()
    }

    fn chunk(summary: &str) -> (Fragment, Id) {
        memory::chunk_fragment(memory::ChunkDraft {
            content: memory::ChunkDraftContent::Text(summary.to_owned()),
            start_at: point(10.0),
            end_at: point(20.0),
            lens: None,
            references: BTreeSet::new(),
            about_exec_result: None,
            about_archive_message: None,
            observed_at: BTreeSet::new(),
            aliases: BTreeSet::new(),
        })
        .unwrap()
    }

    #[test]
    fn multiple_tellings_of_one_span_coexist() {
        let (mut fragment, first) = chunk("first telling");
        let (second_fragment, second) = chunk("second telling");
        fragment += second_fragment;

        let catalog = memory::load_catalog(fragment.facts()).unwrap();
        let mut expected = vec![first, second];
        expected.sort_unstable();
        assert_eq!(catalog.chunk_ids(), expected);
        assert_eq!(catalog.chunks.len(), 2);
    }
}
