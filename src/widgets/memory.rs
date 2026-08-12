//! Read-only GORBIE-embeddable viewer for the `memory` faculty.
//!
//! Memory chunks are immutable states in an intrinsic supersedes DAG. This
//! widget projects the canonical Memory collection and shows the most-recent
//! N live content heads as cards. Concurrent content and retraction heads stay
//! visible as an unresolved frontier; presentation order never arbitrates a
//! fork.
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
//! v1 limits: no tree drill-down (children render in their own
//! card by virtue of being chunks too — the relationship isn't
//! drawn), no archive-message blob resolution (only the link is
//! shown), no live time-range filter.
//!
//! ```ignore
//! let mut panel = MemoryViewer::default();
//! panel.render(ctx, memory_ws);
//! ```

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Datelike, NaiveDate, TimeZone, Timelike, Utc};
use hifitime::Epoch;

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use crate::memory::{self, ChunkContent, MemoryCatalog};
use crate::widgets::storage::{DatasetRevision, DatasetView};
use triblespace::core::id::Id;

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
    predecessors: Vec<Id>,
    frontier: Option<FrontierView>,
}

impl ChunkRow {
    fn span_seconds(&self) -> i64 {
        (self.end - self.start).num_seconds().max(0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrontierKind {
    Chunk,
    Retraction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FrontierHead {
    id: Id,
    kind: FrontierKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FrontierView {
    heads: Vec<FrontierHead>,
}

#[derive(Clone, Debug)]
struct RetractionView {
    id: Id,
    reason: Option<String>,
    frontier: Option<FrontierView>,
}

struct MemoryLive {
    cached_revision: DatasetRevision,
    chunks: Vec<ChunkRow>,
    /// Total chunk count regardless of MAX_CHUNKS clamp — surfaced in
    /// the section header so the user can tell when they're seeing a
    /// truncated window.
    total: usize,
    retractions: Vec<RetractionView>,
    forked_components: usize,
}

// ── Live snapshot ────────────────────────────────────────────────────

impl MemoryLive {
    fn refresh(dataset: DatasetView<'_>) -> Result<Self, String> {
        // Use the domain validator even though StorageState normally admitted
        // this exact snapshot already.  Keeping the widget boundary strict
        // makes a directly embedded viewer surface malformed structure or
        // missing payloads as a diagnostic instead of partially rendering it.
        let catalog = memory::validate_catalog(dataset.reader, dataset.facts)
            .map_err(|error| format!("validate Memory collection: {error:#}"))?;
        let frontiers = component_frontiers(&catalog);
        let forked_components = frontiers.iter().filter(|view| view.heads.len() > 1).count();
        let fork_by_head: BTreeMap<Id, FrontierView> = frontiers
            .iter()
            .filter(|view| view.heads.len() > 1)
            .flat_map(|view| {
                view.heads
                    .iter()
                    .map(|head| (head.id, view.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();

        let mut chunks = Vec::new();
        for id in catalog.live_chunk_ids() {
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
                predecessors: row.predecessors.iter().copied().collect(),
                frontier: fork_by_head.get(&id).cloned(),
            });
        }
        let total = chunks.len();

        let mut retractions = Vec::new();
        for id in catalog.head_ids() {
            let Some(row) = catalog.retractions.get(&id) else {
                continue;
            };
            let reason = row
                .reason
                .map(|handle| memory::read_text(dataset.reader, handle))
                .transpose()
                .map_err(|error| format!("read Memory retraction {id:x}: {error:#}"))?;
            retractions.push(RetractionView {
                id,
                reason,
                frontier: fork_by_head.get(&id).cloned(),
            });
        }

        // Newest-first is presentation only. The id tie-break makes equal
        // spans deterministic without pretending that time resolves a fork.
        chunks.sort_by(|a, b| b.start.cmp(&a.start).then_with(|| a.id.cmp(&b.id)));
        chunks.truncate(MAX_CHUNKS);

        Ok(MemoryLive {
            cached_revision: dataset.revision,
            chunks,
            total,
            retractions,
            forked_components,
        })
    }
}

fn component_frontiers(catalog: &MemoryCatalog) -> Vec<FrontierView> {
    let mut neighbours: BTreeMap<Id, BTreeSet<Id>> = catalog
        .node_ids()
        .into_iter()
        .map(|id| (id, BTreeSet::new()))
        .collect();
    for (id, predecessors) in catalog
        .chunks
        .values()
        .map(|row| (row.id, &row.predecessors))
        .chain(
            catalog
                .retractions
                .values()
                .map(|row| (row.id, &row.predecessors)),
        )
    {
        for predecessor in predecessors {
            neighbours.entry(id).or_default().insert(*predecessor);
            neighbours.entry(*predecessor).or_default().insert(id);
        }
    }

    let heads: BTreeSet<Id> = catalog.head_ids().into_iter().collect();
    let mut unseen: BTreeSet<Id> = neighbours.keys().copied().collect();
    let mut frontiers = Vec::new();
    while let Some(seed) = unseen.pop_first() {
        let mut stack = vec![seed];
        let mut component = BTreeSet::new();
        while let Some(node) = stack.pop() {
            if !component.insert(node) {
                continue;
            }
            unseen.remove(&node);
            stack.extend(neighbours[&node].iter().copied());
        }
        let frontier = component
            .intersection(&heads)
            .map(|id| FrontierHead {
                id: *id,
                kind: if catalog.chunks.contains_key(id) {
                    FrontierKind::Chunk
                } else {
                    FrontierKind::Retraction
                },
            })
            .collect();
        frontiers.push(FrontierView { heads: frontier });
    }
    frontiers.sort_by_key(|frontier| frontier.heads.first().map(|head| head.id));
    frontiers
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
    live: Option<MemoryLive>,
    error: Option<(DatasetRevision, String)>,
}

impl Default for MemoryViewer {
    fn default() -> Self {
        Self {
            live: None,
            error: None,
        }
    }
}

impl MemoryViewer {
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
            match MemoryLive::refresh(dataset) {
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
            let Some(live) = self.live.as_ref() else {
                return;
            };

            ctx.grid(|g| {
                g.full(|ctx| {
                    let ui = ctx.ui_mut();
                    let shown = live.chunks.len();
                    let label = if shown < live.total {
                        format!(
                            "SHOWING {shown} OF {} LIVE CHUNKS (NEWEST FIRST) · {} RETRACTION HEAD{}",
                            live.total,
                            live.retractions.len(),
                            if live.retractions.len() == 1 { "" } else { "S" },
                        )
                    } else {
                        format!(
                            "{shown} LIVE CHUNK{} · {} RETRACTION HEAD{}",
                            if shown == 1 { "" } else { "S" },
                            live.retractions.len(),
                            if live.retractions.len() == 1 { "" } else { "S" },
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

                if live.forked_components > 0 {
                    g.full(|ctx| {
                        render_frontier_warning(ctx.ui_mut(), live.forked_components);
                    });
                }

                for retraction in &live.retractions {
                    g.full(|ctx| {
                        render_retraction(ctx.ui_mut(), retraction);
                    });
                }

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
                            let message = if live.retractions.is_empty() {
                                "No memory chunks yet."
                            } else {
                                "No live content heads; retractions are shown above."
                            };
                            ui.label(
                                egui::RichText::new(message)
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

            // ── Header: time range + span + reference/fork state ──
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
                        if let Some(frontier) = chunk.frontier.as_ref() {
                            ui.label(
                                egui::RichText::new(format!(
                                    "· FORK {} HEADS",
                                    frontier.heads.len()
                                ))
                                .monospace()
                                .small()
                                .strong()
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

                    if !chunk.predecessors.is_empty() {
                        render_id_list(ui, "SUPERSEDES", &chunk.predecessors, body_muted);
                    }
                    if let Some(frontier) = chunk.frontier.as_ref() {
                        render_frontier_heads(ui, frontier, body_muted);
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

fn render_frontier_warning(ui: &mut egui::Ui, count: usize) {
    let color = egui::Color32::from_rgb(0xb0, 0x55, 0xc9);
    egui::Frame::NONE
        .fill(egui::Color32::from_rgba_unmultiplied(
            color.r(),
            color.g(),
            color.b(),
            40,
        ))
        .stroke(egui::Stroke::new(1.0, color))
        .inner_margin(egui::Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(format!(
                    "⚠ {count} FORKED LINEAGE{} · ALL HEADS SHOWN · NONE SELECTED",
                    if count == 1 { "" } else { "S" }
                ))
                .monospace()
                .small()
                .strong()
                .color(color),
            );
        });
}

fn render_retraction(ui: &mut egui::Ui, retraction: &RetractionView) {
    let color = egui::Color32::from_rgb(0xcc, 0x0a, 0x17);
    let fork = retraction
        .frontier
        .as_ref()
        .map(|frontier| format!(" · FORK {} HEADS", frontier.heads.len()))
        .unwrap_or_default();
    egui::Frame::NONE
        .fill(egui::Color32::from_rgba_unmultiplied(
            color.r(),
            color.g(),
            color.b(),
            28,
        ))
        .stroke(egui::Stroke::new(1.0, color))
        .inner_margin(egui::Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(format!("RETRACTION HEAD {}{fork}", id_hex(retraction.id)))
                    .monospace()
                    .small()
                    .strong()
                    .color(color),
            );
            if let Some(reason) = retraction.reason.as_ref() {
                ui.label(
                    egui::RichText::new(reason)
                        .small()
                        .color(ui.visuals().text_color()),
                );
            }
            if let Some(frontier) = retraction.frontier.as_ref() {
                render_frontier_heads(ui, frontier, color_muted(ui));
            }
        });
}

fn render_frontier_heads(ui: &mut egui::Ui, frontier: &FrontierView, color: egui::Color32) {
    let heads = frontier
        .heads
        .iter()
        .map(|head| {
            let kind = match head.kind {
                FrontierKind::Chunk => "CHUNK",
                FrontierKind::Retraction => "RETRACTION",
            };
            format!("{kind} {}", id_hex(head.id))
        })
        .collect::<Vec<_>>()
        .join(" · ");
    ui.label(
        egui::RichText::new(format!("FRONTIER · {heads}"))
            .monospace()
            .small()
            .color(color),
    );
}

fn render_id_list(ui: &mut egui::Ui, label: &str, ids: &[Id], color: egui::Color32) {
    let values = ids
        .iter()
        .map(|id| id_hex(*id))
        .collect::<Vec<_>>()
        .join(" · ");
    ui.label(
        egui::RichText::new(format!("{label} · {values}"))
            .monospace()
            .small()
            .color(color),
    );
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

    use triblespace::prelude::{Fragment, TryToInline};

    fn point(seconds: f64) -> memory::IntervalValue {
        let at = Epoch::from_tai_seconds(seconds);
        (at, at).try_to_inline().unwrap()
    }

    fn chunk(summary: &str, predecessors: impl IntoIterator<Item = Id>) -> (Fragment, Id) {
        memory::chunk_fragment(memory::ChunkDraft {
            content: memory::ChunkDraftContent::Text(summary.to_owned()),
            start_at: point(10.0),
            end_at: point(20.0),
            lens: None,
            references: BTreeSet::new(),
            about_exec_result: None,
            about_archive_message: None,
            predecessors: predecessors.into_iter().collect(),
            observed_at: BTreeSet::new(),
            aliases: BTreeSet::new(),
        })
        .unwrap()
    }

    #[test]
    fn independent_memory_roots_are_not_mislabelled_as_a_fork() {
        let (mut fragment, first) = chunk("first", []);
        let (second_fragment, second) = chunk("second", []);
        fragment += second_fragment;

        let catalog = memory::load_catalog(fragment.facts()).unwrap();
        let frontiers = component_frontiers(&catalog);
        assert_eq!(frontiers.len(), 2);
        assert!(frontiers.iter().all(|frontier| frontier.heads.len() == 1));
        let mut expected = vec![first, second];
        expected.sort_unstable();
        assert_eq!(catalog.live_chunk_ids(), expected);
    }

    #[test]
    fn content_retraction_race_keeps_both_heads_visible() {
        let (mut fragment, base) = chunk("base", []);
        let (content_fragment, content) = chunk("edited", [base]);
        fragment += content_fragment;
        let (retraction_fragment, retraction) =
            memory::retraction_fragment(memory::RetractionDraft {
                reason: Some("withdrawn elsewhere".to_owned()),
                predecessors: BTreeSet::from([base]),
                observed_at: BTreeSet::new(),
            })
            .unwrap();
        fragment += retraction_fragment;

        let catalog = memory::load_catalog(fragment.facts()).unwrap();
        let frontiers = component_frontiers(&catalog);
        assert_eq!(frontiers.len(), 1);
        assert_eq!(
            frontiers[0].heads,
            vec![
                FrontierHead {
                    id: content.min(retraction),
                    kind: if content < retraction {
                        FrontierKind::Chunk
                    } else {
                        FrontierKind::Retraction
                    },
                },
                FrontierHead {
                    id: content.max(retraction),
                    kind: if content > retraction {
                        FrontierKind::Chunk
                    } else {
                        FrontierKind::Retraction
                    },
                },
            ]
        );
        assert_eq!(catalog.live_chunk_ids(), vec![content]);
        assert!(catalog.head_ids().contains(&retraction));
    }

    #[test]
    fn explicit_join_collapses_a_content_fork_without_time_arbitration() {
        let (mut fragment, base) = chunk("base", []);
        let (left_fragment, left) = chunk("left", [base]);
        fragment += left_fragment;
        let (right_fragment, right) = chunk("right", [base]);
        fragment += right_fragment;

        let fork = memory::load_catalog(fragment.facts()).unwrap();
        assert_eq!(component_frontiers(&fork)[0].heads.len(), 2);

        let (join_fragment, join) = chunk("joined", [left, right]);
        fragment += join_fragment;
        let joined = memory::load_catalog(fragment.facts()).unwrap();
        assert_eq!(
            component_frontiers(&joined),
            vec![FrontierView {
                heads: vec![FrontierHead {
                    id: join,
                    kind: FrontierKind::Chunk,
                }],
            }]
        );
        assert_eq!(joined.live_chunk_ids(), vec![join]);
    }
}
