//! Read-only GORBIE-embeddable viewer for the `teams` faculty.
//!
//! Renders the canonical source-scoped receipt-DAG projection. A causal fork
//! is a visible diagnostic; this widget never recreates timestamp-based
//! latest-message arbitration.
//!
//! ```ignore
//! let mut panel = TeamsViewer::default();
//! panel.render(ctx, teams_ws);
//! ```

use std::collections::BTreeMap;

use chrono::{DateTime, Datelike, TimeZone, Timelike, Utc};
use hifitime::{Duration as HifiDuration, Epoch};

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use triblespace::core::id::Id;

use crate::teams;
use crate::widgets::storage::{DatasetRevision, DatasetView};

const MAX_MESSAGES: usize = 30;

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

fn chat_color(id: Id) -> egui::Color32 {
    colorhash::ral_categorical(id.as_ref())
}

fn author_color(id: Id) -> egui::Color32 {
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

// ── Row structs ──────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct MessageRow {
    id: Id,
    observation: Option<Id>,
    at: Option<DateTime<Utc>>,
    author_id: Option<Id>,
    author_name: String,
    chat_id: Id,
    content: String,
    deleted: bool,
    attachments: usize,
}

struct TeamsLive {
    cached_revision: DatasetRevision,
    messages: Vec<MessageRow>,
    chats: BTreeMap<Id, String>,
    total_messages: usize,
    chat_count: usize,
    diagnostics: Vec<String>,
}

// ── Live snapshot ────────────────────────────────────────────────────

impl TeamsLive {
    fn refresh(dataset: DatasetView<'_>) -> Self {
        let mut chats = BTreeMap::new();
        let mut messages = Vec::new();
        let mut diagnostics = Vec::new();
        for source in teams::source_ids(dataset.facts) {
            let source_label = match teams::source_label(dataset.reader, dataset.facts, source) {
                Ok(label) => label,
                Err(error) => {
                    diagnostics.push(format!(
                        "Teams source {source:x} identity is invalid: {error:#}"
                    ));
                    short_hex(source)
                }
            };
            match teams::chat_labels(dataset.reader, dataset.facts, source) {
                Ok(labels) => chats.extend(labels),
                Err(error) => diagnostics.push(format!(
                    "Teams source {source_label} chat identities are invalid: {error:#}"
                )),
            }
            match load_source_messages(dataset, source) {
                Ok(mut rows) => messages.append(&mut rows),
                Err(error) => diagnostics.push(format!(
                    "Teams source {source_label} has no unambiguous current frontier: {error:#}"
                )),
            }
        }
        let total_messages = messages.len();
        messages.sort_by(|a, b| b.at.cmp(&a.at));
        messages.truncate(MAX_MESSAGES);

        TeamsLive {
            cached_revision: dataset.revision,
            messages,
            total_messages,
            chat_count: chats.len(),
            chats,
            diagnostics,
        }
    }

    fn chat_label(&self, cid: Id) -> String {
        match self.chats.get(&cid) {
            Some(n) => n.clone(),
            None => format!("chat:{}", short_hex(cid)),
        }
    }
}

fn load_source_messages(dataset: DatasetView<'_>, source: Id) -> anyhow::Result<Vec<MessageRow>> {
    teams::current_messages(dataset.facts, source)?
        .into_iter()
        .map(|message| {
            let mut names = message
                .author_names
                .iter()
                .map(|&handle| teams::read_text(dataset.reader, handle, "Teams author name"))
                .collect::<anyhow::Result<Vec<_>>>()?;
            names.sort();
            names.dedup();
            let author_name = if names.is_empty() {
                message
                    .author
                    .map(short_hex)
                    .unwrap_or_else(|| "unknown".to_owned())
            } else {
                names.join(" / ")
            };
            let content = message
                .content
                .map(|handle| teams::read_text(dataset.reader, handle, "Teams message content"))
                .transpose()?
                .map(|content| strip_html(&content))
                .unwrap_or_else(|| "[deleted]".to_owned());
            let at = message
                .created_at
                .or(message.modified_at)
                .map(teams::interval_key)
                .map(ns_to_chrono)
                .transpose()?;
            Ok(MessageRow {
                id: message.message,
                observation: message.observation,
                at,
                author_id: message.author,
                author_name,
                chat_id: message.chat,
                content,
                deleted: message.deleted,
                attachments: message.attachments.len(),
            })
        })
        .collect()
}

fn epoch_to_chrono(epoch: Epoch) -> anyhow::Result<DateTime<Utc>> {
    let secs = epoch.to_unix_seconds();
    if !secs.is_finite() {
        anyhow::bail!("Teams timestamp is not finite");
    }
    let whole = secs.floor();
    if whole < i64::MIN as f64 || whole > i64::MAX as f64 {
        anyhow::bail!("Teams timestamp is outside the displayable UTC range");
    }
    let nanos = ((secs - whole) * 1e9).round().clamp(0.0, 999_999_999.0) as u32;
    Utc.timestamp_opt(whole as i64, nanos)
        .single()
        .ok_or_else(|| anyhow::anyhow!("Teams timestamp is outside the displayable UTC range"))
}

fn ns_to_chrono(ns: i128) -> anyhow::Result<DateTime<Utc>> {
    epoch_to_chrono(Epoch::from_tai_duration(
        HifiDuration::from_total_nanoseconds(ns),
    ))
}

fn current_utc() -> Option<DateTime<Utc>> {
    crate::clock::now()
        .ok()
        .and_then(|epoch| epoch_to_chrono(epoch).ok())
}

fn id_hex(id: Id) -> String {
    format!("{id:x}")
}

fn short_hex(id: Id) -> String {
    let s = format!("{id:x}");
    s.chars().take(8).collect()
}

fn format_chat_time(t: DateTime<Utc>) -> String {
    let date = t.date_naive();
    let weekday = date.format("%a").to_string().to_uppercase();
    let month = date.format("%b").to_string().to_uppercase();
    format!(
        "{weekday} {} {month} · {:02}:{:02}",
        date.day(),
        t.hour(),
        t.minute()
    )
}

fn age_label(now: DateTime<Utc>, at: DateTime<Utc>) -> String {
    let secs = (now - at).num_seconds().max(0);
    if secs < 60 {
        format!("{secs}S AGO")
    } else if secs < 3_600 {
        format!("{}M AGO", secs / 60)
    } else if secs < 86_400 {
        format!("{}H AGO", secs / 3_600)
    } else {
        format!("{}D AGO", secs / 86_400)
    }
}

fn truncate_to(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        let cut: String = text.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

/// Strip basic HTML tags from a Teams message body so cards stay
/// readable. Teams stores message content as HTML fragments
/// (`<p>...</p>`, `<emoji>...</emoji>`, etc.) — the raw markup
/// dominates the card otherwise. This is not a real HTML parser,
/// just a tag-elision pass with whitespace normalisation; good
/// enough for the preview layer.
fn strip_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_tag = false;
    let mut last_ws = false;
    for ch in text.chars() {
        match ch {
            '<' => {
                in_tag = true;
            }
            '>' if in_tag => {
                in_tag = false;
                if !last_ws {
                    out.push(' ');
                    last_ws = true;
                }
            }
            _ if in_tag => {}
            c if c.is_whitespace() => {
                if !last_ws {
                    out.push(' ');
                    last_ws = true;
                }
            }
            c => {
                out.push(c);
                last_ws = false;
            }
        }
    }
    out.trim().to_string()
}

// ── Widget ───────────────────────────────────────────────────────────

pub struct TeamsViewer {
    live: Option<TeamsLive>,
}

impl Default for TeamsViewer {
    fn default() -> Self {
        Self { live: None }
    }
}

impl TeamsViewer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn render(&mut self, ctx: &mut CardCtx<'_>, dataset: DatasetView<'_>) {
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => l.cached_revision != dataset.revision,
        };
        if need_refresh {
            self.live = Some(TeamsLive::refresh(dataset));
        }

        ctx.section("Teams", |ctx| {
            let Some(live) = self.live.as_ref() else { return };
            let now = current_utc();

            ctx.grid(|g| {
                for diagnostic in &live.diagnostics {
                    g.full(|ctx| render_diagnostic(ctx.ui_mut(), diagnostic));
                }
                g.full(|ctx| {
                    let ui = ctx.ui_mut();
                    let shown = live.messages.len();
                    let label = if shown < live.total_messages {
                        format!(
                            "SHOWING {shown} OF {} MESSAGES · {} CHAT{}",
                            live.total_messages,
                            live.chat_count,
                            if live.chat_count == 1 { "" } else { "S" }
                        )
                    } else {
                        format!(
                            "{shown} MESSAGE{} · {} CHAT{}",
                            if shown == 1 { "" } else { "S" },
                            live.chat_count,
                            if live.chat_count == 1 { "" } else { "S" }
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

                if live.messages.is_empty() {
                    g.full(|ctx| {
                        let ui = ctx.ui_mut();
                        ui.add_space(16.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                egui::RichText::new("\u{1F4AC}") // 💬
                                    .size(28.0)
                                    .color(color_muted(ui)),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new("No Teams messages on this branch.")
                                    .monospace()
                                    .small()
                                    .strong()
                                    .color(color_muted(ui)),
                            );
                            ui.add_space(2.0);
                            ui.label(
                                egui::RichText::new(
                                    "run `teams read` to sync from Graph (refresh token may need renewing).",
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

                for msg in &live.messages {
                    g.full(|ctx| {
                        render_message_card(ctx.ui_mut(), msg, live, now);
                    });
                }
            });
        });
    }
}

// ── Message card ────────────────────────────────────────────────────

fn render_message_card(
    ui: &mut egui::Ui,
    msg: &MessageRow,
    live: &TeamsLive,
    now: Option<DateTime<Utc>>,
) {
    let bubble_fill = ui.visuals().window_fill;
    let accent = chat_color(msg.chat_id);
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

            // ── Header: chat · time ──
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
                            egui::RichText::new(live.chat_label(msg.chat_id))
                                .monospace()
                                .strong()
                                .color(text_on_accent),
                        );
                        if msg.deleted {
                            ui.label(
                                egui::RichText::new("DELETED")
                                    .monospace()
                                    .small()
                                    .strong()
                                    .color(text_on_accent),
                            );
                        }
                        if msg.attachments > 0 {
                            ui.label(
                                egui::RichText::new(format!("📎 {}", msg.attachments))
                                    .monospace()
                                    .small()
                                    .color(text_on_accent),
                            );
                        }
                        let time = match (msg.at, now) {
                            (Some(at), Some(now)) => {
                                format!("· {} · {}", format_chat_time(at), age_label(now, at))
                            }
                            (Some(at), None) => format!("· {}", format_chat_time(at)),
                            (None, _) => "· SOURCE TIME UNKNOWN".to_owned(),
                        };
                        ui.label(
                            egui::RichText::new(time)
                                .monospace()
                                .small()
                                .color(text_on_accent),
                        );
                    });

                    let author_label = msg.author_name.clone();
                    let author_fill = msg
                        .author_id
                        .map(author_color)
                        .unwrap_or_else(|| egui::Color32::from_gray(150));
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing = egui::vec2(6.0, 2.0);
                        render_author_chip(ui, &author_label, author_fill);
                        ui.label(
                            egui::RichText::new(truncate_to(
                                msg.content.lines().next().unwrap_or("").trim(),
                                160,
                            ))
                            .size(14.0)
                            .color(text_on_accent),
                        );
                    });
                });

            // ── Body: rest of content + id ──
            let multi_line = msg.content.lines().count() > 1;
            if multi_line {
                egui::Frame::NONE
                    .fill(bubble_fill)
                    .corner_radius(egui::CornerRadius::ZERO)
                    .inner_margin(egui::Margin {
                        left: 10,
                        right: 10,
                        top: 6,
                        bottom: 6,
                    })
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        let rest: String =
                            msg.content.lines().skip(1).collect::<Vec<_>>().join("\n");
                        ui.label(
                            egui::RichText::new(truncate_to(rest.trim(), 200))
                                .size(13.0)
                                .color(body_muted),
                        );
                    });
            }

            egui::Frame::NONE
                .fill(bubble_fill)
                .corner_radius(egui::CornerRadius::ZERO)
                .inner_margin(egui::Margin {
                    left: 10,
                    right: 10,
                    top: 2,
                    bottom: 6,
                })
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.label(
                        egui::RichText::new(match msg.observation {
                            Some(observation) => format!(
                                "message {} · observation {}",
                                id_hex(msg.id),
                                id_hex(observation)
                            ),
                            None => format!("message {} · source tombstone", id_hex(msg.id)),
                        })
                        .monospace()
                        .small()
                        .color(body_muted),
                    );
                });
        });
}

fn render_diagnostic(ui: &mut egui::Ui, diagnostic: &str) {
    egui::Frame::NONE
        .fill(color_frame(ui))
        .inner_margin(egui::Margin::same(10))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new("TEAMS FRONTIER REQUIRES RECONCILIATION")
                    .monospace()
                    .small()
                    .strong()
                    .color(egui::Color32::from_rgb(0xe2, 0x5b, 0x12)),
            );
            ui.label(egui::RichText::new(diagnostic).monospace().small());
        });
}

fn render_author_chip(ui: &mut egui::Ui, label: &str, fill: egui::Color32) {
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
