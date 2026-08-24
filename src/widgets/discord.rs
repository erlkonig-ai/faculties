//! Read-only GORBIE-embeddable viewer for the `discord` faculty.
//!
//! Renders the canonical Discord read model: immutable observations selected
//! by official source version, with divergent maximal semantic variants kept
//! visible rather than reduced to an iteration-order winner.
//!
//! ```ignore
//! let mut panel = DiscordViewer::default();
//! panel.render(ctx, discord_ws);
//! ```

use chrono::{DateTime, Datelike, TimeZone, Timelike, Utc};
use hifitime::{Duration as HifiDuration, Epoch};

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use triblespace::core::id::Id;

use crate::discord;
use crate::widgets::storage::{DatasetRevision, DatasetView};

/// Cap on visible messages. Older messages are still on the
/// branch; the `discord read` CLI is the right tool for full
/// history.
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

fn channel_color(id: Id) -> egui::Color32 {
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
    anchor: Id,
    at: DateTime<Utc>,
    author_id: Id,
    author_name: String,
    channel_id: Id,
    content: String,
    variant_index: usize,
    variant_count: usize,
}

struct DiscordLive {
    cached_revision: DatasetRevision,
    messages: Vec<MessageRow>,
    channels: std::collections::BTreeMap<Id, String>,
    total_messages: usize,
    channel_count: usize,
    conflict_count: usize,
    diagnostic: Option<String>,
}

// ── Live snapshot ────────────────────────────────────────────────────

impl DiscordLive {
    fn refresh(dataset: DatasetView<'_>) -> Self {
        match Self::load(dataset) {
            Ok(live) => live,
            Err(error) => Self {
                cached_revision: dataset.revision,
                messages: Vec::new(),
                channels: Default::default(),
                total_messages: 0,
                channel_count: 0,
                conflict_count: 0,
                diagnostic: Some(format!("Discord projection is invalid: {error:#}")),
            },
        }
    }

    fn load(dataset: DatasetView<'_>) -> anyhow::Result<Self> {
        let channels = discord::channel_labels(dataset.facts, dataset.reader)?;
        let authors = discord::user_labels(dataset.facts, dataset.reader)?;
        let selected = discord::select_messages(dataset.facts, None, None)?;
        let total_messages = selected
            .iter()
            .map(|message| message.anchor)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let conflict_count = selected
            .iter()
            .filter(|message| message.variant_count > 1)
            .map(|message| message.anchor)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let all_messages = selected
            .into_iter()
            .map(|message| {
                let content =
                    discord::read_text(dataset.reader, message.content, "Discord message content")?;
                Ok(MessageRow {
                    id: message.observation,
                    anchor: message.anchor,
                    at: ns_to_chrono(discord::interval_key(message.created_at))?,
                    author_id: message.author,
                    author_name: authors
                        .get(&message.author)
                        .cloned()
                        .unwrap_or_else(|| short_hex(message.author)),
                    channel_id: message.channel,
                    content: strip_html(&content),
                    variant_index: message.variant_index,
                    variant_count: message.variant_count,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let messages = newest_complete_message_groups(all_messages, MAX_MESSAGES);
        Ok(Self {
            cached_revision: dataset.revision,
            channel_count: channels.len(),
            messages,
            channels,
            total_messages,
            conflict_count,
            diagnostic: None,
        })
    }

    fn channel_label(&self, cid: Id) -> String {
        match self.channels.get(&cid) {
            Some(name) => format!("#{name}"),
            None => format!("#{}", short_hex(cid)),
        }
    }
}

fn newest_complete_message_groups(all_messages: Vec<MessageRow>, limit: usize) -> Vec<MessageRow> {
    let mut by_anchor = std::collections::BTreeMap::<Id, Vec<MessageRow>>::new();
    for message in all_messages {
        by_anchor.entry(message.anchor).or_default().push(message);
    }
    let mut groups = by_anchor.into_values().collect::<Vec<_>>();
    groups.sort_by(|left, right| {
        right
            .iter()
            .map(|message| message.at)
            .max()
            .cmp(&left.iter().map(|message| message.at).max())
            .then_with(|| left[0].anchor.cmp(&right[0].anchor))
    });
    let mut messages = Vec::new();
    for mut group in groups.into_iter().take(limit) {
        group.sort_by_key(|message| (message.variant_index, message.id));
        messages.append(&mut group);
    }
    messages
}

fn epoch_to_chrono(epoch: Epoch) -> anyhow::Result<DateTime<Utc>> {
    let secs = epoch.to_unix_seconds();
    if !secs.is_finite() {
        anyhow::bail!("Discord timestamp is not finite");
    }
    let whole = secs.floor();
    if whole < i64::MIN as f64 || whole > i64::MAX as f64 {
        anyhow::bail!("Discord timestamp is outside the displayable UTC range");
    }
    let nanos = ((secs - whole) * 1e9).round().clamp(0.0, 999_999_999.0) as u32;
    Utc.timestamp_opt(whole as i64, nanos)
        .single()
        .ok_or_else(|| anyhow::anyhow!("Discord timestamp is outside the displayable UTC range"))
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

/// Strip basic HTML/markup so message previews stay readable when
/// content arrives with embedded tags. Discord messages are usually
/// plain text, but bot integrations and webhooks sometimes ship
/// HTML-fragmented payloads. Cheap tag elision is enough for the
/// preview layer; the message id is always available for the CLI
/// drill-down if the raw form matters.
fn strip_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_tag = false;
    let mut last_ws = false;
    for ch in text.chars() {
        match ch {
            '<' => in_tag = true,
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

pub struct DiscordViewer {
    live: Option<DiscordLive>,
}

impl Default for DiscordViewer {
    fn default() -> Self {
        Self { live: None }
    }
}

impl DiscordViewer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn render(&mut self, ctx: &mut CardCtx<'_>, dataset: DatasetView<'_>) {
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => l.cached_revision != dataset.revision,
        };
        if need_refresh {
            self.live = Some(DiscordLive::refresh(dataset));
        }

        ctx.section("Discord", |ctx| {
            let Some(live) = self.live.as_ref() else {
                return;
            };
            let now = current_utc();

            ctx.grid(|g| {
                if let Some(diagnostic) = &live.diagnostic {
                    g.full(|ctx| render_diagnostic(ctx.ui_mut(), diagnostic));
                    return;
                }
                g.full(|ctx| {
                    let ui = ctx.ui_mut();
                    let shown_states = live.messages.len();
                    let shown_messages = live
                        .messages
                        .iter()
                        .map(|message| message.anchor)
                        .collect::<std::collections::BTreeSet<_>>()
                        .len();
                    let label = if shown_messages < live.total_messages {
                        format!(
                            "SHOWING {shown_messages} OF {} MESSAGES · {shown_states} STATES · {} CHANNEL{} · {} CONFLICT{}",
                            live.total_messages,
                            live.channel_count,
                            if live.channel_count == 1 { "" } else { "S" },
                            live.conflict_count,
                            if live.conflict_count == 1 { "" } else { "S" },
                        )
                    } else {
                        format!(
                            "{} MESSAGE{} · {} VISIBLE STATE{} · {} CHANNEL{} · {} CONFLICT{}",
                            live.total_messages,
                            if live.total_messages == 1 { "" } else { "S" },
                            shown_states,
                            if shown_states == 1 { "" } else { "S" },
                            live.channel_count,
                            if live.channel_count == 1 { "" } else { "S" },
                            live.conflict_count,
                            if live.conflict_count == 1 { "" } else { "S" },
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
                                egui::RichText::new("\u{1F47E}") // 👾
                                    .size(28.0)
                                    .color(color_muted(ui)),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new("No Discord messages on this branch.")
                                    .monospace()
                                    .small()
                                    .strong()
                                    .color(color_muted(ui)),
                            );
                            ui.add_space(2.0);
                            ui.label(
                                egui::RichText::new(
                                    "run `discord read` to ingest channels visible to the bot.",
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
    live: &DiscordLive,
    now: Option<DateTime<Utc>>,
) {
    let bubble_fill = ui.visuals().window_fill;
    // Header accent = channel's hashed colour so all messages from
    // the same channel visually group.
    let accent = channel_color(msg.channel_id);
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

            // ── Header: guild · channel · time ──
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
                            egui::RichText::new(live.channel_label(msg.channel_id))
                                .monospace()
                                .strong()
                                .color(text_on_accent),
                        );
                        if msg.variant_count > 1 {
                            ui.label(
                                egui::RichText::new(format!(
                                    "CONFLICT {}/{}",
                                    msg.variant_index + 1,
                                    msg.variant_count
                                ))
                                .monospace()
                                .small()
                                .strong()
                                .color(text_on_accent),
                            );
                        }
                        let time = match now {
                            Some(now) => format!(
                                "· {} · {}",
                                format_chat_time(msg.at),
                                age_label(now, msg.at)
                            ),
                            None => format!("· {}", format_chat_time(msg.at)),
                        };
                        ui.label(
                            egui::RichText::new(time)
                                .monospace()
                                .small()
                                .color(text_on_accent),
                        );
                    });

                    // Author chip + content first line.
                    let author_label = msg.author_name.clone();
                    let author_fill = author_color(msg.author_id);
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

            // ── Body: rest of content (when multi-line) + id ──
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
                        egui::RichText::new(format!(
                            "observation {} · message {}",
                            id_hex(msg.id),
                            id_hex(msg.anchor)
                        ))
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
                egui::RichText::new("DISCORD STATE NOT SELECTABLE")
                    .monospace()
                    .small()
                    .strong()
                    .color(color_contrast_warning()),
            );
            ui.label(egui::RichText::new(diagnostic).monospace().small());
        });
}

fn color_contrast_warning() -> egui::Color32 {
    egui::Color32::from_rgb(0xe2, 0x5b, 0x12)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn row(anchor: Id, observation: Id, variant_index: usize, variant_count: usize) -> MessageRow {
        MessageRow {
            id: observation,
            anchor,
            at: Utc.timestamp_opt(1_000, 0).single().unwrap(),
            author_id: id(9),
            author_name: "author".to_owned(),
            channel_id: id(8),
            content: String::new(),
            variant_index,
            variant_count,
        }
    }

    #[test]
    fn message_limit_never_slices_a_conflict_frontier() {
        let anchor = id(1);
        let rows = vec![row(anchor, id(2), 0, 2), row(anchor, id(3), 1, 2)];
        let visible = newest_complete_message_groups(rows, 1);
        assert_eq!(visible.len(), 2);
        assert!(visible.iter().all(|row| row.anchor == anchor));
    }
}
