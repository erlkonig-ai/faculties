//! Read-only GORBIE-embeddable viewer for the `discord` faculty.
//!
//! The widget consumes the same shared semantic selector as the CLI: volatile
//! REST state cannot create cards, exact semantic replays collapse, and every
//! divergent state at a maximal official edit timestamp remains visible.
//!
//! ```ignore
//! let mut panel = DiscordViewer::default();
//! panel.render(ctx, discord_ws);
//! ```

use std::collections::HashMap;

use chrono::{DateTime, Datelike, TimeZone, Timelike, Utc};

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use triblespace::core::id::Id;
use triblespace::core::metadata;
use triblespace::macros::{find, pattern};

use crate::discord as discord_model;
use crate::schemas::discord::discord as discord_attrs;
use crate::widgets::storage::{DatasetRevision, DatasetView};

/// Cap on visible messages. Older messages are still in the
/// collection; the `discord read` CLI is the right tool for full
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
    at: DateTime<Utc>,
    author_id: Id,
    author_name: Option<String>,
    channel_id: Id,
    content: String,
    variant_index: usize,
    variant_count: usize,
}

#[derive(Clone, Debug, Default)]
struct Channel {
    name: Option<String>,
    guild_id: Option<Id>,
}

#[derive(Clone, Debug, Default)]
struct Guild {
    name: Option<String>,
}

struct DiscordLive {
    cached_revision: DatasetRevision,
    messages: Vec<MessageRow>,
    channels: HashMap<Id, Channel>,
    guilds: HashMap<Id, Guild>,
    total_messages: usize,
    channel_count: usize,
    guild_count: usize,
    error: Option<String>,
}

// ── Live snapshot ────────────────────────────────────────────────────

impl DiscordLive {
    fn refresh(dataset: DatasetView<'_>) -> Self {
        match Self::try_refresh(dataset) {
            Ok(live) => live,
            Err(error) => Self {
                cached_revision: dataset.revision,
                messages: Vec::new(),
                channels: HashMap::new(),
                guilds: HashMap::new(),
                total_messages: 0,
                channel_count: 0,
                guild_count: 0,
                error: Some(format!("{error:#}")),
            },
        }
    }

    fn try_refresh(dataset: DatasetView<'_>) -> anyhow::Result<Self> {
        let space = dataset.facts;

        // Channels — read first so messages can look up channel
        // names without an extra per-message find!().
        let mut channels: HashMap<Id, Channel> = HashMap::new();
        for (cid,) in find!(
            (cid: Id,),
            pattern!(space, [{ ?cid @ metadata::tag: &discord_attrs::kind_channel }])
        ) {
            channels.insert(cid, Channel::default());
        }
        let channel_count = channels.len();

        // Use the same stable external-id labels as the CLI.
        for (cid, name) in discord_model::channel_labels(space, dataset.reader)? {
            if let Some(c) = channels.get_mut(&cid) {
                c.name = Some(name);
            }
        }
        // Channel → guild pointer (so chips can show the guild).
        for (cid, gid) in find!(
            (cid: Id, gid: Id),
            pattern!(space, [{ ?cid @ discord_attrs::guild: ?gid }])
        ) {
            if let Some(c) = channels.get_mut(&cid) {
                c.guild_id = Some(gid);
            }
        }

        // Guilds — names only; we don't need to enumerate them
        // exhaustively, the message-loop only references the ones
        // a channel points to.
        let mut guilds: HashMap<Id, Guild> = HashMap::new();
        for (gid,) in find!(
            (gid: Id,),
            pattern!(space, [{ ?gid @ metadata::tag: &discord_attrs::kind_guild }])
        ) {
            guilds.insert(gid, Guild::default());
        }
        let guild_count = guilds.len();
        let guild_name_rows: Vec<(Id, discord_model::TextHandle)> = find!(
            (gid: Id, h: discord_model::TextHandle),
            pattern!(space, [{
                ?gid @
                metadata::tag: &discord_attrs::kind_guild,
                metadata::name: ?h,
            }])
        )
        .collect();
        for (gid, h) in guild_name_rows {
            if let Some(g) = guilds.get_mut(&gid) {
                g.name = discord_model::read_text(dataset.reader, h, "Discord guild name").ok();
            }
        }

        let selected = discord_model::select_messages(space, None, None)?;
        let author_names = discord_model::user_labels(space, dataset.reader)?;
        let total_messages = selected.len();
        let mut messages: Vec<MessageRow> = Vec::with_capacity(selected.len());
        for version in selected {
            let raw = discord_model::read_text(
                dataset.reader,
                version.content,
                "Discord message content",
            )?;
            let author_name = author_names.get(&version.author).cloned();
            messages.push(MessageRow {
                id: version.observation,
                at: ns_to_chrono(discord_model::interval_key(version.created_at)),
                author_id: version.author,
                author_name,
                channel_id: version.channel,
                content: raw,
                variant_index: version.variant_index,
                variant_count: version.variant_count,
            });
        }

        // Newest first, clamp to MAX_MESSAGES.
        messages.sort_by(|a, b| b.at.cmp(&a.at));
        messages.truncate(MAX_MESSAGES);

        Ok(DiscordLive {
            cached_revision: dataset.revision,
            messages,
            channels,
            guilds,
            total_messages,
            channel_count,
            guild_count,
            error: None,
        })
    }

    fn channel_label(&self, cid: Id) -> String {
        match self.channels.get(&cid).and_then(|c| c.name.clone()) {
            Some(n) => format!("#{n}"),
            None => format!("#{}", short_hex(cid)),
        }
    }

    fn guild_label_for(&self, cid: Id) -> Option<String> {
        let gid = self.channels.get(&cid)?.guild_id?;
        let name = self.guilds.get(&gid).and_then(|g| g.name.clone());
        Some(name.unwrap_or_else(|| short_hex(gid)))
    }
}

fn ns_to_chrono(ns: i128) -> DateTime<Utc> {
    let secs = (ns / 1_000_000_000) as i64;
    let nanos = ((ns % 1_000_000_000) as u32).min(999_999_999);
    Utc.timestamp_opt(secs, nanos)
        .single()
        .unwrap_or_else(Utc::now)
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
            if let Some(error) = &live.error {
                ctx.grid(|g| {
                    g.full(|ctx| {
                        let ui = ctx.ui_mut();
                        ui.label(
                            egui::RichText::new(format!("Discord data error: {error}"))
                                .monospace()
                                .small()
                                .color(ui.visuals().error_fg_color),
                        );
                    });
                });
                return;
            }
            let now = Utc::now();

            ctx.grid(|g| {
                g.full(|ctx| {
                    let ui = ctx.ui_mut();
                    let shown = live.messages.len();
                    let label = if shown < live.total_messages {
                        format!(
                            "SHOWING {shown} OF {} MESSAGES · {} CHANNEL{} · {} GUILD{}",
                            live.total_messages,
                            live.channel_count,
                            if live.channel_count == 1 { "" } else { "S" },
                            live.guild_count,
                            if live.guild_count == 1 { "" } else { "S" },
                        )
                    } else {
                        format!(
                            "{shown} MESSAGE{} · {} CHANNEL{} · {} GUILD{}",
                            if shown == 1 { "" } else { "S" },
                            live.channel_count,
                            if live.channel_count == 1 { "" } else { "S" },
                            live.guild_count,
                            if live.guild_count == 1 { "" } else { "S" },
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
                                egui::RichText::new("No Discord messages in this collection.")
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
    now: DateTime<Utc>,
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
                        let cid = msg.channel_id;
                        if let Some(guild) = live.guild_label_for(cid) {
                            ui.label(
                                egui::RichText::new(guild)
                                    .monospace()
                                    .strong()
                                    .small()
                                    .color(text_on_accent),
                            );
                            ui.label(
                                egui::RichText::new("·")
                                    .monospace()
                                    .small()
                                    .color(text_on_accent),
                            );
                        }
                        ui.label(
                            egui::RichText::new(live.channel_label(cid))
                                .monospace()
                                .strong()
                                .color(text_on_accent),
                        );
                        ui.label(
                            egui::RichText::new(format!(
                                "· {} · {}",
                                format_chat_time(msg.at),
                                age_label(now, msg.at)
                            ))
                            .monospace()
                            .small()
                            .color(text_on_accent),
                        );
                    });

                    // Author chip + content first line.
                    let author_label = msg
                        .author_name
                        .clone()
                        .unwrap_or_else(|| short_hex(msg.author_id));
                    let author_fill = author_color(msg.author_id);
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing = egui::vec2(6.0, 2.0);
                        render_author_chip(ui, &author_label, author_fill);
                        if msg.variant_count > 1 {
                            ui.label(
                                egui::RichText::new(format!(
                                    "DIVERGENT {}/{}",
                                    msg.variant_index + 1,
                                    msg.variant_count
                                ))
                                .monospace()
                                .strong()
                                .small()
                                .color(text_on_accent),
                            );
                        }
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
                        egui::RichText::new(id_hex(msg.id))
                            .monospace()
                            .small()
                            .color(body_muted),
                    );
                });
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
