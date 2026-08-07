//! Read-only GORBIE-embeddable viewer for the `teams` faculty.
//!
//! Microsoft Teams chat messages on disk use the protocol-agnostic
//! `archive::kind_message` tag plus the teams-specific `teams::chat`
//! join. This widget renders the most recent N messages as a
//! chronological feed, each card identifying its chat + author.
//!
//! ```ignore
//! let mut panel = TeamsViewer::default();
//! panel.render(ctx, teams_ws);
//! ```

use std::collections::HashMap;

use chrono::{DateTime, Datelike, TimeZone, Timelike, Utc};

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::Inline;
use triblespace::core::metadata;
use triblespace::core::repo::BlobStoreGet;
use triblespace::macros::{find, pattern};
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::View;

use crate::schemas::archive::archive as archive_attrs;
use crate::schemas::teams::teams as teams_attrs;
use crate::widgets::storage::{DatasetRevision, DatasetView};

type TextHandle = Inline<Handle<LongString>>;

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
    at: DateTime<Utc>,
    author_id: Option<Id>,
    author_name: Option<String>,
    chat_id: Option<Id>,
    content: String,
}

#[derive(Clone, Debug, Default)]
struct Chat {
    name: Option<String>,
}

struct TeamsLive {
    cached_revision: DatasetRevision,
    messages: Vec<MessageRow>,
    chats: HashMap<Id, Chat>,
    total_messages: usize,
    chat_count: usize,
}

// ── Live snapshot ────────────────────────────────────────────────────

impl TeamsLive {
    fn refresh(dataset: DatasetView<'_>) -> Self {
        let space = dataset.facts;

        let mut chats: HashMap<Id, Chat> = HashMap::new();
        for (cid,) in find!(
            (cid: Id,),
            pattern!(space, [{ ?cid @ metadata::tag: &teams_attrs::kind_chat }])
        ) {
            chats.insert(cid, Chat::default());
        }
        let chat_count = chats.len();

        // Chat names — chats often don't have metadata::name set
        // (Graph API doesn't surface a name for 1:1 chats), but we
        // still resolve when present.
        let chat_name_rows: Vec<(Id, TextHandle)> = find!(
            (cid: Id, h: TextHandle),
            pattern!(space, [{
                ?cid @
                metadata::tag: &teams_attrs::kind_chat,
                metadata::name: ?h,
            }])
        )
        .collect();
        for (cid, h) in chat_name_rows {
            if let Some(c) = chats.get_mut(&cid) {
                c.name = read_text(dataset, h);
            }
        }

        // Messages: archive::kind_message + teams::chat. The join
        // is what makes a message a Teams message vs. a discord
        // message vs. an archived ChatGPT export — all three share
        // archive::kind_message.
        let msg_rows: Vec<(Id, Id, TextHandle, (i128, i128))> = find!(
            (mid: Id, cid: Id, content: TextHandle, ts: (i128, i128)),
            pattern!(space, [{
                ?mid @
                metadata::tag: &archive_attrs::kind_message,
                teams_attrs::chat: ?cid,
                archive_attrs::content: ?content,
                metadata::created_at: ?ts,
            }])
        )
        .collect();

        let author_rows: HashMap<Id, Id> = find!(
            (mid: Id, aid: Id),
            pattern!(space, [{ ?mid @ archive_attrs::author: ?aid }])
        )
        .collect();
        let author_name_rows: Vec<(Id, TextHandle)> = find!(
            (aid: Id, h: TextHandle),
            pattern!(space, [{ ?aid @ archive_attrs::author_name: ?h }])
        )
        .collect();
        let mut author_names: HashMap<Id, String> = HashMap::new();
        for (aid, h) in author_name_rows {
            if let Some(name) = read_text(dataset, h) {
                author_names.insert(aid, name);
            }
        }

        let total_messages = msg_rows.len();
        let mut messages: Vec<MessageRow> = Vec::with_capacity(msg_rows.len());
        for (mid, cid, content_h, ts) in msg_rows {
            let raw = read_text(dataset, content_h).unwrap_or_default();
            let content = strip_html(&raw);
            let author_id = author_rows.get(&mid).copied();
            let author_name = author_id.and_then(|aid| author_names.get(&aid).cloned());
            messages.push(MessageRow {
                id: mid,
                at: ns_to_chrono(ts.0),
                author_id,
                author_name,
                chat_id: Some(cid),
                content,
            });
        }

        messages.sort_by(|a, b| b.at.cmp(&a.at));
        messages.truncate(MAX_MESSAGES);

        TeamsLive {
            cached_revision: dataset.revision,
            messages,
            chats,
            total_messages,
            chat_count,
        }
    }

    fn chat_label(&self, cid: Id) -> String {
        match self.chats.get(&cid).and_then(|c| c.name.clone()) {
            Some(n) => n,
            None => format!("chat:{}", short_hex(cid)),
        }
    }
}

fn read_text(dataset: DatasetView<'_>, h: TextHandle) -> Option<String> {
    dataset
        .reader
        .get::<View<str>, LongString>(h)
        .ok()
        .map(|v| {
            let s: &str = v.as_ref();
            s.to_string()
        })
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
            let now = Utc::now();

            ctx.grid(|g| {
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

fn render_message_card(ui: &mut egui::Ui, msg: &MessageRow, live: &TeamsLive, now: DateTime<Utc>) {
    let bubble_fill = ui.visuals().window_fill;
    let accent = msg
        .chat_id
        .map(chat_color)
        .unwrap_or_else(|| egui::Color32::from_gray(120));
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
                        if let Some(cid) = msg.chat_id {
                            ui.label(
                                egui::RichText::new(live.chat_label(cid))
                                    .monospace()
                                    .strong()
                                    .color(text_on_accent),
                            );
                        }
                        ui.label(
                            egui::RichText::new(format!(
                                "· {} · {}",
                                format_chat_time(msg.at),
                                age_label(now, msg.at),
                            ))
                            .monospace()
                            .small()
                            .color(text_on_accent),
                        );
                    });

                    let author_label = msg.author_name.clone().unwrap_or_else(|| {
                        msg.author_id
                            .map(short_hex)
                            .unwrap_or_else(|| "?".to_string())
                    });
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
