//! Read-only GORBIE-embeddable local-messages panel.
//!
//! Renders the append-only direct messages kept on a pile's
//! `local-messages` branch as a chronological feed: oldest at the top,
//! newest at the bottom. Each message lays out as a sharp-cornered
//! paper-card bubble — sender + recipient chips, body text (with
//! search-match underlines when a notebook-wide search is active),
//! optional read receipts, and a short id footer.
//!
//! The widget holds UI + cached-query state only; the host supplies
//! the local-messages workspace (required) and an optional `relations`
//! workspace at render time.
//!
//! Identity display is resolved against the relations branch (if
//! supplied): `alias → first_name last_name → display_name → 8-char
//! hex prefix`. If relations is absent the widget quietly degrades to
//! the hex-prefix view. Per-person color chips use
//! `GORBIE::themes::colorhash::ral_categorical` keyed on the user id
//! bytes.
//!
//! ```ignore
//! let mut panel = MessagesPanel::default();
//! panel.render(ctx, messages_ws, Some(relations_ws));
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

use crate::schemas::local_messages::{local, KIND_MESSAGE_ID, KIND_READ_ID};
use crate::schemas::relations::{relations as rel, KIND_PERSON_ID};

/// Handle to a long-string blob (message bodies).
type TextHandle = Inline<Handle<LongString>>;

// ── ID / time helpers ────────────────────────────────────────────────

/// Full hex of an Id — used as a fallback label when no friendly name
/// is resolvable from the relations branch.
fn id_hex(id: Id) -> String {
    format!("{id:x}")
}

fn now_tai_ns() -> i128 {
    hifitime::Epoch::now()
        .map(|e| e.to_tai_duration().total_nanoseconds())
        .unwrap_or(0)
}

fn format_age(now_key: i128, maybe_key: Option<i128>) -> String {
    let Some(key) = maybe_key else {
        return "-".to_string();
    };
    let delta_ns = now_key.saturating_sub(key);
    let delta_s = (delta_ns / 1_000_000_000).max(0) as i64;
    if delta_s < 60 {
        format!("{delta_s}s")
    } else if delta_s < 60 * 60 {
        format!("{}m", delta_s / 60)
    } else if delta_s < 24 * 60 * 60 {
        format!("{}h", delta_s / 3600)
    } else {
        format!("{}d", delta_s / 86_400)
    }
}

fn format_age_key(now_key: i128, past_key: i128) -> String {
    format_age(now_key, Some(past_key))
}

/// Absolute timestamp from a TAI ns key. Used for hover tooltips so the
/// compact age chips can still surface precise times on demand.
fn format_timestamp_key(key: i128) -> String {
    let ns = hifitime::Duration::from_total_nanoseconds(key);
    let epoch = hifitime::Epoch::from_tai_duration(ns);
    let (y, m, d, h, min, s, _) = epoch.to_gregorian_utc();
    format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:{s:02} UTC")
}

// ── Color palette (reuses compass.rs conventions) ────────────────────

// Theme-adaptive neutrals (mirror of compass.rs). The accent /
// read / person colors are legible on both themes, but the
// frame / bubble / muted greys need to flip so theme-aware text
// doesn't land dark-on-dark in light mode.

fn color_frame(ui: &egui::Ui) -> egui::Color32 {
    if ui.visuals().dark_mode {
        egui::Color32::from_rgb(0x29, 0x32, 0x36) // RAL 7016
    } else {
        egui::Color32::from_rgb(0xec, 0xec, 0xec)
    }
}

fn color_muted(ui: &egui::Ui) -> egui::Color32 {
    if ui.visuals().dark_mode {
        egui::Color32::from_rgb(0x9a, 0x9a, 0x9a)
    } else {
        egui::Color32::from_rgb(0x6a, 0x6a, 0x6a)
    }
}

fn color_read() -> egui::Color32 {
    // RAL 6017 may green — "read" accent, matches playground diagnostics.
    egui::Color32::from_rgb(0x4a, 0x77, 0x29)
}

/// Deterministic per-person color chip via GORBIE's colorhash palette.
fn person_color(id: Id) -> egui::Color32 {
    colorhash::ral_categorical(id.as_ref())
}

// ── Row structs ──────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct MessageRow {
    id: Id,
    from: Id,
    to: Id,
    body: String,
    /// TAI ns of the message's `metadata::created_at` (sort key).
    created_at: Option<i128>,
    /// Read receipts for this message. Each entry is `(reader, ts_ns)`.
    reads: Vec<(Id, i128)>,
}

impl MessageRow {
    fn sort_key(&self) -> i128 {
        self.created_at.unwrap_or(i128::MIN)
    }

    /// True when `id` has filed a read receipt for this message.
    fn read_by(&self, id: Id) -> bool {
        self.reads.iter().any(|(reader, _)| *reader == id)
    }
}

/// Everything we know about a person for UI purposes.
#[derive(Clone, Debug, Default)]
struct Person {
    alias: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    display_name: Option<String>,
    /// True when the relations entry carries the `operator` affinity —
    /// i.e. this is a human the agents work for, not another zooid.
    /// Messages addressed to an operator form the "inbox" subset.
    is_operator: bool,
}

impl Person {
    /// Display name: alias > first+last > display_name > hex prefix.
    fn display(&self, fallback_id: Id) -> String {
        if let Some(a) = self.alias.as_ref() {
            if !a.trim().is_empty() {
                return a.clone();
            }
        }
        match (self.first_name.as_ref(), self.last_name.as_ref()) {
            (Some(f), Some(l)) if !f.trim().is_empty() && !l.trim().is_empty() => {
                return format!("{f} {l}");
            }
            (Some(f), _) if !f.trim().is_empty() => return f.clone(),
            (_, Some(l)) if !l.trim().is_empty() => return l.clone(),
            _ => {}
        }
        if let Some(d) = self.display_name.as_ref() {
            if !d.trim().is_empty() {
                return d.clone();
            }
        }
        id_hex(fallback_id)
    }
}

// ── Cached message query state ───────────────────────────────────────

/// Cached fact spaces + head markers + resolved people map. Rebuilt
/// whenever the local-messages head advances or the relations head
/// changes.
struct MessagesLive {
    space: TribleSet,
    cached_head: Option<CommitHandle>,
    relations_cached_head: Option<CommitHandle>,
    people: HashMap<Id, Person>,
}

impl MessagesLive {
    /// Refresh cached fact spaces + people map from the provided
    /// workspaces.
    fn refresh(
        ws: &mut Workspace<Pile>,
        relations_ws: Option<&mut Workspace<Pile>>,
    ) -> Self {
        let space = ws
            .checkout(..)
            .map(|co| co.into_facts())
            .unwrap_or_else(|e| {
                eprintln!("[messages] checkout: {e:?}");
                TribleSet::new()
            });
        let cached_head = ws.head();

        let (relations_cached_head, people) = match relations_ws {
            Some(rws) => {
                let head = rws.head();
                let rspace = rws
                    .checkout(..)
                    .map(|co| co.into_facts())
                    .unwrap_or_else(|e| {
                        eprintln!("[messages] relations checkout: {e:?}");
                        TribleSet::new()
                    });
                let people = build_people(&rspace, rws);
                (head, people)
            }
            None => (None, HashMap::new()),
        };

        MessagesLive {
            space,
            cached_head,
            relations_cached_head,
            people,
        }
    }

    fn text(&self, ws: &mut Workspace<Pile>, h: TextHandle) -> String {
        ws.get::<View<str>, LongString>(h)
            .map(|v| {
                let s: &str = v.as_ref();
                s.to_string()
            })
            .unwrap_or_default()
    }

    /// Friendly display name for an Id, falling back to hex prefix.
    fn display_name(&self, id: Id) -> String {
        match self.people.get(&id) {
            Some(p) => p.display(id),
            None => id_hex(id),
        }
    }

    /// Collect every message with its from/to/body/created_at and fold
    /// in the read-receipt events that target it.
    fn messages(&self, ws: &mut Workspace<Pile>) -> Vec<MessageRow> {
        let mut by_id: HashMap<Id, MessageRow> = HashMap::new();

        let rows: Vec<(Id, Id, Id, TextHandle, (i128, i128))> = find!(
            (
                mid: Id,
                from: Id,
                to: Id,
                body: TextHandle,
                ts: (i128, i128)
            ),
            pattern!(&self.space, [{
                ?mid @
                metadata::tag: &KIND_MESSAGE_ID,
                local::from: ?from,
                local::to: ?to,
                local::body: ?body,
                metadata::created_at: ?ts,
            }])
        )
        .collect();

        for (mid, from, to, body_handle, ts) in rows {
            if by_id.contains_key(&mid) {
                continue;
            }
            let body = self.text(ws, body_handle);
            by_id.insert(
                mid,
                MessageRow {
                    id: mid,
                    from,
                    to,
                    body,
                    created_at: Some(ts.0),
                    reads: Vec::new(),
                },
            );
        }

        // Read-receipt pairing.
        let mut latest: HashMap<(Id, Id), i128> = HashMap::new();
        for (mid, reader, ts) in find!(
            (mid: Id, reader: Id, ts: (i128, i128)),
            pattern!(&self.space, [{
                _?event @
                metadata::tag: &KIND_READ_ID,
                local::about_message: ?mid,
                local::reader: ?reader,
                local::read_at: ?ts,
            }])
        ) {
            let key = (mid, reader);
            let entry = latest.entry(key).or_insert(i128::MIN);
            if ts.0 > *entry {
                *entry = ts.0;
            }
        }
        for ((mid, reader), ts) in latest {
            if let Some(row) = by_id.get_mut(&mid) {
                row.reads.push((reader, ts));
            }
        }

        for row in by_id.values_mut() {
            row.reads.sort_by(|a, b| b.1.cmp(&a.1));
        }

        by_id.into_values().collect()
    }

}

/// Build the people map by scanning the relations fact space.
fn build_people(
    relations_space: &TribleSet,
    relations_ws: &mut Workspace<Pile>,
) -> HashMap<Id, Person> {
    let mut people: HashMap<Id, Person> = HashMap::new();

    let person_ids: Vec<Id> = find!(
        pid: Id,
        pattern!(relations_space, [{ ?pid @ metadata::tag: &KIND_PERSON_ID }])
    )
    .collect();
    for pid in &person_ids {
        people.insert(*pid, Person::default());
    }

    let alias_rows: Vec<(Id, String)> = find!(
        (pid: Id, alias: String),
        pattern!(relations_space, [{ ?pid @ rel::alias: ?alias }])
    )
    .collect();
    for (pid, alias) in alias_rows {
        if let Some(p) = people.get_mut(&pid) {
            match p.alias.as_ref() {
                Some(existing) if existing.as_str() <= alias.as_str() => {}
                _ => p.alias = Some(alias),
            }
        }
    }

    let relations_text = |ws: &mut Workspace<Pile>, h: TextHandle| -> Option<String> {
        ws.get::<View<str>, LongString>(h).ok().map(|v| {
            let s: &str = v.as_ref();
            s.to_string()
        })
    };

    let first_rows: Vec<(Id, TextHandle)> = find!(
        (pid: Id, h: TextHandle),
        pattern!(relations_space, [{ ?pid @ rel::first_name: ?h }])
    )
    .collect();
    for (pid, h) in first_rows {
        if people.contains_key(&pid) {
            if let Some(v) = relations_text(relations_ws, h) {
                if let Some(p) = people.get_mut(&pid) {
                    p.first_name.get_or_insert(v);
                }
            }
        }
    }

    let last_rows: Vec<(Id, TextHandle)> = find!(
        (pid: Id, h: TextHandle),
        pattern!(relations_space, [{ ?pid @ rel::last_name: ?h }])
    )
    .collect();
    for (pid, h) in last_rows {
        if people.contains_key(&pid) {
            if let Some(v) = relations_text(relations_ws, h) {
                if let Some(p) = people.get_mut(&pid) {
                    p.last_name.get_or_insert(v);
                }
            }
        }
    }

    let display_rows: Vec<(Id, TextHandle)> = find!(
        (pid: Id, h: TextHandle),
        pattern!(relations_space, [{ ?pid @ rel::display_name: ?h }])
    )
    .collect();
    for (pid, h) in display_rows {
        if people.contains_key(&pid) {
            if let Some(v) = relations_text(relations_ws, h) {
                if let Some(p) = people.get_mut(&pid) {
                    p.display_name.get_or_insert(v);
                }
            }
        }
    }

    // Operator detection — the `operator` affinity marks humans the
    // agents work for. Their inbound messages form the inbox subset.
    for (pid, affinity) in find!(
        (pid: Id, a: String),
        pattern!(relations_space, [{ ?pid @ rel::affinity: ?a }])
    ) {
        if affinity.eq_ignore_ascii_case("operator") {
            if let Some(p) = people.get_mut(&pid) {
                p.is_operator = true;
            }
        }
    }

    people
}

// ── Widget ───────────────────────────────────────────────────────────

/// GORBIE-embeddable local-messages panel with compose, relations
/// identity lookup, scroll-to-bottom on new messages, and automatic
/// read-receipts for inbound messages.
///
/// See the module docs for construction examples.
/// Which subset of the stream to show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamFilter {
    /// Everything — intra-zooid traffic included.
    All,
    /// Only messages addressed to an operator (a relations entry with
    /// the `operator` affinity) — the human's inbox.
    Inbox,
}

pub struct MessagesPanel {
    /// Rebuilt when the messages / relations head changes.
    live: Option<MessagesLive>,
    /// Current stream filter — toggled via the ALL / INBOX chips.
    filter: StreamFilter,
}

impl Default for MessagesPanel {
    fn default() -> Self {
        Self {
            live: None,
            filter: StreamFilter::All,
        }
    }
}

impl MessagesPanel {
    /// New read-only panel.
    pub fn new() -> Self {
        Self::default()
    }

    /// Backwards-compatibility shim: the panel no longer has an
    /// internal scroll area (the notebook's own scroll handles
    /// overflow), so a configured height is a no-op.
    pub fn with_height(self, _height: f32) -> Self {
        self
    }

    /// Render the panel. `ws` must point at the local-messages branch;
    /// `relations_ws` is optional and, when provided, is used for
    /// friendly-name resolution.
    pub fn render(
        &mut self,
        ctx: &mut CardCtx<'_>,
        ws: &mut Workspace<Pile>,
        mut relations_ws: Option<&mut Workspace<Pile>>,
    ) {
        // Refresh cached state if any head advanced.
        let head = ws.head();
        let rhead = relations_ws.as_ref().and_then(|w| w.head());
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => l.cached_head != head || l.relations_cached_head != rhead,
        };
        if need_refresh {
            self.live = Some(MessagesLive::refresh(
                ws,
                relations_ws.as_mut().map(|w| &mut **w),
            ));
        }

        let filter = &mut self.filter;
        ctx.section("Messages", |ctx| {
            let Some(live) = self.live.as_ref() else { return };

            // Pre-materialize everything the UI closure needs.
            let mut messages = live.messages(ws);
            messages.sort_by(|a, b| {
                a.sort_key()
                    .cmp(&b.sort_key())
                    .then_with(|| a.id.cmp(&b.id))
            });

            // Build a name lookup for every id we'll paint.
            let mut names: HashMap<Id, String> = HashMap::new();
            for m in &messages {
                names
                    .entry(m.from)
                    .or_insert_with(|| live.display_name(m.from));
                names.entry(m.to).or_insert_with(|| live.display_name(m.to));
                for (r, _) in &m.reads {
                    names.entry(*r).or_insert_with(|| live.display_name(*r));
                }
            }

            let now = now_tai_ns();
            let count = messages.len();
            let latest_age = messages
                .iter()
                .filter_map(|m| m.created_at)
                .max()
                .map(|k| format_age_key(now, k));

            // Inbox stats: messages addressed to an operator (a human
            // per the relations `operator` affinity); unread = the
            // recipient hasn't filed a read receipt yet.
            let is_inbox = |m: &MessageRow| {
                live.people
                    .get(&m.to)
                    .map_or(false, |p| p.is_operator)
            };
            let inbox_total = messages.iter().filter(|m| is_inbox(m)).count();
            let inbox_unread = messages
                .iter()
                .filter(|m| is_inbox(m) && !m.read_by(m.to))
                .count();
            // No operators in relations → no inbox notion; pin the
            // filter back to ALL so the chip row doesn't strand the
            // view on a permanently-empty subset.
            if inbox_total == 0 {
                *filter = StreamFilter::All;
            }

            // Open a notebook-wide search session — makes the bar
            // appear in the top-right and lets us filter messages by
            // body / from-name / to-name substring.
            let mut search = ctx.search();
            let needle = search.query().to_lowercase();
            let search_active = !needle.is_empty();

            ctx.grid(|g| {
                // Header row: filter chips + count on the left,
                // "LAST <age>" right.
                g.full(|ctx| {
                    let ui = ctx.ui_mut();
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;

                        // Filter chips — only offered when an inbox
                        // notion exists (some relations entry carries
                        // the operator affinity and has mail).
                        if inbox_total > 0 {
                            let all_label = format!("ALL {count}");
                            let inbox_label = if inbox_unread > 0 {
                                format!(
                                    "\u{1F4E5} INBOX {inbox_total} · {inbox_unread} NEW"
                                )
                            } else {
                                format!("\u{1F4E5} INBOX {inbox_total}")
                            };
                            if render_filter_chip(
                                ui,
                                &all_label,
                                *filter == StreamFilter::All,
                            ) {
                                *filter = StreamFilter::All;
                            }
                            if render_filter_chip(
                                ui,
                                &inbox_label,
                                *filter == StreamFilter::Inbox,
                            ) {
                                *filter = StreamFilter::Inbox;
                            }
                        } else {
                            ui.label(
                                egui::RichText::new(format!("{count} MESSAGES"))
                                    .monospace()
                                    .strong()
                                    .small()
                                    .color(color_muted(ui)),
                            );
                        }

                        if let Some(age) = latest_age.as_ref() {
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "LAST {}",
                                            age.to_uppercase()
                                        ))
                                        .monospace()
                                        .small()
                                        .strong()
                                        .color(color_muted(ui)),
                                    );
                                },
                            );
                        }
                    });
                });

                if messages.is_empty() {
                    g.full(|ctx| {
                        render_messages_empty_state(
                            ctx.ui_mut(),
                            "No messages yet.",
                            None,
                        );
                    });
                    return;
                }

                // One grid cell per message; the notebook's own scroll
                // area handles overflow. No nested ScrollArea + no
                // arrival/stickiness state machine — the viewer is
                // read-only, so the user just scrolls the notebook.
                for msg in &messages {
                    let msg_is_inbox = is_inbox(msg);
                    if *filter == StreamFilter::Inbox && !msg_is_inbox {
                        continue;
                    }
                    if search_active && !message_matches_search(msg, &names, &needle) {
                        continue;
                    }
                    let match_info = if search_active {
                        Some(search.report(egui::Id::new(("messages_match", msg.id))))
                    } else {
                        None
                    };
                    let is_focused =
                        match_info.as_ref().map_or(false, |i| i.is_focused);
                    let inbox_unread_msg = msg_is_inbox && !msg.read_by(msg.to);
                    g.full(|ctx| {
                        let ui = ctx.ui_mut();
                        let pre_y = ui.cursor().min.y;
                        render_message(
                            ui,
                            msg,
                            now,
                            &names,
                            &needle,
                            is_focused,
                            msg_is_inbox,
                            inbox_unread_msg,
                        );
                        if let Some(info) = match_info {
                            if info.should_scroll_to {
                                let post_y = ui.cursor().min.y;
                                let msg_rect = egui::Rect::from_min_max(
                                    egui::pos2(ui.min_rect().left(), pre_y),
                                    egui::pos2(ui.min_rect().right(), post_y),
                                );
                                ui.scroll_to_rect(
                                    msg_rect,
                                    Some(egui::Align::Center),
                                );
                            }
                        }
                    });
                }
            });

            // Read-only viewer — no writes to apply post-render.
            let _ = ws;
        });
    }
}

// ── Row rendering ────────────────────────────────────────────────────

/// True if the message's body, sender display name, or recipient
/// display name contains the (lowercased) needle.
fn message_matches_search(
    msg: &MessageRow,
    names: &HashMap<Id, String>,
    needle: &str,
) -> bool {
    if msg.body.to_lowercase().contains(needle) {
        return true;
    }
    for id in [msg.from, msg.to] {
        if let Some(name) = names.get(&id) {
            if name.to_lowercase().contains(needle) {
                return true;
            }
        }
    }
    false
}

/// Toggle chip for the stream filter. Active chip fills with RAL 1003
/// signal yellow; inactive renders on the frame colour. Returns true
/// on click.
fn render_filter_chip(ui: &mut egui::Ui, label: &str, active: bool) -> bool {
    let (fill, text) = if active {
        let fill = egui::Color32::from_rgb(0xf7, 0xba, 0x0b); // RAL 1003
        (fill, colorhash::text_color_on(fill))
    } else {
        (color_frame(ui), color_muted(ui))
    };
    let resp = ui.add(
        egui::Button::new(
            egui::RichText::new(label)
                .monospace()
                .small()
                .strong()
                .color(text),
        )
        .fill(fill)
        .corner_radius(egui::CornerRadius::ZERO)
        .min_size(egui::vec2(0.0, 18.0)),
    );
    resp.clicked()
}

/// Small filled badge used for 📥 INBOX / NEW markers in the bubble
/// header row.
fn render_badge(ui: &mut egui::Ui, label: &str, fill: egui::Color32) {
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

#[allow(clippy::too_many_arguments)]
fn render_message(
    ui: &mut egui::Ui,
    msg: &MessageRow,
    now: i128,
    names: &HashMap<Id, String>,
    // Lowercased search needle ("" = no search).
    search_needle: &str,
    // True when this bubble is the bar's currently-focused match;
    // makes every needle occurrence inside render with the double
    // underline (same emphasis the typst widget uses).
    focused: bool,
    // True when the recipient is an operator (human) — gets an 📥
    // badge so operator-directed mail stands out in the ALL stream.
    is_inbox: bool,
    // True when an inbox message has no read receipt from its
    // recipient yet — gets a NEW badge in RAL 1003.
    is_unread: bool,
) {
    let bubble_fill = ui.visuals().window_fill;
    let from_color = person_color(msg.from);
    let to_color = person_color(msg.to);
    // Sender/recipient stripes flank the bubble (compass-card idiom).
    // Width 18 fits a 9-pt monospace name rotated 90°. Inner content
    // is inset on both sides to leave room.
    const STRIPE_WIDTH: f32 = 18.0;
    const STRIPE_GAP: f32 = 8.0;
    const STROKE_INSET: f32 = 1.0;

    ui.vertical(|ui| {
    let inner_margin = egui::Margin {
        left: (STROKE_INSET + STRIPE_WIDTH + STRIPE_GAP) as i8,
        right: (STROKE_INSET + STRIPE_WIDTH + STRIPE_GAP) as i8,
        top: 6,
        bottom: 6,
    };
    let frame_resp = egui::Frame::NONE
        .fill(bubble_fill)
        .stroke(egui::Stroke::new(STROKE_INSET, color_frame(ui)))
        // Hard offset shadow + sharp corners: same paper-card idiom
        // compass goals use, giving the bubble physical "lift" instead
        // of a backlit LCD look.
        .shadow(egui::epaint::Shadow {
            offset: [2, 2],
            blur: 0,
            spread: 0,
            color: egui::Color32::from_black_alpha(48),
        })
        .corner_radius(egui::CornerRadius::ZERO)
        .inner_margin(inner_margin)
        .show(ui, |ui| {
            // Header row: just the age, right-aligned. Sender/recipient
            // are conveyed via the colored side stripes painted after
            // the Frame returns — no need for in-header chips.
            //
            // `Align::Min` on the cross-axis (top) so the layout
            // doesn't try to fill the cell's available_rect.height —
            // with frame-delayed cell sizing, that fill would feed
            // back into next frame's larger cell, growing forever.
            ui.with_layout(
                egui::Layout::right_to_left(egui::Align::Min),
                |ui| {
                    let (age, hover) = match msg.created_at {
                        Some(k) => {
                            (format_age_key(now, k), Some(format_timestamp_key(k)))
                        }
                        None => ("-".to_string(), None),
                    };
                    let resp = ui.label(
                        egui::RichText::new(age)
                            .monospace()
                            .small()
                            .color(color_muted(ui)),
                    );
                    if let Some(h) = hover {
                        resp.on_hover_text(h);
                    }

                    // Inbox badges flow in from the LEFT edge of this
                    // right-to-left row, i.e. they render before the
                    // age. NEW (RAL 1003) only while the operator
                    // hasn't read-receipted; 📥 marks operator mail
                    // permanently so it stands out in the ALL stream.
                    ui.with_layout(
                        egui::Layout::left_to_right(egui::Align::Min),
                        |ui| {
                            ui.spacing_mut().item_spacing.x = 4.0;
                            if is_inbox {
                                render_badge(
                                    ui,
                                    "\u{1F4E5} INBOX",
                                    egui::Color32::from_rgb(0x23, 0x7f, 0x52), // RAL 6032
                                );
                            }
                            if is_unread {
                                render_badge(
                                    ui,
                                    "NEW",
                                    egui::Color32::from_rgb(0xf7, 0xba, 0x0b), // RAL 1003
                                );
                            }
                        },
                    );
                },
            );

            ui.add_space(2.0);

            // Body. When a search is active, occurrences of the needle
            // are underlined inline; the bar's focused match gets a
            // second underline overlay via `highlight_label`.
            let base = egui::TextFormat {
                font_id: egui::TextStyle::Body.resolve(ui.style()),
                color: ui.visuals().text_color(),
                ..Default::default()
            };
            GORBIE::search::highlight_label(
                ui,
                &msg.body,
                search_needle,
                base,
                focused,
            );

            // Read receipts — compact "✓✓ NameA · NameB · 2h" line in
            // the may-green accent. Newest receipt's age is used as the
            // overall age; individual ages show on hover.
            if !msg.reads.is_empty() {
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    ui.label(
                        egui::RichText::new("\u{2713}\u{2713}")
                            .small()
                            .color(color_read()),
                    );
                    let mut first = true;
                    for (reader, ts) in &msg.reads {
                        if !first {
                            ui.label(
                                egui::RichText::new("\u{00b7}")
                                    .small()
                                    .color(color_muted(ui)),
                            );
                        }
                        first = false;
                        let name = names
                            .get(reader)
                            .cloned()
                            .unwrap_or_else(|| id_hex(*reader));
                        // Tint each reader name with its own person
                        // color so the reader list matches the
                        // sender/recipient chips above.
                        let response = ui.label(
                            egui::RichText::new(name)
                                .small()
                                .color(person_color(*reader)),
                        );
                        response.on_hover_text(format!(
                            "read {} · {}",
                            format_age_key(now, *ts),
                            format_timestamp_key(*ts),
                        ));
                    }
                    // Newest-reader age as a trailing muted suffix.
                    if let Some((_, newest_ts)) =
                        msg.reads.iter().max_by_key(|(_, t)| *t)
                    {
                        ui.label(
                            egui::RichText::new(format!(
                                "\u{00b7} {}",
                                format_age_key(now, *newest_ts)
                            ))
                            .small()
                            .color(color_muted(ui)),
                        );
                    }
                });
            }

            // Short id footer.
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(id_hex(msg.id))
                        .monospace()
                        .small()
                        .color(color_muted(ui)),
                );
            });
        });

    // ── Sender / recipient stripes (compass-card idiom) ─────────────
    //
    // After the Frame has measured + painted, lay two colored stripes
    // along the bubble's left and right edges (inset by the stroke so
    // the 1px outline draws around them). Each stripe carries the
    // person's monospace name rotated 90° — sender top-down on the
    // left, recipient bottom-up on the right — so the bubble reads
    // like an envelope: FROM ➝ TO without any in-body chips eating
    // the header.
    let outer = frame_resp.response.rect;
    let from_name = names
        .get(&msg.from)
        .cloned()
        .unwrap_or_else(|| id_hex(msg.from));
    let to_name = names
        .get(&msg.to)
        .cloned()
        .unwrap_or_else(|| id_hex(msg.to));
    paint_party_stripe(
        ui.painter(),
        outer,
        StripeSide::Left,
        from_color,
        &from_name.to_uppercase(),
    );
    paint_party_stripe(
        ui.painter(),
        outer,
        StripeSide::Right,
        to_color,
        &to_name.to_uppercase(),
    );
    });
}

#[derive(Clone, Copy)]
enum StripeSide {
    Left,
    Right,
}

/// Paint a compass-style colored stripe along one vertical edge of
/// `outer`, with `label` rendered as monospace rotated 90°. The text
/// is skipped when the stripe is too short to hold the glyphs (avoids
/// overflowing into the bubble body on one-line messages).
fn paint_party_stripe(
    painter: &egui::Painter,
    outer: egui::Rect,
    side: StripeSide,
    color: egui::Color32,
    label: &str,
) {
    const STRIPE_WIDTH: f32 = 18.0;
    const STROKE_INSET: f32 = 1.0;
    let stripe_min = match side {
        StripeSide::Left => outer.min + egui::vec2(STROKE_INSET, STROKE_INSET),
        StripeSide::Right => egui::pos2(
            outer.right() - STROKE_INSET - STRIPE_WIDTH,
            outer.top() + STROKE_INSET,
        ),
    };
    let stripe_rect = egui::Rect::from_min_size(
        stripe_min,
        egui::vec2(STRIPE_WIDTH, outer.height() - 2.0 * STROKE_INSET),
    );
    painter.rect_filled(stripe_rect, egui::CornerRadius::ZERO, color);

    let font = egui::FontId::monospace(9.0);
    let text_color = colorhash::text_color_on(color);
    let galley = painter.layout_no_wrap(label.to_string(), font, text_color);
    // Need height for the glyphs + a little breathing room.
    if galley.size().x + 6.0 > stripe_rect.height() {
        return;
    }
    let gh = galley.size().y;
    let mut text_shape = match side {
        StripeSide::Left => {
            // 90° clockwise rotation: text reads top-to-bottom. egui's
            // `TextShape::angle = +π/2` rotates around `pos` such that
            // the galley extends LEFT and DOWN from `pos`. So `pos`
            // sits on the right edge of where the text should appear.
            let pos = egui::pos2(
                stripe_rect.left() + (STRIPE_WIDTH + gh) * 0.5,
                stripe_rect.top() + 5.0,
            );
            let mut s = egui::epaint::TextShape::new(pos, galley, text_color);
            s.angle = std::f32::consts::FRAC_PI_2;
            s
        }
        StripeSide::Right => {
            // 90° counter-clockwise (bottom-to-top read) so the
            // recipient name visually faces the sender across the
            // bubble. `angle = -π/2` rotates around `pos` such that
            // the galley extends RIGHT and UP — so `pos` sits at the
            // left edge of where the rotated text should appear.
            let pos = egui::pos2(
                stripe_rect.left() + (STRIPE_WIDTH - gh) * 0.5,
                stripe_rect.bottom() - 5.0,
            );
            let mut s = egui::epaint::TextShape::new(pos, galley, text_color);
            s.angle = -std::f32::consts::FRAC_PI_2;
            s
        }
    };
    text_shape.fallback_color = text_color;
    painter.add(text_shape);
}

/// Centered empty-state block with an envelope glyph, a headline
/// message, and an optional muted sub-line. Used whenever the
/// messages panel has nothing to show.
fn render_messages_empty_state(ui: &mut egui::Ui, headline: &str, hint: Option<&str>) {
    ui.add_space(24.0);
    ui.vertical_centered(|ui| {
        ui.label(
            egui::RichText::new("\u{2709}")
                .size(32.0)
                .color(color_muted(ui)),
        );
        ui.add_space(6.0);
        ui.label(
            egui::RichText::new(headline)
                .monospace()
                .small()
                .strong()
                .color(color_muted(ui)),
        );
        if let Some(h) = hint {
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(h)
                    .small()
                    .color(color_muted(ui)),
            );
        }
    });
    ui.add_space(24.0);
}

