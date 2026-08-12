//! Read-only GORBIE-embeddable message panel.
//!
//! Renders the canonical immutable envelopes in a Message collection as a
//! chronological feed: oldest at the top,
//! newest at the bottom. Each message lays out as a sharp-cornered
//! paper-card bubble — sender + recipient chips, body text (with
//! search-match underlines when a notebook-wide search is active),
//! optional read receipts, and a short id footer.
//!
//! The widget holds UI + cached-query state only; the host supplies
//! the message dataset (required) and an optional `relations`
//! dataset at render time.
//!
//! Identity display is resolved against the Relations collection (if
//! supplied): `alias → first_name last_name → display_name → 8-char
//! hex prefix`. If relations is absent the widget quietly degrades to
//! the hex-prefix view. Per-person color chips use
//! `GORBIE::themes::colorhash::ral_categorical` keyed on the user id
//! bytes.
//!
//! ```ignore
//! let mut panel = MessagesPanel::default();
//! panel.render(ctx, messages_view, Some(relations_view));
//! ```

use std::collections::HashMap;

use triblespace::core::id::Id;
use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use crate::message as message_model;
use crate::relations::{self, Head, ProfileInput, ProfileView};
use crate::widgets::storage::{DatasetRevision, DatasetView};

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
    /// Canonical read markers and every additive observation attached to them.
    reads: Vec<ReadReceipt>,
    /// At least one current operator is a canonical inbox recipient.
    is_inbox: bool,
    /// At least one eligible operator has no equivalent canonical read marker.
    is_unread: bool,
}

impl MessageRow {
    fn sort_key(&self) -> i128 {
        self.created_at.unwrap_or(i128::MIN)
    }
}

#[derive(Clone, Debug)]
struct ReadReceipt {
    reader: Id,
    observations: Vec<i128>,
}

/// Everything we know about a person for UI purposes.
#[derive(Clone, Debug, Default)]
struct Person {
    alias: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    display_name: Option<String>,
    /// True when the relations entry carries the `operator` affinity —
    /// i.e. this is a human the agents work for, not another agent.
    /// Messages addressed to an operator form the "inbox" subset.
    is_operator: bool,
}

impl Person {
    fn from_profile(profile: ProfileInput) -> Self {
        Self {
            alias: Some(profile.label),
            first_name: profile.first_name,
            last_name: profile.last_name,
            display_name: profile.display_name,
            is_operator: profile
                .affinities
                .iter()
                .any(|affinity| affinity.eq_ignore_ascii_case("operator")),
        }
    }

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

/// Cached canonical projections + revision markers + resolved people map.
/// Rebuilt whenever the Message or Relations dataset revision changes.
struct MessagesLive {
    cached_revision: DatasetRevision,
    relations_cached_revision: Option<DatasetRevision>,
    people: HashMap<Id, Person>,
    messages: Vec<MessageRow>,
    diagnostics: Vec<String>,
}

impl MessagesLive {
    /// Refresh canonical Message/Relations projections from the provided
    /// dataset views.
    fn refresh(view: DatasetView<'_>, relations: Option<DatasetView<'_>>) -> Self {
        let (relations_cached_revision, people, mut diagnostics) = match relations {
            Some(relations) => {
                let (people, diagnostics) = build_people(relations);
                (Some(relations.revision), people, diagnostics)
            }
            None => (None, HashMap::new(), Vec::new()),
        };
        let (messages, message_diagnostics) = collect_messages(view, relations, &people);
        diagnostics.extend(message_diagnostics);

        MessagesLive {
            cached_revision: view.revision,
            relations_cached_revision,
            people,
            messages,
            diagnostics,
        }
    }

    /// Friendly display name for an Id, falling back to hex prefix.
    fn display_name(&self, id: Id) -> String {
        match self.people.get(&id) {
            Some(p) => p.display(id),
            None => id_hex(id),
        }
    }
}

fn build_people(relations_view: DatasetView<'_>) -> (HashMap<Id, Person>, Vec<String>) {
    let mut people = HashMap::new();
    let mut diagnostics = Vec::new();
    for (person, view) in
        relations::person_profile_views(relations_view.reader, relations_view.facts)
    {
        match view {
            ProfileView::Current { value, .. } => {
                people.insert(person, Person::from_profile(value));
            }
            ProfileView::Forked(heads) => diagnostics.push(format!(
                "Relations profile {person:x} is forked across {}",
                heads
                    .iter()
                    .map(|id| format!("{id:x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            ProfileView::Invalid(error) => {
                diagnostics.push(format!("Relations profile {person:x} is invalid: {error}"));
            }
        }

        match relations::lifecycle_head(relations_view.facts, person) {
            Ok(Head::Unique(snapshot)) => {
                if let Err(error) = relations::lifecycle_snapshot(relations_view.facts, snapshot) {
                    diagnostics.push(format!(
                        "Relations lifecycle {person:x} is invalid: {error}"
                    ));
                }
            }
            Ok(Head::Forked(heads)) => diagnostics.push(format!(
                "Relations lifecycle {person:x} is forked across {}",
                heads
                    .iter()
                    .map(|id| format!("{id:x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            Ok(Head::Missing) => diagnostics.push(format!(
                "Relations person {person:x} has no lifecycle snapshot"
            )),
            Err(error) => diagnostics.push(format!(
                "Relations lifecycle {person:x} is invalid: {error}"
            )),
        }
    }
    (people, diagnostics)
}

fn collect_messages(
    view: DatasetView<'_>,
    relations_view: Option<DatasetView<'_>>,
    people: &HashMap<Id, Person>,
) -> (Vec<MessageRow>, Vec<String>) {
    let mut diagnostics = Vec::new();
    let rows = match message_model::load_message_rows(view.facts) {
        Ok(rows) => rows,
        Err(error) => {
            return (
                Vec::new(),
                vec![format!("Messages catalog is invalid: {error}")],
            );
        }
    };
    let domain_rows: HashMap<Id, message_model::MessageRow> =
        rows.iter().map(|row| (row.id, *row)).collect();

    let mut messages: HashMap<Id, MessageRow> = rows
        .into_iter()
        .map(|row| {
            let body = match message_model::read_body(view.reader, row.body) {
                Ok(body) => body,
                Err(error) => {
                    diagnostics.push(format!("Message {:x} body is unavailable: {error}", row.id));
                    "⚠ body unavailable".to_owned()
                }
            };
            let created_at = match row.created_at.try_from_inline::<(i128, i128)>() {
                Ok((start, _)) => Some(start),
                Err(error) => {
                    diagnostics.push(format!(
                        "Message {:x} has an invalid creation interval: {error:?}",
                        row.id
                    ));
                    None
                }
            };
            (
                row.id,
                MessageRow {
                    id: row.id,
                    from: row.from,
                    to: row.to,
                    body,
                    created_at,
                    reads: Vec::new(),
                    is_inbox: false,
                    is_unread: false,
                },
            )
        })
        .collect();

    let mut domain_reads = Vec::new();
    match message_model::load_read_receipts(view.facts) {
        Ok(receipts) => {
            for receipt in receipts {
                let read = receipt.marker;
                domain_reads.push(read);
                let mut observations = Vec::new();
                for observed_at in receipt.observed_at {
                    match observed_at.try_from_inline::<(i128, i128)>() {
                        Ok((start, _)) => observations.push(start),
                        Err(error) => diagnostics.push(format!(
                            "Read marker {:x} has an invalid observation: {error:?}",
                            read.id
                        )),
                    }
                }
                observations.sort_unstable();
                observations.dedup();
                match messages.get_mut(&read.message) {
                    Some(message) => message.reads.push(ReadReceipt {
                        reader: read.reader,
                        observations,
                    }),
                    None => diagnostics.push(format!(
                        "Read marker {:x} names absent message {:x}",
                        read.id, read.message
                    )),
                }
            }
        }
        Err(error) => diagnostics.push(format!("Message read catalog is invalid: {error}")),
    }

    if let Some(relations_view) = relations_view {
        match relations::IdentityComponents::from_facts(relations_view.facts) {
            Ok(identities) => {
                let operators: Vec<Id> = people
                    .iter()
                    .filter_map(|(id, person)| person.is_operator.then_some(*id))
                    .collect();
                for message in messages.values_mut() {
                    let domain = domain_rows
                        .get(&message.id)
                        .expect("display message came from the canonical domain rows");
                    let mut eligible = Vec::new();
                    for operator in &operators {
                        match message_model::is_inbox_message(
                            domain,
                            *operator,
                            relations_view.facts,
                            &identities,
                        ) {
                            Ok(true) => eligible.push(*operator),
                            Ok(false) => {}
                            Err(error) => diagnostics.push(format!(
                                "Message {:x} inbox relation for operator {operator:x} is unsettled: {error}",
                                message.id
                            )),
                        }
                    }
                    message.is_inbox = !eligible.is_empty();
                    for operator in eligible {
                        match message_model::is_read_by(
                            &domain_reads,
                            message.id,
                            operator,
                            &identities,
                        ) {
                            Ok(false) => message.is_unread = true,
                            Ok(true) => {}
                            Err(error) => diagnostics.push(format!(
                                "Message {:x} read state for operator {operator:x} is unsettled: {error}",
                                message.id
                            )),
                        }
                    }
                }
            }
            Err(error) => diagnostics.push(format!(
                "Relations identity catalog cannot classify the inbox: {error}"
            )),
        }
    }

    for message in messages.values_mut() {
        message.reads.sort_by_key(|read| read.reader);
    }
    let mut messages: Vec<_> = messages.into_values().collect();
    messages.sort_by(|left, right| {
        left.sort_key()
            .cmp(&right.sort_key())
            .then_with(|| left.id.cmp(&right.id))
    });
    (messages, diagnostics)
}

// ── Widget ───────────────────────────────────────────────────────────

/// GORBIE-embeddable message panel with compose, relations
/// identity lookup, scroll-to-bottom on new messages, and automatic
/// read-receipts for inbound messages.
///
/// See the module docs for construction examples.
/// Which subset of the stream to show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamFilter {
    /// Everything — agent-to-agent traffic included.
    All,
    /// Only messages addressed to an operator (a relations entry with
    /// the `operator` affinity) — the human's inbox.
    Inbox,
}

pub struct MessagesPanel {
    /// Rebuilt when the messages / relations revision changes.
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

    /// Render the panel. `view` is the messages dataset;
    /// `relations` is optional and, when provided, is used for
    /// friendly-name resolution.
    pub fn render(
        &mut self,
        ctx: &mut CardCtx<'_>,
        view: DatasetView<'_>,
        relations: Option<DatasetView<'_>>,
    ) {
        // Refresh cached state if either logical dataset changed.
        let revision = view.revision;
        let relations_revision = relations.map(|view| view.revision);
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => {
                l.cached_revision != revision || l.relations_cached_revision != relations_revision
            }
        };
        if need_refresh {
            self.live = Some(MessagesLive::refresh(view, relations));
        }

        let filter = &mut self.filter;
        ctx.section("Messages", |ctx| {
            let Some(live) = self.live.as_ref() else {
                return;
            };

            // Pre-materialize everything the UI closure needs.
            let messages = live.messages.clone();

            // Build a name lookup for every id we'll paint.
            let mut names: HashMap<Id, String> = HashMap::new();
            for m in &messages {
                names
                    .entry(m.from)
                    .or_insert_with(|| live.display_name(m.from));
                names.entry(m.to).or_insert_with(|| live.display_name(m.to));
                for read in &m.reads {
                    names
                        .entry(read.reader)
                        .or_insert_with(|| live.display_name(read.reader));
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
            let inbox_total = messages.iter().filter(|m| m.is_inbox).count();
            let inbox_unread = messages
                .iter()
                .filter(|m| m.is_inbox && m.is_unread)
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
                for diagnostic in &live.diagnostics {
                    g.full(|ctx| render_diagnostic(ctx.ui_mut(), diagnostic));
                }

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
                                format!("\u{1F4E5} INBOX {inbox_total} · {inbox_unread} NEW")
                            } else {
                                format!("\u{1F4E5} INBOX {inbox_total}")
                            };
                            if render_filter_chip(ui, &all_label, *filter == StreamFilter::All) {
                                *filter = StreamFilter::All;
                            }
                            if render_filter_chip(ui, &inbox_label, *filter == StreamFilter::Inbox)
                            {
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
                                        egui::RichText::new(format!("LAST {}", age.to_uppercase()))
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
                        render_messages_empty_state(ctx.ui_mut(), "No messages yet.", None);
                    });
                    return;
                }

                // One grid cell per message; the notebook's own scroll
                // area handles overflow. No nested ScrollArea + no
                // arrival/stickiness state machine — the viewer is
                // read-only, so the user just scrolls the notebook.
                for msg in &messages {
                    let msg_is_inbox = msg.is_inbox;
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
                    let is_focused = match_info.as_ref().map_or(false, |i| i.is_focused);
                    let inbox_unread_msg = msg.is_unread;
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
                                ui.scroll_to_rect(msg_rect, Some(egui::Align::Center));
                            }
                        }
                    });
                }
            });
        });
    }
}

// ── Row rendering ────────────────────────────────────────────────────

/// True if the message's body, sender display name, or recipient
/// display name contains the (lowercased) needle.
fn message_matches_search(msg: &MessageRow, names: &HashMap<Id, String>, needle: &str) -> bool {
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
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                    let (age, hover) = match msg.created_at {
                        Some(k) => (format_age_key(now, k), Some(format_timestamp_key(k))),
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
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Min), |ui| {
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
                    });
                });

                ui.add_space(2.0);

                // Body. When a search is active, occurrences of the needle
                // are underlined inline; the bar's focused match gets a
                // second underline overlay via `highlight_label`.
                let base = egui::TextFormat {
                    font_id: egui::TextStyle::Body.resolve(ui.style()),
                    color: ui.visuals().text_color(),
                    ..Default::default()
                };
                GORBIE::search::highlight_label(ui, &msg.body, search_needle, base, focused);

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
                        for read in &msg.reads {
                            if !first {
                                ui.label(
                                    egui::RichText::new("\u{00b7}")
                                        .small()
                                        .color(color_muted(ui)),
                                );
                            }
                            first = false;
                            let name = names
                                .get(&read.reader)
                                .cloned()
                                .unwrap_or_else(|| id_hex(read.reader));
                            // Tint each reader name with its own person
                            // color so the reader list matches the
                            // sender/recipient chips above.
                            let response = ui.label(
                                egui::RichText::new(name)
                                    .small()
                                    .color(person_color(read.reader)),
                            );
                            let hover = if read.observations.is_empty() {
                                "read · no timestamp observation".to_owned()
                            } else {
                                read.observations
                                    .iter()
                                    .map(|timestamp| {
                                        format!(
                                            "read {} · {}",
                                            format_age_key(now, *timestamp),
                                            format_timestamp_key(*timestamp),
                                        )
                                    })
                                    .collect::<Vec<_>>()
                                    .join("\n")
                            };
                            response.on_hover_text(hover);
                        }
                        // Most recent observation is a compact presentation
                        // summary; every observation remains visible on hover.
                        if let Some(newest_ts) = msg
                            .reads
                            .iter()
                            .flat_map(|read| read.observations.iter())
                            .max()
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

fn render_diagnostic(ui: &mut egui::Ui, message: &str) {
    let accent = egui::Color32::from_rgb(0xe6, 0x32, 0x46);
    egui::Frame::NONE
        .fill(accent.gamma_multiply(0.12))
        .stroke(egui::Stroke::new(1.0, accent))
        .corner_radius(egui::CornerRadius::ZERO)
        .inner_margin(egui::Margin::symmetric(8, 6))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(
                egui::RichText::new(format!("⚠ {message}"))
                    .monospace()
                    .small()
                    .color(ui.visuals().text_color()),
            );
        });
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
            ui.label(egui::RichText::new(h).small().color(color_muted(ui)));
        }
    });
    ui.add_space(24.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_relation_profile_controls_name_and_operator_classification() {
        let person = Person::from_profile(ProfileInput {
            label: "Example".to_owned(),
            aliases: vec!["sample".to_owned()],
            affinities: vec!["Operator".to_owned()],
            first_name: Some("Example".to_owned()),
            ..ProfileInput::default()
        });

        let id = Id::new([1; 16]).unwrap();
        assert_eq!(person.display(id), "Example");
        assert!(person.is_operator);
    }

    #[test]
    fn read_marker_without_observation_remains_visible() {
        let reader = Id::new([2; 16]).unwrap();
        let message = MessageRow {
            id: Id::new([3; 16]).unwrap(),
            from: Id::new([4; 16]).unwrap(),
            to: reader,
            body: "hello".to_owned(),
            created_at: None,
            reads: vec![ReadReceipt {
                reader,
                observations: Vec::new(),
            }],
            is_inbox: true,
            is_unread: false,
        };

        assert_eq!(message.reads.len(), 1);
        assert_eq!(message.reads[0].reader, reader);
        assert!(message.reads[0].observations.is_empty());
    }
}
