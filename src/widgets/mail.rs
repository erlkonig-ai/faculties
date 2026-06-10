//! Read-only GORBIE-embeddable viewer for the `mail` faculty.
//!
//! Renders RFC-5322-shaped messages as paper cards: sender + first
//! recipient on left/right stripes (compass-card idiom), subject as
//! the card heading, body text below, sent-at age and attachment
//! count in the footer. Spam-tagged messages are filtered by default.
//! Drafts show a DRAFT badge in the header.
//!
//! Threading via `in_reply_to` / `references` is rendered as a small
//! "RE" badge when the message has any parent reference; a full
//! tree-of-replies view is a follow-on.
//!
//! ```ignore
//! let mut panel = MailViewer::default();
//! panel.render(ctx, mail_ws, Some(relations_ws));
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

use crate::schemas::mail::{mail as mail_attrs, KIND_DRAFT, KIND_MESSAGE, KIND_SPAM};
use crate::schemas::relations::{relations as rel, KIND_PERSON_ID};

type TextHandle = Inline<Handle<LongString>>;

// ── Color palette ────────────────────────────────────────────────────

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

/// RAL 1003 signal yellow — DRAFT badge.
fn color_draft() -> egui::Color32 {
    egui::Color32::from_rgb(0xf7, 0xba, 0x0b)
}

/// RAL 2004 pure orange — SPAM badge (when surfaced).
fn color_spam() -> egui::Color32 {
    egui::Color32::from_rgb(0xe2, 0x5b, 0x12)
}

/// RAL 6018 yellow green — has-attachment indicator.
fn color_attach() -> egui::Color32 {
    egui::Color32::from_rgb(0x57, 0xa6, 0x39)
}

fn person_color(id: Id) -> egui::Color32 {
    colorhash::ral_categorical(id.as_ref())
}

// ── Row structs ──────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct MailRow {
    id: Id,
    from: Option<Id>,
    to: Vec<Id>,
    cc: Vec<Id>,
    subject: String,
    body: String,
    sent_at: Option<i128>,
    attachments: usize,
    is_draft: bool,
    is_spam: bool,
    /// Immediate parent entity id, if that parent is also a mail in
    /// pile. Chosen from `in_reply_to` first, falling back to the last
    /// `references` entry (RFC 5322 convention: References lists the
    /// thread ancestry in order, with the immediate parent last).
    /// Mails whose declared parent isn't in the pile are treated as
    /// thread roots.
    parent_in_pile: Option<Id>,
    /// True when the message has any `in_reply_to` or `references`
    /// link at all — used for the `RE` badge even when the parent
    /// isn't itself in the pile.
    has_parent_reference: bool,
}

impl MailRow {
    /// Raw chronological key: the sent timestamp, with missing dates
    /// mapped to `i128::MIN` so they sort as "oldest". Callers wrap
    /// in `std::cmp::Reverse` for newest-first ordering. (The earlier
    /// version negated the value, which overflows on `i128::MIN` —
    /// a panic in debug builds the moment a mail has no sent_at.)
    fn sort_key(&self) -> i128 {
        self.sent_at.unwrap_or(i128::MIN)
    }
}

/// Friendly display info for an address.
#[derive(Clone, Debug, Default)]
struct Person {
    alias: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    display_name: Option<String>,
    email: Option<String>,
}

impl Person {
    fn display(&self, id: Id) -> String {
        if let Some(a) = self.alias.as_ref() {
            if !a.is_empty() {
                return a.clone();
            }
        }
        match (self.first_name.as_ref(), self.last_name.as_ref()) {
            (Some(f), Some(l)) if !f.is_empty() && !l.is_empty() => {
                return format!("{f} {l}");
            }
            (Some(f), _) if !f.is_empty() => return f.clone(),
            (_, Some(l)) if !l.is_empty() => return l.clone(),
            _ => {}
        }
        if let Some(d) = self.display_name.as_ref() {
            if !d.is_empty() {
                return d.clone();
            }
        }
        if let Some(e) = self.email.as_ref() {
            if !e.is_empty() {
                return e.clone();
            }
        }
        id_hex(id)
    }
}

fn id_hex(id: Id) -> String {
    format!("{id:x}")
}

// ── Live snapshot ────────────────────────────────────────────────────

struct MailLive {
    cached_head: Option<CommitHandle>,
    relations_cached_head: Option<CommitHandle>,
    people: HashMap<Id, Person>,
    mails: Vec<MailRow>,
}

impl MailLive {
    fn refresh(
        ws: &mut Workspace<Pile>,
        relations_ws: Option<&mut Workspace<Pile>>,
    ) -> Self {
        let space = ws
            .checkout(..)
            .map(|co| co.into_facts())
            .unwrap_or_else(|e| {
                eprintln!("[mail] checkout: {e:?}");
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
                        eprintln!("[mail] relations checkout: {e:?}");
                        TribleSet::new()
                    });
                (head, build_people(&rspace, rws))
            }
            None => (None, HashMap::new()),
        };

        let mails = collect_mails(ws, &space);

        MailLive {
            cached_head,
            relations_cached_head,
            people,
            mails,
        }
    }

    fn display(&self, id: Id) -> String {
        self.people
            .get(&id)
            .map(|p| p.display(id))
            .unwrap_or_else(|| id_hex(id))
    }
}

fn collect_mails(ws: &mut Workspace<Pile>, space: &TribleSet) -> Vec<MailRow> {
    // All KIND_MESSAGE ids.
    let mut by_id: HashMap<Id, MailRow> = HashMap::new();
    for (id,) in find!(
        (m: Id,),
        pattern!(space, [{ ?m @ metadata::tag: KIND_MESSAGE }])
    ) {
        by_id.insert(
            id,
            MailRow {
                id,
                from: None,
                to: Vec::new(),
                cc: Vec::new(),
                subject: String::new(),
                body: String::new(),
                sent_at: None,
                attachments: 0,
                is_draft: false,
                is_spam: false,
                parent_in_pile: None,
                has_parent_reference: false,
            },
        );
    }

    // Draft / spam status — same id may carry both KIND_DRAFT (was a
    // draft) and KIND_MESSAGE (now sent), per schema docs.
    for (id,) in find!(
        (m: Id,),
        pattern!(space, [{ ?m @ metadata::tag: KIND_DRAFT }])
    ) {
        if let Some(row) = by_id.get_mut(&id) {
            row.is_draft = true;
        } else {
            // A pure draft (never sent) has KIND_DRAFT but no
            // KIND_MESSAGE. Surface those too.
            by_id.insert(
                id,
                MailRow {
                    id,
                    from: None,
                    to: Vec::new(),
                    cc: Vec::new(),
                    subject: String::new(),
                    body: String::new(),
                    sent_at: None,
                    attachments: 0,
                    is_draft: true,
                    is_spam: false,
                    parent_in_pile: None,
                    has_parent_reference: false,
                },
            );
        }
    }
    for (id,) in find!(
        (m: Id,),
        pattern!(space, [{ ?m @ metadata::tag: KIND_SPAM }])
    ) {
        if let Some(row) = by_id.get_mut(&id) {
            row.is_spam = true;
        }
    }

    // From.
    for (id, from) in find!(
        (m: Id, f: Id),
        pattern!(space, [{ ?m @ mail_attrs::from: ?f }])
    ) {
        if let Some(row) = by_id.get_mut(&id) {
            row.from = Some(from);
        }
    }

    // Recipients (TO / CC). Each is repeated, hence the per-row Vec.
    for (id, to) in find!(
        (m: Id, t: Id),
        pattern!(space, [{ ?m @ mail_attrs::to: ?t }])
    ) {
        if let Some(row) = by_id.get_mut(&id) {
            row.to.push(to);
        }
    }
    for (id, cc) in find!(
        (m: Id, c: Id),
        pattern!(space, [{ ?m @ mail_attrs::cc: ?c }])
    ) {
        if let Some(row) = by_id.get_mut(&id) {
            row.cc.push(cc);
        }
    }

    // Subject / body — Handle<LongString>, resolved via `ws.get`.
    let subject_rows: Vec<(Id, TextHandle)> = find!(
        (m: Id, h: TextHandle),
        pattern!(space, [{ ?m @ mail_attrs::subject: ?h }])
    )
    .collect();
    for (id, h) in subject_rows {
        if let Some(row) = by_id.get_mut(&id) {
            if let Some(text) = read_text(ws, h) {
                row.subject = text;
            }
        }
    }
    let body_rows: Vec<(Id, TextHandle)> = find!(
        (m: Id, h: TextHandle),
        pattern!(space, [{ ?m @ mail_attrs::body: ?h }])
    )
    .collect();
    for (id, h) in body_rows {
        if let Some(row) = by_id.get_mut(&id) {
            if let Some(text) = read_text(ws, h) {
                row.body = text;
            }
        }
    }

    // Sent-at — interval, take start ns.
    for (id, ts) in find!(
        (m: Id, ts: (i128, i128)),
        pattern!(space, [{ ?m @ mail_attrs::sent_at: ?ts }])
    ) {
        if let Some(row) = by_id.get_mut(&id) {
            row.sent_at = Some(ts.0);
        }
    }

    // Attachments — repeated GenIds, just count for now.
    for (id, _att) in find!(
        (m: Id, a: Id),
        pattern!(space, [{ ?m @ mail_attrs::attachment: ?a }])
    ) {
        if let Some(row) = by_id.get_mut(&id) {
            row.attachments += 1;
        }
    }

    // Thread parentage. The schema lets a mail carry multiple
    // `in_reply_to` GenIds (RFC 5322 allows multiple parents — rare,
    // but happens on merged threads) and an ordered `references`
    // chain. We pick `in_reply_to` first; if that parent isn't in
    // pile, fall back to the most recent `references` entry that
    // IS in pile. Mails whose declared parents are all out-of-pile
    // are treated as roots.
    let mut in_reply_to_pairs: HashMap<Id, Vec<Id>> = HashMap::new();
    for (id, parent) in find!(
        (m: Id, p: Id),
        pattern!(space, [{ ?m @ mail_attrs::in_reply_to: ?p }])
    ) {
        in_reply_to_pairs.entry(id).or_default().push(parent);
        if let Some(row) = by_id.get_mut(&id) {
            row.has_parent_reference = true;
        }
    }
    let mut references_pairs: HashMap<Id, Vec<Id>> = HashMap::new();
    for (id, parent) in find!(
        (m: Id, p: Id),
        pattern!(space, [{ ?m @ mail_attrs::references: ?p }])
    ) {
        references_pairs.entry(id).or_default().push(parent);
        if let Some(row) = by_id.get_mut(&id) {
            row.has_parent_reference = true;
        }
    }
    let known_ids: std::collections::HashSet<Id> = by_id.keys().copied().collect();
    for (id, parents) in in_reply_to_pairs.iter() {
        if let Some(parent) = parents.iter().copied().find(|p| known_ids.contains(p)) {
            if let Some(row) = by_id.get_mut(id) {
                row.parent_in_pile = Some(parent);
            }
        }
    }
    // If in_reply_to didn't give an in-pile parent, scan references
    // backwards (last entry is the immediate parent per the RFC).
    for (id, parents) in references_pairs.iter() {
        if let Some(row) = by_id.get_mut(id) {
            if row.parent_in_pile.is_some() {
                continue;
            }
            if let Some(parent) = parents.iter().rev().copied().find(|p| known_ids.contains(p)) {
                row.parent_in_pile = Some(parent);
            }
        }
    }

    let mut mails: Vec<MailRow> = by_id.into_values().collect();
    // Newest first; missing dates (MIN key) sink to the bottom.
    mails.sort_by_key(|m| std::cmp::Reverse(m.sort_key()));
    mails
}

/// Flatten the mail forest into DFS order with depth per row.
/// Roots = mails with no `parent_in_pile`, ordered newest-first by
/// `sent_at`. Children of each parent ordered oldest-first within
/// that parent (conversation flow). Indent depth capped at
/// `MAX_DEPTH` so deeply-nested chains don't squeeze the bubble to
/// nothing.
fn flatten_threaded(mails: &[MailRow]) -> Vec<(usize, &MailRow)> {
    const MAX_DEPTH: usize = 3;

    let mut children: HashMap<Id, Vec<usize>> = HashMap::new();
    let mut roots: Vec<usize> = Vec::new();
    for (idx, m) in mails.iter().enumerate() {
        match m.parent_in_pile {
            Some(p) => children.entry(p).or_default().push(idx),
            None => roots.push(idx),
        }
    }
    // Roots: newest-first (same as the flat-list order).
    roots.sort_by_key(|&i| std::cmp::Reverse(mails[i].sort_key()));
    // Children: oldest-first inside each parent (conversation flow).
    for kids in children.values_mut() {
        kids.sort_by_key(|&i| mails[i].sort_key());
    }

    let mut out: Vec<(usize, &MailRow)> = Vec::with_capacity(mails.len());
    let mut stack: Vec<(usize, usize)> = roots
        .iter()
        .rev()
        .map(|&i| (i, 0usize))
        .collect();
    while let Some((idx, depth)) = stack.pop() {
        out.push((depth, &mails[idx]));
        if let Some(kids) = children.get(&mails[idx].id) {
            let child_depth = (depth + 1).min(MAX_DEPTH);
            for &k in kids.iter().rev() {
                stack.push((k, child_depth));
            }
        }
    }
    out
}

fn build_people(
    rspace: &TribleSet,
    rws: &mut Workspace<Pile>,
) -> HashMap<Id, Person> {
    let person_ids: Vec<Id> = find!(
        (pid: Id,),
        pattern!(rspace, [{ ?pid @ metadata::tag: KIND_PERSON_ID }])
    )
    .map(|(pid,)| pid)
    .collect();

    let mut people: HashMap<Id, Person> = person_ids
        .into_iter()
        .map(|pid| (pid, Person::default()))
        .collect();

    let alias_rows: Vec<(Id, String)> = find!(
        (pid: Id, alias: String),
        pattern!(rspace, [{ ?pid @ rel::alias: ?alias }])
    )
    .collect();
    for (pid, alias) in alias_rows {
        if let Some(p) = people.get_mut(&pid) {
            p.alias = Some(alias);
        }
    }
    let first_rows: Vec<(Id, TextHandle)> = find!(
        (pid: Id, h: TextHandle),
        pattern!(rspace, [{ ?pid @ rel::first_name: ?h }])
    )
    .collect();
    for (pid, h) in first_rows {
        if let Some(p) = people.get_mut(&pid) {
            p.first_name = read_text(rws, h);
        }
    }
    let last_rows: Vec<(Id, TextHandle)> = find!(
        (pid: Id, h: TextHandle),
        pattern!(rspace, [{ ?pid @ rel::last_name: ?h }])
    )
    .collect();
    for (pid, h) in last_rows {
        if let Some(p) = people.get_mut(&pid) {
            p.last_name = read_text(rws, h);
        }
    }
    let display_rows: Vec<(Id, TextHandle)> = find!(
        (pid: Id, h: TextHandle),
        pattern!(rspace, [{ ?pid @ rel::display_name: ?h }])
    )
    .collect();
    for (pid, h) in display_rows {
        if let Some(p) = people.get_mut(&pid) {
            p.display_name = read_text(rws, h);
        }
    }
    let email_rows: Vec<(Id, String)> = find!(
        (pid: Id, e: String),
        pattern!(rspace, [{ ?pid @ rel::email: ?e }])
    )
    .collect();
    for (pid, e) in email_rows {
        if let Some(p) = people.get_mut(&pid) {
            p.email = Some(e);
        }
    }

    people
}

fn read_text(ws: &mut Workspace<Pile>, h: TextHandle) -> Option<String> {
    ws.get::<View<str>, LongString>(h).ok().map(|v| {
        let s: &str = v.as_ref();
        s.to_string()
    })
}

// ── Widget ───────────────────────────────────────────────────────────

/// Read-only mail viewer. Set `show_spam(true)` to surface spam-tagged
/// messages alongside the normal list (default is hide).
pub struct MailViewer {
    live: Option<MailLive>,
    show_spam: bool,
}

impl Default for MailViewer {
    fn default() -> Self {
        Self {
            live: None,
            show_spam: false,
        }
    }
}

impl MailViewer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn show_spam(mut self, on: bool) -> Self {
        self.show_spam = on;
        self
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
            self.live = Some(MailLive::refresh(
                ws,
                relations_ws.as_mut().map(|w| &mut **w),
            ));
        }

        ctx.section("Mail", |ctx| {
            let Some(live) = self.live.as_ref() else { return };

            let total = live.mails.len();
            let drafts = live.mails.iter().filter(|m| m.is_draft).count();
            let spam = live.mails.iter().filter(|m| m.is_spam).count();
            let visible_count = live
                .mails
                .iter()
                .filter(|m| self.show_spam || !m.is_spam)
                .count();
            let show_spam = self.show_spam;

            let mut search = ctx.search();
            let needle = search.query().to_lowercase();
            let search_active = !needle.is_empty();

            ctx.grid(|g| {
                g.full(|ctx| {
                    let ui = ctx.ui_mut();
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 12.0;
                        ui.label(
                            egui::RichText::new(format!("{visible_count} / {total} MAIL"))
                                .monospace()
                                .strong()
                                .small()
                                .color(color_muted(ui)),
                        );
                        if drafts > 0 {
                            ui.label(
                                egui::RichText::new(format!("{drafts} DRAFT"))
                                    .monospace()
                                    .small()
                                    .color(color_draft()),
                            );
                        }
                        if spam > 0 {
                            ui.label(
                                egui::RichText::new(format!(
                                    "{spam} SPAM{}",
                                    if show_spam { " (shown)" } else { " (hidden)" }
                                ))
                                .monospace()
                                .small()
                                .color(color_spam()),
                            );
                        }
                    });
                });

                if live.mails.is_empty() {
                    g.full(|ctx| {
                        let ui = ctx.ui_mut();
                        ui.add_space(16.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                egui::RichText::new("\u{2709}") // ✉
                                    .size(28.0)
                                    .color(color_muted(ui)),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new("No mail yet.")
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

                // Iterate the mail forest in DFS order. Each row gets
                // a depth-driven left indent (in grid columns), so
                // replies visually nest under their parents and
                // sibling threads stay at column 0.
                let threaded = flatten_threaded(&live.mails);
                for (depth, mail) in threaded {
                    if mail.is_spam && !show_spam {
                        continue;
                    }
                    if search_active && !mail_matches_search(mail, live, &needle) {
                        continue;
                    }
                    let match_info = if search_active {
                        Some(search.report(egui::Id::new(("mail_match", mail.id))))
                    } else {
                        None
                    };
                    let is_focused =
                        match_info.as_ref().map_or(false, |i| i.is_focused);
                    let indent_cols = depth.min(3) as u32;
                    let width_cols = 12 - indent_cols;
                    if indent_cols > 0 {
                        g.skip(indent_cols);
                    }
                    g.place(width_cols, |ctx| {
                        let ui = ctx.ui_mut();
                        let pre_y = ui.cursor().min.y;
                        render_mail(ui, mail, live, &needle, is_focused);
                        if let Some(info) = match_info {
                            if info.should_scroll_to {
                                let post_y = ui.cursor().min.y;
                                let rect = egui::Rect::from_min_max(
                                    egui::pos2(ui.min_rect().left(), pre_y),
                                    egui::pos2(ui.min_rect().right(), post_y),
                                );
                                ui.scroll_to_rect(rect, Some(egui::Align::Center));
                            }
                        }
                    });
                }
            });
        });
    }
}

fn mail_matches_search(mail: &MailRow, live: &MailLive, needle: &str) -> bool {
    if mail.subject.to_lowercase().contains(needle) {
        return true;
    }
    if mail.body.to_lowercase().contains(needle) {
        return true;
    }
    if let Some(from) = mail.from {
        if live.display(from).to_lowercase().contains(needle) {
            return true;
        }
    }
    for id in mail.to.iter().chain(mail.cc.iter()) {
        if live.display(*id).to_lowercase().contains(needle) {
            return true;
        }
    }
    false
}

// ── Rendering ────────────────────────────────────────────────────────

const STRIPE_WIDTH: f32 = 18.0;
const STRIPE_GAP: f32 = 8.0;
const STROKE_INSET: f32 = 1.0;

fn render_mail(
    ui: &mut egui::Ui,
    mail: &MailRow,
    live: &MailLive,
    search_needle: &str,
    focused: bool,
) {
    let bubble_fill = ui.visuals().window_fill;
    let from_color = mail
        .from
        .map(person_color)
        .unwrap_or_else(|| color_muted(ui));
    let primary_recipient = mail.to.first().copied().or_else(|| mail.cc.first().copied());
    let to_color = primary_recipient
        .map(person_color)
        .unwrap_or_else(|| color_muted(ui));

    let inner_margin = egui::Margin {
        left: (STROKE_INSET + STRIPE_WIDTH + STRIPE_GAP) as i8,
        right: (STROKE_INSET + STRIPE_WIDTH + STRIPE_GAP) as i8,
        top: 6,
        bottom: 6,
    };

    ui.vertical(|ui| {
    let frame_resp = egui::Frame::NONE
        .fill(bubble_fill)
        .stroke(egui::Stroke::new(STROKE_INSET, color_frame(ui)))
        .shadow(egui::epaint::Shadow {
            offset: [2, 2],
            blur: 0,
            spread: 0,
            color: egui::Color32::from_black_alpha(48),
        })
        .corner_radius(egui::CornerRadius::ZERO)
        .inner_margin(inner_margin)
        .show(ui, |ui| {
            // Top row: status badges (DRAFT / SPAM / RE / +N CC),
            // attachment count, and sent-at age — all right-aligned
            // so the subject heading owns the left side of the row.
            // `Align::Min` cross-axis avoids the frame-delayed cell
            // sizing feedback we hit on the messages widget.
            ui.with_layout(
                egui::Layout::right_to_left(egui::Align::Min),
                |ui| {
                    if let Some(age) = format_relative_age(mail.sent_at) {
                        ui.label(
                            egui::RichText::new(age)
                                .monospace()
                                .small()
                                .color(color_muted(ui)),
                        );
                    }
                    if mail.attachments > 0 {
                        ui.label(
                            egui::RichText::new(format!(
                                "\u{1F4CE} {}", // 📎
                                mail.attachments
                            ))
                            .monospace()
                            .small()
                            .color(color_attach()),
                        );
                    }
                    let extra_cc = mail.cc.len();
                    let extra_to = mail.to.len().saturating_sub(1);
                    let extras = extra_cc + extra_to;
                    if extras > 0 {
                        ui.label(
                            egui::RichText::new(format!("+{extras}"))
                                .monospace()
                                .small()
                                .color(color_muted(ui)),
                        );
                    }
                    if mail.has_parent_reference {
                        render_badge(ui, "RE", color_muted(ui));
                    }
                    if mail.is_draft {
                        render_badge(ui, "DRAFT", color_draft());
                    }
                    if mail.is_spam {
                        render_badge(ui, "SPAM", color_spam());
                    }
                },
            );

            ui.add_space(2.0);

            // Subject (heading).
            let subject_text = if mail.subject.trim().is_empty() {
                "(no subject)".to_string()
            } else {
                mail.subject.clone()
            };
            GORBIE::search::highlight_label(
                ui,
                &subject_text,
                search_needle,
                heading_format(ui),
                focused,
            );

            ui.add_space(4.0);

            // Body.
            GORBIE::search::highlight_label(
                ui,
                &mail.body,
                search_needle,
                body_format(ui, ui.visuals().text_color()),
                focused,
            );
        });

    // Left / right stripes — sender + first recipient, compass idiom.
    let outer = frame_resp.response.rect;
    let from_label = mail
        .from
        .map(|id| live.display(id))
        .unwrap_or_else(|| "(no sender)".into());
    paint_party_stripe(
        ui.painter(),
        outer,
        StripeSide::Left,
        from_color,
        &from_label.to_uppercase(),
    );
    let to_label = primary_recipient
        .map(|id| live.display(id))
        .unwrap_or_else(|| "(no recipient)".into());
    paint_party_stripe(
        ui.painter(),
        outer,
        StripeSide::Right,
        to_color,
        &to_label.to_uppercase(),
    );
    });
}

fn render_badge(ui: &mut egui::Ui, label: &str, color: egui::Color32) {
    let text = colorhash::text_color_on(color);
    egui::Frame::NONE
        .fill(color)
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

#[derive(Clone, Copy)]
enum StripeSide {
    Left,
    Right,
}

fn paint_party_stripe(
    painter: &egui::Painter,
    outer: egui::Rect,
    side: StripeSide,
    color: egui::Color32,
    label: &str,
) {
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
    if galley.size().x + 6.0 > stripe_rect.height() {
        return;
    }
    let gh = galley.size().y;
    let mut text_shape = match side {
        StripeSide::Left => {
            let pos = egui::pos2(
                stripe_rect.left() + (STRIPE_WIDTH + gh) * 0.5,
                stripe_rect.top() + 5.0,
            );
            let mut s = egui::epaint::TextShape::new(pos, galley, text_color);
            s.angle = std::f32::consts::FRAC_PI_2;
            s
        }
        StripeSide::Right => {
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

fn heading_format(ui: &egui::Ui) -> egui::TextFormat {
    egui::TextFormat {
        font_id: egui::TextStyle::Heading.resolve(ui.style()),
        color: ui.visuals().text_color(),
        ..Default::default()
    }
}

fn body_format(ui: &egui::Ui, color: egui::Color32) -> egui::TextFormat {
    egui::TextFormat {
        font_id: egui::TextStyle::Body.resolve(ui.style()),
        color,
        ..Default::default()
    }
}

fn format_relative_age(ts: Option<i128>) -> Option<String> {
    let ts = ts?;
    let now = now_tai_ns();
    let secs = ((now - ts) / 1_000_000_000).max(0) as i64;
    Some(format_age_secs(secs))
}

fn format_age_secs(secs: i64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else if secs < 86400 * 30 {
        format!("{}d", secs / 86400)
    } else if secs < 86400 * 365 {
        format!("{}mo", secs / (86400 * 30))
    } else {
        format!("{}y", secs / (86400 * 365))
    }
}

fn now_tai_ns() -> i128 {
    use hifitime::Epoch;
    let now = Epoch::now().unwrap_or_else(|_| Epoch::from_tai_seconds(0.0));
    now.to_tai_duration().total_nanoseconds()
}
