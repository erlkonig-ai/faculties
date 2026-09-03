//! Read-only GORBIE-embeddable viewer for the `mail` faculty.
//!
//! Renders RFC-5322-shaped messages as paper cards: sender + first
//! recipient on left/right stripes (compass-card idiom), subject as
//! the card heading, body text below, sent-at age and attachment
//! count in the footer. Spam-tagged messages are filtered by default.
//! Drafts show a DRAFT badge in the header.
//!
//! Threading via `in_reply_to` / `references` is rendered as a small
//! "RE" badge and, when one parent wire resolves to exactly one visible
//! projection, as a nested reply. Ambiguous parents stay unnested and visible.
//!
//! ```ignore
//! let mut panel = MailViewer::default();
//! panel.render(ctx, mail_view, Some(relations_view));
//! ```

use std::collections::{BTreeMap, HashMap, HashSet};

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use triblespace::core::id::Id;
use triblespace::core::repo::pile::PileSnapshot;

use crate::mail::{self, ProjectionDirection};
use crate::relations::{self, ProfileInput, ProfileView};
use crate::storage::FactArchive;
use crate::widgets::storage::{DatasetRevision, DatasetView};

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
    wire: Option<Id>,
    from: Option<String>,
    to: Vec<String>,
    cc: Vec<String>,
    subject: String,
    body: String,
    sent_at: Option<i128>,
    attachments: usize,
    is_draft: bool,
    is_spam: bool,
    /// Exact projection/draft row used for visual nesting when the canonical
    /// parent wire resolves to one and only one in-pile row.
    parent_in_pile: Option<Id>,
    /// Wire identities named by the canonical projection. Multiple possible
    /// in-pile parents remain diagnostic rather than becoming a chosen edge.
    parent_candidates: Vec<Id>,
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
#[derive(Clone, Debug)]
struct Person {
    id: Id,
    display: String,
}

impl Person {
    fn from_profile(id: Id, profile: &ProfileInput) -> Self {
        let display = profile
            .display_name
            .clone()
            .or_else(|| match (&profile.first_name, &profile.last_name) {
                (Some(first), Some(last)) => Some(format!("{first} {last}")),
                (Some(first), None) => Some(first.clone()),
                (None, Some(last)) => Some(last.clone()),
                (None, None) => None,
            })
            .unwrap_or_else(|| profile.label.clone());
        Self { id, display }
    }
}

// ── Live snapshot ────────────────────────────────────────────────────

struct MailLive {
    cached_revision: DatasetRevision,
    relations_cached_revision: Option<DatasetRevision>,
    people: HashMap<String, Person>,
    mails: Vec<MailRow>,
    diagnostics: Vec<String>,
}

impl MailLive {
    fn refresh(view: DatasetView<'_>, relations: Option<DatasetView<'_>>) -> Self {
        let (relations_cached_revision, people, mut diagnostics) = match relations {
            Some(relations) => {
                let (people, diagnostics) = build_people(relations.facts, relations.reader);
                (Some(relations.revision), people, diagnostics)
            }
            None => (None, HashMap::new(), Vec::new()),
        };

        let (mails, mail_diagnostics) = collect_mails(view.reader, view.facts);
        diagnostics.extend(mail_diagnostics);

        MailLive {
            cached_revision: view.revision,
            relations_cached_revision,
            people,
            mails,
            diagnostics,
        }
    }

    fn display(&self, address: &str) -> String {
        self.people
            .get(&mailbox_key(address))
            .map(|person| person.display.clone())
            .unwrap_or_else(|| address.to_owned())
    }

    fn color(&self, address: &str) -> egui::Color32 {
        self.people
            .get(&mailbox_key(address))
            .map(|person| person_color(person.id))
            .unwrap_or_else(|| colorhash::ral_categorical(mailbox_key(address).as_bytes()))
    }
}

fn collect_mails(reader: &PileSnapshot, space: &FactArchive) -> (Vec<MailRow>, Vec<String>) {
    let mut mails = Vec::new();
    let mut diagnostics = Vec::new();
    for id in mail::projection_ids(space) {
        match projection_row(reader, space, id) {
            Ok(row) => mails.push(row),
            Err(error) => diagnostics.push(format!("Mail projection {id:x} is invalid: {error:#}")),
        }
    }
    for id in mail::draft_ids(space) {
        match draft_row(reader, space, id) {
            Ok(row) => mails.push(row),
            Err(error) => diagnostics.push(format!("Mail draft {id:x} is invalid: {error:#}")),
        }
    }
    resolve_thread_parents(&mut mails, &mut diagnostics);
    mails.sort_by_key(|m| std::cmp::Reverse(m.sort_key()));
    (mails, diagnostics)
}

fn projection_row(reader: &PileSnapshot, space: &FactArchive, id: Id) -> anyhow::Result<MailRow> {
    let projection = mail::projection_view(reader, space, id)?;
    let direction = mail::projection_direction(space, projection.source)?;
    let parent_candidates = if projection.in_reply_to.is_empty() {
        projection.references.clone()
    } else {
        projection.in_reply_to.clone()
    };
    Ok(MailRow {
        id,
        wire: Some(projection.wire),
        from: projection.from,
        to: projection.to,
        cc: projection.cc,
        subject: projection.subject,
        body: projection.body,
        sent_at: projection.claimed_date.map(interval_ns).transpose()?,
        attachments: projection.attachments.len(),
        is_draft: direction == ProjectionDirection::Draft,
        is_spam: projection.spam,
        parent_in_pile: None,
        has_parent_reference: !parent_candidates.is_empty(),
        parent_candidates,
    })
}

fn draft_row(reader: &PileSnapshot, space: &FactArchive, id: Id) -> anyhow::Result<MailRow> {
    let draft = mail::draft_value(space, id)?;
    let read_all = |handles: &[mail::TextHandle]| -> anyhow::Result<Vec<String>> {
        handles
            .iter()
            .map(|&handle| mail::read_text(reader, handle))
            .collect()
    };
    let parent_candidates = if draft.in_reply_to.is_empty() {
        draft.references.clone()
    } else {
        draft.in_reply_to.clone()
    };
    Ok(MailRow {
        id,
        wire: None,
        from: Some(mail::read_text(reader, draft.envelope_from)?),
        to: read_all(&draft.to)?,
        cc: read_all(&draft.cc)?,
        subject: mail::read_text(reader, draft.subject)?,
        body: mail::read_text(reader, draft.body)?,
        sent_at: Some(interval_ns(draft.created_at)?),
        attachments: draft.attachments.len(),
        is_draft: true,
        is_spam: false,
        parent_in_pile: None,
        has_parent_reference: !parent_candidates.is_empty(),
        parent_candidates,
    })
}

fn interval_ns(value: mail::IntervalValue) -> anyhow::Result<i128> {
    let (lower, _upper): (i128, i128) = value
        .try_from_inline()
        .map_err(|error| anyhow::anyhow!("decode Mail timestamp: {error:?}"))?;
    Ok(lower)
}

fn resolve_thread_parents(mails: &mut [MailRow], diagnostics: &mut Vec<String>) {
    let mut rows_by_wire = BTreeMap::<Id, Vec<usize>>::new();
    for (index, row) in mails.iter().enumerate() {
        if let Some(wire) = row.wire {
            rows_by_wire.entry(wire).or_default().push(index);
        }
    }
    for index in 0..mails.len() {
        let candidates = mails[index]
            .parent_candidates
            .iter()
            .filter_map(|wire| rows_by_wire.get(wire).map(|rows| (*wire, rows)))
            .collect::<Vec<_>>();
        match candidates.as_slice() {
            [] => {}
            [(_wire, rows)] if rows.len() == 1 => {
                mails[index].parent_in_pile = Some(mails[rows[0]].id);
            }
            _ => diagnostics.push(format!(
                "Mail projection {} has {} possible in-pile parent projections; thread nesting was left unresolved",
                mails[index].id,
                candidates.iter().map(|(_, rows)| rows.len()).sum::<usize>()
            )),
        }
    }
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
    let mut stack: Vec<(usize, usize)> = roots.iter().rev().map(|&i| (i, 0usize)).collect();
    let mut visited = HashSet::new();
    while let Some((idx, depth)) = stack.pop() {
        if !visited.insert(idx) {
            continue;
        }
        out.push((depth, &mails[idx]));
        if let Some(kids) = children.get(&mails[idx].id) {
            let child_depth = (depth + 1).min(MAX_DEPTH);
            for &k in kids.iter().rev() {
                stack.push((k, child_depth));
            }
        }
    }
    // Malformed or cyclic source thread claims must not make messages vanish.
    // Surface every remaining row at root depth; the canonical projection
    // remains visible even when nesting cannot be represented as a forest.
    for idx in 0..mails.len() {
        if visited.insert(idx) {
            out.push((0, &mails[idx]));
        }
    }
    out
}

fn build_people(
    rspace: &FactArchive,
    reader: &PileSnapshot,
) -> (HashMap<String, Person>, Vec<String>) {
    let mut candidates = BTreeMap::<String, Vec<Person>>::new();
    let mut diagnostics = Vec::new();
    for (person, view) in relations::person_profile_views(reader, rspace) {
        match view {
            ProfileView::Current { value, .. } => {
                let display = Person::from_profile(person, &value);
                for email in &value.emails {
                    candidates
                        .entry(mailbox_key(email))
                        .or_default()
                        .push(display.clone());
                }
            }
            ProfileView::Forked(heads) => diagnostics.push(format!(
                "Relations person {person:x} has {} profile heads; Mail address labels remain unresolved",
                heads.len()
            )),
            ProfileView::Invalid(error) => diagnostics.push(format!(
                "Relations person {person:x} profile is invalid: {error}"
            )),
        }
    }

    let mut people = HashMap::new();
    for (email, mut values) in candidates {
        values.sort_by_key(|person| person.id);
        values.dedup_by_key(|person| person.id);
        if values.len() == 1 {
            people.insert(email, values.pop().expect("one person"));
        } else {
            diagnostics.push(format!(
                "Mail address {email} belongs to {} Relations anchors; no display identity was selected",
                values.len()
            ));
        }
    }
    (people, diagnostics)
}

fn mailbox_key(value: &str) -> String {
    let value = value.trim();
    let address = value
        .rfind('<')
        .and_then(|start| {
            value[start + 1..]
                .find('>')
                .map(|end| &value[start + 1..start + 1 + end])
        })
        .unwrap_or(value)
        .trim();
    let address = address.to_ascii_lowercase();
    address
        .strip_prefix("mailto:")
        .unwrap_or(&address)
        .to_owned()
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
        view: DatasetView<'_>,
        relations: Option<DatasetView<'_>>,
    ) {
        let revision = view.revision;
        let relations_revision = relations.map(|view| view.revision);
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => {
                l.cached_revision != revision || l.relations_cached_revision != relations_revision
            }
        };
        if need_refresh {
            self.live = Some(MailLive::refresh(view, relations));
        }

        ctx.section("Mail", |ctx| {
            let Some(live) = self.live.as_ref() else {
                return;
            };

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
                for diagnostic in &live.diagnostics {
                    g.full(|ctx| render_diagnostic(ctx.ui_mut(), diagnostic));
                }
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
                    let is_focused = match_info.as_ref().map_or(false, |i| i.is_focused);
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
    if let Some(from) = &mail.from {
        if live.display(from).to_lowercase().contains(needle) {
            return true;
        }
    }
    for address in mail.to.iter().chain(mail.cc.iter()) {
        if live.display(address).to_lowercase().contains(needle) {
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
        .as_deref()
        .map(|address| live.color(address))
        .unwrap_or_else(|| color_muted(ui));
    let primary_recipient = mail.to.first().or_else(|| mail.cc.first());
    let to_color = primary_recipient
        .map(|address| live.color(address))
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
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
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
                });

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
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(format!(
                        "{} {}",
                        if mail.wire.is_some() {
                            "projection"
                        } else {
                            "draft"
                        },
                        format_args!("{:x}", mail.id)
                    ))
                    .monospace()
                    .small()
                    .color(color_muted(ui)),
                );
            });

        // Left / right stripes — sender + first recipient, compass idiom.
        let outer = frame_resp.response.rect;
        let from_label = mail
            .from
            .as_deref()
            .map(|address| live.display(address))
            .unwrap_or_else(|| "(no sender)".into());
        paint_party_stripe(
            ui.painter(),
            outer,
            StripeSide::Left,
            from_color,
            &from_label.to_uppercase(),
        );
        let to_label = primary_recipient
            .map(|address| live.display(address))
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

fn render_diagnostic(ui: &mut egui::Ui, diagnostic: &str) {
    egui::Frame::NONE
        .fill(color_frame(ui))
        .inner_margin(egui::Margin::same(10))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new("MAIL PROJECTION DIAGNOSTIC")
                    .monospace()
                    .small()
                    .strong()
                    .color(color_spam()),
            );
            ui.label(egui::RichText::new(diagnostic).monospace().small());
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
    let now = crate::clock::tai_nanoseconds_now().ok()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn row(id_byte: u8, wire: Option<Id>, parents: Vec<Id>) -> MailRow {
        MailRow {
            id: id(id_byte),
            wire,
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
            has_parent_reference: !parents.is_empty(),
            parent_candidates: parents,
        }
    }

    #[test]
    fn address_lookup_normalizes_display_mailboxes_without_guessing_names() {
        assert_eq!(
            mailbox_key("Alice Example <Alice@Example.TEST>"),
            "alice@example.test"
        );
        assert_eq!(mailbox_key("MAILTO:Me@Example.TEST"), "me@example.test");
    }

    #[test]
    fn ambiguous_parent_projection_is_diagnostic_not_arbitrated() {
        let wire = id(9);
        let mut rows = vec![
            row(1, Some(wire), Vec::new()),
            row(2, Some(wire), Vec::new()),
            row(3, None, vec![wire]),
        ];
        let mut diagnostics = Vec::new();
        resolve_thread_parents(&mut rows, &mut diagnostics);
        assert_eq!(rows[2].parent_in_pile, None);
        assert_eq!(diagnostics.len(), 1);

        let mut unique = vec![row(1, Some(wire), Vec::new()), row(3, None, vec![wire])];
        diagnostics.clear();
        resolve_thread_parents(&mut unique, &mut diagnostics);
        assert_eq!(unique[1].parent_in_pile, Some(unique[0].id));
        assert!(diagnostics.is_empty());
    }
}
