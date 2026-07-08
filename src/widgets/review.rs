//! Read-only GORBIE-embeddable review bench.
//!
//! Renders every compass goal whose *latest* status is `"review"` as a
//! collapsed-by-default section — the human's primary work surface for
//! auditing finished-but-unblessed work. Per goal it gathers the whole
//! review context in one place:
//!
//! - title, tags, age (time in review + time since creation);
//! - the goal's notes, newest-first;
//! - wiki fragments REFERENCED from the notes — extracted by regexing
//!   32-hex ids out of the note text (pragmatic v0: a real link edge
//!   arrives with the Great Unification epic later) — each rendered
//!   with its title and full typst prose via the wiki widget's
//!   rendering path;
//! - decide entries whose `decide::about` edge points at the goal,
//!   rendered as pros / cons / outcome.
//!
//! Strictly READ-ONLY: the widget never commits or pushes — auditing
//! posture. All state is queried on demand from cached `TribleSet`
//! snapshots (no shadow datamodels); the snapshots refresh whenever a
//! workspace head advances.
//!
//! ```ignore
//! let mut panel = ReviewPanel::default();
//! panel.render(ctx, compass_ws, wiki_ws, decide_ws);
//! ```

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::Inline;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{CommitHandle, Workspace};
use triblespace::core::trible::TribleSet;
use triblespace::macros::{find, pattern};
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::View;

use crate::schemas::compass::{board as compass, KIND_GOAL_ID, KIND_NOTE_ID, KIND_STATUS_ID};
use crate::schemas::decide::{decide as decide_attrs, factor, KIND_CON, KIND_DECISION, KIND_PRO};
use crate::schemas::wiki::{attrs as wiki, KIND_VERSION_ID};
use crate::widgets::wiki::render_wiki_content;

type TextHandle = Inline<Handle<LongString>>;

/// The compass status this bench collects. Not part of
/// `DEFAULT_STATUSES` — it's the human-in-the-loop gate between
/// "done by the agent" and "blessed by JP".
const REVIEW_STATUS: &str = "review";

// ── Palette (shared idiom across the dashboard widgets) ─────────────

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

/// RAL 6018 yellow green — "PRO" accent (decide-widget idiom).
fn color_pro() -> egui::Color32 {
    egui::Color32::from_rgb(0x57, 0xa6, 0x39)
}

/// RAL 3020 traffic red — "CON" accent.
fn color_con() -> egui::Color32 {
    egui::Color32::from_rgb(0xcc, 0x0a, 0x17)
}

/// RAL 1003 signal yellow — outcome / resolved accent.
fn color_resolved() -> egui::Color32 {
    egui::Color32::from_rgb(0xf7, 0xba, 0x0b)
}

/// "Paper" frame recipe — matches the compass/decide card chrome.
fn paper_frame(ui: &egui::Ui) -> egui::Frame {
    egui::Frame::NONE
        .fill(ui.visuals().window_fill)
        .stroke(egui::Stroke::new(1.0, color_frame(ui)))
        .shadow(egui::epaint::Shadow {
            offset: [2, 2],
            blur: 0,
            spread: 0,
            color: egui::Color32::from_black_alpha(48),
        })
        .corner_radius(egui::CornerRadius::ZERO)
}

fn render_chip(ui: &mut egui::Ui, label: &str, fill: egui::Color32) {
    let text_color = colorhash::text_color_on(fill);
    let font = egui::TextStyle::Small.resolve(ui.style());
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_string(), font, text_color);
    const PAD_X: f32 = 5.0;
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(galley.size().x + PAD_X * 2.0, galley.size().y),
        egui::Sense::hover(),
    );
    let painter = ui.painter();
    painter.rect_filled(rect, egui::CornerRadius::ZERO, fill);
    painter.galley(egui::pos2(rect.left() + PAD_X, rect.top()), galley, text_color);
}

// ── Time helpers ─────────────────────────────────────────────────────

fn now_tai_ns() -> i128 {
    hifitime::Epoch::now()
        .map(|e| e.to_tai_duration().total_nanoseconds())
        .unwrap_or(0)
}

fn format_age(now_key: i128, maybe_key: Option<i128>) -> String {
    let Some(key) = maybe_key else {
        return "-".to_string();
    };
    let delta_s = (now_key.saturating_sub(key) / 1_000_000_000).max(0) as i64;
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

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

/// 32-hex-id matcher for note text. `\b` on both ends keeps a 64-char
/// content hash from yielding a bogus half-match. Pragmatic v0 — the
/// note→fragment relationship should become a real link edge (queried
/// via `pattern!`, no text scraping) with the Great Unification epic;
/// this regex is the bridge until then.
fn hex32_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[0-9a-fA-F]{32}\b").expect("static regex"))
}

// ── Cached snapshots ─────────────────────────────────────────────────

/// Cached fact spaces + head markers for the three branches the bench
/// reads. Queries run against the `TribleSet`s on demand; text blobs
/// are dereffed through the owning branch's workspace at render time.
struct ReviewLive {
    compass_space: TribleSet,
    wiki_space: TribleSet,
    decide_space: TribleSet,
    compass_head: Option<CommitHandle>,
    wiki_head: Option<CommitHandle>,
    decide_head: Option<CommitHandle>,
}

fn checkout_space(ws: &mut Workspace<Pile>, label: &str) -> TribleSet {
    ws.checkout(..)
        .map(|co| co.into_facts())
        .unwrap_or_else(|e| {
            eprintln!("[review] {label} checkout: {e:?}");
            TribleSet::new()
        })
}

impl ReviewLive {
    fn refresh(
        compass_ws: &mut Workspace<Pile>,
        wiki_ws: Option<&mut Workspace<Pile>>,
        decide_ws: Option<&mut Workspace<Pile>>,
    ) -> Self {
        let compass_space = checkout_space(compass_ws, "compass");
        let compass_head = compass_ws.head();
        let (wiki_space, wiki_head) = match wiki_ws {
            Some(ws) => (checkout_space(ws, "wiki"), ws.head()),
            None => (TribleSet::new(), None),
        };
        let (decide_space, decide_head) = match decide_ws {
            Some(ws) => (checkout_space(ws, "decide"), ws.head()),
            None => (TribleSet::new(), None),
        };
        ReviewLive {
            compass_space,
            wiki_space,
            decide_space,
            compass_head,
            wiki_head,
            decide_head,
        }
    }
}

fn read_text(ws: &mut Workspace<Pile>, h: TextHandle) -> Option<String> {
    ws.get::<View<str>, LongString>(h).ok().map(|v| {
        let s: &str = v.as_ref();
        s.to_string()
    })
}

// ── On-demand queries ────────────────────────────────────────────────

/// Goals whose latest status event says "review", newest-entered
/// first. Returns (goal_id, entered_review_at).
fn review_goals(space: &TribleSet) -> Vec<(Id, i128)> {
    // Latest status event per goal — same rollup CompassBoard does.
    let mut latest: std::collections::HashMap<Id, (String, i128)> =
        std::collections::HashMap::new();
    for (gid, status, ts) in find!(
        (gid: Id, status: String, ts: (i128, i128)),
        pattern!(space, [{
            _?event @
            metadata::tag: &KIND_STATUS_ID,
            compass::task: ?gid,
            compass::status: ?status,
            metadata::created_at: ?ts,
        }])
    ) {
        match latest.get_mut(&gid) {
            Some(slot) if slot.1 < ts.0 => *slot = (status, ts.0),
            Some(_) => {}
            None => {
                latest.insert(gid, (status, ts.0));
            }
        }
    }
    let mut goals: Vec<(Id, i128)> = latest
        .into_iter()
        .filter(|(_, (status, _))| status == REVIEW_STATUS)
        .map(|(gid, (_, ts))| (gid, ts))
        .collect();
    goals.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    goals
}

fn goal_title(space: &TribleSet, ws: &mut Workspace<Pile>, goal_id: Id) -> String {
    find!(
        h: TextHandle,
        pattern!(space, [{
            goal_id @
            metadata::tag: &KIND_GOAL_ID,
            compass::title: ?h,
        }])
    )
    .next()
    .and_then(|h| read_text(ws, h))
    .unwrap_or_else(|| "(untitled)".to_string())
}

fn goal_tags(space: &TribleSet, goal_id: Id) -> Vec<String> {
    let mut tags: Vec<String> = find!(
        tag: String,
        pattern!(space, [{
            goal_id @
            metadata::tag: &KIND_GOAL_ID,
            compass::tag: ?tag,
        }])
    )
    .collect();
    tags.sort();
    tags
}

fn goal_created_at(space: &TribleSet, goal_id: Id) -> Option<i128> {
    find!(
        ts: (i128, i128),
        pattern!(space, [{
            goal_id @
            metadata::tag: &KIND_GOAL_ID,
            metadata::created_at: ?ts,
        }])
    )
    .next()
    .map(|ts| ts.0)
}

/// Notes on a goal, newest-first: (created_at, body).
fn goal_notes(
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
    goal_id: Id,
) -> Vec<(Option<i128>, String)> {
    let raw: Vec<(TextHandle, (i128, i128))> = find!(
        (h: TextHandle, ts: (i128, i128)),
        pattern!(space, [{
            _?event @
            metadata::tag: &KIND_NOTE_ID,
            compass::task: &goal_id,
            compass::note: ?h,
            metadata::created_at: ?ts,
        }])
    )
    .collect();
    let mut notes: Vec<(Option<i128>, String)> = raw
        .into_iter()
        .map(|(h, ts)| (Some(ts.0), read_text(ws, h).unwrap_or_default()))
        .collect();
    notes.sort_by(|a, b| b.0.cmp(&a.0));
    notes
}

/// Extract candidate fragment references from note bodies: every
/// 32-hex id, in order of first appearance, deduped, minus the goal's
/// own id. See [`hex32_regex`] for why this is a regex and not an edge.
fn referenced_ids(notes: &[(Option<i128>, String)], goal_id: Id) -> Vec<Id> {
    let mut seen: HashSet<Id> = HashSet::new();
    let mut out = Vec::new();
    for (_, body) in notes {
        for m in hex32_regex().find_iter(body) {
            if let Some(id) = Id::from_hex(m.as_str()) {
                if id != goal_id && seen.insert(id) {
                    out.push(id);
                }
            }
        }
    }
    out
}

/// Resolve a referenced id against the wiki: the id may be a fragment
/// id or one of its version ids. Returns (fragment_id, latest_version).
fn resolve_wiki_fragment(wiki_space: &TribleSet, id: Id) -> Option<(Id, Id)> {
    // Fragment id? (has at least one version pointing at it)
    let is_fragment = find!(
        vid: Id,
        pattern!(wiki_space, [{
            ?vid @
            metadata::tag: &KIND_VERSION_ID,
            wiki::fragment: &id,
        }])
    )
    .next()
    .is_some();
    let frag = if is_fragment {
        id
    } else {
        // Version id? — hop to its fragment.
        find!(frag: Id, pattern!(wiki_space, [{ id @ wiki::fragment: ?frag }])).next()?
    };
    let latest = find!(
        (vid: Id, ts: (i128, i128)),
        pattern!(wiki_space, [{
            ?vid @
            metadata::tag: &KIND_VERSION_ID,
            wiki::fragment: &frag,
            metadata::created_at: ?ts,
        }])
    )
    .max_by_key(|(_, ts)| ts.0)
    .map(|(vid, _)| vid)?;
    Some((frag, latest))
}

/// Decisions whose about-edge points at the goal (see
/// `schemas/decide.rs` + `src/bin/decide.rs`: `decide propose --about
/// <goal-id>` writes `decide::about`).
fn decisions_about(space: &TribleSet, goal_id: Id) -> Vec<Id> {
    let mut ids: Vec<Id> = find!(
        d: Id,
        pattern!(space, [{
            ?d @
            metadata::tag: &KIND_DECISION,
            decide_attrs::about: &goal_id,
        }])
    )
    .collect();
    ids.sort();
    ids
}

/// One-liner texts of a decision's factors of `kind`, oldest-first.
fn decision_factors(
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
    decision_id: Id,
    kind: Id,
) -> Vec<String> {
    let rows: Vec<(TextHandle, (i128, i128))> = find!(
        (h: TextHandle, ts: (i128, i128)),
        pattern!(space, [{
            _?f @
            metadata::tag: &kind,
            factor::about_decision: &decision_id,
            metadata::name: ?h,
            metadata::created_at: ?ts,
        }])
    )
    .collect();
    let mut rows = rows;
    rows.sort_by_key(|(_, ts)| ts.0);
    rows.into_iter()
        .map(|(h, _)| read_text(ws, h).unwrap_or_else(|| "(unnamed)".into()))
        .collect()
}

// ── Widget ───────────────────────────────────────────────────────────

/// GORBIE-embeddable review bench. See the module docs.
pub struct ReviewPanel {
    live: Option<ReviewLive>,
}

impl Default for ReviewPanel {
    fn default() -> Self {
        Self { live: None }
    }
}

impl ReviewPanel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Render the bench. `compass_ws` is required (the bench is a view
    /// over compass goals); `wiki_ws` / `decide_ws` are optional — when
    /// absent, referenced fragments / linked decisions simply don't
    /// resolve. READ-ONLY: no commits, no pushes.
    pub fn render(
        &mut self,
        ctx: &mut CardCtx<'_>,
        compass_ws: &mut Workspace<Pile>,
        mut wiki_ws: Option<&mut Workspace<Pile>>,
        decide_ws: Option<&mut Workspace<Pile>>,
    ) {
        let mut decide_ws = decide_ws;
        let compass_head = compass_ws.head();
        let wiki_head = wiki_ws.as_ref().and_then(|ws| ws.head());
        let decide_head = decide_ws.as_ref().and_then(|ws| ws.head());
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => {
                l.compass_head != compass_head
                    || l.wiki_head != wiki_head
                    || l.decide_head != decide_head
            }
        };
        if need_refresh {
            self.live = Some(ReviewLive::refresh(
                compass_ws,
                wiki_ws.as_deref_mut(),
                decide_ws.as_deref_mut(),
            ));
        }
        let Some(live) = self.live.as_ref() else { return };

        let goals = review_goals(&live.compass_space);
        let now = now_tai_ns();

        ctx.section("Review", |ctx| {
            // Header count line.
            {
                let ui = ctx.ui_mut();
                let n = goals.len();
                ui.label(
                    egui::RichText::new(format!(
                        "{n} GOAL{} IN REVIEW",
                        if n == 1 { "" } else { "S" }
                    ))
                    .monospace()
                    .strong()
                    .small()
                    .color(color_muted(ui)),
                );
            }

            if goals.is_empty() {
                let ui = ctx.ui_mut();
                ui.add_space(16.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        egui::RichText::new("\u{2705}") // ✅
                            .size(28.0)
                            .color(color_muted(ui)),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new("Nothing awaiting review.")
                            .monospace()
                            .small()
                            .strong()
                            .color(color_muted(ui)),
                    );
                    ui.add_space(2.0);
                    ui.label(
                        egui::RichText::new(
                            "Goals moved to status \"review\" via `compass move` land here.",
                        )
                        .small()
                        .color(color_muted(ui)),
                    );
                });
                ui.add_space(16.0);
                return;
            }

            for &(goal_id, entered_at) in &goals {
                let title = goal_title(&live.compass_space, compass_ws, goal_id);
                let title_line = title.lines().next().unwrap_or("").trim();
                // Include the id prefix in the section title so two
                // same-titled goals don't share a persisted fold state.
                let header = format!(
                    "{} · {}",
                    if title_line.is_empty() { "(untitled)" } else { title_line },
                    &fmt_id(goal_id)[..8],
                );
                // Per-goal collapsed-by-default section — inherits the
                // notebook-wide `set_default_section_open(false)`
                // dashboard default (headless captures force open).
                ctx.section(&header, |ctx| {
                    render_goal(
                        ctx,
                        live,
                        goal_id,
                        entered_at,
                        now,
                        compass_ws,
                        wiki_ws.as_deref_mut(),
                        decide_ws.as_deref_mut(),
                    );
                });
            }
        });
    }
}

// ── Per-goal rendering ───────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn render_goal(
    ctx: &mut CardCtx<'_>,
    live: &ReviewLive,
    goal_id: Id,
    entered_at: i128,
    now: i128,
    compass_ws: &mut Workspace<Pile>,
    mut wiki_ws: Option<&mut Workspace<Pile>>,
    mut decide_ws: Option<&mut Workspace<Pile>>,
) {
    let tags = goal_tags(&live.compass_space, goal_id);
    let created_at = goal_created_at(&live.compass_space, goal_id);
    let notes = goal_notes(&live.compass_space, compass_ws, goal_id);
    let refs = referenced_ids(&notes, goal_id);
    let decisions = decisions_about(&live.decide_space, goal_id);

    ctx.grid(|g| {
        // Meta row: id · ages · tags.
        g.full(|ctx| {
            let ui = ctx.ui_mut();
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = egui::vec2(6.0, 4.0);
                ui.label(
                    egui::RichText::new(fmt_id(goal_id))
                        .monospace()
                        .small()
                        .color(color_muted(ui)),
                );
                ui.label(
                    egui::RichText::new(format!(
                        "IN REVIEW {} · CREATED {}",
                        format_age(now, Some(entered_at)),
                        format_age(now, created_at),
                    ))
                    .monospace()
                    .small()
                    .strong()
                    .color(color_muted(ui)),
                );
                for tag in &tags {
                    render_chip(
                        ui,
                        &format!("#{tag}"),
                        colorhash::ral_categorical(tag.as_bytes()),
                    );
                }
            });
        });

        // ── Notes ──
        g.full(|ctx| {
            let ui = ctx.ui_mut();
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(format!("NOTES ({})", notes.len()))
                    .monospace()
                    .strong()
                    .small()
                    .color(color_muted(ui)),
            );
        });
        if notes.is_empty() {
            g.full(|ctx| {
                let ui = ctx.ui_mut();
                ui.label(
                    egui::RichText::new("no notes")
                        .small()
                        .color(color_muted(ui)),
                );
            });
        }
        for (at, body) in &notes {
            let at = *at;
            g.full(|ctx| {
                let ui = ctx.ui_mut();
                paper_frame(ui)
                    .inner_margin(egui::Margin {
                        left: 8,
                        right: 6,
                        top: 4,
                        bottom: 4,
                    })
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(
                            egui::RichText::new(format_age(now, at))
                                .small()
                                .monospace()
                                .color(color_muted(ui)),
                        );
                        ui.add(
                            egui::Label::new(egui::RichText::new(body).small())
                                .wrap_mode(egui::TextWrapMode::Wrap),
                        );
                    });
                ui.add_space(3.0);
            });
        }

        // ── Referenced wiki fragments ──
        if !refs.is_empty() {
            g.full(|ctx| {
                let ui = ctx.ui_mut();
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(format!("REFERENCES ({})", refs.len()))
                        .monospace()
                        .strong()
                        .small()
                        .color(color_muted(ui)),
                );
            });
        }
        for rid in &refs {
            let rid = *rid;
            match resolve_wiki_fragment(&live.wiki_space, rid) {
                Some((frag_id, vid)) => {
                    let title = find!(
                        h: TextHandle,
                        pattern!(&live.wiki_space, [{ vid @ wiki::title: ?h }])
                    )
                    .next()
                    .and_then(|h| {
                        wiki_ws.as_deref_mut().and_then(|ws| read_text(ws, h))
                    })
                    .unwrap_or_default();
                    let content = find!(
                        h: TextHandle,
                        pattern!(&live.wiki_space, [{ vid @ wiki::content: ?h }])
                    )
                    .next()
                    .and_then(|h| {
                        wiki_ws.as_deref_mut().and_then(|ws| read_text(ws, h))
                    })
                    .unwrap_or_default();
                    g.full(move |ctx| {
                        let frag_col = colorhash::ral_categorical(frag_id.as_ref());
                        {
                            let ui = ctx.ui_mut();
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 8.0;
                                let (dot_rect, _) = ui.allocate_exact_size(
                                    egui::vec2(10.0, 10.0),
                                    egui::Sense::hover(),
                                );
                                ui.painter().circle_filled(dot_rect.center(), 5.0, frag_col);
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(&title).strong(),
                                    )
                                    .wrap(),
                                );
                                ui.label(
                                    egui::RichText::new(format!("wiki:{}", fmt_id(frag_id)))
                                        .monospace()
                                        .small()
                                        .color(frag_col),
                                );
                            });
                        }
                        // Reuse the wiki widget's typst rendering path
                        // (incl. wiki:/files: link interception so egui
                        // doesn't try to shell-open them). The bench is
                        // an auditing surface — clicks are swallowed;
                        // open the wiki section to navigate.
                        let _ = render_wiki_content(ctx, &content);
                        ctx.ui_mut().add_space(6.0);
                    });
                }
                None => {
                    g.full(move |ctx| {
                        let ui = ctx.ui_mut();
                        ui.label(
                            egui::RichText::new(format!(
                                "{} — not a wiki fragment (goal/decision id or dangling)",
                                fmt_id(rid)
                            ))
                            .monospace()
                            .small()
                            .color(color_muted(ui)),
                        );
                    });
                }
            }
        }

        // ── Linked decisions ──
        if !decisions.is_empty() {
            g.full(|ctx| {
                let ui = ctx.ui_mut();
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(format!("DECISIONS ({})", decisions.len()))
                        .monospace()
                        .strong()
                        .small()
                        .color(color_muted(ui)),
                );
            });
        }
        for did in &decisions {
            let did = *did;
            let title = find!(
                h: TextHandle,
                pattern!(&live.decide_space, [{
                    did @ metadata::tag: &KIND_DECISION, metadata::name: ?h,
                }])
            )
            .next()
            .and_then(|h| decide_ws.as_deref_mut().and_then(|ws| read_text(ws, h)))
            .unwrap_or_else(|| "(untitled)".to_string());
            let outcome = find!(
                h: TextHandle,
                pattern!(&live.decide_space, [{
                    did @ metadata::tag: &KIND_DECISION, decide_attrs::outcome: ?h,
                }])
            )
            .next()
            .and_then(|h| decide_ws.as_deref_mut().and_then(|ws| read_text(ws, h)));
            let finished = find!(
                ts: (i128, i128),
                pattern!(&live.decide_space, [{
                    did @ metadata::tag: &KIND_DECISION, metadata::finished_at: ?ts,
                }])
            )
            .next()
            .is_some();
            let pros = match decide_ws.as_deref_mut() {
                Some(ws) => decision_factors(&live.decide_space, ws, did, KIND_PRO),
                None => Vec::new(),
            };
            let cons = match decide_ws.as_deref_mut() {
                Some(ws) => decision_factors(&live.decide_space, ws, did, KIND_CON),
                None => Vec::new(),
            };
            let resolved =
                finished && outcome.as_deref().map_or(false, |o| !o.trim().is_empty());

            g.full(move |ctx| {
                let ui = ctx.ui_mut();
                paper_frame(ui)
                    .inner_margin(egui::Margin {
                        left: 8,
                        right: 8,
                        top: 6,
                        bottom: 6,
                    })
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing.x = 6.0;
                            ui.label(egui::RichText::new(&title).strong());
                            let (label, fill) = if resolved {
                                ("RESOLVED", color_resolved())
                            } else {
                                ("PROPOSED", color_muted(ui))
                            };
                            render_chip(ui, label, fill);
                            ui.label(
                                egui::RichText::new(fmt_id(did))
                                    .monospace()
                                    .small()
                                    .color(color_muted(ui)),
                            );
                        });
                        ui.add_space(4.0);
                        ui.columns(2, |cols| {
                            render_factor_column(&mut cols[0], "PROS", color_pro(), &pros);
                            render_factor_column(&mut cols[1], "CONS", color_con(), &cons);
                        });
                        if let Some(outcome) = outcome.as_deref() {
                            if !outcome.trim().is_empty() {
                                ui.add_space(4.0);
                                ui.separator();
                                ui.label(
                                    egui::RichText::new("OUTCOME")
                                        .monospace()
                                        .small()
                                        .strong()
                                        .color(color_resolved()),
                                );
                                ui.add(
                                    egui::Label::new(egui::RichText::new(outcome).small())
                                        .wrap_mode(egui::TextWrapMode::Wrap),
                                );
                            }
                        }
                    });
                ui.add_space(3.0);
            });
        }
    });
}

fn render_factor_column(
    ui: &mut egui::Ui,
    heading: &str,
    accent: egui::Color32,
    factors: &[String],
) {
    ui.vertical(|ui| {
        ui.label(
            egui::RichText::new(heading)
                .monospace()
                .strong()
                .small()
                .color(accent),
        );
        if factors.is_empty() {
            ui.label(
                egui::RichText::new("\u{2014}") // em dash
                    .small()
                    .color(color_muted(ui)),
            );
            return;
        }
        for f in factors {
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                ui.label(egui::RichText::new("\u{2022}").small().color(accent));
                ui.add(
                    egui::Label::new(egui::RichText::new(f).small())
                        .wrap_mode(egui::TextWrapMode::Wrap),
                );
            });
        }
    });
}
