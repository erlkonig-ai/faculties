//! Full-featured GORBIE-embeddable compass (kanban) board widget.
//!
//! Renders goals from a triblespace pile's `compass` branch grouped into
//! kanban columns by their latest status (default: todo / doing / blocked /
//! review / done). The widget holds only UI + cached-query state; the host is
//! responsible for pulling the compass branch and passing the workspace
//! in at render time. Writes go through `Workspace::commit(..)`; pushing
//! is the host's responsibility (e.g. via
//! [`StorageState::push`](crate::widgets::StorageState::push)).
//!
//! Features beyond read-only display:
//!
//! - Composing new goals (title, tags, optional parent, initial status)
//! - Moving a goal to a new status (click a goal card → pick a status)
//! - Adding notes to an expanded goal
//! - Parent/child indentation with a collapse toggle per subtree
//! - Priority arrows: `board::higher` / `board::lower` edges rendered as
//!   `> over <id_str>` badges on the card
//! - Tag chips colored via `GORBIE::themes::colorhash::ral_categorical`.
//!
//! ```ignore
//! let mut board = CompassBoard::default();
//! // Inside a GORBIE card, with `compass_ws`:
//! board.render(ctx, compass_ws);
//! ```

use std::collections::{BTreeMap, HashMap, HashSet};

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;
use GORBIE::widgets::ChoiceToggle;
use triblespace::core::id::Id;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{CommitHandle, Workspace};
use triblespace::core::trible::TribleSet;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::Inline;
use triblespace::macros::{find, pattern};
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::View;

use crate::schemas::compass::{
    board as compass, DEFAULT_STATUSES, KIND_GOAL_ID, KIND_NOTE_ID, KIND_PRIORITIZE_ID,
    KIND_STATUS_ID,
};

/// Handle to a long-string blob (titles, notes).
type TextHandle = Inline<Handle<LongString>>;

// ── ID / time helpers ────────────────────────────────────────────────

fn fmt_id_full(id: Id) -> String {
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

// ── Color palette (RAL-inspired, matches playground diagnostics) ────

fn color_todo() -> egui::Color32 {
    egui::Color32::from_rgb(0x57, 0xa6, 0x39) // RAL 6018
}
fn color_doing() -> egui::Color32 {
    egui::Color32::from_rgb(0xf7, 0xba, 0x0b) // RAL 1003
}
fn color_blocked() -> egui::Color32 {
    egui::Color32::from_rgb(0xcc, 0x0a, 0x17) // RAL 3020
}
fn color_review() -> egui::Color32 {
    egui::Color32::from_rgb(0x92, 0x45, 0x92) // RAL 4008
}
fn color_done() -> egui::Color32 {
    egui::Color32::from_rgb(0x15, 0x4e, 0xa1) // RAL 5005
}
// Theme-adaptive neutrals. The status colors (todo/doing/blocked/review/
// done) are legible on both light and dark backgrounds, but the
// frame / card / muted colors need to flip with the theme — hard-
// coded dark shades turned into "dark on dark" (body text uses
// egui's theme-aware color, which is dark in light mode).

/// Muted mid-grey for secondary labels, borders, and separators.
fn color_muted(ui: &egui::Ui) -> egui::Color32 {
    if ui.visuals().dark_mode {
        egui::Color32::from_rgb(0x9a, 0x9a, 0x9a)
    } else {
        egui::Color32::from_rgb(0x6a, 0x6a, 0x6a)
    }
}

/// "Paper" frame recipe — matches GORBIE's float-card chrome
/// (`floating.rs::draw_card_chrome`): theme `window_fill` + thin
/// outline + hard offset shadow + sharp corners. Static-content
/// surfaces (lanes, goal cards, note bubbles) use this so they
/// read as paper sheets rather than backlit LCD blocks. Dynamic /
/// input widgets (count chips, +ADD button, status indicator,
/// edit fields) keep their existing styling.
fn paper_frame(ui: &egui::Ui, shadow_offset: i8) -> egui::Frame {
    let v = ui.visuals();
    let outline = v.widgets.noninteractive.bg_stroke.color;
    // Semi-transparent black shadow reads as a darker tint on both
    // light and dark panels; matches the float-chrome look without
    // hard-coding a value that disappears in dark mode.
    let shadow_color = egui::Color32::from_black_alpha(48);
    egui::Frame::NONE
        .fill(v.window_fill)
        .stroke(egui::Stroke::new(1.0, outline))
        .shadow(egui::epaint::Shadow {
            offset: [shadow_offset, shadow_offset],
            blur: 0,
            spread: 0,
            color: shadow_color,
        })
        .corner_radius(egui::CornerRadius::ZERO)
}

fn status_color(status: &str) -> egui::Color32 {
    match status {
        "todo" => color_todo(),
        "doing" => color_doing(),
        "blocked" => color_blocked(),
        "review" => color_review(),
        "done" => color_done(),
        // Mid-grey fallback — legible on both light and dark panels
        // without needing a `&Ui` argument.
        _ => egui::Color32::from_rgb(0x80, 0x80, 0x80),
    }
}

/// Deterministic color for a tag string via GORBIE's colorhash palette.
fn tag_color(tag: &str) -> egui::Color32 {
    colorhash::ral_categorical(tag.as_bytes())
}


/// Truncate `s` at char boundary to `max` chars, appending `…` if cut.
/// Char-aware so multibyte sequences don't panic on slice.
fn truncate_inline(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let take: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{take}…")
}

#[derive(Clone, Debug)]
struct NoteRow {
    at: Option<i128>,
    body: String,
}

// ── Cached compass query state ───────────────────────────────────────

/// Holds a cached fact space for the compass branch plus a head marker.
/// Queries run against `space`; writes take a `&mut Workspace<Pile>` from
/// the host and call `ws.commit(..)`. Push is the host's concern.
struct CompassLive {
    space: TribleSet,
    cached_head: Option<CommitHandle>,
}

impl CompassLive {
    fn refresh(ws: &mut Workspace<Pile>) -> Self {
        let space = ws
            .checkout(..)
            .map(|co| co.into_facts())
            .unwrap_or_else(|e| {
                eprintln!("[compass] checkout: {e:?}");
                TribleSet::new()
            });
        Self {
            space,
            cached_head: ws.head(),
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

    /// Notes on a specific goal, sorted newest-first.
    fn notes_for(&self, ws: &mut Workspace<Pile>, goal_id: Id) -> Vec<NoteRow> {
        let raw: Vec<(TextHandle, (i128, i128))> = find!(
            (note_handle: TextHandle, ts: (i128, i128)),
            pattern!(&self.space, [{
                _?event @
                metadata::tag: &KIND_NOTE_ID,
                compass::task: &goal_id,
                compass::note: ?note_handle,
                metadata::created_at: ?ts,
            }])
        )
        .collect();

        let mut notes: Vec<NoteRow> = raw
            .into_iter()
            .map(|(h, ts)| NoteRow {
                at: Some(ts.0),
                body: self.text(ws, h),
            })
            .collect();
        notes.sort_by(|a, b| b.at.cmp(&a.at));
        notes
    }

}

// ── Tree layout ──────────────────────────────────────────────────────

/// Depth-first walk through the parent/child forest induced by a
/// goal's `compass::parent` edges, restricted to the lane's id set.
/// Goals whose parent isn't in the lane are treated as roots; the
/// caller has already sorted the lane in display order so the
/// children-by-parent buckets inherit that order.
fn order_rows(lane_ids: Vec<Id>, space: &TribleSet) -> Vec<(Id, usize)> {
    let ids: HashSet<Id> = lane_ids.iter().copied().collect();
    let mut children: HashMap<Id, Vec<Id>> = HashMap::new();
    let mut has_visible_parent: HashSet<Id> = HashSet::new();

    // Iterate the lane in caller-given order so that pushing into
    // `children` and the root set preserves that ordering.
    for &gid in &lane_ids {
        let parent = find!(
            (parent: Id),
            pattern!(space, [{
                gid @
                metadata::tag: &KIND_GOAL_ID,
                compass::parent: ?parent,
            }])
        )
        .next()
        .map(|(p,)| p);
        if let Some(parent) = parent {
            if ids.contains(&parent) {
                children.entry(parent).or_default().push(gid);
                has_visible_parent.insert(gid);
            }
        }
    }

    let mut ordered = Vec::new();
    let mut visited = HashSet::new();

    fn walk(
        id: Id,
        depth: usize,
        children: &HashMap<Id, Vec<Id>>,
        visited: &mut HashSet<Id>,
        out: &mut Vec<(Id, usize)>,
    ) {
        if !visited.insert(id) {
            return;
        }
        out.push((id, depth));
        if let Some(kids) = children.get(&id) {
            for kid in kids {
                walk(*kid, depth + 1, children, visited, out);
            }
        }
    }

    for id in &lane_ids {
        if !has_visible_parent.contains(id) {
            walk(*id, 0, &children, &mut visited, &mut ordered);
        }
    }
    // Any unvisited (e.g. parent cycle) goals get a depth-0 fallback.
    for id in &lane_ids {
        if !visited.contains(id) {
            walk(*id, 0, &children, &mut visited, &mut ordered);
        }
    }
    ordered
}

/// True if the goal matches the (lowercased) search needle in any of:
/// its full hex id, its title body, or any of its tags. Substring match;
/// case-insensitive (caller lowercases). Each piece is a per-goal query
/// — single-digit µs each per JP's measurement.
fn goal_matches_search(
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
    goal_id: Id,
    needle: &str,
) -> bool {
    if fmt_id_full(goal_id).contains(needle) {
        return true;
    }
    if let Some((handle,)) = find!(
        (t: TextHandle),
        pattern!(space, [{
            goal_id @
            metadata::tag: &KIND_GOAL_ID,
            compass::title: ?t,
        }])
    )
    .next()
    {
        if let Ok(v) = ws.get::<View<str>, LongString>(handle) {
            if v.as_ref().to_lowercase().contains(needle) {
                return true;
            }
        }
    }
    for (tag,) in find!(
        (tag: String),
        pattern!(space, [{
            goal_id @
            metadata::tag: &KIND_GOAL_ID,
            compass::tag: ?tag,
        }])
    ) {
        if tag.to_lowercase().contains(needle) {
            return true;
        }
    }
    false
}

/// Shape the input goal set into a render stream according to the
/// active axis. The renderer is agnostic to the axis — it just iterates
/// `RenderItem`s and dispatches on the variant.
fn produce_items(
    axis: SortAxis,
    goals: Vec<(Id, String, i128)>,
    space: &TribleSet,
) -> Vec<RenderItem> {
    let mut sorted = goals;
    // Most-recently-changed first across all axes; this is the
    // baseline order before any axis-specific re-shape.
    sorted.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));

    match axis {
        SortAxis::Status => {
            // Cluster by status — DEFAULT_STATUSES first, extras
            // alphabetical. Within each lane keep the global sort_at
            // order, then run the parent forest so children sit under
            // visible parents.
            let mut by_status: BTreeMap<String, Vec<(Id, i128)>> = BTreeMap::new();
            for (id, status, sort_at) in sorted {
                by_status.entry(status).or_default().push((id, sort_at));
            }
            let mut columns: Vec<String> =
                DEFAULT_STATUSES.iter().map(|s| s.to_string()).collect();
            let mut extras: Vec<String> = by_status
                .keys()
                .filter(|s| !DEFAULT_STATUSES.contains(&s.as_str()))
                .cloned()
                .collect();
            extras.sort();
            columns.extend(extras);

            let mut items = Vec::new();
            for status in columns {
                let lane = by_status.remove(&status).unwrap_or_default();
                let ids: Vec<Id> = lane.into_iter().map(|(id, _)| id).collect();
                for (id, depth) in order_rows(ids, space) {
                    items.push(RenderItem {
                        id,
                        status: status.clone(),
                        depth,
                    });
                }
            }
            items
        }
        SortAxis::Age => sorted
            .into_iter()
            .map(|(id, status, _)| RenderItem {
                id,
                status,
                depth: 0,
            })
            .collect(),
        SortAxis::Parent => {
            let id_status: HashMap<Id, String> =
                sorted.iter().map(|(id, s, _)| (*id, s.clone())).collect();
            let ids: Vec<Id> = sorted.into_iter().map(|(id, _, _)| id).collect();
            order_rows(ids, space)
                .into_iter()
                .map(|(id, depth)| {
                    let status = id_status
                        .get(&id)
                        .cloned()
                        .unwrap_or_else(|| "todo".to_string());
                    RenderItem { id, status, depth }
                })
                .collect()
        }
    }
}

// ── Widget ───────────────────────────────────────────────────────────

/// GORBIE-embeddable kanban-style compass board.
///
/// Full-featured: supports composing goals, moving status, adding notes,
/// parent/child nesting with per-subtree collapse, priority arrow badges,
/// and colorhashed tag chips. See the module docs for details.
///
/// ```ignore
/// let mut board = CompassBoard::default();
/// // Inside a GORBIE card, with `compass_ws`:
/// board.render(ctx, compass_ws);
/// ```
/// Axis the user picks to organise the goal list. Switching the axis
/// re-shapes the rendered stream but doesn't touch the underlying data —
/// status (per-card colored stripe) is shown regardless.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SortAxis {
    /// Group into status sections, tree-walked within each section.
    #[default]
    Status,
    /// Flat list, most-recently-changed first.
    Age,
    /// Global parent/child forest, root-first DFS.
    Parent,
}

/// One element of the rendered goal stream. The axis chooses which
/// items to emit and in which order; cards carry their own status
/// (per-card colored stripe), so no header item is needed.
struct RenderItem {
    id: Id,
    status: String,
    depth: usize,
}

pub struct CompassBoard {
    /// Rebuilt when the workspace's head advances.
    live: Option<CompassLive>,
    expanded_goal: Option<Id>,
    /// Goals whose children should be hidden (parent-node collapsed).
    collapsed: HashSet<Id>,
    /// Active sort/group axis (user-selectable).
    axis: SortAxis,
}

impl Default for CompassBoard {
    fn default() -> Self {
        Self {
            live: None,
            expanded_goal: None,
            collapsed: HashSet::new(),
            axis: SortAxis::default(),
        }
    }
}

impl CompassBoard {
    /// Build a board with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Render the board into a GORBIE card context. `ws` must point at
    /// the compass branch.
    pub fn render(&mut self, ctx: &mut CardCtx<'_>, ws: &mut Workspace<Pile>) {
        // Refresh cached state if the workspace head has advanced.
        let head = ws.head();
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => l.cached_head != head,
        };
        if need_refresh {
            self.live = Some(CompassLive::refresh(ws));
        }
        let live = self.live.as_ref().expect("refreshed above");

        // Top-level query: latest status per goal, then enumerate every
        // goal as (id, effective_status, sort_at). No row struct — the
        // renderer reads what it needs from the tribleset inline.
        let space = &live.space;
        let mut latest_status: HashMap<Id, (String, i128)> = HashMap::new();
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
            match latest_status.get_mut(&gid) {
                Some(slot) if slot.1 < ts.0 => *slot = (status, ts.0),
                Some(_) => {}
                None => {
                    latest_status.insert(gid, (status, ts.0));
                }
            }
        }

        let mut goals: Vec<(Id, String, i128)> = Vec::new();
        for (gid, _t, created) in find!(
            (gid: Id, _t: TextHandle, created: (i128, i128)),
            pattern!(space, [{
                ?gid @
                metadata::tag: &KIND_GOAL_ID,
                compass::title: ?_t,
                metadata::created_at: ?created,
            }])
        ) {
            let (status, sort_at) = match latest_status.get(&gid) {
                Some((s, t)) => (s.clone(), *t),
                None => ("todo".to_string(), created.0),
            };
            goals.push((gid, status, sort_at));
        }

        // Per-status counts for the section header chips.
        let mut status_counts: BTreeMap<String, usize> = BTreeMap::new();
        for (_, status, _) in &goals {
            *status_counts.entry(status.clone()).or_insert(0) += 1;
        }

        let axis = self.axis;
        let items = produce_items(axis, goals, space);
        let total_goals: usize = items.len();

        // Compute the per-card collapsed-ancestors set once over the
        // global item stream — a Card whose any depth-ancestor is in
        // `self.collapsed` is hidden. Tree boundaries between status
        // groups are implicit: when a lane resets to depth 0 the path
        // pops to empty before pushing.
        let ancestors_collapsed: HashSet<Id> = {
            let mut hidden: HashSet<Id> = HashSet::new();
            let mut path: Vec<(Id, usize)> = Vec::new();
            for item in &items {
                while path.last().map(|(_, d)| *d >= item.depth).unwrap_or(false) {
                    path.pop();
                }
                let parent_hidden = path
                    .iter()
                    .any(|(pid, _)| hidden.contains(pid) || self.collapsed.contains(pid));
                if parent_hidden {
                    hidden.insert(item.id);
                }
                path.push((item.id, item.depth));
            }
            hidden
        };

        // Resolve expanded goal's notes (if any).
        let expanded = self.expanded_goal;
        let expanded_notes: Option<(Id, Vec<NoteRow>)> = expanded.map(|gid| {
            let notes = live.notes_for(ws, gid);
            (gid, notes)
        });

        // Mutable handles to self state we need inside the closure.
        // The viewer is read-only — view state (expansion, collapse,
        // axis selection) is the only thing that mutates.
        let expanded_goal = &mut self.expanded_goal;
        let collapsed = &mut self.collapsed;
        let axis_ref = &mut self.axis;
        // Borrow the live tribleset so renderers can run on-the-spot
        // queries instead of reading hydrated row fields.
        let space = &live.space;

        ctx.section("Compass", |ctx| {
            // Header: total + per-status breakdown as small colored
            // chips. The chips are a mini-legend for the colored
            // accent stripes on each card.
            let ui = ctx.ui_mut();
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                ui.label(
                    egui::RichText::new(format!("{total_goals} GOALS"))
                        .monospace()
                        .strong()
                        .small()
                        .color(color_muted(ui)),
                );
                ui.label(
                    egui::RichText::new("\u{00b7}")
                        .small()
                        .color(color_muted(ui)),
                );
                for (status, count) in &status_counts {
                    if *count == 0 {
                        continue;
                    }
                    let (dot, _) = ui.allocate_exact_size(
                        egui::vec2(8.0, 8.0),
                        egui::Sense::hover(),
                    );
                    ui.painter().circle_filled(dot.center(), 3.5, status_color(status));
                    ui.label(
                        egui::RichText::new(status.to_uppercase())
                            .monospace()
                            .strong()
                            .small(),
                    );
                    ui.label(
                        egui::RichText::new(count.to_string())
                            .monospace()
                            .small()
                            .color(color_muted(ui)),
                    );
                }
            });

            // Toolbar row: axis selector (segmented selector with a lit
            // active segment) + global +ADD button. Status grouping is
            // implicit via the per-card stripes; adding a goal is one
            // global action with status chosen inside the form.
            ctx.horizontal(|ctx| {
                let ui = ctx.ui_mut();
                ui.label(
                    egui::RichText::new("GROUP")
                        .small()
                        .monospace()
                        .strong()
                        .color(color_muted(ui)),
                );
                ui.add(
                    ChoiceToggle::new(axis_ref)
                        .choice(SortAxis::Status, "BY STATUS")
                        .choice(SortAxis::Age, "BY AGE")
                        .choice(SortAxis::Parent, "BY PARENT"),
                );
            });

            // Notebook-wide search — opt-in. `ctx.search()` makes the
            // global search bar appear and lets us report matches back
            // so the bar can show counts + drive prev/next navigation.
            let mut search = ctx.search();
            let needle = search.query().to_lowercase();
            let search_active = !needle.is_empty();

            if total_goals == 0 {
                render_empty_state(
                    ctx.ui_mut(),
                    "\u{1f9ed}",
                    "No goals yet",
                    Some("Add goals via `compass add` on the CLI."),
                );
            }

            // Card grid — one card per row (full 12-column width ≈
            // 744 px). Cards have the room to breathe; depth still
            // visualized by the internal dep-line gutter and the
            // content shift.
            let mut card_rects: HashMap<Id, egui::Rect> = HashMap::new();
            ctx.grid(|g| {
                for item in &items {
                    if ancestors_collapsed.contains(&item.id) {
                        continue;
                    }
                    let match_info = if search_active {
                        if !goal_matches_search(space, ws, item.id, &needle) {
                            continue;
                        }
                        Some(search.report(egui::Id::new(("compass_match", item.id))))
                    } else {
                        None
                    };
                    let id = item.id;
                    let status_str = item.status.as_str();
                    let depth = item.depth;
                    g.full(|cell_ctx| {
                        render_goal_card(
                            cell_ctx.ui_mut(),
                            id,
                            status_str,
                            depth,
                            space,
                            ws,
                            expanded_goal,
                            expanded_notes.as_ref(),
                            collapsed,
                            &mut card_rects,
                            &needle,
                        );
                        if let Some(info) = match_info {
                            if info.should_scroll_to {
                                if let Some(rect) = card_rects.get(&id) {
                                    cell_ctx
                                        .ui_mut()
                                        .scroll_to_rect(*rect, Some(egui::Align::Center));
                                }
                            }
                        }
                    });
                }
            });

            // Priority-edge overlay — iterate cards in the item stream.
            let painter = ctx.ui_mut().painter().clone();
            for item in &items {
                let Some(from_rect) = card_rects.get(&item.id) else {
                    continue;
                };
                let base = status_color(&item.status);
                let edge_color = egui::Color32::from_rgba_unmultiplied(
                    base.r(),
                    base.g(),
                    base.b(),
                    200,
                );
                let higher_id = item.id;
                for (lower,) in find!(
                    (lower: Id),
                    pattern!(space, [{
                        _?event @
                        metadata::tag: &KIND_PRIORITIZE_ID,
                        compass::higher: higher_id,
                        compass::lower: ?lower,
                    }])
                ) {
                    let Some(to_rect) = card_rects.get(&lower) else {
                        continue;
                    };
                    draw_priority_edge(&painter, *from_rect, *to_rect, edge_color);
                }
            }
        });

        // Read-only viewer: no writes to apply post-render.
        let _ = ws; // suppress unused-warning while ws stays in the signature
    }
}

// ── Card rendering ───────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn render_goal_card(
    ui: &mut egui::Ui,
    goal_id: Id,
    status: &str,
    depth: usize,
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
    expanded_goal: &mut Option<Id>,
    expanded_notes: Option<&(Id, Vec<NoteRow>)>,
    collapsed: &mut HashSet<Id>,
    card_rects: &mut HashMap<Id, egui::Rect>,
    // Lowercased search needle ("" = no search).
    search_needle: &str,
) {
    const DEP_LINE_STEP: f32 = 6.0;
    const DEP_LINE_BASE: f32 = 8.0;
    let dep_lines = depth.min(3);
    let dep_indent = if dep_lines == 0 {
        0.0
    } else {
        (dep_lines as f32 * DEP_LINE_STEP) + DEP_LINE_BASE
    };
    let id_str = fmt_id_full(goal_id);

    let is_expanded = *expanded_goal == Some(goal_id);
    let is_collapsed = collapsed.contains(&goal_id);

    // Depth indentation: the card frame itself shifts right by
    // `dep_indent`, narrowing the card and exposing a gutter on the
    // left of the cell for the dep-lines. Safe under the one-card-
    // per-row grid layout (no neighbouring cell to bleed into).
    let card_response = paper_frame(ui, 3)
        .outer_margin(egui::Margin {
            left: dep_indent as i8,
            right: 0,
            top: 0,
            bottom: 0,
        })
        .inner_margin(egui::Margin {
            left: 26,
            right: 8,
            top: 6,
            bottom: 6,
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());

            // Row 1: title · collapse triangle · short id. Status used
            // to be a chip here but the per-card accent stripe already
            // carries that info — keeping both was redundant.
            ui.horizontal(|ui| {
                // Collapse-subtree triangle, only shown when there are
                // visible children (we don't know here without the tree
                // snapshot, so show it always at depth=0 or higher — the
                // click is a no-op for leaves but is harmless).
                let tri = if is_collapsed { "▸" } else { "▾" };
                if ui
                    .add(
                        egui::Label::new(
                            egui::RichText::new(tri).monospace().color(color_muted(ui)),
                        )
                        .sense(egui::Sense::click()),
                    )
                    .clicked()
                {
                    if is_collapsed {
                        collapsed.remove(&goal_id);
                    } else {
                        collapsed.insert(goal_id);
                    }
                }

                if let Some((handle,)) = find!(
                    (t: TextHandle),
                    pattern!(space, [{
                        goal_id @
                        metadata::tag: &KIND_GOAL_ID,
                        compass::title: ?t,
                    }])
                )
                .next()
                {
                    if let Ok(v) = ws.get::<View<str>, LongString>(handle) {
                        let base = egui::TextFormat {
                            font_id: egui::TextStyle::Monospace.resolve(ui.style()),
                            color: ui.visuals().text_color(),
                            ..Default::default()
                        };
                        let job = GORBIE::search::highlight_match(
                            v.as_ref(),
                            search_needle,
                            base,
                        );
                        ui.add(egui::Label::new(job).wrap_mode(egui::TextWrapMode::Wrap));
                    }
                }
            });

            // Row 2: id prefix · optional parent pointer (left) · note
            // count chip (right). Note count lives on the right edge so
            // it reads like a metadata badge, not a continuation of the
            // id string.
            ui.horizontal(|ui| {
                let parent_id = find!(
                    (parent: Id),
                    pattern!(space, [{
                        goal_id @
                        metadata::tag: &KIND_GOAL_ID,
                        compass::parent: ?parent,
                    }])
                )
                .next()
                .map(|(p,)| p);
                let id_text = match parent_id {
                    Some(parent) => format!("^{} {}", fmt_id_full(parent), id_str),
                    None => id_str.clone(),
                };
                ui.label(
                    egui::RichText::new(id_text)
                        .monospace()
                        .small()
                        .color(color_muted(ui)),
                );
                let note_count = find!(
                    (event: Id),
                    pattern!(space, [{
                        ?event @
                        metadata::tag: &KIND_NOTE_ID,
                        compass::task: goal_id,
                    }])
                )
                .count();
                if note_count > 0 {
                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::Center),
                        |ui| {
                            render_chip(ui, &format!("{note_count}n"), color_muted(ui));
                        },
                    );
                }
            });

            // Row 3: priority edges + tags. Queried directly from the
            // tribleset rather than read from a hydrated row struct —
            // long names get truncated so a single chip can't overflow
            // the column. The wrapped block is unconditional; if both
            // queries are empty it's a near-zero-height no-op.
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = egui::vec2(4.0, 4.0);
                for (lower,) in find!(
                    (lower: Id),
                    pattern!(space, [{
                        _?event @
                        metadata::tag: &KIND_PRIORITIZE_ID,
                        compass::higher: goal_id,
                        compass::lower: ?lower,
                    }])
                ) {
                    let target_label = find!(
                        (t: TextHandle),
                        pattern!(space, [{
                            lower @
                            metadata::tag: &KIND_GOAL_ID,
                            compass::title: ?t,
                        }])
                    )
                    .next()
                    .and_then(|(h,)| ws.get::<View<str>, LongString>(h).ok())
                    .map(|v| truncate_inline(v.as_ref(), 16))
                    .unwrap_or_else(|| fmt_id_full(lower));
                    render_chip(
                        ui,
                        &format!("▲ {target_label}"),
                        egui::Color32::from_rgb(0x55, 0x3f, 0x7f),
                    );
                }
                for (tag,) in find!(
                    (tag: String),
                    pattern!(space, [{
                        goal_id @
                        metadata::tag: &KIND_GOAL_ID,
                        compass::tag: ?tag,
                    }])
                ) {
                    let tag_label = truncate_inline(&tag, 18);
                    render_chip(ui, &format!("#{tag_label}"), tag_color(&tag));
                }
            });
        })
        .response;

    // Whole card is clickable to toggle note expansion (view state).
    let click_id = ui.make_persistent_id(("compass_goal", goal_id));
    let response = ui.interact(card_response.rect, click_id, egui::Sense::click());
    if response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        response.clone().on_hover_text("Click to expand notes");
    }
    if response.clicked() {
        if *expanded_goal == Some(goal_id) {
            *expanded_goal = None;
        } else {
            *expanded_goal = Some(goal_id);
        }
    }

    if is_expanded {
        let notes: &[NoteRow] = expanded_notes
            .filter(|(gid, _)| *gid == goal_id)
            .map(|(_, n)| n.as_slice())
            .unwrap_or(&[]);
        egui::Frame::NONE
            .stroke(egui::Stroke::new(1.0, color_muted(ui)))
            .outer_margin(egui::Margin {
                left: dep_indent as i8,
                right: 0,
                top: 0,
                bottom: 0,
            })
            .inner_margin(egui::Margin::symmetric(8, 6))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());

                // Notes — rendered as their own small framed cards
                // with an age-chip header and a thin left-accent in
                // the goal's status color, so the note stream reads
                // like a timeline of annotations on this goal.
                let now = now_tai_ns();
                if notes.is_empty() {
                    ui.add_space(4.0);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            egui::RichText::new("NO NOTES YET")
                                .monospace()
                                .small()
                                .color(color_muted(ui)),
                        );
                    });
                    ui.add_space(4.0);
                } else {
                    let status_col = status_color(status);
                    for note in notes {
                        let note_resp = paper_frame(ui, 2)
                            .inner_margin(egui::Margin {
                                left: 8,
                                right: 6,
                                top: 4,
                                bottom: 4,
                            })
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.label(
                                    egui::RichText::new(format_age(now, note.at))
                                        .small()
                                        .monospace()
                                        .color(color_muted(ui)),
                                );
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(&note.body).small(),
                                    )
                                    .wrap_mode(egui::TextWrapMode::Wrap),
                                );
                            });
                        // Paint a 2-px status-colored accent on the
                        // note's left edge after layout.
                        let r = note_resp.response.rect;
                        let painter = ui.painter();
                        painter.rect_filled(
                            egui::Rect::from_min_size(
                                r.min,
                                egui::vec2(2.0, r.height()),
                            ),
                            0.0,
                            status_col,
                        );
                        ui.add_space(3.0);
                    }
                }
            });
        ui.add_space(4.0);
    }

    // Dependency gutter lines, one per visible ancestor, each drawn
    // at the ancestor's rendered left edge so the lines visually
    // anchor the indented child back to the column where its
    // ancestors live.
    // `card_response.rect` is the OUTER rect (includes outer_margin
    // padding). The visible frame is shifted right by `dep_indent`.
    // For dep-line positioning the outer rect's left edge IS the
    // un-indented column origin we want to anchor lines to.
    let outer_rect = card_response.rect;
    let frame_rect = egui::Rect::from_min_max(
        egui::pos2(outer_rect.left() + dep_indent, outer_rect.top()),
        outer_rect.max,
    );
    card_rects.insert(goal_id, frame_rect);
    let painter = ui.painter();
    let stroke = egui::Stroke::new(1.2, color_muted(ui));
    // Dep-lines anchor to the un-indented column (= outer_rect.left);
    // clamp to clip-edge so they don't fall outside the visible area.
    let column_left = outer_rect
        .left()
        .max(painter.clip_rect().left() + stroke.width * 0.5);
    for idx in 0..dep_lines {
        let ancestor_indent = if idx == 0 {
            0.0
        } else {
            (idx as f32 * DEP_LINE_STEP) + DEP_LINE_BASE
        };
        let x = column_left + ancestor_indent;
        let y1 = frame_rect.top() + 0.5;
        let y2 = frame_rect.bottom() - 0.5;
        painter.line_segment([egui::pos2(x, y1), egui::pos2(x, y2)], stroke);
    }

    // Per-card colored accent stripe on the left edge — wide enough
    // for the rotated status name to read cleanly. Insets by the
    // paper-frame's 1px outline stroke so the stroke draws around the
    // stripe (instead of being painted over). Replaces the old
    // per-lane stripe so each card carries its own status mark and
    // the renderer can drop status grouping entirely under non-Status
    // axes.
    const STRIPE_WIDTH: f32 = 18.0;
    const STROKE_INSET: f32 = 1.0;
    let stripe_color = status_color(status);
    // Stripe anchors to the VISIBLE FRAME (`frame_rect`), not the
    // outer rect — otherwise depth>0 cards would render the stripe
    // off in the outer_margin gutter region instead of attached to
    // the card.
    let stripe_rect = egui::Rect::from_min_size(
        frame_rect.min + egui::vec2(STROKE_INSET, STROKE_INSET),
        egui::vec2(STRIPE_WIDTH, frame_rect.height() - 2.0 * STROKE_INSET),
    );
    painter.rect_filled(stripe_rect, egui::CornerRadius::ZERO, stripe_color);
    // Status name on the stripe, rotated 90° clockwise so it reads
    // top-to-bottom. Skipped when the card's too short to fit the
    // glyphs (avoids text overflowing into the card body).
    let stripe_font = egui::FontId::monospace(9.0);
    let stripe_text_color = colorhash::text_color_on(stripe_color);
    let galley =
        painter.layout_no_wrap(status.to_uppercase(), stripe_font, stripe_text_color);
    if galley.size().x + 6.0 <= frame_rect.height() {
        // egui's `TextShape::angle` rotates the galley around `pos`.
        // For angle = +π/2 (vertices x ↦ -y, y ↦ x in screen-space),
        // the rotated text extends LEFT and DOWN from `pos`. So `pos`
        // needs to sit at the right edge of where the text should
        // appear in the stripe. Center horizontally by placing `pos`
        // at `stripe_left + (stripe_width + galley_height) / 2`.
        let gh = galley.size().y;
        let pos = egui::pos2(
            frame_rect.left() + STROKE_INSET + (STRIPE_WIDTH + gh) * 0.5,
            frame_rect.top() + STROKE_INSET + 5.0,
        );
        let mut text_shape = egui::epaint::TextShape::new(pos, galley, stripe_text_color);
        text_shape.angle = std::f32::consts::FRAC_PI_2;
        painter.add(text_shape);
    }
}

/// Paint a priority edge between two goal cards: a smooth horizontal
/// cubic Bézier from the higher card's side to the lower card's side
/// with a small filled arrowhead at the target. The horizontally-
/// tangent control points make the curve bow outward from the
/// straight line, which naturally keeps it clear of intervening
/// cards most of the time (much better than the old 3-segment path
/// that cut straight through).
fn draw_priority_edge(
    painter: &egui::Painter,
    from: egui::Rect,
    to: egui::Rect,
    color: egui::Color32,
) {
    let (start, end, dir) = if from.center().x < to.center().x {
        (
            egui::pos2(from.right(), from.center().y),
            egui::pos2(to.left() - 6.0, to.center().y),
            1.0_f32,
        )
    } else {
        (
            egui::pos2(from.left(), from.center().y),
            egui::pos2(to.right() + 6.0, to.center().y),
            -1.0_f32,
        )
    };
    // Control-point offset: ~half the horizontal gap, clamped so short
    // edges still bow visibly and long edges don't over-curve.
    let dx = (end.x - start.x).abs().max(40.0).min(240.0) * 0.5;
    let c1 = egui::pos2(start.x + dir * dx, start.y);
    let c2 = egui::pos2(end.x - dir * dx, end.y);
    let stroke = egui::Stroke::new(1.5, color);
    painter.add(egui::Shape::CubicBezier(egui::epaint::CubicBezierShape {
        points: [start, c1, c2, end],
        closed: false,
        fill: egui::Color32::TRANSPARENT,
        stroke: egui::epaint::PathStroke::new(stroke.width, stroke.color),
    }));
    // Arrowhead — small filled triangle at the target, pointing along
    // the curve's terminal tangent (which is horizontal here).
    let head_len = 6.0;
    let back_x = end.x - dir * head_len;
    let tip = end;
    let back = egui::pos2(back_x, end.y);
    let wing_up = egui::pos2(back_x, end.y - 3.5);
    let wing_dn = egui::pos2(back_x, end.y + 3.5);
    painter.add(egui::Shape::convex_polygon(
        vec![tip, wing_up, back, wing_dn],
        color,
        egui::Stroke::NONE,
    ));
}

/// Centered empty-state block: a muted glyph, a monospace headline,
/// and an optional muted sub-hint. Used when the board is empty and
/// the user needs a nudge toward the right action.
fn render_empty_state(ui: &mut egui::Ui, glyph: &str, headline: &str, hint: Option<&str>) {
    ui.add_space(16.0);
    ui.vertical_centered(|ui| {
        ui.label(
            egui::RichText::new(glyph)
                .size(28.0)
                .color(color_muted(ui)),
        );
        ui.add_space(4.0);
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
    ui.add_space(16.0);
}

fn render_chip(ui: &mut egui::Ui, label: &str, fill: egui::Color32) {
    // Bypass `egui::Frame::show` + `ui.label` here because both pad
    // their content to `ui.spacing.interact_size.y` (default ≈ 18 px),
    // which makes the chip far taller than the text it contains.
    // Painting directly off the small text metric keeps the chip just
    // tall enough for its glyphs.
    let text_color = colorhash::text_color_on(fill);
    let font = egui::TextStyle::Small.resolve(ui.style());
    let galley = ui.painter().layout_no_wrap(label.to_string(), font, text_color);
    const PAD_X: f32 = 5.0;
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(galley.size().x + PAD_X * 2.0, galley.size().y),
        egui::Sense::hover(),
    );
    let painter = ui.painter();
    painter.rect_filled(rect, egui::CornerRadius::ZERO, fill);
    painter.galley(
        egui::pos2(rect.left() + PAD_X, rect.top()),
        galley,
        text_color,
    );
}
