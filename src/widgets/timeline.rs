//! GORBIE-embeddable branch timeline.
//!
//! A pan/zoom time axis that overlays events from one or more pile
//! branches on a single vertical timeline (newest at top, oldest at
//! bottom). The widget holds UI + cached-event state only; the host
//! configures it with a list of [`SourceKind`]s (what kind of decoration
//! to use per branch) and passes in the matching workspaces at render
//! time.
//!
//! Per-kind decoration:
//! * Compass — goal status changes (pill + goal title)
//! * Local messages — body preview with sender/recipient pills
//! * Wiki — fragment-version commits with title
//! * Commits — generic commit-bar rendering for arbitrary branches
//!
//! ```ignore
//! let mut timeline = BranchTimeline::multi(vec![
//!     TimelineSource::Compass { label: "goals".into() },
//!     TimelineSource::LocalMessages { label: "local".into() },
//!     TimelineSource::Wiki { label: "wiki".into() },
//! ]);
//! // Inside a GORBIE card:
//! timeline.render(ctx, &mut [
//!     ("compass", &mut compass_ws),
//!     ("message", &mut messages_ws),
//!     ("wiki", &mut wiki_ws),
//! ]);
//! ```
//!
//! Input handling:
//! * scroll = pan (vertical)
//! * pinch or cmd/ctrl + scroll = zoom (horizontal trackpad drift no longer zooms)
//! * drag = pan
//! * double-click = jump to "now"
//!
//! The ruler is a "four-sine" design: overlapping cosines at the natural
//! time periods (minute, hour, day) that produce constructive interference
//! at nice times. Labels are placed independently at the coarsest interval
//! that gives ~6-10 labels per viewport.

use std::collections::HashMap;

use hifitime::{Duration as HifiDuration, Epoch};
use GORBIE::card_ctx::GRID_ROW_MODULE;
use GORBIE::prelude::CardCtx;
use triblespace::core::id::Id;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{
    ancestors, CommitHandle, CommitSelector, CommitSet, Workspace,
};
use triblespace::core::trible::TribleSet;
use triblespace::core::inline::encodings::hash::{Blake3, Handle};
use triblespace::core::inline::Inline;
use triblespace::macros::{find, pattern};
use triblespace::prelude::blobencodings::{LongString, SimpleArchive};
use triblespace::prelude::View;

use crate::schemas::compass::{
    board as compass_attrs, KIND_GOAL_ID, KIND_NOTE_ID, KIND_STATUS_ID,
};
use crate::schemas::archive::archive as archive_attrs;
use crate::schemas::message::{local as local_attrs, KIND_MESSAGE_ID};
use crate::schemas::reason::{reason_schema as reason_attrs, KIND_REASON_ID};
use crate::schemas::wiki::{attrs as wiki_attrs, KIND_VERSION_ID};

/// Handle to a long-string blob (branch names, titles, bodies, notes).
type TextHandle = Inline<Handle<LongString>>;
/// A commit blob handle (SimpleArchive of its metadata tribles).
type CommitHandleValue = Inline<Handle<SimpleArchive>>;

// ── Rendering constants ──────────────────────────────────────────────

/// Default viewport height in pixels.
const DEFAULT_VIEWPORT_HEIGHT: f32 = 800.0;
/// Default zoom: pixels per minute of wall time.
const TIMELINE_DEFAULT_SCALE: f32 = 2.0;

/// Tick intervals (in nanoseconds) used for label placement. Picks the
/// smallest interval >= `label_min_ns` so labels never overlap.
const TICK_INTERVALS: &[i128] = {
    const NS: i128 = 1_000_000_000;
    &[
        NS,             // 1 second
        5 * NS,         // 5 seconds
        10 * NS,        // 10 seconds
        30 * NS,        // 30 seconds
        60 * NS,        // 1 minute
        5 * 60 * NS,    // 5 minutes
        10 * 60 * NS,   // 10 minutes
        30 * 60 * NS,   // 30 minutes
        3600 * NS,      // 1 hour
        3 * 3600 * NS,  // 3 hours
        6 * 3600 * NS,  // 6 hours
        12 * 3600 * NS, // 12 hours
        86400 * NS,     // 1 day
        7 * 86400 * NS, // 1 week
    ]
};

/// Format a TAI nanosecond key as a human-readable time marker.
fn format_time_marker(key: i128) -> String {
    let ns = HifiDuration::from_total_nanoseconds(key);
    let epoch = Epoch::from_tai_duration(ns);
    let (y, m, d, h, min, s, _) = epoch.to_gregorian_utc();
    format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:{s:02}")
}

/// Current TAI time as a ns key, or 0 if the system clock is unavailable.
fn now_key() -> i128 {
    Epoch::now()
        .map(|e| e.to_tai_duration().total_nanoseconds())
        .unwrap_or(0)
}

/// First 8 hex chars of an Id — compact label for pills / hover.
fn id_hex(id: Id) -> String {
    format!("{id:x}")
}

/// Truncate `s` to fit in `max_px` at `char_px` per char, appending
/// "…" if truncated. Char-aware so multibyte sequences don't panic
/// on slice.
fn truncate_to_chip_width(s: &str, max_px: f32, char_px: f32) -> String {
    let max_chars = (max_px / char_px).max(3.0) as usize;
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let take: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    format!("{take}…")
}

/// Trim a string to `max` chars on a single line, replacing inner
/// newlines with spaces. Used for body/title previews on event rows.
fn preview(text: &str, max: usize) -> String {
    let flat: String = text
        .chars()
        .map(|c| if c == '\n' || c == '\r' || c == '\t' { ' ' } else { c })
        .collect();
    let trimmed = flat.trim();
    if trimmed.chars().count() <= max {
        trimmed.to_string()
    } else {
        let take: String = trimmed.chars().take(max.saturating_sub(1)).collect();
        format!("{take}…")
    }
}

/// Pick black or white text color for good contrast on `fill`.
fn text_on(fill: egui::Color32) -> egui::Color32 {
    let r = fill.r() as f32 / 255.0;
    let g = fill.g() as f32 / 255.0;
    let b = fill.b() as f32 / 255.0;
    let lin = |c: f32| {
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    let l = 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
    if l > 0.4 {
        egui::Color32::BLACK
    } else {
        egui::Color32::WHITE
    }
}

// ── Source descriptions & styling ────────────────────────────────────

/// Decoration description for a timeline source. Branch names are
/// supplied separately at render time.
#[derive(Clone, Debug)]
pub enum TimelineSource {
    /// Plain commit bars (useful for arbitrary branches).
    Commits {
        label: String,
        color: egui::Color32,
    },
    /// Compass — render goal status changes with the goal title and
    /// status-color pill.
    Compass { label: String },
    /// Local-messages — render each message with sender/body preview.
    LocalMessages { label: String },
    /// Wiki — render fragment-version commits with title.
    Wiki { label: String },
    /// Reason events — explicit reasoning notes the agent records
    /// alongside the command it ran (cognition branch). Useful as
    /// "thought before action" markers along the activity axis.
    Reason { label: String },
    /// Archive — externally imported conversation messages (archive
    /// branch), so e.g. ChatGPT / Codex / Copilot history appears
    /// inline with the rest of the timeline.
    Archive { label: String },
}

/// Coarse kind used on the widget's `selected_event` and as a color key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceKind {
    Commits,
    Compass,
    LocalMessages,
    Wiki,
    Reason,
    Archive,
}

impl TimelineSource {
    /// A short (≤6 char) source label used in the pill.
    fn label(&self) -> String {
        match self {
            TimelineSource::Commits { label, .. }
            | TimelineSource::Compass { label }
            | TimelineSource::LocalMessages { label }
            | TimelineSource::Wiki { label }
            | TimelineSource::Reason { label }
            | TimelineSource::Archive { label } => label.clone(),
        }
    }

    fn color(&self) -> egui::Color32 {
        match self {
            TimelineSource::Commits { color, .. } => *color,
            // RAL 1012 lemon yellow — matches playground color_goals.
            TimelineSource::Compass { .. } => egui::Color32::from_rgb(0xd9, 0xc2, 0x2e),
            // RAL 6032 signal green — matches playground color_local_msg.
            TimelineSource::LocalMessages { .. } => egui::Color32::from_rgb(0x23, 0x7f, 0x52),
            // RAL 3012 beige red — matches playground color_wiki.
            TimelineSource::Wiki { .. } => egui::Color32::from_rgb(0xc1, 0x87, 0x6b),
            // RAL 1003 signal yellow — reason events read as "agent thought".
            TimelineSource::Reason { .. } => egui::Color32::from_rgb(0xf7, 0xba, 0x0b),
            // RAL 5012 light blue — archived conversation messages.
            TimelineSource::Archive { .. } => egui::Color32::from_rgb(0x3b, 0x83, 0xbd),
        }
    }
}

/// Kanban status color — reused for the inline pill on Compass events.
fn status_color(status: &str) -> egui::Color32 {
    match status {
        // RAL 6018 yellow green
        "todo" => egui::Color32::from_rgb(0x57, 0xa6, 0x39),
        // RAL 1003 signal yellow
        "doing" => egui::Color32::from_rgb(0xf7, 0xba, 0x0b),
        // RAL 3020 traffic red
        "blocked" => egui::Color32::from_rgb(0xcc, 0x0a, 0x17),
        // RAL 5005 signal blue
        "done" => egui::Color32::from_rgb(0x15, 0x4e, 0xa1),
        // RAL 7012 basalt grey (muted)
        _ => egui::Color32::from_rgb(0x4d, 0x55, 0x59),
    }
}

// ── Event model ──────────────────────────────────────────────────────

/// A single point on the timeline. Flat enough that we can sort and
/// paint without re-querying per frame. Per-kind fields live as
/// optional extras on the row so the painter can decorate without
/// re-reading the fact space.
#[derive(Clone, Debug)]
struct Event {
    source_idx: usize,
    kind: SourceKind,
    entity_id: Id,
    ts_ns: i128,
    /// Primary one-line preview (goal title, message body, wiki title,
    /// or short commit id for generic sources).
    summary: String,
    /// Optional kanban-status pill label (Compass).
    status: Option<String>,
    /// Optional sender pill label (LocalMessages — "<from_prefix> → <to_prefix>").
    from_to: Option<String>,
}

// ── Live connection ──────────────────────────────────────────────────

/// Cached events + per-source head markers. Rebuilt when any source's
/// workspace head advances.
struct MultiLive {
    cached_heads: Vec<Option<CommitHandle>>,
    events: Vec<Event>,
}

impl MultiLive {
    /// Rebuild events from the provided workspaces.
    fn refresh(
        sources: &[TimelineSource],
        workspaces: &mut [(&str, &mut Workspace<Pile>)],
    ) -> Self {
        let mut out: Vec<Event> = Vec::new();
        let mut heads: Vec<Option<CommitHandle>> = Vec::with_capacity(sources.len());

        for (idx, src) in sources.iter().enumerate() {
            let entry = workspaces.get_mut(idx);
            let ws = match entry {
                Some((_, ws)) => ws,
                None => {
                    heads.push(None);
                    continue;
                }
            };
            heads.push(ws.head());
            match src {
                TimelineSource::Commits { .. } => collect_commit_events(idx, ws, &mut out),
                TimelineSource::Compass { .. } => collect_compass_events(idx, ws, &mut out),
                TimelineSource::LocalMessages { .. } => {
                    collect_local_events(idx, ws, &mut out)
                }
                TimelineSource::Wiki { .. } => collect_wiki_events(idx, ws, &mut out),
                TimelineSource::Reason { .. } => collect_reason_events(idx, ws, &mut out),
                TimelineSource::Archive { .. } => collect_archive_events(idx, ws, &mut out),
            }
        }
        out.sort_by_key(|e| e.ts_ns);
        MultiLive {
            cached_heads: heads,
            events: out,
        }
    }
}

/// Walk every commit reachable from HEAD and emit one Event per commit.
/// Commits without `created_at` are skipped — they're merge commits by
/// design and carry no author-time bits.
fn collect_commit_events(
    idx: usize,
    ws: &mut Workspace<Pile>,
    out: &mut Vec<Event>,
) {
    let Some(head) = ws.head() else {
        return;
    };
    let Ok(set): Result<CommitSet, _> = ancestors(head).select(ws) else {
        return;
    };
    for raw in set.iter() {
        let handle: CommitHandleValue = Inline::new(*raw);
        let Ok(meta) = ws.get::<TribleSet, SimpleArchive>(handle) else {
            continue;
        };
        if let Some((cid, ts)) = find!(
            (cid: Id, ts: (i128, i128)),
            pattern!(&meta, [{ ?cid @ metadata::created_at: ?ts }])
        )
        .next()
        {
            out.push(Event {
                source_idx: idx,
                kind: SourceKind::Commits,
                entity_id: cid,
                ts_ns: ts.0,
                summary: "commit".to_string(),
                status: None,
                from_to: None,
            });
        }
    }
}

fn read_text(ws: &mut Workspace<Pile>, h: TextHandle) -> String {
    ws.get::<View<str>, LongString>(h)
        .map(|v| {
            let s: &str = v.as_ref();
            s.to_string()
        })
        .unwrap_or_default()
}

/// Emit a Compass event per status-change entity. Also records "goal
/// created" and "note" events so quiet boards still show up.
fn collect_compass_events(
    idx: usize,
    ws: &mut Workspace<Pile>,
    out: &mut Vec<Event>,
) {
    let space = match ws.checkout(..) {
        Ok(co) => co.into_facts(),
        Err(e) => {
            eprintln!("[timeline] compass checkout: {e:?}");
            return;
        }
    };

    let mut title_by_goal: HashMap<Id, String> = HashMap::new();

    let goal_rows: Vec<(Id, TextHandle, (i128, i128))> = find!(
        (gid: Id, title: TextHandle, ts: (i128, i128)),
        pattern!(&space, [{
            ?gid @
            metadata::tag: &KIND_GOAL_ID,
            compass_attrs::title: ?title,
            metadata::created_at: ?ts,
        }])
    )
    .collect();

    for (gid, title_h, ts) in goal_rows {
        let title = read_text(ws, title_h);
        title_by_goal.insert(gid, title.clone());
        out.push(Event {
            source_idx: idx,
            kind: SourceKind::Compass,
            entity_id: gid,
            ts_ns: ts.0,
            summary: preview(&title, 80),
            status: Some("created".to_string()),
            from_to: None,
        });
    }

    let status_rows: Vec<(Id, Id, String, (i128, i128))> = find!(
        (event_id: Id, gid: Id, status: String, ts: (i128, i128)),
        pattern!(&space, [{
            ?event_id @
            metadata::tag: &KIND_STATUS_ID,
            compass_attrs::task: ?gid,
            compass_attrs::status: ?status,
            metadata::created_at: ?ts,
        }])
    )
    .collect();

    for (event_id, gid, status, ts) in status_rows {
        let title = title_by_goal
            .get(&gid)
            .cloned()
            .unwrap_or_else(|| "(untitled)".to_string());
        out.push(Event {
            source_idx: idx,
            kind: SourceKind::Compass,
            entity_id: event_id,
            ts_ns: ts.0,
            summary: preview(&title, 80),
            status: Some(status),
            from_to: None,
        });
    }

    let note_rows: Vec<(Id, Id, TextHandle, (i128, i128))> = find!(
        (event_id: Id, gid: Id, note: TextHandle, ts: (i128, i128)),
        pattern!(&space, [{
            ?event_id @
            metadata::tag: &KIND_NOTE_ID,
            compass_attrs::task: ?gid,
            compass_attrs::note: ?note,
            metadata::created_at: ?ts,
        }])
    )
    .collect();

    for (event_id, gid, note_h, ts) in note_rows {
        let body = read_text(ws, note_h);
        let title = title_by_goal
            .get(&gid)
            .cloned()
            .unwrap_or_else(|| "(untitled)".to_string());
        let summary = if body.is_empty() {
            preview(&title, 80)
        } else {
            preview(&format!("{title} — {body}"), 80)
        };
        out.push(Event {
            source_idx: idx,
            kind: SourceKind::Compass,
            entity_id: event_id,
            ts_ns: ts.0,
            summary,
            status: Some("note".to_string()),
            from_to: None,
        });
    }
}

/// Emit a LocalMessages event per message.
fn collect_local_events(
    idx: usize,
    ws: &mut Workspace<Pile>,
    out: &mut Vec<Event>,
) {
    let space = match ws.checkout(..) {
        Ok(co) => co.into_facts(),
        Err(e) => {
            eprintln!("[timeline] message checkout: {e:?}");
            return;
        }
    };

    let rows: Vec<(Id, Id, Id, TextHandle, (i128, i128))> = find!(
        (mid: Id, from: Id, to: Id, body: TextHandle, ts: (i128, i128)),
        pattern!(&space, [{
            ?mid @
            metadata::tag: &KIND_MESSAGE_ID,
            local_attrs::from: ?from,
            local_attrs::to: ?to,
            local_attrs::body: ?body,
            metadata::created_at: ?ts,
        }])
    )
    .collect();

    for (mid, from, to, body_h, ts) in rows {
        let body = read_text(ws, body_h);
        out.push(Event {
            source_idx: idx,
            kind: SourceKind::LocalMessages,
            entity_id: mid,
            ts_ns: ts.0,
            summary: preview(&body, 80),
            status: None,
            from_to: Some(format!("{} → {}", id_hex(from), id_hex(to))),
        });
    }
}

/// Emit a Wiki event per fragment-version.
fn collect_wiki_events(
    idx: usize,
    ws: &mut Workspace<Pile>,
    out: &mut Vec<Event>,
) {
    let space = match ws.checkout(..) {
        Ok(co) => co.into_facts(),
        Err(e) => {
            eprintln!("[timeline] wiki checkout: {e:?}");
            return;
        }
    };

    let rows: Vec<(Id, TextHandle, (i128, i128))> = find!(
        (vid: Id, title: TextHandle, ts: (i128, i128)),
        pattern!(&space, [{
            ?vid @
            metadata::tag: &KIND_VERSION_ID,
            wiki_attrs::title: ?title,
            metadata::created_at: ?ts,
        }])
    )
    .collect();

    for (vid, title_h, ts) in rows {
        let title = read_text(ws, title_h);
        out.push(Event {
            source_idx: idx,
            kind: SourceKind::Wiki,
            entity_id: vid,
            ts_ns: ts.0,
            summary: preview(&title, 80),
            status: None,
            from_to: None,
        });
    }
}

/// Emit a Reason event per cognition-branch reason entity. Each
/// entity has a long-string `text` payload (the agent's thought)
/// and a created-at timestamp; the timeline chip shows the first
/// line of the thought as its summary.
fn collect_reason_events(idx: usize, ws: &mut Workspace<Pile>, out: &mut Vec<Event>) {
    let space = match ws.checkout(..) {
        Ok(co) => co.into_facts(),
        Err(e) => {
            eprintln!("[timeline] reason checkout: {e:?}");
            return;
        }
    };

    let rows: Vec<(Id, TextHandle, (i128, i128))> = find!(
        (rid: Id, text: TextHandle, ts: (i128, i128)),
        pattern!(&space, [{
            ?rid @
            metadata::tag: &KIND_REASON_ID,
            reason_attrs::text: ?text,
            metadata::created_at: ?ts,
        }])
    )
    .collect();

    for (rid, text_h, ts) in rows {
        let text = read_text(ws, text_h);
        out.push(Event {
            source_idx: idx,
            kind: SourceKind::Reason,
            entity_id: rid,
            ts_ns: ts.0,
            summary: preview(&text, 80),
            status: None,
            from_to: None,
        });
    }
}

/// Emit an Archive event per externally imported conversation
/// message (archive branch). Each archived message carries the
/// same `kind_message` tag we use for local messages — we
/// disambiguate by branch (the archive workspace is what's
/// passed in here). The chip's summary line is the message
/// `content`'s first line.
fn collect_archive_events(idx: usize, ws: &mut Workspace<Pile>, out: &mut Vec<Event>) {
    let space = match ws.checkout(..) {
        Ok(co) => co.into_facts(),
        Err(e) => {
            eprintln!("[timeline] archive checkout: {e:?}");
            return;
        }
    };

    // archive::archive::kind_message is the canonical tag id for an
    // archived message payload — same value the message
    // schema uses for KIND_MESSAGE_ID, since both faculties share
    // the protocol-agnostic "this is a message" marker.
    let rows: Vec<(Id, TextHandle, (i128, i128))> = find!(
        (mid: Id, content: TextHandle, ts: (i128, i128)),
        pattern!(&space, [{
            ?mid @
            metadata::tag: &archive_attrs::kind_message,
            archive_attrs::content: ?content,
            metadata::created_at: ?ts,
        }])
    )
    .collect();

    for (mid, content_h, ts) in rows {
        let content = read_text(ws, content_h);
        out.push(Event {
            source_idx: idx,
            kind: SourceKind::Archive,
            entity_id: mid,
            ts_ns: ts.0,
            summary: preview(&content, 80),
            status: None,
            from_to: None,
        });
    }
}

// ── Widget ───────────────────────────────────────────────────────────

/// GORBIE-embeddable pan/zoom timeline for one or more pile branches.
///
/// Paints a full-width vertical time axis (newest at top, oldest at
/// bottom) with:
///
/// * a four-sine ruler (constructive interference at minute / hour /
///   day boundaries)
/// * time labels at the coarsest interval that fits
/// * per-source event chips with source-specific decoration
///
/// The pile + all requested source branches are opened lazily on the
/// first render, in the same pattern as [`WikiViewer`](crate::widgets::WikiViewer).
pub struct BranchTimeline {
    /// One entry per source — matches the workspaces passed in at
    /// render time (by index). Single-branch constructor builds a single
    /// `TimelineSource::Commits` entry.
    sources: Vec<TimelineSource>,
    viewport_height: f32,
    /// Cached events + head markers; rebuilt when any source's head
    /// advances.
    live: Option<MultiLive>,
    /// Top edge of viewport, in TAI ns. Newest visible time.
    timeline_start: i128,
    /// Pixels per minute of wall time.
    timeline_scale: f32,
    /// Tracks the first render so we can initialize `timeline_start` to
    /// "now" before painting.
    first_render: bool,
    /// The most-recently-clicked event, if any. Hosts can read this to
    /// drive floating detail cards.
    pub selected_event: Option<(SourceKind, Id)>,
}

impl BranchTimeline {
    /// Single-source commit-bars timeline (matches v1 behavior).
    pub fn new(label: impl Into<String>) -> Self {
        // Default commit-bar color: muted amber (matches v1 "commit_color").
        let color = egui::Color32::from_rgb(0xff, 0xc8, 0x3a);
        Self::multi(vec![TimelineSource::Commits {
            label: label.into(),
            color,
        }])
    }

    /// Multi-source overlay — each source paints its own events on the
    /// shared axis.
    pub fn multi(sources: Vec<TimelineSource>) -> Self {
        Self {
            sources,
            viewport_height: DEFAULT_VIEWPORT_HEIGHT,
            live: None,
            timeline_start: 0,
            timeline_scale: TIMELINE_DEFAULT_SCALE,
            first_render: true,
            selected_event: None,
        }
    }

    /// Override the viewport height (pixels). Defaults to 800.
    pub fn with_height(mut self, height: f32) -> Self {
        self.viewport_height = height.max(48.0);
        self
    }

    /// Render the timeline. `workspaces` must have the same length and
    /// ordering as the `sources` list configured at construction. Each
    /// entry is `(branch_name, &mut Workspace)` — the branch name is
    /// only used in error messages; indices are what's authoritative.
    pub fn render(
        &mut self,
        ctx: &mut CardCtx<'_>,
        workspaces: &mut [(&str, &mut Workspace<Pile>)],
    ) {
        let now = now_key();
        if self.first_render {
            self.timeline_start = now;
            self.first_render = false;
        }

        // Refresh if any head advanced (or first pass).
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => {
                if l.cached_heads.len() != self.sources.len() {
                    true
                } else {
                    (0..self.sources.len()).any(|i| {
                        let head = workspaces.get(i).map(|(_, ws)| ws.head()).unwrap_or(None);
                        l.cached_heads.get(i).copied().flatten() != head
                    })
                }
            }
        };
        if need_refresh {
            self.live = Some(MultiLive::refresh(&self.sources, workspaces));
        }

        let events = self.live.as_ref().map(|l| l.events.clone()).unwrap_or_default();
        let sources = self.sources.clone();
        let viewport_height = self.viewport_height;

        // Visible time span in the viewport — used for the right-
        // aligned scale chip in the legend row so the viewer always
        // knows what range they're looking at without manually
        // reading the tick marks.
        ctx.section("Activity", |ctx| {
            // Paint the viewport directly on the section ctx (no
            // grid wrapper) so it runs edge-to-edge inside the
            // section, matching the wiki graph's treatment. Legend
            // + SPAN + zoom-hint all live as overlays inside the
            // viewport itself.
            self.paint_viewport(ctx, viewport_height, now, &events, &sources);
        });
    }

    /// Paint the timeline viewport. All pan/zoom/scroll logic lives here.
    fn paint_viewport(
        &mut self,
        ctx: &mut CardCtx<'_>,
        viewport_height: f32,
        now: i128,
        events: &[Event],
        sources: &[TimelineSource],
    ) {
        let ui = ctx.ui_mut();
        let scroll_speed = 3.0;
        let viewport_width = ui.available_width();
        // egui's drag sense is z-aware (only the topmost widget claims
        // the drag), so floats dragged across the viewport don't pan
        // the timeline. The hit_test.rs panic that prompted manual
        // detection in earlier 0.34 versions has been fixed upstream.
        let (viewport_rect, viewport_response) = ui.allocate_exact_size(
            egui::vec2(viewport_width, viewport_height),
            egui::Sense::click_and_drag(),
        );

        // Input handling — compute ns_per_px from CURRENT scale.
        {
            let ns_per_px = 60_000_000_000.0 / self.timeline_scale as f64;

            // Check hover via direct rect-contains-pointer test rather
            // than `viewport_response.hovered()`, because the outer
            // notebook ScrollArea claims hover priority and makes
            // the widget-level hovered() unreliable for scroll capture.
            let pointer_in_viewport = ui
                .input(|i| i.pointer.hover_pos())
                .map(|p| viewport_rect.contains(p))
                .unwrap_or(false);
            if pointer_in_viewport {
                let (scroll_y, ctrl, pointer_pos, pinch) = ui.input(|i| {
                    (
                        i.smooth_scroll_delta.y,
                        i.modifiers.command || i.modifiers.ctrl,
                        i.pointer.hover_pos(),
                        i.zoom_delta(),
                    )
                });

                let cursor_rel_y = pointer_pos
                    .map(|p| (p.y - viewport_rect.top()).max(0.0))
                    .unwrap_or(viewport_height * 0.5);

                let cursor_time =
                    self.timeline_start - (cursor_rel_y as f64 * ns_per_px) as i128;

                // Scroll without a modifier → pan the timeline.
                // Cmd/Ctrl + scroll OR native trackpad pinch → zoom
                // around the cursor row. Horizontal scroll no longer
                // zooms — trackpad sideways drift was triggering
                // unintended zoom on every swipe.
                let mut consumed_scroll = false;
                if scroll_y != 0.0 && !ctrl {
                    let pan_ns = (scroll_y as f64 * scroll_speed * ns_per_px) as i128;
                    self.timeline_start += pan_ns;
                    consumed_scroll = true;
                }

                let zoom_factor = if pinch != 1.0 {
                    pinch
                } else if ctrl && scroll_y != 0.0 {
                    if scroll_y > 0.0 {
                        1.15
                    } else {
                        1.0 / 1.15
                    }
                } else {
                    1.0
                };

                if zoom_factor != 1.0 {
                    let new_scale = (self.timeline_scale * zoom_factor).clamp(0.01, 1000.0);
                    let new_ns_per_px = 60_000_000_000.0 / new_scale as f64;
                    self.timeline_start =
                        cursor_time + (cursor_rel_y as f64 * new_ns_per_px) as i128;
                    self.timeline_scale = new_scale;
                    consumed_scroll = true;
                }

                // Only swallow the scroll delta when we actually used
                // it for pan/zoom — otherwise let the outer notebook
                // ScrollArea consume the gesture normally.
                if consumed_scroll {
                    ui.ctx().input_mut(|i| {
                        i.smooth_scroll_delta = egui::Vec2::ZERO;
                    });
                }
            }

            // Drag-to-pan via egui's z-aware drag sense. egui handles
            // the click/drag deadzone internally — short press+release
            // returns clicked() without ever flipping dragged() — so
            // we don't need a manual threshold.
            let drag_dy = viewport_response.drag_delta().y;
            if drag_dy != 0.0 {
                let pan_ns = (drag_dy as f64 * ns_per_px) as i128;
                self.timeline_start += pan_ns;
            }

            if viewport_response.double_clicked() {
                self.timeline_start = now;
            }
        }

        // Recompute bounds AFTER input with final scale.
        let ns_per_px = 60_000_000_000.0 / self.timeline_scale as f64;
        let viewport_ns = (viewport_height as f64 * ns_per_px) as i128;
        let view_start = self.timeline_start;
        let view_end = view_start - viewport_ns;

        let painter = ui.painter_at(viewport_rect);

        // Neutral dark-grey viewport background — makes the ruler
        // ticks and event chips pop against a consistent panel
        // regardless of the notebook theme fill.
        let frame_color = egui::Color32::from_rgb(0x29, 0x2c, 0x2f);
        painter.rect_filled(viewport_rect, 0.0, frame_color);

        // Four-sine ruler: one cosine per natural time period.
        let muted = egui::Color32::from_rgb(0x8a, 0x8a, 0x8a);
        let max_len = 80.0;
        let tick_spacing_px = GRID_ROW_MODULE;
        let tau = std::f64::consts::TAU;

        let ns = 1_000_000_000.0f64;
        let periods = [60.0 * ns, 3600.0 * ns, 86400.0 * ns];

        let significance = |t: f64| -> f32 {
            let mut sig = 0.0f32;
            let mut n = 0.0f32;
            for &period in &periods {
                let px_wave = period / ns_per_px;
                let vis = ((px_wave as f32 / tick_spacing_px - 1.0) / 3.0).clamp(0.0, 1.0);
                if vis < 0.001 {
                    continue;
                }
                sig += vis * (0.5 + 0.5 * (tau * t / period).cos() as f32);
                n += vis;
            }
            if n > 0.0 {
                sig / n
            } else {
                0.0
            }
        };

        let n_samples = (viewport_height / tick_spacing_px) as usize + 1;
        for i in 0..=n_samples {
            let y = viewport_rect.top() + i as f32 * tick_spacing_px;
            if y > viewport_rect.bottom() {
                break;
            }
            let t = view_start as f64 - (i as f64 * tick_spacing_px as f64 * ns_per_px);
            let sig = significance(t);
            let tick_len = 2.0 + (max_len - 2.0) * sig;

            painter.line_segment(
                [
                    egui::pos2(viewport_rect.left(), y),
                    egui::pos2(viewport_rect.left() + tick_len, y),
                ],
                egui::Stroke::new(0.5, muted),
            );
        }

        // Labels at coarsest interval giving >= label_min_spacing_px.
        let label_min_spacing_px = 100.0;
        let label_min_ns = (label_min_spacing_px as f64 * ns_per_px) as i128;
        let label_interval = TICK_INTERVALS
            .iter()
            .copied()
            .find(|&iv| iv >= label_min_ns)
            .unwrap_or(*TICK_INTERVALS.last().unwrap());

        if label_interval > 0 {
            let first = (view_start / label_interval) * label_interval;
            let mut tick = first;
            while tick > view_end {
                let y = viewport_rect.top()
                    + ((view_start - tick) as f64 / ns_per_px) as f32;
                if y >= viewport_rect.top() && y <= viewport_rect.bottom() {
                    let label = format_time_marker(tick);
                    painter.text(
                        egui::pos2(viewport_rect.left() + max_len + 4.0, y),
                        egui::Align2::LEFT_CENTER,
                        &label,
                        egui::FontId::monospace(9.0),
                        muted,
                    );
                }
                tick -= label_interval;
            }
        }

        // NOW marker — a dashed horizontal guideline at current time
        // so the viewer can orient immediately. Only painted when
        // `now` falls inside the visible window.
        if now >= view_end && now <= view_start {
            // egui only repaints on input events, which froze the
            // marker until the mouse moved. Schedule a repaint for
            // when the marker will have travelled ~1px at the current
            // zoom, clamped to [1s, 60s] so a zoomed-out idle viewer
            // doesn't busy-spin and a zoomed-in one still glides.
            let secs_per_px = (ns_per_px / 1e9).clamp(1.0, 60.0);
            painter
                .ctx()
                .request_repaint_after(std::time::Duration::from_secs_f64(secs_per_px));

            let y = viewport_rect.top()
                + ((view_start - now) as f64 / ns_per_px) as f32;
            let now_color = egui::Color32::from_rgb(0xf7, 0xba, 0x0b); // RAL 1003
            // Dashed line: short segments every 10px.
            let mut x = viewport_rect.left();
            let x_end = viewport_rect.right();
            while x < x_end {
                let seg_end = (x + 6.0).min(x_end);
                painter.line_segment(
                    [egui::pos2(x, y), egui::pos2(seg_end, y)],
                    egui::Stroke::new(1.0, now_color),
                );
                x += 10.0;
            }
            painter.text(
                egui::pos2(viewport_rect.right() - 4.0, y - 6.0),
                egui::Align2::RIGHT_BOTTOM,
                "NOW",
                egui::FontId::monospace(9.0),
                now_color,
            );
        }

        // Top-right overlay: visible-window span + interaction hint.
        // Painted as plain text over the ruler — no pill background,
        // relies on the muted colors to recede against both the
        // viewport fill and the event chips.
        {
            let visible_secs =
                viewport_height as f64 * 60.0 / self.timeline_scale as f64;
            let span_label = format!("SPAN {}", format_span(visible_secs));
            let hint_label = "PINCH/\u{2318}+SCROLL \u{2192} ZOOM · DBL-CLICK \u{2192} NOW";
            let span_font = egui::FontId::monospace(10.0);
            let hint_font = egui::FontId::monospace(9.0);
            let span_color = egui::Color32::from_rgb(0xc8, 0xc8, 0xc8);
            let hint_color = egui::Color32::from_rgb(0x7a, 0x7a, 0x7a);
            let top = viewport_rect.top() + 6.0;
            let right = viewport_rect.right() - 8.0;
            let gap = 12.0;
            let hint_galley =
                painter.layout_no_wrap(hint_label.to_string(), hint_font, hint_color);
            let span_galley =
                painter.layout_no_wrap(span_label, span_font, span_color);
            let hint_pos = egui::pos2(right - hint_galley.size().x, top);
            painter.galley(hint_pos, hint_galley, hint_color);
            let span_pos = egui::pos2(
                hint_pos.x - gap - span_galley.size().x,
                top,
            );
            painter.galley(span_pos, span_galley, span_color);
        }

        // Per-source event rendering.
        //
        // Two layouts depending on source count:
        //   1 source, all Commits → v1 ribbon-on-right style (short
        //      horizontal tick + dot on a thin vertical axis line).
        //   Otherwise → chip-style rows: wide chip with source pill +
        //      per-kind decoration + summary text.
        let only_commits = sources.len() == 1
            && matches!(sources[0], TimelineSource::Commits { .. });

        let pointer_pos = ui.input(|i| i.pointer.hover_pos());
        let mut hover_label: Option<(egui::Pos2, String)> = None;
        let mut clicked_event: Option<(SourceKind, Id)> = None;
        let mut hover_rect: Option<(egui::Rect, egui::Color32)> = None;

        if only_commits {
            // v1 compact ribbon.
            let commit_color = sources[0].color();
            let axis_color = egui::Color32::from_rgb(0xbd, 0xbd, 0xbd);
            let axis_x = viewport_rect.right() - 40.0;
            painter.line_segment(
                [
                    egui::pos2(axis_x, viewport_rect.top()),
                    egui::pos2(axis_x, viewport_rect.bottom()),
                ],
                egui::Stroke::new(0.5, axis_color),
            );

            // Empty state: when there are no events at all, paint a
            // centered hourglass + muted hint over the ruler so the
            // viewport isn't a blank scrubbing surface.
            if events.is_empty() {
                let center = viewport_rect.center();
                painter.text(
                    egui::pos2(center.x, center.y - 14.0),
                    egui::Align2::CENTER_CENTER,
                    "\u{231b}",
                    egui::FontId::proportional(28.0),
                    muted,
                );
                painter.text(
                    egui::pos2(center.x, center.y + 12.0),
                    egui::Align2::CENTER_CENTER,
                    "NO EVENTS IN RANGE",
                    egui::FontId::monospace(11.0),
                    muted,
                );
                painter.text(
                    egui::pos2(center.x, center.y + 28.0),
                    egui::Align2::CENTER_CENTER,
                    "Drag to pan · pinch or ⌘+scroll to zoom",
                    egui::FontId::proportional(11.0),
                    muted,
                );
            }

            for ev in events {
                if ev.ts_ns < view_end || ev.ts_ns > view_start {
                    continue;
                }
                let y =
                    viewport_rect.top() + ((view_start - ev.ts_ns) as f64 / ns_per_px) as f32;
                let x1 = axis_x - 8.0;
                let x2 = axis_x + 8.0;
                painter.line_segment(
                    [egui::pos2(x1, y), egui::pos2(x2, y)],
                    egui::Stroke::new(1.5, commit_color),
                );
                painter.circle_filled(egui::pos2(axis_x, y), 2.5, commit_color);

                if let Some(p) = pointer_pos {
                    if viewport_rect.contains(p)
                        && (p.y - y).abs() <= 4.0
                        && (p.x - axis_x).abs() <= 40.0
                    {
                        let label =
                            format!("{}  {}", ev.summary, format_time_marker(ev.ts_ns));
                        hover_label = Some((egui::pos2(axis_x - 12.0, y), label));
                        if viewport_response.clicked() {
                            clicked_event = Some((ev.kind, ev.entity_id));
                        }
                    }
                }
            }

            if let Some((pos, label)) = hover_label {
                painter.text(
                    pos,
                    egui::Align2::RIGHT_CENTER,
                    label,
                    egui::FontId::monospace(10.0),
                    axis_color,
                );
            }
        } else {
            // Multi-source chip layout.
            let event_left = viewport_rect.left() + max_len + 110.0;
            let event_right_margin = 8.0;
            let event_width = (viewport_rect.right() - event_left - event_right_margin).max(80.0);
            let chip_h = 16.0;
            let text_color = egui::Color32::from_rgb(0xe6, 0xe6, 0xe6);

            for ev in events {
                if ev.ts_ns < view_end || ev.ts_ns > view_start {
                    continue;
                }
                let y =
                    viewport_rect.top() + ((view_start - ev.ts_ns) as f64 / ns_per_px) as f32;
                let src = &sources[ev.source_idx];
                let src_color = src.color();
                let src_label = src.label();

                let chip_rect = egui::Rect::from_min_size(
                    egui::pos2(event_left, y - chip_h * 0.5),
                    egui::vec2(event_width, chip_h),
                );

                // Chip background.
                painter.rect_filled(chip_rect, 3.0, frame_color);

                // Source pill (left).
                let src_pill_w = 42.0;
                let src_pill = egui::Rect::from_min_size(
                    egui::pos2(event_left + 2.0, y - chip_h * 0.5 + 1.0),
                    egui::vec2(src_pill_w, chip_h - 2.0),
                );
                painter.rect_filled(src_pill, 3.0, src_color);
                painter.text(
                    src_pill.center(),
                    egui::Align2::CENTER_CENTER,
                    &src_label.to_uppercase(),
                    egui::FontId::monospace(9.0),
                    text_on(src_color),
                );

                // Optional secondary pill (status / from→to).
                let mut text_x = event_left + src_pill_w + 6.0;
                if let Some(status) = &ev.status {
                    let pill_color = match ev.kind {
                        SourceKind::Compass => status_color(status),
                        _ => src_color,
                    };
                    let pill_w = 40.0 + (status.len() as f32 * 4.0).min(40.0);
                    let pill = egui::Rect::from_min_size(
                        egui::pos2(text_x, y - chip_h * 0.5 + 1.0),
                        egui::vec2(pill_w, chip_h - 2.0),
                    );
                    painter.rect_filled(pill, 3.0, pill_color);
                    painter.text(
                        pill.center(),
                        egui::Align2::CENTER_CENTER,
                        &status.to_uppercase(),
                        egui::FontId::monospace(9.0),
                        text_on(pill_color),
                    );
                    text_x = pill.right() + 6.0;
                }
                // `from_to` is intentionally not painted on the chip
                // strip — those are bare IDs and would dominate the
                // visible row. The full sender/recipient line is
                // surfaced in the hover tooltip instead.

                // Summary text — char-truncated to fit the available
                // chip width with a trailing "…". Cleaner than a hard
                // clip-rect cutoff because it always ends at a char
                // boundary with a visible overflow indicator.
                let available_px = (chip_rect.right() - text_x - 4.0).max(0.0);
                let truncated = truncate_to_chip_width(&ev.summary, available_px, 6.0);
                painter.text(
                    egui::pos2(text_x, y),
                    egui::Align2::LEFT_CENTER,
                    &truncated,
                    egui::FontId::monospace(10.0),
                    text_color,
                );

                // Interaction: hover highlight + click + tooltip with
                // full summary + absolute timestamp (truncated chip text
                // often hides context, so surface it on hover).
                if let Some(p) = pointer_pos {
                    if chip_rect.contains(p) {
                        hover_rect = Some((chip_rect, src_color));
                        if viewport_response.clicked() {
                            clicked_event = Some((ev.kind, ev.entity_id));
                        }
                        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                        let time_str = format_time_marker(ev.ts_ns);
                        let summary = ev.summary.clone();
                        let src_label = src_label.clone();
                        let status_label = ev.status.clone();
                        let fromto_label = ev.from_to.clone();
                        let src_color_tip = src_color;
                        egui::Tooltip::always_open(
                            ui.ctx().clone(),
                            ui.layer_id(),
                            egui::Id::new(("timeline_event_tip", ev.entity_id)),
                            egui::PopupAnchor::Pointer,
                        )
                        .gap(12.0)
                        .show(|tip| {
                                tip.set_max_width(360.0);
                                // Header: colored source dot + source
                                // label + timestamp on a single line.
                                tip.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 6.0;
                                    let (dot_rect, _) = ui.allocate_exact_size(
                                        egui::vec2(8.0, 8.0),
                                        egui::Sense::hover(),
                                    );
                                    ui.painter().circle_filled(
                                        dot_rect.center(),
                                        4.0,
                                        src_color_tip,
                                    );
                                    ui.label(
                                        egui::RichText::new(src_label.to_uppercase())
                                            .small()
                                            .monospace()
                                            .strong()
                                            .color(src_color_tip),
                                    );
                                    ui.label(
                                        egui::RichText::new("·")
                                            .small()
                                            .weak(),
                                    );
                                    ui.label(
                                        egui::RichText::new(time_str)
                                            .small()
                                            .monospace()
                                            .weak(),
                                    );
                                });
                                // Optional status + from→to meta line.
                                if status_label.is_some() || fromto_label.is_some() {
                                    tip.horizontal_wrapped(|ui| {
                                        ui.spacing_mut().item_spacing.x = 6.0;
                                        if let Some(st) = status_label {
                                            ui.label(
                                                egui::RichText::new(st.to_uppercase())
                                                    .small()
                                                    .monospace()
                                                    .strong(),
                                            );
                                        }
                                        if let Some(ft) = fromto_label {
                                            ui.label(
                                                egui::RichText::new(ft)
                                                    .small()
                                                    .monospace()
                                                    .weak(),
                                            );
                                        }
                                    });
                                }
                                tip.separator();
                                tip.add(egui::Label::new(summary).wrap());
                                // Full canonical id at the bottom — the
                                // chip strip itself omits ids to keep the
                                // top-level view readable, so the hover
                                // surface is where they live.
                                tip.add(
                                    egui::Label::new(
                                        egui::RichText::new(id_hex(ev.entity_id))
                                            .monospace()
                                            .small()
                                            .weak(),
                                    )
                                    .wrap(),
                                );
                            });
                    }
                }
            }

            if let Some((rect, color)) = hover_rect {
                painter.rect_stroke(
                    rect,
                    3.0,
                    egui::Stroke::new(1.0, color),
                    egui::StrokeKind::Outside,
                );
            }
        }

        if let Some(sel) = clicked_event {
            self.selected_event = Some(sel);
        }
    }
}

/// Format a visible-window duration as a short human-readable span
/// label ("2h", "30m", "3d") for the right-aligned scale chip. Only
/// two significant units — enough precision for a header chip.
fn format_span(secs: f64) -> String {
    let s = secs.max(1.0);
    if s >= 86_400.0 {
        let d = s / 86_400.0;
        if d >= 10.0 { format!("{d:.0}D") } else { format!("{d:.1}D") }
    } else if s >= 3_600.0 {
        let h = s / 3_600.0;
        if h >= 10.0 { format!("{h:.0}H") } else { format!("{h:.1}H") }
    } else if s >= 60.0 {
        format!("{:.0}M", s / 60.0)
    } else {
        format!("{s:.0}S")
    }
}

