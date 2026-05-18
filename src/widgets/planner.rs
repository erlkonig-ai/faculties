//! Read-only GORBIE-embeddable viewer for the `planner` faculty.
//!
//! Renders the current week's events two ways in one section:
//!
//! 1. **Week grid** — 7-day calendar grid with time on the Y axis
//!    (06:00–22:00), events as coloured blocks. All-day events sit
//!    in a narrow band above the hour grid. Today's column header
//!    is highlighted.
//! 2. **Agenda list** — chronological cards beneath the grid, one
//!    per event, with day headers in between. Each card shows
//!    time range, status, summary, location, recurrence,
//!    attendee/organiser chips, and any attached notes.
//!
//! Event colour = organiser's `relations` colour, so the same visual
//! identity carries between this widget and the others
//! (`relations`, `messages`, `mail`). Status modifies the rendering:
//! CANCELLED events are muted; TENTATIVE events use a lighter fill.
//!
//! v1 limitations: no RRULE expansion (only the base `time` interval
//! renders), no week navigation (always anchored to the current
//! ISO-week), no overlap layout (overlapping events stack on top of
//! one another within their day column).
//!
//! ```ignore
//! let mut panel = PlannerViewer::default();
//! panel.render(ctx, planner_ws, relations_ws.as_mut());
//! ```

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use chrono::{
    DateTime, Datelike, Duration as ChronoDuration, NaiveDate, NaiveTime, TimeZone, Timelike, Utc,
};
use hifitime::Epoch;

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

use crate::schemas::planner::{event, note, KIND_EVENT_ID, KIND_NOTE_ID};
use crate::schemas::relations::{relations as rel, KIND_PERSON_ID};

type TextHandle = Inline<Handle<LongString>>;

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

fn color_faint(ui: &egui::Ui) -> egui::Color32 {
    if ui.visuals().dark_mode {
        egui::Color32::from_rgb(0x3a, 0x42, 0x46)
    } else {
        egui::Color32::from_rgb(0xe2, 0xe2, 0xe2)
    }
}

/// RAL 5012 light blue — fallback when an event has no organiser, so
/// blocks without person-color provenance still render legibly.
fn color_default_event() -> egui::Color32 {
    egui::Color32::from_rgb(0x3b, 0x83, 0xbd)
}

/// RAL 1003 signal yellow — today's column accent in the grid header.
fn color_today() -> egui::Color32 {
    egui::Color32::from_rgb(0xf7, 0xba, 0x0b)
}

fn person_color(id: Id) -> egui::Color32 {
    colorhash::ral_categorical(id.as_ref())
}

// ── Time helpers ─────────────────────────────────────────────────────

fn epoch_to_chrono(e: Epoch) -> DateTime<Utc> {
    let secs = e.to_unix_seconds();
    Utc.timestamp_opt(secs as i64, ((secs.fract() * 1e9) as u32).min(999_999_999))
        .single()
        .unwrap_or_else(Utc::now)
}

fn current_week_monday() -> NaiveDate {
    let today = Utc::now().date_naive();
    today - ChronoDuration::days(today.weekday().num_days_from_monday() as i64)
}

fn is_all_day(start: DateTime<Utc>, end: DateTime<Utc>) -> bool {
    let dur = (end - start).num_seconds();
    start.time() == NaiveTime::from_hms_opt(0, 0, 0).unwrap()
        && dur > 0
        && dur % 86_400 == 0
}

fn format_day_header(date: NaiveDate) -> String {
    let weekday = date.format("%a").to_string().to_uppercase();
    format!("{weekday} {}", date.day())
}

fn format_day_section(date: NaiveDate) -> String {
    let weekday = date.format("%a").to_string().to_uppercase();
    let month = date.format("%b").to_string().to_uppercase();
    format!("{weekday} {} {month} {}", date.day(), date.year())
}

fn format_time_range(start: DateTime<Utc>, end: DateTime<Utc>) -> String {
    if is_all_day(start, end) {
        if (end - start).num_days() <= 1 {
            "ALL DAY".to_string()
        } else {
            format!("ALL DAY × {}", (end - start).num_days())
        }
    } else {
        format!(
            "{:02}:{:02} — {:02}:{:02}",
            start.hour(),
            start.minute(),
            end.hour(),
            end.minute(),
        )
    }
}

// ── Data structs ─────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EventStatus {
    Confirmed,
    Tentative,
    Cancelled,
}

impl EventStatus {
    fn parse(s: &str) -> Self {
        match s.trim().to_ascii_uppercase().as_str() {
            "TENTATIVE" => Self::Tentative,
            "CANCELLED" => Self::Cancelled,
            _ => Self::Confirmed,
        }
    }

    fn badge(self) -> Option<&'static str> {
        match self {
            Self::Confirmed => None,
            Self::Tentative => Some("TENTATIVE"),
            Self::Cancelled => Some("CANCELLED"),
        }
    }
}

#[derive(Clone, Debug)]
struct EventRow {
    summary: String,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    location: Option<String>,
    status: EventStatus,
    rrule: Option<String>,
    attendees: Vec<Id>,
    organizer: Option<Id>,
    notes: Vec<String>,
}

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
        format!("{id:x}")
    }
}

// ── Live snapshot ────────────────────────────────────────────────────

struct PlannerLive {
    cached_head: Option<CommitHandle>,
    relations_cached_head: Option<CommitHandle>,
    events: Vec<EventRow>,
    people: HashMap<Id, Person>,
}

impl PlannerLive {
    fn refresh(
        ws: &mut Workspace<Pile>,
        relations_ws: Option<&mut Workspace<Pile>>,
    ) -> Self {
        let space = ws
            .checkout(..)
            .map(|co| co.into_facts())
            .unwrap_or_else(|e| {
                eprintln!("[planner] checkout: {e:?}");
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
                        eprintln!("[planner] relations checkout: {e:?}");
                        TribleSet::new()
                    });
                (head, build_people(&rspace, rws))
            }
            None => (None, HashMap::new()),
        };

        let events = collect_events(ws, &space);

        PlannerLive {
            cached_head,
            relations_cached_head,
            events,
            people,
        }
    }

    fn display(&self, id: Id) -> String {
        self.people
            .get(&id)
            .map(|p| p.display(id))
            .unwrap_or_else(|| format!("{id:x}"))
    }
}

fn collect_events(ws: &mut Workspace<Pile>, space: &TribleSet) -> Vec<EventRow> {
    let mut by_id: HashMap<Id, EventRow> = HashMap::new();

    for (id,) in find!(
        (e: Id,),
        pattern!(space, [{ ?e @ metadata::tag: KIND_EVENT_ID }])
    ) {
        by_id.insert(
            id,
            EventRow {
                summary: String::new(),
                start: Utc::now(),
                end: Utc::now(),
                location: None,
                status: EventStatus::Confirmed,
                rrule: None,
                attendees: Vec::new(),
                organizer: None,
                notes: Vec::new(),
            },
        );
    }

    for (id, s) in find!(
        (e: Id, s: String),
        pattern!(space, [{ ?e @ event::summary: ?s }])
    ) {
        if let Some(row) = by_id.get_mut(&id) {
            row.summary = s;
        }
    }

    for (id, range) in find!(
        (e: Id, t: (Epoch, Epoch)),
        pattern!(space, [{ ?e @ event::time: ?t }])
    ) {
        if let Some(row) = by_id.get_mut(&id) {
            let (s, end) = range;
            row.start = epoch_to_chrono(s);
            row.end = epoch_to_chrono(end);
        }
    }

    for (id, s) in find!(
        (e: Id, s: String),
        pattern!(space, [{ ?e @ event::location: ?s }])
    ) {
        if let Some(row) = by_id.get_mut(&id) {
            row.location = Some(s);
        }
    }

    for (id, s) in find!(
        (e: Id, s: String),
        pattern!(space, [{ ?e @ event::status: ?s }])
    ) {
        if let Some(row) = by_id.get_mut(&id) {
            row.status = EventStatus::parse(&s);
        }
    }

    for (id, s) in find!(
        (e: Id, s: String),
        pattern!(space, [{ ?e @ event::rrule: ?s }])
    ) {
        if let Some(row) = by_id.get_mut(&id) {
            row.rrule = Some(s);
        }
    }

    for (id, pid) in find!(
        (e: Id, p: Id),
        pattern!(space, [{ ?e @ event::attendee: ?p }])
    ) {
        if let Some(row) = by_id.get_mut(&id) {
            row.attendees.push(pid);
        }
    }

    for (id, pid) in find!(
        (e: Id, p: Id),
        pattern!(space, [{ ?e @ event::organizer: ?p }])
    ) {
        if let Some(row) = by_id.get_mut(&id) {
            row.organizer = Some(pid);
        }
    }

    let note_rows: Vec<(Id, Id, TextHandle)> = find!(
        (n: Id, e: Id, h: TextHandle),
        pattern!(space, [{
            ?n @
            metadata::tag: KIND_NOTE_ID,
            note::note_about: ?e,
            note::note_text: ?h,
        }])
    )
    .collect();
    for (_, eid, h) in note_rows {
        if let Some(row) = by_id.get_mut(&eid) {
            if let Some(text) = read_text(ws, h) {
                row.notes.push(text);
            }
        }
    }

    let mut events: Vec<EventRow> = by_id.into_values().collect();
    events.sort_by_key(|e| e.start);
    events
}

fn build_people(rspace: &TribleSet, rws: &mut Workspace<Pile>) -> HashMap<Id, Person> {
    let person_ids: Vec<Id> = find!(
        (pid: Id,),
        pattern!(rspace, [{ ?pid @ metadata::tag: KIND_PERSON_ID }])
    )
    .map(|(pid,)| pid)
    .collect();

    let mut people: HashMap<Id, Person> =
        person_ids.into_iter().map(|p| (p, Person::default())).collect();

    for (pid, alias) in find!(
        (p: Id, a: String),
        pattern!(rspace, [{ ?p @ rel::alias: ?a }])
    ) {
        if let Some(p) = people.get_mut(&pid) {
            p.alias = Some(alias);
        }
    }
    let first_rows: Vec<(Id, TextHandle)> = find!(
        (p: Id, h: TextHandle),
        pattern!(rspace, [{ ?p @ rel::first_name: ?h }])
    )
    .collect();
    for (pid, h) in first_rows {
        if let Some(p) = people.get_mut(&pid) {
            p.first_name = read_text(rws, h);
        }
    }
    let last_rows: Vec<(Id, TextHandle)> = find!(
        (p: Id, h: TextHandle),
        pattern!(rspace, [{ ?p @ rel::last_name: ?h }])
    )
    .collect();
    for (pid, h) in last_rows {
        if let Some(p) = people.get_mut(&pid) {
            p.last_name = read_text(rws, h);
        }
    }
    let display_rows: Vec<(Id, TextHandle)> = find!(
        (p: Id, h: TextHandle),
        pattern!(rspace, [{ ?p @ rel::display_name: ?h }])
    )
    .collect();
    for (pid, h) in display_rows {
        if let Some(p) = people.get_mut(&pid) {
            p.display_name = read_text(rws, h);
        }
    }
    for (pid, e) in find!(
        (p: Id, e: String),
        pattern!(rspace, [{ ?p @ rel::email: ?e }])
    ) {
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

pub struct PlannerViewer {
    live: Option<PlannerLive>,
}

impl Default for PlannerViewer {
    fn default() -> Self {
        Self { live: None }
    }
}

impl PlannerViewer {
    pub fn new() -> Self {
        Self::default()
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
            self.live = Some(PlannerLive::refresh(
                ws,
                relations_ws.as_mut().map(|w| &mut **w),
            ));
        }

        ctx.section("Planner", |ctx| {
            let Some(live) = self.live.as_ref() else {
                return;
            };

            ctx.grid(|g| {
                let monday = current_week_monday();
                let today = Utc::now().date_naive();

                // Header line — week-of label + event count.
                g.full(|ctx| {
                    let ui = ctx.ui_mut();
                    let label = format!(
                        "WEEK OF {} — {} EVENT{}",
                        monday.format("%-d %b %Y").to_string().to_uppercase(),
                        live.events.len(),
                        if live.events.len() == 1 { "" } else { "S" },
                    );
                    ui.label(
                        egui::RichText::new(label)
                            .monospace()
                            .strong()
                            .small()
                            .color(color_muted(ui)),
                    );
                });

                // Week grid card.
                g.full(|ctx| {
                    render_week_grid(ctx.ui_mut(), live, monday, today);
                });

                // Agenda list.
                if live.events.is_empty() {
                    g.full(|ctx| {
                        let ui = ctx.ui_mut();
                        ui.add_space(16.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                egui::RichText::new("\u{1F4C5}") // 📅
                                    .size(28.0)
                                    .color(color_muted(ui)),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new("No events.")
                                    .monospace()
                                    .small()
                                    .strong()
                                    .color(color_muted(ui)),
                            );
                        });
                        ui.add_space(16.0);
                    });
                } else {
                    let mut by_date: BTreeMap<NaiveDate, Vec<&EventRow>> = BTreeMap::new();
                    for event in &live.events {
                        by_date
                            .entry(event.start.date_naive())
                            .or_default()
                            .push(event);
                    }
                    for (date, events) in by_date.iter() {
                        let header = format_day_section(*date);
                        g.full(|ctx| {
                            let ui = ctx.ui_mut();
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new(header)
                                    .monospace()
                                    .strong()
                                    .small()
                                    .color(color_muted(ui)),
                            );
                        });
                        for event in events {
                            g.full(|ctx| {
                                render_event_card(ctx.ui_mut(), event, live);
                            });
                        }
                    }
                }
            });
        });
    }
}

// ── Week grid ────────────────────────────────────────────────────────

const DAY_HEADER_HEIGHT: f32 = 24.0;
const ALL_DAY_HEIGHT: f32 = 22.0;
const HOUR_START: u32 = 6;
const HOUR_END: u32 = 22;
const PX_PER_HOUR: f32 = 18.0;
const HOUR_LABEL_WIDTH: f32 = 36.0;

fn render_week_grid(
    ui: &mut egui::Ui,
    live: &PlannerLive,
    monday: NaiveDate,
    today: NaiveDate,
) {
    let width = ui.available_width();
    let hours_visible = (HOUR_END - HOUR_START) as f32;
    let grid_height = DAY_HEADER_HEIGHT + ALL_DAY_HEIGHT + hours_visible * PX_PER_HOUR;

    let (rect, _resp) = ui.allocate_exact_size(
        egui::vec2(width, grid_height),
        egui::Sense::hover(),
    );

    let painter = ui.painter().clone();
    let bubble_fill = ui.visuals().window_fill;
    let stroke = egui::Stroke::new(1.0, color_frame(ui));
    let faint_stroke = egui::Stroke::new(0.5, color_faint(ui));
    let muted = color_muted(ui);

    painter.rect_filled(rect, egui::CornerRadius::ZERO, bubble_fill);
    painter.rect_stroke(rect, 0.0, stroke, egui::StrokeKind::Inside);

    let day_grid_left = rect.left() + HOUR_LABEL_WIDTH;
    let day_grid_width = rect.right() - day_grid_left;
    let day_col_width = day_grid_width / 7.0;
    let day_header_top = rect.top();
    let all_day_top = day_header_top + DAY_HEADER_HEIGHT;
    let hour_grid_top = all_day_top + ALL_DAY_HEIGHT;
    let hour_grid_bottom = hour_grid_top + hours_visible * PX_PER_HOUR;

    // Day headers.
    for day in 0..7u32 {
        let date = monday + ChronoDuration::days(day as i64);
        let col_left = day_grid_left + (day as f32) * day_col_width;
        let header_rect = egui::Rect::from_min_size(
            egui::pos2(col_left, day_header_top),
            egui::vec2(day_col_width, DAY_HEADER_HEIGHT),
        );
        let is_today = date == today;
        let header_fill = if is_today { color_today() } else { color_frame(ui) };
        let text_color = if is_today {
            colorhash::text_color_on(header_fill)
        } else {
            muted
        };
        painter.rect_filled(header_rect, egui::CornerRadius::ZERO, header_fill);
        painter.text(
            header_rect.center(),
            egui::Align2::CENTER_CENTER,
            format_day_header(date),
            egui::FontId::monospace(11.0),
            text_color,
        );
    }

    // All-day band background — same colour as day headers but muted.
    let all_day_rect = egui::Rect::from_min_size(
        egui::pos2(day_grid_left, all_day_top),
        egui::vec2(day_grid_width, ALL_DAY_HEIGHT),
    );
    painter.rect_filled(all_day_rect, egui::CornerRadius::ZERO, color_faint(ui));

    // Hour labels & horizontal gridlines.
    for h in HOUR_START..=HOUR_END {
        let y = hour_grid_top + ((h - HOUR_START) as f32) * PX_PER_HOUR;
        painter.text(
            egui::pos2(rect.left() + HOUR_LABEL_WIDTH - 4.0, y),
            egui::Align2::RIGHT_CENTER,
            format!("{h:02}"),
            egui::FontId::monospace(9.0),
            muted,
        );
        painter.line_segment(
            [egui::pos2(day_grid_left, y), egui::pos2(rect.right(), y)],
            faint_stroke,
        );
    }

    // Day-column dividers.
    for day in 0..=7u32 {
        let x = day_grid_left + (day as f32) * day_col_width;
        painter.line_segment(
            [egui::pos2(x, all_day_top), egui::pos2(x, hour_grid_bottom)],
            faint_stroke,
        );
    }

    // Event blocks.
    let week_end = monday + ChronoDuration::days(7);
    for event in &live.events {
        let event_date = event.start.date_naive();
        if event_date < monday || event_date >= week_end {
            continue;
        }
        let day_index = (event_date - monday).num_days() as u32;
        let col_left = day_grid_left + (day_index as f32) * day_col_width;

        if is_all_day(event.start, event.end) {
            let block_rect = egui::Rect::from_min_size(
                egui::pos2(col_left + 1.0, all_day_top + 2.0),
                egui::vec2(day_col_width - 2.0, ALL_DAY_HEIGHT - 4.0),
            );
            paint_event_block(&painter, block_rect, event, true);
        } else {
            let start_hour_f =
                event.start.hour() as f32 + (event.start.minute() as f32) / 60.0;
            let end_hour_f =
                event.end.hour() as f32 + (event.end.minute() as f32) / 60.0;
            let top_y = hour_grid_top
                + (start_hour_f - HOUR_START as f32) * PX_PER_HOUR;
            let bot_y = hour_grid_top
                + (end_hour_f - HOUR_START as f32) * PX_PER_HOUR;
            let top_y = top_y.max(hour_grid_top);
            // Enforce a minimum 14-pt block height so very short
            // events don't render as invisible slivers.
            let bot_y = bot_y.min(hour_grid_bottom).max(top_y + 14.0);

            let block_rect = egui::Rect::from_min_max(
                egui::pos2(col_left + 1.0, top_y),
                egui::pos2(col_left + day_col_width - 1.0, bot_y),
            );
            paint_event_block(&painter, block_rect, event, false);
        }
    }
}

fn paint_event_block(
    painter: &egui::Painter,
    rect: egui::Rect,
    event: &EventRow,
    is_all_day_block: bool,
) {
    let accent = match event.organizer {
        Some(org) => person_color(org),
        None => color_default_event(),
    };
    let (fill, text_color) = match event.status {
        EventStatus::Confirmed => (accent, colorhash::text_color_on(accent)),
        EventStatus::Tentative => (
            accent.gamma_multiply(0.45),
            colorhash::text_color_on(accent),
        ),
        EventStatus::Cancelled => (
            egui::Color32::from_gray(170),
            egui::Color32::from_gray(80),
        ),
    };

    painter.rect_filled(rect, egui::CornerRadius::ZERO, fill);

    let pad = 3.0;
    let text_rect = rect.shrink(pad);
    if text_rect.height() < 9.0 || text_rect.width() < 14.0 {
        return;
    }

    let summary_font = egui::FontId::proportional(11.0);
    let mono_font = egui::FontId::monospace(9.0);

    if is_all_day_block || rect.height() < 28.0 {
        // Single line: just summary (truncated to width).
        let galley =
            ellipsized_galley(painter, &event.summary, &summary_font, text_color, text_rect.width());
        painter.galley(text_rect.min, galley, text_color);
    } else {
        // Two lines: time on top, summary below.
        painter.text(
            text_rect.min,
            egui::Align2::LEFT_TOP,
            format!("{:02}:{:02}", event.start.hour(), event.start.minute()),
            mono_font,
            text_color,
        );
        let galley =
            ellipsized_galley(painter, &event.summary, &summary_font, text_color, text_rect.width());
        painter.galley(
            egui::pos2(text_rect.min.x, text_rect.min.y + 11.0),
            galley,
            text_color,
        );
    }
}

/// Lay out `text` as a single line and truncate with `…` if it doesn't
/// fit `max_width`. Cheap visual truncation — not Unicode-bidi-aware,
/// fine for event titles.
fn ellipsized_galley(
    painter: &egui::Painter,
    text: &str,
    font: &egui::FontId,
    color: egui::Color32,
    max_width: f32,
) -> Arc<egui::Galley> {
    let galley = painter.layout_no_wrap(text.to_string(), font.clone(), color);
    if galley.size().x <= max_width {
        return galley;
    }
    let char_count = text.chars().count().max(1);
    let approx_char_width = galley.size().x / char_count as f32;
    let max_chars = ((max_width / approx_char_width) - 1.0).max(1.0) as usize;
    let truncated: String =
        text.chars().take(max_chars).collect::<String>() + "…";
    painter.layout_no_wrap(truncated, font.clone(), color)
}

// ── Agenda card ──────────────────────────────────────────────────────

fn render_event_card(ui: &mut egui::Ui, event: &EventRow, live: &PlannerLive) {
    let bubble_fill = ui.visuals().window_fill;
    let accent = match event.organizer {
        Some(org) => person_color(org),
        None => color_default_event(),
    };
    let text_on_accent = colorhash::text_color_on(accent);
    let muted = color_muted(ui);

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

            // ── Header: time / status / summary on the accent ──
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
                    ui.spacing_mut().item_spacing.y = 2.0;

                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format_time_range(event.start, event.end))
                                .monospace()
                                .strong()
                                .color(text_on_accent),
                        );
                        if let Some(badge) = event.status.badge() {
                            ui.label(
                                egui::RichText::new(format!("· {badge}"))
                                    .monospace()
                                    .small()
                                    .strong()
                                    .color(text_on_accent),
                            );
                        }
                        if event.rrule.is_some() {
                            ui.label(
                                egui::RichText::new("· \u{21BB}") // ↻
                                    .monospace()
                                    .small()
                                    .color(text_on_accent),
                            );
                        }
                    });

                    let mut summary = egui::RichText::new(&event.summary)
                        .size(15.0)
                        .color(text_on_accent);
                    if matches!(event.status, EventStatus::Cancelled) {
                        summary = summary.strikethrough();
                    }
                    ui.label(summary);
                });

            // ── Body: location / recurrence / attendees / notes ──
            egui::Frame::NONE
                .fill(bubble_fill)
                .corner_radius(egui::CornerRadius::ZERO)
                .inner_margin(egui::Margin {
                    left: 10,
                    right: 10,
                    top: 6,
                    bottom: 8,
                })
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;

                    if let Some(loc) = event.location.as_ref() {
                        ui.label(
                            egui::RichText::new(format!("\u{1F4CD} {loc}")) // 📍
                                .monospace()
                                .small()
                                .color(muted),
                        );
                    }

                    if let Some(rrule) = event.rrule.as_ref() {
                        ui.label(
                            egui::RichText::new(format!("\u{21BB} {rrule}")) // ↻
                                .monospace()
                                .small()
                                .color(muted),
                        );
                    }

                    if event.organizer.is_some() || !event.attendees.is_empty() {
                        ui.add_space(2.0);
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing = egui::vec2(4.0, 4.0);
                            if let Some(org) = event.organizer {
                                render_attendee_chip(
                                    ui,
                                    &live.display(org),
                                    person_color(org),
                                    true,
                                );
                            }
                            for &att in &event.attendees {
                                if Some(att) == event.organizer {
                                    continue;
                                }
                                render_attendee_chip(
                                    ui,
                                    &live.display(att),
                                    person_color(att),
                                    false,
                                );
                            }
                        });
                    }

                    for note_text in &event.notes {
                        ui.add_space(2.0);
                        ui.label(
                            egui::RichText::new(format!("» {note_text}"))
                                .size(13.0)
                                .color(ui.visuals().text_color()),
                        );
                    }
                });
        });
}

fn render_attendee_chip(
    ui: &mut egui::Ui,
    label: &str,
    fill: egui::Color32,
    is_organizer: bool,
) {
    let text = colorhash::text_color_on(fill);
    let display = if is_organizer {
        format!("\u{25CE} {label}") // ◎ = organizer marker
    } else {
        label.to_string()
    };
    egui::Frame::NONE
        .fill(fill)
        .corner_radius(egui::CornerRadius::ZERO)
        .inner_margin(egui::Margin::symmetric(5, 1))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(display)
                    .monospace()
                    .small()
                    .strong()
                    .color(text),
            );
        });
}
