//! Planner schema: calendar events (RFC 5545 VEVENT-shaped) plus
//! the notes a user attaches to them.
//!
//! Used by `planner.rs` (the faculty CLI). Decomposes RFC 5545
//! VEVENT properties into individual triblespace attributes so
//! queries are native pile patterns; round-trips back to `.ics`
//! by re-serializing the attributes.
//!
//! All-day events are stored as a 24-hour `NsTAIInterval` window
//! at UTC midnight (multi-day all-day events span the whole
//! contiguous range). Re-exporting to `.ics` would emit
//! `DTSTART;VALUE=DATE-TIME` rather than `DTSTART;VALUE=DATE`;
//! that's a v1 acceptable lossiness — the `all_day` boolean
//! re-export hint can be added later if it becomes a problem.

use triblespace::macros::id_hex;
use triblespace::prelude::*;

pub const DEFAULT_BRANCH: &str = "planner";

/// Marks an entity as an event (VEVENT-shaped record).
pub const KIND_EVENT_ID: Id = id_hex!("576743CE8E79C663D116AAAAF5168F40");
/// Marks an entity as a planner note (free-text context attached
/// to an event — minutes, prep, post-meeting takeaways).
pub const KIND_NOTE_ID: Id = id_hex!("AF8C3BF988B4D97B1AAC665F2B9B8FB5");

/// Event attributes — one per RFC 5545 VEVENT property we care
/// about. Time-of-day data lives in a single `time: NsTAIInterval`
/// attribute that holds both DTSTART and DTEND as the inclusive
/// interval bounds; instantaneous events use a zero-length
/// interval (start == end).
pub mod event {
    use super::*;
    attributes! {
        // Original RFC 5545 UID from an ingested .ics, kept for
        // round-trip fidelity. Stored as a blob handle because
        // real-world UIDs can be 100+ chars (Outlook in
        // particular). Self-created events synthesise a UID like
        // `<entity-id>@triblespace`.
        "E9BA10B4508134CAB1B2A2831D0A0553" as ical_uid:
            inlineencodings::Handle<blobencodings::LongString>;
        // Short title — fits the column width of `planner list`
        // and `orient` views without truncation.
        "8E91381379F0567B9E318E253A1D19E6" as summary: inlineencodings::ShortString;
        // Long-form description / agenda / minutes — stored as a
        // blob handle so multi-paragraph descriptions don't
        // bloat the trible store.
        "8A9ADE8F45D85B74F97712C33967A830" as description:
            inlineencodings::Handle<blobencodings::LongString>;
        // The event's time window: NsTAIInterval (inclusive bounds,
        // 32 bytes, range-scannable via byte-lex order). For
        // instantaneous events use start == end. For all-day
        // events use [00:00 UTC, 24:00 UTC] of the named day(s).
        "6D17851364D9A5BA06B71606A49CDFEC" as time: inlineencodings::NsTAIInterval;
        // Raw RFC 5545 RRULE string (e.g.
        // `FREQ=WEEKLY;BYDAY=MO,WE,FR;UNTIL=20271231T235959Z`).
        // Materialised by the `rrule` crate at query time — we
        // store the rule, never the expanded occurrence set.
        "5D8D78E60807B241039E69A49DE8C4E8" as rrule: inlineencodings::ShortString;
        // RDATE: extra one-off occurrence dates outside the RRULE
        // pattern. Repeated.
        "15EBFFA245CF255F2550C8670A544D58" as rdate: inlineencodings::NsTAIInterval;
        // EXDATE: occurrence dates excluded from the RRULE
        // expansion. Repeated.
        "38E77BDD78C7C3C86B2C7EC48CF5CC1E" as exdate: inlineencodings::NsTAIInterval;
        // Free-text location (RFC 5545's LOCATION property) —
        // physical room, video-call URL, etc.
        "A487B9784985D0E285A5CC9C6B053B94" as location: inlineencodings::ShortString;
        // RFC 5545 STATUS — one of `TENTATIVE` / `CONFIRMED` /
        // `CANCELLED`. Cancelled events stay in the pile (history
        // is append-only) but are filtered out of "today" /
        // "week" views by default.
        "BDE09DF9E0DF0A0738727348037EFA84" as status: inlineencodings::ShortString;
        // RFC 5545 TRANSP — `OPAQUE` (blocks the time slot;
        // counts toward "busy") or `TRANSPARENT` (informational,
        // doesn't block — e.g. a deadline reminder). Defaults to
        // `OPAQUE` since "occupies a time slot" is the use case.
        "48AB5C7B026CAFDA33A5FD2699C90C2F" as transp: inlineencodings::ShortString;
        // ATTENDEE: pointer to a `relations` entry. Repeated.
        "B67EF51577844872CB2D1A11B85399B0" as attendee: inlineencodings::GenId;
        // ORGANIZER: pointer to a single `relations` entry.
        "662F53293011B3C0F2A0790D6A5F01FA" as organizer: inlineencodings::GenId;
        // RFC 5545 SEQUENCE — revision counter incremented each
        // time the event is edited. iCal clients use this to
        // resolve which copy of an event is newest when multiple
        // are received.
        "FCE0827D74722DCF89E4AD87F866936D" as sequence: inlineencodings::U256BE;
    }
}

/// Note attributes — `note_about` points at the event a note
/// belongs to; `note_text` is the body. The commit's transaction
/// time orders notes chronologically (no separate timestamp
/// attribute needed).
pub mod note {
    use super::*;
    attributes! {
        "A7971D096F0FE50C896338802A8A3B1A" as note_about: inlineencodings::GenId;
        "4DFEEF75B29536E5F77DFFC54D7B5130" as note_text:
            inlineencodings::Handle<blobencodings::LongString>;
    }
}
