//! Decide schema: deliberation primitive shared across faculties.
//!
//! A *decision* is a small append-only deliberation: a title + optional
//! context, zero-or-more pro factors, zero-or-more con factors, and an
//! eventual resolution (outcome text + finished_at timestamp). Decisions
//! can be linked to whatever they're *about* via `decide::about` — a mail
//! draft, a compass goal, an arbitrary topic — and other faculties gate
//! their own high-stakes actions on a resolved decision.
//!
//! The point isn't to *extract* a machine-readable verdict from the
//! decision (the outcome is free-form text and remains so); the point is
//! to nudge the deliberation into existence. `decide resolve` itself
//! enforces the "≥1 pro AND ≥1 con" gate (with `--force` as the explicit
//! bypass — a resolved decision with no factors is by definition a
//! forced one, no separate flag needed in the schema). Downstream
//! faculties just check "is it resolved?" and trust the system.
//!
//! Most metadata is reused: `metadata::name` for the decision's title
//! and a factor's text, `metadata::description` for longer context,
//! `metadata::created_at` for proposal time, `metadata::finished_at`
//! for resolution time, `metadata::tag` for kind markers. Only three
//! attrs are unique to decide.

use triblespace::macros::id_hex;
use triblespace::prelude::*;

pub const DEFAULT_BRANCH: &str = "decide";

/// Marks an entity as a deliberation (a decision proposal, possibly
/// resolved). Always has a `metadata::name` (title) and
/// `metadata::created_at`; gains `decide::outcome` and
/// `metadata::finished_at` when resolved.
pub const KIND_DECISION: Id = id_hex!("BA824EF82FE972F1315A790068192691");

/// Marks an entity as a "for" factor — a reason to take the decided
/// action. Always linked to its parent decision via `factor::about_decision`.
/// The factor's own content lives in `metadata::name` (one-liner) and
/// optionally `metadata::description` (longer).
pub const KIND_PRO: Id = id_hex!("01C453F122A83E6255618DFE26984E53");

/// Marks an entity as an "against" factor — a reason not to, or a
/// risk to consider. Mirror-image of KIND_PRO.
pub const KIND_CON: Id = id_hex!("BBD13287E7151B254B49D49A6F11DAFD");

/// Attributes unique to decide. Title/description/timestamps are
/// reused from `metadata::*`.
pub mod decide {
    use super::*;
    attributes! {
        // Optional pointer to the thing this decision is *about* —
        // a mail draft, a compass goal, a wiki fragment, an arbitrary
        // topic. Downstream faculties find their linked decision by
        // pattern-matching on this attribute pointing at their entity.
        "CCB764C79C22F45F11141912C50695D0" as about: inlineencodings::GenId;

        // Free-form resolution text — what was decided and why, in the
        // resolver's own words. Set at resolution time alongside
        // `metadata::finished_at`. Empty until resolved. The decision
        // is "resolved" iff this attribute is non-empty AND
        // finished_at is set; faculties gating on resolution check
        // both.
        "384E8074DB17FFE12FAFFB4344A6D196" as outcome:
            inlineencodings::Handle<blobencodings::LongString>;
    }
}

/// Attributes unique to factors (pros and cons share the same
/// attribute layout; the kind tag tells them apart).
pub mod factor {
    use super::*;
    attributes! {
        // Required pointer to the parent decision entity. Factors
        // without a parent decision are orphans (and queries always
        // join on this attribute, so orphans are silently excluded).
        "D4B3A79837BB2D9E7DA985FFA4C2FEB2" as about_decision: inlineencodings::GenId;
    }
}
