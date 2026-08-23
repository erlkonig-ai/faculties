//! Body schema: the Reachy Mini body — perception in, action out — and the
//! deliberate sensory/touch captures it keeps in the pile.
//!
//! Renamed from `senses` (2026-06-16): the faculty is both afferent
//! (perception: look/listen/pose/feel) and efferent (action: gesture/move),
//! the whole embodied loop a vision-language-action model closes. "Body" is
//! the honest name for that loop.
//!
//! Only DELIBERATE captures land here — "I choose to remember this". The
//! continuous perception stream (live camera/mic/encoders) stays ephemeral
//! and is never minted into facts (periphery principle): there is no
//! continuous-capture command, so the ephemerality is structural.
//!
//! Each capture entity carries the raw payload (for vision: a PNG frame; for
//! touch: no payload, the signature lives in `pose`), the modality, optional
//! geometry, an optional deliberate note ("why I kept this"), and the
//! proprioceptive context at capture time (JSON state / touch signature) so a
//! future VLA model can ground the moment in the body state that produced it.

use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::{RawBytes, UTF8String};
use triblespace::prelude::inlineencodings::{Handle, ShortString, U256BE};
use triblespace::prelude::*;

/// Stable extrinsic scope for deliberate body captures and intents.
///
/// Minted with `trible genid` on 2026-08-07:
/// `7CF255AAA8D79CA997F991183611C6A5`.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("7CF255AAA8D79CA997F991183611C6A5");

/// Exact name of the pre-collection repository branch.
///
/// Native operations address [`DEFAULT_SCOPE_ID`]. This name is retained only
/// as stopped-world migration input vocabulary.
pub const BODY_BRANCH_NAME: &str = "body";

/// Exact historical Body branch name retained for the stopped-world rewrite.
pub const LEGACY_BODY_BRANCH_NAME: &str = BODY_BRANCH_NAME;

/// Earlier branch containing the squashed pre-rename sensory history.
pub const LEGACY_SENSES_BRANCH_NAME: &str = "senses";

/// Tag for a deliberate capture (a frame, an audio clip, or a felt touch).
pub const KIND_CAPTURE: Id = id_hex!("9C26C6EFD09EB2A401EF009FE9229E16");

// Speech moved OUT of `body` into the dedicated `voice` faculty (2026-06-30):
// speaking is its own organ. Utterances now live on the pile's `voice` branch
// (see `schemas::voice`). The body is the physical Reachy loop only.

/// Tag for an INTENT — a reasoned instruction (the perceive-then-reason model output): gemma's
/// perceive+reason output, the language the VLA is conditioned on. Unlike the
/// raw perception stream (ephemeral, periphery principle), intent is DELIBERATE
/// and kept — it fires only on salience (a handful a minute, never per-frame),
/// so the log is sparse and worth keeping: an auditable, replayable
/// train of thought. The VLA reads the LATEST intent by canonical
/// `metadata::created_at`, then intrinsic event ID for equal-time ties. There
/// is no shared mutable state; selection over the immutable event set is
/// deterministic and monotonic in storage.
pub const KIND_INTENT: Id = id_hex!("285A12E316AD15C9A6EA45969AB85A5C");

pub mod intent {
    use super::*;
    attributes! {
        /// The language instruction gemma emits and the VLA acts on
        /// ("someone's stroking your head — lean in, perk the antennas").
        /// The time coordinate is the canonical `metadata::created_at`.
        "C81A15C5C436CABC9328599858FA1B33" unsafe as pub text: Handle<UTF8String>;
    }
}

pub mod capture {
    use super::*;
    attributes! {
        /// The raw payload, content-addressed (PNG frame, WAV clip, …).
        /// Absent on touch captures (the signature lives in `pose`).
        "FC033C3E4E74105D83E8C44004AD8EB7" unsafe as pub frame: Handle<RawBytes>;
        /// MIME type of the payload (e.g. "image/png", "audio/wav").
        "ACB762F023B9AF391D914A4F00163192" unsafe as pub mime: ShortString;
        /// Pixel width (vision captures).
        "C5251A43428C595C36A276828ECDD232" unsafe as pub width: U256BE;
        /// Pixel height (vision captures).
        "D2CE800163450CE0A34AA164AE66E8FF" unsafe as pub height: U256BE;
        /// "vision" | "audio" | "touch" — the sense that produced this capture.
        "11487C7943FB2ED6A675A0E35477A966" unsafe as pub modality: ShortString;
        /// Optional deliberate note: why this moment was kept.
        "4E12AEBAB07830F8EEEF997957EA27D4" unsafe as pub note: Handle<UTF8String>;
        /// Proprioceptive context at capture (JSON: head pose / joints, or the
        /// touch signature), so a moment can be grounded in the body state
        /// that produced it.
        "509530F784B438714D7A6F2A236F2CFB" unsafe as pub pose: Handle<UTF8String>;
    }
}
