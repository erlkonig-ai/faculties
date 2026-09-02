//! Voice schema: a text-to-speech faculty — speech out, on two channels, with a
//! pile-backed routing policy that decides which audio device each channel
//! plays through.
//!
//! Extracted from `body` (2026-06-30): speaking is its own organ, not a limb of
//! the Reachy body. The body stays the physical Reachy loop (pose/look/feel/act);
//! the voice owns synthesis (F5/mary) and output
//! routing. New utterances and routing config live in one fixed native
//! collection. The historical `voice` Repository branch is migration input
//! only and is never consulted by the live faculty.
//!
//! Two channels, each a hard contract — NOT a soft preference:
//! - `say` — the PRIVATE channel: in-ear/headphone only. If no private device
//!   is connected it falls back to printing text. There is no code path that
//!   lets a `say` utterance play through a room speaker (the invariant is
//!   enforced in `voice.rs`, not here).
//! - `shout` — the PUBLIC channel: broadcast freely (Reachy speaker → room →
//!   laptop), audible by design.
//!
//! Routing is an ORDERED list of device preferences per channel: a `KIND_ROUTE`
//! entity per (channel, device, priority). At speak-time the faculty reads the
//! preferences, intersects with the actually-connected devices, and (for `say`)
//! re-checks each candidate is a private device before it plays. The list is
//! advisory ordering; the privacy guarantee is code, so no misconfiguration can
//! leak a private utterance into a room.

use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::{RawBytes, UTF8String};
use triblespace::prelude::inlineencodings::{Handle, ShortString, U256BE};
use triblespace::prelude::*;

/// Stable extrinsic scope of the one canonical Voice collection.
///
/// Minted with `trible genid` on 2026-08-07 while the first collection-backed
/// Voice implementation was developed:
/// `D51A6FB28036D12290404277F273E909`.
pub const COLLECTION_SCOPE_ID: Id = id_hex!("D51A6FB28036D12290404277F273E909");

/// Marks records admitted to live Voice semantics.
///
/// Both the native writer and the stopped-world canonical rewrite emit this
/// tag. Marker-free rows from the historical identity epoch remain inert if
/// they coexist in a collection. Minted with `trible genid` on 2026-08-11:
/// `6EDFB5684161B58337A0EBB9B10836DC`.
pub const KIND_LIVE_RECORD: Id = id_hex!("6EDFB5684161B58337A0EBB9B10836DC");

/// Canonical channel names — also the `route::channel` discriminator.
pub const CHANNEL_SAY: &str = "say";
pub const CHANNEL_SHOUT: &str = "shout";

/// Tag for an utterance — the voice speaking. Carries the words, the channel it
/// went out on, and the content-addressed audio (so the moment is replayable).
pub const KIND_UTTERANCE: Id = id_hex!("E77C9FC0AAB42065153F337B2FA215E9");

pub mod utterance {
    use super::*;
    attributes! {
        /// The words spoken.
        "F38AD7DD14F63E61BEE1E036FC74FBEA" unsafe as pub text: Handle<UTF8String>;
        /// Channel: "say" (private) | "shout" (aloud).
        "4BD1230C0AA831B3A53D2FB4E5A53583" unsafe as pub channel: ShortString;
        /// The synthesized audio, content-addressed.
        "7C45F21BDF9EEDD6887F860471327F3B" unsafe as pub audio: Handle<RawBytes>;
        /// MIME type of the audio (e.g. "audio/wav").
        "0F013F9C63960A9693B2264E703ED5D6" unsafe as pub mime: ShortString;
    }
}

/// Tag for a ROUTE preference — one (channel, device, priority) entry. A
/// channel's policy is the set of its entries read in ascending priority. The
/// route-set operation publishes a complete timestamped generation, and
/// readers choose the latest generation by `metadata::updated_at`; exact-time
/// ties are unioned. Reconfiguring is a monotonic append, never a mutation.
pub const KIND_ROUTE: Id = id_hex!("1198DF29E642F2598BB4BDF9D4CD1F07");

pub mod route {
    use super::*;
    attributes! {
        /// Which channel this preference belongs to ("say" | "shout").
        "065384592943F9FF9FF3F88BE7538FEC" unsafe as pub channel: ShortString;
        /// A case-insensitive substring matched against a connected device's
        /// name ("AirPods", "Reachy Mini Audio", "MacBook Pro Speakers", …).
        "AF7D8DB4D88A097A4DDA0DD1FF0755A8" unsafe as pub device: ShortString;
        /// Preference order — lower is tried first.
        "F377C84B75C50B5B11FDE856F4C29B5F" unsafe as pub priority: U256BE;
    }
}
