//! Collection-native Orient checkpoint schema.
//!
//! Orient stores immutable snapshots of the complete persona-visible view plus
//! grow-only `Seen` observations. Physical collection history, rollup layout,
//! and pile offsets are not semantic checkpoint state.

use triblespace::macros::id_hex;
use triblespace::prelude::*;

/// Stable scope of the native Orient checkpoint collection.
///
/// Minted with `trible genid` on 2026-08-11.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("F53E5FE10DC419D59973C668ACF018B4");

/// One immutable `(persona, canonical view, point time)` checkpoint event.
///
/// Minted with `trible genid` on 2026-08-11.
pub const KIND_CHECKPOINT_EVENT: Id = id_hex!("34D66D3B791F4F16C9EFD375163CB1FA");

/// One immutable proof that a persona has observed a note identity.
///
/// Originally minted with `trible genid` on 2026-08-08 and reused here with
/// its exact `Seen(persona, source_kind, source_item)` semantics.
pub const KIND_SEEN: Id = id_hex!("69142629A37B362F36DA573384EDB9C6");

/// One immutable proof that a persona has explicitly initialized the
/// grow-only seen-note frontier.
///
/// Minted with `trible genid` on 2026-08-12:
/// `4CC44C94FC3E0AFA1F20FC9E87971ED4`.
pub const KIND_SEEN_FRONTIER: Id = id_hex!("4CC44C94FC3E0AFA1F20FC9E87971ED4");

pub mod checkpoint {
    use super::*;

    attributes! {
        /// Exact persona anchor whose observation this is. The anchor may
        /// predate its Relations profile.
        /// Minted with `trible genid` on 2026-08-11.
        "3CD5AAC437782247E0AE445D199B92E9" as persona: inlineencodings::GenId;

        /// Canonical serialized `WatchedView` value.
        /// Minted with `trible genid` on 2026-08-11.
        "55D805540D0E44B2779FC5116BB66B3F" as view: inlineencodings::Handle<blobencodings::LongString>;
    }
}

pub mod observation {
    use super::*;

    attributes! {
        /// Exact observer/persona anchor whose observation this is. The
        /// anchor may predate its Relations profile.
        /// Anchor minted with `trible genid` on 2026-08-08.
        "CB21CD07804C9C02C42AB3B9CDB4F8B7" as persona: inlineencodings::GenId;

        /// Semantic kind of the observed entity (currently KIND_NOTE_ID).
        /// Anchor minted with `trible genid` on 2026-08-08.
        "53500ABEBA5331A8E7C9264C71087DD2" as source_kind: inlineencodings::GenId;

        /// Exact observed entity anchor.
        /// Anchor minted with `trible genid` on 2026-08-08.
        "5DC77854F78F95BB9ACE52DB4B5AE1EC" as source_item: inlineencodings::GenId;
    }
}
