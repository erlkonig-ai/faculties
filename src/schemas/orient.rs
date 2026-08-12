//! Collection-native Orient checkpoint schema.
//!
//! Orient stores only immutable observations of the complete persona-visible
//! view. Physical collection history, rollup layout, and pile offsets are not
//! semantic checkpoint state.

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

pub mod checkpoint {
    use super::*;

    attributes! {
        /// Exact Relations person anchor whose observation this is.
        /// Minted with `trible genid` on 2026-08-11.
        "3CD5AAC437782247E0AE445D199B92E9" as persona: inlineencodings::GenId;

        /// Canonical serialized `WatchedView` value.
        /// Minted with `trible genid` on 2026-08-11.
        "55D805540D0E44B2779FC5116BB66B3F" as view: inlineencodings::Handle<blobencodings::LongString>;
    }
}
