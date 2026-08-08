//! Collection-native Orient observation schema.
//!
//! Orient persistence is a monotone set of two intrinsic records. A
//! `Baseline(persona)` distinguishes an initialized observer from one that has
//! never consumed a view. A `Seen(persona, source_kind, source_item)` records
//! one exact upstream observation. Neither record carries time, ancestry, or
//! mutable head state.

use triblespace::macros::{attributes, id_hex};
use triblespace::prelude::*;

/// Stable extrinsic scope of the Orient `SimpleArchive`-union collection.
///
/// Minted with `trible genid` on 2026-08-08.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("0EEA654E3BF6DF08A04614904C122099");

/// Intrinsic `Baseline(persona)` marker.
/// Minted with `trible genid` on 2026-08-08.
pub const KIND_BASELINE: Id = id_hex!("B015484F3866EBFA69DD8377D65C724B");

/// Intrinsic `Seen(persona, source_kind, source_item)` marker.
/// Minted with `trible genid` on 2026-08-08.
pub const KIND_SEEN: Id = id_hex!("69142629A37B362F36DA573384EDB9C6");

pub mod observation {
    use super::*;

    attributes! {
        /// Exact Relations person anchor owning this observation.
        /// Minted with `trible genid` on 2026-08-08.
        "CB21CD07804C9C02C42AB3B9CDB4F8B7" as persona: inlineencodings::GenId;

        /// Existing upstream entity-kind id which types `source_item`.
        /// Minted with `trible genid` on 2026-08-08.
        "53500ABEBA5331A8E7C9264C71087DD2" as source_kind: inlineencodings::GenId;

        /// Exact upstream entity observed by the persona.
        /// Minted with `trible genid` on 2026-08-08.
        "5DC77854F78F95BB9ACE52DB4B5AE1EC" as source_item: inlineencodings::GenId;
    }
}
