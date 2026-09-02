//! Orient's grow-only presentation-ledger schema.
//!
//! A presentation atom records one observer-local workflow fact. It does not
//! copy a source collection's state and does not imply that the source event
//! was read, handled, or acknowledged in its native domain.

use triblespace::macros::id_hex;
use triblespace::prelude::*;

/// Stable scope of the Orient presentation collection.
///
/// Minted with `trible genid` on 2026-08-11.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("F53E5FE10DC419D59973C668ACF018B4");

/// One intrinsic `(persona, event)` presentation atom.
///
/// Minted with `trible genid` on 2026-09-02:
/// `66825BD9E1D9F71615855A96C4C60DB7`.
pub const KIND_PRESENTED: Id = id_hex!("66825BD9E1D9F71615855A96C4C60DB7");

pub mod presentation {
    use super::*;

    attributes! {
        /// Exact observer/persona anchor to whom the event was presented.
        /// Minted with `trible genid` on 2026-09-02.
        "B9290A07396C56825900D3F552969E5E" as persona: inlineencodings::GenId;

        /// Stable identity of the presented source event.
        /// Minted with `trible genid` on 2026-09-02.
        "9676166D45A7EAE009DDB1B56C933526" as event: inlineencodings::GenId;
    }
}
