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

/// Key-private receipt facts. This deliberately differs from the legacy
/// mixed-persona `orient` collection: its owner is the descriptor's authority.
pub const RECEIPT_COLLECTION_NAME: &str = "orient-receipts";

/// One presented-event receipt. Legacy mixed ledgers also carry a persona;
/// current private collections take their observer from descriptor authority.
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

        /// The standing intention whose due occurrence was presented.
        ///
        /// A habit due event has no record of its own to name, so a receipt
        /// cites the intention and the instant its due began instead of a
        /// derived identity. That is deliberate: an id you must COMPUTE in
        /// order to look it up is a hash-join, and the only reason the older
        /// membership set needed one was that a set of ids cannot answer any
        /// other question. A queryable projection can, so the receipt carries
        /// what the join actually needs.
        ///
        /// Minted with `trible genid` on 2026-09-18.
        "B1103608112B9A8043DAE1B1C10EE26E" as habit: inlineencodings::GenId;

        /// The instant that due occurrence began: the last completion plus the
        /// cooldown. With `habit` it identifies ONE due event, so completing
        /// the intention and coming due again is a different occurrence and is
        /// presented again.
        ///
        /// Minted with `trible genid` on 2026-09-18.
        "6C6D4F69E59F96DD55C996CDDEDE9598" as due_at: inlineencodings::NsTAIInterval;
    }
}
