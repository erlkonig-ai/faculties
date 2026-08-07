//! Status schema: per-window "currently doing X" updates.
//!
//! A status update is an append-only timestamped event keyed to a window
//! (a relations persona / zooid). Latest-per-window = current status; the
//! history is exhaust (a free per-window activity timeline). Mirrors the
//! compass goal-status shape. Status events live in their own union collection
//! so high-churn present-tense updates remain independent from relations.

use triblespace::macros::id_hex;
use triblespace::prelude::*;

/// Stable extrinsic scope of the status event collection.
///
/// Minted with `trible genid` on 2026-08-07.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("5C563832935FD4CFC726D63D2631DC5D");

pub const KIND_STATUS_UPDATE: Id = id_hex!("1622DB88E9D9B455EEE1E82470E6730C");

pub mod status {
    use super::*;
    attributes! {
        // The window (relations persona id) this status is about.
        "51D3C4DEDA7BCFCCA4C3D85FFB7CCFAC" as window: inlineencodings::GenId;
        // The status text ("currently …").
        "0DB5E52B99D75A09E666718147C45208" as text: inlineencodings::Handle<blobencodings::LongString>;
    }
}
