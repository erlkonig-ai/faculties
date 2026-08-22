//! Status schema: per-window "currently doing X" updates.
//!
//! A status update is an append-only timestamped event keyed to a window
//! (a relations persona / agent). Latest-per-window = current status; the
//! history is exhaust (a free per-window activity timeline). Mirrors the
//! compass goal-status shape. Native operations use one fixed append-only
//! collection; the historical branch name survives only as stopped-world
//! migration vocabulary.

use triblespace::macros::id_hex;
use triblespace::prelude::*;

/// Stable extrinsic scope for immutable Status events.
///
/// Minted with `trible genid` on 2026-08-09:
/// `5C563832935FD4CFC726D63D2631DC5D`.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("5C563832935FD4CFC726D63D2631DC5D");

/// Exact name of the pre-collection repository branch.
///
/// Live commands never read or write this branch.
pub const STATUS_BRANCH_NAME: &str = "status";

pub const KIND_STATUS_UPDATE: Id = id_hex!("1622DB88E9D9B455EEE1E82470E6730C");

pub mod status {
    use super::*;
    attributes! {
        // The window (relations persona id) this status is about.
        "51D3C4DEDA7BCFCCA4C3D85FFB7CCFAC" unsafe as window: inlineencodings::GenId;
        // The status text ("currently …").
        "0DB5E52B99D75A09E666718147C45208" unsafe as text: inlineencodings::Handle<blobencodings::UTF8String>;
    }
}
