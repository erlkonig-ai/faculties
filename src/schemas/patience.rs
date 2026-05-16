//! Patience schema: timeout extension events appended to the cognition branch.
//!
//! Used by `patience.rs` (the faculty CLI).

use triblespace::macros::id_hex;
use triblespace::prelude::*;

pub const DEFAULT_BRANCH: &str = "cognition";
pub const KIND_TIMEOUT_EXTENSION_ID: Id = id_hex!("75BC66A1C39131B9A0975613AC9B59FD");

pub mod exec_schema {
    use super::*;

    attributes! {
        "AA2F34973589295FA70B538D92CD30F8" as kind: inlineencodings::GenId;
        "C4C3870642CAB5F55E7E575B1A62E640" as about_request: inlineencodings::GenId;
        "442A275ABC6834231FC65A4B89773ECD" as worker: inlineencodings::GenId;
        "7FFF32386EBB2AE92094B7D88DE2743D" as timeout_ms: inlineencodings::U256BE;
        "D8910A14B31096DF94DE9E807B87645F" as requested_at: inlineencodings::NsTAIInterval;
    }
}
