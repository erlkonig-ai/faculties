//! Reason schema: explicit reasoning notes tied to the current execution turn.
//!
//! Used by `reason.rs` (the faculty CLI).

use triblespace::macros::id_hex;
use triblespace::prelude::*;

pub const DEFAULT_BRANCH: &str = "cognition";
pub const KIND_REASON_ID: Id = id_hex!("9D43BB36D8B4A6275CAF38A1D5DACF36");

pub mod reason_schema {
    use super::*;

    attributes! {
        "B10329D5D1087D15A3DAFF7A7CC50696" as text: inlineencodings::Handle<blobencodings::LongString>;
        "E6B1C728F1AE9F46CAB4DBB60D1A9528" as about_turn: inlineencodings::GenId;
        "721DED6DA776F2CF4FB91C54D9F82358" as worker: inlineencodings::GenId;
        "514F4FE9F560FB155450462C8CF50749" as command_text: inlineencodings::Handle<blobencodings::LongString>;
    }
}
