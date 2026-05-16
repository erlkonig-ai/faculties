//! Compass (kanban) schema: goals, statuses, notes, priority relations.
//!
//! Used by `compass.rs` (the faculty CLI) and by any viewer that wants to
//! read compass boards from a pile (the playground dashboard, the pile
//! inspector notebook, etc.).

use triblespace::macros::id_hex;
use triblespace::prelude::*;

pub const KIND_GOAL_LABEL: &str = "goal";
pub const KIND_STATUS_LABEL: &str = "status";
pub const KIND_NOTE_LABEL: &str = "note";
pub const KIND_PRIORITIZE_LABEL: &str = "prioritize";
pub const KIND_DEPRIORITIZE_LABEL: &str = "deprioritize";

pub const KIND_GOAL_ID: Id = id_hex!("83476541420F46402A6A9911F46FBA3B");
pub const KIND_STATUS_ID: Id = id_hex!("89602B3277495F4E214D4A417C8CF260");
pub const KIND_NOTE_ID: Id = id_hex!("D4E49A6F02A14E66B62076AE4C01715F");
pub const KIND_PRIORITIZE_ID: Id = id_hex!("6907A81922DA6DF79966616EA60DEC70");
pub const KIND_DEPRIORITIZE_ID: Id = id_hex!("86C4621538FB0E30CD63BB7A3B847E8B");

pub const KIND_SPECS: [(Id, &str); 5] = [
    (KIND_GOAL_ID, KIND_GOAL_LABEL),
    (KIND_STATUS_ID, KIND_STATUS_LABEL),
    (KIND_NOTE_ID, KIND_NOTE_LABEL),
    (KIND_PRIORITIZE_ID, KIND_PRIORITIZE_LABEL),
    (KIND_DEPRIORITIZE_ID, KIND_DEPRIORITIZE_LABEL),
];

pub const DEFAULT_STATUSES: [&str; 4] = ["todo", "doing", "blocked", "done"];

pub mod board {
    use super::*;

    attributes! {
        "EE18CEC15C18438A2FAB670E2E46E00C" as title: inlineencodings::Handle<blobencodings::LongString>;
        // TODO: migrate to metadata::tag (GenId) — tags should be entities with
        // their own ID + metadata::name, not inline strings. See wiki.rs TagIndex
        // for the correct pattern. This ShortString tag is a legacy design mistake.
        "5FF4941DCC3F6C35E9B3FD57216F69ED" as tag: inlineencodings::ShortString;
        "9D2B6EBDA67E9BB6BE6215959D182041" as parent: inlineencodings::GenId;

        "C1EAAA039DA7F486E4A54CC87D42E72C" as task: inlineencodings::GenId;
        "61C44E0F8A73443ED592A713151E99A4" as status: inlineencodings::ShortString;
        "47351DF00B3DDA96CB305157CD53D781" as note: inlineencodings::Handle<blobencodings::LongString>;
        "B88842D9D00361A0F2728C478C79D75C" as higher: inlineencodings::GenId;
        "18F3446C9E9281A248D370A56395A3F0" as lower: inlineencodings::GenId;
    }
}
