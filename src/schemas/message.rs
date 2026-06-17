//! Local messages schema: append-only direct messages between people,
//! with read acknowledgements.
//!
//! Used by `message.rs` (the faculty CLI) and by readers (e.g.
//! `orient.rs`) that need the same message/read attribute view.

use triblespace::macros::id_hex;
use triblespace::prelude::*;

pub const DEFAULT_BRANCH: &str = "message";
pub const DEFAULT_RELATIONS_BRANCH: &str = "relations";

pub const KIND_MESSAGE_LABEL: &str = "local_message";
pub const KIND_READ_LABEL: &str = "local_read";

pub const KIND_MESSAGE_ID: Id = id_hex!("A3556A66B00276797FCE8A2742AB850F");
pub const KIND_READ_ID: Id = id_hex!("B663C15BB6F2BF591EA870386DD48537");

pub const KIND_PERSON_ID: Id = id_hex!("D8ADDE47121F4E7868017463EC860726");

pub const KIND_SPECS: [(Id, &str); 2] = [
    (KIND_MESSAGE_ID, KIND_MESSAGE_LABEL),
    (KIND_READ_ID, KIND_READ_LABEL),
];

pub mod local {
    use super::*;

    attributes! {
        "42C4DB210F7EAFAF38F179ADCB4A9D5B" as from: inlineencodings::GenId;
        "95D58D3E68A43979F8AA51415541414C" as to: inlineencodings::GenId;
        "23075866B369B5F393D43B30649469F6" as body: inlineencodings::Handle<blobencodings::LongString>;

        "2213B191326E9B99605FA094E516E50E" as about_message: inlineencodings::GenId;
        "99E92F483731FA6D59115A8D6D187A37" as reader: inlineencodings::GenId;
        "CFEF2E96BC66FF3BE0A39C34E70A5032" as read_at: inlineencodings::NsTAIInterval;
    }
}

pub mod relations_schema {
    use super::*;
    attributes! {
        "299E28A10114DC8C3B1661CD90CB8DF6" as label_norm: inlineencodings::ShortString;
        "3E8812F6D22B2C93E2BCF0CE3C8C1979" as alias_norm: inlineencodings::ShortString;
    }
}
