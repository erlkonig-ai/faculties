//! Teams schema: Microsoft Teams chat ingestion, token cache, delta cursor,
//! and app configuration.
//!
//! Used by `teams.rs` (the faculty CLI). The Teams faculty also uses the
//! archive and files schemas; this module only owns the Teams-specific
//! attributes and kinds.

use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::{GenId, Handle};
use triblespace::prelude::*;

pub const DEFAULT_BRANCH: &str = "teams";
pub const DEFAULT_LOG_BRANCH: &str = "logs";
pub const DEFAULT_DELTA_URL: &str =
    "https://graph.microsoft.com/v1.0/users/{user_id}/chats/getAllMessages/delta";

pub mod teams {
    use super::*;

    attributes! {
        "1E525B603A0060D9FA132B3D4EE9538A" as pub chat: GenId;
        "B6089037C04529F55D2A2D1A668DBE95" as pub chat_id: Handle<LongString>;
        "02D2C105E35BD5DD6CF7A1F1B74BA686" as pub message_id: Handle<LongString>;
        "1DE123824D5BDA58F92CD002FCFB2BFF" as pub message_raw: Handle<LongString>;
        "5820C49A7A8B4ADBCA4637E3AE2499EB" as pub user_id: Handle<LongString>;
        "57AABA4FBA3A5EC6EF28DC80CD6E0919" as pub delta_link: Handle<LongString>;
        "438A29922F91F873A69C3856AA7A553F" as pub access_token: Handle<LongString>;
        "60C85DD37D09D3D27BC6BFA0E8040EA9" as pub refresh_token: Handle<LongString>;
        "0F7784BBDA2EE5B9009DE688472D6F24" as pub token_type: Handle<LongString>;
        "139B46989D7F56C7DFE6259FD74479AC" as pub scope: Handle<LongString>;
        "34ACCCECE281E1A0E191EEEBE7E47A23" as pub tenant: Handle<LongString>;
        "8C6CA6A45DCA9F78420BC216A83F4C22" as pub client_id: Handle<LongString>;
        "0E734F66EBBA45ED022D1EE539B11EBE" as pub client_secret: Handle<LongString>;
    }

    /// Root id for describing the Teams protocol.
    #[allow(non_upper_case_globals)]
    #[allow(dead_code)]
    pub const teams_metadata: Id = id_hex!("CFE203B942D2534CC1212F1866804228");

    /// Tag for Teams chat entities.
    #[allow(non_upper_case_globals)]
    pub const kind_chat: Id = id_hex!("5BA4D47ED4358A77E29E372B972CA4F9");
    /// Tag for Teams cursor entities.
    #[allow(non_upper_case_globals)]
    pub const kind_cursor: Id = id_hex!("18B65C92AC77B1C1E2B3A4D6182A7EE7");
    /// Tag for Teams token cache entities.
    #[allow(non_upper_case_globals)]
    pub const kind_token: Id = id_hex!("7B6DBE9FD29182D97F1699437CF6627C");
    /// Tag for Teams log entries.
    #[allow(non_upper_case_globals)]
    pub const kind_log: Id = id_hex!("CAC47F309F894B23847E9A293F15C9B2");
    /// Tag for Teams app configuration entities.
    #[allow(non_upper_case_globals)]
    pub const kind_config: Id = id_hex!("0D7F4BBE36BD0D6FF4E6C651110D6E8B");
}

// ── Files branch schema (shared with files.rs faculty) ───────────────────
pub const FILES_BRANCH_NAME: &str = "files";

pub mod file_schema {
    use triblespace::macros::id_hex;
    use triblespace::prelude::*;

    #[allow(non_upper_case_globals)]
    pub const KIND_FILE: Id = id_hex!("1F9C9DCA69504452F318BA11E81D47D1");

    pub mod file {
        use triblespace::prelude::*;
        attributes! {
            "C1E3A12230595280F22ABEB8733D082C" as pub content: inlineencodings::Handle<blobencodings::RawBytes>;
            "AA6AB6F5E68F3A9D95681251C2B9DAFA" as pub name: inlineencodings::Handle<blobencodings::LongString>;
            "BFE2C88ECD13D56F80967C343FC072EE" as pub mime: inlineencodings::ShortString;
        }
    }
}
