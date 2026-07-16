//! Orient schema: checkpoint state for the orient faculty plus the subset
//! of message, compass, and config attributes it reads.
//!
//! Used by `orient.rs` (the faculty CLI). The checkpoint attributes are
//! unique to this faculty; the shared message/board/config attributes are
//! duplicated here so orient can stay self-contained.

use triblespace::macros::id_hex;
use triblespace::prelude::*;

pub const CONFIG_BRANCH_ID: Id = id_hex!("6069A136254E1B87E4C0D2E0295DB382");

pub const KIND_MESSAGE_ID: Id = id_hex!("A3556A66B00276797FCE8A2742AB850F");
pub const KIND_READ_ID: Id = id_hex!("B663C15BB6F2BF591EA870386DD48537");
pub const KIND_GOAL_ID: Id = id_hex!("83476541420F46402A6A9911F46FBA3B");
pub const KIND_STATUS_ID: Id = id_hex!("89602B3277495F4E214D4A417C8CF260");
pub const KIND_NOTE_ID: Id = id_hex!("D4E49A6F02A14E66B62076AE4C01715F");
pub const KIND_ORIENT_CHECKPOINT_ID: Id = id_hex!("163114E5F2272D15F21E1994EF418A31");

pub const CONFIG_KIND_ID: Id = id_hex!("A8DCBFD625F386AA7CDFD62A81183E82");

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

pub mod config_schema {
    use super::*;

    attributes! {
        "79F990573A9DCC91EF08A5F8CBA7AA25" as kind: inlineencodings::GenId;
        "D1DC11B303725409AB8A30C6B59DB2D7" as persona_id: inlineencodings::GenId;
    }
}

pub mod board {
    use super::*;
    attributes! {
        "EE18CEC15C18438A2FAB670E2E46E00C" as title: inlineencodings::Handle<blobencodings::LongString>;
        "5FF4941DCC3F6C35E9B3FD57216F69ED" as tag: inlineencodings::ShortString;
        "9D2B6EBDA67E9BB6BE6215959D182041" as parent: inlineencodings::GenId;

        "C1EAAA039DA7F486E4A54CC87D42E72C" as task: inlineencodings::GenId;
        "61C44E0F8A73443ED592A713151E99A4" as status: inlineencodings::ShortString;
        // Acting persona on a status event (see schemas::compass::board::by).
        "34718CDC13D0E3D8750DB58105390AB3" as by: inlineencodings::GenId;
        "47351DF00B3DDA96CB305157CD53D781" as note: inlineencodings::Handle<blobencodings::LongString>;
    }
}

pub mod orient_state {
    use super::*;
    attributes! {
        "EB687567424358B8780A561EA900513C" as at: inlineencodings::NsTAIInterval;
        "6F2D6C7C796B41C2DC7885E7E4D3D750" as local_head: inlineencodings::Handle<blobencodings::SimpleArchive>;
        "6E6A761126C5101CC69BE185A4B4EC4C" as compass_head: inlineencodings::Handle<blobencodings::SimpleArchive>;
        "3A58593A230497DEC735E92381C4C522" as relations_head: inlineencodings::Handle<blobencodings::SimpleArchive>;
        "789078EA4AA95F7B7AD047FF23E04C60" as config_head: inlineencodings::Handle<blobencodings::SimpleArchive>;
        // Persona-scoped view checkpoints: which zooid has seen what.
        // `wait` wakes on NEWS for the persona (a new unread message, a
        // goals change) rather than raw branch movement, so a persona's
        // own acks and sends don't wake its own watcher.
        "AE16414EE1D15DBAC9DF44F77A742E0A" as persona: inlineencodings::GenId;
        "174944957EC01DF2C10D470DBCE4263F" as unread_msg: inlineencodings::GenId;
        "7D7D457CA0184919497E2585CF779125" as goals_view: inlineencodings::Handle<blobencodings::LongString>;
        // Sorted newly-seen note-id/goal-id lines for this checkpoint. Readers
        // union every persona checkpoint. Optional only so pre-notification
        // checkpoints remain readable; new checkpoints always carry it,
        // including an empty delta that marks format initialization.
        "673BA8486630927882901829C286FA15" as notes_view: inlineencodings::Handle<blobencodings::LongString>;
        "5D3327421EB2F0D92FD50CF32D5A513C" as roster_member: inlineencodings::GenId;
    }
}
