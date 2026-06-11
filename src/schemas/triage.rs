//! Triage schema: doctor-style diagnostic attributes plus the kind markers
//! and foreign attribute views the faculty reads when cross-referencing
//! cognition, compass, local-messages, and relations branches.
//!
//! Used by `triage.rs` (the faculty CLI). Most of these kind/attribute
//! IDs are duplicated from the faculties that own them; triage keeps its
//! own view so it can inspect piles without coupling to other faculty
//! library modules.

use triblespace::macros::id_hex;
use triblespace::prelude::*;

pub const KIND_PERSON_ID: Id = id_hex!("D8ADDE47121F4E7868017463EC860726");
pub const KIND_LOCAL_MESSAGE_ID: Id = id_hex!("A3556A66B00276797FCE8A2742AB850F");
pub const KIND_LOCAL_READ_ID: Id = id_hex!("B663C15BB6F2BF591EA870386DD48537");
pub const KIND_EXEC_REQUEST_ID: Id = id_hex!("3D2512DAE86B14B9049930F3146A3188");
pub const KIND_EXEC_IN_PROGRESS_ID: Id = id_hex!("2D81A8D840822CF082DE5DE569B53730");
pub const KIND_EXEC_RESULT_ID: Id = id_hex!("DF7165210F066E84D93E9A430BB0D4BD");
pub const KIND_MODEL_REQUEST_ID: Id = id_hex!("1524B4C030D4F10365D9DCEE801A09C8");
pub const KIND_MODEL_IN_PROGRESS_ID: Id = id_hex!("16C69FC4928D54BF93E6F3222B4685A7");
pub const KIND_MODEL_RESULT_ID: Id = id_hex!("DE498E4697F9F01219C75E7BC183DB91");
pub const KIND_REASON_EVENT_ID: Id = id_hex!("9D43BB36D8B4A6275CAF38A1D5DACF36");
pub const KIND_CONTEXT_CHUNK_ID: Id = id_hex!("40E6004417F9B767AFF1F138DE3D3AAC");
pub const REPO_HEAD_ATTR: Id = id_hex!("272FBC56108F336C4D2E17289468C35F");
pub const REPO_PARENT_ATTR: Id = id_hex!("317044B612C690000D798CA660ECFD2A");
pub const REPO_CONTENT_ATTR: Id = id_hex!("4DD4DDD05CC31734B03ABB4E43188B1F");

pub mod config {
    use super::*;
    attributes! {
        "D1DC11B303725409AB8A30C6B59DB2D7" as persona_id: inlineencodings::GenId;
        "950B556A74F71AC7CB008AB23FBB6544" as system_prompt: inlineencodings::Handle<blobencodings::LongString>;
        "79E1B50756FB64A30916E9353225E179" as active_model_profile_id: inlineencodings::GenId;
        "6691CF3F872C6107DCFAD0BCF7CDC1A0" as model_profile_id: inlineencodings::GenId;
        "F9CEA1A2E81D738BB125B4D144B7A746" as model_context_window_tokens: inlineencodings::U256BE;
        "4200F6746B36F2784DEBA1555595D6AC" as model_max_output_tokens: inlineencodings::U256BE;
        "1FF004BB48F7A4F8F72541F4D4FA75FF" as model_context_safety_margin_tokens: inlineencodings::U256BE;
        "095FAECDB8FF205DF591DF594E593B01" as model_chars_per_token: inlineencodings::U256BE;
    }
}

pub mod local {
    use super::*;
    attributes! {
        "95D58D3E68A43979F8AA51415541414C" as to: inlineencodings::GenId;
        "2213B191326E9B99605FA094E516E50E" as about_message: inlineencodings::GenId;
        "99E92F483731FA6D59115A8D6D187A37" as reader: inlineencodings::GenId;
    }
}

pub mod relations {
    use super::*;
    attributes! {
        "8F162B593D390E1424394DBF6883A72C" as alias: inlineencodings::ShortString;
    }
}

pub mod exec {
    use super::*;
    attributes! {
        "AA2F34973589295FA70B538D92CD30F8" as kind: inlineencodings::GenId;
        "79DD6A1A02E598033EDCE5C667E8E3E6" as command_text: inlineencodings::Handle<blobencodings::LongString>;
        "C4C3870642CAB5F55E7E575B1A62E640" as about_request: inlineencodings::GenId;
        "B68F9025545C7E616EB90C6440220348" as exit_code: inlineencodings::U256BE;
        "CA7AF66AAF5105EC15625ED14E1A2AC0" as stdout_text: inlineencodings::Handle<blobencodings::LongString>;
        "BE4D1876B22EAF93AAD1175DB76D1C72" as stderr_text: inlineencodings::Handle<blobencodings::LongString>;
        "E9C77284C7DDCF522A8AC4622FE3FB11" as error: inlineencodings::Handle<blobencodings::LongString>;
        "90307D583A8F085828E1007AE432BF86" as about_thought: inlineencodings::GenId;
    }
}

pub mod model_chat {
    use super::*;
    attributes! {
        "5F10520477A04E5FB322C85CC78C6762" as kind: inlineencodings::GenId;
        "5A14A02113CE43A59881D0717726F465" as about_request: inlineencodings::GenId;
        "DA8E31E47919337B3E00724EBE32D14E" as about_thought: inlineencodings::GenId;
        "B1B904590F0FA70AD1BA247F3D23A6CC" as output_text: inlineencodings::Handle<blobencodings::LongString>;
        "567E35DACDB00C799E75AEED0B6EFDF7" as reasoning_text: inlineencodings::Handle<blobencodings::LongString>;
        "9E9B829C473E416E9150D4B94A6A2DC4" as error: inlineencodings::Handle<blobencodings::LongString>;
        "115637F43C28E6ABE3A1B0C4095CAC03" as input_tokens: inlineencodings::U256BE;
        "F17EB3EABC10A0210403B807BEB25D08" as output_tokens: inlineencodings::U256BE;
        "B680DCFAB2E8D1413E450C89AB156197" as cache_creation_input_tokens: inlineencodings::U256BE;
        "0A9C7D70295A65413375842916821032" as cache_read_input_tokens: inlineencodings::U256BE;
    }
}

pub mod reason {
    use super::*;
    attributes! {
        "B10329D5D1087D15A3DAFF7A7CC50696" as text: inlineencodings::Handle<blobencodings::LongString>;
        "E6B1C728F1AE9F46CAB4DBB60D1A9528" as about_turn: inlineencodings::GenId;
        "514F4FE9F560FB155450462C8CF50749" as command_text: inlineencodings::Handle<blobencodings::LongString>;
    }
}

pub mod context {
    use super::*;
    attributes! {
        "81E520987033BE71EB0AFFA8297DE613" as kind: inlineencodings::GenId;
        "3292CF0B3B6077991D8ECE6E2973D4B6" as summary: inlineencodings::Handle<blobencodings::LongString>;
        "502F7D33822A90366F0F0ADA0556177F" as start_at: inlineencodings::NsTAIInterval;
        "DF84E872EB68FBFCA63D760F27FD8A6F" as end_at: inlineencodings::NsTAIInterval;
        "CB97C36A32DEC70E0D1149E7C5D88588" as left: inlineencodings::GenId;
        "087D07E3D9D94F0C4E96813C7BC5E74C" as right: inlineencodings::GenId;
        "9B83D68AECD6888AA9CE95E754494768" as reference: inlineencodings::GenId; // renamed from `child` (same id): annotation, not tree structure
        "316834CC6B0EA6F073BF5362D67AC530" as about_exec_result: inlineencodings::GenId;
    }
}

pub mod cog {
    use super::*;
    attributes! {
        "07F063ECF1DC9FB3C1984BDB10B98BFA" as kind: inlineencodings::GenId;
        "FA6090FB00EEE2F5EF1E51F1F68EA5B8" as context: inlineencodings::Handle<blobencodings::LongString>;
    }
}
