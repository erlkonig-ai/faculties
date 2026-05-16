//! Relations schema: people and their labels, aliases, contact info.
//!
//! Used by `relations.rs` (the faculty CLI) and by any faculty that
//! needs to resolve a person by label or alias (e.g. `local_messages.rs`).

use triblespace::macros::id_hex;
use triblespace::prelude::*;

pub const DEFAULT_BRANCH: &str = "relations";

pub const KIND_PERSON_ID: Id = id_hex!("D8ADDE47121F4E7868017463EC860726");

pub mod relations {
    use super::*;
    attributes! {
        "8F162B593D390E1424394DBF6883A72C" as alias: inlineencodings::ShortString;
        "299E28A10114DC8C3B1661CD90CB8DF6" as label_norm: inlineencodings::ShortString;
        "3E8812F6D22B2C93E2BCF0CE3C8C1979" as alias_norm: inlineencodings::ShortString;
        "32B22FBA3EC2ADC3FFEB48483FE8961F" as affinity: inlineencodings::ShortString;
        "F0AD0BBFAC4C4C899637573DC965622E" as first_name: inlineencodings::Handle<blobencodings::LongString>;
        "764DD765142B3F4725B614BD3B9118EC" as last_name: inlineencodings::Handle<blobencodings::LongString>;
        "DC0916CB5F640984EFE359A33105CA9A" as display_name: inlineencodings::Handle<blobencodings::LongString>;
        "9B3329149D54CB9A8E8075E4AA862649" as teams_user_id: inlineencodings::ShortString;
        "B563A063474CBE62ED25A8D0E9A1853C" as email: inlineencodings::ShortString;
    }
}
