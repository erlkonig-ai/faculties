//! Web schema: search and fetch events, plus the config subset that holds
//! provider API keys (Tavily, Exa).
//!
//! Used by `web.rs` (the faculty CLI).

use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::{Blake3, GenId, Handle, ShortString};
use triblespace::prelude::*;

pub const CONFIG_BRANCH_ID: Id = id_hex!("6069A136254E1B87E4C0D2E0295DB382");
pub const CONFIG_KIND_ID: Id = id_hex!("A8DCBFD625F386AA7CDFD62A81183E82");

pub mod config_schema {
    use super::*;

    attributes! {
        "328B29CE81665EE719C5A6E91695D4D4" as tavily_api_key: Handle<LongString>;
        "AB0DF9F03F28A27A6DB95B693CC0EC53" as exa_api_key: Handle<LongString>;
    }
}

pub mod web_schema {
    use super::*;

    // Attribute IDs minted with: `trible genid`
    attributes! {
        "0CA16690DE44435B773224C275FD4E76" as query: Handle<LongString>;
        "D0A6B39F715FE17935540232656CE0A3" as provider: ShortString;
        "D50E38414AB7068C78602DD56C785634" as result: GenId;

        "099BE36C62777693D66A5F6183ABE9F2" as url: Handle<LongString>;
        "A88A91F1F794A30088AB1E4913812D6B" as title: Handle<LongString>;
        "6C149EFDDCFEAE8EC101A362035F75D7" as snippet: Handle<LongString>;
        "A16BCA98FDE2E8E15F599F3D76E7CDC8" as content: Handle<LongString>;
    }

    #[allow(non_upper_case_globals)]
    pub const kind_search: Id = id_hex!("0D70C8051CF577A9263CCFBE76027D0A");
    #[allow(non_upper_case_globals)]
    pub const kind_result: Id = id_hex!("8BCF14DAAC2CE403666FBE58C4368013");
    #[allow(non_upper_case_globals)]
    pub const kind_fetch: Id = id_hex!("91D6FD34AAB1A9C6B24A39D0674F7359");
}
