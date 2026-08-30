//! Web schema: immutable search and fetch events.
//!
//! Provider credentials belong to the fixed Headspace collection as exact
//! immutable Secrets-version references. Web owns only the observations it
//! produces.

use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::UTF8String;
use triblespace::prelude::inlineencodings::{GenId, Handle, ShortString};
use triblespace::prelude::*;

/// Stable extrinsic scope of the Web observation collection.
///
/// Minted with `trible genid` on 2026-08-07:
/// `74897A5A9C573A8A17AD515F782951A2`.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("74897A5A9C573A8A17AD515F782951A2");

/// Exact stopped Repository branch consumed only by the additive cutover.
pub const LEGACY_BRANCH_NAME: &str = "web";

pub mod web_schema {
    use super::*;

    // Attribute IDs minted with: `trible genid`
    attributes! {
        "0CA16690DE44435B773224C275FD4E76" unsafe as query: Handle<UTF8String>;
        "D0A6B39F715FE17935540232656CE0A3" unsafe as provider: ShortString;
        "D50E38414AB7068C78602DD56C785634" unsafe as result: GenId;

        "099BE36C62777693D66A5F6183ABE9F2" unsafe as url: Handle<UTF8String>;
        "A88A91F1F794A30088AB1E4913812D6B" unsafe as title: Handle<UTF8String>;
        "6C149EFDDCFEAE8EC101A362035F75D7" unsafe as snippet: Handle<UTF8String>;
        "A16BCA98FDE2E8E15F599F3D76E7CDC8" unsafe as content: Handle<UTF8String>;
    }

    #[allow(non_upper_case_globals)]
    pub const kind_search: Id = id_hex!("0D70C8051CF577A9263CCFBE76027D0A");
    #[allow(non_upper_case_globals)]
    pub const kind_result: Id = id_hex!("8BCF14DAAC2CE403666FBE58C4368013");
    #[allow(non_upper_case_globals)]
    pub const kind_fetch: Id = id_hex!("91D6FD34AAB1A9C6B24A39D0674F7359");
}

/// Web's operation vocabulary for the generic Egress ledger.
///
/// An egress request names its faculty by [`DEFAULT_SCOPE_ID`] and its
/// operation by one of these. They are Web's, not the ledger's: a second
/// egress faculty mints its own and the broker needs no change.
///
/// Minted with `trible genid` on 2026-08-30.
pub const OPERATION_SEARCH: Id = id_hex!("34BB625AB159D9D0F565E1DE26EF2C89");
/// See [`OPERATION_SEARCH`]. Minted with `trible genid` on 2026-08-30.
pub const OPERATION_FETCH: Id = id_hex!("58DC4A1428609773B3CE7D68FF27A6B5");
