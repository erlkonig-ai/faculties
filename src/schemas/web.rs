//! Web schema: immutable search and fetch events.
//!
//! Provider credentials belong to the fixed Headspace collection as exact
//! immutable Secrets-version references. Web owns only the observations it
//! produces.

use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::LongString;
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
        "0CA16690DE44435B773224C275FD4E76" unsafe as query: Handle<LongString>;
        "D0A6B39F715FE17935540232656CE0A3" unsafe as provider: ShortString;
        "D50E38414AB7068C78602DD56C785634" unsafe as result: GenId;

        "099BE36C62777693D66A5F6183ABE9F2" unsafe as url: Handle<LongString>;
        "A88A91F1F794A30088AB1E4913812D6B" unsafe as title: Handle<LongString>;
        "6C149EFDDCFEAE8EC101A362035F75D7" unsafe as snippet: Handle<LongString>;
        "A16BCA98FDE2E8E15F599F3D76E7CDC8" unsafe as content: Handle<LongString>;
    }

    #[allow(non_upper_case_globals)]
    pub const kind_search: Id = id_hex!("0D70C8051CF577A9263CCFBE76027D0A");
    #[allow(non_upper_case_globals)]
    pub const kind_result: Id = id_hex!("8BCF14DAAC2CE403666FBE58C4368013");
    #[allow(non_upper_case_globals)]
    pub const kind_fetch: Id = id_hex!("91D6FD34AAB1A9C6B24A39D0674F7359");
}
