//! Collection-native Decide ontology.
//!
//! A decision id is a stable extrinsic anchor. Its proposal is one immutable
//! intrinsic genesis; factors are independent intrinsic occurrences; and a
//! resolution is an intrinsic predecessor DAG. Union therefore preserves
//! concurrent deliberation without timestamp arbitration or mutation of the
//! anchor.

use triblespace::macros::{attributes, id_hex};
use triblespace::prelude::*;

/// Stable extrinsic scope of the authored Decide collection.
///
/// Minted with `trible genid` on 2026-08-08.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("C6B9CAB355E18CD59AF913C870AA3FF8");

/// Exact marker on a stable random decision anchor.
///
/// This retains the already-published meaning of `KIND_DECISION`.
pub const KIND_DECISION: Id = id_hex!("BA824EF82FE972F1315A790068192691");

/// Intrinsic immutable proposal record for one decision anchor.
///
/// Minted with `trible genid` on 2026-08-08.
pub const KIND_DECISION_GENESIS: Id = id_hex!("4380D62FB2434BD85DFA70DF10BFA033");

/// Intrinsic full resolution event in one decision's predecessor DAG.
///
/// Minted with `trible genid` on 2026-08-08.
pub const KIND_RESOLUTION_SNAPSHOT: Id = id_hex!("921DF13B0E932AD46FEA8C26A927482D");

/// Exact pro-side marker on an intrinsic factor occurrence.
///
/// This retains the already-published meaning of `KIND_PRO`.
pub const KIND_PRO: Id = id_hex!("01C453F122A83E6255618DFE26984E53");

/// Exact con-side marker on an intrinsic factor occurrence.
///
/// This retains the already-published meaning of `KIND_CON`.
pub const KIND_CON: Id = id_hex!("BBD13287E7151B254B49D49A6F11DAFD");

pub mod decide {
    use super::*;

    attributes! {
        /// Optional entity the immutable decision genesis concerns.
        /// This retains the already-published meaning.
        "CCB764C79C22F45F11141912C50695D0" as about: inlineencodings::GenId;

        /// Free-form outcome carried by an intrinsic resolution snapshot.
        /// This retains the already-published meaning.
        "384E8074DB17FFE12FAFFB4344A6D196" as outcome:
            inlineencodings::Handle<blobencodings::LongString>;

        /// Stable decision anchor described by an immutable genesis.
        /// Minted with `trible genid` on 2026-08-08.
        "571C6D5F411476FA197B489687E317E1" as of: inlineencodings::GenId;
    }
}

pub mod factor {
    use super::*;

    attributes! {
        /// Stable decision anchor this factor concerns.
        /// This retains the already-published meaning.
        "D4B3A79837BB2D9E7DA985FFA4C2FEB2" as about_decision: inlineencodings::GenId;

        /// Explicit random occurrence token, keeping identical factors distinct.
        /// Minted with `trible genid` on 2026-08-08.
        "FFE5D5C231C39483A9F824649012FD15" as occurrence: inlineencodings::GenId;
    }
}

pub mod resolution {
    use super::*;

    attributes! {
        /// Stable decision anchor governed by this resolution snapshot.
        /// Minted with `trible genid` on 2026-08-08.
        "5FBA407A4315422CD2BA1BD0A5FBD32A" as of: inlineencodings::GenId;

        /// Explicit bypass bit; it is never inferred from later factor state.
        /// Minted with `trible genid` on 2026-08-08.
        "68DBFB130C7CC5A2017D3EEC0D419DE3" as forced: inlineencodings::Boolean;

        /// Exact factor occurrence cited as evidence by this snapshot.
        /// Minted with `trible genid` on 2026-08-08.
        "0D3399D0E9024D344858BE1D59133EA6" as evidence: inlineencodings::GenId;
    }
}
