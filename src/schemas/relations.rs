//! Collection-native Relations schema.
//!
//! Person and group ids are stable extrinsic anchors. Mutable state never
//! accumulates on those anchors: exact intrinsic snapshots carry profiles,
//! lifecycle, and group composition. Identity adjudication is an intrinsic
//! predecessor DAG over canonical unordered person pairs.

use triblespace::macros::{attributes, id_hex};
use triblespace::prelude::*;

/// Stable extrinsic scope of the authored Relations collection.
///
/// Minted with `trible genid` on 2026-08-08.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("A36AB53B3F9B4D52AC6BD473C1F8C4F1");

/// Exact marker on a stable person anchor.
pub const KIND_PERSON_ID: Id = id_hex!("D8ADDE47121F4E7868017463EC860726");
/// Exact marker on a stable addressable-group anchor.
pub const KIND_GROUP: Id = id_hex!("2CEE877C6C996CE66B4572CE8863DF04");

/// Intrinsic full-state person profile snapshot.
/// Minted with `trible genid` on 2026-08-08.
pub const KIND_PERSON_PROFILE: Id = id_hex!("BEFF639D71F2AF70BC01E0DBE99C0304");
/// Intrinsic person active/retired lifecycle snapshot.
/// Minted with `trible genid` on 2026-08-08.
pub const KIND_PERSON_LIFECYCLE: Id = id_hex!("717DCED8539A871037AFFC7893F6FF9F");
/// Intrinsic full-state group snapshot.
/// Minted with `trible genid` on 2026-08-08.
pub const KIND_GROUP_SNAPSHOT: Id = id_hex!("A42E379E89D2F3A52EEA7A40771B51BF");
/// Intrinsic same-person/distinct-person verdict snapshot.
/// Minted with `trible genid` on 2026-08-08.
pub const KIND_IDENTITY_VERDICT: Id = id_hex!("4BEAD16C2FDBBDEB7BA37B464594E1CE");

pub mod profile {
    use super::*;

    attributes! {
        /// Stable person anchor described by this snapshot.
        /// Minted with `trible genid` on 2026-08-08.
        "6BB0306AA13B62F7E5490AEB255430E3" as of: inlineencodings::GenId;

        /// Exact aliases in this profile snapshot.
        /// Minted with `trible genid` on 2026-08-08.
        "8663728605F1212E3B454D0E7F09FB76" as alias: inlineencodings::Handle<blobencodings::LongString>;
        /// Exact affinity/relationship labels in this profile snapshot.
        /// Minted with `trible genid` on 2026-08-08.
        "96101F2E1A20978BEBD12BB97D6E84F6" as affinity: inlineencodings::Handle<blobencodings::LongString>;
        /// Tenant-scoped external Teams identifiers.
        /// Minted with `trible genid` on 2026-08-08.
        "9DBA8FAEF649E33919BC708F943F0C2D" as teams_user_id: inlineencodings::Handle<blobencodings::LongString>;
        /// Exact email-address set.
        /// Minted with `trible genid` on 2026-08-08.
        "962F91429CE0432204B12E9A041E56A8" as email: inlineencodings::Handle<blobencodings::LongString>;
        /// Exact phone-number set.
        /// Minted with `trible genid` on 2026-08-08.
        "140A6AAD3F1845694F33B00D97B9AF40" as phone: inlineencodings::Handle<blobencodings::LongString>;

        // These LongString attributes retain their already-published meaning;
        // only their subject moves from the mutable anchor to a sealed profile.
        "F0AD0BBFAC4C4C899637573DC965622E" as first_name: inlineencodings::Handle<blobencodings::LongString>;
        "764DD765142B3F4725B614BD3B9118EC" as last_name: inlineencodings::Handle<blobencodings::LongString>;
        "DC0916CB5F640984EFE359A33105CA9A" as display_name: inlineencodings::Handle<blobencodings::LongString>;
        "E3D486BD7C9C088D908DF1B9E1F4D925" as company: inlineencodings::Handle<blobencodings::LongString>;
        "173B771D35FEE90B83F2731DD3C59EF8" as position: inlineencodings::Handle<blobencodings::LongString>;
        "5A71C103E026FC1AC01E35EDAC274A5C" as profile_url: inlineencodings::Handle<blobencodings::LongString>;
    }
}

pub mod lifecycle {
    use super::*;

    attributes! {
        /// Stable person anchor governed by this lifecycle snapshot.
        /// Minted with `trible genid` on 2026-08-08.
        "36E4966DA6704AA84C44A3E4E8DEB70F" as of: inlineencodings::GenId;
        /// Explicit active/retired state; false means active.
        /// Minted with `trible genid` on 2026-08-08.
        "639BD621C86B6B6C39F08D6E97026988" as retired: inlineencodings::Boolean;
    }
}

pub mod group {
    use super::*;

    attributes! {
        /// Exact member set of a group snapshot.
        "EF5B6F8429FA30D503BA8B8F3ABD5FD9" as member: inlineencodings::GenId;
        /// Stable group anchor described by this snapshot.
        "D944552B560826095BCEAFDAACE6DF66" as snapshot_of: inlineencodings::GenId;
    }
}

pub mod identity {
    use super::*;

    attributes! {
        /// Canonically lower person anchor of the adjudicated pair.
        /// Minted with `trible genid` on 2026-08-08.
        "31B34A0C3B2129DA19ECEF84961E92EC" as low: inlineencodings::GenId;
        /// Canonically higher person anchor of the adjudicated pair.
        /// Minted with `trible genid` on 2026-08-08.
        "86B8EF9DA613C443C27A1A9519222CBE" as high: inlineencodings::GenId;
        /// True means same person; false means explicitly distinct.
        /// Minted with `trible genid` on 2026-08-08.
        "EFBE40002918177DCBAAEC2D20D223FD" as same: inlineencodings::Boolean;
    }
}
