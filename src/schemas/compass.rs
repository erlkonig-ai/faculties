//! Collection-native Compass schema.
//!
//! Goal ids are stable extrinsic anchors. Their immutable descriptive fields
//! live in one intrinsic genesis record. Notes are independent ledger
//! occurrences. Status and board priority are intrinsic full-state snapshots
//! whose `metadata::supersedes` edges form explicit predecessor DAGs.

use triblespace::macros::{attributes, id_hex};
use triblespace::prelude::*;

/// Stable extrinsic scope of the authored Compass collection.
///
/// Minted with `trible genid` on 2026-08-08.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("B9566CF892C55CCB0E58411E1B18CD7F");

/// Stable goal anchor.
/// Minted with `trible genid` on 2026-08-08.
pub const KIND_GOAL: Id = id_hex!("E28B47D3EEC8AB65F4096E50FCC032C6");
/// Intrinsic immutable description of one goal anchor.
/// Minted with `trible genid` on 2026-08-08.
pub const KIND_GOAL_GENESIS: Id = id_hex!("D0CCD84AEF68BCB1083AD5AB6514FF9E");
/// Independent additive note occurrence.
/// Minted with `trible genid` on 2026-08-08.
pub const KIND_NOTE: Id = id_hex!("846652BA3DEEC9ADC73D0A17F4C18772");
/// Intrinsic full-state status snapshot for one goal.
/// Minted with `trible genid` on 2026-08-08.
pub const KIND_STATUS_SNAPSHOT: Id = id_hex!("C59D4BAB989BBD8A4F509C6103E34027");
/// Intrinsic full-board priority snapshot.
/// Minted with `trible genid` on 2026-08-08.
pub const KIND_PRIORITY_SNAPSHOT: Id = id_hex!("974590991741BA7361EE94E024AC47AE");
/// Intrinsic ordered pair used by a priority snapshot.
/// Minted with `trible genid` on 2026-08-08.
pub const KIND_PRIORITY_EDGE: Id = id_hex!("8E118E43D3BF8310C34BCA71B213775E");
/// Intrinsic canonical user tag, named through `metadata::name`.
/// Minted with `trible genid` on 2026-08-08.
pub const KIND_TAG: Id = id_hex!("58ADB7B29613AC4C594A303767C49A69");

pub const DEFAULT_STATUSES: [&str; 4] = ["todo", "doing", "blocked", "done"];

pub mod goal {
    use super::*;

    attributes! {
        /// Stable goal anchor described by this genesis record.
        /// Minted with `trible genid` on 2026-08-08.
        "5B0D4715864A3D29BA461E82D053229F" as of: inlineencodings::GenId;

        // These ids retain their already-published meanings; only their
        // subject moves from a mutable goal anchor to its sealed genesis.
        "EE18CEC15C18438A2FAB670E2E46E00C" as title: inlineencodings::Handle<blobencodings::LongString>;
        "9D2B6EBDA67E9BB6BE6215959D182041" as parent: inlineencodings::GenId;
    }
}

pub mod event {
    use super::*;

    attributes! {
        /// Optional acting Relations person. Attribution only.
        "34718CDC13D0E3D8750DB58105390AB3" as by: inlineencodings::GenId;
    }
}

pub mod note {
    use super::*;

    attributes! {
        /// Fresh entropy token making otherwise-identical note occurrences
        /// distinct while leaving the note entity itself intrinsic and sealed.
        /// Minted with `trible genid` on 2026-08-08.
        "7DE97CCF8D5EF7C393763BF2B122472C" as occurrence: inlineencodings::GenId;
        /// Goal to which this ledger occurrence belongs.
        "C1EAAA039DA7F486E4A54CC87D42E72C" as of: inlineencodings::GenId;
        "47351DF00B3DDA96CB305157CD53D781" as body: inlineencodings::Handle<blobencodings::LongString>;
        /// Opaque exact reference such as `wiki:0123abcd`.
        "FD59B704D0F1D06AF14102ADCB5F6FF0" as reference: inlineencodings::Handle<blobencodings::LongString>;
    }
}

pub mod status {
    use super::*;

    attributes! {
        /// Goal whose complete scalar status is captured by this snapshot.
        "C1EAAA039DA7F486E4A54CC87D42E72C" as of: inlineencodings::GenId;
        "61C44E0F8A73443ED592A713151E99A4" as value: inlineencodings::ShortString;
    }
}

pub mod priority {
    use super::*;

    attributes! {
        /// Exact set of priority-edge record ids in a board snapshot.
        /// Minted with `trible genid` on 2026-08-08.
        "37E63417D1E6781A0FF0B2A95919A56A" as edge: inlineencodings::GenId;
        "B88842D9D00361A0F2728C478C79D75C" as higher: inlineencodings::GenId;
        "18F3446C9E9281A248D370A56395A3F0" as lower: inlineencodings::GenId;
    }
}
