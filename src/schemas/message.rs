//! Collection-native local messaging schema.
//!
//! A message is the canonical intrinsic identity of one complete immutable
//! envelope. A read acknowledgement is likewise the canonical intrinsic fact
//! `(message, reader)`; optional timestamps are merely additive evidence about
//! that fact. Group delivery records the stable group anchor, the exact
//! immutable Relations group snapshot used for delivery, and a typed basis for
//! that choice, so later membership edits cannot rewrite an old audience and a
//! migration cannot masquerade inferred history as directly witnessed fact.

use triblespace::macros::{attributes, id_hex};
use triblespace::prelude::*;

use std::collections::HashSet;

/// Stable extrinsic scope of the Message `SimpleArchive`-union collection.
///
/// Minted with `trible genid` on 2026-08-08.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("D04664CE96355FFF819AC0F2642A81A8");

/// Name of the pre-collection Message branch this scope replaced.
pub const LEGACY_BRANCH_NAME: &str = "message";

/// Intrinsic immutable message envelope.
pub const KIND_MESSAGE_ID: Id = id_hex!("A3556A66B00276797FCE8A2742AB850F");
/// Intrinsic `(message, reader)` acknowledgement.
pub const KIND_READ_ID: Id = id_hex!("B663C15BB6F2BF591EA870386DD48537");

/// The sender directly witnessed this exact Relations group snapshot.
/// Minted with `trible genid` on 2026-08-08.
pub const GROUP_SNAPSHOT_BASIS_WITNESSED: Id = id_hex!("28CB0DE44836C9FA412EAB697F17502A");
/// Atomic legacy migration inferred the snapshot from the old event time.
/// Minted with `trible genid` on 2026-08-08.
pub const GROUP_SNAPSHOT_BASIS_LEGACY_TIME_INFERRED: Id =
    id_hex!("42E01196896E2465625BC74DFB46DA9D");
/// Atomic cutover froze an operator-approved reconstructed audience.
/// Minted with `trible genid` on 2026-08-08.
pub const GROUP_SNAPSHOT_BASIS_CUTOVER_RECONSTRUCTED: Id =
    id_hex!("B2DDAE4D699D3C67C898926B607978C7");

pub const GROUP_SNAPSHOT_BASES: [Id; 3] = [
    GROUP_SNAPSHOT_BASIS_WITNESSED,
    GROUP_SNAPSHOT_BASIS_LEGACY_TIME_INFERRED,
    GROUP_SNAPSHOT_BASIS_CUTOVER_RECONSTRUCTED,
];

pub mod local {
    use super::*;

    attributes! {
        "42C4DB210F7EAFAF38F179ADCB4A9D5B" unsafe as from: inlineencodings::GenId;
        "95D58D3E68A43979F8AA51415541414C" unsafe as to: inlineencodings::GenId;
        "23075866B369B5F393D43B30649469F6" unsafe as body: inlineencodings::Handle<blobencodings::UTF8String>;

        /// Exact immutable Relations group snapshot witnessed at send time.
        /// Present exactly when `to` is a group anchor.
        /// Minted with `trible genid` on 2026-08-08.
        "3E30BBF68B2930146A296BD9346DAFDE" unsafe as group_snapshot: inlineencodings::GenId;
        /// How the exact frozen snapshot was selected. The value is one of
        /// `GROUP_SNAPSHOT_BASES`, never a free-form migration label.
        /// Minted with `trible genid` on 2026-08-08.
        "9DDB67BEBA6ED435D1C007CD8E1ACE1B" unsafe as group_snapshot_basis: inlineencodings::GenId;

        "2213B191326E9B99605FA094E516E50E" unsafe as about_message: inlineencodings::GenId;
        "99E92F483731FA6D59115A8D6D187A37" unsafe as reader: inlineencodings::GenId;
        /// Optional, additive observation about an already-canonical read fact.
        "CFEF2E96BC66FF3BE0A39C34E70A5032" unsafe as read_at: inlineencodings::NsTAIInterval;
    }
}

/// Legacy branch-reader predicate retained for consumers not migrated in this
/// lane. Native Message readers use the frozen-snapshot semantics in
/// [`crate::message::is_inbox_message`].
pub fn is_inbox_message(from: Id, to: Id, reader: Id, reader_groups: &HashSet<Id>) -> bool {
    from != reader && (to == reader || reader_groups.contains(&to))
}

/// Legacy normalized lookup vocabulary retained until its remaining branch
/// consumers move to the native Relations resolver.
pub mod relations_schema {
    use super::*;
    attributes! {
        "299E28A10114DC8C3B1661CD90CB8DF6" unsafe as label_norm: inlineencodings::ShortString;
        "3E8812F6D22B2C93E2BCF0CE3C8C1979" unsafe as alias_norm: inlineencodings::ShortString;
    }
}
