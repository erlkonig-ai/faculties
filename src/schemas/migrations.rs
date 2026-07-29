//! Schema for the `migrations` faculty: which migrations a pile has had.
//!
//! # Why a pile records this
//!
//! Before this existed, migrations were one-off scripts. The failure that
//! argues for it is already in the tree: `message` tells operators to "run
//! playground/migrations/relations_backfill_norm.rs for older piles" and
//! that path does not exist. The only surviving record that the migration
//! was ever needed is prose inside an error string, and the only way to
//! know whether a pile has had it is to guess.
//!
//! Recording an applied migration as a fact makes "is this pile current?"
//! answerable, and makes idempotence a property of the runner rather than
//! something each migration hand-rolls. The record is exhaust of running
//! it — the ledger principle applied to schema evolution.

use triblespace::core::metadata;
use triblespace::prelude::*;

/// Tag marking a record that a migration ran against this pile.
///
/// Minted 2026-07-29 with `trible genid`.
pub const KIND_MIGRATION_APPLIED: Id = id_hex!("8C223D8D84F30E228D1BA8597B431D1C");

/// The default branch these records live on.
pub const DEFAULT_BRANCH: &str = "migrations";

pub mod migration {
    use triblespace::prelude::*;

    attributes! {
        /// The migration's own stable id — minted once, never derived from
        /// its name, so renaming a migration cannot make a pile look
        /// un-migrated.
        "B8D463655318FACF022C11B3856259A6" as pub applied: inlineencodings::GenId;
        /// The persona that ran it, when one was set.
        "651C7F58A3AA068B0BE2059F2A1AC032" as pub by: inlineencodings::GenId;
    }
}

/// Ids of every migration recorded as applied to `space`.
pub fn applied_ids(space: &TribleSet) -> std::collections::HashSet<Id> {
    find!(
        (rec: Id, m: Inline<inlineencodings::GenId>),
        pattern!(space, [{ ?rec @ metadata::tag: KIND_MIGRATION_APPLIED, migration::applied: ?m }])
    )
    .filter_map(|(_, m)| m.try_from_inline().ok())
    .collect()
}
