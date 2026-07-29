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

/// Tag marking a *run manifest*: one immutable record of a single migration
/// run across however many branches it touched.
///
/// # Why completeness is not per-branch
///
/// The obvious design records "migration X applied" on each branch it
/// touched, so any branch can answer "am I current?". Under partial failure
/// that answer is a lie assembled from true statements: branch A cut over,
/// branch B did not, and A truthfully reports itself migrated while
/// cross-branch referential integrity is broken. Completeness is a property
/// of the RUN, which no single branch has access to.
///
/// So the manifest names the whole vector — every pinned source commit,
/// every intended output commit, each branch's role — and is
/// content-addressed. The identical blob is attached to every participating
/// head, so there are no copies to reconcile, only one fact referenced from
/// several places. A reader may DISCOVER the run from any participant, but
/// may call it complete only after resolving the entire vector and finding
/// it matches.
///
/// If a cutover fails halfway the manifest stays truthful: it remains
/// evidence of an incomplete run, which an applied-flag cannot express.
/// (Design settled with liora-gpt, 2026-07-29.)
///
/// Minted 2026-07-29 with `trible genid`.
pub const KIND_RUN_MANIFEST: Id = id_hex!("2D284967A061668798453DBD05131541");

pub mod run {
    use triblespace::prelude::*;

    attributes! {
        /// The run manifest an entity belongs to — the shared handle every
        /// participating head carries.
        "BB8EE6267FA7EDF7D601F4740B882627" as pub manifest: inlineencodings::GenId;
        /// A branch this run touched, and the commit its content was pinned
        /// at when the plan was computed. Re-checked at apply: if the branch
        /// has moved, the plan describes a state that no longer exists and
        /// must be refused rather than applied to a moved target.
        ///
        /// This names a CONTENT COMMIT, never a branch-metadata handle —
        /// the manifest is attached to those same heads, so naming their
        /// metadata would be a self-reference cycle.
        "BC9E3081276313BAAC0EB8D5CF1E4EB4" as pub pinned_source: inlineencodings::GenId;
        /// The content commit this run intends the branch to end at.
        "C67FA6996E9FBD16F53E1BB38E8C2F34" as pub intended_output: inlineencodings::GenId;
        /// What the branch is to this run — the local role, which is what
        /// makes a single participating head legible on its own.
        "ADD5D2AEDDFB923273DCFAD6F0E26D79" as pub role: inlineencodings::ShortString;
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
