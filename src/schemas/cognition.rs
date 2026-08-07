//! Shared collection identity for the cognition event stream.
//!
//! `reason`, `patience`, `triage`, and memory provenance historically share
//! one `cognition` branch because they form one union dataset, not because a
//! branch is part of any individual faculty's identity. Collection-native
//! writers preserve that boundary with this stable extrinsic scope.

use triblespace::macros::id_hex;
use triblespace::prelude::*;

/// Stable extrinsic scope for cognition events.
///
/// Minted with `trible genid` on 2026-08-07:
/// `1CDB716A21EE56231CB454EF85BE93D3`.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("1CDB716A21EE56231CB454EF85BE93D3");

/// Input name used only by the future coordinated legacy migration.
///
/// The migration belongs to the whole cognition dataset and must run exactly
/// once after all of its readers and writers have moved to collections. It is
/// deliberately not exposed by any one faculty.
pub const LEGACY_BRANCH_NAME: &str = "cognition";
