//! Shared native collection identity for cognition events.
//!
//! `reason`, `patience`, `triage`, and Memory provenance historically shared
//! one `cognition` branch because they form one union dataset.  The fixed
//! descriptor keeps that boundary without making a branch part of any one
//! faculty's identity.

use triblespace::macros::id_hex;
use triblespace::prelude::*;

/// Stable extrinsic scope for cognition events.
///
/// Minted with `trible genid` on 2026-08-07:
/// `1CDB716A21EE56231CB454EF85BE93D3`.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("1CDB716A21EE56231CB454EF85BE93D3");
