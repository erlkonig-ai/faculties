//! Atlas schema: the fixed collection containing inspectable schema metadata.

use triblespace::macros::id_hex;
use triblespace::prelude::*;

/// Stable extrinsic scope for the schema-metadata Atlas.
///
/// Minted with `trible genid` on 2026-08-07:
/// `37F3B30B4EF60E5ADB07FF7961DA4EF0`.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("37F3B30B4EF60E5ADB07FF7961DA4EF0");
