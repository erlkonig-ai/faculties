//! LinkedIn import naming protocol.
//!
//! Relations owns the resulting person/profile facts. This schema only
//! domain-separates deterministic person-anchor names derived from stable
//! LinkedIn URL or email keys; the naming record is not a second source of
//! mutable profile state.

use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;

attributes! {
    /// Canonical `url:<normalized-url>` or `email:<normalized-email>` key
    /// used to derive a new Relations person anchor.
    /// Minted with `trible genid` on 2026-08-08.
    "0D1FACE2C1D76558015933A094CC2C9E" as pub person_key: Handle<LongString>;
}
