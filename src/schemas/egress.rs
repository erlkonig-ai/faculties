//! Egress ledger: the one collection where a crossing of the sandbox boundary
//! is asked for, granted, or refused.
//!
//! A mind that runs inside a sandbox has no network and no credentials, which
//! is the point of the sandbox. It still needs to search, fetch, send mail and
//! post. This collection is how it asks: it writes a *request* fact, and a
//! broker that does hold a network route and the keys writes a *response* fact
//! naming what happened. Nothing else crosses.
//!
//! The vocabulary here is deliberately faculty-agnostic. A request names the
//! faculty it is for by that faculty's own scope id, names an operation from
//! that faculty's vocabulary, carries one target string and an open bag of
//! string parameters. The broker does not interpret any of it — it dispatches
//! to a handler registered for that faculty. Web is the first handler; `mail`,
//! `linkedin` and `discord` are the same shape with different operations, and
//! adding one requires no change to this schema.
//!
//! Three invariants make the ledger worth having:
//!
//! - **Every crossing is one durable fact.** "Everything this mind ever asked
//!   the outside world for" is a query over [`KIND_REQUEST`]; "what actually
//!   crossed" is a query over [`KIND_RESPONSE`]. Neither is a log file that
//!   can be rotated away.
//! - **A response always states its status positively.** [`STATUS_FULFILLED`]
//!   or [`STATUS_DENIED`] is asserted, never inferred from the absence of
//!   something else, because in an append-only store absence is also what a
//!   partial read looks like.
//! - **A refusal is a fact, not a silence.** A dropped request is
//!   indistinguishable from a slow one; a recorded denial carries the reason
//!   the broker refused and which category it fell in.

use triblespace::macros::{attributes, id_hex};
use triblespace::prelude::blobencodings::UTF8String;
use triblespace::prelude::inlineencodings::{GenId, Handle, ShortString};
use triblespace::prelude::*;

/// Stable extrinsic scope of the Egress ledger collection.
///
/// Minted with `trible genid` on 2026-08-30:
/// `3DD9E288C988FFF6DDA5543E9BDB1EAD`.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("3DD9E288C988FFF6DDA5543E9BDB1EAD");

/// One asked-for crossing of the sandbox boundary.
pub const KIND_REQUEST: Id = id_hex!("C25108AF801EDFD9B441679BC14EB844");
/// The broker's answer to exactly one request: fulfilled or denied.
pub const KIND_RESPONSE: Id = id_hex!("D3337B20C6F1C0E127CFAADE6ED6DBA3");
/// One named option carried by a request.
///
/// Parameters are string-valued on purpose. The ledger stays legible without
/// any faculty's vocabulary loaded, and a value the handler cannot parse
/// becomes a recorded [`DENIAL_MALFORMED`] rather than a type error nobody
/// sees.
pub const KIND_PARAMETER: Id = id_hex!("95CCE643AD1FEB7136A210A4CBE4AF6E");

/// The broker performed the crossing and named the observation it produced.
pub const STATUS_FULFILLED: Id = id_hex!("023C30B29BD077F8F02FE7F3E72AB459");
/// The broker refused the crossing and named why.
pub const STATUS_DENIED: Id = id_hex!("4C1D12C4425F8E78563F765E48A71278");

/// The broker declines to perform this crossing: host or scheme not allowed,
/// no credential configured for the requested provider, operation not served.
pub const DENIAL_POLICY: Id = id_hex!("993C4C971578576DDA5E65E303EA1B77");
/// The request itself does not parse: unknown operation, empty target,
/// unreadable parameter value.
pub const DENIAL_MALFORMED: Id = id_hex!("6D4E710B0BA42074A5B1415B96F4CE0A");
/// The crossing was attempted and the far side failed it.
pub const DENIAL_PROVIDER_ERROR: Id = id_hex!("BDC0BE3ADD878112D03BC35449B82FF5");
/// The far side refused for rate or budget reasons (HTTP 402/429 and kin).
pub const DENIAL_QUOTA: Id = id_hex!("BA7D5BA47662536675F50353159A06A7");

pub mod request {
    use super::*;

    // Anchors minted with `trible genid` on 2026-08-30. These are new
    // attributes, so they use the anchor form in which the value encoding
    // participates in identity.
    attributes! {
        /// Scope id of the faculty this request is addressed to. A faculty is
        /// identified by its own collection scope, so no parallel registry of
        /// faculty names has to be kept in step with one.
        "E4BAB9ECC97C3089AFB8176AD4C0BB99" as pub faculty: GenId;
        /// Operation from the target faculty's vocabulary, e.g.
        /// `schemas::web::OPERATION_FETCH`. The broker never interprets it.
        "7DC1FC2E6665641E6789AF62F09BEA21" as pub operation: GenId;
        /// The one subject of the request: a search query, a URL, a recipient.
        "1AAD55E5AB4154A608AB4B0DEFE2550F" as pub target: Handle<UTF8String>;
        /// Zero or more [`KIND_PARAMETER`] entities.
        "D48D63B91C8EB5EB56D24CFC4C59BAD8" as pub parameter: GenId;
        /// Optional anchor of whoever the crossing is asked for, so a shared
        /// pile can still answer "everything *this* mind fetched, ever".
        "3C47891158B93D1A938B0830C6966446" as pub requester: GenId;
    }
}

pub mod parameter {
    use super::*;

    attributes! {
        "26122E3CAE3D49ECD5D7EEDE0BEFD12D" as pub name: ShortString;
        "FB9D11062AA4D3CBBC14E41AF0249E3E" as pub value: Handle<UTF8String>;
    }
}

pub mod response {
    use super::*;

    attributes! {
        /// The [`KIND_REQUEST`] entity this answers. Exactly one.
        "5CCD466E842B59F023CA5E0CB06432C1" as pub request: GenId;
        /// [`STATUS_FULFILLED`] or [`STATUS_DENIED`], always asserted.
        "387A69D78D5843304BBDBD8158F069C5" as pub status: GenId;
        /// Faculty-native observation this crossing produced, in that
        /// faculty's own collection. Present exactly when fulfilled.
        "A7F883DBCACE45109904109575793030" as pub observation: GenId;
        /// One of the `DENIAL_*` categories. Present exactly when denied.
        "821DDE39C876EED7B498F56097642B6F" as pub denial: GenId;
        /// Human-readable reason. Present exactly when denied.
        "3B62DB29CFBC6BA2ECB71302F354C9F0" as pub reason: Handle<UTF8String>;
    }
}
