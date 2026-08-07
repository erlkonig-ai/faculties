//! Canonical Microsoft Teams observation and synchronization schema.
//!
//! Teams data is an append-only collection of source-scoped identities,
//! immutable message/attachment observations, and causal page-coverage
//! receipts. Authentication material is deliberately absent: bearer tokens,
//! refresh tokens, client secrets, and application configuration belong in an
//! external secret store, never in a shareable data pile.
//!
//! Attachment occurrence entities preserve immutable source evidence
//! (message, source-local id/kind, and occurrence name). Source URLs are
//! repeatable provenance, while canonical file records and byte sizes are
//! additive materializations. This makes fetching ordinary pointer-only Graph
//! attachments a later collection-native DERIVE rather than a rewrite of the
//! source page or a change to attachment identity.

use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::{GenId, Handle, NsTAIInterval, ShortString, U256BE};
use triblespace::prelude::*;

/// Stable extrinsic scope for Teams observations and coverage receipts.
///
/// Minted with `trible genid` on 2026-08-07:
/// `48179822F1000D8F82DF2C43AABD8C6D`.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("48179822F1000D8F82DF2C43AABD8C6D");

pub const DEFAULT_DELTA_URL: &str =
    "https://graph.microsoft.com/v1.0/users/{user_id}/chats/getAllMessages/delta";

pub mod teams {
    use super::*;

    // Attribute IDs below were minted individually with `trible genid` on
    // 2026-08-07. Existing IDs retain their historical field meanings; new
    // IDs describe the collection-native observation/coverage model.
    attributes! {
        /// A message observation's containing logical chat.
        "1E525B603A0060D9FA132B3D4EE9538A" as pub chat: GenId;
        /// Microsoft-local chat id. The entity is globally scoped by `source`.
        "B6089037C04529F55D2A2D1A668DBE95" as pub chat_id: Handle<LongString>;
        /// Microsoft-local message id. Identity also includes the chat.
        "02D2C105E35BD5DD6CF7A1F1B74BA686" as pub message_id: Handle<LongString>;
        /// One raw Graph representation of a semantic message observation.
        "1DE123824D5BDA58F92CD002FCFB2BFF" as pub message_raw: Handle<LongString>;
        /// Logical message which owns an attachment observation.
        "617A66047DCBBDDED1BC5167336FADE0" as pub attachment_message: GenId;
        /// Graph attachment collection (`attachment` or `hosted-content`).
        "E0FC3B5C541A7DA9C56158D41B322623" as pub attachment_kind: ShortString;
        /// Microsoft-local user id. The entity is globally scoped by `source`.
        "5820C49A7A8B4ADBCA4637E3AE2499EB" as pub user_id: Handle<LongString>;

        /// Tenant-qualified Microsoft Graph source named by an entity.
        "0F0DB4037A0C4F7070D684AF92480F82" as pub source: GenId;
        /// Exact Microsoft tenant id used to derive a source entity.
        "DA46346DEC18824BF6D175014AA25A1E" as pub tenant_id: Handle<LongString>;
        /// Logical message represented by an immutable observation entity.
        "F5D32FC62D82A20CE84D515A873BB46A" as pub message: GenId;
        /// Graph `lastModifiedDateTime` of a message observation.
        "8A36C483238853E65085DCB46C895186" as pub modified_at: NsTAIInterval;
        /// Graph `deletedDateTime`, when the observation is a deletion.
        "ADE52EF46FBBE5BA5422FD22267ACD54" as pub deleted_at: NsTAIInterval;
        /// Graph message version/etag; with modified time it names a source version.
        "92BC318B2A215D7BE08795B213C44324" as pub etag: Handle<LongString>;
        /// Display name observed for the author in this message version.
        "69A8805536179FB6E4447B59854FA608" as pub author_name: Handle<LongString>;
        /// Monotone diagnostic depth of a coverage receipt.
        "DE8DE9AAC084A323393944238E143E18" as pub coverage_generation: U256BE;
        /// Exact request URL consumed by one Graph page.
        "26A7228FBA3678FB356A76D62197CE23" as pub coverage_request: Handle<LongString>;
        /// Opaque next/delta URL produced by one Graph page.
        "6E435B4201F7E8487EBBE60EFD724079" as pub coverage_cursor: Handle<LongString>;
        /// `next` for an incomplete round, `delta` for a completed round.
        "CCDB0B26489A4AE7C7FD3385F7489AD8" as pub coverage_kind: ShortString;
        /// Message observation or source tombstone carried by a page.
        "CCF3BCE0AA5D8D7CA79A69E0E769F2A0" as pub coverage_observation: GenId;
        /// `present` or `deleted`; every message observation has exactly one.
        "F8164FF23A7A499756F9A150CA1F587E" as pub message_state: ShortString;
    }

    /// Tenant-qualified Microsoft Graph source.
    #[allow(non_upper_case_globals)]
    pub const kind_source: Id = id_hex!("AF94D22855CA0A2EF939E9B30919863D");
    /// Logical Teams chat.
    #[allow(non_upper_case_globals)]
    pub const kind_chat: Id = id_hex!("5BA4D47ED4358A77E29E372B972CA4F9");
    /// Immutable source version of one logical Teams message.
    #[allow(non_upper_case_globals)]
    pub const kind_message_observation: Id = id_hex!("5AEAF409E604F6F68ECAE0DA0A8742C2");
    /// Source deletion marker for one fully resolved logical message.
    ///
    /// The marker itself has no synthetic timestamp. Its ordering comes from
    /// the coverage receipts which carry it, so a later full observation can
    /// faithfully restore a message deleted by an earlier delta page.
    ///
    /// Minted with `trible genid` on 2026-08-07:
    /// `304424C5B2C65709A134A4BE1ECBE89F`.
    #[allow(non_upper_case_globals)]
    pub const kind_message_tombstone: Id = id_hex!("304424C5B2C65709A134A4BE1ECBE89F");
    /// Causal receipt for one completely persisted Graph delta page.
    #[allow(non_upper_case_globals)]
    pub const kind_coverage: Id = id_hex!("8DE0B4F28A29E87D5E09FF6F6D20F663");
    /// Professional presentation context; versions form a supersession DAG.
    #[allow(non_upper_case_globals)]
    pub const kind_context: Id = id_hex!("F2FB22C36519673BFF3BFE77DB005F6F");
}
