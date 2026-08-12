//! Canonical Microsoft Teams observation and synchronization schema.
//!
//! Teams data is an append-only collection of source-scoped identities,
//! immutable message/attachment observations, and causal page-coverage
//! receipts. Public authentication configuration is represented by immutable
//! source-scoped profile snapshots. Secret-bearing fields are never embedded
//! here: profiles name exact encrypted versions in the shared Secrets
//! collection.
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
        "1E525B603A0060D9FA132B3D4EE9538A" unsafe as pub chat: GenId;
        /// Microsoft-local chat id. The entity is globally scoped by `source`.
        "B6089037C04529F55D2A2D1A668DBE95" unsafe as pub chat_id: Handle<LongString>;
        /// Microsoft-local message id. Identity also includes the chat.
        "02D2C105E35BD5DD6CF7A1F1B74BA686" unsafe as pub message_id: Handle<LongString>;
        /// One raw Graph representation of a semantic message observation.
        "1DE123824D5BDA58F92CD002FCFB2BFF" unsafe as pub message_raw: Handle<LongString>;
        /// Logical message which owns an attachment observation.
        "617A66047DCBBDDED1BC5167336FADE0" unsafe as pub attachment_message: GenId;
        /// Graph attachment collection (`attachment` or `hosted-content`).
        "E0FC3B5C541A7DA9C56158D41B322623" unsafe as pub attachment_kind: ShortString;
        /// Microsoft-local user id. The entity is globally scoped by `source`.
        "5820C49A7A8B4ADBCA4637E3AE2499EB" unsafe as pub user_id: Handle<LongString>;

        /// Tenant-qualified Microsoft Graph source named by an entity.
        "0F0DB4037A0C4F7070D684AF92480F82" unsafe as pub source: GenId;
        /// Exact Microsoft tenant id used to derive a source entity.
        "DA46346DEC18824BF6D175014AA25A1E" unsafe as pub tenant_id: Handle<LongString>;
        /// Logical message represented by an immutable observation entity.
        "F5D32FC62D82A20CE84D515A873BB46A" unsafe as pub message: GenId;
        /// Graph `lastModifiedDateTime` of a message observation.
        "8A36C483238853E65085DCB46C895186" unsafe as pub modified_at: NsTAIInterval;
        /// Graph `deletedDateTime`, when the observation is a deletion.
        "ADE52EF46FBBE5BA5422FD22267ACD54" unsafe as pub deleted_at: NsTAIInterval;
        /// Graph message version/etag; with modified time it names a source version.
        "92BC318B2A215D7BE08795B213C44324" unsafe as pub etag: Handle<LongString>;
        /// Display name observed for the author in this message version.
        "69A8805536179FB6E4447B59854FA608" unsafe as pub author_name: Handle<LongString>;
        /// Monotone diagnostic depth of a coverage receipt.
        "DE8DE9AAC084A323393944238E143E18" unsafe as pub coverage_generation: U256BE;
        /// Exact request URL consumed by one Graph page.
        "26A7228FBA3678FB356A76D62197CE23" unsafe as pub coverage_request: Handle<LongString>;
        /// Opaque next/delta URL produced by one Graph page.
        "6E435B4201F7E8487EBBE60EFD724079" unsafe as pub coverage_cursor: Handle<LongString>;
        /// `next` for an incomplete round, `delta` for a completed round.
        "CCDB0B26489A4AE7C7FD3385F7489AD8" unsafe as pub coverage_kind: ShortString;
        /// Message observation or source tombstone carried by a page.
        "CCF3BCE0AA5D8D7CA79A69E0E769F2A0" unsafe as pub coverage_observation: GenId;
        /// Exact frozen legacy source coordinate consumed by a generation-0 snapshot.
        ///
        /// Minted with `trible genid` on 2026-08-09:
        /// `6E52C046D67BF9446A161A1E3068917E`.
        "6E52C046D67BF9446A161A1E3068917E" unsafe as pub snapshot_source_coordinate: Handle<LongString>;
        /// `present` or `deleted`; every message observation has exactly one.
        "F8164FF23A7A499756F9A150CA1F587E" unsafe as pub message_state: ShortString;

        /// Microsoft application/client id in an auth-profile snapshot.
        ///
        /// Minted with `trible genid` on 2026-08-12:
        /// `35CED3BE8703D51670F55A0A7D7379A2`.
        "35CED3BE8703D51670F55A0A7D7379A2" as pub auth_client_id: Handle<LongString>;
        /// User id whose chats are tracked by an auth-profile snapshot.
        ///
        /// Minted with `trible genid` on 2026-08-12:
        /// `70B7AD9A1FE24A186F6E45DF979AE4C1`.
        "70B7AD9A1FE24A186F6E45DF979AE4C1" as pub auth_user_id: Handle<LongString>;
        /// Canonical space-delimited delegated OAuth scopes.
        ///
        /// Minted with `trible genid` on 2026-08-12:
        /// `3EE1F37036587FA6F678B66474747C50`.
        "3EE1F37036587FA6F678B66474747C50" as pub auth_scopes: Handle<LongString>;
        /// Exact encrypted Secrets version containing the app client secret.
        ///
        /// Minted with `trible genid` on 2026-08-12:
        /// `16BCD72691DE40244513D2D2276C6E6C`.
        "16BCD72691DE40244513D2D2276C6E6C" as pub auth_client_secret_version: GenId;
        /// Exact encrypted Secrets version containing the delegated token bundle.
        ///
        /// Minted with `trible genid` on 2026-08-12:
        /// `32B44CCD1C4C95B87F263BFA39909404`.
        "32B44CCD1C4C95B87F263BFA39909404" as pub auth_delegated_token_version: GenId;
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
    /// Source-scoped generation-0 receipt for one exact frozen legacy snapshot.
    ///
    /// It carries the complete observed event set but deliberately has no
    /// request URL, cursor, coverage kind, or predecessor. The first genuine
    /// Graph page supersedes it at generation 1 and begins from the base
    /// endpoint.
    ///
    /// Minted with `trible genid` on 2026-08-09:
    /// `E1928107BAEE6FBAC8C7B759F074B97A`.
    #[allow(non_upper_case_globals)]
    pub const kind_legacy_snapshot: Id = id_hex!("E1928107BAEE6FBAC8C7B759F074B97A");
    /// Professional presentation context; versions form a supersession DAG.
    #[allow(non_upper_case_globals)]
    pub const kind_context: Id = id_hex!("F2FB22C36519673BFF3BFE77DB005F6F");
    /// Immutable full-state Teams authentication profile. Versions form a
    /// source-scoped predecessor/supersession DAG.
    ///
    /// Minted with `trible genid` on 2026-08-12:
    /// `D029AB8855EF032BD3049900614F1121`.
    #[allow(non_upper_case_globals)]
    pub const kind_auth_profile: Id = id_hex!("D029AB8855EF032BD3049900614F1121");
}
