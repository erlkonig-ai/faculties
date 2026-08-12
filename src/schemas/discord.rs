//! Discord schema: stable upstream anchors, immutable semantic observations,
//! attachment occurrences, and explicit ingestion coverage.
//!
//! Used by `discord.rs` (the faculty CLI). Message observations use the generic
//! `archive::*` schema for their common projection (author / content / reply_to
//! / kind_message); this module owns only Discord-specific identity and
//! context. Attachment occurrences link to canonical file records built with
//! the shared `faculties::files` model.
//!
//! ## Identity
//!
//! Discord snowflakes are globally unique upstream, but mutable Discord
//! resources must not become mutable entities in a union-only collection. A
//! message snowflake therefore derives a stable identity anchor carrying only
//! [`discord::message_id`]. Each semantic version is a separate intrinsic
//! observation linked to that anchor through [`discord::message`]. Volatile
//! REST response state is deliberately absent. Discord users follow the same
//! pattern: messages point to stable user anchors, while names are independent
//! profile observations.
//!
//! Coverage is an integer interval `(after_exclusive, through_inclusive]`, not
//! a scalar high-water mark. Baseline intervals make the intentionally bounded
//! first import explicit; ordinary intervals may advance a reader only when
//! they connect to that baseline cover.

use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::{GenId, Handle, U256BE};
use triblespace::prelude::*;

/// Stable extrinsic scope of the Discord observation collection.
///
/// Minted with `trible genid` on 2026-08-07:
/// `908A81B67AF50D568C3863E7D6708EEB`.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("908A81B67AF50D568C3863E7D6708EEB");

/// Exact name of the stopped legacy Repository branch consumed by migration.
/// Native reads and writes never consult this coordinate.
pub const LEGACY_BRANCH_NAME: &str = "discord";

pub mod discord {
    use super::*;

    attributes! {
        /// Link from a channel entity to its parent guild.
        "E3022EC14FD000BB8556CD32C2C68E59" unsafe as pub guild: GenId;
        /// Link from a message entity to its channel.
        "B8EA57CD650A678ACA5D1479BF195C4C" unsafe as pub channel: GenId;
        /// Link from an immutable message observation to the stable identity
        /// anchor derived from the upstream Discord message snowflake.
        ///
        /// Minted with `trible genid` on 2026-08-07:
        /// `4B9C024EDD627A4E8786E01B196FDF16`.
        "4B9C024EDD627A4E8786E01B196FDF16" as pub message: GenId;
        /// Link from an immutable Discord profile observation to its stable
        /// Discord user anchor.
        ///
        /// Minted with `trible genid` on 2026-08-08:
        /// `CE2A12E5A260253138C86DD2D15654C7`.
        "CE2A12E5A260253138C86DD2D15654C7" as pub user: GenId;
        /// External Discord snowflake for a guild (server). Stored
        /// as a string — Discord ids are u64 but the REST API
        /// ships them as strings to survive JavaScript clients.
        "9E8EC81F5C14805CCFD4930A4B877138" unsafe as pub guild_id: Handle<LongString>;
        /// External Discord snowflake for a channel.
        "7C943A11E09C922989CAFE22B92E9A51" unsafe as pub channel_id: Handle<LongString>;
        /// External Discord snowflake for a message.
        "758C42164B566C2AFECBCD7129163A34" unsafe as pub message_id: Handle<LongString>;
        /// External Discord snowflake for a user.
        "2A74F35C6720A0C60BF43D30DF272F85" unsafe as pub user_id: Handle<LongString>;
        /// Full Discord JSON body of a message. Stored raw so
        /// future code can derive additional fields without
        /// re-fetching.
        #[allow(dead_code)]
        "5B9DCF6170CD775FC5DA22C8DB96599D" unsafe as pub message_raw: Handle<LongString>;
        /// Bot token (passed to the REST API as `Authorization:
        /// Bot <token>`). One token per bot identity; a caller
        /// who operates multiple bots would tag the token entity
        /// with a different `kind` or a user-scoped id.
        #[allow(dead_code)]
        "E20FEC3E1714D5EDC556936AE1C0F463" unsafe as pub bot_token: Handle<LongString>;
        /// Per-channel pagination cursor — the snowflake of the
        /// newest message we ingested. Next sync fetches
        /// `?after=<cursor>`. Stored as a LongString handle for
        /// consistency with the other snowflake attributes.
        #[allow(dead_code)]
        "3C510E125ACE09DC9B297D533C0F13B7" unsafe as pub cursor_last_message_id: Handle<LongString>;
        /// Exclusive lower endpoint of one fully persisted numeric coverage
        /// interval.
        ///
        /// Minted with `trible genid` on 2026-08-08:
        /// `A37BBC85528AF14B6C20280886B7A537`.
        "A37BBC85528AF14B6C20280886B7A537" as pub receipt_after_exclusive: U256BE;
        /// Inclusive upper endpoint of one fully persisted numeric coverage
        /// interval.
        ///
        /// Minted with `trible genid` on 2026-08-07:
        /// `8B9F2C90AB42911696E17F49974CD28B`.
        "8B9F2C90AB42911696E17F49974CD28B" as pub receipt_through_inclusive: U256BE;
    }

    /// Root id for describing the Discord protocol in metadata.
    #[allow(non_upper_case_globals)]
    #[allow(dead_code)]
    pub const discord_metadata: Id = id_hex!("2D7920FB46B6821912F51371BF1FB4FE");

    /// Tag for Discord guild (server) entities.
    #[allow(non_upper_case_globals)]
    pub const kind_guild: Id = id_hex!("6D2F005AEAE95696708C50DDE1E09BED");
    /// Tag for Discord channel entities.
    #[allow(non_upper_case_globals)]
    pub const kind_channel: Id = id_hex!("7812454E8EFBB87245AE770B48EFC611");
    /// Tag for stable Discord user anchors.
    ///
    /// Minted with `trible genid` on 2026-08-08:
    /// `3548F7AC7E229BCFAD1347FEC256C25C`.
    #[allow(non_upper_case_globals)]
    pub const kind_user: Id = id_hex!("3548F7AC7E229BCFAD1347FEC256C25C");
    /// Tag for immutable observed Discord user profiles.
    ///
    /// Minted with `trible genid` on 2026-08-08:
    /// `B1751751B2DDFDF166D4EF0DA8D53D13`.
    #[allow(non_upper_case_globals)]
    pub const kind_user_profile: Id = id_hex!("B1751751B2DDFDF166D4EF0DA8D53D13");
    /// Tag for a fully successful forward-ingestion interval.
    ///
    /// Minted with `trible genid` on 2026-08-07:
    /// `EB592647E59EBBF07E7221DDC746A2B6`.
    #[allow(non_upper_case_globals)]
    pub const kind_ingestion_receipt: Id = id_hex!("EB592647E59EBBF07E7221DDC746A2B6");
    /// Tag for the explicit bounded-history baseline established by a first
    /// import. Older snowflakes are intentionally outside its claim.
    ///
    /// Minted with `trible genid` on 2026-08-08:
    /// `D5CE5556F159FE3F34A67A87DB105281`.
    #[allow(non_upper_case_globals)]
    pub const kind_ingestion_baseline: Id = id_hex!("D5CE5556F159FE3F34A67A87DB105281");
}
