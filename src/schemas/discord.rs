//! Discord schema: bot-token cache, channel/guild/message identity,
//! per-channel sync cursors, and log entries.
//!
//! Used by `discord.rs` (the faculty CLI). Messages use the generic
//! `archive::*` schema for the common shape (author / content /
//! reply_to / kind_message); this module only owns the Discord-
//! specific attributes and kinds. Attachments go through the shared
//! `files` branch + `file_schema` — not duplicated here.
//!
//! ## Identity
//!
//! Entity ids are derived intrinsically from the external Discord
//! snowflake via the identity-only-fragment idiom:
//!
//! ```rust,ignore
//! let id_frag = entity! { _ @ discord::message_id: external_handle };
//! let message_id = id_frag.root().expect("rooted");
//! let full = entity! { ExclusiveId::force_ref(&message_id) @
//!     metadata::tag: archive::kind_message,
//!     archive::author: author_id,
//!     archive::content: content_handle,
//!     // ...
//! } + id_frag;
//! ```
//!
//! Re-ingesting the same external id collapses to the same entity,
//! so edits update the existing entity rather than spawning a new one.

use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::{Blake3, GenId, Handle};
use triblespace::prelude::*;

pub const DEFAULT_BRANCH: &str = "discord";
pub const DEFAULT_LOG_BRANCH: &str = "logs";

pub mod discord {
    use super::*;

    attributes! {
        /// Link from a channel entity to its parent guild.
        "E3022EC14FD000BB8556CD32C2C68E59" as pub guild: GenId;
        /// Link from a message entity to its channel.
        "B8EA57CD650A678ACA5D1479BF195C4C" as pub channel: GenId;
        /// External Discord snowflake for a guild (server). Stored
        /// as a string — Discord ids are u64 but the REST API
        /// ships them as strings to survive JavaScript clients.
        "9E8EC81F5C14805CCFD4930A4B877138" as pub guild_id: Handle<LongString>;
        /// External Discord snowflake for a channel.
        "7C943A11E09C922989CAFE22B92E9A51" as pub channel_id: Handle<LongString>;
        /// External Discord snowflake for a message.
        "758C42164B566C2AFECBCD7129163A34" as pub message_id: Handle<LongString>;
        /// External Discord snowflake for a user.
        "2A74F35C6720A0C60BF43D30DF272F85" as pub user_id: Handle<LongString>;
        /// Full Discord JSON body of a message. Stored raw so
        /// future code can derive additional fields without
        /// re-fetching.
        "5B9DCF6170CD775FC5DA22C8DB96599D" as pub message_raw: Handle<LongString>;
        /// Bot token (passed to the REST API as `Authorization:
        /// Bot <token>`). One token per bot identity; a caller
        /// who operates multiple bots would tag the token entity
        /// with a different `kind` or a user-scoped id.
        "E20FEC3E1714D5EDC556936AE1C0F463" as pub bot_token: Handle<LongString>;
        /// Per-channel pagination cursor — the snowflake of the
        /// newest message we ingested. Next sync fetches
        /// `?after=<cursor>`. Stored as a LongString handle for
        /// consistency with the other snowflake attributes.
        "3C510E125ACE09DC9B297D533C0F13B7" as pub cursor_last_message_id: Handle<LongString>;
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
    /// Tag for per-channel sync cursors.
    #[allow(non_upper_case_globals)]
    pub const kind_cursor: Id = id_hex!("4BB2A6C06AF842F1C24C5A6A1386E810");
    /// Tag for the bot-token cache entity.
    #[allow(non_upper_case_globals)]
    pub const kind_token: Id = id_hex!("E630CD6620C35F3CAE02945A9962B2C5");
    /// Tag for Discord sync log entries.
    #[allow(non_upper_case_globals)]
    pub const kind_log: Id = id_hex!("AED1F7A81D9D23F929C4AAF747888235");
}
