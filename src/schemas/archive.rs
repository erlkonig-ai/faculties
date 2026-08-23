//! Archive schema: unified message/author/attachment projection for imported conversations,
//! plus the import metadata schema that tracks original source identifiers.
//!
//! Used by `archive.rs` (the faculty CLI) and by any downstream consumer
//! that wants to read archived conversations or import provenance from a pile.

use triblespace::macros::id_hex;
pub use triblespace::prelude::blobencodings::RawBytes;
use triblespace::prelude::blobencodings::UTF8String;
use triblespace::prelude::inlineencodings::{GenId, Handle, NsTAIInterval, ShortString, U256BE};
use triblespace::prelude::*;

/// Tag for BM25 search-index entities on the archive branch. Each
/// `archive index` run mints a fresh entity (kind + blob handle +
/// indexed_at); readers take the latest by `indexed_at` — indexes are
/// rebuild-and-replace, the history is just exhaust.
pub const KIND_SEARCH_INDEX: Id = id_hex!("0378075561687300E7028D923708A7BC");

pub mod search_index {
    use super::*;
    use triblespace_search::succinct::SuccinctBM25Blob;
    attributes! {
        /// Exact-TF BM25 artifact. Rotated with `SuccinctBM25Blob` on
        /// 2026-08-03; retired score blobs remain inert and `archive index`
        /// rebuilds under this attribute.
        "BE3EF8A63DFD0C29993E93B8037BC2C7" unsafe as index: Handle<SuccinctBM25Blob>;
        "DCEC5F15A91F89F95A2A5E1D3C1C34DB" unsafe as indexed_at: NsTAIInterval;
    }
}

/// A unified archive projection for externally sourced conversations.
///
/// This schema is used by archive importers (ChatGPT, Codex, Copilot, Gemini, ...)
/// to store a common message/author/attachment graph, while keeping the raw
/// source artifacts separately (e.g. JSON trees, HTML, etc).
pub mod archive {
    use super::*;

    attributes! {

        "0D9195A7B1B20DE312A08ECE39168079" unsafe as pub reply_to: GenId;
        "838CC157FFDD37C6AC7CC5A472E43ADB" unsafe as pub author: GenId;
        /// Wall-clock interval at which the message was last
        /// edited. Absent on unedited messages. Protocol-agnostic
        /// — every messaging faculty (teams, discord, any future
        /// Slack / Matrix / etc.) writes the same attribute.
        "76ED22B5BBB68EC6418DE2B6234EA5FB" unsafe as pub edited_at: NsTAIInterval;
        "E63EE961ABDB1D1BEC0789FDAFFB9501" unsafe as pub author_name: Handle<UTF8String>;
        "2D15150501ACCD9DFD96CB4BF19D1883" unsafe as pub author_role: Handle<UTF8String>;
        "4FE6A8A43658BC2F61FEDF5CFB29EEFC" unsafe as pub author_model: Handle<UTF8String>;
        "1F127324384335D12ECFE0CB84840925" unsafe as pub author_provider: Handle<UTF8String>;
        "ACF09FF3D62B73983A222313FF0C52D2" unsafe as pub content: Handle<UTF8String>;
        "D8A469EAC2518D1A85692E0BEBF20D6C" unsafe as pub content_type: ShortString;
        "8334E282F24A4C7779C8899191B29E00" unsafe as pub attachment: GenId;

        "C9132D7400892F65B637BCBE92E230FB" unsafe as pub attachment_source_id: Handle<UTF8String>;
        /// Content artifact represented by this source-specific attachment
        /// occurrence. The target is a `files::KIND_FILE` entity; keeping the
        /// occurrence and artifact separate lets identical bytes deduplicate
        /// without conflating their message-local provenance.
        "983BE64C7663D4DFBF7F227BA6D32634" unsafe as pub attachment_file: GenId;
        "A8F6CF04A9B2391A26F04BC84B77217D" unsafe as pub attachment_source_pointer: Handle<UTF8String>;
        "9ADD88D3FFD9E4F91E0DC08126D9180A" unsafe as pub attachment_name: Handle<UTF8String>;
        "EEFDB32D37B7B2834D99ACCF159B6507" unsafe as pub attachment_mime: ShortString;
        "D233E7BE0E973B09BD51E768E528ACA5" unsafe as pub attachment_size_bytes: U256BE;
        "5937E1072AF2F8E493321811B483C57B" unsafe as pub attachment_width_px: U256BE;
        "B252F4F77929E54FF8472027B7603EE9" unsafe as pub attachment_height_px: U256BE;
        "B0D18159D6035C576AE6B5D871AB4D63" unsafe as pub attachment_data: Handle<RawBytes>;
    }

    /// Tag for message payloads.
    #[allow(non_upper_case_globals)]
    pub const kind_message: Id = id_hex!("1A0841C92BBDA0A26EA9A8252D6ECD9B");
    /// Tag for author entities.
    #[allow(non_upper_case_globals)]
    pub const kind_author: Id = id_hex!("4E4512EFB0BF0CD42265BD107AE7F082");
    /// Tag for attachment entities.
    #[allow(non_upper_case_globals)]
    pub const kind_attachment: Id = id_hex!("B465C85DD800633F58FE211B920AF2D9");
}

pub mod import_schema {
    use super::*;

    attributes! {
        "891508CAD6E1430B221ADA937EFBD982" unsafe as pub conversation: GenId;
        "E997DCAAF43BAA04790FCB0FA0FBFE3A" unsafe as pub source_format: ShortString;
        "973FB59D3452D3A8276172F8E3272324" unsafe as pub source_raw_root: GenId;
        "87B587A3906056038FD767F4225274F9" unsafe as pub source_conversation_id: Handle<UTF8String>;
        "1B2A09FF44D2A5736FA320AB255026C1" unsafe as pub source_message_id: Handle<UTF8String>;
        "AA3CF220F15CCF724276F1251AFE053B" unsafe as pub source_author: Handle<UTF8String>;
        "B4C084B61FB46A932BFCA75B8BC621FA" unsafe as pub source_role: Handle<UTF8String>;
        "220DA5084D6261B5420922EADC064A5A" unsafe as pub source_parent_id: Handle<UTF8String>;
        "D59247F3AADD3DE8E23B01E8B7406020" unsafe as pub source_created_at: NsTAIInterval;
        /// Conversation → message edge (repeated).
        "06DB96427C8EA6FC982D44E018AB0831" unsafe as pub message: GenId;
        /// Source-assigned conversation title (e.g. claude.ai `name`).
        "BCFFFF156EB6D8694D263DCFDAA39CF6" unsafe as pub source_conversation_title: Handle<UTF8String>;
        /// Source-assigned conversation summary (e.g. claude.ai `summary`).
        "F23BD37982802B051A261561A694DA0C" unsafe as pub source_conversation_summary: Handle<UTF8String>;
    }

    /// Root id for describing the import metadata protocol.
    #[allow(non_upper_case_globals)]
    #[allow(dead_code)]
    pub const import_metadata: Id = id_hex!("5D57DD8335FECADB173616D780965F0C");

    /// Tag for import conversation entities.
    #[allow(non_upper_case_globals)]
    pub const kind_conversation: Id = id_hex!("573E4291B63CBA1B5AE090B0C25A2D34");
}
