//! Canonical block-DAG archive schema.
//!
//! Archive data is split into semantic/source-occurrence layers plus an
//! orthogonal exact-source substrate:
//!
//! ```text
//! content fact  -- semantic datum (text, media, tool payload, ...)
//! content part  -- ordinal-bearing occurrence of one fact inside a block
//! block         -- structural event in the predecessor DAG
//! source projection -- exact vendor occurrence projected onto one block
//! source chunk      -- reusable content-addressed source byte range
//! source snapshot   -- exact ordered version of one source file
//! ```
//!
//! The first three layers are structural hash-consing. Source multiplicity,
//! actor pairing, vendor ids, and movable paths belong only to projection
//! receipts. This lets repeated exports converge without erasing how often a
//! source actually emitted the event.
//!
//! The block/content-fact ids and attributes preserve the approved
//! `8011a65..a2e575c` design lineage. The scope, content-part, media-type, and
//! projection ids below were minted with `trible genid` on 2026-08-08; their
//! exact values are kept here beside the protocol they identify.

use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::LongString;
pub use triblespace::prelude::blobencodings::RawBytes;
use triblespace::prelude::inlineencodings::{GenId, Handle, NsTAIInterval, U256BE};
use triblespace::prelude::*;

/// Stable extrinsic scope of the Archive source collection.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("940F76A54E6C2E64469935B9FEF724A1");

/// Name of the pre-collection Archive branch this scope replaced.
///
/// Retained so `faculties::legacy_hint` can tell an unmigrated pile where its
/// facts still are; the transform itself lives in the `faculties-migrations`
/// crate.
pub const LEGACY_BRANCH_NAME: &str = "archive";

/// A content-addressed position in the perception/action DAG.
pub mod block {
    use super::*;

    attributes! {
        /// IDENTITY. Structural predecessor set. Absent on a root block.
        "9B8F693BE959136E90C34CF054F9033F" unsafe as pub previous: GenId;
        /// IDENTITY when present. A genuine normalized event interval.
        /// Missing or uncertain source time contributes no row; a sentinel is
        /// never substituted.
        "695A45C4A57FDA7FDF8A609117878E97" unsafe as pub timestamp: NsTAIInterval;
        /// IDENTITY. One or more ordinal-bearing [`content_part`] entities.
        "A8A1254C922182ECDF5DC50A21D74493" unsafe as pub contains: GenId;
    }

    /// Nonidentity kind marker attached after intrinsic block construction.
    pub const KIND: Id = id_hex!("91B88464F7B5A178DC4FA87DE28CDFA9");
}

/// An ordered occurrence of one semantic content fact inside a block.
///
/// Position is not vendor occurrence identity: it is part of the semantic
/// block value. It preserves order and repeated equal payloads even though
/// `block::contains` itself is a set.
pub mod content_part {
    use super::*;

    attributes! {
        /// IDENTITY. Zero-based position inside the source block.
        "63C7750587AD040429750C15BAB9CF29" unsafe as pub ordinal: U256BE;
        /// IDENTITY. Canonical semantic datum at this position.
        "28E039E5B292CEE5E41C22EDD0E396E7" unsafe as pub fact: GenId;
        /// IDENTITY when present. Semantic tool-result/tool-call relation to a
        /// target part. An unresolved vendor correlator stays in raw source
        /// provenance; resolving it yields a richer immutable projection.
        "A7CC0F4A24275330DD48F2836B70F0EC" unsafe as pub responds_to: GenId;
    }

    /// Nonidentity kind marker attached after intrinsic part construction.
    pub const KIND: Id = id_hex!("DA0B1A13326EFB5567B182BDE1F33880");
}

/// A single perceived, produced, or ambient semantic datum.
pub mod content_fact {
    use super::*;

    attributes! {
        /// IDENTITY. Reified modality entity.
        "9044EA72B7B056F20CB02375ABFB7D87" unsafe as pub modality: GenId;
        /// IDENTITY. Reified `in`, `out`, or `ambient` direction entity.
        "3A42C2348E452E2C2E98B6C576576947" unsafe as pub direction: GenId;
        /// IDENTITY for text, thinking, and textual tool payloads.
        "6CA37B269D7900D866824EB5560E747B" unsafe as pub payload: Handle<LongString>;
        /// IDENTITY when media bytes are resident.
        "EEA16296F288D635B9BA4F603827E109" unsafe as pub blob: Handle<RawBytes>;
        /// IDENTITY when bytes are not held. External pointers are meaningful
        /// only together with `asset_namespace`.
        "91FB71A7D25EC34E208DA622DD680481" unsafe as pub asset_pointer: Handle<LongString>;
        /// IDENTITY with `asset_pointer`. Source namespace of the external
        /// pointer, preventing unrelated vendors from sharing an id string.
        "9B38698BD76DB91C8ED478D304375286" unsafe as pub asset_namespace: GenId;
        /// IDENTITY when known. Link to Files' intrinsic canonical media-type
        /// entity, never an inline MIME spelling.
        "CCEC81B576FF10DDA85C522C6FE86345" unsafe as pub media_type: GenId;
        /// IDENTITY when known. Claimed byte size of an unresolved asset.
        "2CF092F132FA9110BA10B1B1482831DB" unsafe as pub asset_size: U256BE;

        /// NONIDENTITY, monotone. Bytes later recovered for a pointer-identified
        /// fact. Conflicting resolutions are an ambiguity, never last-write-wins.
        "61604A1C2B6AA2A6F1D36541323B0CFE" unsafe as pub resolved_to: Handle<RawBytes>;
    }

    /// Nonidentity kind marker attached after intrinsic fact construction.
    pub const KIND: Id = id_hex!("C29DDE04AD573274192D1AB86BA5B0A3");

    pub mod modality {
        use super::*;
        pub const TEXT: Id = id_hex!("AE8DC7E9948F3B2408F86049F1D2C548");
        pub const AUDIO: Id = id_hex!("BD2EF853BA7CC99A10DDDA2E5C25D1A4");
        pub const IMAGE: Id = id_hex!("2EEF41445AE93BFABD02423BEDB6ECEF");
        pub const TOOL_CALL: Id = id_hex!("A4B7EC585B0906BFFC42464015E2903C");
        pub const TOOL_RESULT: Id = id_hex!("09A663D69EBDEC15ED329EC5CB7AF445");
        pub const THINKING: Id = id_hex!("293748A40FE28BDC888C1AF336F60D5C");
        pub const EVENT: Id = id_hex!("2F13E9308B0760AAFBAC4B1FF959154C");
        /// Generic file payload. Minted with `trible genid` on 2026-08-17.
        pub const FILE: Id = id_hex!("2F241F546612E13BBED8D08048F4298E");
        /// Moving-image payload. Minted with `trible genid` on 2026-08-17.
        pub const VIDEO: Id = id_hex!("F987E4C900B76116CE7E84045DC9F5F4");

        /// Canonical, queryable display vocabulary for Archive modalities.
        pub const SPECS: &[(Id, &str)] = &[
            (TEXT, "text"),
            (AUDIO, "audio"),
            (IMAGE, "image"),
            (FILE, "file"),
            (VIDEO, "video"),
            (TOOL_CALL, "tool-call"),
            (TOOL_RESULT, "tool-result"),
            (THINKING, "thinking"),
            (EVENT, "event"),
        ];
    }

    pub mod direction {
        use super::*;
        pub const IN: Id = id_hex!("1452B759336E0DEF96E78937D6E7F15D");
        pub const OUT: Id = id_hex!("39990F231B5FDB6F0FF4DB55616A2939");
        pub const AMBIENT: Id = id_hex!("0EE490D68C82C4F734D15222C8F2AF5D");

        /// Canonical, queryable display vocabulary for Archive directions.
        pub const SPECS: &[(Id, &str)] = &[(IN, "in"), (OUT, "out"), (AMBIENT, "ambient")];
    }
}

/// One content-addressed byte range inside an exact frozen source snapshot.
pub mod source_chunk {
    use super::*;

    /// Canonical fixed boundary used by every Archive source adapter.
    pub const CANONICAL_BYTES: usize = 8 * 1024 * 1024;

    attributes! {
        /// IDENTITY. Zero-based byte offset inside the frozen source.
        "28C0C5F405037AD6D385E47B8504EC05" as pub offset: U256BE;
        /// IDENTITY. Exact bytes in this range; chunk boundaries may split
        /// UTF-8 and source-format records.
        "A4839C10C67A7AD3952BEA072865CC2B" as pub bytes: Handle<RawBytes>;
    }

    /// Nonidentity kind marker. Minted with `trible genid` on 2026-08-17.
    pub const KIND: Id = id_hex!("6BE555E2350E42803AFF1DF43283ACD0");
}

/// One exact, reconstructible version of a potentially live source file.
pub mod source_snapshot {
    use super::*;

    attributes! {
        /// IDENTITY. Exact source length in bytes.
        "6123C7D5D325756485E74212336BD1D4" as pub byte_length: U256BE;
        /// IDENTITY. Ordered byte ranges, whose offsets live on the referenced
        /// [`source_chunk`] entities.
        "F9A5D6DC87EA518FAC423D5E81158A2D" as pub contains: GenId;
    }

    /// Nonidentity kind marker. Minted with `trible genid` on 2026-08-17.
    pub const KIND: Id = id_hex!("CF3D9B1669728FD0A5DAC20417ACEE58");
}

/// Exact vendor occurrence and projection receipt.
///
/// The first four fields are the identity core. Every other field is
/// occurrence-scoped evidence attached monotonically after construction.
pub mod source_projection {
    use super::*;

    attributes! {
        /// IDENTITY. Reified source protocol/namespace.
        "3D9FCD3A68CBFBCFD7375E35D63FB87D" unsafe as pub source_namespace: GenId;
        /// IDENTITY. Vendor id scoped by session, or an append-stable fallback
        /// coordinate. Never a movable filesystem path by itself.
        "5F3F80B819EBFB04E2AF20852F9FE3E3" unsafe as pub source_locator: Handle<LongString>;
        /// IDENTITY. Exact raw source record bytes.
        "584415CC85A866E45B91C2673C7F794E" unsafe as pub raw_record: Handle<RawBytes>;
        /// IDENTITY. Canonical block produced by this projection.
        "3810AAD922D0523B9A609E4E1EBA9320" unsafe as pub projects_to: GenId;

        /// NONIDENTITY. Additive receipt evidence supporting the semantic
        /// predecessor classes of the projected block. This is deliberately
        /// not the raw occurrence's vendor `parent` relation; exact vendor
        /// adjacency remains recoverable from `raw_record`.
        "1CE3ACF6B860D6009BA4CB622FBE1DC9" unsafe as pub semantic_predecessor_support: GenId;
        /// NONIDENTITY. Genuine source timestamp claim, when decodable.
        "A6892FD4C7FEB9445C3C5F8E96FC9E6A" unsafe as pub source_timestamp: NsTAIInterval;
        /// NONIDENTITY. Stable Relations entity that produced the occurrence.
        /// This intentionally reuses Archive's already-published generic
        /// author relation id.
        "838CC157FFDD37C6AC7CC5A472E43ADB" unsafe as pub author: GenId;
        /// NONIDENTITY. Stable Relations entity whose stream observed/produced
        /// the occurrence.
        "EBE88D7DDF43CCC594A695504B599AA5" unsafe as pub experiencer: GenId;
        /// NONIDENTITY. Exact vendor author label retained for provenance.
        "01BA2CB9FF56564100D64C81D0391E28" unsafe as pub raw_author: Handle<LongString>;
        /// NONIDENTITY. Exact vendor role label retained for provenance.
        "2874AFE6553B4E044D4EBFB8FA89A641" unsafe as pub raw_role: Handle<LongString>;
        /// NONIDENTITY. Exact vendor model label retained for provenance.
        "CEB26C9520076D245DF83F77D994A800" unsafe as pub raw_model: Handle<LongString>;
    }

    /// Nonidentity kind marker attached after intrinsic receipt construction.
    pub const KIND: Id = id_hex!("F93BD1665DCC2A8EA75054986A2EA148");

    /// Claude Code JSONL source namespace.
    pub const SOURCE_CLAUDE_CODE: Id = id_hex!("08C70B08B8F48CA5C9FAFEA714A4EACE");

    /// Codex app-server rollout JSONL source namespace. Minted with
    /// `trible genid` on 2026-08-16.
    pub const SOURCE_CODEX: Id = id_hex!("C9B3D07DA2B5939383F342B1054E08F3");

    /// ChatGPT data-export source namespace. Minted with `trible genid` on
    /// 2026-08-17.
    pub const SOURCE_CHATGPT: Id = id_hex!("5F2A3161281F3A8EA18589208FE729DA");
    /// Claude Web data-export source namespace. Minted with `trible genid` on
    /// 2026-08-17.
    pub const SOURCE_CLAUDE_WEB: Id = id_hex!("A77D6A2BE2BECFD88641652EBC8EF1D4");
    /// Gemini Takeout activity source namespace. Minted with `trible genid` on
    /// 2026-08-17.
    pub const SOURCE_GEMINI: Id = id_hex!("8F043C104DEF05097364108E8826634F");
    /// GitHub Copilot / VS Code chat-session source namespace. Minted with
    /// `trible genid` on 2026-08-17.
    pub const SOURCE_COPILOT: Id = id_hex!("2D8A49CBF2B2D4D4E705B37C4FFEDB48");
    /// Gemini Antigravity transcript source namespace. Minted with `trible
    /// genid` on 2026-08-17.
    pub const SOURCE_AGY: Id = id_hex!("29D3BFFAF4AC6C2AD2EFD1C7D22B60FB");
}
