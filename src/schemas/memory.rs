//! Memory schema: compacted context chunks with time spans, tree structure,
//! and provenance links back to exec results or archived messages.
//!
//! Used by `memory.rs` (the faculty CLI) and by any downstream consumer
//! that wants to read memory chunks from a pile.

use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::{RawBytes, UTF8String};
use triblespace::prelude::inlineencodings::{GenId, Handle, NsTAIInterval, ShortString};
use triblespace::prelude::*;

/// Stable extrinsic scope of the durable Memory journal collection.
///
/// Minted with `trible genid` on 2026-08-09:
/// `E12E0AF29345CA6D9C58A32B50BAC9D8`.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("E12E0AF29345CA6D9C58A32B50BAC9D8");

/// Historical input consumed only by the stopped-world additive cutover.
/// Ordinary Memory readers and writers never resolve a named branch.
pub const LEGACY_MEMORY_BRANCH_NAME: &str = "memory";

/// Stable extrinsic scope of persona-scoped Comb cursor state.
///
/// Minted with `trible genid` on 2026-08-08 in the canonical Memory/Comb
/// collection lineage. Archive replay shares this scope; Archive facts never
/// enter it.
pub const DEFAULT_COMB_SCOPE_ID: Id = id_hex!("6CB9F473105A56504531486F14382F78");

/// Historical branch name consumed only by stopped-world migrations.
pub const LEGACY_COMB_BRANCH_NAME: &str = "comb-state";

pub const KIND_CHUNK_ID: Id = id_hex!("40E6004417F9B767AFF1F138DE3D3AAC");

/// Marks a *retraction* tombstone: an entity that retracts a chunk (via
/// `ctx::supersedes`) without being a chunk itself. Deliberately distinct from
/// `KIND_CHUNK_ID` so retractions never enumerate in chunk views, yet remain
/// queryable as their own class ("what have I walked back, and why"). The
/// reason, when given, is stored as the tombstone's `ctx::summary`. Minted
/// 2026-07-03.
pub const KIND_RETRACTION: Id = id_hex!("89ACC4C9A8B961A529CC5DB19C2D393B");

pub const KIND_EXEC_RESULT: Id = id_hex!("DF7165210F066E84D93E9A430BB0D4BD");

pub const KIND_ARCHIVE_MESSAGE: Id = id_hex!("1A0841C92BBDA0A26EA9A8252D6ECD9B");

/// Tag for historical BM25 search-index entities in Memory. Each
/// `memory index` run mints a fresh entity (kind + blob handle +
/// indexed_at); readers take the latest by `indexed_at` — indexes are
/// rebuild-and-replace, the history is just exhaust.
pub const KIND_SEARCH_INDEX: Id = id_hex!("1C4A927F170DE0C99BD9723C164E17F9");

pub mod search_index {
    use super::*;
    use triblespace_search::succinct::SuccinctBM25Blob;
    attributes! {
        /// Exact-TF BM25 artifact. Rotated with `SuccinctBM25Blob` on
        /// 2026-08-03; retired score blobs remain inert and `memory index`
        /// rebuilds under this attribute.
        "E8AE08F96BB552892BD106E45AAB5007" unsafe as index: Handle<SuccinctBM25Blob>;
        "FD8C086B68F20AD04B2C70B9CE3C2BCC" unsafe as indexed_at: NsTAIInterval;
    }
}

pub mod archive_schema {
    use super::*;
    attributes! {
        "838CC157FFDD37C6AC7CC5A472E43ADB" unsafe as author: GenId;
        "E63EE961ABDB1D1BEC0789FDAFFB9501" unsafe as author_name: Handle<UTF8String>;
    }
}

pub mod archive_import_schema {
    use super::*;
    attributes! {
        "E997DCAAF43BAA04790FCB0FA0FBFE3A" unsafe as source_format: ShortString;
        "87B587A3906056038FD767F4225274F9" unsafe as source_conversation_id: Handle<UTF8String>;
    }
}

/// Comb-practice cursor state (replay positions, consolidation edge).
///
/// Cursors are PERSONA-SCOPED bookkeeping for the remembering practice —
/// the memories themselves are never persona-scoped: chunks carry no author
/// or persona attribute, and every reader reads all of them. One being, one
/// memory; many sessions, many cursors.
///
/// Cursor snapshots form an intrinsic `metadata::supersedes` DAG per
/// (stream, persona). Readers expose concurrent heads until a later snapshot
/// reconciles the live frontier; observation times remain additive exhaust.
pub mod comb {
    use super::*;

    /// Tag for cursor entities (kind-filtered out of all chunk/message views).
    #[allow(non_upper_case_globals)]
    pub const kind_comb_cursor: Id = id_hex!("9CB7D5FDC1255FCB3ADC73A5BDEE7337");

    attributes! {
        /// Which practice stream this cursor belongs to:
        /// "archive-replay", "memory-replay", or "consolidate-edge".
        "E095C3752346D4FC73841BC8A975368F" unsafe as cursor_stream: ShortString;
        /// Persona label owning this cursor (from $PERSONA; never defaulted).
        "E5BB54261818A75DB8DA622450EAC97E" unsafe as cursor_persona: ShortString;
        /// Position: the timestamp up to which this stream has been consumed
        /// (exclusive); for the consolidation edge, where the next chunk opens.
        "79F4E916807654A5A8DDFAE5F402D21D" unsafe as cursor_position: NsTAIInterval;
        /// Replay granularity as typed (e.g. "2h", "1d", "30d") — stored on
        /// memory-replay cursors so a bare `memory replay` knows its zoom.
        "AEF10362CC939FA43CBED29D84CCAC13" unsafe as cursor_grain: ShortString;
        /// Exact content identity at `cursor_position`. Streams with several
        /// items at one position use this anchor to resume after one item
        /// without skipping the rest. Minted 2026-08-28 with `trible genid`.
        "C87DAFECBAA04E7B217C17877EA74839" as cursor_anchor: GenId;
    }
}

pub mod ctx {
    use super::*;
    attributes! {
        "3292CF0B3B6077991D8ECE6E2973D4B6" unsafe as summary: Handle<UTF8String>;
        "502F7D33822A90366F0F0ADA0556177F" unsafe as start_at: NsTAIInterval;
        "DF84E872EB68FBFCA63D760F27FD8A6F" unsafe as end_at: NsTAIInterval;
        /// Contextualised cross-reference to another chunk, extracted from
        /// `[why this matters here](memory:<hex>)` at create. Annotation, not
        /// structure: no span effect, no tree role — hierarchy is temporal
        /// subsumption. Soft references use `(memory:<from>..<to>)` (an
        /// address resolved at read time; no fact minted).
        ///
        /// RENAMED from `child` (2026-06-12), same id on purpose: the old
        /// design minted these edges from the same inline-reference notation
        /// and additionally treated them as tree structure (cover splitting,
        /// children-union spans). The structural role is retired; legacy
        /// edges in any pile reinterpret as what they always semantically
        /// were — contextualised references.
        "9B83D68AECD6888AA9CE95E754494768" unsafe as reference: GenId;
        "CB97C36A32DEC70E0D1149E7C5D88588" unsafe as left: GenId;
        "087D07E3D9D94F0C4E96813C7BC5E74C" unsafe as right: GenId;
        "316834CC6B0EA6F073BF5362D67AC530" unsafe as about_exec_result: GenId;
        "A4E2B712CA28AB1EED76C34DE72AFA39" unsafe as about_archive_message: GenId;
        /// This chunk replaces another (wrong span, superseded retelling).
        /// Monotonic correction: the fact is appended, never removed; readers
        /// exclude any chunk that something else supersedes (read-side policy,
        /// periphery principle). Mis-created chunks stay in history but leave
        /// every view.
        "0381735B64BFE71EA0341B95EA42C984" unsafe as supersedes: GenId;
        /// Marks this chunk as a thematic LENS rather than part of the
        /// chronological spine; the value is the theme name. Lens chunks are
        /// excluded from the temporal containment tree, so a wide lens (e.g. a
        /// "story of us" over many months) can't hijack the spine by containing
        /// the eras it overlaps. They are read on their own axis via
        /// `memory lens <theme>`. This is what lets memory be a many-threaded
        /// weave — overlapping views over the same time — instead of one tree.
        "B53D37A3BE552B0F47E279D69AB7ECD3" unsafe as lens: Handle<UTF8String>;
        /// The raw image bytes of a WORDLESS image memory chunk. A chunk with
        /// this attribute is a memory whose content is a picture, not prose —
        /// no `ctx::summary` is required. It shares the same time-coordinate
        /// (`start_at`/`end_at`) and the same shared-space `embeddings::embedding`
        /// (via nomic-VISION-768, co-embedded with nomic-text) as text memories,
        /// so `memory similar` ranks text and image memories together by meaning.
        "1490E76164F3B523E32EDB15D949BD1C" unsafe as image: Handle<RawBytes>;
    }
}
