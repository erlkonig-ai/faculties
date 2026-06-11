//! Memory schema: compacted context chunks with time spans, tree structure,
//! and provenance links back to exec results or archived messages.
//!
//! Used by `memory.rs` (the faculty CLI) and by any downstream consumer
//! that wants to read memory chunks from a pile.

use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::{GenId, Handle, NsTAIInterval, ShortString};
use triblespace::prelude::*;

pub const DEFAULT_MEMORY_BRANCH: &str = "memory";
pub const DEFAULT_COGNITION_BRANCH: &str = "cognition";
pub const DEFAULT_ARCHIVE_BRANCH: &str = "archive";

pub const KIND_CHUNK_ID: Id = id_hex!("40E6004417F9B767AFF1F138DE3D3AAC");

pub const KIND_EXEC_RESULT: Id = id_hex!("DF7165210F066E84D93E9A430BB0D4BD");

pub const KIND_ARCHIVE_MESSAGE: Id = id_hex!("1A0841C92BBDA0A26EA9A8252D6ECD9B");

pub mod archive_schema {
    use super::*;
    attributes! {
        "838CC157FFDD37C6AC7CC5A472E43ADB" as author: GenId;
        "E63EE961ABDB1D1BEC0789FDAFFB9501" as author_name: Handle<LongString>;
    }
}

pub mod archive_import_schema {
    use super::*;
    attributes! {
        "E997DCAAF43BAA04790FCB0FA0FBFE3A" as source_format: ShortString;
        "87B587A3906056038FD767F4225274F9" as source_conversation_id: Handle<LongString>;
    }
}

pub mod ctx {
    use super::*;
    attributes! {
        "3292CF0B3B6077991D8ECE6E2973D4B6" as summary: Handle<LongString>;
        "502F7D33822A90366F0F0ADA0556177F" as start_at: NsTAIInterval;
        "DF84E872EB68FBFCA63D760F27FD8A6F" as end_at: NsTAIInterval;
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
        "9B83D68AECD6888AA9CE95E754494768" as reference: GenId;
        "CB97C36A32DEC70E0D1149E7C5D88588" as left: GenId;
        "087D07E3D9D94F0C4E96813C7BC5E74C" as right: GenId;
        "316834CC6B0EA6F073BF5362D67AC530" as about_exec_result: GenId;
        "A4E2B712CA28AB1EED76C34DE72AFA39" as about_archive_message: GenId;
        /// This chunk replaces another (wrong span, superseded retelling).
        /// Monotonic correction: the fact is appended, never removed; readers
        /// exclude any chunk that something else supersedes (read-side policy,
        /// periphery principle). Mis-created chunks stay in history but leave
        /// every view.
        "0381735B64BFE71EA0341B95EA42C984" as supersedes: GenId;
    }
}
