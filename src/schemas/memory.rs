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

/// Tag for BM25 search-index entities on the memory branch. Each
/// `memory index` run mints a fresh entity (kind + blob handle +
/// indexed_at); readers take the latest by `indexed_at` — indexes are
/// rebuild-and-replace, the history is just exhaust.
pub const KIND_SEARCH_INDEX: Id = id_hex!("1C4A927F170DE0C99BD9723C164E17F9");

pub mod search_index {
    use super::*;
    use triblespace_search::succinct::SuccinctBM25Blob;
    attributes! {
        "3BAF1837E1A1128042A0582CF6D71CE0" as index: Handle<SuccinctBM25Blob>;
        "FD8C086B68F20AD04B2C70B9CE3C2BCC" as indexed_at: NsTAIInterval;
    }
}

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

/// Comb-practice cursor state (replay positions, consolidation edge).
///
/// Cursors are PERSONA-SCOPED bookkeeping for the remembering practice —
/// the memories themselves are never persona-scoped: chunks carry no author
/// or persona attribute, and every reader reads all of them. One being, one
/// memory; many sessions, many cursors.
///
/// Mutation model is coordinate-and-cursor: every advance appends a new
/// dated cursor entity; readers take the latest `metadata::created_at` per
/// (stream, persona). The comb's own progress accumulates as auditable
/// exhaust — no state is ever overwritten.
pub mod comb {
    use super::*;

    /// Tag for cursor entities (kind-filtered out of all chunk/message views).
    #[allow(non_upper_case_globals)]
    pub const kind_comb_cursor: Id = id_hex!("9CB7D5FDC1255FCB3ADC73A5BDEE7337");

    attributes! {
        /// Which practice stream this cursor belongs to:
        /// "archive-replay", "memory-replay", or "consolidate-edge".
        "E095C3752346D4FC73841BC8A975368F" as cursor_stream: ShortString;
        /// Persona label owning this cursor (from $PERSONA; never defaulted).
        "E5BB54261818A75DB8DA622450EAC97E" as cursor_persona: ShortString;
        /// Position: the timestamp up to which this stream has been consumed
        /// (exclusive); for the consolidation edge, where the next chunk opens.
        "79F4E916807654A5A8DDFAE5F402D21D" as cursor_position: NsTAIInterval;
        /// Replay granularity as typed (e.g. "2h", "1d", "30d") — stored on
        /// memory-replay cursors so a bare `memory replay` knows its zoom.
        "AEF10362CC939FA43CBED29D84CCAC13" as cursor_grain: ShortString;
    }

    use triblespace::core::id::ufoid;
    use triblespace::core::metadata;
    use triblespace::macros::{entity, find, pattern};

    fn interval_key(interval: Inline<NsTAIInterval>) -> i128 {
        let (lower, _): (hifitime::Epoch, hifitime::Epoch) =
            interval.try_from_inline().unwrap();
        lower.to_tai_duration().total_nanoseconds()
    }

    /// Latest cursor for (stream, persona): None = never started,
    /// Some((None, _)) = stopped, Some((Some(key), grain)) = active.
    pub fn latest(
        catalog: &TribleSet,
        stream: &str,
        persona: &str,
    ) -> Option<(Option<i128>, Option<String>)> {
        let mut best: Option<(i128, Option<i128>, Option<String>)> = None;
        for (cursor_id, c_stream, c_persona, created) in find!(
            (c: Id, s: String, p: String, t: Inline<NsTAIInterval>),
            pattern!(catalog, [{
                ?c @
                    metadata::tag: kind_comb_cursor,
                    cursor_stream: ?s,
                    cursor_persona: ?p,
                    metadata::created_at: ?t,
            }])
        ) {
            if c_stream != stream || c_persona != persona {
                continue;
            }
            let created_key = interval_key(created);
            let position = find!(
                v: Inline<NsTAIInterval>,
                pattern!(catalog, [{ cursor_id @ cursor_position: ?v }])
            )
            .next()
            .map(interval_key);
            let grain = find!(
                g: String,
                pattern!(catalog, [{ cursor_id @ cursor_grain: ?g }])
            )
            .next();
            match best {
                Some((prev, _, _)) if prev >= created_key => {}
                _ => best = Some((created_key, position, grain)),
            }
        }
        best.map(|(_, position, grain)| (position, grain))
    }

    /// Facts for a cursor advance (append-only latest-wins; the comb's
    /// progress accumulates as auditable exhaust). `position: None` = stop.
    pub fn advance_change(
        stream: &str,
        persona: &str,
        position: Option<hifitime::Epoch>,
        grain: Option<&str>,
        now: hifitime::Epoch,
    ) -> TribleSet {
        let cursor_id = ufoid();
        let now_val: Inline<NsTAIInterval> = (now, now).try_to_inline().unwrap();
        let position_val: Option<Inline<NsTAIInterval>> =
            position.map(|p| (p, p).try_to_inline().unwrap());
        let mut change = TribleSet::new();
        change += entity! { &cursor_id @
            metadata::tag: kind_comb_cursor,
            cursor_stream: stream,
            cursor_persona: persona,
            metadata::created_at: now_val,
            cursor_position?: position_val,
            cursor_grain?: grain,
        };
        change
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
