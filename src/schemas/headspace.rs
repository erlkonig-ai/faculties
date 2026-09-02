//! Headspace schema: fork-visible configuration and model-profile snapshots.
//!
//! The exact-additive cutover leaves historical `config` branch facts in the
//! collection as immutable evidence. Native semantics apply only to entities
//! carrying [`KIND_LIVE_RECORD`]. Complete intrinsic snapshots form one global
//! config DAG and one DAG per stable profile anchor through
//! [`metadata::supersedes`](triblespace::core::metadata::supersedes).

use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::UTF8String;
use triblespace::prelude::inlineencodings::{GenId, Handle, U256BE};
use triblespace::prelude::*;

pub const DEFAULT_MODEL: &str = "gpt-oss:120b";
pub const DEFAULT_BASE_URL: &str = "http://localhost:11434/v1";
pub const DEFAULT_STREAM: bool = false;
pub const DEFAULT_CONTEXT_WINDOW_TOKENS: u64 = 32 * 1024;
pub const DEFAULT_MAX_OUTPUT_TOKENS: u64 = 1024;
pub const DEFAULT_CONTEXT_SAFETY_MARGIN_TOKENS: u64 = 512;
pub const DEFAULT_CHARS_PER_TOKEN: u64 = 4;
pub const DEFAULT_SYSTEM_PROMPT: &str = "You are a terminal-based agent. Respond with exactly one shell command per turn. You can include an optional leading comment block for context. Faculties are executable helper scripts in ./faculties; run them with no arguments to see usage and prefer them over ad-hoc commands when applicable.";
pub const DEFAULT_AUTHOR: &str = "agent";
pub const DEFAULT_AUTHOR_ROLE: &str = "user";
pub const DEFAULT_POLL_MS: u64 = 1;

/// Stable extrinsic scope for the one native Headspace collection.
///
/// Minted with `trible genid` on 2026-08-08:
/// `0A497071DF78800A265608C70849828A`.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("0A497071DF78800A265608C70849828A");

/// Marks records admitted to native Headspace semantics.
///
/// Historical rows copied byte-for-byte by migration lack this marker and
/// remain inert even when they use the old config/profile kind ids. Minted
/// with `trible genid` on 2026-08-11:
/// `B033F57E1A820DFB137A9685CDA38CAA`.
pub const KIND_LIVE_RECORD: Id = id_hex!("B033F57E1A820DFB137A9685CDA38CAA");

/// Kind of a stable, authored model-profile anchor.
///
/// Minted with `trible genid` on 2026-08-08:
/// `140BB1AF97C1971819CAB83D8ACA6B65`.
pub const KIND_PROFILE_ANCHOR_ID: Id = id_hex!("140BB1AF97C1971819CAB83D8ACA6B65");

// These published ids already mean config/profile records. The live marker,
// complete-state constructors, and lineage make their native meaning exact.
pub const KIND_CONFIG_ID: Id = id_hex!("A8DCBFD625F386AA7CDFD62A81183E82");
pub const KIND_MODEL_PROFILE_ID: Id = id_hex!("B08E356C4B08F44AB7EC177D47129447");

pub mod playground_config {
    use super::*;
    attributes! {
        // Published attributes retain their literal ids for exact legacy reads.
        "950B556A74F71AC7CB008AB23FBB6544" unsafe as system_prompt: Handle<UTF8String>;
        "35E36AE7B60AD946661BD63B3CD64672" unsafe as branch: Handle<UTF8String>;
        "F0F90572249284CD57E48580369DEB6D" unsafe as author: Handle<UTF8String>;
        "98A194178CFD7CBB915C1BC9EB561A7F" unsafe as author_role: Handle<UTF8String>;
        "D1DC11B303725409AB8A30C6B59DB2D7" unsafe as persona_id: GenId;
        "79E1B50756FB64A30916E9353225E179" unsafe as active_model_profile_id: GenId;
        "698519DFB681FABC3F06160ACAC9DA8E" unsafe as poll_ms: U256BE;
        "6691CF3F872C6107DCFAD0BCF7CDC1A0" unsafe as model_profile_id: GenId;
        "85BE7BDA465B3CB0F800F76EEF8FAC9B" unsafe as model_name: Handle<UTF8String>;
        "B216CFBBF85AA1350B142D510E26268B" unsafe as model_base_url: Handle<UTF8String>;
        "55F3FFD721AF7C1258E45BC91CDBF30F" unsafe as model_api_key: Handle<UTF8String>;
        "328B29CE81665EE719C5A6E91695D4D4" unsafe as tavily_api_key: Handle<UTF8String>;
        "AB0DF9F03F28A27A6DB95B693CC0EC53" unsafe as exa_api_key: Handle<UTF8String>;
        "BA4E05799CA2ACDCF3F9350FC8742F2F" unsafe as model_reasoning_effort: Handle<UTF8String>;
        "5F04F7A0EB4EBBE6161022B336F83513" unsafe as model_stream: U256BE;
        "F9CEA1A2E81D738BB125B4D144B7A746" unsafe as model_context_window_tokens: U256BE;
        "4200F6746B36F2784DEBA1555595D6AC" unsafe as model_max_output_tokens: U256BE;
        "1FF004BB48F7A4F8F72541F4D4FA75FF" unsafe as model_context_safety_margin_tokens: U256BE;
        "095FAECDB8FF205DF591DF594E593B01" unsafe as model_chars_per_token: U256BE;
        "120F9C6BBB103FAFFB31A66E2ABC15E6" unsafe as exec_default_cwd: Handle<UTF8String>;
        "D18A351B6E03A460E4F400D97D285F96" unsafe as exec_sandbox_profile: GenId;

        // New native attributes use minted anchors; their encodings participate
        // in attribute identity rather than relying on unsafe literal pinning.
        // Minted 2026-08-08: DAE53BDA7C5D7878AF846490BF3DC62F.
        "DAE53BDA7C5D7878AF846490BF3DC62F" as cognition_scope: GenId;
        // Minted 2026-08-11: 740B82A5C35A7577171627F01F13A1BA.
        "740B82A5C35A7577171627F01F13A1BA" as model_secret_version: GenId;
        // Minted 2026-08-11: 7B2CAEA05A9B7247E86916E13372EDF1.
        "7B2CAEA05A9B7247E86916E13372EDF1" as tavily_secret_version: GenId;
        // Minted 2026-08-11: 05C8F916018E3E4DDAD5D5F2DBE148B2.
        "05C8F916018E3E4DDAD5D5F2DBE148B2" as exa_secret_version: GenId;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_scope_and_live_marker_are_stable() {
        assert_eq!(
            format!("{DEFAULT_SCOPE_ID:X}"),
            "0A497071DF78800A265608C70849828A"
        );
        assert_eq!(
            format!("{KIND_LIVE_RECORD:X}"),
            "B033F57E1A820DFB137A9685CDA38CAA"
        );
    }

    #[test]
    fn secret_references_do_not_reuse_plaintext_attribute_ids() {
        assert_ne!(
            playground_config::model_secret_version.id(),
            playground_config::model_api_key.id()
        );
        assert_ne!(
            playground_config::tavily_secret_version.id(),
            playground_config::tavily_api_key.id()
        );
        assert_ne!(
            playground_config::exa_secret_version.id(),
            playground_config::exa_api_key.id()
        );
    }
}
