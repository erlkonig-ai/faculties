//! Headspace (playground config) schema: active profile, model parameters,
//! API keys, execution context.
//!
//! Used by `headspace.rs` (the faculty CLI) and by any runtime that needs
//! to read the active model profile, system prompt, persona id, or related
//! settings from a pile.

use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::{GenId, Handle, U256BE};
use triblespace::prelude::*;

pub const DEFAULT_MODEL: &str = "gpt-oss:120b";
pub const DEFAULT_BASE_URL: &str = "http://localhost:11434/v1";
pub const DEFAULT_STREAM: bool = false;
pub const DEFAULT_CONTEXT_WINDOW_TOKENS: u64 = 32 * 1024;
pub const DEFAULT_MAX_OUTPUT_TOKENS: u64 = 1024;
pub const DEFAULT_CONTEXT_SAFETY_MARGIN_TOKENS: u64 = 512;
pub const DEFAULT_CHARS_PER_TOKEN: u64 = 4;
/// Minimal starting prompt used when no system prompt has been configured.
/// Intentionally short and generic — specific agent runtimes should override
/// this with their own prompt via `headspace set system-prompt @<file>`.
pub const DEFAULT_SYSTEM_PROMPT: &str = "You are a terminal-based agent. Respond with exactly one shell command per turn. You can include an optional leading comment block for context. Faculties are executable helper scripts in ./faculties; run them with no arguments to see usage and prefer them over ad-hoc commands when applicable.";

pub const DEFAULT_BRANCH: &str = "cognition";
pub const DEFAULT_AUTHOR: &str = "agent";
pub const DEFAULT_AUTHOR_ROLE: &str = "user";
pub const DEFAULT_POLL_MS: u64 = 1;
pub const CONFIG_BRANCH: &str = "config";
pub const KIND_CONFIG_ID: Id = id_hex!("A8DCBFD625F386AA7CDFD62A81183E82");
pub const KIND_MODEL_PROFILE_ID: Id = id_hex!("B08E356C4B08F44AB7EC177D47129447");

pub mod playground_config {
    use super::*;
    attributes! {
        "950B556A74F71AC7CB008AB23FBB6544" as system_prompt: Handle<LongString>;
        "35E36AE7B60AD946661BD63B3CD64672" as branch: Handle<LongString>;
        "F0F90572249284CD57E48580369DEB6D" as author: Handle<LongString>;
        "98A194178CFD7CBB915C1BC9EB561A7F" as author_role: Handle<LongString>;
        "D1DC11B303725409AB8A30C6B59DB2D7" as persona_id: GenId;
        "79E1B50756FB64A30916E9353225E179" as active_model_profile_id: GenId;
        "698519DFB681FABC3F06160ACAC9DA8E" as poll_ms: U256BE;
        "6691CF3F872C6107DCFAD0BCF7CDC1A0" as model_profile_id: GenId;
        "85BE7BDA465B3CB0F800F76EEF8FAC9B" as model_name: Handle<LongString>;
        "B216CFBBF85AA1350B142D510E26268B" as model_base_url: Handle<LongString>;
        "55F3FFD721AF7C1258E45BC91CDBF30F" as model_api_key: Handle<LongString>;
        "328B29CE81665EE719C5A6E91695D4D4" as tavily_api_key: Handle<LongString>;
        "AB0DF9F03F28A27A6DB95B693CC0EC53" as exa_api_key: Handle<LongString>;
        "BA4E05799CA2ACDCF3F9350FC8742F2F" as model_reasoning_effort: Handle<LongString>;
        "5F04F7A0EB4EBBE6161022B336F83513" as model_stream: U256BE;
        "F9CEA1A2E81D738BB125B4D144B7A746" as model_context_window_tokens: U256BE;
        "4200F6746B36F2784DEBA1555595D6AC" as model_max_output_tokens: U256BE;
        "1FF004BB48F7A4F8F72541F4D4FA75FF" as model_context_safety_margin_tokens: U256BE;
        "095FAECDB8FF205DF591DF594E593B01" as model_chars_per_token: U256BE;
        "120F9C6BBB103FAFFB31A66E2ABC15E6" as exec_default_cwd: Handle<LongString>;
        "D18A351B6E03A460E4F400D97D285F96" as exec_sandbox_profile: GenId;
    }
}
