//! Shared infrastructure for triblespace-backed faculties.
//!
//! The individual rust-script faculties at the root of this repo (e.g.
//! `compass.rs`, `wiki.rs`, `message.rs`) all store data in
//! triblespace piles using attribute IDs defined here. Centralizing the
//! schemas means every consumer — the rust-script itself, other faculties
//! that cross-reference, the playground dashboard, and any GORBIE notebook
//! that embeds a faculty widget — uses the same attribute IDs.

/// Crate version + baked git hash (see `build.rs`) — lets every installed
/// binary answer the stale-binary/version-skew question via `--version`.
pub const GIT_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("FACULTIES_GIT_VERSION"),
    ")"
);

/// The directory holding the durable model piles and voice reference assets
/// (`nomic_text.pile`, `qwen3tts.pile`, `ref_voice_v2_24k.wav`, …).
///
/// Resolution: the `FACULTIES_MODEL_DIR` environment variable overrides it;
/// otherwise it defaults to `$HOME/.cache/faculties/models` (with `HOME`
/// falling back to the current directory `.` when unset). This keeps the
/// faculties off any one machine's absolute layout — callers `join` the
/// specific filename onto it.
pub fn model_dir() -> std::path::PathBuf {
    if let Some(dir) = std::env::var_os("FACULTIES_MODEL_DIR") {
        return std::path::PathBuf::from(dir);
    }
    let home = std::env::var_os("HOME").unwrap_or_else(|| std::ffi::OsString::from("."));
    std::path::PathBuf::from(home).join(".cache/faculties/models")
}

pub mod activation_cutover;
pub mod archive_bm25;
pub mod archive_claude_code;
pub mod archive_collection;
pub mod archive_cutover;
pub mod atlas;
pub mod atlas_cutover;
pub mod blockdag;
pub mod body;
pub mod body_cutover;
pub mod bootstrap;
pub mod cognition;
pub mod cognition_cutover;
pub mod collection_cutover;
pub mod comb;
pub mod comb_cutover;
pub mod compass;
pub mod compass_cutover;
pub mod decide;
pub mod decide_cutover;
pub mod discord;
pub mod discord_cutover;
pub mod disposable_cutover;
pub mod files;
pub mod files_cutover;
pub mod habit_cutover;
pub mod habits;
pub mod headspace;
pub mod headspace_cutover;
pub mod mail;
pub mod mail_cutover;
pub mod mail_pop;
pub mod memory;
pub mod memory_cover;
pub mod memory_cutover;
pub mod message;
pub mod message_cutover;
#[cfg(feature = "local-embed")]
pub mod nomic;
pub mod orient;
pub mod orient_cutover;
pub mod planner;
pub mod planner_cutover;
pub mod posture_cutover;
pub mod relations;
pub mod relations_cutover;
pub mod schemas;
pub mod secrets_cutover;
pub mod status;
pub mod status_cutover;
pub mod teams;
pub mod teams_cutover;
pub mod tokens;
pub mod triage;
pub mod voice;
pub mod voice_cutover;
pub mod web_cutover;
pub mod wiki;
pub mod wiki_additive;
pub mod wiki_cutover;

#[cfg(test)]
mod attribute_id_preservation_tests;

/// Resolve a free-text argument that may reference a file or stdin, so every
/// faculty that takes prose content (`memory create`, `message send`,
/// `wiki create/edit`, `compass note`, `status set`, …) shares one convention:
///
/// - `@-`         → read all of stdin
/// - `@<path>`    → read the file at `<path>`
/// - `@@<text>`   → the literal string `@<text>` (escape hatch for content that
///                  genuinely begins with `@`, e.g. a memory summary opening
///                  with an `@mention`)
/// - anything else → the literal string, unchanged
///
/// `label` names the value in error messages (e.g. `"summary"`, `"message text"`).
///
/// This is the canonical resolver; faculties must call it rather than
/// re-implementing the `@` prefix logic, so the interface stays uniform. The
/// footgun this closes: passing `@-` as a plain positional argv (with the body
/// on a heredoc) silently stores the literal string `"@-"` unless the faculty
/// actually routes the argument through here.
pub fn text_arg(raw: &str, label: &str) -> anyhow::Result<String> {
    use anyhow::Context;
    use std::io::Read;
    if let Some(rest) = raw.strip_prefix("@@") {
        return Ok(format!("@{rest}"));
    }
    if let Some(path) = raw.strip_prefix('@') {
        if path == "-" {
            let mut value = String::new();
            std::io::stdin()
                .read_to_string(&mut value)
                .with_context(|| format!("read {label} from stdin"))?;
            return Ok(value);
        }
        return std::fs::read_to_string(path).with_context(|| format!("read {label} from {path}"));
    }
    Ok(raw.to_string())
}

/// The `secrets` faculty's capability + envelope-encryption core, re-exported so
/// faculties consumers can reach it as `faculties::secrets`. It
/// lives in the standalone `faculties-secrets` crate so other consumers can use
/// the same implementation without pulling the mary/GORBIE/egui stack.
pub use faculties_secrets as secrets;

#[cfg(feature = "widgets")]
pub mod widgets;

/// Resolve an [`triblespace::core::id::Id`] from a hex string, accepting
/// either a full 32-char id or a shorter prefix.
///
/// Fast path: a 32-char input is parsed directly without consuming
/// `candidates` — the common case when the user pasted a full id from
/// earlier output.
///
/// Prefix path: every candidate is scanned; if exactly one matches,
/// it's returned. Zero matches or multiple matches return descriptive
/// errors. Callers provide the candidate iterator — typically by
/// querying the relevant space for the entity kind they care about
/// (e.g. `find!(e: Id, pattern!(&space, [{ ?e @ metadata::tag: KIND_X }]))`).
///
/// Each faculty wraps this with a kind-specific helper that knows its
/// own `KIND_*` tags. The wrapper is what command handlers should call;
/// the goal is that every faculty command accepts prefixes uniformly.
pub fn resolve_id_prefix<I>(input: &str, candidates: I) -> anyhow::Result<triblespace::core::id::Id>
where
    I: IntoIterator<Item = triblespace::core::id::Id>,
{
    use anyhow::bail;
    use triblespace::core::id::Id;
    let trimmed = input.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        bail!("empty id");
    }
    if trimmed.len() == 32 {
        return Id::from_hex(&trimmed).ok_or_else(|| anyhow::anyhow!("invalid id '{trimmed}'"));
    }
    let mut matches: std::collections::HashSet<Id> = std::collections::HashSet::new();
    for id in candidates {
        if format!("{id:x}").starts_with(&trimmed) {
            matches.insert(id);
        }
    }
    match matches.len() {
        0 => bail!("no id starts with '{trimmed}'"),
        1 => Ok(matches.into_iter().next().unwrap()),
        n => bail!("{n} matches for prefix '{trimmed}'; provide a longer prefix"),
    }
}
