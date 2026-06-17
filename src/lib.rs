//! Shared infrastructure for triblespace-backed faculties.
//!
//! The individual rust-script faculties at the root of this repo (e.g.
//! `compass.rs`, `wiki.rs`, `message.rs`) all store data in
//! triblespace piles using attribute IDs defined here. Centralizing the
//! schemas means every consumer — the rust-script itself, other faculties
//! that cross-reference, the playground dashboard, and any GORBIE notebook
//! that embeds a faculty widget — uses the same attribute IDs.

pub mod schemas;

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
pub fn resolve_id_prefix<I>(
    input: &str,
    candidates: I,
) -> anyhow::Result<triblespace::core::id::Id>
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
