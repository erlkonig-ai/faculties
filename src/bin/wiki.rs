
use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::schemas::embeddings::{self, Embedding768};
use ed25519_dalek::SigningKey;
use hifitime::Epoch;
use itertools::Itertools;
use hifitime::efmt::Formatter;
use hifitime::efmt::consts::ISO8601_DATE;
use rand_core::OsRng;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use triblespace::core::metadata;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::macros::id_hex;
use triblespace::prelude::*;

// ── wiki branch name ──────────────────────────────────────────────────────
const WIKI_BRANCH_NAME: &str = "wiki";

// ── kinds ──────────────────────────────────────────────────────────────────
const KIND_VERSION_ID: Id = id_hex!("1AA0310347EDFED7874E8BFECC6438CF");

// ── tag vocabulary ────────────────────────────────────────────────────────
const TAG_ARCHIVED_ID: Id = id_hex!("480CB6A663C709478A26A8B49F366C3F");

const TAG_SPECS: [(Id, &str); 9] = [
    (KIND_VERSION_ID, "version"),
    (id_hex!("1A7FB717FBFCA81CA3AA7D3D186ACC8F"), "hypothesis"),
    (id_hex!("72CE6B03E39A8AAC37BC0C4015ED54E2"), "critique"),
    (id_hex!("243AE22C5E020F61EBBC8C0481BF05A4"), "finding"),
    (id_hex!("8871C1709EBFCDD2588369003D3964DE"), "paper"),
    (id_hex!("7D58EBA4E1E4A1EF868C3C4A58AEC22E"), "source"),
    (id_hex!("C86BCF906D270403A0A2083BB95B3552"), "concept"),
    (id_hex!("F8172CC4E495817AB52D2920199EF4BD"), "experiment"),
    (TAG_ARCHIVED_ID, "archived"),
];

type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;

// ── wiki attributes ────────────────────────────────────────────────────────
mod wiki {
    use super::*;
    attributes! {
        "EBFC56D50B748E38A14F5FC768F1B9C1" as fragment: inlineencodings::GenId;
        "6DBBE746B7DD7A4793CA098AB882F553" as content: inlineencodings::Handle<blobencodings::LongString>;
        "78BABEF1792531A2E51A372D96FE5F3E" as title: inlineencodings::Handle<blobencodings::LongString>;
        "DEAFB7E307DF72389AD95A850F24BAA5" as links_to: inlineencodings::GenId;
        // Content-hash reference: `files:<64-char-blake3>` points to file bytes directly.
        "C61CA2F2A70103FD79E97C2F88B854D8" as references_file_content: inlineencodings::Handle<blobencodings::RawBytes>;
        // File-entity reference: `files:<32-char-id>` points to a file entity with metadata.
        "C98FE0EF9151F196D8F7D816ABBBCC49" as references_file: inlineencodings::GenId;
    }
}

// ── CLI ────────────────────────────────────────────────────────────────────
#[derive(Parser)]
#[command(name = "wiki", about = "A TribleSpace knowledge wiki faculty")]
struct Cli {
    /// Path to the pile file
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Branch id (hex). Overrides name-based lookup.
    #[arg(long)]
    branch_id: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new fragment with its first version
    Create {
        /// Fragment title
        title: String,
        /// Content text. Use @path for file input or @- for stdin.
        content: String,
        /// Tags (by name). Unknown tags are minted automatically.
        #[arg(long)]
        tag: Vec<String>,
        /// Allow links to fragment IDs (instead of requiring version IDs),
        /// including targets that don't exist yet (`wiki check` reports
        /// any still dangling)
        #[arg(long)]
        force: bool,
        /// Use a pre-minted fragment id (32-char hex from `trible genid`)
        /// instead of generating one. Keeps ids stable across regeneration
        /// of build-artifact piles like bootstrap.pile.
        #[arg(long)]
        id: Option<String>,
    },
    /// Create a new version of an existing fragment
    Edit {
        /// Fragment or version id (full 32-char hex id)
        id: String,
        /// New content (optional; inherits previous if omitted). Use @path for file input or @- for stdin.
        content: Option<String>,
        /// New title (optional, inherits previous if omitted)
        #[arg(long)]
        title: Option<String>,
        /// Tags (replaces previous version's tags)
        #[arg(long)]
        tag: Vec<String>,
        /// Allow links to fragment IDs (instead of requiring version IDs)
        #[arg(long)]
        force: bool,
    },
    /// Show a fragment (latest version) or a specific version
    Show {
        /// Fragment or version id (full 32-char hex id)
        id: String,
        /// If id is a version, look up its fragment and show the latest version instead
        #[arg(long)]
        latest: bool,
    },
    /// Print raw content without metadata header
    Export {
        /// Fragment or version id (full 32-char hex id)
        id: String,
    },
    /// Compare two versions of a fragment
    Diff {
        /// Fragment id (full 32-char hex id)
        id: String,
        /// First version number (1-based, default: second-to-last)
        #[arg(long)]
        from: Option<usize>,
        /// Second version number (1-based, default: latest)
        #[arg(long)]
        to: Option<usize>,
    },
    /// Soft-delete a fragment (adds #archived tag)
    Archive {
        /// Fragment id (full 32-char hex id)
        id: String,
    },
    /// Restore an archived fragment (removes #archived tag)
    Restore {
        /// Fragment id (full 32-char hex id)
        id: String,
    },
    /// Revert a fragment to a previous version
    Revert {
        /// Fragment id (full 32-char hex id)
        id: String,
        /// Version number to revert to (1-based)
        #[arg(long)]
        to: usize,
    },
    /// Show links from/to a fragment (extracted from `[text](<faculty>:<hex>)` references)
    Links {
        /// Fragment id (full 32-char hex id)
        id: String,
    },
    /// List fragments, optionally filtered by tag and backlink structure
    List {
        /// Filter by tag name
        #[arg(long)]
        tag: Vec<String>,
        /// Only show fragments that have a backlink from a fragment with this tag
        #[arg(long)]
        with_backlink_tag: Vec<String>,
        /// Only show fragments that do NOT have a backlink from a fragment with this tag
        #[arg(long)]
        without_backlink_tag: Vec<String>,
        /// Only show fragments that have a typed backlink (e.g. "reviews", "cites")
        #[arg(long)]
        with_backlink_type: Vec<String>,
        /// Only show fragments that do NOT have a typed backlink of this type
        #[arg(long)]
        without_backlink_type: Vec<String>,
        /// Include archived fragments
        #[arg(long)]
        all: bool,
    },
    /// Show version history for a fragment
    History {
        /// Fragment id (full 32-char hex id)
        id: String,
    },
    /// Tag management: add, remove, list, mint
    Tag {
        #[command(subcommand)]
        command: TagCommand,
    },
    /// Import a file or directory of .typ files into the wiki
    Import {
        /// File or directory path
        path: PathBuf,
        /// Tags to apply to all imported fragments
        #[arg(long)]
        tag: Vec<String>,
    },
    /// Search fragment titles and content (substring, case-insensitive)
    Search {
        /// Search query
        query: String,
        /// Also show matching context lines
        #[arg(long, short = 'c')]
        context: bool,
        /// Include archived fragments
        #[arg(long)]
        all: bool,
    },
    /// Embed every current fragment into the shared nomic space (build step for
    /// `wiki similar`; idempotent — only embeds fragments not yet embedded).
    /// Needs `--features local-embed`.
    Embed,
    /// Semantic search: nearest fragments to a free-text query by MEANING in the
    /// shared nomic space (build/refresh with `wiki embed`). The complement to
    /// `wiki search` (lexical substring). Needs `--features local-embed`.
    Similar {
        /// Query text (matched by meaning, not keywords).
        query: String,
    },
    /// Batch export/import all fragments (version-addressed for CAS safety)
    Batch {
        #[command(subcommand)]
        action: BatchAction,
    },
    /// Check all fragments for common issues: invalid typst, broken links,
    /// truncated IDs, missing format tags.
    Check {
        /// Also try compiling typst fragments (in-process, no external tools needed)
        #[arg(long)]
        compile: bool,
    },
    /// Resolve a list of scheme:prefix lines to full-length IDs.
    /// Input: one `wiki:<hex>` or `files:<hex>` per line (from @path or @-).
    /// Output: `old\tnew` mapping for each resolved prefix, one per line.
    /// Ambiguous or unresolvable prefixes are reported on stderr.
    FixTruncated {
        /// File with scheme:prefix lines. Use @path or @- for stdin.
        input: String,
    },
    /// Apply lint transforms (markdown→typst, expand short IDs) to all latest versions.
    /// Also rebuilds the `links_to` index when the stored edges drift from what the
    /// current extract_references regex would parse (e.g. after a lint rule change).
    Lint {
        /// Actually write fixed versions and link updates (default: dry-run)
        #[arg(long)]
        fix: bool,
        /// Only check for issues, don't show diffs (CI mode)
        #[arg(long)]
        check: bool,
    },
}

#[derive(clap::Subcommand)]
enum BatchAction {
    /// Export all fragments (version-addressed .typ files)
    Export {
        /// Output directory
        dir: PathBuf,
    },
    /// Re-import edited fragments (CAS check: aborts if versions changed)
    Import {
        /// Directory containing <version-id>.typ files
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum TagCommand {
    /// Add a tag to a fragment (creates a new version)
    Add {
        /// Fragment id (full 32-char hex id)
        id: String,
        /// Tag name
        name: String,
    },
    /// Remove a tag from a fragment (creates a new version)
    Remove {
        /// Fragment id (full 32-char hex id)
        id: String,
        /// Tag name
        name: String,
    },
    /// List all tags with usage counts
    List,
    /// Mint and register a new tag name
    Mint {
        /// Tag name
        name: String,
    },
}

/// Resolve a tag ID to its name, or format as hex if unnamed.
fn tag_name(space: &TribleSet, ws: &mut Workspace<Pile>, id: Id) -> String {
    find!(h: TextHandle, pattern!(space, [{ id @ metadata::name: ?h }]))
        .next()
        .and_then(|h| ws.get::<View<str>, _>(h).ok())
        .map(|v| v.as_ref().to_string())
        .unwrap_or_else(|| format!("{:x}", id))
}

/// Format a list of tag IDs as a bracketed, comma-separated string of names.
fn format_tags(space: &TribleSet, ws: &mut Workspace<Pile>, tags: &[Id]) -> String {
    let names: Vec<String> = tags.iter().map(|t| tag_name(space, ws, *t)).collect();
    if names.is_empty() { String::new() } else { format!(" [{}]", names.join(", ")) }
}

/// Find a tag ID by name, or mint a new one if it doesn't exist.
fn resolve_tag(
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
    name: &str,
    change: &mut TribleSet,
) -> Id {
    // Search all named entities for a matching name.
    for (id, handle) in find!(
        (id: Id, h: TextHandle),
        pattern!(space, [{ ?id @ metadata::name: ?h }])
    ) {
        if let Ok(view) = ws.get::<View<str>, _>(handle) {
            if view.as_ref().eq_ignore_ascii_case(name) {
                return id;
            }
        }
    }
    // Not found — mint deterministically: the tag entity's id is
    // content-derived from its (lowercased) name, so the same tag
    // name mints the same id in every pile, and vocabularies
    // converge on merge instead of forking.
    let name_handle = ws.put(name.to_lowercase());
    let tag = entity! { _ @ metadata::name: name_handle };
    let tag_id = tag.root().expect("tag should be rooted");
    *change += tag;
    tag_id
}

/// Resolve a list of tag names to IDs, minting unknown ones.
fn resolve_tags(
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
    names: &[String],
    change: &mut TribleSet,
) -> Vec<Id> {
    names.iter()
        .filter(|n| !n.trim().is_empty())
        .map(|n| resolve_tag(space, ws, n.trim(), change))
        .collect()
}

/// Find a tag ID by name (returns None if not found).
fn find_tag_by_name(space: &TribleSet, ws: &mut Workspace<Pile>, name: &str) -> Option<Id> {
    for (id, handle) in find!(
        (id: Id, h: TextHandle),
        pattern!(space, [{ ?id @ metadata::name: ?h }])
    ) {
        if let Ok(view) = ws.get::<View<str>, _>(handle) {
            if view.as_ref().eq_ignore_ascii_case(name) {
                return Some(id);
            }
        }
    }
    None
}

// ── triblespace query helpers ──────────────────────────────────────────────

/// Check if an ID is a version entity (has KIND_VERSION tag).
fn is_version(space: &TribleSet, id: Id) -> bool {
    exists!(
        (frag: Id),
        pattern!(space, [{ id @ metadata::tag: &KIND_VERSION_ID, wiki::fragment: ?frag }])
    )
}

/// Get the fragment ID that a version belongs to.
fn version_fragment(space: &TribleSet, version_id: Id) -> Option<Id> {
    find!(
        (frag: Id),
        pattern!(space, [{ version_id @ wiki::fragment: ?frag }])
    )
    .next()
    .map(|(frag,)| frag)
}

/// Find the latest version ID for a fragment (by created_at).
fn latest_version_of(space: &TribleSet, fragment_id: Id) -> Option<Id> {
    find!(
        (vid: Id, ts: Lower),
        pattern!(space, [{
            ?vid @
            metadata::tag: &KIND_VERSION_ID,
            wiki::fragment: &fragment_id,
            metadata::created_at: ?ts,
        }])
    )
    .max_by_key(|(_, ts)| *ts)
    .map(|(vid, _)| vid)
}

/// All version IDs of a fragment, sorted oldest-first.
fn version_history_of(space: &TribleSet, fragment_id: Id) -> Vec<Id> {
    let mut versions: Vec<(Id, Lower)> = find!(
        (vid: Id, ts: Lower),
        pattern!(space, [{
            ?vid @
            metadata::tag: &KIND_VERSION_ID,
            wiki::fragment: &fragment_id,
            metadata::created_at: ?ts,
        }])
    )
    .collect();
    versions.sort_by_key(|(_, ts)| *ts);
    versions.into_iter().map(|(vid, _)| vid).collect()
}

/// Read title string for a version entity.
fn read_title(
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
    vid: Id,
) -> Option<String> {
    let (h,) = find!(
        (h: TextHandle),
        pattern!(space, [{ vid @ wiki::title: ?h }])
    )
    .next()?;
    let view: View<str> = ws.get(h).ok()?;
    Some(view.as_ref().to_string())
}

/// Get the content handle for a version entity.
fn content_handle_of(space: &TribleSet, vid: Id) -> Option<TextHandle> {
    find!(
        (h: TextHandle),
        pattern!(space, [{ vid @ wiki::content: ?h }])
    )
    .next()
    .map(|(h,)| h)
}

/// Get created_at timestamp for a version entity.
fn created_at_of(space: &TribleSet, vid: Id) -> Option<Lower> {
    find!(
        (ts: Lower),
        pattern!(space, [{ vid @ metadata::created_at: ?ts }])
    )
    .next()
    .map(|(ts,)| ts)
}

/// Get tags for a version entity (excluding KIND_VERSION).
fn tags_of(space: &TribleSet, vid: Id) -> Vec<Id> {
    find!(
        tag: Id,
        pattern!(space, [{ vid @ metadata::tag: ?tag }])
    )
    .filter(|t| *t != KIND_VERSION_ID)
    .collect()
}

/// Get stored links_to targets for a version entity.
fn links_of(space: &TribleSet, vid: Id) -> Vec<Id> {
    find!(
        target: Id,
        pattern!(space, [{ vid @ wiki::links_to: ?target }])
    )
    .collect()
}

/// Expand a hex prefix into a min/max ID range for range queries.
/// E.g. prefix "ab55" → min=ab550000...00, max=ab55ffff...ff
fn prefix_to_range(hex_prefix: &str) -> Result<(Id, Id)> {
    let clean = hex_prefix.trim().to_lowercase();
    if clean.is_empty() || clean.len() > 32 {
        bail!("invalid prefix length: expected 1-32 hex chars, got {}", clean.len());
    }
    if !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("invalid hex prefix '{clean}'");
    }
    // Pad to 32 hex chars (16 bytes) with 0s for min, Fs for max.
    let min_hex = format!("{:0<32}", clean);
    let max_hex = format!("{:f<32}", clean);
    let min = Id::from_hex(&min_hex)
        .ok_or_else(|| anyhow::anyhow!("failed to parse min id from prefix '{clean}'"))?;
    let max = Id::from_hex(&max_hex)
        .ok_or_else(|| anyhow::anyhow!("failed to parse max id from prefix '{clean}'"))?;
    Ok((min, max))
}

/// Resolve a hex prefix to an ID. Matches both version and fragment IDs.
/// Uses entity range queries on the EAV index for O(log n) lookup.
fn resolve_prefix(space: &TribleSet, input: &str) -> Result<Id> {
    let trimmed = input.trim().to_lowercase();
    // Fast path: full 32-char hex ID.
    if trimmed.len() == 32 {
        return Id::from_hex(&trimmed)
            .ok_or_else(|| anyhow::anyhow!("invalid id '{trimmed}'"));
    }
    let (min, max) = prefix_to_range(&trimmed)?;
    let mut matches = Vec::new();
    let mut seen_frags = std::collections::HashSet::new();
    // Use entity range to narrow the search to version IDs in the prefix range.
    for (vid, frag) in find!(
        (vid: Id, frag: Id),
        and!(
            pattern!(space, [{ ?vid @ metadata::tag: &KIND_VERSION_ID, wiki::fragment: ?frag }]),
            space.entity_in_range(vid, min, max),
        )
    ) {
        matches.push(vid);
        seen_frags.insert(frag);
    }
    // Also check if the prefix matches a fragment ID (stored as a value, not entity).
    // Fragment IDs are in the value position of wiki::fragment, so we need a separate scan.
    // Use the value range constraint for this.
    let frag_min_val: Inline<inlineencodings::GenId> = min.to_inline();
    let frag_max_val: Inline<inlineencodings::GenId> = max.to_inline();
    for (frag,) in find!(
        (frag: Id),
        and!(
            pattern!(space, [{ metadata::tag: &KIND_VERSION_ID, wiki::fragment: ?frag }]),
            space.value_in_range(frag, frag_min_val, frag_max_val),
        )
    ) {
        if seen_frags.insert(frag) {
            matches.push(frag);
        }
    }
    matches.sort();
    matches.dedup();
    match matches.len() {
        0 => bail!("no id matches '{input}'"),
        1 => Ok(matches[0]),
        n => bail!("ambiguous id '{input}' ({n} matches)"),
    }
}

/// Resolve a hex prefix to a fragment ID only (not version IDs).
/// Uses value range queries for O(log n) lookup on fragment IDs.
fn resolve_fragment_prefix(space: &TribleSet, input: &str) -> Result<Id> {
    let trimmed = input.trim().to_lowercase();
    // Fast path: full 32-char hex ID.
    if trimmed.len() == 32 {
        return Id::from_hex(&trimmed)
            .ok_or_else(|| anyhow::anyhow!("invalid id '{trimmed}'"));
    }
    let (min, max) = prefix_to_range(&trimmed)?;
    let frag_min_val: Inline<inlineencodings::GenId> = min.to_inline();
    let frag_max_val: Inline<inlineencodings::GenId> = max.to_inline();
    let mut matches: Vec<Id> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (frag,) in find!(
        (frag: Id),
        and!(
            pattern!(space, [{ metadata::tag: &KIND_VERSION_ID, wiki::fragment: ?frag }]),
            space.value_in_range(frag, frag_min_val, frag_max_val),
        )
    ) {
        if seen.insert(frag) {
            matches.push(frag);
        }
    }
    matches.sort();
    matches.dedup();
    match matches.len() {
        0 => bail!("no fragment matches '{input}'"),
        1 => Ok(matches[0]),
        n => bail!("ambiguous fragment prefix '{input}' ({n} matches)"),
    }
}



/// Given an ID, resolve to the fragment it belongs to.
/// Identity for fragment IDs, lookup for version IDs.
fn to_fragment(space: &TribleSet, id: Id) -> Result<Id> {
    // Try as version first (direct entity lookup, O(1)).
    if let Some(frag) = version_fragment(space, id) {
        return Ok(frag);
    }
    // Check if it's a known fragment (reverse lookup via value index).
    let is_frag = exists!(
        (vid: Id),
        pattern!(space, [{ ?vid @ wiki::fragment: &id }])
    );
    if is_frag {
        return Ok(id);
    }
    bail!("no fragment for id {}", id)
}

/// Human-readable label for a link target (version or fragment).
fn link_label(
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
    id: Id,
) -> String {
    if is_version(space, id) {
        let title = read_title(space, ws, id).unwrap_or_else(|| "?".into());
        let frag = version_fragment(space, id);
        let frag_str = frag.map(|f| format!(" of {}", f)).unwrap_or_default();
        format!("{title} [version {}{}]", id, frag_str)
    } else {
        // Fragment — show its latest version's title.
        let title = latest_version_of(space, id)
            .and_then(|vid| read_title(space, ws, vid))
            .unwrap_or_else(|| "?".into());
        format!("{title} ({})", id)
    }
}

// ── helpers ────────────────────────────────────────────────────────────────
use triblespace::core::inline::encodings::time::Lower;

fn now_tai() -> Inline<inlineencodings::NsTAIInterval> {
    let now = Epoch::now().unwrap_or(Epoch::from_unix_seconds(0.0));
    (now, now).try_to_inline().expect("TAI interval")
}

/// Build a map of fragment → (latest_version_id, timestamp) in one pass.
fn latest_versions(space: &TribleSet) -> HashMap<Id, (Id, Lower)> {
    find!(
        (vid: Id, frag: Id, ts: Lower),
        pattern!(space, [{
            ?vid @
            metadata::tag: &KIND_VERSION_ID,
            wiki::fragment: ?frag,
            metadata::created_at: ?ts,
        }])
    )
    .into_grouping_map_by(|(_, frag, _)| *frag)
    .max_by_key(|_, (_, _, ts)| *ts)
    .into_iter()
    .map(|(frag, (vid, _, ts))| (frag, (vid, ts)))
    .collect()
}


fn load_value_or_file(raw: &str, label: &str) -> Result<String> {
    if let Some(path) = raw.strip_prefix('@') {
        if path == "-" {
            let mut value = String::new();
            std::io::stdin()
                .read_to_string(&mut value)
                .with_context(|| format!("read {label} from stdin"))?;
            return Ok(value);
        }
        return fs::read_to_string(path).with_context(|| format!("read {label} from {path}"));
    }
    Ok(raw.to_string())
}

/// Format a `Lower` timestamp as ISO 8601 date (e.g. "2026-03-11").
fn format_date(ts: Lower) -> String {
    let epoch = Epoch::from_tai_duration(hifitime::Duration::from_total_nanoseconds(ts.0));
    Formatter::new(epoch, ISO8601_DATE).to_string()
}


/// Extract outgoing link facts from a version's content and return them as a
/// TribleSet rooted at `source_vid`. Everything — wiki edges, typed edges,
/// file-entity refs, and file-content refs — goes into the returned set.
///
/// STRICT: only matches `#link("<faculty>:...")` typst form with a full-length
/// hex (32 chars for GenIds, 64 chars for Blake3 content hashes). Markdown,
/// bare refs, and prefixes are NOT treated as links — lint is responsible for
/// repairing them first.
///
/// Edge kinds produced:
///   wiki:HEX32             → `wiki::links_to` (GenId)
///   wiki:<type>:HEX32      → `wiki::links_to` + derived attribute named `<type>`
///   files:HEX32            → `wiki::references_file` (GenId, points to a file entity)
///   files:HEX64            → `wiki::references_file_content` (Blake3 content handle)
fn extract_references(
    content: &str,
    space: &TribleSet,
    source_vid: Id,
) -> TribleSet {
    use regex::Regex;
    let re = Regex::new(
        r#"#link\("([a-zA-Z_][a-zA-Z0-9_]*):((?:[a-zA-Z_][a-zA-Z0-9_]*:)?)([0-9a-fA-F]{64}|[0-9a-fA-F]{32})"\)"#
    ).unwrap();

    let mut edges = TribleSet::new();
    for caps in re.captures_iter(content) {
        let faculty = &caps[1];
        let type_prefix = &caps[2];
        let hex = caps[3].to_lowercase();

        match (faculty, hex.len()) {
            ("wiki", 32) => {
                let Some(target) = Id::from_hex(&hex) else { continue; };
                if !is_version(space, target) && !is_fragment(space, target) { continue; }
                if target == source_vid { continue; }
                let eid = ExclusiveId::force_ref(&source_vid);
                edges += entity! { eid @ wiki::links_to: &target };
                if !type_prefix.is_empty() {
                    let type_name = type_prefix[..type_prefix.len() - 1].to_owned();
                    let name_handle = type_name.to_blob().get_handle();
                    let attr = triblespace::core::attribute::Attribute::<inlineencodings::GenId>::from(entity! {
                        metadata::name: name_handle,
                        metadata::value_encoding: <inlineencodings::GenId as triblespace::core::metadata::MetaDescribe>::id(),
                    });
                    let eid = ExclusiveId::force_ref(&source_vid);
                    edges += entity! { eid @ attr: &target };
                }
            }
            ("wiki", 64) => {
                // 64-char is a Blake3 hash; wiki targets are GenIds, not content
                // hashes, so ignore.
                continue;
            }
            ("files", 32) => {
                let Some(target) = Id::from_hex(&hex) else { continue; };
                let eid = ExclusiveId::force_ref(&source_vid);
                edges += entity! { eid @ wiki::references_file: &target };
            }
            ("files", 64) => {
                let Ok(hash) = inlineencodings::Hash::<inlineencodings::Blake3>::from_hex(&hex) else {
                    continue;
                };
                let handle: Inline<inlineencodings::Handle<blobencodings::RawBytes>> =
                    inlineencodings::Handle::from_hash(hash);
                let eid = ExclusiveId::force_ref(&source_vid);
                edges += entity! { eid @ wiki::references_file_content: handle };
            }
            _ => {}
        }
    }
    edges
}

fn is_fragment(space: &TribleSet, id: Id) -> bool {
    exists!(pattern!(space, [{ _?vid @ wiki::fragment: id }]))
}

type Repo = Repository<Pile>;

/// Ensure all built-in tag/kind IDs have metadata::name entries.
fn ensure_tag_vocabulary(
    repo: &mut Repo,
    ws: &mut Workspace<Pile>,
) -> Result<()> {
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow::anyhow!("checkout for tag names: {e:?}"))?;
    let existing: std::collections::HashSet<Id> = find!(
        (kind: Id),
        pattern!(&space, [{ ?kind @ metadata::name: _?handle }])
    )
    .map(|(kind,)| kind)
    .collect();

    let mut change = TribleSet::new();
    for (id, label) in TAG_SPECS {
        if existing.contains(&id) {
            continue;
        }
        let name_handle = ws.put(label.to_owned());
        change += entity! { ExclusiveId::force_ref(&id) @ metadata::name: name_handle };
    }

    if !change.is_empty() {
        ws.commit(change, "wiki: register tag names");
        repo.push(ws)
            .map_err(|e| anyhow::anyhow!("push tag names: {e:?}"))?;
    }
    Ok(())
}

// ── in-process typst validation ──────────────────────────────────────

mod typst_validate {
    use typst::foundations::{Bytes, Datetime};
    use typst::text::{Font, FontBook};
    use typst::syntax::{FileId, Source, VirtualPath};
    use typst::diag::FileResult;
    use typst::utils::LazyHash;
    use typst::{Library, LibraryExt, World};
    use typst::layout::PagedDocument;

    pub struct ValidateWorld {
        library: LazyHash<Library>,
        book: LazyHash<FontBook>,
        main_id: FileId,
        source: Source,
    }

    impl ValidateWorld {
        pub fn new(content: &str) -> Self {
            let main_id = FileId::new(None, VirtualPath::new("main.typ"));
            let source = Source::new(main_id, content.to_string());
            Self {
                library: LazyHash::new(Library::default()),
                book: LazyHash::new(FontBook::new()),
                main_id,
                source,
            }
        }

        pub fn validate(&self) -> Result<(), Vec<String>> {
            let result = typst::compile::<PagedDocument>(self);
            match result.output {
                Ok(_) => Ok(()),
                Err(errors) => {
                    let msgs: Vec<String> = errors.iter()
                        // Font errors are expected (minimal world has no fonts).
                        .filter(|e| !e.message.contains("no font"))
                        .map(|e| {
                            let mut msg = e.message.to_string();
                            if let Some(range) = self.source.range(e.span) {
                                let line = self.source.text()[..range.start]
                                    .chars().filter(|&c| c == '\n').count() + 1;
                                msg = format!("line {line}: {msg}");
                            }
                            msg
                        }).collect();
                    if msgs.is_empty() { Ok(()) } else { Err(msgs) }
                }
            }
        }
    }

    impl World for ValidateWorld {
        fn library(&self) -> &LazyHash<Library> { &self.library }
        fn book(&self) -> &LazyHash<FontBook> { &self.book }
        fn main(&self) -> FileId { self.main_id }
        fn source(&self, id: FileId) -> FileResult<Source> {
            if id == self.main_id {
                return Ok(self.source.clone());
            }
            // Resolve @preview/... package files from the local typst cache.
            if let Some(path) = package_file_path(&id) {
                let bytes = std::fs::read(&path)
                    .map_err(|_| typst::diag::FileError::NotFound(id.vpath().as_rootless_path().into()))?;
                let text = String::from_utf8(bytes)
                    .map_err(|_| typst::diag::FileError::NotFound(id.vpath().as_rootless_path().into()))?;
                return Ok(Source::new(id, text));
            }
            Err(typst::diag::FileError::NotFound(id.vpath().as_rootless_path().into()))
        }
        fn file(&self, id: FileId) -> FileResult<Bytes> {
            if let Some(path) = package_file_path(&id) {
                let bytes = std::fs::read(&path)
                    .map_err(|_| typst::diag::FileError::NotFound(id.vpath().as_rootless_path().into()))?;
                return Ok(Bytes::new(bytes));
            }
            Err(typst::diag::FileError::NotFound(id.vpath().as_rootless_path().into()))
        }
        fn font(&self, _index: usize) -> Option<Font> { None }
        fn today(&self, _offset: Option<i64>) -> Option<Datetime> { None }
    }

    /// Resolve a typst FileId pointing into a package (e.g.
    /// `@preview/cetz:0.3.2`) to a path on the local typst package cache.
    /// Returns None if the FileId has no package spec, or the cache
    /// directory cannot be located on this platform.
    ///
    /// Cache layout follows the typst CLI's convention:
    ///   <cache-root>/typst/packages/<namespace>/<name>/<version>/<vpath>
    ///
    /// Where <cache-root> is `dirs::cache_dir()`. On macOS that's
    /// `~/Library/Caches`; on Linux `$XDG_CACHE_HOME` or `~/.cache`.
    /// We fall back to `~/.cache/typst/packages` if `dirs::cache_dir`
    /// cannot be determined.
    fn package_file_path(id: &FileId) -> Option<std::path::PathBuf> {
        let pkg = id.package()?;
        let cache_root = dirs::cache_dir()
            .or_else(|| {
                std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".cache"))
            })?;
        let mut p = cache_root;
        p.push("typst");
        p.push("packages");
        p.push(pkg.namespace.as_str());
        p.push(pkg.name.as_str());
        p.push(pkg.version.to_string());
        p.push(id.vpath().as_rootless_path());
        Some(p)
    }
}

// ── lint / auto-fix ────────────────────────────────────────────────

/// Apply lint transforms to content: markdown→typst syntax, expand short IDs.
/// Returns the transformed content. The TribleSet is used for ID expansion.
fn lint_fix(content: &str, space: &TribleSet) -> String {
    let mut out = String::with_capacity(content.len());
    let mut in_code_block = false;
    for line in content.lines() {
        if line.trim_start().starts_with("```") {
            in_code_block = !in_code_block;
        }
        let fixed = if in_code_block {
            line.to_string() // Skip all transforms inside code blocks
        } else {
            lint_line(line, space)
        };
        out.push_str(&fixed);
        out.push('\n');
    }
    // Remove trailing newline if original didn't have one
    if !content.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Find well-formed *bare* references — `(wiki|files):[type:]<32|64-hex>` sitting
/// in prose, NOT inside a `#link(...)`, markdown `[..](..)`, or `[..]` bracket,
/// and not in a fenced or inline code span. These read like citations but create
/// no traversable link (only the `[label](scheme:hex)` form does). Returns
/// `(line_number, matched_text)` per occurrence. We never auto-link these — bare
/// prose that merely looks like a ref must not forge graph edges — so the caller
/// surfaces them as a warning instead.
fn bare_ref_warnings(content: &str) -> Vec<(usize, String)> {
    use regex::Regex;
    let re = Regex::new(r"(?:wiki|files):(?:[a-zA-Z_][a-zA-Z0-9_]*:)?[0-9a-fA-F]+").unwrap();
    let mut out = Vec::new();
    let mut in_code_block = false;
    for (i, line) in content.lines().enumerate() {
        if line.trim_start().starts_with("```") {
            in_code_block = !in_code_block;
            continue;
        }
        if in_code_block {
            continue;
        }
        for m in re.find_iter(line) {
            // The hex is the final colon-separated segment; require exactly a
            // 32-char id or 64-char hash (excludes `<hex>` placeholders, stray runs).
            let hex = m.as_str().rsplit(':').next().unwrap_or("");
            if hex.len() != 32 && hex.len() != 64 {
                continue;
            }
            let before = &line[..m.start()];
            // Skip if already linked/bracketed: `](files:hex)`, `#link("files:hex")`,
            // or `[files:hex]` (the latter is auto-converted by lint_bare_brackets).
            if matches!(before.chars().last(), Some('(') | Some('"') | Some('[')) {
                continue;
            }
            // Skip inside an inline `code` span (odd number of backticks before it).
            if before.matches('`').count() % 2 == 1 {
                continue;
            }
            out.push((i + 1, m.as_str().to_string()));
        }
    }
    out
}

/// Print a non-fatal warning for each bare reference (used by create/edit).
fn warn_bare_refs(content: &str) {
    for (line, r) in bare_ref_warnings(content) {
        eprintln!(
            "⚠ line {line}: bare reference `{r}` is not a traversable link — wrap it to cite: [{r}]({r})"
        );
    }
}

/// Transform a single line: headings, bold, links.
/// Bare `[wiki:HEX]`, `[wiki:<type>:HEX]` or `[files:HEX]` (no parenthesized URL, not
/// inside #link) → `#link("scheme:hex")[scheme:hex]`.
/// Must run BEFORE lint_links (which handles the markdown `[text](scheme:hex)` form).
fn lint_bare_brackets(line: &str, space: &TribleSet) -> String {
    use regex::Regex;
    // Match [wiki:HEX], [wiki:type:HEX], or [files:HEX] NOT followed by ( and NOT preceded by ") (inside a #link)
    let re_bare = Regex::new(
        r"\[(wiki|files):((?:[a-zA-Z_][a-zA-Z0-9_]*:)?[0-9a-fA-F]+)\]([^(]|$)"
    ).unwrap();
    let mut result = String::new();
    let mut last_end = 0;
    for caps in re_bare.captures_iter(line) {
        let m = caps.get(0).unwrap();
        // Skip if preceded by ") — this is the [text] part of an existing #link("...")[text]
        if m.start() > 0 && &line[m.start()-1..m.start()] == ")" {
            continue;
        }
        // Skip if preceded by a quote — inside #link("scheme:hex")
        if m.start() > 1 && &line[m.start()-1..m.start()] == "\"" {
            continue;
        }
        let scheme = &caps[1];
        let rest = &caps[2];
        let after = &caps[3];
        // Split optional type prefix: "reviews:HEX" vs "HEX"
        let (type_prefix, hex) = split_typed(rest);
        let full_hex = match try_expand_id(hex, space) {
            Ok(id) => format!("{:x}", id),
            Err(_) => hex.to_lowercase(),
        };
        result.push_str(&line[last_end..m.start()]);
        result.push_str(&format!(
            "#link(\"{scheme}:{type_prefix}{full_hex}\")[{scheme}:{type_prefix}{hex}]{after}"
        ));
        last_end = m.end();
    }
    result.push_str(&line[last_end..]);
    if result.is_empty() { line.to_string() } else { result }
}

/// Split a reference tail into (type_prefix_with_colon, hex). For `reviews:HEX`
/// returns `("reviews:", "HEX")`; for plain `HEX` returns `("", "HEX")`.
fn split_typed(rest: &str) -> (String, &str) {
    if let Some(colon) = rest.find(':') {
        let t = &rest[..colon];
        let h = &rest[colon + 1..];
        // Only treat as typed if the part before : is NOT all hex
        if !t.chars().all(|c| c.is_ascii_hexdigit()) {
            return (format!("{t}:"), h);
        }
    }
    (String::new(), rest)
}

/// `[text](https://url)` → `#link("https://url")[text]` — markdown web links to typst
fn lint_web_links(line: &str) -> String {
    use regex::Regex;
    let re = Regex::new(r"\[([^\]]+)\]\((https?://[^\)]+)\)").unwrap();
    re.replace_all(line, |caps: &regex::Captures| {
        let text = &caps[1];
        let url = &caps[2];
        format!("#link(\"{url}\")[{text}]")
    }).to_string()
}

fn lint_line(line: &str, space: &TribleSet) -> String {
    let mut s = lint_headings(line);
    s = lint_bold(&s);
    s = lint_bare_brackets(&s, space);
    s = lint_links(&s, space);
    s = lint_web_links(&s);
    // NB: bare `scheme:HEX` in prose is deliberately NOT auto-linked — a graph
    // edge must come from an explicit `[label](scheme:hex)`. `bare_ref_warnings`
    // surfaces bare refs as a warning instead (create/edit + check).
    s = lint_horizontal_rule(&s);
    s
}

/// `## Heading` → `== Heading` (only at line start, with space after #)
fn lint_headings(line: &str) -> String {
    if line.starts_with("### ") {
        format!("=== {}", &line[4..])
    } else if line.starts_with("## ") {
        format!("== {}", &line[3..])
    } else if line.starts_with("# ") {
        format!("= {}", &line[2..])
    } else {
        line.to_string()
    }
}

/// `**text**` → `*text*` (double-star bold only). Respects `\*` escapes so
/// that typst-escaped asterisks adjacent to real bold markers (e.g. `\**` at
/// the end of a table cell) are not mistaken for a markdown `**` pair.
fn lint_bold(line: &str) -> String {
    let mut result = String::with_capacity(line.len());
    let mut chars = line.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        // Backslash escape: emit the backslash and the next char literally.
        if c == '\\' {
            result.push('\\');
            if let Some((_, next)) = chars.next() {
                result.push(next);
            }
            continue;
        }
        if c == '*' {
            if let Some(&(_, '*')) = chars.peek() {
                // Found **, look for closing ** while respecting escapes.
                chars.next(); // consume second *
                if chars.peek().is_none() { break; }
                let mut found_close = false;
                let mut inner = String::new();
                while let Some((_, ic)) = chars.next() {
                    if ic == '\\' {
                        inner.push('\\');
                        if let Some((_, next)) = chars.next() {
                            inner.push(next);
                        }
                        continue;
                    }
                    if ic == '*' {
                        if let Some(&(_, '*')) = chars.peek() {
                            chars.next(); // consume closing **
                            found_close = true;
                            break;
                        }
                    }
                    inner.push(ic);
                }
                if found_close {
                    result.push('*');
                    result.push_str(&inner);
                    result.push('*');
                } else {
                    // No closing **, emit as-is
                    result.push_str(&line[i..]);
                    return result;
                }
            } else {
                result.push(c);
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// `[text](wiki:ID)` → `#link("wiki:ID")[text]`; also handles `wiki:<type>:ID`
/// and `files:ID`. Expands short ID prefixes to full 32-char hex.
fn lint_links(line: &str, space: &TribleSet) -> String {
    use regex::Regex;
    let re = Regex::new(
        r"\[([^\]]+)\]\((wiki|files):((?:[a-zA-Z_][a-zA-Z0-9_]*:)?[0-9a-fA-F]+)\)"
    ).unwrap();
    re.replace_all(line, |caps: &regex::Captures| {
        let text = &caps[1];
        let scheme = &caps[2];
        let rest = &caps[3];
        let (type_prefix, hex) = split_typed(rest);
        let full_hex = match try_expand_id(hex, space) {
            Ok(id) => format!("{:x}", id),
            Err(_) => hex.to_lowercase(),
        };
        format!("#link(\"{scheme}:{type_prefix}{full_hex}\")[{text}]")
    }).to_string()
}

/// `---` alone on a line → removed (typst doesn't have horizontal rules by default)
fn lint_horizontal_rule(line: &str) -> String {
    let trimmed = line.trim();
    if trimmed == "---" || trimmed == "***" || trimmed == "___" {
        String::new()
    } else {
        line.to_string()
    }
}

/// Try to expand a hex prefix to a full ID using the space.
/// Prefers fragment IDs over version IDs for wiki: links.
/// Returns Ok(Id) if unique, Err if ambiguous/missing/already full.
fn try_expand_id(hex: &str, space: &TribleSet) -> Result<Id> {
    let clean = hex.trim().to_lowercase();
    if clean.len() == 32 {
        return Id::from_hex(&clean)
            .ok_or_else(|| anyhow::anyhow!("invalid hex"));
    }
    if clean.len() < 4 {
        bail!("prefix too short");
    }
    // Prefer fragment resolution (stable pointers) over version resolution
    match resolve_fragment_prefix(space, &clean) {
        Ok(id) => Ok(id),
        Err(_) => resolve_prefix(space, &clean), // Fall back to version IDs
    }
}

/// Validate typst content by compiling in-process. No temp files, no shell-out.
fn validate_typst(content: &str) -> Result<()> {
    let world = typst_validate::ValidateWorld::new(content);
    match world.validate() {
        Ok(()) => Ok(()),
        Err(errors) => bail!("typst compilation failed:\n{}", errors.join("\n")),
    }
}

/// Validate that every `wiki:HEX` link in the content points at an existing
/// fragment or version. Rejects truncated links (hex != 32 chars) and links
/// to IDs that don't exist in the current wiki space. This prevents
/// hallucinated IDs and stale references from being committed.
///
/// With `allow_dangling` (the `--force` path), links to well-formed but
/// not-yet-existing targets are downgraded to warnings — needed when a
/// build script writes a cyclic link graph (e.g. bootstrap.pile, where
/// the hub and the tour spine forward-reference fragments created later).
/// `wiki check` still reports anything left dangling afterwards.
fn validate_wiki_links(content: &str, space: &TribleSet, allow_dangling: bool) -> Result<()> {
    use regex::Regex;
    let re = Regex::new(r"wiki:([0-9a-fA-F]+)").unwrap();

    let known_frags: std::collections::HashSet<Id> = find!(
        frag: Id,
        pattern!(space, [{ _?vid @ metadata::tag: &KIND_VERSION_ID, wiki::fragment: ?frag }])
    ).collect();
    let known_versions: std::collections::HashSet<Id> = find!(
        vid: Id,
        pattern!(space, [{ ?vid @ metadata::tag: &KIND_VERSION_ID }])
    ).collect();

    let mut errors = Vec::new();
    for caps in re.captures_iter(content) {
        let hex = &caps[1];
        if hex.len() != 32 {
            errors.push(format!("truncated link wiki:{hex} ({} chars, expected 32)", hex.len()));
            continue;
        }
        let Some(id) = Id::from_hex(hex) else {
            errors.push(format!("invalid hex in wiki:{hex}"));
            continue;
        };
        if !known_frags.contains(&id) && !known_versions.contains(&id) {
            if allow_dangling {
                eprintln!("warning: dangling link wiki:{hex} (target does not exist yet)");
            } else {
                errors.push(format!("broken link wiki:{hex} (target does not exist)"));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        bail!("wiki link validation failed:\n  {}", errors.join("\n  "))
    }
}

fn commit_version(
    repo: &mut Repo,
    ws: &mut Workspace<Pile>,
    mut change: TribleSet,
    fragment_id: Id,
    title: &str,
    content: TextHandle,
    tags: &[Id],
    space: &TribleSet,
    message: &str,
    force_fragment_links: bool,
) -> Result<Id> {
    let mut tag_ids = tags.to_vec();
    tag_ids.push(KIND_VERSION_ID);
    tag_ids.sort();
    tag_ids.dedup();

    // Read content text for link extraction.
    let content_text: View<str> = ws
        .get(content)
        .map_err(|e| anyhow::anyhow!("read content for link extraction: {e:?}"))?;

    let title_handle = ws.put(title.to_owned());

    // Create the version entity. Only the stable identity — fragment,
    // title, content — feeds the intrinsic id, so the same source always
    // mints the same version id (reproducible pile builds; re-creating
    // identical content dedups instead of duplicating). The volatile
    // metadata (timestamp, tags — tags are mutable via `wiki tag` and
    // tag ids are minted per pile) merges onto the id afterwards.
    // Edges (links_to + derived typed attrs) likewise follow below.
    let version = entity! { _ @
        wiki::fragment: &fragment_id,
        wiki::title: title_handle,
        wiki::content: content,
    };
    let version_id = version.root().expect("version should be rooted");
    change += version;
    change += entity! { ExclusiveId::force_ref(&version_id) @
        metadata::created_at: now_tai(),
        metadata::tag*: tag_ids.iter(),
    };

    let edges = extract_references(content_text.as_ref(), space, version_id);

    // Reject links to fragments (should target versions for stable references).
    if !force_fragment_links {
        let bad_links: Vec<Id> = find!(
            target: Id,
            pattern!(&edges, [{ version_id @ wiki::links_to: ?target }])
        ).filter(|t| !is_version(space, *t)).collect();
        if !bad_links.is_empty() {
            let ids: Vec<String> = bad_links.iter().map(|id| format!("{:x}", id)).collect();
            bail!("link targets are fragments, not versions: {}. \
                Use version IDs for stable references, or pass --force to override.",
                ids.join(", "));
        }
    }

    change += edges;

    ws.commit(change, message);
    repo.push(ws).map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
    Ok(version_id)
}

/// Outgoing and incoming links for an ID (fragment or version).
/// Returns (outgoing targets, incoming sources, external references).
fn find_links(
    space: &TribleSet,
    ws: &mut Workspace<Pile>,
    id: Id,
) -> Result<(Vec<Id>, Vec<Id>, Vec<(String, String)>)> {
    // Determine the version to read outgoing links from.
    let vid = if is_version(space, id) {
        id
    } else {
        latest_version_of(space, id)
            .ok_or_else(|| anyhow::anyhow!("no versions for {}", id))?
    };

    // Outgoing: stored links_to on this version, with content-parse fallback.
    let mut outgoing = links_of(space, vid);
    if outgoing.is_empty() {
        if let Some(ch) = content_handle_of(space, vid) {
            let content: View<str> = ws.get(ch)
                .map_err(|e| anyhow::anyhow!("read content: {e:?}"))?;
            let edges = extract_references(content.as_ref(), space, vid);
            outgoing = find!(
                target: Id,
                pattern!(&edges, [{ vid @ wiki::links_to: ?target }])
            ).filter(|&t| t != id).collect();
        }
    }
    outgoing.sort();
    outgoing.dedup();

    // Incoming: all entities that link_to this ID (direct conjunctive query).
    let mut incoming: Vec<Id> = find!(
        source: Id,
        pattern!(space, [{ ?source @ wiki::links_to: &id }])
    )
    .collect();
    // Also check for links to the fragment if id is a version (or vice versa).
    if is_version(space, id) {
        if let Some(frag) = version_fragment(space, id) {
            for s in find!(
                source: Id,
                pattern!(space, [{ ?source @ wiki::links_to: &frag }])
            ) {
                incoming.push(s);
            }
        }
    } else {
        // id is a fragment — also collect links to any of its versions.
        let versions: Vec<Id> = version_history_of(space, id);
        if !versions.is_empty() {
            let version_set: std::collections::HashSet<Id> = versions.into_iter().collect();
            incoming.extend(find!(
                source: Id,
                temp!((vid),
                    and!(
                        (&version_set).has(vid),
                        pattern!(space, [{ ?source @ wiki::links_to: ?vid }])
                    )
                )
            ));
        }
    }
    incoming.sort();
    incoming.dedup();

    // File references: stored as tribles on the version. Query both the
    // entity-reference index (references_file) and the content-hash index
    // (references_file_content) and return them in a uniform (faculty, hex) shape
    // for display.
    let mut external: Vec<(String, String)> = Vec::new();
    for (target,) in find!(
        (t: Id),
        pattern!(space, [{ vid @ wiki::references_file: ?t }])
    ) {
        external.push(("files".to_string(), format!("{:x}", target)));
    }
    for (handle,) in find!(
        (h: Inline<inlineencodings::Handle<blobencodings::RawBytes>>),
        pattern!(space, [{ vid @ wiki::references_file_content: ?h }])
    ) {
        let hash: Inline<inlineencodings::Hash<inlineencodings::Blake3>> =
            inlineencodings::Handle::to_hash(handle);
        external.push((
            "files".to_string(),
            inlineencodings::Hash::<inlineencodings::Blake3>::to_hex(&hash),
        ));
    }
    external.sort();
    external.dedup();

    Ok((outgoing, incoming, external))
}

/// Determine the version to display for a given ID.
/// If `follow_latest` is true and id is a version, jump to the latest version
/// of its fragment instead.
fn resolve_to_show(space: &TribleSet, id: Id, follow_latest: bool) -> Result<Id> {
    if is_version(space, id) {
        if follow_latest {
            let frag = version_fragment(space, id)
                .ok_or_else(|| anyhow::anyhow!("version has no fragment"))?;
            latest_version_of(space, frag)
                .ok_or_else(|| anyhow::anyhow!("no versions for fragment"))
        } else {
            Ok(id)
        }
    } else {
        // Fragment — always show latest version.
        latest_version_of(space, id)
            .ok_or_else(|| anyhow::anyhow!("no versions for {}", id))
    }
}

// ── commands ───────────────────────────────────────────────────────────────

fn cmd_fix_truncated(repo: &mut Repo, bid: Id, raw_input: String) -> Result<()> {
    let input = load_value_or_file(&raw_input, "input")?;

    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;

    let mut resolved = 0u32;
    let mut ambiguous = 0u32;
    let mut already_full = 0u32;

    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let Some((scheme, hex)) = line.split_once(':') else {
            eprintln!("SKIP: {line} (no scheme:prefix format)");
            continue;
        };
        let full_len = if scheme == "wiki" { 32 } else if scheme == "files" { 64 } else {
            eprintln!("SKIP: {line} (unknown scheme '{scheme}')");
            continue;
        };
        if hex.len() >= full_len {
            already_full += 1;
            continue; // already full length, nothing to do
        }
        match resolve_prefix(&space, hex) {
            Ok(id) => {
                println!("{}\t{}:{}", line, scheme, id);
                resolved += 1;
            }
            Err(e) => {
                eprintln!("AMBIGUOUS: {} — {}", line, e);
                ambiguous += 1;
            }
        }
    }
    eprintln!("{} resolved, {} ambiguous, {} already full", resolved, ambiguous, already_full);
    Ok(())
}

fn cmd_check(repo: &mut Repo, bid: Id, try_compile: bool) -> Result<()> {
    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;

    let latest = latest_versions(&space);

    // Collect ALL known IDs for link checking (fragments + every version, not just latest)
    let all_frag_ids: std::collections::HashSet<Id> = latest.keys().copied().collect();
    let all_version_ids: std::collections::HashSet<Id> = find!(
        vid: Id,
        pattern!(&space, [{ ?vid @ metadata::tag: &KIND_VERSION_ID }])
    ).collect();

    // All fragments are typst — no markdown path

    let mut issues = 0u32;
    let mut checked = 0u32;
    let mut compile_ok = 0u32;
    let mut compile_fail = 0u32;

    let tmp_dir = std::env::temp_dir().join("wiki-check");
    if try_compile {
        let _ = fs::create_dir_all(&tmp_dir);
    }

    for (frag_id, (vid, _)) in &latest {
        let tags = tags_of(&space, *vid);
        if tags.contains(&TAG_ARCHIVED_ID) {
            continue;
        }
        checked += 1;
        let title = read_title(&space, &mut ws, *vid).unwrap_or_else(|| "?".into());
        let frag_hex = format!("{:x}", frag_id);

        // All fragments are typst (no markdown path)

        // Read content
        let Some(ch) = content_handle_of(&space, *vid) else {
            eprintln!("NO_CONTENT   {}  {}", frag_hex, title);
            issues += 1;
            continue;
        };
        let content: View<str> = ws.get(ch)
            .map_err(|e| anyhow::anyhow!("read content: {e:?}"))?;
        let content_str = content.as_ref();

        // Check: truncated links
        use regex::Regex;
        let re = Regex::new(r"(wiki|files):([0-9a-fA-F]+)").unwrap();
        for caps in re.captures_iter(content_str) {
            let scheme = &caps[1];
            let hex = &caps[2];
            // wiki: links must be 32 chars (entity ID)
            // files: links can be 32 chars (entity ID) or 64 chars (hash)
            let is_truncated = match scheme {
                "wiki" => hex.len() < 32,
                "files" => hex.len() != 32 && hex.len() != 64,
                _ => false,
            };
            if is_truncated {
                eprintln!("TRUNCATED    {}  {}:{}  in {}", frag_hex, scheme, hex, title);
                issues += 1;
            }
        }

        // Check: broken wiki links
        for caps in re.captures_iter(content_str) {
            let scheme = &caps[1];
            let hex = &caps[2];
            if scheme == "wiki" && hex.len() == 32 {
                if let Some(id) = Id::from_hex(hex) {
                    if !all_frag_ids.contains(&id) && !all_version_ids.contains(&id) {
                        eprintln!("BROKEN_LINK  {}  wiki:{}  in {}", frag_hex, hex, title);
                        issues += 1;
                    }
                }
            }
        }

        // Check: markdown-style links [text](faculty:hex) — should be typst #link("faculty:hex")[text]
        {
            let md_link_re = regex::Regex::new(r"\[([^\]]+)\]\(((?:wiki|files):[^)]+)\)").unwrap();
            for caps in md_link_re.captures_iter(content_str) {
                let text = &caps[1];
                let url = &caps[2];
                // Skip illustrative examples with a placeholder target
                // (`[label](files:<hash>)`) — those can't lint to #link and are
                // meant to show the source form.
                if url.contains('<') {
                    continue;
                }
                eprintln!("MD_LINK      {}  [{}]({})  in {}", frag_hex, text, url, title);
                issues += 1;
            }
        }

        // Check: bare references — well-formed scheme:hex in prose that isn't a
        // link. Looks like a citation but creates no traversable edge.
        for (lineno, refstr) in bare_ref_warnings(content_str) {
            eprintln!("BARE_REF     {}  {} (line {})  in {}", frag_hex, refstr, lineno, title);
            issues += 1;
        }

        // Check: typst compilation (in-process)
        if try_compile {
            let world = typst_validate::ValidateWorld::new(content_str);
            match world.validate() {
                Ok(()) => { compile_ok += 1; }
                Err(errors) => {
                    let first = errors.first().map(|s| s.as_str()).unwrap_or("unknown");
                    eprintln!("TYPST_ERROR  {}  {}  {}", frag_hex, title, first);
                    compile_fail += 1;
                    issues += 1;
                }
            }
        }
    }

    let _ = fs::remove_dir(&tmp_dir);

    // Check: orphaned fragments (no incoming or outgoing wiki edges)
    let mut has_outgoing: std::collections::HashSet<Id> = std::collections::HashSet::new();
    let mut has_incoming: std::collections::HashSet<Id> = std::collections::HashSet::new();
    for (frag_id, (vid, _)) in &latest {
        let tags = tags_of(&space, *vid);
        if tags.contains(&TAG_ARCHIVED_ID) { continue; }
        let outgoing = links_of(&space, *vid);
        if !outgoing.is_empty() {
            has_outgoing.insert(*frag_id);
        }
        for target in &outgoing {
            has_incoming.insert(*target);
            // Also mark the fragment that owns this version
            if let Some(target_frag) = version_fragment(&space, *target) {
                has_incoming.insert(target_frag);
            }
        }
    }
    let mut orphans = 0u32;
    for (frag_id, (vid, _)) in &latest {
        let tags = tags_of(&space, *vid);
        if tags.contains(&TAG_ARCHIVED_ID) { continue; }
        if !has_outgoing.contains(frag_id) && !has_incoming.contains(frag_id) {
            let title = read_title(&space, &mut ws, *vid).unwrap_or_else(|| "?".into());
            eprintln!("ORPHAN       {}  {}", frag_id, title);
            orphans += 1;
        }
    }

    println!();
    println!("Checked {} fragments, {} issues found", checked, issues);
    if orphans > 0 {
        println!("Orphans: {} (no incoming or outgoing wiki links)", orphans);
    }
    if try_compile {
        println!("Typst: {} ok, {} failed", compile_ok, compile_fail);
    }
    if issues == 0 && orphans == 0 {
        println!("All clear!");
    }
    Ok(())
}

fn cmd_lint(repo: &mut Repo, bid: Id, do_fix: bool, check_only: bool) -> Result<()> {
    // Dry-run and check modes: single pull, no commits.
    if !do_fix {
        let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let latest = latest_versions(&space);

        let mut changed = 0u32;
        let mut relinked = 0u32;
        let mut checked = 0u32;

        for (&frag_id, &(vid, _ts)) in &latest {
            let Some(ch) = content_handle_of(&space, vid) else { continue; };
            let Ok(content) = ws.get::<View<str>, _>(ch) else { continue; };
            let original = content.as_ref().to_string();
            checked += 1;

            let fixed = lint_fix(&original, &space);
            if fixed != original {
                changed += 1;
                let title = read_title(&space, &mut ws, vid).unwrap_or_default();
                if check_only {
                    eprintln!("LINT {:x} — {title}", frag_id);
                } else {
                    println!("WOULD FIX {:x} — {title}", frag_id);
                    let orig_lines: Vec<&str> = original.lines().collect();
                    let fixed_lines: Vec<&str> = fixed.lines().collect();
                    for (i, (o, f)) in orig_lines.iter().zip(fixed_lines.iter()).enumerate() {
                        if o != f {
                            println!("  L{}: - {}", i + 1, o);
                            println!("  L{}: + {}", i + 1, f);
                        }
                    }
                }
            } else {
                // Text unchanged: compute desired edges and subtract stored.
                let desired = extract_references(&original, &space, vid);
                let missing = desired.difference(&space);
                if !missing.is_empty() {
                    relinked += 1;
                    let title = read_title(&space, &mut ws, vid).unwrap_or_default();
                    let n = missing.len();
                    if check_only {
                        eprintln!("RELINK {:x} +{n} edges — {title}", frag_id);
                    } else {
                        println!("WOULD RELINK {:x} +{n} edges — {title}", frag_id);
                    }
                }
            }
        }

        println!();
        println!("Checked: {checked}, Changed: {changed}, Relinked: {relinked}");
        if check_only && (changed > 0 || relinked > 0) {
            bail!("{changed} fragments need lint fixes; {relinked} need relink");
        }
        return Ok(());
    }

    // Fix mode: CAS loop like cmd_import_all. Accumulate all changes, try_push
    // once, retry on conflict. No new tags needed — lint preserves existing tags.
    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;

    loop {
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let latest = latest_versions(&space);

        let mut change = TribleSet::new();
        let mut fixed_count = 0u32;
        let mut relinked_count = 0u32;
        let mut new_links_count = 0u32;
        let mut error_count = 0u32;
        let mut checked = 0u32;

        for (&frag_id, &(vid, _ts)) in &latest {
            let Some(ch) = content_handle_of(&space, vid) else { continue; };
            let Ok(content) = ws.get::<View<str>, _>(ch) else { continue; };
            let original = content.as_ref().to_string();
            checked += 1;

            let fixed = lint_fix(&original, &space);
            if fixed == original {
                // Text already clean: rebuild the desired link tribles and subtract
                // what's already in the space — add only the missing ones.
                let desired = extract_references(&original, &space, vid);
                let missing = desired.difference(&space);
                if missing.is_empty() {
                    continue;
                }

                let title = read_title(&space, &mut ws, vid).unwrap_or_default();
                let added = missing.len();
                change += missing;
                relinked_count += 1;
                new_links_count += added as u32;
                println!("RELINKED {:x} +{} edges — {title}", frag_id, added);
                continue;
            }

            let title = read_title(&space, &mut ws, vid).unwrap_or_default();

            if let Err(e) = validate_typst(&fixed) {
                eprintln!("LINT_TYPST_ERROR {:x} — {title}: {e}", frag_id);
                error_count += 1;
                continue;
            }
            if let Err(e) = validate_wiki_links(&fixed, &space, false) {
                eprintln!("LINT_LINK_ERROR {:x} — {title}: {e}", frag_id);
                error_count += 1;
                continue;
            }

            // Build new version entity directly (same pattern as cmd_import_all).
            let tag_ids = tags_of(&space, vid);
            let content_handle = ws.put(fixed);
            let content_text: View<str> = match ws.get(content_handle) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("LINT_READ_ERROR {:x}: {e:?}", frag_id);
                    error_count += 1;
                    continue;
                }
            };
            let mut all_tags = tag_ids;
            all_tags.push(KIND_VERSION_ID);
            all_tags.sort(); all_tags.dedup();
            let title_handle = ws.put(title.clone());
            let version = entity! { _ @
                wiki::fragment: &frag_id,
                wiki::title: title_handle,
                wiki::content: content_handle,
                metadata::created_at: now_tai(),
                metadata::tag*: all_tags.iter(),
            };
            let version_id = version.root().expect("version should be rooted");
            change += version;
            change += extract_references(content_text.as_ref(), &space, version_id);
            fixed_count += 1;
            println!("FIXED {:x} — {title}", frag_id);
        }

        if fixed_count == 0 && relinked_count == 0 {
            println!("Checked: {checked}, Changed: 0, Errors: {error_count}");
            return Ok(());
        }

        ws.commit(change, "wiki lint --fix");
        match repo.try_push(&mut ws) {
            Ok(None) => {
                println!();
                println!(
                    "Checked: {checked}, Fixed: {fixed_count}, Relinked: {relinked_count} (+{new_links_count} links), Errors: {error_count}"
                );
                return Ok(());
            }
            Ok(Some(conflict_ws)) => {
                eprintln!("Push conflict — retrying...");
                ws = conflict_ws;
            }
            Err(e) => bail!("push failed: {e:?}"),
        }
    }
}

fn cmd_export_all(repo: &mut Repo, bid: Id, dir: PathBuf) -> Result<()> {
    fs::create_dir_all(&dir).context("create output directory")?;
    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let mut count = 0u32;
    let latest = latest_versions(&space);
    for (_frag_id, (vid, _)) in &latest {
        // Skip archived
        let tags = tags_of(&space, *vid);
        if tags.contains(&TAG_ARCHIVED_ID) {
            continue;
        }
        let Some(ch) = content_handle_of(&space, *vid) else { continue };
        let content: View<str> = ws.get(ch)
            .map_err(|e| anyhow::anyhow!("read content: {e:?}"))?;
        // Name by version ID so import-all can do CAS check.
        let path = dir.join(format!("{:x}.typ", vid));
        fs::write(&path, content.as_ref())
            .with_context(|| format!("write {}", path.display()))?;
        count += 1;
    }
    eprintln!("Exported {} fragments (version-addressed) to {}", count, dir.display());
    Ok(())
}

fn cmd_import_all(repo: &mut Repo, bid: Id, dir: PathBuf) -> Result<()> {
    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    ensure_tag_vocabulary(repo, &mut ws)?;

    // Build version->fragment map for filename resolution.
    let mut vid_to_frag: HashMap<Id, Id> = HashMap::new();
    for (vid, frag) in find!(
        (vid: Id, frag: Id),
        pattern!(&space, [{
            ?vid @
            metadata::tag: &KIND_VERSION_ID,
            wiki::fragment: ?frag,
        }])
    ) {
        vid_to_frag.insert(vid, frag);
    }

    let entries: Vec<_> = fs::read_dir(&dir)
        .with_context(|| format!("read dir {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "typ"))
        .collect();

    // Parse version IDs from filenames and resolve to fragments.
    let mut work: Vec<(Id, Id, std::path::PathBuf)> = Vec::new(); // (frag_id, exported_vid, path)
    for entry in &entries {
        let stem = entry.path().file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_string);
        let Some(hex) = stem else { continue };
        let Some(exported_vid) = Id::from_hex(hex.trim()) else {
            eprintln!("skip {}: invalid version id", entry.path().display());
            continue;
        };
        let Some(&frag_id) = vid_to_frag.get(&exported_vid) else {
            eprintln!("skip {}: unknown version (not in wiki)", entry.path().display());
            continue;
        };
        work.push((frag_id, exported_vid, entry.path()));
    }

    // CAS loop: checkout -> check versions -> build changes -> commit -> try_push.
    // On conflict, take the new workspace and retry.
    loop {
        let space = ws.checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;

        let curr_latest = latest_versions(&space);

        // Build change set: only fragments whose latest version matches export.
        let mut change = TribleSet::new();
        let mut updated = 0u32;

        for (frag_id, exported_vid, path) in &work {
            let still_latest = curr_latest.get(frag_id)
                .map_or(false, |(current, _)| *current == *exported_vid);
            if !still_latest {
                eprintln!("CONFLICT {:x} — skipping", frag_id);
                continue;
            }

            let new_content = fs::read_to_string(path)
                .with_context(|| format!("read {}", path.display()))?;

            let existing_content = content_handle_of(&space, *exported_vid)
                .and_then(|ch| ws.get::<View<str>, _>(ch).ok())
                .map(|v| v.as_ref().to_string())
                .unwrap_or_default();
            if new_content == existing_content { continue; }

            // Lint-fix then validate typst
            let new_content = lint_fix(&new_content, &space);
            if let Err(e) = validate_typst(&new_content) {
                eprintln!("TYPST_ERROR {}: {}", path.display(), e);
                continue;
            }

            let tag_ids = tags_of(&space, *exported_vid);
            let title = read_title(&space, &mut ws, *exported_vid).unwrap_or_default();
            let content_handle = ws.put(new_content);
            let content_text = ws.get::<View<str>, _>(content_handle)
                .map_err(|e| anyhow::anyhow!("read: {e:?}"))?
                .as_ref()
                .to_string();
            let mut all_tags = tag_ids;
            all_tags.push(KIND_VERSION_ID);
            all_tags.sort(); all_tags.dedup();
            let title_handle = ws.put(title);
            let version = entity! { _ @
                wiki::fragment: frag_id,
                wiki::title: title_handle,
                wiki::content: content_handle,
                metadata::created_at: now_tai(),
                metadata::tag*: all_tags.iter(),
            };
            let version_id = version.root().expect("version should be rooted");
            change += version;
            change += extract_references(&content_text, &space, version_id);
            updated += 1;
        }

        if updated == 0 {
            eprintln!("Nothing to import (all unchanged or conflicted).");
            return Ok(());
        }

        ws.commit(change, "wiki import-all");
        match repo.try_push(&mut ws) {
            Ok(None) => {
                eprintln!("Imported: {} updated, {} total files", updated, entries.len());
                return Ok(());
            }
            Ok(Some(conflict_ws)) => {
                eprintln!("Push conflict — retrying...");
                ws = conflict_ws;
            }
            Err(e) => bail!("push failed: {e:?}"),
        }
    }
}

fn cmd_create(
    repo: &mut Repo,
    bid: Id,
    title: String,
    content: String,
    tags: Vec<String>,
    force: bool,
    id: Option<String>,
) -> Result<()> {
    let title = load_value_or_file(&title, "title")?;
    let content = load_value_or_file(&content, "content")?;

    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    ensure_tag_vocabulary(repo, &mut ws)?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let mut change = TribleSet::new();
    let tag_ids = resolve_tags(&space, &mut ws, &tags, &mut change);

    // Lint-fix then validate typst compilation and link targets.
    let content = lint_fix(&content, &space);
    validate_typst(&content)?;
    validate_wiki_links(&content, &space, force)?;
    warn_bare_refs(&content);

    let fragment_id = match id {
        Some(hex) => {
            if hex.len() != 32 {
                bail!("--id must be 32 hex chars (got {})", hex.len());
            }
            let Some(id) = Id::from_hex(&hex) else {
                bail!("--id is not valid hex: {hex}");
            };
            if latest_version_of(&space, id).is_some() {
                bail!("fragment {id} already exists — use `wiki edit`");
            }
            id
        }
        None => genid().id,
    };
    let content_handle = ws.put(content);
    let vid = commit_version(
        repo, &mut ws, change, fragment_id, &title, content_handle, &tag_ids, &space, "wiki create", force,
    )?;

    println!("fragment {}", fragment_id);
    println!("version  {}", vid);
    Ok(())
}

fn cmd_edit(
    repo: &mut Repo,
    bid: Id,
    id: String,
    content: Option<String>,
    new_title: Option<String>,
    tags: Vec<String>,
    force: bool,
) -> Result<()> {
    let content = content.map(|c| load_value_or_file(&c, "content")).transpose()?;
    let new_title = new_title.map(|t| load_value_or_file(&t, "title")).transpose()?;
    if content.is_none() && new_title.is_none() && tags.is_empty() {
        bail!("nothing to change — provide content, --title, or --tag");
    }

    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let resolved = resolve_prefix(&space, &id)?;
    let fragment_id = to_fragment(&space, resolved)?;
    let prev_vid = latest_version_of(&space, fragment_id)
        .ok_or_else(|| anyhow::anyhow!("no versions for fragment {}", fragment_id))?;

    ensure_tag_vocabulary(repo, &mut ws)?;
    let mut change = TribleSet::new();
    let tag_ids = if tags.is_empty() {
        tags_of(&space, prev_vid)
    } else {
        resolve_tags(&space, &mut ws, &tags, &mut change)
    };

    let title = new_title.unwrap_or_else(|| {
        read_title(&space, &mut ws, prev_vid).unwrap_or_default()
    });
    // Validate typst if tagged (either explicitly or inherited)
    let content_handle = match &content {
        Some(text) => {
            // Lint-fix then validate typst compilation and link targets.
            let fixed = lint_fix(text, &space);
            validate_typst(&fixed)?;
            validate_wiki_links(&fixed, &space, force)?;
            warn_bare_refs(&fixed);
            ws.put(fixed)
        }
        None => content_handle_of(&space, prev_vid)
            .ok_or_else(|| anyhow::anyhow!("no content on previous version"))?,
    };
    let vid = commit_version(
        repo, &mut ws, change, fragment_id, &title, content_handle, &tag_ids, &space, "wiki edit", force,
    )?;

    println!("fragment {}", fragment_id);
    println!("version  {}", vid);
    Ok(())
}

fn cmd_show(repo: &mut Repo, bid: Id, id: String, follow_latest: bool) -> Result<()> {
    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let parsed_id = resolve_prefix(&space, &id)?;
    let vid = resolve_to_show(&space, parsed_id, follow_latest)?;
    let fragment_id = version_fragment(&space, vid)
        .ok_or_else(|| anyhow::anyhow!("version has no fragment"))?;

    let content_h = content_handle_of(&space, vid)
        .ok_or_else(|| anyhow::anyhow!("no content"))?;
    let content: View<str> = ws.get(content_h)
        .map_err(|e| anyhow::anyhow!("read content: {e:?}"))?;
    let title = read_title(&space, &mut ws, vid).unwrap_or_default();
    let tags = tags_of(&space, vid);
    let created_at = created_at_of(&space, vid).unwrap_or(Lower(0));

    println!("# {title}");
    println!(
        "fragment: {}  version: {}  date: {}",
        format!("{:x}", fragment_id), vid, format_date(created_at),
    );
    let tag_str = format_tags(&space, &mut ws, &tags);
    if !tag_str.is_empty() {
        println!("tags:{tag_str}");
    }
    println!();
    print!("{}", content.as_ref());

    let (outgoing, incoming, external) = find_links(&space, &mut ws, fragment_id)?;
    if !outgoing.is_empty() || !incoming.is_empty() || !external.is_empty() {
        println!("\n---");
    }
    for target in &outgoing {
        let label = link_label(&space, &mut ws, *target);
        println!("→ {label}");
    }
    for source in &incoming {
        let label = link_label(&space, &mut ws, *source);
        println!("← {label}");
    }
    for (faculty, hex) in &external {
        println!("⇢ {faculty}:{hex}");
    }

    Ok(())
}

fn cmd_export(repo: &mut Repo, bid: Id, id: String) -> Result<()> {
    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let parsed_id = resolve_prefix(&space, &id)?;
    let vid = resolve_to_show(&space, parsed_id, false)?;
    let ch = content_handle_of(&space, vid)
        .ok_or_else(|| anyhow::anyhow!("no content"))?;
    let content: View<str> = ws.get(ch)
        .map_err(|e| anyhow::anyhow!("read content: {e:?}"))?;
    print!("{}", content.as_ref());
    Ok(())
}

fn cmd_diff(
    repo: &mut Repo,
    bid: Id,
    id: String,
    from: Option<usize>,
    to: Option<usize>,
) -> Result<()> {
    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let resolved = resolve_prefix(&space, &id)?;
    let fragment_id = to_fragment(&space, resolved)?;
    let history = version_history_of(&space, fragment_id);
    let n = history.len();
    if n < 2 {
        bail!(
            "fragment {} has only {n} version(s), need at least 2 to diff",
            format!("{:x}", fragment_id)
        );
    }

    let from_idx = from.map(|v| v.saturating_sub(1)).unwrap_or(n - 2);
    let to_idx = to.map(|v| v.saturating_sub(1)).unwrap_or(n - 1);
    if from_idx >= n || to_idx >= n {
        bail!("version index out of range (fragment has {n} versions)");
    }

    let old_vid = history[from_idx];
    let new_vid = history[to_idx];

    let old_ch = content_handle_of(&space, old_vid).ok_or_else(|| anyhow::anyhow!("no content"))?;
    let new_ch = content_handle_of(&space, new_vid).ok_or_else(|| anyhow::anyhow!("no content"))?;
    let old_content: View<str> = ws.get(old_ch).map_err(|e| anyhow::anyhow!("read old content: {e:?}"))?;
    let new_content: View<str> = ws.get(new_ch).map_err(|e| anyhow::anyhow!("read new content: {e:?}"))?;

    let old_title = read_title(&space, &mut ws, old_vid).unwrap_or_default();
    let new_title = read_title(&space, &mut ws, new_vid).unwrap_or_default();

    println!("--- v{} {}  {}", from_idx + 1, old_vid, old_title);
    println!("+++ v{} {}  {}", to_idx + 1, new_vid, new_title);

    let old_tags = format_tags(&space, &mut ws, &tags_of(&space, old_vid));
    let new_tags = format_tags(&space, &mut ws, &tags_of(&space, new_vid));
    if old_tags != new_tags {
        println!("- tags:{old_tags}");
        println!("+ tags:{new_tags}");
    }

    let old_lines: Vec<&str> = old_content.as_ref().lines().collect();
    let new_lines: Vec<&str> = new_content.as_ref().lines().collect();
    let hunks = unified_diff(&old_lines, &new_lines, 3);

    if hunks.is_empty() && old_tags == new_tags && old_title == new_title {
        println!("(no changes)");
    }
    for line in hunks {
        println!("{line}");
    }

    Ok(())
}

fn cmd_archive(repo: &mut Repo, bid: Id, id: String) -> Result<()> {
    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let resolved = resolve_prefix(&space, &id)?;
    let fragment_id = to_fragment(&space, resolved)?;
    let prev_vid = latest_version_of(&space, fragment_id)
        .ok_or_else(|| anyhow::anyhow!("no versions for fragment {}", fragment_id))?;
    let prev_tags = tags_of(&space, prev_vid);
    let prev_title = read_title(&space, &mut ws, prev_vid).unwrap_or_default();

    if prev_tags.contains(&TAG_ARCHIVED_ID) {
        println!("already archived: {} ({})", prev_title, fragment_id);
        return Ok(());
    }

    ensure_tag_vocabulary(repo, &mut ws)?;
    let mut tags = prev_tags;
    tags.push(TAG_ARCHIVED_ID);
    let prev_ch = content_handle_of(&space, prev_vid)
        .ok_or_else(|| anyhow::anyhow!("no content"))?;
    commit_version(
        repo, &mut ws, TribleSet::new(), fragment_id, &prev_title, prev_ch, &tags,
        &space, "wiki archive", true,
    )?;

    println!("archived: {} ({})", prev_title, fragment_id);
    Ok(())
}

fn cmd_restore(repo: &mut Repo, bid: Id, id: String) -> Result<()> {
    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let resolved = resolve_prefix(&space, &id)?;
    let fragment_id = to_fragment(&space, resolved)?;
    let prev_vid = latest_version_of(&space, fragment_id)
        .ok_or_else(|| anyhow::anyhow!("no versions for fragment {}", fragment_id))?;
    let prev_tags = tags_of(&space, prev_vid);
    let prev_title = read_title(&space, &mut ws, prev_vid).unwrap_or_default();

    if !prev_tags.contains(&TAG_ARCHIVED_ID) {
        println!("not archived: {} ({})", prev_title, fragment_id);
        return Ok(());
    }

    let tags: Vec<Id> = prev_tags.into_iter().filter(|t| *t != TAG_ARCHIVED_ID).collect();
    let prev_ch = content_handle_of(&space, prev_vid)
        .ok_or_else(|| anyhow::anyhow!("no content"))?;
    commit_version(
        repo, &mut ws, TribleSet::new(), fragment_id, &prev_title, prev_ch, &tags,
        &space, "wiki restore", true,
    )?;

    println!("restored: {} ({})", prev_title, fragment_id);
    Ok(())
}

fn cmd_revert(repo: &mut Repo, bid: Id, id: String, to: usize) -> Result<()> {
    if to == 0 {
        bail!("version number is 1-based");
    }

    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let resolved = resolve_prefix(&space, &id)?;
    let fragment_id = to_fragment(&space, resolved)?;
    let history = version_history_of(&space, fragment_id);

    let idx = to - 1;
    if idx >= history.len() {
        bail!(
            "fragment {} has {} version(s), cannot revert to v{to}",
            format!("{:x}", fragment_id), history.len(),
        );
    }

    let target_vid = history[idx];
    let target_title = read_title(&space, &mut ws, target_vid).unwrap_or_default();
    let target_ch = content_handle_of(&space, target_vid)
        .ok_or_else(|| anyhow::anyhow!("no content"))?;
    let target_tags = tags_of(&space, target_vid);
    let vid = commit_version(
        repo, &mut ws, TribleSet::new(), fragment_id, &target_title, target_ch,
        &target_tags, &space, "wiki revert", true,
    )?;

    println!("reverted {} ({}) to v{to}: {}", fragment_id, vid, target_title);
    Ok(())
}

fn cmd_links(repo: &mut Repo, bid: Id, id: String) -> Result<()> {
    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let resolved = resolve_prefix(&space, &id)?;
    let title = if is_version(&space, resolved) {
        read_title(&space, &mut ws, resolved).unwrap_or_else(|| "?".into())
    } else {
        latest_version_of(&space, resolved)
            .and_then(|vid| read_title(&space, &mut ws, vid))
            .unwrap_or_else(|| "?".into())
    };
    let (outgoing, incoming, external) = find_links(&space, &mut ws, resolved)?;

    println!("# Links for: {} ({})", title, resolved);

    if !outgoing.is_empty() {
        println!("\n→ outgoing:");
        for target in &outgoing {
            println!("  → {}", link_label(&space, &mut ws, *target));
        }
    }
    if !incoming.is_empty() {
        println!("\n← incoming:");
        for source in &incoming {
            println!("  ← {}", link_label(&space, &mut ws, *source));
        }
    }
    if !external.is_empty() {
        println!("\n⇢ external:");
        for (faculty, hex) in &external {
            println!("  ⇢ {faculty}:{hex}");
        }
    }
    if outgoing.is_empty() && incoming.is_empty() && external.is_empty() {
        println!("\n(no links)");
    }

    Ok(())
}

fn cmd_list(
    repo: &mut Repo,
    bid: Id,
    filter_tags: Vec<String>,
    with_backlink_tag: Vec<String>,
    without_backlink_tag: Vec<String>,
    with_backlink_type: Vec<String>,
    without_backlink_type: Vec<String>,
    show_all: bool,
) -> Result<()> {
    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    // A tag name that doesn't resolve to a tag entity matches zero fragments.
    // Silently dropping it (filter_map) would degrade the filter to "no
    // filter" and list everything — so unknown positive filters short-circuit
    // to an empty listing instead.
    let mut filter_ids: Vec<Id> = Vec::new();
    for name in &filter_tags {
        let name = name.trim().to_lowercase();
        match find_tag_by_name(&space, &mut ws, &name) {
            Some(id) => filter_ids.push(id),
            None => return Ok(()),
        }
    }

    let mut with_bl_ids: Vec<Id> = Vec::new();
    for name in &with_backlink_tag {
        match find_tag_by_name(&space, &mut ws, &name.trim().to_lowercase()) {
            Some(id) => with_bl_ids.push(id),
            None => return Ok(()),
        }
    }
    // Unknown tags in the *negative* filter exclude nothing, so dropping
    // them is the correct semantics here.
    let without_bl_ids: Vec<Id> = without_backlink_tag
        .iter()
        .filter_map(|name| find_tag_by_name(&space, &mut ws, &name.trim().to_lowercase()))
        .collect();
    // Derive attribute IDs for typed backlink filters.
    // Helper closure: derive a GenId-valued attribute from its name via
    // the entity-core mechanism. The hex id is hashed from the
    // `(metadata::name, metadata::value_encoding)` pair so the same name
    // + schema produces the same attribute id deterministically.
    let attr_from_name = |name: &str| -> triblespace::core::attribute::Attribute<inlineencodings::GenId> {
        let name_handle = name.to_owned().to_blob().get_handle();
        triblespace::core::attribute::Attribute::<inlineencodings::GenId>::from(entity! {
            metadata::name: name_handle,
            metadata::value_encoding: <inlineencodings::GenId as triblespace::core::metadata::MetaDescribe>::id(),
        })
    };
    let with_bl_type_attrs: Vec<(String, triblespace::core::attribute::Attribute<inlineencodings::GenId>)> =
        with_backlink_type.iter()
            .map(|name| (name.clone(), attr_from_name(name)))
            .collect();
    let without_bl_type_attrs: Vec<(String, triblespace::core::attribute::Attribute<inlineencodings::GenId>)> =
        without_backlink_type.iter()
            .map(|name| (name.clone(), attr_from_name(name)))
            .collect();
    let has_backlink_filter = !with_bl_ids.is_empty() || !without_bl_ids.is_empty()
        || !with_bl_type_attrs.is_empty() || !without_bl_type_attrs.is_empty();

    let latest = latest_versions(&space);

    let mut entries: Vec<(Id, Id, Lower)> = latest.into_iter()
        .map(|(frag, (vid, ts))| (frag, vid, ts))
        .collect();
    entries.sort_by(|a, b| b.2.cmp(&a.2));

    // Set of latest version IDs for backlink filtering.
    let latest_vids: std::collections::HashSet<Id> =
        entries.iter().map(|(_, vid, _)| *vid).collect();

    for (frag_id, vid, created_at) in &entries {
        let tags = tags_of(&space, *vid);
        if !show_all && tags.contains(&TAG_ARCHIVED_ID) {
            continue;
        }
        if !filter_ids.is_empty() && !filter_ids.iter().all(|ft| tags.contains(ft)) {
            continue;
        }

        // Backlink tag filter: check tags of latest versions that link TO any
        // version of this fragment (or the fragment ID itself).
        if has_backlink_filter {
            // Targets = {frag_id} ∪ {every version of frag_id}. A single
            // pattern with `SortedSlice::has(target)` constrains the target
            // slot to any of these — one constraint, one pattern, no union.
            let mut targets: Vec<Id> = version_history_of(&space, *frag_id);
            targets.push(*frag_id);
            targets.sort();
            targets.dedup();
            let targets_slice = triblespace::core::query::sortedsliceconstraint::SortedSlice::new_unchecked(&targets);

            let all_backlinks: Vec<Id> = find!(
                src: Id,
                temp!((target),
                    and!(
                        pattern!(&space, [{ ?src @ wiki::links_to: ?target }]),
                        targets_slice.has(target),
                    )
                )
            ).collect();

            let mut backlink_tags: Vec<Id> = Vec::new();
            for &source_vid in &all_backlinks {
                if latest_vids.contains(&source_vid) {
                    backlink_tags.extend(tags_of(&space, source_vid));
                }
            }

            if !with_bl_ids.is_empty()
                && !with_bl_ids.iter().all(|t| backlink_tags.contains(t))
            {
                continue;
            }
            if !without_bl_ids.is_empty()
                && without_bl_ids.iter().any(|t| backlink_tags.contains(t))
            {
                continue;
            }

            // Typed backlink filter: does any latest-version entity have a
            // derived-attribute edge of the given type pointing to *any* version
            // of this fragment (or to the fragment id itself)? Same single-pattern
            // trick — target constrained to the sorted target slice.
            let check_type_target = |attr: &triblespace::core::attribute::Attribute<inlineencodings::GenId>| -> bool {
                find!(
                    src: Id,
                    temp!((target),
                        and!(
                            pattern!(&space, [{ ?src @ attr: ?target }]),
                            targets_slice.has(target),
                        )
                    )
                ).any(|src| latest_vids.contains(&src))
            };
            if !with_bl_type_attrs.is_empty() {
                let all_present = with_bl_type_attrs.iter()
                    .all(|(_, attr)| check_type_target(attr));
                if !all_present { continue; }
            }
            if !without_bl_type_attrs.is_empty() {
                let any_present = without_bl_type_attrs.iter()
                    .any(|(_, attr)| check_type_target(attr));
                if any_present { continue; }
            }
        }

        let title = read_title(&space, &mut ws, *vid).unwrap_or_default();
        let tag_str = format_tags(&space, &mut ws, &tags);
        let n_versions = version_history_of(&space, *frag_id).len();
        let ver_str = if n_versions > 1 {
            format!(" (v{})", n_versions)
        } else {
            String::new()
        };

        println!(
            "{}  {}  {}{}{}",
            format!("{:x}", frag_id), format_date(*created_at), title, tag_str, ver_str,
        );

        if let Some(ch) = content_handle_of(&space, *vid) {
            if let Ok(view) = ws.get(ch) {
                let view: View<str> = view;
                if let Some(line) = view.as_ref().lines().find(|l| !l.trim().is_empty()) {
                    let preview = line.trim();
                    let truncated: String = preview.chars().take(77).collect();
                    if truncated.len() < preview.len() {
                        println!("    {truncated}...");
                    } else {
                        println!("    {preview}");
                    }
                }
            }
        }
    }
    Ok(())
}

fn cmd_history(repo: &mut Repo, bid: Id, id: String) -> Result<()> {
    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let resolved = resolve_prefix(&space, &id)?;
    let fragment_id = to_fragment(&space, resolved)?;
    let history = version_history_of(&space, fragment_id);

    let latest_title = history.last()
        .and_then(|vid| read_title(&space, &mut ws, *vid))
        .unwrap_or_else(|| "?".into());
    println!("# History: {} ({})", latest_title, fragment_id);
    println!();

    for (i, vid) in history.iter().enumerate() {
        let title = read_title(&space, &mut ws, *vid).unwrap_or_default();
        let ts = created_at_of(&space, *vid).unwrap_or(Lower(0));
        let tags = tags_of(&space, *vid);
        println!(
            "  v{}  {}  {}  {}{}",
            i + 1, vid, format_date(ts), title, format_tags(&space, &mut ws, &tags),
        );
    }
    Ok(())
}

fn cmd_tag_add(repo: &mut Repo, bid: Id, id: String, name: String) -> Result<()> {
    let name = name.trim().to_lowercase();
    if name.is_empty() {
        bail!("tag name cannot be empty");
    }
    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let resolved = resolve_prefix(&space, &id)?;
    let fragment_id = to_fragment(&space, resolved)?;
    let prev_vid = latest_version_of(&space, fragment_id)
        .ok_or_else(|| anyhow::anyhow!("no versions for fragment {}", fragment_id))?;

    ensure_tag_vocabulary(repo, &mut ws)?;
    let mut change = TribleSet::new();
    let new_tag = resolve_tags(&space, &mut ws, &[name.clone()], &mut change)[0];

    let prev_tags = tags_of(&space, prev_vid);
    if prev_tags.contains(&new_tag) {
        println!("already tagged: #{name}");
        return Ok(());
    }

    let mut tags = prev_tags;
    tags.push(new_tag);
    let prev_title = read_title(&space, &mut ws, prev_vid).unwrap_or_default();
    let prev_ch = content_handle_of(&space, prev_vid)
        .ok_or_else(|| anyhow::anyhow!("no content"))?;
    commit_version(
        repo, &mut ws, change, fragment_id, &prev_title, prev_ch, &tags,
        &space, "wiki tag add", true,
    )?;

    println!("added #{name} to {} ({})", prev_title, fragment_id);
    Ok(())
}

fn cmd_tag_remove(repo: &mut Repo, bid: Id, id: String, name: String) -> Result<()> {
    let name = name.trim().to_lowercase();
    if name.is_empty() {
        bail!("tag name cannot be empty");
    }
    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let resolved = resolve_prefix(&space, &id)?;
    let fragment_id = to_fragment(&space, resolved)?;
    let prev_vid = latest_version_of(&space, fragment_id)
        .ok_or_else(|| anyhow::anyhow!("no versions for fragment {}", fragment_id))?;

    let tag_id = find_tag_by_name(&space, &mut ws, &name)
        .ok_or_else(|| anyhow::anyhow!("unknown tag '{name}'"))?;
    let prev_tags = tags_of(&space, prev_vid);
    if !prev_tags.contains(&tag_id) {
        println!("not tagged: #{name}");
        return Ok(());
    }

    let tags: Vec<Id> = prev_tags.into_iter().filter(|t| *t != tag_id).collect();
    let prev_title = read_title(&space, &mut ws, prev_vid).unwrap_or_default();
    let prev_ch = content_handle_of(&space, prev_vid)
        .ok_or_else(|| anyhow::anyhow!("no content"))?;
    commit_version(
        repo, &mut ws, TribleSet::new(), fragment_id, &prev_title, prev_ch, &tags,
        &space, "wiki tag remove", true,
    )?;

    println!("removed #{name} from {} ({})", prev_title, fragment_id);
    Ok(())
}

fn cmd_tag_list(repo: &mut Repo, bid: Id) -> Result<()> {
    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let mut counts: HashMap<Id, usize> = HashMap::new();
    for (tag_id,) in find!(
        (tag_id: Id),
        pattern!(&space, [{ _?vid @ metadata::tag: &KIND_VERSION_ID, metadata::tag: ?tag_id }])
    ) {
        if tag_id != KIND_VERSION_ID {
            *counts.entry(tag_id).or_default() += 1;
        }
    }

    // Build name→id map from all named entities.
    let mut all_named: Vec<(String, Id, usize)> = Vec::new();
    for (id, handle) in find!(
        (id: Id, h: TextHandle),
        pattern!(&space, [{ ?id @ metadata::name: ?h }])
    ) {
        if let Ok(view) = ws.get::<View<str>, _>(handle) {
            let name = view.as_ref().to_string();
            let count = counts.get(&id).copied().unwrap_or(0);
            all_named.push((name, id, count));
        }
    }
    let mut entries = all_named;
    entries.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));

    for (name, id, count) in entries {
        println!("{}  {}  ({})", id, name, count);
    }
    Ok(())
}

fn cmd_tag_mint(repo: &mut Repo, bid: Id, name: String) -> Result<()> {
    let name = name.trim().to_lowercase();
    if name.is_empty() {
        bail!("tag name cannot be empty");
    }

    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    if let Some(existing) = find_tag_by_name(&space, &mut ws, &name) {
        println!("tag '{}' already exists: {}", name, existing);
        return Ok(());
    }

    let tag_id = genid();
    let tag_ref = tag_id.id;
    let name_handle = ws.put(name.clone());
    let mut change = TribleSet::new();
    change += entity! { &tag_id @ metadata::name: name_handle };

    ws.commit(change, "wiki mint tag");
    repo.push(&mut ws)
        .map_err(|e| anyhow::anyhow!("push: {e:?}"))?;

    println!("{}  {}", tag_ref, name);
    Ok(())
}

fn cmd_import(repo: &mut Repo, bid: Id, path: PathBuf, tags: Vec<String>) -> Result<()> {
    let files = if path.is_dir() {
        let mut entries: Vec<PathBuf> = Vec::new();
        collect_typ_files(&path, &mut entries)?;
        entries.sort();
        entries
    } else {
        vec![path]
    };

    if files.is_empty() {
        println!("no .typ files found");
        return Ok(());
    }

    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    ensure_tag_vocabulary(repo, &mut ws)?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    for file in &files {
        let content = fs::read_to_string(file)
            .with_context(|| format!("read {}", file.display()))?;

        let title = content
            .lines()
            .find(|l| l.starts_with("= "))
            .map(|l| l.trim_start_matches('=').trim().to_string())
            .unwrap_or_else(|| {
                file.file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string()
            });

        let mut change = TribleSet::new();
        let tag_ids = resolve_tags(&space, &mut ws, &tags, &mut change);
        let fragment_id = genid().id;
        let content_handle = ws.put(content);
        let vid = commit_version(
            repo, &mut ws, change, fragment_id, &title, content_handle, &tag_ids, &space, "wiki import", true,
        )?;

        println!("{}  {}  {}", fragment_id, vid, file.display());
    }

    Ok(())
}

fn collect_typ_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("read dir {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_typ_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "typ") {
            out.push(path);
        }
    }
    Ok(())
}

// ── semantic embedding seam (nomic + shared HNSW, behind `local-embed`) ─────
// The wiki end of one cross-faculty semantic search: fragment prose is embedded
// into the SAME shared nomic-768 space as memory chunks and file images, so a
// query here is directly comparable to a memory or an image elsewhere. `wiki
// embed` is the build step (embed each current fragment's content once, store
// the vector as exhaust on its latest version), `wiki similar` the query.
// Complements `wiki search` (lexical substring) by matching MEANING.

#[cfg(feature = "local-embed")]
const NOMIC_TEXT_MODEL: &str = "nomic-ai/nomic-embed-text-v1.5";

/// L2-normalize so dot-product == cosine downstream (the shared `nearest` core
/// assumes unit vectors).
#[cfg(feature = "local-embed")]
fn l2_normalize(mut v: Vec<f32>) -> Vec<f32> {
    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if n > 0.0 {
        for x in &mut v {
            *x /= n;
        }
    }
    v
}

/// The stored shared-space embedding handle for a version, if embedded.
#[cfg(feature = "local-embed")]
fn version_embedding_handle(
    space: &TribleSet,
    vid: Id,
) -> Option<Inline<inlineencodings::Handle<Embedding768>>> {
    find!(
        h: Inline<inlineencodings::Handle<Embedding768>>,
        pattern!(space, [{ vid @ embeddings::attr::embedding: ?h }])
    )
    .next()
}

/// `wiki embed` — embed every current (non-archived) fragment that lacks a
/// vector, storing it as exhaust on the latest version. Idempotent; re-running
/// after `wiki edit` re-embeds only the new versions.
#[cfg(feature = "local-embed")]
fn cmd_embed(repo: &mut Repo, bid: Id) -> Result<()> {
    eprintln!("wiki: loading nomic-embed-text (once)…");
    let emb = mary::embed::load_nomic_text_from_hf(NOMIC_TEXT_MODEL, mary::embed::default_device())
        .map_err(|e| anyhow::anyhow!("load nomic embedder: {e:?}"))?;

    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let latest = latest_versions(&space);

    let mut todo: Vec<(Id, TextHandle)> = Vec::new();
    for (_frag, &(vid, _)) in &latest {
        if tags_of(&space, vid).contains(&TAG_ARCHIVED_ID) {
            continue;
        }
        if version_embedding_handle(&space, vid).is_some() {
            continue;
        }
        if let Some(ch) = content_handle_of(&space, vid) {
            todo.push((vid, ch));
        }
    }
    if todo.is_empty() {
        println!("all current fragments already embedded.");
        return Ok(());
    }
    let total = todo.len();
    let mut change = TribleSet::new();
    for (i, (vid, ch)) in todo.into_iter().enumerate() {
        let content: View<str> = ws.get(ch).map_err(|e| anyhow::anyhow!("read content: {e:?}"))?;
        let v = l2_normalize(
            emb.embed_document(content.as_ref())
                .map_err(|e| anyhow::anyhow!("embed {vid:x}: {e:?}"))?,
        );
        let handle = ws.put::<Embedding768, _>(v);
        change += entity! { ExclusiveId::force_ref(&vid) @ embeddings::attr::embedding: handle };
        if (i + 1) % 25 == 0 || i + 1 == total {
            eprintln!("  embedded {}/{total}", i + 1);
        }
    }
    ws.commit(change, "wiki embed");
    repo.push(&mut ws).map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
    println!("embedded {total} fragments into the shared nomic space.");
    Ok(())
}

#[cfg(not(feature = "local-embed"))]
fn cmd_embed(_repo: &mut Repo, _bid: Id) -> Result<()> {
    bail!("`wiki embed` needs the local embedder — rebuild with `--features local-embed`");
}

/// `wiki similar <query>` — nearest fragments to a free-text query by meaning.
#[cfg(feature = "local-embed")]
fn cmd_similar(repo: &mut Repo, bid: Id, query: String) -> Result<()> {
    eprintln!("wiki: loading nomic-embed-text (once)…");
    let emb = mary::embed::load_nomic_text_from_hf(NOMIC_TEXT_MODEL, mary::embed::default_device())
        .map_err(|e| anyhow::anyhow!("load nomic embedder: {e:?}"))?;
    let qv = l2_normalize(
        emb.embed_query(&query)
            .map_err(|e| anyhow::anyhow!("embed query: {e:?}"))?,
    );

    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let latest = latest_versions(&space);

    let mut pairs: Vec<(Id, Vec<f32>)> = Vec::new();
    let mut vid_to_frag: HashMap<Id, Id> = HashMap::new();
    let mut current = 0usize;
    for (&frag, &(vid, _)) in &latest {
        if tags_of(&space, vid).contains(&TAG_ARCHIVED_ID) {
            continue;
        }
        current += 1;
        if let Some(h) = version_embedding_handle(&space, vid) {
            let v: View<[f32]> = ws.get(h).map_err(|e| anyhow::anyhow!("read embedding: {e:?}"))?;
            pairs.push((vid, v.as_ref().to_vec()));
            vid_to_frag.insert(vid, frag);
        }
    }
    if pairs.is_empty() {
        bail!("no fragment embeddings on this pile yet — run `wiki embed` first");
    }
    if pairs.len() < current {
        eprintln!(
            "note: {} current fragment(s) not yet embedded — run `wiki embed` to refresh",
            current - pairs.len()
        );
    }

    let ranked = embeddings::nearest(&pairs, &qv, 0.0).map_err(|e| anyhow::anyhow!("nearest: {e:?}"))?;
    if ranked.is_empty() {
        println!("no matches.");
        return Ok(());
    }
    for (cos, vid) in ranked.into_iter().take(10) {
        let frag = vid_to_frag.get(&vid).copied().unwrap_or(vid);
        let title = read_title(&space, &mut ws, vid).unwrap_or_default();
        println!("{cos:6.3}  {}  {title}", format!("{:x}", frag));
    }
    Ok(())
}

#[cfg(not(feature = "local-embed"))]
fn cmd_similar(_repo: &mut Repo, _bid: Id, _query: String) -> Result<()> {
    bail!("`wiki similar` needs the local embedder — rebuild with `--features local-embed`");
}

fn cmd_search(
    repo: &mut Repo,
    bid: Id,
    query: String,
    show_context: bool,
    show_all: bool,
) -> Result<()> {
    let query_lower = query.to_lowercase();

    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let latest = latest_versions(&space);

    let mut hits: Vec<(Id, Id, Lower, String, Vec<Id>, Vec<String>)> = Vec::new();

    for (&frag_id, &(vid, created_at)) in &latest {
        let tags = tags_of(&space, vid);
        if !show_all && tags.contains(&TAG_ARCHIVED_ID) {
            continue;
        }
        let title = read_title(&space, &mut ws, vid).unwrap_or_default();
        let ch = match content_handle_of(&space, vid) {
            Some(ch) => ch,
            None => continue,
        };
        let content: View<str> = ws.get(ch)
            .map_err(|e| anyhow::anyhow!("read content: {e:?}"))?;
        let content_str = content.as_ref();

        let title_match = title.to_lowercase().contains(&query_lower);
        let content_lower = content_str.to_lowercase();
        let content_match = content_lower.contains(&query_lower);

        if title_match || content_match {
            let mut context_lines = Vec::new();
            if show_context && content_match {
                for line in content_str.lines() {
                    if line.to_lowercase().contains(&query_lower) {
                        context_lines.push(line.to_string());
                    }
                }
            }
            hits.push((frag_id, vid, created_at, title, tags, context_lines));
        }
    }

    hits.sort_by(|a, b| b.2.cmp(&a.2));

    if hits.is_empty() {
        println!("no matches for '{query}'");
        return Ok(());
    }

    for (frag_id, _vid, created_at, title, tags, context_lines) in &hits {
        println!(
            "{}  {}  {}{}",
            format!("{:x}", frag_id), format_date(*created_at), title, format_tags(&space, &mut ws, tags),
        );
        for line in context_lines {
            println!("    {}", line.trim());
        }
    }

    Ok(())
}

// ── diff engine ────────────────────────────────────────────────────────────

enum DiffOp<'a> {
    Equal(&'a str),
    Add(&'a str),
    Remove(&'a str),
}

/// Produce unified-style diff lines with `context` lines of surrounding context.
fn unified_diff<'a>(old: &[&'a str], new: &[&'a str], context: usize) -> Vec<String> {
    let table = lcs_table(old, new);

    // Walk LCS table backwards to produce diff ops.
    let mut ops: Vec<DiffOp<'a>> = Vec::new();
    let (mut i, mut j) = (old.len(), new.len());
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && old[i - 1] == new[j - 1] {
            ops.push(DiffOp::Equal(old[i - 1]));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || table[i][j - 1] >= table[i - 1][j]) {
            ops.push(DiffOp::Add(new[j - 1]));
            j -= 1;
        } else {
            ops.push(DiffOp::Remove(old[i - 1]));
            i -= 1;
        }
    }
    ops.reverse();

    // Mark which ops are near a change and should be shown.
    let change_indices: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, op)| !std::matches!(op, DiffOp::Equal(_)))
        .map(|(i, _)| i)
        .collect();

    if change_indices.is_empty() {
        return Vec::new();
    }

    let mut shown = vec![false; ops.len()];
    for &ci in &change_indices {
        let start = ci.saturating_sub(context);
        let end = (ci + context + 1).min(ops.len());
        for idx in start..end {
            shown[idx] = true;
        }
    }

    let mut lines = Vec::new();
    let mut in_hunk = false;
    for (idx, op) in ops.iter().enumerate() {
        if shown[idx] {
            if !in_hunk && idx > 0 {
                lines.push("---".to_string());
            }
            in_hunk = true;
            match op {
                DiffOp::Equal(line) => lines.push(format!(" {line}")),
                DiffOp::Add(line) => lines.push(format!("+{line}")),
                DiffOp::Remove(line) => lines.push(format!("-{line}")),
            }
        } else {
            in_hunk = false;
        }
    }

    lines
}

fn lcs_table(old: &[&str], new: &[&str]) -> Vec<Vec<usize>> {
    let (m, n) = (old.len(), new.len());
    let mut table = vec![vec![0usize; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            table[i][j] = if old[i - 1] == new[j - 1] {
                table[i - 1][j - 1] + 1
            } else {
                table[i - 1][j].max(table[i][j - 1])
            };
        }
    }
    table
}

// ── main ───────────────────────────────────────────────────────────────────
fn main() -> Result<()> {
    let cli = Cli::parse();

    let Some(command) = cli.command else {
        let mut cmd = Cli::command();
        cmd.print_help()?;
        println!();
        return Ok(());
    };

    let pile = Pile::open(&cli.pile)
        .map_err(|e| anyhow::anyhow!("open pile: {e:?}"))?;
    let signing_key = SigningKey::generate(&mut OsRng);
    let mut repo = Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|e| anyhow::anyhow!("create repo: {e:?}"))?;

    let branch_id = if let Some(hex) = cli.branch_id.as_deref() {
        Id::from_hex(hex.trim()).ok_or_else(|| anyhow::anyhow!("invalid branch id"))?
    } else {
        repo.ensure_branch(WIKI_BRANCH_NAME, None)
            .map_err(|e| anyhow::anyhow!("ensure wiki branch: {e:?}"))?
    };

    let result = match command {
        Command::Create { title, content, tag, force, id } => {
            cmd_create(&mut repo, branch_id, title, content, tag, force, id)
        }
        Command::Edit {
            id,
            content,
            title,
            tag,
            force,
        } => cmd_edit(&mut repo, branch_id, id, content, title, tag, force),
        Command::Show { id, latest } => cmd_show(&mut repo, branch_id, id, latest),
        Command::Export { id } => cmd_export(&mut repo, branch_id, id),
        Command::Diff { id, from, to } => cmd_diff(&mut repo, branch_id, id, from, to),
        Command::Archive { id } => cmd_archive(&mut repo, branch_id, id),
        Command::Restore { id } => cmd_restore(&mut repo, branch_id, id),
        Command::Revert { id, to } => cmd_revert(&mut repo, branch_id, id, to),
        Command::Links { id } => cmd_links(&mut repo, branch_id, id),
        Command::List { tag, with_backlink_tag, without_backlink_tag, with_backlink_type, without_backlink_type, all } =>
            cmd_list(&mut repo, branch_id, tag, with_backlink_tag, without_backlink_tag, with_backlink_type, without_backlink_type, all),
        Command::History { id } => cmd_history(&mut repo, branch_id, id),
        Command::Tag { command: tag_cmd } => match tag_cmd {
            TagCommand::Add { id, name } => cmd_tag_add(&mut repo, branch_id, id, name),
            TagCommand::Remove { id, name } => cmd_tag_remove(&mut repo, branch_id, id, name),
            TagCommand::List => cmd_tag_list(&mut repo, branch_id),
            TagCommand::Mint { name } => cmd_tag_mint(&mut repo, branch_id, name),
        },
        Command::Import { path, tag } => cmd_import(&mut repo, branch_id, path, tag),
        Command::Search { query, context, all } => {
            cmd_search(&mut repo, branch_id, query, context, all)
        }
        Command::Embed => cmd_embed(&mut repo, branch_id),
        Command::Similar { query } => cmd_similar(&mut repo, branch_id, query),
        Command::Check { compile } => cmd_check(&mut repo, branch_id, compile),
        Command::Batch { action } => match action {
            BatchAction::Export { dir } => cmd_export_all(&mut repo, branch_id, dir),
            BatchAction::Import { dir } => cmd_import_all(&mut repo, branch_id, dir),
        },
        Command::FixTruncated { input } => cmd_fix_truncated(&mut repo, branch_id, input),
        Command::Lint { fix, check } => cmd_lint(&mut repo, branch_id, fix, check),
    };

    repo.close().map_err(|e| anyhow::anyhow!("close: {e:?}"))?;
    result
}
