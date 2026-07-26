//! Claude Code (`.claude` JSONL) importer — block-DAG projection.
//!
//! Each JSONL record becomes one **block** in the perception/action DAG
//! ([`faculties::schemas::blockdag`]); each content block inside a record's
//! `message.content` becomes a **content-fact** owned by that block via
//! [`block::contains`]. `parentUuid` resolves to [`block::previous`]; the
//! record `type` (`user`/`assistant`) plus the content block type set each
//! content-fact's [`content_fact::direction`] (the training loss mask).
//!
//! The projection is a *streaming projection*: it scans only the fields it
//! needs out of each JSONL line with [`triblespace::core::import::scanner`]
//! and never materializes a `serde_json::Value` tree. This replaces the old
//! `serde_json::Value` + `MessageRecord` + `JsonTreeImporter` path (which
//! allocated several times the source size per record — a cold `~/.claude`
//! import reached 57.9 GB resident, 2026-07-26).
//!
//! Phase 1 (this file) delivers the core block/content-fact projection with a
//! strict two-pass `entity!` discipline. Deferred pieces are marked
//! `// TODO(phase2):` — image/media content-facts, the tool-correlator →
//! `responds_to` edge, and `author`/`experiencer` roster entity links (phase 1
//! keeps only the raw [`import_schema::source_author`] label).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::common;
use anyhow::{anyhow, Context, Result};
use hifitime::Epoch;
use tracing::info_span;
use triblespace::core::blob::Bytes;
use triblespace::core::import::scanner as sc;
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::*;

#[derive(Debug, Default, Clone)]
struct ImportStats {
    files: usize,
    blocks: usize,
    content_facts: usize,
    commits: usize,
}

fn import_claude_code_path(
    path: &Path,
    repo: &mut common::Repo,
    branch_id: Id,
) -> Result<ImportStats> {
    let start = Instant::now();
    println!("claude-code phase pull: {}", path.display());
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
    let mut catalog = ws.checkout(..).context("checkout workspace")?.into_facts();
    let mut catalog_head = ws.head();
    println!("claude-code phase pull: done in {:?}", start.elapsed());

    if path.is_dir() {
        let scan_start = Instant::now();
        println!("claude-code phase scan: {}", path.display());
        let mut paths = Vec::new();
        collect_jsonl_files(path, &mut paths)
            .with_context(|| format!("scan {}", path.display()))?;
        paths.sort();
        println!(
            "claude-code phase scan: found {} jsonl file(s) under {} in {:?}",
            paths.len(),
            path.display(),
            scan_start.elapsed()
        );
        let mut total = ImportStats::default();
        let total_files = paths.len();
        // Bounded in-flight parses. `parse_paths_streaming` runs the whole
        // per-file projection (scan + `entity!`) on the parser threads and
        // hands each finished `Fragment` to the sequential committer as it
        // arrives, never holding more than PARSE_IN_FLIGHT projected files at
        // once. Kept small deliberately — a single transcript can be 2 GB.
        const PARSE_IN_FLIGHT: usize = 4;
        common::parse_paths_streaming(
            "claude-code",
            &paths,
            PARSE_IN_FLIGHT,
            parse_jsonl,
            |index, file, parsed_fragment| {
                let processed = index + 1;
                let file_start = Instant::now();
                println!(
                    "claude-code file {processed}/{total_files}: {}",
                    file.display()
                );
                let fragment =
                    parsed_fragment.with_context(|| format!("parse {}", file.display()))?;
                if fragment.facts().is_empty() {
                    return Ok(());
                }
                let stats = import_claude_code_records(
                    &file,
                    fragment,
                    repo,
                    &mut ws,
                    &mut catalog,
                    &mut catalog_head,
                )
                .with_context(|| format!("import {}", file.display()))?;
                total.files += stats.files;
                total.blocks += stats.blocks;
                total.content_facts += stats.content_facts;
                total.commits += stats.commits;
                println!(
                    "claude-code progress files {}/{} (blocks {}, content-facts {}, commits {}) in {:?}",
                    processed, total_files, total.blocks, total.content_facts, total.commits,
                    file_start.elapsed()
                );
                Ok(())
            },
        )?;
        return Ok(total);
    }

    let parse_start = Instant::now();
    println!("claude-code phase parse: {}", path.display());
    let fragment = parse_jsonl(path)?;
    println!(
        "claude-code phase parse: projected {} trible(s) in {:?}",
        fragment.facts().len(),
        parse_start.elapsed()
    );
    import_claude_code_records(
        path,
        fragment,
        repo,
        &mut ws,
        &mut catalog,
        &mut catalog_head,
    )
}

/// Stage a projected file's blobs into the workspace and commit its facts.
///
/// The heavy work (scan + content-addressed `entity!` projection) already
/// happened in [`parse_jsonl`] on a parser thread; this sequential step owns
/// `&mut Workspace`, so it only merges the fragment's self-contained blob
/// store into the staging area and commits the delta.
fn import_claude_code_records(
    _path: &Path,
    fragment: Fragment,
    repo: &mut common::Repo,
    ws: &mut common::Ws,
    catalog: &mut TribleSet,
    catalog_head: &mut Option<common::CommitHandle>,
) -> Result<ImportStats> {
    let mut stats = ImportStats {
        files: 1,
        ..ImportStats::default()
    };

    {
        let facts = fragment.facts();
        stats.blocks = find!(
            (block: Id),
            pattern!(facts, [{ ?block @ common::metadata::tag: common::block::KIND }])
        )
        .count();
        stats.content_facts = find!(
            (cf: Id),
            pattern!(facts, [{ ?cf @ common::metadata::tag: common::content_fact::KIND }])
        )
        .count();
    }

    // The projection put every referenced payload/label/signature blob into
    // the fragment's own MemoryBlobStore; merge them into the workspace's
    // staging area so the commit ships them alongside the facts.
    let (facts, blobs) = fragment.into_facts_and_blobs();
    ws.staged.union(blobs);

    if common::commit_delta(
        repo,
        ws,
        catalog,
        catalog_head,
        facts,
        "import claude-code block-dag",
    )? {
        stats.commits += 1;
    }

    Ok(stats)
}

// ---------------------------------------------------------------------------
// Parsing + projection
// ---------------------------------------------------------------------------

/// Read a `.claude` JSONL file and project it onto the block-DAG schema,
/// returning a self-contained [`Fragment`] (facts + the blobs they reference).
///
/// Runs on the parser threads of [`common::parse_paths_streaming`]. The
/// projection is content-addressed and side-effect-free — no workspace, no
/// pile — so it is safe to run off the committing thread.
fn parse_jsonl(path: &Path) -> Result<Fragment> {
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let bytes = Bytes::from_source(data);
    project_jsonl(&bytes).with_context(|| format!("project {}", path.display()))
}

/// Core projection: fold each JSONL line into the accumulating fragment.
///
/// Streams line-by-line — at most one [`RawRecord`] is alive at a time — so
/// peak memory is the raw file plus the growing fragment, never a per-record
/// dynamic JSON tree.
fn project_jsonl(bytes: &Bytes) -> Result<Fragment> {
    let mut frag = Fragment::empty();
    // uuid → block id, so a record's `parentUuid` resolves to `block::previous`.
    let mut uuid_to_block: HashMap<String, Id> = HashMap::new();
    // vendor tool correlator (`toolu_…`) → tool_call content-fact id. Built now,
    // consumed by the phase-2 `responds_to` edge resolution.
    let mut correlator_to_cf: HashMap<String, Id> = HashMap::new();

    let raw = bytes.as_ref();
    let len = raw.len();
    let mut start = 0usize;
    for i in 0..=len {
        let is_boundary = i == len || raw[i] == b'\n';
        if !is_boundary {
            continue;
        }
        if i > start {
            // Trim ASCII whitespace (including a trailing `\r`) so the scanner
            // sees the record's opening `{` as the first byte.
            let seg = &raw[start..i];
            let first = seg.iter().position(|c| !c.is_ascii_whitespace());
            let last = seg.iter().rposition(|c| !c.is_ascii_whitespace());
            if let (Some(a), Some(z)) = (first, last) {
                let mut line = bytes.slice((start + a)..(start + z + 1));
                let record = scan_record(&mut line)
                    .map_err(|e| anyhow!("scan claude-code jsonl record: {e}"))?;
                project_record(&record, &mut frag, &mut uuid_to_block, &mut correlator_to_cf);
            }
        }
        start = i + 1;
    }

    Ok(frag)
}

/// Project one scanned record into the fragment (identity-core pass, then the
/// non-identity pass) for both its content-facts and the block itself.
fn project_record(
    record: &RawRecord,
    frag: &mut Fragment,
    uuid_to_block: &mut HashMap<String, Id>,
    correlator_to_cf: &mut HashMap<String, Id>,
) {
    // Only user/assistant records are blocks. `user` is perceived (`in`),
    // `assistant` is produced (`out`); other line types (system, progress,
    // file-history-snapshot, …) are skipped — they carry no dialogue.
    let record_direction = match record.record_type.as_str() {
        "user" => common::content_fact::direction::in_,
        "assistant" => common::content_fact::direction::out_,
        _ => return,
    };

    let mut contained: Vec<Id> = Vec::new();
    for block in &record.blocks {
        let (modality, direction) = match block.kind {
            BlockKind::Text => (common::content_fact::modality::text, record_direction),
            BlockKind::Thinking => (
                common::content_fact::modality::thinking,
                common::content_fact::direction::out_,
            ),
            BlockKind::ToolUse => (
                common::content_fact::modality::tool_call,
                common::content_fact::direction::out_,
            ),
            BlockKind::ToolResult => (
                common::content_fact::modality::tool_result,
                common::content_fact::direction::in_,
            ),
            // TODO(phase2): image/media content-facts. An `image` block becomes
            // a content-fact keyed by `content_fact::blob` (inline base64 bytes)
            // or `content_fact::asset_pointer` + `asset_mime`/`asset_size` (a
            // `file_<id>.dat` reference), with `resolved_to` attaching bytes
            // that arrive later. Skipped for now.
            BlockKind::Image => continue,
            BlockKind::Other => continue,
        };
        if block.payload.trim().is_empty() {
            continue;
        }

        // Pass 1 — identity core (`_` mints the content-derived id).
        let payload = frag.put::<LongString, _>(block.payload.clone());
        let cf = entity! { _ @
            common::content_fact::modality:  modality,
            common::content_fact::direction: direction,
            common::content_fact::payload:   payload,
        };
        let cf_id = cf
            .root()
            .expect("content_fact entity! must export a single root id");
        *frag += cf;

        // Pass 2 — non-identity facts on the same content-fact id.
        let signature = block
            .signature
            .as_ref()
            .map(|s| frag.put::<LongString, _>(s.clone()));
        let cf_entity = ExclusiveId::force(cf_id);
        *frag += entity! { &cf_entity @
            common::metadata::tag:          common::content_fact::KIND,
            common::content_fact::signature?: signature,
        };
        // TODO(phase2): when this is a `tool_result`, resolve `block.correlator`
        // against `correlator_to_cf` and attach
        // `content_fact::responds_to: <tool_call cf id>` (non-identity edge,
        // distinct from `block::previous`). The correlator string is then
        // dropped — it never enters the content-address.

        if let BlockKind::ToolUse = block.kind {
            if let Some(correlator) = &block.correlator {
                correlator_to_cf.insert(correlator.clone(), cf_id);
            }
        }

        contained.push(cf_id);
    }

    // Block identity core: {previous?, timestamp, contains-<cf ids>}.
    let timestamp =
        common::epoch_interval(record.timestamp.unwrap_or_else(common::unknown_epoch));
    let previous = record
        .parent_uuid
        .as_ref()
        .and_then(|parent| uuid_to_block.get(parent).copied());
    let block = entity! { _ @
        common::block::timestamp: timestamp,
        common::block::previous?: previous,
        common::block::contains*: contained,
    };
    let block_id = block
        .root()
        .expect("block entity! must export a single root id");
    *frag += block;

    // Block non-identity pass: kind tag + raw author label. Roster links are
    // phase 2.
    let author_label = match record.record_type.as_str() {
        "assistant" => record
            .model
            .clone()
            .unwrap_or_else(|| "assistant".to_string()),
        other => other.to_string(),
    };
    let source_author = frag.put::<LongString, _>(author_label);
    let block_entity = ExclusiveId::force(block_id);
    *frag += entity! { &block_entity @
        common::metadata::tag:                  common::block::KIND,
        common::import_schema::source_author:   source_author,
        common::import_schema::source_created_at: timestamp,
        // TODO(phase2): block::author / block::experiencer — link to the
        // `relations` roster once the participant is rosterable (the invariant
        // `direction = out ⟺ author == experiencer` is checked there).
        // TODO(phase2): retain `sessionId` / `parentUuid` as source-id
        // provenance if a raw-record round-trip is wanted.
    };

    if let Some(uuid) = &record.uuid {
        uuid_to_block.insert(uuid.clone(), block_id);
    }
}

// ---------------------------------------------------------------------------
// Streaming scan — project only the fields the block-DAG needs
// ---------------------------------------------------------------------------

#[derive(Default)]
struct RawRecord {
    record_type: String,
    uuid: Option<String>,
    parent_uuid: Option<String>,
    timestamp: Option<Epoch>,
    /// `message.model` (assistant records) — the raw author label.
    model: Option<String>,
    blocks: Vec<RawBlock>,
}

struct RawBlock {
    kind: BlockKind,
    /// Rendered-to-text payload: `text`/`thinking` verbatim, tool_use `input`
    /// as raw JSON, tool_result `content` as its textual content.
    payload: String,
    /// Vendor tool correlator: `id` (`toolu_…`) on tool_use, `tool_use_id` on
    /// tool_result. Used to build the phase-2 `responds_to` edge.
    correlator: Option<String>,
    /// Claude's `thinking.signature` attestation (thinking blocks only).
    signature: Option<String>,
}

enum BlockKind {
    Text,
    Thinking,
    ToolUse,
    ToolResult,
    Image,
    Other,
}

/// Fields of a single `message.content` block, gathered order-independently.
#[derive(Default)]
struct BlockAccum {
    btype: String,
    text: Option<String>,
    thinking: Option<String>,
    signature: Option<String>,
    tool_id: Option<String>,
    tool_use_id: Option<String>,
    input_raw: Option<String>,
    tool_result_content: Option<String>,
}

/// Fields projected out of the nested `message` object.
#[derive(Default)]
struct MessagePart {
    model: Option<String>,
    blocks: Vec<RawBlock>,
}

fn scan_syntax(message: &str) -> sc::ScanError {
    sc::ScanError::Syntax(message.to_owned())
}

/// Decode a scanned JSON string to an owned `String`.
fn bytes_to_string(bytes: Bytes) -> Result<String, sc::ScanError> {
    Ok(bytes
        .view::<str>()
        .map_err(|_| scan_syntax("invalid utf-8 string"))?
        .as_ref()
        .to_owned())
}

/// Parse a string value, or `None` for `null` / any non-string value (which is
/// skipped without materializing).
fn parse_opt_str(bytes: &mut Bytes) -> Result<Option<String>, sc::ScanError> {
    if bytes.first().copied() == Some(b'"') {
        Ok(Some(bytes_to_string(sc::parse_string(bytes)?)?))
    } else {
        sc::skip_value(bytes)?;
        Ok(None)
    }
}

/// Capture the raw JSON bytes of the value at the cursor (used to render a
/// tool_use `input` object to text losslessly), advancing past it.
fn capture_raw_json(bytes: &mut Bytes) -> Result<String, sc::ScanError> {
    let before = bytes.clone();
    sc::skip_value(bytes)?;
    let consumed = before.len() - bytes.len();
    let raw = before.slice(0..consumed);
    Ok(String::from_utf8_lossy(raw.as_ref()).into_owned())
}

fn scan_record(line: &mut Bytes) -> Result<RawRecord, sc::ScanError> {
    let mut record = RawRecord::default();
    sc::object(line, &mut record, |record, key, value| {
        let key = key
            .view::<str>()
            .map_err(|_| scan_syntax("invalid utf-8 key"))?;
        match key.as_ref() {
            "type" => record.record_type = parse_opt_str(value)?.unwrap_or_default(),
            "uuid" => record.uuid = parse_opt_str(value)?,
            "parentUuid" => record.parent_uuid = parse_opt_str(value)?,
            "timestamp" => {
                record.timestamp = parse_opt_str(value)?
                    .as_deref()
                    .and_then(parse_iso_timestamp)
            }
            "message" => {
                let part = scan_message(value)?;
                record.model = part.model;
                record.blocks = part.blocks;
            }
            _ => sc::skip_value(value)?,
        }
        Ok(record)
    })?;
    Ok(record)
}

fn scan_message(bytes: &mut Bytes) -> Result<MessagePart, sc::ScanError> {
    let mut part = MessagePart::default();
    sc::object(bytes, &mut part, |part, key, value| {
        let key = key
            .view::<str>()
            .map_err(|_| scan_syntax("invalid utf-8 key"))?;
        match key.as_ref() {
            "model" => part.model = parse_opt_str(value)?,
            "content" => part.blocks = scan_content(value)?,
            _ => sc::skip_value(value)?,
        }
        Ok(part)
    })?;
    Ok(part)
}

/// `message.content` is either a plain string (one text block) or an array of
/// content blocks.
fn scan_content(bytes: &mut Bytes) -> Result<Vec<RawBlock>, sc::ScanError> {
    let mut blocks: Vec<RawBlock> = Vec::new();
    match bytes.first().copied() {
        Some(b'"') => {
            let text = bytes_to_string(sc::parse_string(bytes)?)?;
            blocks.push(RawBlock {
                kind: BlockKind::Text,
                payload: text,
                correlator: None,
                signature: None,
            });
        }
        Some(b'[') => {
            sc::array(bytes, &mut blocks, |blocks, element| {
                blocks.push(scan_content_block(element)?);
                Ok(blocks)
            })?;
        }
        _ => sc::skip_value(bytes)?,
    }
    Ok(blocks)
}

fn scan_content_block(bytes: &mut Bytes) -> Result<RawBlock, sc::ScanError> {
    let mut accum = BlockAccum::default();
    sc::object(bytes, &mut accum, |accum, key, value| {
        let key = key
            .view::<str>()
            .map_err(|_| scan_syntax("invalid utf-8 key"))?;
        match key.as_ref() {
            "type" => accum.btype = parse_opt_str(value)?.unwrap_or_default(),
            "text" => accum.text = parse_opt_str(value)?,
            "thinking" => accum.thinking = parse_opt_str(value)?,
            "signature" => accum.signature = parse_opt_str(value)?,
            "id" => accum.tool_id = parse_opt_str(value)?,
            "tool_use_id" => accum.tool_use_id = parse_opt_str(value)?,
            "input" => accum.input_raw = Some(capture_raw_json(value)?),
            "content" => accum.tool_result_content = Some(scan_tool_result_content(value)?),
            _ => sc::skip_value(value)?,
        }
        Ok(accum)
    })?;
    Ok(build_block(accum))
}

fn build_block(accum: BlockAccum) -> RawBlock {
    match accum.btype.as_str() {
        "text" => RawBlock {
            kind: BlockKind::Text,
            payload: accum.text.unwrap_or_default(),
            correlator: None,
            signature: None,
        },
        "thinking" => RawBlock {
            kind: BlockKind::Thinking,
            payload: accum.thinking.unwrap_or_default(),
            correlator: None,
            signature: accum.signature,
        },
        "tool_use" => RawBlock {
            kind: BlockKind::ToolUse,
            payload: accum.input_raw.unwrap_or_default(),
            correlator: accum.tool_id,
            signature: None,
        },
        "tool_result" => RawBlock {
            kind: BlockKind::ToolResult,
            payload: accum.tool_result_content.unwrap_or_default(),
            correlator: accum.tool_use_id,
            signature: None,
        },
        "image" => RawBlock {
            kind: BlockKind::Image,
            payload: String::new(),
            correlator: None,
            signature: None,
        },
        _ => RawBlock {
            kind: BlockKind::Other,
            payload: String::new(),
            correlator: None,
            signature: None,
        },
    }
}

/// A `tool_result` `content` field is a string, or an array of `{type,text}`
/// blocks, or (rarely) some other JSON — captured raw as a fallback.
fn scan_tool_result_content(bytes: &mut Bytes) -> Result<String, sc::ScanError> {
    match bytes.first().copied() {
        Some(b'"') => bytes_to_string(sc::parse_string(bytes)?),
        Some(b'[') => {
            let mut parts: Vec<String> = Vec::new();
            sc::array(bytes, &mut parts, |parts, element| {
                if let Some(text) = extract_block_text(element)? {
                    if !text.is_empty() {
                        parts.push(text);
                    }
                }
                Ok(parts)
            })?;
            Ok(parts.join("\n\n"))
        }
        _ => capture_raw_json(bytes),
    }
}

/// Extract a `text` field from one content block (or a bare string element).
fn extract_block_text(bytes: &mut Bytes) -> Result<Option<String>, sc::ScanError> {
    match bytes.first().copied() {
        Some(b'"') => Ok(Some(bytes_to_string(sc::parse_string(bytes)?)?)),
        Some(b'{') => {
            let mut text: Option<String> = None;
            sc::object(bytes, &mut text, |text, key, value| {
                let key = key
                    .view::<str>()
                    .map_err(|_| scan_syntax("invalid utf-8 key"))?;
                match key.as_ref() {
                    "text" => *text = parse_opt_str(value)?,
                    _ => sc::skip_value(value)?,
                }
                Ok(text)
            })?;
            Ok(text)
        }
        _ => {
            sc::skip_value(bytes)?;
            Ok(None)
        }
    }
}

fn collect_jsonl_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("read dir {}", path.display()))? {
        let entry = entry.context("read dir entry")?;
        let entry_path = entry.path();
        let file_type = entry.file_type().context("entry type")?;
        if file_type.is_dir() {
            // Recurse into subdirectories (projects/*/subagents/, etc).
            collect_jsonl_files(&entry_path, out)?;
        } else if file_type.is_file()
            && entry_path.extension().and_then(|ext| ext.to_str()) == Some("jsonl")
        {
            out.push(entry_path);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Timestamp parsing
// ---------------------------------------------------------------------------

/// Parse an ISO 8601 timestamp like "2026-03-01T15:34:01.542Z".
fn parse_iso_timestamp(value: &str) -> Option<Epoch> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    // hifitime's Epoch parser handles ISO 8601 / RFC 3339.
    trimmed.parse::<Epoch>().ok()
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn import_into_archive(
    path: &Path,
    pile_path: &Path,
    branch_name: &str,
    branch_id: Id,
) -> Result<()> {
    let _span = info_span!(
        "claude_code_import",
        path = %path.display(),
        branch = branch_name,
        branch_id = %format!("{branch_id:x}")
    )
    .entered();
    let import_start = Instant::now();
    let (mut repo, branch_id) = common::open_repo_for_write(pile_path, branch_id, branch_name)?;
    let res = import_claude_code_path(path, &mut repo, branch_id);
    tracing::info!(
        ok = res.is_ok(),
        elapsed_ms = import_start.elapsed().as_millis() as u64,
        "claude-code import finished"
    );
    let close_res = repo
        .close()
        .map_err(|e| anyhow!("close pile {}: {e:?}", pile_path.display()));
    match (res, close_res) {
        (Ok(stats), Ok(())) => {
            println!(
                "Imported {} file(s), {} block(s), {} content-fact(s) in {} new commit(s).",
                stats.files, stats.blocks, stats.content_facts, stats.commits
            );
            Ok(())
        }
        (Ok(_), Err(err)) => Err(err),
        (Err(err), Ok(())) => Err(err),
        (Err(err), Err(close_err)) => {
            eprintln!("warning: close pile after error: {close_err:#}");
            Err(err)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — projection only, no pile (in-memory fragment + query-back).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use triblespace::prelude::inlineencodings::Handle;

    /// A tiny synthetic `.claude` conversation: user → assistant (thinking +
    /// text + tool_use) → user (tool_result), plus a `system` line that must be
    /// ignored.
    const SAMPLE: &str = r#"{"type":"user","uuid":"u1","parentUuid":null,"timestamp":"2026-03-01T15:34:01.542Z","sessionId":"s1","message":{"role":"user","content":"hello there"}}
{"type":"assistant","uuid":"a1","parentUuid":"u1","timestamp":"2026-03-01T15:34:05.000Z","sessionId":"s1","message":{"role":"assistant","model":"claude-opus-4","content":[{"type":"thinking","thinking":"let me think","signature":"sig-abc"},{"type":"text","text":"hi!"},{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"ls"}}]}}
{"type":"user","uuid":"u2","parentUuid":"a1","timestamp":"2026-03-01T15:34:06.000Z","sessionId":"s1","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"file1\nfile2","is_error":false}]}}
{"type":"system","uuid":"sys1","parentUuid":"u2","timestamp":"2026-03-01T15:34:07.000Z","content":"ignored"}"#;

    fn project(sample: &str) -> Fragment {
        let bytes = Bytes::from_source(sample.as_bytes().to_vec());
        project_jsonl(&bytes).expect("projection succeeds")
    }

    fn resolve_payload(frag: &Fragment, handle: Inline<Handle<LongString>>) -> String {
        let mut blobs = frag.blobs().clone();
        let reader = blobs.reader().expect("blob reader");
        let view: View<str> = reader
            .get::<View<str>, LongString>(handle)
            .expect("payload bytes present");
        view.as_ref().to_owned()
    }

    fn block_ids(frag: &Fragment) -> Vec<Id> {
        find!(
            (block: Id),
            pattern!(frag.facts(), [{ ?block @ common::metadata::tag: common::block::KIND }])
        )
        .map(|(block,)| block)
        .collect()
    }

    fn block_payloads(frag: &Fragment, block: Id) -> Vec<String> {
        find!(
            (cf: Id, payload: Inline<Handle<LongString>>),
            pattern!(frag.facts(), [
                { block @ common::block::contains: ?cf },
                { ?cf @ common::content_fact::payload: ?payload },
            ])
        )
        .map(|(_cf, payload)| resolve_payload(frag, payload))
        .collect()
    }

    fn block_directions(frag: &Fragment, block: Id) -> Vec<Id> {
        find!(
            (cf: Id, direction: Id),
            pattern!(frag.facts(), [
                { block @ common::block::contains: ?cf },
                { ?cf @ common::content_fact::direction: ?direction },
            ])
        )
        .map(|(_cf, direction)| direction)
        .collect()
    }

    fn previous_of(frag: &Fragment, block: Id) -> Option<Id> {
        find!(
            (prev: Id),
            pattern!(frag.facts(), [{ block @ common::block::previous: ?prev }])
        )
        .map(|(prev,)| prev)
        .next()
    }

    fn find_block(frag: &Fragment, needle: &str) -> Id {
        block_ids(frag)
            .into_iter()
            .find(|&block| block_payloads(frag, block).iter().any(|p| p.contains(needle)))
            .unwrap_or_else(|| panic!("no block contains payload {needle:?}"))
    }

    #[test]
    fn projects_one_block_per_user_or_assistant_record() {
        let frag = project(SAMPLE);
        // u1, a1, u2 → 3 blocks; the `system` line is ignored.
        assert_eq!(block_ids(&frag).len(), 3);
        // 1 (u1 text) + 3 (a1 thinking/text/tool_use) + 1 (u2 tool_result).
        let content_facts = find!(
            (cf: Id),
            pattern!(frag.facts(), [{ ?cf @ common::metadata::tag: common::content_fact::KIND }])
        )
        .count();
        assert_eq!(content_facts, 5);
    }

    #[test]
    fn previous_edges_chain_through_parent_uuid() {
        let frag = project(SAMPLE);
        let u1 = find_block(&frag, "hello there");
        let a1 = find_block(&frag, "hi!");
        let u2 = find_block(&frag, "file1");

        assert_eq!(previous_of(&frag, u1), None, "root record has no previous");
        assert_eq!(previous_of(&frag, a1), Some(u1));
        assert_eq!(previous_of(&frag, u2), Some(a1));
    }

    #[test]
    fn direction_follows_record_and_block_type() {
        let frag = project(SAMPLE);
        let u1 = find_block(&frag, "hello there");
        let a1 = find_block(&frag, "hi!");
        let u2 = find_block(&frag, "file1");

        let in_ = common::content_fact::direction::in_;
        let out_ = common::content_fact::direction::out_;

        assert!(block_directions(&frag, u1).iter().all(|&d| d == in_));
        assert!(block_directions(&frag, a1).iter().all(|&d| d == out_));
        assert!(block_directions(&frag, u2).iter().all(|&d| d == in_));
    }

    #[test]
    fn modality_and_payload_projected_per_content_block() {
        let frag = project(SAMPLE);
        let facts: Vec<(Id, Inline<Handle<LongString>>)> = find!(
            (modality: Id, payload: Inline<Handle<LongString>>),
            pattern!(frag.facts(), [{ _?cf @
                common::content_fact::modality: ?modality,
                common::content_fact::payload:  ?payload,
            }])
        )
        .collect();

        let payload_for = |wanted: Id| -> Option<String> {
            facts
                .iter()
                .find(|(modality, _)| *modality == wanted)
                .map(|(_, payload)| resolve_payload(&frag, *payload))
        };

        assert_eq!(
            payload_for(common::content_fact::modality::tool_call).as_deref(),
            Some(r#"{"command":"ls"}"#),
            "tool_use input rendered to raw-json text"
        );
        assert_eq!(
            payload_for(common::content_fact::modality::thinking).as_deref(),
            Some("let me think")
        );
        assert_eq!(
            payload_for(common::content_fact::modality::tool_result).as_deref(),
            Some("file1\nfile2")
        );

        let texts: HashSet<String> = facts
            .iter()
            .filter(|(modality, _)| *modality == common::content_fact::modality::text)
            .map(|(_, payload)| resolve_payload(&frag, *payload))
            .collect();
        assert!(texts.contains("hello there"));
        assert!(texts.contains("hi!"));
    }

    #[test]
    fn thinking_signature_is_non_identity_annotation() {
        let frag = project(SAMPLE);
        // The thinking content-fact carries its signature; find it and resolve.
        let signature = find!(
            (sig: Inline<Handle<LongString>>),
            pattern!(frag.facts(), [{ _?cf @
                common::content_fact::modality:  common::content_fact::modality::thinking,
                common::content_fact::signature: ?sig,
            }])
        )
        .map(|(sig,)| resolve_payload(&frag, sig))
        .next();
        assert_eq!(signature.as_deref(), Some("sig-abc"));
    }

    #[test]
    fn reprojection_is_content_addressed_stable() {
        let first: HashSet<Id> = block_ids(&project(SAMPLE)).into_iter().collect();
        let second: HashSet<Id> = block_ids(&project(SAMPLE)).into_iter().collect();
        assert_eq!(first, second, "re-projecting the same input yields identical block ids");
    }
}
