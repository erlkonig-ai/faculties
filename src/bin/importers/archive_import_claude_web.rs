use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::common;
use anyhow::{anyhow, Context, Result};
use hifitime::Epoch;
use serde_json::Value as JsonValue;
use tracing::info_span;
use triblespace::core::blob::Bytes;
use triblespace::core::import::json_tree::JsonTreeImporter;
use triblespace::prelude::*;

#[derive(Debug, Default, Clone)]
struct ImportStats {
    files: usize,
    conversations: usize,
    messages: usize,
    attachments: usize,
    commits: usize,
}

/// Import claude.ai data-export folders (web/desktop app exports).
///
/// Expected layout: one or more directories containing a `conversations.json`
/// (an array of conversations, each with `uuid`, `name`, `summary`,
/// `created_at`, and `chat_messages[]`). Overlapping export batches are safe:
/// identity is content-derived from the source uuids, so re-imports converge.
fn import_claude_web_path(
    path: &Path,
    repo: &mut common::Repo,
    branch_id: Id,
) -> Result<ImportStats> {
    let start = Instant::now();
    println!("claude-web phase pull: {}", path.display());
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
    let mut catalog = ws.checkout(..).context("checkout workspace")?.into_facts();
    let mut catalog_head = ws.head();
    println!("claude-web phase pull: done in {:?}", start.elapsed());

    let scan_start = Instant::now();
    let mut paths = Vec::new();
    if path.is_file() {
        paths.push(path.to_path_buf());
    } else {
        collect_conversation_files(path, &mut paths)
            .with_context(|| format!("scan {}", path.display()))?;
    }
    paths.sort();
    println!(
        "claude-web phase scan: found {} conversations.json file(s) under {} in {:?}",
        paths.len(),
        path.display(),
        scan_start.elapsed()
    );

    let parsed_files: Vec<(PathBuf, Result<Vec<JsonValue>>)> =
        common::parse_paths_parallel("claude-web", &paths, parse_conversations_json)?;

    let mut stats = ImportStats::default();
    for (file, parsed) in parsed_files {
        let conversations = parsed.with_context(|| format!("parse {}", file.display()))?;
        stats.files += 1;
        let total_conversations = conversations.len();
        for (index, convo) in conversations.into_iter().enumerate() {
            import_one_conversation(
                repo,
                &mut ws,
                &mut catalog,
                &mut catalog_head,
                &convo,
                &mut stats,
            )
            .with_context(|| format!("conversation {} in {}", index, file.display()))?;
            let processed = index + 1;
            if processed % 50 == 0 || processed == total_conversations {
                println!(
                    "claude-web progress {}/{} conversations (messages {}, attachments {}, commits {})",
                    processed,
                    total_conversations,
                    stats.messages,
                    stats.attachments,
                    stats.commits
                );
            }
        }
    }
    Ok(stats)
}

fn import_one_conversation(
    repo: &mut common::Repo,
    ws: &mut common::Ws,
    catalog: &mut TribleSet,
    catalog_head: &mut Option<common::CommitHandle>,
    convo: &JsonValue,
    stats: &mut ImportStats,
) -> Result<()> {
    let convo_uuid = convo
        .get("uuid")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("conversation missing uuid"))?;

    // Raw provenance: the conversation JSON as a content-addressed tree.
    let convo_raw = serde_json::to_string(convo).context("serialize conversation")?;
    let raw_root = {
        let mut raw_importer = JsonTreeImporter::<_>::new(repo.storage_mut(), None);
        let raw_fragment = raw_importer
            .import_str(&convo_raw)
            .with_context(|| format!("import json tree for conversation {convo_uuid}"))?;
        let raw_root = raw_fragment
            .root()
            .ok_or_else(|| anyhow!("json tree importer did not return a single root"))?;
        if common::commit_delta(
            repo,
            ws,
            catalog,
            catalog_head,
            raw_fragment.facts().clone(),
            "import claude-web json tree",
        )? {
            stats.commits += 1;
        }
        raw_root
    };

    // Identity = format + source conversation uuid only; the raw root is
    // export-dependent and merges on afterwards (see chatgpt importer).
    let conversation_fragment = entity! { _ @
        common::metadata::tag: common::import_schema::kind_conversation,
        common::import_schema::source_format: "claude-web",
        common::import_schema::source_conversation_id: ws.put(convo_uuid.to_string()),
    };
    let conversation_id = conversation_fragment
        .root()
        .expect("entity! must export a single root id");

    let mut change = TribleSet::new();
    change += conversation_fragment;
    {
        let title = convo
            .get("name")
            .and_then(JsonValue::as_str)
            .filter(|s| !s.is_empty())
            .map(|s| ws.put(s.to_string()));
        let summary = convo
            .get("summary")
            .and_then(JsonValue::as_str)
            .filter(|s| !s.is_empty())
            .map(|s| ws.put(s.to_string()));
        let conversation_entity = conversation_id
            .acquire()
            .expect("entity! root ids should be acquired in current thread");
        change += entity! { &conversation_entity @
            common::import_schema::source_raw_root: raw_root,
            common::import_schema::source_conversation_title?: title,
            common::import_schema::source_conversation_summary?: summary,
        };
    }

    let convo_created = convo
        .get("created_at")
        .and_then(JsonValue::as_str)
        .and_then(parse_iso_timestamp);

    let empty = Vec::new();
    let messages = convo
        .get("chat_messages")
        .and_then(JsonValue::as_array)
        .unwrap_or(&empty);

    let mut author_cache: HashMap<String, Id> = HashMap::new();
    // claude.ai conversations are linear; thread messages via previous-link.
    let mut previous: Option<(Id, String)> = None;

    for message in messages {
        let Some(msg_uuid) = message.get("uuid").and_then(JsonValue::as_str) else {
            continue;
        };
        // Identity = format + message uuid (uuids are globally unique).
        let source_message_id_handle = ws.put(msg_uuid.to_string());
        let message_fragment = entity! { _ @
            common::import_schema::source_format: "claude-web",
            common::import_schema::source_message_id: source_message_id_handle,
        };
        let message_id = message_fragment
            .root()
            .expect("entity! must export a single root id");
        change += message_fragment;
        let message_entity = message_id
            .acquire()
            .expect("entity! root ids should be acquired in current thread");

        let role = message
            .get("sender")
            .and_then(JsonValue::as_str)
            .unwrap_or("unknown");
        let author_id = if let Some(id) = author_cache.get(role).copied() {
            id
        } else {
            let (id, author_change) = common::ensure_author(ws, catalog, role, role)?;
            change += author_change;
            author_cache.insert(role.to_string(), id);
            id
        };

        let created_at_epoch = message
            .get("created_at")
            .and_then(JsonValue::as_str)
            .and_then(parse_iso_timestamp)
            .or(convo_created)
            .unwrap_or_else(common::unknown_epoch);
        let created_at = common::epoch_interval(created_at_epoch);

        let content = extract_message_text(message);
        let content_handle = ws.put(content);

        // Attachments carry extracted text content (claude.ai exports do not
        // include raw binary payloads). Identity = conversation/message/name.
        let mut attachment_ids = Vec::new();
        for attachment in collect_attachments(message) {
            let source_id = format!("{}/{}/{}", convo_uuid, msg_uuid, attachment.file_name);
            let source_id_handle = ws.put(source_id);
            let attachment_fragment = entity! { _ @
                common::metadata::tag: common::archive::kind_attachment,
                common::archive::attachment_source_id: source_id_handle,
            };
            let attachment_id = attachment_fragment
                .root()
                .expect("entity! must export a single root id");
            let attachment_entity = attachment_id
                .acquire()
                .expect("entity! root ids should be acquired in current thread");
            attachment_ids.push(attachment_id);
            change += attachment_fragment;

            let name_handle = ws.put(attachment.file_name.clone());
            let mime = attachment.file_type.as_deref().filter(|s| !s.is_empty());
            let data = attachment
                .extracted_content
                .filter(|text| !text.is_empty())
                .map(|text| ws.put(Bytes::from_source(text.into_bytes())));
            if data.is_some() {
                stats.attachments += 1;
            }
            change += entity! { &attachment_entity @
                common::archive::attachment_name: name_handle,
                common::archive::attachment_mime?: mime,
                common::archive::attachment_size_bytes?: attachment.file_size,
                common::archive::attachment_data?: data,
            };
        }

        let (reply_to, source_parent_id) = match &previous {
            Some((prev_id, prev_uuid)) => (Some(*prev_id), Some(ws.put(prev_uuid.clone()))),
            None => (None, None),
        };

        change += entity! { &message_entity @
            common::metadata::tag: common::archive::kind_message,
            common::import_schema::conversation: conversation_id,
            common::archive::author: author_id,
            common::archive::content: content_handle,
            common::metadata::created_at: created_at,
            common::archive::attachment*: attachment_ids,
            common::archive::reply_to?: reply_to,
            common::import_schema::source_author: ws.put(role.to_string()),
            common::import_schema::source_role: ws.put(role.to_string()),
            common::import_schema::source_created_at: created_at,
            common::import_schema::source_parent_id?: source_parent_id,
        };

        previous = Some((message_id, msg_uuid.to_string()));
        stats.messages += 1;
    }

    if common::commit_delta(repo, ws, catalog, catalog_head, change, "import claude-web")? {
        stats.commits += 1;
    }
    stats.conversations += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

struct AttachmentFields {
    file_name: String,
    file_type: Option<String>,
    file_size: Option<u64>,
    extracted_content: Option<String>,
}

fn collect_attachments(message: &JsonValue) -> Vec<AttachmentFields> {
    let mut out = Vec::new();
    for key in ["attachments", "files"] {
        let Some(items) = message.get(key).and_then(JsonValue::as_array) else {
            continue;
        };
        for item in items {
            let Some(file_name) = item.get("file_name").and_then(JsonValue::as_str) else {
                continue;
            };
            out.push(AttachmentFields {
                file_name: file_name.to_string(),
                file_type: item
                    .get("file_type")
                    .and_then(JsonValue::as_str)
                    .map(str::to_string),
                file_size: item.get("file_size").and_then(JsonValue::as_u64),
                extracted_content: item
                    .get("extracted_content")
                    .and_then(JsonValue::as_str)
                    .map(str::to_string),
            });
        }
    }
    out
}

/// Prefer the flat `text` field; fall back to joining `content[]` text blocks.
fn extract_message_text(message: &JsonValue) -> String {
    if let Some(text) = message.get("text").and_then(JsonValue::as_str) {
        if !text.is_empty() {
            return text.to_string();
        }
    }
    let mut parts = Vec::new();
    if let Some(blocks) = message.get("content").and_then(JsonValue::as_array) {
        for block in blocks {
            if let Some(text) = block.get("text").and_then(JsonValue::as_str) {
                if !text.is_empty() {
                    parts.push(text.to_string());
                }
            }
        }
    }
    parts.join("\n")
}

fn parse_conversations_json(path: &Path) -> Result<Vec<JsonValue>> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let value: JsonValue =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    match value {
        JsonValue::Array(items) => Ok(items),
        other => Ok(vec![other]),
    }
}

fn collect_conversation_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("read dir {}", path.display()))? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            collect_conversation_files(&entry_path, out)?;
        } else if entry_path.file_name().and_then(|name| name.to_str())
            == Some("conversations.json")
        {
            out.push(entry_path);
        }
    }
    Ok(())
}

/// Parse an ISO 8601 timestamp like "2026-03-01T23:59:11.198120Z".
fn parse_iso_timestamp(value: &str) -> Option<Epoch> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
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
        "claude_web_import",
        path = %path.display(),
        branch = branch_name,
        branch_id = %format!("{branch_id:x}")
    )
    .entered();
    let import_start = Instant::now();
    let (mut repo, branch_id) = common::open_repo_for_write(pile_path, branch_id, branch_name)?;
    let res = import_claude_web_path(path, &mut repo, branch_id);
    tracing::info!(
        ok = res.is_ok(),
        elapsed_ms = import_start.elapsed().as_millis() as u64,
        "claude-web import finished"
    );
    let close_res = repo
        .close()
        .map_err(|e| anyhow!("close pile {}: {e:?}", pile_path.display()));
    match (res, close_res) {
        (Ok(stats), Ok(())) => {
            println!(
                "Imported {} file(s), {} conversation(s), {} message(s), {} attachment(s) in {} new commit(s).",
                stats.files,
                stats.conversations,
                stats.messages,
                stats.attachments,
                stats.commits
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
