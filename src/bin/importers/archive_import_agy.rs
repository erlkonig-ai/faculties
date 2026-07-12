use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::common;
use anyhow::{Context, Result, anyhow};
use hifitime::Epoch;
use serde_json::Value as JsonValue;
use std::str::FromStr;
use tracing::info_span;
use triblespace::core::import::json_tree::JsonTreeImporter;
use triblespace::prelude::*;

#[derive(Debug, Default, Clone)]
struct ImportStats {
    files: usize,
    conversations: usize,
    messages: usize,
    commits: usize,
}

#[derive(Debug, Clone)]
struct MessageRecord {
    conversation_id: String,
    source_message_id: String,
    parent_source_id: Option<String>,
    role: String,
    author: String,
    content: String,
    created_at: Option<Epoch>,
    order: usize,
}

fn import_agy_path(
    path: &Path,
    repo: &mut common::Repo,
    branch_id: Id,
) -> Result<ImportStats> {
    let start = Instant::now();
    println!("agy phase pull: {}", path.display());
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
    let mut catalog = ws.checkout(..).context("checkout workspace")?.into_facts();
    let mut catalog_head = ws.head();
    println!("agy phase pull: done in {:?}", start.elapsed());

    if path.is_dir() {
        let scan_start = Instant::now();
        println!("agy phase scan: {}", path.display());
        let mut paths = Vec::new();
        collect_agy_files(path, &mut paths)
            .with_context(|| format!("scan {}", path.display()))?;
        paths.sort();
        let total_files = paths.len();
        println!(
            "agy phase scan: found {} jsonl file(s) under {} in {:?}",
            total_files,
            path.display(),
            scan_start.elapsed()
        );
        let parsed_files: Vec<(PathBuf, Result<Vec<JsonValue>>)> =
            common::parse_paths_parallel("agy", &paths, parse_jsonl)?;

        let mut total = ImportStats::default();
        for (index, (file, parsed_records)) in parsed_files.into_iter().enumerate() {
            let file_start = Instant::now();
            let raw_records = parsed_records.with_context(|| format!("parse {}", file.display()))?;
            if raw_records.is_empty() {
                continue;
            }
            
            let conv_id = file.parent().unwrap().parent().unwrap().parent().unwrap().file_name().unwrap().to_string_lossy().to_string();

            let stats = import_agy_records(
                &conv_id,
                raw_records,
                repo,
                &mut ws,
                &mut catalog,
                &mut catalog_head,
            )
            .with_context(|| format!("import {}", file.display()))?;
            total.files += stats.files;
            total.conversations += stats.conversations;
            total.messages += stats.messages;
            total.commits += stats.commits;
            println!(
                "agy file {}/{}: {} ({} msgs) in {:?}",
                index + 1,
                total_files,
                file.display(),
                stats.messages,
                file_start.elapsed()
            );
        }
        return Ok(total);
    }
    
    let conv_id = path.parent().unwrap().parent().unwrap().parent().unwrap().file_name().unwrap().to_string_lossy().to_string();
    let raw_records = parse_jsonl(path)?;
    import_agy_records(
        &conv_id,
        raw_records,
        repo,
        &mut ws,
        &mut catalog,
        &mut catalog_head,
    )
}

fn import_agy_records(
    conv_id: &str,
    raw_records: Vec<JsonValue>,
    repo: &mut common::Repo,
    ws: &mut common::Ws,
    catalog: &mut TribleSet,
    catalog_head: &mut Option<common::CommitHandle>,
) -> Result<ImportStats> {
    let mut stats = ImportStats {
        files: 1,
        ..ImportStats::default()
    };

    if raw_records.is_empty() {
        return Ok(stats);
    }
    stats.conversations = 1;

    let raw_root = {
        let raw_payload = serde_json::to_string(&raw_records).context("serialize agy jsonl")?;
        let mut importer = JsonTreeImporter::<_>::new(repo.storage_mut(), None);
        let fragment = importer.import_str(&raw_payload).context("import agy raw json tree")?;
        let root = fragment.root().ok_or_else(|| anyhow!("json tree importer did not return a single root"))?;
        if common::commit_delta(repo, ws, catalog, catalog_head, fragment.facts().clone(), "import agy json tree")? {
            stats.commits += 1;
        }
        root
    };

    let mut messages = collect_messages(conv_id, &raw_records);
    messages.sort_by_key(|m| m.order);

    let mut change = TribleSet::new();
    let mut author_cache: HashMap<String, Id> = HashMap::new();
    let conversation_id_str = format!("agy:{}", conv_id);

    let mut message_ids: Vec<(Id, &MessageRecord)> = Vec::new();
    
    // Pass 1: create message entities
    for msg in &messages {
        let source_message_id_handle = ws.put(msg.source_message_id.clone());
        let message_fragment = entity! { _ @
            common::import_schema::source_format: "agy",
            common::import_schema::source_message_id: source_message_id_handle,
        };
        let message_id = message_fragment.root().expect("entity! must export a single root id");
        change += message_fragment;
        message_ids.push((message_id, msg));
    }

    // Pass 2: create conversation entity
    let conversation_fragment = entity! { _ @
        common::metadata::tag: common::import_schema::kind_conversation,
        common::import_schema::source_format: "agy",
        common::import_schema::source_conversation_id: ws.put(conversation_id_str.clone()),
    };
    let conversation_id = conversation_fragment.root().expect("entity! must export a single root id");
    change += conversation_fragment;

    {
        let conversation_entity = conversation_id.acquire().expect("entity! root ids should be acquired in current thread");
        let msg_id_list: Vec<Id> = message_ids.iter().map(|(id, _)| *id).collect();
        change += entity! { &conversation_entity @
            common::import_schema::message*: msg_id_list,
            common::import_schema::source_raw_root: raw_root,
        };
    }

    // Pass 3: attach content attributes
    let mut previous: Option<(Id, String)> = None;
    for (message_id, msg) in &message_ids {
        let message_entity = message_id.acquire().expect("entity! root ids should be acquired in current thread");

        let author_key = format!("{}::{}", msg.author, msg.role);
        let author_id = if let Some(id) = author_cache.get(&author_key).copied() {
            id
        } else {
            let (id, author_change) = common::ensure_author(ws, catalog, &msg.author, &msg.role)?;
            change += author_change;
            author_cache.insert(author_key, id);
            id
        };

        let created_at = common::epoch_interval(msg.created_at.unwrap_or_else(common::unknown_epoch));
        let content_handle = ws.put(msg.content.clone());

        let reply_to = previous.as_ref().map(|(parent_id, _)| *parent_id);
        let source_parent_id = previous.as_ref().map(|(_, parent_source_id)| ws.put(parent_source_id.clone()));

        change += entity! { &message_entity @
            common::metadata::tag: common::archive::kind_message,
            common::archive::author: author_id,
            common::archive::content: content_handle,
            common::metadata::created_at: created_at,
            common::import_schema::source_author: ws.put(msg.author.clone()),
            common::import_schema::source_role: ws.put(msg.role.clone()),
            common::import_schema::source_created_at: created_at,
            common::archive::reply_to?: reply_to,
            common::import_schema::source_parent_id?: source_parent_id,
        };
        previous = Some((*message_id, msg.source_message_id.clone()));
        stats.messages += 1;
    }

    if common::commit_delta(repo, ws, catalog, catalog_head, change, "import agy")? {
        stats.commits += 1;
    }
    Ok(stats)
}

fn collect_agy_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(path).with_context(|| format!("read dir {}", path.display()))? {
        let entry = entry.context("read dir entry")?;
        let entry_path = entry.path();
        let file_type = entry.file_type().context("entry type")?;
        if file_type.is_dir() {
            collect_agy_files(&entry_path, out)?;
            continue;
        }
        if file_type.is_file() {
            if entry_path.file_name().unwrap_or_default() == "transcript_full.jsonl" {
                out.push(entry_path);
            }
        }
    }
    Ok(())
}

fn parse_jsonl(path: &Path) -> Result<Vec<JsonValue>> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value = serde_json::from_str::<JsonValue>(trimmed)
            .with_context(|| format!("malformed JSON on line {}", i + 1))?;
        out.push(value);
    }
    Ok(out)
}

fn collect_messages(conv_id: &str, records: &[JsonValue]) -> Vec<MessageRecord> {
    let mut out = Vec::new();
    for (ordinal, value) in records.iter().enumerate() {
        let source = value.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let content = value.get("content").and_then(|v| v.as_str()).unwrap_or("");
        let step_index = value.get("step_index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let t = value.get("type").and_then(|v| v.as_str()).unwrap_or("");
        
        let created_at_str = value.get("created_at").and_then(|v| v.as_str()).unwrap_or("");
        let created_at = Epoch::from_str(created_at_str).ok();
        
        let (role, author) = match source {
            "USER_EXPLICIT" | "USER_INPUT" => ("user", "user"),
            "MODEL" => ("assistant", "assistant"),
            "SYSTEM" => {
                if t == "TOOL_CALL" || t == "TOOL_RESPONSE" {
                    ("system", "system")
                } else {
                    continue;
                }
            },
            _ => continue,
        };
        
        let content_to_store = if !content.is_empty() {
            content.to_string()
        } else {
            serde_json::to_string(value).unwrap_or_default()
        };
        
        if content_to_store.is_empty() {
            continue;
        }
        
        let source_msg_id = format!("agy:{}:{}:{}", conv_id, step_index, ordinal);
        
        out.push(MessageRecord {
            conversation_id: conv_id.to_string(),
            source_message_id: source_msg_id,
            parent_source_id: None,
            role: role.to_string(),
            author: author.to_string(),
            content: content_to_store,
            created_at,
            order: ordinal,
        });
    }
    out
}

pub fn import_into_archive(
    path: &Path,
    pile_path: &Path,
    branch_name: &str,
    branch_id: Id,
) -> Result<()> {
    let _span = info_span!(
        "agy_import",
        path = %path.display(),
        branch = branch_name,
        branch_id = %format!("{branch_id:x}")
    )
    .entered();
    let (mut repo, branch_id) = common::open_repo_for_write(pile_path, branch_id, branch_name)?;
    let res = import_agy_path(path, &mut repo, branch_id);
    let close_res = repo.close();
    match (res, close_res) {
        (Ok(stats), Ok(())) => {
            println!(
                "Imported {} file(s), {} conversation(s), {} message(s) in {} new commit(s).",
                stats.files, stats.conversations, stats.messages, stats.commits
            );
            Ok(())
        }
        (Ok(_), Err(err)) => Err(anyhow::anyhow!("close error: {}", err)),
        (Err(err), Ok(())) => Err(err),
        (Err(err), Err(_)) => Err(err),
    }
}
