//! Serde-free projection of Gemini Antigravity transcript JSONL.

use std::fs;
use std::path::{Path, PathBuf};

use anybytes::{Bytes, View};
use anyhow::{bail, Context, Result};
use hifitime::Epoch;
use triblespace::core::import::scanner as sc;
use triblespace::core::inline::TryToInline;

use crate::archive_source::{
    self, ProjectedSource, ProjectionStats, SourceClaims, SourcePart, SourceRecord, Threading,
};
use crate::schemas::blockdag as schema;

/// Result returned after every selected transcript reaches the sink.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProjectionSummary {
    pub files_scanned: usize,
    pub fragments_emitted: usize,
    pub stats: ProjectionStats,
}

#[derive(Default)]
struct RawFields {
    source: Option<View<str>>,
    content: Option<View<str>>,
    record_type: Option<View<str>>,
    created_at: Option<View<str>>,
    thinking: Option<View<str>>,
    step_index: Option<u64>,
    tool_calls: Option<Bytes>,
}

/// Project one `transcript_full.jsonl`, or all matching files below a directory.
pub fn project_path<F>(path: &Path, mut emit: F) -> Result<ProjectionSummary>
where
    F: FnMut(ProjectedSource) -> Result<()>,
{
    let mut paths = Vec::new();
    if path.is_dir() {
        collect_transcripts(path, &mut paths)?;
        paths.sort();
    } else {
        paths.push(path.to_path_buf());
    }
    if paths.is_empty() {
        bail!(
            "no Antigravity transcript_full.jsonl files below {}",
            path.display()
        );
    }

    let mut summary = ProjectionSummary::default();
    for source_path in paths {
        let records = parse_file(&source_path)?;
        let stats = archive_source::project_records(
            schema::source_projection::SOURCE_AGY,
            &source_path,
            records,
            |projected| {
                summary.fragments_emitted += 1;
                emit(projected)
            },
        )?;
        summary.files_scanned += 1;
        absorb(&mut summary.stats, stats);
    }
    Ok(summary)
}

fn collect_transcripts(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("read {}", path.display()))? {
        let entry = entry.context("read Antigravity directory entry")?;
        let file_type = entry.file_type().context("read Antigravity entry type")?;
        let entry_path = entry.path();
        if file_type.is_dir() {
            collect_transcripts(&entry_path, out)?;
        } else if file_type.is_file()
            && entry_path.file_name().and_then(|name| name.to_str())
                == Some("transcript_full.jsonl")
        {
            out.push(entry_path);
        }
    }
    Ok(())
}

fn parse_file(path: &Path) -> Result<Vec<SourceRecord>> {
    let bytes = archive_source::read_file(path)?;
    let lines = exact_lines(&bytes);
    let conversation = conversation_anchor(lines.first());
    let mut records = Vec::new();
    let mut previous = None::<View<str>>;

    for (line_index, raw) in lines.into_iter().enumerate() {
        let line_number = u64::try_from(line_index + 1).expect("line number fits u64");
        let locator = archive_source::owned_text(format!("{conversation}/line/{line_number}"));
        let trimmed = trim_ascii(raw.clone());
        let (parts, claims, threading) = if trimmed.is_empty() {
            (Vec::new(), SourceClaims::default(), Threading::Transparent)
        } else {
            let fields = scan_fields(trimmed).with_context(|| {
                format!("parse Antigravity {} line {line_number}", path.display())
            })?;
            interpret(fields)?
        };
        let block_timestamp = claims.timestamp;
        records.push(SourceRecord {
            locator: locator.clone(),
            raw_record: raw,
            predecessors: previous.iter().cloned().collect(),
            block_timestamp,
            threading,
            parts,
            claims,
        });
        previous = Some(locator);
    }
    Ok(records)
}

fn exact_lines(bytes: &Bytes) -> Vec<Bytes> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let mut lines = Vec::new();
    let mut start = 0usize;
    for (index, byte) in bytes.as_ref().iter().copied().enumerate() {
        if byte == b'\n' {
            lines.push(bytes.slice(start..index + 1));
            start = index + 1;
        }
    }
    if start < bytes.len() {
        lines.push(bytes.slice(start..bytes.len()));
    }
    lines
}

fn trim_ascii(bytes: Bytes) -> Bytes {
    let raw = bytes.as_ref();
    let start = raw
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(raw.len());
    let end = raw
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    bytes.slice(start..end)
}

fn scan_fields(mut bytes: Bytes) -> std::result::Result<RawFields, sc::ScanError> {
    let mut fields = RawFields::default();
    sc::object(&mut bytes, &mut fields, |fields, key, value| {
        let key = key
            .view::<str>()
            .map_err(|_| sc::ScanError::Syntax("object key is not UTF-8".to_owned()))?;
        match key.as_ref() {
            "source" => fields.source = optional_string(value)?,
            "content" => fields.content = optional_string(value)?,
            "type" => fields.record_type = optional_string(value)?,
            "created_at" => fields.created_at = optional_string(value)?,
            "thinking" => fields.thinking = optional_string(value)?,
            "step_index" => fields.step_index = optional_u64(value)?,
            "tool_calls" => fields.tool_calls = Some(archive_source::raw_value(value)?),
            _ => sc::skip_value(value)?,
        }
        Ok(fields)
    })?;
    sc::skip_ws(&mut bytes);
    if !bytes.is_empty() {
        return Err(sc::ScanError::Syntax(
            "trailing bytes after Antigravity record".to_owned(),
        ));
    }
    Ok(fields)
}

fn optional_string(value: &mut Bytes) -> std::result::Result<Option<View<str>>, sc::ScanError> {
    if value.first().copied() == Some(b'"') {
        archive_source::string(value).map(Some)
    } else {
        sc::skip_value(value)?;
        Ok(None)
    }
}

fn optional_u64(value: &mut Bytes) -> std::result::Result<Option<u64>, sc::ScanError> {
    if value
        .first()
        .copied()
        .is_some_and(|byte| byte.is_ascii_digit())
    {
        let raw = sc::parse_number(value)?;
        let text = raw
            .view::<str>()
            .map_err(|_| sc::ScanError::Syntax("number is not UTF-8".to_owned()))?;
        Ok(text.as_ref().parse().ok())
    } else {
        sc::skip_value(value)?;
        Ok(None)
    }
}

fn interpret(fields: RawFields) -> Result<(Vec<SourcePart>, SourceClaims, Threading)> {
    let source = fields.source.as_ref().map(AsRef::as_ref).unwrap_or("");
    let record_type = fields.record_type.as_ref().map(AsRef::as_ref).unwrap_or("");
    let (direction, modality, threading) = match source {
        "USER_EXPLICIT" | "USER_INPUT" => (
            schema::content_fact::direction::IN,
            schema::content_fact::modality::TEXT,
            Threading::Semantic,
        ),
        "MODEL" if record_type == "PLANNER_RESPONSE" => (
            schema::content_fact::direction::OUT,
            schema::content_fact::modality::TEXT,
            Threading::Semantic,
        ),
        "SYSTEM" if record_type == "TOOL_CALL" => (
            schema::content_fact::direction::OUT,
            schema::content_fact::modality::TOOL_CALL,
            Threading::Transparent,
        ),
        "SYSTEM" if record_type == "TOOL_RESPONSE" => (
            schema::content_fact::direction::IN,
            schema::content_fact::modality::TOOL_RESULT,
            Threading::Transparent,
        ),
        "MODEL" => (
            schema::content_fact::direction::OUT,
            schema::content_fact::modality::TOOL_RESULT,
            Threading::Transparent,
        ),
        _ => (
            schema::content_fact::direction::AMBIENT,
            schema::content_fact::modality::EVENT,
            Threading::Transparent,
        ),
    };

    let mut parts = Vec::new();
    if let Some(content) = fields
        .content
        .filter(|content| !content.as_ref().trim().is_empty())
    {
        parts.push(SourcePart::text(modality, direction, content));
    }
    if let Some(thinking) = fields
        .thinking
        .filter(|thinking| !thinking.as_ref().trim().is_empty())
    {
        parts.push(SourcePart::text(
            schema::content_fact::modality::THINKING,
            schema::content_fact::direction::OUT,
            thinking,
        ));
    }
    if let Some(tool_calls) = fields.tool_calls {
        let value = archive_source::owned_text(archive_source::canonical_json(tool_calls)?);
        parts.push(SourcePart::text(
            schema::content_fact::modality::TOOL_CALL,
            schema::content_fact::direction::OUT,
            value,
        ));
    }

    let timestamp = fields
        .created_at
        .as_ref()
        .and_then(|value| value.as_ref().trim().parse::<Epoch>().ok())
        .and_then(|epoch| (epoch, epoch).try_to_inline().ok());
    let claims = SourceClaims {
        timestamp,
        raw_author: fields.source.clone(),
        raw_role: fields.record_type.clone(),
        ..SourceClaims::default()
    };
    let _ = fields.step_index;
    Ok((parts, claims, threading))
}

/// Derive a path-independent birth anchor from the first physical JSONL
/// record. Antigravity's transcript body exposes no conversation identifier,
/// but it is append-only: later records cannot change this prefix. Strip only
/// the line terminator so appending to a one-line file does not rename the
/// conversation when the exporter inserts the separating newline.
fn conversation_anchor(first_line: Option<&Bytes>) -> String {
    let mut birth = first_line.map_or(&[][..], Bytes::as_ref);
    if let Some(without_lf) = birth.strip_suffix(b"\n") {
        birth = without_lf;
        if let Some(without_cr) = birth.strip_suffix(b"\r") {
            birth = without_cr;
        }
    }
    format!("agy:birth/v1/{}", blake3::hash(birth).to_hex())
}

fn absorb(target: &mut ProjectionStats, source: ProjectionStats) {
    target.records_seen += source.records_seen;
    target.projections_emitted += source.projections_emitted;
    target.content_parts += source.content_parts;
    target.transparent_records += source.transparent_records;
    target.raw_only_records += source.raw_only_records;
    target.missing_predecessors += source.missing_predecessors;
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;

    use tempfile::TempDir;
    use triblespace::prelude::*;

    use super::*;

    fn semantic_identity(fragment: &Fragment) -> (Id, BTreeSet<(Id, Id)>) {
        let projection = fragment.root().expect("source projection has one root");
        let block = find!(
            (block: Id),
            pattern!(fragment.facts(), [{
                projection @ schema::source_projection::projects_to: ?block
            }])
        )
        .next()
        .map(|(block,)| block)
        .expect("source projection names one block");
        let content = find!(
            (part: Id, fact: Id),
            pattern!(fragment.facts(), [
                { block @ schema::block::contains: ?part },
                { ?part @ schema::content_part::fact: ?fact },
            ])
        )
        .collect();
        (block, content)
    }

    #[test]
    fn scans_dialogue_thinking_tools_and_unknown_records_natively() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("transcript_full.jsonl");
        fs::write(
            &path,
            concat!(
                r#"{"source":"USER_INPUT","content":"hello","step_index":1,"created_at":"2026-08-17T01:02:03Z"}"#,
                "\n",
                r#"{"source":"MODEL","type":"PLANNER_RESPONSE","content":"hi","thinking":"hmm","tool_calls":[{"name":"x"}]}"#,
                "\n",
                r#"{"source":"FUTURE_KIND","payload":{"kept":true}}"#,
                "\n"
            ),
        )
        .unwrap();

        let mut fragments = Vec::new();
        let summary = project_path(&path, |projected| {
            fragments.push(projected.fragment);
            Ok(())
        })
        .unwrap();
        assert_eq!(summary.files_scanned, 1);
        assert_eq!(summary.fragments_emitted, 3);
        assert_eq!(summary.stats.records_seen, 3);
        assert_eq!(summary.stats.projections_emitted, 3);
        assert_eq!(summary.stats.content_parts, 4);
        assert_eq!(summary.stats.raw_only_records, 1);
    }

    #[test]
    fn move_and_append_do_not_rename_existing_source_occurrences() {
        let dir = TempDir::new().unwrap();
        let first_dir = dir.path().join("before");
        let second_dir = dir.path().join("after/renamed");
        fs::create_dir_all(&first_dir).unwrap();
        fs::create_dir_all(&second_dir).unwrap();
        let first_path = first_dir.join("transcript_full.jsonl");
        let second_path = second_dir.join("transcript_full.jsonl");
        let prefix = concat!(
            r#"{"source":"USER_INPUT","content":"same birth","step_index":1}"#,
            "\n",
            r#"{"source":"MODEL","type":"PLANNER_RESPONSE","content":"same answer","step_index":2}"#,
            "\n",
        );
        fs::write(&first_path, prefix).unwrap();
        fs::write(
            &second_path,
            format!(
                "{prefix}{}",
                r#"{"source":"USER_INPUT","content":"appended","step_index":3}"#
            ),
        )
        .unwrap();

        let before = parse_file(&first_path).unwrap();
        let after = parse_file(&second_path).unwrap();
        assert_eq!(before.len(), 2);
        assert_eq!(after.len(), 3);
        assert_eq!(before[0].locator, after[0].locator);
        assert_eq!(before[1].locator, after[1].locator);

        let mut before_fragments = Vec::new();
        project_path(&first_path, |projected| {
            before_fragments.push(projected.fragment);
            Ok(())
        })
        .unwrap();
        let mut after_fragments = Vec::new();
        project_path(&second_path, |projected| {
            after_fragments.push(projected.fragment);
            Ok(())
        })
        .unwrap();
        assert_eq!(before_fragments[0].root(), after_fragments[0].root());
        assert_eq!(before_fragments[1].root(), after_fragments[1].root());
    }

    #[test]
    fn structured_tool_calls_converge_while_raw_receipts_remain_exact() {
        let dir = TempDir::new().unwrap();
        let first_dir = dir.path().join("first/session");
        let second_dir = dir.path().join("second/session");
        fs::create_dir_all(&first_dir).unwrap();
        fs::create_dir_all(&second_dir).unwrap();
        let first_path = first_dir.join("transcript_full.jsonl");
        let second_path = second_dir.join("transcript_full.jsonl");
        let first = r#"{"source":"SYSTEM","type":"TOOL_CALL","tool_calls":[{"name":"x","input":{"b":2,"a":1}}]}"#;
        let second = r#"{ "tool_calls": [ { "input": { "a": 1, "b": 2 }, "name": "x" } ], "type": "TOOL_CALL", "source": "SYSTEM" }"#;
        fs::write(&first_path, first).unwrap();
        fs::write(&second_path, second).unwrap();
        assert_eq!(
            parse_file(&first_path).unwrap()[0].raw_record.as_ref(),
            first.as_bytes()
        );
        assert_eq!(
            parse_file(&second_path).unwrap()[0].raw_record.as_ref(),
            second.as_bytes()
        );

        let mut first_fragments = Vec::new();
        project_path(&first_path, |projected| {
            first_fragments.push(projected.fragment);
            Ok(())
        })
        .unwrap();
        let mut second_fragments = Vec::new();
        project_path(&second_path, |projected| {
            second_fragments.push(projected.fragment);
            Ok(())
        })
        .unwrap();

        assert_eq!(first_fragments.len(), 1);
        assert_eq!(second_fragments.len(), 1);
        assert_ne!(
            first_fragments[0].root(),
            second_fragments[0].root(),
            "exactly different source records retain distinct receipt identities"
        );
        let first_semantics = semantic_identity(&first_fragments[0]);
        let second_semantics = semantic_identity(&second_fragments[0]);
        assert_eq!(first_semantics, second_semantics);
        assert_eq!(first_semantics.1.len(), 1);
    }
}
