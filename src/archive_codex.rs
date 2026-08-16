//! Streaming projection of one Codex app-server rollout onto Archive's
//! canonical block DAG.
//!
//! Codex writes several overlapping views of a turn. `event_msg` user and
//! agent messages are the visible dialogue stream; `response_item/message`
//! mirrors those messages while also carrying harness-only context. This
//! adapter projects the visible event stream exactly once and contracts every
//! other record. Tool and reasoning exhaust remain in the exact rollout and
//! can become additional modalities in a later, independently testable cut.
//!
//! A live rollout is frozen at its last newline-terminated record. Both passes
//! hash that fixed prefix, so appends are harmless and mutation of already
//! observed bytes aborts before `ArchiveImportWriter` can publish its COMMIT.
//! The implementation never materializes the rollout: the active root file is
//! already larger than a gigabyte, while its visible dialogue is only a few
//! megabytes.

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use hifitime::Epoch;
use memchr::memmem;
use serde_json::{Map, Value as JsonValue};
use triblespace::core::inline::encodings::time::NsTAIInterval;
use triblespace::core::inline::{Inline, TryToInline};
use triblespace::core::trible::Fragment;
use triblespace::prelude::*;

use crate::schemas::blockdag as schema;
use crate::{blockdag, files};

/// Observable projection accounting. Non-dialogue records are contracted, not
/// silently mistaken for additional messages.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProjectionStats {
    /// Non-empty, newline-terminated JSONL records in the frozen prefix.
    pub records_seen: usize,
    /// Visible user/agent source receipts emitted.
    pub source_projections: usize,
    /// Ordered content parts emitted before set-level deduplication.
    pub content_parts: usize,
    /// Telemetry, response mirrors, tool exhaust, and other non-dialogue rows.
    pub skipped_records: usize,
    /// Source timestamp strings that were present but not decodable.
    pub invalid_timestamps: usize,
    /// Data-URI assets whose bytes could not be decoded.
    pub undecodable_assets: usize,
}

/// One frozen rollout projection.
#[derive(Debug)]
pub struct ProjectedFile {
    pub source_path: PathBuf,
    pub fragment: Fragment,
    pub stats: ProjectionStats,
}

/// Result returned after the frozen source prefix reaches the sink.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProjectionSummary {
    pub files_scanned: usize,
    pub fragments_emitted: usize,
    pub frozen_bytes: u64,
    /// A concurrently written final partial record is deliberately deferred.
    pub trailing_bytes_ignored: u64,
    pub stats: ProjectionStats,
}

#[derive(Clone, Debug)]
struct PrefixPlan {
    session_id: String,
    complete_bytes: u64,
    trailing_bytes: u64,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct LineScan {
    complete_bytes: u64,
    records_seen: usize,
    digest: [u8; 32],
}

struct Projector<'a> {
    session_id: &'a str,
    source_path: &'a Path,
    current_model: Option<String>,
    previous_block: Option<Id>,
    previous_projection: Option<Id>,
    fragment: Fragment,
    stats: ProjectionStats,
}

/// Project one explicit Codex rollout file.
///
/// Recursive session-directory ingestion is intentionally absent: Codex child
/// rollouts replay large parent prefixes, and a normal local installation can
/// contain hundreds of gigabytes of them. Callers choose each lived stream
/// deliberately.
pub fn project_path<F>(path: &Path, mut emit: F) -> Result<ProjectionSummary>
where
    F: FnMut(ProjectedFile) -> Result<()>,
{
    if path.is_dir() {
        bail!(
            "Codex Archive import requires one explicit rollout JSONL file; recursive session-directory ingestion is intentionally unsupported"
        );
    }

    let plan = plan_prefix(path)?;
    let mut projector = Projector {
        session_id: &plan.session_id,
        source_path: path,
        current_model: None,
        previous_block: None,
        previous_projection: None,
        fragment: Fragment::empty(),
        stats: ProjectionStats::default(),
    };
    let projected = scan_prefix(path, plan.complete_bytes, |line, raw| {
        projector.project_record(line, raw)
    })?;
    if projected.digest != plan.digest {
        bail!(
            "Codex rollout {} changed inside its frozen prefix between identity pre-scan and projection",
            path.display()
        );
    }
    projector.stats.records_seen = projected.records_seen;

    let stats = projector.stats;
    let mut summary = ProjectionSummary {
        files_scanned: 1,
        frozen_bytes: plan.complete_bytes,
        trailing_bytes_ignored: plan.trailing_bytes,
        stats,
        ..ProjectionSummary::default()
    };
    if !projector.fragment.facts().is_empty() {
        emit(ProjectedFile {
            source_path: path.to_path_buf(),
            fragment: projector.fragment,
            stats,
        })?;
        summary.fragments_emitted = 1;
    }
    Ok(summary)
}

fn plan_prefix(path: &Path) -> Result<PrefixPlan> {
    let source_len = File::open(path)
        .with_context(|| format!("open Codex rollout {}", path.display()))?
        .metadata()
        .with_context(|| format!("stat Codex rollout {}", path.display()))?
        .len();
    let mut session_id = None;
    let scan = scan_prefix(path, source_len, |_line, raw| {
        if !contains(raw, b"\"session_meta\"") {
            return Ok(());
        }
        let record = parse_record(raw, path)?;
        if record.get("type").and_then(JsonValue::as_str) != Some("session_meta") {
            return Ok(());
        }
        let payload = required_object(&record, "payload", "Codex session_meta")?;
        let id = consistent_session_id(payload)?;
        match &session_id {
            Some(previous) if previous != &id => bail!(
                "Codex rollout {} contains conflicting session ids {:?} and {:?}",
                path.display(),
                previous,
                id
            ),
            Some(_) => {}
            None => session_id = Some(id),
        }
        Ok(())
    })?;
    let session_id = session_id.ok_or_else(|| {
        anyhow!(
            "Codex rollout {} has no stable session_meta.payload.id/session_id in its complete prefix",
            path.display()
        )
    })?;
    Ok(PrefixPlan {
        session_id,
        complete_bytes: scan.complete_bytes,
        trailing_bytes: source_len.saturating_sub(scan.complete_bytes),
        digest: scan.digest,
    })
}

fn scan_prefix<F>(path: &Path, byte_limit: u64, mut visit: F) -> Result<LineScan>
where
    F: FnMut(u64, &[u8]) -> Result<()>,
{
    let file =
        File::open(path).with_context(|| format!("open Codex rollout {}", path.display()))?;
    let actual_len = file
        .metadata()
        .with_context(|| format!("stat Codex rollout {}", path.display()))?
        .len();
    if actual_len < byte_limit {
        bail!(
            "Codex rollout {} shrank from frozen length {byte_limit} to {actual_len}",
            path.display()
        );
    }
    let mut reader = BufReader::new(file.take(byte_limit));
    let mut buffer = Vec::new();
    let mut line = 0u64;
    let mut complete_bytes = 0u64;
    let mut records_seen = 0usize;
    let mut digest = blake3::Hasher::new();
    loop {
        buffer.clear();
        let read = reader
            .read_until(b'\n', &mut buffer)
            .with_context(|| format!("read Codex rollout {}", path.display()))?;
        if read == 0 {
            break;
        }
        if !buffer.ends_with(b"\n") {
            break;
        }
        line = line
            .checked_add(1)
            .ok_or_else(|| anyhow!("Codex rollout has more than u64::MAX lines"))?;
        complete_bytes = complete_bytes
            .checked_add(u64::try_from(read).expect("one read length fits u64"))
            .ok_or_else(|| anyhow!("Codex rollout complete prefix exceeds u64 bytes"))?;
        // Preserve every source byte except the JSONL LF delimiter. Parsing
        // accepts surrounding JSON whitespace, but exact source receipts and
        // the frozen-prefix digest must still distinguish it.
        let raw = &buffer[..buffer.len() - 1];
        hash_record(&mut digest, raw);
        if trim_ascii_whitespace(raw).is_empty() {
            continue;
        }
        records_seen += 1;
        visit(line, raw)?;
    }
    Ok(LineScan {
        complete_bytes,
        records_seen,
        digest: *digest.finalize().as_bytes(),
    })
}

impl Projector<'_> {
    fn project_record(&mut self, line: u64, raw: &[u8]) -> Result<()> {
        if contains(raw, b"\"turn_context\"") {
            let record = parse_record(raw, self.source_path)?;
            if record.get("type").and_then(JsonValue::as_str) == Some("turn_context") {
                self.current_model = record
                    .get("payload")
                    .and_then(JsonValue::as_object)
                    .and_then(|payload| payload.get("model"))
                    .and_then(JsonValue::as_str)
                    .filter(|model| !model.trim().is_empty())
                    .map(str::to_owned);
                self.stats.skipped_records += 1;
                return Ok(());
            }
        }

        if !contains(raw, b"\"event_msg\"") {
            self.stats.skipped_records += 1;
            return Ok(());
        }
        let record = parse_record(raw, self.source_path)?;
        if record.get("type").and_then(JsonValue::as_str) != Some("event_msg") {
            self.stats.skipped_records += 1;
            return Ok(());
        }
        let payload = required_object(&record, "payload", "Codex event_msg")?;
        let (direction, raw_role) = match payload.get("type").and_then(JsonValue::as_str) {
            Some("user_message") => (schema::content_fact::direction::IN, "user_message"),
            Some("agent_message") => (schema::content_fact::direction::OUT, "agent_message"),
            _ => {
                self.stats.skipped_records += 1;
                return Ok(());
            }
        };

        let parts = project_message_parts(payload, direction, &mut self.stats)?;
        if parts.exports().next().is_none() {
            self.stats.skipped_records += 1;
            return Ok(());
        }

        // Codex child rollouts replay inherited response items while rewriting
        // their top-level observation time. Time therefore belongs to the
        // exact source receipt, not to the shared semantic block identity.
        let block = blockdag::block(self.previous_block, None, parts)?;
        let block_id = block
            .root()
            .expect("canonical block constructor returns one root");
        let locator = format!("{}/line/{line}", self.session_id);
        let projection = blockdag::source_projection(
            schema::source_projection::SOURCE_CODEX,
            locator,
            raw.to_vec(),
            block,
        )?;
        let source_timestamp = record
            .get("timestamp")
            .and_then(JsonValue::as_str)
            .and_then(|value| match parse_iso_timestamp(value) {
                Some(timestamp) => Some(timestamp),
                None => {
                    self.stats.invalid_timestamps += 1;
                    None
                }
            })
            .and_then(epoch_interval);
        let projection = blockdag::annotate_source_projection(
            projection,
            blockdag::ProjectionAnnotations {
                semantic_predecessor_support: self.previous_projection.into_iter().collect(),
                source_timestamp,
                raw_role: Some(raw_role.to_owned()),
                raw_model: self.current_model.clone(),
                source_path: Some(self.source_path.to_string_lossy().into_owned()),
                ..blockdag::ProjectionAnnotations::default()
            },
        )?;
        let projection_id = projection
            .root()
            .expect("canonical source-projection constructor returns one root");
        self.fragment += projection;
        self.previous_block = Some(block_id);
        self.previous_projection = Some(projection_id);
        self.stats.source_projections += 1;
        Ok(())
    }
}

fn project_message_parts(
    payload: &Map<String, JsonValue>,
    direction: Id,
    stats: &mut ProjectionStats,
) -> Result<Fragment> {
    let mut parts = Fragment::empty();
    let mut ordinal = 0u64;
    if let Some(message) = payload
        .get("message")
        .and_then(JsonValue::as_str)
        .filter(|message| !message.trim().is_empty())
    {
        push_part(
            &mut parts,
            &mut ordinal,
            blockdag::text_fact(
                schema::content_fact::modality::TEXT,
                direction,
                message.to_owned(),
            )?,
            stats,
        )?;
    }

    for pointer in pointers(payload, &["images", "local_images"]) {
        if let Some(fact) = project_asset(
            &pointer,
            schema::content_fact::modality::IMAGE,
            direction,
            stats,
        )? {
            push_part(&mut parts, &mut ordinal, fact, stats)?;
        }
    }
    for pointer in pointers(payload, &["audio", "local_audio"]) {
        if let Some(fact) = project_asset(
            &pointer,
            schema::content_fact::modality::AUDIO,
            direction,
            stats,
        )? {
            push_part(&mut parts, &mut ordinal, fact, stats)?;
        }
    }
    Ok(parts)
}

fn push_part(
    parts: &mut Fragment,
    ordinal: &mut u64,
    fact: Fragment,
    stats: &mut ProjectionStats,
) -> Result<()> {
    *parts += blockdag::content_part(*ordinal, fact, None)?;
    *ordinal = ordinal
        .checked_add(1)
        .ok_or_else(|| anyhow!("Codex message has more than u64::MAX content parts"))?;
    stats.content_parts += 1;
    Ok(())
}

fn pointers(payload: &Map<String, JsonValue>, fields: &[&str]) -> Vec<String> {
    let mut pointers = Vec::new();
    for field in fields {
        let Some(values) = payload.get(*field).and_then(JsonValue::as_array) else {
            continue;
        };
        for value in values {
            let pointer = value.as_str().or_else(|| {
                value.as_object().and_then(|object| {
                    ["image_url", "audio_url", "url", "path"]
                        .into_iter()
                        .find_map(|key| object.get(key).and_then(JsonValue::as_str))
                })
            });
            if let Some(pointer) = pointer.filter(|pointer| !pointer.trim().is_empty()) {
                pointers.push(pointer.to_owned());
            }
        }
    }
    pointers
}

fn project_asset(
    pointer: &str,
    modality: Id,
    direction: Id,
    stats: &mut ProjectionStats,
) -> Result<Option<Fragment>> {
    if let Some(data) = pointer.strip_prefix("data:") {
        let Some((header, payload)) = data.split_once(',') else {
            stats.undecodable_assets += 1;
            return Ok(None);
        };
        if !header
            .split(';')
            .any(|component| component.eq_ignore_ascii_case("base64"))
        {
            stats.undecodable_assets += 1;
            return Ok(None);
        }
        let bytes = match BASE64_STANDARD.decode(payload.as_bytes()) {
            Ok(bytes) => bytes,
            Err(_) => {
                stats.undecodable_assets += 1;
                return Ok(None);
            }
        };
        let media_type = header
            .split(';')
            .next()
            .filter(|value| !value.trim().is_empty())
            .map(files::normalize_media_type_or_default)
            .unwrap_or_else(|| files::DEFAULT_MEDIA_TYPE.to_owned());
        return Ok(Some(blockdag::blob_fact(
            modality,
            direction,
            bytes,
            &media_type,
        )?));
    }

    Ok(Some(blockdag::asset_pointer_fact(
        modality,
        direction,
        schema::source_projection::SOURCE_CODEX,
        pointer.to_owned(),
        None,
        None,
    )?))
}

fn consistent_session_id(payload: &Map<String, JsonValue>) -> Result<String> {
    let id = payload
        .get("id")
        .and_then(JsonValue::as_str)
        .filter(|value| !value.trim().is_empty());
    let session_id = payload
        .get("session_id")
        .and_then(JsonValue::as_str)
        .filter(|value| !value.trim().is_empty());
    if let (Some(id), Some(session_id)) = (id, session_id) {
        if id != session_id {
            bail!("Codex session_meta payload id {id:?} disagrees with session_id {session_id:?}");
        }
    }
    id.or(session_id)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("Codex session_meta payload has neither id nor session_id"))
}

fn required_object<'a>(
    value: &'a JsonValue,
    field: &str,
    context: &str,
) -> Result<&'a Map<String, JsonValue>> {
    value
        .get(field)
        .and_then(JsonValue::as_object)
        .ok_or_else(|| anyhow!("{context} has no object field {field:?}"))
}

fn parse_record(raw: &[u8], source_path: &Path) -> Result<JsonValue> {
    serde_json::from_slice(raw)
        .with_context(|| format!("parse candidate Codex record in {}", source_path.display()))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    memmem::find(haystack, needle).is_some()
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn hash_record(digest: &mut blake3::Hasher, raw: &[u8]) {
    let len = u64::try_from(raw.len()).expect("one JSONL record fits u64 bytes");
    digest.update(&len.to_le_bytes());
    digest.update(raw);
}

fn parse_iso_timestamp(value: &str) -> Option<Epoch> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        value.parse().ok()
    }
}

fn epoch_interval(epoch: Epoch) -> Option<Inline<NsTAIInterval>> {
    (epoch, epoch).try_to_inline().ok()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;

    use tempfile::TempDir;
    use triblespace::core::metadata;
    use triblespace::core::repo::pile::{Pile, PileReader};
    use triblespace::core::repo::BlobStore;
    use triblespace::macros::{find, pattern};

    use super::*;

    const ROLLOUT: &str = concat!(
        r#"{"timestamp":"2026-08-16T08:00:00.000Z","type":"session_meta","payload":{"id":"thread-1","session_id":"thread-1"}}"#,
        "\n",
        r#"{"timestamp":"2026-08-16T08:00:00.001Z","type":"turn_context","payload":{"model":"gpt-test"}}"#,
        "\n",
        r#"{"timestamp":"2026-08-16T08:00:00.002Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}}"#,
        "\n",
        r#"{"timestamp":"2026-08-16T08:00:00.003Z","type":"event_msg","payload":{"type":"user_message","message":"hello","images":[],"local_images":["/moved/reference.png"]}}"#,
        "\n",
        r#"{"timestamp":"2026-08-16T08:00:01.000Z","type":"event_msg","payload":{"type":"agent_message","phase":"commentary","message":"hi"}}"#,
        "\n",
        r#"{"timestamp":"2026-08-16T08:00:01.001Z","type":"response_item","payload":{"type":"message","id":"msg_1","role":"assistant","content":[{"type":"output_text","text":"hi"}]}}"#,
        "\n",
        r#"{"timestamp":"2026-08-16T08:00:01.002Z","type":"event_msg","payload":{"type":"token_count"}}"#,
        "\n",
    );

    fn project_text(text: &str, name: &str) -> (TempDir, ProjectionSummary, Fragment) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(name);
        fs::write(&path, text).unwrap();
        let mut fragment = Fragment::empty();
        let summary = project_path(&path, |projected| {
            fragment += projected.fragment;
            Ok(())
        })
        .unwrap();
        (directory, summary, fragment)
    }

    fn empty_reader() -> (TempDir, PileReader) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("empty.pile");
        File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        let reader = pile.reader().unwrap();
        pile.close().unwrap();
        (directory, reader)
    }

    fn ids_with_tag(fragment: &Fragment, tag: Id) -> BTreeSet<Id> {
        find!(
            entity: Id,
            pattern!(fragment.facts(), [{ ?entity @ metadata::tag: &tag }])
        )
        .collect()
    }

    #[test]
    fn visible_events_are_projected_once_and_response_mirrors_are_contracted() {
        let (_directory, summary, fragment) = project_text(ROLLOUT, "rollout.jsonl");
        assert_eq!(summary.stats.source_projections, 2);
        assert_eq!(summary.stats.content_parts, 3);
        assert_eq!(summary.stats.records_seen, 7);
        assert_eq!(summary.stats.skipped_records, 5);
        assert_eq!(
            ids_with_tag(&fragment, schema::source_projection::KIND).len(),
            2
        );
        assert_eq!(ids_with_tag(&fragment, schema::block::KIND).len(), 2);

        let (_directory, reader) = empty_reader();
        let (_, validation) =
            blockdag::validate_catalog_union(&reader, &TribleSet::new(), &fragment).unwrap();
        assert_eq!(validation, blockdag::CatalogValidation::Accepted);

        assert_eq!(
            find!(
                block: Id,
                pattern!(fragment.facts(), [{
                    ?block @ schema::block::previous: _?previous
                }])
            )
            .count(),
            1
        );
        assert_eq!(
            find!(
                projection: Id,
                pattern!(fragment.facts(), [{
                    ?projection @ schema::source_projection::source_timestamp: _?timestamp
                }])
            )
            .count(),
            2
        );
        assert!(!exists!(pattern!(fragment.facts(), [{
            _?block @ schema::block::timestamp: _?timestamp
        }])));
    }

    #[test]
    fn append_and_source_move_preserve_every_existing_intrinsic_identity() {
        let (_first_dir, _, first) = project_text(ROLLOUT, "first.jsonl");
        let appended = format!(
            "{ROLLOUT}{}\n",
            r#"{"timestamp":"2026-08-16T08:00:02.000Z","type":"event_msg","payload":{"type":"user_message","message":"again"}}"#
        );
        let (_second_dir, _, appended) = project_text(&appended, "second.jsonl");
        assert!(ids_with_tag(&first, schema::block::KIND)
            .is_subset(&ids_with_tag(&appended, schema::block::KIND)));
        assert!(ids_with_tag(&first, schema::source_projection::KIND)
            .is_subset(&ids_with_tag(&appended, schema::source_projection::KIND)));

        let (_moved_dir, _, moved) = project_text(ROLLOUT, "moved.jsonl");
        assert_eq!(
            ids_with_tag(&first, schema::block::KIND),
            ids_with_tag(&moved, schema::block::KIND)
        );
        assert_eq!(
            ids_with_tag(&first, schema::source_projection::KIND),
            ids_with_tag(&moved, schema::source_projection::KIND)
        );
        assert_ne!(
            first.facts(),
            moved.facts(),
            "the movable path remains additive source evidence"
        );

        let spaced_source = ROLLOUT.replace(
            r#"{"timestamp":"2026-08-16T08:00:00.003Z","type":"event_msg""#,
            r#"  {"timestamp":"2026-08-16T08:00:00.003Z","type":"event_msg""#,
        );
        let (_spaced_dir, _, spaced) = project_text(&spaced_source, "spaced.jsonl");
        assert_eq!(
            ids_with_tag(&first, schema::block::KIND),
            ids_with_tag(&spaced, schema::block::KIND),
            "JSON whitespace is not semantic block identity"
        );
        assert_ne!(
            ids_with_tag(&first, schema::source_projection::KIND),
            ids_with_tag(&spaced, schema::source_projection::KIND),
            "JSON whitespace remains exact source evidence"
        );
    }

    #[test]
    fn partial_live_tail_is_deferred_and_missing_session_identity_is_rejected() {
        let partial = format!("{ROLLOUT}{{\"type\":\"event_msg\"");
        let (_directory, summary, fragment) = project_text(&partial, "live.jsonl");
        assert!(summary.trailing_bytes_ignored > 0);
        assert_eq!(
            ids_with_tag(&fragment, schema::source_projection::KIND).len(),
            2
        );

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("missing-meta.jsonl");
        fs::write(
            &path,
            concat!(
                r#"{"timestamp":"2026-08-16T08:00:00Z","type":"event_msg","payload":{"type":"user_message","message":"orphan"}}"#,
                "\n"
            ),
        )
        .unwrap();
        let error = project_path(&path, |_| Ok(())).unwrap_err();
        assert!(error.to_string().contains("no stable session_meta"));
    }
}
