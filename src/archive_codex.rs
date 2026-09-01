//! Streaming projection of one Codex app-server rollout onto Archive's
//! canonical block DAG.
//!
//! Codex writes several overlapping views of a turn. `event_msg` user and
//! agent messages are the visible dialogue stream, while `agent_reasoning`
//! carries usable model reasoning. `response_item/message` mirrors dialogue
//! while also carrying harness-only context. This adapter projects the useful
//! event stream exactly once. Everything else, including encrypted reasoning,
//! tool exhaust, and telemetry, remains losslessly available through one exact
//! source snapshot over fixed-size content-addressed chunks. Snapshots are
//! disjoint from dialogue projections, so later semantic interpretations do
//! not pollute the current DAG or require the live source. Stable byte-offset
//! chunks also make growing-log reimports append-idempotent instead of
//! retaining overlapping whole-file payloads.
//!
//! A live rollout is planned at its last newline-terminated semantic record,
//! while every currently observed byte is copied into a tempfile-backed,
//! read-only snapshot. Appends are harmless and mutation of already observed
//! bytes aborts before `ArchiveImportWriter` can publish its COMMIT. The
//! implementation never heap-materializes the rollout or creates a
//! trible per telemetry row: the active root file is already larger than a
//! gigabyte, while its visible dialogue is only a few megabytes.

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use anybytes::{Bytes, View};
use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use hifitime::Epoch;
use memchr::{memchr_iter, memmem};
use triblespace::core::import::scanner as sc;
use triblespace::core::inline::encodings::time::NsTAIInterval;
use triblespace::core::inline::{Inline, TryToInline};
use triblespace::core::trible::Fragment;
use triblespace::prelude::*;

use crate::schemas::blockdag as schema;
use crate::{archive_source, blockdag, files};

/// Observable projection accounting. Non-dialogue records are contracted, not
/// silently mistaken for additional messages.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProjectionStats {
    /// Non-empty, newline-terminated JSONL records in the frozen prefix.
    pub records_seen: usize,
    /// Exact source projections emitted for semantic event rows.
    pub source_projections: usize,
    /// Exact frozen source versions retained independently of semantic rows.
    pub source_snapshots: usize,
    /// Content-addressed byte ranges referenced by those snapshots.
    pub raw_chunks: usize,
    /// Ordered content parts emitted before set-level deduplication.
    pub content_parts: usize,
    /// Telemetry, response mirrors, tool exhaust, and other rows retained by
    /// the frozen-prefix snapshot rather than projected as semantic blocks.
    pub skipped_records: usize,
    /// Source timestamp strings that were present but not decodable.
    pub invalid_timestamps: usize,
    /// Data-URI assets whose bytes could not be decoded.
    pub undecodable_assets: usize,
}

impl ProjectionStats {
    fn since(self, earlier: Self) -> Self {
        Self {
            records_seen: self.records_seen.saturating_sub(earlier.records_seen),
            source_projections: self
                .source_projections
                .saturating_sub(earlier.source_projections),
            source_snapshots: self
                .source_snapshots
                .saturating_sub(earlier.source_snapshots),
            raw_chunks: self.raw_chunks.saturating_sub(earlier.raw_chunks),
            content_parts: self.content_parts.saturating_sub(earlier.content_parts),
            skipped_records: self.skipped_records.saturating_sub(earlier.skipped_records),
            invalid_timestamps: self
                .invalid_timestamps
                .saturating_sub(earlier.invalid_timestamps),
            undecodable_assets: self
                .undecodable_assets
                .saturating_sub(earlier.undecodable_assets),
        }
    }
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
    /// A final non-newline record retained exactly but deferred semantically.
    pub trailing_bytes_ignored: u64,
    pub stats: ProjectionStats,
}

#[derive(Clone, Debug)]
struct PrefixPlan {
    session_id: String,
    observed_bytes: u64,
    complete_bytes: u64,
    trailing_bytes: u64,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct LineScan {
    complete_bytes: u64,
    records_seen: usize,
}

struct Projector<'a> {
    session_id: &'a str,
    source_path: &'a Path,
    current_model: Option<String>,
    previous_block: Option<Id>,
    previous_projection: Option<Id>,
    stats: ProjectionStats,
}

#[derive(Default)]
struct CodexRecord {
    record_type: Option<View<str>>,
    timestamp: Option<View<str>>,
    payload: Option<CodexPayload>,
}

#[derive(Default)]
struct CodexPayload {
    payload_type: Option<View<str>>,
    id: Option<View<str>>,
    session_id: Option<View<str>>,
    model: Option<View<str>>,
    message: Option<View<str>>,
    text: Option<View<str>>,
    images: Vec<View<str>>,
    local_images: Vec<View<str>>,
    audio: Vec<View<str>>,
    local_audio: Vec<View<str>>,
}

/// Project one explicit Codex rollout file.
///
/// Recursive session-directory ingestion is intentionally absent: Codex child
/// rollouts replay large parent prefixes, and a normal local installation can
/// contain hundreds of gigabytes of them. Callers choose each lived stream
/// deliberately. Semantic records are emitted as bounded fragments as soon as
/// they are projected from the immutable snapshot. Final bounded fragments
/// cover the entire exact frozen prefix without creating one receipt per
/// telemetry event. Callers must stage every emitted fragment and publish only
/// after this function returns successfully.
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
    let frozen = archive_source::freeze_prefix(path, plan.observed_bytes)?;
    if frozen.digest != plan.digest {
        bail!(
            "Codex rollout {} changed inside its planned prefix before projection",
            path.display()
        );
    }
    let mut projector = Projector {
        session_id: &plan.session_id,
        source_path: path,
        current_model: None,
        previous_block: None,
        previous_projection: None,
        stats: ProjectionStats::default(),
    };
    let mut fragments_emitted = 0usize;
    let projected = scan_frozen_prefix(&frozen.bytes, |line, raw| {
        let before = projector.stats;
        if let Some(fragment) = projector.project_record(line, raw)? {
            let mut record_stats = projector.stats.since(before);
            record_stats.records_seen = 1;
            emit(ProjectedFile {
                source_path: path.to_path_buf(),
                fragment,
                stats: record_stats,
            })?;
            fragments_emitted += 1;
        }
        Ok(())
    })?;
    if projected.complete_bytes != plan.complete_bytes {
        bail!(
            "Codex rollout {} frozen-prefix length changed during projection",
            path.display()
        );
    }
    projector.stats.records_seen = projected.records_seen;

    let before_snapshot = projector.stats;
    let (snapshot, raw_chunks) = archive_source::source_snapshot_fragment(
        schema::source_projection::SOURCE_CODEX,
        &format!("session/{}", plan.session_id),
        path,
        &frozen.bytes,
    )?;
    projector.stats.source_snapshots += 1;
    projector.stats.raw_chunks += raw_chunks;
    emit(ProjectedFile {
        source_path: path.to_path_buf(),
        fragment: snapshot,
        stats: projector.stats.since(before_snapshot),
    })?;
    fragments_emitted += 1;

    let stats = projector.stats;
    let summary = ProjectionSummary {
        files_scanned: 1,
        fragments_emitted,
        frozen_bytes: plan.observed_bytes,
        trailing_bytes_ignored: plan.trailing_bytes,
        stats,
        ..ProjectionSummary::default()
    };
    Ok(summary)
}

fn plan_prefix(path: &Path) -> Result<PrefixPlan> {
    let source_len = File::open(path)
        .with_context(|| format!("open Codex rollout {}", path.display()))?
        .metadata()
        .with_context(|| format!("stat Codex rollout {}", path.display()))?
        .len();
    let mut session_id = None;
    let (scan, digest) = scan_prefix(path, source_len, |_line, raw| {
        if !contains(raw, b"\"session_meta\"") {
            return Ok(());
        }
        // The live planning pass owns only candidate session metadata rows;
        // the large immutable snapshot is created immediately afterwards.
        let record = parse_record(Bytes::from_source(raw.to_vec()), path)?;
        if record.record_type.as_deref() != Some("session_meta") {
            return Ok(());
        }
        let payload = record
            .payload
            .as_ref()
            .ok_or_else(|| anyhow!("Codex session_meta has no object field \"payload\""))?;
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
        observed_bytes: source_len,
        complete_bytes: scan.complete_bytes,
        trailing_bytes: source_len.saturating_sub(scan.complete_bytes),
        digest,
    })
}

fn scan_prefix<F>(path: &Path, byte_limit: u64, mut visit: F) -> Result<(LineScan, [u8; 32])>
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
        // Retain/hash the entire observed file. A final non-newline row is
        // exact source evidence even though it is not yet a semantic record.
        digest.update(&buffer);
        if !buffer.ends_with(b"\n") {
            break;
        }
        line = line
            .checked_add(1)
            .ok_or_else(|| anyhow!("Codex rollout has more than u64::MAX lines"))?;
        complete_bytes = complete_bytes
            .checked_add(u64::try_from(read).expect("one read length fits u64"))
            .ok_or_else(|| anyhow!("Codex rollout complete prefix exceeds u64 bytes"))?;
        let raw = &buffer[..buffer.len() - 1];
        if trim_ascii_whitespace(raw).is_empty() {
            continue;
        }
        records_seen += 1;
        visit(line, raw)?;
    }
    Ok((
        LineScan {
            complete_bytes,
            records_seen,
        },
        *digest.finalize().as_bytes(),
    ))
}

/// Scan the immutable snapshot without allocating a buffer for every JSONL
/// row. Each callback receives a zero-copy view backed by the frozen mapping.
fn scan_frozen_prefix<F>(frozen: &Bytes, mut visit: F) -> Result<LineScan>
where
    F: FnMut(u64, Bytes) -> Result<()>,
{
    let mut line = 0u64;
    let mut start = 0usize;
    let mut records_seen = 0usize;
    for newline in memchr_iter(b'\n', frozen.as_ref()) {
        line = line
            .checked_add(1)
            .ok_or_else(|| anyhow!("Codex rollout has more than u64::MAX lines"))?;
        let raw = frozen.slice(start..newline);
        start = newline + 1;
        if trim_ascii_whitespace(raw.as_ref()).is_empty() {
            continue;
        }
        records_seen += 1;
        visit(line, raw)?;
    }
    Ok(LineScan {
        complete_bytes: u64::try_from(start).expect("frozen complete prefix length fits u64"),
        records_seen,
    })
}

impl Projector<'_> {
    fn project_record(&mut self, line: u64, raw: Bytes) -> Result<Option<Fragment>> {
        if contains(raw.as_ref(), b"\"turn_context\"") {
            let record = parse_record(raw.clone(), self.source_path)?;
            if record.record_type.as_deref() == Some("turn_context") {
                self.current_model = record
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.model.as_deref())
                    .filter(|model| !model.trim().is_empty())
                    .map(ToString::to_string);
                self.stats.skipped_records += 1;
                return Ok(None);
            }
        }

        if !contains(raw.as_ref(), b"\"event_msg\"") {
            self.stats.skipped_records += 1;
            return Ok(None);
        }
        let record = parse_record(raw.clone(), self.source_path)?;
        if record.record_type.as_deref() != Some("event_msg") {
            self.stats.skipped_records += 1;
            return Ok(None);
        }
        let payload = record
            .payload
            .as_ref()
            .ok_or_else(|| anyhow!("Codex event_msg has no object field \"payload\""))?;
        let (parts, raw_role) = match payload.payload_type.as_deref() {
            Some("user_message") => (
                project_message_parts(
                    payload,
                    schema::content_fact::direction::IN,
                    &mut self.stats,
                )?,
                "user_message",
            ),
            Some("agent_message") => (
                project_message_parts(
                    payload,
                    schema::content_fact::direction::OUT,
                    &mut self.stats,
                )?,
                "agent_message",
            ),
            Some("agent_reasoning") => (
                project_reasoning_parts(payload, &mut self.stats)?,
                "agent_reasoning",
            ),
            _ => {
                self.stats.skipped_records += 1;
                return Ok(None);
            }
        };

        if parts.exports().next().is_none() {
            self.stats.skipped_records += 1;
            return Ok(None);
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
            raw,
            block,
        )?;
        let source_timestamp = record
            .timestamp
            .as_deref()
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
        self.previous_block = Some(block_id);
        self.previous_projection = Some(projection_id);
        self.stats.source_projections += 1;
        Ok(Some(projection))
    }
}

fn project_reasoning_parts(
    payload: &CodexPayload,
    stats: &mut ProjectionStats,
) -> Result<Fragment> {
    let mut parts = Fragment::empty();
    let Some(text) = payload
        .text
        .as_deref()
        .filter(|text| !text.trim().is_empty())
    else {
        return Ok(parts);
    };
    let mut ordinal = 0;
    push_part(
        &mut parts,
        &mut ordinal,
        blockdag::text_fact(
            schema::content_fact::modality::THINKING,
            schema::content_fact::direction::OUT,
            text,
        )?,
        stats,
    )?;
    Ok(parts)
}

fn project_message_parts(
    payload: &CodexPayload,
    direction: Id,
    stats: &mut ProjectionStats,
) -> Result<Fragment> {
    let mut parts = Fragment::empty();
    let mut ordinal = 0u64;
    if let Some(message) = payload
        .message
        .as_deref()
        .filter(|message| !message.trim().is_empty())
    {
        push_part(
            &mut parts,
            &mut ordinal,
            blockdag::text_fact(schema::content_fact::modality::TEXT, direction, message)?,
            stats,
        )?;
    }

    for pointer in payload.images.iter().chain(&payload.local_images) {
        if let Some(fact) = project_asset(
            pointer,
            schema::content_fact::modality::IMAGE,
            direction,
            stats,
        )? {
            push_part(&mut parts, &mut ordinal, fact, stats)?;
        }
    }
    for pointer in payload.audio.iter().chain(&payload.local_audio) {
        if let Some(fact) = project_asset(
            pointer,
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

fn consistent_session_id(payload: &CodexPayload) -> Result<String> {
    let id = payload
        .id
        .as_deref()
        .filter(|value| !value.trim().is_empty());
    let session_id = payload
        .session_id
        .as_deref()
        .filter(|value| !value.trim().is_empty());
    // `id` and `session_id` are DIFFERENT THINGS in the post-2026-07 rollout
    // format, and requiring them equal refused every recent Codex session.
    // MEASURED 2026-09-01 over 8,265 rollouts in ~/.codex/sessions/2026:
    //
    //   2026-01..06   0% refused   (older shape: `id` only, no session_id)
    //   2026-07..09  99% refused   (3,161 files carrying both)
    //
    // That is a clean format cutover, not a data defect — and it meant the
    // Codex half of the archive silently stopped ingesting in July while
    // nothing announced it. Exactly the failure the archive epic exists to
    // prevent (compass 9d9768c9: "the absence of a transcript is
    // indistinguishable from its never having existed").
    //
    // `id` identifies THIS ROLLOUT and matches the filename; `session_id`
    // identifies the CONVERSATION and is stable across resumes. The archive's
    // unit is a conversation — a DAG whose complete ancestry `archive thread`
    // walks — so `session_id` is the correct identity and must WIN. Preferring
    // `id` would shatter one resumed conversation into as many conversations
    // as it had resumes.
    session_id
        .or(id)
        .map(ToString::to_string)
        .ok_or_else(|| anyhow!("Codex session_meta payload has neither id nor session_id"))
}

fn scan_syntax(message: &str) -> sc::ScanError {
    sc::ScanError::Syntax(message.to_owned())
}

fn scan_string(bytes: &mut Bytes) -> std::result::Result<Option<View<str>>, sc::ScanError> {
    if bytes.first().copied() != Some(b'"') {
        sc::skip_value(bytes)?;
        return Ok(None);
    }
    sc::parse_string(bytes)?
        .view::<str>()
        .map(Some)
        .map_err(|_| scan_syntax("JSON string is not UTF-8"))
}

#[derive(Default)]
struct PointerFields {
    image_url: Option<View<str>>,
    audio_url: Option<View<str>>,
    url: Option<View<str>>,
    path: Option<View<str>>,
}

fn scan_pointers(bytes: &mut Bytes) -> std::result::Result<Vec<View<str>>, sc::ScanError> {
    if bytes.first().copied() != Some(b'[') {
        sc::skip_value(bytes)?;
        return Ok(Vec::new());
    }
    sc::array(bytes, Vec::new(), |mut pointers, value| {
        let pointer = match value.first().copied() {
            Some(b'"') => scan_string(value)?,
            Some(b'{') => {
                let fields = sc::object(
                    value,
                    PointerFields::default(),
                    |mut fields, key, member| {
                        let key = key
                            .view::<str>()
                            .map_err(|_| scan_syntax("JSON object key is not UTF-8"))?;
                        match key.as_ref() {
                            "image_url" => fields.image_url = scan_string(member)?,
                            "audio_url" => fields.audio_url = scan_string(member)?,
                            "url" => fields.url = scan_string(member)?,
                            "path" => fields.path = scan_string(member)?,
                            _ => sc::skip_value(member)?,
                        }
                        Ok(fields)
                    },
                )?;
                fields
                    .image_url
                    .or(fields.audio_url)
                    .or(fields.url)
                    .or(fields.path)
            }
            _ => {
                sc::skip_value(value)?;
                None
            }
        };
        if let Some(pointer) = pointer.filter(|pointer| !pointer.as_ref().trim().is_empty()) {
            pointers.push(pointer);
        }
        Ok(pointers)
    })
}

fn scan_payload(bytes: &mut Bytes) -> std::result::Result<Option<CodexPayload>, sc::ScanError> {
    if bytes.first().copied() != Some(b'{') {
        sc::skip_value(bytes)?;
        return Ok(None);
    }
    sc::object(bytes, CodexPayload::default(), |mut payload, key, value| {
        let key = key
            .view::<str>()
            .map_err(|_| scan_syntax("JSON object key is not UTF-8"))?;
        match key.as_ref() {
            "type" => payload.payload_type = scan_string(value)?,
            "id" => payload.id = scan_string(value)?,
            "session_id" => payload.session_id = scan_string(value)?,
            "model" => payload.model = scan_string(value)?,
            "message" => payload.message = scan_string(value)?,
            "text" => payload.text = scan_string(value)?,
            "images" => payload.images = scan_pointers(value)?,
            "local_images" => payload.local_images = scan_pointers(value)?,
            "audio" => payload.audio = scan_pointers(value)?,
            "local_audio" => payload.local_audio = scan_pointers(value)?,
            _ => sc::skip_value(value)?,
        }
        Ok(payload)
    })
    .map(Some)
}

fn parse_record(raw: Bytes, source_path: &Path) -> Result<CodexRecord> {
    std::str::from_utf8(raw.as_ref()).with_context(|| {
        format!(
            "parse candidate Codex record in {}: JSON is not UTF-8",
            source_path.display()
        )
    })?;
    let mut bytes = raw;
    sc::skip_ws(&mut bytes);
    if bytes.first().copied() != Some(b'{') {
        sc::skip_value(&mut bytes).with_context(|| {
            format!("parse candidate Codex record in {}", source_path.display())
        })?;
        sc::skip_ws(&mut bytes);
        if !bytes.is_empty() {
            bail!(
                "parse candidate Codex record in {}: trailing bytes after JSON value",
                source_path.display()
            );
        }
        return Ok(CodexRecord::default());
    }
    let record = sc::object(
        &mut bytes,
        CodexRecord::default(),
        |mut record, key, value| {
            let key = key
                .view::<str>()
                .map_err(|_| scan_syntax("JSON object key is not UTF-8"))?;
            match key.as_ref() {
                "type" => record.record_type = scan_string(value)?,
                "timestamp" => record.timestamp = scan_string(value)?,
                "payload" => record.payload = scan_payload(value)?,
                _ => sc::skip_value(value)?,
            }
            Ok(record)
        },
    )
    .with_context(|| format!("parse candidate Codex record in {}", source_path.display()))?;
    sc::skip_ws(&mut bytes);
    if !bytes.is_empty() {
        bail!(
            "parse candidate Codex record in {}: trailing bytes after JSON object",
            source_path.display()
        );
    }
    Ok(record)
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
    use triblespace::core::repo::pile::{Pile, PileSnapshot};
    use triblespace::core::repo::BlobStoreGet;
    use triblespace::macros::{find, pattern};
    use triblespace::prelude::blobencodings::{RawBytes, UTF8String};
    use triblespace::prelude::inlineencodings::Handle;

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
        r#"{"timestamp":"2026-08-16T08:00:00.500Z","type":"event_msg","payload":{"type":"agent_reasoning","text":"I should answer directly."}}"#,
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

    fn empty_reader() -> (TempDir, PileSnapshot) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("empty.pile");
        File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        let reader = pile.snapshot().unwrap();
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

    fn source_chunk_raws(fragment: &Fragment) -> Vec<(Id, u128, Bytes)> {
        let mut blobs = fragment.blobs().clone();
        let reader = blobs.snapshot().unwrap();
        find!(
            (
                chunk: Id,
                offset: Inline<triblespace::prelude::inlineencodings::U256BE>,
                raw: Inline<Handle<RawBytes>>
            ),
            pattern!(fragment.facts(), [
                { ?chunk @ metadata::tag: &schema::source_chunk::KIND },
                { ?chunk @ schema::source_chunk::offset: ?offset },
                { ?chunk @ schema::source_chunk::bytes: ?raw },
            ])
        )
        .map(|(chunk, offset, raw)| {
            let offset = u128::try_from_inline(&offset).unwrap();
            let raw = reader.get::<Bytes, RawBytes>(raw).unwrap();
            (chunk, offset, raw)
        })
        .collect()
    }

    fn source_chunk_for_raw(fragment: &Fragment, expected: &[u8]) -> Id {
        let matches: Vec<_> = source_chunk_raws(fragment)
            .into_iter()
            .filter_map(|(chunk, _, raw)| (raw.as_ref() == expected).then_some(chunk))
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "expected exactly one matching raw receipt"
        );
        matches[0]
    }

    fn exact_source_snapshot(fragment: &Fragment) -> Vec<u8> {
        let snapshots = ids_with_tag(fragment, schema::source_snapshot::KIND);
        assert_eq!(snapshots.len(), 1, "expected exactly one source snapshot");
        let snapshot = *snapshots.first().unwrap();
        let selected: BTreeSet<_> = find!(
            chunk: Id,
            pattern!(fragment.facts(), [{
                snapshot @ schema::source_snapshot::contains: ?chunk
            }])
        )
        .collect();
        let mut chunks = source_chunk_raws(fragment)
            .into_iter()
            .filter(|(chunk, _, _)| selected.contains(chunk))
            .collect::<Vec<_>>();
        chunks.sort_by_key(|(_, offset, _)| *offset);
        chunks
            .into_iter()
            .flat_map(|(_, _, bytes)| bytes.as_ref().to_vec())
            .collect()
    }

    fn chunked_telemetry_rollout(target_len: usize) -> String {
        let mut rollout = concat!(
            r#"{"timestamp":"2026-08-16T08:00:00Z","type":"session_meta","payload":{"id":"chunk-thread"}}"#,
            "\n"
        )
        .to_owned();
        let telemetry = concat!(
            r#"{"timestamp":"2026-08-16T08:00:01Z","type":"response_item","payload":{"type":"reasoning","encrypted_content":"opaque"}}"#,
            "\n"
        );
        for _ in 0..1_024 {
            rollout.push_str(telemetry);
        }
        let padding_prefix = r#"{"type":"response_item","padding":""#;
        let padding_suffix = "\"}\n";
        let padding = target_len
            .checked_sub(rollout.len() + padding_prefix.len() + padding_suffix.len())
            .expect("target leaves room for the final telemetry row");
        rollout.push_str(padding_prefix);
        rollout.extend(std::iter::repeat_n('x', padding));
        rollout.push_str(padding_suffix);
        assert_eq!(rollout.len(), target_len);
        rollout
    }

    #[test]
    fn visible_events_and_reasoning_are_semantic_once_with_one_exact_snapshot() {
        let (_directory, summary, fragment) = project_text(ROLLOUT, "rollout.jsonl");
        assert_eq!(summary.stats.source_projections, 3);
        assert_eq!(summary.stats.source_snapshots, 1);
        assert_eq!(summary.stats.raw_chunks, 1);
        assert_eq!(summary.stats.content_parts, 4);
        assert_eq!(summary.stats.records_seen, 8);
        assert_eq!(summary.fragments_emitted, 4);
        assert_eq!(summary.stats.skipped_records, 5);
        assert_eq!(
            ids_with_tag(&fragment, schema::source_projection::KIND).len(),
            3
        );
        assert_eq!(
            ids_with_tag(&fragment, schema::block::KIND).len(),
            3,
            "only semantic events participate in the block DAG"
        );
        assert_eq!(exact_source_snapshot(&fragment), ROLLOUT.as_bytes());

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
            2
        );
        assert_eq!(
            find!(
                projection: Id,
                pattern!(fragment.facts(), [{
                    ?projection @ schema::source_projection::semantic_predecessor_support:
                        _?previous
                }])
            )
            .count(),
            2
        );
        assert_eq!(
            find!(
                projection: Id,
                pattern!(fragment.facts(), [{
                    ?projection @ schema::source_projection::source_timestamp: _?timestamp
                }])
            )
            .count(),
            3
        );
        let thinking_payloads: Vec<Inline<Handle<UTF8String>>> = find!(
            payload: Inline<Handle<UTF8String>>,
            pattern!(fragment.facts(), [
                {
                    _?fact @ schema::content_fact::modality:
                        schema::content_fact::modality::THINKING
                },
                {
                    _?fact @ schema::content_fact::direction:
                        schema::content_fact::direction::OUT
                },
                { _?fact @ schema::content_fact::payload: ?payload }
            ])
        )
        .collect();
        assert_eq!(thinking_payloads.len(), 1);
        let mut blobs = fragment.blobs().clone();
        let blob_reader = blobs.snapshot().unwrap();
        let reasoning = blob_reader
            .get::<View<str>, UTF8String>(thinking_payloads[0])
            .unwrap();
        assert_eq!(reasoning.as_ref(), "I should answer directly.");
        assert!(!exists!(pattern!(fragment.facts(), [{
            _?block @ schema::block::timestamp: _?timestamp
        }])));
    }

    #[test]
    fn append_and_source_move_preserve_every_existing_intrinsic_identity() {
        let (_first_dir, _, first) = project_text(ROLLOUT, "first.jsonl");
        let appended_source = format!(
            "{ROLLOUT}{}\n",
            r#"{"timestamp":"2026-08-16T08:00:02.000Z","type":"event_msg","payload":{"type":"user_message","message":"again"}}"#
        );
        let (_second_dir, _, appended) = project_text(&appended_source, "second.jsonl");
        assert!(ids_with_tag(&first, schema::block::KIND)
            .is_subset(&ids_with_tag(&appended, schema::block::KIND)));
        let first_snapshot = *ids_with_tag(&first, schema::source_snapshot::KIND)
            .first()
            .unwrap();
        let appended_snapshot = *ids_with_tag(&appended, schema::source_snapshot::KIND)
            .first()
            .unwrap();
        assert_ne!(
            first_snapshot, appended_snapshot,
            "the tiny file is one growing tail"
        );
        let first_semantic = ids_with_tag(&first, schema::source_projection::KIND);
        let appended_semantic = ids_with_tag(&appended, schema::source_projection::KIND);
        assert!(first_semantic.is_subset(&appended_semantic));

        let (_moved_dir, _, moved) = project_text(ROLLOUT, "moved.jsonl");
        assert_eq!(
            ids_with_tag(&first, schema::block::KIND),
            ids_with_tag(&moved, schema::block::KIND)
        );
        assert_eq!(
            ids_with_tag(&first, schema::source_projection::KIND),
            ids_with_tag(&moved, schema::source_projection::KIND)
        );
        assert_eq!(
            ids_with_tag(&first, schema::source_snapshot::KIND),
            ids_with_tag(&moved, schema::source_snapshot::KIND)
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
    fn telemetry_is_bounded_into_stable_full_chunks_and_one_changed_tail() {
        let chunk_bytes = schema::source_chunk::CANONICAL_BYTES;
        let first_source = chunked_telemetry_rollout(chunk_bytes + 257);
        let (_first_dir, first_summary, first) = project_text(&first_source, "chunks.jsonl");
        assert_eq!(first_summary.stats.records_seen, 1_026);
        assert_eq!(first_summary.stats.skipped_records, 1_026);
        assert_eq!(first_summary.fragments_emitted, 1);
        assert_eq!(first_summary.stats.source_projections, 0);
        assert_eq!(first_summary.stats.source_snapshots, 1);
        assert_eq!(first_summary.stats.raw_chunks, 2);

        let first_full = source_chunk_for_raw(&first, &first_source.as_bytes()[..chunk_bytes]);
        let first_tail = source_chunk_for_raw(&first, &first_source.as_bytes()[chunk_bytes..]);
        assert!(source_chunk_raws(&first)
            .iter()
            .all(|(_, _, raw)| raw.len() <= chunk_bytes));

        let appended_source = format!(
            "{first_source}{}\n",
            r#"{"type":"response_item","payload":{"type":"telemetry"}}"#
        );
        let (_appended_dir, appended_summary, appended) =
            project_text(&appended_source, "chunks-grown.jsonl");
        assert_eq!(appended_summary.fragments_emitted, 1);
        let appended_ids = ids_with_tag(&appended, schema::source_chunk::KIND);
        assert!(
            appended_ids.contains(&first_full),
            "the completed 8 MiB offset chunk is append-idempotent"
        );
        assert!(
            !appended_ids.contains(&first_tail),
            "only the bounded tail receipt changes when growth stays in its chunk"
        );
        assert_eq!(
            source_chunk_raws(&first)
                .into_iter()
                .map(|(chunk, _, _)| chunk)
                .collect::<BTreeSet<_>>()
                .intersection(&appended_ids)
                .copied()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([first_full])
        );
    }

    #[test]
    fn partial_live_tail_is_archived_but_deferred_and_missing_session_identity_is_rejected() {
        let partial = format!("{ROLLOUT}{{\"type\":\"event_msg\"");
        let (_directory, summary, fragment) = project_text(&partial, "live.jsonl");
        assert!(summary.trailing_bytes_ignored > 0);
        assert_eq!(
            ids_with_tag(&fragment, schema::source_projection::KIND).len(),
            3
        );
        assert_eq!(exact_source_snapshot(&fragment), partial.as_bytes());

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

    #[test]
    fn scanner_decodes_escaped_fields_and_nested_pointer_objects_without_a_dom() {
        let record = parse_record(
            Bytes::from_source(
                br#" {"type":"event_msg","timestamp":"2026-08-16T08:00:00Z","payload":{"type":"user_message","message":"hello\nworld","images":[{"path":"fallback","url":"chosen\u002epng"},17,"plain.png"],"local_images":"not-an-array"}} "#
                    .to_vec(),
            ),
            Path::new("scanner.jsonl"),
        )
        .unwrap();
        assert_eq!(record.record_type.as_deref(), Some("event_msg"));
        let payload = record.payload.unwrap();
        assert_eq!(payload.message.as_deref(), Some("hello\nworld"));
        assert_eq!(
            payload
                .images
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<&str>>(),
            vec!["chosen.png", "plain.png"]
        );
        assert!(payload.local_images.is_empty());
    }
}
