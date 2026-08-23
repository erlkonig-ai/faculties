//! Zero-copy projection of Claude Web data exports onto Archive's block DAG.
//!
//! Claude's `conversations.json` is an immutable export artifact rather than a
//! live log.  The adapter therefore mmaps it once and uses TribleSpace's
//! streaming scanner to retain `View<str>` values and exact `Bytes` slices of
//! every conversation envelope and message. No dynamic JSON tree or
//! reserialization sits between the source evidence and its source-projection
//! receipt.

use std::fs;
use std::path::{Path, PathBuf};

use anybytes::{Bytes, View};
use anyhow::{Context, Result};
use hifitime::Epoch;
use triblespace::core::import::scanner as sc;
use triblespace::prelude::inlineencodings::NsTAIInterval;
use triblespace::prelude::*;

use crate::archive_source::{
    self, ProjectedSource, SourceClaims, SourcePart, SourceRecord, Threading,
};
use crate::schemas::blockdag as schema;

type ScanResult<T> = std::result::Result<T, sc::ScanError>;

/// Observable Claude Web projection accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProjectionStats {
    pub conversations: usize,
    pub messages: usize,
    pub attachments: usize,
    pub extracted_contents: usize,
    pub missing_conversation_uuids: usize,
    pub missing_message_uuids: usize,
    pub invalid_timestamps: usize,
    /// Future content kinds retained only by their exact raw message receipt.
    pub unknown_content_items: usize,
    pub common: archive_source::ProjectionStats,
}

impl ProjectionStats {
    fn absorb(&mut self, other: Self) {
        self.conversations += other.conversations;
        self.messages += other.messages;
        self.attachments += other.attachments;
        self.extracted_contents += other.extracted_contents;
        self.missing_conversation_uuids += other.missing_conversation_uuids;
        self.missing_message_uuids += other.missing_message_uuids;
        self.invalid_timestamps += other.invalid_timestamps;
        self.unknown_content_items += other.unknown_content_items;
        self.common.records_seen += other.common.records_seen;
        self.common.projections_emitted += other.common.projections_emitted;
        self.common.content_parts += other.common.content_parts;
        self.common.transparent_records += other.common.transparent_records;
        self.common.raw_only_records += other.common.raw_only_records;
        self.common.missing_predecessors += other.common.missing_predecessors;
    }
}

/// One input export projected into an attachment-complete fragment.
pub struct ProjectedFile {
    pub source_path: PathBuf,
    pub fragment: Fragment,
    pub stats: ProjectionStats,
}

/// Corpus-level result after every deterministic callback has completed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProjectionSummary {
    pub files_scanned: usize,
    pub fragments_emitted: usize,
    pub stats: ProjectionStats,
}

/// Project one `conversations.json`, or every such file below a directory.
///
/// Files and callbacks are ordered lexicographically.  The adapter performs no
/// pile writes; callers can stage all returned fragments and publish one
/// validated Archive collection COMMIT.
pub fn project_path<F>(path: &Path, mut emit: F) -> Result<ProjectionSummary>
where
    F: FnMut(ProjectedFile) -> Result<()>,
{
    let mut paths = Vec::new();
    if path.is_file() {
        paths.push(path.to_path_buf());
    } else {
        collect_conversation_files(path, &mut paths)
            .with_context(|| format!("scan Claude Web export {}", path.display()))?;
        paths.sort();
    }

    let mut summary = ProjectionSummary::default();
    for source_path in paths {
        let (fragment, stats) = project_file(&source_path)?;
        summary.files_scanned += 1;
        summary.stats.absorb(stats);
        if !fragment.facts().is_empty() {
            emit(ProjectedFile {
                source_path,
                fragment,
                stats,
            })?;
            summary.fragments_emitted += 1;
        }
    }
    Ok(summary)
}

fn project_file(path: &Path) -> Result<(Fragment, ProjectionStats)> {
    let bytes = archive_source::map_immutable_file(path)?;
    let conversations = parse_export(bytes)
        .map_err(anyhow::Error::new)
        .with_context(|| format!("scan Claude Web export {}", path.display()))?;
    let (records, mut stats) = records_from_conversations(conversations)?;
    let mut fragment = Fragment::empty();
    stats.common = archive_source::project_records(
        schema::source_projection::SOURCE_CLAUDE_WEB,
        path,
        records,
        |projected: ProjectedSource| {
            fragment += projected.fragment;
            Ok(())
        },
    )?;
    Ok((fragment, stats))
}

fn collect_conversation_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("read dir {}", path.display()))? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let entry_path = entry.path();
        if kind.is_dir() {
            collect_conversation_files(&entry_path, out)?;
        } else if kind.is_file()
            && entry_path.file_name().and_then(|name| name.to_str()) == Some("conversations.json")
        {
            out.push(entry_path);
        }
    }
    Ok(())
}

#[derive(Clone)]
struct ConversationDraft {
    raw: Bytes,
    uuid: Option<View<str>>,
    messages: Vec<MessageDraft>,
}

#[derive(Clone)]
struct MessageDraft {
    raw: Bytes,
    uuid: Option<View<str>>,
    parent: ParentReference,
    sender: Option<View<str>>,
    model: Option<View<str>>,
    created_at: Option<View<str>>,
    flat_text: Option<View<str>>,
    content: Vec<ContentDraft>,
    attachments: Vec<AttachmentDraft>,
}

/// Source-level parent claim after fixed-priority alias resolution.
///
/// Absence permits the legacy linear-order fallback. An explicit null (or
/// empty UUID) is a positive root claim and must not be collapsed into absence.
#[derive(Clone, Default)]
enum ParentReference {
    #[default]
    Absent,
    Root,
    Message(View<str>),
}

#[derive(Clone)]
enum ContentDraft {
    Text {
        modality: Id,
        text: View<str>,
    },
    Pointer {
        modality: Id,
        pointer: View<str>,
        media_type: Option<View<str>>,
    },
    Unknown,
}

#[derive(Clone, Copy)]
enum AttachmentGroup {
    Attachments,
    Files,
}

impl AttachmentGroup {
    fn label(self) -> &'static str {
        match self {
            Self::Attachments => "attachments",
            Self::Files => "files",
        }
    }
}

#[derive(Clone)]
struct AttachmentDraft {
    group: AttachmentGroup,
    ordinal: usize,
    file_uuid: Option<View<str>>,
    file_name: Option<View<str>>,
    media_type: Option<View<str>>,
    size: Option<u128>,
    extracted_content: Option<View<str>>,
}

fn parse_export(bytes: Bytes) -> ScanResult<Vec<ConversationDraft>> {
    let mut cursor = bytes;
    sc::skip_ws(&mut cursor);
    let conversations = match cursor.as_ref().first().copied() {
        Some(b'[') => sc::array(&mut cursor, Vec::new(), |mut out, value| {
            let raw = archive_source::raw_value(value)?;
            out.push(parse_conversation(raw)?);
            Ok(out)
        })?,
        Some(b'{') => {
            let raw = archive_source::raw_value(&mut cursor)?;
            vec![parse_conversation(raw)?]
        }
        _ => return Err(syntax("expected a conversation object or array")),
    };
    sc::skip_ws(&mut cursor);
    if !cursor.is_empty() {
        return Err(syntax("trailing bytes after Claude Web export"));
    }
    Ok(conversations)
}

fn parse_conversation(raw: Bytes) -> ScanResult<ConversationDraft> {
    #[derive(Default)]
    struct Fields {
        uuid: Option<View<str>>,
        chat_messages: Option<Vec<MessageDraft>>,
        messages: Option<Vec<MessageDraft>>,
    }

    let mut cursor = raw.clone();
    let fields = sc::object(&mut cursor, Fields::default(), |mut fields, key, value| {
        match key.as_ref() {
            b"uuid" => fields.uuid = nullable_string(value)?,
            b"chat_messages" => fields.chat_messages = Some(parse_messages(value)?),
            b"messages" => fields.messages = Some(parse_messages(value)?),
            _ => sc::skip_value(value)?,
        }
        Ok(fields)
    })?;
    Ok(ConversationDraft {
        raw,
        uuid: fields.uuid,
        // `chat_messages` is Claude's native spelling. `messages` is an
        // import-compatibility alias, not a second list to concatenate.
        messages: fields.chat_messages.or(fields.messages).unwrap_or_default(),
    })
}

fn parse_messages(value: &mut Bytes) -> ScanResult<Vec<MessageDraft>> {
    sc::skip_ws(value);
    if consume_null(value)? {
        return Ok(Vec::new());
    }
    sc::array(value, Vec::new(), |mut messages, value| {
        let raw = archive_source::raw_value(value)?;
        messages.push(parse_message(raw)?);
        Ok(messages)
    })
}

fn parse_message(raw: Bytes) -> ScanResult<MessageDraft> {
    #[derive(Default)]
    struct Fields {
        uuid: Option<View<str>>,
        parent_message_uuid: Option<Option<View<str>>>,
        parent_uuid: Option<Option<View<str>>>,
        sender: Option<Option<View<str>>>,
        role: Option<Option<View<str>>>,
        model: Option<Option<View<str>>>,
        model_slug: Option<Option<View<str>>>,
        created_at: Option<Option<View<str>>>,
        timestamp: Option<Option<View<str>>>,
        flat_text: Option<View<str>>,
        content: Vec<ContentDraft>,
        attachments: Option<Vec<AttachmentDraft>>,
        files: Option<Vec<AttachmentDraft>>,
    }

    let mut cursor = raw.clone();
    let fields = sc::object(&mut cursor, Fields::default(), |mut fields, key, value| {
        match key.as_ref() {
            b"uuid" => fields.uuid = nullable_string(value)?,
            b"parent_message_uuid" => {
                fields.parent_message_uuid = Some(nullable_string(value)?);
            }
            b"parent_uuid" => fields.parent_uuid = Some(nullable_string(value)?),
            b"sender" => fields.sender = Some(nullable_string(value)?),
            b"role" => fields.role = Some(nullable_string(value)?),
            b"model" => fields.model = Some(nullable_string(value)?),
            b"model_slug" => fields.model_slug = Some(nullable_string(value)?),
            b"created_at" => fields.created_at = Some(nullable_string(value)?),
            b"timestamp" => fields.timestamp = Some(nullable_string(value)?),
            b"text" => fields.flat_text = nullable_string(value)?,
            b"content" => fields.content.extend(parse_content(value)?),
            b"attachments" => {
                fields.attachments = Some(parse_attachments(value, AttachmentGroup::Attachments)?);
            }
            b"files" => {
                fields.files = Some(parse_attachments(value, AttachmentGroup::Files)?);
            }
            _ => sc::skip_value(value)?,
        }
        Ok(fields)
    })?;

    let mut attachments = fields.attachments.unwrap_or_default();
    // These are distinct groups rather than aliases. Their semantic order is
    // fixed even when the source object spells `files` first.
    attachments.extend(fields.files.unwrap_or_default());
    let parent = match preferred_nullable_alias([fields.parent_message_uuid, fields.parent_uuid]) {
        None => ParentReference::Absent,
        Some(Some(uuid)) if !uuid.as_ref().trim().is_empty() => ParentReference::Message(uuid),
        Some(_) => ParentReference::Root,
    };
    Ok(MessageDraft {
        raw,
        uuid: fields.uuid,
        parent,
        sender: preferred_alias([fields.sender, fields.role]),
        model: preferred_alias([fields.model, fields.model_slug]),
        created_at: preferred_alias([fields.created_at, fields.timestamp]),
        flat_text: fields.flat_text,
        content: fields.content,
        attachments,
    })
}

fn parse_content(value: &mut Bytes) -> ScanResult<Vec<ContentDraft>> {
    sc::skip_ws(value);
    match value.as_ref().first().copied() {
        Some(b'n') => {
            sc::expect_literal(value, b"null")?;
            Ok(Vec::new())
        }
        Some(b'"') => Ok(nonempty(archive_source::string(value)?)
            .into_iter()
            .map(|text| ContentDraft::Text {
                modality: schema::content_fact::modality::TEXT,
                text,
            })
            .collect()),
        Some(b'[') => sc::array(value, Vec::new(), |mut parts, value| {
            let raw = archive_source::raw_value(value)?;
            parts.extend(parse_content_item(raw)?);
            Ok(parts)
        }),
        Some(b'{') => {
            let raw = archive_source::raw_value(value)?;
            parse_content_item(raw)
        }
        _ => {
            sc::skip_value(value)?;
            Ok(Vec::new())
        }
    }
}

fn parse_content_item(raw: Bytes) -> ScanResult<Vec<ContentDraft>> {
    let original = raw.clone();
    let mut cursor = raw;
    sc::skip_ws(&mut cursor);
    if cursor.as_ref().first() == Some(&b'"') {
        return Ok(nonempty(archive_source::string(&mut cursor)?)
            .into_iter()
            .map(|text| ContentDraft::Text {
                modality: schema::content_fact::modality::TEXT,
                text,
            })
            .collect());
    }
    if cursor.as_ref().first() != Some(&b'{') {
        sc::skip_value(&mut cursor)?;
        return Ok(Vec::new());
    }

    #[derive(Default)]
    struct Fields {
        kind: Option<View<str>>,
        text: Option<View<str>>,
        thinking: Option<View<str>>,
        id: Option<View<str>>,
        tool_use_id: Option<View<str>>,
        name: Option<View<str>>,
        uuid: Option<View<str>>,
        file_uuid: Option<View<str>>,
        file_path: Option<View<str>>,
        mime_type: Option<Option<View<str>>>,
        media_type: Option<Option<View<str>>>,
        input: Option<Bytes>,
        message: Option<Bytes>,
        display_content: Option<Bytes>,
        content: Option<Bytes>,
        structured_content: Option<Bytes>,
        is_error: Option<Bytes>,
        json_block: Option<Bytes>,
        code: Option<View<str>>,
        table: Option<Bytes>,
        link: Option<Bytes>,
    }

    let fields = sc::object(&mut cursor, Fields::default(), |mut fields, key, value| {
        match key.as_ref() {
            b"type" => fields.kind = nullable_string(value)?,
            b"text" => fields.text = nullable_string(value)?,
            b"thinking" => fields.thinking = nullable_string(value)?,
            b"id" => fields.id = nullable_string(value)?,
            b"tool_use_id" => fields.tool_use_id = nullable_string(value)?,
            b"name" => fields.name = nullable_string(value)?,
            b"uuid" => fields.uuid = nullable_string(value)?,
            b"file_uuid" => fields.file_uuid = nullable_string(value)?,
            b"file_path" => fields.file_path = nullable_string(value)?,
            b"mime_type" => fields.mime_type = Some(nullable_string(value)?),
            b"media_type" => fields.media_type = Some(nullable_string(value)?),
            b"input" => fields.input = Some(archive_source::raw_value(value)?),
            b"message" => fields.message = Some(archive_source::raw_value(value)?),
            b"display_content" => fields.display_content = Some(archive_source::raw_value(value)?),
            b"content" => fields.content = Some(archive_source::raw_value(value)?),
            b"structured_content" => {
                fields.structured_content = Some(archive_source::raw_value(value)?)
            }
            b"is_error" => fields.is_error = Some(archive_source::raw_value(value)?),
            b"json_block" => fields.json_block = Some(archive_source::raw_value(value)?),
            b"code" => fields.code = nullable_string(value)?,
            b"table" => fields.table = Some(archive_source::raw_value(value)?),
            b"link" => fields.link = Some(archive_source::raw_value(value)?),
            _ => sc::skip_value(value)?,
        }
        Ok(fields)
    })?;
    let media_type = preferred_alias([fields.mime_type, fields.media_type]);
    let kind = fields.kind.as_ref().map(AsRef::as_ref).unwrap_or_default();
    let text = |modality, text: Option<View<str>>| {
        Ok(text
            .and_then(nonempty)
            .map(|text| vec![ContentDraft::Text { modality, text }])
            .unwrap_or_default())
    };
    match kind {
        "text" | "knowledge" => text(schema::content_fact::modality::TEXT, fields.text),
        "thinking" | "reasoning" => text(
            schema::content_fact::modality::THINKING,
            fields.thinking.or(fields.text),
        ),
        "tool_use" | "tool_call" => Ok(vec![ContentDraft::Text {
            modality: schema::content_fact::modality::TOOL_CALL,
            text: archive_source::owned_text(canonical_tool_payload(
                fields.id.as_ref(),
                fields.name.as_ref(),
                fields.input,
                fields.message,
                fields.display_content,
            )?),
        }]),
        "tool_result" => Ok(vec![ContentDraft::Text {
            modality: schema::content_fact::modality::TOOL_RESULT,
            text: archive_source::owned_text(canonical_tool_result(
                fields.tool_use_id.as_ref(),
                fields.name.as_ref(),
                fields.content,
                fields.message,
                fields.display_content,
                fields.structured_content,
                fields.is_error,
            )?),
        }]),
        "json_block" => text(
            schema::content_fact::modality::TEXT,
            fields
                .json_block
                .map(json_value_as_text)
                .transpose()?
                .flatten(),
        ),
        "code_block" => text(schema::content_fact::modality::TEXT, fields.code),
        "table" => text(
            schema::content_fact::modality::TEXT,
            fields
                .table
                .map(archive_source::canonical_json)
                .transpose()?
                .map(archive_source::owned_text),
        ),
        "rich_content" => match fields.content {
            Some(mut content) => parse_content(&mut content),
            None => Ok(Vec::new()),
        },
        "rich_link" => text(
            schema::content_fact::modality::TEXT,
            fields
                .link
                .map(archive_source::canonical_json)
                .transpose()?
                .map(archive_source::owned_text),
        ),
        "local_resource" => {
            let pointer = fields
                .uuid
                .or(fields.file_uuid)
                .or_else(|| fields.file_path.clone())
                .or(fields.name.clone());
            let Some(pointer) = pointer else {
                return Ok(vec![ContentDraft::Unknown]);
            };
            let media_type = normalized_media_type(
                media_type.as_ref(),
                fields.file_path.as_ref().or(fields.name.as_ref()),
            );
            let modality = media_type
                .as_ref()
                .map(|media| archive_source::modality_for_media_type(media.as_ref()))
                .unwrap_or(schema::content_fact::modality::FILE);
            Ok(vec![ContentDraft::Pointer {
                modality,
                pointer,
                media_type,
            }])
        }
        "image" => match fields.file_uuid.or(fields.uuid) {
            Some(pointer) => Ok(vec![ContentDraft::Pointer {
                modality: schema::content_fact::modality::IMAGE,
                pointer,
                media_type: normalized_media_type(media_type.as_ref(), fields.name.as_ref()),
            }]),
            None => Ok(vec![ContentDraft::Unknown]),
        },
        "webpage_metadata" | "single_select" => Ok(vec![ContentDraft::Text {
            modality: schema::content_fact::modality::TEXT,
            text: archive_source::owned_text(archive_source::canonical_json(original)?),
        }]),
        _ => Ok(vec![ContentDraft::Unknown]),
    }
}

fn canonical_tool_payload(
    id: Option<&View<str>>,
    name: Option<&View<str>>,
    input: Option<Bytes>,
    message: Option<Bytes>,
    display_content: Option<Bytes>,
) -> ScanResult<String> {
    Ok(format!(
        r#"{{"display_content":{},"id":{},"input":{},"message":{},"name":{}}}"#,
        canonical_or_null(display_content)?,
        canonical_string_or_null(id),
        canonical_or_null(input)?,
        canonical_or_null(message)?,
        canonical_string_or_null(name),
    ))
}

#[allow(clippy::too_many_arguments)]
fn canonical_tool_result(
    tool_use_id: Option<&View<str>>,
    name: Option<&View<str>>,
    content: Option<Bytes>,
    message: Option<Bytes>,
    display_content: Option<Bytes>,
    structured_content: Option<Bytes>,
    is_error: Option<Bytes>,
) -> ScanResult<String> {
    Ok(format!(
        r#"{{"content":{},"display_content":{},"is_error":{},"message":{},"name":{},"structured_content":{},"tool_use_id":{}}}"#,
        canonical_or_null(content)?,
        canonical_or_null(display_content)?,
        canonical_or_null(is_error)?,
        canonical_or_null(message)?,
        canonical_string_or_null(name),
        canonical_or_null(structured_content)?,
        canonical_string_or_null(tool_use_id),
    ))
}

fn canonical_or_null(value: Option<Bytes>) -> ScanResult<String> {
    value
        .map(archive_source::canonical_json)
        .transpose()
        .map(|value| value.unwrap_or_else(|| "null".to_owned()))
}

fn canonical_string_or_null(value: Option<&View<str>>) -> String {
    value
        .map(|value| archive_source::canonical_json_string(value.as_ref()))
        .unwrap_or_else(|| "null".to_owned())
}

fn json_value_as_text(mut value: Bytes) -> ScanResult<Option<View<str>>> {
    sc::skip_ws(&mut value);
    match value.as_ref().first().copied() {
        Some(b'n') => {
            sc::expect_literal(&mut value, b"null")?;
            Ok(None)
        }
        Some(b'"') => {
            let text = archive_source::string(&mut value)?;
            if text.as_ref().is_empty() {
                return Ok(None);
            }
            // `json_block` stores its JSON document inside a JSON string. It
            // is canonical semantic data, not merely presentation text; keep
            // the source view as a fallback for future non-JSON variants.
            Ok(match archive_source::canonical_json(text.clone().bytes()) {
                Ok(canonical) => Some(archive_source::owned_text(canonical)),
                Err(_) => Some(text),
            })
        }
        Some(_) => archive_source::canonical_json(value)
            .map(archive_source::owned_text)
            .map(Some),
        None => Ok(None),
    }
}

fn normalized_media_type(
    source: Option<&View<str>>,
    name: Option<&View<str>>,
) -> Option<View<str>> {
    let explicit = source.map(|value| value.as_ref().trim().to_ascii_lowercase());
    let normalized = explicit.as_deref().and_then(|value| match value {
        "txt" | "text" => Some("text/plain"),
        "html" | "htm" => Some("text/html"),
        "json" => Some("application/json"),
        "pdf" => Some("application/pdf"),
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        value if value.contains('/') => value.split(';').next(),
        _ => None,
    });
    let inferred = name.and_then(|name| {
        let extension = name.as_ref().rsplit_once('.')?.1.to_ascii_lowercase();
        match extension.as_str() {
            "txt" | "md" => Some("text/plain"),
            "html" | "htm" => Some("text/html"),
            "json" => Some("application/json"),
            "csv" => Some("text/csv"),
            "pdf" => Some("application/pdf"),
            "png" => Some("image/png"),
            "jpg" | "jpeg" => Some("image/jpeg"),
            "gif" => Some("image/gif"),
            "webp" => Some("image/webp"),
            "svg" => Some("image/svg+xml"),
            "wav" => Some("audio/wav"),
            "mp3" => Some("audio/mpeg"),
            "mp4" => Some("video/mp4"),
            _ => None,
        }
    });
    normalized
        .or(inferred)
        .map(|value| archive_source::owned_text(value.to_owned()))
}

fn parse_attachments(
    value: &mut Bytes,
    group: AttachmentGroup,
) -> ScanResult<Vec<AttachmentDraft>> {
    sc::skip_ws(value);
    if consume_null(value)? {
        return Ok(Vec::new());
    }
    sc::array(value, Vec::new(), |mut attachments, value| {
        let raw = archive_source::raw_value(value)?;
        let ordinal = attachments.len();
        attachments.push(parse_attachment(raw, group, ordinal)?);
        Ok(attachments)
    })
}

fn parse_attachment(
    raw: Bytes,
    group: AttachmentGroup,
    ordinal: usize,
) -> ScanResult<AttachmentDraft> {
    #[derive(Default)]
    struct Fields {
        file_uuid: Option<Option<View<str>>>,
        uuid: Option<Option<View<str>>>,
        file_name: Option<Option<View<str>>>,
        filename: Option<Option<View<str>>>,
        name: Option<Option<View<str>>>,
        file_type: Option<Option<View<str>>>,
        mime_type: Option<Option<View<str>>>,
        media_type: Option<Option<View<str>>>,
        file_size: Option<Option<u128>>,
        size: Option<Option<u128>>,
        extracted_content: Option<View<str>>,
    }

    let mut cursor = raw;
    let fields = sc::object(&mut cursor, Fields::default(), |mut fields, key, value| {
        match key.as_ref() {
            b"file_uuid" => fields.file_uuid = Some(nullable_string(value)?),
            b"uuid" => fields.uuid = Some(nullable_string(value)?),
            b"file_name" => fields.file_name = Some(nullable_string(value)?),
            b"filename" => fields.filename = Some(nullable_string(value)?),
            b"name" => fields.name = Some(nullable_string(value)?),
            b"file_type" => fields.file_type = Some(nullable_string(value)?),
            b"mime_type" => fields.mime_type = Some(nullable_string(value)?),
            b"media_type" => fields.media_type = Some(nullable_string(value)?),
            b"file_size" => fields.file_size = Some(nullable_u128(value)?),
            b"size" => fields.size = Some(nullable_u128(value)?),
            b"extracted_content" => fields.extracted_content = nullable_string(value)?,
            _ => sc::skip_value(value)?,
        }
        Ok(fields)
    })?;
    Ok(AttachmentDraft {
        group,
        ordinal,
        file_uuid: preferred_alias([fields.file_uuid, fields.uuid]),
        file_name: preferred_alias([fields.file_name, fields.filename, fields.name]),
        media_type: preferred_alias([fields.file_type, fields.mime_type, fields.media_type]),
        size: preferred_alias([fields.file_size, fields.size]),
        extracted_content: fields.extracted_content,
    })
}

fn records_from_conversations(
    conversations: Vec<ConversationDraft>,
) -> Result<(Vec<SourceRecord>, ProjectionStats)> {
    let mut records = Vec::new();
    let mut stats = ProjectionStats::default();
    for conversation in conversations {
        let ConversationDraft {
            raw,
            uuid,
            messages,
        } = conversation;
        stats.conversations += 1;
        let conversation_uuid = match uuid {
            Some(uuid) if !uuid.as_ref().trim().is_empty() => uuid,
            _ => {
                stats.missing_conversation_uuids += 1;
                anonymous_conversation_anchor(&messages, &raw)
            }
        };
        let mut previous = None::<View<str>>;
        for (ordinal, message) in messages.into_iter().enumerate() {
            stats.messages += 1;
            let message_uuid = match message.uuid {
                Some(uuid) if !uuid.as_ref().trim().is_empty() => uuid,
                _ => {
                    stats.missing_message_uuids += 1;
                    archive_source::owned_text(format!(
                        "anonymous-message/{ordinal}/{}",
                        blake3::hash(message.raw.as_ref()).to_hex()
                    ))
                }
            };
            let locator = qualified_locator(&conversation_uuid, &message_uuid);
            let predecessor = match &message.parent {
                ParentReference::Absent => previous.clone(),
                ParentReference::Root => None,
                ParentReference::Message(uuid) => Some(qualified_locator(&conversation_uuid, uuid)),
            };
            let direction = direction_for_sender(message.sender.as_ref().map(AsRef::as_ref));

            let mut parts = Vec::new();
            if message.content.is_empty() {
                if let Some(text) = message.flat_text.clone().and_then(nonempty) {
                    parts.push(SourcePart::text(
                        schema::content_fact::modality::TEXT,
                        direction,
                        text,
                    ));
                }
            } else {
                for content in message.content {
                    match content {
                        ContentDraft::Text { modality, text } => {
                            if let Some(text) = nonempty(text) {
                                parts.push(SourcePart::text(modality, direction, text));
                            }
                        }
                        ContentDraft::Pointer {
                            modality,
                            pointer,
                            media_type,
                        } => parts.push(SourcePart::Pointer {
                            modality,
                            direction,
                            namespace: schema::source_projection::SOURCE_CLAUDE_WEB,
                            pointer,
                            media_type,
                            size: None,
                            resolved: None,
                        }),
                        ContentDraft::Unknown => stats.unknown_content_items += 1,
                    }
                }
            }

            for attachment in message.attachments {
                stats.attachments += 1;
                let file_name = attachment.file_name.unwrap_or_else(|| {
                    archive_source::owned_text(format!(
                        "{}-{}",
                        attachment.group.label(),
                        attachment.ordinal
                    ))
                });
                let pointer = attachment
                    .file_uuid
                    .filter(|uuid| !uuid.as_ref().is_empty())
                    .unwrap_or_else(|| {
                        archive_source::owned_text(format!(
                            "{}/{}/{}/{}/{}",
                            conversation_uuid.as_ref(),
                            message_uuid.as_ref(),
                            attachment.group.label(),
                            attachment.ordinal,
                            file_name.as_ref()
                        ))
                    });
                let media_type =
                    normalized_media_type(attachment.media_type.as_ref(), Some(&file_name));
                let modality = media_type
                    .as_ref()
                    .map(|media_type| archive_source::modality_for_media_type(media_type.as_ref()))
                    .unwrap_or(schema::content_fact::modality::FILE);
                parts.push(SourcePart::Pointer {
                    modality,
                    direction,
                    namespace: schema::source_projection::SOURCE_CLAUDE_WEB,
                    pointer,
                    media_type,
                    size: attachment.size,
                    resolved: None,
                });
                if let Some(extracted) = attachment.extracted_content.and_then(nonempty) {
                    stats.extracted_contents += 1;
                    parts.push(SourcePart::text(
                        schema::content_fact::modality::TEXT,
                        direction,
                        extracted,
                    ));
                }
            }

            let timestamp =
                parse_timestamp(message.created_at.as_ref(), &mut stats.invalid_timestamps);
            let threading = if parts.is_empty() {
                Threading::Transparent
            } else {
                Threading::Semantic
            };
            records.push(SourceRecord {
                locator: locator.clone(),
                raw_record: message.raw,
                predecessors: predecessor.into_iter().collect(),
                block_timestamp: timestamp,
                threading,
                parts,
                claims: SourceClaims {
                    timestamp,
                    raw_author: message.sender.clone(),
                    raw_role: message.sender,
                    raw_model: message.model,
                    ..SourceClaims::default()
                },
            });
            previous = Some(locator);
        }

        // The conversation object carries source evidence that is not part of
        // any individual message: name, summary, account, settings, and future
        // vendor fields. Keep its exact bytes as a source-only occurrence. It
        // deliberately has no semantic predecessors or parts, so the shared
        // projector maps it to the canonical bottom block and contracts it out
        // of the message DAG rather than inventing an ambient EVENT.
        records.push(SourceRecord {
            locator: conversation_envelope_locator(&conversation_uuid),
            raw_record: raw,
            predecessors: Vec::new(),
            block_timestamp: None,
            threading: Threading::Transparent,
            parts: Vec::new(),
            claims: SourceClaims::default(),
        });
    }
    Ok((records, stats))
}

fn conversation_envelope_locator(conversation: &View<str>) -> View<str> {
    archive_source::owned_text(format!(
        "conversation:{}:{}/envelope",
        conversation.as_ref().len(),
        conversation.as_ref()
    ))
}

/// Path-independent birth identity for a conversation without a native UUID.
///
/// The first message is immutable prefix evidence in Claude exports. Prefer
/// its native UUID, then its exact record bytes. Appending later messages
/// therefore cannot rename existing receipts. An empty anonymous conversation
/// has no append-stable birth evidence, so its exact envelope is the only
/// available identity until the first message appears.
fn anonymous_conversation_anchor(messages: &[MessageDraft], raw: &Bytes) -> View<str> {
    match messages.first() {
        Some(message) => match message
            .uuid
            .as_ref()
            .filter(|uuid| !uuid.as_ref().trim().is_empty())
        {
            Some(uuid) => archive_source::owned_text(format!(
                "anonymous-conversation/message:{}:{}",
                uuid.as_ref().len(),
                uuid.as_ref()
            )),
            None => archive_source::owned_text(format!(
                "anonymous-conversation/birth/{}",
                blake3::hash(message.raw.as_ref()).to_hex()
            )),
        },
        None => archive_source::owned_text(format!(
            "anonymous-conversation/empty/{}",
            blake3::hash(raw.as_ref()).to_hex()
        )),
    }
}

fn qualified_locator(conversation: &View<str>, message: &View<str>) -> View<str> {
    archive_source::owned_text(format!("{}/{}", conversation.as_ref(), message.as_ref()))
}

fn direction_for_sender(sender: Option<&str>) -> Id {
    let Some(sender) = sender else {
        return schema::content_fact::direction::AMBIENT;
    };
    if sender.eq_ignore_ascii_case("human") || sender.eq_ignore_ascii_case("user") {
        schema::content_fact::direction::IN
    } else if sender.eq_ignore_ascii_case("assistant") || sender.eq_ignore_ascii_case("claude") {
        schema::content_fact::direction::OUT
    } else {
        schema::content_fact::direction::AMBIENT
    }
}

fn parse_timestamp(
    value: Option<&View<str>>,
    invalid_timestamps: &mut usize,
) -> Option<Inline<NsTAIInterval>> {
    let value = value?.as_ref().trim();
    if value.is_empty() {
        return None;
    }
    let epoch = match value.parse::<Epoch>() {
        Ok(epoch) => epoch,
        Err(_) => {
            *invalid_timestamps += 1;
            return None;
        }
    };
    match (epoch, epoch).try_to_inline() {
        Ok(interval) => Some(interval),
        Err(_) => {
            *invalid_timestamps += 1;
            None
        }
    }
}

/// Resolve source-schema aliases by semantic priority rather than JSON member
/// order. The outer option records whether a spelling was present; therefore
/// an explicit `null` in a preferred field remains authoritative.
fn preferred_alias<T, const N: usize>(aliases: [Option<Option<T>>; N]) -> Option<T> {
    preferred_nullable_alias(aliases).flatten()
}

fn preferred_nullable_alias<T, const N: usize>(
    aliases: [Option<Option<T>>; N],
) -> Option<Option<T>> {
    for alias in aliases {
        if alias.is_some() {
            return alias;
        }
    }
    None
}

fn nullable_string(value: &mut Bytes) -> ScanResult<Option<View<str>>> {
    sc::skip_ws(value);
    if consume_null(value)? {
        Ok(None)
    } else {
        archive_source::string(value).map(Some)
    }
}

fn nullable_u128(value: &mut Bytes) -> ScanResult<Option<u128>> {
    sc::skip_ws(value);
    if consume_null(value)? {
        return Ok(None);
    }
    let raw = sc::parse_number(value)?;
    let text = raw
        .view::<str>()
        .map_err(|_| syntax("attachment size is not UTF-8"))?;
    text.as_ref()
        .parse::<u128>()
        .map(Some)
        .map_err(|_| syntax("attachment size is not an unsigned integer"))
}

fn consume_null(value: &mut Bytes) -> ScanResult<bool> {
    if value.as_ref().starts_with(b"null") {
        sc::expect_literal(value, b"null")?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn nonempty(value: View<str>) -> Option<View<str>> {
    (!value.as_ref().is_empty()).then_some(value)
}

fn syntax(message: impl Into<String>) -> sc::ScanError {
    sc::ScanError::Syntax(message.into())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use tempfile::TempDir;
    use triblespace::core::repo::{BlobStore, BlobStoreGet};
    use triblespace::macros::{exists, pattern};
    use triblespace::prelude::blobencodings::{RawBytes, UTF8String};
    use triblespace::prelude::inlineencodings::Handle;

    use super::*;

    const EXPORT: &str = r#"[
      {
        "uuid":"conversation-1",
        "created_at":"2026-08-17T08:00:00Z",
        "chat_messages":[
          { "uuid":"m1", "sender":"human", "text":"hello" },
          {
            "uuid":"m2",
            "sender":"assistant",
            "model":"claude-test",
            "content":[
              {"type":"text","text":"answer"},
              {"type":"thinking","thinking":"consider"}
            ],
            "attachments":[{
              "file_name":"notes.txt",
              "file_type":"text/plain",
              "file_size":12,
              "extracted_content":"attachment text"
            }]
          },
          {
            "uuid":"m3",
            "parent_message_uuid":"m1",
            "sender":"human",
            "content":[{"type":"text","text":"fork"}]
          }
        ]
      }
    ]"#;

    const STRUCTURED_EXPORT: &str = r#"{
      "uuid":"conversation-structured",
      "chat_messages":[{
        "uuid":"s1",
        "sender":"assistant",
        "content":[
          {
            "type":"tool_use",
            "id":"toolu-1",
            "name":"bash_tool",
            "input":{"z":2,"a":1},
            "message":"run it",
            "display_content":{"type":"json_block","json_block":"{\"x\":1}"}
          },
          {"type":"json_block","json_block":"{\"b\":2,\"a\":1}"},
          {
            "type":"tool_result",
            "tool_use_id":"toolu-1",
            "name":"bash_tool",
            "content":[{"type":"text","text":"done"}],
            "is_error":false
          }
        ],
        "files":[{"file_uuid":"file-image-1","file_name":"photo.PNG"}]
      }]
    }"#;

    fn parsed_records() -> (Vec<SourceRecord>, ProjectionStats) {
        let bytes = Bytes::from_source(EXPORT.as_bytes().to_vec());
        let conversations = parse_export(bytes).unwrap();
        records_from_conversations(conversations).unwrap()
    }

    #[derive(Debug)]
    struct Receipt {
        projection: Id,
        block: Id,
        raw: Vec<u8>,
        has_content: bool,
        has_block_timestamp: bool,
        has_source_timestamp: bool,
    }

    fn projected_receipts(
        export: &str,
    ) -> (BTreeMap<String, Receipt>, archive_source::ProjectionStats) {
        let conversations = parse_export(Bytes::from_source(export.as_bytes().to_vec())).unwrap();
        let (records, _) = records_from_conversations(conversations).unwrap();
        let mut receipts = BTreeMap::new();
        let stats = archive_source::project_records(
            schema::source_projection::SOURCE_CLAUDE_WEB,
            Path::new("conversations.json"),
            records,
            |mut projected| {
                let projection = projected
                    .fragment
                    .root()
                    .expect("source projection has one root");
                let (locator, raw, block) = find!(
                    (
                        locator: Inline<Handle<UTF8String>>,
                        raw: Inline<Handle<RawBytes>>,
                        block: Id
                    ),
                    pattern!(&projected.fragment, [{
                        projection @
                            schema::source_projection::source_locator: ?locator,
                            schema::source_projection::raw_record: ?raw,
                            schema::source_projection::projects_to: ?block
                    }])
                )
                .next()
                .expect("projection has its identity core");
                let has_content = exists!(pattern!(&projected.fragment, [{
                    block @ schema::block::contains: _?part
                }]));
                let has_block_timestamp = exists!(pattern!(&projected.fragment, [{
                    block @ schema::block::timestamp: _?timestamp
                }]));
                let has_source_timestamp = exists!(pattern!(&projected.fragment, [{
                    projection @ schema::source_projection::source_timestamp: _?timestamp
                }]));
                let reader = projected
                    .fragment
                    .blobs_mut()
                    .reader()
                    .expect("memory blob reader construction is infallible");
                let locator: View<str> = reader.get(locator).unwrap();
                let raw: Bytes = reader.get(raw).unwrap();
                receipts.insert(
                    locator.as_ref().to_owned(),
                    Receipt {
                        projection,
                        block,
                        raw: raw.as_ref().to_vec(),
                        has_content,
                        has_block_timestamp,
                        has_source_timestamp,
                    },
                );
                Ok(())
            },
        )
        .unwrap();
        (receipts, stats)
    }

    #[test]
    fn scanner_preserves_exact_messages_and_true_source_parentage() {
        let (records, stats) = parsed_records();
        assert_eq!(stats.conversations, 1);
        assert_eq!(stats.messages, 3);
        assert_eq!(records[0].locator.as_ref(), "conversation-1/m1");
        assert!(records[0]
            .raw_record
            .as_ref()
            .starts_with(b"{ \"uuid\":\"m1\""));
        assert_eq!(records[1].predecessors[0].as_ref(), "conversation-1/m1");
        assert_eq!(
            records[2].predecessors[0].as_ref(),
            "conversation-1/m1",
            "an explicit parent beats the linear m2 fallback"
        );
    }

    #[test]
    fn content_order_and_attachment_metadata_survive_projection_input() {
        let (records, stats) = parsed_records();
        assert_eq!(stats.attachments, 1);
        assert_eq!(stats.extracted_contents, 1);
        assert_eq!(records[1].parts.len(), 4);
        match &records[1].parts[0] {
            SourcePart::Text {
                modality, value, ..
            } => {
                assert_eq!(*modality, schema::content_fact::modality::TEXT);
                assert_eq!(value.as_ref(), "answer");
            }
            _ => panic!("first content part is not text"),
        }
        match &records[1].parts[1] {
            SourcePart::Text {
                modality, value, ..
            } => {
                assert_eq!(*modality, schema::content_fact::modality::THINKING);
                assert_eq!(value.as_ref(), "consider");
            }
            _ => panic!("second content part is not thinking"),
        }
        match &records[1].parts[2] {
            SourcePart::Pointer {
                media_type, size, ..
            } => {
                assert_eq!(media_type.as_ref().unwrap().as_ref(), "text/plain");
                assert_eq!(*size, Some(12));
            }
            _ => panic!("third content part is not the attachment pointer"),
        }
    }

    #[test]
    fn structured_tool_json_and_stable_file_identity_are_semantic_parts() {
        let conversations =
            parse_export(Bytes::from_source(STRUCTURED_EXPORT.as_bytes().to_vec())).unwrap();
        let (records, stats) = records_from_conversations(conversations).unwrap();
        assert_eq!(stats.unknown_content_items, 0);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].parts.len(), 4);

        match &records[0].parts[0] {
            SourcePart::Text {
                modality, value, ..
            } => {
                assert_eq!(*modality, schema::content_fact::modality::TOOL_CALL);
                assert_eq!(
                    value.as_ref(),
                    r#"{"display_content":{"json_block":"{\"x\":1}","type":"json_block"},"id":"toolu-1","input":{"a":1,"z":2},"message":"run it","name":"bash_tool"}"#
                );
            }
            _ => panic!("first part is not a canonical tool call"),
        }
        match &records[0].parts[1] {
            SourcePart::Text {
                modality, value, ..
            } => {
                assert_eq!(*modality, schema::content_fact::modality::TEXT);
                assert_eq!(value.as_ref(), r#"{"a":1,"b":2}"#);
            }
            _ => panic!("second part is not the json_block text"),
        }
        match &records[0].parts[2] {
            SourcePart::Text {
                modality, value, ..
            } => {
                assert_eq!(*modality, schema::content_fact::modality::TOOL_RESULT);
                assert!(value.as_ref().contains(r#""tool_use_id":"toolu-1""#));
                assert!(value
                    .as_ref()
                    .contains(r#""content":[{"text":"done","type":"text"}]"#));
            }
            _ => panic!("third part is not a canonical tool result"),
        }
        match &records[0].parts[3] {
            SourcePart::Pointer {
                modality,
                pointer,
                media_type,
                ..
            } => {
                assert_eq!(*modality, schema::content_fact::modality::IMAGE);
                assert_eq!(pointer.as_ref(), "file-image-1");
                assert_eq!(media_type.as_ref().unwrap().as_ref(), "image/png");
            }
            _ => panic!("fourth part is not the stable file pointer"),
        }
        assert!(records[1].parts.is_empty());
    }

    #[test]
    fn exact_conversation_envelope_is_lossless_but_not_semantic() {
        const FIRST: &str = r#"{"uuid":"conversation-envelope","name":"First name","summary":"private summary","account":{"uuid":"account-1","plan":"pro"},"future_vendor_field":{"kept":true},"chat_messages":[{"uuid":"m1","sender":"human","text":"same message"}]}"#;
        const SECOND: &str = r#"{"uuid":"conversation-envelope","name":"Renamed","summary":"different summary","account":{"uuid":"account-2","plan":"team"},"future_vendor_field":{"kept":false},"chat_messages":[{"uuid":"m1","sender":"human","text":"same message"}]}"#;
        let (first, first_stats) = projected_receipts(&format!("[{FIRST}]"));
        let (second, second_stats) = projected_receipts(&format!("[{SECOND}]"));
        let conversation = archive_source::owned_text("conversation-envelope".to_owned());
        let envelope_locator = conversation_envelope_locator(&conversation);
        let first_envelope = &first[envelope_locator.as_ref()];
        let second_envelope = &second[envelope_locator.as_ref()];

        assert_eq!(first_envelope.raw, FIRST.as_bytes());
        assert_eq!(second_envelope.raw, SECOND.as_bytes());
        assert_ne!(
            first_envelope.projection, second_envelope.projection,
            "changing unmodeled envelope evidence changes its receipt identity"
        );
        assert_eq!(
            first_envelope.block, second_envelope.block,
            "both envelopes project to the same canonical bottom block"
        );
        assert!(!first_envelope.has_content);
        assert!(!second_envelope.has_content);

        let message_locator = qualified_locator(&conversation, &archive_source::owned_text("m1"));
        assert_eq!(
            first[message_locator.as_ref()].projection,
            second[message_locator.as_ref()].projection,
            "envelope metadata cannot perturb the message occurrence"
        );
        assert_eq!(
            first[message_locator.as_ref()].block,
            second[message_locator.as_ref()].block,
            "envelope metadata cannot perturb semantic block identity"
        );
        assert_eq!(first_stats.raw_only_records, 1);
        assert_eq!(second_stats.raw_only_records, 1);
        assert_eq!(first_stats.transparent_records, 1);
        assert_eq!(second_stats.transparent_records, 1);
    }

    #[test]
    fn conversation_time_does_not_fabricate_a_missing_message_time() {
        const WITH_CONVERSATION_TIME: &str = r#"{"uuid":"conversation-time","created_at":"2026-08-17T08:00:00Z","chat_messages":[{"uuid":"m1","sender":"human","text":"untimed message"}]}"#;
        const WITHOUT_CONVERSATION_TIME: &str = r#"{"uuid":"conversation-time","chat_messages":[{"uuid":"m1","sender":"human","text":"untimed message"}]}"#;

        let (with_time, _) = projected_receipts(WITH_CONVERSATION_TIME);
        let (without_time, _) = projected_receipts(WITHOUT_CONVERSATION_TIME);
        let conversation = archive_source::owned_text("conversation-time".to_owned());
        let message_locator = qualified_locator(&conversation, &archive_source::owned_text("m1"));
        let message = &with_time[message_locator.as_ref()];

        assert!(!message.has_block_timestamp);
        assert!(!message.has_source_timestamp);
        assert_eq!(
            message.block,
            without_time[message_locator.as_ref()].block,
            "conversation metadata cannot alter semantic message identity"
        );
        assert_eq!(
            message.projection,
            without_time[message_locator.as_ref()].projection,
            "conversation metadata cannot alter the message source receipt"
        );

        let envelope_locator = conversation_envelope_locator(&conversation);
        let envelope = &with_time[envelope_locator.as_ref()];
        assert_eq!(envelope.raw, WITH_CONVERSATION_TIME.as_bytes());
        assert!(!envelope.has_block_timestamp);
        assert!(!envelope.has_source_timestamp);
    }

    #[test]
    fn message_alias_priority_is_member_order_independent_and_raw_stays_exact() {
        const PRIMARY_FIRST: &str = r#"{"uuid":"m1","parent_message_uuid":"canonical-parent","parent_uuid":"legacy-parent","sender":"assistant","role":"human","model":"canonical-model","model_slug":"legacy-model","created_at":"2026-08-17T08:00:00Z","timestamp":"2025-01-01T00:00:00Z","text":"same"}"#;
        const PRIMARY_LAST: &str = r#"{"uuid":"m1","parent_uuid":"legacy-parent","parent_message_uuid":"canonical-parent","role":"human","sender":"assistant","model_slug":"legacy-model","model":"canonical-model","timestamp":"2025-01-01T00:00:00Z","created_at":"2026-08-17T08:00:00Z","text":"same"}"#;

        let export =
            |message: &str| format!(r#"{{"uuid":"alias-order","chat_messages":[{message}]}}"#);
        let first_export = export(PRIMARY_FIRST);
        let last_export = export(PRIMARY_LAST);
        let first = parse_export(Bytes::from_source(first_export.as_bytes().to_vec())).unwrap();
        let last = parse_export(Bytes::from_source(last_export.as_bytes().to_vec())).unwrap();
        let first_message = &first[0].messages[0];
        let last_message = &last[0].messages[0];

        for message in [first_message, last_message] {
            assert!(matches!(
                &message.parent,
                ParentReference::Message(parent) if parent.as_ref() == "canonical-parent"
            ));
            assert_eq!(message.sender.as_ref().unwrap().as_ref(), "assistant");
            assert_eq!(message.model.as_ref().unwrap().as_ref(), "canonical-model");
            assert_eq!(
                message.created_at.as_ref().unwrap().as_ref(),
                "2026-08-17T08:00:00Z"
            );
        }
        assert_eq!(first_message.raw.as_ref(), PRIMARY_FIRST.as_bytes());
        assert_eq!(last_message.raw.as_ref(), PRIMARY_LAST.as_bytes());

        let (first_receipts, _) = projected_receipts(&first_export);
        let (last_receipts, _) = projected_receipts(&last_export);
        let first_receipt = &first_receipts["alias-order/m1"];
        let last_receipt = &last_receipts["alias-order/m1"];
        assert_eq!(first_receipt.raw, PRIMARY_FIRST.as_bytes());
        assert_eq!(last_receipt.raw, PRIMARY_LAST.as_bytes());
        assert_ne!(
            first_receipt.projection, last_receipt.projection,
            "exactly different source envelopes remain different occurrences"
        );
        assert_eq!(
            first_receipt.block, last_receipt.block,
            "member order cannot alter the semantic block"
        );

        let explicit_null = |message: &str| {
            let export = export(message);
            parse_export(Bytes::from_source(export.into_bytes())).unwrap()
        };
        let null_first = explicit_null(
            r#"{"uuid":"m-null","parent_message_uuid":null,"parent_uuid":"stale","created_at":null,"timestamp":"2025-01-01T00:00:00Z","text":"root"}"#,
        );
        let null_last = explicit_null(
            r#"{"uuid":"m-null","parent_uuid":"stale","parent_message_uuid":null,"timestamp":"2025-01-01T00:00:00Z","created_at":null,"text":"root"}"#,
        );
        for message in [&null_first[0].messages[0], &null_last[0].messages[0]] {
            assert!(matches!(&message.parent, ParentReference::Root));
            assert!(message.created_at.is_none());
        }
    }

    #[test]
    fn explicit_null_parent_suppresses_the_linear_fallback() {
        let export = r#"{
            "uuid":"explicit-root",
            "chat_messages":[
                {"uuid":"m1","sender":"human","text":"first"},
                {"uuid":"m2","parent_message_uuid":null,"parent_uuid":"stale","sender":"human","text":"second"},
                {"uuid":"m3","sender":"human","text":"third"}
            ]
        }"#;
        let conversations = parse_export(Bytes::from_source(export.as_bytes().to_vec())).unwrap();
        let (records, _) = records_from_conversations(conversations).unwrap();

        assert!(records[0].predecessors.is_empty());
        assert!(
            records[1].predecessors.is_empty(),
            "an explicit null is a root claim, not an absent-parent fallback"
        );
        assert_eq!(records[2].predecessors, vec![records[1].locator.clone()]);

        let mut second_has_predecessor = None;
        archive_source::project_records(
            schema::source_projection::SOURCE_CLAUDE_WEB,
            Path::new("conversations.json"),
            records,
            |mut projected| {
                let projection = projected.fragment.root().unwrap();
                let (locator, block) = find!(
                    (
                        locator: Inline<Handle<UTF8String>>,
                        block: Id
                    ),
                    pattern!(&projected.fragment, [{
                        projection @
                            schema::source_projection::source_locator: ?locator,
                            schema::source_projection::projects_to: ?block
                    }])
                )
                .next()
                .unwrap();
                let reader = projected.fragment.blobs_mut().reader().unwrap();
                let locator: View<str> = reader.get(locator).unwrap();
                if locator.as_ref() == "explicit-root/m2" {
                    second_has_predecessor = Some(exists!(pattern!(&projected.fragment, [{
                        block @ schema::block::previous: _?previous
                    }])));
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(second_has_predecessor, Some(false));
    }

    #[test]
    fn anonymous_conversation_birth_and_message_occurrences_survive_append() {
        const FIRST: &str = r#"{
            "chat_messages":[
                {"uuid":"native-first","sender":"human","text":"first"},
                {"sender":"assistant","text":"same anonymous message"},
                {"sender":"assistant","text":"same anonymous message"}
            ]
        }"#;
        const APPENDED: &str = r#"{
            "chat_messages":[
                {"uuid":"native-first","sender":"human","text":"first"},
                {"sender":"assistant","text":"same anonymous message"},
                {"sender":"assistant","text":"same anonymous message"},
                {"uuid":"later","sender":"human","text":"appended"}
            ]
        }"#;

        let records = |source: &str| {
            let conversations =
                parse_export(Bytes::from_source(source.as_bytes().to_vec())).unwrap();
            records_from_conversations(conversations).unwrap().0
        };
        let before = records(FIRST);
        let after = records(APPENDED);
        assert_eq!(before.len(), 4);
        assert_eq!(after.len(), 5);
        assert_eq!(before[0].locator, after[0].locator);
        assert_eq!(before[1].locator, after[1].locator);
        assert_eq!(before[2].locator, after[2].locator);
        assert_ne!(before[1].locator, before[2].locator);
        assert_eq!(before[3].locator, after[4].locator);

        let stats = archive_source::project_records(
            schema::source_projection::SOURCE_CLAUDE_WEB,
            Path::new("conversations.json"),
            before,
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(stats.projections_emitted, 4);
    }

    #[test]
    fn attachment_aliases_and_groups_have_fixed_semantic_order() {
        const ATTACHMENT_PRIMARY_FIRST: &str = r#"{"file_uuid":"attachment-primary","uuid":"attachment-legacy","file_name":"primary.txt","filename":"legacy.pdf","name":"legacy.png","file_type":"text/plain","mime_type":"application/pdf","media_type":"image/png","file_size":7,"size":99}"#;
        const ATTACHMENT_PRIMARY_LAST: &str = r#"{"size":99,"file_size":7,"media_type":"image/png","mime_type":"application/pdf","file_type":"text/plain","name":"legacy.png","filename":"legacy.pdf","file_name":"primary.txt","uuid":"attachment-legacy","file_uuid":"attachment-primary"}"#;
        const FILE: &str = r#"{"file_uuid":"file-primary","file_name":"second.txt"}"#;
        let first = format!(
            r#"{{"uuid":"attachment-order","chat_messages":[{{"uuid":"m1","attachments":[{ATTACHMENT_PRIMARY_FIRST}],"files":[{FILE}]}}]}}"#
        );
        let last = format!(
            r#"{{"uuid":"attachment-order","chat_messages":[{{"uuid":"m1","files":[{FILE}],"attachments":[{ATTACHMENT_PRIMARY_LAST}]}}]}}"#
        );

        for export in [&first, &last] {
            let conversations =
                parse_export(Bytes::from_source(export.as_bytes().to_vec())).unwrap();
            let attachments = &conversations[0].messages[0].attachments;
            assert_eq!(attachments.len(), 2);
            assert_eq!(attachments[0].group.label(), "attachments");
            assert_eq!(attachments[1].group.label(), "files");
            assert_eq!(
                attachments[0].file_uuid.as_ref().unwrap().as_ref(),
                "attachment-primary"
            );
            assert_eq!(
                attachments[0].file_name.as_ref().unwrap().as_ref(),
                "primary.txt"
            );
            assert_eq!(
                attachments[0].media_type.as_ref().unwrap().as_ref(),
                "text/plain"
            );
            assert_eq!(attachments[0].size, Some(7));
        }

        let (first_receipts, _) = projected_receipts(&first);
        let (last_receipts, _) = projected_receipts(&last);
        assert_eq!(
            first_receipts["attachment-order/m1"].block, last_receipts["attachment-order/m1"].block,
            "object member order cannot reorder attachment groups or aliases"
        );
    }

    #[test]
    fn native_chat_messages_beats_messages_alias_in_either_member_order() {
        const NATIVE: &str = r#"[{"uuid":"native","text":"native"}]"#;
        const FALLBACK: &str = r#"[{"uuid":"fallback","text":"fallback"}]"#;
        let alias_first = format!(
            r#"{{"uuid":"conversation-list-alias","messages":{FALLBACK},"chat_messages":{NATIVE}}}"#
        );
        let native_first = format!(
            r#"{{"uuid":"conversation-list-alias","chat_messages":{NATIVE},"messages":{FALLBACK}}}"#
        );
        for export in [alias_first, native_first] {
            let conversations = parse_export(Bytes::from_source(export.into_bytes())).unwrap();
            assert_eq!(conversations[0].messages.len(), 1);
            assert_eq!(
                conversations[0].messages[0].uuid.as_ref().unwrap().as_ref(),
                "native"
            );
        }
    }

    #[test]
    fn singleton_and_array_exports_project_through_one_callback_api() {
        let directory = TempDir::new().unwrap();
        let array_path = directory.path().join("array.json");
        fs::write(&array_path, EXPORT).unwrap();
        let mut calls = 0;
        let summary = project_path(&array_path, |projected| {
            calls += 1;
            assert!(exists!(pattern!(projected.fragment.facts(), [{
                _?projection @ schema::source_projection::source_namespace:
                    &schema::source_projection::SOURCE_CLAUDE_WEB
            }])));
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(summary.files_scanned, 1);
        assert_eq!(summary.stats.messages, 3);

        let singleton = EXPORT
            .trim()
            .strip_prefix('[')
            .unwrap()
            .strip_suffix(']')
            .unwrap();
        let singleton_path = directory.path().join("singleton.json");
        fs::write(&singleton_path, singleton).unwrap();
        let summary = project_path(&singleton_path, |_| Ok(())).unwrap();
        assert_eq!(summary.stats.messages, 3);
    }
}
