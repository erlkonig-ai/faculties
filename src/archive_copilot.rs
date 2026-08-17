//! Serde-free projection of GitHub Copilot / VS Code chat-session JSON.

use std::collections::HashMap;
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProjectionSummary {
    pub files_scanned: usize,
    pub files_ignored: usize,
    pub fragments_emitted: usize,
    pub stats: ProjectionStats,
}

#[derive(Default)]
struct RootFields {
    session_id: Option<View<str>>,
    conversation_id: Option<View<str>>,
    thread_id: Option<View<str>>,
    thread_url: Option<View<str>>,
    thread_name: Option<View<str>>,
    requests: Option<Vec<Bytes>>,
    messages: Option<Vec<Bytes>>,
}

impl RootFields {
    /// Select the most semantic available identity, independent of object
    /// member order. These aliases occur across different Copilot exporters;
    /// source order must not decide which namespace an otherwise identical
    /// session inhabits.
    fn canonical_conversation_id(&self) -> Option<View<str>> {
        [
            &self.session_id,
            &self.conversation_id,
            &self.thread_id,
            &self.thread_url,
            &self.thread_name,
        ]
        .into_iter()
        .find_map(|value| {
            value
                .as_ref()
                .filter(|value| !value.as_ref().trim().is_empty())
                .cloned()
        })
    }

    fn is_recognized(&self) -> bool {
        self.requests.is_some() || self.messages.is_some()
    }
}

#[derive(Default)]
struct RequestFields {
    request_id: Option<View<str>>,
    timestamp: Option<Bytes>,
    message: Option<Bytes>,
    variable_data: Option<Bytes>,
    response: Option<Bytes>,
    result: Option<Bytes>,
}

#[derive(Default)]
struct MessageFields {
    id: Option<View<str>>,
    parent_id: Option<View<str>>,
    role: Option<View<str>>,
    timestamp: Option<Bytes>,
    content: Option<Bytes>,
    skill_executions: Option<Bytes>,
}

#[derive(Default)]
struct ResultProjection {
    session_id: Option<View<str>>,
    parts: Vec<SourcePart>,
}

#[derive(Default)]
struct VariableFields {
    kind: Option<View<str>>,
    id: Option<View<str>>,
    name: Option<View<str>>,
    media_type: Option<View<str>>,
    value: Option<Bytes>,
    references: Option<Bytes>,
    is_file: bool,
}

#[derive(Default)]
struct ToolCallFields {
    id: Option<View<str>>,
    name: Option<View<str>>,
    arguments: Option<Bytes>,
}

#[derive(Default)]
struct SkillFields {
    id: Option<View<str>>,
    name: Option<View<str>>,
    status: Option<View<str>>,
    arguments: Option<Bytes>,
    references: Option<Bytes>,
}

/// Project one chat-session JSON file, or every recognized JSON file below a directory.
pub fn project_path<F>(path: &Path, mut emit: F) -> Result<ProjectionSummary>
where
    F: FnMut(ProjectedSource) -> Result<()>,
{
    let explicit_file = path.is_file();
    let mut paths = Vec::new();
    if path.is_dir() {
        collect_json_files(path, &mut paths)?;
        paths.sort();
    } else {
        paths.push(path.to_path_buf());
    }

    let mut summary = ProjectionSummary::default();
    for source_path in paths {
        let Some(records) = parse_file(&source_path)? else {
            if explicit_file {
                bail!(
                    "{} is not a recognized Copilot chat-session JSON file",
                    source_path.display()
                );
            }
            summary.files_ignored += 1;
            continue;
        };
        let stats = archive_source::project_records(
            schema::source_projection::SOURCE_COPILOT,
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

fn collect_json_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("read {}", path.display()))? {
        let entry = entry.context("read Copilot directory entry")?;
        let entry_path = entry.path();
        let file_type = entry.file_type().context("read Copilot entry type")?;
        if file_type.is_dir() {
            collect_json_files(&entry_path, out)?;
        } else if file_type.is_file()
            && entry_path.extension().and_then(|value| value.to_str()) == Some("json")
        {
            out.push(entry_path);
        }
    }
    Ok(())
}

fn parse_file(path: &Path) -> Result<Option<Vec<SourceRecord>>> {
    // VS Code may still be updating these files. One owned snapshot avoids the
    // unsafe concurrently-mutated mmap case while retaining zero-copy views.
    let bytes = archive_source::read_file(path)?;
    let root = scan_root(bytes.clone())
        .with_context(|| format!("parse Copilot root {}", path.display()))?;
    if !root.is_recognized() {
        return Ok(None);
    }
    let default_conversation = match root.canonical_conversation_id() {
        Some(conversation) => conversation,
        None => archive_source::owned_text(fallback_conversation_id(&root, &bytes)?),
    };
    let requests = root.requests.unwrap_or_default();
    let messages = root.messages.unwrap_or_default();
    let root_locator =
        archive_source::owned_text(format!("{}/root", default_conversation.as_ref()));
    let mut records = vec![SourceRecord {
        locator: root_locator.clone(),
        raw_record: bytes,
        predecessors: Vec::new(),
        block_timestamp: None,
        threading: Threading::Transparent,
        parts: Vec::new(),
        claims: SourceClaims::default(),
    }];

    if !requests.is_empty() {
        // VS Code stores the durable conversation identity under each
        // request's `result.metadata.sessionId`, not necessarily at the file
        // root. A single editor-state file can contain more than one session,
        // so keep one predecessor frontier per nested session.
        let mut previous_by_session = HashMap::<String, View<str>>::new();
        for (ordinal, raw) in requests.into_iter().enumerate() {
            let request = scan_request(raw.clone()).with_context(|| {
                format!(
                    "parse Copilot request {} in {}",
                    ordinal + 1,
                    path.display()
                )
            })?;
            let request_id = request
                .request_id
                .clone()
                .unwrap_or_else(|| archive_source::owned_text(format!("request-{ordinal:08}")));
            let result = request
                .result
                .as_ref()
                .map(extract_result)
                .transpose()?
                .unwrap_or_default();
            let conversation = result
                .session_id
                .clone()
                .unwrap_or_else(|| default_conversation.clone());
            let session_key = conversation.as_ref().to_owned();
            let mut previous = previous_by_session
                .get(&session_key)
                .cloned()
                .unwrap_or_else(|| root_locator.clone());
            let timestamp = request.timestamp.as_ref().and_then(parse_timestamp);
            let occurrence = format!("{}/request/{}", conversation.as_ref(), request_id.as_ref());
            let user_parts = extract_user_parts(&request, &occurrence)?;
            let assistant = extract_assistant(&request, result)?;

            if !user_parts.is_empty() {
                let locator = archive_source::owned_text(format!(
                    "{}/request/{}/user",
                    conversation.as_ref(),
                    request_id.as_ref()
                ));
                records.push(SourceRecord {
                    locator: locator.clone(),
                    raw_record: raw.clone(),
                    predecessors: vec![previous],
                    block_timestamp: timestamp,
                    threading: Threading::Semantic,
                    parts: user_parts,
                    claims: SourceClaims {
                        timestamp,
                        raw_author: Some(archive_source::owned_text("user")),
                        raw_role: Some(archive_source::owned_text("user")),
                        ..SourceClaims::default()
                    },
                });
                previous = locator;
            }

            if !assistant.is_empty() {
                let locator = archive_source::owned_text(format!(
                    "{}/request/{}/assistant",
                    conversation.as_ref(),
                    request_id.as_ref()
                ));
                records.push(SourceRecord {
                    locator: locator.clone(),
                    raw_record: raw.clone(),
                    predecessors: vec![previous],
                    block_timestamp: timestamp,
                    threading: Threading::Semantic,
                    parts: assistant,
                    claims: SourceClaims {
                        timestamp,
                        raw_author: Some(archive_source::owned_text("assistant")),
                        raw_role: Some(archive_source::owned_text("assistant")),
                        ..SourceClaims::default()
                    },
                });
                previous = locator;
            }

            if request.message.is_none()
                && request.variable_data.is_none()
                && request.response.is_none()
                && request.result.is_none()
            {
                let locator = archive_source::owned_text(format!(
                    "{}/request/{}/raw",
                    conversation.as_ref(),
                    request_id.as_ref()
                ));
                records.push(SourceRecord {
                    locator: locator.clone(),
                    raw_record: raw,
                    predecessors: vec![previous],
                    block_timestamp: timestamp,
                    threading: Threading::Transparent,
                    parts: Vec::new(),
                    claims: SourceClaims {
                        timestamp,
                        ..SourceClaims::default()
                    },
                });
                previous = locator;
            }
            previous_by_session.insert(session_key, previous);
        }
    } else {
        // GitHub Copilot exports an explicit message DAG. Plan all locators
        // before projection so forks remain forks instead of being flattened
        // into the incidental array order.
        let mut planned_messages = Vec::with_capacity(messages.len());
        for (ordinal, raw) in messages.into_iter().enumerate() {
            let message = scan_message(raw.clone()).with_context(|| {
                format!(
                    "parse Copilot message {} in {}",
                    ordinal + 1,
                    path.display()
                )
            })?;
            let id = message
                .id
                .clone()
                .unwrap_or_else(|| archive_source::owned_text(format!("message-{ordinal:08}")));
            let locator = archive_source::owned_text(format!(
                "{}/message/{}",
                default_conversation.as_ref(),
                id.as_ref()
            ));
            planned_messages.push((raw, message, locator));
        }

        for (raw, message, locator) in planned_messages {
            let role = message
                .role
                .unwrap_or_else(|| archive_source::owned_text("assistant"));
            let direction = if role.as_ref() == "user" {
                schema::content_fact::direction::IN
            } else {
                schema::content_fact::direction::OUT
            };
            let mut parts = message
                .skill_executions
                .as_ref()
                .map(extract_skill_executions)
                .transpose()?
                .unwrap_or_default();
            parts.extend(
                message
                    .content
                    .as_ref()
                    .map(extract_content_value)
                    .transpose()?
                    .unwrap_or_default()
                    .into_iter()
                    .map(|value| {
                        SourcePart::text(schema::content_fact::modality::TEXT, direction, value)
                    }),
            );
            let predecessors = message.parent_id.as_ref().map_or_else(
                || vec![root_locator.clone()],
                |parent| {
                    vec![archive_source::owned_text(format!(
                        "{}/message/{}",
                        default_conversation.as_ref(),
                        parent.as_ref()
                    ))]
                },
            );
            let timestamp = message.timestamp.as_ref().and_then(parse_timestamp);
            records.push(SourceRecord {
                locator: locator.clone(),
                raw_record: raw,
                predecessors,
                block_timestamp: timestamp,
                threading: if parts.is_empty() {
                    Threading::Transparent
                } else {
                    Threading::Semantic
                },
                parts,
                claims: SourceClaims {
                    timestamp,
                    raw_author: Some(role.clone()),
                    raw_role: Some(role),
                    ..SourceClaims::default()
                },
            });
        }
    }
    Ok(Some(records))
}

fn scan_root(mut bytes: Bytes) -> std::result::Result<RootFields, sc::ScanError> {
    let mut root = RootFields::default();
    sc::skip_ws(&mut bytes);
    sc::object(&mut bytes, &mut root, |root, key, value| {
        let key = utf8_key(key)?;
        match key.as_ref() {
            "sessionId" => root.session_id = optional_string(value)?,
            "conversationId" => root.conversation_id = optional_string(value)?,
            "threadID" => root.thread_id = optional_string(value)?,
            "threadUrl" => root.thread_url = optional_string(value)?,
            "threadName" => root.thread_name = optional_string(value)?,
            "requests" => root.requests = optional_raw_array(value)?,
            "messages" => root.messages = optional_raw_array(value)?,
            _ => sc::skip_value(value)?,
        }
        Ok(root)
    })?;
    sc::skip_ws(&mut bytes);
    if !bytes.is_empty() {
        return Err(syntax("trailing bytes after Copilot root"));
    }
    Ok(root)
}

fn scan_request(mut bytes: Bytes) -> std::result::Result<RequestFields, sc::ScanError> {
    let mut request = RequestFields::default();
    sc::object(&mut bytes, &mut request, |request, key, value| {
        let key = utf8_key(key)?;
        match key.as_ref() {
            "requestId" => request.request_id = optional_string(value)?,
            "timestamp" => request.timestamp = Some(archive_source::raw_value(value)?),
            "message" => request.message = Some(archive_source::raw_value(value)?),
            "variableData" => request.variable_data = Some(archive_source::raw_value(value)?),
            "response" => request.response = Some(archive_source::raw_value(value)?),
            "result" => request.result = Some(archive_source::raw_value(value)?),
            _ => sc::skip_value(value)?,
        }
        Ok(request)
    })?;
    Ok(request)
}

fn scan_message(mut bytes: Bytes) -> std::result::Result<MessageFields, sc::ScanError> {
    #[derive(Default)]
    struct MessageAliases {
        parent_id: [Option<Option<View<str>>>; 3],
        timestamp: [Option<Option<Bytes>>; 3],
    }

    let mut state = (MessageFields::default(), MessageAliases::default());
    sc::object(&mut bytes, &mut state, |state, key, value| {
        let key = utf8_key(key)?;
        match key.as_ref() {
            "id" => state.0.id = optional_string(value)?,
            "parentMessageID" => state.1.parent_id[0] = Some(optional_string(value)?),
            "parentMessageId" => state.1.parent_id[1] = Some(optional_string(value)?),
            "parent_message_id" => state.1.parent_id[2] = Some(optional_string(value)?),
            "role" => state.0.role = optional_string(value)?,
            "createdAt" => state.1.timestamp[0] = Some(optional_raw_value(value)?),
            "created_at" => state.1.timestamp[1] = Some(optional_raw_value(value)?),
            "timestamp" => state.1.timestamp[2] = Some(optional_raw_value(value)?),
            "content" => state.0.content = Some(archive_source::raw_value(value)?),
            "skillExecutions" => state.0.skill_executions = Some(archive_source::raw_value(value)?),
            _ => sc::skip_value(value)?,
        }
        Ok(state)
    })?;
    let (mut message, aliases) = state;
    message.parent_id = preferred_alias(aliases.parent_id);
    message.timestamp = preferred_alias(aliases.timestamp);
    Ok(message)
}

fn extract_message_text(bytes: &Bytes) -> Result<Vec<View<str>>> {
    let mut input = bytes.clone();
    let mut values = Vec::new();
    if input.first().copied() == Some(b'"') {
        values.push(archive_source::string(&mut input)?);
        return Ok(values);
    }
    if input.first().copied() != Some(b'{') {
        return Ok(values);
    }
    let mut fields = (None::<View<str>>, Vec::<View<str>>::new());
    sc::object(&mut input, &mut fields, |fields, key, value| {
        let key = utf8_key(key)?;
        match key.as_ref() {
            "text" => {
                if let Some(text) = optional_string(value)? {
                    if !text.as_ref().trim().is_empty() {
                        fields.0 = Some(text);
                    }
                }
            }
            "parts" => fields.1 = text_array(value)?,
            _ => sc::skip_value(value)?,
        }
        Ok(fields)
    })?;
    // VS Code stores `text` as the aggregate of `parts`. Treat it as the
    // canonical message when present; reading both duplicates every prompt.
    Ok(match fields.0 {
        Some(text) => vec![text],
        None => fields.1,
    })
}

fn extract_user_parts(request: &RequestFields, occurrence: &str) -> Result<Vec<SourcePart>> {
    let mut parts = request
        .message
        .as_ref()
        .map(extract_message_text)
        .transpose()?
        .unwrap_or_default()
        .into_iter()
        .map(|value| {
            SourcePart::text(
                schema::content_fact::modality::TEXT,
                schema::content_fact::direction::IN,
                value,
            )
        })
        .collect::<Vec<_>>();
    if let Some(variable_data) = request.variable_data.as_ref() {
        parts.extend(extract_variable_parts(variable_data, occurrence)?);
    }
    Ok(parts)
}

fn extract_assistant(request: &RequestFields, result: ResultProjection) -> Result<Vec<SourcePart>> {
    let mut parts = result.parts;
    let has_final_text = parts.iter().any(|part| {
        matches!(
            part,
            SourcePart::Text { modality, .. }
                if *modality == schema::content_fact::modality::TEXT
        )
    });
    if !has_final_text {
        parts.extend(
            request
                .response
                .as_ref()
                .map(extract_content_value)
                .transpose()?
                .unwrap_or_default()
                .into_iter()
                .map(|value| {
                    SourcePart::text(
                        schema::content_fact::modality::TEXT,
                        schema::content_fact::direction::OUT,
                        value,
                    )
                }),
        );
    }
    Ok(parts)
}

fn extract_result(bytes: &Bytes) -> Result<ResultProjection> {
    let mut input = bytes.clone();
    let mut metadata = None;
    if input.first().copied() != Some(b'{') {
        return Ok(ResultProjection::default());
    }
    sc::object(&mut input, &mut metadata, |metadata, key, value| {
        if utf8_key(key)?.as_ref() == "metadata" {
            *metadata = Some(archive_source::raw_value(value)?);
        } else {
            sc::skip_value(value)?;
        }
        Ok(metadata)
    })?;
    let Some(mut metadata) = metadata else {
        return Ok(ResultProjection::default());
    };

    #[derive(Default)]
    struct MetadataFields {
        session_id: Option<View<str>>,
        messages: Option<Bytes>,
        tool_rounds: Option<Bytes>,
    }

    let mut fields = MetadataFields::default();
    sc::object(&mut metadata, &mut fields, |fields, key, value| {
        match utf8_key(key)?.as_ref() {
            "sessionId" => fields.session_id = optional_string(value)?,
            "messages" => fields.messages = Some(archive_source::raw_value(value)?),
            "toolCallRounds" => fields.tool_rounds = Some(archive_source::raw_value(value)?),
            _ => sc::skip_value(value)?,
        }
        Ok(fields)
    })?;

    // Tool calls/results causally precede the final assistant response even
    // though VS Code's metadata object may serialize `messages` first.
    let mut parts = fields
        .tool_rounds
        .as_ref()
        .map(tool_round_parts)
        .transpose()?
        .unwrap_or_default();
    if let Some(mut messages) = fields.messages {
        parts.extend(assistant_messages(&mut messages)?.into_iter().map(|value| {
            SourcePart::text(
                schema::content_fact::modality::TEXT,
                schema::content_fact::direction::OUT,
                value,
            )
        }));
    }
    Ok(ResultProjection {
        session_id: fields.session_id,
        parts,
    })
}

fn assistant_messages(bytes: &mut Bytes) -> std::result::Result<Vec<View<str>>, sc::ScanError> {
    let mut latest = Vec::new();
    sc::array(bytes, &mut latest, |latest, element| {
        if element.first().copied() != Some(b'{') {
            sc::skip_value(element)?;
            return Ok(latest);
        }
        let raw = archive_source::raw_value(element)?;
        let message = scan_message(raw)?;
        if message.role.as_ref().map(AsRef::as_ref) == Some("assistant") {
            *latest = message
                .content
                .as_ref()
                .map(|content| extract_content_value_scan(&mut content.clone()))
                .transpose()?
                .unwrap_or_default();
        }
        Ok(latest)
    })?;
    Ok(latest)
}

fn tool_round_parts(bytes: &Bytes) -> Result<Vec<SourcePart>> {
    let mut input = bytes.clone();
    let parts = sc::array(&mut input, Vec::new(), |mut parts, element| {
        if element.first().copied() != Some(b'{') {
            sc::skip_value(element)?;
            return Ok(parts);
        }

        #[derive(Default)]
        struct RoundFields {
            calls: Option<Bytes>,
            response: Option<Bytes>,
        }
        let fields = sc::object(element, RoundFields::default(), |mut fields, key, value| {
            match utf8_key(key)?.as_ref() {
                "toolCalls" => fields.calls = Some(archive_source::raw_value(value)?),
                "response" => fields.response = Some(archive_source::raw_value(value)?),
                _ => sc::skip_value(value)?,
            }
            Ok(fields)
        })?;
        if let Some(calls) = fields.calls {
            parts.extend(tool_call_parts(&calls)?);
        }
        if let Some(mut response) = fields.response {
            parts.extend(
                extract_content_value_scan(&mut response)?
                    .into_iter()
                    .map(|value| {
                        SourcePart::text(
                            schema::content_fact::modality::TOOL_RESULT,
                            schema::content_fact::direction::IN,
                            value,
                        )
                    }),
            );
        }
        Ok(parts)
    })?;
    Ok(parts)
}

fn tool_call_parts(bytes: &Bytes) -> std::result::Result<Vec<SourcePart>, sc::ScanError> {
    let mut input = bytes.clone();
    sc::array(&mut input, Vec::new(), |mut parts, element| {
        if element.first().copied() != Some(b'{') {
            sc::skip_value(element)?;
            return Ok(parts);
        }
        let fields = sc::object(
            element,
            ToolCallFields::default(),
            |mut fields, key, value| {
                match utf8_key(key)?.as_ref() {
                    "id" | "callId" | "toolCallId" => fields.id = optional_string(value)?,
                    "name" | "toolId" => fields.name = optional_string(value)?,
                    "arguments" | "input" => {
                        fields.arguments = Some(archive_source::raw_value(value)?)
                    }
                    _ => sc::skip_value(value)?,
                }
                Ok(fields)
            },
        )?;
        if let Some(value) = tool_call_text(&fields)? {
            parts.push(SourcePart::text(
                schema::content_fact::modality::TOOL_CALL,
                schema::content_fact::direction::OUT,
                value,
            ));
        }
        Ok(parts)
    })
}

fn tool_call_text(
    fields: &ToolCallFields,
) -> std::result::Result<Option<View<str>>, sc::ScanError> {
    if fields.id.is_none() && fields.name.is_none() && fields.arguments.is_none() {
        return Ok(None);
    }
    let mut lines = Vec::new();
    if let Some(name) = fields.name.as_ref() {
        lines.push(format!("name: {}", name.as_ref()));
    }
    if let Some(id) = fields.id.as_ref() {
        lines.push(format!("id: {}", id.as_ref()));
    }
    if let Some(arguments) = fields.arguments.as_ref() {
        lines.push(format!("arguments: {}", semantic_json_value(arguments)?));
    }
    Ok(Some(archive_source::owned_text(lines.join("\n"))))
}

fn semantic_json_value(bytes: &Bytes) -> std::result::Result<String, sc::ScanError> {
    let mut input = bytes.clone();
    sc::skip_ws(&mut input);
    if input.first().copied() == Some(b'"') {
        return archive_source::string(&mut input).map(|value| value.as_ref().to_owned());
    }
    archive_source::canonical_json(bytes.clone())
}

fn extract_skill_executions(bytes: &Bytes) -> Result<Vec<SourcePart>> {
    let mut input = bytes.clone();
    let parts = sc::array(&mut input, Vec::new(), |mut parts, element| {
        if element.first().copied() != Some(b'{') {
            sc::skip_value(element)?;
            return Ok(parts);
        }
        let fields = sc::object(element, SkillFields::default(), |mut fields, key, value| {
            match utf8_key(key)?.as_ref() {
                "callId" | "id" | "toolCallId" => fields.id = optional_string(value)?,
                "slug" | "name" => fields.name = optional_string(value)?,
                "status" => fields.status = optional_string(value)?,
                "arguments" | "input" => fields.arguments = Some(archive_source::raw_value(value)?),
                "references" | "result" => {
                    fields.references = Some(archive_source::raw_value(value)?)
                }
                _ => sc::skip_value(value)?,
            }
            Ok(fields)
        })?;

        let call = ToolCallFields {
            id: fields.id.clone(),
            name: fields.name.clone(),
            arguments: fields.arguments.clone(),
        };
        if let Some(value) = tool_call_text(&call)? {
            parts.push(SourcePart::text(
                schema::content_fact::modality::TOOL_CALL,
                schema::content_fact::direction::OUT,
                value,
            ));
        }

        if let Some(status) = fields.status.as_ref() {
            let mut value = format!("status: {}", status.as_ref());
            if let Some(id) = fields.id.as_ref() {
                value.push_str("\nid: ");
                value.push_str(id.as_ref());
            }
            parts.push(SourcePart::text(
                schema::content_fact::modality::TOOL_RESULT,
                schema::content_fact::direction::IN,
                archive_source::owned_text(value),
            ));
        }
        if let Some(references) = fields.references {
            let value = semantic_json_value(&references)?;
            if !matches!(value.trim(), "" | "[]" | "null") {
                parts.push(SourcePart::text(
                    schema::content_fact::modality::TOOL_RESULT,
                    schema::content_fact::direction::IN,
                    archive_source::owned_text(value),
                ));
            }
        }
        Ok(parts)
    })?;
    Ok(parts)
}

fn extract_variable_parts(bytes: &Bytes, occurrence: &str) -> Result<Vec<SourcePart>> {
    let mut input = bytes.clone();
    if input.first().copied() != Some(b'{') {
        return Ok(Vec::new());
    }
    let mut variables = None;
    sc::object(&mut input, &mut variables, |variables, key, value| {
        if utf8_key(key)?.as_ref() == "variables" {
            *variables = Some(archive_source::raw_value(value)?);
        } else {
            sc::skip_value(value)?;
        }
        Ok(variables)
    })?;
    let Some(mut variables) = variables else {
        return Ok(Vec::new());
    };
    let variables = raw_array(&mut variables)?;
    let mut parts = Vec::new();
    for (ordinal, mut variable) in variables.into_iter().enumerate() {
        if variable.first().copied() != Some(b'{') {
            continue;
        }
        let fields = scan_variable(&mut variable)?;
        if let Some(part) = variable_part(fields, occurrence, ordinal)? {
            parts.push(part);
        }
    }
    Ok(parts)
}

fn scan_variable(bytes: &mut Bytes) -> std::result::Result<VariableFields, sc::ScanError> {
    sc::object(
        bytes,
        VariableFields::default(),
        |mut fields, key, value| {
            match utf8_key(key)?.as_ref() {
                "kind" => fields.kind = optional_string(value)?,
                "id" => fields.id = optional_string(value)?,
                "name" | "fileName" => fields.name = optional_string(value)?,
                "mimeType" | "mediaType" => fields.media_type = optional_string(value)?,
                "value" => fields.value = Some(archive_source::raw_value(value)?),
                "references" => fields.references = Some(archive_source::raw_value(value)?),
                "isFile" => fields.is_file = optional_bool(value)?.unwrap_or(false),
                _ => sc::skip_value(value)?,
            }
            Ok(fields)
        },
    )
}

fn variable_part(
    fields: VariableFields,
    occurrence: &str,
    ordinal: usize,
) -> std::result::Result<Option<SourcePart>, sc::ScanError> {
    let kind = fields.kind.as_ref().map(AsRef::as_ref).unwrap_or_default();
    let is_image = kind == "image";
    let is_file = kind == "file" || fields.is_file;
    if !is_image && !is_file {
        return Ok(None);
    }

    let resolved = if is_image {
        fields
            .value
            .as_ref()
            .map(embedded_bytes)
            .transpose()?
            .flatten()
    } else {
        None
    };
    // A resolved image value is usually a very large numeric byte object.
    // Do not recursively rescan it looking for a URI; the stable id or the
    // small `references` envelope supplies the source pointer.
    let value_pointer = if is_image && resolved.is_some() {
        None
    } else {
        fields
            .value
            .as_ref()
            .map(external_pointer)
            .transpose()?
            .flatten()
    };
    let reference_pointer = fields
        .references
        .as_ref()
        .map(external_pointer)
        .transpose()?
        .flatten();
    let pointer = if is_image {
        fields
            .id
            .filter(|value| !value.as_ref().is_empty())
            .or(reference_pointer)
            .or(value_pointer)
    } else {
        value_pointer
            .or(reference_pointer)
            .or_else(|| fields.id.filter(|value| !value.as_ref().is_empty()))
    }
    .unwrap_or_else(|| archive_source::owned_text(format!("{occurrence}/variable/{ordinal}")));

    let media_type = normalized_media_type(
        fields.media_type.as_ref(),
        fields.name.as_ref().or(Some(&pointer)),
        resolved.as_ref().map(AsRef::as_ref),
    );
    let modality = if is_image {
        schema::content_fact::modality::IMAGE
    } else {
        media_type
            .as_ref()
            .map(|value| archive_source::modality_for_media_type(value.as_ref()))
            .unwrap_or(schema::content_fact::modality::FILE)
    };
    let size = resolved.as_ref().map(|bytes| bytes.len() as u128);
    Ok(Some(SourcePart::Pointer {
        modality,
        direction: schema::content_fact::direction::IN,
        namespace: schema::source_projection::SOURCE_COPILOT,
        pointer,
        media_type,
        size,
        resolved,
    }))
}

fn external_pointer(bytes: &Bytes) -> std::result::Result<Option<View<str>>, sc::ScanError> {
    if let Some(pointer) = find_string_field(bytes, "external")? {
        return Ok(Some(pointer));
    }
    if let Some(pointer) = find_string_field(bytes, "path")? {
        return Ok(Some(pointer));
    }
    find_string_field(bytes, "fsPath")
}

fn find_string_field(
    bytes: &Bytes,
    wanted: &str,
) -> std::result::Result<Option<View<str>>, sc::ScanError> {
    fn visit(
        bytes: &mut Bytes,
        wanted: &str,
    ) -> std::result::Result<Option<View<str>>, sc::ScanError> {
        sc::skip_ws(bytes);
        match bytes.first().copied() {
            Some(b'{') => sc::object(bytes, None, |found, key, value| {
                if found.is_some() {
                    sc::skip_value(value)?;
                    return Ok(found);
                }
                if utf8_key(key)?.as_ref() == wanted {
                    return optional_string(value);
                }
                visit(value, wanted)
            }),
            Some(b'[') => sc::array(bytes, None, |found, value| {
                if found.is_some() {
                    sc::skip_value(value)?;
                    Ok(found)
                } else {
                    visit(value, wanted)
                }
            }),
            Some(_) => {
                sc::skip_value(bytes)?;
                Ok(None)
            }
            None => Ok(None),
        }
    }
    visit(&mut bytes.clone(), wanted)
}

fn embedded_bytes(bytes: &Bytes) -> std::result::Result<Option<Bytes>, sc::ScanError> {
    let mut input = bytes.clone();
    sc::skip_ws(&mut input);
    let values = match input.first().copied() {
        Some(b'[') => byte_array(&mut input)?,
        Some(b'{') => byte_object(&mut input)?,
        Some(_) => {
            sc::skip_value(&mut input)?;
            None
        }
        None => None,
    };
    Ok(values.map(Bytes::from_source))
}

fn byte_array(bytes: &mut Bytes) -> std::result::Result<Option<Vec<u8>>, sc::ScanError> {
    sc::array(bytes, Some(Vec::new()), |values, value| {
        let Some(mut values) = values else {
            sc::skip_value(value)?;
            return Ok(None);
        };
        let raw = sc::parse_number(value)?;
        let number = raw
            .view::<str>()
            .map_err(|_| syntax("Copilot byte value is not UTF-8"))?
            .as_ref()
            .parse::<u8>()
            .map_err(|_| syntax("Copilot byte value is outside u8"))?;
        values.push(number);
        Ok(Some(values))
    })
}

fn byte_object(bytes: &mut Bytes) -> std::result::Result<Option<Vec<u8>>, sc::ScanError> {
    #[derive(Default)]
    struct Fields {
        numeric: Option<Vec<u8>>,
        data: Option<Vec<u8>>,
    }
    let fields = sc::object(
        bytes,
        Fields {
            numeric: Some(Vec::new()),
            data: None,
        },
        |mut fields, key, value| {
            let key = utf8_key(key)?;
            if key.as_ref() == "data" && value.first().copied() == Some(b'[') {
                fields.data = byte_array(value)?;
                return Ok(fields);
            }
            let Ok(index) = key.as_ref().parse::<usize>() else {
                fields.numeric = None;
                sc::skip_value(value)?;
                return Ok(fields);
            };
            let Some(numeric) = fields.numeric.as_mut() else {
                sc::skip_value(value)?;
                return Ok(fields);
            };
            if index != numeric.len() {
                fields.numeric = None;
                sc::skip_value(value)?;
                return Ok(fields);
            }
            let raw = sc::parse_number(value)?;
            let number = raw
                .view::<str>()
                .map_err(|_| syntax("Copilot byte value is not UTF-8"))?
                .as_ref()
                .parse::<u8>()
                .map_err(|_| syntax("Copilot byte value is outside u8"))?;
            numeric.push(number);
            Ok(fields)
        },
    )?;
    Ok(fields
        .data
        .or(fields.numeric)
        .filter(|bytes| !bytes.is_empty()))
}

fn normalized_media_type(
    explicit: Option<&View<str>>,
    name: Option<&View<str>>,
    bytes: Option<&[u8]>,
) -> Option<View<str>> {
    let explicit = explicit.and_then(|value| {
        let value = value.as_ref().trim().to_ascii_lowercase();
        let normalized = match value.as_str() {
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            "gif" => "image/gif",
            "webp" => "image/webp",
            "pdf" => "application/pdf",
            "txt" | "text" => "text/plain",
            value if value.contains('/') => value.split(';').next()?,
            _ => return None,
        };
        Some(normalized.to_owned())
    });
    let inferred = name.and_then(|name| {
        let extension = name.as_ref().rsplit_once('.')?.1.to_ascii_lowercase();
        Some(
            match extension.as_str() {
                "png" => "image/png",
                "jpg" | "jpeg" => "image/jpeg",
                "gif" => "image/gif",
                "webp" => "image/webp",
                "svg" => "image/svg+xml",
                "pdf" => "application/pdf",
                "txt" | "md" | "rs" | "py" | "js" | "ts" => "text/plain",
                "json" => "application/json",
                "csv" => "text/csv",
                _ => return None,
            }
            .to_owned(),
        )
    });
    let sniffed = bytes.and_then(|bytes| {
        if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            Some("image/png")
        } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
            Some("image/jpeg")
        } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
            Some("image/gif")
        } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
            Some("image/webp")
        } else {
            None
        }
    });
    explicit
        .or(inferred)
        .or_else(|| sniffed.map(str::to_owned))
        .map(archive_source::owned_text)
}

fn extract_content_value(bytes: &Bytes) -> Result<Vec<View<str>>> {
    extract_content_value_scan(&mut bytes.clone()).map_err(Into::into)
}

fn extract_content_value_scan(
    bytes: &mut Bytes,
) -> std::result::Result<Vec<View<str>>, sc::ScanError> {
    match bytes.first().copied() {
        Some(b'"') => optional_string(bytes).map(|value| value.into_iter().collect()),
        Some(b'[') => text_array(bytes),
        Some(b'{') => {
            let mut values = Vec::new();
            sc::object(bytes, &mut values, |values, key, value| {
                match utf8_key(key)?.as_ref() {
                    "text" | "value" => {
                        if let Some(text) = optional_string(value)? {
                            if !text.as_ref().trim().is_empty() && text.as_ref() != "````" {
                                values.push(text);
                            }
                        }
                    }
                    "parts" => values.extend(text_array(value)?),
                    _ => sc::skip_value(value)?,
                }
                Ok(values)
            })?;
            Ok(values)
        }
        _ => {
            sc::skip_value(bytes)?;
            Ok(Vec::new())
        }
    }
}

fn text_array(bytes: &mut Bytes) -> std::result::Result<Vec<View<str>>, sc::ScanError> {
    let mut values = Vec::new();
    sc::array(bytes, &mut values, |values, element| {
        values.extend(extract_content_value_scan(element)?);
        Ok(values)
    })?;
    Ok(values)
}

fn raw_array(bytes: &mut Bytes) -> std::result::Result<Vec<Bytes>, sc::ScanError> {
    let mut values = Vec::new();
    if bytes.first().copied() != Some(b'[') {
        sc::skip_value(bytes)?;
        return Ok(values);
    }
    sc::array(bytes, &mut values, |values, element| {
        values.push(archive_source::raw_value(element)?);
        Ok(values)
    })?;
    Ok(values)
}

fn optional_raw_array(bytes: &mut Bytes) -> std::result::Result<Option<Vec<Bytes>>, sc::ScanError> {
    sc::skip_ws(bytes);
    if bytes.first().copied() != Some(b'[') {
        sc::skip_value(bytes)?;
        return Ok(None);
    }
    raw_array(bytes).map(Some)
}

fn optional_string(bytes: &mut Bytes) -> std::result::Result<Option<View<str>>, sc::ScanError> {
    if bytes.first().copied() == Some(b'"') {
        archive_source::string(bytes).map(Some)
    } else {
        sc::skip_value(bytes)?;
        Ok(None)
    }
}

/// Resolve source-schema aliases by semantic priority rather than JSON member
/// order. The outer option records presence, so a preferred explicit `null`
/// remains authoritative over lower-priority spellings.
fn preferred_alias<T, const N: usize>(aliases: [Option<Option<T>>; N]) -> Option<T> {
    for alias in aliases {
        if let Some(value) = alias {
            return value;
        }
    }
    None
}

fn optional_raw_value(bytes: &mut Bytes) -> std::result::Result<Option<Bytes>, sc::ScanError> {
    sc::skip_ws(bytes);
    if bytes.starts_with(b"null") {
        sc::expect_literal(bytes, b"null")?;
        Ok(None)
    } else {
        archive_source::raw_value(bytes).map(Some)
    }
}

fn optional_bool(bytes: &mut Bytes) -> std::result::Result<Option<bool>, sc::ScanError> {
    sc::skip_ws(bytes);
    if bytes.starts_with(b"true") {
        sc::expect_literal(bytes, b"true")?;
        Ok(Some(true))
    } else if bytes.starts_with(b"false") {
        sc::expect_literal(bytes, b"false")?;
        Ok(Some(false))
    } else {
        sc::skip_value(bytes)?;
        Ok(None)
    }
}

fn utf8_key(bytes: Bytes) -> std::result::Result<View<str>, sc::ScanError> {
    bytes
        .view::<str>()
        .map_err(|_| syntax("object key is not UTF-8"))
}

fn syntax(message: &str) -> sc::ScanError {
    sc::ScanError::Syntax(message.to_owned())
}

fn parse_timestamp(
    raw: &Bytes,
) -> Option<triblespace::prelude::Inline<triblespace::prelude::inlineencodings::NsTAIInterval>> {
    let mut value = raw.clone();
    let epoch = if value.first().copied() == Some(b'"') {
        let text = archive_source::string(&mut value).ok()?;
        parse_epoch_str(text.as_ref())?
    } else {
        let number = sc::parse_number(&mut value).ok()?;
        let text = number.view::<str>().ok()?;
        parse_epoch_number(text.as_ref().parse().ok()?)?
    };
    (epoch, epoch).try_to_inline().ok()
}

fn parse_epoch_str(value: &str) -> Option<Epoch> {
    let value = value.trim();
    value
        .parse::<Epoch>()
        .ok()
        .or_else(|| value.parse::<f64>().ok().and_then(parse_epoch_number))
}

fn parse_epoch_number(value: f64) -> Option<Epoch> {
    value.is_finite().then(|| {
        let seconds = if value.abs() > 1.0e11 {
            value / 1000.0
        } else {
            value
        };
        Epoch::from_unix_seconds(seconds)
    })
}

/// Derive a path-independent identity when the root has no conversation alias.
///
/// A native first request/message identifier is the strongest birth anchor the
/// two Copilot formats expose. If that identifier is absent, hashing only the
/// first array element keeps the fallback stable when later elements are
/// appended; hashing the whole editor-state file would rename every existing
/// receipt on each append. An entirely empty, anonymous file has no
/// append-stable identity in the format, so its exact root bytes are the only
/// available distinguishing evidence until the first record appears.
fn fallback_conversation_id(root: &RootFields, exact_root: &Bytes) -> Result<String> {
    if let Some(raw) = root.requests.as_ref().and_then(|requests| requests.first()) {
        let request = scan_request(raw.clone())?;
        if let Some(request_id) = request
            .request_id
            .filter(|request_id| !request_id.as_ref().trim().is_empty())
        {
            return Ok(format!("copilot:request/v1/{}", request_id.as_ref()));
        }
        return Ok(format!(
            "copilot:request-birth/v1/{}",
            blake3::hash(raw.as_ref()).to_hex()
        ));
    }
    if let Some(raw) = root.messages.as_ref().and_then(|messages| messages.first()) {
        let message = scan_message(raw.clone())?;
        if let Some(message_id) = message
            .id
            .filter(|message_id| !message_id.as_ref().trim().is_empty())
        {
            return Ok(format!("copilot:message/v1/{}", message_id.as_ref()));
        }
        return Ok(format!(
            "copilot:message-birth/v1/{}",
            blake3::hash(raw.as_ref()).to_hex()
        ));
    }
    Ok(format!(
        "copilot:empty/v1/{}",
        blake3::hash(exact_root.as_ref()).to_hex()
    ))
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
    use triblespace::core::repo::{BlobStore, BlobStoreGet};
    use triblespace::prelude::blobencodings::RawBytes;
    use triblespace::prelude::inlineencodings::Handle;
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
    fn session_id_and_request_ids_are_stable_without_a_dom() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("session.json");
        fs::write(
            &path,
            r#"{"sessionId":"s-1","requests":[{"requestId":"r-1","timestamp":1710000000000,"message":{"text":"hello","parts":[{"text":"hello"}]},"response":[{"value":"world"}]}]}"#,
        )
        .unwrap();
        let mut fragments = Vec::new();
        let summary = project_path(&path, |projected| {
            fragments.push(projected.fragment);
            Ok(())
        })
        .unwrap();
        assert_eq!(summary.files_scanned, 1);
        assert_eq!(summary.fragments_emitted, 3); // source receipt + user + assistant
        assert_eq!(summary.stats.records_seen, 3);
        assert_eq!(summary.stats.content_parts, 2);
        assert_eq!(summary.stats.raw_only_records, 1);
    }

    #[test]
    fn explicit_empty_session_is_retained_as_an_exact_raw_only_receipt() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.json");
        let source = r#"{"sessionId":"empty-session","requests":[]}"#;
        fs::write(&path, source).unwrap();

        let absent_path = dir.path().join("not-a-session.json");
        fs::write(&absent_path, r#"{"sessionId":"mere-metadata"}"#).unwrap();
        assert!(
            parse_file(&absent_path).unwrap().is_none(),
            "an identity alias without a session/message collection stays unrecognized"
        );

        let records = parse_file(&path)
            .unwrap()
            .expect("explicit session is recognized");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].locator.as_ref(), "empty-session/root");
        assert_eq!(records[0].raw_record.as_ref(), source.as_bytes());
        assert!(records[0].parts.is_empty());
        assert_eq!(records[0].threading, Threading::Transparent);

        let mut emitted = Vec::new();
        let summary = project_path(&path, |projected| {
            emitted.push(projected.fragment);
            Ok(())
        })
        .unwrap();
        assert_eq!(summary.files_scanned, 1);
        assert_eq!(summary.fragments_emitted, 1);
        assert_eq!(summary.stats.records_seen, 1);
        assert_eq!(summary.stats.raw_only_records, 1);

        let projection = emitted[0].root().expect("receipt has one root");
        let raw: Inline<Handle<RawBytes>> = find!(
            raw: Inline<Handle<RawBytes>>,
            pattern!(&emitted[0], [{
                projection @ schema::source_projection::raw_record: ?raw
            }])
        )
        .next()
        .expect("receipt retains exact source bytes");
        let reader = emitted[0]
            .blobs_mut()
            .reader()
            .expect("MemoryBlobStore reader construction is infallible");
        let recovered: Bytes = reader.get(raw).unwrap();
        assert_eq!(recovered.as_ref(), source.as_bytes());
    }

    #[test]
    fn rootless_move_and_append_do_not_rename_existing_source_occurrences() {
        let dir = TempDir::new().unwrap();
        let before_path = dir.path().join("before.json");
        let moved_dir = dir.path().join("moved");
        fs::create_dir_all(&moved_dir).unwrap();
        let after_path = moved_dir.join("renamed.json");
        let first_request = r#"{"message":"same birth"}"#;
        fs::write(&before_path, format!(r#"{{"requests":[{first_request}]}}"#)).unwrap();
        fs::write(
            &after_path,
            format!(r#"{{"requests":[{first_request},{{"message":"appended"}}]}}"#),
        )
        .unwrap();

        let before = parse_file(&before_path).unwrap().unwrap();
        let after = parse_file(&after_path).unwrap().unwrap();
        assert_eq!(before.len(), 2); // exact root receipt + first user message
        assert_eq!(after.len(), 3);
        assert_eq!(before[0].locator, after[0].locator);
        assert_eq!(before[1].locator, after[1].locator);
        assert!(before[0]
            .locator
            .as_ref()
            .starts_with("copilot:request-birth/v1/"));

        let mut before_fragments = Vec::new();
        project_path(&before_path, |projected| {
            before_fragments.push(projected.fragment);
            Ok(())
        })
        .unwrap();
        let mut after_fragments = Vec::new();
        project_path(&after_path, |projected| {
            after_fragments.push(projected.fragment);
            Ok(())
        })
        .unwrap();
        assert_ne!(
            before_fragments[0].root(),
            after_fragments[0].root(),
            "the exact root envelope changed when another request was appended"
        );
        assert_eq!(
            before_fragments[1].root(),
            after_fragments[1].root(),
            "the unchanged first request keeps its path-independent identity"
        );
    }

    #[test]
    fn conversation_alias_priority_is_independent_of_object_member_order() {
        let dir = TempDir::new().unwrap();
        let first_path = dir.path().join("first.json");
        let second_path = dir.path().join("second.json");
        let request = r#"{"requestId":"r-1","message":"hello"}"#;
        fs::write(
            &first_path,
            format!(
                r#"{{"threadUrl":"thread-url","conversationId":"conversation-id","sessionId":"session-id","requests":[{request}]}}"#
            ),
        )
        .unwrap();
        fs::write(
            &second_path,
            format!(
                r#"{{"sessionId":"session-id","conversationId":"conversation-id","threadUrl":"thread-url","requests":[{request}]}}"#
            ),
        )
        .unwrap();

        let first_records = parse_file(&first_path).unwrap().unwrap();
        let second_records = parse_file(&second_path).unwrap().unwrap();
        let first_locators: Vec<_> = first_records
            .iter()
            .map(|record| record.locator.as_ref())
            .collect();
        let second_locators: Vec<_> = second_records
            .iter()
            .map(|record| record.locator.as_ref())
            .collect();
        assert_eq!(first_locators, second_locators);
        assert_eq!(first_locators[0], "session-id/root");
        assert_eq!(first_locators[1], "session-id/request/r-1/user");

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
        assert_ne!(
            first_fragments[0].root(),
            second_fragments[0].root(),
            "exact root receipts retain distinct source member order"
        );
        assert_eq!(
            first_fragments[1].root(),
            second_fragments[1].root(),
            "semantic child receipt identity uses fixed alias priority"
        );
        assert_eq!(
            semantic_identity(&first_fragments[1]),
            semantic_identity(&second_fragments[1])
        );
    }

    #[test]
    fn message_alias_priority_is_order_independent_and_preferred_null_is_authoritative() {
        for raw in [
            r#"{"parentMessageID":null,"parentMessageId":"legacy-parent","parent_message_id":"older-parent","createdAt":null,"created_at":1710000000000,"timestamp":1720000000000}"#,
            r#"{"timestamp":1720000000000,"created_at":1710000000000,"createdAt":null,"parent_message_id":"older-parent","parentMessageId":"legacy-parent","parentMessageID":null}"#,
        ] {
            let message = scan_message(Bytes::from_source(raw.as_bytes().to_vec())).unwrap();
            assert!(message.parent_id.is_none());
            assert!(message.timestamp.is_none());
        }

        for raw in [
            r#"{"parentMessageID":"preferred-parent","parentMessageId":"legacy-parent","parent_message_id":"older-parent","createdAt":1700000000000,"created_at":1710000000000,"timestamp":1720000000000}"#,
            r#"{"timestamp":1720000000000,"created_at":1710000000000,"createdAt":1700000000000,"parent_message_id":"older-parent","parentMessageId":"legacy-parent","parentMessageID":"preferred-parent"}"#,
        ] {
            let message = scan_message(Bytes::from_source(raw.as_bytes().to_vec())).unwrap();
            assert_eq!(message.parent_id.unwrap().as_ref(), "preferred-parent");
            assert_eq!(message.timestamp.unwrap().as_ref(), b"1700000000000");
        }
    }

    #[test]
    fn github_parent_ids_preserve_forks_instead_of_array_order() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("github.json");
        fs::write(
            &path,
            r#"{"conversationId":"c-1","messages":[{"id":"root","role":"user","createdAt":"2026-02-17T10:00:00Z"},{"id":"u-1","parentMessageID":"root","role":"user","content":"first","createdAt":"2026-02-17T10:01:00Z"},{"id":"a-1","parentMessageID":"u-1","role":"assistant","content":"answer","createdAt":"2026-02-17T10:02:00Z"},{"id":"u-fork","parentMessageID":"root","role":"user","content":"fork","createdAt":"2026-02-17T10:03:00Z"}]}"#,
        )
        .unwrap();

        let records = parse_file(&path).unwrap().unwrap();
        let fork = records
            .iter()
            .find(|record| record.locator.as_ref() == "c-1/message/u-fork")
            .unwrap();
        assert_eq!(fork.predecessors.len(), 1);
        assert_eq!(fork.predecessors[0].as_ref(), "c-1/message/root");

        let answer = records
            .iter()
            .find(|record| record.locator.as_ref() == "c-1/message/a-1")
            .unwrap();
        assert_eq!(answer.predecessors[0].as_ref(), "c-1/message/u-1");
    }

    #[test]
    fn vscode_nested_sessions_tools_and_embedded_media_preserve_source_semantics() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("editor-state.json");
        let first_request = r#"{"requestId":"r-a","message":{"text":"hello","parts":[{"text":"hello"}]},"variableData":{"variables":[{"kind":"image","value":{"0":137,"1":80,"2":78,"3":71,"4":13,"5":10,"6":26,"7":10},"id":"image-sha","name":"pasted.png","mimeType":"image/png"},{"kind":"file","id":"vscode.implicit.selection","name":"lib.rs","value":{"uri":{"external":"file:///repo/src/lib.rs"}}}]},"result":{"metadata":{"messages":[{"role":"assistant","content":"done"}],"sessionId":"session-a","toolCallRounds":[{"response":"file contents","toolCalls":[{"name":"read_file","arguments":"{\"filePath\":\"/repo/src/lib.rs\"}","id":"call-1"}]}]}}}"#;
        let source = format!(
            r#"{{"requests":[{first_request},{{"requestId":"r-b","message":"other session","result":{{"metadata":{{"sessionId":"session-b","messages":[{{"role":"assistant","content":"other answer"}}]}}}}}},{{"requestId":"r-a2","message":"same session again","result":{{"metadata":{{"sessionId":"session-a","messages":[{{"role":"assistant","content":"second answer"}}]}}}}}}]}}"#
        );
        fs::write(&path, &source).unwrap();

        let records = parse_file(&path).unwrap().unwrap();
        let first_user = records
            .iter()
            .find(|record| record.locator.as_ref() == "session-a/request/r-a/user")
            .unwrap();
        assert_eq!(first_user.raw_record.as_ref(), first_request.as_bytes());
        assert_eq!(first_user.parts.len(), 3);
        match &first_user.parts[1] {
            SourcePart::Pointer {
                modality,
                pointer,
                media_type,
                size,
                resolved,
                ..
            } => {
                assert_eq!(*modality, schema::content_fact::modality::IMAGE);
                assert_eq!(pointer.as_ref(), "image-sha");
                assert_eq!(media_type.as_ref().unwrap().as_ref(), "image/png");
                assert_eq!(*size, Some(8));
                assert_eq!(resolved.as_ref().unwrap().as_ref(), b"\x89PNG\r\n\x1a\n");
            }
            _ => panic!("expected resolved image pointer"),
        }
        match &first_user.parts[2] {
            SourcePart::Pointer {
                modality, pointer, ..
            } => {
                assert_eq!(*modality, schema::content_fact::modality::FILE);
                assert_eq!(pointer.as_ref(), "file:///repo/src/lib.rs");
            }
            _ => panic!("expected file pointer"),
        }

        let first_assistant = records
            .iter()
            .find(|record| record.locator.as_ref() == "session-a/request/r-a/assistant")
            .unwrap();
        assert_eq!(first_assistant.parts.len(), 3);
        assert!(matches!(
            &first_assistant.parts[0],
            SourcePart::Text { modality, value, .. }
                if *modality == schema::content_fact::modality::TOOL_CALL
                    && value.as_ref().contains("name: read_file")
                    && value.as_ref().contains("call-1")
        ));
        assert!(matches!(
            &first_assistant.parts[1],
            SourcePart::Text { modality, value, .. }
                if *modality == schema::content_fact::modality::TOOL_RESULT
                    && value.as_ref() == "file contents"
        ));
        assert!(matches!(
            &first_assistant.parts[2],
            SourcePart::Text { modality, value, .. }
                if *modality == schema::content_fact::modality::TEXT
                    && value.as_ref() == "done"
        ));

        let other_session = records
            .iter()
            .find(|record| record.locator.as_ref() == "session-b/request/r-b/user")
            .unwrap();
        assert_eq!(
            other_session.predecessors[0].as_ref(),
            "copilot:request/v1/r-a/root"
        );
        let same_session = records
            .iter()
            .find(|record| record.locator.as_ref() == "session-a/request/r-a2/user")
            .unwrap();
        assert_eq!(
            same_session.predecessors[0].as_ref(),
            "session-a/request/r-a/assistant"
        );
    }

    #[test]
    fn github_skill_executions_are_ordered_calls_results_then_response() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("github.json");
        let raw_message = r#"{"id":"m-1","role":"assistant","content":"summary","skillExecutions":[{"slug":"code-search","status":"completed","arguments":"{\"query\":\"needle\"}","references":[{"type":"text","text":"hit"}],"callId":"toolu-1"}]}"#;
        fs::write(
            &path,
            format!(r#"{{"threadUrl":"thread-1","messages":[{raw_message}]}}"#),
        )
        .unwrap();

        let records = parse_file(&path).unwrap().unwrap();
        let message = records
            .iter()
            .find(|record| record.locator.as_ref() == "thread-1/message/m-1")
            .unwrap();
        assert_eq!(message.raw_record.as_ref(), raw_message.as_bytes());
        assert_eq!(message.parts.len(), 4);
        assert!(matches!(
            &message.parts[0],
            SourcePart::Text { modality, value, .. }
                if *modality == schema::content_fact::modality::TOOL_CALL
                    && value.as_ref().contains("name: code-search")
                    && value.as_ref().contains("toolu-1")
                    && value.as_ref().contains("needle")
        ));
        assert!(matches!(
            &message.parts[1],
            SourcePart::Text { modality, value, .. }
                if *modality == schema::content_fact::modality::TOOL_RESULT
                    && value.as_ref().contains("status: completed")
        ));
        assert!(matches!(
            &message.parts[2],
            SourcePart::Text { modality, value, .. }
                if *modality == schema::content_fact::modality::TOOL_RESULT
                    && value.as_ref().contains("\"text\":\"hit\"")
        ));
        assert!(matches!(
            &message.parts[3],
            SourcePart::Text { modality, value, .. }
                if *modality == schema::content_fact::modality::TEXT
                    && value.as_ref() == "summary"
        ));
    }

    #[test]
    fn structured_skill_payloads_converge_while_raw_receipts_remain_exact() {
        let dir = TempDir::new().unwrap();
        let first_dir = dir.path().join("first");
        let second_dir = dir.path().join("second");
        fs::create_dir_all(&first_dir).unwrap();
        fs::create_dir_all(&second_dir).unwrap();
        let first_path = first_dir.join("github.json");
        let second_path = second_dir.join("github.json");
        let first_message = r#"{"id":"m-1","role":"assistant","content":"done","skillExecutions":[{"slug":"search","status":"completed","arguments":{"z":1,"a":[true,null]},"references":[{"text":"hit","type":"text"}],"callId":"c-1"}]}"#;
        let second_message = r#"{ "skillExecutions": [ { "callId": "c-1", "references": [ { "type": "text", "text": "hit" } ], "arguments": { "a": [ true, null ], "z": 1 }, "status": "completed", "slug": "search" } ], "content": "done", "role": "assistant", "id": "m-1" }"#;
        fs::write(
            &first_path,
            format!(r#"{{"threadUrl":"thread-1","messages":[{first_message}]}}"#),
        )
        .unwrap();
        fs::write(
            &second_path,
            format!(r#"{{ "messages": [ {second_message} ], "threadUrl": "thread-1" }}"#),
        )
        .unwrap();
        let first_records = parse_file(&first_path).unwrap().unwrap();
        let second_records = parse_file(&second_path).unwrap().unwrap();
        assert_eq!(
            first_records[1].raw_record.as_ref(),
            first_message.as_bytes()
        );
        assert_eq!(
            second_records[1].raw_record.as_ref(),
            second_message.as_bytes()
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

        assert_eq!(first_fragments.len(), 2);
        assert_eq!(second_fragments.len(), 2);
        assert_ne!(
            first_fragments[1].root(),
            second_fragments[1].root(),
            "exactly different source records retain distinct receipt identities"
        );
        let first_semantics = semantic_identity(&first_fragments[1]);
        let second_semantics = semantic_identity(&second_fragments[1]);
        assert_eq!(first_semantics, second_semantics);
        assert_eq!(first_semantics.1.len(), 4);
    }
}
