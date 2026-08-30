//! Zero-copy projection of ChatGPT data exports onto Archive's block DAG.
//!
//! ChatGPT exports are immutable JSON arrays, sometimes sharded as
//! `conversations-000.json`, with each conversation represented by a mapping
//! DAG.  This adapter mmaps those arrays and uses TribleSpace's scanner rather
//! than materializing a dynamic JSON value tree. Unescaped strings and exact
//! mapping-node and conversation-envelope receipts therefore remain views of
//! the source mapping.
//!
//! A mapping node with a null `message` is retained as exact source evidence
//! but marked transparent, so it does not invent a semantic turn between its
//! nearest message-bearing ancestors and descendants.  The complete mapping
//! DAG is handed to `archive_source` before anything is emitted.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anybytes::{Bytes, View};
use anyhow::{anyhow, bail, Context, Result};
use hifitime::Epoch;
use triblespace::core::import::scanner as sc;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::blobencodings::UTF8String;
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval};
use triblespace::prelude::*;

use crate::archive_source::{
    self, ProjectedSource, ProjectionStats, SourceClaims, SourcePart, SourceRecord, Threading,
};
use crate::blockdag::{self, ProjectionAnnotations};
use crate::files;
use crate::schemas::blockdag as schema;

/// Corpus-level accounting returned after all projected receipts reach `emit`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProjectionSummary {
    pub files_scanned: usize,
    pub conversations_seen: usize,
    pub mapping_nodes_seen: usize,
    pub attachments_seen: usize,
    pub attachments_resolved: usize,
    pub stats: ProjectionStats,
}

impl ProjectionSummary {
    fn absorb(&mut self, other: Self) {
        self.files_scanned += other.files_scanned;
        self.conversations_seen += other.conversations_seen;
        self.mapping_nodes_seen += other.mapping_nodes_seen;
        self.attachments_seen += other.attachments_seen;
        self.attachments_resolved += other.attachments_resolved;
        self.stats.records_seen += other.stats.records_seen;
        self.stats.projections_emitted += other.stats.projections_emitted;
        self.stats.content_parts += other.stats.content_parts;
        self.stats.transparent_records += other.stats.transparent_records;
        self.stats.raw_only_records += other.stats.raw_only_records;
        self.stats.missing_predecessors += other.stats.missing_predecessors;
    }
}

/// Project one ChatGPT `conversations*.json` export or a directory containing
/// one or more shards.
///
/// Files and conversations are visited deterministically. The callback sees
/// one source-projection fragment per mapping node plus one exact conversation
/// envelope receipt; callers may stage their union and publish it only after
/// this function succeeds.
pub fn project_path<F>(path: &Path, mut emit: F) -> Result<ProjectionSummary>
where
    F: FnMut(ProjectedSource) -> Result<()>,
{
    let mut conversation_files = Vec::new();
    if path.is_dir() {
        collect_conversation_files(path, &mut conversation_files)?;
    } else {
        if !is_conversation_file(path) {
            bail!(
                "{} is not a ChatGPT conversations.json shard",
                path.display()
            );
        }
        conversation_files.push(path.to_path_buf());
    }
    conversation_files.sort();
    conversation_files.dedup();

    let export_root = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or_else(|| Path::new("."))
    };
    let sidecars = ExportFiles::index(export_root)?;

    let mut summary = ProjectionSummary::default();
    for source_path in conversation_files {
        let file_summary = project_file(&source_path, &sidecars, &mut emit)
            .with_context(|| format!("project ChatGPT export {}", source_path.display()))?;
        summary.absorb(file_summary);
    }
    Ok(summary)
}

fn project_file<F>(
    source_path: &Path,
    sidecars: &ExportFiles,
    emit: &mut F,
) -> Result<ProjectionSummary>
where
    F: FnMut(ProjectedSource) -> Result<()>,
{
    let mapped = archive_source::map_immutable_file(source_path)?;
    let conversations = scan_export(mapped)
        .map_err(|error| anyhow!(error))
        .with_context(|| format!("scan {}", source_path.display()))?;

    let mut summary = ProjectionSummary {
        files_scanned: 1,
        conversations_seen: conversations.len(),
        ..ProjectionSummary::default()
    };
    for conversation in conversations {
        let (records, envelope, attachments_seen, attachments_resolved) =
            conversation.into_records(sidecars)?;
        summary.mapping_nodes_seen += records.len();
        summary.attachments_seen += attachments_seen;
        summary.attachments_resolved += attachments_resolved;
        let expected_tip = envelope.current_locator.clone();
        let mut projected_tip = None;
        let stats = archive_source::project_records(
            schema::source_projection::SOURCE_CHATGPT,
            source_path,
            records,
            |mut projected| {
                if expected_tip.is_some() {
                    let (_, locator, block) = projected_identity(&mut projected.fragment)?;
                    if expected_tip.as_ref() == Some(&locator) {
                        projected_tip = Some(block);
                    }
                }
                emit(projected)
            },
        )?;
        summary.stats.records_seen += stats.records_seen;
        summary.stats.projections_emitted += stats.projections_emitted;
        summary.stats.content_parts += stats.content_parts;
        summary.stats.transparent_records += stats.transparent_records;
        summary.stats.raw_only_records += stats.raw_only_records;
        summary.stats.missing_predecessors += stats.missing_predecessors;

        let target = match envelope.current_locator.as_ref() {
            Some(current_locator) => {
                let tip_block = projected_tip.ok_or_else(|| {
                    anyhow!(
                        "ChatGPT current_node {:?} has no projected mapping node",
                        current_locator.as_ref()
                    )
                })?;
                Fragment::rooted(tip_block, TribleSet::new())
            }
            None => blockdag::block(std::iter::empty::<Id>(), None, Fragment::empty())?,
        };
        // The complete conversation envelope is another exact source
        // occurrence projecting onto the selected canonical tip. Source UI
        // state (title, account, plugins, timestamps, and the mapping wrapper)
        // therefore remains lossless without entering semantic block identity
        // or searchable content. Without an active tip it projects to the
        // canonical bottom rather than inventing a branch.
        let projection = blockdag::source_projection_view(
            schema::source_projection::SOURCE_CHATGPT,
            envelope.locator,
            envelope.raw_record,
            target,
        )?;
        let projection = blockdag::annotate_source_projection(
            projection,
            ProjectionAnnotations {
                source_path: Some(source_path.display().to_string()),
                ..ProjectionAnnotations::default()
            },
        )?;
        emit(ProjectedSource {
            source_path: source_path.to_path_buf(),
            fragment: projection,
        })?;
        summary.stats.records_seen += 1;
        summary.stats.projections_emitted += 1;
        summary.stats.raw_only_records += 1;
    }
    Ok(summary)
}

#[derive(Debug)]
struct Conversation {
    id: View<str>,
    current_node: Option<View<str>>,
    raw_record: Bytes,
    nodes: Vec<MappingNode>,
}

#[derive(Debug)]
struct EnvelopeProjection {
    locator: View<str>,
    raw_record: Bytes,
    current_locator: Option<View<str>>,
}

impl Conversation {
    fn into_records(
        self,
        sidecars: &ExportFiles,
    ) -> Result<(Vec<SourceRecord>, EnvelopeProjection, usize, usize)> {
        let mut locators = HashMap::<View<str>, View<str>>::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let locator = node_locator(
                self.id.as_ref(),
                node.id.as_ref(),
                node.message
                    .as_ref()
                    .and_then(|message| message.id.as_ref()),
            );
            if locators.insert(node.id.clone(), locator).is_some() {
                bail!(
                    "conversation {:?} contains duplicate mapping node {:?}",
                    self.id.as_ref(),
                    node.id.as_ref()
                );
            }
        }

        let current_locator = self
            .current_node
            .as_ref()
            .map(|current| {
                locators.get(current).cloned().ok_or_else(|| {
                    anyhow!(
                        "conversation {:?} current_node {:?} is absent from mapping",
                        self.id.as_ref(),
                        current.as_ref()
                    )
                })
            })
            .transpose()?;
        let envelope = EnvelopeProjection {
            locator: envelope_locator(self.id.as_ref()),
            raw_record: self.raw_record,
            current_locator,
        };

        let mut attachments_seen = 0usize;
        let mut attachments_resolved = 0usize;
        let mut records = Vec::with_capacity(self.nodes.len());
        for node in self.nodes {
            let locator = locators
                .get(&node.id)
                .expect("locator was planned for every mapping node")
                .clone();
            let predecessors =
                node.parent
                    .as_ref()
                    .map(|parent| {
                        locators.get(parent).cloned().unwrap_or_else(|| {
                            node_locator(self.id.as_ref(), parent.as_ref(), None)
                        })
                    })
                    .into_iter()
                    .collect();

            let (threading, block_timestamp, parts, claims) = match node.message {
                Some(message) => {
                    let timestamp = message.timestamp.and_then(epoch_interval);
                    let direction = direction_for_role(message.role.as_deref());
                    let text_modality =
                        text_modality(message.role.as_deref(), message.content_type.as_deref());
                    let mut parts = Vec::new();
                    let mut represented_attachments = HashSet::<String>::new();

                    for item in message.content {
                        match item {
                            ContentItem::Text(value) => {
                                parts.push(SourcePart::text(text_modality, direction, value));
                            }
                            ContentItem::Attachment(mut attachment) => {
                                if let Some(id) = attachment.id.as_ref() {
                                    represented_attachments.insert(id.as_ref().to_owned());
                                    if let Some(metadata) = message
                                        .attachments
                                        .iter()
                                        .find(|candidate| candidate.id.as_ref() == Some(id))
                                    {
                                        attachment.enrich(metadata);
                                    }
                                }
                                let (part, was_resolved) =
                                    attachment.into_source_part(direction, sidecars)?;
                                parts.push(part);
                                attachments_seen += 1;
                                attachments_resolved += usize::from(was_resolved);
                            }
                        }
                    }

                    // Metadata attachments which had no ordered content-part
                    // pointer are still semantic file occurrences.  They are
                    // appended in their source array order.
                    for attachment in message.attachments {
                        if attachment
                            .id
                            .as_ref()
                            .is_some_and(|id| represented_attachments.contains(id.as_ref()))
                        {
                            continue;
                        }
                        let (part, was_resolved) =
                            attachment.into_source_part(direction, sidecars)?;
                        parts.push(part);
                        attachments_seen += 1;
                        attachments_resolved += usize::from(was_resolved);
                    }

                    let claims = SourceClaims {
                        timestamp,
                        raw_author: message.author_name,
                        raw_role: message.role,
                        raw_model: message.model,
                        ..SourceClaims::default()
                    };
                    (Threading::Semantic, timestamp, parts, claims)
                }
                None => (
                    Threading::Transparent,
                    None,
                    Vec::new(),
                    SourceClaims::default(),
                ),
            };

            records.push(SourceRecord {
                locator,
                raw_record: node.raw_record,
                predecessors,
                block_timestamp,
                threading,
                parts,
                claims,
            });
        }
        Ok((records, envelope, attachments_seen, attachments_resolved))
    }
}

#[derive(Debug)]
struct MappingNode {
    id: View<str>,
    raw_record: Bytes,
    parent: Option<View<str>>,
    message: Option<Message>,
}

#[derive(Debug, Default)]
struct Message {
    id: Option<View<str>>,
    role: Option<View<str>>,
    author_name: Option<View<str>>,
    model: Option<View<str>>,
    timestamp: Option<Epoch>,
    content_type: Option<View<str>>,
    content: Vec<ContentItem>,
    attachments: Vec<Attachment>,
}

#[derive(Debug)]
enum ContentItem {
    Text(View<str>),
    Attachment(Attachment),
}

#[derive(Clone, Debug, Default)]
struct Attachment {
    id: Option<View<str>>,
    pointer: Option<View<str>>,
    name: Option<View<str>>,
    media_type: Option<View<str>>,
    format: Option<View<str>>,
    kind: Option<View<str>>,
    size: Option<u128>,
}

/// Presence-aware source-schema aliases for one attachment.
///
/// The outer option distinguishes an absent spelling from an explicitly null
/// preferred spelling.  That makes semantic selection independent of JSON
/// member order without silently reviving a legacy value behind a native
/// `null`.
#[derive(Debug, Default)]
struct AttachmentAliases {
    asset_pointer: Option<Option<View<str>>>,
    url: Option<Option<View<str>>>,
    id: Option<Option<View<str>>>,
    file_id: Option<Option<View<str>>>,
    name: Option<Option<View<str>>>,
    filename: Option<Option<View<str>>>,
    content_type: Option<Option<View<str>>>,
    kind: Option<Option<View<str>>>,
    size: Option<Option<u128>>,
    size_bytes: Option<Option<u128>>,
}

impl AttachmentAliases {
    fn resolve_into(self, attachment: &mut Attachment) {
        if self.asset_pointer.is_some() || self.url.is_some() {
            attachment.pointer = preferred_alias([self.asset_pointer, self.url]);
        }
        attachment.id = preferred_alias([self.id, self.file_id]);
        attachment.name = preferred_alias([self.name, self.filename]);
        attachment.kind = preferred_alias([self.content_type, self.kind]);
        attachment.size = preferred_alias([self.size, self.size_bytes]);
    }
}

impl Attachment {
    fn enrich(&mut self, other: &Self) {
        if self.id.is_none() {
            self.id = other.id.clone();
        }
        if self.pointer.is_none() {
            self.pointer = other.pointer.clone();
        }
        if self.name.is_none() {
            self.name = other.name.clone();
        }
        if self.media_type.is_none() {
            self.media_type = other.media_type.clone();
        }
        if self.format.is_none() {
            self.format = other.format.clone();
        }
        if self.kind.is_none() {
            self.kind = other.kind.clone();
        }
        if self.size.is_none() {
            self.size = other.size;
        }
    }

    fn into_source_part(self, direction: Id, sidecars: &ExportFiles) -> Result<(SourcePart, bool)> {
        let source_id = self
            .id
            .as_ref()
            .map(|id| id.as_ref().to_owned())
            .or_else(|| {
                self.pointer
                    .as_ref()
                    .and_then(|pointer| file_id_from_asset_pointer(pointer.as_ref()))
                    .map(str::to_owned)
            });
        let pointer = match self.pointer {
            Some(pointer) => pointer,
            None => {
                let source_id = source_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("ChatGPT attachment has neither id nor pointer"))?;
                canonical_pointer(source_id)
            }
        };
        let resolved_path = sidecars.resolve(source_id.as_deref(), self.name.as_deref());
        let resolved = resolved_path
            .map(|path| archive_source::map_immutable_file(path))
            .transpose()?;

        let media_type = clean_media_type(
            self.media_type.clone(),
            self.format.as_deref(),
            self.kind.as_deref(),
            resolved_path,
        );
        let modality = media_type
            .as_ref()
            .map(|media_type| archive_source::modality_for_media_type(media_type.as_ref()))
            .unwrap_or_else(|| modality_for_kind(self.kind.as_deref()));
        let was_resolved = resolved.is_some();
        Ok((
            SourcePart::Pointer {
                modality,
                direction,
                namespace: schema::source_projection::SOURCE_CHATGPT,
                pointer,
                media_type,
                size: self.size,
                resolved,
            },
            was_resolved,
        ))
    }
}

#[derive(Debug)]
enum ExportFile {
    Unique(PathBuf),
    Ambiguous,
}

#[derive(Debug, Default)]
struct ExportFiles {
    by_id: HashMap<String, ExportFile>,
    by_name: HashMap<String, ExportFile>,
}

impl ExportFiles {
    fn index(root: &Path) -> Result<Self> {
        let mut paths = Vec::new();
        collect_files(root, &mut paths)?;
        Ok(Self::from_paths(paths))
    }

    fn from_paths(paths: impl IntoIterator<Item = PathBuf>) -> Self {
        let mut index = Self::default();
        for path in paths {
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            insert_export_file(&mut index.by_name, name.to_owned(), path.clone());
            if let Some(id) = file_id_from_filename(name) {
                insert_export_file(&mut index.by_id, id, path);
            }
        }
        index
    }

    /// Resolve only when every matching piece of attachment identity agrees
    /// on one path. An ambiguous id or basename poisons the resolution rather
    /// than letting traversal order choose bytes or letting another key hide
    /// the ambiguity.
    fn resolve(&self, id: Option<&str>, name: Option<&str>) -> Option<&PathBuf> {
        let mut resolved = None;
        for candidate in [
            id.and_then(|id| self.by_id.get(id)),
            name.and_then(|name| self.by_name.get(name)),
        ] {
            match candidate {
                Some(ExportFile::Ambiguous) => return None,
                Some(ExportFile::Unique(path)) => match resolved {
                    Some(previous) if previous != path => return None,
                    Some(_) => {}
                    None => resolved = Some(path),
                },
                None => {}
            }
        }
        resolved
    }
}

fn insert_export_file(index: &mut HashMap<String, ExportFile>, key: String, path: PathBuf) {
    use std::collections::hash_map::Entry;

    match index.entry(key) {
        Entry::Vacant(entry) => {
            entry.insert(ExportFile::Unique(path));
        }
        Entry::Occupied(mut entry) => {
            if matches!(entry.get(), ExportFile::Unique(previous) if previous != &path) {
                entry.insert(ExportFile::Ambiguous);
            }
        }
    }
}

fn scan_export(mut bytes: Bytes) -> std::result::Result<Vec<Conversation>, sc::ScanError> {
    sc::skip_ws(&mut bytes);
    let conversations = sc::array(&mut bytes, Vec::new(), |mut conversations, value| {
        let raw = archive_source::raw_value(value)?;
        conversations.push(scan_conversation(raw)?);
        Ok(conversations)
    })?;
    sc::skip_ws(&mut bytes);
    if !bytes.is_empty() {
        return Err(syntax("trailing bytes after ChatGPT conversation array"));
    }
    Ok(conversations)
}

fn scan_conversation(raw: Bytes) -> std::result::Result<Conversation, sc::ScanError> {
    let mut cursor = raw.clone();
    let mut id = None;
    let mut conversation_id = None;
    let mut current_node = None;
    let mut nodes = Vec::new();
    sc::object(&mut cursor, (), |(), key, value| {
        match key_text(key)?.as_ref() {
            "id" => id = Some(optional_string(value)?),
            "conversation_id" => conversation_id = Some(optional_string(value)?),
            "current_node" => current_node = optional_string(value)?,
            "mapping" => nodes = scan_mapping(value)?,
            _ => sc::skip_value(value)?,
        }
        Ok(())
    })?;
    let id = preferred_alias([id, conversation_id])
        .ok_or_else(|| syntax("ChatGPT conversation has no stable id"))?;
    Ok(Conversation {
        id,
        current_node,
        raw_record: raw,
        nodes,
    })
}

fn scan_mapping(bytes: &mut Bytes) -> std::result::Result<Vec<MappingNode>, sc::ScanError> {
    sc::object(bytes, Vec::new(), |mut nodes, node_id, value| {
        let id = key_text(node_id)?;
        let raw_record = archive_source::raw_value(value)?;
        let (parent, message) = scan_mapping_node(raw_record.clone())?;
        nodes.push(MappingNode {
            id,
            raw_record,
            parent,
            message,
        });
        Ok(nodes)
    })
}

fn scan_mapping_node(
    mut bytes: Bytes,
) -> std::result::Result<(Option<View<str>>, Option<Message>), sc::ScanError> {
    let mut parent = None;
    let mut message = None;
    sc::object(&mut bytes, (), |(), key, value| {
        match key_text(key)?.as_ref() {
            "parent" => parent = optional_string(value)?,
            "message" => {
                message = if consume_null(value)? {
                    None
                } else {
                    Some(scan_message(value)?)
                }
            }
            _ => sc::skip_value(value)?,
        }
        Ok(())
    })?;
    Ok((parent, message))
}

fn scan_message(bytes: &mut Bytes) -> std::result::Result<Message, sc::ScanError> {
    let mut message = Message::default();
    sc::object(bytes, &mut message, |message, key, value| {
        match key_text(key)?.as_ref() {
            "id" => message.id = optional_string(value)?,
            "author" => scan_author(value, message)?,
            "create_time" => message.timestamp = optional_epoch(value)?,
            "content" => scan_content(value, message)?,
            "metadata" => scan_metadata(value, message)?,
            _ => sc::skip_value(value)?,
        }
        Ok(message)
    })?;
    Ok(message)
}

fn scan_author(bytes: &mut Bytes, message: &mut Message) -> std::result::Result<(), sc::ScanError> {
    if consume_null(bytes)? {
        return Ok(());
    }
    sc::object(bytes, (), |(), key, value| {
        match key_text(key)?.as_ref() {
            "role" => message.role = optional_string(value)?,
            "name" => message.author_name = optional_string(value)?,
            _ => sc::skip_value(value)?,
        }
        Ok(())
    })
}

fn scan_content(
    bytes: &mut Bytes,
    message: &mut Message,
) -> std::result::Result<(), sc::ScanError> {
    if consume_null(bytes)? {
        return Ok(());
    }
    if bytes.first().copied() == Some(b'"') {
        message
            .content
            .push(ContentItem::Text(archive_source::string(bytes)?));
        return Ok(());
    }
    let mut text = None;
    let mut content = None;
    sc::object(bytes, (), |(), key, value| {
        match key_text(key)?.as_ref() {
            "content_type" => message.content_type = optional_string(value)?,
            "parts" => {
                message.content = sc::array(value, Vec::new(), |mut parts, part| {
                    parts.extend(scan_content_part(part)?);
                    Ok(parts)
                })?
            }
            "text" => text = Some(optional_string(value)?),
            "content" => content = Some(optional_string(value)?),
            "thoughts" => {
                message
                    .content
                    .extend(scan_thoughts(value)?.into_iter().map(ContentItem::Text));
            }
            "audio_asset_pointer" => {
                if let Some(attachment) = scan_pointer_value(value, Some("audio_asset_pointer"))? {
                    message.content.push(ContentItem::Attachment(attachment));
                }
            }
            "frames_asset_pointers" => {
                message.content.extend(
                    scan_pointer_array(value, Some("image_asset_pointer"))?
                        .into_iter()
                        .map(ContentItem::Attachment),
                );
            }
            "video_container_asset_pointer" => {
                if let Some(attachment) = scan_pointer_value(value, Some("video_asset_pointer"))? {
                    message.content.push(ContentItem::Attachment(attachment));
                }
            }
            _ => sc::skip_value(value)?,
        }
        Ok(())
    })?;
    if let Some(text) = preferred_alias([text, content]) {
        message.content.push(ContentItem::Text(text));
    }
    Ok(())
}

fn scan_content_part(bytes: &mut Bytes) -> std::result::Result<Vec<ContentItem>, sc::ScanError> {
    match bytes.first().copied() {
        Some(b'"') => Ok(vec![ContentItem::Text(archive_source::string(bytes)?)]),
        Some(b'{') => {
            let mut attachment = Attachment::default();
            let mut aliases = AttachmentAliases::default();
            let mut text = None;
            let mut nested_attachments = Vec::new();
            sc::object(bytes, (), |(), key, value| {
                match key_text(key)?.as_ref() {
                    "asset_pointer" => attachment.pointer = optional_string(value)?,
                    "id" => aliases.id = Some(optional_string(value)?),
                    "file_id" => aliases.file_id = Some(optional_string(value)?),
                    "name" => aliases.name = Some(optional_string(value)?),
                    "filename" => aliases.filename = Some(optional_string(value)?),
                    "mime_type" => attachment.media_type = optional_string(value)?,
                    "format" => attachment.format = optional_string(value)?,
                    "content_type" => aliases.content_type = Some(optional_string(value)?),
                    "type" => aliases.kind = Some(optional_string(value)?),
                    "size" => aliases.size = Some(optional_u128(value)?),
                    "size_bytes" => aliases.size_bytes = Some(optional_u128(value)?),
                    "text" => text = optional_string(value)?,
                    "audio_asset_pointer" => {
                        if let Some(nested) =
                            scan_pointer_value(value, Some("audio_asset_pointer"))?
                        {
                            nested_attachments.push(nested);
                        }
                    }
                    "frames_asset_pointers" => nested_attachments
                        .extend(scan_pointer_array(value, Some("image_asset_pointer"))?),
                    "video_container_asset_pointer" => {
                        if let Some(nested) =
                            scan_pointer_value(value, Some("video_asset_pointer"))?
                        {
                            nested_attachments.push(nested);
                        }
                    }
                    _ => sc::skip_value(value)?,
                }
                Ok(())
            })?;
            aliases.resolve_into(&mut attachment);
            if attachment.id.is_none() {
                attachment.id = attachment
                    .pointer
                    .as_ref()
                    .and_then(|pointer| file_id_from_asset_pointer(pointer.as_ref()))
                    .map(archive_source::owned_text);
            }
            let mut items = Vec::new();
            if let Some(text) = text {
                items.push(ContentItem::Text(text));
            }
            if attachment.pointer.is_some() || attachment.id.is_some() {
                items.push(ContentItem::Attachment(attachment));
            }
            items.extend(nested_attachments.into_iter().map(ContentItem::Attachment));
            Ok(items)
        }
        _ => {
            sc::skip_value(bytes)?;
            Ok(Vec::new())
        }
    }
}

/// Extract the semantic text of each ChatGPT reasoning thought without
/// duplicating its alternative chunked representation.  A completed thought's
/// `content` is authoritative; `summary` is a useful fallback for records that
/// carry no content.  The exact object, including chunks and completion state,
/// remains in the enclosing mapping-node receipt.
fn scan_thoughts(bytes: &mut Bytes) -> std::result::Result<Vec<View<str>>, sc::ScanError> {
    sc::array(bytes, Vec::new(), |mut thoughts, thought| {
        if thought.first().copied() == Some(b'"') {
            let text = archive_source::string(thought)?;
            if !text.as_ref().is_empty() {
                thoughts.push(text);
            }
            return Ok(thoughts);
        }
        if thought.first().copied() != Some(b'{') {
            sc::skip_value(thought)?;
            return Ok(thoughts);
        }

        let mut content = None;
        let mut summary = None;
        sc::object(thought, (), |(), key, value| {
            match key_text(key)?.as_ref() {
                "content" => content = optional_string(value)?,
                "summary" => summary = optional_string(value)?,
                _ => sc::skip_value(value)?,
            }
            Ok(())
        })?;
        if let Some(text) = content
            .filter(|text| !text.as_ref().is_empty())
            .or_else(|| summary.filter(|text| !text.as_ref().is_empty()))
        {
            thoughts.push(text);
        }
        Ok(thoughts)
    })
}

fn scan_pointer_array(
    bytes: &mut Bytes,
    kind_hint: Option<&str>,
) -> std::result::Result<Vec<Attachment>, sc::ScanError> {
    if consume_null(bytes)? {
        return Ok(Vec::new());
    }
    sc::array(bytes, Vec::new(), |mut pointers, pointer| {
        if let Some(pointer) = scan_pointer_value(pointer, kind_hint)? {
            pointers.push(pointer);
        }
        Ok(pointers)
    })
}

fn scan_pointer_value(
    bytes: &mut Bytes,
    kind_hint: Option<&str>,
) -> std::result::Result<Option<Attachment>, sc::ScanError> {
    if consume_null(bytes)? {
        return Ok(None);
    }
    if bytes.first().copied() == Some(b'"') {
        let pointer = archive_source::string(bytes)?;
        let id = file_id_from_asset_pointer(pointer.as_ref()).map(archive_source::owned_text);
        return Ok(Some(Attachment {
            id,
            pointer: Some(pointer),
            kind: kind_hint.map(archive_source::owned_text),
            ..Attachment::default()
        }));
    }
    if bytes.first().copied() != Some(b'{') {
        sc::skip_value(bytes)?;
        return Ok(None);
    }

    let mut attachment = Attachment {
        kind: kind_hint.map(archive_source::owned_text),
        ..Attachment::default()
    };
    let mut aliases = AttachmentAliases::default();
    sc::object(bytes, &mut attachment, |attachment, key, value| {
        match key_text(key)?.as_ref() {
            "asset_pointer" => aliases.asset_pointer = Some(optional_string(value)?),
            "url" => aliases.url = Some(optional_string(value)?),
            "id" => aliases.id = Some(optional_string(value)?),
            "file_id" => aliases.file_id = Some(optional_string(value)?),
            "name" => aliases.name = Some(optional_string(value)?),
            "filename" => aliases.filename = Some(optional_string(value)?),
            "mime_type" => attachment.media_type = optional_string(value)?,
            "format" => attachment.format = optional_string(value)?,
            "content_type" => aliases.content_type = Some(optional_string(value)?),
            "type" => aliases.kind = Some(optional_string(value)?),
            "size" => aliases.size = Some(optional_u128(value)?),
            "size_bytes" => aliases.size_bytes = Some(optional_u128(value)?),
            _ => sc::skip_value(value)?,
        }
        Ok(attachment)
    })?;
    let hinted_kind = attachment.kind.take();
    aliases.resolve_into(&mut attachment);
    if attachment.kind.is_none() {
        attachment.kind = hinted_kind;
    }
    if attachment.id.is_none() {
        attachment.id = attachment
            .pointer
            .as_ref()
            .and_then(|pointer| file_id_from_asset_pointer(pointer.as_ref()))
            .map(archive_source::owned_text);
    }
    Ok((attachment.pointer.is_some() || attachment.id.is_some()).then_some(attachment))
}

fn scan_metadata(
    bytes: &mut Bytes,
    message: &mut Message,
) -> std::result::Result<(), sc::ScanError> {
    if consume_null(bytes)? {
        return Ok(());
    }
    let mut model_slug = None;
    let mut model = None;
    sc::object(bytes, (), |(), key, value| {
        match key_text(key)?.as_ref() {
            "model_slug" => model_slug = Some(optional_string(value)?),
            "model" => model = Some(optional_string(value)?),
            "attachments" => {
                message.attachments = sc::array(value, Vec::new(), |mut attachments, item| {
                    if item.first().copied() == Some(b'{') {
                        if let Some(attachment) = scan_attachment(item)? {
                            attachments.push(attachment);
                        }
                    } else {
                        sc::skip_value(item)?;
                    }
                    Ok(attachments)
                })?
            }
            _ => sc::skip_value(value)?,
        }
        Ok(())
    })?;
    message.model = preferred_alias([model_slug, model]);
    Ok(())
}

fn scan_attachment(bytes: &mut Bytes) -> std::result::Result<Option<Attachment>, sc::ScanError> {
    let mut attachment = Attachment::default();
    let mut aliases = AttachmentAliases::default();
    sc::object(bytes, &mut attachment, |attachment, key, value| {
        match key_text(key)?.as_ref() {
            "id" => aliases.id = Some(optional_string(value)?),
            "file_id" => aliases.file_id = Some(optional_string(value)?),
            "asset_pointer" => aliases.asset_pointer = Some(optional_string(value)?),
            "url" => aliases.url = Some(optional_string(value)?),
            "name" => aliases.name = Some(optional_string(value)?),
            "filename" => aliases.filename = Some(optional_string(value)?),
            "mime_type" => attachment.media_type = optional_string(value)?,
            "format" => attachment.format = optional_string(value)?,
            "content_type" => aliases.content_type = Some(optional_string(value)?),
            "type" => aliases.kind = Some(optional_string(value)?),
            "size" => aliases.size = Some(optional_u128(value)?),
            "size_bytes" => aliases.size_bytes = Some(optional_u128(value)?),
            _ => sc::skip_value(value)?,
        }
        Ok(attachment)
    })?;
    aliases.resolve_into(&mut attachment);
    Ok((attachment.id.is_some() || attachment.pointer.is_some()).then_some(attachment))
}

fn key_text(bytes: Bytes) -> std::result::Result<View<str>, sc::ScanError> {
    bytes
        .view::<str>()
        .map_err(|_| syntax("JSON object key is not UTF-8"))
}

/// Resolve source-schema aliases by semantic priority rather than JSON member
/// order. The outer option records whether a spelling was present, so an
/// explicit `null` in a preferred spelling remains authoritative.
fn preferred_alias<T, const N: usize>(aliases: [Option<Option<T>>; N]) -> Option<T> {
    for alias in aliases {
        if let Some(value) = alias {
            return value;
        }
    }
    None
}

fn optional_string(bytes: &mut Bytes) -> std::result::Result<Option<View<str>>, sc::ScanError> {
    if consume_null(bytes)? {
        Ok(None)
    } else if bytes.first().copied() == Some(b'"') {
        Ok(Some(archive_source::string(bytes)?))
    } else {
        sc::skip_value(bytes)?;
        Ok(None)
    }
}

fn optional_epoch(bytes: &mut Bytes) -> std::result::Result<Option<Epoch>, sc::ScanError> {
    if consume_null(bytes)? {
        return Ok(None);
    }
    if bytes.first().copied() == Some(b'"') {
        let text = archive_source::string(bytes)?;
        return Ok(text.as_ref().trim().parse().ok());
    }
    let seconds = sc::parse_f64(bytes)?;
    Ok(seconds
        .is_finite()
        .then(|| Epoch::from_unix_seconds(seconds)))
}

fn optional_u128(bytes: &mut Bytes) -> std::result::Result<Option<u128>, sc::ScanError> {
    if consume_null(bytes)? {
        return Ok(None);
    }
    if bytes.first().copied() == Some(b'"') {
        let text = archive_source::string(bytes)?;
        return Ok(text.as_ref().parse().ok());
    }
    let number = sc::parse_number(bytes)?;
    let number = number
        .view::<str>()
        .map_err(|_| syntax("JSON number is not UTF-8"))?;
    Ok(number.as_ref().parse().ok())
}

fn consume_null(bytes: &mut Bytes) -> std::result::Result<bool, sc::ScanError> {
    if bytes.first().copied() == Some(b'n') {
        sc::expect_literal(bytes, b"null")?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn syntax(message: &str) -> sc::ScanError {
    sc::ScanError::Syntax(message.to_owned())
}

fn projected_identity(fragment: &mut Fragment) -> Result<(Id, View<str>, Id)> {
    let projection = fragment
        .root()
        .ok_or_else(|| anyhow!("projected source fragment is not singly rooted"))?;
    let locator = find!(
        (locator: Inline<Handle<UTF8String>>),
        pattern!(&*fragment, [{
            projection @ schema::source_projection::source_locator: ?locator
        }])
    )
    .next()
    .map(|(locator,)| locator)
    .ok_or_else(|| anyhow!("source projection {projection:x} has no locator"))?;
    let block = find!(
        (block: Id),
        pattern!(&*fragment, [{
            projection @ schema::source_projection::projects_to: ?block
        }])
    )
    .next()
    .map(|(block,)| block)
    .ok_or_else(|| anyhow!("source projection {projection:x} has no projected block"))?;
    let reader = fragment
        .blobs_mut()
        .snapshot()
        .expect("MemoryBlobStore reader construction is infallible");
    let locator: View<str> = reader
        .get(locator)
        .map_err(|error| anyhow!("read source locator for {projection:x}: {error}"))?;
    Ok((projection, locator, block))
}

fn envelope_locator(conversation: &str) -> View<str> {
    archive_source::owned_text(format!(
        "conversation:{}:{conversation}/envelope",
        conversation.len()
    ))
}

fn node_locator(conversation: &str, node: &str, message: Option<&View<str>>) -> View<str> {
    let mut locator = format!(
        "conversation:{}:{conversation}/node:{}:{node}",
        conversation.len(),
        node.len()
    );
    if let Some(message) = message {
        use std::fmt::Write as _;
        let _ = write!(
            locator,
            "/message:{}:{}",
            message.as_ref().len(),
            message.as_ref()
        );
    }
    archive_source::owned_text(locator)
}

fn direction_for_role(role: Option<&str>) -> Id {
    match role {
        Some("user") | Some("tool") => schema::content_fact::direction::IN,
        Some("assistant") => schema::content_fact::direction::OUT,
        _ => schema::content_fact::direction::AMBIENT,
    }
}

fn text_modality(role: Option<&str>, content_type: Option<&str>) -> Id {
    if content_type.is_some_and(|kind| {
        let kind = kind.to_ascii_lowercase();
        kind.contains("thought") || kind.contains("reasoning")
    }) {
        schema::content_fact::modality::THINKING
    } else if role == Some("tool") {
        schema::content_fact::modality::TOOL_RESULT
    } else {
        schema::content_fact::modality::TEXT
    }
}

fn epoch_interval(epoch: Epoch) -> Option<Inline<NsTAIInterval>> {
    (epoch, epoch).try_to_inline().ok()
}

fn modality_for_kind(kind: Option<&str>) -> Id {
    let kind = kind.unwrap_or_default().to_ascii_lowercase();
    if kind.contains("image") {
        schema::content_fact::modality::IMAGE
    } else if kind.contains("audio") {
        schema::content_fact::modality::AUDIO
    } else if kind.contains("video") {
        schema::content_fact::modality::VIDEO
    } else {
        schema::content_fact::modality::FILE
    }
}

fn clean_media_type(
    raw: Option<View<str>>,
    format: Option<&str>,
    kind: Option<&str>,
    path: Option<&PathBuf>,
) -> Option<View<str>> {
    if let Some(raw) = raw {
        if let Ok(normalized) = files::normalize_media_type(raw.as_ref()) {
            if normalized == raw.as_ref() {
                return Some(raw);
            }
            return Some(archive_source::owned_text(normalized));
        }
    }
    if let Some(format) = format.and_then(|format| media_type_for_format(format, kind)) {
        return Some(archive_source::owned_text(format));
    }
    path.map(|path| archive_source::owned_text(files::infer_media_type(path)))
}

fn media_type_for_format(format: &str, kind: Option<&str>) -> Option<String> {
    let format = format.trim().trim_start_matches('.').to_ascii_lowercase();
    if format.is_empty() {
        return None;
    }
    let kind = kind.unwrap_or_default().to_ascii_lowercase();
    let media_type = match format.as_str() {
        "wav" | "wave" => "audio/wav".to_owned(),
        "mp3" => "audio/mpeg".to_owned(),
        "m4a" => "audio/mp4".to_owned(),
        "opus" => "audio/opus".to_owned(),
        "flac" => "audio/flac".to_owned(),
        "mov" => "video/quicktime".to_owned(),
        "jpg" | "jpeg" => "image/jpeg".to_owned(),
        "svg" => "image/svg+xml".to_owned(),
        "mp4" if kind.contains("audio") => "audio/mp4".to_owned(),
        "webm" if kind.contains("audio") => "audio/webm".to_owned(),
        "ogg" if kind.contains("audio") => "audio/ogg".to_owned(),
        "mp4" => "video/mp4".to_owned(),
        "webm" => "video/webm".to_owned(),
        "ogg" => "video/ogg".to_owned(),
        "png" | "gif" | "webp" | "bmp" | "tiff" => format!("image/{format}"),
        _ if kind.contains("audio") => format!("audio/{format}"),
        _ if kind.contains("video") => format!("video/{format}"),
        _ if kind.contains("image") => format!("image/{format}"),
        _ => format!("application/{format}"),
    };
    files::normalize_media_type(&media_type).ok()
}

fn canonical_pointer(source_id: &str) -> View<str> {
    if source_id.starts_with("file-") {
        archive_source::owned_text(format!("file-service://{source_id}"))
    } else if source_id.starts_with("file_") {
        archive_source::owned_text(format!("sediment://{source_id}"))
    } else {
        archive_source::owned_text(source_id.to_owned())
    }
}

fn file_id_from_asset_pointer(pointer: &str) -> Option<&str> {
    let rest = pointer.split_once("://").map(|(_, rest)| rest)?;
    let rest = rest.trim_start_matches('/');
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let id = &rest[..end];
    (id.starts_with("file-") || id.starts_with("file_")).then_some(id)
}

fn file_id_from_filename(filename: &str) -> Option<String> {
    if let Some(rest) = filename.strip_prefix("file_") {
        let id = rest.split('.').next().unwrap_or(rest);
        return (!id.is_empty()).then(|| format!("file_{id}"));
    }
    if filename.starts_with("file-") {
        let stem = filename
            .rsplit_once('.')
            .map(|(stem, _extension)| stem)
            .unwrap_or(filename);
        let mut segments = stem.splitn(3, '-');
        let prefix = segments.next()?;
        let id = segments.next()?;
        return (prefix == "file" && !id.is_empty()).then(|| format!("file-{id}"));
    }
    None
}

fn is_conversation_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if name == "conversations.json" {
        return true;
    }
    let Some(shard) = name
        .strip_prefix("conversations-")
        .and_then(|name| name.strip_suffix(".json"))
    else {
        return false;
    };
    !shard.is_empty() && shard.bytes().all(|byte| byte.is_ascii_digit())
}

fn collect_conversation_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("read dir {}", path.display()))? {
        let entry = entry.context("read directory entry")?;
        let entry_path = entry.path();
        let file_type = entry.file_type().context("read directory entry type")?;
        if file_type.is_dir() {
            collect_conversation_files(&entry_path, out)?;
        } else if file_type.is_file() && is_conversation_file(&entry_path) {
            out.push(entry_path);
        }
    }
    Ok(())
}

fn collect_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("read dir {}", path.display()))? {
        let entry = entry.context("read directory entry")?;
        let entry_path = entry.path();
        let file_type = entry.file_type().context("read directory entry type")?;
        if file_type.is_dir() {
            collect_files(&entry_path, out)?;
        } else if file_type.is_file() && !is_conversation_file(&entry_path) {
            out.push(entry_path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;
    use triblespace::prelude::blobencodings::RawBytes;

    use super::*;

    const TINY_EXPORT: &str = r#"[
  {
    "id": "conversation-1",
    "current_node": "assistant-node",
    "mapping": {
      "root": { "id": "root", "parent": null, "message": null },
      "user-node": {
        "id": "user-node",
        "parent": "root",
        "message": {
          "id": "message-user",
          "author": { "role": "user", "name": "jp" },
          "create_time": 1772382841.5,
          "content": { "content_type": "text", "parts": ["hello", "again"] }
        }
      },
      "assistant-node": {
        "id": "assistant-node",
        "parent": "user-node",
        "message": {
          "id": "message-assistant",
          "author": { "role": "assistant", "name": null },
          "create_time": 1772382842,
          "content": {
            "content_type": "multimodal_text",
            "parts": [
              "hi!",
              { "content_type": "image_asset_pointer", "asset_pointer": "file-service://file-abc", "size_bytes": 4 }
            ]
          },
          "metadata": {
            "model_slug": "gpt-test",
            "attachments": [{ "id": "file-abc", "name": "picture.png", "mime_type": "image/png", "size": 4 }]
          }
        }
      }
    }
  }
]"#;

    const RICH_CONTENT_EXPORT: &str = r#"[
      {
        "id": "rich-content",
        "mapping": {
          "thought": {
            "parent": null,
            "message": {
              "id": "thought-message",
              "author": {"role": "assistant"},
              "content": {
                "content_type": "thoughts",
                "source_analysis_msg_id": "analysis-1",
                "thoughts": [
                  {"chunks": ["do", " not", " duplicate"], "content": "full thought", "finished": true, "summary": "thought summary"},
                  {"chunks": [], "content": "", "finished": false, "summary": "fallback summary"}
                ]
              }
            }
          },
          "recap": {
            "parent": "thought",
            "message": {
              "id": "recap-message",
              "author": {"role": "assistant"},
              "content": {"content": "reasoning recap", "content_type": "reasoning_recap"}
            }
          },
          "realtime": {
            "parent": "recap",
            "message": {
              "id": "realtime-message",
              "author": {"role": "user"},
              "content": {
                "content_type": "multimodal_text",
                "parts": [{
                  "audio_asset_pointer": {
                    "asset_pointer": "sediment://file_audio",
                    "content_type": "audio_asset_pointer",
                    "format": "wav",
                    "size_bytes": 10
                  },
                  "audio_start_timestamp": 12.5,
                  "content_type": "real_time_user_audio_video_asset_pointer",
                  "frames_asset_pointers": [
                    {"asset_pointer": "sediment://file_frame", "content_type": "image_asset_pointer", "size_bytes": 20},
                    "sediment://file_frame2"
                  ],
                  "video_container_asset_pointer": {
                    "asset_pointer": "sediment://file_video",
                    "content_type": "video_asset_pointer",
                    "size_bytes": 30
                  }
                }]
              }
            }
          }
        }
      }
    ]"#;

    #[derive(Debug)]
    struct Snapshot {
        receipt: Id,
        locator: String,
        block: Id,
        raw: Vec<u8>,
    }

    fn snapshots(path: &Path, export: &str) -> Vec<Snapshot> {
        fs::write(path, export).unwrap();
        let mut projections = Vec::new();
        project_path(path, |projection| {
            projections.push(projection);
            Ok(())
        })
        .unwrap();

        projections
            .iter_mut()
            .map(|projection| {
                let (receipt, locator, block) =
                    projected_identity(&mut projection.fragment).unwrap();
                let raw: Inline<Handle<RawBytes>> = find!(
                    raw: Inline<Handle<RawBytes>>,
                    pattern!(&projection.fragment, [{
                        receipt @ schema::source_projection::raw_record: ?raw
                    }])
                )
                .next()
                .unwrap();
                let reader = projection
                    .fragment
                    .blobs_mut()
                    .snapshot()
                    .expect("MemoryBlobStore reader construction is infallible");
                let raw: Bytes = reader.get(raw).unwrap();
                Snapshot {
                    receipt,
                    locator: locator.as_ref().to_owned(),
                    block,
                    raw: raw.as_ref().to_vec(),
                }
            })
            .collect()
    }

    fn semantic_blocks(snapshots: &[Snapshot]) -> Vec<(String, Id)> {
        let mut blocks: Vec<_> = snapshots
            .iter()
            .filter(|snapshot| snapshot.locator.contains("/node:"))
            .map(|snapshot| (snapshot.locator.clone(), snapshot.block))
            .collect();
        blocks.sort_by(|left, right| left.0.cmp(&right.0));
        blocks
    }

    #[test]
    fn scanner_keeps_exact_nodes_and_mapping_dag() {
        let conversations =
            scan_export(Bytes::from_source(TINY_EXPORT.as_bytes().to_vec())).unwrap();
        assert_eq!(conversations.len(), 1);
        let conversation = &conversations[0];
        assert_eq!(conversation.id.as_ref(), "conversation-1");
        assert_eq!(conversation.current_node.as_deref(), Some("assistant-node"));
        let envelope = conversation.raw_record.clone().view::<str>().unwrap();
        assert!(envelope.as_ref().starts_with('{'));
        assert!(envelope
            .as_ref()
            .contains(r#""current_node": "assistant-node""#));
        assert!(envelope.as_ref().contains(r#""mapping": {"#));
        assert_eq!(conversation.nodes.len(), 3);
        assert!(conversation.nodes[0].message.is_none());
        assert_eq!(conversation.nodes[1].parent.as_deref(), Some("root"));
        assert_eq!(
            conversation.nodes[1]
                .message
                .as_ref()
                .and_then(|message| message.id.as_deref()),
            Some("message-user")
        );
        let raw = conversation.nodes[1]
            .raw_record
            .clone()
            .view::<str>()
            .unwrap();
        assert!(raw.as_ref().starts_with('{'));
        assert!(raw.as_ref().contains("\"message-user\""));
        assert!(!raw.as_ref().starts_with("{\""));
    }

    #[test]
    fn semantic_alias_priority_is_member_order_independent_and_raw_stays_exact() {
        const PRIMARY_FIRST_NODE: &str = r#"{"parent":null,"message":{"id":"message","author":{"role":"assistant"},"content":{"text":"preferred-text","content":"fallback-text","parts":[{"id":"preferred-part","file_id":"fallback-part","name":"preferred.png","filename":"fallback.txt","content_type":"image_asset_pointer","type":"file","size":7,"size_bytes":99,"asset_pointer":"https://example.invalid/part"}],"content_type":"multimodal_text"},"metadata":{"model_slug":"preferred-model","model":"fallback-model","attachments":[{"id":"preferred-meta","file_id":"fallback-meta","name":"preferred.pdf","filename":"fallback.bin","content_type":"file","type":"image","size":11,"size_bytes":101}]}}}"#;
        const PRIMARY_LAST_NODE: &str = r#"{"message":{"metadata":{"attachments":[{"size_bytes":101,"size":11,"type":"image","content_type":"file","filename":"fallback.bin","name":"preferred.pdf","file_id":"fallback-meta","id":"preferred-meta"}],"model":"fallback-model","model_slug":"preferred-model"},"content":{"content_type":"multimodal_text","parts":[{"asset_pointer":"https://example.invalid/part","size_bytes":99,"size":7,"type":"file","content_type":"image_asset_pointer","filename":"fallback.txt","name":"preferred.png","file_id":"fallback-part","id":"preferred-part"}],"content":"fallback-text","text":"preferred-text"},"author":{"role":"assistant"},"id":"message"},"parent":null}"#;

        let conversation = |id_fields: &str, node: &str| {
            format!(r#"{{{id_fields},"current_node":"node","mapping":{{"node":{node}}}}}"#)
        };
        let first_object = conversation(
            r#""id":"preferred-conversation","conversation_id":"fallback-conversation""#,
            PRIMARY_FIRST_NODE,
        );
        let last_object = conversation(
            r#""conversation_id":"fallback-conversation","id":"preferred-conversation""#,
            PRIMARY_LAST_NODE,
        );
        let parse = |object: &str| {
            scan_export(Bytes::from_source(format!("[{object}]").into_bytes()))
                .unwrap()
                .pop()
                .unwrap()
        };
        let first = parse(&first_object);
        let last = parse(&last_object);

        for parsed in [&first, &last] {
            assert_eq!(parsed.id.as_ref(), "preferred-conversation");
            let message = parsed.nodes[0].message.as_ref().unwrap();
            assert_eq!(message.model.as_deref(), Some("preferred-model"));
            let text: Vec<_> = message
                .content
                .iter()
                .filter_map(|part| match part {
                    ContentItem::Text(text) => Some(text.as_ref()),
                    ContentItem::Attachment(_) => None,
                })
                .collect();
            assert_eq!(text, ["preferred-text"]);
            let content_attachment = message
                .content
                .iter()
                .find_map(|part| match part {
                    ContentItem::Text(_) => None,
                    ContentItem::Attachment(attachment) => Some(attachment),
                })
                .unwrap();
            assert_eq!(content_attachment.id.as_deref(), Some("preferred-part"));
            assert_eq!(content_attachment.name.as_deref(), Some("preferred.png"));
            assert_eq!(
                content_attachment.kind.as_deref(),
                Some("image_asset_pointer")
            );
            assert_eq!(content_attachment.size, Some(7));

            let metadata_attachment = &message.attachments[0];
            assert_eq!(metadata_attachment.id.as_deref(), Some("preferred-meta"));
            assert_eq!(metadata_attachment.name.as_deref(), Some("preferred.pdf"));
            assert_eq!(metadata_attachment.kind.as_deref(), Some("file"));
            assert_eq!(metadata_attachment.size, Some(11));
        }

        assert_eq!(first.raw_record.as_ref(), first_object.as_bytes());
        assert_eq!(last.raw_record.as_ref(), last_object.as_bytes());
        assert_eq!(
            first.nodes[0].raw_record.as_ref(),
            PRIMARY_FIRST_NODE.as_bytes()
        );
        assert_eq!(
            last.nodes[0].raw_record.as_ref(),
            PRIMARY_LAST_NODE.as_bytes()
        );

        let temp = TempDir::new().unwrap();
        let path = temp.path().join("conversations.json");
        let first_export = format!("[{first_object}]");
        let last_export = format!("[{last_object}]");
        assert_eq!(
            semantic_blocks(&snapshots(&path, &first_export)),
            semantic_blocks(&snapshots(&path, &last_export)),
            "JSON member order and lower-priority aliases cannot alter semantic blocks"
        );
    }

    #[test]
    fn preferred_alias_nulls_are_authoritative() {
        for object in [
            r#"{"id":null,"conversation_id":"legacy","mapping":{}}"#,
            r#"{"conversation_id":"legacy","id":null,"mapping":{}}"#,
        ] {
            assert!(scan_export(Bytes::from_source(format!("[{object}]").into_bytes())).is_err());
        }

        const NULL_FIRST_NODE: &str = r#"{"parent":null,"message":{"id":"message","content":{"text":null,"content":"fallback-text","parts":[{"id":null,"file_id":"fallback-id","name":null,"filename":"fallback.txt","content_type":null,"type":"image","size":null,"size_bytes":99,"asset_pointer":"https://example.invalid/part"}]},"metadata":{"model_slug":null,"model":"fallback-model","attachments":[{"id":"retained","name":null,"filename":"fallback.bin","content_type":null,"type":"file","size":null,"size_bytes":101}]}}}"#;
        const NULL_LAST_NODE: &str = r#"{"message":{"metadata":{"attachments":[{"size_bytes":101,"size":null,"type":"file","content_type":null,"filename":"fallback.bin","name":null,"id":"retained"}],"model":"fallback-model","model_slug":null},"content":{"parts":[{"asset_pointer":"https://example.invalid/part","size_bytes":99,"size":null,"type":"image","content_type":null,"filename":"fallback.txt","name":null,"file_id":"fallback-id","id":null}],"content":"fallback-text","text":null},"id":"message"},"parent":null}"#;

        for node in [NULL_FIRST_NODE, NULL_LAST_NODE] {
            let export = format!(r#"[{{"id":"null-aliases","mapping":{{"node":{node}}}}}]"#);
            let conversations = scan_export(Bytes::from_source(export.into_bytes())).unwrap();
            let message = conversations[0].nodes[0].message.as_ref().unwrap();
            assert!(message.model.is_none());
            assert!(message
                .content
                .iter()
                .all(|part| !matches!(part, ContentItem::Text(_))));
            let content_attachment = message
                .content
                .iter()
                .find_map(|part| match part {
                    ContentItem::Text(_) => None,
                    ContentItem::Attachment(attachment) => Some(attachment),
                })
                .unwrap();
            assert!(content_attachment.id.is_none());
            assert!(content_attachment.name.is_none());
            assert!(content_attachment.kind.is_none());
            assert!(content_attachment.size.is_none());
            let metadata_attachment = &message.attachments[0];
            assert!(metadata_attachment.name.is_none());
            assert!(metadata_attachment.kind.is_none());
            assert!(metadata_attachment.size.is_none());
        }
    }

    #[test]
    fn attachment_pointer_alias_priority_is_order_independent() {
        fn scan_pointer(raw: &str) -> Attachment {
            let mut bytes = Bytes::from_source(raw.as_bytes().to_vec());
            scan_pointer_value(&mut bytes, None).unwrap().unwrap()
        }

        fn scan_metadata_attachment(raw: &str) -> Attachment {
            let mut bytes = Bytes::from_source(raw.as_bytes().to_vec());
            scan_attachment(&mut bytes).unwrap().unwrap()
        }

        for raw in [
            r#"{"asset_pointer":"preferred://asset","url":"fallback://asset","id":"attachment"}"#,
            r#"{"url":"fallback://asset","asset_pointer":"preferred://asset","id":"attachment"}"#,
        ] {
            assert_eq!(
                scan_pointer(raw).pointer.as_deref(),
                Some("preferred://asset")
            );
            assert_eq!(
                scan_metadata_attachment(raw).pointer.as_deref(),
                Some("preferred://asset")
            );
        }

        for raw in [
            r#"{"asset_pointer":null,"url":"fallback://asset","id":"attachment"}"#,
            r#"{"url":"fallback://asset","asset_pointer":null,"id":"attachment"}"#,
        ] {
            assert!(scan_pointer(raw).pointer.is_none());
            assert!(scan_metadata_attachment(raw).pointer.is_none());
        }
    }

    #[test]
    fn project_path_contracts_null_nodes_and_resolves_assets() {
        let temp = TempDir::new().unwrap();
        let export = temp.path().join("conversations-000.json");
        fs::write(&export, TINY_EXPORT).unwrap();
        fs::write(temp.path().join("file-abc-picture.png"), [1, 2, 3, 4]).unwrap();

        let mut projected = Vec::new();
        let summary = project_path(temp.path(), |projection| {
            projected.push(projection);
            Ok(())
        })
        .unwrap();

        assert_eq!(summary.files_scanned, 1);
        assert_eq!(summary.conversations_seen, 1);
        assert_eq!(summary.mapping_nodes_seen, 3);
        assert_eq!(summary.attachments_seen, 1);
        assert_eq!(summary.attachments_resolved, 1);
        assert_eq!(summary.stats.transparent_records, 1);
        assert_eq!(summary.stats.raw_only_records, 2);
        assert_eq!(summary.stats.projections_emitted, 4);
        assert_eq!(summary.stats.content_parts, 4);
        assert_eq!(projected.len(), 4);

        let mut identities = Vec::new();
        for projection in &mut projected {
            identities.push(projected_identity(&mut projection.fragment).unwrap());
        }
        let (_, _, tip_block) = identities
            .iter()
            .find(|(_, locator, _)| locator.as_ref().contains("node:14:assistant-node"))
            .cloned()
            .unwrap();
        let (_, _, envelope_block) = identities
            .iter()
            .find(|(_, locator, _)| locator.as_ref().ends_with("/envelope"))
            .cloned()
            .unwrap();
        assert_eq!(envelope_block, tip_block);
    }

    #[test]
    fn duplicate_sidecars_remain_unresolved_independent_of_input_order() {
        fn project_with_index(
            export: &Path,
            sidecars: &ExportFiles,
        ) -> (ProjectionSummary, TribleSet, bool) {
            let mut facts = TribleSet::new();
            let mut retained_exact_pointer = false;
            let mut emit = |mut projection: ProjectedSource| {
                let (receipt, locator, _) = projected_identity(&mut projection.fragment)?;
                if locator.as_ref().contains("/node:") {
                    let raw: Inline<Handle<RawBytes>> = find!(
                        raw: Inline<Handle<RawBytes>>,
                        pattern!(&projection.fragment, [{
                            receipt @ schema::source_projection::raw_record: ?raw
                        }])
                    )
                    .next()
                    .expect("mapping-node projection retains its exact source receipt");
                    let reader = projection
                        .fragment
                        .blobs_mut()
                        .snapshot()
                        .expect("MemoryBlobStore reader construction is infallible");
                    let raw: Bytes = reader.get(raw).unwrap();
                    retained_exact_pointer = raw.view::<str>().is_ok_and(|raw| {
                        raw.as_ref().contains("file-service://file-abc")
                            && raw.as_ref().contains("https://example.invalid/asset")
                    });
                }
                facts += projection.fragment.facts().clone();
                Ok(())
            };
            let summary = project_file(export, sidecars, &mut emit).unwrap();
            (summary, facts, retained_exact_pointer)
        }

        const AMBIGUOUS_SIDECARS: &str = r#"[
          {
            "id": "ambiguous-sidecars",
            "current_node": "assistant-node",
            "mapping": {
              "assistant-node": {
                "parent": null,
                "message": {
                  "id": "message-assistant",
                  "author": {"role": "assistant"},
                  "content": {
                    "content_type": "multimodal_text",
                    "parts": [
                      {"content_type": "image_asset_pointer", "asset_pointer": "file-service://file-abc"},
                      {"content_type": "file", "asset_pointer": "https://example.invalid/asset", "name": "duplicate.txt"}
                    ]
                  }
                }
              }
            }
          }
        ]"#;

        let temp = TempDir::new().unwrap();
        let export = temp.path().join("conversations.json");
        fs::write(&export, AMBIGUOUS_SIDECARS).unwrap();
        let id_first = temp.path().join("a/file-abc-first.png");
        let id_second = temp.path().join("b/file-abc-second.png");
        let name_first = temp.path().join("c/duplicate.txt");
        let name_second = temp.path().join("d/duplicate.txt");
        for (path, bytes) in [
            (&id_first, [1, 2, 3, 4]),
            (&id_second, [5, 6, 7, 8]),
            (&name_first, [9, 10, 11, 12]),
            (&name_second, [13, 14, 15, 16]),
        ] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }

        let forward = ExportFiles::from_paths([
            id_first.clone(),
            id_second.clone(),
            name_first.clone(),
            name_second.clone(),
        ]);
        let reverse = ExportFiles::from_paths([name_second, name_first, id_second, id_first]);
        let (forward_summary, forward_facts, forward_raw) = project_with_index(&export, &forward);
        let (reverse_summary, reverse_facts, reverse_raw) = project_with_index(&export, &reverse);

        assert_eq!(forward_summary.attachments_seen, 2);
        assert_eq!(forward_summary.attachments_resolved, 0);
        assert_eq!(reverse_summary.attachments_resolved, 0);
        assert!(
            forward_raw && reverse_raw,
            "exact pointer evidence was lost"
        );
        assert_eq!(forward_facts, reverse_facts);
        assert_eq!(
            find!(
                resolved: Inline<Handle<RawBytes>>,
                pattern!(&forward_facts, [{
                    _?fact @ schema::content_fact::resolved_to: ?resolved
                }])
            )
            .count(),
            0,
            "ambiguous sidecar bytes must not be asserted as a resolution"
        );
    }

    #[test]
    fn exact_envelope_changes_receipt_but_not_semantic_blocks() {
        const ENVELOPE: &str = r#"[
  {
    "id": "envelope-lossless",
    "title": "A retained title",
    "create_time": 1772382841,
    "update_time": 1772382842,
    "plugin_ids": ["plugin-one"],
    "account": {"id": "account-one"},
    "future_vendor_field" : { "opaque" : [1, 2, 3] },
    "current_node": "assistant-node",
    "mapping": {
      "user-node": {
        "parent": null,
        "message": {
          "id": "message-user",
          "author": {"role": "user"},
          "content": {"content_type": "text", "parts": ["hello"]}
        }
      },
      "assistant-node": {
        "parent": "user-node",
        "message": {
          "id": "message-assistant",
          "author": {"role": "assistant"},
          "content": {"content_type": "text", "parts": ["hi"]}
        }
      }
    }
  }
]"#;
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("conversations.json");
        let changed_envelope = ENVELOPE.replace("[1, 2, 3]", "[1, 2, 4]");
        let first = snapshots(&path, ENVELOPE);
        let second = snapshots(&path, &changed_envelope);

        assert_eq!(semantic_blocks(&first), semantic_blocks(&second));
        let first_envelope = first
            .iter()
            .find(|snapshot| snapshot.locator.ends_with("/envelope"))
            .unwrap();
        let second_envelope = second
            .iter()
            .find(|snapshot| snapshot.locator.ends_with("/envelope"))
            .unwrap();
        assert_ne!(first_envelope.receipt, second_envelope.receipt);
        assert_eq!(first_envelope.block, second_envelope.block);

        let exact = std::str::from_utf8(&first_envelope.raw).unwrap();
        assert!(exact.starts_with("{\n    \"id\": \"envelope-lossless\""));
        assert!(exact.contains(r#""future_vendor_field" : { "opaque" : [1, 2, 3] }"#));
        assert!(exact.contains(r#""mapping": {"#));
        assert!(exact.ends_with("\n  }"));
    }

    #[test]
    fn envelope_without_active_branch_projects_to_canonical_bottom() {
        const NO_CURRENT_NODE: &str = r#"[
  {
    "id": "no-current-node",
    "title": "Still lossless",
    "current_node": null,
    "mapping": {
      "node": {
        "parent": null,
        "message": {
          "id": "message",
          "author": {"role": "user"},
          "content": {"content_type": "text", "parts": ["hello"]}
        }
      }
    }
  }
]"#;

        let temp = TempDir::new().unwrap();
        let path = temp.path().join("conversations.json");
        let projected = snapshots(&path, NO_CURRENT_NODE);
        assert_eq!(projected.len(), 2);

        let envelope = projected
            .iter()
            .find(|snapshot| snapshot.locator.ends_with("/envelope"))
            .unwrap();
        let bottom = blockdag::block(std::iter::empty::<Id>(), None, Fragment::empty())
            .unwrap()
            .root()
            .unwrap();
        assert_eq!(envelope.block, bottom);
        let exact = std::str::from_utf8(&envelope.raw).unwrap();
        assert!(exact.contains(r#""title": "Still lossless""#));
        assert!(exact.contains(r#""current_node": null"#));
        assert!(exact.contains(r#""mapping": {"#));
    }

    #[test]
    fn discovers_only_canonical_and_numeric_shards() {
        let temp = TempDir::new().unwrap();
        for name in [
            "conversations.json",
            "conversations-000.json",
            "conversations-backup.json",
            "other.json",
        ] {
            fs::write(temp.path().join(name), "[]").unwrap();
        }
        let mut found = Vec::new();
        collect_conversation_files(temp.path(), &mut found).unwrap();
        found.sort();
        let names: Vec<_> = found
            .iter()
            .map(|path| path.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(names, ["conversations-000.json", "conversations.json"]);
    }

    #[test]
    fn thoughts_and_reasoning_recap_project_as_thinking_text() {
        let conversations =
            scan_export(Bytes::from_source(RICH_CONTENT_EXPORT.as_bytes().to_vec())).unwrap();
        let thought = conversations[0].nodes[0].message.as_ref().unwrap();
        assert_eq!(thought.content_type.as_deref(), Some("thoughts"));
        assert_eq!(
            text_modality(thought.role.as_deref(), thought.content_type.as_deref()),
            schema::content_fact::modality::THINKING
        );
        let thought_text: Vec<_> = thought
            .content
            .iter()
            .filter_map(|part| match part {
                ContentItem::Text(text) => Some(text.as_ref()),
                ContentItem::Attachment(_) => None,
            })
            .collect();
        assert_eq!(thought_text, ["full thought", "fallback summary"]);

        let recap = conversations[0].nodes[1].message.as_ref().unwrap();
        assert_eq!(recap.content_type.as_deref(), Some("reasoning_recap"));
        assert_eq!(
            text_modality(recap.role.as_deref(), recap.content_type.as_deref()),
            schema::content_fact::modality::THINKING
        );
        assert!(matches!(
            recap.content.as_slice(),
            [ContentItem::Text(text)] if text.as_ref() == "reasoning recap"
        ));
    }

    #[test]
    fn real_time_nested_media_pointers_are_not_lost() {
        let conversations =
            scan_export(Bytes::from_source(RICH_CONTENT_EXPORT.as_bytes().to_vec())).unwrap();
        let realtime = conversations[0].nodes[2].message.as_ref().unwrap();
        let attachments: Vec<_> = realtime
            .content
            .iter()
            .filter_map(|part| match part {
                ContentItem::Attachment(attachment) => Some(attachment),
                ContentItem::Text(_) => None,
            })
            .collect();
        assert_eq!(attachments.len(), 4);
        let pointers: Vec<_> = attachments
            .iter()
            .map(|attachment| attachment.pointer.as_deref().unwrap())
            .collect();
        assert_eq!(
            pointers,
            [
                "sediment://file_audio",
                "sediment://file_frame",
                "sediment://file_frame2",
                "sediment://file_video"
            ]
        );
        assert_eq!(
            modality_for_kind(attachments[0].kind.as_deref()),
            schema::content_fact::modality::AUDIO
        );
        assert_eq!(attachments[0].format.as_deref(), Some("wav"));
        let (audio, _) = attachments[0]
            .clone()
            .into_source_part(schema::content_fact::direction::IN, &ExportFiles::default())
            .unwrap();
        assert!(matches!(
            audio,
            SourcePart::Pointer { media_type: Some(media_type), .. }
                if media_type.as_ref() == "audio/wav"
        ));
        assert_eq!(
            modality_for_kind(attachments[1].kind.as_deref()),
            schema::content_fact::modality::IMAGE
        );
        assert_eq!(
            modality_for_kind(attachments[3].kind.as_deref()),
            schema::content_fact::modality::VIDEO
        );
    }

    #[test]
    fn both_chatgpt_asset_naming_schemes_converge() {
        assert_eq!(
            file_id_from_asset_pointer("file-service://file-deadbeef"),
            Some("file-deadbeef")
        );
        assert_eq!(
            file_id_from_asset_pointer("sediment://file_voice123"),
            Some("file_voice123")
        );
        assert_eq!(
            file_id_from_filename("file-deadbeef-image.png").as_deref(),
            Some("file-deadbeef")
        );
        assert_eq!(
            file_id_from_filename("file-X.dat").as_deref(),
            Some("file-X")
        );
        assert_eq!(
            file_id_from_filename("file_voice123.wav").as_deref(),
            Some("file_voice123")
        );
    }
}
