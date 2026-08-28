//! Canonical file-record construction shared by every faculty.
//!
//! A file entity is an immutable description of one named file value. Its
//! intrinsic identity is derived from exactly four facts:
//!
//! - [`metadata::tag`] = [`KIND_FILE`]
//! - [`file::content`] = the content-addressed raw-bytes handle
//! - [`file::name`] = the leaf name (never a containing path)
//! - [`file::media_type`] = an intrinsic [`KIND_MEDIA_TYPE`] entity
//!
//! Paths, source-system identifiers, timestamps, tags, embeddings, and other
//! provenance are deliberately absent from that identity. New callers attach
//! those facts to imports or source-specific occurrence entities; complete
//! catalogs also preserve historical path/timestamp provenance on file ids.

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use hifitime::Epoch;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use triblespace::core::collection::{CollectionCommit, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet};
use triblespace::prelude::blobencodings::{RawBytes, UTF8String};
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval, ShortString};
use triblespace::prelude::*;
use triblespace_search::schemas::Embedding;

use crate::legacy_hint::open_scope;
use crate::schemas::embeddings;
use crate::schemas::files::{file, KIND_DIRECTORY, KIND_FILE, KIND_IMPORT, KIND_MEDIA_TYPE};

pub type ContentHandle = Inline<Handle<RawBytes>>;
pub type NameHandle = Inline<Handle<UTF8String>>;
pub type ImportTime = Inline<NsTAIInterval>;
pub const DEFAULT_MEDIA_TYPE: &str = "application/octet-stream";

/// The two canonical targets carried by a `files:` reference token.
///
/// Unlike an entity selector, a content reference identifies bytes directly:
/// several named file entities may intentionally share one content handle.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FileReference {
    Entity(Id),
    Content(ContentHandle),
}

impl FileReference {
    pub fn hex(self) -> String {
        match self {
            Self::Entity(entity) => format!("{entity:x}"),
            Self::Content(content) => content_hash_hex(content),
        }
    }
}

/// One structurally complete file in a validated Files snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileRecord {
    pub id: Id,
    pub name: String,
    pub content: ContentHandle,
    pub media_type: Id,
}

/// One structurally complete directory in a validated Files snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryRecord {
    pub id: Id,
    pub name: String,
    pub children: Vec<Id>,
}

/// One structurally complete import in a validated Files snapshot.
///
/// The writer derives an import id from exactly one source path, timestamp,
/// and root. Repeated values are therefore corruption or conflicting additive
/// evidence, not alternate candidates from which a reader may choose.
#[derive(Clone, Debug, PartialEq)]
pub struct ImportRecord {
    pub id: Id,
    pub imported_at: Epoch,
    pub source_path: String,
    pub root: Id,
    pub tags: Vec<String>,
}

/// A validated file-system node.
#[derive(Clone, Copy, Debug)]
pub enum NodeRecord<'a> {
    File(&'a FileRecord),
    Directory(&'a DirectoryRecord),
}

/// A byte reference together with every catalog name that describes it.
///
/// Entity references always have one name because [`FilesCatalog`] rejects
/// malformed scalar fields. Content references may intentionally be shared by
/// several differently named files, so callers must not pick one name as a
/// winner. [`ResolvedFile::unique_name`] is `None` in that case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedFile {
    pub content: ContentHandle,
    pub names: Vec<String>,
}

impl ResolvedFile {
    pub fn unique_name(&self) -> Option<&str> {
        (self.names.len() == 1).then(|| self.names[0].as_str())
    }
}

/// Canonical read model for one complete Files collection value.
///
/// Scalar writer fields are validated as exactly-one values. Directory edges
/// and tags remain set-valued and are sorted for deterministic presentation.
/// This type is the shared boundary for the Files and Wiki widgets so neither
/// can accidentally reinstate `Iterator::next()` winner semantics.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FilesCatalog {
    files: BTreeMap<Id, FileRecord>,
    directories: BTreeMap<Id, DirectoryRecord>,
    imports: BTreeMap<Id, ImportRecord>,
}

impl FilesCatalog {
    pub fn files(&self) -> impl ExactSizeIterator<Item = &FileRecord> {
        self.files.values()
    }

    pub fn directories(&self) -> impl ExactSizeIterator<Item = &DirectoryRecord> {
        self.directories.values()
    }

    pub fn imports(&self) -> impl ExactSizeIterator<Item = &ImportRecord> {
        self.imports.values()
    }

    pub fn file(&self, id: Id) -> Option<&FileRecord> {
        self.files.get(&id)
    }

    pub fn directory(&self, id: Id) -> Option<&DirectoryRecord> {
        self.directories.get(&id)
    }

    pub fn import(&self, id: Id) -> Option<&ImportRecord> {
        self.imports.get(&id)
    }

    pub fn node(&self, id: Id) -> Option<NodeRecord<'_>> {
        self.file(id)
            .map(NodeRecord::File)
            .or_else(|| self.directory(id).map(NodeRecord::Directory))
    }

    /// Resolve the canonical selector language using only validated records.
    pub fn resolve_reference(&self, input: &str) -> Result<FileReference> {
        let selector = normalize_selector(input)?;

        if selector.len() == 32 {
            return Id::from_hex(&selector)
                .map(FileReference::Entity)
                .ok_or_else(|| anyhow!("invalid entity id '{selector}'"));
        }
        if selector.len() == 64 {
            let hash = inlineencodings::Hash::<inlineencodings::Blake3>::from_hex(&selector)
                .map_err(|_| anyhow!("invalid content hash '{selector}'"))?;
            return Ok(FileReference::Content(inlineencodings::Handle::from_hash(
                hash,
            )));
        }

        let mut matches = BTreeSet::new();
        for file in self.files.values() {
            if format!("{:x}", file.id).starts_with(&selector) {
                matches.insert(FileReference::Entity(file.id));
            }
            if content_hash_hex(file.content).starts_with(&selector) {
                matches.insert(FileReference::Content(file.content));
            }
        }
        for id in self.directories.keys().chain(self.imports.keys()).copied() {
            if format!("{id:x}").starts_with(&selector) {
                matches.insert(FileReference::Entity(id));
            }
        }
        exactly_one(&selector, matches, "file reference", |reference| {
            format!("files:{}", reference.hex())
        })
    }

    /// Resolve bytes without manufacturing a display-name winner.
    pub fn resolve_file(&self, input: &str) -> Result<ResolvedFile> {
        match self.resolve_reference(input)? {
            FileReference::Entity(id) => {
                let file = self
                    .file(id)
                    .ok_or_else(|| anyhow!("files entity {id:x} is not a file"))?;
                Ok(ResolvedFile {
                    content: file.content,
                    names: vec![file.name.clone()],
                })
            }
            FileReference::Content(content) => {
                let names = self
                    .files
                    .values()
                    .filter(|file| file.content == content)
                    .map(|file| file.name.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                Ok(ResolvedFile { content, names })
            }
        }
    }
}

/// Return the lowercase Blake3 digest addressed by a canonical file handle.
pub fn content_hash_hex(handle: ContentHandle) -> String {
    let hash: Inline<inlineencodings::Hash<inlineencodings::Blake3>> =
        inlineencodings::Handle::to_hash(handle);
    inlineencodings::Hash::<inlineencodings::Blake3>::to_hex(&hash).to_ascii_lowercase()
}

fn normalize_selector(input: &str) -> Result<String> {
    let trimmed = input.trim();
    let raw = trimmed.strip_prefix("files:").unwrap_or(trimmed);
    let selector = raw.to_ascii_lowercase();
    if selector.is_empty()
        || selector.len() > 64
        || !selector.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        anyhow::bail!(
            "invalid file selector '{selector}': expected 1 to 64 hexadecimal characters, optionally prefixed by 'files:'"
        );
    }
    Ok(selector)
}

fn exactly_one<T>(
    selector: &str,
    matches: BTreeSet<T>,
    kind: &str,
    render: impl Fn(T) -> String,
) -> Result<T>
where
    T: Copy + Ord,
{
    match matches.len() {
        0 => anyhow::bail!("no {kind} matches selector '{selector}'"),
        1 => Ok(*matches.first().expect("one selector match")),
        _ => {
            let candidates = matches
                .into_iter()
                .map(render)
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!("{kind} selector '{selector}' is ambiguous; candidates: {candidates}")
        }
    }
}

#[derive(Default)]
struct SelectorMatches {
    entities: BTreeSet<Id>,
    references: BTreeSet<FileReference>,
}

fn selector_matches(space: &TribleSet, selector: &str) -> SelectorMatches {
    let mut matches = SelectorMatches::default();
    for (entity, content) in find!(
        (entity: Id, content: ContentHandle),
        pattern!(space, [{
            ?entity @ metadata::tag: &KIND_FILE,
            file::content: ?content,
        }])
    ) {
        if format!("{entity:x}").starts_with(selector) {
            matches.entities.insert(entity);
            matches.references.insert(FileReference::Entity(entity));
        }
        if content_hash_hex(content).starts_with(selector) {
            matches.entities.insert(entity);
            matches.references.insert(FileReference::Content(content));
        }
    }
    for entity in find!(
        entity: Id,
        pattern!(space, [{ ?entity @ metadata::tag: &KIND_DIRECTORY }])
    )
    .chain(find!(
        entity: Id,
        pattern!(space, [{ ?entity @ metadata::tag: &KIND_IMPORT }])
    )) {
        if format!("{entity:x}").starts_with(selector) {
            matches.entities.insert(entity);
            matches.references.insert(FileReference::Entity(entity));
        }
    }
    matches
}

/// Resolve a file-faculty selector to exactly one entity.
///
/// Selectors are case-insensitive hexadecimal with an optional `files:`
/// prefix. A complete 32-character entity id is direct and intentionally does
/// not scan the catalog. A complete 64-character digest resolves through
/// [`file::content`] and must identify exactly one canonical file entity. Any
/// other shorter selector is matched against eligible file, directory, and
/// import entity ids as well as file content digests. Matches are deduplicated
/// by entity, so one file matching through both its id and digest remains one
/// candidate.
pub fn resolve_selector(space: &TribleSet, input: &str) -> Result<Id> {
    let selector = normalize_selector(input)?;

    if selector.len() == 32 {
        return Id::from_hex(&selector).ok_or_else(|| anyhow!("invalid entity id '{selector}'"));
    }

    if selector.len() == 64 {
        let hash = inlineencodings::Hash::<inlineencodings::Blake3>::from_hex(&selector)
            .map_err(|_| anyhow!("invalid content hash '{selector}'"))?;
        let handle: ContentHandle = inlineencodings::Handle::from_hash(hash);
        let matches: BTreeSet<Id> = find!(
            entity: Id,
            pattern!(space, [{
                ?entity @ metadata::tag: &KIND_FILE,
                file::content: &handle,
            }])
        )
        .collect();
        return exactly_one(&selector, matches, "file entity", |entity| {
            format!("{entity:x}")
        });
    }

    exactly_one(
        &selector,
        selector_matches(space, &selector).entities,
        "file entity",
        |entity| format!("{entity:x}"),
    )
}

/// Expand a selector to one canonical `files:` reference token.
///
/// This is deliberately distinct from [`resolve_selector`]. Entity selectors
/// collapse matches by entity and therefore reject one content hash shared by
/// multiple named files. Reference selectors collapse by reference token: the
/// shared content handle is one valid content reference, while entity ids are
/// separate reference tokens. Complete 32- and 64-character tokens are direct
/// and need no catalog evidence; shorter prefixes are expanded from canonical
/// file, directory, and import records.
pub fn resolve_reference(space: &TribleSet, input: &str) -> Result<FileReference> {
    let selector = normalize_selector(input)?;

    if selector.len() == 32 {
        return Id::from_hex(&selector)
            .map(FileReference::Entity)
            .ok_or_else(|| anyhow!("invalid entity id '{selector}'"));
    }

    if selector.len() == 64 {
        let hash = inlineencodings::Hash::<inlineencodings::Blake3>::from_hex(&selector)
            .map_err(|_| anyhow!("invalid content hash '{selector}'"))?;
        return Ok(FileReference::Content(inlineencodings::Handle::from_hash(
            hash,
        )));
    }

    exactly_one(
        &selector,
        selector_matches(space, &selector).references,
        "file reference",
        |reference| format!("files:{}", reference.hex()),
    )
}

/// Best-effort media type inferred from a filename extension.
///
/// This table is shared because media type participates in canonical file
/// identity: two faculties must not classify the same named bytes differently
/// merely because they each grew their own extension mapping. Extensions are
/// ASCII-case-insensitive.
pub fn infer_media_type(path: &Path) -> &'static str {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match extension.as_str() {
        "pdf" => "application/pdf",
        "json" => "application/json",
        "toml" => "application/toml",
        "yaml" | "yml" => "application/yaml",
        "xml" => "application/xml",
        "csv" => "text/csv",
        "txt" => "text/plain",
        "md" | "markdown" => "text/markdown",
        "rs" => "text/x-rust",
        "py" => "text/x-python",
        "js" => "application/javascript",
        "ts" => "application/typescript",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "tif" | "tiff" => "image/tiff",
        "tar" => "application/x-tar",
        "gz" | "gzip" => "application/gzip",
        "zip" => "application/zip",
        "wasm" => "application/wasm",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        _ => DEFAULT_MEDIA_TYPE,
    }
}

/// Reduce a source-provided name to the path-independent leaf used by file
/// identity. Both separator styles are recognized so records converge across
/// Unix, Windows, mail clients, and remote APIs.
pub fn leaf_name(name: &str) -> String {
    name.rsplit(['/', '\\'])
        .find(|part| !part.is_empty() && *part != "." && *part != "..")
        .unwrap_or("unnamed")
        .to_owned()
}

/// Parse a source-provided content type and return its canonical media-type
/// essence (parameters removed, type/subtype lower-cased).
///
/// An absent content type is represented by `application/octet-stream`.
/// Invalid non-empty values are rejected rather than becoming distinct bogus
/// media-type entities.
pub fn normalize_media_type(media_type: &str) -> Result<String> {
    let media_type = media_type.trim();
    if media_type.is_empty() {
        return Ok(DEFAULT_MEDIA_TYPE.to_owned());
    }
    let parsed = media_type
        .parse::<mime::Mime>()
        .map_err(|err| anyhow!("invalid file media type {media_type:?}: {err}"))?;
    Ok(parsed.essence_str().to_ascii_lowercase())
}

/// Normalize an untrusted protocol-provided content type, degrading malformed
/// values to the generic binary type. Source adapters use this when rejecting
/// one bad header would prevent an otherwise replayable sync cursor from
/// advancing; explicit user-facing MIME overrides should stay on the strict
/// [`normalize_media_type`] / [`stage`] path.
pub fn normalize_media_type_or_default(media_type: &str) -> String {
    normalize_media_type(media_type).unwrap_or_else(|_| DEFAULT_MEDIA_TYPE.to_owned())
}

/// Resolve the full media-type name handle for a canonical file record.
///
/// The join deliberately verifies the target's kind as well as following the
/// relation. A dangling or wrongly-typed target is not a valid media type.
pub fn media_type_name_handle(space: &TribleSet, file_id: Id) -> Option<NameHandle> {
    find!(
        (name: NameHandle),
        pattern!(space, [
            { file_id @ file::media_type: _?media_type },
            { _?media_type @ metadata::tag: &KIND_MEDIA_TYPE, metadata::name: ?name }
        ])
    )
    .next()
    .map(|(name,)| name)
}

fn one_file_value<T: Ord>(values: BTreeSet<T>, field: &str, file_id: Id) -> Result<Option<T>> {
    match values.len() {
        0 => Ok(None),
        1 => Ok(values.into_iter().next()),
        count => anyhow::bail!("file {file_id:x} has {count} values for {field}"),
    }
}

/// Resolve the unique content handle of one file entity, if present.
pub fn content_handle(space: &TribleSet, file_id: Id) -> Result<Option<ContentHandle>> {
    one_file_value(
        find!(
            content: ContentHandle,
            pattern!(space, [{ file_id @ file::content: ?content }])
        )
        .collect(),
        "content",
        file_id,
    )
}

/// Resolve the unique leaf-name handle of one file entity, if present.
pub fn name_handle(space: &TribleSet, file_id: Id) -> Result<Option<NameHandle>> {
    one_file_value(
        find!(
            name: NameHandle,
            pattern!(space, [{ file_id @ file::name: ?name }])
        )
        .collect(),
        "name",
        file_id,
    )
}

/// Resolve a file's unique media-type name while checking the referenced
/// entity's canonical kind.
pub fn media_type_name_handle_strict(space: &TribleSet, file_id: Id) -> Result<Option<NameHandle>> {
    one_file_value(
        find!(
            name: NameHandle,
            pattern!(space, [
                { file_id @ file::media_type: _?media_type },
                { _?media_type @ metadata::tag: &KIND_MEDIA_TYPE, metadata::name: ?name }
            ])
        )
        .collect(),
        "media type name",
        file_id,
    )
}

fn required_catalog_value<T: Ord>(values: BTreeSet<T>, field: &str, id: Id) -> Result<T> {
    match values.len() {
        1 => Ok(values.into_iter().next().expect("one catalog value")),
        count => anyhow::bail!(
            "Files entity {id:x} has {count} values for {field}; expected exactly one"
        ),
    }
}

fn read_catalog_text<R: BlobStoreGet>(
    reader: &R,
    handle: NameHandle,
    field: &str,
    id: Id,
) -> Result<String> {
    let value: anybytes::View<str> = reader
        .get(handle)
        .map_err(|error| anyhow!("read Files {field} for {id:x}: {error:?}"))?;
    Ok(value.to_string())
}

fn decode_point_imported_at(value: ImportTime, owner: &str, id: Id) -> Result<Epoch> {
    let (start, end): (Epoch, Epoch) = value
        .try_from_inline()
        .map_err(|error| anyhow!("decode Files {owner} imported_at for {id:x}: {error:?}"))?;
    if start != end {
        anyhow::bail!("Files {owner} {id:x} has a non-point imported_at interval");
    }
    Ok(start)
}

fn entities_with_attributes(facts: &TribleSet, attributes: &[Id]) -> BTreeSet<Id> {
    facts
        .iter()
        .filter(|fact| attributes.contains(fact.a()))
        .map(|fact| *fact.e())
        .collect()
}

fn validate_directory_acyclic(
    id: Id,
    directories: &BTreeMap<Id, DirectoryRecord>,
    visiting: &mut BTreeSet<Id>,
    visited: &mut BTreeSet<Id>,
) -> Result<()> {
    if visited.contains(&id) {
        return Ok(());
    }
    if !visiting.insert(id) {
        anyhow::bail!("Files directory graph contains a cycle through {id:x}");
    }
    let directory = directories
        .get(&id)
        .expect("cycle walk starts from a directory");
    for child in &directory.children {
        if directories.contains_key(child) {
            validate_directory_acyclic(*child, directories, visiting, visited)?;
        }
    }
    visiting.remove(&id);
    visited.insert(id);
    Ok(())
}

/// Strictly read every payload whose encoding is known to Files.
///
/// Structural validation lives in [`load_catalog`]; this narrower function is
/// also used while replaying stopped legacy commits, where preserving an exact
/// authored delta must happen before the union-level structure can be checked.
pub fn validate_known_payloads<R: BlobStoreGet>(reader: &R, facts: &TribleSet) -> Result<()> {
    for fact in facts {
        if fact.a() == &file::content.id() {
            let handle = *fact.v::<Handle<RawBytes>>();
            let _: anybytes::Bytes = reader.get(handle).map_err(|error| {
                anyhow!(
                    "strictly read file content {}: {error:?}",
                    hex::encode(handle.raw)
                )
            })?;
        } else if fact.a() == &file::name.id()
            || fact.a() == &file::source_path.id()
            || fact.a() == &metadata::name.id()
            || fact.a() == &metadata::description.id()
        {
            let handle = *fact.v::<Handle<UTF8String>>();
            let _: anybytes::View<str> = reader.get(handle).map_err(|error| {
                anyhow!(
                    "strictly read Files text {}: {error:?}",
                    hex::encode(handle.raw)
                )
            })?;
        } else if fact.a() == &file::embedding.id() {
            let handle = *fact.v::<Handle<Embedding>>();
            let _: anybytes::View<[f32]> = reader.get(handle).map_err(|error| {
                anyhow!(
                    "strictly read Files CLIP embedding {}: {error:?}",
                    hex::encode(handle.raw)
                )
            })?;
        } else if fact.a() == &embeddings::attr::embedding.id() {
            let handle = *fact.v::<Handle<embeddings::Embedding768>>();
            let _: anybytes::View<[f32]> = reader.get(handle).map_err(|error| {
                anyhow!(
                    "strictly read Files 768-d embedding {}: {error:?}",
                    hex::encode(handle.raw)
                )
            })?;
        } else if fact.a() == &embeddings::attr_mm7b::embedding.id() {
            let handle = *fact.v::<Handle<embeddings::Embedding3584>>();
            let _: anybytes::View<[f32]> = reader.get(handle).map_err(|error| {
                anyhow!(
                    "strictly read Files 3584-d embedding {}: {error:?}",
                    hex::encode(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

/// Project and validate one complete canonical Files collection value.
///
/// Every scalar used by a reader is checked for exact cardinality before any
/// record is returned. Imports cannot be partial, conflicting file names or
/// content cannot acquire an implicit winner, and directory extraction cannot
/// overwrite one same-named child with another.
pub fn load_catalog<R: BlobStoreGet>(reader: &R, facts: &TribleSet) -> Result<FilesCatalog> {
    validate_known_payloads(reader, facts)?;

    let file_ids = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_FILE }])
    )
    .collect::<BTreeSet<_>>();
    let directory_ids = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_DIRECTORY }])
    )
    .collect::<BTreeSet<_>>();
    let import_ids = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_IMPORT }])
    )
    .collect::<BTreeSet<_>>();

    for id in file_ids
        .intersection(&directory_ids)
        .chain(file_ids.intersection(&import_ids))
        .chain(directory_ids.intersection(&import_ids))
    {
        anyhow::bail!("Files entity {id:x} carries competing file/directory/import kinds");
    }

    let file_candidates =
        entities_with_attributes(facts, &[file::content.id(), file::media_type.id()]);
    if let Some(id) = file_candidates.difference(&file_ids).next() {
        anyhow::bail!("Files entity {id:x} carries file fields without KIND_FILE");
    }
    let directory_candidates = entities_with_attributes(facts, &[file::children.id()]);
    if let Some(id) = directory_candidates.difference(&directory_ids).next() {
        anyhow::bail!("Files entity {id:x} carries directory children without KIND_DIRECTORY");
    }
    let root_candidates = entities_with_attributes(facts, &[file::root.id()]);
    if let Some(id) = root_candidates.difference(&import_ids).next() {
        anyhow::bail!("Files entity {id:x} carries an import root without KIND_IMPORT");
    }
    let provenance_candidates =
        entities_with_attributes(facts, &[file::imported_at.id(), file::source_path.id()]);
    let provenance_owners = file_ids
        .union(&import_ids)
        .copied()
        .collect::<BTreeSet<_>>();
    if let Some(id) = provenance_candidates.difference(&provenance_owners).next() {
        anyhow::bail!(
            "Files entity {id:x} carries source_path/imported_at provenance without KIND_FILE or KIND_IMPORT"
        );
    }
    // Historical producers attached path/time provenance directly to some
    // file ids. It remains set-valued and outside canonical file identity,
    // but every timestamp still has to be a decodable point interval.
    for fact in facts
        .iter()
        .filter(|fact| fact.a() == &file::imported_at.id() && file_ids.contains(fact.e()))
    {
        decode_point_imported_at(*fact.v::<NsTAIInterval>(), "file", *fact.e())?;
    }
    let named_candidates = entities_with_attributes(facts, &[file::name.id()]);
    let named_nodes = file_ids
        .union(&directory_ids)
        .copied()
        .collect::<BTreeSet<_>>();
    if let Some(id) = named_candidates.difference(&named_nodes).next() {
        anyhow::bail!("Files entity {id:x} carries a file name without a file or directory kind");
    }

    let media_type_ids = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_MEDIA_TYPE }])
    )
    .collect::<BTreeSet<_>>();
    let mut media_type_names = BTreeMap::new();
    for &id in &media_type_ids {
        let handle = required_catalog_value(
            find!(
                name: NameHandle,
                pattern!(facts, [{ id @ metadata::name: ?name }])
            )
            .collect(),
            "media-type name",
            id,
        )?;
        let name = read_catalog_text(reader, handle, "media-type name", id)?;
        let normalized = normalize_media_type(&name)?;
        if normalized != name {
            anyhow::bail!("Files media-type entity {id:x} stores non-normalized name {name:?}");
        }
        media_type_names.insert(id, name);
    }

    let mut files = BTreeMap::new();
    for &id in &file_ids {
        let name_handle = required_catalog_value(
            find!(
                name: NameHandle,
                pattern!(facts, [{ id @ file::name: ?name }])
            )
            .collect(),
            "file name",
            id,
        )?;
        let content = required_catalog_value(
            find!(
                content: ContentHandle,
                pattern!(facts, [{ id @ file::content: ?content }])
            )
            .collect(),
            "file content",
            id,
        )?;
        let media_type = required_catalog_value(
            find!(
                media_type: Id,
                pattern!(facts, [{ id @ file::media_type: ?media_type }])
            )
            .collect(),
            "file media type",
            id,
        )?;
        if !media_type_names.contains_key(&media_type) {
            anyhow::bail!("Files file {id:x} points at unknown media type {media_type:x}");
        }
        files.insert(
            id,
            FileRecord {
                id,
                name: read_catalog_text(reader, name_handle, "file name", id)?,
                content,
                media_type,
            },
        );
    }

    let mut directories = BTreeMap::new();
    for &id in &directory_ids {
        let name_handle = required_catalog_value(
            find!(
                name: NameHandle,
                pattern!(facts, [{ id @ file::name: ?name }])
            )
            .collect(),
            "directory name",
            id,
        )?;
        let children = find!(
            child: Id,
            pattern!(facts, [{ id @ file::children: ?child }])
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
        directories.insert(
            id,
            DirectoryRecord {
                id,
                name: read_catalog_text(reader, name_handle, "directory name", id)?,
                children,
            },
        );
    }

    for directory in directories.values() {
        let mut child_names = BTreeMap::<&str, Id>::new();
        for child in &directory.children {
            let name = if let Some(file) = files.get(child) {
                file.name.as_str()
            } else if let Some(child_directory) = directories.get(child) {
                child_directory.name.as_str()
            } else {
                anyhow::bail!(
                    "Files directory {:x} names unknown child {child:x}",
                    directory.id
                );
            };
            if let Some(previous) = child_names.insert(name, *child) {
                anyhow::bail!(
                    "Files directory {:x} has same-named children {previous:x} and {child:x} ({name:?})",
                    directory.id
                );
            }
        }
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for id in directories.keys().copied() {
        validate_directory_acyclic(id, &directories, &mut visiting, &mut visited)?;
    }

    let mut imports = BTreeMap::new();
    for &id in &import_ids {
        let imported_at = required_catalog_value(
            find!(
                value: ImportTime,
                pattern!(facts, [{ id @ file::imported_at: ?value }])
            )
            .collect(),
            "imported_at",
            id,
        )?;
        let imported_at = decode_point_imported_at(imported_at, "import", id)?;
        let source_path = required_catalog_value(
            find!(
                value: NameHandle,
                pattern!(facts, [{ id @ file::source_path: ?value }])
            )
            .collect(),
            "source_path",
            id,
        )?;
        let root = required_catalog_value(
            find!(
                value: Id,
                pattern!(facts, [{ id @ file::root: ?value }])
            )
            .collect(),
            "root",
            id,
        )?;
        if !files.contains_key(&root) && !directories.contains_key(&root) {
            anyhow::bail!("Files import {id:x} points at unknown root {root:x}");
        }
        let tags = find!(
            value: Inline<ShortString>,
            pattern!(facts, [{ id @ file::tag: ?value }])
        )
        .map(|value| {
            String::try_from_inline(&value)
                .map_err(|error| anyhow!("decode Files tag for {id:x}: {error:?}"))
        })
        .collect::<Result<BTreeSet<_>>>()?
        .into_iter()
        .collect();
        imports.insert(
            id,
            ImportRecord {
                id,
                imported_at,
                source_path: read_catalog_text(reader, source_path, "source_path", id)?,
                root,
                tags,
            },
        );
    }

    Ok(FilesCatalog {
        files,
        directories,
        imports,
    })
}

/// Validate one complete Files value without retaining its projection.
pub fn validate_catalog<R: BlobStoreGet>(reader: &R, facts: &TribleSet) -> Result<()> {
    load_catalog(reader, facts).map(drop)
}

/// Construct the canonical intrinsic entity for one normalized IANA media
/// type. Other faculties use this when describing bytes which are not Files
/// records while still sharing Files' media-type vocabulary.
pub fn media_type_fragment(media_type: &str) -> Result<Fragment> {
    let media_type = normalize_media_type(media_type)?;
    let mut fragment = Fragment::empty();
    let name = fragment.put::<UTF8String, _>(media_type);
    fragment += entity! {
        metadata::tag: &KIND_MEDIA_TYPE,
        metadata::name: name,
    };
    Ok(fragment)
}

/// Build one self-contained canonical file fragment.
///
/// `name` is a leaf name supplied by the caller, not a filesystem path. The
/// returned [`Fragment`] owns the content, name, and media-type-name blobs, so
/// callers can safely compose it into a larger fragment and publish that one
/// ownership unit through the native collection API.
pub fn stage<T>(bytes: T, name: impl Into<String>, media_type: &str) -> Result<Fragment>
where
    T: triblespace::core::blob::IntoBlob<RawBytes>,
{
    let media_type = normalize_media_type(media_type)?;
    let mut fragment = Fragment::empty();
    let content = fragment.put::<RawBytes, _>(bytes);
    let name = fragment.put::<UTF8String, _>(leaf_name(&name.into()));
    let media_type_name = fragment.put::<UTF8String, _>(media_type);
    let media_type = entity! {
        metadata::tag: &KIND_MEDIA_TYPE,
        metadata::name: media_type_name,
    };

    // Spreading the child fragment consumes its exported id into the relation
    // while folding its facts into the returned fragment. The file remains the
    // fragment's sole exported root.
    fragment += entity! {
        metadata::tag: &KIND_FILE,
        file::content: content,
        file::name: name,
        file::media_type*: media_type,
    };
    Ok(fragment)
}

/// Materialize the complete WRITE-authorized Files collection through an already
/// open pile.
///
/// Opening the scope introduces no second pile handle or lifecycle policy.
/// The returned immutable reader is the same coherent snapshot which admitted
/// the materialized facts.
pub fn materialize_collection(
    pile: &mut Pile,
    signer: &SigningKey,
) -> Result<(TribleSet, PileReader)> {
    let collection = open_scope(pile, crate::schemas::files::DEFAULT_SCOPE_ID, signer)?;
    let (facts, _, reader) = pile
        .snapshot(collection, &[])
        .map_err(|error| anyhow!("materialize Files collection: {error}"))?
        .into_parts();
    Ok((facts, reader))
}

/// Publish one complete Files fragment through an already open pile.
///
/// This is the Files-first boundary used by attachment producers. The signed
/// record is appended before this returns; the caller retains ownership of the
/// pile's flush/close boundary.
pub fn commit_collection(
    pile: &mut Pile,
    signer: &SigningKey,
    fragment: Fragment,
) -> Result<CollectionCommit> {
    let collection = open_scope(pile, crate::schemas::files::DEFAULT_SCOPE_ID, signer)?;
    pile.commit(collection, signer, fragment)
        .map_err(|error| anyhow!("commit Files collection fragment: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use triblespace::core::collection::CollectionStoreExt;
    use triblespace::core::repo::memoryrepo::MemoryRepo;
    use triblespace::core::repo::{BlobStore, BlobStoreGet};

    fn content_of(fragment: &Fragment) -> ContentHandle {
        find!(
            (content: ContentHandle),
            pattern!(fragment, [{ _?file @ file::content: ?content }])
        )
        .next()
        .expect("file content")
        .0
    }

    fn media_type_of(fragment: &Fragment) -> Id {
        find!(
            (media_type: Id),
            pattern!(fragment, [{ _?file @ file::media_type: ?media_type }])
        )
        .next()
        .expect("file media type")
        .0
    }

    fn facts_of(fragments: impl IntoIterator<Item = Fragment>) -> TribleSet {
        let mut facts = TribleSet::new();
        for fragment in fragments {
            facts += fragment;
        }
        facts
    }

    fn imported_file_fragment(path: &str) -> (Fragment, Id, Id) {
        let mut fragment = stage(b"imported bytes".to_vec(), "report.txt", "text/plain").unwrap();
        let root = fragment.root().unwrap();
        let source_path = fragment.put::<UTF8String, _>(path.to_owned());
        let instant = Epoch::from_tai_seconds(42.0);
        let imported_at: ImportTime = (instant, instant).try_to_inline().unwrap();
        let import = entity! {
            metadata::tag: &KIND_IMPORT,
            file::root: &root,
            file::imported_at: imported_at,
            file::source_path: source_path,
        };
        let import_id = import.root().unwrap();
        fragment += import;
        (fragment, root, import_id)
    }

    #[test]
    fn catalog_projects_complete_imports_without_scalar_arbitration() {
        let (fragment, root, import_id) = imported_file_fragment("/tmp/report.txt");
        let mut blobs = fragment.blobs().clone();
        let reader = blobs.reader().unwrap();
        let catalog = load_catalog(&reader, fragment.facts()).unwrap();
        let import = catalog.import(import_id).unwrap();

        assert_eq!(import.root, root);
        assert_eq!(import.source_path, "/tmp/report.txt");
        assert_eq!(catalog.files().len(), 1);
        assert_eq!(catalog.imports().len(), 1);
    }

    #[test]
    fn catalog_preserves_set_valued_legacy_file_provenance() {
        let mut fragment = stage(b"legacy bytes".to_vec(), "legacy.txt", "text/plain").unwrap();
        let file_id = fragment.root().unwrap();
        let first_path = fragment.put::<UTF8String, _>("mail:first".to_owned());
        let second_path = fragment.put::<UTF8String, _>("mail:second".to_owned());
        let first_time = Epoch::from_tai_seconds(41.0);
        let first_time: ImportTime = (first_time, first_time).try_to_inline().unwrap();
        let second_time = Epoch::from_tai_seconds(42.0);
        let second_time: ImportTime = (second_time, second_time).try_to_inline().unwrap();
        fragment += entity! { ExclusiveId::force_ref(&file_id) @
            file::source_path: first_path,
            file::imported_at: first_time,
        };
        fragment += entity! { ExclusiveId::force_ref(&file_id) @
            file::source_path: second_path,
            file::imported_at: second_time,
        };
        let mut blobs = fragment.blobs().clone();
        let reader = blobs.reader().unwrap();

        let catalog = load_catalog(&reader, fragment.facts()).unwrap();

        assert!(catalog.file(file_id).is_some());
        assert_eq!(catalog.files().len(), 1);
        assert_eq!(catalog.imports().len(), 0);
    }

    #[test]
    fn catalog_rejects_non_point_file_provenance_timestamps() {
        let mut fragment = stage(b"legacy bytes".to_vec(), "legacy.txt", "text/plain").unwrap();
        let file_id = fragment.root().unwrap();
        let start = Epoch::from_tai_seconds(41.0);
        let end = Epoch::from_tai_seconds(42.0);
        let interval: ImportTime = (start, end).try_to_inline().unwrap();
        fragment += entity! { ExclusiveId::force_ref(&file_id) @ file::imported_at: interval };
        let mut blobs = fragment.blobs().clone();
        let reader = blobs.reader().unwrap();

        let error = load_catalog(&reader, fragment.facts()).unwrap_err();

        assert!(format!("{error:#}").contains("non-point imported_at interval"));
    }

    #[test]
    fn catalog_rejects_provenance_or_roots_on_untyped_entities() {
        let mut with_path = stage(b"typed".to_vec(), "typed.txt", "text/plain").unwrap();
        let unknown = Id::new([0x53; 16]).unwrap();
        let path = with_path.put::<UTF8String, _>("unknown:path".to_owned());
        with_path += entity! { ExclusiveId::force_ref(&unknown) @ file::source_path: path };
        let mut blobs = with_path.blobs().clone();
        let reader = blobs.reader().unwrap();
        let error = load_catalog(&reader, with_path.facts()).unwrap_err();
        assert!(format!("{error:#}")
            .contains("source_path/imported_at provenance without KIND_FILE or KIND_IMPORT"));

        let mut with_time = stage(b"typed".to_vec(), "typed.txt", "text/plain").unwrap();
        let instant = Epoch::from_tai_seconds(43.0);
        let instant: ImportTime = (instant, instant).try_to_inline().unwrap();
        with_time += entity! { ExclusiveId::force_ref(&unknown) @ file::imported_at: instant };
        let mut blobs = with_time.blobs().clone();
        let reader = blobs.reader().unwrap();
        let error = load_catalog(&reader, with_time.facts()).unwrap_err();
        assert!(format!("{error:#}")
            .contains("source_path/imported_at provenance without KIND_FILE or KIND_IMPORT"));

        let mut with_root = stage(b"typed".to_vec(), "typed.txt", "text/plain").unwrap();
        let root = with_root.root().unwrap();
        with_root += entity! { ExclusiveId::force_ref(&unknown) @ file::root: &root };
        let mut blobs = with_root.blobs().clone();
        let reader = blobs.reader().unwrap();
        let error = load_catalog(&reader, with_root.facts()).unwrap_err();
        assert!(format!("{error:#}").contains("import root without KIND_IMPORT"));
    }

    #[test]
    fn catalog_rejects_partial_and_conflicting_imports() {
        let (mut conflicting, _, import_id) = imported_file_fragment("/tmp/report.txt");
        let alternate = Epoch::from_tai_seconds(43.0);
        let alternate: ImportTime = (alternate, alternate).try_to_inline().unwrap();
        conflicting +=
            entity! { ExclusiveId::force_ref(&import_id) @ file::imported_at: alternate };
        let mut blobs = conflicting.blobs().clone();
        let reader = blobs.reader().unwrap();
        let error = load_catalog(&reader, conflicting.facts()).unwrap_err();
        assert!(format!("{error:#}").contains("2 values for imported_at"));

        let (mut conflicting, _, import_id) = imported_file_fragment("/tmp/report.txt");
        let alternate = conflicting.put::<UTF8String, _>("/tmp/alternate.txt".to_owned());
        conflicting +=
            entity! { ExclusiveId::force_ref(&import_id) @ file::source_path: alternate };
        let mut blobs = conflicting.blobs().clone();
        let reader = blobs.reader().unwrap();
        let error = load_catalog(&reader, conflicting.facts()).unwrap_err();
        assert!(format!("{error:#}").contains("2 values for source_path"));

        let (mut conflicting, _, import_id) = imported_file_fragment("/tmp/report.txt");
        let alternate_root = Id::new([0x51; 16]).unwrap();
        conflicting += entity! { ExclusiveId::force_ref(&import_id) @ file::root: &alternate_root };
        let mut blobs = conflicting.blobs().clone();
        let reader = blobs.reader().unwrap();
        let error = load_catalog(&reader, conflicting.facts()).unwrap_err();
        assert!(format!("{error:#}").contains("2 values for root"));

        let file = stage(b"partial bytes".to_vec(), "partial.txt", "text/plain").unwrap();
        let root = file.root().unwrap();
        let partial_id = Id::new([0x52; 16]).unwrap();
        let mut partial = file;
        partial += entity! { ExclusiveId::force_ref(&partial_id) @
            metadata::tag: &KIND_IMPORT,
            file::root: &root,
        };
        let mut blobs = partial.blobs().clone();
        let reader = blobs.reader().unwrap();
        let error = load_catalog(&reader, partial.facts()).unwrap_err();
        assert!(format!("{error:#}").contains("0 values for imported_at"));
    }

    #[test]
    fn catalog_rejects_competing_file_name_and_content() {
        let mut fragment = stage(b"named".to_vec(), "record.txt", "text/plain").unwrap();
        let file_id = fragment.root().unwrap();
        let competing = fragment.put::<UTF8String, _>("alternate.txt".to_owned());
        fragment += entity! { ExclusiveId::force_ref(&file_id) @ file::name: competing };
        let mut blobs = fragment.blobs().clone();
        let reader = blobs.reader().unwrap();
        let error = load_catalog(&reader, fragment.facts()).unwrap_err();
        assert!(format!("{error:#}").contains("2 values for file name"));

        let mut fragment = stage(b"first".to_vec(), "record.txt", "text/plain").unwrap();
        let file_id = fragment.root().unwrap();
        let competing = fragment.put::<RawBytes, _>(b"second".to_vec());
        fragment += entity! { ExclusiveId::force_ref(&file_id) @ file::content: competing };
        let mut blobs = fragment.blobs().clone();
        let reader = blobs.reader().unwrap();

        let error = load_catalog(&reader, fragment.facts()).unwrap_err();
        assert!(format!("{error:#}").contains("2 values for file content"));
    }

    #[test]
    fn shared_content_keeps_all_names_and_has_no_name_winner() {
        let first = stage(b"shared".to_vec(), "alpha.txt", "text/plain").unwrap();
        let content = content_of(&first);
        let second = stage(b"shared".to_vec(), "beta.txt", "text/plain").unwrap();
        let mut fragment = first;
        fragment += second;
        let mut blobs = fragment.blobs().clone();
        let reader = blobs.reader().unwrap();
        let catalog = load_catalog(&reader, fragment.facts()).unwrap();

        let resolved = catalog.resolve_file(&content_hash_hex(content)).unwrap();
        assert_eq!(resolved.names, ["alpha.txt", "beta.txt"]);
        assert_eq!(resolved.unique_name(), None);
    }

    #[test]
    fn complete_entity_ids_are_direct_and_case_insensitive() {
        let expected = Id::from_hex("abcdef0123456789abcdef0123456789").unwrap();
        assert_eq!(
            resolve_selector(&TribleSet::new(), "files:ABCDEF0123456789ABCDEF0123456789").unwrap(),
            expected
        );
        assert_eq!(
            resolve_reference(&TribleSet::new(), "files:ABCDEF0123456789ABCDEF0123456789").unwrap(),
            FileReference::Entity(expected)
        );
    }

    #[test]
    fn entity_and_content_prefixes_resolve_without_a_minimum_length() {
        let file = stage(b"selector bytes".to_vec(), "selector.txt", "text/plain").unwrap();
        let file_id = file.root().unwrap();
        let content = content_of(&file);
        let hash = content_hash_hex(content);
        let facts = facts_of([file]);
        let id_hex = format!("{file_id:x}");
        assert_eq!(hash, hash.to_ascii_lowercase());

        assert_eq!(
            resolve_selector(&facts, &id_hex[..1].to_ascii_uppercase()).unwrap(),
            file_id
        );
        assert_eq!(
            resolve_selector(&facts, &id_hex[..12].to_ascii_uppercase()).unwrap(),
            file_id
        );
        assert_eq!(
            resolve_selector(
                &facts,
                &format!("files:{}", hash[..20].to_ascii_uppercase())
            )
            .unwrap(),
            file_id
        );
        assert_eq!(
            resolve_selector(&facts, &hash.to_ascii_uppercase()).unwrap(),
            file_id
        );

        let id_reference_prefix = (1..32)
            .map(|len| &id_hex[..len])
            .find(|prefix| {
                resolve_reference(&facts, prefix).ok() == Some(FileReference::Entity(file_id))
            })
            .expect("entity reference has an unambiguous prefix");
        assert_eq!(
            resolve_reference(&facts, &id_reference_prefix.to_ascii_uppercase()).unwrap(),
            FileReference::Entity(file_id)
        );
        assert_eq!(
            resolve_reference(&facts, &hash[..40].to_ascii_uppercase()).unwrap(),
            FileReference::Content(content)
        );
    }

    #[test]
    fn duplicate_content_is_ambiguous_by_entity_even_for_a_complete_hash() {
        let first = stage(b"shared bytes".to_vec(), "first.txt", "text/plain").unwrap();
        let second = stage(b"shared bytes".to_vec(), "second.txt", "text/plain").unwrap();
        let content = content_of(&first);
        let hash = content_hash_hex(content);
        let mut expected = vec![first.root().unwrap(), second.root().unwrap()];
        expected.sort();
        let facts = facts_of([first, second]);

        let message = resolve_selector(&facts, &hash).unwrap_err().to_string();
        assert!(message.contains("ambiguous"));
        for candidate in expected {
            assert!(message.contains(&format!("{candidate:x}")));
        }

        assert_eq!(
            resolve_reference(&facts, &hash).unwrap(),
            FileReference::Content(content)
        );
        assert_eq!(
            resolve_reference(&facts, &hash[..40]).unwrap(),
            FileReference::Content(content)
        );
        assert_eq!(
            resolve_reference(&TribleSet::new(), &hash).unwrap(),
            FileReference::Content(content)
        );
    }

    #[test]
    fn directory_and_import_ids_are_prefix_eligible() {
        let directory_id = *fucid();
        let import_id = *fucid();
        let directory = entity! { ExclusiveId::force_ref(&directory_id) @
            metadata::tag: &KIND_DIRECTORY,
        };
        let import = entity! { ExclusiveId::force_ref(&import_id) @
            metadata::tag: &KIND_IMPORT,
        };

        let directory_facts = facts_of([directory]);
        let directory_hex = format!("{directory_id:x}");
        assert_eq!(
            resolve_selector(&directory_facts, &directory_hex[..1]).unwrap(),
            directory_id
        );

        let import_facts = facts_of([import]);
        let import_hex = format!("{import_id:x}");
        assert_eq!(
            resolve_selector(&import_facts, &import_hex[..1]).unwrap(),
            import_id
        );
    }

    #[test]
    fn identical_file_records_have_identical_intrinsic_ids() {
        let left = stage(b"same bytes".to_vec(), "report.txt", "text/plain").unwrap();
        let right = stage(b"same bytes".to_vec(), "report.txt", "text/plain").unwrap();

        assert_eq!(left.root(), right.root());
        assert_eq!(left, right);
    }

    #[test]
    fn name_and_media_type_are_identity_but_bytes_still_deduplicate() {
        let text = stage(b"same bytes".to_vec(), "report.txt", "text/plain").unwrap();
        let renamed = stage(b"same bytes".to_vec(), "renamed.txt", "text/plain").unwrap();
        let retyped = stage(
            b"same bytes".to_vec(),
            "report.txt",
            "application/octet-stream",
        )
        .unwrap();

        assert_ne!(text.root(), renamed.root());
        assert_ne!(text.root(), retyped.root());
        assert_eq!(content_of(&text), content_of(&renamed));
        assert_eq!(content_of(&text), content_of(&retyped));
        assert_eq!(media_type_of(&text), media_type_of(&renamed));
        assert_ne!(media_type_of(&text), media_type_of(&retyped));
    }

    #[test]
    fn containing_paths_never_enter_file_identity() {
        let unix = stage(
            b"same bytes".to_vec(),
            "/tmp/archive/report.txt",
            "text/plain",
        )
        .unwrap();
        let windows = stage(
            b"same bytes".to_vec(),
            r"C:\archive\report.txt",
            "text/plain",
        )
        .unwrap();
        let bare = stage(b"same bytes".to_vec(), "report.txt", "text/plain").unwrap();

        assert_eq!(unix.root(), bare.root());
        assert_eq!(windows.root(), bare.root());
    }

    #[test]
    fn invalid_media_type_is_reported_instead_of_panicking() {
        let error = stage(
            Vec::<u8>::new(),
            "document.bin",
            "application/invalid\0mime",
        )
        .unwrap_err();
        assert!(error.to_string().contains("invalid file media type"));
    }

    #[test]
    fn media_type_normalization_is_lossless_and_deterministic() {
        assert_eq!(normalize_media_type("text/plain").unwrap(), "text/plain");
        assert_eq!(
            normalize_media_type(" TEXT/PLAIN; charset=UTF-8").unwrap(),
            "text/plain"
        );
        let vendor = "application/vnd.openxmlformats-officedocument.presentationml.presentation";
        assert_eq!(normalize_media_type(vendor).unwrap(), vendor);
        assert_eq!(
            normalize_media_type_or_default("not a media type"),
            DEFAULT_MEDIA_TYPE
        );
    }

    #[test]
    fn media_type_inference_is_case_insensitive_and_shared() {
        assert_eq!(infer_media_type(Path::new("README.MD")), "text/markdown");
        assert_eq!(
            infer_media_type(Path::new("deck.PPTX")),
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        );
        assert_eq!(infer_media_type(Path::new("unknown")), DEFAULT_MEDIA_TYPE);
    }

    #[test]
    fn normalized_variants_converge_and_long_suffixes_remain_identity() {
        let plain = stage(b"same bytes".to_vec(), "document.bin", "text/plain").unwrap();
        let decorated = stage(
            b"same bytes".to_vec(),
            "document.bin",
            " TEXT/PLAIN; charset=UTF-8",
        )
        .unwrap();
        assert_eq!(plain.root(), decorated.root());
        assert_eq!(media_type_of(&plain), media_type_of(&decorated));

        let document = stage(
            b"same bytes".to_vec(),
            "document.bin",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        .unwrap();
        let sheet = stage(
            b"same bytes".to_vec(),
            "document.bin",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        .unwrap();
        assert_ne!(document.root(), sheet.root());
        assert_ne!(media_type_of(&document), media_type_of(&sheet));
    }

    #[test]
    fn staged_fragment_owns_content_name_and_joinable_media_type_name() {
        let file = stage(
            b"slides".to_vec(),
            "deck.pptx",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        )
        .unwrap();
        let file_id = file.root().expect("file root");
        let content = content_of(&file);
        let file_name = find!(
            name: NameHandle,
            pattern!(&file, [{ file_id @ file::name: ?name }])
        )
        .next()
        .expect("file name");
        let media_type_id = find!(
            (media_type: Id),
            pattern!(&file, [{ file_id @ file::media_type: ?media_type }])
        )
        .next()
        .expect("media type relation")
        .0;

        assert!(exists!(
            (name: NameHandle),
            pattern!(&file, [{ media_type_id @ metadata::tag: &KIND_MEDIA_TYPE, metadata::name: ?name }])
        ));
        let name_handle = media_type_name_handle(&file, file_id).expect("media type name");
        assert_eq!(
            Some(name_handle),
            find!(
                (name: NameHandle),
                pattern!(&file, [{ media_type_id @ metadata::name: ?name }])
            )
            .next()
            .map(|(name,)| name)
        );
        let mut blobs = file.blobs().clone();
        let reader = blobs.reader().expect("fragment blob reader");
        let name: anybytes::View<str> = reader
            .get::<anybytes::View<str>, UTF8String>(name_handle)
            .expect("staged media type name");
        assert_eq!(
            name.as_ref(),
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        );
        let content: anybytes::Bytes = reader.get(content).expect("staged content");
        assert_eq!(content.as_ref(), b"slides");
        let file_name: anybytes::View<str> = reader.get(file_name).expect("staged name");
        assert_eq!(file_name.as_ref(), "deck.pptx");
    }

    #[test]
    fn complete_fragment_survives_native_collection_commit_and_materialization() {
        let signer = SigningKey::generate(&mut OsRng);
        let mut store = MemoryRepo::default();
        let collection = store
            .collection(crate::collection_names::root_descriptor(
                crate::schemas::files::DEFAULT_SCOPE_ID,
                signer.verifying_key(),
            ))
            .unwrap();
        let file = stage(
            b"slides".to_vec(),
            "deck.pptx",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        )
        .unwrap();
        let file_id = file.root().expect("file root");

        // The Fragment is the ownership unit: collapsing it into a TribleSet
        // would discard its attachment store before commit can persist the
        // closure.
        store
            .commit(collection, &signer, file)
            .expect("commit canonical file");
        let (catalog, _, reader) = store
            .snapshot(collection, &[])
            .expect("materialize files")
            .into_parts();
        let content_handle = find!(
            content: ContentHandle,
            pattern!(&catalog, [{ file_id @ file::content: ?content }])
        )
        .next()
        .expect("persisted content handle");
        let file_name_handle = find!(
            name: NameHandle,
            pattern!(&catalog, [{ file_id @ file::name: ?name }])
        )
        .next()
        .expect("persisted file name handle");
        let name_handle = media_type_name_handle(&catalog, file_id).expect("canonical media type");
        let name: anybytes::View<str> = reader
            .get::<anybytes::View<str>, UTF8String>(name_handle)
            .expect("persisted media type name");
        assert_eq!(
            name.as_ref(),
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        );
        let content: anybytes::Bytes = reader.get(content_handle).expect("persisted content");
        assert_eq!(content.as_ref(), b"slides");
        let file_name: anybytes::View<str> =
            reader.get(file_name_handle).expect("persisted file name");
        assert_eq!(file_name.as_ref(), "deck.pptx");
    }
}
