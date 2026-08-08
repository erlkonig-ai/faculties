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
//! provenance are deliberately not accepted here. Callers attach those facts
//! to imports or source-specific occurrence entities instead.

use anyhow::{anyhow, bail, Context, Result};
use std::collections::BTreeSet;
use std::path::Path;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::blobencodings::{LongString, RawBytes};
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;
use triblespace_search::schemas::Embedding;

use crate::schemas::embeddings;
use crate::schemas::files::{
    file, page, KIND_DIRECTORY, KIND_FILE, KIND_IMPORT, KIND_MEDIA_TYPE, KIND_PAGE,
};

pub type ContentHandle = Inline<Handle<RawBytes>>;
pub type NameHandle = Inline<Handle<LongString>>;
pub type EmbeddingHandle = Inline<Handle<Embedding>>;
pub type Mm7bHandle = Inline<Handle<embeddings::Embedding3584>>;
pub const DEFAULT_MEDIA_TYPE: &str = "application/octet-stream";

// Historical schema ids are intentionally private to the canonical-catalog
// gate. Exact-copying either attribute into the collection would preserve an
// obsolete identity projection and permanently poison the union. The existing
// `canonical-file-media-types` migration (commit 93643ef) must rewrite those
// lineages before collection publication.
const LEGACY_FILE_MIME_ATTRIBUTE: Id = id_hex!("BFE2C88ECD13D56F80967C343FC072EE");
const LEGACY_IMPORTED_AT_ATTRIBUTE: Id = id_hex!("EA8B5429A86AF26D2B87F169AFEE3919");

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
    media_type_name_handle_strict(space, file_id).ok().flatten()
}

/// Strict variant of [`media_type_name_handle`].
///
/// A file may name exactly one media-type entity and that entity may carry
/// exactly one canonical name. Ambiguity is corruption, not an arbitrary
/// iterator-order choice.
pub fn media_type_name_handle_strict(space: &TribleSet, file_id: Id) -> Result<Option<NameHandle>> {
    let values: BTreeSet<(Id, NameHandle)> = find!(
        (media_type: Id, name: NameHandle),
        pattern!(space, [
            { file_id @ file::media_type: ?media_type },
            { ?media_type @ metadata::tag: &KIND_MEDIA_TYPE, metadata::name: ?name }
        ])
    )
    .collect();
    one(values, "file media type").map(|value| value.map(|(_, name)| name))
}

fn file_record(content: ContentHandle, name: NameHandle, media_type_name: NameHandle) -> Fragment {
    let media_type = entity! {
        metadata::tag: &KIND_MEDIA_TYPE,
        metadata::name: media_type_name,
    };

    // Spreading the child fragment consumes its exported id into the relation
    // while folding its facts into the returned fragment. The file remains the
    // fragment's sole exported root.
    entity! {
        metadata::tag: &KIND_FILE,
        file::content: content,
        file::name: name,
        file::media_type*: media_type,
    }
}

/// Construct one self-contained canonical file fragment.
///
/// This is the collection-native constructor: the returned [`Fragment`] owns
/// every referenced blob and can be published directly as part of a signed
/// collection COMMIT. File identity remains exactly kind + content + leaf name
/// + intrinsic media-type entity; no source path, containing directory, clock,
/// tag, or embedding participates.
pub fn fragment<T>(bytes: T, name: impl Into<String>, media_type: &str) -> Result<Fragment>
where
    T: triblespace::core::blob::IntoBlob<RawBytes>,
{
    let media_type = normalize_media_type(media_type)?;
    let mut fragment = Fragment::empty();
    let content = fragment.put::<RawBytes, _>(bytes);
    let name = fragment.put::<LongString, _>(leaf_name(&name.into()));
    let media_type_name = fragment.put::<LongString, _>(media_type);
    fragment += file_record(content, name, media_type_name);
    Ok(fragment)
}

/// The result of wrapping one immutable file/directory tree in an import
/// occurrence. `root_id` identifies the path-independent Merkle value;
/// `import_id` identifies this source-path/time observation.
#[derive(Debug)]
pub struct ImportedTree {
    pub fragment: Fragment,
    pub root_id: Id,
    pub import_id: Id,
}

/// Construct an intrinsic directory value from its leaf name and child roots.
///
/// `children` is spread into the directory so all descendant facts and blobs
/// remain self-contained. Child order and duplicates are ignored by `entity!`;
/// empty directories remain valid values carrying just kind + name.
pub fn directory_fragment(name: impl Into<String>, children: Fragment) -> Fragment {
    entity! {
        metadata::tag: &KIND_DIRECTORY,
        file::name: leaf_name(&name.into()),
        file::children*: children,
    }
}

/// Wrap one immutable tree in an immutable import-occurrence record.
///
/// The import identity is derived from root, source path, and import time.
/// Tags are additive annotations on that identity and deliberately do not
/// affect it. The source path belongs only to the import; it never leaks into
/// file or directory identities.
pub fn import_fragment(
    tree: Fragment,
    source_path: impl Into<String>,
    imported_at: Inline<inlineencodings::NsTAIInterval>,
    tags: impl IntoIterator<Item = String>,
) -> Result<ImportedTree> {
    let root_id = tree
        .root()
        .ok_or_else(|| anyhow!("file tree must export exactly one root"))?;
    let import = entity! {
        metadata::tag: &KIND_IMPORT,
        file::root: &root_id,
        file::imported_at: imported_at,
        file::source_path: source_path.into(),
    };
    let import_id = import
        .root()
        .ok_or_else(|| anyhow!("import record must export exactly one root"))?;
    let mut fragment = tree;
    fragment += import;
    for tag in tags {
        fragment += entity! { ExclusiveId::force_ref(&import_id) @ file::tag: tag };
    }
    Ok(ImportedTree {
        fragment,
        root_id,
        import_id,
    })
}

/// Stable identity of one rasterized page within a file.
///
/// The embedding is deliberately exhaust: identity is only parent file +
/// 1-based page label. A different model/recipe must therefore use a distinct
/// derived collection rather than append a second value to this record.
pub fn page_id(parent: Id, index: &str) -> Id {
    entity! { _ @
        page::parent: parent,
        page::index: index,
    }
    .root()
    .expect("page identity fields derive one root")
}

/// Construct one self-contained page record with its canonical 3584-d vector.
pub fn page_fragment(parent: Id, index: impl Into<String>, vector: Vec<f32>) -> Fragment {
    let index = index.into();
    let id = page_id(parent, &index);
    let mut fragment = Fragment::empty();
    let embedding: Mm7bHandle = fragment.put::<embeddings::Embedding3584, _>(vector);
    fragment += entity! { ExclusiveId::force_ref(&id) @
        metadata::tag: &KIND_PAGE,
        page::parent: parent,
        page::index: index,
        embeddings::attr_mm7b::embedding: embedding,
    };
    fragment
}

/// The mutually exclusive canonical record kinds understood by Files.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileEntityKind {
    File,
    Directory,
    Import,
    Page,
    MediaType,
}

fn one<T: Ord>(mut values: BTreeSet<T>, field: &str) -> Result<Option<T>> {
    match values.len() {
        0 => Ok(None),
        1 => Ok(values.pop_first()),
        count => bail!("{field} is ambiguous ({count} distinct values)"),
    }
}

fn one_required<T: Ord>(values: BTreeSet<T>, field: &str) -> Result<T> {
    one(values, field)?.ok_or_else(|| anyhow!("missing {field}"))
}

/// Classify a Files entity without relying on query iteration order.
pub fn entity_kind(space: &TribleSet, id: Id) -> Result<Option<FileEntityKind>> {
    let candidates = [
        (KIND_FILE, FileEntityKind::File),
        (KIND_DIRECTORY, FileEntityKind::Directory),
        (KIND_IMPORT, FileEntityKind::Import),
        (KIND_PAGE, FileEntityKind::Page),
        (KIND_MEDIA_TYPE, FileEntityKind::MediaType),
    ];
    let kinds: Vec<_> = candidates
        .into_iter()
        .filter_map(|(tag, kind)| {
            exists!(pattern!(space, [{ id @ metadata::tag: &tag }])).then_some(kind)
        })
        .collect();
    match kinds.as_slice() {
        [] => Ok(None),
        [kind] => Ok(Some(*kind)),
        _ => bail!("files entity {id:x} has multiple canonical kinds"),
    }
}

pub fn content_handle(space: &TribleSet, id: Id) -> Result<Option<ContentHandle>> {
    one(
        find!(
            content: ContentHandle,
            pattern!(space, [{ id @ file::content: ?content }])
        )
        .collect(),
        "file content",
    )
}

pub fn name_handle(space: &TribleSet, id: Id) -> Result<Option<NameHandle>> {
    one(
        find!(
            name: NameHandle,
            pattern!(space, [{ id @ file::name: ?name }])
        )
        .collect(),
        "file name",
    )
}

pub fn import_root(space: &TribleSet, id: Id) -> Result<Option<Id>> {
    one(
        find!(root: Id, pattern!(space, [{ id @ file::root: ?root }])).collect(),
        "import root",
    )
}

pub fn imported_at(
    space: &TribleSet,
    id: Id,
) -> Result<Option<Inline<inlineencodings::NsTAIInterval>>> {
    one(
        find!(
            imported_at: Inline<inlineencodings::NsTAIInterval>,
            pattern!(space, [{ id @ file::imported_at: ?imported_at }])
        )
        .collect(),
        "imported-at time",
    )
}

pub fn source_path_handle(space: &TribleSet, id: Id) -> Result<Option<NameHandle>> {
    one(
        find!(
            source: NameHandle,
            pattern!(space, [{ id @ file::source_path: ?source }])
        )
        .collect(),
        "import source path",
    )
}

pub fn embedding_handle(space: &TribleSet, id: Id) -> Result<Option<EmbeddingHandle>> {
    one(
        find!(
            embedding: EmbeddingHandle,
            pattern!(space, [{ id @ file::embedding: ?embedding }])
        )
        .collect(),
        "file CLIP embedding",
    )
}

pub fn mm7b_embedding_handle(space: &TribleSet, id: Id) -> Result<Option<Mm7bHandle>> {
    one(
        find!(
            embedding: Mm7bHandle,
            pattern!(space, [{ id @ embeddings::attr_mm7b::embedding: ?embedding }])
        )
        .collect(),
        "Files 3584-d embedding",
    )
}

pub fn children(space: &TribleSet, id: Id) -> Vec<Id> {
    find!(child: Id, pattern!(space, [{ id @ file::children: ?child }]))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn tags(space: &TribleSet, id: Id) -> Vec<String> {
    find!(tag: String, pattern!(space, [{ id @ file::tag: ?tag }]))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn page_origin(space: &TribleSet, id: Id) -> Result<Option<(Id, String)>> {
    one(
        find!(
            (parent: Id, index: String),
            pattern!(space, [{ id @ metadata::tag: &KIND_PAGE, page::parent: ?parent, page::index: ?index }])
        )
        .collect(),
        "page origin",
    )
}

fn read_long_string<B: BlobStoreGet>(blobs: &B, handle: NameHandle, field: &str) -> Result<String> {
    let value: anybytes::View<str> = blobs
        .get(handle)
        .with_context(|| format!("read {field} blob {}", content_hash_hex_raw(handle.raw)))?;
    Ok(value.as_ref().to_owned())
}

fn content_hash_hex_raw(raw: [u8; 32]) -> String {
    hex::encode(raw)
}

pub fn read_name<B: BlobStoreGet>(space: &TribleSet, blobs: &B, id: Id) -> Result<Option<String>> {
    name_handle(space, id)?
        .map(|handle| read_long_string(blobs, handle, "file name"))
        .transpose()
}

pub fn read_media_type<B: BlobStoreGet>(
    space: &TribleSet,
    blobs: &B,
    id: Id,
) -> Result<Option<String>> {
    media_type_name_handle_strict(space, id)?
        .map(|handle| read_long_string(blobs, handle, "media type name"))
        .transpose()
}

pub fn read_source_path<B: BlobStoreGet>(
    space: &TribleSet,
    blobs: &B,
    id: Id,
) -> Result<Option<String>> {
    source_path_handle(space, id)?
        .map(|handle| read_long_string(blobs, handle, "import source path"))
        .transpose()
}

/// Strictly read every directly named Files payload in `facts`.
///
/// The generic collection walker retains resident closure conservatively, but
/// migration must additionally prove that every schema-known direct handle is
/// present and decodes under its declared encoding before publication begins.
pub fn validate_known_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts {
        if fact.a() == &file::content.id() {
            let handle = *fact.v::<Handle<RawBytes>>();
            let _: anybytes::Bytes = reader.get(handle).with_context(|| {
                format!(
                    "strictly read file content payload {}",
                    hex::encode(handle.raw)
                )
            })?;
        } else if fact.a() == &file::name.id()
            || fact.a() == &file::source_path.id()
            || fact.a() == &metadata::name.id()
            || fact.a() == &metadata::description.id()
        {
            let handle = *fact.v::<Handle<LongString>>();
            let _: anybytes::View<str> = reader.get(handle).with_context(|| {
                format!(
                    "strictly read Files text payload {}",
                    hex::encode(handle.raw)
                )
            })?;
        } else if fact.a() == &file::embedding.id() {
            let handle = *fact.v::<Handle<Embedding>>();
            let _: anybytes::View<[f32]> = reader.get(handle).with_context(|| {
                format!(
                    "strictly read Files CLIP embedding {}",
                    hex::encode(handle.raw)
                )
            })?;
        } else if fact.a() == &embeddings::attr::embedding.id() {
            let handle = *fact.v::<Handle<embeddings::Embedding768>>();
            let _: anybytes::View<[f32]> = reader.get(handle).with_context(|| {
                format!(
                    "strictly read Files 768-d embedding {}",
                    hex::encode(handle.raw)
                )
            })?;
        } else if fact.a() == &embeddings::attr_mm7b::embedding.id() {
            let handle = *fact.v::<Handle<embeddings::Embedding3584>>();
            let _: anybytes::View<[f32]> = reader.get(handle).with_context(|| {
                format!(
                    "strictly read Files 3584-d embedding {}",
                    hex::encode(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

/// Validate the complete materialized Files catalog and every attachment.
///
/// Files records are immutable value objects plus additive annotations. Every
/// field that the CLI treats as singular is required to be exactly one here;
/// no command is allowed to select an arbitrary witness with `.next()`.
pub fn validate_catalog(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    validate_known_payloads(reader, facts)?;

    if facts.iter().any(|fact| {
        fact.a() == &LEGACY_FILE_MIME_ATTRIBUTE || fact.a() == &LEGACY_IMPORTED_AT_ATTRIBUTE
    }) {
        bail!(
            "Files catalog contains the historical inline-MIME/import-time schema; refusing an exact-copy collection migration. Run the canonical-file-media-types lineage rewrite before publishing this catalog"
        );
    }

    let files: BTreeSet<Id> = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_FILE }])
    )
    .collect();
    let directories: BTreeSet<Id> = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_DIRECTORY }])
    )
    .collect();
    let imports: BTreeSet<Id> = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_IMPORT }])
    )
    .collect();
    let pages: BTreeSet<Id> = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_PAGE }])
    )
    .collect();
    let media_types: BTreeSet<Id> = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &KIND_MEDIA_TYPE }])
    )
    .collect();

    for id in files
        .iter()
        .chain(&directories)
        .chain(&imports)
        .chain(&pages)
    {
        entity_kind(facts, *id)?;
    }

    for id in &media_types {
        entity_kind(facts, *id)?;
        let name = one_required(
            find!(
                name: NameHandle,
                pattern!(facts, [{ *id @ metadata::name: ?name }])
            )
            .collect(),
            "media type name",
        )?;
        let expected = entity! {
            metadata::tag: &KIND_MEDIA_TYPE,
            metadata::name: name,
        }
        .root()
        .expect("media type intrinsic core has one root");
        if expected != *id {
            bail!("media type {id:x} does not match its intrinsic core {expected:x}");
        }
    }

    for id in &files {
        let content = one_required(
            find!(
                content: ContentHandle,
                pattern!(facts, [{ *id @ file::content: ?content }])
            )
            .collect(),
            "file content",
        )?;
        let name = one_required(
            find!(
                name: NameHandle,
                pattern!(facts, [{ *id @ file::name: ?name }])
            )
            .collect(),
            "file name",
        )?;
        let media_type = one_required(
            find!(
                media_type: Id,
                pattern!(facts, [{ *id @ file::media_type: ?media_type }])
            )
            .collect(),
            "file media type",
        )?;
        if !media_types.contains(&media_type) {
            bail!("file {id:x} points to non-media-type entity {media_type:x}");
        }
        let expected = entity! {
            metadata::tag: &KIND_FILE,
            file::content: content,
            file::name: name,
            file::media_type: &media_type,
        }
        .root()
        .expect("file intrinsic core has one root");
        if expected != *id {
            bail!("file {id:x} does not match its intrinsic core {expected:x}");
        }
        one(
            find!(
                embedding: EmbeddingHandle,
                pattern!(facts, [{ *id @ file::embedding: ?embedding }])
            )
            .collect(),
            "file CLIP embedding",
        )?;
        one(
            find!(
                embedding: Mm7bHandle,
                pattern!(facts, [{ *id @ embeddings::attr_mm7b::embedding: ?embedding }])
            )
            .collect(),
            "file 3584-d embedding",
        )?;
    }

    for id in &directories {
        let name = one_required(
            find!(
                name: NameHandle,
                pattern!(facts, [{ *id @ file::name: ?name }])
            )
            .collect(),
            "directory name",
        )?;
        let children = children(facts, *id);
        for child in &children {
            if !files.contains(child) && !directories.contains(child) {
                bail!("directory {id:x} has non-tree child {child:x}");
            }
        }
        let expected = entity! {
            metadata::tag: &KIND_DIRECTORY,
            file::name: name,
            file::children*: children.iter(),
        }
        .root()
        .expect("directory intrinsic core has one root");
        if expected != *id {
            bail!("directory {id:x} does not match its intrinsic core {expected:x}");
        }
    }

    for id in &imports {
        let root = one_required(
            find!(root: Id, pattern!(facts, [{ *id @ file::root: ?root }])).collect(),
            "import root",
        )?;
        if !files.contains(&root) && !directories.contains(&root) {
            bail!("import {id:x} has non-tree root {root:x}");
        }
        let imported_at = one_required(
            find!(
                imported_at: Inline<inlineencodings::NsTAIInterval>,
                pattern!(facts, [{ *id @ file::imported_at: ?imported_at }])
            )
            .collect(),
            "imported-at time",
        )?;
        let source = one_required(
            find!(
                source: NameHandle,
                pattern!(facts, [{ *id @ file::source_path: ?source }])
            )
            .collect(),
            "import source path",
        )?;
        let expected = entity! {
            metadata::tag: &KIND_IMPORT,
            file::root: &root,
            file::imported_at: imported_at,
            file::source_path: source,
        }
        .root()
        .expect("import intrinsic core has one root");
        if expected != *id {
            bail!("import {id:x} does not match its intrinsic core {expected:x}");
        }
    }

    for id in &pages {
        let parent = one_required(
            find!(parent: Id, pattern!(facts, [{ *id @ page::parent: ?parent }])).collect(),
            "page parent",
        )?;
        if !files.contains(&parent) {
            bail!("page {id:x} has non-file parent {parent:x}");
        }
        let index = one_required(
            find!(
                index: String,
                pattern!(facts, [{ *id @ page::index: ?index }])
            )
            .collect(),
            "page index",
        )?;
        let expected = page_id(parent, &index);
        if expected != *id {
            bail!("page {id:x} does not match its intrinsic core {expected:x}");
        }
        one_required(
            find!(
                embedding: Mm7bHandle,
                pattern!(facts, [{ *id @ embeddings::attr_mm7b::embedding: ?embedding }])
            )
            .collect(),
            "page 3584-d embedding",
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use triblespace::core::repo::memoryrepo::MemoryRepo;
    use triblespace::core::repo::{BlobStore, Repository};

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
        let file = fragment(b"selector bytes".to_vec(), "selector.txt", "text/plain").unwrap();
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
        let first = fragment(b"shared bytes".to_vec(), "first.txt", "text/plain").unwrap();
        let second = fragment(b"shared bytes".to_vec(), "second.txt", "text/plain").unwrap();
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
        let left = fragment(b"same bytes".to_vec(), "report.txt", "text/plain").unwrap();
        let right = fragment(b"same bytes".to_vec(), "report.txt", "text/plain").unwrap();

        assert_eq!(left.root(), right.root());
        assert_eq!(left, right);
    }

    #[test]
    fn name_and_media_type_are_identity_but_bytes_still_deduplicate() {
        let text = fragment(b"same bytes".to_vec(), "report.txt", "text/plain").unwrap();
        let renamed = fragment(b"same bytes".to_vec(), "renamed.txt", "text/plain").unwrap();
        let retyped = fragment(
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
        let unix = fragment(
            b"same bytes".to_vec(),
            "/tmp/archive/report.txt",
            "text/plain",
        )
        .unwrap();
        let windows = fragment(
            b"same bytes".to_vec(),
            r"C:\archive\report.txt",
            "text/plain",
        )
        .unwrap();
        let bare = fragment(b"same bytes".to_vec(), "report.txt", "text/plain").unwrap();

        assert_eq!(unix.root(), bare.root());
        assert_eq!(windows.root(), bare.root());
    }

    #[test]
    fn directories_are_path_independent_merkle_values_including_empty_ones() {
        let first = fragment(b"first".to_vec(), "/tmp/one/first.txt", "text/plain").unwrap();
        let second = fragment(b"second".to_vec(), r"C:\two\second.txt", "text/plain").unwrap();

        let forward = directory_fragment("/snapshot/root", first.clone() + second.clone());
        let reverse = directory_fragment("root", second.clone() + first.clone());
        assert_eq!(forward.root(), reverse.root());
        assert_eq!(forward, reverse);

        let changed_child = fragment(b"changed".to_vec(), "second.txt", "text/plain").unwrap();
        let changed = directory_fragment("root", first + changed_child);
        assert_ne!(forward.root(), changed.root());

        let empty = directory_fragment("empty", Fragment::empty());
        assert!(matches!(
            entity_kind(empty.facts(), empty.root().unwrap()).unwrap(),
            Some(FileEntityKind::Directory)
        ));
        assert!(children(empty.facts(), empty.root().unwrap()).is_empty());
    }

    #[test]
    fn imports_are_occurrence_snapshots_while_tags_are_annotations() {
        let tree = fragment(b"snapshot".to_vec(), "snapshot.txt", "text/plain").unwrap();
        let instant = hifitime::Epoch::from_unix_seconds(10.0);
        let at: Inline<inlineencodings::NsTAIInterval> =
            (instant, instant).try_to_inline().unwrap();
        let first =
            import_fragment(tree.clone(), "/one/snapshot.txt", at, ["alpha".to_owned()]).unwrap();
        let retagged =
            import_fragment(tree.clone(), "/one/snapshot.txt", at, ["beta".to_owned()]).unwrap();
        let moved = import_fragment(tree, "/two/snapshot.txt", at, Vec::new()).unwrap();

        assert_eq!(first.root_id, retagged.root_id);
        assert_eq!(first.import_id, retagged.import_id);
        assert_ne!(first.fragment, retagged.fragment);
        assert_ne!(first.import_id, moved.import_id);
    }

    #[test]
    fn page_identity_excludes_embedding_exhaust() {
        let parent = Id::new([0x44; 16]).unwrap();
        let first = page_fragment(parent, "1", vec![0.0; embeddings::DIM_3584]);
        let second = page_fragment(parent, "1", vec![1.0; embeddings::DIM_3584]);
        assert_eq!(first.root(), second.root());
        assert_ne!(first, second);
    }

    #[test]
    fn invalid_media_type_is_reported_instead_of_panicking() {
        let error = fragment(
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
        let plain = fragment(b"same bytes".to_vec(), "document.bin", "text/plain").unwrap();
        let decorated = fragment(
            b"same bytes".to_vec(),
            "document.bin",
            " TEXT/PLAIN; charset=UTF-8",
        )
        .unwrap();
        assert_eq!(plain.root(), decorated.root());
        assert_eq!(media_type_of(&plain), media_type_of(&decorated));

        let document = fragment(
            b"same bytes".to_vec(),
            "document.bin",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        .unwrap();
        let sheet = fragment(
            b"same bytes".to_vec(),
            "document.bin",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        .unwrap();
        assert_ne!(document.root(), sheet.root());
        assert_ne!(media_type_of(&document), media_type_of(&sheet));
    }

    #[test]
    fn media_type_is_a_joinable_intrinsic_entity() {
        let mut file = fragment(
            b"slides".to_vec(),
            "deck.pptx",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        )
        .unwrap();
        let file_id = file.root().expect("file root");
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
        let reader = file
            .blobs_mut()
            .reader()
            .expect("fragment blob reader creation is infallible");
        let name: anybytes::View<str> = reader
            .get::<anybytes::View<str>, LongString>(name_handle)
            .expect("fragment-local media type name");
        assert_eq!(
            name.as_ref(),
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        );
    }

    #[test]
    fn media_type_name_survives_fragment_commit_and_checkout() {
        let mut repo = Repository::new(
            MemoryRepo::default(),
            SigningKey::generate(&mut OsRng),
            TribleSet::new(),
        )
        .expect("repository");
        let branch = *repo.create_branch("files", None).expect("branch");
        let mut workspace = repo.pull(branch).expect("workspace");
        let file = fragment(
            b"slides".to_vec(),
            "deck.pptx",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        )
        .unwrap();
        let file_id = file.root().expect("file root");

        // Workspace::commit absorbs a Fragment's self-contained blobs. There
        // is no separate workspace-staging constructor or compatibility path.
        workspace.commit(file, "store canonical file");
        repo.push(&mut workspace).expect("push");

        let mut reopened = repo.pull(branch).expect("reopen");
        let catalog = reopened.checkout(..).expect("checkout").into_facts();
        let name_handle = media_type_name_handle(&catalog, file_id).expect("canonical media type");
        let name: anybytes::View<str> = reopened
            .get::<anybytes::View<str>, LongString>(name_handle)
            .expect("persisted media type name");
        assert_eq!(
            name.as_ref(),
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        );
    }
}
