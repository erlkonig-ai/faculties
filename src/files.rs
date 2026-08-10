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

use anyhow::{anyhow, Result};
use std::collections::BTreeSet;
use std::path::Path;
use triblespace::core::metadata;
use triblespace::prelude::blobencodings::{LongString, RawBytes};
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;

use crate::schemas::files::{file, KIND_DIRECTORY, KIND_FILE, KIND_IMPORT, KIND_MEDIA_TYPE};

pub type ContentHandle = Inline<Handle<RawBytes>>;
pub type NameHandle = Inline<Handle<LongString>>;
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

/// Build one self-contained canonical file fragment.
///
/// `name` is a leaf name supplied by the caller, not a filesystem path. The
/// returned [`Fragment`] owns the content, name, and media-type-name blobs, so
/// callers can safely compose it into a larger fragment and publish that one
/// ownership unit through either the native collection API or a legacy
/// [`Workspace`](triblespace::core::repo::Workspace).
pub fn stage<T>(bytes: T, name: impl Into<String>, media_type: &str) -> Result<Fragment>
where
    T: triblespace::core::blob::IntoBlob<RawBytes>,
{
    let media_type = normalize_media_type(media_type)?;
    let mut fragment = Fragment::empty();
    let content = fragment.put::<RawBytes, _>(bytes);
    let name = fragment.put::<LongString, _>(leaf_name(&name.into()));
    let media_type_name = fragment.put::<LongString, _>(media_type);
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use triblespace::core::repo::memoryrepo::MemoryRepo;
    use triblespace::core::repo::{BlobStore, BlobStoreGet, Repository};

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
            .get::<anybytes::View<str>, LongString>(name_handle)
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
    fn complete_fragment_survives_legacy_workspace_commit_and_checkout() {
        let mut repo = Repository::new(
            MemoryRepo::default(),
            SigningKey::generate(&mut OsRng),
            TribleSet::new(),
        )
        .expect("repository");
        let branch = *repo.create_branch("files", None).expect("branch");
        let mut workspace = repo.pull(branch).expect("workspace");
        let file = stage(
            b"slides".to_vec(),
            "deck.pptx",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        )
        .unwrap();
        let file_id = file.root().expect("file root");

        // Legacy Repository callers must preserve the returned Fragment as the
        // ownership unit: collapsing it into a TribleSet would discard its
        // attachment store before Workspace::commit can persist the closure.
        workspace.commit(file, "store canonical file");
        repo.push(&mut workspace).expect("push");

        let mut reopened = repo.pull(branch).expect("reopen");
        let catalog = reopened.checkout(..).expect("checkout").into_facts();
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
        let name: anybytes::View<str> = reopened
            .get::<anybytes::View<str>, LongString>(name_handle)
            .expect("persisted media type name");
        assert_eq!(
            name.as_ref(),
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        );
        let content: anybytes::Bytes = reopened.get(content_handle).expect("persisted content");
        assert_eq!(content.as_ref(), b"slides");
        let file_name: anybytes::View<str> =
            reopened.get(file_name_handle).expect("persisted file name");
        assert_eq!(file_name.as_ref(), "deck.pptx");
    }
}
