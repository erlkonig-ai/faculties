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
use std::path::Path;
use triblespace::core::metadata;
use triblespace::core::repo::{BlobStore, Workspace};
use triblespace::prelude::blobencodings::{LongString, RawBytes};
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;

use crate::schemas::files::{file, KIND_FILE, KIND_MEDIA_TYPE};

pub type ContentHandle = Inline<Handle<RawBytes>>;
pub type NameHandle = Inline<Handle<LongString>>;
pub const DEFAULT_MEDIA_TYPE: &str = "application/octet-stream";

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

/// Stage a file's blobs in `workspace` and return its canonical fragment.
///
/// `name` is a leaf name supplied by the caller, not a filesystem path. The
/// workspace remains responsible for commit composition and push ordering, so
/// faculties can include this fragment in larger cross-branch operations.
pub fn stage<Blobs, T>(
    workspace: &mut Workspace<Blobs>,
    bytes: T,
    name: impl Into<String>,
    media_type: &str,
) -> Result<Fragment>
where
    Blobs: BlobStore,
    T: triblespace::core::blob::IntoBlob<RawBytes>,
{
    // Validate before mutating the workspace. `stage_content_handle` repeats
    // normalization deliberately so both public entry points retain the same
    // strict contract when called independently.
    let media_type = normalize_media_type(media_type)?;
    let content = workspace.put::<RawBytes, _>(bytes);
    stage_content_handle(workspace, content, name, &media_type)
}

/// Stage a canonical file record around content already present in the pile.
///
/// This is the migration/import counterpart to [`stage`]: the raw bytes remain
/// addressed by the same handle, while the leaf name and media-type entity are
/// canonicalized through the exact same constructor. It intentionally accepts
/// no provenance or source path, because those are not part of file identity.
pub fn stage_content_handle<Blobs>(
    workspace: &mut Workspace<Blobs>,
    content: ContentHandle,
    name: impl Into<String>,
    media_type: &str,
) -> Result<Fragment>
where
    Blobs: BlobStore,
{
    let media_type = normalize_media_type(media_type)?;
    let name = workspace.put::<LongString, _>(leaf_name(&name.into()));
    let media_type_name = workspace.put::<LongString, _>(media_type);
    let media_type = entity! {
        metadata::tag: &KIND_MEDIA_TYPE,
        metadata::name: media_type_name,
    };

    // Spreading the child fragment consumes its exported id into the relation
    // while folding its facts into the returned fragment. The file remains the
    // fragment's sole exported root.
    Ok(entity! {
        metadata::tag: &KIND_FILE,
        file::content: content,
        file::name: name,
        file::media_type*: media_type,
    })
}

/// Build a self-contained canonical file fragment around an existing content
/// handle without writing to a workspace.
///
/// The returned fragment carries the newly addressed leaf-name and media-type
/// name blobs. This is the dry-run-safe constructor for migrations: committing
/// the fragment later absorbs those blobs into the destination workspace.
pub fn fragment_content_handle(
    content: ContentHandle,
    name: impl Into<String>,
    media_type: &str,
) -> Result<Fragment> {
    let media_type = normalize_media_type(media_type)?;
    let mut result = Fragment::empty();
    let name = result.put::<LongString, _>(leaf_name(&name.into()));
    let media_type_name = result.put::<LongString, _>(media_type);
    let media_type = entity! {
        metadata::tag: &KIND_MEDIA_TYPE,
        metadata::name: media_type_name,
    };
    result += entity! {
        metadata::tag: &KIND_FILE,
        file::content: content,
        file::name: name,
        file::media_type*: media_type,
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use triblespace::core::repo::memoryrepo::MemoryRepo;
    use triblespace::core::repo::Repository;

    fn workspace() -> Workspace<MemoryRepo> {
        let mut repo = Repository::new(
            MemoryRepo::default(),
            SigningKey::generate(&mut OsRng),
            TribleSet::new(),
        )
        .expect("repository");
        let branch = repo.create_branch("files", None).expect("branch");
        repo.pull(*branch).expect("workspace")
    }

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

    #[test]
    fn identical_file_records_have_identical_intrinsic_ids() {
        let mut workspace = workspace();
        let left = stage(
            &mut workspace,
            b"same bytes".to_vec(),
            "report.txt",
            "text/plain",
        )
        .unwrap();
        let right = stage(
            &mut workspace,
            b"same bytes".to_vec(),
            "report.txt",
            "text/plain",
        )
        .unwrap();

        assert_eq!(left.root(), right.root());
        assert_eq!(left, right);
    }

    #[test]
    fn existing_content_handle_uses_the_same_canonical_constructor() {
        let mut workspace = workspace();
        let content = workspace.put::<RawBytes, _>(b"same bytes".to_vec());
        let from_handle = stage_content_handle(
            &mut workspace,
            content,
            "nested/report.txt",
            "TEXT/PLAIN; charset=utf-8",
        )
        .unwrap();
        let from_bytes = stage(
            &mut workspace,
            b"same bytes".to_vec(),
            "report.txt",
            "text/plain",
        )
        .unwrap();

        assert_eq!(from_handle, from_bytes);
    }

    #[test]
    fn self_contained_handle_fragment_matches_and_carries_its_blobs() {
        let mut workspace = workspace();
        let content = workspace.put::<RawBytes, _>(b"same bytes".to_vec());
        let self_contained = fragment_content_handle(content, "report.txt", "text/plain").unwrap();
        let staged =
            stage_content_handle(&mut workspace, content, "report.txt", "text/plain").unwrap();

        assert_eq!(self_contained.facts(), staged.facts());
        assert!(!self_contained.blobs().is_empty());
    }

    #[test]
    fn name_and_media_type_are_identity_but_bytes_still_deduplicate() {
        let mut workspace = workspace();
        let text = stage(
            &mut workspace,
            b"same bytes".to_vec(),
            "report.txt",
            "text/plain",
        )
        .unwrap();
        let renamed = stage(
            &mut workspace,
            b"same bytes".to_vec(),
            "renamed.txt",
            "text/plain",
        )
        .unwrap();
        let retyped = stage(
            &mut workspace,
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
        let mut workspace = workspace();
        let unix = stage(
            &mut workspace,
            b"same bytes".to_vec(),
            "/tmp/archive/report.txt",
            "text/plain",
        )
        .unwrap();
        let windows = stage(
            &mut workspace,
            b"same bytes".to_vec(),
            r"C:\archive\report.txt",
            "text/plain",
        )
        .unwrap();
        let bare = stage(
            &mut workspace,
            b"same bytes".to_vec(),
            "report.txt",
            "text/plain",
        )
        .unwrap();

        assert_eq!(unix.root(), bare.root());
        assert_eq!(windows.root(), bare.root());
    }

    #[test]
    fn invalid_media_type_is_reported_instead_of_panicking() {
        let mut workspace = workspace();
        let error = stage(
            &mut workspace,
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
        let mut workspace = workspace();
        let plain = stage(
            &mut workspace,
            b"same bytes".to_vec(),
            "document.bin",
            "text/plain",
        )
        .unwrap();
        let decorated = stage(
            &mut workspace,
            b"same bytes".to_vec(),
            "document.bin",
            " TEXT/PLAIN; charset=UTF-8",
        )
        .unwrap();
        assert_eq!(plain.root(), decorated.root());
        assert_eq!(media_type_of(&plain), media_type_of(&decorated));

        let document = stage(
            &mut workspace,
            b"same bytes".to_vec(),
            "document.bin",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        .unwrap();
        let sheet = stage(
            &mut workspace,
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
        let mut workspace = workspace();
        let file = stage(
            &mut workspace,
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
        let name: anybytes::View<str> = workspace
            .get::<anybytes::View<str>, LongString>(name_handle)
            .expect("staged media type name");
        assert_eq!(
            name.as_ref(),
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        );
    }

    #[test]
    fn media_type_name_survives_tribleset_commit_and_checkout() {
        let mut repo = Repository::new(
            MemoryRepo::default(),
            SigningKey::generate(&mut OsRng),
            TribleSet::new(),
        )
        .expect("repository");
        let branch = *repo.create_branch("files", None).expect("branch");
        let mut workspace = repo.pull(branch).expect("workspace");
        let file = stage(
            &mut workspace,
            b"slides".to_vec(),
            "deck.pptx",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        )
        .unwrap();
        let file_id = file.root().expect("file root");

        // Mail, Teams, and Discord currently accumulate facts in a TribleSet.
        // The constructor therefore stages blobs in the Workspace rather than
        // relying on Fragment-local blob propagation alone.
        let mut facts = TribleSet::new();
        facts += file;
        workspace.commit(facts, "store canonical file");
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
