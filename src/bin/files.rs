use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::collection_access::{self, CollectionSnapshot, CollectionView};
use faculties::files as file_capability;
use faculties::schemas::embeddings;
use faculties::schemas::files::{
    file, DEFAULT_SCOPE_ID, FILES_BRANCH_NAME, KIND_FILE, KIND_IMPORT,
};
use hifitime::efmt::consts::ISO8601_DATE;
use hifitime::efmt::Formatter;
use hifitime::Epoch;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::prelude::*;
use triblespace_search::schemas::Embedding;

// ── type aliases ─────────────────────────────────────────────────────────
type FileHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;
type EmbHandle = Inline<inlineencodings::Handle<Embedding>>;
/// Handle into the nomic-embed-multimodal-7b dense space (3584-d). A distinct
/// type from `EmbHandle` (CLIP-512) so the two spaces index independently and
/// can never collide in one HNSW.
type Mm7bHandle = Inline<inlineencodings::Handle<embeddings::Embedding3584>>;

// ── CLI ──────────────────────────────────────────────────────────────────
#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, name = "files", about = "Content-addressed file storage in a TribleSpace pile")]
struct Cli {
    /// Path to the pile file
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it;
    /// initialize explicitly with `trible pile signing-key init <pile>`.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Extrinsic Files collection scope. Defaults to the stable scope declared
    /// by this faculty.
    #[arg(long, value_parser = parse_id_arg)]
    scope: Option<Id>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Import a file or directory into the pile
    Add {
        /// Path to a file or directory
        path: PathBuf,
        /// Override MIME type (single file only)
        #[arg(long)]
        mime: Option<String>,
        /// Add tags to the import (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Preview what would be imported without committing
        #[arg(long)]
        dry_run: bool,
    },
    /// List all imported files
    List {
        /// Filter by tag
        #[arg(long)]
        tag: Vec<String>,
        /// Filter by MIME type prefix (e.g. "application/pdf")
        #[arg(long)]
        mime: Option<String>,
    },
    /// Show metadata for a file, directory, or import
    Show {
        /// Entity id/content hash or an unambiguous prefix (optional files: prefix)
        id: String,
    },
    /// Extract a file, directory, or import.
    /// Use @- to write to stdout, or omit for the stored filename.
    Get {
        /// Entity id/content hash or an unambiguous prefix (file, directory, or import)
        id: String,
        /// Output path. Omit to use the stored filename. Use @- for stdout.
        output: Option<String>,
    },
    /// Add a tag to a file
    Tag {
        /// Entity id/content hash or an unambiguous prefix
        id: String,
        /// Tag to add
        name: String,
    },
    /// Fetch a URL and import it as a file
    Fetch {
        /// URL to fetch
        url: String,
        /// Override MIME type
        #[arg(long)]
        mime: Option<String>,
        /// Override filename
        #[arg(long)]
        name: Option<String>,
        /// Add tags to the import (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Maximum response size in bytes (default 8 MiB)
        #[arg(long, default_value_t = 8 * 1024 * 1024)]
        max_bytes: usize,
    },
    /// Search files by name or tag
    Search {
        /// Search query (substring, case-insensitive)
        query: String,
    },
    /// Find files semantically similar to a query — by an embedded image file,
    /// or cross-modally by `--text "a description"` (same CLIP space). `--tag`
    /// makes it a hybrid query: similar AND carrying the tag — the join that
    /// tells "a form of me" from the project mascots.
    Similar {
        /// Entity id/content hash or an unambiguous prefix (omit with --text)
        id: Option<String>,
        /// Text query for cross-modal search (omit when querying by file)
        #[arg(long)]
        text: Option<String>,
        /// Minimum cosine similarity, 0..1. NB image↔image scores run high
        /// (~0.9 for near-dupes) but text↔image run low (~0.2, CLIP's modality
        /// gap), so this low default serves both; raise it to tighten.
        #[arg(long, default_value_t = 0.15)]
        floor: f32,
        /// Maximum results
        #[arg(long, short = 'n', default_value_t = 10)]
        limit: usize,
        /// Only results carrying ALL these tags (repeatable) — the hybrid filter
        #[arg(long)]
        tag: Vec<String>,
        /// Search the nomic-embed-multimodal-7b 3584-d space (run `files
        /// embed-7b` first) instead of the CLIP-512 space. A *separate*,
        /// stronger text→image space — not comparable to the CLIP one.
        #[arg(long)]
        mm7b: bool,
    },
    /// Embed image files (or, with `--pdf`, PDF *pages*) with
    /// nomic-embed-multimodal-7b (3584-d) and store the vector on
    /// `attr_mm7b::embedding`. Idempotent: skips already-embedded files/pages.
    /// The 7b model loads once (~20s cold), then ~0.5-1s per
    /// image. Needs `--features local-embed` and macOS (Metal). This is the
    /// index that powers `files similar --mm7b --text "…"` (text→image recall).
    Embed7b {
        /// Embed `application/pdf` files instead of raster images: rasterize
        /// each page (via `pdftoppm`) and embed it as a separate page entity,
        /// so a hit points to "file X, page N". The big batch — combine with
        /// `--limit`/`--max-pages` for incremental runs over a large corpus.
        #[arg(long)]
        pdf: bool,
        /// (PDF mode) Rasterization resolution in DPI. Lower = faster + smaller.
        #[arg(long, default_value_t = 150)]
        dpi: u32,
        /// (PDF mode) Process at most this many PDF files this run (0 = all).
        #[arg(long, default_value_t = 0)]
        limit: usize,
        /// (PDF mode) Embed at most this many pages per PDF (0 = all pages).
        #[arg(long, default_value_t = 0)]
        max_pages: usize,
    },
    /// Publish an already-canonical signed legacy `files` branch as collection
    /// commits, then verify the exact materialized view. Branches carrying the
    /// historical inline-MIME/import-time schema are rejected before any
    /// append; they require the canonical-file-media-types lineage rewrite.
    /// Stop every legacy Files writer and every collection-native writer using
    /// the same target scope first. The legacy pin is never moved or removed.
    MigrateLegacy {
        /// Exact legacy files branch id. Needed only when duplicate `files`
        /// branch names make name lookup ambiguous.
        #[arg(long, value_parser = parse_id_arg)]
        legacy_branch_id: Option<Id>,
    },
    /// List imports (snapshots)
    Imports,
    /// Show the tree structure of an import or directory
    Tree {
        /// Import/directory entity id or an unambiguous prefix
        id: String,
        /// Maximum depth to display (0 = root only, 1 = immediate children, etc.)
        #[arg(long, short)]
        depth: Option<usize>,
    },
    /// Expand hash/id selectors to canonical reference tokens. Use @path/@- for batch input.
    /// Batch mode outputs `old\tfiles:<full-token>`; failures go to stderr.
    Resolve {
        /// Selector, or @path/@- for batch input (one selector per line)
        input: String,
    },
    /// Compare two imports, directories, or files
    Diff {
        /// Left (older) entity/hash selector
        left: String,
        /// Right (newer) entity/hash selector
        right: String,
    },
}

// ── helpers ──────────────────────────────────────────────────────────────

fn now_tai() -> Inline<inlineencodings::NsTAIInterval> {
    let now = Epoch::now().unwrap_or(Epoch::from_unix_seconds(0.0));
    (now, now).try_to_inline().expect("valid TAI interval")
}

fn interval_key(interval: Inline<inlineencodings::NsTAIInterval>) -> i128 {
    let (lower, _): (Epoch, Epoch) = interval.try_from_inline().expect("valid TAI interval");
    lower.to_tai_duration().total_nanoseconds()
}

fn format_date(tai_ns: i128) -> String {
    const NANOS_PER_CENTURY: i128 = 3_155_760_000_000_000_000;
    let centuries = (tai_ns / NANOS_PER_CENTURY) as i16;
    let nanos = (tai_ns % NANOS_PER_CENTURY) as u64;
    let dur = hifitime::Duration::from_parts(centuries, nanos);
    let epoch = Epoch::from_tai_duration(dur);
    Formatter::new(epoch, ISO8601_DATE).to_string()
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn handle_hex(h: FileHandle) -> String {
    file_capability::content_hash_hex(h)
}

fn human_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1} GiB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MiB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KiB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

// ── query helpers ────────────────────────────────────────────────────────

fn parse_id_arg(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim()).ok_or_else(|| format!("invalid id '{raw}'"))
}

fn read_name(space: &TribleSet, reader: &PileReader, eid: Id) -> Result<Option<String>> {
    file_capability::read_name(space, reader, eid)
}

fn read_mime(space: &TribleSet, reader: &PileReader, eid: Id) -> Result<Option<String>> {
    file_capability::read_media_type(space, reader, eid)
}

/// If `eid` is a rasterized-PDF page entity, return its `(parent file id, page
/// index label)`. Used by the 7b similarity display so a page hit reads back as
/// "file X, page N" instead of a nameless entity.
fn read_page(space: &TribleSet, eid: Id) -> Result<Option<(Id, String)>> {
    file_capability::page_origin(space, eid)
}

fn content_handle_of(space: &TribleSet, eid: Id) -> Result<Option<FileHandle>> {
    file_capability::content_handle(space, eid)
}

fn is_file(space: &TribleSet, id: Id) -> bool {
    exists!(
        (h: FileHandle),
        pattern!(space, [{ id @ metadata::tag: &KIND_FILE, file::content: ?h }])
    )
}

fn is_directory(space: &TribleSet, id: Id) -> bool {
    matches!(
        file_capability::entity_kind(space, id),
        Ok(Some(file_capability::FileEntityKind::Directory))
    )
}

fn is_import(space: &TribleSet, id: Id) -> bool {
    exists!(
        (r: Id),
        pattern!(space, [{ id @ metadata::tag: &KIND_IMPORT, file::root: ?r }])
    )
}

fn children_of(space: &TribleSet, id: Id) -> Vec<Id> {
    file_capability::children(space, id)
}

fn root_of(space: &TribleSet, id: Id) -> Result<Option<Id>> {
    file_capability::import_root(space, id)
}

fn imported_at_of(space: &TribleSet, eid: Id) -> Result<Option<i128>> {
    Ok(file_capability::imported_at(space, eid)?.map(interval_key))
}

fn source_path_of(space: &TribleSet, reader: &PileReader, eid: Id) -> Result<Option<String>> {
    file_capability::read_source_path(space, reader, eid)
}

fn tags_of(space: &TribleSet, eid: Id) -> Vec<String> {
    file_capability::tags(space, eid)
}

// ── repo helpers ─────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct FilesStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
    scope: Id,
}

impl FilesStorage<'_> {
    fn view(&self) -> Result<CollectionView> {
        let signer = collection_access::load_signer(self.pile, self.key)?;
        let allowed = HashSet::from([signer.verifying_key()]);
        let snapshot = CollectionSnapshot::open(self.pile)?;
        let view = snapshot.materialize_scope(self.scope, &allowed)?;
        file_capability::validate_catalog(&view.reader, &view.facts)?;
        Ok(view)
    }

    fn publish(&self, fragment: Fragment, message: &str) -> Result<CollectionCommit> {
        let metadata = entity! { metadata::description: message.to_owned() };
        collection_access::publish_fragment(self.pile, self.key, self.scope, fragment, metadata)
    }
}

// ── tree builder ─────────────────────────────────────────────────────────

struct TreeStats {
    files: usize,
    dirs: usize,
    bytes: u64,
}

/// Build a Merkle tree from a filesystem path, bottom-up.
/// Returns a Fragment whose root is the top-level entity and whose
/// facts contain the entire tree.
fn print_fs_tree(
    path: &Path,
    prefix: &str,
    child_prefix: &str,
    stats: &mut TreeStats,
) -> Result<()> {
    let meta = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or(".");

    if meta.is_file() {
        let size = meta.len();
        stats.bytes += size;
        stats.files += 1;
        let mime = file_capability::infer_media_type(path);
        println!("{prefix}{name}  ({mime}, {})", human_size(size));
    } else if meta.is_dir() {
        stats.dirs += 1;
        let mut dirs: Vec<(String, PathBuf)> = Vec::new();
        let mut files: Vec<(String, PathBuf)> = Vec::new();
        for entry in fs::read_dir(path).with_context(|| format!("read dir {}", path.display()))? {
            let entry = entry?;
            let ename = entry.file_name().to_string_lossy().to_string();
            if ename.starts_with('.') {
                continue;
            }
            if entry.file_type()?.is_dir() {
                dirs.push((ename, entry.path()));
            } else {
                files.push((ename, entry.path()));
            }
        }
        dirs.sort_by(|a, b| a.0.cmp(&b.0));
        files.sort_by(|a, b| a.0.cmp(&b.0));

        println!("{prefix}{name}/");
        let all: Vec<_> = dirs.into_iter().chain(files).collect();
        for (i, (_, child_path)) in all.iter().enumerate() {
            let last = i == all.len() - 1;
            let connector = if last { "└── " } else { "├── " };
            let continuation = if last { "    " } else { "│   " };
            print_fs_tree(
                child_path,
                &format!("{child_prefix}{connector}"),
                &format!("{child_prefix}{continuation}"),
                stats,
            )?;
        }
    }
    Ok(())
}

// ── embedder seam (mary, behind `local-embed`) ────────────────────────────
// A faculties-local trait so the rest of `files` stays feature-independent;
// the only impl is mary's `LocalEmbedder`, gated behind `local-embed`. Without
// the feature there is no way to construct one, so embed-on-add is a no-op.
#[allow(dead_code)] // embed_text is used by `files similar --text` (feature-gated)
trait ImageEmbedder {
    fn embed_image(&self, bytes: &[u8]) -> Result<Vec<f32>>;
    fn embed_text(&self, text: &str) -> Result<Vec<f32>>;
}

#[cfg(feature = "local-embed")]
impl<T: mary::embed::LocalEmbedder> ImageEmbedder for T {
    fn embed_image(&self, bytes: &[u8]) -> Result<Vec<f32>> {
        mary::embed::LocalEmbedder::embed_image(self, bytes)
    }
    fn embed_text(&self, text: &str) -> Result<Vec<f32>> {
        mary::embed::LocalEmbedder::embed_text(self, text)
    }
}

/// Load mary's CLIP-ViT-B v0 (warm; ~1-2s, ~600MB) from its durable pile
/// (write it with mary's `embed_persist`; `CLIP_PILE` overrides the path —
/// tokenizer.json stays a small HF-cache side-file). SigLIP so400m swaps in
/// behind this same trait later.
#[cfg(feature = "local-embed")]
fn load_clip_embedder() -> Result<Box<dyn ImageEmbedder>> {
    const CLIP_MODEL: &str = "openai/clip-vit-base-patch32";
    let pile = match std::env::var_os("CLIP_PILE") {
        Some(p) => PathBuf::from(p),
        None => faculties::model_dir().join("clip.pile"),
    };
    let tok = mary::embed::hf_cache_resolve(CLIP_MODEL, "tokenizer.json")
        .ok_or_else(|| anyhow::anyhow!("tokenizer.json not in HF cache for {CLIP_MODEL}"))?;
    let emb = mary::embed::load_clip_from_pile(&pile, &tok, mary::embed::default_device())?;
    Ok(Box::new(emb))
}

/// Embed an image on `add` and stage it as `file::embedding` exhaust (stored
/// under the file's intrinsic record id, so identity is unaffected). Lazy-loads
/// the embedder on the first image. No-op without `local-embed` or for
/// non-raster mimes (SVG isn't a bitmap CLIP can decode).
#[allow(unused_variables)]
fn embed_image_on_add(
    embedder: &mut Option<Box<dyn ImageEmbedder>>,
    mime: &str,
    bytes: &[u8],
) -> Result<Option<Vec<f32>>> {
    #[cfg(feature = "local-embed")]
    {
        if !mime.starts_with("image/") || mime == "image/svg+xml" {
            return Ok(None);
        }
        if embedder.is_none() {
            eprintln!("files: loading CLIP embedder (once)…");
            *embedder = Some(load_clip_embedder()?);
        }
        return embedder.as_ref().unwrap().embed_image(bytes).map(Some);
    }
    #[cfg(not(feature = "local-embed"))]
    {
        let _ = (embedder, mime, bytes);
        Ok(None)
    }
}

/// Embed a text query into the shared image+text space (for `files similar
/// --text`). Loads the embedder fresh — a one-off query, no warm handle needed.
#[allow(unused_variables)]
fn embed_text_query(text: &str) -> Result<Vec<f32>> {
    #[cfg(feature = "local-embed")]
    {
        let emb = load_clip_embedder()?;
        return emb.embed_text(text);
    }
    #[cfg(not(feature = "local-embed"))]
    bail!("`files similar --text` needs the embedder — rebuild with --features local-embed");
}

// ── nomic-embed-multimodal-7b seam (3584-d dense space) ───────────────────
// A SEPARATE, additive path from the CLIP one above. The 7b model embeds both
// images (`embed_image`, pure-Rust decode→preprocess→vision→backbone) and text
// queries (`embed_query`) into one 3584-d space — strong text→image retrieval.
// Loaded once per command (cold mmap ~20s, then ~0.5-1s/embed). macOS/Metal
// only; gated behind `local-embed`.

#[cfg(all(feature = "local-embed", target_os = "macos"))]
type Mm7bEmbedder =
    mary::models::qwen2_5_vl::embedder::NomicMultimodalEmbedder<mary::nn::backend::B>;

/// Default weights pile + tokenizer for the 7b, overridable via env so the
/// faculty isn't pinned to one machine's paths.
#[cfg(all(feature = "local-embed", target_os = "macos"))]
fn load_mm7b() -> Result<Mm7bEmbedder> {
    const DEFAULT_TOKENIZER: &str = "/Users/jp/.cache/huggingface/hub/models--nomic-ai--nomic-embed-multimodal-7b/snapshots/1291f1b6ca07061b0329df9d5713c09b294be576/tokenizer.json";
    let pile = match std::env::var_os("NOMIC_MM7B_PILE") {
        Some(p) => PathBuf::from(p),
        None => faculties::model_dir().join("nomic_mm7b.pile"),
    };
    let tok =
        std::env::var("NOMIC_MM7B_TOKENIZER").unwrap_or_else(|_| DEFAULT_TOKENIZER.to_string());
    eprintln!("files: loading nomic-embed-multimodal-7b (once, ~20s)…");
    mary::persist::load_nomic_mm7b_aliased_from_pile(
        &pile,
        Path::new(&tok),
        mary::nn::backend::WgpuDevice::default(),
    )
}

/// Embed image bytes into the 3584-d 7b space.
#[allow(unused_variables)]
fn mm7b_embed_image(emb: &Mm7bEmbedderOpt, bytes: &[u8]) -> Result<Vec<f32>> {
    #[cfg(all(feature = "local-embed", target_os = "macos"))]
    {
        return emb.embed_image(bytes);
    }
    #[cfg(not(all(feature = "local-embed", target_os = "macos")))]
    bail!("`files embed-7b` needs the 7b embedder — rebuild with --features local-embed on macOS");
}

/// Embed a text query into the 3584-d 7b space (query-side augmentation).
#[allow(unused_variables)]
fn mm7b_embed_query(emb: &Mm7bEmbedderOpt, text: &str) -> Result<Vec<f32>> {
    #[cfg(all(feature = "local-embed", target_os = "macos"))]
    {
        return emb.embed_query(text);
    }
    #[cfg(not(all(feature = "local-embed", target_os = "macos")))]
    bail!("`files similar --mm7b --text` needs the 7b embedder — rebuild with --features local-embed on macOS");
}

// A tiny alias so the helper signatures above are the same with/without the
// feature: with it, the concrete embedder; without it, the unit type (the
// helpers `bail!` before ever touching the value).
#[cfg(all(feature = "local-embed", target_os = "macos"))]
type Mm7bEmbedderOpt = Mm7bEmbedder;
#[cfg(not(all(feature = "local-embed", target_os = "macos")))]
type Mm7bEmbedderOpt = ();

/// Construct the 7b embedder, or `bail!` cleanly when the feature/platform is
/// absent. Returns the concrete embedder (feature) or `()` (no feature, after a
/// bail — so the call site never proceeds without a real model).
#[allow(unreachable_code)]
fn load_mm7b_opt() -> Result<Mm7bEmbedderOpt> {
    #[cfg(all(feature = "local-embed", target_os = "macos"))]
    {
        return load_mm7b();
    }
    #[cfg(not(all(feature = "local-embed", target_os = "macos")))]
    bail!(
        "the nomic-embed-multimodal-7b path needs `--features local-embed` on macOS (Metal); \
         this build doesn't have it"
    );
}

/// Read a stored 3584-d embedding blob back into a plain `Vec<f32>`.
fn read_embedding_3584(reader: &PileReader, h: Mm7bHandle) -> Result<Vec<f32>> {
    let v: anybytes::View<[f32]> = reader
        .get(h)
        .map_err(|e| anyhow::anyhow!("read 7b embedding blob: {e:?}"))?;
    Ok(v.as_ref().to_vec())
}

fn build_tree(
    path: &Path,
    mime_override: Option<&str>,
    stats: &mut TreeStats,
    embedder: &mut Option<Box<dyn ImageEmbedder>>,
) -> Result<Fragment> {
    let meta = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;

    if meta.is_file() {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        stats.bytes += bytes.len() as u64;
        let mime = mime_override.unwrap_or_else(|| file_capability::infer_media_type(path));
        // Embed BEFORE the bytes are moved into the blob store.
        let embedding = embed_image_on_add(embedder, mime, &bytes)?;
        let name_str = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unnamed");

        stats.files += 1;
        let mut frag = file_capability::fragment(bytes, name_str, mime)?;
        if let Some(embedding) = embedding {
            // Exhaust: stored under the intrinsic record id, so identity holds.
            let fid = frag.root().expect("file entity has an intrinsic id");
            let eh: EmbHandle = frag.put::<Embedding, _>(embedding);
            frag += entity! { ExclusiveId::force_ref(&fid) @ file::embedding: eh };
        }
        Ok(frag)
    } else if meta.is_dir() {
        // Collect children sorted by name for deterministic ordering.
        let mut entries: BTreeMap<String, PathBuf> = BTreeMap::new();
        for entry in fs::read_dir(path).with_context(|| format!("read dir {}", path.display()))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            // Skip hidden files and common noise.
            if name.starts_with('.') {
                continue;
            }
            entries.insert(name, entry.path());
        }

        let mut children = Fragment::default();

        for (_name, child_path) in &entries {
            let child_frag = build_tree(child_path, None, stats, embedder)?;
            children += child_frag;
        }

        let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or(".");
        stats.dirs += 1;
        Ok(file_capability::directory_fragment(dir_name, children))
    } else {
        bail!("unsupported file type: {}", path.display());
    }
}

// ── commands ─────────────────────────────────────────────────────────────

fn cmd_add(
    storage: FilesStorage<'_>,
    path: &Path,
    mime_override: Option<&str>,
    tags: &[String],
    dry_run: bool,
) -> Result<()> {
    let abs_path =
        fs::canonicalize(path).with_context(|| format!("canonicalize {}", path.display()))?;

    if dry_run {
        let mut stats = TreeStats {
            files: 0,
            dirs: 0,
            bytes: 0,
        };
        print_fs_tree(&abs_path, "", "", &mut stats)?;
        println!();
        println!(
            "Would import: {} files, {} dirs, {}",
            stats.files,
            stats.dirs,
            human_size(stats.bytes),
        );
        if !tags.is_empty() {
            println!("Tags: {}", tags.join(", "));
        }
        return Ok(());
    }

    let source = abs_path.to_string_lossy().to_string();

    let mut stats = TreeStats {
        files: 0,
        dirs: 0,
        bytes: 0,
    };
    let mut embedder: Option<Box<dyn ImageEmbedder>> = None;
    let tree = build_tree(&abs_path, mime_override, &mut stats, &mut embedder)?;
    let imported = file_capability::import_fragment(tree, source, now_tai(), tags.iter().cloned())?;
    let root_id = imported.root_id;
    let import_id = imported.import_id;
    let content = if stats.dirs == 0 {
        content_handle_of(&imported.fragment, root_id)?
    } else {
        None
    };
    storage.publish(imported.fragment, "files add")?;

    if stats.dirs > 0 {
        println!(
            "Imported {} ({} files, {} dirs, {})",
            abs_path.display(),
            stats.files,
            stats.dirs,
            human_size(stats.bytes),
        );
    } else {
        // Single file — show the content hash.
        let h = content.ok_or_else(|| anyhow::anyhow!("missing content handle"))?;
        let hash = handle_hex(h);
        let name = abs_path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        let mime = file_capability::normalize_media_type(
            mime_override.unwrap_or_else(|| file_capability::infer_media_type(&abs_path)),
        )?;
        println!("{}  {}  ({})", hash, name, human_size(stats.bytes));
        if mime.starts_with("image/") {
            println!("![{name}](files:{hash})");
        }
    }
    println!("Import: {}", fmt_id(import_id));
    Ok(())
}

fn cmd_fetch(
    storage: FilesStorage<'_>,
    url: &str,
    mime_override: Option<&str>,
    name_override: Option<&str>,
    tags: &[String],
    max_bytes: usize,
) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("playground-files-faculty/0")
        .build()
        .context("build http client")?;
    let response = client
        .get(url)
        .send()
        .with_context(|| format!("fetch {url}"))?
        .error_for_status()
        .with_context(|| format!("fetch {url}"))?;

    let header_mime = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string);
    let bytes = response.bytes().context("read response body")?;
    if bytes.len() > max_bytes {
        bail!(
            "response too large: {} bytes (limit {})",
            bytes.len(),
            max_bytes
        );
    }

    let guessed_name = name_override.map(str::to_owned).or_else(|| {
        let before_query = url.split('?').next().unwrap_or(url);
        let last = before_query.rsplit('/').next()?.trim();
        if last.is_empty() {
            None
        } else {
            Some(last.to_owned())
        }
    });
    let mime = mime_override
        .map(str::to_owned)
        .or(header_mime)
        .unwrap_or_else(|| {
            guessed_name
                .as_deref()
                .map(|n| file_capability::infer_media_type(Path::new(n)))
                .unwrap_or("application/octet-stream")
                .to_string()
        });
    let fname = guessed_name.unwrap_or_else(|| "fetched".to_string());

    let mut embedder: Option<Box<dyn ImageEmbedder>> = None;
    let embedding = embed_image_on_add(&mut embedder, &mime, bytes.as_ref())?;
    let mut file = file_capability::fragment(bytes.to_vec(), fname.clone(), &mime)?;
    let file_id = file.root().expect("canonical file has one root");
    if let Some(embedding) = embedding {
        let handle: EmbHandle = file.put::<Embedding, _>(embedding);
        file += entity! { ExclusiveId::force_ref(&file_id) @ file::embedding: handle };
    }
    let content = content_handle_of(&file, file_id)?
        .ok_or_else(|| anyhow::anyhow!("canonical fetched file has no content"))?;
    let imported =
        file_capability::import_fragment(file, url.to_owned(), now_tai(), tags.iter().cloned())?;
    let import_id = imported.import_id;
    storage.publish(imported.fragment, "files fetch")?;

    let hash = handle_hex(content);
    println!("{}  {}  ({})", hash, fname, human_size(bytes.len() as u64));
    if mime.starts_with("image/") {
        println!("![{fname}](files:{hash})");
    }
    println!("Import: {}", fmt_id(import_id));
    Ok(())
}

fn cmd_list(
    view: &CollectionView,
    filter_tags: &[String],
    filter_mime: Option<&str>,
) -> Result<()> {
    let space = &view.facts;
    let reader = &view.reader;

    let mut entries: Vec<(String, String, String, Vec<String>)> = Vec::new();

    for (eid, h) in find!(
        (eid: Id, h: FileHandle),
        pattern!(space, [{ ?eid @ metadata::tag: &KIND_FILE, file::content: ?h }])
    ) {
        let fname = read_name(space, reader, eid)?.unwrap_or_else(|| "?".into());
        let mime = read_mime(space, reader, eid)?.unwrap_or_else(|| "?".into());
        let tags = tags_of(space, eid);

        if let Some(mp) = filter_mime {
            if !mime.starts_with(mp) {
                continue;
            }
        }
        if !filter_tags.is_empty() && !filter_tags.iter().all(|ft| tags.iter().any(|t| t == ft)) {
            continue;
        }

        let hash = handle_hex(h);
        entries.push((hash, fname, mime, tags));
    }

    entries.sort_by(|a, b| a.1.cmp(&b.1));

    if entries.is_empty() {
        println!("(no files)");
        return Ok(());
    }

    for (hash, fname, mime, tags) in &entries {
        let tag_str = if tags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", tags.join(", "))
        };
        println!("{}  {}  {}{}", hash, fname, mime, tag_str);
    }

    Ok(())
}

fn cmd_resolve(view: &CollectionView, input: &str) -> Result<()> {
    let space = &view.facts;

    // Batch mode: @path or @-
    if let Some(path) = input.strip_prefix('@') {
        let content = if path == "-" {
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf).context("read stdin")?;
            buf
        } else {
            fs::read_to_string(path).with_context(|| format!("read {path}"))?
        };
        let mut resolved = 0u32;
        let mut failed = 0u32;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match file_capability::resolve_reference(space, line) {
                Ok(reference) => {
                    println!("{line}\tfiles:{}", reference.hex());
                    resolved += 1;
                }
                Err(error) => {
                    eprintln!("UNRESOLVED: {line} — {error}");
                    failed += 1;
                }
            }
        }
        eprintln!("{resolved} resolved, {failed} unresolved");
        return Ok(());
    }

    let reference = file_capability::resolve_reference(space, input)?;
    println!("{}", reference.hex());
    Ok(())
}

fn cmd_show(view: &CollectionView, id: &str) -> Result<()> {
    let space = &view.facts;
    let reader = &view.reader;
    let eid = file_capability::resolve_selector(space, id)?;

    if is_file(space, eid) {
        let h =
            content_handle_of(space, eid)?.ok_or_else(|| anyhow::anyhow!("file has no content"))?;
        let size = reader
            .get::<anybytes::Bytes, _>(h)
            .with_context(|| format!("read content for file {eid:x}"))?
            .len() as u64;
        println!("Type:     file");
        println!("Hash:     {}", handle_hex(h));
        println!("Entity:   {}", fmt_id(eid));
        println!(
            "Name:     {}",
            read_name(space, reader, eid)?.unwrap_or("?".into())
        );
        println!(
            "MIME:     {}",
            read_mime(space, reader, eid)?.unwrap_or("?".into())
        );
        println!("Size:     {}", human_size(size));
    } else if is_directory(space, eid) {
        let children = children_of(space, eid);
        println!("Type:     directory");
        println!("Entity:   {}", fmt_id(eid));
        println!(
            "Name:     {}",
            read_name(space, reader, eid)?.unwrap_or("?".into())
        );
        println!("Children: {}", children.len());
    } else if is_import(space, eid) {
        let root = root_of(space, eid)?;
        let ts = imported_at_of(space, eid)?;
        let src = source_path_of(space, reader, eid)?;
        println!("Type:     import");
        println!("Entity:   {}", fmt_id(eid));
        if let Some(r) = root {
            println!("Root:     {}", fmt_id(r));
        }
        if let Some(t) = ts {
            println!("Imported: {}", format_date(t));
        }
        if let Some(s) = src {
            println!("Source:   {s}");
        }
    } else {
        bail!("unknown entity kind for '{id}'");
    }

    let tags = tags_of(space, eid);
    if !tags.is_empty() {
        println!("Tags:     {}", tags.join(", "));
    }

    Ok(())
}

fn cmd_get(view: &CollectionView, id: &str, output: Option<&str>) -> Result<()> {
    let space = &view.facts;
    let reader = &view.reader;
    let eid = file_capability::resolve_selector(space, id)?;

    // For imports, follow to root.
    let target = if is_import(space, eid) {
        root_of(space, eid)?.ok_or_else(|| anyhow::anyhow!("import has no root"))?
    } else {
        eid
    };

    let to_stdout = output == Some("@-");

    if is_file(space, target) {
        let h = content_handle_of(space, target)?
            .ok_or_else(|| anyhow::anyhow!("no content for file"))?;
        let bytes: anybytes::Bytes = reader
            .get::<anybytes::Bytes, _>(h)
            .map_err(|e| anyhow::anyhow!("get blob: {e:?}"))?;

        if to_stdout {
            use std::io::Write;
            std::io::stdout()
                .write_all(bytes.as_ref())
                .context("write to stdout")?;
        } else {
            let out_path = if let Some(p) = output {
                PathBuf::from(p)
            } else {
                let fname = read_name(space, reader, target)?.unwrap_or_else(|| "file.bin".into());
                PathBuf::from(fname)
            };
            fs::write(&out_path, bytes.as_ref())
                .with_context(|| format!("write {}", out_path.display()))?;
            eprintln!(
                "Wrote {} ({})",
                out_path.display(),
                human_size(bytes.len() as u64)
            );
        }
    } else if is_directory(space, target) {
        if to_stdout {
            bail!("cannot write directory to stdout");
        }
        let dir_name = read_name(space, reader, target)?.unwrap_or_else(|| "extracted".into());
        let out_dir = output
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(&dir_name));
        let mut stats = TreeStats {
            files: 0,
            dirs: 0,
            bytes: 0,
        };
        extract_tree(space, reader, target, &out_dir, &mut stats)?;
        eprintln!(
            "Extracted to {} ({} files, {} dirs, {})",
            out_dir.display(),
            stats.files,
            stats.dirs,
            human_size(stats.bytes),
        );
    } else {
        bail!("entity is not a file, directory, or import");
    }

    Ok(())
}

fn extract_tree(
    space: &TribleSet,
    reader: &PileReader,
    id: Id,
    dest: &Path,
    stats: &mut TreeStats,
) -> Result<()> {
    if is_file(space, id) {
        let h =
            content_handle_of(space, id)?.ok_or_else(|| anyhow::anyhow!("no content for file"))?;
        let bytes: anybytes::Bytes = reader
            .get::<anybytes::Bytes, _>(h)
            .map_err(|e| anyhow::anyhow!("get blob: {e:?}"))?;
        fs::write(dest, bytes.as_ref()).with_context(|| format!("write {}", dest.display()))?;
        stats.files += 1;
        stats.bytes += bytes.len() as u64;
    } else if is_directory(space, id) {
        fs::create_dir_all(dest).with_context(|| format!("mkdir {}", dest.display()))?;
        stats.dirs += 1;
        for cid in children_of(space, id) {
            let cname = read_name(space, reader, cid)?.unwrap_or_else(|| fmt_id(cid));
            extract_tree(space, reader, cid, &dest.join(&cname), stats)?;
        }
    } else {
        bail!("unknown entity kind during extraction");
    }
    Ok(())
}

fn cmd_tag(storage: FilesStorage<'_>, id: &str, tag_name: &str) -> Result<()> {
    let view = storage.view()?;
    let eid = file_capability::resolve_selector(&view.facts, id)?;

    let existing = tags_of(&view.facts, eid);
    if existing.iter().any(|t| t == tag_name) {
        println!("Tag '{tag_name}' already present.");
        return Ok(());
    }

    let change = entity! { ExclusiveId::force_ref(&eid) @ file::tag: tag_name };
    storage.publish(change, "files tag")?;

    let name = read_name(&view.facts, &view.reader, eid)?.unwrap_or_else(|| fmt_id(eid));
    println!("Tagged {name} with '{tag_name}'");
    Ok(())
}

fn cmd_search(view: &CollectionView, query: &str) -> Result<()> {
    let space = &view.facts;
    let reader = &view.reader;

    let needle = query.to_lowercase();
    let mut hits: Vec<(String, String, String, Vec<String>)> = Vec::new();

    for (eid, h) in find!(
        (eid: Id, h: FileHandle),
        pattern!(space, [{ ?eid @ metadata::tag: &KIND_FILE, file::content: ?h }])
    ) {
        let fname = read_name(space, reader, eid)?.unwrap_or_else(|| "?".into());
        let mime = read_mime(space, reader, eid)?.unwrap_or_else(|| "?".into());
        let tags = tags_of(space, eid);

        let fname_match = fname.to_lowercase().contains(&needle);
        let tag_match = tags.iter().any(|t| t.to_lowercase().contains(&needle));
        let mime_match = mime.to_lowercase().contains(&needle);

        if fname_match || tag_match || mime_match {
            hits.push((handle_hex(h), fname, mime, tags));
        }
    }

    hits.sort_by(|a, b| a.1.cmp(&b.1));

    if hits.is_empty() {
        println!("No files matching '{query}'");
        return Ok(());
    }

    for (hash, fname, mime, tags) in &hits {
        let tag_str = if tags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", tags.join(", "))
        };
        println!("{}  {}  {}{}", hash, fname, mime, tag_str);
    }

    Ok(())
}

fn cmd_imports(view: &CollectionView) -> Result<()> {
    let space = &view.facts;
    let reader = &view.reader;

    let mut imports: Vec<(i128, Id, Option<String>, Vec<String>)> = Vec::new();

    for (eid,) in find!(
        (eid: Id),
        pattern!(space, [{ ?eid @ metadata::tag: &KIND_IMPORT }])
    ) {
        let ts = imported_at_of(space, eid)?.unwrap_or(0);
        let src = source_path_of(space, reader, eid)?;
        let tags = tags_of(space, eid);
        imports.push((ts, eid, src, tags));
    }

    imports.sort_by(|a, b| b.0.cmp(&a.0));

    if imports.is_empty() {
        println!("(no imports)");
        return Ok(());
    }

    for (ts, eid, src, tags) in &imports {
        let date = if *ts > 0 {
            format_date(*ts)
        } else {
            "?".into()
        };
        let src_str = src.as_deref().unwrap_or("?");
        let tag_str = if tags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", tags.join(", "))
        };
        println!("{}  {}  {}{}", &fmt_id(*eid)[..12], date, src_str, tag_str);
    }

    Ok(())
}

fn cmd_tree(view: &CollectionView, id: &str, max_depth: Option<usize>) -> Result<()> {
    let space = &view.facts;
    let reader = &view.reader;
    let eid = file_capability::resolve_selector(space, id)?;

    // If it's an import, follow to root.
    let root = if is_import(space, eid) {
        root_of(space, eid)?.ok_or_else(|| anyhow::anyhow!("import has no root"))?
    } else {
        eid
    };

    print_tree(space, reader, root, "", "", max_depth, 0)
}

fn print_tree(
    space: &TribleSet,
    reader: &PileReader,
    id: Id,
    prefix: &str,
    child_prefix: &str,
    max_depth: Option<usize>,
    depth: usize,
) -> Result<()> {
    let name = read_name(space, reader, id)?.unwrap_or_else(|| fmt_id(id));

    if is_file(space, id) {
        let mime = read_mime(space, reader, id)?.unwrap_or_else(|| "?".into());
        let size_str = content_handle_of(space, id)?
            .and_then(|h| reader.get::<anybytes::Bytes, _>(h).ok())
            .map(|b| human_size(b.len() as u64))
            .unwrap_or_else(|| "?".into());
        println!("{prefix}{name}  ({mime}, {size_str})");
    } else if is_directory(space, id) {
        let children = children_of(space, id);
        if max_depth.is_some_and(|d| depth >= d) {
            println!("{prefix}{name}/  ({} children)", children.len());
            return Ok(());
        }
        println!("{prefix}{name}/");
        let mut dirs: Vec<(String, Id)> = Vec::new();
        let mut files: Vec<(String, Id)> = Vec::new();
        for &cid in &children {
            let cname = read_name(space, reader, cid)?.unwrap_or_else(|| fmt_id(cid));
            if is_directory(space, cid) {
                dirs.push((cname, cid));
            } else {
                files.push((cname, cid));
            }
        }
        dirs.sort_by(|a, b| a.0.cmp(&b.0));
        files.sort_by(|a, b| a.0.cmp(&b.0));

        let all: Vec<Id> = dirs.iter().chain(files.iter()).map(|(_, id)| *id).collect();
        for (i, &cid) in all.iter().enumerate() {
            let last = i == all.len() - 1;
            let connector = if last { "└── " } else { "├── " };
            let continuation = if last { "    " } else { "│   " };
            print_tree(
                space,
                reader,
                cid,
                &format!("{child_prefix}{connector}"),
                &format!("{child_prefix}{continuation}"),
                max_depth,
                depth + 1,
            )?;
        }
    } else {
        println!("{prefix}{name}  (unknown)");
    }
    Ok(())
}

fn cmd_diff(view: &CollectionView, left_id: &str, right_id: &str) -> Result<()> {
    let space = &view.facts;
    let reader = &view.reader;

    let resolve_root = |raw: &str| -> Result<Id> {
        let eid = file_capability::resolve_selector(space, raw)?;
        if is_import(space, eid) {
            root_of(space, eid)?.ok_or_else(|| anyhow::anyhow!("import has no root"))
        } else {
            Ok(eid)
        }
    };

    let left = resolve_root(left_id)?;
    let right = resolve_root(right_id)?;

    if left == right {
        println!("Identical (same entity).");
        return Ok(());
    }

    let mut stats = DiffStats::default();
    diff_tree(space, reader, left, right, "", &mut stats)?;

    if stats.is_empty() {
        println!("No differences.");
    } else {
        println!(
            "\n{} added, {} removed, {} modified",
            stats.added, stats.removed, stats.modified,
        );
    }
    Ok(())
}

#[derive(Default)]
struct DiffStats {
    added: usize,
    removed: usize,
    modified: usize,
}

impl DiffStats {
    fn is_empty(&self) -> bool {
        self.added == 0 && self.removed == 0 && self.modified == 0
    }
}

fn diff_tree(
    space: &TribleSet,
    reader: &PileReader,
    left: Id,
    right: Id,
    path: &str,
    stats: &mut DiffStats,
) -> Result<()> {
    // Merkle shortcut: same id means identical subtree.
    if left == right {
        return Ok(());
    }

    let left_is_dir = is_directory(space, left);
    let right_is_dir = is_directory(space, right);

    // Both files — content changed.
    if !left_is_dir && !right_is_dir {
        let lname = read_name(space, reader, left)?.unwrap_or_else(|| "?".into());
        let lsize = file_size(space, reader, left)?;
        let rsize = file_size(space, reader, right)?;
        println!(
            "  ~ {path}{lname}  ({} → {})",
            human_size(lsize),
            human_size(rsize)
        );
        stats.modified += 1;
        return Ok(());
    }

    // Type mismatch: show as remove + add.
    if left_is_dir != right_is_dir {
        print_diff_removed(space, reader, left, path, stats)?;
        print_diff_added(space, reader, right, path, stats)?;
        return Ok(());
    }

    // Both directories — diff children by name.
    let left_children = named_children(space, reader, left)?;
    let right_children = named_children(space, reader, right)?;

    let left_name = read_name(space, reader, left)?.unwrap_or_else(|| "?".into());
    let sub = if path.is_empty() {
        format!("{left_name}/")
    } else {
        format!("{path}{left_name}/")
    };

    let mut li = left_children.iter().peekable();
    let mut ri = right_children.iter().peekable();

    // Merge-join on name (BTreeMap is sorted).
    loop {
        match (li.peek(), ri.peek()) {
            (None, None) => break,
            (Some(_), None) => {
                let (_lname, lid) = li.next().unwrap();
                print_diff_removed(space, reader, *lid, &sub, stats)?;
            }
            (None, Some(_)) => {
                let (_rname, rid) = ri.next().unwrap();
                print_diff_added(space, reader, *rid, &sub, stats)?;
            }
            (Some((lname, _)), Some((rname, _))) => match lname.cmp(rname) {
                std::cmp::Ordering::Less => {
                    let (lname, lid) = li.next().unwrap();
                    print_diff_removed(space, reader, *lid, &sub, stats)?;
                    let _ = lname;
                }
                std::cmp::Ordering::Greater => {
                    let (rname, rid) = ri.next().unwrap();
                    print_diff_added(space, reader, *rid, &sub, stats)?;
                    let _ = rname;
                }
                std::cmp::Ordering::Equal => {
                    let (_lname, lid) = li.next().unwrap();
                    let (_rname, rid) = ri.next().unwrap();
                    diff_tree(space, reader, *lid, *rid, &sub, stats)?;
                }
            },
        }
    }
    Ok(())
}

fn named_children(space: &TribleSet, reader: &PileReader, id: Id) -> Result<BTreeMap<String, Id>> {
    let mut map = BTreeMap::new();
    for cid in children_of(space, id) {
        let name = read_name(space, reader, cid)?.unwrap_or_else(|| fmt_id(cid));
        if let Some(previous) = map.insert(name.clone(), cid) {
            bail!(
                "directory {id:x} contains two children named {name:?}: {previous:x} and {cid:x}"
            );
        }
    }
    Ok(map)
}

fn file_size(space: &TribleSet, reader: &PileReader, id: Id) -> Result<u64> {
    let Some(handle) = content_handle_of(space, id)? else {
        return Ok(0);
    };
    let bytes: anybytes::Bytes = reader
        .get(handle)
        .with_context(|| format!("read content for file {id:x}"))?;
    Ok(bytes.len() as u64)
}

fn print_diff_added(
    space: &TribleSet,
    reader: &PileReader,
    id: Id,
    path: &str,
    stats: &mut DiffStats,
) -> Result<()> {
    let name = read_name(space, reader, id)?.unwrap_or_else(|| "?".into());
    if is_directory(space, id) {
        println!("  + {path}{name}/");
        stats.added += 1;
        let sub = format!("{path}{name}/");
        for cid in children_of(space, id) {
            print_diff_added(space, reader, cid, &sub, stats)?;
        }
    } else {
        let size = file_size(space, reader, id)?;
        println!("  + {path}{name}  ({})", human_size(size));
        stats.added += 1;
    }
    Ok(())
}

fn print_diff_removed(
    space: &TribleSet,
    reader: &PileReader,
    id: Id,
    path: &str,
    stats: &mut DiffStats,
) -> Result<()> {
    let name = read_name(space, reader, id)?.unwrap_or_else(|| "?".into());
    if is_directory(space, id) {
        println!("  - {path}{name}/");
        stats.removed += 1;
        let sub = format!("{path}{name}/");
        for cid in children_of(space, id) {
            print_diff_removed(space, reader, cid, &sub, stats)?;
        }
    } else {
        let size = file_size(space, reader, id)?;
        println!("  - {path}{name}  ({})", human_size(size));
        stats.removed += 1;
    }
    Ok(())
}

// ── main ─────────────────────────────────────────────────────────────────

/// Read a stored embedding blob back into a plain `Vec<f32>`.
fn read_embedding(reader: &PileReader, h: EmbHandle) -> Result<Vec<f32>> {
    let v: anybytes::View<[f32]> = reader
        .get(h)
        .map_err(|e| anyhow::anyhow!("read embedding blob: {e:?}"))?;
    Ok(v.as_ref().to_vec())
}

/// Embed every image file with nomic-embed-multimodal-7b and store the 3584-d
/// vector on `attr_mm7b::embedding` (under the file's intrinsic record id, so
/// identity is unaffected — pure exhaust). Additive to the CLIP `file::embedding`
/// path: both coexist. Idempotent — already-embedded files are skipped.
/// Identical bytes (duplicate imports) are embedded once and the
/// vector fanned out to every entity that shares the content.
fn cmd_embed7b(storage: FilesStorage<'_>) -> Result<()> {
    let view = storage.view()?;
    let space = &view.facts;
    let reader = &view.reader;

    // Gather image file entities, grouped by content hash so identical bytes are
    // embedded once. Skip SVG (not a raster the vision tower can decode).
    let mut groups: BTreeMap<String, (FileHandle, Vec<(Id, bool)>)> = BTreeMap::new();
    for (eid, h) in find!(
        (eid: Id, h: FileHandle),
        pattern!(space, [{ ?eid @ metadata::tag: &KIND_FILE, file::content: ?h }])
    ) {
        let mime = read_mime(space, reader, eid)?.unwrap_or_default();
        if !mime.starts_with("image/") || mime == "image/svg+xml" {
            continue;
        }
        let has_emb = exists!(
            (e: Mm7bHandle),
            pattern!(space, [{ eid @ embeddings::attr_mm7b::embedding: ?e }])
        );
        groups
            .entry(handle_hex(h))
            .or_insert_with(|| (h, Vec::new()))
            .1
            .push((eid, has_emb));
    }

    if groups.is_empty() {
        println!("(no image files to embed)");
        return Ok(());
    }

    // Which groups still need work?
    let pending: Vec<_> = groups
        .into_iter()
        .filter(|(_, (_, eids))| eids.iter().any(|(_, has)| !*has))
        .collect();

    let total_imgs: usize = pending.iter().map(|(_, (_, e))| e.len()).sum();
    if pending.is_empty() {
        println!("All image files already have a 7b embedding.");
        return Ok(());
    }

    let embedder = load_mm7b_opt()?;

    let mut change = Fragment::empty();
    let mut embedded = 0usize;
    let mut assigned = 0usize;
    let mut failed = 0usize;
    for (hash, (content, eids)) in &pending {
        let bytes: anybytes::Bytes = match reader.get::<anybytes::Bytes, _>(*content) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("  skip {hash}: read content failed: {e:?}");
                failed += 1;
                continue;
            }
        };
        let v = match mm7b_embed_image(&embedder, bytes.as_ref()) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  skip {hash}: embed failed: {e:#}");
                failed += 1;
                continue;
            }
        };
        embedded += 1;
        for (eid, has) in eids {
            if *has {
                continue;
            }
            let handle: Mm7bHandle = change.put::<embeddings::Embedding3584, _>(v.clone());
            change += entity! {
                ExclusiveId::force_ref(eid) @ embeddings::attr_mm7b::embedding: handle
            };
            assigned += 1;
        }
        eprintln!("  embedded {hash}  ({} bytes → 3584-d)", bytes.len());
    }

    if change.is_empty() {
        println!("Nothing to commit (embedded {embedded}, failed {failed}).");
        return Ok(());
    }

    storage.publish(change, "files embed-7b")?;

    println!(
        "7b-embedded {embedded} unique images → {assigned} file entities (of {total_imgs} pending){}",
        if failed > 0 { format!(", {failed} failed") } else { String::new() },
    );
    Ok(())
}

// ── PDF rasterization (page-level 7b embedding) ────────────────────────────
// A PDF isn't an image — to put it in the nomic-mm7b space we rasterize each
// page to a PNG and embed that. We shell out to `pdftoppm` (poppler): it is
// already present on this machine, renders robustly to RGB, has no heavy
// build-time C dependency (unlike `mupdf`) and no runtime dylib to vendor
// (unlike `pdfium-render`, which needs `libpdfium`). The only cost is a runtime
// dependency on `pdftoppm` being on PATH — checked up front with a clear bail.
// nomic-embed-multimodal-7b is itself a *visual document* retrieval model
// (ColPali-style, trained on page screenshots), so a rendered page is exactly
// its native input — this is the path the model is strongest at.

/// Render a PDF (raw bytes) to per-page PNGs via `pdftoppm`. Returns
/// `(page_number, png_bytes)` sorted by page, 1-based. `max_pages == 0` renders
/// all pages; otherwise only the first `max_pages`. Pure side-effect-free from
/// the pile's view: writes to a private temp dir that is removed on return.
fn render_pdf_pages(bytes: &[u8], dpi: u32, max_pages: usize) -> Result<Vec<(usize, Vec<u8>)>> {
    use std::process::Command as PCommand;

    if which_pdftoppm().is_none() {
        bail!(
            "`pdftoppm` not found on PATH — install poppler (e.g. `brew install poppler`) \
             to rasterize PDFs for 7b embedding"
        );
    }

    // Private temp dir under the system temp root; cleaned up before returning.
    let dir = std::env::temp_dir().join(format!("files_pdf7b_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).with_context(|| format!("create temp dir {dir:?}"))?;
    let in_pdf = dir.join("in.pdf");
    fs::write(&in_pdf, bytes).with_context(|| format!("write temp pdf {in_pdf:?}"))?;
    let prefix = dir.join("page");

    let mut cmd = PCommand::new("pdftoppm");
    cmd.arg("-png").arg("-r").arg(dpi.to_string());
    if max_pages > 0 {
        cmd.arg("-l").arg(max_pages.to_string());
    }
    cmd.arg(&in_pdf).arg(&prefix);
    let out = cmd.output().with_context(|| "spawn pdftoppm")?;
    if !out.status.success() {
        let _ = fs::remove_dir_all(&dir);
        bail!(
            "pdftoppm failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    // Collect page PNGs: pdftoppm names them `<prefix>-<n>.png`, n zero-padded
    // to the page-count width. Parse the trailing number so order is numeric.
    let mut pages: Vec<(usize, Vec<u8>)> = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("read temp dir {dir:?}"))? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("png") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        let num = stem
            .rsplit('-')
            .next()
            .and_then(|d| d.parse::<usize>().ok());
        if let Some(n) = num {
            let data = fs::read(&path).with_context(|| format!("read page {path:?}"))?;
            pages.push((n, data));
        }
    }
    let _ = fs::remove_dir_all(&dir);
    pages.sort_by_key(|(n, _)| *n);
    Ok(pages)
}

/// `which pdftoppm` without spawning a shell — returns the resolved path.
fn which_pdftoppm() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join("pdftoppm");
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

fn missing_page_parents(space: &TribleSet, parents: &[Id], index: &str) -> Vec<Id> {
    parents
        .iter()
        .copied()
        .filter(|parent| {
            let id = file_capability::page_id(*parent, index);
            !exists!(
                (embedding: Mm7bHandle),
                pattern!(space, [{ id @ embeddings::attr_mm7b::embedding: ?embedding }])
            )
        })
        .collect()
}

/// Embed PDF *pages* into the 3584-d 7b space. Each page becomes a page entity
/// (`KIND_PAGE`, `page::parent` → file, `page::index` → 1-based number) carrying
/// the shared `embeddings::attr_mm7b::embedding`, so `files similar --mm7b`
/// ranks pages and a hit resolves to "file X, page N". Page entity ids are
/// intrinsic (parent+index), and the command checks every page in the actual
/// requested render range. A prior partial run therefore never masquerades as
/// complete. Unique PDF bytes are rendered+embedded once and vectors fan out to
/// every file entity sharing the content.
fn cmd_embed7b_pdf(
    storage: FilesStorage<'_>,
    dpi: u32,
    file_limit: usize,
    max_pages: usize,
) -> Result<()> {
    let view = storage.view()?;
    let space = &view.facts;
    let reader = &view.reader;

    // Gather PDF file entities grouped by content hash (render once per unique
    // bytes, fan pages out to every sibling file entity).
    let mut groups: BTreeMap<String, (FileHandle, Vec<Id>)> = BTreeMap::new();
    for (eid, h) in find!(
        (eid: Id, h: FileHandle),
        pattern!(space, [{ ?eid @ metadata::tag: &KIND_FILE, file::content: ?h }])
    ) {
        if read_mime(space, reader, eid)?.as_deref() != Some("application/pdf") {
            continue;
        }
        groups
            .entry(handle_hex(h))
            .or_insert_with(|| (h, Vec::new()))
            .1
            .push(eid);
    }

    if groups.is_empty() {
        println!("(no PDF files to embed)");
        return Ok(());
    }

    let mut groups: Vec<_> = groups.into_iter().collect();
    groups.sort_by(|left, right| left.0.cmp(&right.0));

    let mut embedder: Option<Mm7bEmbedderOpt> = None;
    let mut change = Fragment::empty();
    let mut pdfs_done = 0usize;
    let mut pages_embedded = 0usize;
    let mut failed = 0usize;
    for (hash, (content, eids)) in &groups {
        let bytes: anybytes::Bytes = match reader.get::<anybytes::Bytes, _>(*content) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("  skip {hash}: read content failed: {e:?}");
                failed += 1;
                continue;
            }
        };
        let pages = match render_pdf_pages(bytes.as_ref(), dpi, max_pages) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("  skip {hash}: render failed: {e:#}");
                failed += 1;
                continue;
            }
        };
        if pages.is_empty() {
            eprintln!("  skip {hash}: pdftoppm produced no pages");
            failed += 1;
            continue;
        }

        // Determine the exact missing page identities only after rendering:
        // max-pages may exceed the document's real page count, while a prior
        // run may have stopped after any subset. "Any page exists" is never a
        // completion criterion.
        let plans: Vec<_> = pages
            .into_iter()
            .filter_map(|(page_no, png)| {
                let index = page_no.to_string();
                let missing = missing_page_parents(space, eids, &index);
                (!missing.is_empty()).then_some((page_no, index, png, missing))
            })
            .collect();
        if plans.is_empty() {
            continue;
        }
        if file_limit > 0 && pdfs_done >= file_limit {
            break;
        }
        if embedder.is_none() {
            embedder = Some(load_mm7b_opt()?);
        }

        let mut this_pages = 0usize;
        let mut this_entities = 0usize;
        for (page_no, index, png, missing) in plans {
            let vector = match mm7b_embed_image(embedder.as_ref().unwrap(), &png) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("  {hash} page {page_no}: embed failed: {e:#}");
                    failed += 1;
                    continue;
                }
            };
            for parent in missing {
                change += file_capability::page_fragment(parent, index.clone(), vector.clone());
                this_entities += 1;
            }
            this_pages += 1;
            pages_embedded += 1;
        }
        pdfs_done += 1;
        eprintln!("  {hash}: {this_pages} newly embedded pages → {this_entities} entities");
    }

    if change.is_empty() {
        println!("All requested PDF pages already have embeddings ({failed} failures). ");
        return Ok(());
    }

    storage.publish(change, "files embed-7b --pdf")?;

    println!(
        "7b-embedded {pages_embedded} pages across {pdfs_done} PDFs{}",
        if failed > 0 {
            format!(", {failed} failures")
        } else {
            String::new()
        },
    );
    Ok(())
}

/// Semantic nearest-neighbour search over image embeddings.
///
/// Embeddings are persisted as exhaust of `add` (one `Handle<Embedding>` per
/// image file); the HNSW index itself is rebuilt on demand here — at this
/// scale a build is sub-second, so there is no stale index to maintain. The
/// query is pile-native: `candidates_above` walks the graph, and the optional
/// `--tag` filter is the hybrid join that separates real forms from mascots.
/// With `mm7b`, the query and candidates live in the 3584-d nomic-7b space
/// (`attr_mm7b::embedding`, populated by `files embed-7b`) instead of CLIP-512.
fn cmd_similar(
    view: &CollectionView,
    id: Option<&str>,
    text: Option<&str>,
    floor: f32,
    limit: usize,
    filter_tags: &[String],
    mm7b: bool,
) -> Result<()> {
    if mm7b {
        return cmd_similar_mm7b(view, id, text, floor, limit, filter_tags);
    }
    let space = &view.facts;
    let reader = &view.reader;

    // The query vector + a label, from either a text string (cross-modal) or a
    // query file's stored embedding. `query_eid` is Some only for a file query,
    // so it drops itself from its own results.
    let (query_vec, query_eid, label): (Vec<f32>, Option<Id>, String) = match (text, id) {
        (Some(t), _) => (embed_text_query(t)?, None, format!("{t:?}")),
        (None, Some(idstr)) => {
            let eid = file_capability::resolve_selector(space, idstr)?;
            let h = file_capability::embedding_handle(space, eid)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "that file has no embedding — only image/* files are embedded \
                     on `add` (re-add it), or query with --text instead"
                )
            })?;
            let name = read_name(space, reader, eid)?.unwrap_or_else(|| "?".into());
            (read_embedding(reader, h)?, Some(eid), name)
        }
        (None, None) => bail!("give a file id/hash, or --text \"a query\""),
    };

    // Every embedded file: (entity, handle). Read each vector back from the
    // pile and stage it into a local store the HNSW can attach to.
    let pairs: Vec<(Id, EmbHandle)> = find!(
        (eid: Id, h: EmbHandle),
        pattern!(space, [{ ?eid @ file::embedding: ?h }])
    )
    .collect();
    if pairs.is_empty() {
        bail!("no embedded files yet — add some images first");
    }

    // Read every embedding into a plain vector and run the pure NN core.
    let mut vec_pairs: Vec<(Id, Vec<f32>)> = Vec::with_capacity(pairs.len());
    for (eid, h) in &pairs {
        vec_pairs.push((*eid, read_embedding(reader, *h)?));
    }
    let ranked = embeddings::nearest(&vec_pairs, &query_vec, floor)?;

    // Drop self (file query only), apply the hybrid tag filter, truncate.
    let mut rows: Vec<(f32, Id)> = Vec::new();
    for (cos, eid) in ranked {
        if Some(eid) == query_eid {
            continue;
        }
        if !filter_tags.is_empty() {
            let tags = tags_of(space, eid);
            if !filter_tags.iter().all(|ft| tags.iter().any(|t| t == ft)) {
                continue;
            }
        }
        rows.push((cos, eid));
    }
    rows.truncate(limit);

    if rows.is_empty() {
        println!("no files similar to {label} above cos {floor}");
        return Ok(());
    }
    println!("Similar to {label} (cos ≥ {floor}):");
    for (cos, eid) in &rows {
        let name = read_name(space, reader, *eid)?.unwrap_or_else(|| "?".into());
        let mime = read_mime(space, reader, *eid)?.unwrap_or_else(|| "?".into());
        let hash = content_handle_of(space, *eid)?
            .map(handle_hex)
            .unwrap_or_default();
        let tags = tags_of(space, *eid);
        let tagstr = if tags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", tags.join(", "))
        };
        println!("  {cos:.3}  {name}  ({mime})  {hash}{tagstr}");
    }
    Ok(())
}

/// Nearest-neighbour search in the nomic-embed-multimodal-7b 3584-d space.
/// Same shape as [`cmd_similar`] but over `attr_mm7b::embedding`: a text query
/// is embedded with the 7b's query-side path (text→image recall), a file query
/// reuses that file's stored 7b vector (image→image).
fn cmd_similar_mm7b(
    view: &CollectionView,
    id: Option<&str>,
    text: Option<&str>,
    floor: f32,
    limit: usize,
    filter_tags: &[String],
) -> Result<()> {
    let space = &view.facts;
    let reader = &view.reader;

    let (query_vec, query_eid, label): (Vec<f32>, Option<Id>, String) = match (text, id) {
        (Some(t), _) => {
            let embedder = load_mm7b_opt()?;
            (mm7b_embed_query(&embedder, t)?, None, format!("{t:?}"))
        }
        (None, Some(idstr)) => {
            let eid = file_capability::resolve_selector(space, idstr)?;
            let h = file_capability::mm7b_embedding_handle(space, eid)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "that file has no 7b embedding — run `files embed-7b` first, \
                     or query with --text instead"
                )
            })?;
            let name = read_name(space, reader, eid)?.unwrap_or_else(|| "?".into());
            (read_embedding_3584(reader, h)?, Some(eid), name)
        }
        (None, None) => bail!("give a file id/hash, or --text \"a query\""),
    };

    let pairs: Vec<(Id, Mm7bHandle)> = find!(
        (eid: Id, h: Mm7bHandle),
        pattern!(space, [{ ?eid @ embeddings::attr_mm7b::embedding: ?h }])
    )
    .collect();
    if pairs.is_empty() {
        bail!("no 7b-embedded files yet — run `files embed-7b` first");
    }

    let mut vec_pairs: Vec<(Id, Vec<f32>)> = Vec::with_capacity(pairs.len());
    for (eid, h) in &pairs {
        vec_pairs.push((*eid, read_embedding_3584(reader, *h)?));
    }
    let ranked = embeddings::nearest(&vec_pairs, &query_vec, floor)?;

    let mut rows: Vec<(f32, Id)> = Vec::new();
    for (cos, eid) in ranked {
        if Some(eid) == query_eid {
            continue;
        }
        if !filter_tags.is_empty() {
            let tags = tags_of(space, eid);
            if !filter_tags.iter().all(|ft| tags.iter().any(|t| t == ft)) {
                continue;
            }
        }
        rows.push((cos, eid));
    }
    rows.truncate(limit);

    if rows.is_empty() {
        println!("no files similar to {label} above cos {floor} (7b space)");
        return Ok(());
    }
    println!("Similar to {label} (7b space, cos ≥ {floor}):");
    for (cos, eid) in &rows {
        // A page hit resolves to its parent file (name/mime/hash) + page number.
        let (display_eid, page_suffix) = match read_page(space, *eid)? {
            Some((parent, idx)) => (parent, format!("  page {idx}")),
            None => (*eid, String::new()),
        };
        let name = read_name(space, reader, display_eid)?.unwrap_or_else(|| "?".into());
        let mime = read_mime(space, reader, display_eid)?.unwrap_or_else(|| "?".into());
        let hash = content_handle_of(space, display_eid)?
            .map(handle_hex)
            .unwrap_or_default();
        let tags = tags_of(space, display_eid);
        let tagstr = if tags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", tags.join(", "))
        };
        println!("  {cos:.3}  {name}{page_suffix}  ({mime})  {hash}{tagstr}");
    }
    Ok(())
}

fn migrate_legacy(
    storage: FilesStorage<'_>,
    explicit_branch: Option<Id>,
) -> Result<collection_access::LegacyMigrationReport> {
    let report = collection_access::migrate_legacy_simplearchive_branch(
        storage.pile,
        storage.key,
        storage.scope,
        FILES_BRANCH_NAME,
        explicit_branch,
        file_capability::validate_known_payloads,
        file_capability::validate_catalog,
    )?;
    // Revalidate the published view as defense in depth. The same complete
    // catalog was already checked before the first append by migration.
    storage.view()?;
    Ok(report)
}

fn cmd_migrate_legacy(storage: FilesStorage<'_>, explicit_branch: Option<Id>) -> Result<()> {
    let report = migrate_legacy(storage, explicit_branch)?;
    println!(
        "migrated {} authored commit{} ({} facts); skipped {} contentless merge{}",
        report.commits.len(),
        if report.commits.len() == 1 { "" } else { "s" },
        report.facts,
        report.skipped_merges,
        if report.skipped_merges == 1 { "" } else { "s" },
    );
    println!("  legacy branch {}", report.branch_id);
    println!(
        "  legacy head   {}",
        report
            .head
            .map(|head| hex::encode_upper(head.raw))
            .unwrap_or_else(|| "<empty>".to_owned())
    );
    println!(
        "  retention     {} direct + {} recursive roots (verified, not persisted)",
        report.retention_direct, report.retention_recursive
    );
    println!("  legacy pin remains in place until the coordinated cutover");
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let Some(command) = cli.command else {
        Cli::command().print_help()?;
        return Ok(());
    };

    let storage = FilesStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
        scope: cli.scope.unwrap_or(DEFAULT_SCOPE_ID),
    };

    match command {
        Command::Add {
            path,
            mime,
            tag,
            dry_run,
        } => cmd_add(storage, &path, mime.as_deref(), &tag, dry_run),
        Command::List { tag, mime } => {
            let view = storage.view()?;
            cmd_list(&view, &tag, mime.as_deref())
        }
        Command::Show { id } => {
            let view = storage.view()?;
            cmd_show(&view, &id)
        }
        Command::Get { id, output } => {
            let view = storage.view()?;
            cmd_get(&view, &id, output.as_deref())
        }
        Command::Tag { id, name } => cmd_tag(storage, &id, &name),
        Command::Fetch {
            url,
            mime,
            name,
            tag,
            max_bytes,
        } => cmd_fetch(
            storage,
            &url,
            mime.as_deref(),
            name.as_deref(),
            &tag,
            max_bytes,
        ),
        Command::Search { query } => {
            let view = storage.view()?;
            cmd_search(&view, &query)
        }
        Command::Similar {
            id,
            text,
            floor,
            limit,
            tag,
            mm7b,
        } => {
            let view = storage.view()?;
            cmd_similar(
                &view,
                id.as_deref(),
                text.as_deref(),
                floor,
                limit,
                &tag,
                mm7b,
            )
        }
        Command::Embed7b {
            pdf,
            dpi,
            limit,
            max_pages,
        } => {
            if pdf {
                cmd_embed7b_pdf(storage, dpi, limit, max_pages)
            } else {
                cmd_embed7b(storage)
            }
        }
        Command::MigrateLegacy { legacy_branch_id } => {
            cmd_migrate_legacy(storage, legacy_branch_id)
        }
        Command::Imports => {
            let view = storage.view()?;
            cmd_imports(&view)
        }
        Command::Tree { id, depth } => {
            let view = storage.view()?;
            cmd_tree(&view, &id, depth)
        }
        Command::Resolve { input } => {
            let view = storage.view()?;
            cmd_resolve(&view, &input)
        }
        Command::Diff { left, right } => {
            let view = storage.view()?;
            cmd_diff(&view, &left, &right)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::fs::File;
    use triblespace::core::repo::{PinStore, Repository};
    use triblespace::core::trible::{E_END, E_START};

    use faculties::schemas::files::KIND_MEDIA_TYPE;

    mod legacy_schema {
        use triblespace::prelude::*;

        attributes! {
            "BFE2C88ECD13D56F80967C343FC072EE" as mime: inlineencodings::ShortString;
        }
    }

    struct Fixture {
        directory: tempfile::TempDir,
        pile: PathBuf,
        key: PathBuf,
        scope: Id,
    }

    impl Fixture {
        fn new(scope_byte: u8) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let pile = directory.path().join("files.pile");
            let key = directory.path().join("files.key");
            File::create(&pile).unwrap();
            collection_access::initialize_signer(&pile, Some(&key)).unwrap();
            Self {
                directory,
                pile,
                key,
                scope: Id::new([scope_byte; 16]).unwrap(),
            }
        }

        fn storage(&self) -> FilesStorage<'_> {
            FilesStorage {
                pile: &self.pile,
                key: Some(&self.key),
                scope: self.scope,
            }
        }
    }

    fn embedded_file(bytes: &[u8], name: &str, axis: usize) -> Fragment {
        let mut file = file_capability::fragment(bytes.to_vec(), name, "image/png").unwrap();
        let id = file.root().unwrap();
        let clip: EmbHandle = file.put::<Embedding, _>(if axis == 0 {
            vec![1.0, 0.0]
        } else {
            vec![0.8, 0.2]
        });
        let mut vector = vec![0.0; embeddings::DIM_3584];
        vector[axis] = 1.0;
        let mm7b: Mm7bHandle = file.put::<embeddings::Embedding3584, _>(vector);
        file += entity! { ExclusiveId::force_ref(&id) @
            file::embedding: clip,
            embeddings::attr_mm7b::embedding: mm7b,
        };
        file
    }

    fn force_entity_id(fragment: Fragment, from: Id, to: Id) -> Fragment {
        let (facts, blobs) = fragment.into_facts_and_blobs();
        let mut rewritten = TribleSet::new();
        for fact in &facts {
            if fact.e() == &from {
                let mut raw = fact.data;
                raw[E_START..=E_END].copy_from_slice(&to[..]);
                rewritten.insert(&Trible::force_raw(raw).unwrap());
            } else {
                rewritten.insert(&fact);
            }
        }
        Fragment::from_facts_and_blobs(rewritten, blobs)
    }

    fn assert_catalog_rejects(fragment: Fragment, scope_byte: u8, message: &str) {
        let fixture = Fixture::new(scope_byte);
        let storage = fixture.storage();
        storage.publish(fragment, "malformed identity").unwrap();
        let error = storage.view().unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(message),
            "unexpected validation error: {error:#}"
        );
        assert!(
            rendered.contains("does not match its intrinsic core"),
            "unexpected validation error: {error:#}"
        );
    }

    fn seed_two(storage: FilesStorage<'_>) -> (Id, Id, String) {
        let first = embedded_file(b"first file", "first.png", 0);
        let second = embedded_file(b"second file", "second.png", 1);
        let first_id = first.root().unwrap();
        let second_id = second.root().unwrap();
        let first_hash = handle_hex(
            content_handle_of(&first, first_id)
                .unwrap()
                .expect("first content"),
        );
        storage.publish(first + second, "seed files").unwrap();
        (first_id, second_id, first_hash)
    }

    fn unique_id_prefix(space: &TribleSet, entity: Id) -> String {
        let hex = format!("{entity:x}");
        (1..32)
            .find_map(|len| {
                let prefix = &hex[..len];
                (file_capability::resolve_selector(space, prefix).ok() == Some(entity))
                    .then(|| prefix.to_owned())
            })
            .expect("entity has a unique short selector")
    }

    fn unique_hash_prefix(space: &TribleSet, hash: &str, entity: Id) -> String {
        (33..64)
            .find_map(|len| {
                let prefix = &hash[..len];
                (file_capability::resolve_selector(space, prefix).ok() == Some(entity)
                    && file_capability::resolve_reference(space, prefix).ok()
                        == Some(file_capability::FileReference::Content(
                            content_handle_of(space, entity).unwrap().unwrap(),
                        )))
                .then(|| prefix.to_owned())
            })
            .expect("content has a unique short selector")
    }

    #[test]
    fn every_entity_taking_command_accepts_the_shared_selector_language() {
        let fixture = Fixture::new(0x81);
        let storage = fixture.storage();
        let (first_id, second_id, first_hash) = seed_two(storage);
        let view = storage.view().unwrap();
        let first_prefix = unique_id_prefix(&view.facts, first_id);
        let second_prefix = unique_id_prefix(&view.facts, second_id);
        let hash_prefix = unique_hash_prefix(&view.facts, &first_hash, first_id);

        let upper_prefixed = format!("files:{}", first_prefix.to_ascii_uppercase());
        cmd_show(&view, &upper_prefixed).unwrap();

        let extracted = fixture.directory.path().join("extracted.png");
        cmd_get(&view, &hash_prefix, Some(extracted.to_str().unwrap())).unwrap();
        assert_eq!(fs::read(&extracted).unwrap(), b"first file");

        cmd_tag(storage, &first_prefix, "selected").unwrap();
        let view = storage.view().unwrap();
        cmd_tree(&view, &first_prefix, None).unwrap();
        cmd_diff(&view, &first_prefix, &second_prefix).unwrap();
        cmd_similar(&view, Some(&first_prefix), None, 0.0, 10, &[], false).unwrap();
        cmd_similar(&view, Some(&first_prefix), None, 0.0, 10, &[], true).unwrap();
        cmd_resolve(&view, &hash_prefix).unwrap();
    }

    #[test]
    fn repeated_publication_and_tagging_are_idempotent() {
        let fixture = Fixture::new(0x82);
        let storage = fixture.storage();
        let file = file_capability::fragment(b"same".to_vec(), "same.txt", "text/plain").unwrap();
        storage.publish(file.clone(), "same commit").unwrap();
        let length = fs::metadata(&fixture.pile).unwrap().len();
        storage.publish(file.clone(), "same commit").unwrap();
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), length);
        assert_eq!(storage.view().unwrap().commits.len(), 1);

        let id = file.root().unwrap();
        cmd_tag(storage, &format!("{id:x}"), "stable").unwrap();
        let tagged_length = fs::metadata(&fixture.pile).unwrap().len();
        cmd_tag(storage, &format!("{id:x}"), "stable").unwrap();
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), tagged_length);
    }

    #[test]
    fn dry_run_and_immutable_reads_do_not_touch_storage() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("dry.txt");
        fs::write(&source, b"preview").unwrap();
        let missing_pile = directory.path().join("missing.pile");
        let missing_key = directory.path().join("missing.key");
        let dry_storage = FilesStorage {
            pile: &missing_pile,
            key: Some(&missing_key),
            scope: Id::new([0x83; 16]).unwrap(),
        };
        cmd_add(dry_storage, &source, None, &[], true).unwrap();
        assert!(!missing_pile.exists());
        assert!(!missing_key.exists());

        let fixture = Fixture::new(0x84);
        let storage = fixture.storage();
        storage
            .publish(
                file_capability::fragment(b"read".to_vec(), "read.txt", "text/plain").unwrap(),
                "seed read",
            )
            .unwrap();
        let length = fs::metadata(&fixture.pile).unwrap().len();
        let key = fs::read(&fixture.key).unwrap();
        let first = storage.view().unwrap();
        let second = storage.view().unwrap();
        assert_eq!(first.revision, second.revision);
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), length);
        assert_eq!(fs::read(&fixture.key).unwrap(), key);
    }

    #[test]
    fn singleton_ambiguity_fails_closed() {
        let fixture = Fixture::new(0x85);
        let storage = fixture.storage();
        let file = file_capability::fragment(b"one".to_vec(), "one.txt", "text/plain").unwrap();
        let id = file.root().unwrap();
        storage.publish(file, "seed").unwrap();
        storage
            .publish(
                entity! { ExclusiveId::force_ref(&id) @ file::name: "other.txt" },
                "invalid second name",
            )
            .unwrap();
        let error = storage.view().unwrap_err();
        assert!(format!("{error:#}").contains("file name is ambiguous"));
    }

    #[test]
    fn every_canonical_files_kind_requires_its_intrinsic_id() {
        let media_type = entity! {
            metadata::tag: &KIND_MEDIA_TYPE,
            metadata::name: "text/plain".to_owned(),
        };
        let media_type_id = media_type.root().unwrap();
        assert_catalog_rejects(
            force_entity_id(media_type, media_type_id, Id::new([0xA1; 16]).unwrap()),
            0xA0,
            "media type",
        );

        let file = file_capability::fragment(b"file".to_vec(), "file.txt", "text/plain").unwrap();
        let file_id = file.root().unwrap();
        assert_catalog_rejects(
            force_entity_id(file, file_id, Id::new([0xA3; 16]).unwrap()),
            0xA2,
            "file",
        );

        let tree = file_capability::directory_fragment(
            "directory",
            file_capability::fragment(b"child".to_vec(), "child.txt", "text/plain").unwrap(),
        );
        let directory_id = tree.root().unwrap();
        assert_catalog_rejects(
            force_entity_id(tree, directory_id, Id::new([0xA5; 16]).unwrap()),
            0xA4,
            "directory",
        );

        let import = file_capability::import_fragment(
            file_capability::fragment(b"import".to_vec(), "import.txt", "text/plain").unwrap(),
            "/tmp/import.txt",
            now_tai(),
            std::iter::empty::<String>(),
        )
        .unwrap();
        let import_id = import.import_id;
        assert_catalog_rejects(
            force_entity_id(import.fragment, import_id, Id::new([0xA7; 16]).unwrap()),
            0xA6,
            "import",
        );

        let parent =
            file_capability::fragment(b"pdf".to_vec(), "document.pdf", "application/pdf").unwrap();
        let parent_id = parent.root().unwrap();
        let page = file_capability::page_fragment(parent_id, "1", vec![0.0; embeddings::DIM_3584]);
        let page_id = file_capability::page_id(parent_id, "1");
        assert_catalog_rejects(
            parent + force_entity_id(page, page_id, Id::new([0xA9; 16]).unwrap()),
            0xA8,
            "page",
        );
    }

    #[test]
    fn one_existing_pdf_page_does_not_complete_other_requested_pages() {
        let parent = Id::new([0x86; 16]).unwrap();
        let page = file_capability::page_fragment(parent, "1", vec![0.0; embeddings::DIM_3584]);
        assert!(missing_page_parents(page.facts(), &[parent], "1").is_empty());
        assert_eq!(
            missing_page_parents(page.facts(), &[parent], "2"),
            vec![parent]
        );
    }

    fn legacy_pin(
        pile_path: &Path,
        branch: Id,
    ) -> Inline<inlineencodings::Handle<blobencodings::SimpleArchive>> {
        let mut pile = collection_access::open_pile_strict(pile_path).unwrap();
        let pin = pile.head(branch).unwrap().unwrap();
        pile.close().unwrap();
        pin
    }

    #[test]
    fn legacy_migration_preserves_atomic_commits_and_pin_and_is_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("legacy.pile");
        let key = directory.path().join("collection.key");
        File::create(&pile).unwrap();
        let repository_pile = collection_access::open_pile_strict(&pile).unwrap();
        let mut repository = Repository::new(
            repository_pile,
            SigningKey::from_bytes(&[0x91; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let branch = *repository.create_branch(FILES_BRANCH_NAME, None).unwrap();
        let mut expected = TribleSet::new();
        for (bytes, name) in [
            (b"first".as_slice(), "first.txt"),
            (b"second".as_slice(), "second.txt"),
        ] {
            let mut workspace = repository.pull(branch).unwrap();
            let file =
                file_capability::stage(&mut workspace, bytes.to_vec(), name, "text/plain").unwrap();
            expected += file.clone();
            workspace.commit(file, &format!("add {name}"));
            repository.push(&mut workspace).unwrap();
        }
        repository.close().unwrap();
        collection_access::initialize_signer(&pile, Some(&key)).unwrap();

        let storage = FilesStorage {
            pile: &pile,
            key: Some(&key),
            scope: Id::new([0x87; 16]).unwrap(),
        };
        let pin = legacy_pin(&pile, branch);
        let first = migrate_legacy(storage, None).unwrap();
        let length = fs::metadata(&pile).unwrap().len();
        let second = migrate_legacy(storage, Some(branch)).unwrap();

        assert_eq!(first.commits.len(), 2);
        assert_eq!(first.commits, second.commits);
        assert_eq!(storage.view().unwrap().facts, expected);
        assert_eq!(legacy_pin(&pile, branch), pin);
        assert_eq!(fs::metadata(&pile).unwrap().len(), length);
    }

    #[test]
    fn legacy_schema_migration_is_rejected_before_any_collection_append() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("legacy-schema.pile");
        let key = directory.path().join("collection.key");
        File::create(&pile).unwrap();
        let repository_pile = collection_access::open_pile_strict(&pile).unwrap();
        let mut repository = Repository::new(
            repository_pile,
            SigningKey::from_bytes(&[0x92; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let branch = *repository.create_branch(FILES_BRANCH_NAME, None).unwrap();
        let mut workspace = repository.pull(branch).unwrap();
        let content: FileHandle = workspace.put::<blobencodings::RawBytes, _>(b"legacy".to_vec());
        let name = workspace.put::<blobencodings::LongString, _>("legacy.txt".to_owned());
        let legacy_file = entity! {
            metadata::tag: &KIND_FILE,
            file::content: content,
            file::name: name,
            legacy_schema::mime: "text/plain",
        };
        workspace.commit(legacy_file, "legacy inline MIME");
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();
        collection_access::initialize_signer(&pile, Some(&key)).unwrap();

        let storage = FilesStorage {
            pile: &pile,
            key: Some(&key),
            scope: Id::new([0x8A; 16]).unwrap(),
        };
        let before = fs::read(&pile).unwrap();
        let error = migrate_legacy(storage, Some(branch)).unwrap_err();

        let message = format!("{error:#}");
        assert!(message.contains("preflight materialized target union"));
        assert!(message.contains("historical inline-MIME/import-time schema"));
        assert_eq!(fs::read(&pile).unwrap(), before);
    }
}
