use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::storage::{load_signer, open_pile_strict};
use faculties::files as file_capability;
use faculties::schemas::embeddings;
use faculties::schemas::files::{
    file, page, DEFAULT_SCOPE_ID, KIND_DIRECTORY, KIND_FILE, KIND_IMPORT, KIND_PAGE,
};
use hifitime::efmt::consts::ISO8601_DATE;
use hifitime::efmt::Formatter;
use hifitime::Epoch;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use triblespace::core::collection::Collection;
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet};
use triblespace::prelude::*;
use triblespace_search::schemas::Embedding;
use faculties::legacy_hint::open_scope;

// ── type aliases ─────────────────────────────────────────────────────────
type FileHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;
type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;
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
    /// `attr_mm7b::embedding`. Idempotent: skips already-embedded files/pages
    /// unless `--force`. The 7b model loads once (~20s cold), then ~0.5-1s per
    /// image. Needs `--features local-embed` and macOS (Metal). This is the
    /// index that powers `files similar --mm7b --text "…"` (text→image recall).
    Embed7b {
        /// Re-embed even files/pages that already carry a 7b embedding.
        #[arg(long)]
        force: bool,
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

fn read_name<R: BlobStoreGet>(space: &TribleSet, reader: &R, eid: Id) -> Option<String> {
    let (h,) = find!(
        (h: TextHandle),
        pattern!(space, [{ eid @ file::name: ?h }])
    )
    .next()?;
    let view: View<str> = reader.get(h).ok()?;
    Some(view.as_ref().to_string())
}

fn read_mime<R: BlobStoreGet>(space: &TribleSet, reader: &R, eid: Id) -> Option<String> {
    let handle = file_capability::media_type_name_handle(space, eid)?;
    let view: View<str> = reader.get(handle).ok()?;
    Some(view.as_ref().to_string())
}

/// If `eid` is a rasterized-PDF page entity, return its `(parent file id, page
/// index label)`. Used by the 7b similarity display so a page hit reads back as
/// "file X, page N" instead of a nameless entity.
fn read_page(space: &TribleSet, eid: Id) -> Option<(Id, String)> {
    find!(
        (parent: Id, idx: String),
        pattern!(space, [{ eid @ metadata::tag: &KIND_PAGE, page::parent: ?parent, page::index: ?idx }])
    )
    .next()
}

fn content_handle_of(space: &TribleSet, eid: Id) -> Option<FileHandle> {
    find!(
        (h: FileHandle),
        pattern!(space, [{ eid @ file::content: ?h }])
    )
    .next()
    .map(|(h,)| h)
}

fn is_file(space: &TribleSet, id: Id) -> bool {
    exists!(
        (h: FileHandle),
        pattern!(space, [{ id @ metadata::tag: &KIND_FILE, file::content: ?h }])
    )
}

fn is_directory(space: &TribleSet, id: Id) -> bool {
    exists!(
        (c: Id),
        pattern!(space, [{ id @ metadata::tag: &KIND_DIRECTORY, file::children: ?c }])
    )
}

fn is_import(space: &TribleSet, id: Id) -> bool {
    exists!(
        (r: Id),
        pattern!(space, [{ id @ metadata::tag: &KIND_IMPORT, file::root: ?r }])
    )
}

fn children_of(space: &TribleSet, id: Id) -> Vec<Id> {
    find!(
        (c: Id),
        pattern!(space, [{ id @ file::children: ?c }])
    )
    .map(|(c,)| c)
    .collect()
}

fn root_of(space: &TribleSet, id: Id) -> Option<Id> {
    find!(
        (r: Id),
        pattern!(space, [{ id @ file::root: ?r }])
    )
    .next()
    .map(|(r,)| r)
}

fn imported_at_of(space: &TribleSet, eid: Id) -> Option<i128> {
    find!(
        (ts: Inline<inlineencodings::NsTAIInterval>),
        pattern!(space, [{ eid @ file::imported_at: ?ts }])
    )
    .next()
    .map(|(ts,)| interval_key(ts))
}

fn source_path_of<R: BlobStoreGet>(space: &TribleSet, reader: &R, eid: Id) -> Option<String> {
    let (h,) = find!(
        (h: TextHandle),
        pattern!(space, [{ eid @ file::source_path: ?h }])
    )
    .next()?;
    let view: View<str> = reader.get(h).ok()?;
    Some(view.as_ref().to_string())
}

fn tags_of(space: &TribleSet, eid: Id) -> Vec<String> {
    find!(
        t: String,
        pattern!(space, [{ eid @ file::tag: ?t }])
    )
    .collect()
}

// ── native collection boundary ───────────────────────────────────────────

/// Open the signer-owned Files collection for append-only work, then close its
/// pile exactly once. Commands that construct a complete fragment locally do
/// not pay to reconstruct the existing collection value.
fn with_files_collection<T>(
    pile: &Path,
    f: impl FnOnce(&mut Collection<Pile>) -> Result<T>,
) -> Result<T> {
    // Authority is durable and explicit: ordinary Files commands never mint a
    // new signer and never fall back to an ephemeral identity.
    let signer = load_signer(pile, None)?;
    let storage = open_pile_strict(pile)?;
    let mut collection = open_scope(storage, DEFAULT_SCOPE_ID, signer);
    let result = f(&mut collection);
    let close = collection.into_storage().close();
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(anyhow::anyhow!("close pile: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing pile also failed: {close_error}")))
        }
    }
}

/// Open one immutable materialized Files view for commands whose result or
/// mutation depends on facts already present in the collection.
fn with_files_view<T>(
    pile: &Path,
    f: impl FnOnce(&mut Collection<Pile>, &TribleSet, &PileReader) -> Result<T>,
) -> Result<T> {
    with_files_collection(pile, |collection| {
        let space = collection
            .materialize()
            .context("materialize Files collection")?;
        let reader = collection
            .storage_mut()
            .reader()
            .context("open Files blob reader")?;
        f(collection, &space, &reader)
    })
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

/// Load mary's CLIP-ViT-B v0 (warm; ~1-2s, ~600MB) from its native model
/// collection (`CLIP_PILE` overrides the path; import with source
/// `openai/clip-vit-base-patch32` and quantization `native`). The weights and
/// named tokenizer are selected from one frozen collection snapshot; no HF
/// cache or side-file participates in runtime authority. SigLIP so400m swaps
/// in behind this same trait later.
#[cfg(feature = "local-embed")]
fn load_clip_embedder() -> Result<Box<dyn ImageEmbedder>> {
    const CLIP_MODEL: &str = "openai/clip-vit-base-patch32";
    let pile = match std::env::var_os("CLIP_PILE") {
        Some(p) => PathBuf::from(p),
        None => faculties::model_dir().join("clip.pile"),
    };
    // Which team's model graph? The pile says — this caller holds only a path.
    let team = mary::model_collection::model_graph_team_at(&pile)
        .context("read the sole model-graph team from the Mary model pile")?;
    let snapshot = mary::model_collection::load_model_collection_local_latest(&pile, team)
        .context("load native Mary CLIP model collection")?;
    let keymap = mary::selection::load_keymap_from_graph(
        snapshot.facts(),
        snapshot.reader(),
        mary::selection::ModelSelector::Source {
            source: CLIP_MODEL,
            quantization: mary::persist::QUANTIZATION_NATIVE,
        },
    )
    .context("select native CLIP weights")?;
    let tokenizer = mary::selection::load_tokenizer_from_graph(
        snapshot.facts(),
        snapshot.reader(),
        mary::selection::TokenizerSelector::Name(CLIP_MODEL),
    )
    .context("select native CLIP tokenizer")?;
    let emb = mary::embed::clip_from_parts(keymap, tokenizer, mary::embed::default_device())?;
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
        return Ok(Some(embedder.as_ref().unwrap().embed_image(bytes)?));
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

/// Default weights pile + tokenizer for the 7b. Both can be overridden, while
/// the tokenizer's ordinary fallback is resolved from the Hugging Face cache.
#[cfg(all(feature = "local-embed", target_os = "macos"))]
fn load_mm7b() -> Result<Mm7bEmbedder> {
    const MODEL: &str = "nomic-ai/nomic-embed-multimodal-7b";
    let pile = match std::env::var_os("NOMIC_MM7B_PILE") {
        Some(p) => PathBuf::from(p),
        None => faculties::model_dir().join("nomic_mm7b.pile"),
    };
    let tok = match std::env::var_os("NOMIC_MM7B_TOKENIZER") {
        Some(path) => PathBuf::from(path),
        None => {
            let path = mary::embed::hf_cache_main_snapshot(MODEL)?.join("tokenizer.json");
            anyhow::ensure!(
                path.is_file(),
                "tokenizer.json not in cached main revision for {MODEL}; set NOMIC_MM7B_TOKENIZER"
            );
            path
        }
    };
    eprintln!("files: loading nomic-embed-multimodal-7b (once, ~20s)…");
    // Which team's model graph? The pile says — this caller holds only a path.
    let team = mary::model_collection::model_graph_team_at(&pile)
        .context("read the sole model-graph team from the Mary model pile")?;
    let snapshot = mary::model_collection::load_model_collection_local_latest(&pile, team)
        .context("load native Mary MM7B model collection")?;
    mary::persist::load_nomic_mm7b_aliased_from_snapshot(
        snapshot,
        mary::selection::ModelSelector::Source {
            source: MODEL,
            quantization: mary::persist::QUANTIZATION_NATIVE,
        },
        &tok,
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
fn read_embedding_3584<R: BlobStoreGet>(reader: &R, h: Mm7bHandle) -> Result<Vec<f32>> {
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
        let mut frag = file_capability::stage(bytes, name_str, mime)?;
        if let Some(vector) = embedding {
            // Exhaust: stored under the intrinsic record id, so identity holds.
            let fid = frag.root().expect("file entity has an intrinsic id");
            let eh: EmbHandle = frag.put::<Embedding, _>(vector);
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
        let mut directory = Fragment::empty();
        let name_h: TextHandle = directory.put(dir_name.to_string());
        stats.dirs += 1;
        directory += entity! {
            metadata::tag: &KIND_DIRECTORY,
            file::name: name_h,
            file::children*: children
        };
        Ok(directory)
    } else {
        bail!("unsupported file type: {}", path.display());
    }
}

// ── commands ─────────────────────────────────────────────────────────────

fn cmd_add_dry_run(path: &Path, tags: &[String]) -> Result<()> {
    let abs_path =
        fs::canonicalize(path).with_context(|| format!("canonicalize {}", path.display()))?;
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
    Ok(())
}

fn cmd_add(
    collection: &mut Collection<Pile>,
    path: &Path,
    mime_override: Option<&str>,
    tags: &[String],
) -> Result<()> {
    let abs_path =
        fs::canonicalize(path).with_context(|| format!("canonicalize {}", path.display()))?;

    let source = abs_path.to_string_lossy().to_string();

    let mut stats = TreeStats {
        files: 0,
        dirs: 0,
        bytes: 0,
    };
    let mut embedder: Option<Box<dyn ImageEmbedder>> = None;
    let tree = build_tree(&abs_path, mime_override, &mut stats, &mut embedder)?;
    let root_id = tree.root().expect("tree has a root");
    let root_content = content_handle_of(&tree, root_id);

    // Create import entity, spreading the tree into it.
    let ts = now_tai();
    let mut import_frag = Fragment::empty();
    let source_h: TextHandle = import_frag.put(source.clone());
    import_frag += entity! {
        metadata::tag: &KIND_IMPORT,
        file::root: &root_id,
        file::imported_at: ts,
        file::source_path: source_h
    };
    let import_id = import_frag.root().expect("import has an id");
    let mut change = tree;
    change += import_frag;

    // Tags go on the import entity.
    for t in tags {
        change += entity! { ExclusiveId::force_ref(&import_id) @ file::tag: t.as_str() };
    }

    collection.commit(change).context("commit Files import")?;

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
        let h = root_content.ok_or_else(|| anyhow::anyhow!("missing content handle"))?;
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
    collection: &mut Collection<Pile>,
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

    // Write to a temp file so we can reuse build_tree / cmd_add flow.
    let tmp_dir = std::env::temp_dir().join("files-fetch");
    fs::create_dir_all(&tmp_dir).context("create temp dir")?;
    let tmp_path = tmp_dir.join(&fname);
    fs::write(&tmp_path, bytes.as_ref())
        .with_context(|| format!("write temp file {}", tmp_path.display()))?;

    let result = cmd_add(collection, &tmp_path, Some(mime.as_str()), tags);
    let _ = fs::remove_file(&tmp_path);
    let _ = fs::remove_dir(&tmp_dir);
    result
}

fn cmd_list(
    space: &TribleSet,
    reader: &PileReader,
    filter_tags: &[String],
    filter_mime: Option<&str>,
) -> Result<()> {
    let mut entries: Vec<(String, String, String, Vec<String>)> = Vec::new();

    for (eid, h) in find!(
        (eid: Id, h: FileHandle),
        pattern!(space, [{ ?eid @ metadata::tag: &KIND_FILE, file::content: ?h }])
    ) {
        let fname = read_name(space, reader, eid).unwrap_or_else(|| "?".into());
        let mime = read_mime(space, reader, eid).unwrap_or_else(|| "?".into());
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

fn cmd_resolve(space: &TribleSet, input: &str) -> Result<()> {
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

fn cmd_show(space: &TribleSet, reader: &PileReader, id: &str) -> Result<()> {
    let eid = file_capability::resolve_selector(space, id)?;

    if is_file(space, eid) {
        let h = content_handle_of(space, eid).unwrap();
        let size = reader
            .get::<anybytes::Bytes, _>(h)
            .map(|b| b.len() as u64)
            .unwrap_or(0);
        println!("Type:     file");
        println!("Hash:     {}", handle_hex(h));
        println!("Entity:   {}", fmt_id(eid));
        println!(
            "Name:     {}",
            read_name(space, reader, eid).unwrap_or("?".into())
        );
        println!(
            "MIME:     {}",
            read_mime(space, reader, eid).unwrap_or("?".into())
        );
        println!("Size:     {}", human_size(size));
    } else if is_directory(space, eid) {
        let children = children_of(space, eid);
        println!("Type:     directory");
        println!("Entity:   {}", fmt_id(eid));
        println!(
            "Name:     {}",
            read_name(space, reader, eid).unwrap_or("?".into())
        );
        println!("Children: {}", children.len());
    } else if is_import(space, eid) {
        let root = root_of(space, eid);
        let ts = imported_at_of(space, eid);
        let src = source_path_of(space, reader, eid);
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

fn cmd_get(space: &TribleSet, reader: &PileReader, id: &str, output: Option<&str>) -> Result<()> {
    let eid = file_capability::resolve_selector(space, id)?;

    // For imports, follow to root.
    let target = if is_import(space, eid) {
        root_of(space, eid).ok_or_else(|| anyhow::anyhow!("import has no root"))?
    } else {
        eid
    };

    let to_stdout = output == Some("@-");

    if is_file(space, target) {
        let h = content_handle_of(space, target)
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
                let fname = read_name(space, reader, target).unwrap_or_else(|| "file.bin".into());
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
        let dir_name = read_name(space, reader, target).unwrap_or_else(|| "extracted".into());
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

fn extract_tree<R: BlobStoreGet>(
    space: &TribleSet,
    reader: &R,
    id: Id,
    dest: &Path,
    stats: &mut TreeStats,
) -> Result<()> {
    if is_file(space, id) {
        let h =
            content_handle_of(space, id).ok_or_else(|| anyhow::anyhow!("no content for file"))?;
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
            let cname = read_name(space, reader, cid).unwrap_or_else(|| fmt_id(cid));
            extract_tree(space, reader, cid, &dest.join(&cname), stats)?;
        }
    } else {
        bail!("unknown entity kind during extraction");
    }
    Ok(())
}

fn cmd_tag(
    collection: &mut Collection<Pile>,
    space: &TribleSet,
    reader: &PileReader,
    id: &str,
    tag_name: &str,
) -> Result<()> {
    let eid = file_capability::resolve_selector(space, id)?;

    let existing = tags_of(space, eid);
    if existing.iter().any(|t| t == tag_name) {
        println!("Tag '{tag_name}' already present.");
        return Ok(());
    }

    let change = entity! { ExclusiveId::force_ref(&eid) @ file::tag: tag_name };
    collection.commit(change).context("commit Files tag")?;

    let name = read_name(space, reader, eid).unwrap_or_else(|| fmt_id(eid));
    println!("Tagged {name} with '{tag_name}'");
    Ok(())
}

fn cmd_search(space: &TribleSet, reader: &PileReader, query: &str) -> Result<()> {
    let needle = query.to_lowercase();
    let mut hits: Vec<(String, String, String, Vec<String>)> = Vec::new();

    for (eid, h) in find!(
        (eid: Id, h: FileHandle),
        pattern!(space, [{ ?eid @ metadata::tag: &KIND_FILE, file::content: ?h }])
    ) {
        let fname = read_name(space, reader, eid).unwrap_or_else(|| "?".into());
        let mime = read_mime(space, reader, eid).unwrap_or_else(|| "?".into());
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

fn cmd_imports(space: &TribleSet, reader: &PileReader) -> Result<()> {
    let mut imports: Vec<(i128, Id, Option<String>, Vec<String>)> = Vec::new();

    for (eid,) in find!(
        (eid: Id),
        pattern!(space, [{ ?eid @ metadata::tag: &KIND_IMPORT }])
    ) {
        let ts = imported_at_of(space, eid).unwrap_or(0);
        let src = source_path_of(space, reader, eid);
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

fn cmd_tree(
    space: &TribleSet,
    reader: &PileReader,
    id: &str,
    max_depth: Option<usize>,
) -> Result<()> {
    let eid = file_capability::resolve_selector(space, id)?;

    // If it's an import, follow to root.
    let root = if is_import(space, eid) {
        root_of(space, eid).ok_or_else(|| anyhow::anyhow!("import has no root"))?
    } else {
        eid
    };

    print_tree(space, reader, root, "", "", max_depth, 0);
    Ok(())
}

fn print_tree<R: BlobStoreGet>(
    space: &TribleSet,
    reader: &R,
    id: Id,
    prefix: &str,
    child_prefix: &str,
    max_depth: Option<usize>,
    depth: usize,
) {
    let name = read_name(space, reader, id).unwrap_or_else(|| fmt_id(id));

    if is_file(space, id) {
        let mime = read_mime(space, reader, id).unwrap_or_else(|| "?".into());
        let size_str = content_handle_of(space, id)
            .and_then(|h| reader.get::<anybytes::Bytes, _>(h).ok())
            .map(|b| human_size(b.len() as u64))
            .unwrap_or_else(|| "?".into());
        println!("{prefix}{name}  ({mime}, {size_str})");
    } else if is_directory(space, id) {
        let children = children_of(space, id);
        if max_depth.is_some_and(|d| depth >= d) {
            println!("{prefix}{name}/  ({} children)", children.len());
            return;
        }
        println!("{prefix}{name}/");
        let mut dirs: Vec<(String, Id)> = Vec::new();
        let mut files: Vec<(String, Id)> = Vec::new();
        for &cid in &children {
            let cname = read_name(space, reader, cid).unwrap_or_else(|| fmt_id(cid));
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
            );
        }
    } else {
        println!("{prefix}{name}  (unknown)");
    }
}

fn cmd_diff(space: &TribleSet, reader: &PileReader, left_id: &str, right_id: &str) -> Result<()> {
    let resolve_root = |raw: &str| -> Result<Id> {
        let eid = file_capability::resolve_selector(space, raw)?;
        if is_import(space, eid) {
            root_of(space, eid).ok_or_else(|| anyhow::anyhow!("import has no root"))
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
    diff_tree(space, reader, left, right, "", &mut stats);

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

fn diff_tree<R: BlobStoreGet>(
    space: &TribleSet,
    reader: &R,
    left: Id,
    right: Id,
    path: &str,
    stats: &mut DiffStats,
) {
    // Merkle shortcut: same id means identical subtree.
    if left == right {
        return;
    }

    let left_is_dir = is_directory(space, left);
    let right_is_dir = is_directory(space, right);

    // Both files — content changed.
    if !left_is_dir && !right_is_dir {
        let lname = read_name(space, reader, left).unwrap_or_else(|| "?".into());
        let lsize = file_size(space, reader, left);
        let rsize = file_size(space, reader, right);
        println!(
            "  ~ {path}{lname}  ({} → {})",
            human_size(lsize),
            human_size(rsize)
        );
        stats.modified += 1;
        return;
    }

    // Type mismatch: show as remove + add.
    if left_is_dir != right_is_dir {
        print_diff_removed(space, reader, left, path, stats);
        print_diff_added(space, reader, right, path, stats);
        return;
    }

    // Both directories — diff children by name.
    let left_children = named_children(space, reader, left);
    let right_children = named_children(space, reader, right);

    let left_name = read_name(space, reader, left).unwrap_or_else(|| "?".into());
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
                print_diff_removed(space, reader, *lid, &sub, stats);
            }
            (None, Some(_)) => {
                let (_rname, rid) = ri.next().unwrap();
                print_diff_added(space, reader, *rid, &sub, stats);
            }
            (Some((lname, _)), Some((rname, _))) => match lname.cmp(rname) {
                std::cmp::Ordering::Less => {
                    let (lname, lid) = li.next().unwrap();
                    print_diff_removed(space, reader, *lid, &sub, stats);
                    let _ = lname;
                }
                std::cmp::Ordering::Greater => {
                    let (rname, rid) = ri.next().unwrap();
                    print_diff_added(space, reader, *rid, &sub, stats);
                    let _ = rname;
                }
                std::cmp::Ordering::Equal => {
                    let (_lname, lid) = li.next().unwrap();
                    let (_rname, rid) = ri.next().unwrap();
                    diff_tree(space, reader, *lid, *rid, &sub, stats);
                }
            },
        }
    }
}

fn named_children<R: BlobStoreGet>(space: &TribleSet, reader: &R, id: Id) -> BTreeMap<String, Id> {
    let mut map = BTreeMap::new();
    for cid in children_of(space, id) {
        let name = read_name(space, reader, cid).unwrap_or_else(|| fmt_id(cid));
        map.insert(name, cid);
    }
    map
}

fn file_size<R: BlobStoreGet>(space: &TribleSet, reader: &R, id: Id) -> u64 {
    content_handle_of(space, id)
        .and_then(|h| reader.get::<anybytes::Bytes, _>(h).ok())
        .map(|b| b.len() as u64)
        .unwrap_or(0)
}

fn print_diff_added<R: BlobStoreGet>(
    space: &TribleSet,
    reader: &R,
    id: Id,
    path: &str,
    stats: &mut DiffStats,
) {
    let name = read_name(space, reader, id).unwrap_or_else(|| "?".into());
    if is_directory(space, id) {
        println!("  + {path}{name}/");
        stats.added += 1;
        let sub = format!("{path}{name}/");
        for cid in children_of(space, id) {
            print_diff_added(space, reader, cid, &sub, stats);
        }
    } else {
        let size = file_size(space, reader, id);
        println!("  + {path}{name}  ({})", human_size(size));
        stats.added += 1;
    }
}

fn print_diff_removed<R: BlobStoreGet>(
    space: &TribleSet,
    reader: &R,
    id: Id,
    path: &str,
    stats: &mut DiffStats,
) {
    let name = read_name(space, reader, id).unwrap_or_else(|| "?".into());
    if is_directory(space, id) {
        println!("  - {path}{name}/");
        stats.removed += 1;
        let sub = format!("{path}{name}/");
        for cid in children_of(space, id) {
            print_diff_removed(space, reader, cid, &sub, stats);
        }
    } else {
        let size = file_size(space, reader, id);
        println!("  - {path}{name}  ({})", human_size(size));
        stats.removed += 1;
    }
}

// ── main ─────────────────────────────────────────────────────────────────

/// Read a stored embedding blob back into a plain `Vec<f32>`.
fn read_embedding<R: BlobStoreGet>(reader: &R, h: EmbHandle) -> Result<Vec<f32>> {
    let v: anybytes::View<[f32]> = reader
        .get(h)
        .map_err(|e| anyhow::anyhow!("read embedding blob: {e:?}"))?;
    Ok(v.as_ref().to_vec())
}

/// Embed every image file with nomic-embed-multimodal-7b and store the 3584-d
/// vector on `attr_mm7b::embedding` (under the file's intrinsic record id, so
/// identity is unaffected — pure exhaust). Additive to the CLIP `file::embedding`
/// path: both coexist. Idempotent — already-embedded files are skipped unless
/// `--force`. Identical bytes (duplicate imports) are embedded once and the
/// vector fanned out to every entity that shares the content.
fn cmd_embed7b(
    collection: &mut Collection<Pile>,
    space: &TribleSet,
    reader: &PileReader,
    force: bool,
) -> Result<()> {
    // Gather image file entities, grouped by content hash so identical bytes are
    // embedded once. Skip SVG (not a raster the vision tower can decode).
    let mut groups: BTreeMap<String, (FileHandle, Vec<(Id, bool)>)> = BTreeMap::new();
    for (eid, h) in find!(
        (eid: Id, h: FileHandle),
        pattern!(space, [{ ?eid @ metadata::tag: &KIND_FILE, file::content: ?h }])
    ) {
        let mime = read_mime(space, reader, eid).unwrap_or_default();
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
        .filter(|(_, (_, eids))| force || eids.iter().any(|(_, has)| !*has))
        .collect();

    let total_imgs: usize = pending.iter().map(|(_, (_, e))| e.len()).sum();
    if pending.is_empty() {
        println!("All image files already have a 7b embedding (use --force to re-embed).");
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
            if *has && !force {
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

    collection
        .commit(change)
        .context("commit Files 7b embeddings")?;

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

/// Embed PDF *pages* into the 3584-d 7b space. Each page becomes a page entity
/// (`KIND_PAGE`, `page::parent` → file, `page::index` → 1-based number) carrying
/// the shared `embeddings::attr_mm7b::embedding`, so `files similar --mm7b`
/// ranks pages and a hit resolves to "file X, page N". Idempotent: a file whose
/// pages already exist is skipped unless `--force`; page entity ids are intrinsic
/// (derived from parent+index), so re-runs merge rather than duplicate. Unique
/// PDF bytes are rendered+embedded once and the per-page vectors fan out to every
/// file entity that shares the content.
fn cmd_embed7b_pdf(
    collection: &mut Collection<Pile>,
    space: &TribleSet,
    reader: &PileReader,
    force: bool,
    dpi: u32,
    file_limit: usize,
    max_pages: usize,
) -> Result<()> {
    // Gather PDF file entities grouped by content hash (render once per unique
    // bytes, fan pages out to every sibling file entity).
    let mut groups: BTreeMap<String, (FileHandle, Vec<Id>)> = BTreeMap::new();
    for (eid, h) in find!(
        (eid: Id, h: FileHandle),
        pattern!(space, [{ ?eid @ metadata::tag: &KIND_FILE, file::content: ?h }])
    ) {
        if read_mime(space, reader, eid).as_deref() != Some("application/pdf") {
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

    // A file entity is "done" if any page already references it as parent.
    let has_pages = |eid: Id| -> bool {
        exists!(
            (p: Id),
            pattern!(space, [{ ?p @ metadata::tag: &KIND_PAGE, page::parent: eid }])
        )
    };

    // Keep only groups with at least one file entity still needing work.
    let mut pending: Vec<(String, FileHandle, Vec<Id>)> = groups
        .into_iter()
        .filter_map(|(hash, (h, eids))| {
            let todo: Vec<Id> = if force {
                eids
            } else {
                eids.into_iter().filter(|e| !has_pages(*e)).collect()
            };
            (!todo.is_empty()).then_some((hash, h, todo))
        })
        .collect();

    if pending.is_empty() {
        println!("All PDF files already have page embeddings (use --force to re-embed).");
        return Ok(());
    }
    pending.sort_by(|a, b| a.0.cmp(&b.0));
    if file_limit > 0 && pending.len() > file_limit {
        pending.truncate(file_limit);
    }
    let pending_pdfs = pending.len();

    let embedder = load_mm7b_opt()?;

    let mut change = Fragment::empty();
    let mut pdfs_done = 0usize;
    let mut pages_embedded = 0usize;
    let mut failed = 0usize;
    for (hash, content, eids) in &pending {
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
        let mut this_pages = 0usize;
        for (page_no, png) in &pages {
            let v = match mm7b_embed_image(&embedder, png) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("  {hash} page {page_no}: embed failed: {e:#}");
                    failed += 1;
                    continue;
                }
            };
            let idx_label = page_no.to_string();
            let handle: Mm7bHandle = change.put::<embeddings::Embedding3584, _>(v);
            for eid in eids {
                // Intrinsic page id from (parent, index): stable across re-runs.
                let page_id = entity! { _ @
                    page::parent: *eid,
                    page::index: idx_label.clone(),
                }
                .root()
                .expect("entity! derives a root id");
                change += entity! { ExclusiveId::force_ref(&page_id) @
                    metadata::tag: &KIND_PAGE,
                    page::parent: *eid,
                    page::index: idx_label.clone(),
                    embeddings::attr_mm7b::embedding: handle,
                };
            }
            this_pages += 1;
            pages_embedded += 1;
        }
        pdfs_done += 1;
        eprintln!(
            "  {hash}: {this_pages} pages → {} entities",
            this_pages * eids.len()
        );
    }

    if change.is_empty() {
        println!("Nothing to commit (PDFs {pdfs_done}, failed {failed}).");
        return Ok(());
    }

    collection
        .commit(change)
        .context("commit Files PDF page embeddings")?;

    println!(
        "7b-embedded {pages_embedded} pages across {pdfs_done} PDFs (of {pending_pdfs} pending){}",
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
    space: &TribleSet,
    reader: &PileReader,
    id: Option<&str>,
    text: Option<&str>,
    floor: f32,
    limit: usize,
    filter_tags: &[String],
    mm7b: bool,
) -> Result<()> {
    if mm7b {
        return cmd_similar_mm7b(space, reader, id, text, floor, limit, filter_tags);
    }

    // The query vector + a label, from either a text string (cross-modal) or a
    // query file's stored embedding. `query_eid` is Some only for a file query,
    // so it drops itself from its own results.
    let (query_vec, query_eid, label): (Vec<f32>, Option<Id>, String) = match (text, id) {
        (Some(t), _) => (embed_text_query(t)?, None, format!("{t:?}")),
        (None, Some(idstr)) => {
            let eid = file_capability::resolve_selector(space, idstr)?;
            let h: EmbHandle = find!(
                (h: EmbHandle),
                pattern!(space, [{ eid @ file::embedding: ?h }])
            )
            .map(|(h,)| h)
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "that file has no embedding — only image/* files are embedded \
                     on `add` (re-add it), or query with --text instead"
                )
            })?;
            let name = read_name(space, reader, eid).unwrap_or_else(|| "?".into());
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
        let name = read_name(space, reader, *eid).unwrap_or_else(|| "?".into());
        let mime = read_mime(space, reader, *eid).unwrap_or_else(|| "?".into());
        let hash = content_handle_of(space, *eid)
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
    space: &TribleSet,
    reader: &PileReader,
    id: Option<&str>,
    text: Option<&str>,
    floor: f32,
    limit: usize,
    filter_tags: &[String],
) -> Result<()> {
    let (query_vec, query_eid, label): (Vec<f32>, Option<Id>, String) = match (text, id) {
        (Some(t), _) => {
            let embedder = load_mm7b_opt()?;
            (mm7b_embed_query(&embedder, t)?, None, format!("{t:?}"))
        }
        (None, Some(idstr)) => {
            let eid = file_capability::resolve_selector(space, idstr)?;
            let h: Mm7bHandle = find!(
                (h: Mm7bHandle),
                pattern!(space, [{ eid @ embeddings::attr_mm7b::embedding: ?h }])
            )
            .map(|(h,)| h)
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "that file has no 7b embedding — run `files embed-7b` first, \
                     or query with --text instead"
                )
            })?;
            let name = read_name(space, reader, eid).unwrap_or_else(|| "?".into());
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
        let (display_eid, page_suffix) = match read_page(space, *eid) {
            Some((parent, idx)) => (parent, format!("  page {idx}")),
            None => (*eid, String::new()),
        };
        let name = read_name(space, reader, display_eid).unwrap_or_else(|| "?".into());
        let mime = read_mime(space, reader, display_eid).unwrap_or_else(|| "?".into());
        let hash = content_handle_of(space, display_eid)
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

fn run_command(pile: &Path, command: Command) -> Result<()> {
    match command {
        Command::Add {
            path,
            mime,
            tag,
            dry_run,
        } => {
            if dry_run {
                cmd_add_dry_run(&path, &tag)
            } else {
                with_files_collection(pile, |collection| {
                    cmd_add(collection, &path, mime.as_deref(), &tag)
                })
            }
        }
        Command::List { tag, mime } => with_files_view(pile, |_collection, space, reader| {
            cmd_list(space, reader, &tag, mime.as_deref())
        }),
        Command::Show { id } => with_files_view(pile, |_collection, space, reader| {
            cmd_show(space, reader, &id)
        }),
        Command::Get { id, output } => with_files_view(pile, |_collection, space, reader| {
            cmd_get(space, reader, &id, output.as_deref())
        }),
        Command::Tag { id, name } => with_files_view(pile, |collection, space, reader| {
            cmd_tag(collection, space, reader, &id, &name)
        }),
        Command::Fetch {
            url,
            mime,
            name,
            tag,
            max_bytes,
        } => with_files_collection(pile, |collection| {
            cmd_fetch(
                collection,
                &url,
                mime.as_deref(),
                name.as_deref(),
                &tag,
                max_bytes,
            )
        }),
        Command::Search { query } => with_files_view(pile, |_collection, space, reader| {
            cmd_search(space, reader, &query)
        }),
        Command::Similar {
            id,
            text,
            floor,
            limit,
            tag,
            mm7b,
        } => with_files_view(pile, |_collection, space, reader| {
            cmd_similar(
                space,
                reader,
                id.as_deref(),
                text.as_deref(),
                floor,
                limit,
                &tag,
                mm7b,
            )
        }),
        Command::Embed7b {
            force,
            pdf,
            dpi,
            limit,
            max_pages,
        } => with_files_view(pile, |collection, space, reader| {
            if pdf {
                cmd_embed7b_pdf(collection, space, reader, force, dpi, limit, max_pages)
            } else {
                cmd_embed7b(collection, space, reader, force)
            }
        }),
        Command::Imports => with_files_view(pile, |_collection, space, reader| {
            cmd_imports(space, reader)
        }),
        Command::Tree { id, depth } => with_files_view(pile, |_collection, space, reader| {
            cmd_tree(space, reader, &id, depth)
        }),
        Command::Resolve { input } => with_files_view(pile, |_collection, space, _reader| {
            cmd_resolve(space, &input)
        }),
        Command::Diff { left, right } => with_files_view(pile, |_collection, space, reader| {
            cmd_diff(space, reader, &left, &right)
        }),
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let Some(command) = cli.command else {
        Cli::command().print_help()?;
        return Ok(());
    };

    run_command(&cli.pile, command)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "local-embed")]
    use ed25519_dalek::SigningKey;
    use faculties::storage::initialize_signer;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_PILE: AtomicU64 = AtomicU64::new(0);

    #[cfg(feature = "local-embed")]
    const WORDPIECE: &str = r###"{
      "added_tokens": [],
      "normalizer": {"type": "BertNormalizer", "clean_text": true,
                     "handle_chinese_chars": true, "strip_accents": null,
                     "lowercase": true},
      "pre_tokenizer": {"type": "BertPreTokenizer"},
      "decoder": {"type": "WordPiece", "prefix": "##", "cleanup": true},
      "model": {"type": "WordPiece", "unk_token": "[UNK]",
                "continuing_subword_prefix": "##",
                "max_input_chars_per_word": 100,
                "vocab": {"[UNK]": 0, "hello": 1}}
    }"###;

    #[cfg(feature = "local-embed")]
    const LATER_WORDPIECE: &str = r###"{
      "added_tokens": [],
      "normalizer": {"type": "BertNormalizer", "clean_text": true,
                     "handle_chinese_chars": true, "strip_accents": null,
                     "lowercase": true},
      "pre_tokenizer": {"type": "BertPreTokenizer"},
      "decoder": {"type": "WordPiece", "prefix": "##", "cleanup": true},
      "model": {"type": "WordPiece", "unk_token": "[UNK]",
                "continuing_subword_prefix": "##",
                "max_input_chars_per_word": 100,
                "vocab": {"[UNK]": 0, "later": 1}}
    }"###;

    struct TestPile {
        dir: PathBuf,
        path: PathBuf,
    }

    impl TestPile {
        fn new() -> Self {
            let nonce = NEXT_TEST_PILE.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "faculties-files-selector-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join("test.pile");
            fs::File::create(&path).unwrap();
            initialize_signer(&path, None).unwrap();
            Self { dir, path }
        }
    }

    impl Drop for TestPile {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[cfg(feature = "local-embed")]
    fn native_model_fragment(source: &str, tensor_name: &str, value: f32) -> Fragment {
        use mary::format::attrs;

        let mut fragment = Fragment::empty();
        let data = fragment.put::<mary::format::F32Array, _>(vec![value]);
        let shape = fragment.put::<mary::format::U64Array, _>(vec![1_u64]);
        let leaf = entity! { _ @ attrs::data: data, attrs::shape: shape };
        let leaf_id = leaf.root().unwrap();
        fragment += leaf;

        let tensor_name = fragment.put::<blobencodings::UTF8String, _>(tensor_name.to_owned());
        let member = entity! { _ @
            attrs::kind: "vector",
            attrs::safetensor_path: tensor_name,
            attrs::weight: &leaf_id,
        };
        let member_id = member.root().unwrap();
        fragment += member;

        let root = entity! { _ @ attrs::member: &member_id };
        let root_id = root.root().unwrap();
        fragment += root;
        let source = fragment.put::<blobencodings::UTF8String, _>(source.to_owned());
        fragment += entity! { ExclusiveId::force_ref(&root_id) @
            attrs::source: source,
            attrs::quantization: "native",
        };
        fragment
    }

    #[cfg(feature = "local-embed")]
    fn native_tokenizer_fragment(source: &str, json: &str) -> Fragment {
        let mut fragment = Fragment::empty();
        let tokenizer =
            mary::tokenizer::save_tokenizer_json(json.as_bytes(), source, fragment.blobs_mut())
                .unwrap();
        fragment += tokenizer;
        fragment
    }

    #[cfg(feature = "local-embed")]
    #[test]
    fn native_clip_parts_are_selected_from_one_explicit_snapshot() {
        const CLIP_MODEL: &str = "clip/target";
        let test_pile = TestPile::new();
        let signer = SigningKey::from_bytes(&[0x73; 32]);
        // A team of one: this fixture signs its own model graph, so its key is
        // also the team that graph is rooted at.
        let team = signer.verifying_key();
        let mut pile = Pile::open(&test_pile.path).unwrap();
        mary::model_collection::publish_model_fragment(
            &mut pile,
            team,
            &signer,
            native_model_fragment(CLIP_MODEL, "target.weight", 1.0),
        )
        .unwrap();
        mary::model_collection::publish_model_fragment(
            &mut pile,
            team,
            &signer,
            native_model_fragment("clip/distractor", "distractor.weight", 2.0),
        )
        .unwrap();
        mary::model_collection::publish_model_fragment(
            &mut pile,
            team,
            &signer,
            native_tokenizer_fragment(CLIP_MODEL, WORDPIECE),
        )
        .unwrap();
        pile.close().unwrap();

        let frozen =
            mary::model_collection::load_model_collection_local_latest(&test_pile.path, team).unwrap();
        let selected = mary::selection::load_keymap_from_graph(
            frozen.facts(),
            frozen.reader(),
            mary::selection::ModelSelector::Source {
                source: CLIP_MODEL,
                quantization: mary::persist::QUANTIZATION_NATIVE,
            },
        )
        .unwrap();
        let tokenizer = mary::selection::load_tokenizer_from_graph(
            frozen.facts(),
            frozen.reader(),
            mary::selection::TokenizerSelector::Name(CLIP_MODEL),
        )
        .unwrap();
        assert_eq!(selected["target.weight"], (vec![1.0], vec![1]));
        assert!(!selected.contains_key("distractor.weight"));
        assert_eq!(tokenizer.token_to_id("hello"), Some(1));

        let mut pile = Pile::open(&test_pile.path).unwrap();
        mary::model_collection::publish_model_fragment(
            &mut pile,
            team,
            &signer,
            native_model_fragment(CLIP_MODEL, "later.weight", 3.0),
        )
        .unwrap();
        mary::model_collection::publish_model_fragment(
            &mut pile,
            team,
            &signer,
            native_tokenizer_fragment(CLIP_MODEL, LATER_WORDPIECE),
        )
        .unwrap();
        pile.close().unwrap();

        let still_selected = mary::selection::load_keymap_from_graph(
            frozen.facts(),
            frozen.reader(),
            mary::selection::ModelSelector::Source {
                source: CLIP_MODEL,
                quantization: mary::persist::QUANTIZATION_NATIVE,
            },
        )
        .unwrap();
        let still_tokenizer = mary::selection::load_tokenizer_from_graph(
            frozen.facts(),
            frozen.reader(),
            mary::selection::TokenizerSelector::Name(CLIP_MODEL),
        )
        .unwrap();
        assert_eq!(still_selected["target.weight"], (vec![1.0], vec![1]));
        assert!(!still_selected.contains_key("later.weight"));
        assert_eq!(still_tokenizer.token_to_id("hello"), Some(1));
        assert_eq!(still_tokenizer.token_to_id("later"), None);

        let latest =
            mary::model_collection::load_model_collection_local_latest(&test_pile.path, team).unwrap();
        let model_error = mary::selection::load_keymap_from_graph(
            latest.facts(),
            latest.reader(),
            mary::selection::ModelSelector::Source {
                source: CLIP_MODEL,
                quantization: mary::persist::QUANTIZATION_NATIVE,
            },
        )
        .unwrap_err();
        assert!(
            model_error.to_string().contains("ambiguous"),
            "{model_error}"
        );
        let tokenizer_error = mary::selection::load_tokenizer_from_graph(
            latest.facts(),
            latest.reader(),
            mary::selection::TokenizerSelector::Name(CLIP_MODEL),
        )
        .unwrap_err();
        assert!(
            tokenizer_error.to_string().contains("ambiguous"),
            "{tokenizer_error}"
        );
    }

    #[test]
    fn empty_native_collection_opens_as_an_empty_catalog() {
        let test_pile = TestPile::new();
        with_files_view(&test_pile.path, |_collection, space, _reader| {
            assert!(space.is_empty());
            cmd_list(space, _reader, &[], None)
        })
        .unwrap();
    }

    #[test]
    fn add_dry_run_needs_neither_signer_nor_pile() {
        let nonce = NEXT_TEST_PILE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "faculties-files-dry-run-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let input = dir.join("local.txt");
        fs::write(&input, b"local preview").unwrap();
        let absent_pile = dir.join("must-not-be-opened.pile");

        run_command(
            &absent_pile,
            Command::Add {
                path: input,
                mime: None,
                tag: vec!["preview".to_owned()],
                dry_run: true,
            },
        )
        .unwrap();

        assert!(!absent_pile.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn independent_commits_materialize_for_list_show_and_get() {
        let test_pile = TestPile::new();
        let first =
            file_capability::stage(b"first file".to_vec(), "first.png", "image/png").unwrap();
        let second =
            file_capability::stage(b"second file".to_vec(), "second.txt", "text/plain").unwrap();
        let first_id = first.root().unwrap();
        let second_id = second.root().unwrap();

        with_files_collection(&test_pile.path, |collection| {
            collection.commit(first).context("commit first fixture")?;
            collection.commit(second).context("commit second fixture")?;
            Ok(())
        })
        .unwrap();

        let first_out = test_pile.dir.join("first.png");
        let second_out = test_pile.dir.join("second.txt");
        with_files_view(&test_pile.path, |_collection, space, reader| {
            assert_eq!(
                find!(
                    entity: Id,
                    pattern!(space, [{ ?entity @ metadata::tag: &KIND_FILE }])
                )
                .collect::<BTreeSet<_>>()
                .len(),
                2
            );
            cmd_list(space, reader, &[], None)?;
            cmd_show(space, reader, &format!("{first_id:x}"))?;
            cmd_show(space, reader, &format!("{second_id:x}"))?;
            cmd_get(
                space,
                reader,
                &format!("{first_id:x}"),
                Some(first_out.to_str().unwrap()),
            )?;
            cmd_get(
                space,
                reader,
                &format!("{second_id:x}"),
                Some(second_out.to_str().unwrap()),
            )
        })
        .unwrap();
        assert_eq!(fs::read(first_out).unwrap(), b"first file");
        assert_eq!(fs::read(second_out).unwrap(), b"second file");
    }

    #[test]
    fn replaying_one_complete_fragment_is_idempotent() {
        let test_pile = TestPile::new();
        let file = file_capability::stage(b"same".to_vec(), "same.txt", "text/plain").unwrap();
        let file_id = file.root().unwrap();

        with_files_collection(&test_pile.path, |collection| {
            let first = collection.commit(file.clone()).context("first replay")?;
            let second = collection.commit(file).context("second replay")?;
            assert_eq!(first.id(), second.id());
            Ok(())
        })
        .unwrap();

        with_files_view(&test_pile.path, |_collection, space, _reader| {
            assert_eq!(
                file_capability::resolve_selector(space, &format!("{file_id:x}"))?,
                file_id
            );
            assert_eq!(
                find!(
                    entity: Id,
                    pattern!(space, [{ ?entity @ metadata::tag: &KIND_FILE }])
                )
                .collect::<BTreeSet<_>>()
                .len(),
                1
            );
            Ok(())
        })
        .unwrap();
    }
}
