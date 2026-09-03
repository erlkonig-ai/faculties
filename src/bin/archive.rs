use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Once;

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use faculties::archive_agy::{self, ProjectionSummary as AgyProjectionSummary};
use faculties::archive_chatgpt::{self, ProjectionSummary as ChatGptProjectionSummary};
use faculties::archive_claude_code::{self, ProjectionSummary as ClaudeCodeProjectionSummary};
use faculties::archive_claude_web::{self, ProjectionSummary as ClaudeWebProjectionSummary};
use faculties::archive_codex::{self, ProjectionSummary as CodexProjectionSummary};
use faculties::archive_collection::{
    self as archive_collection, ArchiveBlock, ArchiveImportWriter, ArchivePart, ArchivePayload,
    ArchiveProjection, ArchiveSearchSnapshot, ArchiveSnapshot, ArchiveTimelineBlock,
    ArchiveTimelineCursor,
};
use faculties::archive_copilot::{self, ProjectionSummary as CopilotProjectionSummary};
use faculties::archive_gemini::{self, ProjectionSummary as GeminiProjectionSummary};
use faculties::collection_names::open_configured;
use faculties::comb::{
    self as comb_model, CursorDraft, CursorResolution, CursorRow, CursorState, CursorTrack,
};
use faculties::schemas::blockdag as archive_schema;
use faculties::schemas::memory::{comb as comb_schema, DEFAULT_COMB_SCOPE_ID};
use faculties::storage::{load_signer, open_pile_strict, FactArchive, FactCollection};
use hifitime::Epoch;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;
use triblespace::core::collection::{CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::time::NsTAIInterval;
use triblespace::core::inline::{Inline, TryToInline};
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::SnapshotSource;
use triblespace::core::trible::Fragment;
use triblespace::prelude::{exists, find, pattern};

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "archive",
    about = "Import and query the canonical Archive block DAG"
)]
struct Cli {
    /// Path to the pile file to use.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Enable tracing spans for projection and collection derivation.
    #[arg(long)]
    trace: bool,
    /// Optional tracing filter (defaults to `info`).
    #[arg(long)]
    trace_filter: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Project one or more sources into the Archive, publishing one COMMIT each.
    ///
    /// Several PATHS are projected in ONE process: the pile is opened once and
    /// each source still gets its own signed commit. Atomicity is per source,
    /// not per process — and the open costs ~9.3 s on the live pile against ~1 s
    /// of projection for a small rollout, so a per-file process put a 3,161-file
    /// Codex backfill at ~8.2 hours of pure opening.
    Import {
        /// Source files (or a directory, where the adapter accepts one).
        #[arg(required = true, num_args = 1..)]
        path: Vec<PathBuf>,
        /// Source adapter used to interpret PATH.
        #[arg(long, value_enum, default_value = "claude-code")]
        source: ImportSource,
    },
    /// List the most recent source projections from one frozen Archive view.
    List {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Show one exact source projection by id prefix.
    Show { id: String },
    /// Show the complete canonical ancestor DAG of one source projection.
    Thread {
        id: String,
        /// Maximum accepted block count. Exceeding it is an error rather than
        /// silently hiding one fork.
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Search canonical block text through an exact portable BM25 cover.
    Search {
        #[arg(help = "Query text. Use @path for file input or @- for stdin.")]
        text: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Ensure exact raw-Succinct and portable BM25 collection derives.
    Index,
    /// Replay canonical blocks as one interleaved temporal stream.
    Replay {
        /// `start <from-ts>`, `stop`, or nothing for the next batch.
        #[arg(value_name = "ACTION")]
        action: Vec<String>,
        /// Blocks per batch. The exact block cursor makes every boundary safe.
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Include tool, thinking, event, and media-only blocks.
        #[arg(long)]
        with_tools: bool,
        /// Cursor owner. There is deliberately no default persona.
        #[arg(long, env = "PERSONA")]
        persona: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ImportSource {
    Agy,
    #[value(name = "chatgpt")]
    ChatGpt,
    ClaudeCode,
    ClaudeWeb,
    Codex,
    Copilot,
    Gemini,
}

#[derive(Clone, Copy)]
struct ArchiveStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

struct ReplayView {
    archive: ArchiveSnapshot,
    comb_facts: FactArchive,
}

impl ArchiveStorage<'_> {
    fn load(&self) -> Result<ArchiveSnapshot> {
        ArchiveSnapshot::load_local(self.pile, self.key, archive_schema::DEFAULT_SCOPE_ID)
    }

    fn load_comb(&self) -> Result<FactArchive> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = (|| {
            let source = open_configured(&mut pile, DEFAULT_COMB_SCOPE_ID, signer.verifying_key())?;
            let collection = FactCollection::new(&mut pile, source)
                .context("register maintained Comb cursor collection")?;
            let instant = faculties::clock::now()?;
            let before = pile.snapshot().context("freeze Comb source snapshot")?;
            let support = before
                .collection_at(collection.source(), instant)
                .context("observe resident Comb cursor collection")?
                .support()
                .clone();
            let after = collection
                .maintain_exact(&mut pile, &support)
                .context("maintain Comb cursor collection")?;
            after
                .collection_exact(collection.rank9(), &support)
                .context("attach exact Comb cursor collection")?
                .view::<FactArchive>()
                .context("read exact Comb cursor collection")
        })();
        finish_pile(pile, result)
    }

    /// Attach Archive and its separate Comb cursor collection at one watermark.
    ///
    /// Both foundational supports come from `before`; both maintained views
    /// are then attached through Archive's final immutable store snapshot.
    /// The cursor view therefore cannot come from a later source watermark
    /// than the Archive view read alongside it.
    fn load_replay(&self) -> Result<ReplayView> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = (|| {
            let archive_source = open_configured(
                &mut pile,
                archive_schema::DEFAULT_SCOPE_ID,
                signer.verifying_key(),
            )?;
            let archive_collections = FactCollection::new(&mut pile, archive_source)
                .context("register maintained Archive fact collection")?;
            let comb_source =
                open_configured(&mut pile, DEFAULT_COMB_SCOPE_ID, signer.verifying_key())?;
            let comb_collections = FactCollection::new(&mut pile, comb_source)
                .context("register maintained Comb cursor collection")?;

            let instant = faculties::clock::now()?;
            let before = pile
                .snapshot()
                .context("freeze Archive replay source snapshot")?;
            let comb_support = before
                .collection_at(comb_collections.source(), instant)
                .context("observe resident Comb cursor collection")?
                .support()
                .clone();

            drop(
                comb_collections
                    .maintain_exact(&mut pile, &comb_support)
                    .context("maintain Comb cursor collection")?,
            );
            let archive = ArchiveSnapshot::maintain_from(
                &mut pile,
                archive_collections,
                archive_schema::DEFAULT_SCOPE_ID,
                &before,
                instant,
            )?;
            let comb_facts = archive
                .store_snapshot()
                .collection_exact(comb_collections.rank9(), &comb_support)
                .context("attach exact Comb cursor collection")?
                .view::<FactArchive>()
                .context("read exact Comb cursor collection")?;
            Ok(ReplayView {
                archive,
                comb_facts,
            })
        })();
        finish_pile(pile, result)
    }
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    let close = pile.close();
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(close_error)) => Err(anyhow!("close Archive pile: {close_error}")),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing Archive pile after failure also failed: {close_error}"
        ))),
    }
}

fn init_tracing(enabled: bool, filter: Option<&str>) {
    static TRACE_INIT: Once = Once::new();
    if !enabled {
        return;
    }
    TRACE_INIT.call_once(|| {
        let env_filter = filter
            .map(EnvFilter::new)
            .or_else(|| {
                std::env::var("PLAYGROUND_ARCHIVE_TRACE_FILTER")
                    .ok()
                    .map(EnvFilter::new)
            })
            .unwrap_or_else(|| EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_target(false)
            .without_time()
            .with_env_filter(env_filter)
            .with_span_events(FmtSpan::CLOSE)
            .try_init();
    });
}

/// Import every PATH in one process, one signed COMMIT per source.
///
/// A failure names the path that caused it and stops: the sources already
/// committed stay committed, because each was its own atomic publication. That
/// is the property that made per-file processes look necessary; it never was.
fn run_import_all(
    storage: ArchiveStorage<'_>,
    paths: &[PathBuf],
    source: ImportSource,
) -> Result<()> {
    if paths.len() == 1 {
        return run_import(storage, &paths[0], source);
    }
    let total = paths.len();
    if source == ImportSource::Codex {
        // The batch case that matters: 3,161 refused Codex rollouts, and the
        // open is ~9.3 s against ~1 s of projection. One open, N commits.
        let mut writer = ArchiveImportWriter::open(storage.pile, storage.key)?;
        let result = (|| {
            for (index, path) in paths.iter().enumerate() {
                eprintln!("[{}/{total}] {}", index + 1, path.display());
                run_codex_into(&mut writer, path)
                    .with_context(|| format!("import {}", path.display()))?;
            }
            Ok(())
        })();
        return writer.close(result);
    }
    for (index, path) in paths.iter().enumerate() {
        eprintln!("[{}/{total}] {}", index + 1, path.display());
        run_import(storage, path, source).with_context(|| format!("import {}", path.display()))?;
    }
    Ok(())
}

fn run_import(storage: ArchiveStorage<'_>, path: &Path, source: ImportSource) -> Result<()> {
    match source {
        ImportSource::Agy => run_agy_import(storage, path),
        ImportSource::ChatGpt => run_chatgpt_import(storage, path),
        ImportSource::ClaudeCode => run_claude_code_import(storage, path),
        ImportSource::ClaudeWeb => run_claude_web_import(storage, path),
        ImportSource::Codex => run_codex_import(storage, path),
        ImportSource::Copilot => run_copilot_import(storage, path),
        ImportSource::Gemini => run_gemini_import(storage, path),
    }
}

fn run_agy_import(storage: ArchiveStorage<'_>, path: &Path) -> Result<()> {
    let mut writer = ArchiveImportWriter::open(storage.pile, storage.key)?;
    let projection = archive_agy::project_path(path, |projected| {
        writer
            .stage_fragment(projected.fragment)
            .with_context(|| format!("stage {}", projected.source_path.display()))
    });
    let (summary, commit) = writer.finish(projection)?;
    print_agy_import_summary(&summary, commit.is_some());
    Ok(())
}

fn run_chatgpt_import(storage: ArchiveStorage<'_>, path: &Path) -> Result<()> {
    let mut writer = ArchiveImportWriter::open(storage.pile, storage.key)?;
    let projection = archive_chatgpt::project_path(path, |projected| {
        writer
            .stage_fragment(projected.fragment)
            .with_context(|| format!("stage {}", projected.source_path.display()))
    });
    let (summary, commit) = writer.finish(projection)?;
    print_chatgpt_import_summary(&summary, commit.is_some());
    Ok(())
}

fn run_claude_code_import(storage: ArchiveStorage<'_>, path: &Path) -> Result<()> {
    let mut writer = ArchiveImportWriter::open(storage.pile, storage.key)?;
    let projection = archive_claude_code::project_path(path, |projected| {
        writer
            .stage_fragment(projected.fragment)
            .with_context(|| format!("stage {}", projected.source_path.display()))
    });
    let (summary, commit) = writer.finish(projection)?;
    print_claude_code_import_summary(&summary, commit.is_some());
    Ok(())
}

fn run_codex_import(storage: ArchiveStorage<'_>, path: &Path) -> Result<()> {
    let mut writer = ArchiveImportWriter::open(storage.pile, storage.key)?;
    let result = run_codex_into(&mut writer, path);
    writer.close(result)
}

/// Project one Codex rollout into an ALREADY-OPEN writer and commit it.
///
/// Split out so a batch can open the pile once and still publish one signed
/// commit per rollout — the atomicity was always per source, never per process.
fn run_codex_into(writer: &mut ArchiveImportWriter, path: &Path) -> Result<()> {
    let projection = archive_codex::project_path(path, |projected| {
        writer
            .stage_fragment(projected.fragment)
            .with_context(|| format!("stage {}", projected.source_path.display()))
    });
    let summary = projection?;
    let commit = writer.commit_unit()?;
    print_codex_import_summary(&summary, commit.is_some());
    Ok(())
}

#[allow(dead_code)]
fn run_codex_import_legacy(storage: ArchiveStorage<'_>, path: &Path) -> Result<()> {
    let mut writer = ArchiveImportWriter::open(storage.pile, storage.key)?;
    let projection = archive_codex::project_path(path, |projected| {
        writer
            .stage_fragment(projected.fragment)
            .with_context(|| format!("stage {}", projected.source_path.display()))
    });
    let (summary, commit) = writer.finish(projection)?;
    print_codex_import_summary(&summary, commit.is_some());
    Ok(())
}

fn run_claude_web_import(storage: ArchiveStorage<'_>, path: &Path) -> Result<()> {
    let mut writer = ArchiveImportWriter::open(storage.pile, storage.key)?;
    let projection = archive_claude_web::project_path(path, |projected| {
        writer
            .stage_fragment(projected.fragment)
            .with_context(|| format!("stage {}", projected.source_path.display()))
    });
    let (summary, commit) = writer.finish(projection)?;
    print_claude_web_import_summary(&summary, commit.is_some());
    Ok(())
}

fn run_copilot_import(storage: ArchiveStorage<'_>, path: &Path) -> Result<()> {
    let mut writer = ArchiveImportWriter::open(storage.pile, storage.key)?;
    let projection = archive_copilot::project_path(path, |projected| {
        writer
            .stage_fragment(projected.fragment)
            .with_context(|| format!("stage {}", projected.source_path.display()))
    });
    let (summary, commit) = writer.finish(projection)?;
    print_copilot_import_summary(&summary, commit.is_some());
    Ok(())
}

fn run_gemini_import(storage: ArchiveStorage<'_>, path: &Path) -> Result<()> {
    let mut writer = ArchiveImportWriter::open(storage.pile, storage.key)?;
    let projection = archive_gemini::project_path(path, |projected| {
        writer
            .stage_fragment(projected.fragment)
            .with_context(|| format!("stage {}", projected.source_path.display()))
    });
    let (summary, commit) = writer.finish(projection)?;
    print_gemini_import_summary(&summary, commit.is_some());
    Ok(())
}

fn print_agy_import_summary(summary: &AgyProjectionSummary, published: bool) {
    println!(
        "projected {} Antigravity transcript file(s), emitted {} fragment(s), {} source projection(s), {} content part(s)",
        summary.files_scanned,
        summary.fragments_emitted,
        summary.stats.projections_emitted,
        summary.stats.content_parts,
    );
    println!(
        "records={} transparent={} raw_only={} missing_predecessors={}",
        summary.stats.records_seen,
        summary.stats.transparent_records,
        summary.stats.raw_only_records,
        summary.stats.missing_predecessors,
    );
    print_collection_publication(published);
}

fn print_chatgpt_import_summary(summary: &ChatGptProjectionSummary, published: bool) {
    println!(
        "projected {} ChatGPT shard(s), {} conversation(s), {} mapping node(s), {} source projection(s), {} content part(s)",
        summary.files_scanned,
        summary.conversations_seen,
        summary.mapping_nodes_seen,
        summary.stats.projections_emitted,
        summary.stats.content_parts,
    );
    println!(
        "attachments={} resolved={} transparent={} raw_only={} missing_predecessors={}",
        summary.attachments_seen,
        summary.attachments_resolved,
        summary.stats.transparent_records,
        summary.stats.raw_only_records,
        summary.stats.missing_predecessors,
    );
    print_collection_publication(published);
}

fn print_claude_code_import_summary(summary: &ClaudeCodeProjectionSummary, published: bool) {
    println!(
        "projected {} Claude Code file(s), emitted {} fragment(s), {} source projection(s), {} content part(s)",
        summary.files_scanned,
        summary.fragments_emitted,
        summary.stats.source_projections,
        summary.stats.content_parts,
    );
    println!(
        "skipped={} missing_identity={} skipped_parents={} unresolved_parents={} unresolved_tool_results={} undecodable_images={}",
        summary.stats.skipped_records,
        summary.stats.missing_source_identity,
        summary.stats.skipped_parents,
        summary.stats.unresolved_parents,
        summary.stats.unresolved_tool_results,
        summary.stats.undecodable_images,
    );
    print_collection_publication(published);
}

fn print_codex_import_summary(summary: &CodexProjectionSummary, published: bool) {
    println!(
        "projected {} Codex rollout file(s), emitted {} fragment(s), {} source projection(s), {} content part(s)",
        summary.files_scanned,
        summary.fragments_emitted,
        summary.stats.source_projections,
        summary.stats.content_parts,
    );
    println!(
        "records={} skipped={} invalid_timestamps={} undecodable_assets={} frozen_bytes={} trailing_bytes_ignored={}",
        summary.stats.records_seen,
        summary.stats.skipped_records,
        summary.stats.invalid_timestamps,
        summary.stats.undecodable_assets,
        summary.frozen_bytes,
        summary.trailing_bytes_ignored,
    );
    print_collection_publication(published);
}

fn print_claude_web_import_summary(summary: &ClaudeWebProjectionSummary, published: bool) {
    println!(
        "projected {} Claude Web export file(s), emitted {} fragment(s), {} conversation(s), {} message(s), {} content part(s)",
        summary.files_scanned,
        summary.fragments_emitted,
        summary.stats.conversations,
        summary.stats.messages,
        summary.stats.common.content_parts,
    );
    println!(
        "attachments={} extracted_contents={} missing_conversation_ids={} missing_message_ids={} invalid_timestamps={} missing_predecessors={}",
        summary.stats.attachments,
        summary.stats.extracted_contents,
        summary.stats.missing_conversation_uuids,
        summary.stats.missing_message_uuids,
        summary.stats.invalid_timestamps,
        summary.stats.common.missing_predecessors,
    );
    print_collection_publication(published);
}

fn print_copilot_import_summary(summary: &CopilotProjectionSummary, published: bool) {
    println!(
        "projected {} Copilot session file(s), ignored {} unrelated JSON file(s), emitted {} fragment(s), {} source projection(s), {} content part(s)",
        summary.files_scanned,
        summary.files_ignored,
        summary.fragments_emitted,
        summary.stats.projections_emitted,
        summary.stats.content_parts,
    );
    println!(
        "records={} transparent={} raw_only={} missing_predecessors={}",
        summary.stats.records_seen,
        summary.stats.transparent_records,
        summary.stats.raw_only_records,
        summary.stats.missing_predecessors,
    );
    print_collection_publication(published);
}

fn print_gemini_import_summary(summary: &GeminiProjectionSummary, published: bool) {
    println!(
        "projected {} Gemini Takeout file(s), ignored {} unrelated HTML file(s), {} activity card(s), {} source projection(s), {} content part(s)",
        summary.files_scanned,
        summary.files_ignored,
        summary.cards_seen,
        summary.stats.projections_emitted,
        summary.stats.content_parts,
    );
    println!(
        "assets={} resolved={} transparent={} raw_only={} missing_predecessors={}",
        summary.assets_seen,
        summary.assets_resolved,
        summary.stats.transparent_records,
        summary.stats.raw_only_records,
        summary.stats.missing_predecessors,
    );
    print_collection_publication(published);
}

fn print_collection_publication(published: bool) {
    println!(
        "Archive collection: {}",
        if published {
            "one signed COMMIT published"
        } else {
            "unchanged (no novel facts)"
        }
    );
}

fn short_id(id: Id) -> String {
    format!("{id:X}").chars().take(8).collect()
}

fn snippet(text: &str, max: usize) -> String {
    let mut out = String::new();
    for (count, ch) in text.chars().enumerate() {
        if count == max {
            out.push_str("...");
            break;
        }
        out.push(if ch == '\n' || ch == '\r' { ' ' } else { ch });
    }
    out
}

fn interval_bounds(interval: Inline<NsTAIInterval>) -> Result<(Epoch, Epoch)> {
    interval
        .try_from_inline()
        .map_err(|error| anyhow!("decode Archive timestamp: {error:?}"))
}

#[cfg(test)]
fn interval_key(interval: Inline<NsTAIInterval>) -> Result<i128> {
    let (lower, _upper): (i128, i128) = interval
        .try_from_inline()
        .map_err(|error| anyhow!("decode Archive timestamp: {error:?}"))?;
    Ok(lower)
}

fn format_interval(interval: Option<Inline<NsTAIInterval>>) -> Result<String> {
    let Some(interval) = interval else {
        return Ok("<untimed>".to_owned());
    };
    let (lower, upper) = interval_bounds(interval)?;
    if lower == upper {
        Ok(lower.to_string())
    } else {
        Ok(format!("{lower}..{upper}"))
    }
}

fn projection_display_timestamp(projection: &ArchiveProjection) -> Option<Inline<NsTAIInterval>> {
    projection.source_timestamp.or(projection.block_timestamp)
}

fn entity_label(archive: &ArchiveSnapshot, id: Id, namespace: &str) -> Result<String> {
    let names = archive.names(id)?;
    if names.is_empty() {
        Ok(format!("{namespace}:{id:X}"))
    } else {
        Ok(names.join(" / "))
    }
}

fn payload_summary(payload: &ArchivePayload) -> String {
    match payload {
        ArchivePayload::Text(text) => snippet(text, 120),
        ArchivePayload::Resident { blob, media_type } => format!(
            "[resident {} bytes {}]",
            short_id(*media_type),
            hex::encode_upper(blob.raw),
        ),
        ArchivePayload::External {
            pointer,
            namespace,
            media_type,
            size,
            resolutions,
        } => format!(
            "[external {} namespace={} media={} size={} resolutions={}]",
            pointer,
            short_id(*namespace),
            media_type.map(short_id).unwrap_or_else(|| "?".to_owned()),
            size.map(|value| value.to_string())
                .unwrap_or_else(|| "?".to_owned()),
            resolutions.len(),
        ),
    }
}

fn projection_snippet(projection: &ArchiveProjection) -> String {
    let joined = projection
        .parts
        .iter()
        .map(|part| payload_summary(&part.payload))
        .collect::<Vec<_>>()
        .join(" ");
    snippet(&joined, 120)
}

fn projection_actor(projection: &ArchiveProjection) -> String {
    let mut values = Vec::new();
    if let Some(author) = &projection.raw_author {
        values.push(author.clone());
    }
    if let Some(role) = &projection.raw_role {
        values.push(role.clone());
    }
    if let Some(model) = &projection.raw_model {
        values.push(model.clone());
    }
    if values.is_empty() {
        "<unattributed>".to_owned()
    } else {
        values.join("/")
    }
}

fn render_projection_summary(projection: &ArchiveProjection) -> Result<String> {
    Ok(format!(
        "{} {} {} {}",
        short_id(projection.id),
        format_interval(projection_display_timestamp(projection))?,
        projection_actor(projection),
        projection_snippet(projection),
    ))
}

fn render_part(out: &mut String, archive: &ArchiveSnapshot, part: &ArchivePart) -> Result<()> {
    writeln!(
        out,
        "part[{}]: {} {} id={:X} fact={:X}",
        part.ordinal,
        entity_label(archive, part.modality, "modality")?,
        entity_label(archive, part.direction, "direction")?,
        part.id,
        part.fact,
    )?;
    if let Some(target) = part.responds_to {
        writeln!(out, "  responds_to: {target:X}")?;
    }
    match &part.payload {
        ArchivePayload::Text(text) => {
            writeln!(out, "  text:")?;
            for line in text.lines() {
                writeln!(out, "    {line}")?;
            }
        }
        ArchivePayload::Resident { blob, media_type } => {
            writeln!(out, "  resident_blob: {}", hex::encode_upper(blob.raw))?;
            writeln!(out, "  media_type: {media_type:X}")?;
        }
        ArchivePayload::External {
            pointer,
            namespace,
            media_type,
            size,
            resolutions,
        } => {
            writeln!(out, "  external_pointer: {pointer}")?;
            writeln!(out, "  asset_namespace: {namespace:X}")?;
            if let Some(media_type) = media_type {
                writeln!(out, "  media_type: {media_type:X}")?;
            }
            if let Some(size) = size {
                writeln!(out, "  size: {size}")?;
            }
            for resolution in resolutions {
                writeln!(out, "  resolution: {}", hex::encode_upper(resolution.raw))?;
            }
        }
    }
    Ok(())
}

fn render_projection(archive: &ArchiveSnapshot, projection: &ArchiveProjection) -> Result<String> {
    let mut out = String::new();
    writeln!(out, "projection: {:X}", projection.id)?;
    writeln!(out, "source_namespace: {:X}", projection.source_namespace)?;
    writeln!(out, "source_locator: {}", projection.source_locator)?;
    writeln!(
        out,
        "raw_record: {}",
        hex::encode_upper(projection.raw_record.raw)
    )?;
    writeln!(out, "block: {:X}", projection.block)?;
    writeln!(
        out,
        "block_timestamp: {}",
        format_interval(projection.block_timestamp)?
    )?;
    writeln!(
        out,
        "source_timestamp: {}",
        format_interval(projection.source_timestamp)?
    )?;
    for predecessor in &projection.block_previous {
        writeln!(out, "block_previous: {predecessor:X}")?;
    }
    for receipt in &projection.semantic_predecessor_support {
        writeln!(out, "semantic_predecessor_support: {receipt:X}")?;
    }
    if let Some(author) = projection.author {
        writeln!(out, "author: {author:X}")?;
    }
    if let Some(experiencer) = projection.experiencer {
        writeln!(out, "experiencer: {experiencer:X}")?;
    }
    if let Some(author) = &projection.raw_author {
        writeln!(out, "raw_author: {author}")?;
    }
    if let Some(role) = &projection.raw_role {
        writeln!(out, "raw_role: {role}")?;
    }
    if let Some(model) = &projection.raw_model {
        writeln!(out, "raw_model: {model}")?;
    }
    for path in &projection.source_paths {
        writeln!(out, "source_path: {path}")?;
    }
    for part in &projection.parts {
        render_part(&mut out, archive, part)?;
    }
    Ok(out)
}

fn run_list(storage: ArchiveStorage<'_>, limit: usize) -> Result<()> {
    let archive = storage.load()?;
    for id in archive.recent_projection_ids(limit) {
        println!("{}", render_projection_summary(&archive.projection(id)?)?);
    }
    Ok(())
}

fn run_show(storage: ArchiveStorage<'_>, prefix: &str) -> Result<()> {
    let archive = storage.load()?;
    let id = archive.resolve_projection_prefix(prefix)?;
    print!("{}", render_projection(&archive, &archive.projection(id)?)?);
    Ok(())
}

fn load_thread(
    archive: &ArchiveSnapshot,
    projection_prefix: &str,
    limit: usize,
) -> Result<Vec<ArchiveBlock>> {
    if limit == 0 {
        bail!("thread limit must be at least 1");
    }
    let leaf = archive.resolve_projection_prefix(projection_prefix)?;
    let leaf_block = archive.projection(leaf)?.block;
    let mut pending = BTreeSet::from([leaf_block]);
    let mut nodes = BTreeMap::new();
    while let Some(block) = pending.pop_first() {
        if nodes.contains_key(&block) {
            continue;
        }
        if nodes.len() == limit {
            bail!(
                "thread ancestry exceeds {limit} canonical blocks; increase --limit so no fork is hidden"
            );
        }
        let loaded = archive.block(block)?;
        pending.extend(loaded.semantic.block_previous.iter().copied());
        nodes.insert(block, loaded);
    }

    let mut indegree: BTreeMap<Id, usize> = nodes
        .iter()
        .map(|(block, loaded)| (*block, loaded.semantic.block_previous.len()))
        .collect();
    let mut children = BTreeMap::<Id, BTreeSet<Id>>::new();
    for (block, loaded) in &nodes {
        for parent in &loaded.semantic.block_previous {
            children.entry(*parent).or_default().insert(*block);
        }
    }
    let mut ready: BTreeSet<Id> = indegree
        .iter()
        .filter_map(|(block, count)| (*count == 0).then_some(*block))
        .collect();
    let mut ordered = Vec::with_capacity(nodes.len());
    while let Some(block) = ready.pop_first() {
        ordered.push(nodes[&block].clone());
        for child in children.get(&block).into_iter().flatten() {
            let count = indegree
                .get_mut(child)
                .expect("every Archive child has an indegree");
            *count -= 1;
            if *count == 0 {
                ready.insert(*child);
            }
        }
    }
    if ordered.len() != nodes.len() {
        bail!("Archive thread contains a block cycle despite catalog validation");
    }
    Ok(ordered)
}

fn render_block(
    archive: &ArchiveSnapshot,
    block: &ArchiveBlock,
    include_all_parts: bool,
) -> Result<String> {
    let mut out = String::new();
    writeln!(out, "block: {:X}", block.semantic.block)?;
    writeln!(
        out,
        "timestamp: {}",
        format_interval(block.timeline_timestamp()?)?
    )?;
    for predecessor in &block.semantic.block_previous {
        writeln!(out, "previous: {predecessor:X}")?;
    }
    for receipt in &block.receipts {
        writeln!(
            out,
            "receipt: {:X} {} {}",
            receipt.id,
            receipt.source_locator,
            projection_actor(receipt),
        )?;
    }
    for part in &block.semantic.parts {
        if include_all_parts || part.modality == archive_schema::content_fact::modality::TEXT {
            render_part(&mut out, archive, part)?;
        }
    }
    Ok(out)
}

fn run_thread(storage: ArchiveStorage<'_>, prefix: &str, limit: usize) -> Result<()> {
    let archive = storage.load()?;
    for (index, block) in load_thread(&archive, prefix, limit)?.iter().enumerate() {
        if index != 0 {
            println!("---");
        }
        print!("{}", render_block(&archive, block, true)?);
    }
    Ok(())
}

fn run_search(storage: ArchiveStorage<'_>, text: &str, limit: usize) -> Result<()> {
    let text = faculties::text_arg(text, "search text")?;
    let search = ArchiveSearchSnapshot::ensure_local(storage.pile, storage.key)?;
    for hit in search.search(&text, limit)? {
        let block = search.archive().block(hit.block)?;
        println!(
            "{:.4} {} {} receipt(s) {} {}",
            hit.score,
            short_id(hit.block),
            hit.projections.len(),
            format_interval(block.timeline_timestamp()?)?,
            projection_snippet(&block.semantic),
        );
    }
    Ok(())
}

fn run_index(storage: ArchiveStorage<'_>) -> Result<()> {
    let succinct = archive_collection::ensure_succinct_index(storage.pile, storage.key)?;
    let bm25 = archive_collection::ensure_bm25_index(storage.pile, storage.key)?;
    println!(
        "Archive: {} authored commit(s), {} distinct source element(s) covered by raw-Succinct",
        succinct.source_commits, succinct.source_elements,
    );
    println!(
        "Archive BM25: {} distinct source element(s), {} resident cover segment(s)",
        bm25.source_elements, bm25.cover_segments,
    );
    Ok(())
}

fn parse_tai_timestamp(value: &str) -> Result<Epoch> {
    let (date, time) = value
        .split_once('T')
        .ok_or_else(|| anyhow!("invalid timestamp (expected YYYY-MM-DDTHH:MM:SS): {value}"))?;
    let date = date.split('-').collect::<Vec<_>>();
    let time = time.split(':').collect::<Vec<_>>();
    if date.len() != 3 || time.len() != 3 {
        bail!("invalid timestamp (expected YYYY-MM-DDTHH:MM:SS): {value}");
    }
    Ok(Epoch::from_gregorian_tai(
        date[0].parse().context("year")?,
        date[1].parse().context("month")?,
        date[2].parse().context("day")?,
        time[0].parse().context("hour")?,
        time[1].parse().context("minute")?,
        time[2].parse().context("second")?,
        0,
    ))
}

fn cursor_state(position: Option<Epoch>, anchor: Option<Id>) -> CursorState {
    CursorState {
        position: position.map(|epoch| (epoch, epoch).try_to_inline().unwrap()),
        anchor,
        grain: None,
    }
}

/// Resolve one cursor track directly from the maintained fact archive.
///
/// The query is deliberately local to the track used by replay. Unknown or
/// undecodable rows remain inert under the open-world schema; there is no
/// whole-Comb catalog, closed-world fact accounting, or intrinsic-id check on
/// the normal read path.
fn cursor_resolution(
    facts: &FactArchive,
    stream: &str,
    persona: &str,
) -> Result<Option<CursorResolution>> {
    let members: BTreeSet<Id> = find!(
        id: Id,
        pattern!(facts, [{
            ?id @ metadata::tag: &comb_schema::kind_comb_cursor,
            comb_schema::cursor_stream: stream,
            comb_schema::cursor_persona: persona,
        }])
    )
    .collect();
    if members.is_empty() {
        return Ok(None);
    }

    let track = CursorTrack {
        stream: stream.to_owned(),
        persona: persona.to_owned(),
    };
    let mut rows = Vec::new();
    for id in members {
        let has_position = exists!(pattern!(facts, [{
            id @ comb_schema::cursor_position: _?position
        }]));
        let positions: BTreeSet<Inline<NsTAIInterval>> = find!(
            value: Inline<NsTAIInterval>,
            pattern!(facts, [{ id @ comb_schema::cursor_position: ?value }])
        )
        .filter(|value| {
            value
                .try_from_inline()
                .is_ok_and(|(lower, upper): (i128, i128)| lower == upper)
        })
        .collect();
        let has_anchor = exists!(pattern!(facts, [{
            id @ comb_schema::cursor_anchor: _?anchor
        }]));
        let anchors: BTreeSet<Id> = find!(
            value: Id,
            pattern!(facts, [{ id @ comb_schema::cursor_anchor: ?value }])
        )
        .collect();
        let has_grain = exists!(pattern!(facts, [{
            id @ comb_schema::cursor_grain: _?grain
        }]));
        let grains: BTreeSet<String> = find!(
            value: String,
            pattern!(facts, [{ id @ comb_schema::cursor_grain: ?value }])
        )
        .collect();
        let predecessors: BTreeSet<Id> = find!(
            value: Id,
            pattern!(facts, [{ id @ metadata::supersedes: ?value }])
        )
        .collect();
        let observed_at: BTreeSet<Inline<NsTAIInterval>> = find!(
            value: Inline<NsTAIInterval>,
            pattern!(facts, [{ id @ metadata::created_at: ?value }])
        )
        .filter(|value| {
            value
                .try_from_inline()
                .is_ok_and(|(lower, upper): (i128, i128)| lower == upper)
        })
        .collect();

        if positions.is_empty() {
            if !has_position && !has_anchor && !has_grain {
                rows.push(CursorRow {
                    id,
                    track: track.clone(),
                    state: CursorState {
                        position: None,
                        anchor: None,
                        grain: None,
                    },
                    predecessors,
                    observed_at,
                });
            }
            continue;
        }
        if (has_anchor && anchors.is_empty()) || (has_grain && grains.is_empty()) {
            continue;
        }

        let anchors: Vec<Option<Id>> = if anchors.is_empty() {
            vec![None]
        } else {
            anchors.into_iter().map(Some).collect()
        };
        let grains: Vec<Option<String>> = if grains.is_empty() {
            vec![None]
        } else {
            grains.into_iter().map(Some).collect()
        };
        for position in positions {
            for anchor in &anchors {
                for grain in &grains {
                    rows.push(CursorRow {
                        id,
                        track: track.clone(),
                        state: CursorState {
                            position: Some(position),
                            anchor: *anchor,
                            grain: grain.clone(),
                        },
                        predecessors: predecessors.clone(),
                        observed_at: observed_at.clone(),
                    });
                }
            }
        }
    }

    if rows.is_empty() {
        return Ok(None);
    }
    let typed_members: BTreeSet<Id> = rows.iter().map(|row| row.id).collect();
    let replaced: BTreeSet<Id> = rows
        .iter()
        .flat_map(|row| row.predecessors.iter().copied())
        .filter(|predecessor| typed_members.contains(predecessor))
        .collect();
    let mut heads: Vec<_> = rows
        .into_iter()
        .filter(|row| !replaced.contains(&row.id))
        .collect();

    heads.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| {
                left.state
                    .position
                    .map(|value| value.raw)
                    .cmp(&right.state.position.map(|value| value.raw))
            })
            .then_with(|| left.state.anchor.cmp(&right.state.anchor))
            .then_with(|| left.state.grain.cmp(&right.state.grain))
    });
    let resolution = match heads.as_slice() {
        [] => bail!("Comb cursor track ({stream}, {persona}) has no typed live head"),
        [row] => CursorResolution::Unique(row.clone()),
        rows if rows.iter().all(|row| row.state == rows[0].state) => {
            CursorResolution::Agreed(heads)
        }
        _ => CursorResolution::Forked(heads),
    };
    Ok(Some(resolution))
}

fn plan_cursor_update(
    facts: &FactArchive,
    stream: &str,
    persona: &str,
    position: Option<Epoch>,
    anchor: Option<Id>,
) -> Result<Option<Fragment>> {
    let state = cursor_state(position, anchor);
    let predecessors = match cursor_resolution(facts, stream, persona)? {
        None => BTreeSet::new(),
        Some(ref resolution) => {
            let settled = resolution.settled_state()?;
            if matches!(resolution, CursorResolution::Unique(_)) && settled == &state {
                return Ok(None);
            }
            resolution.head_ids().into_iter().collect()
        }
    };
    let (fragment, _) = comb_model::cursor_fragment(CursorDraft {
        stream: stream.to_owned(),
        persona: persona.to_owned(),
        position: state.position,
        anchor: state.anchor,
        grain: state.grain,
        predecessors,
        observed_at: BTreeSet::new(),
    })?;
    Ok(Some(fragment))
}

fn active_archive_cursor(
    facts: &FactArchive,
    stream: &str,
    persona: &str,
) -> Result<ArchiveTimelineCursor> {
    let resolution = cursor_resolution(facts, stream, persona)?.ok_or_else(|| {
        anyhow!("no active replay for persona {persona}: use `archive replay start <from>`")
    })?;
    let state = resolution.settled_state()?;
    let position = state.position.ok_or_else(|| {
        anyhow!("no active replay for persona {persona}: use `archive replay start <from>`")
    })?;
    let (lower, upper): (i128, i128) = position
        .try_from_inline()
        .map_err(|error| anyhow!("decode archive replay cursor: {error:?}"))?;
    if lower != upper {
        bail!("archive replay cursor is not a point interval");
    }
    Ok(state.anchor.map_or(
        ArchiveTimelineCursor::AfterTime(lower),
        ArchiveTimelineCursor::AfterBlock,
    ))
}

fn publish_cursor_update(storage: ArchiveStorage<'_>, fragment: Fragment) -> Result<()> {
    let signer = load_signer(storage.pile, storage.key)?;
    let mut pile = open_pile_strict(storage.pile)?;
    let result = (|| {
        let collection = open_configured(&mut pile, DEFAULT_COMB_SCOPE_ID, signer.verifying_key())?;
        pile.commit(collection, &signer, fragment)
            .context("publish archive replay cursor")?;
        Ok(())
    })();
    finish_pile(pile, result)
}

const REPLAY_STREAM: &str = "archive-replay";

fn split_replay_batch(
    timeline: Vec<ArchiveTimelineBlock>,
    limit: usize,
) -> (Vec<ArchiveTimelineBlock>, usize) {
    let remaining = timeline.len().saturating_sub(limit);
    let selected = timeline.into_iter().take(limit).collect();
    (selected, remaining)
}

fn run_replay(
    storage: ArchiveStorage<'_>,
    action: &[String],
    limit: usize,
    with_tools: bool,
    persona: Option<&str>,
) -> Result<()> {
    let Some(persona) = persona else {
        bail!("no persona: set $PERSONA or pass --persona; replay cursors are session bookkeeping");
    };
    if limit == 0 {
        bail!("replay limit must be at least 1");
    }

    match action.first().map(String::as_str) {
        Some("start") => {
            let Some(raw) = action.get(1) else {
                bail!("usage: archive replay start <YYYY-MM-DDTHH:MM:SS>");
            };
            if action.len() != 2 {
                bail!("usage: archive replay start <YYYY-MM-DDTHH:MM:SS>");
            }
            let from = parse_tai_timestamp(raw)?;
            let position = from - hifitime::Duration::from_total_nanoseconds(1);
            let facts = storage.load_comb()?;
            if let Some(fragment) =
                plan_cursor_update(&facts, REPLAY_STREAM, persona, Some(position), None)?
            {
                publish_cursor_update(storage, fragment)?;
            }
            println!("replay started at {raw} (persona {persona})");
            return Ok(());
        }
        Some("stop") => {
            if action.len() != 1 {
                bail!("usage: archive replay stop");
            }
            let facts = storage.load_comb()?;
            if let Some(fragment) = plan_cursor_update(&facts, REPLAY_STREAM, persona, None, None)?
            {
                publish_cursor_update(storage, fragment)?;
            }
            println!("replay stopped (persona {persona})");
            return Ok(());
        }
        Some(other) => bail!("unknown replay action `{other}` (start/stop or nothing)"),
        None => {}
    }

    let replay = storage.load_replay()?;
    let cursor = active_archive_cursor(&replay.comb_facts, REPLAY_STREAM, persona)?;
    let (selected, remaining) = split_replay_batch(
        replay.archive.timeline_after(cursor, |block| {
            with_tools || block.has_modality(archive_schema::content_fact::modality::TEXT)
        })?,
        limit,
    );
    if selected.is_empty() {
        println!("replay complete: nothing after the cursor. The past is read.");
        return Ok(());
    }

    for block in &selected {
        print!(
            "{}",
            render_block(&replay.archive, &block.block, with_tools)?
        );
        println!("---");
    }
    let last = selected.last().expect("selected is nonempty");
    let last_epoch =
        Epoch::from_tai_duration(hifitime::Duration::from_total_nanoseconds(last.position));
    let fragment = plan_cursor_update(
        &replay.comb_facts,
        REPLAY_STREAM,
        persona,
        Some(last_epoch),
        Some(last.block.semantic.block),
    )?
    .ok_or_else(|| anyhow!("replay emitted blocks without advancing its cursor"))?;
    publish_cursor_update(storage, fragment)?;
    println!(
        "batch: {} block(s); cursor -> {}; {} remaining",
        selected.len(),
        last_epoch,
        remaining,
    );
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.trace, cli.trace_filter.as_deref());
    let Some(command) = cli.command else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };
    let storage = ArchiveStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
    };
    match command {
        Command::Import { path, source } => run_import_all(storage, &path, source),
        Command::List { limit } => run_list(storage, limit),
        Command::Show { id } => run_show(storage, &id),
        Command::Thread { id, limit } => run_thread(storage, &id, limit),
        Command::Search { text, limit } => run_search(storage, &text, limit),
        Command::Index => run_index(storage),
        Command::Replay {
            action,
            limit,
            with_tools,
            persona,
        } => run_replay(storage, &action, limit, with_tools, persona.as_deref()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use faculties::storage::initialize_signer;
    use std::fs;

    struct Fixture {
        _directory: tempfile::TempDir,
        pile: PathBuf,
        key: PathBuf,
    }

    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("archive.pile");
        fs::File::create(&pile).unwrap();
        let key = directory.path().join("archive.key");
        initialize_signer(&pile, Some(&key)).unwrap();
        Fixture {
            _directory: directory,
            pile,
            key,
        }
    }

    fn storage(fixture: &Fixture) -> ArchiveStorage<'_> {
        ArchiveStorage {
            pile: &fixture.pile,
            key: Some(&fixture.key),
        }
    }

    fn archive_root_count(fixture: &Fixture) -> usize {
        storage(fixture).load().unwrap().commits().len()
    }

    #[test]
    fn cli_surface_has_no_branch_or_sidecar_controls() {
        let commands: BTreeSet<_> = Cli::command()
            .get_subcommands()
            .map(|command| command.get_name().to_owned())
            .collect();
        assert_eq!(
            commands,
            ["import", "index", "list", "replay", "search", "show", "thread",]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
        assert!(Cli::try_parse_from([
            "archive",
            "--pile",
            "archive.pile",
            "--branch",
            "archive",
            "list"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "archive",
            "--pile",
            "archive.pile",
            "--branch-id",
            "11111111111111111111111111111111",
            "show",
            "1111"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "archive",
            "--pile",
            "archive.pile",
            "index",
            "--prepare-in-flight",
            "4"
        ])
        .is_err());
        let default_source = Cli::try_parse_from([
            "archive",
            "--pile",
            "archive.pile",
            "import",
            "rollout.jsonl",
        ])
        .unwrap();
        assert!(matches!(
            default_source.command,
            Some(Command::Import {
                source: ImportSource::ClaudeCode,
                ..
            })
        ));
        for (spelling, expected) in [
            ("agy", ImportSource::Agy),
            ("chatgpt", ImportSource::ChatGpt),
            ("claude-code", ImportSource::ClaudeCode),
            ("claude-web", ImportSource::ClaudeWeb),
            ("codex", ImportSource::Codex),
            ("copilot", ImportSource::Copilot),
            ("gemini", ImportSource::Gemini),
        ] {
            let parsed = Cli::try_parse_from([
                "archive",
                "--pile",
                "archive.pile",
                "import",
                "source",
                "--source",
                spelling,
            ])
            .unwrap();
            assert!(matches!(
                parsed.command,
                Some(Command::Import { source, .. }) if source == expected
            ));
        }
    }

    #[test]
    fn new_source_importers_each_publish_one_validated_commit() {
        let fixture = fixture();

        let chatgpt = fixture._directory.path().join("conversations.json");
        fs::write(
            &chatgpt,
            r#"[{"id":"chatgpt-cli","mapping":{"node":{"id":"node","parent":null,"message":{"id":"message","author":{"role":"user"},"content":{"content_type":"text","parts":["chatgpt"]}}}}}]"#,
        )
        .unwrap();
        run_import(storage(&fixture), &chatgpt, ImportSource::ChatGpt).unwrap();
        assert_eq!(archive_root_count(&fixture), 1);

        let claude_web = fixture._directory.path().join("claude-web.json");
        fs::write(
            &claude_web,
            r#"[{"uuid":"claude-cli","chat_messages":[{"uuid":"message","sender":"human","text":"claude"}]}]"#,
        )
        .unwrap();
        run_import(storage(&fixture), &claude_web, ImportSource::ClaudeWeb).unwrap();
        assert_eq!(archive_root_count(&fixture), 2);

        let copilot = fixture._directory.path().join("copilot.json");
        fs::write(
            &copilot,
            r#"{"sessionId":"copilot-cli","requests":[{"requestId":"request","message":{"text":"copilot"},"response":[{"value":"answer"}]}]}"#,
        )
        .unwrap();
        run_import(storage(&fixture), &copilot, ImportSource::Copilot).unwrap();
        assert_eq!(archive_root_count(&fixture), 3);

        let agy = fixture._directory.path().join("transcript_full.jsonl");
        fs::write(
            &agy,
            concat!(
                r#"{"source":"USER_INPUT","content":"agy","step_index":1}"#,
                "\n",
            ),
        )
        .unwrap();
        run_import(storage(&fixture), &agy, ImportSource::Agy).unwrap();
        assert_eq!(archive_root_count(&fixture), 4);

        let gemini = fixture._directory.path().join("My Activity.html");
        fs::write(
            &gemini,
            concat!(
                "<html><body><div class=\"outer-cell mdl-cell mdl-cell--12-col mdl-shadow--2dp\"><div>",
                "<div class=\"header-cell\"><p>Gemini Apps<br></p></div>",
                "<div class=\"content-cell mdl-cell mdl-cell--6-col mdl-typography--body-1\">",
                "Prompted&nbsp;gemini<br>18 Sept 2025, 12:02:52 CET<br><p>answer</p>",
                "</div><div class=\"content-cell mdl-cell mdl-cell--6-col mdl-typography--body-1 mdl-typography--text-right\"></div>",
                "</div></div></body></html>",
            ),
        )
        .unwrap();
        run_import(storage(&fixture), &gemini, ImportSource::Gemini).unwrap();
        assert_eq!(archive_root_count(&fixture), 5);

        assert_eq!(storage(&fixture).load().unwrap().projection_ids().len(), 10);
    }

    #[test]
    fn cli_import_publishes_one_signed_visibility_edge() {
        let fixture = fixture();
        let source = fixture._directory.path().join("claude-code");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("parent.jsonl"),
            r#"{"type":"user","sessionId":"atomic","uuid":"root","timestamp":"2026-03-01T15:34:01Z","message":{"role":"user","content":"parent"}}"#,
        )
        .unwrap();
        fs::write(
            source.join("child.jsonl"),
            r#"{"type":"assistant","sessionId":"atomic","uuid":"child","parentUuid":"root","timestamp":"2026-03-01T15:34:02Z","message":{"role":"assistant","content":"child"}}"#,
        )
        .unwrap();

        run_import(storage(&fixture), &source, ImportSource::ClaudeCode).unwrap();
        assert_eq!(archive_root_count(&fixture), 1);
        let archive = storage(&fixture).load().unwrap();
        assert_eq!(archive.projection_ids().len(), 2);
        drop(archive);
        let after_first = fs::metadata(&fixture.pile).unwrap().len();

        run_import(storage(&fixture), &source, ImportSource::ClaudeCode).unwrap();
        assert_eq!(archive_root_count(&fixture), 1);
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), after_first);
    }

    #[test]
    fn codex_import_uses_receipt_time_and_replays_one_semantic_block_once() {
        let fixture = fixture();
        let first = fixture._directory.path().join("first-rollout.jsonl");
        let second = fixture._directory.path().join("second-rollout.jsonl");
        fs::write(
            &first,
            concat!(
                r#"{"timestamp":"2026-08-16T08:00:00Z","type":"session_meta","payload":{"id":"first-session","session_id":"first-session"}}"#,
                "\n",
                r#"{"timestamp":"2026-08-16T08:01:00Z","type":"event_msg","payload":{"type":"user_message","message":"same semantic message"}}"#,
                "\n",
            ),
        )
        .unwrap();
        fs::write(
            &second,
            concat!(
                r#"{"timestamp":"2026-08-16T08:00:00Z","type":"session_meta","payload":{"id":"second-session","session_id":"second-session"}}"#,
                "\n",
                r#"{"timestamp":"2026-08-16T08:02:00Z","type":"event_msg","payload":{"type":"user_message","message":"same semantic message"}}"#,
                "\n",
            ),
        )
        .unwrap();

        run_import(storage(&fixture), &first, ImportSource::Codex).unwrap();
        run_import(storage(&fixture), &second, ImportSource::Codex).unwrap();

        let archive = storage(&fixture).load().unwrap();
        let projection_ids = archive.projection_ids();
        assert_eq!(projection_ids.len(), 2);
        let projections = projection_ids
            .into_iter()
            .map(|id| archive.projection(id).unwrap())
            .collect::<Vec<_>>();
        assert!(projections
            .iter()
            .all(|projection| projection.block_timestamp.is_none()));
        assert!(projections
            .iter()
            .all(|projection| !render_projection_summary(projection)
                .unwrap()
                .contains("<untimed>")));

        let blocks: BTreeSet<_> = projections
            .iter()
            .map(|projection| projection.block)
            .collect();
        assert_eq!(blocks.len(), 1);
        let block = archive.block(*blocks.first().unwrap()).unwrap();
        let earliest_receipt_key = projections
            .iter()
            .map(|projection| interval_key(projection.source_timestamp.unwrap()).unwrap())
            .min()
            .unwrap();
        assert_eq!(
            interval_key(block.timeline_timestamp().unwrap().unwrap()).unwrap(),
            earliest_receipt_key
        );
        assert!(!render_block(&archive, &block, false)
            .unwrap()
            .contains("<untimed>"));

        let timeline = archive
            .timeline_after(ArchiveTimelineCursor::AfterTime(i128::MIN), |block| {
                block.has_modality(archive_schema::content_fact::modality::TEXT)
            })
            .unwrap();
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].position, earliest_receipt_key);
    }

    #[test]
    fn failed_cli_import_leaves_no_signed_archive_root() {
        let fixture = fixture();
        let source = fixture._directory.path().join("conflict");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("origin.jsonl"),
            r#"{"type":"user","sessionId":"origin","uuid":"message","message":{"role":"user","content":"origin"}}"#,
        )
        .unwrap();
        fs::write(
            source.join("fork.jsonl"),
            r#"{"type":"user","sessionId":"fork","uuid":"copy","forkedFrom":{"sessionId":"origin","messageUuid":"message"},"message":{"role":"user","content":"different"}}"#,
        )
        .unwrap();

        let error = run_import(storage(&fixture), &source, ImportSource::ClaudeCode).unwrap_err();
        assert!(format!("{error:#}").contains("conflicting semantic payloads"));
        assert_eq!(archive_root_count(&fixture), 0);
    }

    #[test]
    fn raw_succinct_and_bm25_derives_are_idempotent_and_search_works() {
        let fixture = fixture();
        let source = fixture._directory.path().join("one.jsonl");
        fs::write(
            &source,
            r#"{"type":"user","sessionId":"read","uuid":"one","timestamp":"2026-03-01T15:34:01Z","message":{"role":"user","content":"quasar needle"}}"#,
        )
        .unwrap();
        run_import(storage(&fixture), &source, ImportSource::ClaudeCode).unwrap();
        let first =
            archive_collection::ensure_succinct_index(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(first.source_commits, 1);
        assert_eq!(first.source_elements, 1);
        assert_ne!(first.source_collection, first.target_collection);
        let before = fs::metadata(&fixture.pile).unwrap().len();

        let archive = storage(&fixture).load().unwrap();
        let id = archive.projection_ids()[0];
        let projection = archive.projection(id).unwrap();
        assert!(render_projection(&archive, &projection)
            .unwrap()
            .contains("quasar needle"));
        assert_eq!(
            load_thread(&archive, &format!("{id:X}"), 10).unwrap().len(),
            1
        );
        drop(archive);
        let repeated =
            archive_collection::ensure_succinct_index(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(repeated, first);

        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), before);

        let first_bm25 =
            archive_collection::ensure_bm25_index(&fixture.pile, Some(&fixture.key)).unwrap();
        assert_eq!(first_bm25.source_commits, 1);
        assert_eq!(first_bm25.source_elements, 1);
        assert_eq!(first_bm25.cover_segments, 1);
        let after_bm25 = fs::metadata(&fixture.pile).unwrap().len();
        assert_eq!(
            archive_collection::ensure_bm25_index(&fixture.pile, Some(&fixture.key)).unwrap(),
            first_bm25
        );
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), after_bm25);

        let search =
            ArchiveSearchSnapshot::ensure_local(&fixture.pile, Some(&fixture.key)).unwrap();
        let hits = search.search("quasar", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].projections, [id]);
        drop(search);
        run_search(storage(&fixture), "quasar", 10).unwrap();
    }

    #[test]
    fn thread_keeps_every_parent_of_a_multi_parent_block() {
        let fixture = fixture();
        let source = fixture._directory.path().join("fork.jsonl");
        fs::write(
            &source,
            concat!(
                r#"{"type":"user","sessionId":"fork","uuid":"left","message":{"role":"user","content":"left"}}"#,
                "\n",
                r#"{"type":"user","sessionId":"fork","uuid":"right","message":{"role":"user","content":"right"}}"#,
                "\n",
                r#"{"type":"assistant","sessionId":"fork","uuid":"join","parentUuid":"left","message":{"role":"assistant","content":"joined"}}"#,
                "\n",
                r#"{"type":"assistant","sessionId":"fork","uuid":"join","parentUuid":"right","message":{"role":"assistant","content":"joined"}}"#,
            ),
        )
        .unwrap();
        run_import(storage(&fixture), &source, ImportSource::ClaudeCode).unwrap();
        let archive = storage(&fixture).load().unwrap();
        let joined = archive
            .projection_ids()
            .into_iter()
            .find(|id| {
                archive
                    .projection(*id)
                    .is_ok_and(|projection| projection_snippet(&projection).contains("joined"))
            })
            .unwrap();
        let thread = load_thread(&archive, &format!("{joined:X}"), 3).unwrap();
        assert_eq!(thread.len(), 3);
        let parent_count: usize = thread
            .iter()
            .map(|block| block.semantic.block_previous.len())
            .sum();
        assert_eq!(parent_count, 2);
        assert!(load_thread(&archive, &format!("{joined:X}"), 2)
            .unwrap_err()
            .to_string()
            .contains("no fork is hidden"));
    }

    #[test]
    fn replay_rejects_zero_limit_and_exact_cursor_can_split_equal_timestamps() {
        let fixture = fixture();
        let source = fixture._directory.path().join("replay.jsonl");
        fs::write(
            &source,
            concat!(
                r#"{"type":"user","sessionId":"replay","uuid":"first","timestamp":"2026-03-01T15:34:01Z","message":{"role":"user","content":"first"}}"#,
                "\n",
                r#"{"type":"user","sessionId":"replay","uuid":"second","timestamp":"2026-03-01T15:34:01Z","message":{"role":"user","content":"second"}}"#,
                "\n",
                r#"{"type":"user","sessionId":"replay","uuid":"third","timestamp":"2026-03-01T15:34:02Z","message":{"role":"user","content":"third"}}"#,
            ),
        )
        .unwrap();
        run_import(storage(&fixture), &source, ImportSource::ClaudeCode).unwrap();

        let archive = storage(&fixture).load().unwrap();
        let timeline = archive
            .timeline_after(ArchiveTimelineCursor::AfterTime(i128::MIN), |block| {
                block.has_modality(archive_schema::content_fact::modality::TEXT)
            })
            .unwrap();
        assert_eq!(timeline.len(), 3);
        assert_eq!(timeline[0].position, timeline[1].position);
        let first_cursor = timeline[0].cursor();
        let (selected, remaining) = split_replay_batch(timeline, 1);
        assert_eq!(selected.len(), 1);
        assert_eq!(remaining, 2);

        let resumed = archive
            .timeline_after(first_cursor, |block| {
                block.has_modality(archive_schema::content_fact::modality::TEXT)
            })
            .unwrap();
        assert_eq!(resumed.len(), 2, "the equal-time peer is not skipped");

        let error = run_replay(storage(&fixture), &[], 0, false, Some("replay-test")).unwrap_err();
        assert_eq!(error.to_string(), "replay limit must be at least 1");
    }
}
