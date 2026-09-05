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
    self as archive_collection, ArchiveImportWriter, ArchiveTimelineBlock, ArchiveTimelineCursor,
};
use faculties::archive_copilot::{self, ProjectionSummary as CopilotProjectionSummary};
use faculties::archive_gemini::{self, ProjectionSummary as GeminiProjectionSummary};
use faculties::collection_names::open_configured;
use faculties::comb::{self as comb_model, CursorDraft, CursorResolution, CursorState};
use faculties::schemas::blockdag as archive_schema;
use faculties::schemas::memory::DEFAULT_COMB_SCOPE_ID;
use faculties::storage::{load_signer, open_pile_strict, FactArchive, FactCollection};
use hifitime::Epoch;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;
use triblespace::core::collection::{
    CollectionSnapshot, CollectionSnapshotExt, CollectionStoreExt,
};
use triblespace::core::id::Id;
use triblespace::core::inline::{Inline, TryFromInline, TryToInline};
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::{BlobStoreGet, SnapshotSource};
use triblespace::core::trible::Fragment;

use anybytes::View;
use triblespace::core::blob::encodings::succinctarchive::Rank9AcceleratedSuccinctArchiveBlob;
use triblespace::core::metadata;
use triblespace::prelude::blobencodings::{RawBytes, UTF8String};
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::{exists, find, pattern};
use triblespace_search::tokens::hash_tokens;

type FactSnapshot = CollectionSnapshot<PileSnapshot, Rank9AcceleratedSuccinctArchiveBlob>;
type TextHandle = Inline<Handle<UTF8String>>;
type RawHandle = Inline<Handle<RawBytes>>;

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
    archive: FactSnapshot,
    comb_facts: FactArchive,
}

impl ArchiveStorage<'_> {
    fn load(&self) -> Result<FactSnapshot> {
        pollster::block_on(archive_collection::ensure_local(self.pile, self.key))
    }

    fn load_comb(&self) -> Result<FactArchive> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = pollster::block_on(async {
            let source = open_configured(&mut pile, DEFAULT_COMB_SCOPE_ID, signer.verifying_key())?;
            let collection = FactCollection::new(&mut pile, source)
                .context("register maintained Comb cursor collection")?;
            let prepared = pile
                .ensure(collection.source())
                .await
                .context("ensure Comb source dependencies")?;
            let support = prepared
                .collection(collection.source())
                .context("observe Comb cursor support")?
                .support()
                .clone();
            drop(prepared);
            let after = collection
                .maintain_exact(&mut pile, &support)
                .await
                .context("maintain Comb cursor collection")?;
            after
                .collection_exact(collection.rank9(), &support)
                .context("attach exact Comb cursor collection")?
                .view::<FactArchive>()
                .context("read exact Comb cursor collection")
        });
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
        let result = pollster::block_on(async {
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

            // Acquire both root closures before selecting either support.
            // One later observation supplies the common semantic watermark.
            drop(
                pile.ensure(archive_collections.source())
                    .await
                    .context("ensure Archive source dependencies")?,
            );
            drop(
                pile.ensure(comb_collections.source())
                    .await
                    .context("ensure Comb cursor dependencies")?,
            );
            let before = pile
                .snapshot()
                .context("freeze Archive replay source snapshot")?;
            let comb_support = before
                .collection(comb_collections.source())
                .context("observe Comb cursor support")?
                .support()
                .clone();
            let archive_support = before
                .collection(archive_collections.source())
                .context("observe Archive support")?
                .support()
                .clone();
            drop(before);

            drop(
                comb_collections
                    .maintain_exact(&mut pile, &comb_support)
                    .await
                    .context("maintain Comb cursor collection")?,
            );
            let after = archive_collections
                .maintain_exact(&mut pile, &archive_support)
                .await
                .context("maintain Archive replay facts")?;
            let archive = after
                .collection_exact(archive_collections.rank9(), &archive_support)
                .context("attach exact Archive replay facts")?;
            let comb_facts = after
                .collection_exact(comb_collections.rank9(), &comb_support)
                .context("attach exact Comb cursor collection")?
                .view::<FactArchive>()
                .context("read exact Comb cursor collection")?;
            Ok(ReplayView {
                archive,
                comb_facts,
            })
        });
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
        let mut writer = pollster::block_on(ArchiveImportWriter::open(storage.pile, storage.key))?;
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
    let mut writer = pollster::block_on(ArchiveImportWriter::open(storage.pile, storage.key))?;
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
    let mut writer = pollster::block_on(ArchiveImportWriter::open(storage.pile, storage.key))?;
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
    let mut writer = pollster::block_on(ArchiveImportWriter::open(storage.pile, storage.key))?;
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
    let mut writer = pollster::block_on(ArchiveImportWriter::open(storage.pile, storage.key))?;
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
    let mut writer = pollster::block_on(ArchiveImportWriter::open(storage.pile, storage.key))?;
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
    let mut writer = pollster::block_on(ArchiveImportWriter::open(storage.pile, storage.key))?;
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
    let mut writer = pollster::block_on(ArchiveImportWriter::open(storage.pile, storage.key))?;
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
    let mut writer = pollster::block_on(ArchiveImportWriter::open(storage.pile, storage.key))?;
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

fn format_interval(interval: Option<(i128, i128)>) -> String {
    let Some((lower, upper)) = interval else {
        return "<untimed>".to_owned();
    };
    let lower = Epoch::from_tai_duration(hifitime::Duration::from_total_nanoseconds(lower));
    let upper = Epoch::from_tai_duration(hifitime::Duration::from_total_nanoseconds(upper));
    if lower == upper {
        lower.to_string()
    } else {
        format!("{lower}..{upper}")
    }
}

fn read_text(reader: &PileSnapshot, handle: TextHandle) -> Result<String> {
    let value: View<str> = reader.get(handle).context("read Archive text")?;
    Ok(value.to_string())
}

fn entity_label(
    facts: &FactArchive,
    reader: &PileSnapshot,
    id: Id,
    namespace: &str,
) -> Result<String> {
    let names: BTreeSet<_> = find!(
        value: TextHandle,
        pattern!(facts, [{ id @ metadata::name: ?value }])
    )
    .map(|handle| read_text(reader, handle))
    .collect::<Result<_>>()?;
    if names.is_empty() {
        Ok(format!("{namespace}:{id:X}"))
    } else {
        Ok(names.into_iter().collect::<Vec<_>>().join(" / "))
    }
}

fn projection_actor(facts: &FactArchive, reader: &PileSnapshot, projection: Id) -> Result<String> {
    let mut values = Vec::new();
    for attribute in [
        &*archive_schema::source_projection::raw_author,
        &*archive_schema::source_projection::raw_role,
        &*archive_schema::source_projection::raw_model,
    ] {
        let handles: BTreeSet<_> = find!(
            value: TextHandle,
            pattern!(facts, [{ projection @ attribute: ?value }])
        )
        .collect();
        for handle in handles {
            values.push(read_text(reader, handle)?);
        }
    }
    Ok(if values.is_empty() {
        "<unattributed>".to_owned()
    } else {
        values.join("/")
    })
}

fn block_snippet(facts: &FactArchive, reader: &PileSnapshot, block: Id) -> Result<String> {
    let parts: BTreeSet<_> = find!(
        (ordinal: u64, part: Id, fact: Id),
        pattern!(facts, [
            { block @ archive_schema::block::contains: ?part },
            { ?part @ archive_schema::content_part::ordinal: ?ordinal,
                archive_schema::content_part::fact: ?fact },
        ])
    )
    .collect();
    let mut values = Vec::new();
    for (_, _, fact) in parts {
        for text in find!(
            text: TextHandle,
            pattern!(facts, [{ fact @ archive_schema::content_fact::payload: ?text }])
        ) {
            values.push(read_text(reader, text)?);
        }
        for blob in find!(
            blob: RawHandle,
            pattern!(facts, [{ fact @ archive_schema::content_fact::blob: ?blob }])
        ) {
            values.push(format!("[resident {}]", hex::encode_upper(blob.raw)));
        }
        for pointer in find!(
            pointer: TextHandle,
            pattern!(facts, [{ fact @ archive_schema::content_fact::asset_pointer: ?pointer }])
        ) {
            values.push(format!("[external {}]", read_text(reader, pointer)?));
        }
    }
    Ok(snippet(&values.join(" "), 120))
}

fn render_projection_summary(
    facts: &FactArchive,
    reader: &PileSnapshot,
    projection: Id,
) -> Result<String> {
    let timestamp = find!(
        value: (i128, i128),
        pattern!(facts, [{
            projection @ archive_schema::source_projection::source_timestamp: ?value
        }])
    )
    .min()
    .or_else(|| {
        find!(
            value: (i128, i128),
            pattern!(facts, [
                { projection @ archive_schema::source_projection::projects_to: _?block },
                { _?block @ archive_schema::block::timestamp: ?value },
            ])
        )
        .min()
    });
    let blocks: BTreeSet<_> = find!(
        block: Id,
        pattern!(facts, [{
            projection @ archive_schema::source_projection::projects_to: ?block
        }])
    )
    .collect();
    let snippets = blocks
        .into_iter()
        .map(|block| block_snippet(facts, reader, block))
        .collect::<Result<Vec<_>>>()?;
    Ok(format!(
        "{} {} {} {}",
        short_id(projection),
        format_interval(timestamp),
        projection_actor(facts, reader, projection)?,
        snippets.join(" / "),
    ))
}

fn render_parts(
    out: &mut String,
    facts: &FactArchive,
    reader: &PileSnapshot,
    block: Id,
    include_all: bool,
) -> Result<()> {
    let parts: BTreeSet<_> = find!(
        (ordinal: u64, part: Id, fact: Id, modality: Id, direction: Id),
        pattern!(facts, [
            { block @ archive_schema::block::contains: ?part },
            { ?part @ archive_schema::content_part::ordinal: ?ordinal,
                archive_schema::content_part::fact: ?fact },
            { ?fact @ archive_schema::content_fact::modality: ?modality,
                archive_schema::content_fact::direction: ?direction },
        ])
    )
    .collect();
    for (ordinal, part, fact, modality, direction) in parts {
        if !include_all && modality != archive_schema::content_fact::modality::TEXT {
            continue;
        }
        writeln!(
            out,
            "part[{ordinal}]: {} {} id={part:X} fact={fact:X}",
            entity_label(facts, reader, modality, "modality")?,
            entity_label(facts, reader, direction, "direction")?,
        )?;
        for target in find!(
            target: Id,
            pattern!(facts, [{ part @ archive_schema::content_part::responds_to: ?target }])
        ) {
            writeln!(out, "  responds_to: {target:X}")?;
        }
        for text in find!(
            text: TextHandle,
            pattern!(facts, [{ fact @ archive_schema::content_fact::payload: ?text }])
        ) {
            writeln!(out, "  text:")?;
            for line in read_text(reader, text)?.lines() {
                writeln!(out, "    {line}")?;
            }
        }
        for blob in find!(
            blob: RawHandle,
            pattern!(facts, [{ fact @ archive_schema::content_fact::blob: ?blob }])
        ) {
            writeln!(out, "  resident_blob: {}", hex::encode_upper(blob.raw))?;
        }
        for pointer in find!(
            pointer: TextHandle,
            pattern!(facts, [{ fact @ archive_schema::content_fact::asset_pointer: ?pointer }])
        ) {
            writeln!(out, "  external_pointer: {}", read_text(reader, pointer)?)?;
        }
        for (label, attribute) in [
            ("media_type", &*archive_schema::content_fact::media_type),
            (
                "asset_namespace",
                &*archive_schema::content_fact::asset_namespace,
            ),
        ] {
            for value in find!(value: Id, pattern!(facts, [{ fact @ attribute: ?value }])) {
                writeln!(out, "  {label}: {value:X}")?;
            }
        }
        for size in find!(
            size: u128,
            pattern!(facts, [{ fact @ archive_schema::content_fact::asset_size: ?size }])
        ) {
            writeln!(out, "  size: {size}")?;
        }
        for resolution in find!(
            resolution: RawHandle,
            pattern!(facts, [{ fact @ archive_schema::content_fact::resolved_to: ?resolution }])
        ) {
            writeln!(out, "  resolution: {}", hex::encode_upper(resolution.raw))?;
        }
        for resolution in find!(
            resolution: RawHandle,
            pattern!(facts, [{ part @ archive_schema::content_part::resolution: ?resolution }])
        ) {
            writeln!(
                out,
                "  selected_resolution: {}",
                hex::encode_upper(resolution.raw)
            )?;
        }
    }
    Ok(())
}

fn render_projection(facts: &FactArchive, reader: &PileSnapshot, projection: Id) -> Result<String> {
    let mut out = String::new();
    writeln!(out, "projection: {projection:X}")?;
    for (label, attribute) in [
        (
            "source_namespace",
            &*archive_schema::source_projection::source_namespace,
        ),
        (
            "semantic_predecessor_support",
            &*archive_schema::source_projection::semantic_predecessor_support,
        ),
        ("author", &*archive_schema::source_projection::author),
        (
            "experiencer",
            &*archive_schema::source_projection::experiencer,
        ),
    ] {
        for value in find!(value: Id, pattern!(facts, [{ projection @ attribute: ?value }])) {
            writeln!(out, "{label}: {value:X}")?;
        }
    }
    for (label, attribute) in [
        (
            "source_locator",
            &*archive_schema::source_projection::source_locator,
        ),
        (
            "raw_author",
            &*archive_schema::source_projection::raw_author,
        ),
        ("raw_role", &*archive_schema::source_projection::raw_role),
        ("raw_model", &*archive_schema::source_projection::raw_model),
        (
            "source_path",
            &*faculties::schemas::files::file::source_path,
        ),
    ] {
        for value in find!(
            value: TextHandle,
            pattern!(facts, [{ projection @ attribute: ?value }])
        ) {
            writeln!(out, "{label}: {}", read_text(reader, value)?)?;
        }
    }
    for raw in find!(
        raw: RawHandle,
        pattern!(facts, [{ projection @ archive_schema::source_projection::raw_record: ?raw }])
    ) {
        writeln!(out, "raw_record: {}", hex::encode_upper(raw.raw))?;
    }
    for timestamp in find!(
        timestamp: (i128, i128),
        pattern!(facts, [{
            projection @ archive_schema::source_projection::source_timestamp: ?timestamp
        }])
    ) {
        writeln!(
            out,
            "source_timestamp: {}",
            format_interval(Some(timestamp))
        )?;
    }
    let blocks: BTreeSet<_> = find!(
        block: Id,
        pattern!(facts, [{ projection @ archive_schema::source_projection::projects_to: ?block }])
    )
    .collect();
    for block in blocks {
        writeln!(out, "block: {block:X}")?;
        for timestamp in find!(
            timestamp: (i128, i128),
            pattern!(facts, [{ block @ archive_schema::block::timestamp: ?timestamp }])
        ) {
            writeln!(out, "block_timestamp: {}", format_interval(Some(timestamp)))?;
        }
        for previous in find!(
            previous: Id,
            pattern!(facts, [{ block @ archive_schema::block::previous: ?previous }])
        ) {
            writeln!(out, "block_previous: {previous:X}")?;
        }
        render_parts(&mut out, facts, reader, block, true)?;
    }
    Ok(out)
}

fn resolve_prefix(ids: impl IntoIterator<Item = Id>, prefix: &str) -> Result<Id> {
    let prefix = prefix.trim();
    if prefix.is_empty() || prefix.len() > 32 || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("Archive projection prefix must contain 1..=32 hexadecimal digits");
    }
    let prefix = prefix.to_ascii_uppercase();
    let matches: BTreeSet<_> = ids
        .into_iter()
        .filter(|id| format!("{id:X}").starts_with(&prefix))
        .collect();
    match matches.len() {
        0 => bail!("no Archive source projection matches {prefix}"),
        1 => Ok(*matches.first().expect("one prefix match")),
        _ => bail!("Archive projection prefix {prefix} is ambiguous"),
    }
}

fn run_list(storage: ArchiveStorage<'_>, limit: usize) -> Result<()> {
    let observed = storage.load()?;
    let facts = observed.view::<FactArchive>()?;
    let mut rows = Vec::new();
    for projection in find!(
        projection: Id,
        pattern!(&facts, [{
            ?projection @ metadata::tag: &archive_schema::source_projection::KIND
        }])
    ) {
        let timestamp = find!(
            timestamp: (i128, i128),
            pattern!(&facts, [{
                projection @ archive_schema::source_projection::source_timestamp: ?timestamp
            }])
        )
        .map(|(lower, _)| lower)
        .min()
        .or_else(|| {
            find!(
                timestamp: (i128, i128),
                pattern!(&facts, [
                    { projection @ archive_schema::source_projection::projects_to: _?block },
                    { _?block @ archive_schema::block::timestamp: ?timestamp },
                ])
            )
            .map(|(lower, _)| lower)
            .min()
        });
        rows.push((timestamp, projection));
    }
    rows.sort_unstable_by(|left, right| right.cmp(left));
    for (_, projection) in rows.into_iter().take(limit) {
        println!(
            "{}",
            render_projection_summary(&facts, observed.snapshot(), projection)?
        );
    }
    Ok(())
}

fn run_show(storage: ArchiveStorage<'_>, prefix: &str) -> Result<()> {
    let observed = storage.load()?;
    let facts = observed.view::<FactArchive>()?;
    let id = resolve_prefix(
        find!(
            projection: Id,
            pattern!(&facts, [{
                ?projection @ metadata::tag: &archive_schema::source_projection::KIND
            }])
        ),
        prefix,
    )?;
    print!("{}", render_projection(&facts, observed.snapshot(), id)?);
    Ok(())
}

fn load_thread(facts: &FactArchive, projection_prefix: &str, limit: usize) -> Result<Vec<Id>> {
    if limit == 0 {
        bail!("thread limit must be at least 1");
    }
    let leaf = resolve_prefix(
        find!(
            projection: Id,
            pattern!(facts, [{
                ?projection @ metadata::tag: &archive_schema::source_projection::KIND
            }])
        ),
        projection_prefix,
    )?;
    let mut pending: BTreeSet<_> = find!(
        block: Id,
        pattern!(facts, [{ leaf @ archive_schema::source_projection::projects_to: ?block }])
    )
    .collect();
    let mut parents = BTreeMap::<Id, BTreeSet<Id>>::new();
    while let Some(block) = pending.pop_first() {
        if parents.contains_key(&block) {
            continue;
        }
        if parents.len() == limit {
            bail!("thread ancestry exceeds {limit} canonical blocks; increase --limit so no fork is hidden");
        }
        let previous: BTreeSet<_> = find!(
            previous: Id,
            pattern!(facts, [{ block @ archive_schema::block::previous: ?previous }])
        )
        .collect();
        pending.extend(previous.iter().copied());
        parents.insert(block, previous);
    }
    let mut indegree: BTreeMap<Id, usize> = parents
        .iter()
        .map(|(block, previous)| (*block, previous.len()))
        .collect();
    let mut children = BTreeMap::<Id, BTreeSet<Id>>::new();
    for (block, previous) in &parents {
        for parent in previous {
            children.entry(*parent).or_default().insert(*block);
        }
    }
    let mut ready: BTreeSet<Id> = indegree
        .iter()
        .filter_map(|(block, count)| (*count == 0).then_some(*block))
        .collect();
    let mut ordered = Vec::with_capacity(parents.len());
    while let Some(block) = ready.pop_first() {
        ordered.push(block);
        for child in children.get(&block).into_iter().flatten() {
            let count = indegree
                .get_mut(child)
                .expect("every child has an indegree");
            *count -= 1;
            if *count == 0 {
                ready.insert(*child);
            }
        }
    }
    if ordered.len() != parents.len() {
        bail!("Archive thread contains a block cycle");
    }
    Ok(ordered)
}

fn render_block(
    facts: &FactArchive,
    reader: &PileSnapshot,
    block: Id,
    include_all_parts: bool,
) -> Result<String> {
    let mut out = String::new();
    writeln!(out, "block: {block:X}")?;
    let timestamp = find!(
        value: (i128, i128),
        pattern!(facts, [{ block @ archive_schema::block::timestamp: ?value }])
    )
    .min()
    .or_else(|| {
        find!(
            value: (i128, i128),
            pattern!(facts, [{
                _?receipt @ archive_schema::source_projection::projects_to: block,
                archive_schema::source_projection::source_timestamp: ?value
            }])
        )
        .min()
    });
    writeln!(out, "timestamp: {}", format_interval(timestamp))?;
    for previous in find!(
        previous: Id,
        pattern!(facts, [{ block @ archive_schema::block::previous: ?previous }])
    ) {
        writeln!(out, "previous: {previous:X}")?;
    }
    let receipts: BTreeSet<_> = find!(
        (receipt: Id, locator: TextHandle),
        pattern!(facts, [{
            ?receipt @ archive_schema::source_projection::projects_to: block,
            archive_schema::source_projection::source_locator: ?locator
        }])
    )
    .collect();
    for (receipt, locator) in receipts {
        writeln!(
            out,
            "receipt: {receipt:X} {} {}",
            read_text(reader, locator)?,
            projection_actor(facts, reader, receipt)?,
        )?;
    }
    render_parts(&mut out, facts, reader, block, include_all_parts)?;
    Ok(out)
}

fn run_thread(storage: ArchiveStorage<'_>, prefix: &str, limit: usize) -> Result<()> {
    let observed = storage.load()?;
    let facts = observed.view::<FactArchive>()?;
    for (index, block) in load_thread(&facts, prefix, limit)?.into_iter().enumerate() {
        if index != 0 {
            println!("---");
        }
        print!(
            "{}",
            render_block(&facts, observed.snapshot(), block, true)?
        );
    }
    Ok(())
}

fn run_search(storage: ArchiveStorage<'_>, text: &str, limit: usize) -> Result<()> {
    let text = faculties::text_arg(text, "search text")?;
    let (observed, index) = pollster::block_on(archive_collection::ensure_search_local(
        storage.pile,
        storage.key,
    ))?;
    let facts = observed.view::<FactArchive>()?;
    for (document, score) in index
        .query_multi(&hash_tokens(&text))
        .into_iter()
        .take(limit)
    {
        let block = Id::try_from_inline(&document)
            .map_err(|error| anyhow!("Archive BM25 document is not a block id: {error:?}"))?;
        let receipts: BTreeSet<_> = find!(
            receipt: Id,
            pattern!(&facts, [{
                ?receipt @ archive_schema::source_projection::projects_to: block
            }])
        )
        .collect();
        println!(
            "{score:.4} {} {} receipt(s) {}",
            short_id(block),
            receipts.len(),
            block_snippet(&facts, observed.snapshot(), block)?,
        );
    }
    Ok(())
}

fn run_index(storage: ArchiveStorage<'_>) -> Result<()> {
    let (succinct, bm25) = pollster::block_on(async {
        let succinct = archive_collection::ensure_succinct_index(storage.pile, storage.key).await?;
        let bm25 = archive_collection::ensure_bm25_index(storage.pile, storage.key).await?;
        Ok::<_, anyhow::Error>((succinct, bm25))
    })?;
    println!(
        "Archive: {} distinct source element(s) covered by accelerated-Succinct",
        succinct.source_elements,
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

fn plan_cursor_update(
    facts: &FactArchive,
    stream: &str,
    persona: &str,
    position: Option<Epoch>,
    anchor: Option<Id>,
) -> Result<Option<Fragment>> {
    let state = cursor_state(position, anchor);
    let predecessors = match comb_model::resolution(facts, stream, persona)? {
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
    let resolution = comb_model::resolution(facts, stream, persona)?.ok_or_else(|| {
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
    let facts = replay.archive.view::<FactArchive>()?;
    let timeline = archive_collection::timeline_after(&facts, cursor)?
        .into_iter()
        .filter(|item| {
            with_tools
                || exists!(pattern!(&facts, [
                    { item.block @ archive_schema::block::contains: _?part },
                    { _?part @ archive_schema::content_part::fact: _?fact },
                    { _?fact @ archive_schema::content_fact::modality:
                        &archive_schema::content_fact::modality::TEXT },
                ]))
        })
        .collect();
    let (selected, remaining) = split_replay_batch(timeline, limit);
    if selected.is_empty() {
        println!("replay complete: nothing after the cursor. The past is read.");
        return Ok(());
    }

    for block in &selected {
        print!(
            "{}",
            render_block(&facts, replay.archive.snapshot(), block.block, with_tools)?
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
        Some(last.block),
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
        let observed = storage(fixture).load().unwrap();
        observed
            .support()
            .commits(observed.snapshot())
            .unwrap()
            .len()
    }

    fn projection_ids(facts: &FactArchive) -> Vec<Id> {
        find!(
            projection: Id,
            pattern!(facts, [{
                ?projection @ metadata::tag: &archive_schema::source_projection::KIND
            }])
        )
        .collect()
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

        assert_eq!(
            projection_ids(
                &storage(&fixture)
                    .load()
                    .unwrap()
                    .view::<FactArchive>()
                    .unwrap()
            )
            .len(),
            10
        );
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
        assert_eq!(
            projection_ids(&archive.view::<FactArchive>().unwrap()).len(),
            2
        );
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
        let facts = archive.view::<FactArchive>().unwrap();
        let ids = projection_ids(&facts);
        assert_eq!(ids.len(), 2);
        let blocks: BTreeSet<_> = find!(
            block: Id,
            pattern!(&facts, [{
                _?projection @ archive_schema::source_projection::projects_to: ?block
            }])
        )
        .collect();
        assert_eq!(blocks.len(), 1);
        let block = *blocks.first().unwrap();
        assert!(!exists!(pattern!(&facts, [{
            block @ archive_schema::block::timestamp: _?timestamp
        }])));
        for projection in ids {
            assert!(
                !render_projection_summary(&facts, archive.snapshot(), projection)
                    .unwrap()
                    .contains("<untimed>")
            );
        }
        let earliest_receipt_key = find!(
            timestamp: (i128, i128),
            pattern!(&facts, [{
                _?projection @ archive_schema::source_projection::source_timestamp: ?timestamp
            }])
        )
        .map(|(lower, _)| lower)
        .min()
        .unwrap();
        assert!(!render_block(&facts, archive.snapshot(), block, false)
            .unwrap()
            .contains("<untimed>"));
        let timeline =
            archive_collection::timeline_after(&facts, ArchiveTimelineCursor::AfterTime(i128::MIN))
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
        let first = pollster::block_on(archive_collection::ensure_succinct_index(
            &fixture.pile,
            Some(&fixture.key),
        ))
        .unwrap();

        assert_eq!(first.source_elements, 1);
        assert_ne!(first.source_collection, first.target_collection);
        let before = fs::metadata(&fixture.pile).unwrap().len();

        let archive = storage(&fixture).load().unwrap();
        let facts = archive.view::<FactArchive>().unwrap();
        let id = projection_ids(&facts)[0];
        assert!(render_projection(&facts, archive.snapshot(), id)
            .unwrap()
            .contains("quasar needle"));
        assert_eq!(
            load_thread(&facts, &format!("{id:X}"), 10).unwrap().len(),
            1
        );
        drop(archive);
        let repeated = pollster::block_on(archive_collection::ensure_succinct_index(
            &fixture.pile,
            Some(&fixture.key),
        ))
        .unwrap();
        assert_eq!(repeated, first);

        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), before);

        let first_bm25 = pollster::block_on(archive_collection::ensure_bm25_index(
            &fixture.pile,
            Some(&fixture.key),
        ))
        .unwrap();

        assert_eq!(first_bm25.source_elements, 1);
        assert_eq!(first_bm25.cover_segments, 1);
        let after_bm25 = fs::metadata(&fixture.pile).unwrap().len();
        assert_eq!(
            pollster::block_on(archive_collection::ensure_bm25_index(
                &fixture.pile,
                Some(&fixture.key),
            ))
            .unwrap(),
            first_bm25
        );
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), after_bm25);

        let search = pollster::block_on(archive_collection::ensure_search_local(
            &fixture.pile,
            Some(&fixture.key),
        ))
        .unwrap();
        let hits = search.1.query_multi(&hash_tokens("quasar"));
        assert_eq!(hits.len(), 1);
        let block = Id::try_from_inline(&hits[0].0).unwrap();
        let found: Vec<_> = find!(
            projection: Id,
            pattern!(&facts, [{
                ?projection @ archive_schema::source_projection::projects_to: block
            }])
        )
        .collect();
        assert_eq!(found, [id]);
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
        let facts = archive.view::<FactArchive>().unwrap();
        let joined = projection_ids(&facts)
            .into_iter()
            .find(|id| {
                render_projection_summary(&facts, archive.snapshot(), *id)
                    .unwrap()
                    .contains("joined")
            })
            .unwrap();
        let thread = load_thread(&facts, &format!("{joined:X}"), 3).unwrap();
        assert_eq!(thread.len(), 3);
        let parent_count: usize = thread
            .iter()
            .map(|block| {
                find!(
                    previous: Id,
                    pattern!(&facts, [{ block @ archive_schema::block::previous: ?previous }])
                )
                .count()
            })
            .sum();
        assert_eq!(parent_count, 2);
        assert!(load_thread(&facts, &format!("{joined:X}"), 2)
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
        let facts = archive.view::<FactArchive>().unwrap();
        let timeline =
            archive_collection::timeline_after(&facts, ArchiveTimelineCursor::AfterTime(i128::MIN))
                .unwrap();
        assert_eq!(timeline.len(), 3);
        assert_eq!(timeline[0].position, timeline[1].position);
        let first_cursor = timeline[0].cursor();
        let (selected, remaining) = split_replay_batch(timeline, 1);
        assert_eq!(selected.len(), 1);
        assert_eq!(remaining, 2);

        let resumed = archive_collection::timeline_after(&facts, first_cursor).unwrap();
        assert_eq!(resumed.len(), 2, "the equal-time peer is not skipped");

        let error = run_replay(storage(&fixture), &[], 0, false, Some("replay-test")).unwrap_err();
        assert_eq!(error.to_string(), "replay limit must be at least 1");
    }
    #[test]
    fn display_queries_keep_annotations_and_skip_undecodable_parts() {
        use faculties::blockdag;
        use triblespace::prelude::{entity, fucid};

        let fixture = fixture();
        let fact = blockdag::text_fact(
            archive_schema::content_fact::modality::TEXT,
            archive_schema::content_fact::direction::IN,
            "readable body",
        )
        .unwrap();
        let fact_id = fact.root().unwrap();
        let part = blockdag::content_part(0, fact, None).unwrap();
        let block = blockdag::block([], None, part).unwrap();
        let block_id = block.root().unwrap();
        let mut fragment = blockdag::source_projection(
            archive_schema::source_projection::SOURCE_CODEX,
            "annotated/source",
            b"exact raw record".to_vec(),
            block,
        )
        .unwrap();
        let projection = fragment.root().unwrap();
        fragment += entity! { triblespace::core::id::ExclusiveId::force_ref(&projection) @
            archive_schema::source_projection::raw_author*: ["one author", "another author"],
            metadata::name: "unmodeled annotation",
        };
        fragment += entity! { triblespace::core::id::ExclusiveId::force_ref(&fact_id) @
            archive_schema::content_fact::asset_pointer: "also an external interpretation",
        };
        let undecodable = fucid();
        fragment += entity! { &undecodable @
            archive_schema::content_part::ordinal: u128::MAX,
            archive_schema::content_part::fact: fact_id,
        };
        fragment += entity! { triblespace::core::id::ExclusiveId::force_ref(&block_id) @
            archive_schema::block::contains: &undecodable,
        };
        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        let collection = open_configured(
            &mut pile,
            archive_schema::DEFAULT_SCOPE_ID,
            signer.verifying_key(),
        )
        .unwrap();
        pile.commit(collection, &signer, fragment).unwrap();
        pile.close().unwrap();

        let observed = storage(&fixture).load().unwrap();
        let facts = observed.view::<FactArchive>().unwrap();
        let rendered = render_projection(&facts, observed.snapshot(), projection).unwrap();
        assert!(rendered.contains("one author"));
        assert!(rendered.contains("another author"));
        assert!(rendered.contains("readable body"));
        assert!(rendered.contains("also an external interpretation"));
        assert_eq!(rendered.matches("part[").count(), 1);
        let summary = render_projection_summary(&facts, observed.snapshot(), projection).unwrap();
        assert!(summary.contains("readable body"));
    }
}
