//! Archive shell syntax, trace setup and explicit local source discovery.
use super::{parse_tai_timestamp, Archive, ImportSource, ImportSummary};
use crate::archive_collection::ArchiveImportWriter;
use crate::out::Out;
use crate::{
    archive_agy, archive_chatgpt, archive_claude_code, archive_claude_web, archive_codex,
    archive_copilot, archive_gemini,
};
use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};
use std::sync::Once;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;
#[derive(Clone, Copy)]
struct ArchiveStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}
#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "archive",
    about = "Import and query the canonical Archive block DAG"
)]
pub struct Cli {
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
    pub(super) command: Option<Command>,
}

#[derive(Subcommand)]
pub(super) enum Command {
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
        source: CliImportSource,
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
pub(super) enum CliImportSource {
    Agy,
    #[value(name = "chatgpt")]
    ChatGpt,
    ClaudeCode,
    ClaudeWeb,
    Codex,
    Copilot,
    Gemini,
}

impl From<CliImportSource> for ImportSource {
    fn from(value: CliImportSource) -> Self {
        match value {
            CliImportSource::Agy => Self::Agy,
            CliImportSource::ChatGpt => Self::ChatGpt,
            CliImportSource::ClaudeCode => Self::ClaudeCode,
            CliImportSource::ClaudeWeb => Self::ClaudeWeb,
            CliImportSource::Codex => Self::Codex,
            CliImportSource::Copilot => Self::Copilot,
            CliImportSource::Gemini => Self::Gemini,
        }
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
    source: CliImportSource,
    out: &mut Out<'_>,
) -> Result<()> {
    if paths.len() == 1 {
        return run_import(storage, &paths[0], source, out);
    }
    let total = paths.len();
    if source == CliImportSource::Codex {
        // The batch case that matters: 3,161 refused Codex rollouts, and the
        // open is ~9.3 s against ~1 s of projection. One open, N commits.
        let mut writer = pollster::block_on(ArchiveImportWriter::open(storage.pile, storage.key))?;
        let result = (|| {
            for (index, path) in paths.iter().enumerate() {
                eprintln!("[{}/{total}] {}", index + 1, path.display());
                run_codex_into(&mut writer, path, out)
                    .with_context(|| format!("import {}", path.display()))?;
            }
            Ok(())
        })();
        return writer.close(result);
    }
    for (index, path) in paths.iter().enumerate() {
        eprintln!("[{}/{total}] {}", index + 1, path.display());
        run_import(storage, path, source, out)
            .with_context(|| format!("import {}", path.display()))?;
    }
    Ok(())
}

fn run_import(
    storage: ArchiveStorage<'_>,
    path: &Path,
    source: CliImportSource,
    out: &mut Out<'_>,
) -> Result<()> {
    match source {
        CliImportSource::Agy => run_agy_import(storage, path, out),
        CliImportSource::ChatGpt => run_chatgpt_import(storage, path, out),
        CliImportSource::ClaudeCode => run_claude_code_import(storage, path, out),
        CliImportSource::ClaudeWeb => run_claude_web_import(storage, path, out),
        CliImportSource::Codex => run_codex_import(storage, path, out),
        CliImportSource::Copilot => run_copilot_import(storage, path, out),
        CliImportSource::Gemini => run_gemini_import(storage, path, out),
    }
}

fn run_agy_import(storage: ArchiveStorage<'_>, path: &Path, out: &mut Out<'_>) -> Result<()> {
    let mut writer = pollster::block_on(ArchiveImportWriter::open(storage.pile, storage.key))?;
    let projection = archive_agy::project_path(path, |projected| {
        writer
            .stage_fragment(projected.fragment)
            .with_context(|| format!("stage {}", projected.source_path.display()))
    });
    let (summary, commit) = writer.finish(projection)?;
    ImportSummary::Agy(summary).write(commit.is_some(), out)?;
    Ok(())
}

fn run_chatgpt_import(storage: ArchiveStorage<'_>, path: &Path, out: &mut Out<'_>) -> Result<()> {
    let mut writer = pollster::block_on(ArchiveImportWriter::open(storage.pile, storage.key))?;
    let projection = archive_chatgpt::project_path(path, |projected| {
        writer
            .stage_fragment(projected.fragment)
            .with_context(|| format!("stage {}", projected.source_path.display()))
    });
    let (summary, commit) = writer.finish(projection)?;
    ImportSummary::ChatGpt(summary).write(commit.is_some(), out)?;
    Ok(())
}

fn run_claude_code_import(
    storage: ArchiveStorage<'_>,
    path: &Path,
    out: &mut Out<'_>,
) -> Result<()> {
    let mut writer = pollster::block_on(ArchiveImportWriter::open(storage.pile, storage.key))?;
    let projection = archive_claude_code::project_path(path, |projected| {
        writer
            .stage_fragment(projected.fragment)
            .with_context(|| format!("stage {}", projected.source_path.display()))
    });
    let (summary, commit) = writer.finish(projection)?;
    ImportSummary::ClaudeCode(summary).write(commit.is_some(), out)?;
    Ok(())
}

fn run_codex_import(storage: ArchiveStorage<'_>, path: &Path, out: &mut Out<'_>) -> Result<()> {
    let mut writer = pollster::block_on(ArchiveImportWriter::open(storage.pile, storage.key))?;
    let result = run_codex_into(&mut writer, path, out);
    writer.close(result)
}

/// Project one Codex rollout into an ALREADY-OPEN writer and commit it.
///
/// Split out so a batch can open the pile once and still publish one signed
/// commit per rollout — the atomicity was always per source, never per process.
fn run_codex_into(writer: &mut ArchiveImportWriter, path: &Path, out: &mut Out<'_>) -> Result<()> {
    let projection = archive_codex::project_path(path, |projected| {
        writer
            .stage_fragment(projected.fragment)
            .with_context(|| format!("stage {}", projected.source_path.display()))
    });
    let summary = projection?;
    let commit = writer.commit_unit()?;
    ImportSummary::Codex(summary).write(commit.is_some(), out)?;
    Ok(())
}

fn run_claude_web_import(
    storage: ArchiveStorage<'_>,
    path: &Path,
    out: &mut Out<'_>,
) -> Result<()> {
    let mut writer = pollster::block_on(ArchiveImportWriter::open(storage.pile, storage.key))?;
    let projection = archive_claude_web::project_path(path, |projected| {
        writer
            .stage_fragment(projected.fragment)
            .with_context(|| format!("stage {}", projected.source_path.display()))
    });
    let (summary, commit) = writer.finish(projection)?;
    ImportSummary::ClaudeWeb(summary).write(commit.is_some(), out)?;
    Ok(())
}

fn run_copilot_import(storage: ArchiveStorage<'_>, path: &Path, out: &mut Out<'_>) -> Result<()> {
    let mut writer = pollster::block_on(ArchiveImportWriter::open(storage.pile, storage.key))?;
    let projection = archive_copilot::project_path(path, |projected| {
        writer
            .stage_fragment(projected.fragment)
            .with_context(|| format!("stage {}", projected.source_path.display()))
    });
    let (summary, commit) = writer.finish(projection)?;
    ImportSummary::Copilot(summary).write(commit.is_some(), out)?;
    Ok(())
}

fn run_gemini_import(storage: ArchiveStorage<'_>, path: &Path, out: &mut Out<'_>) -> Result<()> {
    let mut writer = pollster::block_on(ArchiveImportWriter::open(storage.pile, storage.key))?;
    let projection = archive_gemini::project_path(path, |projected| {
        writer
            .stage_fragment(projected.fragment)
            .with_context(|| format!("stage {}", projected.source_path.display()))
    });
    let (summary, commit) = writer.finish(projection)?;
    ImportSummary::Gemini(summary).write(commit.is_some(), out)?;
    Ok(())
}

pub(super) fn import_paths(
    pile: &Path,
    key: Option<&Path>,
    paths: &[PathBuf],
    source: CliImportSource,
    out: &mut Out<'_>,
) -> Result<()> {
    run_import_all(ArchiveStorage { pile, key }, paths, source, out)
}
pub fn execute(cli: Cli, out: &mut Out<'_>) -> Result<()> {
    let Some(command) = cli.command else {
        out.line(Cli::command().render_help().to_string())?;
        return Ok(());
    };
    let archive = Archive::new(cli.pile.clone(), cli.key.clone());
    match command {
        Command::Import { path, source } => {
            import_paths(&cli.pile, cli.key.as_deref(), &path, source, out)
        }
        Command::List { limit } => archive.list(limit, out),
        Command::Show { id } => archive.show(&id, out),
        Command::Thread { id, limit } => archive.thread(&id, limit, out),
        Command::Search { text, limit } => {
            archive.search(&crate::text_arg(&text, "search text")?, limit, out)
        }
        Command::Index => archive.index(out),
        Command::Replay {
            action,
            limit,
            with_tools,
            persona,
        } => {
            let persona=persona.as_deref().ok_or_else(||anyhow!("no persona: set $PERSONA or pass --persona; replay cursors are session bookkeeping"))?;
            if limit == 0 {
                bail!("replay limit must be at least 1");
            }
            match action.first().map(String::as_str) {
                Some("start") => {
                    if action.len() != 2 {
                        bail!("usage: archive replay start <YYYY-MM-DDTHH:MM:SS>");
                    }
                    let raw = &action[1];
                    archive.replay_start(persona, parse_tai_timestamp(raw)?)?;
                    out.line(format!("replay started at {raw} (persona {persona})"))
                }
                Some("stop") => {
                    if action.len() != 1 {
                        bail!("usage: archive replay stop");
                    }
                    archive.replay_stop(persona)?;
                    out.line(format!("replay stopped (persona {persona})"))
                }
                Some(other) => bail!("unknown replay action `{other}` (start/stop or nothing)"),
                None => archive.replay(persona, limit, with_tools, out),
            }
        }
    }
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.trace, cli.trace_filter.as_deref());
    if cli.command.is_none() {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }
    crate::cli::with_output("archive", |out| execute(cli, out))
}
