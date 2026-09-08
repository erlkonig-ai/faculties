//! Tailored command-line inspection grammar; no work occurs without a verb.
use super::{InspectOptions, Triage};
use crate::out::Out;
use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "triage",
    about = "Doctor-style diagnostics over canonical faculty collections"
)]
pub struct Cli {
    /// Path to the pile file to inspect.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Full health scan with queue and loop heuristics.
    Scan {
        /// Max recent exec attempts used for loop diagnostics.
        #[arg(long, default_value_t = 40)]
        recent: usize,
        /// Minimum repeated attempts to report as a probable loop.
        #[arg(long, default_value_t = 3)]
        loop_min: usize,
        /// Mark in-progress requests older than this as stale.
        #[arg(long, default_value_t = 15)]
        stale_min: i64,
    },
    /// Show recent exec attempts and repeated failure patterns.
    Loops {
        #[arg(long, default_value_t = 40)]
        recent: usize,
        #[arg(long, default_value_t = 3)]
        min_repeat: usize,
    },
    /// Show an interleaved recent activity timeline (exec/model/reason).
    Timeline {
        /// Max events to print (newest first).
        #[arg(long, default_value_t = 80)]
        recent: usize,
    },
    /// Show every canonical Memory chunk and the context budget.
    Cover {
        /// Show complete text instead of a one-line preview.
        #[arg(long)]
        full: bool,
    },
    /// Inspect every canonical Memory chunk or alias matching an ID prefix.
    Chunk {
        /// Intrinsic node ID or historical alias prefix.
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Inspect a full turn cycle: context in, model output, command, exec result.
    Turn {
        /// Nth most recent exec request (1 = latest).
        #[arg(long, default_value_t = 1)]
        turn: usize,
        /// Show full content (context messages, stdout, reasoning).
        #[arg(long)]
        full: bool,
    },
    /// Show every assembled context recorded for a recent turn.
    Context {
        /// Nth most recent exec request (1 = latest).
        #[arg(long, default_value_t = 1)]
        turn: usize,
        /// Show full message content.
        #[arg(long)]
        full: bool,
        /// Dump raw JSON, retaining every context candidate.
        #[arg(long)]
        raw: bool,
    },
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    crate::cli::with_output("triage", |out| execute(cli, out))
}
pub fn execute(cli: Cli, out: &mut Out<'_>) -> Result<()> {
    let Some(command) = cli.command else {
        return out.line(Cli::command().render_long_help().to_string());
    };
    let triage = Triage::new(cli.pile, cli.key);
    match command {
        Command::Scan {
            recent,
            loop_min,
            stale_min,
        } => triage.scan(
            &InspectOptions {
                recent,
                loop_min,
                stale_min,
            },
            out,
        ),
        Command::Loops { recent, min_repeat } => triage.loops(recent, min_repeat, out),
        Command::Timeline { recent } => triage.timeline(recent, out),
        Command::Cover { full } => triage.cover(full, out),
        Command::Chunk { id } => triage.chunk(&id, out),
        Command::Turn { turn, full } => triage.turn(turn, full, out),
        Command::Context { turn, full, raw } => triage.context(turn, full, raw, out),
    }
}
