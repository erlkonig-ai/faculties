//! Explicit Gauge CLI grammar and output routing.
use super::{presentation, Gauge};
use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "gauge",
    about = "Research-quality metrics over Wiki entries and complete DAG frontiers"
)]
struct Cli {
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads never create one.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Show entry, frontier, tag, link, and orphan metrics.
    Health,
    /// Count tags both by current state occurrence and by logical entry.
    Tags,
    /// Show current published/refuted states without settling forks.
    Quality,
    /// Show entries with the most unambiguously resolved incoming links.
    Hubs {
        #[arg(short, long, default_value = "15")]
        top: usize,
    },
    /// Find entries whose current states cite refuted or audit-warned entries.
    Risk,
    /// List entries for which every current state has zero outgoing links.
    Orphans {
        #[arg(short, long, default_value = "20")]
        top: usize,
        /// Print one stable entry selector per line.
        #[arg(long)]
        ids: bool,
    },
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    };
    let gauge = Gauge::new(cli.pile, cli.key);
    crate::cli::with_output("gauge", |out| match command {
        Command::Health => presentation::health(&gauge.health()?, out),
        Command::Tags => presentation::tags(&gauge.tags()?, out),
        Command::Quality => presentation::quality(&gauge.quality()?, out),
        Command::Hubs { top } => presentation::hubs(&gauge.hubs(top)?, out),
        Command::Risk => presentation::risk(&gauge.risk()?, out),
        Command::Orphans { top, ids } => presentation::orphans(&gauge.orphans(top)?, ids, out),
    })
}
