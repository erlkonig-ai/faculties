use std::path::PathBuf;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "bootstrap",
    version = faculties::GIT_VERSION,
    about = "Import the portable onboarding seed under this pile's own signer"
)]
struct Cli {
    /// Destination pile. It must already exist and have a durable signing key.
    #[arg(long, env = "PILE")]
    pile: PathBuf,

    /// Explicit durable signing-key path instead of TRIBLESPACE_KEY or self.key.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Import 21 Wiki fragments and seven Compass goals idempotently.
    Import,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(Command::Import) = cli.command else {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    };

    let report = faculties::bootstrap::import(&cli.pile, cli.key.as_deref())?;
    println!("bootstrap generation {}", hex::encode(report.generation));
    println!("wiki COMMIT {:x}", report.wiki_commit.id());
    println!("compass COMMIT {:x}", report.compass_commit.id());
    Ok(())
}
