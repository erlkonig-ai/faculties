use std::path::PathBuf;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "bootstrap",
    version = crate::GIT_VERSION,
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

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let Some(Command::Import) = cli.command else {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    };

    crate::cli::with_output("bootstrap", |out| {
        let report = pollster::block_on(super::import(&cli.pile, cli.key.as_deref()))?;
        super::render_import(&report, out)
    })
}
