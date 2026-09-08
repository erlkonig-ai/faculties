//! Tailored Cognition command-line adapter.

use super::Cognition;
use crate::out::Out;
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version = crate::GIT_VERSION, name = "cognition", about = "Validate the fixed shared Cognition collection")]
pub struct Cli {
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file; ordinary operations never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate the native Cognition value and all known attachments.
    Check,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    crate::cli::with_output("cognition", |out| execute(cli, out))
}

pub fn execute(cli: Cli, out: &mut Out<'_>) -> Result<()> {
    match cli.command {
        Command::Check => out.line(Cognition::new(cli.pile, cli.key).check()?.summary()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn permanent_cli_exposes_no_scope_branch_or_repair_knobs() {
        let command = Cli::command();
        for forbidden in ["scope", "branch", "branch_id", "head", "repair"] {
            assert!(!command
                .get_arguments()
                .any(|argument| argument.get_id() == forbidden));
        }
    }
}
