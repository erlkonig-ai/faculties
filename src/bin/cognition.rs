//! Whole-dataset administration for the shared Cognition collection.
//!
//! Event writers live in their own faculties. This binary owns only validation
//! and the coordinated legacy cutover because no individual writer owns the
//! historical `cognition` and `main` branches together.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use faculties::cognition;
use faculties::legacy_hint::open_scope;
use faculties::schemas::cognition::DEFAULT_SCOPE_ID;
use faculties::storage::{load_signer, open_pile_strict};
use triblespace::core::collection::CollectionStoreExt;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "cognition",
    about = "Validate or migrate the fixed shared Cognition collection"
)]
struct Cli {
    /// Path to the pile file.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Ordinary operations never create it.
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

fn check(cli: &Cli) -> Result<()> {
    let signer = load_signer(&cli.pile, cli.key.as_deref())?;
    let mut pile = open_pile_strict(&cli.pile)?;
    let collection = open_scope(&mut pile, DEFAULT_SCOPE_ID, &signer)?;
    let result = (|| {
        let snapshot = pile
            .snapshot(collection)
            .context("materialize native Cognition collection")?;
        let (facts, _, reader) = snapshot.into_parts();
        cognition::validate_catalog(&reader, &facts)?;
        println!(
            "Cognition scope {DEFAULT_SCOPE_ID:X}: {} facts validated",
            facts.len()
        );
        Ok(())
    })();
    finish(pile, result)
}

fn finish<T>(pile: triblespace::core::repo::pile::Pile, result: Result<T>) -> Result<T> {
    match (result, pile.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(anyhow!("close Cognition pile: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing Cognition pile also failed: {close_error}")))
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Check => check(&cli),
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

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
