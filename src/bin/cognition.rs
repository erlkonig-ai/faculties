//! Whole-dataset administration for the shared Cognition collection.
//!
//! Event writers live in their own faculties. This binary owns only validation
//! and the coordinated legacy cutover because no individual writer owns the
//! historical `cognition` and `main` branches together.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use faculties::collection_cutover::{freeze_source, load_signer, open_pile_strict};
use faculties::schemas::cognition::DEFAULT_SCOPE_ID;
use faculties::{cognition, cognition_cutover};
use triblespace::core::repo::BlobStore;
use faculties::legacy_hint::open_scope;

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
    /// Additively publish the complete frozen legacy `cognition` and `main`
    /// branches. Stop every Faculties and drive legacy writer first.
    MigrateLegacy,
}

fn check(cli: &Cli) -> Result<()> {
    let signer = load_signer(&cli.pile, cli.key.as_deref())?;
    let pile = open_pile_strict(&cli.pile)?;
    let mut collection = open_scope(pile, DEFAULT_SCOPE_ID, signer);
    let result = (|| {
        let facts = collection
            .materialize()
            .context("materialize native Cognition collection")?;
        let reader = collection
            .storage_mut()
            .reader()
            .context("open Cognition attachment reader")?;
        cognition::validate_catalog(&reader, &facts)?;
        println!(
            "Cognition scope {DEFAULT_SCOPE_ID:X}: {} facts validated",
            facts.len()
        );
        Ok(())
    })();
    finish(collection.into_storage(), result)
}

fn migrate_legacy(cli: &Cli) -> Result<()> {
    // Fail on absent authority before even freezing the stopped source. The
    // migration then deliberately has two pile lifetimes: immutable source
    // snapshot, followed by one target publication lifetime.
    load_signer(&cli.pile, cli.key.as_deref())?;
    let source = freeze_source(&cli.pile).context(
        "freeze the complete legacy Cognition source; every Faculties and drive writer must be stopped",
    )?;
    let plan = cognition_cutover::plan(&source)?;
    let commits = cognition_cutover::publish(&source, &plan, &cli.pile, cli.key.as_deref())?;
    println!(
        "migrated {} authored Cognition/main commit{} ({} authored empty): {} exact facts in fixed scope {DEFAULT_SCOPE_ID:X}",
        commits.len(),
        if commits.len() == 1 { "" } else { "s" },
        plan.report().authored_empty_commits,
        plan.report().facts,
    );
    println!("legacy branches retained as inert evidence; native commands no longer consult them");
    Ok(())
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
        Command::MigrateLegacy => migrate_legacy(&cli),
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
