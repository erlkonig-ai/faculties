//! Explicit additive transformations for the current Faculties storage epoch.

use std::path::PathBuf;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};

use faculties_migrations::collection_policy::{self, CollectionPolicyPlan};

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "migrations",
    about = "Run explicit additive Faculties migrations",
    long_about = "Run one current, explicitly selected additive storage transformation. Every publication replans from a frozen pile snapshot; dry runs never write. Historical parsers live only in the migration module that consumes them."
)]
struct Cli {
    #[arg(long, env = "PILE")]
    pile: PathBuf,

    /// Durable signing key. Defaults to the key beside the pile; migrations
    /// never mint an ephemeral identity.
    #[arg(long)]
    key: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Additively re-seat exact predecessor roots under collection policies.
    CollectionPolicy {
        /// Re-plan and report without publishing descriptors or COMMITs.
        #[arg(long)]
        dry_run: bool,
        /// Print the exact predecessor and successor descriptor handles.
        ///
        /// Names are intentionally not selectors across descriptor epochs:
        /// policy is part of collection identity, so a cutover pile can carry
        /// several collections with the same human-readable name.
        #[arg(long)]
        handles: bool,
    },
}

fn print_plan(plan: &CollectionPolicyPlan, handles: bool) {
    println!("Collection-policy descriptor re-seat");
    println!("ordinary roots   : {}", plan.roots.len());
    println!("missing COMMITs  : {}", plan.missing_commits());
    println!("invalid COMMITs  : {}", plan.invalid_commits());
    println!("non-root COMMITs : {}", plan.unsupported_non_root_commits());
    for root in &plan.roots {
        println!(
            "  {:<24} source={} target={} missing={} invalid={} non-root={} skipped-merge={} skipped-derive={}",
            root.name,
            root.source_commits,
            root.target_commits,
            root.missing_commits,
            root.invalid_commits,
            root.unsupported_non_root_commits,
            root.skipped_merges,
            root.skipped_derives,
        );
        if handles {
            println!("    source=blake3:{}", hex::encode(root.old.raw));
            println!("    target=blake3:{}", hex::encode(root.new.raw));
        }
    }
    println!(
        "Secrets access   : {} record(s), excluded",
        plan.secrets.access_records
    );
    for vault in &plan.secrets.vaults {
        println!("  excluded {:<24} records={}", vault.name, vault.records,);
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    };
    let key = cli.key.as_deref();

    match command {
        Command::CollectionPolicy { dry_run, handles } => {
            if dry_run {
                let plan = collection_policy::plan_path(&cli.pile, key)?;
                print_plan(&plan, handles);
                println!("publication      : dry run; source will be replanned");
            } else {
                let report = collection_policy::publish_path(&cli.pile, key)?;
                print_plan(&report.plan, handles);
                println!("appended COMMITs : {}", report.appended_commits);
            }
        }
    }
    Ok(())
}
