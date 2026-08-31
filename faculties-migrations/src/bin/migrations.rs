//! `migrations` — the one still-live Faculties collection transformation.

use std::path::PathBuf;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};

use faculties_migrations::collection_policy::{self, CollectionPolicyPlan};

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "migrations",
    about = "Run the current Faculties migration epoch",
    long_about = "Re-seat exact immediately-prior ordinary collection descriptors under current READ/WRITE policies. Secrets is deliberately excluded and needs fresh policy-era credentials. A dry run is informative only; activation always replans."
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
    },
}

fn print_plan(plan: &CollectionPolicyPlan) {
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
    }
    println!(
        "Secrets access   : {} record(s), excluded",
        plan.secrets.access_records
    );
    for vault in &plan.secrets.vaults {
        println!("  excluded {:<24} records={}", vault.name, vault.records,);
    }
    println!(
        "Secrets action   : initialize a fresh policy-era vault and supply credentials; old access/vault records, envelopes, and proof bindings are deliberately not carried"
    );
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
        Command::CollectionPolicy { dry_run } => {
            if dry_run {
                let plan = collection_policy::plan_path(&cli.pile, key)?;
                print_plan(&plan);
                println!("publication      : dry run; source will be replanned");
            } else {
                let report = collection_policy::publish_path(&cli.pile, key)?;
                print_plan(&report.plan);
                println!("appended COMMITs : {}", report.appended_commits);
            }
        }
    }
    Ok(())
}
