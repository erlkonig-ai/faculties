//! Explicit additive transformations for the current Faculties storage epoch.

use std::path::PathBuf;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};

use faculties_migrations::collection_policy::{self, CollectionPolicyPlan};
use faculties_migrations::secrets_reader_envelopes::{self, SecretsReaderEnvelopesPlan};
use triblespace::core::collection::CollectionHandle;
use triblespace::core::inline::Inline;

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
    /// Copy legacy custody-vault facts into one direct-reader Secrets boundary.
    SecretsReaderEnvelopes {
        /// Exact legacy vault descriptor. Repeat to consolidate several old
        /// vaults into the same target policy boundary.
        #[arg(long = "legacy-vault", required = true, value_parser = parse_collection_handle)]
        legacy_vaults: Vec<CollectionHandle>,
        /// Exact already-resident target descriptor. Without this option the
        /// ordinary `secrets` collection configuration is used.
        #[arg(long, value_parser = parse_collection_handle)]
        target: Option<CollectionHandle>,
        /// Fully preflight and report without publishing facts or proofs.
        #[arg(long)]
        dry_run: bool,
    },
}

fn parse_collection_handle(raw: &str) -> std::result::Result<CollectionHandle, String> {
    let raw = raw.trim();
    let raw = raw.strip_prefix("blake3:").unwrap_or(raw);
    if raw.len() != 64 {
        return Err("expected one exact 64-digit hexadecimal collection handle".to_owned());
    }
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(raw, &mut bytes)
        .map_err(|_| "collection handle is not hexadecimal".to_owned())?;
    Ok(Inline::new(bytes))
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
    println!(
        "Secrets action   : run `migrations secrets-reader-envelopes` after choosing the current Secrets target; this descriptor re-seat deliberately leaves vault cryptography untouched"
    );
}

fn print_secrets_plan(plan: &SecretsReaderEnvelopesPlan) {
    println!("Secrets direct-reader cutover");
    println!("legacy vaults    : {}", plan.sources.len());
    for source in &plan.sources {
        println!("  source=blake3:{}", hex::encode(source.raw));
    }
    println!("target           : blake3:{}", hex::encode(plan.target.raw));
    println!("source facts     : {}", plan.source_facts);
    println!("facts to copy    : {}", plan.copied_facts);
    println!("secret versions  : {}", plan.secret_versions);
    println!("legacy envelopes : {}", plan.legacy_access_envelopes);
    println!("reader prefixes  : {}", plan.translated_prefixes);
    println!("proof closures   : {} missing", plan.missing_proof_closures);
    println!("current readers  : {}", plan.current_readers);
    println!("custody keys     : {} recovered", plan.recovered_custodies);
    println!("skipped legacy   : {}", plan.skipped_legacy_candidates);
    println!(
        "recipient wraps  : {} missing",
        plan.missing_recipient_wraps
    );
    println!(
        "target COMMIT    : {}",
        if plan.pending_commit {
            "pending"
        } else {
            "not needed"
        }
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
        Command::SecretsReaderEnvelopes {
            legacy_vaults,
            target,
            dry_run,
        } => {
            if dry_run {
                let plan =
                    secrets_reader_envelopes::plan_path(&cli.pile, key, &legacy_vaults, target)?;
                print_secrets_plan(&plan);
                println!("publication      : dry run; source will be replanned");
            } else {
                let report =
                    secrets_reader_envelopes::publish_path(&cli.pile, key, &legacy_vaults, target)?;
                print_secrets_plan(&report.plan);
                println!("appended COMMITs : {}", report.appended_commits);
                println!("ensured proofs   : {}", report.ensured_proof_closures);
            }
        }
    }
    Ok(())
}
