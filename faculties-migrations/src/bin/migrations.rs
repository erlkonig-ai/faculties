//! Explicit additive transformations for the current Faculties storage epoch.

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::{CommandFactory, Parser, Subcommand};
use ed25519_dalek::VerifyingKey;

use faculties_migrations::collection_policy::{self, CollectionPolicyPlan};
use faculties_migrations::resource_capabilities::{self, ResourceCapabilitiesPlan};

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
    /// Re-seat exact READ/WRITE-policy roots under resource-capability bindings.
    /// Old AUTH proofs are not migrated; current grants require separate issuance.
    ResourceCapabilities {
        /// Exact direct-policy root public key (64 hex digits); defaults to signer.
        /// The signer still re-seats only its own COMMITs; other authors are deferred.
        #[arg(long, value_parser = parse_authority)]
        authority: Option<VerifyingKey>,
        /// Re-plan without publishing descriptors, definitions, or COMMITs.
        #[arg(long)]
        dry_run: bool,
        /// Print every exact predecessor and successor descriptor handle.
        #[arg(long)]
        handles: bool,
        /// Report other resident predecessor roots; unrelated history never blocks.
        #[arg(long)]
        inventory: bool,
    },
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

fn parse_authority(raw: &str) -> Result<VerifyingKey> {
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(raw, &mut bytes)
        .map_err(|_| anyhow!("authority must be a 64-digit Ed25519 public key"))?;
    let key = VerifyingKey::from_bytes(&bytes)?;
    triblespace::core::collection::AdmissionPolicy::quorum([key], 1, None)?;
    Ok(key)
}

fn print_resource_plan(plan: &ResourceCapabilitiesPlan, handles: bool, inventory: bool) {
    println!("Resource-capabilities descriptor re-seat (READ/WRITE-policy predecessor)");
    println!(
        "policy root     : {}",
        hex::encode(plan.authority.to_bytes())
    );
    println!("selected author : {}", hex::encode(plan.author.to_bytes()));
    println!("source COMMITs  : {}", plan.source_commits());
    println!("selected COMMITs: {}", plan.selected_commits());
    println!("missing COMMITs : {}", plan.missing_commits());
    println!("invalid COMMITs : {}", plan.invalid_commits());
    println!(
        "deferred COMMITs: {} (other authors; not migrated by this pass)",
        plan.deferred_commits()
    );
    for root in &plan.roots {
        println!(
            "  {:<24} source={} selected={} target={} missing={} invalid-selected={} deferred={} invalid-deferred={} skipped-merge={} skipped-derive={}",
            root.name,
            root.source_commits,
            root.selected_commits,
            root.target_commits,
            root.missing_commits,
            root.invalid_commits,
            root.deferred_commits,
            root.invalid_deferred_commits,
            root.skipped_merges,
            root.skipped_derives,
        );
        if handles {
            println!("    source=blake3:{}", hex::encode(root.old.raw));
            println!("    target=blake3:{}", hex::encode(root.new.raw));
        }
    }
    if inventory {
        println!(
            "unmapped roots  : {} (report only)",
            plan.unmapped_roots.len()
        );
        for root in &plan.unmapped_roots {
            println!(
                "  untouched blake3:{} names={:?}",
                hex::encode(root.collection.raw),
                root.names,
            );
        }
        println!(
            "unreadable descriptors: {} (report only)",
            plan.unreadable_descriptors
        );
    }
    if plan.selected_commits() == 0 {
        println!("selection       : no selected-author COMMITs; no descriptors will be registered");
    }
    println!("authority       : old AUTH untouched; reissue exact current grants separately");
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
        Command::ResourceCapabilities {
            authority,
            dry_run,
            handles,
            inventory,
        } => {
            if dry_run {
                let plan = resource_capabilities::plan_path(&cli.pile, key, authority, inventory)?;
                print_resource_plan(&plan, handles, inventory);
                println!("publication     : dry run; source will be replanned");
            } else {
                let report =
                    resource_capabilities::publish_path(&cli.pile, key, authority, inventory)?;
                print_resource_plan(&report.plan, handles, inventory);
                println!("appended COMMITs: {}", report.appended_commits);
            }
        }
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
