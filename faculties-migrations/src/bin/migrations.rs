//! `migrations` — the three still-live transformations in dependency order.
//!
//! Run `posture-findings` first, then `descriptor-authority`, then
//! `secrets-descriptor-authority`. `--dry-run` never establishes that a later
//! migration may proceed: activation re-plans the source and enforces the
//! ordering again.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use clap::{CommandFactory, Parser, Subcommand};

use faculties_migrations::{descriptor_authority, posture_findings, secrets_descriptor_authority};

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "migrations",
    about = "Run the current Faculties migration epoch",
    long_about = "Run the current Faculties migration epoch. Required order: posture-findings, descriptor-authority, secrets-descriptor-authority. A dry run is informative only; activation always replans."
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
    /// Bridge legacy Posture findings under the retired Posture descriptor.
    /// This must settle before descriptor-authority is activated.
    PostureFindings {
        /// Re-plan and report without publishing a bridge COMMIT.
        #[arg(long)]
        dry_run: bool,
    },

    /// Re-seat ordinary faculty roots under mandatory authority.
    /// Posture's bridge must already be settled; Secrets remains deferred.
    DescriptorAuthority {
        /// Re-plan and report without publishing re-seated COMMITs.
        #[arg(long)]
        dry_run: bool,

        /// Accept legacy Posture findings whose content identity can no longer
        /// be recovered. Valid only for publication, after inspecting dry-run.
        #[arg(long)]
        accept_unbridged_posture: bool,
    },

    /// Re-seat Secrets roots, proofs, and envelopes after ordinary roots.
    SecretsDescriptorAuthority {
        /// Re-plan and report without publishing any Secrets artifacts.
        #[arg(long)]
        dry_run: bool,
    },
}

fn print_posture(plan: &posture_findings::FindingBridgePlan) {
    println!("Posture legacy finding bridge");
    println!("examined         : {}", plan.examined());
    println!("pending bridges  : {}", plan.bridged().len());
    println!("already bridged  : {}", plan.already_bridged());
    println!("unbridgeable     : {}", plan.unbridged().len());
    for entry in plan.unbridged() {
        println!(
            "  {}  {}  ({})",
            entry.occurrence,
            concise_diagnostic(&entry.locator, 240),
            concise_diagnostic(&entry.reason, 240),
        );
    }
}

/// Keep one pathological source line from turning a migration census into
/// megabytes of terminal output. Diagnostics remain individually identified;
/// the full legacy record is still present in the pile for deeper inspection.
fn concise_diagnostic(value: &str, limit: usize) -> String {
    let mut characters = value.chars();
    let mut concise = String::with_capacity(limit.saturating_add(1));
    for _ in 0..limit {
        let Some(character) = characters.next() else {
            return concise;
        };
        concise.push(if character.is_whitespace() {
            ' '
        } else {
            character
        });
    }
    if characters.next().is_some() {
        concise.push('…');
    }
    concise
}

fn print_descriptor(plan: &descriptor_authority::DescriptorAuthorityPlan) {
    println!("Mandatory-authority descriptor re-seat");
    println!("ordinary roots   : {}", plan.roots.len());
    println!("missing COMMITs  : {}", plan.missing_commits());
    println!("foreign roots    : {}", plan.foreign_ordinary_roots());
    println!("authority unclear: {}", plan.authority_ambiguous());
    println!("residues         : {}", plan.residues.len());
    println!("invalid records  : {}", plan.invalid_records);
    println!("Posture bridges : {}", plan.posture_pending_bridges);
    println!("Posture lost    : {}", plan.posture_unbridged);
    println!("Posture re-seated: {}", plan.posture_reseat_complete);
    for root in &plan.roots {
        println!(
            "  {:<24} source={} target={} missing={} skipped-merge={} skipped-derive={}",
            root.name,
            root.source_commits,
            root.target_commits,
            root.missing_commits,
            root.skipped_merges,
            root.skipped_derives,
        );
    }
    for residue in &plan.residues {
        println!(
            "  residue {:?} records={} {}",
            residue.kind, residue.records, residue.detail
        );
    }
}

fn print_secrets(plan: &secrets_descriptor_authority::SecretsDescriptorAuthorityPlan) {
    println!("Secrets mandatory-authority descriptor re-seat");
    println!("vaults            : {}", plan.vaults.len());
    println!("delegated roots   : {}", plan.delegated.len());
    println!("missing COMMITs   : {}", plan.missing_commits());
    println!("pending envelopes : {}", plan.pending_envelopes());
    println!("blocked           : {}", plan.blocked());
    println!("invalid records   : {}", plan.invalid_records);
}

fn require_descriptor_settled(pile: &Path, key: Option<&Path>) -> Result<()> {
    let ordinary = descriptor_authority::plan_path(pile, key)?;
    if !ordinary.settled() {
        bail!(
            "secrets-descriptor-authority is blocked by {} missing ordinary re-seat COMMIT(s); run `migrations descriptor-authority` first",
            ordinary.missing_commits()
        );
    }
    Ok(())
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
        Command::PostureFindings { dry_run } => {
            if dry_run {
                let plan = posture_findings::plan(&cli.pile, key)?;
                print_posture(&plan);
                println!("publication      : dry run; source will be replanned");
            } else {
                let (plan, commit) = posture_findings::publish(&cli.pile, key)?;
                print_posture(&plan);
                println!(
                    "publication      : {}",
                    if commit.is_some() {
                        "one bridge COMMIT appended"
                    } else {
                        "already settled"
                    }
                );
            }
        }
        Command::DescriptorAuthority {
            dry_run,
            accept_unbridged_posture,
        } => {
            let plan = descriptor_authority::plan_path(&cli.pile, key)?;
            if dry_run {
                if accept_unbridged_posture {
                    bail!(
                        "--accept-unbridged-posture is a one-shot publication decision and cannot be used with --dry-run"
                    );
                }
                print_descriptor(&plan);
                println!("publication      : dry run; source will be replanned");
            } else {
                let report = descriptor_authority::publish_path_with_options(
                    &cli.pile,
                    key,
                    descriptor_authority::DescriptorAuthorityOptions {
                        accept_unbridged_posture,
                    },
                )?;
                print_descriptor(&report.plan);
                println!("appended COMMITs : {}", report.appended_commits);
            }
        }
        Command::SecretsDescriptorAuthority { dry_run } => {
            require_descriptor_settled(&cli.pile, key)?;
            if dry_run {
                let plan = secrets_descriptor_authority::plan_path(&cli.pile, key)?;
                print_secrets(&plan);
                println!("publication       : dry run; source will be replanned");
            } else {
                let report = secrets_descriptor_authority::publish_path(&cli.pile, key)?;
                print_secrets(&report.plan);
                println!("appended COMMITs  : {}", report.appended_commits);
                println!("envelopes written : {}", report.published_envelopes);
                println!("proofs persisted  : {}", report.persisted_proofs);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::concise_diagnostic;

    #[test]
    fn diagnostics_are_single_line_and_bounded_by_characters() {
        assert_eq!(concise_diagnostic("alpha\nbeta", 20), "alpha beta");
        assert_eq!(concise_diagnostic("αβγδε", 3), "αβγ…");
        assert_eq!(concise_diagnostic("abc", 3), "abc");
    }
}
