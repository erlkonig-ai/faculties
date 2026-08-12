//! `migrations` — inspect and execute whole-pile migrations.
//!
//! Planning freezes one source snapshot, runs every typed transform, and
//! prints the exact coverage proof. Activation reruns that same pure boundary,
//! then publishes into a disposable sibling and atomically replaces an
//! unchanged live pile. Neither command writes migration bookkeeping facts.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};

use faculties::{activation_cutover, collection_cutover, disposable_cutover};

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "migrations",
    about = "Plan and execute whole-pile schema and storage migrations"
)]
struct Cli {
    #[arg(long, env = "PILE")]
    pile: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Freeze the pile once and prove complete legacy-source coverage without
    /// writing a candidate or changing the live file.
    PlanCutover,

    /// With every pile writer stopped, build and validate a disposable native
    /// candidate and atomically replace the unchanged live pile.
    ActivateCutover,
}

fn plan_cutover(pile: &PathBuf) -> Result<()> {
    let source = collection_cutover::freeze_source(pile)
        .with_context(|| format!("freeze cutover source {}", pile.display()))?;
    let plan = activation_cutover::plan(&source).context("plan aggregate collection cutover")?;

    let semantic = source.fingerprint();
    let physical = source.physical_fingerprint();
    println!("Native collection cutover plan");
    println!("source       : {}", pile.display());
    println!("source bytes : {}", physical.length);
    println!("source hash  : blake3:{}", hex::encode(physical.digest));
    println!("legacy pins  : {}", semantic.pin_count);
    println!("pin digest   : blake3:{}", hex::encode(semantic.digest));
    println!();

    println!("Collections:");
    for collection in plan.collections() {
        let retirement = match collection.retired_source_facts() {
            0 => String::new(),
            count => format!(" | {count} retired source fact(s)"),
        };
        println!(
            "- {} | scope {:X} | {} source pin(s) | {} commit fragment(s) | {} fact(s){}",
            collection.name(),
            collection.scope(),
            collection.source_pins().len(),
            collection.fragments().len(),
            collection.expected_facts().len(),
            retirement,
        );
    }

    println!();
    println!("Dispositions:");
    for disposition in plan.dispositions() {
        println!(
            "- {} | pin {:X} | {}",
            disposition.branch_name(),
            disposition.source_pin().id,
            disposition.reason(),
        );
    }
    Ok(())
}

fn activate_cutover(pile: &PathBuf) -> Result<()> {
    let source = collection_cutover::freeze_source(pile)
        .with_context(|| format!("freeze cutover source {}", pile.display()))?;
    let plan = activation_cutover::plan(&source).context("plan aggregate collection cutover")?;
    let retired_source_facts = plan
        .collections()
        .iter()
        .map(|collection| collection.retired_source_facts())
        .sum::<usize>();
    let outcome = disposable_cutover::activate(
        pile,
        None,
        &source,
        &plan,
        activation_cutover::validate_candidate_views,
    )
    .context("activate disposable native-collection candidate")?;

    match outcome {
        disposable_cutover::ActivationOutcome::Activated { appended_bytes } => {
            println!(
                "Activated native collections by appending {appended_bytes} candidate byte(s); the original source prefix is preserved exactly."
            );
        }
        disposable_cutover::ActivationOutcome::AlreadyActive => {
            println!(
                "Native collection activation was already complete; the live pile was unchanged."
            );
        }
    }
    if retired_source_facts > 0 {
        eprintln!(
            "SECURITY: {retired_source_facts} retired source fact(s) were not republished into native collections, but their historical bytes remain in the exactly preserved legacy prefix. Rotate every affected upstream credential, then repack the validated native collection commits into a fresh pile before distribution or archival."
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::PlanCutover) => plan_cutover(&cli.pile),
        Some(Command::ActivateCutover) => activate_cutover(&cli.pile),
        None => {
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}
