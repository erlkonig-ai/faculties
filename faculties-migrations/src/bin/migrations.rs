//! `migrations` — inspect and execute migrations of a pre-collection pile.
//!
//! Every migration verb lives here, and nowhere else. The faculties read
//! native collections only; a pile written before the storage cutover keeps
//! all of its data on named legacy branches that no faculty consults, and this
//! binary is the single path from there to here. It is kept forever for
//! exactly that reason: deleting it would make an existing user's data
//! invisible the day they upgrade.
//!
//! - `plan-cutover` freezes one source snapshot, runs every typed transform,
//!   and prints the exact coverage proof without writing anything.
//! - `activate-cutover` reruns that same pure boundary, publishes into a
//!   disposable sibling, and atomically replaces an unchanged live pile. This
//!   is the whole-pile path and the one to prefer.
//! - `migrate-legacy <faculty>` migrates one faculty's branch in place, which
//!   is what that faculty's own `migrate-legacy` subcommand used to do.
//! - `faculties` lists the names `migrate-legacy` accepts.
//!
//! No command writes migration bookkeeping facts, and none deletes, consumes,
//! or rewrites a legacy branch.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};

use faculties_migrations::per_faculty::{self, Faculty};
use faculties_migrations::{activation_cutover, collection_cutover, disposable_cutover};

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "migrations",
    about = "Plan and execute migrations of a pre-collection Faculties pile"
)]
struct Cli {
    #[arg(long, env = "PILE")]
    pile: PathBuf,

    /// Durable signing key. Defaults to the key beside the pile; migration
    /// never mints an ephemeral identity.
    #[arg(long)]
    key: Option<PathBuf>,

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

    /// With every pile writer stopped, migrate one faculty's legacy branch
    /// into its native collection, in place, leaving the rest of the pile
    /// alone. This is what each faculty's own `migrate-legacy` subcommand did
    /// before every migration verb moved here.
    MigrateLegacy {
        /// Faculty to migrate; see `migrations faculties` for the full list.
        faculty: Faculty,
    },

    /// List the faculty names `migrate-legacy` accepts.
    Faculties,
}

fn list_faculties() {
    println!("Faculties `migrations migrate-legacy` can move, and the scope each lands in:");
    for faculty in Faculty::ALL {
        println!("- {:<10} scope {:X}", faculty.label(), faculty.scope());
    }
}

fn plan_cutover(pile: &Path) -> Result<()> {
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

fn activate_cutover(pile: &Path, key: Option<&Path>) -> Result<()> {
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
        key,
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
        Some(Command::ActivateCutover) => activate_cutover(&cli.pile, cli.key.as_deref()),
        Some(Command::MigrateLegacy { faculty }) => {
            per_faculty::migrate(faculty, &cli.pile, cli.key.as_deref())
        }
        Some(Command::Faculties) => {
            list_faculties();
            Ok(())
        }
        None => {
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}
