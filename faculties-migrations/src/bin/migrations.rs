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
//! - `status-register` gives Compass's status register the identity it never
//!   had, on the events written before that identity existed.
//! - `faculties` lists the names `migrate-legacy` accepts.
//!
//! No command writes migration bookkeeping facts, and none deletes, consumes,
//! or rewrites a legacy branch.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};

use faculties_migrations::per_faculty::{self, Faculty};
use faculties_migrations::{
    activation_cutover, collection_cutover, descriptor_epoch, disposable_cutover, posture_findings,
    status_register, teams_credentials,
};

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

    /// Bridge pre-2026-08-18 Posture findings onto their content-located
    /// identity, so decisions already resolved about the old id keep applying.
    /// Nothing is deleted or rewritten; the bridges are additive annotations.
    PostureFindings {
        /// Report what would be bridged, and what cannot be, without writing.
        #[arg(long)]
        dry_run: bool,
    },

    /// Re-seat every collection on its self-describing descriptor. A
    /// descriptor now embeds its representation's and its recipe's own
    /// descriptions, which changed its bytes and so its handle: current code
    /// computes a handle no existing collection is under. Additive -- the old
    /// collections stay readable where they are. Run it on a clone first.
    DescriptorEpoch {
        /// Report what would be re-seated, without writing.
        #[arg(long)]
        dry_run: bool,
    },

    /// Give Compass's status register the identity it never had:
    /// `board::status_of` on every complete status event written before that
    /// attribute existed. Additive; nothing is deleted or rewritten.
    StatusRegister {
        /// Report what would be written, without writing.
        #[arg(long)]
        dry_run: bool,
    },

    /// Recover the Teams OAuth credentials the collection cutover retired.
    ///
    /// The cutover deliberately left the legacy plaintext OAuth rows behind
    /// rather than republish a secret into native authority, and nothing was
    /// built to restart authentication from them — so `teams` reports a
    /// missing auth-profile source while the credentials sit on the legacy
    /// branch. This reads them, never writes to the pile, and with `--export`
    /// materializes the newest of each into `0600` files shaped for
    /// `teams login` and `secrets secret add`.
    TeamsCredentials {
        /// Directory to receive the plaintext credential files. Without it,
        /// nothing leaves the pile and only the shape is reported.
        #[arg(long, value_name = "DIR")]
        export: Option<PathBuf>,
    },

    /// List the faculty names `migrate-legacy` accepts.
    Faculties,
}

fn teams_credentials(pile: &Path, export: Option<&Path>) -> Result<()> {
    let report = teams_credentials::plan(pile).context("read legacy Teams credentials")?;
    println!("Legacy Teams credentials");
    println!("pile                     : {}", pile.display());
    if report.legacy_branch_missing {
        println!("\nThe legacy `teams` branch does not exist in this pile.");
        println!("There is nothing to recover: the credentials must be re-issued in Entra");
        println!("and published with `teams login`.");
        return Ok(());
    }
    println!("legacy authored commits  : {}", report.authored_commits);
    println!("credential rows          : {}", report.credentials.len());
    println!("unreadable payload blobs : {}", report.unreadable_payloads);
    println!(
        "tenant                   : {}",
        report.tenant().unwrap_or("(rows disagree)")
    );
    println!(
        "client id                : {}",
        report.client_id().unwrap_or("(rows disagree)")
    );
    println!(
        "signed-in user id        : {}",
        report
            .signed_in_user_id
            .as_deref()
            .unwrap_or("(not recoverable from the newest token)")
    );
    if !report.user_ids.is_empty() {
        println!("chat participants seen   : {}", report.user_ids.join(", "));
    }
    // Not a secret, and `teams login --scopes` / `teams auth set --scopes`
    // both need it verbatim.
    if let Some(scopes) = report.newest_token().and_then(|row| row.scopes.as_deref()) {
        println!("delegated scopes (newest):\n  {scopes}");
    }

    println!("\nrows, newest first (lengths only — no value is ever printed):");
    for row in &report.credentials {
        let created = row
            .created_at
            .map(|epoch| format!("{epoch}"))
            .unwrap_or_else(|| "(no recorded time)".to_owned());
        let mut carries = Vec::new();
        if let Some(len) = row.client_secret_len {
            carries.push(format!("client_secret[{len}]"));
        }
        if let Some(len) = row.access_token_len {
            carries.push(format!("access_token[{len}]"));
        }
        if let Some(len) = row.refresh_token_len {
            carries.push(format!("refresh_token[{len}]"));
        }
        if let Some(expires) = row.expires_at {
            carries.push(format!("expires={expires}"));
        }
        println!(
            "  {:<6} {:x}  {created}  {}",
            row.kind.label(),
            row.entity,
            carries.join(" ")
        );
    }

    let Some(export) = export else {
        println!("\n(nothing written; pass --export <DIR> to materialize the newest of each)");
        return Ok(());
    };
    let written = teams_credentials::export(&report, export).context("export Teams credentials")?;
    println!("\nwrote (mode 0600):");
    for file in &written {
        println!("  {}  — {}", file.path.display(), file.purpose);
    }
    println!("\nThese are live secrets in the clear. Publish them and delete the files.");
    Ok(())
}

fn descriptor_epoch(pile: &Path, key: Option<&Path>, dry_run: bool) -> Result<()> {
    let report = if dry_run {
        descriptor_epoch::plan(pile, key)?
    } else {
        descriptor_epoch::publish(pile, key)?
    };
    println!("Collection descriptor epoch");
    println!("  already self-describing : {}", report.already_current);
    println!("  already re-seated       : {}", report.settled.len());
    println!("  collections to re-seat  : {}", report.reseats.len());
    println!("  signed states to re-sign: {}", report.commits());
    for reseat in &report.reseats {
        println!(
            "    {:.16}… -> {:.16}…  scope={:X}  commits={}",
            hex::encode(reseat.old.raw),
            hex::encode(reseat.new.raw),
            reseat.scope,
            reseat.commits
        );
    }
    if !report.undescribable.is_empty() {
        println!("  left alone ({}):", report.undescribable.len());
        for (handle, reason) in &report.undescribable {
            println!("    {:.16}… {reason}", hex::encode(handle.raw));
        }
    }
    if dry_run {
        println!("  (dry run: nothing written)");
    }
    Ok(())
}

fn status_register(pile: &Path, key: Option<&Path>, dry_run: bool) -> Result<()> {
    let (delta, report) = status_register::plan(pile, key)?;
    println!("Compass status-register identities");
    println!("pile                     : {}", pile.display());
    println!("complete status events   : {}", report.complete_events);
    println!("already identified       : {}", report.already_identified);
    println!("identities to write      : {}", report.facts);
    println!("registers named          : {}", report.registers);
    // Named rather than counted away: an event with no status or no time is
    // not a state of a status register, and handing it one would let it
    // dominate a real status with nothing to say.
    println!("left alone (incomplete)  : {}", report.skipped_incomplete);

    if dry_run {
        println!("\n(dry run — nothing written)");
        return Ok(());
    }
    status_register::publish(pile, key, &delta)?;
    println!("\nwrote {} identities", report.facts);
    Ok(())
}

fn posture_findings(pile: &Path, key: Option<&Path>, dry_run: bool) -> Result<()> {
    let plan = posture_findings::plan(pile, key).context("plan Posture finding bridges")?;
    println!("Posture finding identity bridges");
    println!("pile          : {}", pile.display());
    println!("legacy findings examined : {}", plan.examined());
    println!("already bridged          : {}", plan.already_bridged());
    println!("bridgeable               : {}", plan.bridged().len());
    println!("unbridgeable             : {}", plan.unbridged().len());

    if !plan.unbridged().is_empty() {
        // Named, not counted away: an unbridgeable finding re-blocks under a new
        // id, and whoever resolved it once has to see which ones.
        let mut reasons = std::collections::BTreeMap::<&str, usize>::new();
        for entry in plan.unbridged() {
            *reasons.entry(entry.reason.as_str()).or_default() += 1;
        }
        println!("\nNOT bridged — these re-block under a new id:");
        for (reason, count) in &reasons {
            println!("  {count:>5}  {reason}");
        }
        for entry in plan.unbridged().iter().take(10) {
            println!("    {:X}  {}", entry.occurrence, entry.locator);
        }
        if plan.unbridged().len() > 10 {
            println!("    … {} more", plan.unbridged().len() - 10);
        }
    }

    if dry_run {
        println!("\n(dry run — nothing written)");
        return Ok(());
    }
    match posture_findings::publish(pile, key, plan).context("publish Posture finding bridges")? {
        Some(commit) => println!("\nwrote bridge COMMIT {:X}", commit.id()),
        None => println!("\nnothing to write"),
    }
    Ok(())
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
        Some(Command::PostureFindings { dry_run }) => {
            posture_findings(&cli.pile, cli.key.as_deref(), dry_run)
        }
        Some(Command::DescriptorEpoch { dry_run }) => {
            descriptor_epoch(&cli.pile, cli.key.as_deref(), dry_run)
        }
        Some(Command::StatusRegister { dry_run }) => {
            status_register(&cli.pile, cli.key.as_deref(), dry_run)
        }
        Some(Command::TeamsCredentials { export }) => {
            teams_credentials(&cli.pile, export.as_deref())
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
