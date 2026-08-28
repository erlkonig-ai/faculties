//! `migrations` — inspect and execute explicitly named Faculties migrations.
//!
//! Every migration verb lives here, and nowhere else. The faculties read
//! native collections only; a pile written before the storage cutover keeps
//! all of its data on named legacy branches that no faculty consults, and this
//! binary is the single path from there to here. It is kept forever for
//! exactly that reason: deleting it would make an existing user's data
//! invisible the day they upgrade.
//!
//! - `legacy-branches plan|activate` is the original whole-pile transition
//!   from named branch pins into native collections.
//! - `secrets-direct-proofs plan|activate` additively bridges the unpublished
//!   subject-bearing Secrets access envelopes to direct native proofs.
//! - `descriptor-authority` re-seats ordinary named roots from the retired
//!   namespace/open-admission descriptor epoch under one mandatory authority.
//! - `migrate-legacy <faculty>` migrates one faculty's branch in place, which
//!   is what that faculty's own `migrate-legacy` subcommand used to do.
//! - `status-register` gives Compass's status register the identity it never
//!   had, on the events written before that identity existed.
//! - `memory-journal` inspects and activates the source-bound transition from
//!   Memory's retired revision DAG to its immutable episodic journal.
//! - `mail-credentials` recovers the mail account the Secrets cutover sealed
//!   and retired, so `mail` can be configured again without re-deriving a
//!   password nobody wrote down.
//! - `faculties` lists the names `migrate-legacy` accepts.
//!
//! No command writes migration bookkeeping facts, and none deletes, consumes,
//! or rewrites a legacy branch.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};

use faculties_migrations::per_faculty::{self, Faculty};
use faculties_migrations::{
    activation_cutover, collection_cutover, collection_naming, descriptor_authority,
    disposable_cutover, legacy_password, mail_credentials, memory_journal, posture_findings,
    secrets_direct_proofs, status_register, teams_credentials,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "migrations",
    about = "Plan and execute explicitly named Faculties data migrations"
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
    /// With every pile writer stopped, move the original named legacy branches
    /// into native collections through a validated disposable replacement.
    LegacyBranches {
        #[command(subcommand)]
        action: StoppedWorldAction,
    },

    /// Additively bridge retired subject-bearing Secrets access envelopes to
    /// direct native capability proofs. The durable pile signer is the sole
    /// trust root; this migration never asks for a password.
    SecretsDirectProofs {
        #[command(subcommand)]
        action: AdditiveAction,
    },

    /// Move selected canonical chunks from the retired Memory revision DAG
    /// into the immutable episodic journal. The private omission manifest is
    /// bound to one exact source fact set; stop old Memory writers between
    /// inspection, planning, and activation.
    MemoryJournal {
        #[command(subcommand)]
        action: MemoryJournalAction,
    },

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

    /// Re-seat every scoped root collection onto a name within a namespace.
    ///
    /// A root used to be anchored by an opaque minted scope id, so the pile
    /// could not say which collection was which; it is now a name plus the
    /// historical namespace key. That moves the descriptor's handle, so current code
    /// looks for a collection nobody wrote and finds an empty one where the
    /// data is. Additive: the scoped collections stay exactly where they are
    /// and this appends the named ones beside them.
    CollectionNaming {
        /// Report what would move, without writing.
        #[arg(long)]
        dry_run: bool,
        /// Name a scope this build does not know, as `<32-hex>=<name>`.
        ///
        /// The built-in table is written against this repository's schema
        /// constants, which cannot reach a consumer that lives elsewhere. Its
        /// constants stay in its own repository and it names its own scopes
        /// here, rather than a private id being copied into a public crate
        /// where the two would quietly drift apart.
        #[arg(long = "name", value_name = "HEX=NAME")]
        names: Vec<String>,
    },

    /// Re-seat ordinary faculty roots into UTF-8, mandatory-authority descriptors.
    ///
    /// This is an additive one-shot epoch migration. It reuses every exact
    /// data/metadata blob and re-signs each distinct retired leaf under the
    /// new descriptor. Derived caches are left for lazy reconstruction and
    /// Secrets is deliberately deferred to its handle-aware migration.
    DescriptorAuthority {
        /// Validate and report the exact publication without writing.
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
    /// `teams login --vault <id>` and `secrets secret add --vault <id>`.
    TeamsCredentials {
        /// Directory to receive the plaintext credential files. Without it,
        /// nothing leaves the pile and only the shape is reported.
        #[arg(long, value_name = "DIR")]
        export: Option<PathBuf>,
    },

    /// Recover the Mail account the Secrets cutover retired.
    ///
    /// A pre-cutover mail account lived on the legacy `secrets` branch as a
    /// cleartext address plus a password-locked envelope holding the mailbox
    /// password, hosts, and ports. `secrets_cutover` retires that record by
    /// design and nothing was built to restart from it, so `mail account list`
    /// is empty while the only copy of the password sits sealed on the legacy
    /// branch. This reads it, never writes to the pile, and with `--export`
    /// unlocks the envelope and materializes the password into a `0600` file
    /// next to the exact `mail account set` line that consumes it.
    ///
    /// Reporting needs no password; `--export` needs FACULTIES_SECRETS_PW (or
    /// the configured password file), because the retired envelope predates
    /// direct Secrets vault epochs and is keyed on the retired root password.
    MailCredentials {
        /// Directory to receive the plaintext mailbox password. Without it,
        /// nothing is unsealed and only the shape is reported.
        #[arg(long, value_name = "DIR")]
        export: Option<PathBuf>,
    },

    /// List the faculty names `migrate-legacy` accepts.
    Faculties,
}

#[derive(Clone, Copy, Subcommand)]
enum StoppedWorldAction {
    /// Validate the frozen legacy source and report the disposable replacement.
    Plan,
    /// With every pile writer stopped, atomically replace the validated source.
    Activate,
}

#[derive(Clone, Copy, Subcommand)]
enum AdditiveAction {
    /// Read and validate the exact predecessor/successor state without writing.
    Plan,
    /// Append missing proof closures and one successor inbox COMMIT per vault.
    Activate,
}

#[derive(Clone, Subcommand)]
enum MemoryJournalAction {
    /// Print the frozen legacy source shape and digest needed by a private
    /// omission manifest. Nothing is written.
    Inspect,
    /// Validate one exact source-bound omission manifest and target candidate
    /// without writing.
    Plan {
        #[arg(long, value_name = "PATH")]
        manifest: PathBuf,
    },
    /// Append the exact selected journal seed, then rematerialize and verify
    /// it. Exact replay appends nothing.
    Activate {
        #[arg(long, value_name = "PATH")]
        manifest: PathBuf,
    },
}

fn print_memory_journal_report(plan: &memory_journal::JournalPlan) {
    println!("Memory revision DAG -> episodic journal");
    println!("source facts          : {}", plan.source.facts);
    println!("source commits        : {}", plan.source.commits);
    println!("source chunks         : {}", plan.source.chunks);
    println!(
        "source digest         : blake3:{}",
        plan.source.digest_hex()
    );
    println!("selected chunks       : {}", plan.selected_chunks);
    println!("omitted chunks        : {}", plan.omitted_chunks);
    println!("selected facts        : {}", plan.selected_facts);
    println!("target chunks before  : {}", plan.target_chunks_before);
    println!(
        "publication           : {}",
        if plan.already_complete {
            "already complete"
        } else {
            "pending"
        }
    );
}

fn memory_journal(pile: &Path, key: Option<&Path>, action: MemoryJournalAction) -> Result<()> {
    match action {
        MemoryJournalAction::Inspect => {
            let source = memory_journal::inspect_path(pile, key)?;
            println!("Memory revision-DAG source");
            println!("pile          : {}", pile.display());
            println!("source-facts  : {}", source.facts);
            println!("source-chunks : {}", source.chunks);
            println!("source-commits: {}", source.commits);
            println!("source-digest : {}", source.digest_hex());
            println!();
            println!("Manifest header:");
            println!("memory-journal-omit-v1");
            println!("source-facts {}", source.facts);
            println!("source-chunks {}", source.chunks);
            println!("source-digest {}", source.digest_hex());
            println!("omit <32-hex-memory-id>");
        }
        MemoryJournalAction::Plan { manifest } => {
            let plan = memory_journal::plan_path(pile, key, &manifest)?;
            print_memory_journal_report(&plan);
            println!("\n(dry run — nothing written)");
        }
        MemoryJournalAction::Activate { manifest } => {
            let (plan, outcome) = memory_journal::activate(pile, key, &manifest)?;
            print_memory_journal_report(&plan);
            match outcome {
                memory_journal::ActivationOutcome::Published(commit) => {
                    println!("\npublished and verified COMMIT {:X}", commit.id());
                }
                memory_journal::ActivationOutcome::AlreadyComplete => {
                    println!("\ntarget already contained the complete selected journal; nothing appended");
                }
            }
        }
    }
    Ok(())
}

fn plan_secrets_direct_proofs(pile: &Path, key: Option<&Path>) -> Result<()> {
    let signer = faculties::storage::load_signer(pile, key)
        .context("load durable signer for Secrets direct-proof planning")?;
    let plan = secrets_direct_proofs::plan_path(pile, &signer)
        .context("plan Secrets direct-proof bridge")?;

    let pending = plan.count(secrets_direct_proofs::DirectProofState::Pending);
    let complete = plan.count(secrets_direct_proofs::DirectProofState::Complete);
    let ambiguous = plan.count(secrets_direct_proofs::DirectProofState::Ambiguous);
    let malformed = plan.count(secrets_direct_proofs::DirectProofState::Malformed);
    println!("Retired Secrets envelopes -> direct capability proofs");
    println!("pile        : {}", pile.display());
    println!(
        "publication : {}",
        if plan.is_blocked() {
            "blocked"
        } else if pending == 0 {
            "complete"
        } else {
            "pending"
        }
    );
    println!("pending     : {pending}");
    println!("complete    : {complete}");
    println!("ambiguous   : {ambiguous}");
    println!("malformed   : {malformed}");
    println!("proofs      : {} pending", plan.pending_proofs());
    println!("inbox commits: {pending} pending");
    println!();
    println!("Vaults and candidates:");
    for report in plan.reports() {
        let subject = report
            .vault
            .map(|vault| format!("vault {vault:X}"))
            .or_else(|| {
                report
                    .predecessor
                    .map(|candidate| format!("candidate {candidate:X}"))
            })
            .unwrap_or_else(|| "unidentified candidate".to_owned());
        let secrets = report
            .secret_versions
            .map(|count| format!(" | {count} secret(s)"))
            .unwrap_or_default();
        println!(
            "- {subject} | {}{secrets} | {}",
            report.state.label(),
            report.detail
        );
    }
    if plan.reports().is_empty() {
        println!("- no retired subject-bearing envelopes were found");
    }
    println!();
    if plan.is_blocked() {
        println!("Activation will refuse to append while any candidate is ambiguous or malformed.");
    } else if pending == 0 {
        println!("Every retired envelope already has one exact direct-proof successor; activation would leave the pile unchanged.");
    } else {
        println!("Activation will append each pending proof closure, then one root-signed access-inbox COMMIT per vault.");
    }
    Ok(())
}

fn activate_secrets_direct_proofs(pile: &Path, key: Option<&Path>) -> Result<()> {
    let signer = faculties::storage::load_signer(pile, key)
        .context("load durable signer for Secrets direct-proof activation")?;
    match secrets_direct_proofs::activate(pile, &signer)
        .context("activate additive Secrets direct-proof bridge")?
    {
        secrets_direct_proofs::AdditiveActivationOutcome::Published { inbox_commits } => println!(
            "Activated {inbox_commits} direct-proof access successor(s); retired rows remain inert and unchanged."
        ),
        secrets_direct_proofs::AdditiveActivationOutcome::AlreadyActive => println!(
            "Secrets direct-proof publication was already complete; the live pile was unchanged."
        ),
    }
    Ok(())
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
    println!(
        "\nThese are live secrets in the clear. Select one exact ready vault epoch, publish them with its id, and delete the files."
    );
    Ok(())
}

fn mail_credentials(pile: &Path, export: Option<&Path>) -> Result<()> {
    let report = mail_credentials::plan(pile).context("read the retired Mail account")?;
    println!("Retired Mail account");
    println!("pile                     : {}", pile.display());
    if report.legacy_branch_missing {
        println!("\nThe legacy `secrets` branch does not exist in this pile.");
        println!("There is nothing to recover: configure the account from scratch with");
        println!("`mail account set`.");
        return Ok(());
    }
    println!("legacy authored commits  : {}", report.authored_commits);
    println!("account records          : {}", report.accounts.len());
    println!("unreadable envelopes     : {}", report.unreadable_envelopes);
    println!(
        "active address           : {}",
        report
            .active_address
            .as_deref()
            .unwrap_or("(no pointer was ever set)")
    );

    if report.accounts.is_empty() {
        println!("\nThe legacy branch carries no Mail account record.");
        println!("Nothing was sealed here, so nothing can be recovered: configure the");
        println!("account from scratch with `mail account set`.");
        return Ok(());
    }

    println!("\nrecords, newest first (the envelope stays sealed — nothing here is its content):");
    for row in &report.accounts {
        let created = row
            .created_at
            .map(|epoch| format!("{epoch}"))
            .unwrap_or_else(|| "(no recorded time)".to_owned());
        let envelope = match row.envelope_len {
            Some(len) => format!("envelope[{len}] {:.16}…", row.envelope_handle),
            None => "envelope UNREADABLE".to_owned(),
        };
        println!("  {:x}  {created}  {}  {envelope}", row.entity, row.address);
    }

    let Some(selected) = report.selected() else {
        println!("\nNo record still has a readable envelope; the password is not recoverable.");
        return Ok(());
    };

    let Some(export) = export else {
        println!(
            "\n(nothing unsealed; pass --export <DIR> to open {} and write its password)",
            selected.address
        );
        return Ok(());
    };

    let password = legacy_password::read("unlock the retired Mail account envelope")?;
    let recovered = mail_credentials::open(selected, &password)?;
    let written =
        mail_credentials::export(&recovered, export).context("export mailbox password")?;
    println!("\nwrote (mode 0600):");
    println!("  {}  — {}", written.path.display(), written.purpose);
    println!("\nrecovered settings (not secrets — `mail account set` needs them back):");
    println!("  address       : {}", recovered.address);
    println!("  display name  : {}", recovered.display_name);
    println!("  POP endpoint  : {}", recovered.pop_endpoint);
    println!("  SMTP endpoint : {}", recovered.smtp_endpoint);
    println!("  password      : {} bytes", recovered.password_len);

    // Deliberately a worklist, not an action. `mail account set` owns sealing
    // the password into one exact ready Secrets vault epoch; recovery
    // cannot choose that authority-scoped destination on the operator's behalf.
    println!("\nto publish it (select one exact ready vault epoch with `secrets vault list`):");
    println!(
        "  MAIL_PASS=\"$(cat {})\" mail account set \\\n    --address {} --display-name {:?} \\\n    --pop-endpoint {} --smtp-endpoint {} \\\n    --vault <vault-id>",
        written.path.display(),
        recovered.address,
        recovered.display_name,
        recovered.pop_endpoint,
        recovered.smtp_endpoint,
    );
    println!("\nThe exported file is a live secret in the clear. Publish it and delete it.");
    Ok(())
}

fn status_register(pile: &Path, key: Option<&Path>, dry_run: bool) -> Result<()> {
    let report = if dry_run {
        status_register::plan(pile, key)?.1
    } else {
        status_register::publish(pile, key)?
    };
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
    println!("\nwrote {} identities", report.facts);
    Ok(())
}

fn collection_naming(
    pile: &Path,
    key: Option<&Path>,
    dry_run: bool,
    names: &[String],
) -> Result<()> {
    let extra = names
        .iter()
        .map(|spec| {
            let (hex, name) = spec
                .split_once('=')
                .with_context(|| format!("--name wants <32-hex>=<name>, got {spec:?}"))?;
            let scope = triblespace::core::id::Id::from_hex(hex)
                .ok_or_else(|| anyhow::anyhow!("{hex:?} is not a 32-character hex id"))?;
            let name = collection_naming::CollectionName::new(name)
                .map_err(|error| anyhow::anyhow!("{name:?} is not a legal name: {error}"))?;
            Ok(collection_naming::ExtraName { scope, name })
        })
        .collect::<Result<Vec<_>>>()?;

    let report = if dry_run {
        collection_naming::plan(pile, key, &extra).context("plan the collection naming")?
    } else {
        collection_naming::publish(pile, key, &extra).context("publish the collection naming")?
    };

    println!("Collection naming: scope anchors become names within a namespace");
    println!("pile              : {}", pile.display());
    println!("already named     : {}", report.already_named);
    println!("settled           : {}", report.settled.len());
    println!(
        "{:<18}: {} collection(s), {} state(s)",
        if dry_run { "would move" } else { "moved" },
        report.renames.len(),
        report.commits()
    );

    if !report.renames.is_empty() {
        // Grouped by destination, because several old collections can share
        // one. The descriptor epoch left both an opaque and a self-describing
        // descriptor for the same scope, each with its own handle; both carry
        // the same meaning and so take the same name, and re-seating them
        // merges them. Printed ungrouped that looks like a collection appearing
        // twice by mistake, when it is in fact the duplication being healed.
        let mut by_name: std::collections::BTreeMap<&str, (usize, usize)> =
            std::collections::BTreeMap::new();
        for rename in &report.renames {
            let entry = by_name.entry(rename.name.as_str()).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += rename.commits;
        }
        println!();
        for (name, (sources, states)) in &by_name {
            if *sources == 1 {
                println!("  {name:<16} {states:>6} state(s)");
            } else {
                println!("  {name:<16} {states:>6} state(s)   from {sources} descriptors, merged");
            }
        }
        println!(
            "\n  {} source collection(s) -> {} named collection(s)",
            report.renames.len(),
            by_name.len()
        );
        println!("  State counts are per source; shared states are written once.");
    }

    if !report.unnamed.is_empty() {
        // Named, not counted away. An unnamed collection is one this build
        // does not recognise, and it stays unreachable through the new anchor
        // until someone decides what it is -- which is the right outcome, but
        // only if they are told.
        println!("\nNOT named — these stay reachable only under their old anchor:");
        for (handle, reason) in &report.unnamed {
            println!("  {}  {reason}", hex::encode(&handle.raw[..8]));
        }
    }

    if dry_run {
        println!("\nDry run: nothing was written. Re-run without --dry-run to append.");
        println!("The scoped collections are not removed either way — a pile is");
        println!("append-only, and the reframe is what drops them.");
    }
    Ok(())
}

fn run_descriptor_authority(pile: &Path, key: Option<&Path>, dry_run: bool) -> Result<()> {
    let report = if dry_run {
        (descriptor_authority::plan_path(pile, key)?, None)
    } else {
        let published = descriptor_authority::publish_path(pile, key)?;
        (published.plan, Some(published.appended_commits))
    };
    let (plan, appended) = report;

    println!("Collection descriptor authority epoch");
    println!("pile             : {}", pile.display());
    println!("ordinary roots   : {}", plan.roots.len());
    println!(
        "source commits   : {}",
        plan.roots
            .iter()
            .map(|root| root.source_commits)
            .sum::<usize>()
    );
    println!(
        "target commits   : {}",
        plan.roots
            .iter()
            .map(|root| root.target_commits)
            .sum::<usize>()
    );
    println!("missing commits  : {}", plan.missing_commits());
    println!("invalid records  : {}", plan.invalid_records);
    if let Some(appended) = appended {
        println!("appended commits : {appended}");
    }

    if !plan.roots.is_empty() {
        println!("\nOrdinary roots:");
        for root in &plan.roots {
            println!(
                "- {:<18} {} source -> {} target, {} missing; skipped {} MERGE / {} DERIVE",
                root.name,
                root.source_commits,
                root.target_commits,
                root.missing_commits,
                root.skipped_merges,
                root.skipped_derives,
            );
        }
    }
    if !plan.residues.is_empty() {
        println!("\nResidue (not translated):");
        for residue in &plan.residues {
            println!(
                "- {:.16}… {:?}, {} record(s): {}",
                hex::encode_upper(residue.collection.raw),
                residue.kind,
                residue.records,
                residue.detail
            );
        }
    }
    if dry_run {
        println!("\n(dry run — nothing written; stop old-epoch writers before activation)");
    }
    Ok(())
}

fn posture_findings(pile: &Path, key: Option<&Path>, dry_run: bool) -> Result<()> {
    let (plan, published) = if dry_run {
        (
            posture_findings::plan(pile, key).context("plan Posture finding bridges")?,
            None,
        )
    } else {
        posture_findings::publish(pile, key).context("publish Posture finding bridges")?
    };
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
    match published {
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

fn legacy_branches_plan(
    source: &collection_cutover::FrozenSource,
    signer: &ed25519_dalek::SigningKey,
) -> Result<activation_cutover::ActivationPlan> {
    let first = activation_cutover::plan(source, signer, None);
    let password;
    match first {
        Ok(plan) => Ok(plan),
        Err(error) if activation_cutover::requires_legacy_password(&error) => {
            password = Zeroizing::new(legacy_password::read(
                "re-seal a legacy Secrets DEK during direct activation",
            )?);
            activation_cutover::plan(source, signer, Some(password.as_slice()))
                .context("plan direct Secrets activation with the configured legacy password")
        }
        Err(error) => Err(error),
    }
}

fn plan_legacy_branches(pile: &Path, key: Option<&Path>) -> Result<()> {
    let signer = faculties::storage::load_signer(pile, key)
        .context("load durable signer for activation planning")?;
    let source = collection_cutover::freeze_source(pile)
        .with_context(|| format!("freeze legacy-branch source {}", pile.display()))?;
    let plan = legacy_branches_plan(&source, &signer)
        .context("plan legacy-branch collection migration")?;
    let presence = disposable_cutover::inspect_publication(&source, &signer, &plan)
        .context("inspect legacy-branch publication")?;

    let semantic = source.fingerprint();
    let physical = source.physical_fingerprint();
    println!("Legacy branches -> native collections plan");
    println!("source       : {}", pile.display());
    println!("source bytes : {}", physical.length);
    println!("source hash  : blake3:{}", hex::encode(physical.digest));
    println!("legacy pins  : {}", semantic.pin_count);
    println!("pin digest   : blake3:{}", hex::encode(semantic.digest));
    println!("publication  : {}", presence.status().label());
    println!();

    println!("Collections:");
    for (collection, publication) in plan.collections().iter().zip(presence.collections()) {
        let view = match collection.view() {
            activation_cutover::CandidateViewKey::Faculty(scope) => {
                format!("faculty {scope:X}")
            }
            activation_cutover::CandidateViewKey::AccessInbox => "Secrets access inbox".into(),
            activation_cutover::CandidateViewKey::Vault(vault) => format!("vault {vault:X}"),
        };
        println!(
            "- {} | {} | {} | {}/{} exact COMMIT(s) | {}/{} native proof(s) | {}/{} dependency blob(s) | {} fact(s) | {:?}",
            collection.name().as_str(),
            view,
            publication.status().label(),
            publication.present_commits(),
            publication.planned_commits(),
            publication.present_proofs(),
            publication.planned_proofs(),
            publication.resident_dependencies(),
            publication.required_dependencies(),
            collection.expected_facts().len(),
            collection.policy(),
        );
    }

    println!();
    match presence.status() {
        disposable_cutover::NativePublicationStatus::Complete => println!(
            "All exact legacy-branch publications are already complete. `legacy-branches activate` would add no planned collection bytes; it remains the authoritative aggregate semantic validation."
        ),
        disposable_cutover::NativePublicationStatus::Partial => println!(
            "Legacy-branch publication is partial. `legacy-branches activate` is the authoritative check for whether the deterministic remainder can be completed and validated."
        ),
        disposable_cutover::NativePublicationStatus::Missing => println!(
            "Legacy-branch publication is missing. `legacy-branches activate` would publish and validate the deterministic plan."
        ),
    }

    println!();
    println!("Source transforms:");
    for consumption in plan.consumptions() {
        let retirement = match consumption.retired_source_facts() {
            0 => String::new(),
            count => format!(" | {count} retired source fact(s)"),
        };
        println!(
            "- {} | {} source pin(s){}",
            consumption.name(),
            consumption.source_pins().len(),
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

fn activate_legacy_branches(pile: &Path, key: Option<&Path>) -> Result<()> {
    let signer = faculties::storage::load_signer(pile, key)
        .context("load durable signer for disposable activation")?;
    let source = collection_cutover::freeze_source(pile)
        .with_context(|| format!("freeze legacy-branch source {}", pile.display()))?;
    let plan = legacy_branches_plan(&source, &signer)
        .context("plan legacy-branch collection migration")?;
    let retired_source_facts = plan.retired_source_facts();
    let outcome = disposable_cutover::activate(
        pile,
        &signer,
        &source,
        &plan,
        activation_cutover::validate_candidate_views,
    )
    .context("activate disposable native-collection candidate")?;

    match outcome {
        disposable_cutover::ActivationOutcome::Activated { appended_bytes } => {
            println!(
                "Activated legacy branches into native collections by appending {appended_bytes} candidate byte(s); the original source prefix is preserved exactly."
            );
        }
        disposable_cutover::ActivationOutcome::AlreadyActive => {
            println!("Legacy-branch activation was already complete; the live pile was unchanged.");
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
        Some(Command::LegacyBranches { action }) => match action {
            StoppedWorldAction::Plan => plan_legacy_branches(&cli.pile, cli.key.as_deref()),
            StoppedWorldAction::Activate => activate_legacy_branches(&cli.pile, cli.key.as_deref()),
        },
        Some(Command::SecretsDirectProofs { action }) => match action {
            AdditiveAction::Plan => plan_secrets_direct_proofs(&cli.pile, cli.key.as_deref()),
            AdditiveAction::Activate => {
                activate_secrets_direct_proofs(&cli.pile, cli.key.as_deref())
            }
        },
        Some(Command::MemoryJournal { action }) => {
            memory_journal(&cli.pile, cli.key.as_deref(), action)
        }
        Some(Command::MigrateLegacy { faculty }) => {
            per_faculty::migrate(faculty, &cli.pile, cli.key.as_deref())
        }
        Some(Command::PostureFindings { dry_run }) => {
            posture_findings(&cli.pile, cli.key.as_deref(), dry_run)
        }
        Some(Command::CollectionNaming { dry_run, names }) => {
            collection_naming(&cli.pile, cli.key.as_deref(), dry_run, &names)
        }
        Some(Command::DescriptorAuthority { dry_run }) => {
            run_descriptor_authority(&cli.pile, cli.key.as_deref(), dry_run)
        }
        Some(Command::StatusRegister { dry_run }) => {
            status_register(&cli.pile, cli.key.as_deref(), dry_run)
        }
        Some(Command::TeamsCredentials { export }) => {
            teams_credentials(&cli.pile, export.as_deref())
        }
        Some(Command::MailCredentials { export }) => mail_credentials(&cli.pile, export.as_deref()),
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
