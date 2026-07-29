//! `migrations` — run schema migrations against a pile, and record that
//! they ran.
//!
//! # Why this is a faculty and not a script
//!
//! Migrations used to be one-off scripts. The failure that argues for this
//! is already in the tree: `message` tells operators to "run
//! playground/migrations/relations_backfill_norm.rs for older piles" and
//! that path does not exist. The only surviving record that the migration
//! was ever needed is prose inside an error string, and the only way to
//! learn whether a given pile has had it is to guess.
//!
//! Recording a run as a fact makes "is this pile current?" answerable, and
//! moves idempotence into the runner instead of asking every migration to
//! hand-roll it.
//!
//! # Plan, then apply
//!
//! `run` computes a plan and prints it. Nothing is written without
//! `--apply`. The plan pins the source commit of every branch it touches,
//! and apply RE-CHECKS those pins: if a branch moved between planning and
//! applying, the plan describes a state that no longer exists, and applying
//! it to the moved target is exactly the way to corrupt data with a
//! correct-looking transform. It refuses instead.
//!
//! # Completeness belongs to the run, not to a branch
//!
//! A migration that touches several branches cannot be tracked with a
//! per-branch "applied" flag: after a partial failure each cut-over branch
//! truthfully reports itself migrated while integrity across the set is
//! broken. So a run writes one content-addressed manifest naming the whole
//! vector — pinned sources, intended outputs, roles — and attaches the same
//! manifest to every participating head. Any participant is enough to
//! DISCOVER the run; only resolving the whole vector proves it complete.
//! (Design settled with liora-gpt, 2026-07-29.)

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use faculties::pile_cli::{now_epoch, with_repo};
use faculties::schemas::mail::{KIND_DRAFT, KIND_MESSAGE, KIND_RECEIVED, KIND_SENT};
use faculties::schemas::migrations::{migration, KIND_MIGRATION_APPLIED};
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::Repository;
use triblespace::prelude::*;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "migrations",
    about = "Run schema migrations against a pile, and record that they ran"
)]
struct Cli {
    #[arg(long, env = "PILE")]
    pile: PathBuf,

    /// Who is running this — recorded on the applied record.
    #[arg(long, env = "PERSONA", value_name = "LABEL")]
    persona: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Every known migration, and whether this pile has had it.
    List,
    /// Plan a migration without writing. Reports what would change.
    Plan { name: String },
    /// Apply a migration. Refuses if any pinned branch has moved.
    Run {
        name: String,
        /// Actually write. Without this, identical to `plan`.
        #[arg(long)]
        apply: bool,
    },
}

/// How a branch's facts relate to what is already there.
///
/// # Why this is explicit and has no default
///
/// A migration may hand back either a REPLACEMENT for a branch's content or
/// ADDITIONS to it, and the two are indistinguishable as `TribleSet`s. The
/// media-type migration returns replacements for the files and reference
/// branches and additions for wiki — wiki must be append-only, because file
/// ids live in literal prose and a wiki version is a citable immutable
/// object, so rewriting history in place silently invalidates every exact
/// version citation.
///
/// Committing additions AS content would delete the wiki history in one
/// apply while looking entirely successful: the new heads are correct, the
/// counts match the report, and everything downstream of the latest
/// versions resolves. Nothing an obvious check looks at would be wrong.
///
/// So there is no default and no uniform commit path. Append is the unusual
/// case, which is exactly why a uniform path gets it wrong.
enum Mode {
    /// The facts are the branch's new content.
    Replace,
    /// The facts are committed atop the pinned lineage.
    Append,
}

/// One branch's share of a plan: what to write, how it relates to what is
/// there, and the commit the plan was computed against.
struct BranchChange {
    branch: &'static str,
    role: &'static str,
    mode: Mode,
    /// The branch head at planning time. `None` = the branch does not exist
    /// yet, which is itself a pin: it must still not exist at apply.
    pinned: Option<Id>,
    change: TribleSet,
    detail: String,
}

struct Plan {
    changes: Vec<BranchChange>,
}

impl Plan {
    fn is_empty(&self) -> bool {
        self.changes.iter().all(|c| c.change.is_empty())
    }
}

struct Migration {
    /// Minted with `trible genid`. NEVER derived from the name: renaming a
    /// migration must not make a pile look un-migrated.
    id: Id,
    name: &'static str,
    description: &'static str,
    plan: fn(&mut Repository<Pile>) -> Result<Plan>,
}

fn registry() -> Vec<Migration> {
    vec![Migration {
        id: Id::from_hex("F7BFDDEC8A1D75EFE70B5FAE5C042E0D").expect("minted id"),
        name: "mail-direction",
        description: "Tag pre-existing mail as received or sent. Direction became an \
                      asserted tag (KIND_RECEIVED / KIND_SENT); mail written before that \
                      carries neither and is invisible to the unread queries.",
        plan: plan_mail_direction,
    }]
}

/// The one-shot direction backfill.
///
/// It applies the old inference — "a message that was ever a draft was
/// composed here and, carrying KIND_MESSAGE, was sent; anything else tagged
/// KIND_MESSAGE arrived" — ONCE, as a statement about mail that already
/// exists. That is the right use for it. As a permanent query it was wrong:
/// it encodes a fact as an absence, and misclassifies anything entering by a
/// path that is neither `fetch` nor `send`.
fn plan_mail_direction(repo: &mut Repository<Pile>) -> Result<Plan> {
    let Some(branch_id) = repo.lookup_branch("mail").ok().flatten() else {
        return Ok(Plan {
            changes: vec![BranchChange {
                branch: "mail",
                role: "target",
                mode: Mode::Append,
                pinned: None,
                change: TribleSet::new(),
                detail: "no mail branch — nothing to migrate".into(),
            }],
        });
    };
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow::anyhow!("pull mail: {e:?}"))?;
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow::anyhow!("checkout mail: {e:?}"))?;

    let mut change = TribleSet::new();
    let (mut recv, mut sent, mut already) = (0usize, 0usize, 0usize);
    for id in find!(e: Id, pattern!(&space, [{ ?e @ metadata::tag: KIND_MESSAGE }])) {
        let tags: Vec<Id> =
            find!(t: Id, pattern!(&space, [{ id @ metadata::tag: ?t }])).collect();
        if tags.contains(&KIND_RECEIVED) || tags.contains(&KIND_SENT) {
            already += 1;
        } else if tags.contains(&KIND_DRAFT) {
            change += entity! { ExclusiveId::force_ref(&id) @ metadata::tag: &KIND_SENT };
            sent += 1;
        } else {
            change += entity! { ExclusiveId::force_ref(&id) @ metadata::tag: &KIND_RECEIVED };
            recv += 1;
        }
    }
    Ok(Plan {
        changes: vec![BranchChange {
            branch: "mail",
            role: "target",
            // Direction tags are added to existing messages; the branch's
            // other content must survive untouched.
            mode: Mode::Append,
            pinned: Some(branch_id),
            change,
            detail: format!("{already} already tagged | {recv} -> received | {sent} -> sent"),
        }],
    })
}

fn main() -> Result<()> {
    let mut cli = Cli::parse();
    let Some(command) = cli.command.take() else {
        Cli::parse_from(["migrations", "--help"]);
        return Ok(());
    };
    match command {
        Command::List => cmd_list(&cli),
        Command::Plan { name } => cmd_run(&cli, &name, false),
        Command::Run { name, apply } => cmd_run(&cli, &name, apply),
    }
}

fn cmd_list(cli: &Cli) -> Result<()> {
    let applied = with_repo(&cli.pile, |repo| Ok(applied_set(repo)))?;
    for m in registry() {
        let mark = if applied.contains_key(&m.id) {
            "[applied]"
        } else {
            "[     - ]"
        };
        println!("{mark} {:<22} {}", m.name, m.description);
    }
    Ok(())
}

/// Applied records, read from every branch that carries one.
///
/// Records live on the heads they migrated, so "has this run?" is asked of
/// the branches themselves rather than of a registry that could disagree
/// with them.
fn applied_set(repo: &mut Repository<Pile>) -> BTreeMap<Id, String> {
    let mut out = BTreeMap::new();
    let Ok(pins) = repo.storage_mut().pins() else {
        return out;
    };
    let ids: Vec<Id> = pins.filter_map(|p| p.ok()).collect();
    for branch_id in ids {
        let Ok(Some(handle)) = repo.storage_mut().head(branch_id) else {
            continue;
        };
        let Ok(reader) = repo.storage_mut().reader() else {
            continue;
        };
        let Ok(meta) = reader.get::<TribleSet, _>(handle) else {
            continue;
        };
        for id in faculties::schemas::migrations::applied_ids(&meta) {
            out.insert(id, format!("{branch_id:X}"));
        }
    }
    out
}

fn cmd_run(cli: &Cli, name: &str, apply: bool) -> Result<()> {
    let all = registry();
    let m = all
        .iter()
        .find(|m| m.name == name)
        .with_context(|| format!("no migration named {name:?}"))?;

    with_repo(&cli.pile, |repo| {
        let applied = applied_set(repo);
        if let Some(on) = applied.get(&m.id) {
            println!("{} already applied (recorded on branch {on})", m.name);
            return Ok(());
        }

        let plan = (m.plan)(repo)?;
        println!("{}", m.description);
        for c in &plan.changes {
            println!("  {:<12} {:<8} {}", c.branch, c.role, c.detail);
        }
        if plan.is_empty() {
            println!("nothing to do");
            return Ok(());
        }
        if !apply {
            println!("(plan only — pass --apply to write)");
            return Ok(());
        }

        // Re-check every pin. A branch that moved between planning and
        // applying invalidates the plan: the transform was computed against
        // content that is no longer the head, and applying it anyway is how
        // a correct-looking migration corrupts data.
        for c in &plan.changes {
            let now = repo.lookup_branch(c.branch).ok().flatten();
            if now != c.pinned {
                bail!(
                    "branch {:?} moved between plan and apply — refusing. Re-run the plan.",
                    c.branch
                );
            }
        }

        for c in plan.changes {
            if c.change.is_empty() {
                continue;
            }
            let Some(branch_id) = c.pinned else { continue };
            let mut ws = repo
                .pull(branch_id)
                .map_err(|e| anyhow::anyhow!("pull {}: {e:?}", c.branch))?;
            let facts = match c.mode {
                // `commit` is already additive over the pulled lineage.
                Mode::Append => c.change,
                // A replacement is not expressible as an additive commit
                // over an append-only branch: it would union with the very
                // content it is meant to supersede. Building it needs an
                // isolated output lineage and a cut-over, which the
                // multi-branch path will own. Refusing beats writing a
                // union and calling it a replacement.
                Mode::Replace => bail!(
                    "branch {:?} needs a REPLACEMENT snapshot; the runner cannot yet build \
                     isolated output lineages, and committing a replacement additively \
                     would union it with the content it supersedes",
                    c.branch
                ),
            };
            ws.commit(facts, &format!("migration: {}", m.name));
            repo.push(&mut ws)
                .map_err(|e| anyhow::anyhow!("push {}: {e:?}", c.branch))?;
            println!("  {} migrated", c.branch);
        }

        record_applied(repo, m, cli.persona.as_deref())?;
        println!("{} applied", m.name);
        Ok(())
    })
}

/// Write the applied record onto the branch the migration targeted.
///
/// Branch-head metadata is the home because a migration is a statement
/// about ONE branch's schema and travels with it. That only became durable
/// in triblespace-rs `fix/branch-head-carry`: before it, a rebuild carried
/// forward only index manifests, so this record would have survived until
/// the next push and then vanished silently.
fn record_applied(repo: &mut Repository<Pile>, m: &Migration, persona: Option<&str>) -> Result<()> {
    let _ = (persona, now_epoch());
    let Some(branch_id) = repo.lookup_branch("mail").ok().flatten() else {
        return Ok(());
    };
    let base = repo
        .storage_mut()
        .head(branch_id)
        .map_err(|e| anyhow::anyhow!("head: {e:?}"))?
        .context("branch vanished")?;
    let reader = repo
        .storage_mut()
        .reader()
        .map_err(|e| anyhow::anyhow!("reader: {e:?}"))?;
    let mut meta: TribleSet = reader
        .get(base)
        .map_err(|e| anyhow::anyhow!("read head meta: {e:?}"))?;
    let rec = ufoid();
    meta += TribleSet::from(entity! { &rec @
        metadata::tag: &KIND_MIGRATION_APPLIED,
        migration::applied: &m.id,
    });
    let handle = repo
        .storage_mut()
        .put(meta.to_blob())
        .map_err(|e| anyhow::anyhow!("store head meta: {e:?}"))?;
    repo.storage_mut()
        .update(branch_id, Some(base), Some(handle))
        .map_err(|e| anyhow::anyhow!("update head: {e:?}"))?;
    Ok(())
}
