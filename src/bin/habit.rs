//! Work with pull-based standing intentions in one fixed native collection.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::habits::{self, Catalog, DeclaredState, Habit, State};
use faculties::schemas::habit::{Condition, DEFAULT_SCOPE_ID};
use hifitime::Epoch;
use triblespace::prelude::*;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "habit",
    about = "Standing intentions, pulled rather than pushed"
)]
struct Cli {
    /// Path to the pile file.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Ordinary operations never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Add one immutable standing intention.
    Add {
        /// Short command-facing name, for example `git-lineage-hygiene`.
        label: String,
        /// `every <duration>`, `daily at <HH:MM>`, or `when <command>`.
        ///
        /// Inside `when`, the word `@script` stands for the executable
        /// attached by `--script`: it expands, on whichever window is
        /// evaluating, to the local path of that blob. Write
        /// `--when "when @script --due"` instead of an absolute path, and
        /// the intention means the same thing in every window.
        #[arg(long, value_name = "CONDITION")]
        when: String,
        /// What to do when the intention is due. Supports @file and @-.
        #[arg(long, value_name = "TEXT")]
        nudge: String,
        /// Executable to carry inside the intention, so it needs nothing
        /// machine-local. The bytes are stored in the definition itself and
        /// addressed by content hash; refer to them as `@script` in `--when`.
        /// Pass a path, or `@-` to read the program from stdin.
        #[arg(long, value_name = "PATH")]
        script: Option<String>,
        /// Definition this one replaces, by id or id prefix. Repeatable, to
        /// join several revisions into one. Definitions are immutable, so a
        /// revised intention is a new definition citing the one it retires;
        /// the retired revision stays in the collection as history.
        #[arg(long, value_name = "ID")]
        supersedes: Vec<String>,
    },
    /// List every standing intention and its current fork-visible state.
    List,
    /// Print only intentions which are due now.
    Due,
    /// Record completion. The cooldown starts at this occurrence.
    ///
    /// Addressed by label or by id prefix; an ambiguous label is reported
    /// rather than resolved, because a label is a display name, not a key.
    Done { label: String },
    /// Assert paused state, reconciling every state head currently observed.
    ///
    /// Pausing suspends a definition; it does not replace it. To revise an
    /// intention, `add` the new definition with `--supersedes <id>`.
    Pause { label: String },
    /// Assert active state, reconciling every state head currently observed.
    Resume { label: String },
    /// Validate the complete native Habit catalog and its attachments.
    Check,
}

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn point(epoch: Epoch) -> habits::IntervalValue {
    (epoch, epoch).try_to_inline().unwrap()
}

fn now_secs() -> i64 {
    (now_epoch().to_tai_duration().total_nanoseconds() / 1_000_000_000) as i64
}

fn id_list(habits: &[&Habit]) -> String {
    habits
        .iter()
        .map(|habit| format!("{:x}", habit.id))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Resolve a command-line selector to exactly one live definition.
///
/// A label is a display name, not a key — several definitions may carry it, and
/// none of them owns it. So a selector is a label *or* an intrinsic id prefix,
/// and an ambiguous label is reported with its candidates rather than resolved
/// by picking one. Picking one is the distributed bug: which definition a name
/// resolves to would then depend on which facts this window happens to have
/// observed, and two windows would disagree while each was locally correct.
fn select_live_habit<'a>(catalog: &'a Catalog, selector: &str) -> Result<&'a Habit> {
    let selector = selector.trim();
    let live: Vec<_> = catalog
        .live()
        .into_iter()
        .filter(|habit| habit.label.eq_ignore_ascii_case(selector))
        .collect();
    match live.as_slice() {
        [habit] => return Ok(*habit),
        [] => {}
        many => bail!(
            "label {selector:?} names {} live Habits; address one by id: {}",
            many.len(),
            id_list(many)
        ),
    }

    let id =
        faculties::resolve_id_prefix(selector, catalog.live().into_iter().map(|habit| habit.id))
            .map_err(|error| anyhow!("no Habit labelled {selector:?}, and {error}"))?;
    let habit = catalog
        .habit(id)
        .ok_or_else(|| anyhow!("no live Habit {id:x}"))?;
    if catalog.is_superseded(id) {
        bail!("Habit {id:x} is superseded history and cannot be mutated");
    }
    Ok(habit)
}

/// Resolve one revision predecessor by intrinsic id or id prefix.
///
/// A full id deliberately need not be present in this partial view. The model
/// permits a successor to arrive before the definition it retires; once that
/// predecessor arrives, the already-authored edge retires it monotonically.
fn resolve_predecessor(catalog: &Catalog, selector: &str) -> Result<Id> {
    faculties::resolve_id_prefix(selector, catalog.habits().map(|habit| habit.id))
        .map_err(|error| anyhow!("invalid superseded Habit id {selector:?}: {error}"))
}

/// Read a program to carry, from a path or from stdin.
///
/// Deliberately byte-exact rather than text: what is stored has to be what
/// runs, and a carried program may be a compiled binary.
fn script_arg(raw: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    if raw == "@-" {
        let mut bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut bytes)
            .context("read Habit script from stdin")?;
        return Ok(bytes);
    }
    // `@@` escapes a path that genuinely begins with `@`, matching `text_arg`.
    let path = match raw.strip_prefix("@@") {
        Some(rest) => format!("@{rest}"),
        None => raw.to_owned(),
    };
    std::fs::read(&path).with_context(|| format!("read Habit script from {path}"))
}

fn cmd_add(
    pile: &Path,
    key: Option<&Path>,
    label: String,
    when: String,
    nudge: String,
    script: Option<String>,
    supersedes: Vec<String>,
) -> Result<()> {
    let nudge = faculties::text_arg(&nudge, "Habit nudge")?;
    let script = script.as_deref().map(script_arg).transpose()?;
    // Describe the attachment from the bytes in hand. Re-reading the catalog
    // afterwards would be a second full materialization just to print a hash.
    let carried = script
        .as_ref()
        .map(|bytes| {
            format!(
                " · script {} ({} bytes, carried in the pile)",
                habits::script_digest(bytes)[..8].to_owned(),
                bytes.len()
            )
        })
        .unwrap_or_default();
    let parsed_label = label.trim().to_owned();
    let cooldown = Condition::parse(when.trim())
        .map_err(anyhow::Error::msg)?
        .cooldown_secs;
    let catalog = habits::read_catalog(pile, key)?;
    let mut retiring = supersedes
        .iter()
        .map(|selector| resolve_predecessor(&catalog, selector))
        .collect::<Result<Vec<_>>>()?;
    retiring.sort_unstable();
    retiring.dedup();
    let (fragment, id) = habits::habit_fragment(label, when, nudge, script, &retiring)?;
    if catalog.habit(id).is_some() {
        println!("Habit already present [{id:x}]");
        return Ok(());
    }
    habits::publish(pile, key, fragment)?;
    println!("added {parsed_label} [{id:x}] · cooldown {cooldown}s{carried}");
    for retired in &retiring {
        println!("  supersedes [{retired:x}]");
    }

    // A shared label is legal and sometimes correct — two windows may have
    // authored the same intention independently. Say so rather than refusing:
    // the label is not a key, and nothing here may retire a definition the
    // author did not name.
    let sharing: Vec<_> = catalog
        .live()
        .into_iter()
        .filter(|habit| {
            habit.label.eq_ignore_ascii_case(&parsed_label) && !retiring.contains(&habit.id)
        })
        .collect();
    if !sharing.is_empty() {
        println!(
            "  note: {} other live Habit(s) share this label and remain live: {}",
            sharing.len(),
            id_list(&sharing)
        );
        println!("        add `--supersedes <id>` if this revision replaces one.");
    }
    Ok(())
}

fn state_detail(state: &State) -> Option<String> {
    match state {
        State::Forked(heads) => Some(format!(
            "state heads disagree: {}",
            heads
                .iter()
                .map(|(id, state)| format!("{id:x}={}", state.as_str()))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        State::Unparseable(error) | State::Failed(error) => Some(error.clone()),
        _ => None,
    }
}

fn cmd_list(pile: &Path, key: Option<&Path>, only_due: bool) -> Result<()> {
    let catalog = habits::read_catalog(pile, key)?;
    let now = now_secs();
    let at = habits::evaluation_dir(pile);
    let mut shown = 0usize;
    let mut unevaluable = 0usize;
    for row in catalog.rows()? {
        let state = habits::evaluate(&row, now, &at);
        if only_due {
            if state.is_due() {
                shown += 1;
                println!("{}: {}", row.label, row.nudge);
            } else if let Some(detail) = state_detail(&state) {
                // An intention whose state could not be decided is reported,
                // never filtered. A habit that quietly stops firing is the one
                // failure nobody notices.
                unevaluable += 1;
                eprintln!(
                    "{} [{:x}] {}: {detail}",
                    row.label,
                    row.id,
                    state.word().to_ascii_lowercase()
                );
            }
            continue;
        }
        shown += 1;
        let last = row
            .last_done()
            .map(|done| format!("{}h ago", now.saturating_sub(done).max(0) / 3_600))
            .unwrap_or_else(|| "never".to_owned());
        let carried = row
            .script
            .as_ref()
            .map(|script| format!("  script:{}", script.short_digest()))
            .unwrap_or_default();
        println!(
            "{:<22} {:<9} done {:<12} {}{carried} [{:x}]",
            row.label,
            state.word(),
            last,
            row.condition,
            row.id,
        );
        if let Some(detail) = state_detail(&state) {
            println!("{:<22}   {detail}", "");
        }
    }
    if shown == 0 {
        println!(
            "{}",
            if only_due {
                "nothing due"
            } else {
                "no habits yet"
            }
        );
    }
    if !only_due {
        // Superseded revisions stay in the collection as history. Say how many
        // rather than listing them, so the live view is the default view.
        let retired = catalog.habits().count() - catalog.live().len();
        if retired > 0 {
            println!("({retired} superseded revision(s) not shown)");
        }
    }
    if unevaluable > 0 {
        bail!("{unevaluable} standing intention(s) could not be evaluated (see above)");
    }
    Ok(())
}

fn cmd_done(pile: &Path, key: Option<&Path>, label: &str) -> Result<()> {
    let catalog = habits::read_catalog(pile, key)?;
    let habit = select_live_habit(&catalog, label)?;
    let (fragment, occurrence) = habits::completion_fragment(habit.id, point(now_epoch()))?;
    habits::publish(pile, key, fragment)?;
    println!("done {} [{occurrence:x}]", habit.label);
    Ok(())
}

fn cmd_state(pile: &Path, key: Option<&Path>, label: &str, desired: DeclaredState) -> Result<()> {
    let catalog = habits::read_catalog(pile, key)?;
    let habit = select_live_habit(&catalog, label)?;
    let activation = catalog.activation(habit.id)?;
    if activation.declared() == Some(desired) {
        println!("{} already {}", habit.label, desired.as_str());
        return Ok(());
    }
    let predecessors = activation.head_ids();
    let (fragment, assertion) =
        habits::state_fragment(habit.id, desired, &predecessors, point(now_epoch()))?;
    habits::publish(pile, key, fragment)?;
    println!("{} {} [{assertion:x}]", desired.as_str(), habit.label);
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        None => {
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
        Some(Command::Add {
            label,
            when,
            nudge,
            script,
            supersedes,
        }) => cmd_add(
            &cli.pile,
            cli.key.as_deref(),
            label,
            when,
            nudge,
            script,
            supersedes,
        ),
        Some(Command::List) => cmd_list(&cli.pile, cli.key.as_deref(), false),
        Some(Command::Due) => cmd_list(&cli.pile, cli.key.as_deref(), true),
        Some(Command::Done { label }) => cmd_done(&cli.pile, cli.key.as_deref(), &label),
        Some(Command::Pause { label }) => {
            cmd_state(&cli.pile, cli.key.as_deref(), &label, DeclaredState::Paused)
        }
        Some(Command::Resume { label }) => {
            cmd_state(&cli.pile, cli.key.as_deref(), &label, DeclaredState::Active)
        }
        Some(Command::Check) => {
            let catalog = habits::read_catalog(&cli.pile, cli.key.as_deref())?;
            println!(
                "Habit collection {} (scope {DEFAULT_SCOPE_ID:X}): {} definitions ({} live, {} carrying their own script), {} completions, {} state assertions validated",
                hex::encode_upper(habits::descriptor().handle().raw),
                catalog.habits().count(),
                catalog.live().len(),
                catalog
                    .habits()
                    .filter(|habit| habit.script.is_some())
                    .count(),
                catalog.completions().count(),
                catalog.assertions().count(),
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use faculties::collection_cutover::initialize_signer;

    #[test]
    fn permanent_cli_has_no_branch_scope_head_or_migration_surface() {
        let command = Cli::command();
        for forbidden in ["branch", "branch_id", "scope", "head", "migrate"] {
            assert!(!command
                .get_arguments()
                .any(|argument| argument.get_id() == forbidden));
            assert!(command.find_subcommand(forbidden).is_none());
        }
    }

    #[test]
    fn mutation_selection_never_targets_superseded_history() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("habit.pile");
        let key = directory.path().join("habit.key");
        std::fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();

        let (original, original_id) =
            habits::habit_fragment("sweep", "every 1h", "sweep", None, &[]).unwrap();
        habits::publish(&pile, Some(&key), original).unwrap();
        let (successor, successor_id) =
            habits::habit_fragment("sweep", "every 2h", "sweep", None, &[original_id]).unwrap();
        habits::publish(&pile, Some(&key), successor).unwrap();

        let catalog = habits::read_catalog(&pile, Some(&key)).unwrap();
        assert_eq!(
            select_live_habit(&catalog, "sweep").unwrap().id,
            successor_id
        );
        let error = select_live_habit(&catalog, &format!("{original_id:x}")).unwrap_err();
        assert!(
            error.to_string().contains("superseded history"),
            "{error:#}"
        );
    }

    #[test]
    fn a_full_unseen_id_is_a_valid_revision_predecessor() {
        let catalog = Catalog::default();
        let unseen = Id::new([0xA5; 16]).unwrap();
        assert_eq!(
            resolve_predecessor(&catalog, &format!("{unseen:x}")).unwrap(),
            unseen
        );
        assert!(resolve_predecessor(&catalog, "a5a5").is_err());
    }
}
