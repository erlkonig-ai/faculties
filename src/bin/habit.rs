//! Work with pull-based standing intentions in one fixed native collection.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
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
        #[arg(long, value_name = "CONDITION")]
        when: String,
        /// What to do when the intention is due. Supports @file and @-.
        #[arg(long, value_name = "TEXT")]
        nudge: String,
    },
    /// List every standing intention and its current fork-visible state.
    List,
    /// Print only intentions which are due now.
    Due,
    /// Record completion. The cooldown starts at this occurrence.
    Done { label: String },
    /// Assert paused state, reconciling every state head currently observed.
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

fn unique_label<'a>(catalog: &'a Catalog, label: &str) -> Result<&'a Habit> {
    let matches = catalog.labelled(label);
    match matches.as_slice() {
        [] => bail!("no Habit labelled {label:?}"),
        [habit] => Ok(*habit),
        many => bail!(
            "Habit label {label:?} is forked across {} definitions: {}",
            many.len(),
            many.iter()
                .map(|habit| format!("{:x}", habit.id))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn cmd_add(
    pile: &Path,
    key: Option<&Path>,
    label: String,
    when: String,
    nudge: String,
) -> Result<()> {
    let nudge = faculties::text_arg(&nudge, "Habit nudge")?;
    let parsed_label = label.trim().to_owned();
    let cooldown = Condition::parse(when.trim())
        .map_err(anyhow::Error::msg)?
        .cooldown_secs;
    let (fragment, id) = habits::habit_fragment(label, when, nudge)?;
    let catalog = habits::read_catalog(pile, key)?;
    if catalog.habit(id).is_some() {
        println!("Habit already present [{id:x}]");
        return Ok(());
    }
    let conflicts = catalog.labelled(&parsed_label);
    if !conflicts.is_empty() {
        bail!(
            "a different Habit already uses label {parsed_label:?}: {}",
            conflicts
                .iter()
                .map(|habit| format!("{:x}", habit.id))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    habits::publish(pile, key, fragment)?;
    println!("added {parsed_label} [{id:x}] · cooldown {cooldown}s");
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
    for row in catalog.rows()? {
        let state = habits::evaluate(&row, now, &at);
        if only_due && !state.is_due() {
            continue;
        }
        shown += 1;
        if only_due {
            println!("{}: {}", row.label, row.nudge);
            continue;
        }
        let last = row
            .last_done()
            .map(|done| format!("{}h ago", now.saturating_sub(done).max(0) / 3_600))
            .unwrap_or_else(|| "never".to_owned());
        println!(
            "{:<22} {:<9} done {:<12} {} [{:x}]",
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
    Ok(())
}

fn cmd_done(pile: &Path, key: Option<&Path>, label: &str) -> Result<()> {
    let catalog = habits::read_catalog(pile, key)?;
    let habit = unique_label(&catalog, label)?;
    let (fragment, occurrence) = habits::completion_fragment(habit.id, point(now_epoch()))?;
    habits::publish(pile, key, fragment)?;
    println!("done {} [{occurrence:x}]", habit.label);
    Ok(())
}

fn cmd_state(pile: &Path, key: Option<&Path>, label: &str, desired: DeclaredState) -> Result<()> {
    let catalog = habits::read_catalog(pile, key)?;
    let habit = unique_label(&catalog, label)?;
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
        Some(Command::Add { label, when, nudge }) => {
            cmd_add(&cli.pile, cli.key.as_deref(), label, when, nudge)
        }
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
                "Habit collection {} (scope {DEFAULT_SCOPE_ID:X}): {} definitions, {} completions, {} state assertions validated",
                hex::encode_upper(habits::descriptor().handle().raw),
                catalog.habits().count(),
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
}
