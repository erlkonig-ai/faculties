//! Explicit CLI grammar, local script/prose input, and terminal/Drive delivery.
use super::{render, DeclaredState, Habits};
use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "habit",
    about = "Standing intentions, pulled rather than pushed"
)]
pub(crate) struct Cli {
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
    /// Show one immutable definition, including its nudge and predecessors.
    Show { habit: String },
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

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    };
    let habits = Habits::new(cli.pile, cli.key);
    match command {
        Command::List | Command::Due => {
            let due = matches!(command, Command::Due);
            let report = habits.list(true)?;
            let listing = render::listed(&report, due);
            crate::cli::with_output("habit", |out| out.text(listing.text))?;
            if !listing.diagnostics.is_empty() {
                crate::cli::with_diagnostic_output("habit", |out| {
                    for message in &listing.diagnostics {
                        out.line(message)?;
                    }
                    Ok(())
                })?;
                bail!(
                    "{} standing intention(s) could not be evaluated (see above)",
                    listing.diagnostics.len()
                );
            }
            Ok(())
        }
        command => crate::cli::with_output("habit", |out| match command {
            Command::Add {
                label,
                when,
                nudge,
                script,
                supersedes,
            } => {
                let nudge = crate::text_arg(&nudge, "Habit nudge")?;
                let script = script.as_deref().map(script_arg).transpose()?;
                render::added(
                    &habits.add(&label, &when, &nudge, script.as_deref(), &supersedes)?,
                    out,
                )
            }
            Command::Show { habit } => render::shown(&habits.show(&habit)?, out),
            Command::Done { label } => render::completed(&habits.done(&label)?, out),
            Command::Pause { label } => {
                render::state_changed(&habits.set_state(&label, DeclaredState::Paused)?, out)
            }
            Command::Resume { label } => {
                render::state_changed(&habits.set_state(&label, DeclaredState::Active)?, out)
            }
            Command::Check => out.line(habits.check()?),
            Command::List | Command::Due => unreachable!(),
        }),
    }
}
