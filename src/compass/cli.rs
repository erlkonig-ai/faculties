//! Compass's explicit CLI grammar, file/stdin input, and output presentation.

use std::path::PathBuf;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};

use super::{render, AddOptions, Compass, ListOptions, NoteOptions};
use crate::out::Out;

#[derive(Parser)]
#[command(version = crate::GIT_VERSION, name = "compass", about = "A small TribleSpace kanban faculty")]
pub struct Cli {
    /// Path to the pile file to use
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Acting persona (relations label or 32-char hex id). When set,
    /// status and note events record who made them — the audit trail gains the
    /// actor, and `orient wait` watchers can absorb their own edits.
    #[arg(long, env = "PERSONA")]
    persona: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Add a new goal
    Add {
        #[arg(help = "Goal title. Use @path for file input or @- for stdin.")]
        title: String,
        #[arg(long, default_value = "todo")]
        status: String,
        /// Parent goal id (full 32-char hex id; use `compass resolve` to look up by prefix)
        #[arg(long)]
        parent: Option<String>,
        #[arg(long)]
        tag: Vec<String>,
        #[arg(long, help = "Initial note. Use @path for file input or @- for stdin.")]
        note: Option<String>,
    },
    /// List goals in kanban columns (hides done by default)
    List {
        /// Show done goals too
        #[arg(long)]
        all: bool,
        /// Filter by tag (repeatable, shows goals matching any)
        #[arg(long)]
        tag: Vec<String>,
        #[arg(value_name = "STATUS")]
        status: Vec<String>,
    },
    /// Move a goal to a new status
    Move {
        /// Full 32-char hex id
        id: String,
        status: String,
    },
    /// Add a note to a goal
    Note {
        /// Full 32-char hex id
        id: String,
        #[arg(help = "Note text. Use @path for file input or @- for stdin.")]
        note: String,
        /// Short note tag (repeatable). Relations person or group tags request
        /// attention through Orient without assigning workflow semantics.
        #[arg(long)]
        tag: Vec<String>,
        /// Opaque exact reference stored on the note (repeatable). Recognized
        /// inline `[text](faculty:hex)` links are stored automatically too.
        #[arg(long = "ref", value_name = "REFERENCE")]
        reference: Vec<String>,
        /// Existing note this note supersedes (repeatable). The edge is
        /// provenance only: Compass keeps and displays every note.
        #[arg(long, value_name = "NOTE_ID")]
        supersedes: Vec<String>,
    },
    /// Show a goal with history and notes
    Show {
        /// Full 32-char hex id
        id: String,
    },
    /// Mark a goal as more important than another
    Prioritize {
        /// The more important goal (full 32-char hex id)
        higher: String,
        /// The less important goal (full 32-char hex id)
        #[arg(long)]
        over: String,
    },
    /// Remove a priority relationship
    Deprioritize {
        /// The goal that was marked more important (full 32-char hex id)
        higher: String,
        /// The goal it was prioritized over (full 32-char hex id)
        #[arg(long)]
        over: String,
    },
    /// Resolve a hex prefix to a full 32-char goal id
    Resolve {
        /// Hex prefix to search for
        prefix: String,
    },
}

pub fn execute(cli: Cli, output: &mut Out<'_>) -> Result<()> {
    let Some(command) = cli.command else {
        return output.line(Cli::command().render_help().to_string());
    };
    let compass = Compass::new(cli.pile, cli.key);
    let persona = cli.persona.as_deref();
    match command {
        Command::Add {
            title,
            status,
            parent,
            tag,
            note,
        } => {
            let title = crate::text_arg(&title, "goal title")?;
            let note = note
                .as_deref()
                .map(|value| crate::text_arg(value, "goal note"))
                .transpose()?;
            let receipt = compass.add(
                &title,
                AddOptions {
                    status: &status,
                    parent: parent.as_deref(),
                    tags: &tag,
                    note: note.as_deref(),
                    persona,
                },
            )?;
            render::added(&receipt, output)
        }
        Command::List { status, tag, all } => output.text(compass.list(ListOptions {
            statuses: &status,
            tags: &tag,
            all,
        })?),
        Command::Move { id, status } => {
            render::moved(&compass.move_goal(&id, &status, persona)?, output)
        }
        Command::Note {
            id,
            note,
            tag,
            reference,
            supersedes,
        } => {
            let note = crate::text_arg(&note, "goal note")?;
            let receipt = compass.note(
                &id,
                &note,
                NoteOptions {
                    tags: &tag,
                    references: &reference,
                    supersedes: &supersedes,
                    persona,
                },
            )?;
            render::noted(&receipt, output)
        }
        Command::Show { id } => output.text(compass.show(&id)?),
        Command::Prioritize { higher, over } => {
            render::prioritized(&compass.prioritize(&higher, &over)?, output)
        }
        Command::Deprioritize { higher, over } => {
            render::prioritized(&compass.deprioritize(&higher, &over)?, output)
        }
        Command::Resolve { prefix } => output.line(format!("{:x}", compass.resolve(&prefix)?)),
    }
}

/// Preserve the tailored CLI grammar; delivery uses the shared sensory/stdout
/// emitter only after parsing and help handling have finished.
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    if cli.command.is_none() {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }
    crate::cli::with_output("compass", |output| execute(cli, output))
}
