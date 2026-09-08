//! Planner's local paths, @file/stdin prose, and local-day convenience windows.
use super::{presentation, AddOptions, CalendarInput, Planner};
use crate::out::Out;
use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "planner",
    about = "Calendar and event-tracking faculty"
)]
pub struct Cli {
    /// Path to the pile file.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Add an event manually. Times are ISO 8601 dates or datetimes.
    Add {
        /// Event title (RFC 5545 SUMMARY).
        summary: String,
        /// Start time (ISO 8601 date or datetime).
        #[arg(long)]
        from: String,
        /// End time. Defaults to one hour, or one day for date-only starts.
        #[arg(long)]
        to: Option<String>,
        /// RFC 5545 recurrence rule (for example `FREQ=WEEKLY;BYDAY=MO`).
        #[arg(long)]
        rrule: Option<String>,
        /// Free-text location.
        #[arg(long)]
        location: Option<String>,
        /// `tentative`, `confirmed`, or `cancelled`.
        #[arg(long)]
        status: Option<String>,
        /// `opaque` (default) or `transparent`.
        #[arg(long)]
        transp: Option<String>,
        /// Long-form description. Use @path or @-.
        #[arg(long)]
        description: Option<String>,
        /// Initial note body. Use @path or @-.
        #[arg(long)]
        note: Option<String>,
    },
    /// List events overlapping a window (defaults to all events).
    List {
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
        /// Include cancelled events.
        #[arg(long)]
        all: bool,
    },
    /// Events overlapping today in the local timezone.
    Today,
    /// Events overlapping the next seven days in the local timezone.
    Week,
    /// Next upcoming event.
    Next,
    /// Attach an immutable note to an event.
    Note {
        /// Event id or unambiguous hex prefix.
        id: String,
        /// Note body. Use @path or @-.
        text: String,
    },
    /// Show an event and its notes.
    Show {
        /// Event id or unambiguous hex prefix.
        id: String,
    },
    /// Assert monotonically that an event is cancelled.
    Cancel {
        /// Event id or unambiguous hex prefix.
        id: String,
    },
    /// Resolve an event-id prefix.
    Resolve { prefix: String },
    /// Ingest one or more iCalendar files atomically.
    Ingest { files: Vec<PathBuf> },
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    if cli.command.is_none() {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }
    crate::cli::with_output("planner", |out| execute(cli, out))
}
pub fn execute(cli: Cli, out: &mut Out<'_>) -> Result<()> {
    let Some(command) = cli.command else {
        return out.text(Cli::command().render_help().to_string());
    };
    let planner = Planner::new(cli.pile, cli.key);
    match command {
        Command::Add {
            summary,
            from,
            to,
            rrule,
            location,
            status,
            transp,
            description,
            note,
        } => {
            let mut options = AddOptions::new(summary, super::event_window(&from, to.as_deref())?);
            options.rrule = rrule;
            options.location = location;
            if let Some(status) = status {
                options.status = status.to_ascii_uppercase();
            }
            if let Some(transp) = transp {
                options.transp = transp.to_ascii_uppercase();
            }
            options.description = description
                .as_deref()
                .map(|value| crate::text_arg(value, "description"))
                .transpose()?;
            options.note = note
                .as_deref()
                .map(|value| crate::text_arg(value, "note"))
                .transpose()?;
            presentation::added(&planner.add(&options)?, out)
        }
        Command::List { from, to, all } => {
            let (mut start, mut end) = super::default_window();
            if let Some(from) = from {
                start = super::chrono_to_epoch(super::parse_iso8601(&from)?);
            }
            if let Some(to) = to {
                end = super::chrono_to_epoch(super::parse_iso8601(&to)?);
            }
            presentation::occurrences(&planner.list((start, end), all)?, out)
        }
        Command::Today => {
            presentation::occurrences(&planner.list(super::local_day_window(1)?, false)?, out)
        }
        Command::Week => {
            presentation::occurrences(&planner.list(super::local_day_window(7)?, false)?, out)
        }
        Command::Next => {
            let next = planner.next(None)?;
            presentation::occurrences(next.as_ref().map_or(&[], std::slice::from_ref), out)
        }
        Command::Note { id, text } => {
            presentation::noted(&planner.note(&id, &crate::text_arg(&text, "note")?)?, out)
        }
        Command::Show { id } => presentation::show(&planner.show(&id)?, out),
        Command::Cancel { id } => presentation::cancelled(&planner.cancel(&id)?, out),
        Command::Resolve { prefix } => out.line(format!("{:x}", planner.resolve(&prefix)?)),
        Command::Ingest { files } => {
            if files.is_empty() {
                bail!("no files supplied");
            }
            // Every path is read before the resident operation can publish.
            let texts = files
                .iter()
                .map(|path| {
                    std::fs::read_to_string(path)
                        .with_context(|| format!("read {}", path.display()))
                })
                .collect::<Result<Vec<_>>>()?;
            let names = files
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>();
            let documents = names
                .iter()
                .zip(&texts)
                .map(|(name, text)| CalendarInput { name, text })
                .collect::<Vec<_>>();
            presentation::ingested(&planner.ingest(&documents)?, out)
        }
    }
}
