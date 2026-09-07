//! Message's CLI-only sender environment and @file/stdin conventions.
use super::{render, AckAllOptions, ListOptions, Message, SendOptions};
use crate::out::Out;
use anyhow::{bail, Result};
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "message",
    about = "Local messaging faculty for the agent"
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
    /// Send a message as $PERSONA (override the sender with --from).
    Send {
        /// Recipient label, id, or id prefix (person or group).
        to: String,
        /// Message text. Use @path for file input or @- for stdin.
        text: String,
        /// Sender label, id, or id prefix. Defaults to $PERSONA.
        #[arg(long, env = "PERSONA", value_name = "PERSON")]
        from: Option<String>,
    },
    /// List recent inbox and outbox messages (latest first).
    List {
        /// Reader label, id, or id prefix.
        reader: String,
        /// Only show unread inbox messages.
        #[arg(long)]
        unread: bool,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Mark one inbox message as read.
    Ack {
        /// Message id or unambiguous id prefix.
        id: String,
        /// Reader label, id, or id prefix.
        by: String,
    },
    /// Mark every currently unread inbox message as read in one commit.
    AckAll {
        /// Reader label, id, or id prefix.
        by: String,
        /// Restrict to one sender label, id, or id prefix.
        #[arg(long)]
        from: Option<String>,
    },
}

/// Parse the process command line and use the common CLI output route.
pub fn run() -> Result<()> {
    let request = Cli::parse();
    if request.command.is_none() {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    }
    crate::cli::with_output("message", |out| execute(request, out))
}

/// Execute a parsed CLI command. Only this adapter interprets text as a file
/// path or stdin marker; Message operations and MCP always receive literal text.
pub fn execute(request: Cli, out: &mut Out<'_>) -> Result<()> {
    let Some(command) = request.command else {
        return out.text(Cli::command().render_help().to_string());
    };
    let messages = Message::new(request.pile, request.key);
    match command {
        Command::Send { to, text, from } => {
            let Some(from) = from
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
            else {
                bail!("no sender: set $PERSONA or pass --from <person>\nusage: message send <TO> <TEXT> [--from <PERSON>]");
            };
            let text = crate::text_arg(&text, "message text")?;
            let sent = messages.send(&SendOptions {
                from: &from,
                to: &to,
                text: &text,
            })?;
            render::sent(&sent, &text, out)
        }
        Command::List {
            reader,
            unread,
            limit,
        } => render::list(
            &messages.list(&ListOptions {
                reader: &reader,
                unread,
                limit,
            })?,
            out,
        ),
        Command::Ack { id, by } => render::acknowledged(&messages.ack(&id, &by)?, out),
        Command::AckAll { by, from } => render::acknowledged_all(
            &messages.ack_all(&AckAllOptions {
                by: &by,
                from: from.as_deref(),
            })?,
            out,
        ),
    }
}
