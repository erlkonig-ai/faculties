//! Tailored Status CLI input and shared output delivery.

use super::{render, Status};
use crate::out::Out;
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "status",
    about = "Per-window 'currently doing X' status"
)]
pub struct Cli {
    /// Path to the pile file.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Acting persona: Relations label/alias or exact 32-character id.
    #[arg(long, env = "PERSONA")]
    persona: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Set the current status for your window ($PERSONA).
    Set {
        #[arg(
            help = "Status text, e.g. \"porting SigLIP\". Use @path for file input or @- for stdin."
        )]
        text: String,
    },
    /// Show the latest status of every window.
    List,
    /// Show a window's current status and recent history.
    Show {
        /// Relations label/alias or exact 32-character id.
        window: String,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
}

pub fn execute(cli: Cli, output: &mut Out<'_>) -> Result<()> {
    let operations = Status::new(cli.pile, cli.key);
    match cli.command {
        Command::Set { text } => {
            let text = crate::text_arg(&text, "status text")?;
            let persona = cli.persona.as_deref().ok_or_else(|| {
                anyhow!("no persona — set $PERSONA or pass --persona <Relations label or exact id>")
            })?;
            render::set(&operations.set(persona, &text)?, output)
        }
        Command::List => render::list(&operations.list()?, output),
        Command::Show { window, limit } => render::show(&operations.show(&window, limit)?, output),
    }
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    crate::cli::with_output("status", |output| execute(cli, output))
}
