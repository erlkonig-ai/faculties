//! Explicit Reason CLI, including environment defaults and optional child command.
use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser};
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use triblespace::prelude::*;

#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "reason",
    about = "Record explicit reasoning notes linked to the current execution turn"
)]
pub(crate) struct Cli {
    /// Path to the pile file.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it;
    /// initialize explicitly with `trible pile signing-key init <pile>`.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Turn id to annotate (hex). Defaults to $TURN_ID.
    #[arg(long)]
    turn_id: Option<String>,
    /// Worker id to annotate (hex). Defaults to $WORKER_ID.
    #[arg(long)]
    worker_id: Option<String>,
    /// Free-form reasoning text.
    #[arg(
        value_name = "TEXT",
        help = "Free-form reasoning text. Use @path for file input or @- for stdin."
    )]
    text: Option<String>,
    /// Optional command to run after logging the reason (pass after `--`).
    #[arg(value_name = "COMMAND", allow_hyphen_values = true, last = true)]
    command: Vec<String>,
}

fn parse_optional_hex_id(raw: Option<&str>, label: &str) -> Result<Option<Id>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("{label} is empty");
    }
    let Some(id) = Id::from_hex(trimmed) else {
        bail!("invalid {label} '{trimmed}'");
    };
    Ok(Some(id))
}

fn shell_quote(word: &str) -> String {
    if word.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || std::matches!(ch, '_' | '-' | '.' | '/' | ':' | '=')
    }) {
        return word.to_string();
    }
    format!("'{}'", word.replace('\'', "'\\''"))
}

fn render_command(command: &[String]) -> String {
    command
        .iter()
        .map(|part| shell_quote(part))
        .collect::<Vec<_>>()
        .join(" ")
}

fn run_command(command: &[String]) -> Result<i32> {
    let Some(bin) = command.first() else {
        bail!("missing command");
    };
    let status = ProcessCommand::new(bin)
        .args(command.iter().skip(1))
        .status()
        .with_context(|| format!("run command `{}`", render_command(command)))?;
    Ok(status.code().unwrap_or(1))
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    let Some(text_raw) = cli.text.as_ref() else {
        let mut cmd = Cli::command();
        cmd.print_help()?;
        println!();
        return Ok(());
    };
    let text = crate::text_arg(text_raw, "reason text")?;

    let env_turn_id = std::env::var("TURN_ID").ok();
    let env_worker_id = std::env::var("WORKER_ID").ok();

    let turn_id =
        parse_optional_hex_id(cli.turn_id.as_deref().or(env_turn_id.as_deref()), "turn id")?;
    let worker_id = parse_optional_hex_id(
        cli.worker_id.as_deref().or(env_worker_id.as_deref()),
        "worker id",
    )?;

    if text.trim().is_empty() {
        bail!("reason text is empty");
    }

    let reason = super::Reason::new(cli.pile, cli.key);
    if cli.command.is_empty() {
        return crate::cli::with_output("reason", |out| {
            let id = reason.record(&text, turn_id, worker_id)?;
            out.line(format!("reason_id: {id:x}"))
        });
    }
    let command_text = render_command(&cli.command);
    crate::cli::with_diagnostic_output("reason", |out| {
        let receipt = reason.record_action(&text, &command_text, turn_id, worker_id)?;
        out.line(format!("reason_id: {:x}", receipt.reason))?;
        out.line(format!("reason_action_id: {:x}", receipt.action))
    })?;
    let exit_code = run_command(&cli.command)?;
    std::process::exit(exit_code);
}
