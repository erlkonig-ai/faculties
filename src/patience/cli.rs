//! Explicit Patience CLI, including environment defaults and optional child command.
use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser};
use humantime::parse_duration;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use triblespace::prelude::*;

#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "patience",
    about = "Extend the active turn timeout and optionally run a command"
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
    /// Timeout extension duration (e.g. 5m, 90s, 1h).
    #[arg(value_name = "DURATION")]
    duration: Option<String>,
    /// Optional command to run after extending timeout (pass after `--`).
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

fn parse_timeout_ms(raw: &str) -> Result<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("duration is empty");
    }
    if let Ok(ms) = trimmed.parse::<u64>() {
        anyhow::ensure!(ms > 0, "duration must be greater than zero");
        return Ok(ms);
    }
    let duration =
        parse_duration(trimmed).with_context(|| format!("invalid duration '{trimmed}'"))?;
    let millis = duration.as_millis();
    if millis == 0 {
        bail!("duration must be greater than zero");
    }
    if millis > u128::from(u64::MAX) {
        bail!("duration exceeds maximum supported timeout");
    }
    Ok(millis as u64)
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
    let Some(duration_raw) = cli.duration.as_ref() else {
        let mut cmd = Cli::command();
        cmd.print_help()?;
        println!();
        return Ok(());
    };

    let timeout_ms = parse_timeout_ms(duration_raw)?;
    let env_turn_id = std::env::var("TURN_ID").ok();
    let env_worker_id = std::env::var("WORKER_ID").ok();

    let request_id =
        parse_optional_hex_id(cli.turn_id.as_deref().or(env_turn_id.as_deref()), "turn id")?
            .ok_or_else(|| anyhow!("missing turn id (pass --turn-id or set TURN_ID)"))?;
    let worker_id = parse_optional_hex_id(
        cli.worker_id.as_deref().or(env_worker_id.as_deref()),
        "worker id",
    )?
    .ok_or_else(|| anyhow!("missing worker id (pass --worker-id or set WORKER_ID)"))?;

    let patience = super::Patience::new(cli.pile, cli.key);
    crate::cli::with_diagnostic_output("patience", |out| {
        let event = patience.extend(request_id, worker_id, timeout_ms)?;
        out.line(format!("[{event:x}] timeout extended by {timeout_ms} ms"))
    })?;
    if cli.command.is_empty() {
        return Ok(());
    }
    let exit_code = run_command(&cli.command)?;
    std::process::exit(exit_code);
}
