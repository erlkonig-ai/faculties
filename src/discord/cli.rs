//! Discord CLI host input and sync-then-read workflow.
use super::{operations::*, render};
use crate::out::Out;
use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use std::{fs, io::Read, path::PathBuf};

#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "discord",
    about = "Post to and ingest Discord channels into TribleSpace"
)]
pub struct Cli {
    /// Path to the pile file to use.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it;
    /// initialize explicitly with trible pile signing-key init.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Discord bot token. Use @path or @- to avoid exposing it in argv.
    #[arg(long, env = "DISCORD_TOKEN", hide_env_values = true)]
    token: Option<String>,
    #[command(subcommand)]
    command: Option<CommandMode>,
}

#[derive(Subcommand)]
enum CommandMode {
    /// Post a message and persist the returned Discord observation.
    Send {
        /// Channel id (global Discord snowflake).
        channel_id: String,
        /// Message body. Use @path for file input or @- for stdin.
        text: String,
    },
    /// Pull one complete forward interval plus a bounded recent window.
    Read {
        /// Channel id (global Discord snowflake). If omitted, poll every
        /// visible text-capable channel.
        channel_id: Option<String>,
        /// Only display messages at or after this RFC3339 timestamp.
        #[arg(long)]
        since: Option<String>,
        /// Maximum messages to display after ingestion (0 = no limit).
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Display newest first.
        #[arg(long)]
        descending: bool,
        /// Maximum messages per forward page (Discord caps this at 100).
        #[arg(long, default_value_t = 100)]
        fetch_limit: u32,
        /// Recent messages re-fetched to observe bounded-window edits.
        #[arg(long, default_value_t = 50)]
        reconcile_limit: u32,
    },
    /// List guilds and channels visible to the bot.
    Channels {
        #[command(subcommand)]
        command: ChannelsCommand,
    },
}

#[derive(Subcommand)]
enum ChannelsCommand {
    /// Print guilds and channels.
    List {
        /// Only show channels in this guild (global Discord snowflake).
        #[arg(long)]
        guild: Option<String>,
    },
}

pub fn execute(mut cli: Cli, out: &mut Out<'_>) -> Result<()> {
    let command = cli
        .command
        .take()
        .ok_or_else(|| anyhow!("no Discord command"))?;
    let token = require_token(&cli)?;
    let operations = Discord::new(cli.pile, cli.key).with_token(token);
    match command {
        CommandMode::Send { channel_id, text } => {
            let text = crate::text_arg(&text, "message text")?;
            render::sent(&operations.send(&channel_id, &text)?, out)
        }
        CommandMode::Read {
            channel_id,
            since,
            limit,
            descending,
            fetch_limit,
            reconcile_limit,
        } => {
            let read = ReadOptions {
                channel_id: channel_id.clone(),
                since,
                limit,
                descending,
            };
            read.validate()?;
            let report = operations.pull(PullOptions {
                channel_id,
                fetch_limit: fetch_limit.clamp(1, 100),
                reconcile_limit: reconcile_limit.clamp(1, 100),
            })?;
            render::pull_header(&report, out)?;
            for channel in &report.channels {
                match &channel.result {
                    Ok(receipt) => render::channel_receipt(receipt, out)?,
                    Err(error) => {
                        eprintln!("  ! {} ({}): {error}", channel.channel_id, channel.name)
                    }
                }
            }
            if report.all_visible && report.channels.is_empty() {
                return Ok(());
            }
            render::history(&operations.read(read)?, out)
        }
        CommandMode::Channels {
            command: ChannelsCommand::List { guild },
        } => render::channels(&operations.channels_list(guild.as_deref())?, out),
    }
}
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    if cli.command.is_none() {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }
    crate::cli::with_output("discord", |out| execute(cli, out))
}
fn require_token(cli: &Cli) -> Result<String> {
    let token = cli
        .token
        .as_deref()
        .ok_or_else(|| anyhow!("missing Discord token; pass --token, DISCORD_TOKEN, @path, or @-"))
        .and_then(|raw| load_value_or_file_trimmed(raw, "Discord token"))?;
    if token.is_empty() {
        bail!("empty Discord token");
    }
    Ok(token)
}

fn load_value_or_file(raw: &str, label: &str) -> Result<String> {
    if let Some(path) = raw.strip_prefix('@') {
        if path == "-" {
            let mut value = String::new();
            std::io::stdin()
                .read_to_string(&mut value)
                .with_context(|| format!("read {label} from stdin"))?;
            return Ok(value);
        }
        return fs::read_to_string(path).with_context(|| format!("read {label} from {path}"));
    }
    Ok(raw.to_owned())
}

fn load_value_or_file_trimmed(raw: &str, label: &str) -> Result<String> {
    Ok(load_value_or_file(raw, label)?.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn permanent_cli_has_one_fixed_collection_identity() {
        let command = Cli::command();
        for forbidden in ["scope", "branch", "branch_id", "head", "repair"] {
            assert!(!command
                .get_arguments()
                .any(|argument| argument.get_id() == forbidden));
        }
    }
}
