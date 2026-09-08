//! Decide CLI prose input conventions; MCP and operations receive literal text.
use super::{presentation, Decide, FactorSide, ListOptions};
use crate::out::Out;
use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;
use triblespace::prelude::Id;

#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "decide",
    about = "A fork-visible TribleSpace deliberation ledger"
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
    /// Propose a stable decision with one immutable genesis.
    Propose {
        #[arg(help = "Decision title. Use @path for file input or @- for stdin.")]
        title: String,
        #[arg(
            long,
            help = "Optional context. Use @path for file input or @- for stdin."
        )]
        context: Option<String>,
        /// Optional exact 32-character id of the entity this concerns.
        #[arg(long, value_parser = parse_id_arg)]
        about: Option<Id>,
    },
    /// Add one independent pro factor while the decision is unresolved.
    Pro {
        decision: String,
        #[arg(help = "Factor text. Use @path for file input or @- for stdin.")]
        text: String,
    },
    /// Add one independent con factor while the decision is unresolved.
    Con {
        decision: String,
        #[arg(help = "Factor text. Use @path for file input or @- for stdin.")]
        text: String,
    },
    /// Resolve an open decision. Ordinary resolution is allowed only while its
    /// resolution track is Missing.
    Resolve {
        decision: String,
        #[arg(help = "Outcome text. Use @path for file input or @- for stdin.")]
        outcome: String,
        /// Machine-readable result, alongside the outcome prose. The outcome
        /// is for a reader and may say anything; this is the only part a gate
        /// is allowed to act on, so reasoning and clearance stop competing for
        /// one field.
        #[arg(long, value_parser = parse_result_arg)]
        result: Option<Id>,
        /// Explicitly bypass the pro-and-con evidence gate.
        #[arg(long)]
        force: bool,
    },
    /// Reconcile a genuinely divergent resolution fork, citing every current
    /// head. Agreement is already semantically resolved and cannot use this.
    Reconcile {
        decision: String,
        #[arg(help = "Reconciled outcome. Use @path for file input or @- for stdin.")]
        outcome: String,
        /// Machine-readable result for the reconciled head. See `resolve`.
        #[arg(long, value_parser = parse_result_arg)]
        result: Option<Id>,
        /// Explicitly bypass the pro-and-con evidence gate.
        #[arg(long)]
        force: bool,
    },
    /// List unresolved and diagnostically unsettled decisions.
    List {
        /// Include uniquely resolved and agreeing decisions too.
        #[arg(long)]
        all: bool,
        /// Show only semantically resolved decisions whose explicit forced bit
        /// is true.
        #[arg(long)]
        forced: bool,
    },
    /// Show one decision, factors, and every live resolution head.
    Show { decision: String },
    /// Resolve an unambiguous decision id prefix.
    ResolveId { prefix: String },
}

fn parse_id_arg(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim()).ok_or_else(|| format!("invalid id '{raw}'"))
}
fn parse_result_arg(raw: &str) -> std::result::Result<Id, String> {
    super::result_id(raw).map_err(|error| error.to_string())
}
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    if cli.command.is_none() {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }
    crate::cli::with_output("decide", |out| execute(cli, out))
}
pub fn execute(cli: Cli, out: &mut Out<'_>) -> Result<()> {
    let Some(command) = cli.command else {
        return out.text(Cli::command().render_help().to_string());
    };
    let decide = Decide::new(cli.pile, cli.key);
    match command {
        Command::Propose {
            title,
            context,
            about,
        } => {
            let title = crate::text_arg(&title, "decision title")?;
            let context = context
                .as_deref()
                .map(|value| crate::text_arg(value, "decision context"))
                .transpose()?;
            presentation::proposed(&decide.propose(&title, context.as_deref(), about)?, out)
        }
        Command::Pro { decision, text } => presentation::factor(
            &decide.factor(
                &decision,
                &crate::text_arg(&text, "pro factor")?,
                FactorSide::Pro,
            )?,
            out,
        ),
        Command::Con { decision, text } => presentation::factor(
            &decide.factor(
                &decision,
                &crate::text_arg(&text, "con factor")?,
                FactorSide::Con,
            )?,
            out,
        ),
        Command::Resolve {
            decision,
            outcome,
            result,
            force,
        } => presentation::resolved(
            &decide.resolve(
                &decision,
                &crate::text_arg(&outcome, "resolution outcome")?,
                result,
                force,
            )?,
            false,
            out,
        ),
        Command::Reconcile {
            decision,
            outcome,
            result,
            force,
        } => presentation::resolved(
            &decide.reconcile(
                &decision,
                &crate::text_arg(&outcome, "reconciled outcome")?,
                result,
                force,
            )?,
            true,
            out,
        ),
        Command::List { all, forced } => {
            presentation::list(&decide.list(ListOptions { all, forced })?, out)
        }
        Command::Show { decision } => presentation::show(&decide.show(&decision)?, out),
        Command::ResolveId { prefix } => out.line(format!("{:x}", decide.resolve_id(&prefix)?)),
    }
}
