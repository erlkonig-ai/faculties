//! Tailored Mail CLI: host files/password inputs and ambient persona are decoded here.
use super::{operations::*, render};
use crate::out::Out;
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use std::{
    fs,
    path::{Path, PathBuf},
};
use triblespace::prelude::Id;

#[derive(Parser)]
#[command(version = crate::GIT_VERSION, name = "mail", about = "Immutable email evidence, drafts, and delivery receipts")]
pub struct Cli {
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable collection signer. Ordinary commands never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage immutable full-state mail-account configurations.
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
    /// Fetch every enabled account through UIDL-safe POP.
    Fetch,
    /// Create one immutable draft and its deterministic Decide proposal.
    Draft(DraftArgs),
    /// Create a reply draft from an inbound wire message.
    Reply(ReplyArgs),
    /// Submit one authorized draft under externally serialized execution.
    Send { draft: String },
    /// List immutable drafts and their delivery state.
    Outbox,
    /// List inbound projections for the configured persona.
    List {
        #[arg(long)]
        unread: bool,
        #[arg(long)]
        spam: bool,
    },
    /// Record intrinsic read evidence for one inbound wire message.
    Read { message: String },
    /// Show one inbound or outgoing wire message.
    Show { message: String },
    /// Case-insensitive substring search over projected subject and body.
    Search { query: String },
}

#[derive(Subcommand)]
enum AccountCommand {
    /// Add an account or append a full-state successor to an existing account.
    Set {
        /// Existing account id/address. Omit only when creating a new anchor.
        #[arg(long)]
        account: Option<String>,
        #[arg(long)]
        address: String,
        #[arg(long)]
        display_name: String,
        /// Implicit-TLS endpoint as `host:port`.
        #[arg(long)]
        pop_endpoint: String,
        /// Implicit-TLS endpoint as `host:port`.
        #[arg(long)]
        smtp_endpoint: String,
        #[arg(long)]
        username: Option<String>,
        /// Mailbox secret. Prefer MAIL_PASS rather than a visible argv value.
        #[arg(long, env = "MAIL_PASS", hide_env_values = true)]
        password: Option<String>,
        /// Exact existing Secrets version. This is the repair path when
        /// a Secrets-first account update was interrupted before Mail commit.
        #[arg(long, value_parser = parse_id, conflicts_with = "password")]
        credential_version: Option<Id>,
        #[arg(long)]
        disabled: bool,
    },
    List,
}

#[derive(Args)]
struct DraftArgs {
    /// Account id/address; required even when only one account exists.
    #[arg(long)]
    account: String,
    #[arg(long, required = true)]
    to: Vec<String>,
    #[arg(long)]
    cc: Vec<String>,
    #[arg(long)]
    bcc: Vec<String>,
    #[arg(long)]
    subject: String,
    /// Literal text, `@path`, or `@-`.
    body: String,
    #[arg(long)]
    attach: Vec<PathBuf>,
}

#[derive(Args)]
struct ReplyArgs {
    message: String,
    #[arg(long)]
    account: String,
    /// Literal text, `@path`, or `@-`.
    body: String,
}

fn attachment(path: &Path) -> Result<DraftAttachment> {
    let bytes = fs::read(path).with_context(|| format!("read attachment {}", path.display()))?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("attachment.bin")
        .to_owned();
    Ok(DraftAttachment::Resident(super::AttachmentData {
        filename,
        media_type: crate::files::infer_media_type(path).to_owned(),
        bytes,
    }))
}
fn persona() -> Result<String> {
    std::env::var("PERSONA").context("PERSONA must select an active Relations person")
}
pub fn execute(cli: Cli, out: &mut Out<'_>) -> Result<()> {
    let operations = Mail::new(cli.pile, cli.key);
    match cli.command {
        Command::Account { command } => match command {
            AccountCommand::Set {
                account,
                address,
                display_name,
                pop_endpoint,
                smtp_endpoint,
                username,
                password,
                credential_version,
                disabled,
            } => {
                let input = AccountOptions {
                    account,
                    address,
                    display_name,
                    pop_endpoint,
                    smtp_endpoint,
                    username,
                    credential_version,
                    disabled,
                };
                let value = match password {
                    Some(password) => operations.account_set_with_password(input, password)?,
                    None => operations.account_set(input)?,
                };
                for notice in &value.notices {
                    eprintln!("{notice}");
                }
                render::account_set(&value, out)
            }
            AccountCommand::List => render::accounts(&operations.account_list()?, out),
        },
        Command::Fetch => render::fetched(&operations.fetch()?, out),
        Command::Draft(args) => {
            let body = crate::text_arg(&args.body, "draft body")?;
            let attachments = args
                .attach
                .iter()
                .map(|path| attachment(path))
                .collect::<Result<Vec<_>>>()?;
            render::draft(
                &operations.draft(DraftRequest {
                    account: args.account,
                    to: args.to,
                    cc: args.cc,
                    bcc: args.bcc,
                    subject: args.subject,
                    body,
                    attachments,
                })?,
                out,
            )
        }
        Command::Reply(args) => render::draft(
            &operations.reply(ReplyRequest {
                message: args.message,
                account: args.account,
                body: crate::text_arg(&args.body, "reply body")?,
            })?,
            out,
        ),
        Command::Send { draft } => render::sent(&operations.send(&draft)?, out),
        Command::Outbox => render::outbox(&operations.outbox()?, out),
        Command::List { unread, spam } => {
            render::inbox(&operations.list(&persona()?, unread, spam)?, out)
        }
        Command::Read { message } => render::read(&operations.read(&persona()?, &message)?, out),
        Command::Show { message } => render::show(&operations.show(&message)?, out),
        Command::Search { query } => render::search(&operations.search(&query)?, out),
    }
}
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    crate::cli::with_output("mail", |out| execute(cli, out))
}
fn parse_id(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim())
        .ok_or_else(|| format!("'{raw}' is not one exact nonzero 32-digit hexadecimal id"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_rejects_legacy_secret_identity_and_scope_surface() {
        assert!(Cli::try_parse_from([
            "mail",
            "--pile",
            "/tmp/not-opened-mail-test.pile",
            "--secrets-identity",
            "operator",
            "account",
            "list",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "mail",
            "--pile",
            "/tmp/not-opened-mail-test.pile",
            "account",
            "set",
            "--address",
            "me@example.test",
            "--display-name",
            "Me",
            "--pop-endpoint",
            "pop.example.test:995",
            "--smtp-endpoint",
            "smtp.example.test:465",
            "--password",
            "secret",
            "--secret-scope",
            "mail-test",
        ])
        .is_err());
    }

    #[test]
    fn cli_password_uses_configured_secrets_collection() {
        let command = [
            "mail",
            "--pile",
            "/tmp/not-opened-mail-test.pile",
            "account",
            "set",
            "--address",
            "me@example.test",
            "--display-name",
            "Me",
            "--pop-endpoint",
            "pop.example.test:995",
            "--smtp-endpoint",
            "smtp.example.test:465",
            "--password",
            "secret",
        ];
        assert!(Cli::try_parse_from(command).is_ok());

        let mut with_vault = command.to_vec();
        with_vault.extend(["--vault", "78787878787878787878787878787878"]);
        assert!(Cli::try_parse_from(with_vault).is_err());
    }
}
