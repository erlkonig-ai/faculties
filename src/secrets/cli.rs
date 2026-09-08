//! Shell-specific secret input and exact stdout export.
use super::Secrets;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::{Read, Write};
use std::path::PathBuf;
use triblespace::prelude::Id;
use zeroize::Zeroizing;
#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "secrets",
    about = "Immutable encrypted versions in one capability-governed collection"
)]
struct Cli {
    /// Path to the pile file.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable node signing-key file. Commands never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Add one immutable encrypted version.
    Add {
        #[arg(long)]
        name: String,
        /// Literal value, `@file`, or `@-` for stdin.
        #[arg(long)]
        value: String,
    },
    /// Open one exact immutable version id.
    Get {
        #[arg(long, value_parser = parse_id)]
        secret: Id,
    },
    /// List complete immutable versions in the configured collection.
    List,
    /// Deliver existing DEKs to currently authorized key-delivery recipients.
    Maintain,
}

fn parse_id(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim())
        .ok_or_else(|| format!("'{raw}' is not one exact nonzero 32-digit hexadecimal id"))
}

fn load_value(raw: String) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(path) = raw.strip_prefix('@') {
        if path == "-" {
            let mut value = Vec::new();
            std::io::stdin()
                .read_to_end(&mut value)
                .context("read secret value from stdin")?;
            Ok(Zeroizing::new(value))
        } else {
            std::fs::read(path)
                .map(Zeroizing::new)
                .with_context(|| format!("read {path}"))
        }
    } else {
        Ok(Zeroizing::new(raw.into_bytes()))
    }
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let operations = Secrets::new(cli.pile, cli.key);
    match cli.command {
        // An explicit secret export is never sensory output, even with Drive.
        Command::Get { secret } => {
            let plaintext = operations.get(secret)?;
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(&plaintext)
                .context("write secret to stdout")?;
            stdout.flush().context("flush secret stdout")
        }
        command => crate::cli::with_output("secrets", |out| match command {
            Command::Add { name, value } => {
                let plaintext = load_value(value)?;
                let secret = operations.add(&name, &plaintext)?;
                out.line(format!("secret {secret:x}  {name}"))
            }
            Command::List => {
                let rows = operations.list()?;
                if rows.is_empty() {
                    out.line("(no secrets)")?;
                }
                for row in rows {
                    out.line(format!("{:x}  {}", row.id, row.name))?;
                }
                Ok(())
            }
            Command::Maintain => out.line(format!(
                "added {} recipient envelope(s)",
                operations.maintain()?
            )),
            Command::Get { .. } => unreachable!(),
        }),
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    const PILE: &str = "/tmp/never-opened-secrets-cli-test.pile";
    const ID: &str = "01010101010101010101010101010101";

    #[test]
    fn collection_native_surface_has_no_vault_or_secret_specific_grants() {
        for args in [
            vec![
                "secrets", "--pile", PILE, "add", "--name", "token", "--value", "value",
            ],
            vec!["secrets", "--pile", PILE, "get", "--secret", ID],
            vec!["secrets", "--pile", PILE, "list"],
            vec!["secrets", "--pile", PILE, "maintain"],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }
        for removed in ["vault", "grant", "revoke", "identity", "scope"] {
            assert!(Cli::try_parse_from(["secrets", "--pile", PILE, removed]).is_err());
        }
    }
}
