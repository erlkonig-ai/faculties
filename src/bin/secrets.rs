//! `secrets` — immutable encrypted versions in one configured collection.
//!
//! The collection descriptor owns READ/WRITE policy. This faculty neither
//! discovers vaults nor issues a second kind of grant: generic capability
//! tooling changes admission, and `maintain` delivers existing DEKs to newly
//! admitted finite readers.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use faculties::clock;
use faculties::secrets::{self, storage as secret_storage};
use faculties::storage::{
    load_signer, open_pile_strict, open_secrets_collection, open_secrets_collection_read,
};
use triblespace::core::repo::pile::Pile;
use triblespace::prelude::*;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
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
    /// Deliver existing DEKs to every reader currently admitted by policy.
    Maintain,
}

#[derive(Clone, Copy)]
struct SecretsStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

impl SecretsStorage<'_> {
    fn with_pile<T>(
        self,
        operation: impl FnOnce(&mut Pile, &SigningKey) -> Result<T>,
    ) -> Result<T> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = operation(&mut pile, &signer);
        finish_pile(pile, result)
    }
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context("close Secrets pile")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing Secrets pile also failed: {close_error}")))
        }
    }
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

fn cmd_add(storage: SecretsStorage<'_>, name: String, value: String) -> Result<()> {
    let plaintext = load_value(value)?;
    storage.with_pile(|pile, signer| {
        let collection = open_secrets_collection(pile, signer.verifying_key())?;
        let secret = secret_storage::add_secret(
            pile,
            signer,
            collection,
            &name,
            &plaintext,
            clock::point_now()?,
        )?;
        println!("secret {secret:x}  {name}");
        Ok(())
    })
}

fn cmd_get(storage: SecretsStorage<'_>, secret: Id) -> Result<()> {
    let plaintext = Zeroizing::new(storage.with_pile(|pile, signer| {
        let collection = open_secrets_collection_read(pile, signer.verifying_key())?;
        let snapshot = pollster::block_on(secret_storage::ensure_and_snapshot(pile, collection))?;
        snapshot.open(secret, signer)
    })?);
    std::io::stdout()
        .write_all(&plaintext)
        .context("write secret to stdout")?;
    Ok(())
}

fn cmd_list(storage: SecretsStorage<'_>) -> Result<()> {
    storage.with_pile(|pile, signer| {
        let collection = open_secrets_collection_read(pile, signer.verifying_key())?;
        let snapshot = pollster::block_on(secret_storage::ensure_and_snapshot(pile, collection))?;
        let Some(facts) = snapshot.facts() else {
            println!("(no secrets)");
            return Ok(());
        };
        let rows = secrets::secret_rows(facts);
        if rows.is_empty() {
            println!("(no secrets)");
        }
        for row in rows {
            let name = secrets::read_text(snapshot.store_snapshot(), row.name)?;
            println!("{:x}  {name}", row.id);
        }
        Ok(())
    })
}

fn cmd_maintain(storage: SecretsStorage<'_>) -> Result<()> {
    storage.with_pile(|pile, signer| {
        let collection = open_secrets_collection_read(pile, signer.verifying_key())?;
        let snapshot = pollster::block_on(secret_storage::maintain_and_snapshot(pile, collection))?;
        let added = secret_storage::maintain_recipient_envelopes(
            pile, signer, &snapshot, collection, signer,
        )?;
        println!("added {added} recipient envelope(s)");
        Ok(())
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let storage = SecretsStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
    };
    match cli.command {
        Command::Add { name, value } => cmd_add(storage, name, value),
        Command::Get { secret } => cmd_get(storage, secret),
        Command::List => cmd_list(storage),
        Command::Maintain => cmd_maintain(storage),
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
