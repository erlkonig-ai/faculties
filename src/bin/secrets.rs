//! `secrets` — exact vault epochs with direct public-key custody.
//!
//! There is no identity, scope, password, revocation, or “latest version”
//! language here. One vault is one private collection. Accepted exact `READ`
//! authority determines its recipient keys, and every immutable secret is
//! addressed by its exact id.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use faculties::secrets::v2::{self, storage as vaults};
use faculties::storage::{load_signer, open_pile_strict};
use hifitime::Epoch;
use triblespace::core::repo::pile::Pile;
use triblespace::prelude::*;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "secrets",
    about = "Encrypted exact-version vaults backed by collection authority"
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
    /// Vault epoch management.
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    /// Immutable exact secret versions.
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
}

#[derive(Subcommand)]
enum VaultCommand {
    /// Create one explicit team-of-one vault epoch.
    Create {
        #[arg(long)]
        name: String,
    },
    /// List ready vaults and independently pending candidates.
    List,
    /// List accepted direct `READ` recipient keys.
    Members {
        #[arg(long, value_parser = parse_id)]
        vault: Id,
    },
    /// Wrap every secret in the observed vault before granting exact `READ`.
    Grant {
        #[arg(long, value_parser = parse_id)]
        vault: Id,
        #[arg(long, value_parser = parse_public_key)]
        recipient: VerifyingKey,
    },
}

#[derive(Subcommand)]
enum SecretCommand {
    /// Add one immutable exact version to a vault.
    Add {
        #[arg(long, value_parser = parse_id)]
        vault: Id,
        #[arg(long)]
        name: String,
        /// Literal value, `@file`, or `@-` for stdin.
        #[arg(long)]
        value: String,
    },
    /// Open one exact immutable secret id.
    Get {
        #[arg(long, value_parser = parse_id)]
        secret: Id,
    },
    /// Repair missing wraps for one exact id against current `READ` members.
    Share {
        #[arg(long, value_parser = parse_id)]
        secret: Id,
    },
    /// List every exact immutable version across ready vaults.
    List,
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

fn parse_public_key(raw: &str) -> std::result::Result<VerifyingKey, String> {
    let bytes = hex::decode(raw.trim())
        .map_err(|_| format!("'{raw}' is not a hexadecimal Ed25519 public key"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "an Ed25519 public key must contain exactly 32 bytes".to_owned())?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid Ed25519 public key".to_owned())
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn fmt_key(key: VerifyingKey) -> String {
    hex::encode(key.to_bytes())
}

fn point_now() -> Result<v2::IntervalValue> {
    let now = Epoch::now().map_err(|error| anyhow!("read current clock: {error:?}"))?;
    Ok((now, now)
        .try_to_inline()
        .expect("a clock point is a valid interval"))
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

fn require_location(
    discovery: &vaults::VaultDiscovery,
    vault: Id,
) -> Result<vaults::VaultLocation> {
    discovery
        .location(vault)
        .copied()
        .ok_or_else(|| anyhow!("vault {vault} is not ready for this node"))
}

fn cmd_vault_create(storage: SecretsStorage<'_>, name: String) -> Result<()> {
    storage.with_pile(|pile, signer| {
        let vault = genid().id;
        let location = vaults::create_vault(pile, signer, vault, &name, point_now()?)?;
        println!("vault {}  {name}", fmt_id(location.vault()));
        Ok(())
    })
}

fn print_issues(discovery: &vaults::VaultDiscovery) {
    for issue in discovery.issues() {
        let identity = issue
            .vault()
            .map(fmt_id)
            .unwrap_or_else(|| hex::encode(issue.collection().raw));
        eprintln!(
            "pending/rejected {identity} [{:?}]: {}",
            issue.kind(),
            issue.detail()
        );
    }
}

fn cmd_vault_list(storage: SecretsStorage<'_>) -> Result<()> {
    storage.with_pile(|pile, signer| {
        let discovery = vaults::discover_local_vaults(pile, signer)?;
        if discovery.locations().is_empty() {
            println!("(no ready vaults)");
        }
        for (vault, location) in discovery.locations() {
            let snapshot = discovery
                .snapshot()
                .vault(*vault)
                .expect("every ready location has one aggregate snapshot");
            let name = v2::read_text(
                discovery.snapshot().reader(),
                snapshot.catalog().header.name,
            )?;
            let members = vaults::vault_members(pile, location)?.len();
            println!(
                "{}  {}  ({} secret(s), {members} member(s))",
                fmt_id(*vault),
                name,
                snapshot.catalog().secrets.len()
            );
        }
        print_issues(&discovery);
        Ok(())
    })
}

fn cmd_vault_members(storage: SecretsStorage<'_>, vault: Id) -> Result<()> {
    storage.with_pile(|pile, signer| {
        let discovery = vaults::discover_local_vaults(pile, signer)?;
        let location = require_location(&discovery, vault)?;
        for member in vaults::vault_members(pile, &location)? {
            let key = VerifyingKey::from_bytes(&member)
                .expect("authority projection contains validated Ed25519 keys");
            println!("{}", fmt_key(key));
        }
        Ok(())
    })
}

fn cmd_vault_grant(storage: SecretsStorage<'_>, vault: Id, recipient: VerifyingKey) -> Result<()> {
    storage.with_pile(|pile, signer| {
        let discovery = vaults::discover_local_vaults(pile, signer)?;
        let location = require_location(&discovery, vault)?;
        let (wraps, granted) =
            vaults::grant_vault_read(pile, signer, &location, discovery.snapshot(), recipient)?;
        if granted {
            println!(
                "granted {} after publishing {wraps} missing wrap(s)",
                fmt_key(recipient)
            );
        } else {
            println!(
                "already granted {}; published {wraps} missing wrap(s)",
                fmt_key(recipient)
            );
        }
        Ok(())
    })
}

fn cmd_secret_add(
    storage: SecretsStorage<'_>,
    vault: Id,
    name: String,
    value: String,
) -> Result<()> {
    let plaintext = load_value(value)?;
    storage.with_pile(|pile, signer| {
        let discovery = vaults::discover_local_vaults(pile, signer)?;
        let location = require_location(&discovery, vault)?;
        let (secret, recipients) = vaults::add_secret(
            pile,
            signer,
            &location,
            discovery.snapshot(),
            &name,
            &plaintext,
            point_now()?,
        )?;
        println!(
            "secret {}  {name}  ({recipients} recipient(s))",
            fmt_id(secret)
        );
        Ok(())
    })
}

fn cmd_secret_get(storage: SecretsStorage<'_>, secret: Id) -> Result<()> {
    let plaintext = Zeroizing::new(storage.with_pile(|pile, signer| {
        vaults::discover_local_vaults(pile, signer)?
            .snapshot()
            .open(secret, signer)
    })?);
    std::io::stdout()
        .write_all(&plaintext)
        .context("write secret to stdout")?;
    Ok(())
}

fn cmd_secret_share(storage: SecretsStorage<'_>, secret: Id) -> Result<()> {
    storage.with_pile(|pile, signer| {
        let discovery = vaults::discover_local_vaults(pile, signer)?;
        let (vault, _) = discovery
            .snapshot()
            .lookup(secret)
            .ok_or_else(|| anyhow!("secret {secret} not found"))?;
        let location = require_location(&discovery, vault)?;
        let added = vaults::share_secret(pile, signer, &location, discovery.snapshot(), secret)?;
        println!("published {added} missing wrap(s) for {}", fmt_id(secret));
        Ok(())
    })
}

fn cmd_secret_list(storage: SecretsStorage<'_>) -> Result<()> {
    storage.with_pile(|pile, signer| {
        let discovery = vaults::discover_local_vaults(pile, signer)?;
        let mut count = 0;
        for (vault, snapshot) in discovery.snapshot().vaults() {
            for secret in snapshot.catalog().secrets.values() {
                let name = v2::read_text(discovery.snapshot().reader(), secret.name)?;
                println!("{}  vault {}  {name}", fmt_id(secret.id), fmt_id(*vault));
                count += 1;
            }
        }
        if count == 0 {
            println!("(no secrets)");
        }
        print_issues(&discovery);
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
        Command::Vault { command } => match command {
            VaultCommand::Create { name } => cmd_vault_create(storage, name),
            VaultCommand::List => cmd_vault_list(storage),
            VaultCommand::Members { vault } => cmd_vault_members(storage, vault),
            VaultCommand::Grant { vault, recipient } => cmd_vault_grant(storage, vault, recipient),
        },
        Command::Secret { command } => match command {
            SecretCommand::Add { vault, name, value } => {
                cmd_secret_add(storage, vault, name, value)
            }
            SecretCommand::Get { secret } => cmd_secret_get(storage, secret),
            SecretCommand::Share { secret } => cmd_secret_share(storage, secret),
            SecretCommand::List => cmd_secret_list(storage),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PILE: &str = "/tmp/never-opened-secrets-cli-test.pile";
    const ID: &str = "01010101010101010101010101010101";
    const KEY: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";

    #[test]
    fn v2_surface_accepts_only_vaults_and_exact_secret_ids() {
        for args in [
            vec![
                "secrets", "--pile", PILE, "vault", "create", "--name", "prod",
            ],
            vec!["secrets", "--pile", PILE, "vault", "list"],
            vec!["secrets", "--pile", PILE, "vault", "members", "--vault", ID],
            vec![
                "secrets",
                "--pile",
                PILE,
                "vault",
                "grant",
                "--vault",
                ID,
                "--recipient",
                KEY,
            ],
            vec![
                "secrets", "--pile", PILE, "secret", "add", "--vault", ID, "--name", "token",
                "--value", "value",
            ],
            vec!["secrets", "--pile", PILE, "secret", "get", "--secret", ID],
            vec!["secrets", "--pile", PILE, "secret", "share", "--secret", ID],
            vec!["secrets", "--pile", PILE, "secret", "list"],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }
    }

    #[test]
    fn v1_identity_scope_revoke_node_and_password_surface_is_gone() {
        for command in ["identity", "scope", "grant", "revoke", "node", "selftest"] {
            assert!(
                Cli::try_parse_from(["secrets", "--pile", PILE, command]).is_err(),
                "legacy command {command} still parsed"
            );
        }
        assert!(Cli::try_parse_from([
            "secrets",
            "--pile",
            PILE,
            "secret",
            "get",
            "--scope",
            ID,
            "--name",
            "x",
            "--password",
            "bad"
        ])
        .is_err());
    }
}
