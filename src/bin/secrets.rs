//! `secrets` — capability-gated exact vault epochs with sealed custody.
//!
//! One vault is one private collection with one custody key. Exact `READ`
//! proofs deliver that custody through subject-specific access envelopes;
//! exact `WRITE` proofs admit collection commits. Every immutable secret is
//! addressed by its exact id.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use faculties::clock;
use faculties::secrets::{self, storage as vaults};
use faculties::storage::{load_signer, open_pile_strict};
use triblespace::core::collection::records::CollectionHandle;
use triblespace::core::repo::pile::Pile;
use triblespace::prelude::*;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "secrets",
    about = "Capability-gated exact-version vaults with sealed custody"
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
    /// Create one custody-backed vault epoch and founder access envelope.
    Create {
        /// Exact vault id to create or retry. A fresh id is minted when omitted.
        #[arg(long, value_parser = parse_id)]
        id: Option<Id>,
        #[arg(long)]
        name: String,
    },
    /// List ready vaults and independently pending candidates.
    List,
    /// Deliver an exact delegated `READ` proof and custody envelope.
    Grant {
        /// Unique 32-hex vault id or exact 64-hex collection handle.
        #[arg(long, value_parser = parse_vault_selector)]
        vault: VaultSelector,
        #[arg(long, value_parser = parse_public_key)]
        recipient: VerifyingKey,
    },
}

#[derive(Subcommand)]
enum SecretCommand {
    /// Add one immutable exact version to a vault.
    Add {
        /// Unique 32-hex vault id or exact 64-hex collection handle.
        #[arg(long, value_parser = parse_vault_selector)]
        vault: VaultSelector,
        #[arg(long)]
        name: String,
        /// Literal value, `@file`, or `@-` for stdin.
        #[arg(long)]
        value: String,
    },
    /// Open one exact immutable secret id.
    Get {
        /// Unique 32-hex vault id or exact 64-hex collection handle.
        /// Omit only when the secret id is unique across every ready vault.
        #[arg(long, value_parser = parse_vault_selector)]
        vault: Option<VaultSelector>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VaultSelector {
    Id(Id),
    Collection(CollectionHandle),
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

fn parse_vault_selector(raw: &str) -> std::result::Result<VaultSelector, String> {
    let raw = raw.trim();
    match raw.len() {
        32 => parse_id(raw).map(VaultSelector::Id),
        64 => {
            let bytes = hex::decode(raw)
                .map_err(|_| format!("'{raw}' is not a hexadecimal collection handle"))?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| format!("'{raw}' is not a 64-digit collection handle"))?;
            Ok(VaultSelector::Collection(Inline::new(bytes)))
        }
        _ => Err(format!(
            "'{raw}' is neither a 32-digit vault id nor a 64-digit collection handle"
        )),
    }
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

fn fmt_collection(collection: CollectionHandle) -> String {
    hex::encode(collection.raw)
}

fn fmt_selector(selector: VaultSelector) -> String {
    match selector {
        VaultSelector::Id(vault) => format!("id:{}", fmt_id(vault)),
        VaultSelector::Collection(collection) => {
            format!("collection:{}", fmt_collection(collection))
        }
    }
}

fn point_now() -> Result<secrets::IntervalValue> {
    clock::point_now()
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
    selector: VaultSelector,
) -> Result<vaults::VaultLocation> {
    match selector {
        VaultSelector::Id(vault) => discovery.location(vault).copied().ok_or_else(|| {
            anyhow!(
                "vault id {} is absent or ambiguous for this node; use its exact collection handle",
                fmt_id(vault)
            )
        }),
        VaultSelector::Collection(collection) => discovery
            .location_exact(collection)
            .copied()
            .ok_or_else(|| {
                anyhow!(
                    "vault collection {} is not ready for this node",
                    fmt_collection(collection)
                )
            }),
    }
}

fn cmd_vault_create(storage: SecretsStorage<'_>, vault: Id, name: String) -> Result<()> {
    println!("selected vault {}  {name}", fmt_id(vault));
    std::io::stdout()
        .flush()
        .context("announce selected vault id before publication")?;
    storage.with_pile(|pile, signer| {
        let location = vaults::create_vault(pile, signer, vault, &name, point_now()?)?;
        println!("vault {}  {name}", fmt_id(location.vault()));
        Ok(())
    })
}

fn print_issues(discovery: &vaults::VaultDiscovery) {
    for issue in discovery.issues() {
        let identity = issue
            .vault()
            .map(|vault| {
                format!(
                    "vault {} collection {}",
                    fmt_id(vault),
                    fmt_collection(issue.collection())
                )
            })
            .unwrap_or_else(|| format!("collection {}", fmt_collection(issue.collection())));
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
        for (collection, location) in discovery.locations() {
            let snapshot = discovery
                .snapshot()
                .vault_exact(*collection)
                .expect("every ready location has one aggregate snapshot");
            let name = secrets::read_text(
                discovery.snapshot().store_snapshot(),
                snapshot.catalog().header.name,
            )?;
            println!(
                "{}  collection {}  {}  ({} secret(s))",
                fmt_id(location.vault()),
                fmt_collection(*collection),
                name,
                snapshot.catalog().secrets.len()
            );
        }
        print_issues(&discovery);
        Ok(())
    })
}

fn cmd_vault_grant(
    storage: SecretsStorage<'_>,
    selector: VaultSelector,
    recipient: VerifyingKey,
) -> Result<()> {
    storage.with_pile(|pile, signer| {
        let discovery = vaults::discover_local_vaults(pile, signer)?;
        let location = require_location(&discovery, selector)?;
        let envelopes =
            vaults::grant_vault_read(pile, signer, &location, discovery.snapshot(), recipient)?;
        for envelope in envelopes {
            println!(
                "access {}  vault {}  collection {}  selected-by {}  recipient {}",
                fmt_id(envelope),
                fmt_id(location.vault()),
                fmt_collection(location.collection()),
                fmt_selector(selector),
                fmt_key(recipient)
            );
        }
        Ok(())
    })
}

fn cmd_secret_add(
    storage: SecretsStorage<'_>,
    selector: VaultSelector,
    name: String,
    value: String,
) -> Result<()> {
    let plaintext = load_value(value)?;
    storage.with_pile(|pile, signer| {
        let discovery = vaults::discover_local_vaults(pile, signer)?;
        let location = require_location(&discovery, selector)?;
        let secret = vaults::add_secret(
            pile,
            signer,
            &location,
            discovery.snapshot(),
            &name,
            &plaintext,
            point_now()?,
        )?;
        println!(
            "secret {}  vault {}  collection {}  selected-by {}  {name}",
            fmt_id(secret),
            fmt_id(location.vault()),
            fmt_collection(location.collection()),
            fmt_selector(selector)
        );
        Ok(())
    })
}

fn cmd_secret_get(
    storage: SecretsStorage<'_>,
    selector: Option<VaultSelector>,
    secret: Id,
) -> Result<()> {
    let plaintext = Zeroizing::new(storage.with_pile(|pile, signer| {
        let discovery = vaults::discover_local_vaults(pile, signer)?;
        match selector {
            Some(selector) => {
                let location = require_location(&discovery, selector)?;
                discovery
                    .snapshot()
                    .open_exact(location.collection(), secret, signer)
            }
            None => discovery.snapshot().open(secret, signer),
        }
    })?);
    std::io::stdout()
        .write_all(&plaintext)
        .context("write secret to stdout")?;
    Ok(())
}

fn cmd_secret_list(storage: SecretsStorage<'_>) -> Result<()> {
    storage.with_pile(|pile, signer| {
        let discovery = vaults::discover_local_vaults(pile, signer)?;
        let mut count = 0;
        for snapshot in discovery.snapshot().vaults() {
            let collection = snapshot
                .collection()
                .expect("every discovered vault snapshot retains its exact collection");
            for secret in snapshot.catalog().secrets.values() {
                let name = secrets::read_text(discovery.snapshot().store_snapshot(), secret.name)?;
                println!(
                    "{}  vault {}  collection {}  {name}",
                    fmt_id(secret.id),
                    fmt_id(snapshot.id()),
                    fmt_collection(collection)
                );
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
            VaultCommand::Create { id, name } => {
                cmd_vault_create(storage, id.unwrap_or_else(|| genid().id), name)
            }
            VaultCommand::List => cmd_vault_list(storage),
            VaultCommand::Grant { vault, recipient } => cmd_vault_grant(storage, vault, recipient),
        },
        Command::Secret { command } => match command {
            SecretCommand::Add { vault, name, value } => {
                cmd_secret_add(storage, vault, name, value)
            }
            SecretCommand::Get { vault, secret } => cmd_secret_get(storage, vault, secret),
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
    fn capability_surface_accepts_only_vaults_and_exact_secret_ids() {
        for args in [
            vec![
                "secrets", "--pile", PILE, "vault", "create", "--name", "prod",
            ],
            vec![
                "secrets", "--pile", PILE, "vault", "create", "--id", ID, "--name", "prod",
            ],
            vec!["secrets", "--pile", PILE, "vault", "list"],
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
                "secrets",
                "--pile",
                PILE,
                "vault",
                "grant",
                "--vault",
                KEY,
                "--recipient",
                KEY,
            ],
            vec![
                "secrets", "--pile", PILE, "secret", "add", "--vault", ID, "--name", "token",
                "--value", "value",
            ],
            vec![
                "secrets", "--pile", PILE, "secret", "add", "--vault", KEY, "--name", "token",
                "--value", "value",
            ],
            vec!["secrets", "--pile", PILE, "secret", "get", "--secret", ID],
            vec![
                "secrets", "--pile", PILE, "secret", "get", "--vault", ID, "--secret", ID,
            ],
            vec![
                "secrets", "--pile", PILE, "secret", "get", "--vault", KEY, "--secret", ID,
            ],
            vec!["secrets", "--pile", PILE, "secret", "list"],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }
        for removed in [
            vec!["secrets", "--pile", PILE, "vault", "members", "--vault", ID],
            vec!["secrets", "--pile", PILE, "secret", "share", "--secret", ID],
        ] {
            assert!(Cli::try_parse_from(removed).is_err());
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
