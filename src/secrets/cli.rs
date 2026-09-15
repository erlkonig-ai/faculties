//! Shell-specific secret input and exact stdout export.
use super::Secrets;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::VerifyingKey;
use faculties_secrets::resource::{DeliveryLimits, SecretTarget};
use hifitime::Epoch;
use std::io::{Read, Write};
use std::path::PathBuf;
use triblespace::core::collection::CollectionHandle;
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
    /// Grant future DEK delivery for one immutable resource (not collection READ/WRITE).
    Grant {
        #[arg(long, value_parser = parse_id, required_unless_present = "resource", conflicts_with = "resource")]
        secret: Option<Id>,
        #[arg(long, value_parser = parse_resource, required_unless_present = "secret")]
        resource: Option<CollectionHandle>,
        #[arg(long, value_parser = parse_recipient)]
        recipient: VerifyingKey,
        /// Earliest future delivery instant, inclusive (RFC3339).
        #[arg(long)]
        not_before: Option<Epoch>,
        /// End of future delivery, exclusive (RFC3339); existing envelopes still open.
        #[arg(long)]
        expires_at: Option<Epoch>,
        /// Also allow the recipient to delegate this delivery action.
        #[arg(long)]
        delegate: bool,
    },
    /// Deliver DEKs for selected resources; without a selection, visit held bound resources.
    Maintain {
        #[arg(long, value_parser = parse_id)]
        secret: Vec<Id>,
        #[arg(long, value_parser = parse_resource)]
        resource: Vec<CollectionHandle>,
    },
}

fn parse_id(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim())
        .ok_or_else(|| format!("'{raw}' is not one exact nonzero 32-digit hexadecimal id"))
}

pub(crate) fn parse_resource(raw: &str) -> std::result::Result<CollectionHandle, String> {
    let raw = raw.trim().strip_prefix("blake3:").unwrap_or(raw.trim());
    let bytes: [u8; 32] = hex::decode(raw)
        .map_err(|_| "resource must be a 64-digit blob handle")?
        .try_into()
        .map_err(|_| "resource must be a 64-digit blob handle")?;
    Ok(CollectionHandle::new(bytes))
}

pub(crate) fn parse_recipient(raw: &str) -> std::result::Result<VerifyingKey, String> {
    let bytes: [u8; 32] = hex::decode(raw.trim())
        .map_err(|_| "recipient must be a 64-digit public key")?
        .try_into()
        .map_err(|_| "recipient must be a 64-digit public key")?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid Ed25519 recipient")?;
    if key.is_weak() || key.to_edwards().compress().to_bytes() != bytes {
        return Err("recipient must be a canonical, non-weak Ed25519 key".into());
    }
    Ok(key)
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
            Command::Grant {
                secret,
                resource,
                recipient,
                not_before,
                expires_at,
                delegate,
            } => {
                let target = match (secret, resource) {
                    (Some(secret), None) => SecretTarget::Secret(secret),
                    (None, Some(resource)) => SecretTarget::Resource(resource),
                    _ => unreachable!("clap enforces exactly one target"),
                };
                let ids = operations.grant(
                    target,
                    recipient,
                    DeliveryLimits {
                        not_before,
                        expires_at,
                    },
                    delegate,
                )?;
                for id in ids {
                    out.line(format!("AUTH blake3:{}", hex::encode(id.raw)))?;
                }
                Ok(())
            }
            Command::Maintain { secret, resource } => out.line(format!(
                "added {} recipient envelope(s)",
                operations.maintain_selected(
                    &secret
                        .into_iter()
                        .map(SecretTarget::Secret)
                        .chain(resource.into_iter().map(SecretTarget::Resource))
                        .collect::<Vec<_>>()
                )?
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
    fn resource_native_surface_keeps_add_get_and_selected_maintenance() {
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
        for removed in ["vault", "revoke", "identity", "scope"] {
            assert!(Cli::try_parse_from(["secrets", "--pile", PILE, removed]).is_err());
        }
    }

    #[test]
    fn grant_requires_exactly_one_resource_selection_and_a_recipient() {
        let recipient = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[1; 32])
                .verifying_key()
                .to_bytes(),
        );
        let resource = "02".repeat(32);
        assert!(Cli::try_parse_from([
            "secrets",
            "--pile",
            PILE,
            "grant",
            "--secret",
            ID,
            "--recipient",
            &recipient,
            "--delegate",
            "--expires-at",
            "2030-01-01T00:00:00Z"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "secrets",
            "--pile",
            PILE,
            "grant",
            "--resource",
            &resource,
            "--recipient",
            &recipient
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "secrets",
            "--pile",
            PILE,
            "grant",
            "--recipient",
            &recipient
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "secrets",
            "--pile",
            PILE,
            "grant",
            "--secret",
            ID,
            "--resource",
            &resource,
            "--recipient",
            &recipient
        ])
        .is_err());
    }
}
