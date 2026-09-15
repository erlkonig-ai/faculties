//! Explicit credential operations. Discovery/listing never opens plaintext.
use super::Secrets as Operations;
use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use base64::Engine as _;
use faculties_secrets::resource::{DeliveryLimits, SecretTarget};
use serde::Deserialize;
use std::path::PathBuf;
use triblespace::prelude::Id;
use zeroize::Zeroizing;

const EMPTY: &str = r#"{"type":"object","properties":{},"additionalProperties":false}"#;
const TOOLS: &[Tool] = &[
    Tool {name:"secrets_add", description:"Encrypt one immutable version from literal value text or base64 bytes. Supply exactly one. Returns its ID, never echoes plaintext, and never reads a server file or stdin. Repeating an add creates a new version.", input_schema:r#"{"type":"object","properties":{"name":{"type":"string"},"value":{"type":"string"},"data_base64":{"type":"string"}},"required":["name"],"oneOf":[{"required":["value"]},{"required":["data_base64"]}],"additionalProperties":false}"#},
    Tool {name:"secrets_get", description:"Explicitly decrypt one exact immutable version and return its original plaintext bytes as an embedded binary resource. This reveals the selected secret to the caller; it is not a metadata query or image/audio perception.", input_schema:r#"{"type":"object","properties":{"secret":{"type":"string","description":"Exact nonzero 32-digit version ID"}},"required":["secret"],"additionalProperties":false}"#},
    Tool {name:"secrets_list", description:"List immutable secret version IDs and names in the configured collection. Does not decrypt secret values.", input_schema:EMPTY},
    Tool {name:"secrets_grant", description:"Grant future DEK delivery for one exact secret or resource. Does not grant collection READ/WRITE or reveal plaintext. Optional delivery deadlines do not expire already-delivered envelopes; delegate permits onward grants.", input_schema:r#"{"type":"object","properties":{"secret":{"type":"string"},"resource":{"type":"string"},"recipient":{"type":"string"},"not_before":{"type":"string","format":"date-time"},"expires_at":{"type":"string","format":"date-time"},"delegate":{"type":"boolean","default":false}},"required":["recipient"],"oneOf":[{"required":["secret"]},{"required":["resource"]}],"additionalProperties":false}"#},
    Tool {name:"secrets_maintain", description:"Deliver existing encrypted DEKs to authorized resource-specific recipients. Optional secret/resource selections limit the pass; otherwise visits all bound resources the holder can open. No grants, body rewrites, or plaintext output.", input_schema:r#"{"type":"object","properties":{"secrets":{"type":"array","items":{"type":"string"},"default":[]},"resources":{"type":"array","items":{"type":"string"},"default":[]}},"additionalProperties":false}"#},
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Add {
    name: String,
    value: Option<String>,
    data_base64: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Get {
    secret: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    secret: Option<String>,
    resource: Option<String>,
    recipient: String,
    not_before: Option<String>,
    expires_at: Option<String>,
    #[serde(default)]
    delegate: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Maintain {
    #[serde(default)]
    secrets: Vec<String>,
    #[serde(default)]
    resources: Vec<String>,
}

fn secret_target(raw: &str) -> Result<SecretTarget> {
    Id::from_hex(raw.trim())
        .map(SecretTarget::Secret)
        .ok_or_else(|| invalid_arguments("secret must be an exact nonzero 32-digit version ID"))
}

fn resource_target(raw: &str) -> Result<SecretTarget> {
    super::cli::parse_resource(raw)
        .map(SecretTarget::Resource)
        .map_err(invalid_arguments)
}

pub struct Secrets {
    operations: Operations,
}
impl Secrets {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }
    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self {
            operations: Operations::with_storage(storage),
        }
    }
}
impl Faculty for Secrets {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        match name {
            "secrets_add" => {
                let args: Add = decode_arguments(arguments)?;
                let plaintext = match (args.value, args.data_base64) {
                    (Some(value), None) => Zeroizing::new(value.into_bytes()),
                    (None, Some(encoded)) => {
                        let encoded = Zeroizing::new(encoded);
                        Zeroizing::new(
                            base64::engine::general_purpose::STANDARD
                                .decode(encoded.as_bytes())
                                .map_err(|_| invalid_arguments("invalid data_base64"))?,
                        )
                    }
                    _ => {
                        return Err(invalid_arguments(
                            "supply exactly one of value or data_base64",
                        ))
                    }
                };
                let id = self.operations.add(&args.name, &plaintext)?;
                out.line(format!("secret {id:x}  {}", args.name))
            }
            "secrets_get" => {
                let args: Get = decode_arguments(arguments)?;
                let secret = Id::from_hex(args.secret.trim()).ok_or_else(|| {
                    invalid_arguments("secret must be an exact nonzero 32-digit version ID")
                })?;
                let plaintext = self.operations.get(secret)?;
                out.blob(
                    plaintext.to_vec(),
                    "application/octet-stream",
                    format!("secrets://{secret:x}"),
                )
            }
            "secrets_list" => {
                let _: Empty = decode_arguments(arguments)?;
                let rows = self.operations.list()?;
                if rows.is_empty() {
                    out.line("(no secrets)")?;
                }
                for row in rows {
                    out.line(format!("{:x}  {}", row.id, row.name))?;
                }
                Ok(())
            }
            "secrets_maintain" => {
                let args: Maintain = decode_arguments(arguments)?;
                let selected = args
                    .secrets
                    .iter()
                    .map(|raw| secret_target(raw))
                    .chain(args.resources.iter().map(|raw| resource_target(raw)))
                    .collect::<Result<Vec<_>>>()?;
                out.line(format!(
                    "added {} recipient envelope(s)",
                    self.operations.maintain_selected(&selected)?
                ))
            }
            "secrets_grant" => {
                let args: Grant = decode_arguments(arguments)?;
                let target = match (args.secret, args.resource) {
                    (Some(secret), None) => secret_target(&secret)?,
                    (None, Some(resource)) => resource_target(&resource)?,
                    _ => {
                        return Err(invalid_arguments(
                            "supply exactly one of secret or resource",
                        ))
                    }
                };
                let recipient =
                    super::cli::parse_recipient(&args.recipient).map_err(invalid_arguments)?;
                let parse_time = |raw: String| {
                    raw.parse()
                        .map_err(|_| invalid_arguments("invalid delivery timestamp"))
                };
                let limits = DeliveryLimits {
                    not_before: args.not_before.map(parse_time).transpose()?,
                    expires_at: args.expires_at.map(parse_time).transpose()?,
                };
                for id in self
                    .operations
                    .grant(target, recipient, limits, args.delegate)?
                {
                    out.line(format!("AUTH blake3:{}", hex::encode(id.raw)))?;
                }
                Ok(())
            }
            _ => bail!("Secrets MCP has no tool {name:?}"),
        }
    }
}
