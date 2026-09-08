//! Explicit credential operations. Discovery/listing never opens plaintext.
use super::Secrets as Operations;
use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use base64::Engine as _;
use serde::Deserialize;
use std::path::PathBuf;
use triblespace::prelude::Id;
use zeroize::Zeroizing;

const EMPTY: &str = r#"{"type":"object","properties":{},"additionalProperties":false}"#;
const TOOLS: &[Tool] = &[
    Tool {name:"secrets_add", description:"Encrypt one immutable version from literal value text or base64 bytes. Supply exactly one. Returns its ID, never echoes plaintext, and never reads a server file or stdin. Repeating an add creates a new version.", input_schema:r#"{"type":"object","properties":{"name":{"type":"string"},"value":{"type":"string"},"data_base64":{"type":"string"}},"required":["name"],"oneOf":[{"required":["value"]},{"required":["data_base64"]}],"additionalProperties":false}"#},
    Tool {name:"secrets_get", description:"Explicitly decrypt one exact immutable version and return its original plaintext bytes as an embedded binary resource. This reveals the selected secret to the caller; it is not a metadata query or image/audio perception.", input_schema:r#"{"type":"object","properties":{"secret":{"type":"string","description":"Exact nonzero 32-digit version ID"}},"required":["secret"],"additionalProperties":false}"#},
    Tool {name:"secrets_list", description:"List immutable secret version IDs and names in the configured collection. Does not decrypt secret values.", input_schema:EMPTY},
    Tool {name:"secrets_maintain", description:"Deliver existing encrypted DEKs to currently authorized key-delivery recipients. Does not create grants, rewrite bodies, or reveal plaintext.", input_schema:EMPTY},
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

pub struct Secrets {
    operations: Operations,
}
impl Secrets {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self {
            operations: Operations::new(pile, key),
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
                let _: Empty = decode_arguments(arguments)?;
                out.line(format!(
                    "added {} recipient envelope(s)",
                    self.operations.maintain()?
                ))
            }
            _ => bail!("Secrets MCP has no tool {name:?}"),
        }
    }
}
