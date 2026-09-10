//! Explicit finite Cognition MCP adapter; no caller-selected storage scope.

use crate::mcp::{decode_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::PathBuf;

pub struct Cognition {
    operations: super::Cognition,
}
impl Cognition {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }
    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self {
            operations: super::Cognition::with_storage(storage),
        }
    }
}

const TOOLS: &[Tool] = &[Tool {
    name: "cognition_check",
    description: "Validate the fixed shared Cognition collection and known attachments from one maintained observation. Does not author execution events or run a model.",
    input_schema: r#"{"type":"object","properties":{},"additionalProperties":false}"#,
}];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {}

impl Faculty for Cognition {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        match name {
            "cognition_check" => {
                let _: Check = decode_arguments(arguments)?;
                out.line(self.operations.check()?.summary())
            }
            _ => bail!("unknown Cognition MCP tool {name:?}"),
        }
    }
}
