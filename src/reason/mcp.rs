//! Literal reasoning notes and intended-action records, never command execution.

use std::path::PathBuf;

use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;
use triblespace::prelude::Id;

use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;

const TOOLS: &[Tool] = &[Tool {
    name: "reason_record",
    description: "Record a literal reasoning note with optional explicit turn/worker attribution. Optional command_text records a separate intended-action event; it is metadata and is NEVER executed. Does not consult TURN_ID, WORKER_ID, stdin, or host files.",
    input_schema: r#"{"type":"object","properties":{"text":{"type":"string","minLength":1},"turn_id":{"type":"string"},"worker_id":{"type":"string"},"command_text":{"type":"string","minLength":1}},"required":["text"],"additionalProperties":false}"#,
}];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    text: String,
    turn_id: Option<String>,
    worker_id: Option<String>,
    command_text: Option<String>,
}

fn id(value: Option<&str>, label: &str) -> Result<Option<Id>> {
    value
        .map(|value| {
            Id::from_hex(value.trim()).ok_or_else(|| invalid_arguments(format!("invalid {label}")))
        })
        .transpose()
}

pub struct Reason {
    operations: super::Reason,
}

impl Reason {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }
    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self {
            operations: super::Reason::with_storage(storage),
        }
    }
}

impl Faculty for Reason {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }

    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        if name != "reason_record" {
            bail!("Reason MCP has no tool {name:?}");
        }
        let args: Record = decode_arguments(arguments)?;
        if args.text.trim().is_empty() {
            return Err(invalid_arguments("reason text is empty"));
        }
        let turn = id(args.turn_id.as_deref(), "turn id")?;
        let worker = id(args.worker_id.as_deref(), "worker id")?;
        match args.command_text {
            Some(command) => {
                if command.trim().is_empty() {
                    return Err(invalid_arguments("command text is empty"));
                }
                let receipt = self
                    .operations
                    .record_action(&args.text, &command, turn, worker)?;
                out.line(format!("reason_id: {:x}", receipt.reason))?;
                out.line(format!("reason_action_id: {:x}", receipt.action))
            }
            None => out.line(format!(
                "reason_id: {:x}",
                self.operations.record(&args.text, turn, worker)?
            )),
        }
    }
}
