//! Explicit finite timeout-extension requests, not a shell or a wait loop.

use std::path::PathBuf;

use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;
use triblespace::prelude::Id;

use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;

const TOOLS: &[Tool] = &[Tool {
    name: "patience_extend",
    description: "Publish a timeout-extension request for an explicit execution turn and worker. A receipt confirms publication, not acceptance by a runtime. Never runs a command and never reads ambient TURN_ID or WORKER_ID.",
    input_schema: r#"{"type":"object","properties":{"turn_id":{"type":"string"},"worker_id":{"type":"string"},"duration_ms":{"type":"integer","minimum":1}},"required":["turn_id","worker_id","duration_ms"],"additionalProperties":false}"#,
}];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Extend {
    turn_id: String,
    worker_id: String,
    duration_ms: u64,
}

pub struct Patience {
    operations: super::Patience,
}

impl Patience {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }
    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self {
            operations: super::Patience::with_storage(storage),
        }
    }
}

impl Faculty for Patience {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }

    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        if name != "patience_extend" {
            bail!("Patience MCP has no tool {name:?}");
        }
        let args: Extend = decode_arguments(arguments)?;
        if args.duration_ms == 0 {
            return Err(invalid_arguments("duration_ms must be greater than zero"));
        }
        let turn = Id::from_hex(args.turn_id.trim())
            .ok_or_else(|| invalid_arguments("invalid turn id"))?;
        let worker = Id::from_hex(args.worker_id.trim())
            .ok_or_else(|| invalid_arguments("invalid worker id"))?;
        let event = self.operations.extend(turn, worker, args.duration_ms)?;
        out.line(format!(
            "[{event:x}] timeout extended by {} ms",
            args.duration_ms
        ))
    }
}
