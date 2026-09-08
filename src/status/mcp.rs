//! Status MCP tools: literal prose and an explicit window/persona.

use super::{render, Status as Operations};
use crate::mcp::{decode_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::PathBuf;

const TOOLS: &[Tool] = &[
    Tool {
        name: "status_set",
        description: "Set the status of an explicitly named window. Persona is a Relations label/alias or exact 32-character window id, including unknown ids. Text is literal; no host files or ambient PERSONA are read.",
        input_schema: r#"{"type":"object","properties":{"persona":{"type":"string"},"text":{"type":"string"}},"required":["persona","text"],"additionalProperties":false}"#,
    },
    Tool {
        name: "status_list",
        description: "Show the latest status of every window.",
        input_schema: r#"{"type":"object","properties":{},"additionalProperties":false}"#,
    },
    Tool {
        name: "status_show",
        description: "Show a window's current status and recent history. Retired personas remain selectable; ambiguous or forked labels fail visibly.",
        input_schema: r#"{"type":"object","properties":{"window":{"type":"string"},"limit":{"type":"integer","minimum":0,"default":10}},"required":["window"],"additionalProperties":false}"#,
    },
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetArguments {
    persona: String,
    text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArguments {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShowArguments {
    window: String,
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    10
}

pub struct Status {
    operations: Operations,
}
impl Status {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self {
            operations: Operations::new(pile, key),
        }
    }
}
impl Faculty for Status {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, output: &mut Out<'_>) -> Result<()> {
        match name {
            "status_set" => {
                let args: SetArguments = decode_arguments(arguments)?;
                render::set(&self.operations.set(&args.persona, &args.text)?, output)
            }
            "status_list" => {
                let _: ListArguments = decode_arguments(arguments)?;
                render::list(&self.operations.list()?, output)
            }
            "status_show" => {
                let args: ShowArguments = decode_arguments(arguments)?;
                render::show(&self.operations.show(&args.window, args.limit)?, output)
            }
            other => bail!("Status MCP has no tool {other:?}"),
        }
    }
}
