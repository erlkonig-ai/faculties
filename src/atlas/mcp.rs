//! Finite Atlas MCP tools over callable Rust operations. Pile and key paths
//! belong to the local registration, never to caller-supplied tool arguments.

use std::path::PathBuf;

use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;

use super::{render, Store};
use crate::mcp::{decode_arguments, Faculty, Tool};
use crate::out::Out;

const TOOLS: &[Tool] = &[
    Tool {
        name: "atlas_list",
        description: "List named Atlas entities, preserving every metadata variant.",
        input_schema: r#"{"type":"object","properties":{},"additionalProperties":false}"#,
    },
    Tool {
        name: "atlas_show",
        description: "Show every metadata variant for one entity id or unique prefix.",
        input_schema: r#"{"type":"object","properties":{"id":{"type":"string","description":"Entity id or unique prefix"}},"required":["id"],"additionalProperties":false}"#,
    },
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArguments {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShowArguments {
    id: String,
}

pub struct Atlas {
    pile: PathBuf,
    key: Option<PathBuf>,
}

impl Atlas {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self { pile, key }
    }
}

impl Faculty for Atlas {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }

    fn call(&self, name: &str, arguments: Bytes, output: &mut Out<'_>) -> Result<()> {
        match name {
            "atlas_list" => {
                let _: ListArguments = decode_arguments(arguments)?;
                let mut store = Store::open(&self.pile, self.key.as_deref())?;
                let result = store.list().and_then(|rows| {
                    for row in rows {
                        output.line(render::list_line(&row))?;
                    }
                    Ok(())
                });
                store.finish(result)
            }
            "atlas_show" => {
                let arguments: ShowArguments = decode_arguments(arguments)?;
                let mut store = Store::open(&self.pile, self.key.as_deref())?;
                let result = store.show(&arguments.id).and_then(|row| {
                    for line in render::show_lines(&row) {
                        output.line(line)?;
                    }
                    Ok(())
                });
                store.finish(result)
            }
            other => bail!("Atlas MCP has no tool {other:?}"),
        }
    }
}
