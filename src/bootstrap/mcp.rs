//! Native onboarding import into the launcher's already initialized pile.

use std::path::PathBuf;

use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;

use crate::mcp::{decode_arguments, Faculty, Tool};
use crate::out::Out;

const TOOLS: &[Tool] = &[Tool {
    name: "bootstrap_import",
    description: "Idempotently import the portable onboarding Wiki entries and Compass goals under the configured pile's existing signer. Does not initialize keys or accept another pile or local source path.",
    input_schema: r#"{"type":"object","properties":{},"additionalProperties":false}"#,
}];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

pub struct Bootstrap {
    pile: PathBuf,
    key: Option<PathBuf>,
}

impl Bootstrap {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self { pile, key }
    }
}

impl Faculty for Bootstrap {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }

    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        match name {
            "bootstrap_import" => {
                let _: Empty = decode_arguments(arguments)?;
                let report = pollster::block_on(super::import(&self.pile, self.key.as_deref()))?;
                super::render_import(&report, out)
            }
            _ => bail!("Bootstrap MCP has no tool {name:?}"),
        }
    }
}
