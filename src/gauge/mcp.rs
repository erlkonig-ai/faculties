//! A native read-only MCP lens. Arguments never address server files.
use super::{presentation, Gauge as Operations};
use crate::mcp::{decode_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::PathBuf;

const EMPTY: &str = r#"{"type":"object","properties":{},"additionalProperties":false}"#;
const TOOLS: &[Tool] = &[
    Tool {name:"gauge_health", description:"Read research-health counts from one frozen Wiki frontier. Logical entries and current states are distinct; divergent heads remain visible.", input_schema:EMPTY},
    Tool {name:"gauge_tags", description:"Count current tag evidence both by state occurrence and logical entry, without choosing a fork winner.", input_schema:EMPTY},
    Tool {name:"gauge_quality", description:"Show every published or refuted current Wiki state, including divergent heads.", input_schema:EMPTY},
    Tool {name:"gauge_hubs", description:"Count uniquely resolved incoming references to active Wiki entries. Ambiguous and missing selectors are reported separately.", input_schema:r#"{"type":"object","properties":{"top":{"type":"integer","minimum":0,"default":15}},"additionalProperties":false}"#},
    Tool {name:"gauge_risk", description:"Show current entries citing refuted or audit-warned evidence. Ambiguous references are reported with all candidate entries, not resolved arbitrarily.", input_schema:EMPTY},
    Tool {name:"gauge_orphans", description:"List Wiki entries whose every current state has no outgoing references, with stable entry IDs and fork visibility.", input_schema:r#"{"type":"object","properties":{"top":{"type":"integer","minimum":0,"default":20}},"additionalProperties":false}"#},
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Limit {
    top: Option<usize>,
}
pub struct Gauge {
    operations: Operations,
}
impl Gauge {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self {
            operations: Operations::new(pile, key),
        }
    }
}
impl Faculty for Gauge {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        match name {
            "gauge_hubs" | "gauge_orphans" => {
                let args: Limit = decode_arguments(arguments)?;
                if name == "gauge_hubs" {
                    presentation::hubs(&self.operations.hubs(args.top.unwrap_or(15))?, out)
                } else {
                    presentation::orphans(
                        &self.operations.orphans(args.top.unwrap_or(20))?,
                        false,
                        out,
                    )
                }
            }
            "gauge_health" | "gauge_tags" | "gauge_quality" | "gauge_risk" => {
                let _: Empty = decode_arguments(arguments)?;
                match name {
                    "gauge_health" => presentation::health(&self.operations.health()?, out),
                    "gauge_tags" => presentation::tags(&self.operations.tags()?, out),
                    "gauge_quality" => presentation::quality(&self.operations.quality()?, out),
                    _ => presentation::risk(&self.operations.risk()?, out),
                }
            }
            _ => bail!("Gauge MCP has no tool {name:?}"),
        }
    }
}
