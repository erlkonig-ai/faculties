//! Literal finite provider operations, with credentials owned by the launcher.
use super::{presentation, Provider, Web as Operations};
use crate::mcp::{decode_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::PathBuf;

const TOOLS: &[Tool] = &[
    Tool {name:"web_search", description:"Search Tavily or Exa using the configured exact Headspace credential. Query text is literal. Auto prefers Tavily for search. Records the returned observation after successful emission unless record=false; provider requests have a 60-second timeout.", input_schema:r#"{"type":"object","properties":{"query":{"type":"string"},"provider":{"type":"string","enum":["auto","tavily","exa"],"default":"auto"},"max_results":{"type":"integer","minimum":0,"default":5},"record":{"type":"boolean","default":true}},"required":["query"],"additionalProperties":false}"#},
    Tool {name:"web_fetch", description:"Ask Tavily or Exa to extract a URL as text. This is interpreted content, not original file-byte export. Auto prefers Exa; max_characters is a provider hint honored by Exa, not Tavily. Records the observation unless record=false; provider requests have a 60-second timeout.", input_schema:r#"{"type":"object","properties":{"url":{"type":"string"},"provider":{"type":"string","enum":["auto","tavily","exa"],"default":"auto"},"max_characters":{"type":"integer","minimum":0,"default":12000},"record":{"type":"boolean","default":true}},"required":["url"],"additionalProperties":false}"#},
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Search {
    query: String,
    #[serde(default)]
    provider: Provider,
    #[serde(default = "results_default")]
    max_results: usize,
    #[serde(default = "record_default")]
    record: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fetch {
    url: String,
    #[serde(default)]
    provider: Provider,
    #[serde(default = "characters_default")]
    max_characters: usize,
    #[serde(default = "record_default")]
    record: bool,
}
fn results_default() -> usize {
    5
}
fn characters_default() -> usize {
    12000
}
fn record_default() -> bool {
    true
}
pub struct Web {
    operations: Operations,
}
impl Web {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self {
            operations: Operations::new(pile, key),
        }
    }
    /// Trusted Rust/launcher injection, not request-controlled service routing.
    pub fn from_operations(operations: Operations) -> Self {
        Self { operations }
    }
}
impl Faculty for Web {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        match name {
            "web_search" => {
                let args: Search = decode_arguments(arguments)?;
                let report =
                    self.operations
                        .search(args.provider, &args.query, args.max_results)?;
                presentation::search(&report, out)?;
                if args.record {
                    self.operations.record_search(&report)?;
                }
                Ok(())
            }
            "web_fetch" => {
                let args: Fetch = decode_arguments(arguments)?;
                let report =
                    self.operations
                        .fetch(args.provider, &args.url, args.max_characters)?;
                out.line(&report.content)?;
                if args.record {
                    self.operations.record_fetch(&report)?;
                }
                Ok(())
            }
            _ => bail!("Web MCP has no tool {name:?}"),
        }
    }
}
