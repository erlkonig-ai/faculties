//! Explicit LinkedIn MCP UX. Import rows are resident values; pulling the fixed
//! LinkedIn service is a separate finite operation with trusted host credentials.
use super::{operations::*, render};
use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::PathBuf;

const TOOLS: &[Tool] = &[
    Tool { name: "linkedin_import", description: "Import resident connection records into Relations. Text is literal; no snapshot paths or @file expansion. Stable URL/email keys converge, uncertain identity evidence fails closed, and name-only imports mint fresh anchors. dry_run plans without committing.",
        input_schema: r#"{"type":"object","properties":{"connections":{"type":"array","items":{"type":"object","properties":{"first_name":{"type":"string"},"last_name":{"type":"string"},"company":{"type":"string"},"position":{"type":"string"},"profile_url":{"type":"string"},"email":{"type":"string"}},"additionalProperties":false}},"dry_run":{"type":"boolean","default":false}},"required":["connections"],"additionalProperties":false}"# },
    Tool { name: "linkedin_pull", description: "Explicit finite DMA Member Data Portability API read using the trusted host's LinkedIn token, then import into Relations. dry_run still contacts LinkedIn but commits nothing locally. The app's pinned API version defaults to 202312; no token or arbitrary URL is accepted.",
        input_schema: r#"{"type":"object","properties":{"domain":{"type":"string","default":"CONNECTIONS"},"api_version":{"type":"string","default":"202312"},"dry_run":{"type":"boolean","default":false}},"additionalProperties":false}"# },
    Tool { name: "linkedin_review", description: "Read unresolved same-label identity pairs derived from current resident Relations profiles and verdicts. No token or network required; no review catalog is persisted.",
        input_schema: r#"{"type":"object","properties":{"limit":{"type":"integer","minimum":0,"default":50,"description":"Maximum pairs to display; zero displays none while retaining the total count."}},"additionalProperties":false}"# },
    Tool { name: "linkedin_resolve", description: "Append an explicit same-person or distinct-person identity verdict between two Relations anchors, superseding every current direct fork head. Repeated settled verdicts are no-ops. Does not destructively merge or rewrite profiles.",
        input_schema: r#"{"type":"object","properties":{"first":{"type":"string","description":"Exact person hex ID or unambiguous prefix."},"second":{"type":"string","description":"Exact person hex ID or unambiguous prefix."},"same":{"type":"boolean"}},"required":["first","second","same"],"additionalProperties":false}"# },
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionInput {
    #[serde(default)]
    first_name: String,
    #[serde(default)]
    last_name: String,
    #[serde(default)]
    company: String,
    #[serde(default)]
    position: String,
    #[serde(default)]
    profile_url: String,
    #[serde(default)]
    email: String,
}
impl From<ConnectionInput> for Connection {
    fn from(value: ConnectionInput) -> Self {
        Self {
            first_name: value.first_name,
            last_name: value.last_name,
            company: value.company,
            position: value.position,
            profile_url: value.profile_url,
            email: value.email,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Import {
    #[serde(deserialize_with = "crate::mcp::object::vec")]
    connections: Vec<ConnectionInput>,
    #[serde(default)]
    dry_run: bool,
}
fn domain() -> String {
    "CONNECTIONS".into()
}
fn api_version() -> String {
    "202312".into()
}
fn limit() -> usize {
    50
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pull {
    #[serde(default = "domain")]
    domain: String,
    #[serde(default = "api_version")]
    api_version: String,
    #[serde(default)]
    dry_run: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    #[serde(default = "limit")]
    limit: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Resolve {
    first: String,
    second: String,
    same: bool,
}

#[derive(Clone, Debug)]
pub struct LinkedIn {
    operations: super::operations::LinkedIn,
}
impl LinkedIn {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }
    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self {
            operations: super::operations::LinkedIn::with_storage(storage),
        }
    }
    /// Trusted launcher configuration, deliberately absent from the tool schemas.
    pub fn with_token(mut self, token: String) -> Self {
        self.operations = self.operations.with_token(token);
        self
    }
}
impl Faculty for LinkedIn {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        match name {
            "linkedin_import" => {
                let args: Import = decode_arguments(arguments)?;
                let rows = args
                    .connections
                    .into_iter()
                    .map(Connection::from)
                    .collect::<Vec<_>>();
                let value = self.operations.import(&rows, args.dry_run)?;
                out.line(format!("Read {} resident connection records", rows.len()))?;
                render::import(&value, out)?;
                render::profiles(&value, out)
            }
            "linkedin_pull" => {
                let args: Pull = decode_arguments(arguments)?;
                let options = PullOptions {
                    domain: args.domain,
                    api_version: args.api_version,
                    dry_run: args.dry_run,
                };
                options.validate().map_err(invalid_arguments)?;
                let value = self.operations.pull(options.clone())?;
                out.line(format!(
                    "Fetched {} {} record(s).",
                    value.records, options.domain
                ))?;
                for notice in &value.notices {
                    out.line(notice)?;
                }
                render::import(&value.import, out)?;
                render::profiles(&value.import, out)
            }
            "linkedin_review" => {
                let args: Review = decode_arguments(arguments)?;
                render::review(&self.operations.review(args.limit)?, out)
            }
            "linkedin_resolve" => {
                let args: Resolve = decode_arguments(arguments)?;
                validate_person_selector(&args.first).map_err(invalid_arguments)?;
                validate_person_selector(&args.second).map_err(invalid_arguments)?;
                render::resolved(
                    &self
                        .operations
                        .resolve(&args.first, &args.second, args.same)?,
                    out,
                )
            }
            _ => bail!("unknown LinkedIn MCP tool {name:?}"),
        }
    }
}
