//! Explicit finite Code MCP adapter.
//!
//! Prose is literal here: no `@file`, no `@-`, no ambient `PERSONA` fallback,
//! and no CLI subprocess. Every tool answers from the same operations the CLI
//! uses, and every read renders the same provenance footer, because an answer
//! that cannot say which revisions it is true at is the failure this faculty
//! exists to prevent — through any frontend.

use std::path::PathBuf;

use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;

use super::index::Tier;
use super::operations::{Code as Operations, Filter, IngestOptions, Revision};
use super::render;
use crate::mcp::{decode_arguments, Faculty, Tool};
use crate::out::Out;

pub struct Code {
    operations: Operations,
}

impl Code {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }

    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self {
            operations: Operations::with_storage(storage),
        }
    }
}

const TOOLS: &[Tool] = &[
    Tool {
        name: "code_ingest",
        description: "Catalogue one or more git working copies into the Code collection. Git is the walker, so ignore rules, submodules and target directories come from it. Re-ingesting an unchanged tree parses nothing and writes nothing; an uncommitted tree is catalogued under a content digest of itself. Does not build a search index.",
        input_schema: r#"{"type":"object","properties":{"dirs":{"type":"array","items":{"type":"string"},"description":"Repository root paths."},"commit":{"type":"string","description":"Read this revision from git objects instead of the working tree."},"dry_run":{"type":"boolean","description":"Report what would be read without writing anything."}},"required":["dirs"],"additionalProperties":false}"#,
    },
    Tool {
        name: "code_find",
        description: "Where a name is DEFINED. An absence is an affirmative verdict carrying the number of units it is absent from and the revisions it was checked at, plus exactly-queried name-similar declarations that are labelled as NOT answers. Never uses a lexical index, because a lexical index cannot represent absence.",
        input_schema: r#"{"type":"object","properties":{"name":{"type":"string","description":"Exact declaration name."},"kind":{"type":"string"},"repo":{"type":"string"},"at":{"type":"string"}},"required":["name"],"additionalProperties":false}"#,
    },
    Tool {
        name: "code_uses",
        description: "Which declarations syntactically NAME an identifier, including paths recovered from inside macro token streams. Accepts a full '::'-joined path such as burn::train. Mentions are UNRESOLVED and positionless, so a common identifier returns a spread line and that caveat rather than a settled answer. Zero rows is the answer, not an empty result.",
        input_schema: r#"{"type":"object","properties":{"identifier":{"type":"string"},"imports":{"type":"boolean","description":"Instead count the units whose 'use' paths start with this root."},"kind":{"type":"string"},"repo":{"type":"string"},"at":{"type":"string"}},"required":["identifier"],"additionalProperties":false}"#,
    },
    Tool {
        name: "code_show",
        description: "Everything the catalogue holds about one declaration, selected by item id prefix or by name, including every location it is placed in. Byte-identical code in two files is ONE item with two placements.",
        input_schema: r#"{"type":"object","properties":{"selector":{"type":"string"},"source":{"type":"boolean","description":"Include the declaration's source lines."}},"required":["selector"],"additionalProperties":false}"#,
    },
    Tool {
        name: "code_dup",
        description: "Code that exists in more than one place, as a self-join on the placement relation. These are EXACT duplicates; near-duplicates are out of scope.",
        input_schema: r#"{"type":"object","properties":{"min_lines":{"type":"integer","description":"Ignore duplicates shorter than this many lines."},"cross_repo":{"type":"boolean","description":"Only duplication that crosses a repository boundary."},"repo":{"type":"string"},"at":{"type":"string"}},"additionalProperties":false}"#,
    },
    Tool {
        name: "code_stats",
        description: "What the catalogue holds per revision: units, placements, parse failures and declaration kinds.",
        input_schema: r#"{"type":"object","properties":{"repo":{"type":"string"},"at":{"type":"string"}},"additionalProperties":false}"#,
    },
    Tool {
        name: "code_index",
        description: "Build or refresh the two lexical covers over declaration prose and declaration tokens. The only Code operation that maintains a search index; ingest and reads never do.",
        input_schema: r#"{"type":"object","properties":{},"additionalProperties":false}"#,
    },
    Tool {
        name: "code_search",
        description: "The capability question: what do we already have that is about this? Ranks FILES rather than declarations and attaches derived evidence — the rarest 'use' roots of each file by corpus frequency, and the overlap with the top hit. Lexical: it cannot answer whether something is absent.",
        input_schema: r#"{"type":"object","properties":{"query":{"type":"string"},"top":{"type":"integer"},"in":{"type":"string","enum":["docs","text","both"],"description":"Rank over declaration prose, declaration tokens, or both."},"kind":{"type":"string"},"repo":{"type":"string"},"at":{"type":"string"}},"required":["query"],"additionalProperties":false}"#,
    },
    Tool {
        name: "code_blame",
        description: "Ask git which commits added or removed an occurrence of an identifier. The deliberate seam between the catalogue and history: git shows the diff, so unlike a difference between two scans it cannot misread a rename-with-edit as a removal.",
        input_schema: r#"{"type":"object","properties":{"identifier":{"type":"string"},"dirs":{"type":"array","items":{"type":"string"},"description":"Repository root paths to search."},"limit":{"type":"integer"}},"required":["identifier","dirs"],"additionalProperties":false}"#,
    },
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ingest {
    dirs: Vec<PathBuf>,
    #[serde(default)]
    commit: Option<String>,
    #[serde(default)]
    dry_run: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Find {
    name: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    at: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Uses {
    identifier: String,
    #[serde(default)]
    imports: bool,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    at: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Show {
    selector: String,
    #[serde(default)]
    source: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Dup {
    #[serde(default = "default_min_lines")]
    min_lines: u64,
    #[serde(default)]
    cross_repo: bool,
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    at: Option<String>,
}

fn default_min_lines() -> u64 {
    8
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stats {
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    at: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Search {
    query: String,
    #[serde(default = "default_top")]
    top: usize,
    #[serde(default = "default_tier", rename = "in")]
    tier: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    at: Option<String>,
}

fn default_top() -> usize {
    8
}

fn default_tier() -> String {
    "both".to_owned()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Blame {
    identifier: String,
    dirs: Vec<PathBuf>,
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    10
}

fn filter(kind: Option<String>, repo: Option<String>, at: Option<String>) -> Filter {
    Filter {
        kind,
        repo,
        revision: Revision::parse(at.as_deref()),
    }
}

impl Faculty for Code {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }

    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        match name {
            "code_ingest" => {
                let request: Ingest = decode_arguments(arguments)?;
                let report = self.operations.ingest(
                    &request.dirs,
                    &IngestOptions {
                        commit: request.commit,
                        dry_run: request.dry_run,
                    },
                )?;
                render::ingest(&report, out)
            }
            "code_find" => {
                let request: Find = decode_arguments(arguments)?;
                let answer = self.operations.find(
                    &request.name,
                    &filter(request.kind, request.repo, request.at),
                )?;
                render::definition(&answer, out)
            }
            "code_uses" => {
                let request: Uses = decode_arguments(arguments)?;
                let selected = filter(request.kind, request.repo, request.at);
                if request.imports {
                    let (count, provenance) =
                        self.operations.imports(&request.identifier, &selected)?;
                    out.line(format!(
                        "{} — first segment of a `use` path in {count} unit(s)",
                        request.identifier
                    ))?;
                    out.line("")?;
                    return render::provenance(&provenance, out);
                }
                let answer = self.operations.uses(&request.identifier, &selected)?;
                render::usage(&answer, out)
            }
            "code_show" => {
                let request: Show = decode_arguments(arguments)?;
                let detail = self.operations.show(&request.selector, request.source)?;
                render::detail(&detail, out)
            }
            "code_dup" => {
                let request: Dup = decode_arguments(arguments)?;
                let report = self.operations.duplicates(
                    request.min_lines,
                    request.cross_repo,
                    &filter(None, request.repo, request.at),
                )?;
                render::duplicates(&report, out)
            }
            "code_stats" => {
                let request: Stats = decode_arguments(arguments)?;
                let report = self
                    .operations
                    .stats(&filter(None, request.repo, request.at))?;
                render::stats(&report, out)
            }
            "code_index" => {
                let _: Index = decode_arguments(arguments)?;
                render::index(&self.operations.index()?, out)
            }
            "code_search" => {
                let request: Search = decode_arguments(arguments)?;
                let Some(tier) = Tier::from_name(&request.tier) else {
                    bail!("Code search tier must be one of: docs, text, both");
                };
                let report = self.operations.search(
                    &request.query,
                    tier,
                    request.top,
                    &filter(request.kind, request.repo, request.at),
                )?;
                render::search(&report, out)
            }
            "code_blame" => {
                let request: Blame = decode_arguments(arguments)?;
                let report =
                    self.operations
                        .blame(&request.identifier, &request.dirs, request.limit)?;
                render::blame(&report, out)
            }
            _ => bail!("unknown Code MCP tool {name:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_declares_a_closed_object_schema() {
        for tool in TOOLS {
            assert!(tool.name.starts_with("code_"), "{}", tool.name);
            assert!(
                tool.input_schema.contains("\"additionalProperties\":false"),
                "{} accepts unknown arguments",
                tool.name
            );
        }
    }

    #[test]
    fn every_read_tool_accepts_the_same_revision_selector() {
        // One vocabulary, spelled identically wherever it appears, so a caller
        // learns `--at` once and it means the same thing everywhere.
        for tool in TOOLS {
            if matches!(
                tool.name,
                "code_ingest" | "code_index" | "code_show" | "code_blame"
            ) {
                continue;
            }
            assert!(
                tool.input_schema.contains("\"at\""),
                "{} cannot be asked at a revision",
                tool.name
            );
        }
    }
}
