//! Independent Compass MCP tools over native operations.
//! Launcher configuration is private; attribution is explicit on write calls.

use std::path::PathBuf;

use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;

use super::{render, AddOptions, Compass as Operations, ListOptions, NoteOptions};
use crate::mcp::{decode_arguments, Faculty, Tool};
use crate::out::Out;

const TOOLS: &[Tool] = &[
    Tool {
        name: "compass_add",
        description: "Add a goal with an initial status and optional note. Title and note are literal text; leading @ characters never read host files.",
        input_schema: r#"{"type":"object","properties":{"title":{"type":"string"},"status":{"type":"string","default":"todo"},"parent":{"type":"string","description":"Parent goal id or unique prefix"},"tags":{"type":"array","items":{"type":"string"},"default":[]},"note":{"type":"string"},"persona":{"type":"string","description":"Optional active Relations persona label or full id for cooperative attribution; never read from the server's PERSONA environment."}},"required":["title"],"additionalProperties":false}"#,
    },
    Tool {
        name: "compass_list",
        description: "List goals in kanban columns. Done goals are hidden unless all is true or their status is explicitly selected.",
        input_schema: r#"{"type":"object","properties":{"all":{"type":"boolean","default":false},"tags":{"type":"array","items":{"type":"string"},"default":[]},"statuses":{"type":"array","items":{"type":"string"},"default":[]}},"additionalProperties":false}"#,
    },
    Tool {
        name: "compass_move",
        description: "Append a status event to a goal.",
        input_schema: r#"{"type":"object","properties":{"id":{"type":"string"},"status":{"type":"string"},"persona":{"type":"string","description":"Optional active Relations persona label or full id for cooperative attribution; never read from the server's PERSONA environment."}},"required":["id","status"],"additionalProperties":false}"#,
    },
    Tool {
        name: "compass_note",
        description: "Append a literal note with optional tags, exact references, and note supersedes links. Superseded notes remain visible.",
        input_schema: r#"{"type":"object","properties":{"id":{"type":"string"},"note":{"type":"string"},"tags":{"type":"array","items":{"type":"string"},"default":[]},"references":{"type":"array","items":{"type":"string"},"default":[]},"supersedes":{"type":"array","items":{"type":"string","description":"Existing full 32-character note id"},"default":[]},"persona":{"type":"string","description":"Optional active Relations persona label or full id for cooperative attribution; never read from the server's PERSONA environment."}},"required":["id","note"],"additionalProperties":false}"#,
    },
    Tool {
        name: "compass_show",
        description: "Show a goal, its status history, and every note with references and attribution.",
        input_schema: r#"{"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false}"#,
    },
    Tool {
        name: "compass_prioritize",
        description: "Assert one goal is more important than another; reject priority cycles and conflicts with child-before-parent ordering.",
        input_schema: r#"{"type":"object","properties":{"higher":{"type":"string"},"over":{"type":"string"}},"required":["higher","over"],"additionalProperties":false}"#,
    },
    Tool {
        name: "compass_deprioritize",
        description: "Append a retraction of an active explicit priority relationship.",
        input_schema: r#"{"type":"object","properties":{"higher":{"type":"string"},"over":{"type":"string"}},"required":["higher","over"],"additionalProperties":false}"#,
    },
    Tool {
        name: "compass_resolve",
        description: "Resolve a goal's unique hex prefix to its full id.",
        input_schema: r#"{"type":"object","properties":{"prefix":{"type":"string"}},"required":["prefix"],"additionalProperties":false}"#,
    },
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddArguments {
    title: String,
    #[serde(default = "todo")]
    status: String,
    parent: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    note: Option<String>,
    persona: Option<String>,
}

fn todo() -> String {
    "todo".to_owned()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArguments {
    #[serde(default)]
    all: bool,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    statuses: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MoveArguments {
    id: String,
    status: String,
    persona: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoteArguments {
    id: String,
    note: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    supersedes: Vec<String>,
    persona: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShowArguments {
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PriorityArguments {
    higher: String,
    over: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveArguments {
    prefix: String,
}

pub struct Compass {
    operations: Operations,
}

impl Compass {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }

    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self {
            operations: Operations::with_storage(storage),
        }
    }
}

impl Faculty for Compass {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }

    fn call(&self, name: &str, arguments: Bytes, output: &mut Out<'_>) -> Result<()> {
        match name {
            "compass_add" => {
                let args: AddArguments = decode_arguments(arguments)?;
                let receipt = self.operations.add(
                    &args.title,
                    AddOptions {
                        status: &args.status,
                        parent: args.parent.as_deref(),
                        tags: &args.tags,
                        note: args.note.as_deref(),
                        persona: args.persona.as_deref(),
                    },
                )?;
                render::added(&receipt, output)
            }
            "compass_list" => {
                let args: ListArguments = decode_arguments(arguments)?;
                output.text(self.operations.list(ListOptions {
                    statuses: &args.statuses,
                    tags: &args.tags,
                    all: args.all,
                })?)
            }
            "compass_move" => {
                let args: MoveArguments = decode_arguments(arguments)?;
                render::moved(
                    &self
                        .operations
                        .move_goal(&args.id, &args.status, args.persona.as_deref())?,
                    output,
                )
            }
            "compass_note" => {
                let args: NoteArguments = decode_arguments(arguments)?;
                let receipt = self.operations.note(
                    &args.id,
                    &args.note,
                    NoteOptions {
                        tags: &args.tags,
                        references: &args.references,
                        supersedes: &args.supersedes,
                        persona: args.persona.as_deref(),
                    },
                )?;
                render::noted(&receipt, output)
            }
            "compass_show" => {
                let args: ShowArguments = decode_arguments(arguments)?;
                output.text(self.operations.show(&args.id)?)
            }
            "compass_prioritize" => {
                let args: PriorityArguments = decode_arguments(arguments)?;
                render::prioritized(
                    &self.operations.prioritize(&args.higher, &args.over)?,
                    output,
                )
            }
            "compass_deprioritize" => {
                let args: PriorityArguments = decode_arguments(arguments)?;
                render::prioritized(
                    &self.operations.deprioritize(&args.higher, &args.over)?,
                    output,
                )
            }
            "compass_resolve" => {
                let args: ResolveArguments = decode_arguments(arguments)?;
                output.line(format!("{:x}", self.operations.resolve(&args.prefix)?))
            }
            other => bail!("Compass MCP has no tool {other:?}"),
        }
    }
}
