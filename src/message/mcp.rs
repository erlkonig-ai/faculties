//! Explicit finite Message tools. Text is literal, the sender is required,
//! and pile/key paths are trusted adapter configuration, never tool arguments.
use super::{render, AckAllOptions, ListOptions, Message as Operations, SendOptions};
use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::PathBuf;

pub struct Message {
    operations: Operations,
}

impl Message {
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
        name: "message_send",
        description: "Send literal text from an explicit active person to a person or group. Group delivery uses the selected group snapshot. No PERSONA fallback or @file/stdin expansion.",
        input_schema: r#"{"type":"object","properties":{"from":{"type":"string","minLength":1},"to":{"type":"string","minLength":1},"text":{"type":"string","minLength":1}},"required":["from","to","text"],"additionalProperties":false}"#,
    },
    Tool {
        name: "message_list",
        description: "List recent inbox and outbox messages for a reader, latest first. Unread restricts results to unread inbox messages. Listing does not acknowledge delivery.",
        input_schema: r#"{"type":"object","properties":{"reader":{"type":"string","minLength":1},"unread":{"type":"boolean","default":false},"limit":{"type":"integer","minimum":0,"default":20}},"required":["reader"],"additionalProperties":false}"#,
    },
    Tool {
        name: "message_ack",
        description: "Idempotently mark one eligible inbox message as read by an explicit reader.",
        input_schema: r#"{"type":"object","properties":{"id":{"type":"string","minLength":1},"by":{"type":"string","minLength":1}},"required":["id","by"],"additionalProperties":false}"#,
    },
    Tool {
        name: "message_ack_all",
        description: "Acknowledge currently unread inbox messages in one commit, optionally restricted to one sender. Frozen group delivery and settled identity equivalence are preserved.",
        input_schema: r#"{"type":"object","properties":{"by":{"type":"string","minLength":1},"from":{"type":"string","minLength":1}},"required":["by"],"additionalProperties":false}"#,
    },
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Send {
    from: String,
    to: String,
    text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    reader: String,
    #[serde(default)]
    unread: bool,
    #[serde(default = "list_limit")]
    limit: usize,
}
fn list_limit() -> usize {
    20
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {
    id: String,
    by: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AckAll {
    by: String,
    from: Option<String>,
}

fn nonempty(value: &str, name: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid_arguments(format!("{name} must not be empty")));
    }
    Ok(())
}

impl Faculty for Message {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }

    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        match name {
            "message_send" => {
                let args: Send = decode_arguments(arguments)?;
                let options = SendOptions {
                    from: &args.from,
                    to: &args.to,
                    text: &args.text,
                };
                options.validate().map_err(invalid_arguments)?;
                render::sent(&self.operations.send(&options)?, &args.text, out)
            }
            "message_list" => {
                let args: List = decode_arguments(arguments)?;
                nonempty(&args.reader, "reader")?;
                render::list(
                    &self.operations.list(&ListOptions {
                        reader: &args.reader,
                        unread: args.unread,
                        limit: args.limit,
                    })?,
                    out,
                )
            }
            "message_ack" => {
                let args: Ack = decode_arguments(arguments)?;
                nonempty(&args.id, "id")?;
                nonempty(&args.by, "by")?;
                render::acknowledged(&self.operations.ack(&args.id, &args.by)?, out)
            }
            "message_ack_all" => {
                let args: AckAll = decode_arguments(arguments)?;
                nonempty(&args.by, "by")?;
                if let Some(from) = &args.from {
                    nonempty(from, "from")?;
                }
                render::acknowledged_all(
                    &self.operations.ack_all(&AckAllOptions {
                        by: &args.by,
                        from: args.from.as_deref(),
                    })?,
                    out,
                )
            }
            other => bail!("Message MCP has no tool {other:?}"),
        }
    }
}
