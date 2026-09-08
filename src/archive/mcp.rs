//! Explicit resident Archive MCP adapter. No CLI, environment persona or host input paths.
use super::{parse_tai_timestamp, ImportSource};
use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use base64::Engine as _;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

pub struct Archive {
    operations: super::Archive,
}
impl Archive {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self {
            operations: super::Archive::new(pile, key),
        }
    }
}
const TOOLS:&[Tool]=&[
    Tool { name: "archive_import", description: "Import one immutable resident source in any of seven formats, publishing only after complete projection. Exactly one literal content string or base64 data field. source_name is provenance only, never a file to open. ChatGPT attachment keys are logical export filenames, Gemini keys exact pointer strings; other formats use embedded assets. Missing external references stay unresolved; never accesses host files or networks.", input_schema:r#"{"type":"object","properties":{"source":{"type":"string","enum":["agy","chatgpt","claude-code","claude-web","codex","copilot","gemini"],"default":"claude-code"},"source_name":{"type":"string"},"content":{"type":"string"},"data":{"type":"string","contentEncoding":"base64"},"attachments":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"data":{"type":"string","contentEncoding":"base64"}},"required":["name","data"],"additionalProperties":false}}},"required":["source_name"],"additionalProperties":false}"# },
    Tool { name: "archive_list", description: "List selected recent source projection summaries from one frozen Archive view.", input_schema:r#"{"type":"object","properties":{"limit":{"type":"integer","minimum":0,"default":50}},"additionalProperties":false}"# },
    Tool { name: "archive_show", description: "Inspect one exact projection's text, provenance and content-part metadata. Media rows identify resident blobs or unresolved external pointers; this diagnostic does not claim to render media.", input_schema:r#"{"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false}"# },
    Tool { name: "archive_thread", description: "Inspect the full canonical ancestor DAG; exceeding limit is an error so no fork is hidden.", input_schema:r#"{"type":"object","properties":{"id":{"type":"string"},"limit":{"type":"integer","minimum":1,"default":100}},"required":["id"],"additionalProperties":false}"# },
    Tool { name: "archive_search", description: "Search canonical block text with exact portable BM25. The query is literal, including @ prefixes.", input_schema:r#"{"type":"object","properties":{"text":{"type":"string"},"limit":{"type":"integer","minimum":0,"default":50}},"required":["text"],"additionalProperties":false}"# },
    Tool { name: "archive_index", description: "Maintain exact accelerated-Succinct and portable BM25 derived indexes without authoring new source events.", input_schema:r#"{"type":"object","properties":{},"additionalProperties":false}"# },
    Tool { name: "archive_replay_start", description: "Start or reset this explicit persona's exact Archive replay cursor at the supplied Gregorian TAI timestamp.", input_schema:r#"{"type":"object","properties":{"persona":{"type":"string"},"from":{"type":"string"}},"required":["persona","from"],"additionalProperties":false}"# },
    Tool { name: "archive_replay_stop", description: "Stop this explicit persona's Archive replay cursor.", input_schema:r#"{"type":"object","properties":{"persona":{"type":"string"}},"required":["persona"],"additionalProperties":false}"# },
    Tool { name: "archive_replay", description: "Deliver the next canonical block batch then advance its exact block cursor only after output acceptance. Equal timestamps may split safely. Media stays diagnostic metadata, not synthesized content.", input_schema:r#"{"type":"object","properties":{"persona":{"type":"string"},"limit":{"type":"integer","minimum":1,"default":20},"with_tools":{"type":"boolean","default":false}},"required":["persona"],"additionalProperties":false}"# },
];
fn fifty() -> usize {
    50
}
fn hundred() -> usize {
    100
}
fn twenty() -> usize {
    20
}
#[derive(Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
enum Source {
    Agy,
    #[serde(rename = "chatgpt")]
    ChatGpt,
    #[default]
    ClaudeCode,
    ClaudeWeb,
    Codex,
    Copilot,
    Gemini,
}
impl From<Source> for ImportSource {
    fn from(source: Source) -> Self {
        match source {
            Source::Agy => Self::Agy,
            Source::ChatGpt => Self::ChatGpt,
            Source::ClaudeCode => Self::ClaudeCode,
            Source::ClaudeWeb => Self::ClaudeWeb,
            Source::Codex => Self::Codex,
            Source::Copilot => Self::Copilot,
            Source::Gemini => Self::Gemini,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Attachment {
    name: String,
    data: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Import {
    #[serde(default)]
    source: Source,
    source_name: String,
    content: Option<String>,
    data: Option<String>,
    #[serde(default, deserialize_with = "crate::mcp::object::vec")]
    attachments: Vec<Attachment>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Limit {
    #[serde(default = "fifty")]
    limit: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Id {
    id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Thread {
    id: String,
    #[serde(default = "hundred")]
    limit: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Search {
    text: String,
    #[serde(default = "fifty")]
    limit: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    persona: String,
    from: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Persona {
    persona: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Replay {
    persona: String,
    #[serde(default = "twenty")]
    limit: usize,
    #[serde(default)]
    with_tools: bool,
}
fn decode_base64(data: &str) -> Result<Bytes> {
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .map(Bytes::from)
        .map_err(invalid_arguments)
}
fn valid_persona(persona: &str) -> Result<()> {
    if persona.trim().is_empty() {
        return Err(invalid_arguments("persona must be nonempty"));
    }
    Ok(())
}
impl Faculty for Archive {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        match name {
            "archive_import" => {
                let a: Import = decode_arguments(arguments)?;
                if a.source_name.trim().is_empty() || a.source_name.contains('\0') {
                    return Err(invalid_arguments(
                        "source_name must be nonempty and contain no NUL",
                    ));
                }
                let bytes = match (a.content, a.data) {
                    (Some(content), None) => Bytes::from(content),
                    (None, Some(data)) => decode_base64(&data)?,
                    _ => {
                        return Err(invalid_arguments(
                            "provide exactly one content or data field",
                        ))
                    }
                };
                let source: ImportSource = a.source.into();
                if !a.attachments.is_empty()
                    && !matches!(source, ImportSource::ChatGpt | ImportSource::Gemini)
                {
                    return Err(invalid_arguments("attachment maps are supported for ChatGPT and Gemini; other formats use embedded assets"));
                }
                let mut attachments = BTreeMap::new();
                for a in a.attachments {
                    if a.name.is_empty() || a.name.contains('\0') {
                        return Err(invalid_arguments(
                            "attachment name must be nonempty and contain no NUL",
                        ));
                    }
                    if attachments
                        .insert(a.name, decode_base64(&a.data)?)
                        .is_some()
                    {
                        return Err(invalid_arguments("duplicate attachment name"));
                    }
                }
                self.operations
                    .import(source, &a.source_name, bytes, &attachments)?
                    .write(out)
            }
            "archive_list" => {
                let a: Limit = decode_arguments(arguments)?;
                self.operations.list(a.limit, out)
            }
            "archive_show" => {
                let a: Id = decode_arguments(arguments)?;
                self.operations.show(&a.id, out)
            }
            "archive_thread" => {
                let a: Thread = decode_arguments(arguments)?;
                if a.limit == 0 {
                    return Err(invalid_arguments("thread limit must be at least 1"));
                }
                self.operations.thread(&a.id, a.limit, out)
            }
            "archive_search" => {
                let a: Search = decode_arguments(arguments)?;
                self.operations.search(&a.text, a.limit, out)
            }
            "archive_index" => {
                let _: Empty = decode_arguments(arguments)?;
                self.operations.index(out)
            }
            "archive_replay_start" => {
                let a: Start = decode_arguments(arguments)?;
                valid_persona(&a.persona)?;
                let from = parse_tai_timestamp(&a.from).map_err(invalid_arguments)?;
                self.operations.replay_start(&a.persona, from)?;
                out.line(format!(
                    "replay started at {} (persona {})",
                    a.from, a.persona
                ))
            }
            "archive_replay_stop" => {
                let a: Persona = decode_arguments(arguments)?;
                valid_persona(&a.persona)?;
                self.operations.replay_stop(&a.persona)?;
                out.line(format!("replay stopped (persona {})", a.persona))
            }
            "archive_replay" => {
                let a: Replay = decode_arguments(arguments)?;
                valid_persona(&a.persona)?;
                if a.limit == 0 {
                    return Err(invalid_arguments("replay limit must be at least 1"));
                }
                self.operations
                    .replay(&a.persona, a.limit, a.with_tools, out)
            }
            _ => bail!("unknown Archive MCP tool {name:?}"),
        }
    }
}
