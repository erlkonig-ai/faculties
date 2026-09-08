//! Finite native Posture tools. Pile/key configuration is trusted launcher
//! state; caller-supplied names and prose never cause host path/stdin access.
//! Only the two explicit semantic tools may load a local embedding model.
use super::{presentation, DocumentInput, ListOptions, Posture as Operations, TextInput};
use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use base64::Engine as _;
use serde::Deserialize;
use std::path::PathBuf;
use triblespace::prelude::Id;

pub struct Posture {
    operations: Operations,
}
impl Posture {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self {
            operations: Operations::new(pile, key),
        }
    }
}

const TOOLS: &[Tool] = &[
    Tool {
        name: "posture_scan",
        description: "Inspect resident document bytes for deterministic disclosure candidates and record one complete scan, unless dry_run. Names are literal evidence/type hints, not host paths. No model is loaded. Unsupported content and parse failures remain explicit; no clean-bill-of-health claim.",
        input_schema: r#"{"type":"object","properties":{"label":{"type":"string","minLength":1},"documents":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string","minLength":1},"data_base64":{"type":"string"}},"required":["name","data_base64"],"additionalProperties":false}},"dry_run":{"type":"boolean","default":false}},"required":["label","documents"],"additionalProperties":false}"#,
    },
    Tool {
        name: "posture_list",
        description: "List finding groups from a frozen authorized scan/Decide observation, optionally for one exact scan. Benign decisions hide findings unless include_resolved. Finding IDs are included; examples limits payload reads per group.",
        input_schema: r#"{"type":"object","properties":{"scan":{"type":"string"},"examples":{"type":"integer","minimum":0,"default":3},"include_resolved":{"type":"boolean","default":false}},"additionalProperties":false}"#,
    },
    Tool {
        name: "posture_coverage",
        description: "Show exactly what one scan checked, did not check, failed to parse, or omitted. Omit scan to select the unique newest scan; timestamp ties require an explicit ID.",
        input_schema: r#"{"type":"object","properties":{"scan":{"type":"string"}},"additionalProperties":false}"#,
    },
    Tool {
        name: "posture_scans",
        description: "List recorded authorized scans, newest first. Read only; no scanning or model loading.",
        input_schema: r#"{"type":"object","properties":{},"additionalProperties":false}"#,
    },
    Tool {
        name: "posture_vocab_add",
        description: "Add or replace a protected term's rationale in an explicit channel policy snapshot. Term and rationale are literal, with normal term/channel canonicalization. Existing policy forks require reconciliation; no arbitrary winner is selected.",
        input_schema: r#"{"type":"object","properties":{"term":{"type":"string","minLength":1},"channel":{"type":"string","minLength":1},"why":{"type":"string"}},"required":["term","channel"],"additionalProperties":false}"#,
    },
    Tool {
        name: "posture_vocab_list",
        description: "List protected channel vocabulary. Missing and forked policy snapshots stay visible; a fork is a failed operation, never resolved by time.",
        input_schema: r#"{"type":"object","properties":{"channel":{"type":"string","minLength":1}},"additionalProperties":false}"#,
    },
    Tool {
        name: "posture_exemplar",
        description: "Explicit local-model operation: embed literal exemplar prose and publish it into an explicit channel policy. Requires local-embed and may load Nomic. At least 12 words; benign adds contrast. @file and @- are literal text, never host inputs.",
        input_schema: r#"{"type":"object","properties":{"text":{"type":"string"},"channel":{"type":"string","minLength":1},"benign":{"type":"boolean","default":false}},"required":["text","channel"],"additionalProperties":false}"#,
    },
    Tool {
        name: "posture_semantic",
        description: "Explicit local-model operation: score resident UTF-8 document chunks against an explicit frozen channel exemplar policy. Requires local-embed and may load Nomic. Names/text are literal. Documents over 4 MiB are reported unexamined. Similarity is a detection proxy, not a safety verdict or trustworthy ranking.",
        input_schema: r#"{"type":"object","properties":{"documents":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string","minLength":1},"text":{"type":"string"}},"required":["name","text"],"additionalProperties":false}},"channel":{"type":"string","minLength":1},"threshold":{"type":"number","default":0.55}},"required":["documents","channel"],"additionalProperties":false}"#,
    },
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    name: String,
    data_base64: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scan {
    label: String,
    #[serde(deserialize_with = "crate::mcp::object::vec")]
    documents: Vec<Document>,
    #[serde(default)]
    dry_run: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    scan: Option<String>,
    #[serde(default = "examples")]
    examples: usize,
    #[serde(default)]
    include_resolved: bool,
}
fn examples() -> usize {
    3
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Coverage {
    scan: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Add {
    term: String,
    channel: String,
    why: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Vocabulary {
    channel: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Exemplar {
    text: String,
    channel: String,
    #[serde(default)]
    benign: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Text {
    name: String,
    text: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Semantic {
    #[serde(deserialize_with = "crate::mcp::object::vec")]
    documents: Vec<Text>,
    channel: String,
    #[serde(default = "threshold")]
    threshold: f32,
}
fn threshold() -> f32 {
    0.55
}
fn scan_id(raw: Option<&str>) -> Result<Option<Id>> {
    raw.map(|raw| {
        Id::from_hex(raw.trim())
            .ok_or_else(|| invalid_arguments(format!("invalid scan id '{raw}'")))
    })
    .transpose()
}

impl Faculty for Posture {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        match name {
            "posture_scan" => {
                let args: Scan = decode_arguments(arguments)?;
                super::validate_documents(
                    &args.label,
                    args.documents.iter().map(|document| document.name.as_str()),
                )
                .map_err(invalid_arguments)?;
                // Decode the entire resident batch before any scan publication.
                let bytes = args
                    .documents
                    .iter()
                    .map(|document| {
                        base64::engine::general_purpose::STANDARD
                            .decode(&document.data_base64)
                            .map_err(|error| {
                                invalid_arguments(format!(
                                    "document {:?}: invalid base64: {error}",
                                    document.name
                                ))
                            })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let documents = args
                    .documents
                    .iter()
                    .zip(&bytes)
                    .map(|(document, bytes)| DocumentInput {
                        name: &document.name,
                        bytes,
                    })
                    .collect::<Vec<_>>();
                presentation::scan(
                    &self
                        .operations
                        .scan(&args.label, &documents, args.dry_run)?,
                    out,
                )
            }
            "posture_list" => {
                let args: List = decode_arguments(arguments)?;
                presentation::list(
                    &self.operations.list(ListOptions {
                        scan: scan_id(args.scan.as_deref())?,
                        examples: args.examples,
                        include_resolved: args.include_resolved,
                    })?,
                    true,
                    out,
                )
            }
            "posture_coverage" => {
                let args: Coverage = decode_arguments(arguments)?;
                presentation::coverage(
                    self.operations
                        .coverage(scan_id(args.scan.as_deref())?)?
                        .as_ref(),
                    out,
                )
            }
            "posture_scans" => {
                let _: Empty = decode_arguments(arguments)?;
                presentation::scans(&self.operations.scans()?, out)
            }
            "posture_vocab_add" => {
                let args: Add = decode_arguments(arguments)?;
                super::validate_vocab(&args.term, &args.channel).map_err(invalid_arguments)?;
                presentation::policy(
                    &self
                        .operations
                        .vocab_add(&args.term, &args.channel, args.why.as_deref())?,
                    out,
                )
            }
            "posture_vocab_list" => {
                let args: Vocabulary = decode_arguments(arguments)?;
                if let Some(channel) = &args.channel {
                    super::validate_channel(channel).map_err(invalid_arguments)?;
                }
                presentation::vocabulary(&self.operations.vocab_list(args.channel.as_deref())?, out)
            }
            "posture_exemplar" => {
                let args: Exemplar = decode_arguments(arguments)?;
                super::validate_exemplar(&args.text, &args.channel).map_err(invalid_arguments)?;
                presentation::policy(
                    &self
                        .operations
                        .exemplar(&args.text, &args.channel, args.benign)?,
                    out,
                )
            }
            "posture_semantic" => {
                let args: Semantic = decode_arguments(arguments)?;
                super::validate_semantic(
                    args.documents.iter().map(|document| document.name.as_str()),
                    &args.channel,
                    args.threshold,
                )
                .map_err(invalid_arguments)?;
                let documents = args
                    .documents
                    .iter()
                    .map(|document| TextInput {
                        name: &document.name,
                        text: &document.text,
                    })
                    .collect::<Vec<_>>();
                presentation::semantic(
                    &self
                        .operations
                        .semantic(&documents, &args.channel, args.threshold)?,
                    out,
                )
            }
            _ => bail!("unknown Posture tool '{name}'"),
        }
    }
}
