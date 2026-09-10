//! Explicit finite Decide tools; all prose is literal and attribution comes
//! from the configured collection signer, never an ambient persona argument.
use super::{presentation, Decide as Operations, FactorSide, ListOptions};
use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::PathBuf;
use triblespace::prelude::Id;

pub struct Decide {
    operations: Operations,
}
impl Decide {
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
        name: "decide_propose",
        description: "Propose a stable decision with literal title/context and optional exact about ID. No @file/stdin expansion.",
        input_schema: r#"{"type":"object","properties":{"title":{"type":"string","minLength":1},"context":{"type":"string","minLength":1},"about":{"type":"string"}},"required":["title"],"additionalProperties":false}"#,
    },
    Tool {
        name: "decide_factor",
        description: "Add one independent pro or con factor while the decision is unresolved. Text is literal; ID or unambiguous prefix selects the decision.",
        input_schema: r#"{"type":"object","properties":{"decision":{"type":"string","minLength":1},"text":{"type":"string","minLength":1},"side":{"type":"string","enum":["pro","con"]}},"required":["decision","text","side"],"additionalProperties":false}"#,
    },
    Tool {
        name: "decide_resolve",
        description: "Resolve only an open decision. Requires at least one pro and one con unless force is explicitly true. The optional machine-readable result tag name/exact ID is separate from free outcome prose.",
        input_schema: r#"{"type":"object","properties":{"decision":{"type":"string","minLength":1},"outcome":{"type":"string","minLength":1},"result":{"type":"string","description":"Known tag name (benign) or exact 32-character ID; omitted means no machine-readable result."},"force":{"type":"boolean","default":false}},"required":["decision","outcome"],"additionalProperties":false}"#,
    },
    Tool {
        name: "decide_reconcile",
        description: "Reconcile only a genuinely divergent resolution fork, citing every current head in one new resolution. Agreement is already resolved and is not a fork. Outcome prose, machine-readable result, and explicit force stay distinct.",
        input_schema: r#"{"type":"object","properties":{"decision":{"type":"string","minLength":1},"outcome":{"type":"string","minLength":1},"result":{"type":"string"},"force":{"type":"boolean","default":false}},"required":["decision","outcome"],"additionalProperties":false}"#,
    },
    Tool {
        name: "decide_list",
        description: "List unresolved and diagnostically unsettled decisions. all includes closed/agreeing states; forced selects only semantically resolved explicitly forced states.",
        input_schema: r#"{"type":"object","properties":{"all":{"type":"boolean","default":false},"forced":{"type":"boolean","default":false}},"additionalProperties":false}"#,
    },
    Tool {
        name: "decide_show",
        description: "Show a decision, its factors, and every live resolution head without selecting a winner from a divergent fork.",
        input_schema: r#"{"type":"object","properties":{"decision":{"type":"string","minLength":1}},"required":["decision"],"additionalProperties":false}"#,
    },
    Tool {
        name: "decide_resolve_id",
        description: "Resolve a decision ID or unambiguous hexadecimal prefix.",
        input_schema: r#"{"type":"object","properties":{"prefix":{"type":"string","minLength":1}},"required":["prefix"],"additionalProperties":false}"#,
    },
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Propose {
    title: String,
    context: Option<String>,
    about: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Side {
    Pro,
    Con,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Factor {
    decision: String,
    text: String,
    side: Side,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Resolve {
    decision: String,
    outcome: String,
    result: Option<String>,
    #[serde(default)]
    force: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    #[serde(default)]
    all: bool,
    #[serde(default)]
    forced: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Show {
    decision: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prefix {
    prefix: String,
}
fn selector(value: &str) -> Result<()> {
    let value = value.trim();
    if value.is_empty() || value.len() > 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_arguments(
            "decision selector must be a nonempty hexadecimal ID or prefix, at most 32 characters",
        ));
    }
    Ok(())
}
impl Faculty for Decide {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        match name {
            "decide_propose" => {
                let args: Propose = decode_arguments(arguments)?;
                super::validate_prose(&args.title, "decision title").map_err(invalid_arguments)?;
                if let Some(context) = &args.context {
                    super::validate_prose(context, "decision context")
                        .map_err(invalid_arguments)?;
                }
                let about = args
                    .about
                    .as_deref()
                    .map(|raw| {
                        Id::from_hex(raw.trim())
                            .ok_or_else(|| invalid_arguments(format!("invalid about ID '{raw}'")))
                    })
                    .transpose()?;
                presentation::proposed(
                    &self
                        .operations
                        .propose(&args.title, args.context.as_deref(), about)?,
                    out,
                )
            }
            "decide_factor" => {
                let args: Factor = decode_arguments(arguments)?;
                selector(&args.decision)?;
                super::validate_prose(&args.text, "factor text").map_err(invalid_arguments)?;
                let side = match args.side {
                    Side::Pro => FactorSide::Pro,
                    Side::Con => FactorSide::Con,
                };
                presentation::factor(
                    &self.operations.factor(&args.decision, &args.text, side)?,
                    out,
                )
            }
            "decide_resolve" | "decide_reconcile" => {
                let args: Resolve = decode_arguments(arguments)?;
                selector(&args.decision)?;
                super::validate_prose(&args.outcome, "resolution outcome")
                    .map_err(invalid_arguments)?;
                let result = args
                    .result
                    .as_deref()
                    .map(super::result_id)
                    .transpose()
                    .map_err(invalid_arguments)?;
                let reconcile = name == "decide_reconcile";
                let receipt = if reconcile {
                    self.operations
                        .reconcile(&args.decision, &args.outcome, result, args.force)?
                } else {
                    self.operations
                        .resolve(&args.decision, &args.outcome, result, args.force)?
                };
                presentation::resolved(&receipt, reconcile, out)
            }
            "decide_list" => {
                let args: List = decode_arguments(arguments)?;
                presentation::list(
                    &self.operations.list(ListOptions {
                        all: args.all,
                        forced: args.forced,
                    })?,
                    out,
                )
            }
            "decide_show" => {
                let args: Show = decode_arguments(arguments)?;
                selector(&args.decision)?;
                presentation::show(&self.operations.show(&args.decision)?, out)
            }
            "decide_resolve_id" => {
                let args: Prefix = decode_arguments(arguments)?;
                selector(&args.prefix)?;
                out.line(format!("{:x}", self.operations.resolve_id(&args.prefix)?))
            }
            _ => bail!("unknown Decide tool '{name}'"),
        }
    }
}
