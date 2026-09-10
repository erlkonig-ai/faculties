//! Standing intentions with resident inputs and explicit predicate evaluation.

use super::{render, DeclaredState, Habits as Operations};
use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use base64::Engine as _;
use serde::Deserialize;
use std::path::PathBuf;

const EMPTY: &str = r#"{"type":"object","properties":{},"additionalProperties":false}"#;
const SELECTOR: &str = r#"{"type":"object","properties":{"habit":{"type":"string"}},"required":["habit"],"additionalProperties":false}"#;
const TOOLS: &[Tool] = &[
    Tool { name: "habit_add", description: "Store an immutable standing intention from literal text and an optional base64 carried script. This does not execute the predicate or script. A label is not unique; replacements require explicit supersedes IDs.", input_schema: r#"{"type":"object","properties":{"label":{"type":"string"},"when":{"type":"string"},"nudge":{"type":"string"},"script_base64":{"type":"string"},"supersedes":{"type":"array","items":{"type":"string"},"default":[]}},"required":["label","when","nudge"],"additionalProperties":false}"# },
    Tool { name: "habit_list", description: "Inspect current definitions and activation without evaluating stored predicates by default. Explicit evaluate_conditions=true executes stored shell predicates on the server, as the CLI list command does.", input_schema: r#"{"type":"object","properties":{"evaluate_conditions":{"type":"boolean","default":false}},"additionalProperties":false}"# },
    Tool { name: "habit_show", description: "Inspect an exact definition or unambiguous label, including historical superseded definitions. Does not evaluate predicates.", input_schema: SELECTOR },
    Tool { name: "habit_due", description: "Explicitly evaluate stored standing-intention predicates on the server and return those due. Predicates can execute carried scripts or shell commands; failed evaluations are reported, not silently treated as not due.", input_schema: EMPTY },
    Tool { name: "habit_done", description: "Publish a completion occurrence for one live intention by label or ID.", input_schema: SELECTOR },
    Tool { name: "habit_pause", description: "Publish paused activation, reconciling all observed state heads without changing the definition.", input_schema: SELECTOR },
    Tool { name: "habit_resume", description: "Publish active activation, reconciling all observed state heads without changing the definition.", input_schema: SELECTOR },
    Tool { name: "habit_check", description: "Explicitly validate the complete Habit collection and its resident attachments, without executing carried predicates.", input_schema: EMPTY },
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Add {
    label: String,
    when: String,
    nudge: String,
    script_base64: Option<String>,
    #[serde(default)]
    supersedes: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    #[serde(default)]
    evaluate_conditions: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selector {
    habit: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

pub struct Habits {
    operations: Operations,
}
impl Habits {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }
    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self {
            operations: Operations::with_storage(storage),
        }
    }
}
impl Faculty for Habits {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        match name {
            "habit_add" => {
                let args: Add = decode_arguments(arguments)?;
                let script = args
                    .script_base64
                    .as_deref()
                    .map(|value| {
                        base64::engine::general_purpose::STANDARD
                            .decode(value)
                            .map_err(|error| {
                                invalid_arguments(format!("invalid script_base64: {error}"))
                            })
                    })
                    .transpose()?;
                render::added(
                    &self.operations.add(
                        &args.label,
                        &args.when,
                        &args.nudge,
                        script.as_deref(),
                        &args.supersedes,
                    )?,
                    out,
                )
            }
            "habit_list" | "habit_due" => {
                let due = name == "habit_due";
                let evaluate = if due {
                    let _: Empty = decode_arguments(arguments)?;
                    true
                } else {
                    let args: List = decode_arguments(arguments)?;
                    args.evaluate_conditions
                };
                let listing = render::listed(&self.operations.list(evaluate)?, due);
                out.text(listing.text)?;
                for diagnostic in &listing.diagnostics {
                    out.line(diagnostic)?;
                }
                if !listing.diagnostics.is_empty() {
                    bail!(
                        "{} standing intention(s) could not be evaluated",
                        listing.diagnostics.len()
                    );
                }
                Ok(())
            }
            "habit_show" | "habit_done" | "habit_pause" | "habit_resume" => {
                let args: Selector = decode_arguments(arguments)?;
                match name {
                    "habit_show" => render::shown(&self.operations.show(&args.habit)?, out),
                    "habit_done" => render::completed(&self.operations.done(&args.habit)?, out),
                    _ => render::state_changed(
                        &self.operations.set_state(
                            &args.habit,
                            if name == "habit_pause" {
                                DeclaredState::Paused
                            } else {
                                DeclaredState::Active
                            },
                        )?,
                        out,
                    ),
                }
            }
            "habit_check" => {
                let _: Empty = decode_arguments(arguments)?;
                out.line(self.operations.check()?)
            }
            _ => bail!("Habit MCP has no tool {name:?}"),
        }
    }
}
