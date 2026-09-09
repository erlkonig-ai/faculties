//! Finite explicit Orient tools; no watcher, wall-clock wait or ambient persona.
use super::{ShowOptions, WakeOptions};
use crate::mcp::{decode_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::PathBuf;

pub struct Orient {
    operations: super::Orient,
}
impl Orient {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self {
            operations: super::Orient::new(pile, key),
        }
    }
}

const TOOLS: &[Tool] = &[
    Tool { name: "orient_show", description: "Observe resident local swarm health first, then messages, mail, goals, window status and current Habit labels from frozen source collections. Health performs no network probes and does not prove blob availability. No memory or Wiki. Habit conditions are passive by default; evaluate_habits=true explicitly executes stored local conditions/scripts. Records exact shown attention events only after output acceptance, when persona is supplied.", input_schema: r#"{"type":"object","properties":{"persona":{"type":"string"},"message_limit":{"type":"integer","minimum":0,"default":10},"doing_limit":{"type":"integer","minimum":0,"default":5},"todo_limit":{"type":"integer","minimum":0,"default":5},"evaluate_habits":{"type":"boolean","default":false}},"additionalProperties":false}"# },
    Tool { name: "orient_wake", description: "Assemble the unchanged charged memory cover, cover-tagged Wiki beliefs and goals. No Habit evaluation. A supplied persona records exact shown attention events after output acceptance.", input_schema: r#"{"type":"object","properties":{"persona":{"type":"string"},"chars":{"type":"integer","minimum":0,"default":800000},"doing_limit":{"type":"integer","minimum":0,"default":5},"todo_limit":{"type":"integer","minimum":0,"default":5}},"additionalProperties":false}"# },
    Tool { name: "orient_poll", description: "One finite directed-news observation for an explicit persona. Local health alerts, recoveries and expired reports take priority over ordinary payload acquisition; healthy heartbeats are quiet. Defaults to non-consuming peek=true. peek=false records exact reported event IDs after output acceptance; unavailable selected payloads remain pending. No health network probes, Habit scripts or server wait.", input_schema: r#"{"type":"object","properties":{"persona":{"type":"string"},"peek":{"type":"boolean","default":true}},"required":["persona"],"additionalProperties":false}"# },
    Tool { name: "orient_baseline", description: "Explicitly discard the current attention backlog for this persona by recording exactly all currently visible events as presented, without displaying their content. Does not mark source messages read.", input_schema: r#"{"type":"object","properties":{"persona":{"type":"string"}},"required":["persona"],"additionalProperties":false}"# },
];
fn ten() -> usize {
    10
}
fn five() -> usize {
    5
}
fn chars() -> usize {
    800_000
}
fn yes() -> bool {
    true
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Show {
    persona: Option<String>,
    #[serde(default = "ten")]
    message_limit: usize,
    #[serde(default = "five")]
    doing_limit: usize,
    #[serde(default = "five")]
    todo_limit: usize,
    #[serde(default)]
    evaluate_habits: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wake {
    persona: Option<String>,
    #[serde(default = "chars")]
    chars: usize,
    #[serde(default = "five")]
    doing_limit: usize,
    #[serde(default = "five")]
    todo_limit: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Poll {
    persona: String,
    #[serde(default = "yes")]
    peek: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Persona {
    persona: String,
}
impl Faculty for Orient {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        match name {
            "orient_show" => {
                let a: Show = decode_arguments(arguments)?;
                self.operations.show(
                    a.persona.as_deref(),
                    &ShowOptions {
                        message_limit: a.message_limit,
                        doing_limit: a.doing_limit,
                        todo_limit: a.todo_limit,
                        evaluate_habits: a.evaluate_habits,
                    },
                    out,
                )
            }
            "orient_wake" => {
                let a: Wake = decode_arguments(arguments)?;
                self.operations.wake(
                    a.persona.as_deref(),
                    &WakeOptions {
                        chars: a.chars,
                        doing_limit: a.doing_limit,
                        todo_limit: a.todo_limit,
                    },
                    out,
                )
            }
            "orient_poll" => {
                let a: Poll = decode_arguments(arguments)?;
                self.operations.poll(&a.persona, a.peek, out)
            }
            "orient_baseline" => {
                let a: Persona = decode_arguments(arguments)?;
                let receipt = self.operations.baseline(&a.persona)?;
                out.line(format!(
                    "Baselined {} current attention event(s) for {}.",
                    receipt.events, a.persona
                ))
            }
            _ => bail!("unknown Orient MCP tool {name:?}"),
        }
    }
}
