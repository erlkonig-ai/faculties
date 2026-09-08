//! Finite controls for a launcher-selected Duplex session. No tool chooses a
//! host path, subscribes to Soma, opens a device, loads weights, or starts a loop.
use super::{presentation, ReadOptions, Session};
use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

pub struct Duplex {
    session: Option<Session>,
}
impl Duplex {
    /// None still supports side-effect-free discovery. Calls refuse until the
    /// launcher configures a session; there is no implicit /tmp session fallback.
    pub fn new(session: Option<PathBuf>) -> Self {
        Self {
            session: session.map(Session::new),
        }
    }
    fn session(&self) -> Result<&Session> {
        self.session.as_ref().context("Duplex session is not configured; the local launcher must set --duplex-session or DUPLEX_SESSION")
    }
}
const TOOLS: &[Tool] = &[
    Tool {
        name:"duplex_read",
        description:"Read attributed transcript entries after the shared cursor (or all). Unless peek, publish a deadline-bound one-sided floor hold before reading; the running loop polls this request, so it is not an audio-drain barrier. Read never advances the cursor, never pauses incoming speech, and reports far-end presence/duration, not a fictional transcription. Only the launcher-configured session is used.",
        input_schema:r#"{"type":"object","properties":{"peek":{"type":"boolean","default":false},"all":{"type":"boolean","default":false},"hold_secs":{"type":"integer","minimum":0,"default":180}},"additionalProperties":false}"#,
    },
    Tool {
        name:"duplex_say",
        description:"Queue literal text for the configured running speech channel, then advance the shared cursor to the transcript's current tail and release the floor unless keep_floor. @file and @- are words, never files/stdin. A queue receipt is not proof a loop is running or that audio played. Queue/cursor/floor are separate publications: do not blindly retry an error after queueing.",
        input_schema:r#"{"type":"object","properties":{"text":{"type":"string","minLength":1},"keep_floor":{"type":"boolean","default":false}},"required":["text"],"additionalProperties":false}"#,
    },
    Tool {
        name:"duplex_release",
        description:"Release the configured session's floor and advance the shared cursor to the current transcript tail unless keep_cursor. This does not start a loop or touch a device.",
        input_schema:r#"{"type":"object","properties":{"keep_cursor":{"type":"boolean","default":false}},"additionalProperties":false}"#,
    },
    Tool {
        name:"duplex_status",
        description:"Observe transcript/cursor, floor deadline and queued-line count for the configured session. Expired holds are cleared. This is control-file state, not a process heartbeat or delivery confirmation; no model or device is inspected.",
        input_schema:r#"{"type":"object","properties":{},"additionalProperties":false}"#,
    },
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Read {
    #[serde(default)]
    peek: bool,
    #[serde(default)]
    all: bool,
    #[serde(default = "hold_secs")]
    hold_secs: u64,
}
fn hold_secs() -> u64 {
    ReadOptions::default().hold_secs
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Say {
    text: String,
    #[serde(default)]
    keep_floor: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Release {
    #[serde(default)]
    keep_cursor: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
impl Faculty for Duplex {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        match name {
            "duplex_read" => {
                let args: Read = decode_arguments(arguments)?;
                presentation::read(
                    &self.session()?.read(ReadOptions {
                        peek: args.peek,
                        all: args.all,
                        hold_secs: args.hold_secs,
                    })?,
                    out,
                )
            }
            "duplex_say" => {
                let args: Say = decode_arguments(arguments)?;
                super::validate_text(&args.text).map_err(invalid_arguments)?;
                presentation::say(
                    &self.session()?.say(&args.text, args.keep_floor)?,
                    false,
                    out,
                )
            }
            "duplex_release" => {
                let args: Release = decode_arguments(arguments)?;
                presentation::release(&self.session()?.release(args.keep_cursor)?, out)
            }
            "duplex_status" => {
                let _: Empty = decode_arguments(arguments)?;
                presentation::status(&self.session()?.status()?, None, out)
            }
            _ => bail!("unknown Duplex tool {name:?}"),
        }
    }
}
