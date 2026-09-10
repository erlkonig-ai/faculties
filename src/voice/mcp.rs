//! Explicit MCP UX: a speech clip is an audio attachment, never an instruction
//! to play the server's speakers. Routing metadata is a separate operation.
use super::synthesis::{ModelSources, Synthesizer};
use super::{Channel, Voice as Operations};
use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::PathBuf;

const TOOLS: &[Tool] = &[
    Tool { name: "voice_synthesize", description: "Synthesize literal text with the launcher's local Qwen3-TTS model and return a WAV audio attachment. Never enumerates or plays local audio devices, changes the floor, or records a spoken utterance: this is generation, not proof anyone heard it. Requires the voice build feature and configured model/reference assets; discovery opens none.", input_schema: r#"{"type":"object","properties":{"text":{"type":"string","minLength":1}},"required":["text"],"additionalProperties":false}"# },
    Tool { name: "voice_route", description: "Read the latest stored private say and public shout routing policies (or built-in defaults). Metadata only: no device enumeration, Reachy probe, synthesis, or playback. Private say routing still rejects public devices even if its policy lists them.", input_schema: r#"{"type":"object","properties":{},"additionalProperties":false}"# },
    Tool { name: "voice_route_set", description: "Publish an ordered device-name preference list for local say or shout routing. Names are literal case-insensitive match patterns, not files. A new timestamped generation replaces older policy generations; exact timestamp ties are unioned. This changes future host routing only and does not play audio. The say privacy check cannot be configured away.", input_schema: r#"{"type":"object","properties":{"channel":{"type":"string","enum":["say","shout"]},"devices":{"type":"array","minItems":1,"items":{"type":"string","minLength":1}}},"required":["channel","devices"],"additionalProperties":false}"# },
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Text {
    text: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteSet {
    channel: Channel,
    devices: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
pub struct Voice {
    operations: Operations,
    synthesizer: Synthesizer,
}
impl Voice {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }
    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self::with_storage_and_sources(storage, ModelSources::from_environment())
    }
    pub fn with_sources(pile: PathBuf, key: Option<PathBuf>, sources: ModelSources) -> Self {
        Self::with_storage_and_sources(crate::storage::Storage::new(pile, key), sources)
    }
    pub fn with_storage_and_sources(
        storage: crate::storage::Storage,
        sources: ModelSources,
    ) -> Self {
        Self {
            operations: Operations::with_storage(storage),
            synthesizer: Synthesizer::new(sources),
        }
    }
}
impl Faculty for Voice {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        match name {
            "voice_synthesize" => {
                let args: Text = decode_arguments(arguments)?;
                super::operations::validate_text(&args.text).map_err(invalid_arguments)?;
                let clip = self.synthesizer.synthesize(&args.text)?;
                out.audio(clip.wav.clone(), super::AUDIO_WAV_MIME)?;
                out.line(format!(
                    "{} Hz mono, {} samples ({:.2}s); no host playback",
                    clip.sample_rate,
                    clip.sample_count,
                    clip.duration_seconds()
                ))
            }
            "voice_route" => {
                let _: Empty = decode_arguments(arguments)?;
                for policy in self.operations.routes()? {
                    out.line(format!(
                        "{} policy (priority order): {}",
                        policy.channel.name(),
                        policy.devices.join(" → ")
                    ))?;
                }
                Ok(())
            }
            "voice_route_set" => {
                let args: RouteSet = decode_arguments(arguments)?;
                super::operations::validate_devices(&args.devices).map_err(invalid_arguments)?;
                self.operations
                    .set_route(args.channel, &args.devices)?
                    .emit(out)
            }
            _ => bail!("Voice MCP has no tool {name:?}"),
        }
    }
}
