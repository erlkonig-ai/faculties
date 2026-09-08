//! Images are perceptions, not server filesystem paths. Generation and optional
//! memory publication are distinct steps; delivery errors never restart either.
use super::{operations::remember_range, Imagine as Operations, ModelSources, Options, Variant};
use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

const TOOLS: &[Tool] = &[Tool {
    name: "imagine_generate",
    description: "Generate a resident PNG with the launcher's local FLUX model and return an image attachment. Requires the imagine build feature and installed weights; discovery loads neither. Dimensions are multiples of 16, up to 4096; steps 1–200. Optional remember stores the original PNG as a Memory after output acceptance; it is a TAI timestamp (a 3-second moment ending then) or from..to range. No file paths, downloads, or playback are requested.",
    input_schema: r#"{"type":"object","properties":{"prompt":{"type":"string","minLength":1},"variant":{"type":"string","enum":["klein","dev"],"default":"klein"},"steps":{"type":"integer","minimum":1,"maximum":200},"seed":{"type":"integer","minimum":0,"default":0},"width":{"type":"integer","minimum":16,"maximum":4096,"multipleOf":16,"default":1024},"height":{"type":"integer","minimum":16,"maximum":4096,"multipleOf":16,"default":1024},"guidance":{"type":"number","minimum":0,"default":4},"remember":{"type":"string"}},"required":["prompt"],"additionalProperties":false}"#,
}];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Generate {
    prompt: String,
    #[serde(default)]
    variant: Variant,
    steps: Option<usize>,
    #[serde(default)]
    seed: u64,
    #[serde(default = "dimension")]
    width: usize,
    #[serde(default = "dimension")]
    height: usize,
    #[serde(default = "guidance")]
    guidance: f32,
    remember: Option<String>,
}
fn dimension() -> usize {
    1024
}
fn guidance() -> f32 {
    4.0
}
pub struct Imagine {
    operations: Operations,
    memory: crate::memory::Memory,
}
impl Imagine {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_sources(pile, key, ModelSources::from_environment())
    }
    pub fn with_sources(pile: PathBuf, key: Option<PathBuf>, sources: ModelSources) -> Self {
        Self {
            operations: Operations::new(sources),
            memory: crate::memory::Memory::new(pile, key),
        }
    }
}
impl Faculty for Imagine {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        if name != "imagine_generate" {
            bail!("Imagine MCP has no tool {name:?}");
        }
        let args: Generate = decode_arguments(arguments)?;
        let options = Options {
            prompt: args.prompt,
            variant: args.variant,
            steps: args.steps,
            seed: args.seed,
            width: args.width,
            height: args.height,
            guidance: args.guidance,
        };
        options.validate().map_err(invalid_arguments)?;
        let range = args
            .remember
            .as_deref()
            .map(remember_range)
            .transpose()
            .map_err(invalid_arguments)?;
        let generated = self.operations.generate(&options)?;
        out.image(generated.png.clone(), "image/png")?;
        out.line(generated.diagnostic())?;
        if let Some(range) = range {
            let remembered = self
                .memory
                .image(generated.png.as_ref(), range)
                .context("image generated, but remembering it failed; generation is not retried")?;
            remembered.emit(out)?;
        }
        Ok(())
    }
}
