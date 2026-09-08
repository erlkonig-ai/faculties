use anybytes::Bytes;
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Variant {
    #[default]
    Klein,
    Dev,
}
impl Variant {
    pub fn default_steps(self) -> usize {
        match self {
            Self::Klein => 8,
            Self::Dev => 28,
        }
    }
    fn repo(self) -> &'static str {
        match self {
            Self::Klein => "models--black-forest-labs--FLUX.2-klein-4B",
            Self::Dev => "models--black-forest-labs--FLUX.2-dev",
        }
    }
    fn pile_name(self) -> &'static str {
        match self {
            Self::Klein => "flux_klein.pile",
            Self::Dev => "flux_dev.pile",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Options {
    pub prompt: String,
    pub variant: Variant,
    pub steps: Option<usize>,
    pub seed: u64,
    pub width: usize,
    pub height: usize,
    pub guidance: f32,
}
impl Options {
    /// Reject malformed or accidentally enormous jobs before loading weights.
    /// These are request limits, not a guarantee that a device has enough RAM.
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.prompt.trim().is_empty(), "prompt must not be empty");
        for (label, dimension) in [("width", self.width), ("height", self.height)] {
            ensure!(
                (16..=4096).contains(&dimension) && dimension % 16 == 0,
                "{label} must be a multiple of 16 between 16 and 4096"
            );
        }
        ensure!(
            (1..=200).contains(&self.steps.unwrap_or(self.variant.default_steps())),
            "steps must be between 1 and 200"
        );
        ensure!(
            self.guidance.is_finite() && self.guidance >= 0.0,
            "guidance must be finite and nonnegative"
        );
        Ok(())
    }
}

/// Trusted configuration, captured once by a frontend, not an MCP argument.
#[derive(Clone, Debug)]
pub struct ModelSources {
    pub hub: Option<PathBuf>,
    pub weights_root: PathBuf,
    pub weights_override: Option<PathBuf>,
}
impl ModelSources {
    /// Reads configuration only: no directory scan, model load, or GPU init.
    pub fn from_environment() -> Self {
        Self {
            hub: std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join(".cache/huggingface/hub")),
            weights_root: crate::model_dir(),
            weights_override: std::env::var_os("FLUX_PILE").map(PathBuf::from),
        }
    }
    pub fn weights(&self, variant: Variant) -> PathBuf {
        self.weights_override
            .clone()
            .unwrap_or_else(|| self.weights_root.join(variant.pile_name()))
    }
    pub fn model_directory(&self, variant: Variant) -> Result<PathBuf> {
        let snapshots = self
            .hub
            .as_ref()
            .context("HOME/Hugging Face hub is not configured")?
            .join(variant.repo())
            .join("snapshots");
        // Stable selection when several cached snapshots are present. This is
        // only configuration/tokenizer selection, never arbitrary weight files.
        let mut candidates = std::fs::read_dir(&snapshots)
            .with_context(|| format!("read model snapshots at {}", snapshots.display()))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        candidates.sort();
        candidates
            .into_iter()
            .find(|path| path.join("transformer/config.json").is_file())
            .with_context(|| {
                format!(
                    "no snapshot with transformer/config.json under {}",
                    snapshots.display()
                )
            })
    }
}

#[derive(Clone, Debug)]
pub struct GeneratedImage {
    pub png: Bytes,
    pub width: u32,
    pub height: u32,
    pub elapsed: std::time::Duration,
    pub luminance_mean: f64,
    pub luminance_stddev: f64,
}
impl GeneratedImage {
    pub fn from_rgb(image: image::RgbImage, elapsed: std::time::Duration) -> Result<Self> {
        ensure!(
            image.width() > 0 && image.height() > 0,
            "generated image is empty"
        );
        let (mut sum, mut squared) = (0.0_f64, 0.0_f64);
        for pixel in image.pixels() {
            let luminance = 0.299 * f64::from(pixel[0])
                + 0.587 * f64::from(pixel[1])
                + 0.114 * f64::from(pixel[2]);
            sum += luminance;
            squared += luminance * luminance;
        }
        let count = f64::from(image.width()) * f64::from(image.height());
        let mean = sum / count;
        let mut encoded = std::io::Cursor::new(Vec::new());
        image
            .write_to(&mut encoded, image::ImageFormat::Png)
            .context("encode generated PNG")?;
        Ok(Self {
            png: encoded.into_inner().into(),
            width: image.width(),
            height: image.height(),
            elapsed,
            luminance_mean: mean,
            luminance_stddev: (squared / count - mean * mean).max(0.0).sqrt(),
        })
    }
    pub fn diagnostic(&self) -> String {
        let mut text = format!(
            "{}x{} luminance mean={:.1} std={:.2} ({:.1}s)",
            self.width,
            self.height,
            self.luminance_mean,
            self.luminance_stddev,
            self.elapsed.as_secs_f64()
        );
        if self.luminance_stddev < 1.0 {
            text.push_str("\nWARNING: image is nearly flat; check steps, seed, and model.");
        }
        text
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        std::fs::write(path, self.png.as_ref())
            .with_context(|| format!("write PNG to {}", path.display()))
    }
}

#[derive(Clone, Debug)]
pub struct Imagine {
    pub sources: ModelSources,
}
impl Imagine {
    pub fn new(sources: ModelSources) -> Self {
        Self { sources }
    }

    pub fn generate(&self, options: &Options) -> Result<GeneratedImage> {
        options.validate()?;
        #[cfg(not(feature = "imagine"))]
        anyhow::bail!("image generation requires a build with the `imagine` feature");
        #[cfg(feature = "imagine")]
        {
            use mary::models::flux::pipeline::{Flux2Pipeline, FluxWeights, ModelVariant};
            let variant = match options.variant {
                Variant::Klein => ModelVariant::Klein,
                Variant::Dev => ModelVariant::Dev,
            };
            let directory = self.sources.model_directory(options.variant)?;
            ensure!(
                ModelVariant::detect(&directory)? == variant,
                "FLUX configuration does not match requested variant"
            );
            super::configuration::preflight(&directory, options.variant)?;
            let pile = self.sources.weights(options.variant);
            let snapshot = mary::model_collection::load_model_collection_local_latest(&pile)
                .with_context(|| format!("freeze FLUX model collection at {}", pile.display()))?;
            let weights = FluxWeights::from_snapshot(snapshot, variant)
                .context("select native FLUX components")?;
            let started = std::time::Instant::now();
            let image = Flux2Pipeline::generate_f16(
                &options.prompt,
                options.height,
                options.width,
                options.steps.unwrap_or(options.variant.default_steps()),
                options.guidance,
                options.seed,
                &directory,
                &weights,
                None,
                &mary::nn::backend::WgpuDevice::default(),
            );
            GeneratedImage::from_rgb(image, started.elapsed())
        }
    }
}

pub(super) fn remember_range(raw: &str) -> Result<(hifitime::Epoch, hifitime::Epoch)> {
    use crate::memory::operations::{parse_tai_timestamp, parse_time_range};
    let range = if raw.contains("..") {
        parse_time_range(raw)?
    } else {
        let end = parse_tai_timestamp(raw)?;
        (
            end - hifitime::Duration::from_seconds(crate::memory::MOMENT_SECONDS),
            end,
        )
    };
    ensure!(
        range.1 > range.0,
        "a remembered image needs a nonzero time range"
    );
    Ok(range)
}
