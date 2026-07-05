//! `imagine` — Liora's IMAGINATION faculty: text → image via mary's ported
//! FLUX.2 pipeline (Burn / Metal-GPU). A generated PNG is printed to stdout so a
//! Claude-Code reader can `Read` it; with `--remember <when>` the image is also
//! stored as a wordless `ctx::image` memory at a time-coordinate (shelling out
//! to the `memory` faculty, which nomic-vision-embeds it for recall).
//!
//! Two model variants, auto-detected by mary from the model directory:
//!   --klein  FLUX.2-klein-4B  (Qwen3 encoder, step-distilled, FAST)  [default]
//!   --dev    FLUX.2-dev       (Mistral3 encoder + guidance, QUALITY; ~165G, slow)
//!
//! Build + run (the heavy GPU/Burn deps are gated behind the `imagine` feature):
//!   cargo run --release --features imagine --bin imagine -- \
//!       "a small glass cube on a white table, soft studio light" --klein --steps 8
//!
//! The default (no-feature) build compiles a bail stub so the rest of the
//! faculty suite keeps building light.

use clap::Parser;

/// Generate an image from a text prompt with FLUX.2 (Klein/Dev).
#[derive(Parser, Debug)]
#[command(
    version = faculties::GIT_VERSION,
    name = "imagine",
    about = "Liora's imagination: text → image via mary's FLUX.2 pipeline."
)]
struct Cli {
    /// The text prompt to imagine.
    prompt: String,

    /// Use FLUX.2-klein-4B (fast, step-distilled). This is the default.
    #[arg(long, conflicts_with = "dev")]
    klein: bool,

    /// Use FLUX.2-dev (higher quality, Mistral3 encoder + guidance; large/slow).
    #[arg(long)]
    dev: bool,

    /// Number of denoising steps (klein is distilled — 4..8 is plenty; dev wants ~28).
    #[arg(long)]
    steps: Option<usize>,

    /// RNG seed for the initial noise (default 0).
    #[arg(long, default_value_t = 0)]
    seed: u64,

    /// Output image width in pixels (aligned to a multiple of 16).
    #[arg(long, default_value_t = 1024)]
    width: usize,

    /// Output image height in pixels (aligned to a multiple of 16).
    #[arg(long, default_value_t = 1024)]
    height: usize,

    /// Guidance scale (Dev only; ignored by the distilled Klein).
    #[arg(long, default_value_t = 4.0)]
    guidance: f32,

    /// Output PNG path. Default: /tmp/imagine/<timestamp>_<seed>.png
    #[arg(long)]
    out: Option<String>,

    /// After writing the PNG, store it as a wordless image memory at this
    /// time-coordinate (YYYY-MM-DDTHH:MM:SS) by shelling out to `memory image`.
    #[arg(long)]
    remember: Option<String>,
}

#[cfg(not(feature = "imagine"))]
fn main() -> anyhow::Result<()> {
    let _ = Cli::parse();
    anyhow::bail!(
        "imagine was built without the `imagine` feature — rebuild with \
         `cargo build --release --features imagine --bin imagine` (pulls mary's \
         FLUX.2 Burn pipeline)."
    );
}

#[cfg(feature = "imagine")]
fn main() -> anyhow::Result<()> {
    use anyhow::{anyhow, Context};
    use mary::models::flux::pipeline::{Flux2Pipeline, ModelVariant};
    use mary::nn::backend::WgpuDevice;
    use std::path::{Path, PathBuf};
    use std::time::Instant;

    let cli = Cli::parse();

    // Variant: klein is the default; --dev opts into quality.
    let variant = if cli.dev {
        ModelVariant::Dev
    } else {
        ModelVariant::Klein
    };
    let (label, repo) = match variant {
        ModelVariant::Klein => ("Klein", "models--black-forest-labs--FLUX.2-klein-4B"),
        ModelVariant::Dev => ("Dev", "models--black-forest-labs--FLUX.2-dev"),
    };

    // Resolve the model snapshot dir from the HF cache (the snapshot that has a
    // transformer/config.json — same heuristic the mary test bin uses).
    let model_dir = resolve_model_dir(repo)
        .with_context(|| format!("locating the {label} model in the HF cache"))?;
    eprintln!("imagine: {label} model dir → {}", model_dir.display());

    // WEIGHTS come only from the durable flux pile (write one with mary's
    // `flux_persist`); the model dir supplies configs + tokenizer. `FLUX_PILE`
    // overrides the per-variant default.
    let default_pile = match variant {
        ModelVariant::Klein => "/Users/jp/Desktop/chatbot/liora/models/flux_klein.pile",
        ModelVariant::Dev => "/Users/jp/Desktop/chatbot/liora/models/flux_dev.pile",
    };
    let pile = std::env::var("FLUX_PILE").unwrap_or_else(|_| default_pile.to_string());
    anyhow::ensure!(
        Path::new(&pile).exists(),
        "flux weights pile not found at {pile} — write one with mary's flux_persist \
         (or set FLUX_PILE)"
    );
    eprintln!("imagine: weights pile → {pile}");

    // Step default: distilled Klein needs very few; Dev wants ~28.
    let steps = cli.steps.unwrap_or(match variant {
        ModelVariant::Klein => 8,
        ModelVariant::Dev => 28,
    });

    // Output path.
    let out = match &cli.out {
        Some(p) => PathBuf::from(p),
        None => {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            PathBuf::from(format!("/tmp/imagine/{ts}_{}.png", cli.seed))
        }
    };
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("mkdir -p {}", parent.display()))?;
    }

    eprintln!(
        "imagine: prompt={:?} variant={label} steps={steps} seed={} {}x{}",
        cli.prompt, cli.seed, cli.width, cli.height
    );

    let device = WgpuDevice::default();
    let started = Instant::now();

    // generate_f16 handles both variants: Klein runs all-f32 (the distilled
    // 4-step model is precision-sensitive); Dev streams its 60GB transformer
    // block-by-block in f32 with an f16 text encoder so it fits in memory.
    let image = Flux2Pipeline::generate_f16(
        &cli.prompt,
        cli.height,
        cli.width,
        steps,
        cli.guidance,
        cli.seed,
        &model_dir,
        Path::new(&pile),
        None, // no LoRA
        &device,
    );

    let latency = started.elapsed();

    image
        .save(&out)
        .with_context(|| format!("writing PNG to {}", out.display()))?;

    // Quick non-blank sanity check: stddev of pixel luminance. A fully-black or
    // fully-flat image (a common scheduler/precision failure) has near-zero
    // variance; warn loudly rather than silently shipping a void.
    let (w, h) = (image.width(), image.height());
    let mut sum = 0f64;
    let mut sum_sq = 0f64;
    let n = (w as f64) * (h as f64);
    for px in image.pixels() {
        let l = 0.299 * px[0] as f64 + 0.587 * px[1] as f64 + 0.114 * px[2] as f64;
        sum += l;
        sum_sq += l * l;
    }
    let mean = sum / n;
    let var = (sum_sq / n - mean * mean).max(0.0);
    let std = var.sqrt();
    eprintln!(
        "imagine: {}x{} luminance mean={mean:.1} std={std:.2} ({:.1}s)",
        w,
        h,
        latency.as_secs_f64()
    );
    if std < 1.0 {
        eprintln!(
            "imagine: WARNING — image is nearly flat (luminance std={std:.2}); \
             it may be blank/black. Check steps/seed/model."
        );
    }

    // Print the path on stdout so a reader can Read it.
    println!("{}", out.display());

    // Optional: mint a wordless image memory via the `memory` faculty.
    if let Some(when) = &cli.remember {
        remember_image(&out, when)?;
    }

    return Ok(());

    // ── helpers ─────────────────────────────────────────────────────────────

    /// Glob the HF hub snapshots dir for the repo and return the snapshot that
    /// holds `transformer/config.json`.
    fn resolve_model_dir(repo: &str) -> anyhow::Result<PathBuf> {
        let home = std::env::var("HOME").context("HOME not set")?;
        let snapshots = PathBuf::from(&home)
            .join(".cache/huggingface/hub")
            .join(repo)
            .join("snapshots");
        let dir = std::fs::read_dir(&snapshots)
            .with_context(|| format!("no snapshots dir at {}", snapshots.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| p.join("transformer").join("config.json").exists())
            .ok_or_else(|| {
                anyhow!(
                    "no snapshot with transformer/config.json under {}",
                    snapshots.display()
                )
            })?;
        Ok(dir)
    }

    /// Shell out to the `memory` faculty to store the PNG as a wordless image
    /// memory at `when`. Looks for the `memory` binary next to this one (or on
    /// PATH); prints a note and skips if it can't be found.
    fn remember_image(png: &Path, when: &str) -> anyhow::Result<()> {
        // Find the memory binary: alongside the current exe, in the release
        // target dir, or on PATH.
        let candidates = memory_bin_candidates();
        let memory_bin = candidates
            .iter()
            .find(|p| p.exists())
            .cloned()
            .unwrap_or_else(|| PathBuf::from("memory")); // fall back to PATH

        let pile = std::env::var("PILE").unwrap_or_default();
        if pile.is_empty() {
            eprintln!(
                "imagine: --remember set but PILE is unset; skipping memory mint. \
                 Re-run with PILE=<self.pile> to store the image memory."
            );
            return Ok(());
        }

        eprintln!(
            "imagine: minting image memory → {} image {when} {}",
            memory_bin.display(),
            png.display()
        );
        let status = std::process::Command::new(&memory_bin)
            .arg("image")
            .arg(when)
            .arg(png)
            .env("PILE", &pile)
            .status();
        match status {
            Ok(s) if s.success() => {
                eprintln!("imagine: image memory minted at {when}.");
                Ok(())
            }
            Ok(s) => Err(anyhow!(
                "`memory image` exited with status {s}; the PNG at {} is intact",
                png.display()
            )),
            Err(e) => {
                eprintln!(
                    "imagine: could not run `memory` ({e}); the PNG at {} is intact. \
                     To store it manually: PILE=$PILE memory image {when} {}",
                    png.display(),
                    png.display()
                );
                Ok(())
            }
        }
    }

    fn memory_bin_candidates() -> Vec<PathBuf> {
        let mut v = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                v.push(dir.join("memory"));
            }
        }
        v.push(PathBuf::from("./target/release/memory"));
        v.push(PathBuf::from("faculties/target/release/memory"));
        v
    }
}
