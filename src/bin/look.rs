//! `look` -- turn the body's camera toward her eye.
//!
//! A sense: a command she runs that pushes frames from the camera into her
//! organ (`drive::organ`), raw, as the JPEG Soma serves, for as long as it
//! runs. `kill look` and the eye closes. It sends a frame when the scene has
//! changed and a keyframe every so often, because a frame costs the mind
//! about forty-five positions at the long edge it keeps; `--every` sets the
//! cadence it looks at.
//!
//! `--image <file>` sends pictures instead of the camera, once, and ends: the
//! silent gate.
//!
//! What it does NOT do: derive anything. No patches, no resizing beyond what
//! the change gate needs for itself; the mind owns the front end and the
//! archive keeps the frame she saw.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
#[command(name = "look", about = "Turn the camera toward her eye (a sense)")]
struct Cli {
    /// Her organ: `<endpoint id>[@ip:port]`, as drive prints it at launch.
    #[arg(long, env = "ORGAN")]
    organ: String,
    /// The mesh key this sense identifies as (the organ's allowlist knows it).
    #[arg(long, env = "ORGAN_KEY")]
    key: Option<PathBuf>,
    /// Base URL of the Soma that owns the camera.
    #[arg(long, env = "SOMA_URL", default_value = "http://localhost:8383")]
    soma: String,
    /// Seconds between looks at the camera.
    #[arg(long, default_value_t = 2.0)]
    every: f64,
    /// Send a frame at least this often, seconds, whether or not it changed.
    #[arg(long, default_value_t = 30.0)]
    keyframe: f64,
    /// Mean absolute change (0..1, on a small grey thumbnail) that counts as
    /// the scene having changed.
    #[arg(long, default_value_t = 0.04)]
    change: f64,
    /// Pictures to send once instead of the camera (PNG or JPEG).
    #[arg(long)]
    image: Vec<PathBuf>,
}

#[cfg(feature = "senses")]
fn main() -> Result<()> {
    let cli = Cli::parse();
    let key = cli
        .key
        .clone()
        .unwrap_or_else(faculties::organ_client::default_key_path);

    if !cli.image.is_empty() {
        let mut out =
            faculties::organ_client::open(&cli.organ, &key, "look", "image/jpeg", "frames")?;
        for path in &cli.image {
            let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
            let content_type = match path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_ascii_lowercase())
                .as_deref()
            {
                Some("png") => "image/png",
                Some("jpg") | Some("jpeg") => "image/jpeg",
                other => bail!("{}: unknown picture extension {other:?}", path.display()),
            };
            out.record_as(content_type, &bytes, 1)
                .context("send the picture")?;
            eprintln!(
                "[look] {}: {} bytes of {content_type} sent",
                path.display(),
                bytes.len()
            );
        }
        out.finish(framed_stream::EndStatus::Complete)?.close()?;
        return Ok(());
    }

    let mut out = faculties::organ_client::open(&cli.organ, &key, "look", "image/jpeg", "frames")?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("build the camera client")?;
    let url = format!("{}/camera/frame", cli.soma.trim_end_matches('/'));
    eprintln!(
        "[look] soma={} every {}s, keyframe {}s, change {}",
        cli.soma, cli.every, cli.keyframe, cli.change
    );
    let mut last_thumb: Option<Vec<u8>> = None;
    let mut last_sent = Instant::now() - Duration::from_secs_f64(cli.keyframe);
    loop {
        let started = Instant::now();
        match client.get(&url).send().and_then(|r| r.error_for_status()) {
            Ok(response) => {
                let bytes = response.bytes().context("read the frame")?.to_vec();
                let thumb = thumbnail(&bytes)?;
                let changed = match &last_thumb {
                    Some(prev) => mean_abs_diff(prev, &thumb) >= cli.change,
                    None => true,
                };
                let keyframe_due = last_sent.elapsed() >= Duration::from_secs_f64(cli.keyframe);
                if changed || keyframe_due {
                    out.record(&bytes, 1).context("send a frame")?;
                    eprintln!(
                        "[look] frame sent ({} bytes, {})",
                        bytes.len(),
                        if changed { "changed" } else { "keyframe" }
                    );
                    last_sent = Instant::now();
                    last_thumb = Some(thumb);
                }
            }
            Err(error) => eprintln!("[look] camera: {error}"),
        }
        let spent = started.elapsed();
        let period = Duration::from_secs_f64(cli.every);
        if spent < period {
            std::thread::sleep(period - spent);
        }
    }
}

#[cfg(not(feature = "senses"))]
fn main() -> Result<()> {
    let _ = Cli::parse();
    bail!("look was built without the `senses` feature")
}

/// A 32 x 18 grey thumbnail: enough to tell a changed scene from a still one.
#[cfg(feature = "senses")]
fn thumbnail(jpeg: &[u8]) -> Result<Vec<u8>> {
    let img = image::load_from_memory(jpeg).context("decode the frame for the change gate")?;
    let small = image::imageops::resize(
        &img.to_luma8(),
        32,
        18,
        image::imageops::FilterType::Triangle,
    );
    Ok(small.into_raw())
}

#[cfg(feature = "senses")]
fn mean_abs_diff(a: &[u8], b: &[u8]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 1.0;
    }
    a.iter()
        .zip(b)
        .map(|(x, y)| (f64::from(*x) - f64::from(*y)).abs())
        .sum::<f64>()
        / (a.len() as f64 * 255.0)
}
