//! `listen` -- turn the body's microphone toward her ear.
//!
//! A sense: a command she runs that pushes what the microphone picks up into
//! her organ (`drive::organ`), raw, as 16-bit PCM at the body's own rate, for
//! as long as it runs. `kill listen` and the ear falls silent. By default it
//! sends utterances -- an energy gate cuts the room into stretches of sound
//! and drops the silence between -- because an open microphone costs the mind
//! twenty positions a second; `--continuous` sends every frame.
//!
//! `--wav <file>` sends a recording instead of the microphone, once, and
//! ends: the silent gate.
//!
//! What it does NOT do: derive anything. No mel levels, no resampling; the
//! mind owns the front end and the archive keeps the sound she heard.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "listen",
    about = "Turn the microphone toward her ear (a sense)"
)]
struct Cli {
    /// Her organ: `<endpoint id>[@ip:port]`, as drive prints it at launch.
    #[arg(long, env = "ORGAN")]
    organ: String,
    /// The mesh key this sense identifies as (the organ's allowlist knows it).
    #[arg(long, env = "ORGAN_KEY")]
    key: Option<PathBuf>,
    /// Base URL of the Soma that owns the microphone.
    #[arg(long, env = "SOMA_URL", default_value = "http://localhost:8383")]
    soma: String,
    /// Send every frame rather than utterances.
    #[arg(long)]
    continuous: bool,
    /// Drop utterances shorter than this many seconds.
    #[arg(long, default_value_t = 0.6)]
    min_dur_s: f64,
    /// Sound below this RMS (of full scale) is silence.
    #[arg(long, default_value_t = 0.01)]
    floor: f32,
    /// Silence this long ends an utterance, seconds.
    #[arg(long, default_value_t = 0.5)]
    hangover_s: f64,
    /// Recordings to send once instead of the microphone (16-bit PCM WAV).
    #[arg(long)]
    wav: Vec<PathBuf>,
}

#[cfg(feature = "senses")]
fn main() -> Result<()> {
    let cli = Cli::parse();
    let key = cli
        .key
        .clone()
        .unwrap_or_else(faculties::organ_client::default_key_path);

    if !cli.wav.is_empty() {
        for path in &cli.wav {
            let (rate, samples) = read_wav_mono_i16(path)?;
            let content_type = format!("audio/L16;rate={rate};channels=1");
            let mut out = faculties::organ_client::open(
                &cli.organ,
                &key,
                "listen",
                &content_type,
                "samples",
            )?;
            out.record(&le_bytes(&samples), samples.len() as u64)
                .context("send the recording")?;
            eprintln!(
                "[listen] {}: {:.2}s at {rate} Hz sent",
                path.display(),
                samples.len() as f64 / rate as f64
            );
            out.finish(framed_stream::EndStatus::Complete)?.close()?;
        }
        return Ok(());
    }

    let rate = soma_client::SAMPLE_RATE;
    let content_type = format!("audio/L16;rate={rate};channels=1");
    let mut out =
        faculties::organ_client::open(&cli.organ, &key, "listen", &content_type, "samples")?;
    let mut capture = soma_client::SomaCapture::open(&cli.soma)
        .with_context(|| format!("open Soma capture at {}", cli.soma))?;
    eprintln!(
        "[listen] soma={} {rate} Hz, {}",
        cli.soma,
        if cli.continuous {
            "continuous"
        } else {
            "utterances"
        }
    );
    let frame_s = soma_client::FRAME_MS as f64 / 1000.0;
    let hangover_frames = (cli.hangover_s / frame_s).ceil() as usize;
    let mut utterance: Vec<i16> = Vec::new();
    let mut voiced_frames = 0usize;
    let mut silent_run = 0usize;
    loop {
        let frame = capture.next_frame()?;
        let pcm: Vec<i16> = frame
            .samples
            .iter()
            .map(|s| (s.clamp(-1.0, 1.0) * 32767.0) as i16)
            .collect();
        if cli.continuous {
            out.record(&le_bytes(&pcm), pcm.len() as u64)
                .context("send a frame")?;
            continue;
        }
        let rms =
            (frame.samples.iter().map(|s| s * s).sum::<f32>() / frame.samples.len() as f32).sqrt();
        let voiced = rms >= cli.floor;
        if voiced {
            silent_run = 0;
            voiced_frames += 1;
            utterance.extend_from_slice(&pcm);
        } else if !utterance.is_empty() {
            silent_run += 1;
            utterance.extend_from_slice(&pcm);
            if silent_run >= hangover_frames {
                let dur_s = voiced_frames as f64 * frame_s;
                if dur_s >= cli.min_dur_s {
                    out.record(&le_bytes(&utterance), utterance.len() as u64)
                        .context("send an utterance")?;
                    eprintln!("[listen] utterance {dur_s:.2}s sent");
                } else {
                    eprintln!(
                        "[listen] ({dur_s:.2}s) dropped: shorter than {}s",
                        cli.min_dur_s
                    );
                }
                utterance.clear();
                voiced_frames = 0;
                silent_run = 0;
            }
        }
    }
}

#[cfg(not(feature = "senses"))]
fn main() -> Result<()> {
    let _ = Cli::parse();
    bail!("listen was built without the `senses` feature")
}

fn le_bytes(samples: &[i16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(samples.len() * 2);
    for s in samples {
        out.extend_from_slice(&s.to_le_bytes());
    }
    out
}

/// A 16-bit PCM WAV, downmixed to mono: `(rate, samples)`.
#[allow(dead_code)]
fn read_wav_mono_i16(path: &std::path::Path) -> Result<(u32, Vec<i16>)> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() > 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WAVE",
        "{} is not a RIFF WAVE file",
        path.display()
    );
    let mut pos = 12;
    let mut fmt: Option<(u16, u16, u32, u16)> = None; // (format, channels, rate, bits)
    let mut data: Option<&[u8]> = None;
    while pos + 8 <= bytes.len() {
        let id = &bytes[pos..pos + 4];
        let len = u32::from_le_bytes([
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]) as usize;
        let body = &bytes[pos + 8..(pos + 8 + len).min(bytes.len())];
        if id == b"fmt " && body.len() >= 16 {
            fmt = Some((
                u16::from_le_bytes([body[0], body[1]]),
                u16::from_le_bytes([body[2], body[3]]),
                u32::from_le_bytes([body[4], body[5], body[6], body[7]]),
                u16::from_le_bytes([body[14], body[15]]),
            ));
        } else if id == b"data" {
            data = Some(body);
        }
        pos += 8 + len + (len & 1);
    }
    let (format, channels, rate, bits) = fmt.context("no fmt chunk")?;
    anyhow::ensure!(
        format == 1 && bits == 16,
        "only 16-bit PCM WAV is read; this is format {format} at {bits} bits"
    );
    anyhow::ensure!(channels >= 1, "no channels");
    let data = data.context("no data chunk")?;
    let ch = channels as usize;
    let samples: Vec<i16> = data
        .chunks_exact(2 * ch)
        .map(|frame| {
            let sum: i32 = frame
                .chunks_exact(2)
                .map(|s| i32::from(i16::from_le_bytes([s[0], s[1]])))
                .sum();
            (sum / ch as i32) as i16
        })
        .collect();
    Ok((rate, samples))
}
