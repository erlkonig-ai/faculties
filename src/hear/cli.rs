//! Explicit shell/device/file UX. The live listener never becomes an MCP tool.
use super::operations::{
    hear_segment, now_ms, segment_clip, Ears, CAPTURE_RATE, DEFAULT_PROMPT, HEAR_RATE,
};
use super::segmenter::{Segmenter, VadConfig};
use super::{ModelConfig, Observation, Options, Outcome};
use crate::out::Out;
use crate::turntaking::{self, SpeechWindow};
use anyhow::{bail, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};
use std::path::{Path, PathBuf};
#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "hear",
    about = "Ears: Soma's framed microphone → utterances → audio embeddings."
)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Listen continuously on Soma's framed capture stream.
    Listen(ListenArgs),
    /// Run recorded clips through the SAME segmenter and embed path — the
    /// hardware-free gate for everything below the capture seam.
    Once(OnceArgs),
}

#[derive(Args, Debug, Clone)]
struct Shared {
    /// Native model-collection pile holding the Gemma-4 hearing stack.
    #[arg(long, env = "GEMMA_PILE")]
    pile: Option<PathBuf>,
    /// HF model id for the small side files (config.json / tokenizer.json),
    /// AND the source name the weights are selected by inside the pile. Weights
    /// themselves never come from HF.
    ///
    /// The capitalisation is load-bearing and was wrong here until it was run
    /// against a real pile: the filesystem lookup is case-insensitive on macOS
    /// so `config.json` resolved either way, but the pile's root selection is
    /// not, and `gemma-4-e4b-it` matched no model root at all. `mary`'s own
    /// `gemma_hear` spells it this way.
    #[arg(long, default_value = "google/gemma-4-E4B-it")]
    model: String,
    /// Utterance jsonl to append to.
    #[arg(long, default_value = "/tmp/hear.jsonl")]
    out: PathBuf,
    /// Directory for the raw f32 embedding blobs.
    #[arg(long, default_value = "/tmp/hear_emb")]
    emb_dir: PathBuf,
    /// Also decode text (a debugging convenience — embeddings are the
    /// handover). Enables the prompt-parrot filter, which only has meaning
    /// once a transcript exists.
    #[arg(long, default_value_t = false)]
    transcribe: bool,
    /// Prompt used when `--transcribe` is on.
    #[arg(long, default_value = DEFAULT_PROMPT)]
    prompt: String,
    /// Max tokens to decode under `--transcribe`.
    #[arg(long, default_value_t = 64)]
    tokens: usize,
    /// Drop transcripts with fewer characters than this (`--transcribe` only).
    #[arg(long, default_value_t = 2)]
    min_chars: usize,
    /// Drop segments shorter than this many seconds (VAD blips; 0.46 s ones
    /// were observed in the wild).
    #[arg(long, default_value_t = 0.6)]
    min_dur_s: f64,
    /// Grace after our own speech ends during which an overlapping utterance
    /// is still treated as self-echo, ms.
    #[arg(long, default_value_t = turntaking::DEFAULT_BARGE_GRACE_MS)]
    barge_grace_ms: u64,
}

#[derive(Args, Debug)]
struct ListenArgs {
    #[command(flatten)]
    shared: Shared,
    /// Base URL of the running Soma that owns the microphone.
    #[arg(long, env = "SOMA_URL", default_value = "http://localhost:8000")]
    soma: String,
    /// Half-duplex pause file. While it exists, captured frames are DISCARDED
    /// — the stream is never closed. The speaking side holds the same path
    /// (`voice say|shout --pause-file`).
    #[arg(long, env = "VOICE_PAUSE_FILE")]
    pause_file: Option<PathBuf>,
    /// Stop after this many utterances (0 = run until the stream ends).
    #[arg(long, default_value_t = 0)]
    limit: usize,
}

#[derive(Args, Debug)]
struct OnceArgs {
    #[command(flatten)]
    shared: Shared,
    /// Comma-separated audio files, fed through the same segmenter.
    #[arg(long, value_delimiter = ',', required = true)]
    wav: Vec<PathBuf>,
}

impl Shared {
    fn options(&self) -> Result<Options> {
        let options = Options {
            transcribe: self.transcribe,
            prompt: crate::text_arg(&self.prompt, "hearing prompt")?,
            tokens: self.tokens,
            filter: turntaking::SpeechFilter {
                min_chars: self.min_chars,
                min_dur_s: self.min_dur_s,
                barge_grace_ms: self.barge_grace_ms,
            },
        };
        options.validate()?;
        Ok(options)
    }
}
#[cfg(feature = "hear")]
fn model_config(shared: &Shared) -> Result<ModelConfig> {
    let pile = shared
        .pile
        .clone()
        .context("no Gemma pile: pass --pile or set GEMMA_PILE")?;
    Ok(ModelConfig {
        pile,
        model: shared.model.clone(),
        config_json: find_hf_file(&shared.model, "config.json")?,
        tokenizer_json: find_hf_file(&shared.model, "tokenizer.json")?,
    })
}
#[cfg(not(feature = "hear"))]
fn model_config(_shared: &Shared) -> Result<ModelConfig> {
    bail!("hear was built without the `hear` feature")
}
#[cfg(feature = "hear")]
fn find_hf_file(model: &str, filename: &str) -> Result<PathBuf> {
    let output=std::process::Command::new("python3").args(["-c","import sys; from huggingface_hub import hf_hub_download; print(hf_hub_download(sys.argv[1], sys.argv[2], local_files_only=True))",model,filename]).output().with_context(||format!("resolve local hearing {filename}"))?;
    if !output.status.success() {
        bail!(
            "could not resolve local {filename} for {model}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let path =
        String::from_utf8(output.stdout).context("local hearing side-file path is not UTF-8")?;
    let path = path.trim();
    if path.is_empty() {
        bail!("local hearing side-file resolver returned an empty path");
    }
    Ok(PathBuf::from(path))
}
#[cfg(feature = "hear")]
fn load_16k(path: &Path) -> Result<Vec<f32>> {
    mary::models::gemma::gemma4::audio_load::load_audio_16k_mono(path).map_err(anyhow::Error::msg)
}
#[cfg(not(feature = "hear"))]
fn load_16k(_path: &Path) -> Result<Vec<f32>> {
    bail!("hear was built without the `hear` feature")
}

fn cmd_once(args: OnceArgs, out: &mut Out<'_>) -> Result<()> {
    let options = args.shared.options()?;
    let mut ears = Ears::open(&model_config(&args.shared)?)?;
    std::fs::create_dir_all(&args.shared.emb_dir)
        .with_context(|| format!("create {}", args.shared.emb_dir.display()))?;
    let mut kept = 0;
    for path in &args.wav {
        let wave = load_16k(path)?;
        let segments = segment_clip(&wave)?;
        out.line(format!(
            "{}: {} utterance(s)",
            path.display(),
            segments.len()
        ))?;
        for segment in segments {
            let observation = hear_segment(
                &mut ears,
                &options,
                &segment,
                &path.display().to_string(),
                None,
                now_ms()?,
            )?;
            if observation.kept() {
                kept += 1;
            }
            write_observation(&args.shared, &observation, out)?;
        }
    }
    out.line(format!(
        "{kept} utterance(s) embedded → {}",
        args.shared.out.display()
    ))
}
fn cmd_listen(args: ListenArgs, out: &mut Out<'_>) -> Result<()> {
    let shared = args.shared;
    let options = shared.options()?;
    let mut ears = Ears::open(&model_config(&shared)?)?;
    std::fs::create_dir_all(&shared.emb_dir)
        .with_context(|| format!("create {}", shared.emb_dir.display()))?;
    if let Some(path) = &args.pause_file {
        if turntaking::clear_stale(path) {
            out.line(format!("cleared stale pause file {}", path.display()))?;
        }
    }
    let mut capture = soma_client::SomaCapture::open(&args.soma)
        .with_context(|| format!("open Soma capture at {}", args.soma))?;
    out.line(format!(
        "hear: soma={} {} Hz/{} sample frames; segmenter at {} Hz, model at {} Hz; out={} emb={}",
        args.soma,
        soma_client::SAMPLE_RATE,
        soma_client::FRAME_SAMPLES,
        CAPTURE_RATE,
        HEAR_RATE,
        shared.out.display(),
        shared.emb_dir.display()
    ))?;
    let mut segmenter = Segmenter::new(CAPTURE_RATE, VadConfig::default());
    let mut spoke: Option<SpeechWindow> = None;
    let mut pause_since = None;
    let mut kept = 0;
    loop {
        // Soma remains open during software holds; reading the next frame is
        // the capture clock. Do not add per-frame resampling or a second timer.
        let frame = capture.next_frame()?;
        let held = args
            .pause_file
            .as_deref()
            .map(turntaking::paused)
            .unwrap_or(false);
        if held {
            if pause_since.is_none() {
                pause_since = Some(now_ms()?);
            }
            segmenter.pause_skip(frame.samples.len() as u64);
            continue;
        }
        if let Some(start_ms) = pause_since.take() {
            spoke = Some(SpeechWindow {
                start_ms,
                end_ms: now_ms()?,
            });
        }
        let mut segments = Vec::new();
        segmenter.push(&frame.samples, &mut |segment| segments.push(segment));
        for segment in segments {
            let observation =
                hear_segment(&mut ears, &options, &segment, "soma", spoke, now_ms()?)?;
            let accepted = observation.kept();
            write_observation(&shared, &observation, out)?;
            if accepted {
                kept += 1;
                if args.limit > 0 && kept >= args.limit {
                    return out.line(format!("{kept} utterance(s) embedded — limit reached"));
                }
            }
        }
    }
}
fn write_observation(shared: &Shared, observation: &Observation, out: &mut Out<'_>) -> Result<()> {
    let dur = observation.duration();
    let record = match &observation.outcome {
        Outcome::Dropped { reason, text } => {
            match text {
                Some(text) => {
                    out.line(format!("[heard ] {text:?} ({dur:.2}s) → DROPPED: {reason}"))?
                }
                None => out.line(format!("[heard ] ({dur:.2}s) → DROPPED: {reason}"))?,
            }
            let mut record = serde_json::json!({"utc_ms":observation.utc_ms,"source":observation.source,"start_s":observation.start_s,"end_s":observation.end_s,"dur_s":dur,"dropped":reason});
            if let Some(text) = text {
                record["text"] = serde_json::Value::String(text.clone());
            }
            record
        }
        Outcome::Embedded(heard) => {
            let path = shared.emb_dir.join(format!(
                "utt_{}_{:.0}ms.f32",
                observation.utc_ms,
                dur * 1000.0
            ));
            let bytes = heard.embedding_bytes()?;
            std::fs::write(&path, bytes.as_ref())
                .with_context(|| format!("write {}", path.display()))?;
            match &heard.text {
                Some(text) => out.line(format!(
                    "[heard ] {text:?} ({dur:.2}s) → {} × {} embeddings",
                    heard.n_tokens, heard.hidden
                ))?,
                None => out.line(format!(
                    "[heard ] ({dur:.2}s) → {} × {} embeddings",
                    heard.n_tokens, heard.hidden
                ))?,
            }
            serde_json::json!({"utc_ms":observation.utc_ms,"source":observation.source,"start_s":observation.start_s,"end_s":observation.end_s,"dur_s":dur,"rate":HEAR_RATE,"n_tokens":heard.n_tokens,"hidden":heard.hidden,"dtype":"f32le","layout":"row-major","emb":path.display().to_string(),"text":heard.text})
        }
    };
    append_record(&shared.out, &record)
}
fn append_record(path: &Path, record: &serde_json::Value) -> Result<()> {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open utterance log {}", path.display()))?;
    writeln!(file, "{record}").with_context(|| format!("append utterance log {}", path.display()))
}
pub fn execute(cli: Cli, out: &mut Out<'_>) -> Result<()> {
    match cli.command {
        Some(Command::Listen(args)) => cmd_listen(args, out),
        Some(Command::Once(args)) => cmd_once(args, out),
        None => out.line(Cli::command().render_help().to_string()),
    }
}
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    if cli.command.is_none() {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }
    crate::cli::with_output("hear", |out| execute(cli, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_cli_expands_prompt_file_input() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("prompt.txt");
        std::fs::write(&path, "literal prompt contents").unwrap();
        let at = format!("@{}", path.display());
        let cli = Cli::try_parse_from(["hear", "once", "--wav", "unopened.wav", "--prompt", &at])
            .unwrap();
        let Some(Command::Once(args)) = cli.command else {
            panic!("recorded clip syntax")
        };
        assert_eq!(
            args.shared.options().unwrap().prompt,
            "literal prompt contents"
        );
        let cli = Cli::try_parse_from([
            "hear",
            "once",
            "--wav",
            "unopened.wav",
            "--prompt",
            "@@literal",
        ])
        .unwrap();
        let Some(Command::Once(args)) = cli.command else {
            panic!("recorded clip syntax")
        };
        assert_eq!(args.shared.options().unwrap().prompt, "@literal");
    }

    #[test]
    fn cli_keeps_both_explicit_live_and_recorded_modes() {
        let names: Vec<_> = Cli::command()
            .get_subcommands()
            .map(|c| c.get_name().to_owned())
            .collect();
        assert!(names.contains(&"listen".to_owned()));
        assert!(names.contains(&"once".to_owned()));
        assert!(Cli::try_parse_from(["hear", "once"]).is_err());
        let cli = Cli::try_parse_from([
            "hear",
            "listen",
            "--soma",
            "http://invalid.example",
            "--pause-file",
            "held",
            "--limit",
            "2",
        ])
        .unwrap();
        let Some(Command::Listen(args)) = cli.command else {
            panic!("live syntax")
        };
        assert_eq!(args.limit, 2);
        assert_eq!(args.pause_file, Some(PathBuf::from("held")));
    }
}
