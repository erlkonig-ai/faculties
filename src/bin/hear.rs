//! `hear` — the EARS faculty: Soma's framed microphone → utterances → AUDIO
//! EMBEDDINGS, handed to whatever is driving.
//!
//! ```text
//!   soma /audio/capture ──80 ms frames──▶ energy VAD ──utterance──▶ Gemma-4
//!   (soma-client)                         (this bin)                audio tower
//!                                                                       │
//!                                     jsonl record + f32 blob ◀─────────┘
//! ```
//!
//! # It hands over embeddings, not text
//!
//! `mary::models::gemma::gemma4::hear::Hearing::embed` stops after the
//! parity-gated part of the path — log-mel → audio tower → multimodal embedder
//! — and returns the rows in the DECODER'S OWN WIDTH. Those rows are exactly
//! what `Hearing::understand` then writes over its audio-soft-token positions
//! before prefill, so a consumer that splices them into its own token
//! embeddings performs the operation the model already performs. What that
//! buys is everything a transcript throws away: tone, hesitation, mood. The
//! throwing-away happens at the greedy argmax inside `understand`, which is
//! the last place anyone can still get it back — so the upgrade is to stop one
//! step earlier, and it costs nothing downstream. (`gemma_listen`'s own header
//! named this as the upgrade before it existed; this is it.)
//!
//! `--transcribe` additionally decodes text, for humans reading the log. It is
//! a debugging convenience, not the handover.
//!
//! # Why Gemma-4 and not Inkling (checked 2026-08-27)
//!
//! Inkling has a native dMel audio tower and it is parity-gated at 1e-5 by
//! `inkling_towers_gate`, which is a real result and easy to over-read. It is
//! the TOWER only. `mary::models::inkling::vision::audio_embed` takes
//! ALREADY-DISCRETIZED mel level ids, its one caller in the tree is that gate,
//! and the gate feeds it ids dumped from a Python oracle. There is no dMel
//! front end anywhere (no sample rate, FFT size, hop, or level boundaries are
//! specified in the repo), the forward path takes token ids and has no
//! embeds-taking entry point or splice hook, `inkling_forward` is `<pile> <ids>
//! <out>` with no audio flag, and the runtime never asks the pile for
//! `model.audio.*` even though the importer's name filter puts those weights
//! there. Gemma-4's chain, by contrast, is whole and gated end to end
//! (`gemma_audio_parity`: cos = 1.0 at features / tower / embedder / cascade,
//! shards AND pile). Note the model here is Gemma-4 E4B, not the 31B --
//! `gemma_31b.pile` carries zero `model.audio_tower.*` keys and cannot hear.
//!
//! When Inkling grows the missing pieces, only `Ears` changes: the handover
//! this bin performs is already the one an Inkling splice would need.
//!
//! # Soma owns the microphone; this bin owns nothing
//!
//! **DEVICES ARE ADDRESSED BY NAME, NEVER BY INDEX AND NEVER VIA THE SYSTEM
//! DEFAULT.** A Bluetooth connect silently renumbers CoreAudio and an
//! index-addressed stream lands on a dead virtual channel at -91 dB with
//! nothing in the logs to say so. Opening the named device IS the
//! verification. This bin therefore opens no device at all: exactly one
//! process (Soma) picks the device by name, and every consumer inherits that
//! one choice through `soma-client`. Reading the next record is the
//! conversation clock — no second timer, no CPAL here.
//!
//! **NEVER CLOSE THE MICROPHONE STREAM.** Closing a Bluetooth mic flips the
//! endpoint between its handsfree and high-quality profiles and chops speech
//! mid-sentence. Turn-taking is gated in SOFTWARE ONLY: while the pause file
//! exists (`--pause-file`, the same path the speaking `voice` process holds)
//! this loop keeps pulling frames and DISCARDS them. The hold stops the model,
//! never the person — a human can talk over a hold, and the stream is still
//! there when it lifts. See `faculties::turntaking`.
//!
//! **THE SAY-PRIVACY INVARIANT LIVES IN CODE, NOT CONFIG.** There is no path
//! from `voice say` to a room speaker (`route_say`). Nothing here routes audio
//! out; if that ever changes, the invariant must be enforced at the new owner
//! BEFORE the sink is repointed, or a private utterance lands in the room.
//!
//! # The guards, and why each exists
//!
//! Inherited from the `converse` bridge (deleted with this commit) and now
//! living in `faculties::turntaking`:
//!
//! - the PAUSE FILE, held by the mouth across its whole audible window;
//! - the BARGE-IN OVERLAP heuristic — an utterance stamped inside our own
//!   speech window is presumed self-echo even if the pause file missed it,
//!   because the two guards fail differently;
//! - the NO-SPEECH / PROMPT-PARROT filter — on empty or AEC-suppressed audio a
//!   decoder PARROTS ITS OWN PROMPT back as the transcript, and without the
//!   check a silent room makes the bot recite its instructions aloud. It only
//!   applies under `--transcribe`; the audio-only half (VAD blips, self-echo)
//!   runs on every utterance and runs BEFORE the audio tower is paid for.
//!
//! # Usage
//!
//! ```text
//!   # the file gate — no hardware, the same segmenter and the same embed path:
//!   hear once --wav clip1.wav,clip2.wav --pile gemma_e4b.pile
//!
//!   # live, against a running soma:
//!   hear listen --soma http://localhost:8000 --pile gemma_e4b.pile \
//!     --out /tmp/hear.jsonl --emb-dir /tmp/hear_emb --pause-file /tmp/ears.pause
//!
//!   # the mouth, holding the same pause file for its audible window:
//!   voice shout "…" --pause-file /tmp/ears.pause
//! ```
//!
//! `--pile` falls back to `$GEMMA_PILE`. Each record is one jsonl line;
//! `emb` names a raw little-endian f32 file of `n_tokens * hidden` values,
//! row-major — the same layout `AudioEmbeddings::rows` has in memory.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};
use faculties::clock;
use faculties::turntaking::{self, SpeechFilter, SpeechWindow};

/// Sample rate the Gemma-4 audio front end expects.
const HEAR_RATE: usize = 16_000;

/// Rate the live segmenter runs at: Soma's own, unresampled.
///
/// The VAD is rate-agnostic (it measures RMS per frame), so it runs on the
/// capture stream exactly as it arrives and only the FINISHED utterance is
/// resampled — one contiguous call, which is what `resample_to_16k` is built
/// for. Resampling each 80 ms frame instead would be wrong twice over: the
/// resampler is constructed per call and carries no state across frames, so
/// every frame boundary becomes a discontinuity, and each call skips its own
/// ~85-sample startup delay, which would lose ~5 ms of every 80 ms and drift
/// the stream clock ~6.6% slow.
const CAPTURE_RATE: usize = soma_client::SAMPLE_RATE as usize;

const DEFAULT_PROMPT: &str = "Transcribe exactly what is being said.";

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "hear",
    about = "Ears: Soma's framed microphone → utterances → audio embeddings."
)]
struct Cli {
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
    /// HF model id for the small side files (config.json / tokenizer.json).
    /// Weights never come from here.
    #[arg(long, default_value = "google/gemma-4-e4b-it")]
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

impl Shared {
    fn filter(&self) -> SpeechFilter {
        SpeechFilter {
            min_chars: self.min_chars,
            min_dur_s: self.min_dur_s,
            barge_grace_ms: self.barge_grace_ms,
        }
    }
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Listen(args)) => cmd_listen(args),
        Some(Command::Once(args)) => cmd_once(args),
        None => {
            Cli::command().print_help().ok();
            println!();
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Energy VAD + endpointing
// ---------------------------------------------------------------------------
//
// Carried over from `gemma_listen`'s segmenter: adaptive noise floor with a
// fast warm-up then a slow EMA that only follows CALM audio (speech must not
// drag the floor up), a start debounce, a hangover close, and a pre-roll ring
// so a soft onset is not clipped. Upgrade path unchanged: silero-vad drops
// into `speech_frame` without touching anything downstream.

#[derive(Clone, Debug)]
struct VadConfig {
    frame_ms: usize,
    start_frames: usize,
    hangover_ms: usize,
    min_utt_ms: usize,
    max_utt_s: f32,
    ratio: f32,
    abs_floor: f32,
    preroll_ms: usize,
}

impl Default for VadConfig {
    fn default() -> Self {
        VadConfig {
            frame_ms: 20,
            start_frames: 3,
            hangover_ms: 700,
            min_utt_ms: 300,
            // Stay inside the feature extractor's 30 s window.
            max_utt_s: 28.0,
            ratio: 3.5,
            abs_floor: 0.008,
            preroll_ms: 240,
        }
    }
}

/// A finished utterance at the segmenter's native rate.
struct Segment {
    samples: Vec<f32>,
    /// Sample rate of `samples` — the rate the segmenter ran at, which is the
    /// capture rate live and 16 kHz for recorded clips.
    rate: usize,
    start_s: f64,
    end_s: f64,
}

impl Segment {
    fn dur_s(&self) -> f64 {
        self.end_s - self.start_s
    }
}

/// Streaming energy-VAD segmenter. Feed arbitrary-size mono chunks at a fixed
/// rate; complete utterances go to `emit`. The SAME code path serves the live
/// capture and recorded files, which is what makes `hear once` a real gate.
struct Segmenter {
    cfg: VadConfig,
    rate: usize,
    frame: usize,
    pending: Vec<f32>,
    preroll: std::collections::VecDeque<f32>,
    preroll_cap: usize,
    noise_floor: f32,
    floor_warm: usize,
    in_speech: bool,
    speech_run: usize,
    silence_run: usize,
    current: Vec<f32>,
    utt_start_sample: u64,
    samples_seen: u64,
}

impl Segmenter {
    fn new(rate: usize, cfg: VadConfig) -> Self {
        let frame = rate * cfg.frame_ms / 1000;
        let preroll_cap = rate * cfg.preroll_ms / 1000;
        Segmenter {
            cfg,
            rate,
            frame,
            pending: Vec::new(),
            preroll: std::collections::VecDeque::with_capacity(preroll_cap),
            preroll_cap,
            noise_floor: 0.0,
            floor_warm: 0,
            in_speech: false,
            speech_run: 0,
            silence_run: 0,
            current: Vec::new(),
            utt_start_sample: 0,
            samples_seen: 0,
        }
    }

    fn push(&mut self, chunk: &[f32], emit: &mut impl FnMut(Segment)) {
        self.pending.extend_from_slice(chunk);
        while self.pending.len() >= self.frame {
            let frame: Vec<f32> = self.pending.drain(..self.frame).collect();
            self.frame_in(&frame, emit);
        }
    }

    /// End of stream/file: close any open utterance.
    fn flush(&mut self, emit: &mut impl FnMut(Segment)) {
        if !self.pending.is_empty() {
            let rest = std::mem::take(&mut self.pending);
            if self.in_speech {
                self.current.extend_from_slice(&rest);
                self.samples_seen += rest.len() as u64;
            }
        }
        if self.in_speech {
            self.close(emit);
        }
    }

    /// Half-duplex pause: the mouth is speaking, so `n` incoming samples are
    /// DROPPED — not un-captured. Any open utterance is abandoned (it would be
    /// self-echo), the speech state clears, the adaptive noise floor is KEPT
    /// (no re-warm-up on every reply), and the stream clock still advances so
    /// later timestamps stay stream-relative.
    fn pause_skip(&mut self, n: u64) {
        self.pending.clear();
        self.preroll.clear();
        self.current.clear();
        self.in_speech = false;
        self.speech_run = 0;
        self.silence_run = 0;
        self.samples_seen += n;
    }

    fn frame_in(&mut self, frame: &[f32], emit: &mut impl FnMut(Segment)) {
        let rms = (frame.iter().map(|&x| x * x).sum::<f32>() / frame.len() as f32).sqrt();

        let warm_frames = 500 / self.cfg.frame_ms;
        if self.floor_warm < warm_frames {
            self.noise_floor = if self.floor_warm == 0 {
                rms
            } else {
                0.7 * self.noise_floor + 0.3 * rms
            };
            self.floor_warm += 1;
        } else if !self.in_speech && rms < self.noise_floor * 2.0 {
            self.noise_floor = 0.98 * self.noise_floor + 0.02 * rms;
        }

        let threshold = (self.noise_floor * self.cfg.ratio).max(self.cfg.abs_floor);
        let speech = rms > threshold;

        if !self.in_speech {
            for &s in frame {
                if self.preroll.len() == self.preroll_cap {
                    self.preroll.pop_front();
                }
                self.preroll.push_back(s);
            }
            if speech {
                self.speech_run += 1;
                if self.speech_run >= self.cfg.start_frames {
                    self.in_speech = true;
                    self.silence_run = 0;
                    self.current = self.preroll.iter().copied().collect();
                    self.utt_start_sample = (self.samples_seen + frame.len() as u64)
                        .saturating_sub(self.current.len() as u64);
                }
            } else {
                self.speech_run = 0;
            }
        } else {
            self.current.extend_from_slice(frame);
            if speech {
                self.silence_run = 0;
            } else {
                self.silence_run += 1;
                let hangover_frames = self.cfg.hangover_ms / self.cfg.frame_ms;
                if self.silence_run >= hangover_frames {
                    // Trim most of the hangover, keep a ~200 ms tail.
                    let keep_tail = self.rate * 200 / 1000;
                    let hang = self.silence_run * self.frame;
                    let cut = hang.saturating_sub(keep_tail).min(self.current.len());
                    let newlen = self.current.len() - cut;
                    self.current.truncate(newlen);
                    self.close(emit);
                }
            }
            if self.in_speech && self.current.len() as f32 >= self.cfg.max_utt_s * self.rate as f32
            {
                self.close(emit);
            }
        }
        self.samples_seen += frame.len() as u64;
    }

    fn close(&mut self, emit: &mut impl FnMut(Segment)) {
        let samples = std::mem::take(&mut self.current);
        self.in_speech = false;
        self.speech_run = 0;
        self.silence_run = 0;
        self.preroll.clear();
        let min_len = self.rate * self.cfg.min_utt_ms / 1000;
        if samples.len() >= min_len {
            let start_s = self.utt_start_sample as f64 / self.rate as f64;
            let end_s = start_s + samples.len() as f64 / self.rate as f64;
            emit(Segment {
                samples,
                rate: self.rate,
                start_s,
                end_s,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// The embed seam (feature-gated, mirrors `voice`)
// ---------------------------------------------------------------------------

/// What one utterance became: the audio rows, plus an optional transcript.
struct Heard {
    n_tokens: usize,
    hidden: usize,
    rows: Vec<f32>,
    text: Option<String>,
}

#[cfg(feature = "hear")]
struct Ears {
    hearing: mary::models::gemma::gemma4::hear::Hearing<mary::nn::backend::B>,
}

#[cfg(feature = "hear")]
impl Ears {
    fn open(shared: &Shared) -> Result<Self> {
        use mary::models::gemma::gemma4::config::Gemma4Config;
        use mary::models::gemma::gemma4::hear::Hearing;
        use mary::nn::backend::{WgpuDevice, B};

        let pile = shared
            .pile
            .clone()
            .context("no Gemma pile: pass --pile or set GEMMA_PILE")?;
        // Weights come ONLY from the pile; config.json / tokenizer.json are
        // small side files resolved from the local HF snapshot.
        let cfg_path = find_hf_file(&shared.model, "config.json")?;
        let tok_path = find_hf_file(&shared.model, "tokenizer.json")?;
        let config = Gemma4Config::load(Path::new(&cfg_path));
        let tokenizer = tokenizers::Tokenizer::from_file(&tok_path)
            .map_err(|e| anyhow::anyhow!("load tokenizer {tok_path}: {e}"))?;
        let device = WgpuDevice::default();
        let (model, _vision, tower, embedder) = mary::persist::load_gemma4_hearing_from_pile::<B>(
            &pile,
            mary::selection::ModelSelector::Source {
                source: &shared.model,
                quantization: mary::persist::QUANTIZATION_NATIVE,
            },
            config,
            &device,
        )
        .with_context(|| format!("load Gemma-4 hearing stack from {}", pile.display()))?;
        Ok(Self {
            hearing: Hearing::new(model, tower, embedder, tokenizer, device),
        })
    }

    fn hear(&self, wave: &[f32], shared: &Shared) -> Heard {
        // The handover: stop after the parity-gated audio path and take the
        // rows in the decoder's own width. `understand` would overwrite its
        // audio-soft-token positions with exactly these.
        let audio = self.hearing.embed(wave);
        let text = shared.transcribe.then(|| {
            self.hearing
                .understand(wave, &shared.prompt, shared.tokens, |_| {})
        });
        Heard {
            n_tokens: audio.n_tokens,
            hidden: audio.hidden,
            rows: audio.rows,
            text,
        }
    }
}

#[cfg(not(feature = "hear"))]
struct Ears;

#[cfg(not(feature = "hear"))]
impl Ears {
    fn open(_shared: &Shared) -> Result<Self> {
        bail!(
            "hear was built without the `hear` feature — rebuild with \
             `cargo build --release --features hear --bin hear` (pulls mary's \
             Gemma-4 audio tower + multimodal embedder)."
        )
    }

    fn hear(&self, _wave: &[f32], _shared: &Shared) -> Heard {
        unreachable!("Ears::open always fails without the `hear` feature")
    }
}

#[cfg(feature = "hear")]
fn find_hf_file(model_id: &str, filename: &str) -> Result<String> {
    let out = std::process::Command::new("python3")
        .args([
            "-c",
            &format!(
                "from huggingface_hub import hf_hub_download; \
                 print(hf_hub_download('{model_id}', '{filename}'))"
            ),
        ])
        .output()
        .with_context(|| format!("resolve {filename} from the local HF snapshot"))?;
    if !out.status.success() {
        bail!(
            "could not resolve {filename} for {model_id}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_once(args: OnceArgs) -> Result<()> {
    let ears = Ears::open(&args.shared)?;
    std::fs::create_dir_all(&args.shared.emb_dir)
        .with_context(|| format!("create {}", args.shared.emb_dir.display()))?;
    let filter = args.shared.filter();
    let mut kept = 0usize;

    for path in &args.wav {
        let wave = load_16k(path)?;
        // Recorded clips are decoded straight to 16 kHz, so the segmenter runs
        // at the model's rate and no resample is needed at all.
        let mut segmenter = Segmenter::new(HEAR_RATE, VadConfig::default());
        let mut segments: Vec<Segment> = Vec::new();
        segmenter.push(&wave, &mut |s| segments.push(s));
        segmenter.flush(&mut |s| segments.push(s));
        println!("{}: {} utterance(s)", path.display(), segments.len());
        for segment in segments {
            if handle_segment(
                &ears,
                &args.shared,
                &filter,
                &segment,
                &path.display().to_string(),
                None,
            )? {
                kept += 1;
            }
        }
    }
    println!(
        "{kept} utterance(s) embedded → {}",
        args.shared.out.display()
    );
    Ok(())
}

fn cmd_listen(args: ListenArgs) -> Result<()> {
    let shared = args.shared;
    let ears = Ears::open(&shared)?;
    std::fs::create_dir_all(&shared.emb_dir)
        .with_context(|| format!("create {}", shared.emb_dir.display()))?;
    let filter = shared.filter();

    // A stale pause file permanently deafens the ears, so never trust the last
    // run to have exited cleanly.
    if let Some(path) = &args.pause_file {
        if turntaking::clear_stale(path) {
            eprintln!("cleared stale pause file {}", path.display());
        }
    }

    let mut capture = soma_client::SomaCapture::open(&args.soma)
        .with_context(|| format!("open Soma capture at {}", args.soma))?;
    eprintln!(
        "hear: soma={} {} Hz/{} sample frames; segmenter at {} Hz, model at {} Hz; \
         out={} emb={}",
        args.soma,
        soma_client::SAMPLE_RATE,
        soma_client::FRAME_SAMPLES,
        CAPTURE_RATE,
        HEAR_RATE,
        shared.out.display(),
        shared.emb_dir.display()
    );

    let mut segmenter = Segmenter::new(CAPTURE_RATE, VadConfig::default());
    // The mouth's last audible window, for the self-echo heuristic. `hear`
    // learns it from the pause file's lifetime: the file exists exactly while
    // the mouth may be audible.
    let mut spoke: Option<SpeechWindow> = None;
    let mut pause_since: Option<u64> = None;
    let mut kept = 0usize;

    loop {
        // Reading the next record IS the clock. Never a sleep, never a second
        // timer, and never a device close.
        let frame = capture.next_frame()?;

        let held = args
            .pause_file
            .as_deref()
            .map(turntaking::paused)
            .unwrap_or(false);
        if held {
            // SOFTWARE-ONLY HOLD. The stream stays open and we keep reading;
            // the samples are discarded. Closing a Bluetooth mic flips the
            // endpoint between its handsfree and high-quality profiles and
            // chops speech mid-sentence, so the hold stops the model, never
            // the person.
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

        let mut segments: Vec<Segment> = Vec::new();
        segmenter.push(&frame.samples, &mut |s| segments.push(s));
        for segment in segments {
            if handle_segment(&ears, &shared, &filter, &segment, "soma", spoke)? {
                kept += 1;
                if args.limit > 0 && kept >= args.limit {
                    println!("{kept} utterance(s) embedded — limit reached");
                    return Ok(());
                }
            }
        }
    }
}

/// One segment → maybe one embedding record. `Ok(true)` = handed over.
fn handle_segment(
    ears: &Ears,
    shared: &Shared,
    filter: &SpeechFilter,
    segment: &Segment,
    source: &str,
    spoke: Option<SpeechWindow>,
) -> Result<bool> {
    let utc_ms = now_ms()?;
    let dur_s = segment.dur_s();

    // The audio-only half of the filter runs FIRST, so a blip or our own echo
    // never pays for the audio tower.
    if let Some(reason) = turntaking::audio_drop_reason(dur_s, utc_ms, filter, spoke) {
        println!("[heard ] ({dur_s:.2}s) → DROPPED: {reason}");
        append_record(
            &shared.out,
            &serde_json::json!({
                "utc_ms": utc_ms, "source": source,
                "start_s": segment.start_s, "end_s": segment.end_s, "dur_s": dur_s,
                "dropped": reason,
            }),
        );
        return Ok(false);
    }

    // ONE resample per utterance, on a contiguous buffer — never per frame.
    let wave = to_hear_rate(&segment.samples, segment.rate)?;
    let heard = ears.hear(&wave, shared);

    // The text half only has meaning once a transcript exists. THE
    // PROMPT-PARROT CASE IS WHY IT EXISTS: on empty or AEC-suppressed audio a
    // decoder parrots its own prompt back, and without this a silent room
    // makes the bot recite its instructions aloud.
    if let Some(text) = &heard.text {
        let utterance = turntaking::Utterance {
            text,
            prompt: &shared.prompt,
            utc_ms,
            dur_s,
        };
        if let Some(reason) = turntaking::drop_reason(&utterance, filter, spoke) {
            println!("[heard ] {text:?} ({dur_s:.2}s) → DROPPED: {reason}");
            append_record(
                &shared.out,
                &serde_json::json!({
                    "utc_ms": utc_ms, "source": source,
                    "start_s": segment.start_s, "end_s": segment.end_s, "dur_s": dur_s,
                    "text": text, "dropped": reason,
                }),
            );
            return Ok(false);
        }
    }

    let emb_path = shared
        .emb_dir
        .join(format!("utt_{utc_ms}_{:.0}ms.f32", dur_s * 1000.0));
    write_rows(&emb_path, &heard.rows)?;

    match &heard.text {
        Some(text) => println!(
            "[heard ] {text:?} ({dur_s:.2}s) → {} × {} embeddings",
            heard.n_tokens, heard.hidden
        ),
        None => println!(
            "[heard ] ({dur_s:.2}s) → {} × {} embeddings",
            heard.n_tokens, heard.hidden
        ),
    }
    append_record(
        &shared.out,
        &serde_json::json!({
            "utc_ms": utc_ms, "source": source,
            "start_s": segment.start_s, "end_s": segment.end_s, "dur_s": dur_s,
            "rate": HEAR_RATE,
            "n_tokens": heard.n_tokens, "hidden": heard.hidden,
            "dtype": "f32le", "layout": "row-major", "emb": emb_path.display().to_string(),
            "text": heard.text,
        }),
    );
    Ok(true)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn now_ms() -> Result<u64> {
    Ok(clock::now()?.to_unix_milliseconds() as u64)
}

fn append_record(path: &Path, record: &serde_json::Value) {
    use std::io::Write as _;
    let line = format!("{record}\n");
    if let Err(e) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut f| f.write_all(line.as_bytes()))
    {
        eprintln!("(utterance log append failed: {e})");
    }
}

/// Raw little-endian f32, row-major — the same layout `AudioEmbeddings::rows`
/// has in memory, so a consumer is one `read` and one reshape away.
fn write_rows(path: &Path, rows: &[f32]) -> Result<()> {
    use std::io::Write as _;
    let mut bytes = Vec::with_capacity(rows.len() * 4);
    for value in rows {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    let mut file =
        std::fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

#[cfg(feature = "hear")]
fn load_16k(path: &Path) -> Result<Vec<f32>> {
    mary::models::gemma::gemma4::audio_load::load_audio_16k_mono(path)
        .map_err(|e| anyhow::anyhow!("decode {}: {e}", path.display()))
}

#[cfg(not(feature = "hear"))]
fn load_16k(_path: &Path) -> Result<Vec<f32>> {
    bail!("hear was built without the `hear` feature")
}

/// Resample one FINISHED utterance to the model's rate. Called once per
/// utterance on a contiguous buffer, which is the shape `resample_to_16k`
/// expects: it builds a fresh stateless resampler per call, so a per-frame
/// caller would get a discontinuity and a startup-delay loss at every frame.
#[cfg(feature = "hear")]
fn to_hear_rate(samples: &[f32], rate: usize) -> Result<Vec<f32>> {
    if rate == HEAR_RATE {
        return Ok(samples.to_vec());
    }
    mary::models::gemma::gemma4::audio_load::resample_to_16k(samples.to_vec(), rate)
        .map_err(|e| anyhow::anyhow!("resample {rate} Hz utterance to {HEAR_RATE} Hz: {e}"))
}

#[cfg(not(feature = "hear"))]
fn to_hear_rate(_samples: &[f32], _rate: usize) -> Result<Vec<f32>> {
    bail!("hear was built without the `hear` feature")
}

// ---------------------------------------------------------------------------
// The hardware-free gate for everything below the capture seam
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// `secs` of a 220 Hz tone at `amp`, at the segmenter's rate.
    fn tone(secs: f32, amp: f32) -> Vec<f32> {
        let n = (HEAR_RATE as f32 * secs) as usize;
        (0..n)
            .map(|i| amp * (i as f32 * 2.0 * std::f32::consts::PI * 220.0 / HEAR_RATE as f32).sin())
            .collect()
    }

    fn silence(secs: f32) -> Vec<f32> {
        vec![0.0; (HEAR_RATE as f32 * secs) as usize]
    }

    fn segment_all(chunks: &[Vec<f32>]) -> Vec<Segment> {
        // Recorded clips are decoded straight to 16 kHz, so the segmenter runs
        // at the model's rate and no resample is needed at all.
        let mut segmenter = Segmenter::new(HEAR_RATE, VadConfig::default());
        let mut out = Vec::new();
        for chunk in chunks {
            segmenter.push(chunk, &mut |s| out.push(s));
        }
        segmenter.flush(&mut |s| out.push(s));
        out
    }

    #[test]
    fn two_bursts_separated_by_silence_are_two_utterances() {
        let segments = segment_all(&[
            silence(1.0),
            tone(1.2, 0.3),
            silence(1.2),
            tone(1.0, 0.3),
            silence(1.2),
        ]);
        assert_eq!(segments.len(), 2, "one utterance per burst");
        assert!(segments[0].dur_s() > 0.6, "{:?}", segments[0].dur_s());
        assert!(
            segments[1].start_s > segments[0].end_s,
            "utterance clocks must advance monotonically"
        );
        // Timestamps are stream-relative: the second burst starts around 3.4 s.
        assert!(
            (segments[1].start_s - 3.4).abs() < 0.5,
            "second utterance at {:.2}s",
            segments[1].start_s
        );
    }

    /// Why the filter's `min_dur_s` exists on TOP of the segmenter's
    /// `min_utt_ms`, and why its default is 0.6 s.
    ///
    /// The segmenter's own minimum measures the PADDED segment: 240 ms of
    /// pre-roll (so a soft onset is not clipped) plus the speech plus the
    /// ~200 ms hangover tail it keeps. A 50 ms click therefore comes out as
    /// roughly half a second of audio and sails past `min_utt_ms = 300`. That
    /// is the "sub-second blips trigger the VAD; 0.46 s ones observed" note
    /// `converse` shipped with -- 0.46 s is padding, not speech. The audio-only
    /// filter is what actually catches it, before the audio tower is paid for.
    #[test]
    fn a_click_survives_the_segmenter_and_is_caught_by_the_filter() {
        let segments = segment_all(&[silence(1.0), tone(0.05, 0.4), silence(1.2)]);
        assert_eq!(segments.len(), 1, "the segmenter does emit the padded blip");
        let dur = segments[0].dur_s();
        assert!(
            (0.3..0.6).contains(&dur),
            "a click comes out as padding-sized, got {dur:.2}s"
        );
        let filter = SpeechFilter::default();
        assert_eq!(
            turntaking::audio_drop_reason(dur, 0, &filter, None),
            Some("too-short-segment"),
            "{dur:.2}s must not reach the model"
        );
        // ...and real speech still gets through the same filter.
        let real = segment_all(&[silence(1.0), tone(1.2, 0.3), silence(1.2)]);
        assert_eq!(real.len(), 1);
        assert_eq!(
            turntaking::audio_drop_reason(real[0].dur_s(), 0, &filter, None),
            None
        );
    }

    /// The half-duplex hold, from the ears' side: audio that arrives while the
    /// mouth is speaking is DISCARDED, and the open utterance is abandoned as
    /// presumed self-echo. Nothing here closes a stream — the clock advances
    /// through the hold so later timestamps stay stream-relative.
    #[test]
    fn a_pause_discards_our_own_voice_without_stopping_the_clock() {
        // Recorded clips are decoded straight to 16 kHz, so the segmenter runs
        // at the model's rate and no resample is needed at all.
        let mut segmenter = Segmenter::new(HEAR_RATE, VadConfig::default());
        let mut heard = Vec::new();
        segmenter.push(&silence(1.0), &mut |s| heard.push(s));
        // Speech starts...
        segmenter.push(&tone(0.5, 0.3), &mut |s| heard.push(s));
        // ...and the mouth opens. Everything from here is our own voice.
        let held = tone(2.0, 0.3);
        segmenter.pause_skip(held.len() as u64);
        segmenter.push(&silence(1.2), &mut |s| heard.push(s));
        segmenter.flush(&mut |s| heard.push(s));
        assert!(
            heard.is_empty(),
            "self-echo must not reach the model: {} utterance(s)",
            heard.len()
        );

        // The stream clock still advanced across the hold, so the next real
        // utterance is stamped where it actually happened.
        segmenter.push(&tone(1.2, 0.3), &mut |s| heard.push(s));
        segmenter.push(&silence(1.2), &mut |s| heard.push(s));
        assert_eq!(heard.len(), 1);
        assert!(
            heard[0].start_s > 3.0,
            "clock must survive the hold, got {:.2}s",
            heard[0].start_s
        );
    }

    /// The live segmenter runs at the CAPTURE rate, so a Soma frame is a whole
    /// number of segmenter samples with nothing resampled on the hot path and
    /// nothing to drift. Only the finished utterance is resampled.
    #[test]
    fn the_capture_frame_and_the_segmenter_agree_on_the_clock() {
        assert_eq!(CAPTURE_RATE, soma_client::SAMPLE_RATE as usize);
        assert_eq!(
            soma_client::FRAME_SAMPLES as u32 * 1_000 / soma_client::SAMPLE_RATE,
            soma_client::FRAME_MS
        );
        // One capture frame advances the 20 ms VAD frame exactly four times.
        let cfg = VadConfig::default();
        let vad_frame = CAPTURE_RATE * cfg.frame_ms / 1000;
        assert_eq!(soma_client::FRAME_SAMPLES % vad_frame, 0);
        assert_eq!(soma_client::FRAME_SAMPLES / vad_frame, 4);
    }

    /// A capture-rate utterance is resampled ONCE, whole, and comes out the
    /// right length — the property a per-frame resample would break.
    #[test]
    #[cfg(feature = "hear")]
    fn a_finished_utterance_resamples_to_the_model_rate_in_one_piece() {
        let secs = 1.5f64;
        let at_capture: Vec<f32> = (0..(CAPTURE_RATE as f64 * secs) as usize)
            .map(|i| {
                (i as f32 * 2.0 * std::f32::consts::PI * 220.0 / CAPTURE_RATE as f32).sin() * 0.3
            })
            .collect();
        let at_model = to_hear_rate(&at_capture, CAPTURE_RATE).unwrap();
        let expected = (HEAR_RATE as f64 * secs) as usize;
        // MEASURED (2026-08-27, mary's `resample_to_16k`, 1.5 s at 24 kHz ->
        // 16 kHz): 23828 of an expected 24000, i.e. ~172 samples / ~11 ms
        // short. That is the resampler's own startup delay, which the helper
        // skips from the FRONT without extending the tail, so the loss lands
        // at the END of the utterance -- inside the VAD's ~200 ms hangover
        // tail, which is why it is harmless here. It is also constant per
        // CALL, which is the whole reason this runs once per utterance
        // instead of once per 80 ms frame: per frame it would be ~11 ms lost
        // out of every 80 ms.
        assert!(
            at_model.len() <= expected,
            "resampling must never invent audio: {} > {expected}",
            at_model.len()
        );
        assert!(
            expected - at_model.len() < 300,
            "{} samples, expected ~{expected} (startup-delay loss should stay \
             under ~20 ms)",
            at_model.len()
        );
        // Already at the model rate: an identity, not a round trip through the
        // resampler.
        let same = to_hear_rate(&at_model, HEAR_RATE).unwrap();
        assert_eq!(same, at_model);
    }
}
