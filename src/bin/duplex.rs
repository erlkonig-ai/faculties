//! duplex — a continuously running spoken channel driven by ONE streaming
//! speech model, with a transcript an agent reads from and injects into.
//!
//! The half-duplex bridge (`converse`) chains three models and three
//! processes: a transcriber, a text model, a synthesizer. Every joint between
//! them is a place the conversation breaks, and each adds latency, so the
//! human waits seconds for a reply. This binary replaces the chain with a
//! single streaming speech-to-speech model (mary's PersonaPlex port) on its
//! own 80 ms frame clock: audio codes in, audio codes out, with the model's
//! inner-monologue text falling out of the same step as exhaust.
//!
//! ## The clock
//!
//! The model consumes and produces exactly one 80 ms frame (1920 samples at
//! 24 kHz) per step. THE MICROPHONE IS THE CLOCK: the loop blocks until the
//! capture device has produced the next full frame, so the conversation runs
//! at the pace of the physical device and never invents a second timer.
//!
//!   mic samples → streaming codec encode → LM step → agent codes → speaker
//!                                        ↘ stream-0 text → transcript
//!
//! Codec decode and playback run on their own thread, off the frame clock.
//!
//! ## The two operations an agent gets
//!
//! * `duplex read` — everything said since the cursor, attributed. Reading
//!   TAKES THE FLOOR: the model is held silent from that moment, so nothing is
//!   said that the reader has not seen. Reading does NOT advance the cursor,
//!   so a reader that dies mid-thought loses nothing.
//! * `duplex say <text>` — hand the model a line, release the floor, and
//!   advance the cursor past what was read. The model voices the line in its
//!   own timing and prosody; this is "here is something to say", never "emit
//!   these samples".
//!
//! `duplex release` gives the floor back without saying anything. The hold
//! carries a deadline so a reader that never comes back cannot mute the
//! channel forever.
//!
//! THE HOLD IS ONE-SIDED. It stops the model from speaking; it never stops
//! the microphone. The far end can talk over a hold and every word still
//! reaches the model — you cannot pause a person.
//!
//! ## The model is a mouth and a pair of ears, not a mind
//!
//! Left free, a conversational speech model will fill any silence with
//! plausible speech, and that speech would be attributed to whoever owns the
//! voice. So by default this loop FORCES the text stream to padding: the model
//! hears everything, may backchannel, and generates no words of its own. Words
//! arrive only by injection. `--floor converse` lifts that and lets the model
//! hold up its own end, which is a different product and should be a deliberate
//! choice.
//!
//! ## Where the frame budget goes (measured, and it does not yet fit)
//!
//! The budget is 80 ms per frame. Measured end to end on an M-series laptop,
//! 400-600 frame sessions, a named capture device driving the clock:
//! **p50 ~100 ms, p90 ~130-165 ms, p99 ~170-220 ms, i.e. 0.72-0.77x
//! realtime**, with ~70-97% of frames over budget. The loop stays CURRENT
//! rather than drifting — it discards capture backlog past
//! `MAX_BACKLOG_FRAMES` — but playback still starves, which is audible as
//! rebuffering inside a word.
//!
//! The reason is structural, not incidental. Of the four stages in a frame,
//! only the temporal transformer runs on the GPU; the depth transformer and
//! BOTH codec directions are host-CPU lanes in the model library today. The
//! model library's own budget model allots temporal ~15.6 ms (GPU) + depth
//! ~21.6 ms (CPU) + codec ~5 ms (CPU) + submission ~5 ms, so two thirds of
//! the budget is CPU work before contention. Adding the in-line streaming
//! codec encode to the loop moved the measured mean from ~74 ms to ~101 ms —
//! about 27 ms per frame for one CPU stage.
//!
//! So: this closes the loop and it is honest about its clock, but the path to
//! realtime is porting the depth transformer and the codec to the GPU, not
//! tuning anything here. `--decode-context` / `--decode-hop` are exposed
//! because the codec decoder has no streaming state and re-decodes its
//! context on every hop; they trade boundary artifacts against CPU load.
//!
//! ## Bluetooth handsfree channels, and why the stream is never closed
//!
//! On a handsfree (HFP) endpoint — a car kit, a headset — the duplex channel
//! exists only while something holds the microphone open. Close the input
//! stream to "take a turn" and the endpoint renegotiates: audio drops
//! mid-sentence and the far end hears nothing. The capture stream here is
//! opened once and NEVER closed for the life of the session; the floor is held
//! in software, never by touching the device.
//!
//! DEVICES ARE ADDRESSED BY NAME, NEVER BY INDEX AND NEVER VIA THE SYSTEM
//! DEFAULT. Connecting a Bluetooth endpoint renumbers the platform's device
//! list, so an index-addressed or default-addressed stream can land on a dead
//! virtual channel with nothing in the logs to say so. Opening the named
//! device IS the verification. `duplex devices` prints the exact names.
//!
//! ## What is in the transcript, and what cannot be
//!
//! The live transcript and the cursor are in memory, mirrored to an
//! append-only file in the session directory — the pile is never on the frame
//! clock. Completed model utterances are ALSO appended to the pile's Voice
//! collection as `shout` utterances, the same record `voice shout` writes, so
//! the durable conversation needs no new shape and any process can read it.
//!
//! THE FAR END'S WORDS ARE NOT IN IT. This model has ONE text stream and that
//! stream is its own inner monologue; it does not transcribe its interlocutor.
//! What the transcript can honestly carry for the far end is WHEN they spoke
//! and for how long, which it does. Words would need a transcription model,
//! which is a different seam and a different set of weights.
//!
//! ## Ceremony
//!
//! ```text
//! duplex devices
//! duplex run --weights <weights.pile> --voice-prompt <voice.pt> \
//!            --input '<exact input device name>' \
//!            --output '<exact output device name>'
//! # from anywhere, while it runs:
//! duplex read
//! duplex say 'the line to say'
//! ```

// Without the model runtime the agent-facing half of this binary still
// builds and works — read, say, release, status and device listing need no
// weights. The loop's own machinery is then compiled out, so silence the
// dead-code warnings it would otherwise raise about itself.
#![cfg_attr(not(feature = "duplex"), allow(dead_code))]

use std::collections::VecDeque;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

/// Samples in one model frame at 24 kHz (80 ms).
const FRAME_SAMPLES: usize = 1920;
/// The model's canonical sample rate.
const SAMPLE_RATE: u32 = 24_000;
/// Frame period.
const FRAME: Duration = Duration::from_millis(80);

/// How far the capture ring may run ahead before the loop discards the
/// backlog. The model's step count IS its clock, so a loop that falls behind
/// the world cannot catch up by stepping faster — it can only skip forward.
const MAX_BACKLOG_FRAMES: usize = 8;

/// Text-stream ids carrying no surface text: 0 EPAD, 1 BOS, 2 EOS, 3 PAD.
const N_TEXT_SPECIALS: i64 = 4;
const TEXT_PAD: i64 = 3;

/// Frames of unbroken padding that close an utterance.
const DEFAULT_UTTERANCE_GAP: usize = 10;
/// Frames above the speech floor before the far end counts as talking.
const VOICE_ONSET_FRAMES: usize = 3;
/// Frames below it before their turn counts as over.
const VOICE_RELEASE_FRAMES: usize = 12;
/// RMS below this is room noise, not speech.
const VOICE_FLOOR: f32 = 0.012;

const DEFAULT_SYSTEM: &str = "You are a warm, direct conversational partner. \
Keep replies short and spoken — no lists, no markdown. Answer in the language \
you were addressed in.";

const TRANSCRIPT_FILE: &str = "transcript.jsonl";
const CURSOR_FILE: &str = "cursor";
const HOLD_FILE: &str = "hold";
const INJECT_DIR: &str = "inject";
const RELEASE_FILE: &str = "release";

// ── CLI ────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "duplex",
    about = "A continuously running spoken channel with a transcript to read from and inject into."
)]
struct Cli {
    /// Session directory holding the transcript, cursor, floor and inject
    /// queue. One running loop per directory.
    #[arg(long, env = "DUPLEX_SESSION", global = true)]
    session: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// List the audio devices both directions can be addressed by, with the
    /// native configuration each offers. These exact names are what
    /// `run --input` / `run --output` expect.
    Devices,
    /// Run the channel until interrupted.
    Run(Box<RunArgs>),
    /// Show everything said since the cursor and TAKE THE FLOOR: the model
    /// stays silent until `say` or `release`. Does not advance the cursor.
    Read {
        /// Read without taking the floor — the model keeps talking.
        #[arg(long)]
        peek: bool,
        /// Show the whole transcript rather than only what is new.
        #[arg(long)]
        all: bool,
        /// Give the floor back automatically after this long.
        #[arg(long, default_value_t = 180)]
        hold_secs: u64,
    },
    /// Hand the model a line to say, release the floor, and advance the
    /// cursor past everything currently in the transcript.
    Say {
        /// The words to say.
        text: Vec<String>,
        /// Keep the floor held after saying it.
        #[arg(long)]
        keep_floor: bool,
    },
    /// Give the floor back without saying anything, and advance the cursor.
    Release {
        /// Leave the cursor where it is.
        #[arg(long)]
        keep_cursor: bool,
    },
    /// Report whether a loop is running, where the cursor sits, and who holds
    /// the floor.
    Status,
}

#[derive(clap::Args)]
struct RunArgs {
    /// Model weight pile.
    #[arg(long, env = "PERSONAPLEX_PILE")]
    weights: PathBuf,
    /// Packaged voice prompt the session speaks with.
    #[arg(long, env = "PERSONAPLEX_VOICE_PROMPT")]
    voice_prompt: PathBuf,
    /// EXACT name of the capture device. Held open for the whole session.
    #[arg(long)]
    input: String,
    /// EXACT name of the playback device.
    #[arg(long)]
    output: String,
    /// Weight format for the temporal stack.
    #[arg(long, default_value = "q4")]
    fmt: String,
    /// Whether the model may hold up its own end of the conversation.
    /// `listen` forces its text stream to padding, so it hears everything,
    /// may backchannel, and says only what is injected. `converse` lets it
    /// generate its own words.
    #[arg(long, default_value = "listen")]
    floor: String,
    /// Spoken system prompt.
    #[arg(long, default_value = DEFAULT_SYSTEM)]
    system: String,
    /// Sampling temperature; 0 selects greedy decoding.
    #[arg(long, default_value_t = 0.8)]
    temp: f32,
    /// Sampling seed.
    #[arg(long, default_value_t = 12_345_678)]
    seed: u64,
    /// Frames between forced text tokens, matching the speaking cadence of
    /// the text stream. One token per frame is out of distribution.
    #[arg(long, default_value_t = 2)]
    pace: usize,
    /// Feed the model digital silence on the input channel while it speaks,
    /// so an endpoint without echo cancellation does not hear itself.
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    gate: bool,
    /// Padding-only frames that close an utterance.
    #[arg(long, default_value_t = DEFAULT_UTTERANCE_GAP)]
    utterance_gap: usize,
    /// Pile to record the durable transcript on. Without it nothing is
    /// recorded beyond the session directory.
    #[arg(long, env = "PILE")]
    pile: Option<PathBuf>,
    /// Signing key for the transcript pile.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Stop after this many frames instead of running until interrupted.
    #[arg(long)]
    frames: Option<usize>,
    /// Also tee everything spoken to this WAV file.
    #[arg(long)]
    wav: Option<PathBuf>,
    /// Frames of context the codec decoder re-decodes on every hop.
    #[arg(long, default_value_t = DEFAULT_DECODE_CONTEXT)]
    decode_context: usize,
    /// New frames emitted per decode call.
    #[arg(long, default_value_t = DEFAULT_DECODE_HOP)]
    decode_hop: usize,
    /// Do not open the capture device; feed digital silence instead. For
    /// checking the model, the speaker and the transcript on a machine whose
    /// microphone is busy.
    #[arg(long)]
    no_input: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let session = cli.session.clone().unwrap_or_else(default_session);
    match cli.command {
        None => {
            use clap::CommandFactory;
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
        Some(Command::Devices) => cmd_devices(),
        Some(Command::Read {
            peek,
            all,
            hold_secs,
        }) => cmd_read(&session, peek, all, hold_secs),
        Some(Command::Say { text, keep_floor }) => {
            cmd_say(&session, &text.join(" "), keep_floor)
        }
        Some(Command::Release { keep_cursor }) => cmd_release(&session, keep_cursor),
        Some(Command::Status) => cmd_status(&session),
        Some(Command::Run(args)) => cmd_run(&session, *args),
    }
}

fn default_session() -> PathBuf {
    std::env::temp_dir().join("duplex")
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── the transcript file ────────────────────────────────────────────────────

/// Who said it. `model` is the model's own words, `agent` is a line handed to
/// it, `far` is the other end of the channel — for whom this model can report
/// presence and duration but not words.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Speaker {
    Model,
    Agent,
    Far,
}

impl Speaker {
    fn tag(self) -> &'static str {
        match self {
            Speaker::Model => "model",
            Speaker::Agent => "agent",
            Speaker::Far => "far",
        }
    }
}

#[derive(Clone, Debug)]
struct Line {
    seq: u64,
    at_ms: u64,
    speaker: String,
    text: String,
}

/// One line per entry, appended and flushed as it happens, so a reader in
/// another process always sees a whole line or nothing.
fn append_line(session: &Path, line: &Line) -> Result<()> {
    let path = session.join(TRANSCRIPT_FILE);
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    let record = serde_json::json!({
        "seq": line.seq,
        "at_ms": line.at_ms,
        "speaker": line.speaker,
        "text": line.text,
    });
    writeln!(file, "{record}")?;
    file.flush()?;
    Ok(())
}

fn read_lines(session: &Path) -> Result<Vec<Line>> {
    let path = session.join(TRANSCRIPT_FILE);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(Vec::new());
    };
    let mut lines = Vec::new();
    for raw in text.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
            continue;
        };
        lines.push(Line {
            seq: value.get("seq").and_then(|v| v.as_u64()).unwrap_or(0),
            at_ms: value.get("at_ms").and_then(|v| v.as_u64()).unwrap_or(0),
            speaker: value
                .get("speaker")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_owned(),
            text: value
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned(),
        });
    }
    Ok(lines)
}

fn read_cursor(session: &Path) -> u64 {
    std::fs::read_to_string(session.join(CURSOR_FILE))
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

fn write_cursor(session: &Path, seq: u64) -> Result<()> {
    let path = session.join(CURSOR_FILE);
    let staged = session.join(".cursor.tmp");
    std::fs::write(&staged, seq.to_string())?;
    std::fs::rename(&staged, &path)
        .with_context(|| format!("publish {}", path.display()))?;
    Ok(())
}

// ── the floor ──────────────────────────────────────────────────────────────

/// The hold is a file with a deadline in it — the same primitive the
/// half-duplex bridge used to keep its ears off its own mouth, here keeping
/// the model quiet while a reader catches up. A file survives the reader
/// dying; the deadline means the channel recovers when it does.
fn take_floor(session: &Path, hold_secs: u64) -> Result<()> {
    let deadline = now_millis() + hold_secs.saturating_mul(1_000);
    let staged = session.join(".hold.tmp");
    std::fs::write(&staged, deadline.to_string())?;
    std::fs::rename(&staged, session.join(HOLD_FILE))
        .context("publish the floor hold")?;
    let _ = std::fs::remove_file(session.join(RELEASE_FILE));
    Ok(())
}

fn floor_held(session: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(session.join(HOLD_FILE)) else {
        return false;
    };
    let deadline: u64 = text.trim().parse().unwrap_or(0);
    if now_millis() > deadline {
        // Expired holds are cleared by whoever notices, so a dead reader
        // cannot mute the channel indefinitely.
        let _ = std::fs::remove_file(session.join(HOLD_FILE));
        return false;
    }
    true
}

fn give_floor(session: &Path) -> Result<()> {
    let _ = std::fs::remove_file(session.join(HOLD_FILE));
    Ok(())
}

// ── the inject queue ───────────────────────────────────────────────────────

/// Queue one line. Written under a temporary name and renamed into place, so
/// the loop never observes a half-written file.
fn inject(session: &Path, text: &str) -> Result<PathBuf> {
    let dir = session.join(INJECT_DIR);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create {}", dir.display()))?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let staged = dir.join(format!(".{stamp}.tmp"));
    let published = dir.join(format!("{stamp}.txt"));
    std::fs::write(&staged, text)?;
    std::fs::rename(&staged, &published)
        .with_context(|| format!("publish {}", published.display()))?;
    Ok(published)
}

/// Take every complete line currently queued, oldest first.
fn drain_inject(session: &Path) -> Vec<String> {
    let dir = session.join(INJECT_DIR);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "txt"))
        .collect();
    files.sort();
    let mut lines = Vec::new();
    for path in files {
        if let Ok(text) = std::fs::read_to_string(&path) {
            let text = text.trim().to_owned();
            if !text.is_empty() {
                lines.push(text);
            }
        }
        let _ = std::fs::remove_file(&path);
    }
    lines
}

// ── the agent-facing commands ──────────────────────────────────────────────

fn ensure_session(session: &Path) -> Result<()> {
    std::fs::create_dir_all(session)
        .with_context(|| format!("create session directory {}", session.display()))?;
    std::fs::create_dir_all(session.join(INJECT_DIR))?;
    Ok(())
}

fn cmd_read(session: &Path, peek: bool, all: bool, hold_secs: u64) -> Result<()> {
    ensure_session(session)?;
    if !peek {
        // Take the floor FIRST: nothing may be said between the decision to
        // read and the read itself.
        take_floor(session, hold_secs)?;
    }
    let lines = read_lines(session)?;
    let cursor = read_cursor(session);
    let shown: Vec<&Line> = lines
        .iter()
        .filter(|line| all || line.seq > cursor)
        .collect();
    if shown.is_empty() {
        println!("(nothing new since cursor {cursor})");
    } else {
        for line in &shown {
            println!("[{}] {}", line.speaker, line.text);
        }
    }
    let last = lines.last().map(|line| line.seq).unwrap_or(cursor);
    if peek {
        println!("\ncursor {cursor}, transcript at {last} — floor not taken");
    } else {
        println!(
            "\ncursor {cursor}, transcript at {last} — FLOOR HELD for {hold_secs}s; \
             `duplex say <text>` or `duplex release` gives it back"
        );
    }
    Ok(())
}

fn cmd_say(session: &Path, text: &str, keep_floor: bool) -> Result<()> {
    let text = text.trim();
    if text.is_empty() {
        bail!("nothing to say");
    }
    ensure_session(session)?;
    let published = inject(session, text)?;
    // The cursor advances only once the reader has acted on what it read.
    let last = read_lines(session)?
        .last()
        .map(|line| line.seq)
        .unwrap_or_else(|| read_cursor(session));
    write_cursor(session, last)?;
    if keep_floor {
        println!("queued ({}), cursor at {last}, floor still held", published.display());
    } else {
        give_floor(session)?;
        println!("queued ({}), cursor at {last}, floor released", published.display());
    }
    Ok(())
}

fn cmd_release(session: &Path, keep_cursor: bool) -> Result<()> {
    ensure_session(session)?;
    give_floor(session)?;
    if keep_cursor {
        println!("floor released, cursor unchanged at {}", read_cursor(session));
    } else {
        let last = read_lines(session)?
            .last()
            .map(|line| line.seq)
            .unwrap_or_else(|| read_cursor(session));
        write_cursor(session, last)?;
        println!("floor released, cursor at {last}");
    }
    Ok(())
}

fn cmd_status(session: &Path) -> Result<()> {
    let lines = read_lines(session)?;
    let cursor = read_cursor(session);
    let last = lines.last().map(|line| line.seq).unwrap_or(0);
    println!("session   : {}", session.display());
    println!("transcript: {} lines, latest seq {last}", lines.len());
    println!("cursor    : {cursor} ({} unread)", last.saturating_sub(cursor));
    println!(
        "floor     : {}",
        if floor_held(session) {
            "HELD — the model is silent"
        } else {
            "free — the model may speak"
        }
    );
    let queued = std::fs::read_dir(session.join(INJECT_DIR))
        .map(|entries| entries.filter_map(|e| e.ok()).count())
        .unwrap_or(0);
    println!("queued    : {queued} line(s) waiting to be spoken");
    Ok(())
}

// ── device enumeration ─────────────────────────────────────────────────────

#[cfg(feature = "audio")]
fn cmd_devices() -> Result<()> {
    use rodio::cpal::traits::{DeviceTrait, HostTrait};
    let host = rodio::cpal::default_host();
    println!("capture devices (--input):");
    for device in host.input_devices().context("enumerate capture devices")? {
        let name = device.name().unwrap_or_else(|_| "<unnamed>".into());
        match device.default_input_config() {
            Ok(config) => println!(
                "  {name}\n      {} ch, {} Hz, {:?}",
                config.channels(),
                config.sample_rate(),
                config.sample_format()
            ),
            Err(error) => println!("  {name}\n      no usable input configuration: {error}"),
        }
    }
    println!("playback devices (--output):");
    for device in host.output_devices().context("enumerate playback devices")? {
        let name = device.name().unwrap_or_else(|_| "<unnamed>".into());
        match device.default_output_config() {
            Ok(config) => println!(
                "  {name}\n      {} ch, {} Hz, {:?}",
                config.channels(),
                config.sample_rate(),
                config.sample_format()
            ),
            Err(error) => println!("  {name}\n      no usable output configuration: {error}"),
        }
    }
    Ok(())
}

#[cfg(not(feature = "audio"))]
fn cmd_devices() -> Result<()> {
    bail!("audio device support is not compiled into this build (enable the `audio` feature)")
}

// ── capture: one stream, opened by name, never closed ──────────────────────

#[derive(Default)]
struct CaptureRing {
    samples: VecDeque<f32>,
    /// Frames discarded because the loop could not keep the device's pace.
    skipped: usize,
}

/// Owns the live capture stream. Dropping it closes the device, which is why
/// it is held for the whole session.
struct Capture {
    ring: Arc<Mutex<CaptureRing>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    device_rate: u32,
    channels: u16,
}

impl Capture {
    /// Pull exactly one frame, blocking on the device clock.
    fn next_frame(&self) -> Option<[f32; FRAME_SAMPLES]> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            {
                let mut ring = self.ring.lock().expect("capture ring");
                // Stay current: a backlog means the loop is slower than the
                // world, and the model cannot step faster to catch up.
                let backlog = ring.samples.len() / FRAME_SAMPLES;
                if backlog > MAX_BACKLOG_FRAMES {
                    let drop_frames = backlog - 2;
                    ring.samples.drain(..drop_frames * FRAME_SAMPLES);
                    ring.skipped += drop_frames;
                }
                if ring.samples.len() >= FRAME_SAMPLES {
                    let mut frame = [0.0f32; FRAME_SAMPLES];
                    for slot in frame.iter_mut() {
                        *slot = ring.samples.pop_front().expect("length checked");
                    }
                    return Some(frame);
                }
            }
            if self.stop.load(Ordering::Relaxed) || Instant::now() > deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(4));
        }
    }

    fn skipped(&self) -> usize {
        self.ring.lock().expect("capture ring").skipped
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(feature = "audio")]
fn open_capture(name: &str) -> Result<Capture> {
    use rodio::cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

    let host = rodio::cpal::default_host();
    let device = host
        .input_devices()
        .context("enumerate capture devices")?
        .find(|candidate| candidate.name().map(|n| n == name).unwrap_or(false))
        .with_context(|| format!("capture device '{name}' not found (disconnected?)"))?;
    let config = device
        .default_input_config()
        .with_context(|| format!("capture device '{name}' offers no input configuration"))?;
    let device_rate = config.sample_rate();
    let channels = config.channels();
    let sample_format = config.sample_format();
    let stream_config: rodio::cpal::StreamConfig = config.into();

    let ring: Arc<Mutex<CaptureRing>> = Arc::new(Mutex::new(CaptureRing::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let (ready_tx, ready_rx) = mpsc::channel::<std::result::Result<(), String>>();

    // Streams are !Send, so the stream is built and parked on its own thread
    // and stays there until the session ends.
    let thread = {
        let ring = Arc::clone(&ring);
        let stop = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("duplex-capture".into())
            .spawn(move || {
                let build = || -> Result<rodio::cpal::Stream> {
                    let mut resampler = Resampler::new(device_rate, SAMPLE_RATE);
                    let sink = Arc::clone(&ring);
                    let error_sink = |error| eprintln!("duplex: capture stream error: {error}");
                    let stream = match sample_format {
                        rodio::cpal::SampleFormat::F32 => device.build_input_stream(
                            &stream_config,
                            move |data: &[f32], _: &rodio::cpal::InputCallbackInfo| {
                                let mono = downmix(data, channels);
                                let mut out = Vec::with_capacity(mono.len());
                                resampler.push(&mono, &mut out);
                                if let Ok(mut ring) = sink.lock() {
                                    ring.samples.extend(out);
                                }
                            },
                            error_sink,
                            None,
                        ),
                        rodio::cpal::SampleFormat::I16 => device.build_input_stream(
                            &stream_config,
                            move |data: &[i16], _: &rodio::cpal::InputCallbackInfo| {
                                let scaled: Vec<f32> =
                                    data.iter().map(|v| *v as f32 / 32_768.0).collect();
                                let mono = downmix(&scaled, channels);
                                let mut out = Vec::with_capacity(mono.len());
                                resampler.push(&mono, &mut out);
                                if let Ok(mut ring) = sink.lock() {
                                    ring.samples.extend(out);
                                }
                            },
                            error_sink,
                            None,
                        ),
                        other => bail!("capture sample format {other:?} is not supported"),
                    };
                    stream.context("build capture stream")
                };
                match build() {
                    Ok(stream) => {
                        if let Err(error) = stream.play() {
                            let _ = ready_tx.send(Err(format!("start capture stream: {error}")));
                            return;
                        }
                        let _ = ready_tx.send(Ok(()));
                        // Hold the stream — and therefore the channel — open.
                        while !stop.load(Ordering::Relaxed) {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        drop(stream);
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(format!("{error:#}")));
                    }
                }
            })
            .context("spawn capture thread")?
    };

    match ready_rx.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(())) => {}
        Ok(Err(message)) => bail!("capture device '{name}': {message}"),
        Err(error) => bail!("capture device '{name}' did not start: {error}"),
    }
    Ok(Capture {
        ring,
        stop,
        thread: Some(thread),
        device_rate,
        channels,
    })
}

#[cfg(not(feature = "audio"))]
fn open_capture(_name: &str) -> Result<Capture> {
    bail!("audio device support is not compiled into this build (enable the `audio` feature)")
}

fn downmix(interleaved: &[f32], channels: u16) -> Vec<f32> {
    if channels <= 1 {
        return interleaved.to_vec();
    }
    let channels = channels as usize;
    interleaved
        .chunks_exact(channels)
        .map(|frame| frame.iter().sum::<f32>() / channels as f32)
        .collect()
}

fn rms(samples: &[f32]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    (samples.iter().map(|s| s * s).sum::<f32>() / samples.len() as f32).sqrt()
}

/// Linear rate conversion with a persistent fractional cursor, so successive
/// buffers join without a discontinuity. Handsfree capture is narrowband
/// already; the band this loses is not in the signal.
struct Resampler {
    ratio: f64,
    position: f64,
    last: f32,
    primed: bool,
}

impl Resampler {
    fn new(from: u32, to: u32) -> Self {
        Self {
            ratio: from as f64 / to as f64,
            position: 0.0,
            last: 0.0,
            primed: false,
        }
    }

    fn push(&mut self, input: &[f32], out: &mut Vec<f32>) {
        if input.is_empty() {
            return;
        }
        if (self.ratio - 1.0).abs() < f64::EPSILON {
            out.extend_from_slice(input);
            return;
        }
        if !self.primed {
            self.last = input[0];
            self.primed = true;
        }
        // `position` is in input samples with `last` sitting at index -1, so
        // it carries across buffer boundaries.
        while self.position < input.len() as f64 {
            let floor = self.position.floor();
            let fraction = (self.position - floor) as f32;
            let index = floor as isize;
            let a = if index < 0 {
                self.last
            } else {
                input[index as usize]
            };
            let b = input.get((index + 1).max(0) as usize).copied().unwrap_or(a);
            out.push(a + (b - a) * fraction);
            self.position += self.ratio;
        }
        self.position -= input.len() as f64;
        self.last = *input.last().expect("non-empty");
    }
}

// ── playback: decode away from the frame clock, sink opened by name ────────

/// Frames the decoder keeps as context so a chunk boundary is not audible.
/// The codec decoder has no streaming state, so context is re-decoded on
/// every hop: the decoder does `(context + hop) / hop` times realtime work.
/// At 25 and 2 that is 13.5x, which is why these are knobs and not constants.
const DEFAULT_DECODE_CONTEXT: usize = 8;
/// New frames emitted per decode call.
const DEFAULT_DECODE_HOP: usize = 4;
/// The model may lead the speaker by at most this much. Growing latency is a
/// fault to report, not something to hide in an unbounded queue.
const DECODE_QUEUE_FRAMES: usize = 16;
/// Frames buffered before playback starts. The model produces at realtime, so
/// this covers device start-up, not a production deficit.
const PREBUFFER_FRAMES: usize = 5;

#[cfg(feature = "duplex")]
type Codes = [u32; mary::models::personaplex::mimi::config::NUM_CODEBOOKS];

#[cfg(feature = "duplex")]
use std::sync::atomic::AtomicU64;
#[cfg(feature = "duplex")]
use std::sync::mpsc::{Receiver, TrySendError};

#[cfg(feature = "duplex")]
struct Mouth {
    frames: Option<SyncSender<Codes>>,
    worker: Option<std::thread::JoinHandle<Result<()>>>,
    dropped: Arc<AtomicU64>,
    underruns: Arc<AtomicU64>,
}

#[cfg(feature = "duplex")]
impl Mouth {
    fn spawn(
        weights: PathBuf,
        device: String,
        wav: Option<PathBuf>,
        context_frames: usize,
        hop_frames: usize,
    ) -> Result<Self> {
        let (frame_tx, frame_rx) = mpsc::sync_channel(DECODE_QUEUE_FRAMES);
        let (ready_tx, ready_rx) = mpsc::channel::<std::result::Result<(), String>>();
        let dropped = Arc::new(AtomicU64::new(0));
        let underruns = Arc::new(AtomicU64::new(0));
        let worker = {
            let underruns = Arc::clone(&underruns);
            std::thread::Builder::new()
                .name("duplex-mouth".into())
                .spawn(move || {
                    mouth_worker(
                        weights,
                        device,
                        wav,
                        frame_rx,
                        ready_tx,
                        underruns,
                        context_frames,
                        hop_frames,
                    )
                })
                .context("spawn playback thread")?
        };
        match ready_rx.recv_timeout(Duration::from_secs(900)) {
            Ok(Ok(())) => {}
            Ok(Err(message)) => bail!("playback: {message}"),
            Err(error) => bail!("playback did not come up: {error}"),
        }
        Ok(Self {
            frames: Some(frame_tx),
            worker: Some(worker),
            dropped,
            underruns,
        })
    }

    fn push(&self, codes: Codes) {
        let Some(sender) = self.frames.as_ref() else {
            return;
        };
        if let Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) =
            sender.try_send(codes)
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn underruns(&self) -> u64 {
        self.underruns.load(Ordering::Relaxed)
    }

    fn finish(mut self) -> Result<()> {
        self.frames.take();
        match self.worker.take() {
            Some(worker) => match worker.join() {
                Ok(result) => result,
                Err(_) => bail!("playback thread panicked"),
            },
            None => Ok(()),
        }
    }
}

#[cfg(feature = "duplex")]
#[allow(clippy::too_many_arguments)]
fn mouth_worker(
    weights: PathBuf,
    device_name: String,
    wav: Option<PathBuf>,
    frames: Receiver<Codes>,
    ready: mpsc::Sender<std::result::Result<(), String>>,
    underruns: Arc<AtomicU64>,
    context_frames: usize,
    hop_frames: usize,
) -> Result<()> {
    use mary::models::personaplex::mimi::config as codec_cfg;
    use mary::models::personaplex::mimi::MimiDecoder;
    use rodio::buffer::SamplesBuffer;
    use std::num::NonZero;

    set_interactive_qos();
    let setup = || -> Result<(MimiDecoder, rodio::MixerDeviceSink, rodio::Player)> {
        let loader = mary::persist::personaplex_loader(&weights)
            .with_context(|| format!("load the codec from {}", weights.display()))?;
        let decoder = MimiDecoder::load(&loader);
        // Pay the first-call allocation before the session is live.
        let _ = decoder.decode(&vec![
            [0; codec_cfg::NUM_CODEBOOKS];
            context_frames + hop_frames
        ]);
        let (sink, player) = open_named_sink(&device_name)?;
        Ok((decoder, sink, player))
    };
    let (decoder, _sink, player) = match setup() {
        Ok(value) => {
            let _ = ready.send(Ok(()));
            value
        }
        Err(error) => {
            let _ = ready.send(Err(format!("{error:#}")));
            return Err(error);
        }
    };

    let mono = NonZero::new(1u16).expect("1 is nonzero");
    let rate = NonZero::new(SAMPLE_RATE).expect("24000 is nonzero");
    let mut receipt = wav.map(WavWriter::create).transpose()?;
    let mut history: VecDeque<Codes> = VecDeque::new();
    let mut pending = 0usize;
    let mut emitted = 0usize;
    let mut started = false;

    player.pause();
    let mut emit = |history: &VecDeque<Codes>, pending: usize| {
        let chunk: Vec<Codes> = history.iter().copied().collect();
        let context = chunk.len() - pending;
        let pcm = decoder.decode(&chunk);
        let from = context * FRAME_SAMPLES;
        let to = (from + pending * FRAME_SAMPLES).min(pcm.len());
        let slice = pcm[from..to].to_vec();
        if let Some(receipt) = receipt.as_mut() {
            let _ = receipt.write(&slice);
        }
        player.append(SamplesBuffer::new(mono, rate, slice));
    };

    while let Ok(frame) = frames.recv() {
        history.push_back(frame);
        pending += 1;
        if pending < hop_frames {
            continue;
        }
        // An empty queue after playback started means the decoder fell behind
        // the device — the rebuffering stutter, counted rather than hidden.
        if started && player.empty() {
            underruns.fetch_add(1, Ordering::Relaxed);
        }
        emit(&history, pending);
        emitted += pending;
        pending = 0;
        while history.len() > context_frames {
            history.pop_front();
        }
        if !started && emitted >= PREBUFFER_FRAMES {
            player.play();
            started = true;
        }
    }
    if pending > 0 {
        emit(&history, pending);
    }
    if !started {
        player.play();
    }
    // Let the device drain rather than cutting the last words.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !player.empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(receipt);
    Ok(())
}

#[cfg(feature = "audio")]
fn open_named_sink(name: &str) -> Result<(rodio::MixerDeviceSink, rodio::Player)> {
    use rodio::cpal::traits::{DeviceTrait, HostTrait};
    let host = rodio::cpal::default_host();
    let device = host
        .output_devices()
        .context("enumerate playback devices")?
        .find(|candidate| candidate.name().map(|n| n == name).unwrap_or(false))
        .with_context(|| format!("playback device '{name}' not found (disconnected?)"))?;
    let mut sink = rodio::DeviceSinkBuilder::from_device(device)
        .with_context(|| format!("prepare playback device '{name}'"))?
        .open_stream()
        .with_context(|| format!("open playback device '{name}'"))?;
    let player = rodio::Player::connect_new(sink.mixer());
    sink.log_on_drop(false);
    Ok((sink, player))
}

// ── the durable transcript ─────────────────────────────────────────────────

/// Appends completed model utterances to the pile's Voice collection, off the
/// frame clock. A slow or failing pile delays the ledger, never the audio.
struct Ledger {
    lines: Option<SyncSender<String>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Ledger {
    fn spawn(pile: Option<PathBuf>, key: Option<PathBuf>) -> Self {
        let Some(pile) = pile else {
            return Self {
                lines: None,
                worker: None,
            };
        };
        let (tx, rx) = mpsc::sync_channel::<String>(64);
        let worker = std::thread::Builder::new()
            .name("duplex-ledger".into())
            .spawn(move || {
                while let Ok(text) = rx.recv() {
                    if let Err(error) = record_utterance(&pile, key.as_deref(), &text) {
                        eprintln!("duplex: could not record utterance: {error:#}");
                    }
                }
            })
            .ok();
        Self {
            lines: Some(tx),
            worker,
        }
    }

    fn record(&self, text: &str) {
        if let Some(lines) = self.lines.as_ref() {
            let _ = lines.try_send(text.to_owned());
        }
    }

    fn finish(mut self) {
        self.lines.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// One utterance, one commit — the exact record shape `voice shout` writes, so
/// nothing that reads the collection has to learn a new one.
fn record_utterance(pile_path: &Path, key: Option<&Path>, text: &str) -> Result<()> {
    use faculties::legacy_hint::open_scope;
    use faculties::schemas::voice::{CHANNEL_SHOUT, COLLECTION_SCOPE_ID};
    use faculties::storage::{load_signer, open_pile_strict};
    use hifitime::Epoch;
    use triblespace::core::metadata;
    use triblespace::prelude::*;

    let now = Epoch::now().unwrap_or(Epoch::from_unix_seconds(0.0));
    let stamp: Inline<inlineencodings::NsTAIInterval> =
        (now, now).try_to_inline().expect("valid TAI interval");
    let fragment = faculties::voice::utterance_fragment(CHANNEL_SHOUT, text, None, stamp)?;

    let signer = load_signer(pile_path, key)?;
    let pile = open_pile_strict(pile_path)?;
    let mut collection = open_scope(pile, COLLECTION_SCOPE_ID, signer);
    let result = (|| -> Result<()> {
        let facts = collection
            .materialize()
            .context("materialize the Voice collection")?;
        let reader = collection
            .storage_mut()
            .reader()
            .context("open the Voice attachment reader")?;
        faculties::voice::validate_candidate(&reader, &facts, &fragment)?;
        let mut described = fragment.clone();
        described.describe_with(entity! { metadata::description: "duplex spoke" });
        collection.commit(described).context("commit the utterance")?;
        Ok(())
    })();
    let pile = collection.into_storage();
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) => Err(error.context("close the transcript pile")),
        (Err(error), _) => Err(error),
    }
}

// ── the loop ───────────────────────────────────────────────────────────────

#[cfg(not(feature = "duplex"))]
fn cmd_run(_session: &Path, _args: RunArgs) -> Result<()> {
    bail!("the channel is not compiled into this build (build with --features duplex)")
}

/// What the model is allowed to do with its own text stream.
#[cfg(feature = "duplex")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Floor {
    /// Text stream forced to padding: it hears, it may backchannel, it
    /// generates no words. Words arrive only by injection.
    Listen,
    /// The model holds up its own end.
    Converse,
}

#[cfg(feature = "duplex")]
fn cmd_run(session: &Path, args: RunArgs) -> Result<()> {
    use mary::models::personaplex::config as model_cfg;
    use mary::models::personaplex::pipeline::{agent_codes, RealtimePipeline, SILENCE};
    use mary::models::personaplex::prompt::Prompt;
    use mary::models::personaplex::sampling::SamplingConfig;
    use mary::models::personaplex::temporal_metal::WeightFmt;

    let fmt = match args.fmt.as_str() {
        "q4" => WeightFmt::Q4,
        "q8" => WeightFmt::Q8,
        "f16" => WeightFmt::F16,
        other => bail!("unknown weight format {other} (expected q4, q8 or f16)"),
    };
    let floor_policy = match args.floor.as_str() {
        "listen" => Floor::Listen,
        "converse" => Floor::Converse,
        other => bail!("unknown floor policy {other} (expected listen or converse)"),
    };
    ensure_session(session)?;
    // A fresh run starts a fresh transcript; the durable copy is the pile.
    let _ = std::fs::remove_file(session.join(TRANSCRIPT_FILE));
    let _ = std::fs::remove_file(session.join(HOLD_FILE));
    write_cursor(session, 0)?;

    set_interactive_qos();

    // The mouth loads its own codec while the model loads, so the two long
    // loads overlap instead of queueing.
    println!("duplex: bringing up '{}' …", args.output);
    let mouth = Mouth::spawn(
        args.weights.clone(),
        args.output.clone(),
        args.wav.clone(),
        args.decode_context,
        args.decode_hop,
    )?;

    println!("duplex: loading the model from {} …", args.weights.display());
    let load_start = Instant::now();
    let source = mary::persist::personaplex_bundle(&args.weights)
        .with_context(|| format!("load the model from {}", args.weights.display()))?
        .into_runtime_source();
    let mut pipeline = RealtimePipeline::load_auto(&source, fmt, true);
    if args.temp <= 0.0 {
        pipeline.set_greedy();
    } else {
        pipeline.set_sampling(
            SamplingConfig {
                temp: args.temp,
                top_k: 250,
                top_p: 0.95,
            },
            args.seed,
        );
    }
    let spm = mary::persist::load_spm_tokenizer_from_pile(&args.weights)
        .context("load the text tokenizer from the weight pile")?;
    if spm.vocab_size() != model_cfg::TEXT_CARD {
        bail!(
            "tokenizer vocabulary {} does not match the model's {} — wrong tokenizer",
            spm.vocab_size(),
            model_cfg::TEXT_CARD
        );
    }
    let prompt = Prompt::build(&args.voice_prompt, &spm, &args.system);
    pipeline.run_prompt(&prompt);
    println!(
        "duplex: model ready in {:.1}s ({} prompt steps)",
        load_start.elapsed().as_secs_f64(),
        prompt.total_steps()
    );

    // The capture stream is opened last and held for the whole session. On a
    // handsfree endpoint this open IS the channel.
    let capture = if args.no_input {
        println!("duplex: no capture device requested — feeding silence");
        None
    } else {
        println!("duplex: opening '{}' …", args.input);
        let capture = open_capture(&args.input)?;
        println!(
            "duplex: capture open — {} ch at {} Hz, held for the session",
            capture.channels, capture.device_rate
        );
        Some(capture)
    };

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&stop);
        let _ = ctrlc::set_handler(move || stop.store(true, Ordering::Relaxed));
    }

    let ledger = Ledger::spawn(args.pile.clone(), args.key.clone());
    let mut encoder_state = pipeline.encoder.stream_state();
    let mut queued: VecDeque<i64> = VecDeque::new();
    let mut injected_text: VecDeque<String> = VecDeque::new();
    let mut pace_countdown = 0usize;
    let mut spoken = String::new();
    let mut spoken_was_injected = false;
    let mut pad_run = 0usize;
    let mut speaking_hangover = 0usize;

    let mut seq = 0u64;
    let mut held = false;
    let mut far_loud = 0usize;
    let mut far_quiet = 0usize;
    let mut far_talking = false;
    let mut far_started_ms = 0u64;
    let mut heard_peak = 0f32;
    let mut heard_total = 0f64;
    let mut heard_frames = 0usize;

    let mut frame_index = 0usize;
    let mut step_total = 0f64;
    let mut step_max = 0f64;
    let mut over_budget = 0usize;
    let mut step_times: Vec<f64> = Vec::new();
    let mut frame_wall = Instant::now();
    let mut last_control_poll = Instant::now();

    println!("duplex: live. `duplex read` to catch up, `duplex say` to speak, Ctrl-C to stop.");
    let session_start = Instant::now();
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if let Some(limit) = args.frames {
            if frame_index >= limit {
                break;
            }
        }

        // The control plane is polled four times a second, far below the pace
        // anything can be spoken at, and never on the frame's critical path.
        if last_control_poll.elapsed() >= Duration::from_millis(250) {
            last_control_poll = Instant::now();
            let now_held = floor_held(session);
            if now_held != held {
                println!(
                    "duplex: floor {}",
                    if now_held { "TAKEN — silent" } else { "released" }
                );
                held = now_held;
            }
            for line in drain_inject(session) {
                println!("duplex: to say — {line}");
                queued.extend(spm.encode(&line));
                injected_text.push_back(line);
            }
        }

        // THE MICROPHONE IS THE CLOCK.
        let samples = match capture.as_ref() {
            Some(capture) => match capture.next_frame() {
                Some(frame) => Some(frame),
                None => {
                    eprintln!("duplex: capture stopped producing frames");
                    break;
                }
            },
            None => {
                // No device means no device clock. Pace the synthetic one to
                // the frame period MINUS the work already done, or the loop
                // is non-realtime by construction and every downstream
                // starvation number is an artifact of this sleep.
                let spent = frame_wall.elapsed();
                if spent < FRAME {
                    std::thread::sleep(FRAME - spent);
                }
                None
            }
        };
        frame_wall = Instant::now();

        // The far end's turn structure is the only thing this model can
        // honestly report about them: presence and duration, never words.
        if let Some(frame) = samples.as_ref() {
            let level = rms(frame);
            heard_peak = heard_peak.max(level);
            heard_total += level as f64;
            heard_frames += 1;
            if level >= VOICE_FLOOR {
                far_loud += 1;
                far_quiet = 0;
            } else {
                far_quiet += 1;
                far_loud = 0;
            }
            let _ = level;
            if !far_talking && far_loud >= VOICE_ONSET_FRAMES {
                far_talking = true;
                far_started_ms = now_millis();
            } else if far_talking && far_quiet >= VOICE_RELEASE_FRAMES {
                far_talking = false;
                let seconds = (now_millis().saturating_sub(far_started_ms)) as f64 / 1000.0;
                seq += 1;
                let line = Line {
                    seq,
                    at_ms: far_started_ms,
                    speaker: Speaker::Far.tag().into(),
                    text: format!("[spoke for {seconds:.1}s — no transcription available]"),
                };
                let _ = append_line(session, &line);
            }
        }

        let step_start = Instant::now();
        let heard: [i64; 8] = match samples {
            // While the model speaks, an endpoint without echo cancellation
            // would hear itself; gate in software, never by touching the
            // device.
            Some(_) if args.gate && speaking_hangover > 0 => SILENCE,
            Some(frame) => {
                let codes = pipeline
                    .encoder
                    .encode_stream_frame(&mut encoder_state, &frame);
                std::array::from_fn(|q| codes[q] as i64)
            }
            None => SILENCE,
        };

        // The three states of the mouth.
        //   held      — silent: text padded AND agent audio forced to silence.
        //   speaking  — the injected line, paced to the text stream's cadence.
        //   otherwise — the floor policy decides whether it may find its own
        //               words; under `listen` it may only backchannel.
        let (forced_text, forced_audio) = if held {
            (Some(TEXT_PAD), Some(&SILENCE))
        } else if !queued.is_empty() {
            if pace_countdown == 0 {
                pace_countdown = args.pace;
                (queued.pop_front(), None)
            } else {
                pace_countdown -= 1;
                (Some(TEXT_PAD), None)
            }
        } else {
            match floor_policy {
                Floor::Listen => (Some(TEXT_PAD), None),
                Floor::Converse => (None, None),
            }
        };
        let was_speaking_injected = !queued.is_empty() || pace_countdown > 0;

        let trace = pipeline.step(Some(&heard), forced_audio, forced_text);
        let elapsed = step_start.elapsed().as_secs_f64() * 1e3;
        step_total += elapsed;
        step_max = step_max.max(elapsed);
        step_times.push(elapsed);
        if elapsed > 80.0 {
            over_budget += 1;
        }

        if let Some(out) = trace.out.as_ref() {
            mouth.push(agent_codes(out));
            let token = out[0];
            if token >= N_TEXT_SPECIALS {
                let piece = spm.decode_token(token);
                if !piece.is_empty() {
                    spoken.push_str(&piece);
                    spoken_was_injected |= was_speaking_injected;
                    pad_run = 0;
                    speaking_hangover = args.utterance_gap;
                }
            } else {
                pad_run += 1;
                speaking_hangover = speaking_hangover.saturating_sub(1);
            }
        }

        // An utterance ends where the text stream goes quiet.
        if pad_run >= args.utterance_gap && !spoken.trim().is_empty() {
            let line = spoken.trim().to_owned();
            let speaker = if spoken_was_injected {
                Speaker::Agent
            } else {
                Speaker::Model
            };
            seq += 1;
            println!("  [{}] {line}", speaker.tag());
            let _ = append_line(
                session,
                &Line {
                    seq,
                    at_ms: now_millis(),
                    speaker: speaker.tag().into(),
                    text: line.clone(),
                },
            );
            ledger.record(&line);
            let _ = injected_text.pop_front();
            spoken.clear();
            spoken_was_injected = false;
            pad_run = 0;
        }

        frame_index += 1;
        if frame_index % 125 == 0 {
            let skipped = capture.as_ref().map(Capture::skipped).unwrap_or(0);
            println!(
                "  [clock] {:.1}s | step mean {:.1} ms max {:.1} ms | {} over budget | \
                 {} in skipped | {} out dropped | {} underruns | ear rms mean {:.4} peak {:.4}",
                session_start.elapsed().as_secs_f64(),
                step_total / frame_index as f64,
                step_max,
                over_budget,
                skipped,
                mouth.dropped(),
                mouth.underruns(),
                heard_total / heard_frames.max(1) as f64,
                heard_peak
            );
        }
    }

    // A turn still in progress at shutdown is still a turn. Without this the
    // far end talking right up to the end leaves no trace at all, which reads
    // as "they said nothing" rather than "we stopped listening".
    if far_talking {
        let seconds = (now_millis().saturating_sub(far_started_ms)) as f64 / 1000.0;
        seq += 1;
        let _ = append_line(
            session,
            &Line {
                seq,
                at_ms: far_started_ms,
                speaker: Speaker::Far.tag().into(),
                text: format!(
                    "[speaking for {seconds:.1}s when the session ended — no \
                     transcription available]"
                ),
            },
        );
    }
    if !spoken.trim().is_empty() {
        let line = spoken.trim().to_owned();
        seq += 1;
        println!("  [model] {line}");
        let _ = append_line(
            session,
            &Line {
                seq,
                at_ms: now_millis(),
                speaker: Speaker::Model.tag().into(),
                text: line.clone(),
            },
        );
        ledger.record(&line);
    }
    let wall = session_start.elapsed().as_secs_f64();
    step_times.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    let pct = |p: f64| -> f64 {
        if step_times.is_empty() {
            return 0.0;
        }
        let index = ((step_times.len() - 1) as f64 * p).round() as usize;
        step_times[index]
    };
    println!(
        "duplex: {} frames of audio in {:.1}s wall — {:.2}x realtime\n\
         \x20 step ms: p50 {:.1}  p90 {:.1}  p99 {:.1}  max {:.1}  mean {:.1} \
         (budget 80)\n\
         \x20 {} of {} frames over budget ({:.0}%), {} playback underruns",
        frame_index,
        wall,
        (frame_index as f64 * 0.08) / wall.max(1e-9),
        pct(0.50),
        pct(0.90),
        pct(0.99),
        step_max,
        step_total / frame_index.max(1) as f64,
        over_budget,
        frame_index,
        100.0 * over_budget as f64 / frame_index.max(1) as f64,
        mouth.underruns()
    );
    drop(capture);
    mouth.finish()?;
    ledger.finish();
    Ok(())
}

// ── odds and ends ──────────────────────────────────────────────────────────

/// Ask the scheduler for an interactive class. Without it the frame loop gets
/// parked on efficiency cores under load and its period swings several-fold.
fn set_interactive_qos() {
    #[cfg(target_os = "macos")]
    unsafe {
        extern "C" {
            fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
        }
        let _ = pthread_set_qos_class_self_np(0x21, 0);
    }
}

/// Minimal streaming mono WAV receipt.
struct WavWriter {
    file: std::fs::File,
    data_bytes: u32,
}

impl WavWriter {
    fn create(path: PathBuf) -> Result<Self> {
        let mut file =
            std::fs::File::create(&path).with_context(|| format!("create {}", path.display()))?;
        file.write_all(&wav_header(0))?;
        Ok(Self {
            file,
            data_bytes: 0,
        })
    }

    fn write(&mut self, samples: &[f32]) -> Result<()> {
        let mut bytes = Vec::with_capacity(samples.len() * 2);
        for sample in samples {
            let value = (sample.clamp(-1.0, 1.0) * i16::MAX as f32).round() as i16;
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        self.file.write_all(&bytes)?;
        self.data_bytes = self.data_bytes.saturating_add(bytes.len() as u32);
        Ok(())
    }
}

impl Drop for WavWriter {
    fn drop(&mut self) {
        use std::io::{Seek, SeekFrom};
        if self.file.seek(SeekFrom::Start(0)).is_ok() {
            let _ = self.file.write_all(&wav_header(self.data_bytes));
            let _ = self.file.flush();
        }
    }
}

fn wav_header(data_bytes: u32) -> Vec<u8> {
    let mut header = Vec::with_capacity(44);
    header.extend_from_slice(b"RIFF");
    header.extend_from_slice(&(36u32.saturating_add(data_bytes)).to_le_bytes());
    header.extend_from_slice(b"WAVEfmt ");
    header.extend_from_slice(&16u32.to_le_bytes());
    header.extend_from_slice(&1u16.to_le_bytes());
    header.extend_from_slice(&1u16.to_le_bytes());
    header.extend_from_slice(&SAMPLE_RATE.to_le_bytes());
    header.extend_from_slice(&(SAMPLE_RATE * 2).to_le_bytes());
    header.extend_from_slice(&2u16.to_le_bytes());
    header.extend_from_slice(&16u16.to_le_bytes());
    header.extend_from_slice(b"data");
    header.extend_from_slice(&data_bytes.to_le_bytes());
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn downmix_averages_channels() {
        assert_eq!(downmix(&[1.0, 0.0, 0.5, 0.5], 2), vec![0.5, 0.5]);
        assert_eq!(downmix(&[1.0, 2.0], 1), vec![1.0, 2.0]);
    }

    #[test]
    fn resampling_holds_rate_across_buffer_boundaries() {
        // 48 kHz in, 24 kHz out: the output stays half the input however the
        // input is chopped up.
        let mut resampler = Resampler::new(48_000, 24_000);
        let mut out = Vec::new();
        for _ in 0..10 {
            let block: Vec<f32> = (0..960).map(|n| n as f32).collect();
            resampler.push(&block, &mut out);
        }
        assert_eq!(out.len(), 4_800);
    }

    #[test]
    fn matching_rates_pass_samples_through_untouched() {
        let mut resampler = Resampler::new(24_000, 24_000);
        let mut out = Vec::new();
        resampler.push(&[0.25, -0.5, 1.0], &mut out);
        assert_eq!(out, vec![0.25, -0.5, 1.0]);
    }

    #[test]
    fn injected_lines_come_back_oldest_first_and_only_once() {
        let dir = tempfile::tempdir().unwrap();
        let session = dir.path();
        inject(session, "first").unwrap();
        std::thread::sleep(Duration::from_millis(5));
        inject(session, "second").unwrap();
        assert_eq!(drain_inject(session), vec!["first", "second"]);
        assert!(drain_inject(session).is_empty());
    }

    #[test]
    fn the_floor_is_held_until_given_back_and_expires_on_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let session = dir.path();
        assert!(!floor_held(session));
        take_floor(session, 60).unwrap();
        assert!(floor_held(session));
        give_floor(session).unwrap();
        assert!(!floor_held(session));
        // A reader that never comes back must not mute the channel forever.
        take_floor(session, 0).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(!floor_held(session));
    }

    #[test]
    fn reading_does_not_move_the_cursor_but_saying_does() {
        let dir = tempfile::tempdir().unwrap();
        let session = dir.path();
        ensure_session(session).unwrap();
        for seq in 1..=3 {
            append_line(
                session,
                &Line {
                    seq,
                    at_ms: seq,
                    speaker: "model".into(),
                    text: format!("line {seq}"),
                },
            )
            .unwrap();
        }
        cmd_read(session, false, false, 60).unwrap();
        assert_eq!(read_cursor(session), 0, "reading must not consume");
        assert!(floor_held(session), "reading takes the floor");
        cmd_say(session, "a reply", false).unwrap();
        assert_eq!(read_cursor(session), 3, "acting on a read consumes it");
        assert!(!floor_held(session), "saying gives the floor back");
        assert_eq!(drain_inject(session), vec!["a reply"]);
    }

    #[test]
    fn transcript_lines_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let session = dir.path();
        append_line(
            session,
            &Line {
                seq: 7,
                at_ms: 42,
                speaker: "far".into(),
                text: "[spoke for 1.5s — no transcription available]".into(),
            },
        )
        .unwrap();
        let lines = read_lines(session).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].seq, 7);
        assert_eq!(lines[0].speaker, "far");
        assert!(lines[0].text.contains("1.5s"));
    }

    #[test]
    fn wav_header_states_its_own_length() {
        let header = wav_header(1920 * 2);
        assert_eq!(&header[0..4], b"RIFF");
        assert_eq!(&header[36..40], b"data");
        assert_eq!(
            u32::from_le_bytes(header[40..44].try_into().unwrap()),
            1920 * 2
        );
    }
}
