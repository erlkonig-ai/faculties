//! duplex — a continuously running spoken channel driven by ONE streaming
//! speech model, with a transcript an agent reads from and injects into.
//!
//! The half-duplex bridge (`converse`, removed 2026-08-27) chained three
//! models and three processes: a transcriber, a text model, a synthesizer.
//! Every joint between them is a place the conversation breaks, and each adds
//! latency, so the human waits seconds for a reply. This binary replaces the
//! chain with a single streaming speech-to-speech model (mary's PersonaPlex
//! port) on its own 80 ms frame clock: audio codes in, audio codes out, with
//! the model's inner-monologue text falling out of the same step as exhaust.
//!
//! It is also the only path that can speak WHILE the driver is still
//! generating, and the reason is the `model` cadence below: the model samples
//! stream 0 itself and we substitute our words onto the frames it chose to
//! speak, so the pauses and their lengths are its own. A one-shot synthesizer
//! (`voice`, Qwen3-TTS) takes a whole string per call, so speaking while
//! generating there means chaining independent syntheses back to back, each
//! re-conditioned on the reference clip, with inserted pauses rather than
//! generated ones. The two are not duplicates: `voice` is the one-shot
//! utterance with the two-channel privacy contract, this is the continuous
//! conversational channel.
//!
//! ## The clock
//!
//! The model consumes and produces exactly one 80 ms frame (1920 samples at
//! 24 kHz) per step. THE MICROPHONE IS THE CLOCK: the loop blocks until the
//! capture device has produced the next full frame, so the conversation runs
//! at the pace of the physical device and never invents a second timer.
//!
//! That is now true ONE LAYER REMOVED, and it is stronger for it. The device
//! belongs to Soma; this loop subscribes. Its ear thread blocks in
//! `soma_client::SomaCapture::next_frame` until the body has produced the next
//! exact frame, and the generation loop blocks on the ear until it hands one
//! over. Soma's frame delivery IS the hardware signal — the same discipline
//! `hear` has always run on ("reading the next record is the conversation
//! clock"). There is no sleep, no timer and no polling interval anywhere on
//! the path. The device-owning version of this loop actually polled its own
//! capture ring every 4 ms; blocking on the body removed that too.
//!
//!   Soma /audio/capture ──80 ms frames──▶ streaming codec encode → LM step
//!   (one process owns the mic)                    ↘ agent codes → speaker
//!                                                 ↘ stream-0 text → transcript
//!
//! Codec decode and playback run on their own thread, off the frame clock.
//!
//! With `--no-input` there is no microphone, so THE SPEAKER IS THE CLOCK
//! instead: the loop waits until the playback device has drained the model's
//! lead below `--lead` frames before producing the next one. Both are the
//! same discipline — take the period from the hardware that will actually
//! move the samples, never from a `sleep` (see [`Mouth::pace`]). The model's
//! user-audio embeddings are omitted in this mode; as a user input, learned
//! silence is still real and remains reserved for gating a live microphone.
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
//! ## Where the frame budget goes (measured)
//!
//! The budget is 80 ms per frame, and the two directions of the channel do
//! NOT cost the same, because only one of them pays for the codec encoder.
//!
//! **Generation only (`--no-input`) fits, with room to spare.** Measured on an
//! M-series laptop, 900-frame sessions with real injected utterances, an
//! otherwise quiet machine: **p50 29-30 ms, p90 38-39 ms, p99 43-49 ms, max
//! 74 ms — 0 of 900 frames over budget, 0 playback underruns, and 900 frames
//! of audio in 71.7 s of wall clock, i.e. 1.00x realtime.** The same loop
//! driving a Bluetooth handsfree endpoint measured p50 29.8 ms over 700
//! frames, again with nothing over budget and nothing underrunning.
//!
//! **Full duplex does not fit yet**, and the gap is one stage: the in-line
//! streaming codec ENCODE on the input path, which moved the measured mean
//! from ~74 ms to ~101 ms when it was added — about 27 ms per frame. Of the
//! four stages in a frame, only the temporal transformer runs on the GPU; the
//! depth transformer and both codec directions are host-CPU lanes in the
//! model library today. The model library's own budget model allots temporal
//! ~15.6 ms (GPU) + depth ~21.6 ms (CPU) + codec ~5 ms (CPU) + submission
//! ~5 ms. Generation clears the budget because it never touches the encoder;
//! listening is what has to be paid for, and the way to pay for it is porting
//! the encoder to the GPU, not tuning anything here.
//!
//! **What the frame is really exposed to is CPU CONTENTION, not its own
//! cost.** The same generation-only session measured p50 29.4 ms on an idle
//! machine and p50 90.3 ms — 63% of frames over budget — with a load average
//! of 21 from unrelated compile jobs. Two thirds of the frame is host-CPU
//! work, so a busy machine, not a slow model, is what makes this stutter.
//! Any timing taken here without recording the load average is not a
//! measurement of this loop.
//!
//! `--decode-context` / `--decode-hop` are exposed because the codec decoder
//! has no streaming state and re-decodes its context on every hop; they trade
//! boundary artifacts against CPU load. The context default is DEEP for a
//! reason measured here — see [`DEFAULT_DECODE_CONTEXT`].
//!
//! ## Soma owns the microphone; this binary owns nothing
//!
//! A capture device can be held by exactly one process. While this binary held
//! it, `hear` and `duplex` could not run at the same time — a live transcript
//! and a spoken channel were mutually exclusive by physics, not by policy. Now
//! Soma is the single owner and fans one microphone out to every consumer, so
//! both run off the SAME frames: audio embeddings for the thinking model and a
//! spoken channel, at once, instead of choosing.
//!
//! NEVER CLOSE THE MICROPHONE STREAM. On a handsfree (HFP) endpoint — a car
//! kit, a headset — the duplex channel exists only while something holds the
//! microphone open; close it to "take a turn" and the endpoint renegotiates,
//! audio drops mid-sentence, and the far end hears nothing. Soma holds it for
//! the life of the BODY, so it now outlives this session too: starting and
//! stopping `duplex` is not a device event at all. The floor is held in
//! software, never by touching a device.
//!
//! DEVICES ARE ADDRESSED BY NAME, NEVER BY INDEX AND NEVER VIA THE SYSTEM
//! DEFAULT. Connecting a Bluetooth endpoint renumbers the platform's device
//! list, so an index-addressed or default-addressed stream can land on a dead
//! virtual channel at -91 dB with nothing in the logs to say so. This binary
//! keeps that rule BY SUBTRACTION: it names no capture device at all and
//! inherits Soma's one named choice (`soma --mic-live --mic-device <name>`).
//! `duplex ear` checks what actually arrives; `duplex devices` still prints
//! the PLAYBACK names, which this binary does still open by name.
//!
//! The speaker is a different case and is deliberately still ours: it is
//! multi-client on this hardware, so it never forced the exclusion the
//! microphone did, and repointing an audio SINK through another owner would
//! move the say-privacy invariant (`voice`'s `route_say`: there is no path
//! from a private utterance to a room speaker) across a process boundary
//! before that owner enforces it. That is a change to make deliberately, at
//! the new owner, first.
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
//! # one process owns the microphone, by name, for the life of the body:
//! soma --mic-live --mic-device 'MacBook Pro Microphone' --port 8000
//!
//! duplex devices                       # playback names
//! duplex ear --soma http://localhost:8000   # the capture seam, no model
//! duplex run --weights <weights.pile> --voice-prompt <voice.pt> \
//!            --soma http://localhost:8000 \
//!            --output '<exact output device name>' \
//!            --pause-file /tmp/ears.pause
//!
//! # …and AT THE SAME TIME, off the same frames:
//! hear listen --soma http://localhost:8000 --pile gemma_e4b.pile \
//!             --pause-file /tmp/ears.pause
//!
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
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use faculties::clock;

/// Samples in one model frame at 24 kHz (80 ms).
///
/// Taken FROM Soma's wire format rather than agreed with it: the model's frame
/// and the body's frame are the same frame, and two constants that merely
/// happen to match are a drift waiting to happen.
const FRAME_SAMPLES: usize = soma_client::FRAME_SAMPLES;
/// The model's canonical sample rate — likewise the body's.
const SAMPLE_RATE: u32 = soma_client::SAMPLE_RATE;
const _: () = assert!(FRAME_SAMPLES * 1_000 == 80 * SAMPLE_RATE as usize);

/// Where the body is, unless told otherwise. The same default the rest of the
/// suite uses (`voice`, `body`, `hear`).
const DEFAULT_SOMA: &str = "http://localhost:8000";
/// How far the capture ring may run ahead before the loop discards the
/// backlog. The model's step count IS its clock, so a loop that falls behind
/// the world cannot catch up by stepping faster — it can only skip forward.
const MAX_BACKLOG_FRAMES: usize = 8;

/// Text-stream ids carrying no surface text: 0 EPAD, 1 BOS, 2 EOS, 3 PAD.
const N_TEXT_SPECIALS: i64 = 4;
const TEXT_PAD: i64 = 3;
/// `<epad>` — END of a pad run, i.e. the frame that says a word starts next.
/// The model's own text stream marks a word onset this way, so a schedule that
/// pads with `<pad>` right up to the word gives it no warning that the silence
/// is ending. Measured: with a two-frame gap, padding all the way puts the
/// word onset at rank 113 in the model's own logits; ending the gap with
/// `<epad>` is what a natural stream looks like there.
const TEXT_EPAD: i64 = 0;

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
    /// List the PLAYBACK devices this channel can be addressed by, with the
    /// native configuration each offers. These exact names are what
    /// `run --output` expects. There is no input list: the microphone is
    /// Soma's, chosen once by name there (`soma --mic-device`) and inherited
    /// by every consumer.
    Devices,
    /// Read the body's frames through the SAME ear `run` uses, without the
    /// model. The capture seam's gate: run it beside `hear listen` against one
    /// Soma and watch both read the same clock.
    Ear {
        /// Base URL of the Soma that owns the microphone.
        #[arg(long, env = "SOMA_URL", default_value = DEFAULT_SOMA)]
        soma: String,
        /// Stop after this many frames (0 = until the stream ends).
        #[arg(long, default_value_t = 125)]
        frames: usize,
    },
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
    /// Text tokenizer file, overriding the copy inside `--weights`.
    ///
    /// Needed because the two halves of the weight pile drifted apart: the
    /// codec loader wants a `mary-model-bundles` collection and the pile-side
    /// SPM loader still wants the `mary-model-graph` the bundle migration
    /// replaced, so no pile on this machine satisfies both. Whatever is loaded
    /// is checked against the model's own `TEXT_CARD` below, so a wrong
    /// tokenizer is a loud failure rather than gibberish. `mary`'s own
    /// PersonaPlex bins take the same flag.
    #[arg(long, env = "PERSONAPLEX_SPM")]
    spm: Option<PathBuf>,
    /// Base URL of the Soma that owns the microphone. This process opens no
    /// capture device: it subscribes, so `hear` can be reading the same frames
    /// at the same time. Not needed with `--no-input`.
    #[arg(long, env = "SOMA_URL", default_value = DEFAULT_SOMA)]
    soma: String,
    /// EXACT name of the playback device.
    #[arg(long)]
    output: String,
    /// Weight format for the temporal stack. `q8` is the default because on
    /// an Apple GPU it is not slower than `q4` — at these shapes the matvecs
    /// are dispatch-bound rather than bandwidth-bound, and the hardware has
    /// no FP4 units, so 4-bit is pure dequantization overhead there — while
    /// costing far less fidelity. `q4` is expected to pay on parts that DO
    /// have FP4 hardware.
    #[arg(long, default_value = "q8")]
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
    /// Gap frames inserted at each word boundary in a forced line (the last
    /// of them `<epad>`). Where the gaps GO is set by `--cadence`; this sets
    /// how long they are, and therefore the SPEAKING RATE.
    ///
    /// Only applies to the SCHEDULED cadences. Under the default `model`
    /// cadence there is no schedule to space out — the gaps are the model's.
    ///
    /// 3 is the default because it is the only value that satisfies all three
    /// things we can measure. It puts the schedule at 69% `<pad>`, matching
    /// the ~65% density the model's own text stream runs at; it keeps the
    /// forced tokens inside the model's own distribution (word onset p50 rank
    /// 10, continuation p50 rank 1); and it produces 2.83-3.00 words per
    /// second, which is ordinary English speech. Shorter gaps score just as
    /// well on rank — onset p50 4 at gap 1 — but talk at 3.6-4.0 words per
    /// second, which is a rushed delivery that no rank statistic can see.
    #[arg(long, default_value_t = 3)]
    pace: usize,
    /// Write one line per frame — index, the stream-0 token, and what kind of
    /// token it was — so the audio can be read against what the text stream
    /// was doing at that instant. The way to find out whether the model puts
    /// anything in the gaps it is given: breath, a filled pause, laughter.
    #[arg(long)]
    trace: Option<PathBuf>,
    /// Under `--cadence model`, the fewest frames allowed between one word
    /// ONSET and the next. `0` (the default) imposes nothing and leaves the
    /// rhythm entirely the model's.
    ///
    /// A floor, never a schedule: it can only DELAY a word the model wanted
    /// to start, never bring one forward, so the long pauses it chooses stay
    /// exactly as long. Within-word pieces are untouched — those run
    /// consecutively in real speech and stretching them is the original bug.
    /// It was built to trade back some of the speed of model timing (~4.0
    /// words/s against ordinary English's 2.5-3.0) without flattening the
    /// variation. **Measured, it does not work, and the reason is worth
    /// keeping.** A floor of 3 was predicted to lift the fastest third of
    /// onset gaps and land a mean of 3.92 frames. It produced a mean of
    /// **8.38**, a shortest gap of 4 rather than 3, and the same two
    /// sentences took 33.2 s against model timing's 18.3 s — slower than the
    /// fixed schedule it was meant to improve on.
    ///
    /// Holding PAD on a frame where the model asked for a word does not delay
    /// that word by a frame. The PAD enters the model's own history and
    /// conditions what follows, so it drops into a pause and then EXTENDS it
    /// on its own: the intervention compounds instead of applying once. That
    /// is the same property that makes forcing work at all — a token we
    /// substitute is one it then owns — pointing the other way.
    ///
    /// Left in, defaulted off, as the reproduction for that finding. The
    /// summary counts every frame it holds back. Note also that lengthening
    /// pauses this way trips `--utterance-gap`, which chops one line into
    /// several transcript entries (the audio stays whole).
    #[arg(long, default_value_t = 0)]
    min_word_gap: usize,
    /// Under `--cadence model`, how many frames the model may hold silence
    /// mid-line before we start the next word for it. A backstop, not a
    /// rhythm: every time it fires we have taken the timing back, and the run
    /// summary reports how often that happened.
    #[arg(long, default_value_t = 25)]
    nudge_after: usize,
    /// Who decides WHEN each word lands. `model` (the default) decides
    /// nothing: the model samples stream 0 itself and we substitute our words
    /// onto the frames it chose to speak, so the pauses and their lengths are
    /// its own. The rest impose a schedule and are kept as controls for the
    /// rhythm and rank numbers this command reports — `word-onset` puts a
    /// fixed gap between words, `uniform` puts one after every word piece
    /// (which splits multi-piece words across silence), `dense` uses none.
    #[arg(long, default_value = "model")]
    cadence: String,
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
    /// Frames of context the codec decoder re-decodes on every hop. Deep by
    /// default — the decoder's transformer has a 250-frame window and no
    /// streaming state, so a shallow context makes the hop boundary audible.
    #[arg(long, default_value_t = DEFAULT_DECODE_CONTEXT)]
    decode_context: usize,
    /// New frames emitted per decode call.
    #[arg(long, default_value_t = DEFAULT_DECODE_HOP)]
    decode_hop: usize,
    /// Do not subscribe to the capture stream and omit the model's user-audio
    /// embeddings. This is the GENERATION-ONLY channel — the model speaks and
    /// is not listened to — and it is also what to use on a handsfree endpoint
    /// whose microphone is already held open by something else. With no
    /// microphone the SPEAKER becomes the frame clock (see `--lead`).
    #[arg(long)]
    no_input: bool,
    /// Generation-only clock: frames of audio the model may run ahead of the
    /// speaker before it waits. The floor is one decode hop, since the device
    /// reports its queue a hop at a time; two hops is what keeps a hop of
    /// audio in front of the device at all times.
    #[arg(long)]
    lead: Option<usize>,
    /// Half-duplex pause file, held for exactly as long as this channel is
    /// AUDIBLE IN THE ROOM.
    ///
    /// Needed only because the microphone is now SHARED: another consumer of
    /// the same Soma frames (`hear listen --pause-file <the same path>`) would
    /// otherwise transcribe our own voice back to us. Inside this binary
    /// turn-taking needs no file at all — `--gate` feeds the model digital
    /// silence while it speaks, in process, on the frame clock.
    ///
    /// The window is held past the last generated frame by whatever audio is
    /// still in flight to the speaker, because the mouth is audible LATER than
    /// the model is generating. It is a SOFTWARE hold: nothing here or in
    /// `hear` closes a device.
    #[arg(long, env = "VOICE_PAUSE_FILE")]
    pause_file: Option<PathBuf>,
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
        Some(Command::Ear { soma, frames }) => cmd_ear(&soma, frames),
        Some(Command::Read {
            peek,
            all,
            hold_secs,
        }) => cmd_read(&session, peek, all, hold_secs),
        Some(Command::Say { text, keep_floor }) => cmd_say(&session, &text.join(" "), keep_floor),
        Some(Command::Release { keep_cursor }) => cmd_release(&session, keep_cursor),
        Some(Command::Status) => cmd_status(&session),
        Some(Command::Run(args)) => cmd_run(&session, *args),
    }
}

fn default_session() -> PathBuf {
    std::env::temp_dir().join("duplex")
}

fn now_millis() -> Result<u64> {
    Ok(clock::now()?.to_unix_milliseconds() as u64)
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
    std::fs::rename(&staged, &path).with_context(|| format!("publish {}", path.display()))?;
    Ok(())
}

// ── the floor ──────────────────────────────────────────────────────────────

/// The hold is a file with a deadline in it — the same primitive the
/// half-duplex bridge used to keep its ears off its own mouth, here keeping
/// the model quiet while a reader catches up. A file survives the reader
/// dying; the deadline means the channel recovers when it does.
fn take_floor(session: &Path, hold_secs: u64) -> Result<()> {
    let deadline = now_millis()?.saturating_add(hold_secs.saturating_mul(1_000));
    let staged = session.join(".hold.tmp");
    std::fs::write(&staged, deadline.to_string())?;
    std::fs::rename(&staged, session.join(HOLD_FILE)).context("publish the floor hold")?;
    let _ = std::fs::remove_file(session.join(RELEASE_FILE));
    Ok(())
}

fn floor_held(session: &Path) -> Result<bool> {
    let Ok(text) = std::fs::read_to_string(session.join(HOLD_FILE)) else {
        return Ok(false);
    };
    let deadline: u64 = text.trim().parse().unwrap_or(0);
    if now_millis()? > deadline {
        // Expired holds are cleared by whoever notices, so a dead reader
        // cannot mute the channel indefinitely.
        let _ = std::fs::remove_file(session.join(HOLD_FILE));
        return Ok(false);
    }
    Ok(true)
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
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let stamp = clock::tai_nanoseconds_now()?;
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
        println!(
            "queued ({}), cursor at {last}, floor still held",
            published.display()
        );
    } else {
        give_floor(session)?;
        println!(
            "queued ({}), cursor at {last}, floor released",
            published.display()
        );
    }
    Ok(())
}

fn cmd_release(session: &Path, keep_cursor: bool) -> Result<()> {
    ensure_session(session)?;
    give_floor(session)?;
    if keep_cursor {
        println!(
            "floor released, cursor unchanged at {}",
            read_cursor(session)
        );
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
    println!(
        "cursor    : {cursor} ({} unread)",
        last.saturating_sub(cursor)
    );
    println!(
        "floor     : {}",
        if floor_held(session)? {
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
    // No capture list. A capture device can be held by exactly one process,
    // and that process is Soma: it picks the microphone by name
    // (`soma --mic-live --mic-device <name>`) and fans it out, which is why
    // `hear` and `duplex` can run at once. Naming a second one here would be
    // offering the thing that made them exclusive.
    println!("capture: Soma's, named once there and inherited (`duplex ear` to check it)");
    println!("playback devices (--output):");
    for device in host
        .output_devices()
        .context("enumerate playback devices")?
    {
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

// ── the ear: Soma's frames, and this loop owns no device ───────────────────

/// The far end's voice, as Soma delivers it.
///
/// **THIS BINARY OPENS NO DEVICE.** A capture device can be held by exactly
/// one process, so exactly one process picks it BY NAME and holds it: Soma.
/// Everything else subscribes. That is not tidiness — while this loop opened
/// the microphone itself, `hear` and `duplex` could not run at the same time,
/// and a live transcript and a spoken channel were mutually exclusive by
/// physics. Now they are two consumers of one body.
///
/// DEVICES ARE ADDRESSED BY NAME, NEVER BY INDEX AND NEVER VIA THE SYSTEM
/// DEFAULT — a Bluetooth connect silently renumbers CoreAudio and an
/// index-addressed stream lands on a dead virtual channel at -91 dB with
/// nothing in the logs. This binary keeps that rule BY SUBTRACTION: it names
/// no device at all and inherits Soma's one named choice.
///
/// NEVER CLOSE THE MICROPHONE STREAM. Dropping this ear detaches a consumer;
/// it does not close anything. On a handsfree (HFP) endpoint the duplex
/// channel exists only while something holds the microphone open, and Soma is
/// what holds it — for the life of the body, not the life of this process.
///
/// THE READ IS THE CLOCK. The reader thread blocks in `SomaCapture::next_frame`
/// until the physical device has produced the next exact 80 ms frame, and the
/// generation loop blocks on the condvar until the reader hands one over. There
/// is no sleep, no timer and no polling interval on the path — the period is
/// the hardware's, one layer removed. (The device-owning version of this ear
/// polled its ring every 4 ms; blocking on the body is strictly better.)
struct Ear {
    ring: Arc<(Mutex<EarRing>, Condvar)>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    soma: String,
}

#[derive(Default)]
struct EarRing {
    frames: VecDeque<[f32; FRAME_SAMPLES]>,
    /// Frames discarded because this loop could not keep the body's pace. The
    /// model's step count IS its clock, so a loop that falls behind the world
    /// cannot catch up by stepping faster — it can only skip forward.
    skipped: usize,
    /// Where this ear joined the body's clock, and where it has got to. Soma
    /// fans one microphone out, so these are the BODY's coordinates, shared
    /// with every other consumer of the same frames — which is what lets two
    /// of them say they heard the same instant.
    first_frame: Option<u64>,
    last_frame: u64,
    /// Why the stream ended, if it has. Never a silent stop: missing speech
    /// must not read as silence.
    ended: Option<String>,
}

impl Ear {
    /// Subscribe to the body's microphone. Opening is done here, on the
    /// caller's thread, so a body that is not running says so immediately
    /// rather than one frame into the session.
    fn open(soma: &str) -> Result<Self> {
        let mut capture = soma_client::SomaCapture::open(soma)
            .with_context(|| format!("subscribe to Soma's microphone at {soma}"))?;
        let ring: Arc<(Mutex<EarRing>, Condvar)> =
            Arc::new((Mutex::new(EarRing::default()), Condvar::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let ring = Arc::clone(&ring);
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("duplex-ear".into())
                .spawn(move || {
                    let (lock, ready) = &*ring;
                    while !stop.load(Ordering::Relaxed) {
                        // Blocks on the body, which blocks on the device.
                        match capture.next_frame() {
                            Ok(frame) => {
                                let mut ring = lock.lock().expect("ear ring");
                                ring.first_frame.get_or_insert(frame.frame_index);
                                ring.last_frame = frame.frame_index;
                                ring.frames.push_back(frame.samples);
                                drop(ring);
                                ready.notify_all();
                            }
                            Err(error) => {
                                let mut ring = lock.lock().expect("ear ring");
                                ring.ended = Some(format!("{error:#}"));
                                drop(ring);
                                ready.notify_all();
                                return;
                            }
                        }
                    }
                    let mut ring = lock.lock().expect("ear ring");
                    ring.ended.get_or_insert_with(|| "ear closed".into());
                    drop(ring);
                    ready.notify_all();
                })
                .context("spawn ear thread")?
        };
        Ok(Self {
            ring,
            stop,
            thread: Some(thread),
            soma: soma.to_string(),
        })
    }

    /// Pull exactly one frame, blocking on the body's clock.
    fn next_frame(&self) -> Option<[f32; FRAME_SAMPLES]> {
        let (lock, ready) = &*self.ring;
        let mut ring = lock.lock().expect("ear ring");
        loop {
            // Stay current: a backlog means this loop is slower than the
            // world, and the model cannot step faster to catch up.
            let backlog = ring.frames.len();
            if backlog > MAX_BACKLOG_FRAMES {
                let drop_frames = backlog - 2;
                ring.frames.drain(..drop_frames);
                ring.skipped += drop_frames;
            }
            if let Some(frame) = ring.frames.pop_front() {
                return Some(frame);
            }
            // Buffered frames are handed over before the ending, so a stream
            // that died never swallows audio it already delivered.
            if ring.ended.is_some() {
                return None;
            }
            ring = ready.wait(ring).expect("ear ring");
        }
    }

    fn skipped(&self) -> usize {
        self.ring.0.lock().expect("ear ring").skipped
    }

    /// This ear's place on the body's clock: where it joined and where it is.
    /// The join point is `None` until the first frame actually arrives —
    /// reporting a zero there would claim the body's clock had just started,
    /// which is exactly the thing a shared microphone makes untrue.
    fn clock(&self) -> (Option<u64>, u64) {
        let ring = self.ring.0.lock().expect("ear ring");
        (ring.first_frame, ring.last_frame)
    }

    fn ended(&self) -> Option<String> {
        self.ring.0.lock().expect("ear ring").ended.clone()
    }
}

impl Drop for Ear {
    /// Detaches this consumer. It does NOT close the microphone — that is
    /// Soma's, held for the life of the body.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn rms(samples: &[f32]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    (samples.iter().map(|s| s * s).sum::<f32>() / samples.len() as f32).sqrt()
}

/// The capture seam's gate, without the model: read the body's frames through
/// the SAME ear `run` uses and report what arrives.
///
/// This is what makes the simultaneity claim checkable without paying for
/// weights — run it beside `hear listen` against one Soma and both will report
/// frames off the same clock. It is also how to tell "the body is not
/// producing audio" apart from "the model is not answering".
fn cmd_ear(soma: &str, frames: usize) -> Result<()> {
    let ear = Ear::open(soma)?;
    println!(
        "duplex: ear open on {} — {} Hz, {} sample frames, this process owns no device",
        ear.soma,
        soma_client::SAMPLE_RATE,
        soma_client::FRAME_SAMPLES
    );
    let start = Instant::now();
    let mut read = 0usize;
    let mut peak = 0f32;
    let mut total = 0f64;
    while frames == 0 || read < frames {
        let Some(frame) = ear.next_frame() else {
            break;
        };
        let level = rms(&frame);
        peak = peak.max(level);
        total += level as f64;
        read += 1;
        if read % 12 == 0 {
            let (first, last) = ear.clock();
            println!(
                "  [ear] body frame {last} (joined at {}) | {read} read | \
                 {} skipped | rms {level:.4}",
                first.unwrap_or(0),
                ear.skipped()
            );
        }
    }
    let wall = start.elapsed().as_secs_f64();
    let (first, last) = ear.clock();
    println!(
        "duplex: {read} frames in {wall:.1}s — {:.2}x realtime | body frames {}..{last} | \
         {} skipped | ear rms mean {:.4} peak {:.4}",
        (read as f64 * 0.08) / wall.max(1e-9),
        first.unwrap_or(0),
        ear.skipped(),
        total / read.max(1) as f64,
        peak
    );
    if let Some(reason) = ear.ended() {
        println!("duplex: the body's stream ended — {reason}");
    }
    Ok(())
}

// ── playback: decode away from the frame clock, sink opened by name ────────

/// Frames the decoder keeps as context so a chunk boundary is not audible.
/// The codec decoder has no streaming state, so context is re-decoded on
/// every hop: the decoder does `(context + hop) / hop` times realtime work.
/// At 25 and 2 that is 13.5x, which is why these are knobs and not constants.
/// Frames of already-spoken context the codec decoder re-decodes before the
/// new ones, so that the frames it emits are not decoded from a cold start.
///
/// **This has to be deep, and 8 was far too shallow.** The Mimi decoder has
/// no streaming state, so every hop re-runs the whole graph from zero — and
/// that graph contains an 8-layer transformer with a CAUSAL SLIDING WINDOW OF
/// 250 FRAMES. Handing it 8 frames of context truncates its attention by a
/// factor of thirty, so the same codes decode to a different waveform
/// depending on which hop they land in, and the splice between hops is
/// audible. Measured as the median sample-to-sample jump AT a hop boundary
/// over the same statistic away from one, in loud regions of matched runs:
///
/// | temporal fmt | context | boundary ÷ interior |
/// |---|---|---|
/// | q4  |  8 | 2.63 |
/// | q8  |  8 | 2.23 |
/// | f16 |  8 | 1.06 |
/// | q8  | 64 | **0.95** |
///
/// At 64 the boundary is statistically indistinguishable from the interior,
/// i.e. the splice is gone. The convolutional stack needs only a handful of
/// frames (its receptive field is ~3-4 frames at 12.5 Hz), so this depth buys
/// the TRANSFORMER's context, not the convs'. It costs about 6 ms per frame
/// on the decode thread, which is off the frame clock and affordable: a q8
/// session at context 64 measured p50 35.6 ms of an 80 ms budget, 1.00x
/// realtime with nothing over budget.
const DEFAULT_DECODE_CONTEXT: usize = 64;
/// New frames emitted per decode call.
const DEFAULT_DECODE_HOP: usize = 4;
/// The model may lead the speaker by at most this much. Growing latency is a
/// fault to report, not something to hide in an unbounded queue.
const DECODE_QUEUE_FRAMES: usize = 16;
/// Frames buffered before playback starts. The model produces at realtime, so
/// this covers device start-up, not a production deficit.
const PREBUFFER_FRAMES: usize = 5;
/// Longest the generation clock will wait on the speaker before producing the
/// next frame anyway. A device that stops consuming is a fault to surface, not
/// a reason to wedge the loop forever.
const PACE_DEADLINE: Duration = Duration::from_millis(500);

/// HOW LONG OUR VOICE IS IN THE ROOM, which is not how long the model is
/// generating.
///
/// The mouth is audible LATER than the model is generating: between the two sit
/// the codec decoder and the speaker's own queue. So a window that closed when
/// generation stopped would un-deafen the other consumers of the same
/// microphone while our last words were still coming out of the speaker, and
/// `hear` would transcribe our own voice back to us.
///
/// The tail is not guessed: it is whatever the mouth still has IN FLIGHT at the
/// moment generation stops, counted down one frame per frame, because the
/// speaker consumes one frame per frame. Erring long is the safe direction —
/// the cost is a little extra deafness, the cost of erring short is the loop
/// hearing itself.
///
/// This gates SOFTWARE only. Nothing here touches a device, and the consumer on
/// the other side of the pause file keeps reading frames throughout and simply
/// discards them: the hold stops the model, never the person.
#[derive(Default)]
struct AudibleWindow {
    tail: usize,
}

impl AudibleWindow {
    /// `speaking` is the model's own speech signal for this frame; `in_flight`
    /// is what the mouth has handed the speaker but the speaker has not played.
    /// Returns whether our voice is in the room right now.
    fn observe(&mut self, speaking: bool, in_flight: usize) -> bool {
        if speaking {
            self.tail = in_flight + PREBUFFER_FRAMES;
            return true;
        }
        let sounding = self.tail > 0;
        self.tail = self.tail.saturating_sub(1);
        sounding
    }
}

/// How a line of text is laid out across frames on the inner-monologue
/// stream. The control for the rank measurement below — see
/// [`cadence_schedule`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cadence {
    /// Gap frames at WORD ONSETS only; word pieces run consecutively.
    WordOnset,
    /// Gap frames after EVERY piece, word-internal ones included.
    Uniform,
    /// One token per frame, no gaps at all.
    Dense,
    /// No schedule at all: the model picks the moments, we supply the words.
    Model,
}

/// Lay a line of text out across frames for the model's stream 0.
///
/// **Placement, not density, is what makes a forced token feel native.** The
/// model's own text stream runs word PIECES consecutively and puts its gaps at
/// WORD ONSETS. A schedule that pads after every piece looks correctly sparse
/// on average while being off-distribution *inside* every multi-piece word —
/// a place the model has no gap in its training distribution at all, so it is
/// dragged exactly where it is most confident. That is a different failure
/// from packing too densely and the average PAD fraction cannot see it: a
/// uniform gap of 2 is 67% PAD, SPARSER than the word-onset schedule this
/// model was measured to endorse (~42% PAD), and still wrong.
///
/// The measurement that separates them is the forced token's rank in the
/// model's own logits for that frame — rank 0 means it wanted the token
/// anyway, a large rank means it is being fought. `duplex run` reports the
/// distribution; `--cadence` selects between the three layouts so the claim
/// stays checkable rather than asserted. Measured on two sentences, median
/// rank of a WITHIN-WORD piece:
///
/// | layout | continuation | onset |
/// |---|---|---|
/// | uniform, gap 2 | **24125** | 73 |
/// | word onset, gap 3, `<epad>`-terminated | **1** | 10 |
///
/// A uniform gap is not merely suboptimal — 24125 of 32000 is as hard as this
/// model can be fought, on every multi-piece word, for a whole utterance.
///
/// The gap ENDS with `<epad>`, not `<pad>`, because that is how the model's
/// own stream announces an oncoming word; padding right up to the onset costs
/// an order of magnitude of onset rank (113 vs 7 at gap 2).
///
/// Rank alone does not pick the gap LENGTH: every gap from 1 to 3 sits in the
/// endorsed regime, but only 3 speaks at a natural rate. See `--pace`.
///
/// All of which is why the DEFAULT is [`Cadence::Model`] and none of these:
/// every fixed gap is a metronome, and picking its length is guesswork at a
/// distribution the model already holds. These layouts remain as controls, so
/// the rhythm and rank numbers above stay reproducible.
///
/// SPM marks a word onset with a leading U+2581 on the piece.
#[cfg(feature = "duplex")]
fn cadence_schedule(
    spm: &mary::models::personaplex::spm::SpmTokenizer,
    line: &str,
    gap: usize,
    cadence: Cadence,
) -> Vec<i64> {
    const WORD_MARK: &[u8] = "\u{2581}".as_bytes();
    let ids = spm.encode(line);
    // Nothing to lay out: under `Model` the queue is just the words, and the
    // gaps come from the model one frame at a time.
    if cadence == Cadence::Model {
        return ids;
    }
    let mut out = Vec::with_capacity(ids.len() * (1 + gap));
    for (k, &t) in ids.iter().enumerate() {
        out.push(t);
        let pad_here = match cadence {
            Cadence::Model | Cadence::Dense => false,
            Cadence::Uniform => true,
            Cadence::WordOnset => ids
                .get(k + 1)
                .map(|&n| spm.piece_bytes(n).starts_with(WORD_MARK))
                .unwrap_or(false),
        };
        if pad_here {
            // ... <pad> ... <epad> word: the last gap frame announces the
            // onset rather than looking like more silence.
            for g in 0..gap {
                out.push(if g + 1 == gap { TEXT_EPAD } else { TEXT_PAD });
            }
        }
    }
    out
}

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
    /// Frames the speaker has finished playing. The lead is derived from this
    /// and the push count rather than published directly, so that a stale
    /// reading errs towards WAITING — see [`Mouth::pace`].
    played: Arc<AtomicU64>,
    /// Frames handed to the mouth. Owned by the generation loop, which is the
    /// only pusher.
    pushed: std::cell::Cell<u64>,
    /// Whether the prebuffer is full and the device is actually consuming.
    playing: Arc<AtomicBool>,
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
        let played = Arc::new(AtomicU64::new(0));
        let playing = Arc::new(AtomicBool::new(false));
        let worker = {
            let underruns = Arc::clone(&underruns);
            let played = Arc::clone(&played);
            let playing = Arc::clone(&playing);
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
                        played,
                        playing,
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
            played,
            pushed: std::cell::Cell::new(0),
            playing,
        })
    }

    fn push(&self, codes: Codes) {
        let Some(sender) = self.frames.as_ref() else {
            return;
        };
        match sender.try_send(codes) {
            Ok(()) => self.pushed.set(self.pushed.get() + 1),
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn underruns(&self) -> u64 {
        self.underruns.load(Ordering::Relaxed)
    }

    /// Frames of audio handed to the speaker that it has not played yet.
    ///
    /// Derived rather than published, and that direction is load-bearing: the
    /// decode thread cannot publish while it is INSIDE a decode call, so any
    /// reading here may be stale. Because `pushed` is owned by the caller and
    /// only `played` can lag, a stale reading OVERSTATES the lead and the
    /// pacer waits — the safe way to be wrong. Publishing the lead directly
    /// failed the other way: a lead frozen below the target let the loop
    /// free-run for a whole decode call and overflow the frame queue (138 of
    /// 900 frames dropped in one measured session).
    fn lead(&self) -> u64 {
        self.pushed
            .get()
            .saturating_sub(self.played.load(Ordering::Relaxed))
    }

    /// THE SPEAKER IS THE CLOCK. Block until the device has drained the
    /// model's lead below `target` frames, then let the next frame be
    /// generated.
    ///
    /// A generation-only session has no microphone to take its period from,
    /// and a `sleep(FRAME - work)` is NOT a substitute: `thread::sleep`
    /// overshoots by a millisecond or four every time and the error only ever
    /// accumulates in one direction, so the loop produces 80 ms of audio every
    /// ~84 ms — a ~5% production deficit that drains any prebuffer and then
    /// stutters forever. (Measured: 400 frames of audio took 33.6 s of wall
    /// clock and underran 11 times, with the model itself using 37 ms of its
    /// 80 ms budget.) Waiting on the DEVICE instead takes the period from the
    /// hardware that will actually play the samples, so there is no second
    /// clock to drift against — the same reason the duplex loop takes its
    /// period from the microphone.
    ///
    /// Returns `false` if the deadline expired with the device still full,
    /// which means playback has stalled rather than that the model is fast.
    fn pace(&self, target: u64) -> bool {
        // Before the prebuffer is full nothing is being consumed, so there is
        // nothing to pace against: fill it as fast as the model can.
        if !self.playing.load(Ordering::Relaxed) {
            return true;
        }
        let deadline = Instant::now() + PACE_DEADLINE;
        while self.lead() >= target {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        true
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
    played: Arc<AtomicU64>,
    playing: Arc<AtomicBool>,
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

    // Frames the device has FINISHED, which is what the generation clock
    // paces against (see [`Mouth::pace`]). `player.len()` counts QUEUED
    // SOURCES and the one being played counts until its last sample is gone,
    // so `emitted - len·hop` UNDERSTATES what has been played by at most one
    // hop — the direction that makes the pacer wait rather than run ahead.
    let publish = |player: &rodio::Player, emitted: usize| {
        played.store(
            (emitted.saturating_sub(player.len() * hop_frames)) as u64,
            Ordering::Relaxed,
        );
    };

    loop {
        // A timed receive so the lead stays live while the model is thinking:
        // a producer that only republished on its own writes would tell the
        // pacer the queue is full for as long as it takes to fill it.
        let frame = match frames.recv_timeout(Duration::from_millis(2)) {
            Ok(frame) => frame,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                publish(&player, emitted);
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        history.push_back(frame);
        pending += 1;
        if pending < hop_frames {
            publish(&player, emitted);
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
            playing.store(true, Ordering::Relaxed);
        }
        publish(&player, emitted);
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
    use triblespace::core::collection::CollectionStoreExt;
    use triblespace::core::metadata;
    use triblespace::prelude::*;

    let stamp = clock::point_now()?;
    let fragment = faculties::voice::utterance_fragment(CHANNEL_SHOUT, text, None, stamp)?;

    let signer = load_signer(pile_path, key)?;
    let mut pile = open_pile_strict(pile_path)?;
    let collection = open_scope(&mut pile, COLLECTION_SCOPE_ID, &signer)?;
    let result = (|| -> Result<()> {
        let store_snapshot = pile.snapshot().context("freeze Voice store snapshot")?;
        let (facts, _) = faculties::storage::read_fact_collection(collection, &store_snapshot)
            .context("materialize the Voice collection")?;
        faculties::voice::validate_candidate(&store_snapshot, &facts, &fragment)?;
        let mut described = fragment.clone();
        described.describe_with(entity! { metadata::description: "duplex spoke" });
        pile.commit(collection, &signer, described)
            .context("commit the utterance")?;
        Ok(())
    })();
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

/// Which PersonaPlex token-step contract one frame uses. Keeping this choice
/// explicit prevents generation-only mode from quietly falling back to a
/// learned silence frame, while preserving both ordinary duplex paths.
#[cfg(feature = "duplex")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PersonaPlexStepApi {
    Duplex,
    DuplexArbitrated,
    OutputOnly,
    OutputOnlyArbitrated,
}

#[cfg(feature = "duplex")]
impl PersonaPlexStepApi {
    fn select(output_only: bool, arbitrated: bool) -> Self {
        match (output_only, arbitrated) {
            (false, false) => Self::Duplex,
            (false, true) => Self::DuplexArbitrated,
            (true, false) => Self::OutputOnly,
            (true, true) => Self::OutputOnlyArbitrated,
        }
    }
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
    let cadence = match args.cadence.as_str() {
        "word-onset" => Cadence::WordOnset,
        "uniform" => Cadence::Uniform,
        "dense" => Cadence::Dense,
        "model" => Cadence::Model,
        other => {
            bail!("unknown cadence {other} (expected model, word-onset, uniform or dense)")
        }
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

    println!(
        "duplex: loading the model from {} …",
        args.weights.display()
    );
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
    let spm = match args.spm.as_deref() {
        Some(path) => mary::models::personaplex::spm::SpmTokenizer::load(path),
        None => mary::persist::load_spm_tokenizer_from_pile(&args.weights)
            .context("load the text tokenizer from the weight pile (or pass --spm)")?,
    };
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

    // Generation-only pacing: how far the model may run ahead of the speaker.
    // The device reports its queue one decode hop at a time, so a target below
    // one hop can never be met and a target of exactly one hop lets the queue
    // reach the device's last sample; two hops keeps a full hop in front of it.
    let nudge_after = args.nudge_after;
    let min_word_gap = args.min_word_gap;
    let mut trace_out = match args.trace.as_ref() {
        Some(path) => {
            let mut f = std::fs::File::create(path)
                .with_context(|| format!("open the frame trace {}", path.display()))?;
            use std::io::Write;
            writeln!(f, "frame\ttoken\tclass\tsource")?;
            Some(f)
        }
        None => None,
    };
    let lead_target = args.lead.unwrap_or(2 * args.decode_hop).max(1) as u64;
    let mut stalled = 0usize;

    // The ear is subscribed last, and this process opens no device: Soma holds
    // the microphone for the life of the BODY, so on a handsfree endpoint the
    // channel is Soma's open, not ours, and it outlives this session.
    let ear = if args.no_input {
        println!(
            "duplex: generation only — no ear, the speaker is the clock \
             (lead {lead_target} frames = {} ms)",
            lead_target * 80
        );
        None
    } else {
        println!(
            "duplex: subscribing to the body's microphone at {} …",
            args.soma
        );
        let ear = Ear::open(&args.soma)?;
        println!(
            "duplex: ear open — {} Hz, {} sample frames; this process owns no device, so \
             `hear` can read the same frames",
            SAMPLE_RATE, FRAME_SAMPLES
        );
        Some(ear)
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
    let mut spoken = String::new();
    let mut spoken_was_injected = false;
    let mut pad_run = 0usize;
    let mut speaking_hangover = 0usize;

    // The SHARED-MICROPHONE guard. Inside this binary turn-taking needs no
    // file — `--gate` feeds the model silence while it speaks, in process, on
    // the frame clock. The file exists for the OTHER consumers of the same
    // Soma frames: while it is there, `hear` keeps reading and discards, so it
    // does not transcribe our own voice back to us. A stale one would deafen
    // them permanently, so never trust the last run to have exited cleanly.
    if let Some(path) = args.pause_file.as_deref() {
        if faculties::turntaking::clear_stale(path) {
            println!("duplex: cleared a stale pause file at {}", path.display());
        }
        println!(
            "duplex: holding {} while audible, so a `hear` on the same body stays deaf to us",
            path.display()
        );
    }
    let mut audible: Option<faculties::turntaking::PauseGuard> = None;
    let mut audible_window = AudibleWindow::default();

    let mut seq = 0u64;
    let mut held = false;
    let mut far_loud = 0usize;
    let mut far_quiet = 0usize;
    let mut far_talking = false;
    let mut far_started_ms = 0u64;
    let mut heard_peak = 0f32;
    let mut heard_total = 0f64;
    let mut heard_frames = 0usize;

    // Is the model being DRAGGED? At each forced frame, where the token we are
    // about to force sits in the model's own ranking from the previous frame.
    // Rank 0 means it would have chosen that token itself; a large rank means
    // the schedule is off its distribution. This is the probe's measure, and
    // it is the honest one — an ear cannot tell "wrong words" from "right
    // words in a shape the model never sees", and a waveform statistic cannot
    // either. Kept always-on: one pass over the logit row is ~0.1% of a frame.
    // Split by what the token IS, because the two halves mean different
    // things. The first piece of a word is unpredictable BY CONSTRUCTION — the
    // model cannot know which word we chose — so a high rank there is the
    // price of forcing arbitrary text, not evidence of a bad schedule. A
    // within-word continuation is the opposite: the model is confident about
    // how a word it has already started will finish, so a high rank THERE is
    // the schedule genuinely fighting it. That is the number a cadence change
    // should move.
    let mut rank_onset: Vec<usize> = Vec::new();
    let mut rank_cont: Vec<usize> = Vec::new();
    let mut rank_pad: Vec<usize> = Vec::new();
    // The RHYTHM actually produced: frames from one word to the next. A fixed
    // schedule makes this a constant by construction; letting the model choose
    // the moments is only worth anything if it is not.
    let mut word_gaps: Vec<usize> = Vec::new();
    let mut since_word = 0usize;
    // Free timing, watched: how often the model picked the moment itself, and
    // how often it sat on PAD long enough that we had to start the word for
    // it. A nudge is us imposing rhythm again, so it is counted, not hidden.
    let mut model_chose = 0usize;
    let mut nudged = 0usize;
    let mut wait_frames = 0usize;
    // Frames we held PAD because the model wanted the next word sooner than
    // `--min-word-gap` allows, and frames since the last onset went out.
    let mut held_back = 0usize;
    let mut since_onset = usize::MAX / 2;

    let mut frame_index = 0usize;
    let mut step_total = 0f64;
    let mut step_max = 0f64;
    let mut over_budget = 0usize;
    let mut step_times: Vec<f64> = Vec::new();
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
            let now_held = floor_held(session)?;
            if now_held != held {
                println!(
                    "duplex: floor {}",
                    if now_held {
                        "TAKEN — silent"
                    } else {
                        "released"
                    }
                );
                held = now_held;
            }
            for line in drain_inject(session) {
                println!("duplex: to say — {line}");
                queued.extend(cadence_schedule(&spm, &line, args.pace, cadence));
                injected_text.push_back(line);
            }
        }

        // THE MICROPHONE IS THE CLOCK — one layer removed, and still no timer:
        // the ear blocks until the body hands over the frame the device just
        // produced.
        let samples = match ear.as_ref() {
            Some(ear) => match ear.next_frame() {
                Some(frame) => Some(frame),
                None => {
                    match ear.ended() {
                        Some(reason) => eprintln!("duplex: the body's stream ended — {reason}"),
                        None => eprintln!("duplex: the body stopped producing frames"),
                    }
                    break;
                }
            },
            None => {
                // No microphone means no clock on the input side — so THE
                // SPEAKER IS THE CLOCK. Never a `sleep(FRAME - work)`: that
                // is a second clock, it overshoots in one direction only, and
                // the deficit lands as rebuffering. See [`Mouth::pace`].
                if !mouth.pace(lead_target) {
                    stalled += 1;
                }
                None
            }
        };

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
                far_started_ms = now_millis()?;
            } else if far_talking && far_quiet >= VOICE_RELEASE_FRAMES {
                far_talking = false;
                let seconds = (now_millis()?.saturating_sub(far_started_ms)) as f64 / 1000.0;
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
        let heard: Option<[i64; 8]> = match samples {
            // While the model speaks, an endpoint without echo cancellation
            // would hear itself; gate in software, never by touching the
            // device.
            Some(_) if args.gate && speaking_hangover > 0 => Some(SILENCE),
            Some(frame) => {
                let codes = pipeline
                    .encoder
                    .encode_stream_frame(&mut encoder_state, &frame);
                Some(std::array::from_fn(|q| codes[q] as i64))
            }
            None => None,
        };

        // The three states of the mouth.
        //   held      — silent: text padded AND agent audio forced to silence.
        //   speaking  — the injected line, paced to the text stream's cadence.
        //   otherwise — the floor policy decides whether it may find its own
        //               words; under `listen` it may only backchannel.
        let was_speaking_injected = !queued.is_empty();
        // Arbitration only while a line is draining and the floor is ours.
        // A held floor is an explicit instruction to be silent and must not be
        // handed back to the model's judgement.
        let free_timing = cadence == Cadence::Model && was_speaking_injected && !held;
        let (forced_text, forced_audio) = if held {
            (Some(TEXT_PAD), Some(&SILENCE))
        } else if free_timing {
            // The queue is drained inside the arbiter, at the moment the model
            // asks for a word — not here, on a schedule.
            (None, None)
        } else if !queued.is_empty() {
            // `queued` is a FRAME schedule, not a token list: the gaps are
            // already in it, placed by `cadence_schedule`.
            (queued.pop_front(), None)
        } else {
            match floor_policy {
                Floor::Listen => (Some(TEXT_PAD), None),
                Floor::Converse => (None, None),
            }
        };

        // Two ways to put a word on stream 0, and they divide the labour
        // differently. Forcing a token supplies WHAT is said and WHEN; under
        // `--cadence model` we supply only the what, and the model keeps the
        // when — its own pauses, their lengths, its own `<epad>` placement.
        let step_api = PersonaPlexStepApi::select(args.no_input, free_timing);
        let trace = if free_timing {
            let queue = &mut queued;
            let waited = &mut wait_frames;
            let chose = &mut model_chose;
            let nudges = &mut nudged;
            let held = &mut held_back;
            let gap = &mut since_onset;
            let spm_ref = &spm;
            let onset = move |t: i64| {
                t >= N_TEXT_SPECIALS && spm_ref.piece_bytes(t).starts_with("\u{2581}".as_bytes())
            };
            let mut decide = |_logits: &[f32], sampled: i64| -> i64 {
                if sampled >= N_TEXT_SPECIALS {
                    // It decided to speak. The moment is its own; the word is
                    // ours — unless a floor is set and it wants to start the
                    // next WORD sooner than that allows. Then we hold, which
                    // is us imposing rhythm again, so it is counted.
                    let next_onset = queue.front().copied().map(onset).unwrap_or(false);
                    if min_word_gap > 0 && next_onset && *gap < min_word_gap {
                        *gap += 1;
                        *held += 1;
                        return TEXT_PAD;
                    }
                    *waited = 0;
                    *chose += 1;
                    let t = queue.pop_front().unwrap_or(sampled);
                    if onset(t) {
                        *gap = 0;
                    } else {
                        *gap += 1;
                    }
                    t
                } else if *waited >= nudge_after {
                    // It has held silence longer than we are willing to wait.
                    // Start the word for it and count that we did.
                    *waited = 0;
                    *nudges += 1;
                    let t = queue.pop_front().unwrap_or(sampled);
                    if onset(t) {
                        *gap = 0;
                    } else {
                        *gap += 1;
                    }
                    t
                } else {
                    // PAD or EPAD: leave it exactly as sampled. This is the
                    // whole point — the pause is the model's.
                    *waited += 1;
                    *gap += 1;
                    sampled
                }
            };
            match (step_api, heard.as_ref()) {
                (PersonaPlexStepApi::DuplexArbitrated, Some(heard)) => {
                    pipeline.step_arbitrated(Some(heard), forced_audio, &mut decide)
                }
                (PersonaPlexStepApi::OutputOnlyArbitrated, None) => {
                    pipeline.step_output_only_arbitrated(forced_audio, &mut decide)
                }
                _ => unreachable!("PersonaPlex input protocol changed within one frame"),
            }
        } else {
            match (step_api, heard.as_ref()) {
                (PersonaPlexStepApi::Duplex, Some(heard)) => {
                    pipeline.step(Some(heard), forced_audio, forced_text)
                }
                (PersonaPlexStepApi::OutputOnly, None) => {
                    pipeline.step_output_only(forced_audio, forced_text)
                }
                _ => unreachable!("PersonaPlex input protocol changed within one frame"),
            }
        };
        // What actually went to the depformer this frame, whichever path chose
        // it. Under arbitration this is the substituted token, not the sample.
        let chosen: Option<i64> = if free_timing {
            Some(trace.next_text)
        } else {
            forced_text
        };
        let elapsed = step_start.elapsed().as_secs_f64() * 1e3;
        step_total += elapsed;
        step_max = step_max.max(elapsed);
        step_times.push(elapsed);
        if elapsed > 80.0 {
            over_budget += 1;
        }

        // Is the model being DRAGGED? Where the token we forced sits in the
        // model's own ranking for that frame. Rank 0 means it wanted the token
        // anyway; a large rank means the schedule is off its distribution. An
        // ear cannot tell "wrong words" from "right words in a shape the model
        // never sees", and no waveform statistic can either — this can.
        //
        // It is THIS step's logit row, not the previous one: the step both
        // reads the row and consumes the token it was handed, so the row and
        // the token are the same frame's. That is not an assumption — both
        // pairings were scored side by side, and only this one puts a
        // within-word continuation where it obviously belongs (p50 rank 1,
        // against 14910 for the previous row). Kept always-on: one pass over
        // the logit row is ~0.1% of a frame.
        //
        // Split by what the token IS, because the halves mean different
        // things. The first piece of a word is ours to choose, so the model
        // cannot fully anticipate it and a moderate rank there is the price of
        // forcing arbitrary text. A within-word continuation is the opposite —
        // the model is confident how a word it already started will finish, so
        // a high rank THERE is the schedule genuinely fighting it, and that is
        // the number a cadence change has to move.
        if was_speaking_injected {
            if let Some(t) = chosen {
                if !trace.text_logits.is_empty() && (t as usize) < trace.text_logits.len() {
                    let lv = trace.text_logits[t as usize];
                    let rank = trace.text_logits.iter().filter(|&&v| v > lv).count();
                    if t < N_TEXT_SPECIALS {
                        rank_pad.push(rank);
                    } else if spm.piece_bytes(t).starts_with("\u{2581}".as_bytes()) {
                        rank_onset.push(rank);
                    } else {
                        rank_cont.push(rank);
                    }
                }
            }
        }
        if let Some(f) = trace_out.as_mut() {
            use std::io::Write;
            let t = chosen.unwrap_or(-1);
            let class = if t < 0 {
                "none"
            } else if t == TEXT_EPAD {
                "epad"
            } else if t < N_TEXT_SPECIALS {
                "pad"
            } else if spm.piece_bytes(t).starts_with("\u{2581}".as_bytes()) {
                "onset"
            } else {
                "cont"
            };
            let source = if free_timing { "model" } else { "schedule" };
            let _ = writeln!(f, "{frame_index}\t{t}\t{class}\t{source}");
        }

        // Rhythm, measured wherever it came from.
        if was_speaking_injected {
            match chosen {
                Some(t) if t >= N_TEXT_SPECIALS => {
                    word_gaps.push(since_word);
                    since_word = 0;
                }
                _ => since_word += 1,
            }
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

        // Hold the pause file across the whole time our voice is IN THE ROOM,
        // which is the generation window plus whatever the decoder and the
        // speaker still have queued. Software only: nothing here touches a
        // device, and `hear` keeps reading throughout.
        if let Some(path) = args.pause_file.as_deref() {
            let sounding = audible_window.observe(speaking_hangover > 0, mouth.lead() as usize);
            if sounding && audible.is_none() {
                audible = Some(faculties::turntaking::PauseGuard::hold(path));
            } else if !sounding {
                audible = None;
            }
        }

        // An utterance ends where the text stream goes quiet — but NOT while
        // a line is still being said. A quiet stretch is only an ending when
        // there is nothing left to say; until the queue is drained it is a
        // pause inside the line.
        //
        // This became load-bearing when the model took over the timing. A
        // scheduled cadence bounded every gap at `--pace` frames, so a pause
        // could never reach `--utterance-gap`; the model's own pauses run to
        // 25 frames, well past it, and the rule then cut one sentence into six
        // transcript entries mid-line. The audio and the words were never
        // affected, but the pile recorded fragments and the injected-line
        // bookkeeping advanced once per fragment.
        if queued.is_empty() && pad_run >= args.utterance_gap && !spoken.trim().is_empty() {
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
                    at_ms: now_millis()?,
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
            let skipped = ear.as_ref().map(Ear::skipped).unwrap_or(0);
            // The BODY's frame, not ours: a `hear` on the same microphone is
            // counting the same one, so the two logs can be laid side by side
            // and read as one instant.
            let body = ear
                .as_ref()
                .map(|ear| ear.clock().1.to_string())
                .unwrap_or_else(|| "-".into());
            println!(
                "  [clock] {:.1}s | body frame {body} | step mean {:.1} ms max {:.1} ms | \
                 {} over budget | {} in skipped | {} out dropped | {} underruns | lead {} | \
                 ear rms mean {:.4} peak {:.4}",
                session_start.elapsed().as_secs_f64(),
                step_total / frame_index as f64,
                step_max,
                over_budget,
                skipped,
                mouth.dropped(),
                mouth.underruns(),
                mouth.lead(),
                heard_total / heard_frames.max(1) as f64,
                heard_peak
            );
        }
    }

    // A turn still in progress at shutdown is still a turn. Without this the
    // far end talking right up to the end leaves no trace at all, which reads
    // as "they said nothing" rather than "we stopped listening".
    if far_talking {
        let seconds = (now_millis()?.saturating_sub(far_started_ms)) as f64 / 1000.0;
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
                at_ms: now_millis()?,
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
         \x20 {} of {} frames over budget ({:.0}%), {} playback underruns, \
         {} speaker stalls",
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
        mouth.underruns(),
        stalled
    );
    // Was the model dragged? Report the schedule alongside its cost, so a
    // cadence claim is checkable against the model rather than against ears.
    let quantiles = |v: &mut Vec<usize>| -> (usize, usize, usize) {
        v.sort_unstable();
        let at = |p: f64| v[((v.len() - 1) as f64 * p).round() as usize];
        (at(0.50), at(0.90), at(0.99))
    };
    if rank_onset.is_empty() && rank_cont.is_empty() {
        println!("  forced-token rank: nothing was forced");
    } else {
        let total = rank_onset.len() + rank_cont.len() + rank_pad.len();
        println!(
            "  forced-token rank in the model's own logits ({} cadence, gap {}, {} forced frames, {:.0}% PAD):",
            args.cadence,
            args.pace,
            total,
            100.0 * rank_pad.len() as f64 / total.max(1) as f64,
        );
        for (what, v) in [
            ("word continuation", &mut rank_cont),
            ("word onset       ", &mut rank_onset),
            ("pad              ", &mut rank_pad),
        ] {
            if v.is_empty() {
                continue;
            }
            let n = v.len();
            let (a, b, c) = quantiles(v);
            println!("   {what}  p50 {a:>6}  p90 {b:>6}  p99 {c:>6}  (n={n})");
        }
    }
    if !word_gaps.is_empty() {
        let n = word_gaps.len();
        let spread = {
            let mut u: Vec<usize> = word_gaps.clone();
            u.sort_unstable();
            u.dedup();
            u.len()
        };
        let mean = word_gaps.iter().sum::<usize>() as f64 / n as f64;
        let (g50, g90, g99) = quantiles(&mut word_gaps);
        println!(
            "  rhythm — frames from one word to the next: p50 {g50}  p90 {g90}  p99 {g99}  mean {mean:.2}  ({spread} distinct values over {n} words)"
        );
    }
    if model_chose + nudged > 0 {
        println!(
            "  timing: the model chose the moment {model_chose} times, we started it {nudged} times ({:.0}% ours)",
            100.0 * nudged as f64 / (model_chose + nudged) as f64
        );
        if held_back > 0 {
            println!(
                "          and held it back {held_back} frames for --min-word-gap {min_word_gap}"
            );
        }
    }
    // Give the other consumers their ears back before anything slow.
    drop(audible);
    drop(ear);
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

    /// The frame shape is not this binary's to choose: it is Soma's wire
    /// format, and a divergence would be two agreeing constants drifting
    /// apart. (Also enforced at compile time by the `const _` above.)
    #[test]
    fn the_frame_is_somas_frame() {
        assert_eq!(FRAME_SAMPLES, soma_client::FRAME_SAMPLES);
        assert_eq!(SAMPLE_RATE, soma_client::SAMPLE_RATE);
        assert_eq!(FRAME_SAMPLES as u32 * 1_000 / SAMPLE_RATE, 80);
    }

    /// User-audio presence and text arbitration are independent protocol
    /// axes. In particular, generation-only mode must select Mary's explicit
    /// output-only API under both scheduled and model-timed speech; a learned
    /// silence frame is an ordinary duplex input, not an output-only stand-in.
    #[cfg(feature = "duplex")]
    #[test]
    fn personaplex_step_api_keeps_output_only_separate_from_duplex() {
        use PersonaPlexStepApi::*;

        assert_eq!(PersonaPlexStepApi::select(false, false), Duplex);
        assert_eq!(PersonaPlexStepApi::select(false, true), DuplexArbitrated);
        assert_eq!(PersonaPlexStepApi::select(true, false), OutputOnly);
        assert_eq!(PersonaPlexStepApi::select(true, true), OutputOnlyArbitrated);
    }

    /// A loop slower than the world skips FORWARD rather than falling behind,
    /// and says how much it skipped. The model's step count is its clock, so
    /// it cannot catch up by stepping faster.
    #[test]
    fn a_slow_loop_skips_forward_and_counts_it() {
        let ear = Ear {
            ring: Arc::new((Mutex::new(EarRing::default()), Condvar::new())),
            stop: Arc::new(AtomicBool::new(false)),
            thread: None,
            soma: "test".into(),
        };
        {
            let mut ring = ear.ring.0.lock().unwrap();
            for value in 0..(MAX_BACKLOG_FRAMES + 5) {
                ring.frames.push_back([value as f32; FRAME_SAMPLES]);
            }
        }
        let frame = ear.next_frame().expect("a frame");
        // Everything but the last two frames is dropped, and the frame handed
        // over is the current one, not the stale head.
        assert_eq!(frame[0], (MAX_BACKLOG_FRAMES + 3) as f32);
        assert_eq!(ear.skipped(), MAX_BACKLOG_FRAMES + 3);
    }

    /// The shared-microphone guard's one rule: the window must not close while
    /// our voice is still coming out of the speaker. It opens on the first
    /// speaking frame, stays open for the whole generation window, and then
    /// outlasts it by exactly what the mouth still had in flight — never less.
    #[test]
    fn the_audible_window_outlasts_generation_by_what_is_still_in_flight() {
        let mut window = AudibleWindow::default();
        assert!(!window.observe(false, 0), "silence is not audible");
        // Speaking, with 6 frames sitting in front of the speaker.
        for _ in 0..5 {
            assert!(window.observe(true, 6));
        }
        // Generation stops. The tail is what was queued plus the prebuffer,
        // counted down one frame per frame.
        let tail = 6 + PREBUFFER_FRAMES;
        for frame in 0..tail {
            assert!(
                window.observe(false, 0),
                "frame {frame} of the tail is still in the room"
            );
        }
        assert!(
            !window.observe(false, 0),
            "and then, and only then, silence"
        );
    }

    /// A stream that ended hands over what it already delivered before it
    /// reports the ending: missing speech must never read as silence, and
    /// delivered speech must never be swallowed by the ending.
    #[test]
    fn buffered_frames_survive_the_end_of_the_stream() {
        let ear = Ear {
            ring: Arc::new((Mutex::new(EarRing::default()), Condvar::new())),
            stop: Arc::new(AtomicBool::new(false)),
            thread: None,
            soma: "test".into(),
        };
        {
            let mut ring = ear.ring.0.lock().unwrap();
            ring.frames.push_back([0.5; FRAME_SAMPLES]);
            ring.ended = Some("the body stopped".into());
        }
        assert_eq!(ear.next_frame().expect("the buffered frame")[0], 0.5);
        assert!(ear.next_frame().is_none());
        assert_eq!(ear.ended().as_deref(), Some("the body stopped"));
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
        assert!(!floor_held(session).unwrap());
        take_floor(session, 60).unwrap();
        assert!(floor_held(session).unwrap());
        give_floor(session).unwrap();
        assert!(!floor_held(session).unwrap());
        // A reader that never comes back must not mute the channel forever.
        take_floor(session, 0).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(!floor_held(session).unwrap());
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
        assert!(floor_held(session).unwrap(), "reading takes the floor");
        cmd_say(session, "a reply", false).unwrap();
        assert_eq!(read_cursor(session), 3, "acting on a read consumes it");
        assert!(!floor_held(session).unwrap(), "saying gives the floor back");
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
