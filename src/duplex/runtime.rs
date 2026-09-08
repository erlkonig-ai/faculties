//! Explicit host speech runtime. No discovery or finite session operation
//! invokes this module's device/model entrypoints. Callers own cancellation;
//! it is observed between physical frames, never by closing Soma's microphone.
#![cfg_attr(not(feature = "duplex"), allow(dead_code))]

#[cfg(any(feature = "duplex", test))]
use super::operations::*;
use crate::{clock, out::Out};
use anyhow::{bail, Context, Result};
use std::collections::VecDeque;
#[cfg(any(feature = "duplex", test))]
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Samples in one model frame at 24 kHz (80 ms).
///
/// Taken FROM Soma's wire format rather than agreed with it: the model's frame
/// and the body's frame are the same frame, and two constants that merely
/// happen to match are a drift waiting to happen.
pub const FRAME_SAMPLES: usize = soma_client::FRAME_SAMPLES;
/// The model's canonical sample rate — likewise the body's.
pub const SAMPLE_RATE: u32 = soma_client::SAMPLE_RATE;
const _: () = assert!(FRAME_SAMPLES * 1_000 == 80 * SAMPLE_RATE as usize);

/// Where the body is, unless told otherwise. The same default the rest of the
/// suite uses (`voice`, `body`, `hear`).
pub const DEFAULT_SOMA: &str = "http://localhost:8000";
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
pub const DEFAULT_UTTERANCE_GAP: usize = 10;
/// Frames above the speech floor before the far end counts as talking.
const VOICE_ONSET_FRAMES: usize = 3;
/// Frames below it before their turn counts as over.
const VOICE_RELEASE_FRAMES: usize = 12;
/// RMS below this is room noise, not speech.
const VOICE_FLOOR: f32 = 0.012;

pub const DEFAULT_SYSTEM: &str = "You are a warm, direct conversational partner. \
Keep replies short and spoken — no lists, no markdown. Answer in the language \
you were addressed in.";

#[derive(Clone, Debug)]
pub struct RunOptions {
    /// Model weight pile.
    pub weights: PathBuf,
    /// Packaged voice prompt the session speaks with.
    pub voice_prompt: PathBuf,
    /// Text tokenizer file, overriding the copy inside `--weights`.
    ///
    /// Needed because the two halves of the weight pile drifted apart: the
    /// codec loader wants a `mary-model-bundles` collection and the pile-side
    /// SPM loader still wants the `mary-model-graph` the bundle migration
    /// replaced, so no pile on this machine satisfies both. Whatever is loaded
    /// is checked against the model's own `TEXT_CARD` below, so a wrong
    /// tokenizer is a loud failure rather than gibberish. `mary`'s own
    /// PersonaPlex bins take the same flag.
    pub spm: Option<PathBuf>,
    /// Base URL of the Soma that owns the microphone. This process opens no
    /// capture device: it subscribes, so `hear` can be reading the same frames
    /// at the same time. Not needed with `--no-input`.
    pub soma: String,
    /// EXACT name of the playback device.
    pub output: String,
    /// Weight format for the temporal stack. `q8` is the default because on
    /// an Apple GPU it is not slower than `q4` — at these shapes the matvecs
    /// are dispatch-bound rather than bandwidth-bound, and the hardware has
    /// no FP4 units, so 4-bit is pure dequantization overhead there — while
    /// costing far less fidelity. `q4` is expected to pay on parts that DO
    /// have FP4 hardware.
    pub fmt: WeightFormat,
    /// Whether the model may hold up its own end of the conversation.
    /// `listen` forces its text stream to padding, so it hears everything,
    /// may backchannel, and says only what is injected. `converse` lets it
    /// generate its own words.
    pub floor: Floor,
    /// Spoken system prompt.
    pub system: String,
    /// Sampling temperature; 0 selects greedy decoding.
    pub temp: f32,
    /// Sampling seed.
    pub seed: u64,
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
    pub pace: usize,
    /// Write one line per frame — index, the stream-0 token, and what kind of
    /// token it was — so the audio can be read against what the text stream
    /// was doing at that instant. The way to find out whether the model puts
    /// anything in the gaps it is given: breath, a filled pause, laughter.
    pub trace: Option<PathBuf>,
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
    pub min_word_gap: usize,
    /// Under `--cadence model`, how many frames the model may hold silence
    /// mid-line before we start the next word for it. A backstop, not a
    /// rhythm: every time it fires we have taken the timing back, and the run
    /// summary reports how often that happened.
    pub nudge_after: usize,
    /// Who decides WHEN each word lands. `model` (the default) decides
    /// nothing: the model samples stream 0 itself and we substitute our words
    /// onto the frames it chose to speak, so the pauses and their lengths are
    /// its own. The rest impose a schedule and are kept as controls for the
    /// rhythm and rank numbers this command reports — `word-onset` puts a
    /// fixed gap between words, `uniform` puts one after every word piece
    /// (which splits multi-piece words across silence), `dense` uses none.
    pub cadence: Cadence,
    /// Feed the model digital silence on the input channel while it speaks,
    /// so an endpoint without echo cancellation does not hear itself.
    pub gate: bool,
    /// Padding-only frames that close an utterance.
    pub utterance_gap: usize,
    /// Pile to record the durable transcript on. Without it nothing is
    /// recorded beyond the session directory.
    pub pile: Option<PathBuf>,
    /// Signing key for the transcript pile.
    pub key: Option<PathBuf>,
    /// Stop after this many frames instead of running until interrupted.
    pub frames: Option<usize>,
    /// Also tee everything spoken to this WAV file.
    pub wav: Option<PathBuf>,
    /// Frames of context the codec decoder re-decodes on every hop. Deep by
    /// default — the decoder's transformer has a 250-frame window and no
    /// streaming state, so a shallow context makes the hop boundary audible.
    pub decode_context: usize,
    /// New frames emitted per decode call.
    pub decode_hop: usize,
    /// Do not subscribe to the capture stream and omit the model's user-audio
    /// embeddings. This is the GENERATION-ONLY channel — the model speaks and
    /// is not listened to — and it is also what to use on a handsfree endpoint
    /// whose microphone is already held open by something else. With no
    /// microphone the SPEAKER becomes the frame clock (see `--lead`).
    pub no_input: bool,
    /// Generation-only clock: frames of audio the model may run ahead of the
    /// speaker before it waits. The floor is one decode hop, since the device
    /// reports its queue a hop at a time; two hops is what keeps a hop of
    /// audio in front of the device at all times.
    pub lead: Option<usize>,
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
    pub pause_file: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WeightFormat {
    Q4,
    Q8,
    F16,
}
impl WeightFormat {
    pub fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "q4" => Self::Q4,
            "q8" => Self::Q8,
            "f16" => Self::F16,
            _ => bail!("unknown weight format {value} (expected q4, q8 or f16)"),
        })
    }
}
impl Floor {
    pub fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "listen" => Self::Listen,
            "converse" => Self::Converse,
            _ => bail!("unknown floor policy {value} (expected listen or converse)"),
        })
    }
}
impl Cadence {
    pub fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "model" => Self::Model,
            "word-onset" => Self::WordOnset,
            "uniform" => Self::Uniform,
            "dense" => Self::Dense,
            _ => bail!("unknown cadence {value} (expected model, word-onset, uniform or dense)"),
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Model => "model",
            Self::WordOnset => "word-onset",
            Self::Uniform => "uniform",
            Self::Dense => "dense",
        }
    }
}
impl RunOptions {
    pub fn new(weights: PathBuf, voice_prompt: PathBuf, output: String) -> Self {
        Self {
            weights,
            voice_prompt,
            output,
            spm: None,
            soma: DEFAULT_SOMA.into(),
            fmt: WeightFormat::Q8,
            floor: Floor::Listen,
            system: DEFAULT_SYSTEM.into(),
            temp: 0.8,
            seed: 12_345_678,
            pace: 3,
            trace: None,
            min_word_gap: 0,
            nudge_after: 25,
            cadence: Cadence::Model,
            gate: false,
            utterance_gap: DEFAULT_UTTERANCE_GAP,
            pile: None,
            key: None,
            frames: None,
            wav: None,
            decode_context: DEFAULT_DECODE_CONTEXT,
            decode_hop: DEFAULT_DECODE_HOP,
            no_input: false,
            lead: None,
            pause_file: None,
        }
    }
    /// Pure admission checks before resetting session files or opening devices.
    pub fn validate(&self) -> Result<()> {
        if self.output.trim().is_empty() {
            bail!("an exact named output device is required");
        }
        if !self.temp.is_finite() {
            bail!("sampling temperature must be finite");
        }
        if self.decode_hop == 0 {
            bail!("decode_hop must be positive");
        }
        if self.utterance_gap == 0 {
            bail!("utterance_gap must be positive");
        }
        self.decode_context
            .checked_add(self.decode_hop)
            .context("decode window overflow")?;
        if self.lead.is_none() {
            self.decode_hop
                .checked_mul(2)
                .context("default speaker lead overflow")?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct EarReport {
    pub frames: usize,
    pub wall_seconds: f64,
    pub first_frame: Option<u64>,
    pub last_frame: u64,
    pub skipped: usize,
    pub mean_rms: Option<f64>,
    pub peak_rms: Option<f32>,
    pub ended: Option<String>,
}
#[derive(Clone, Debug)]
pub struct RunReport {
    pub frames: usize,
    pub wall_seconds: f64,
    pub step_times_ms: Vec<f64>,
    pub over_budget: usize,
    pub playback_underruns: u64,
    pub speaker_stalls: usize,
    pub output_dropped: u64,
    pub input_skipped: usize,
    pub forced_onset_ranks: Vec<usize>,
    pub forced_continuation_ranks: Vec<usize>,
    pub forced_padding_ranks: Vec<usize>,
    pub word_gaps: Vec<usize>,
    pub model_chose: usize,
    pub nudged: usize,
    pub held_back: usize,
}
#[derive(Clone, Debug)]
pub struct PlaybackDevice {
    pub name: String,
    pub configuration: std::result::Result<PlaybackConfiguration, String>,
}
#[derive(Clone, Debug)]
pub struct PlaybackConfiguration {
    pub channels: u16,
    pub sample_rate: u32,
    pub sample_format: String,
}
#[cfg(feature = "audio")]
pub fn devices() -> Result<Vec<PlaybackDevice>> {
    use rodio::cpal::traits::{DeviceTrait, HostTrait};
    let mut devices = Vec::new();
    for device in rodio::cpal::default_host()
        .output_devices()
        .context("enumerate playback devices")?
    {
        devices.push(PlaybackDevice {
            name: device.name().unwrap_or_else(|_| "<unnamed>".into()),
            configuration: device
                .default_output_config()
                .map(|config| PlaybackConfiguration {
                    channels: config.channels(),
                    sample_rate: config.sample_rate(),
                    sample_format: format!("{:?}", config.sample_format()),
                })
                .map_err(|error| error.to_string()),
        });
    }
    Ok(devices)
}
#[cfg(not(feature = "audio"))]
pub fn devices() -> Result<Vec<PlaybackDevice>> {
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
pub fn ear(soma: &str, frames: usize, stop: &AtomicBool, out: &mut Out<'_>) -> Result<EarReport> {
    let ear = Ear::open(soma)?;
    out.line(format!(
        "duplex: ear open on {} — {} Hz, {} sample frames, this process owns no device",
        ear.soma,
        soma_client::SAMPLE_RATE,
        soma_client::FRAME_SAMPLES
    ))?;
    let start = Instant::now();
    let mut read = 0usize;
    let mut peak = 0f32;
    let mut total = 0f64;
    while (frames == 0 || read < frames) && !stop.load(Ordering::Relaxed) {
        let Some(frame) = ear.next_frame() else {
            break;
        };
        let level = rms(&frame);
        peak = peak.max(level);
        total += level as f64;
        read += 1;
        if read % 12 == 0 {
            let (first, last) = ear.clock();
            out.line(format!(
                "  [ear] body frame {last} (joined at {}) | {read} read | \
                 {} skipped | rms {level:.4}",
                first.unwrap_or(0),
                ear.skipped()
            ))?;
        }
    }
    let wall = start.elapsed().as_secs_f64();
    let (first, last) = ear.clock();
    out.line(format!(
        "duplex: {read} frames in {wall:.1}s — {:.2}x realtime | body frames {}..{last} | \
         {} skipped | ear rms mean {:.4} peak {:.4}",
        (read as f64 * 0.08) / wall.max(1e-9),
        first.unwrap_or(0),
        ear.skipped(),
        total / read.max(1) as f64,
        peak
    ))?;
    if let Some(reason) = ear.ended() {
        out.line(format!("duplex: the body's stream ended — {reason}"))?;
    }
    Ok(EarReport {
        frames: read,
        wall_seconds: wall,
        first_frame: first,
        last_frame: last,
        skipped: ear.skipped(),
        mean_rms: (read > 0).then_some(total / read as f64),
        peak_rms: (read > 0).then_some(peak),
        ended: ear.ended(),
    })
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
pub const DEFAULT_DECODE_CONTEXT: usize = 64;
/// New frames emitted per decode call.
pub const DEFAULT_DECODE_HOP: usize = 4;
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cadence {
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
    cancel: Arc<AtomicBool>,
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
        let cancel = Arc::new(AtomicBool::new(false));
        let worker = {
            let underruns = Arc::clone(&underruns);
            let played = Arc::clone(&played);
            let playing = Arc::clone(&playing);
            let cancel = Arc::clone(&cancel);
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
                        cancel,
                        context_frames,
                        hop_frames,
                    )
                })
                .context("spawn playback thread")?
        };
        let mouth = Self {
            frames: Some(frame_tx),
            worker: Some(worker),
            dropped,
            underruns,
            played,
            pushed: std::cell::Cell::new(0),
            playing,
            cancel,
        };
        match ready_rx.recv_timeout(Duration::from_secs(900)) {
            Ok(Ok(())) => {}
            Ok(Err(message)) => bail!("playback: {message}"),
            Err(error) => bail!("playback did not come up: {error}"),
        }
        Ok(mouth)
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
impl Drop for Mouth {
    fn drop(&mut self) {
        // Early return cancels pending playback, then closes the receive wait
        // before joining. A currently executing codec/device call must return;
        // this is scoped ownership, not forced interruption of native code.
        self.cancel.store(true, Ordering::Relaxed);
        self.frames.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
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
    cancel: Arc<AtomicBool>,
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
        if cancel.load(Ordering::Relaxed) {
            player.stop();
            return Ok(());
        }
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
    while !player.empty() && Instant::now() < deadline && !cancel.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(20));
    }
    if cancel.load(Ordering::Relaxed) {
        player.stop();
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
    warnings: mpsc::Receiver<String>,
    dropped_warnings: Arc<std::sync::atomic::AtomicUsize>,
    dropped_lines: std::cell::Cell<usize>,
}
impl Ledger {
    fn spawn(pile: Option<PathBuf>, key: Option<PathBuf>) -> Result<Self> {
        let (warning_tx, warnings) = mpsc::sync_channel(16);
        let dropped_warnings = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let Some(pile) = pile else {
            return Ok(Self {
                lines: None,
                worker: None,
                warnings,
                dropped_warnings,
                dropped_lines: std::cell::Cell::new(0),
            });
        };
        let (tx, rx) = mpsc::sync_channel::<String>(64);
        let dropped = Arc::clone(&dropped_warnings);
        let worker = std::thread::Builder::new()
            .name("duplex-ledger".into())
            .spawn(move || {
                while let Ok(text) = rx.recv() {
                    if let Err(error) = record_utterance(&pile, key.as_deref(), &text) {
                        if warning_tx
                            .try_send(format!("duplex: could not record utterance: {error:#}"))
                            .is_err()
                        {
                            dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            })
            .context("spawn transcript ledger")?;
        Ok(Self {
            lines: Some(tx),
            worker: Some(worker),
            warnings,
            dropped_warnings,
            dropped_lines: std::cell::Cell::new(0),
        })
    }
    fn record(&self, text: &str) {
        if let Some(lines) = &self.lines {
            if lines.try_send(text.to_owned()).is_err() {
                self.dropped_lines.set(self.dropped_lines.get() + 1);
            }
        }
    }
    fn report(&self, out: &mut Out<'_>) -> Result<()> {
        for warning in self.warnings.try_iter() {
            out.line(warning)?;
        }
        let dropped = self.dropped_warnings.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            out.line(format!(
                "duplex: {dropped} additional ledger errors exceeded the diagnostic queue"
            ))?;
        }
        let dropped = self.dropped_lines.replace(0);
        if dropped > 0 {
            out.line(format!(
                "duplex: {dropped} utterances could not enter the durable transcript queue"
            ))?;
        }
        Ok(())
    }
    fn finish(mut self, out: &mut Out<'_>) -> Result<()> {
        self.lines.take();
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("transcript ledger thread panicked"))?;
        }
        self.report(out)
    }
}

impl Drop for Ledger {
    fn drop(&mut self) {
        // The sender is closed FIRST; otherwise the worker could stay blocked
        // in recv forever. Already queued utterances finish before we return.
        self.lines.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(any(feature = "duplex", test))]
fn spoken_line(session: &Path, line: &Line, ledger: &Ledger, out: &mut Out<'_>) -> Result<()> {
    let transcript = append_line(session, line);
    ledger.record(&line.text);
    transcript.context("record generated utterance in the session transcript")?;
    out.line(format!("  [{}] {}", line.speaker, line.text))
}

/// Schedule the consumed prefix even when cleanup of a later queue file
/// failed. Such failures are recoverable; identical consecutive failures are
/// reported once, not on every control poll. This is only an in-memory
/// handoff: an Out failure still terminates run, and does not make queued or
/// partially generated speech durable.
#[cfg(any(feature = "duplex", test))]
fn accept_inject_drain(
    drained: InjectDrain,
    last_cleanup_failure: &mut Option<String>,
    mut schedule: impl FnMut(&str),
    out: &mut Out<'_>,
) -> Result<()> {
    for line in &drained.lines {
        schedule(line);
    }
    for line in drained.lines {
        out.line(format!("duplex: to say — {line}"))?;
    }
    let failure = drained.cleanup_failure.map(|error| format!("{error:#}"));
    if failure != *last_cleanup_failure {
        if let Some(error) = &failure {
            out.line(format!("duplex: inject queue cleanup failed — {error}"))?;
        }
        *last_cleanup_failure = failure;
    }
    Ok(())
}

/// One utterance, one commit — the exact record shape `voice shout` writes, so
/// nothing that reads the collection has to learn a new one.
fn record_utterance(pile_path: &Path, key: Option<&Path>, text: &str) -> Result<()> {
    use crate::collection_names::open_configured;
    use crate::schemas::voice::{CHANNEL_SHOUT, COLLECTION_SCOPE_ID};
    use crate::storage::{load_signer, open_pile_strict};
    use triblespace::core::collection::CollectionStoreExt;
    use triblespace::core::metadata;
    use triblespace::prelude::*;

    let stamp = clock::point_now()?;
    let mut fragment = crate::voice::utterance_fragment(CHANNEL_SHOUT, text, None, stamp)?;

    let signer = load_signer(pile_path, key)?;
    let mut pile = open_pile_strict(pile_path)?;
    let collection = open_configured(&mut pile, COLLECTION_SCOPE_ID, signer.verifying_key())?;
    let result = (|| -> Result<()> {
        crate::voice::validate_staged_payloads(&mut fragment)?;
        fragment.describe_with(entity! { metadata::description: "duplex spoke" });
        pile.commit(collection, &signer, fragment)
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
pub fn run(
    _session: &Path,
    _args: &RunOptions,
    _stop: &AtomicBool,
    _out: &mut Out<'_>,
) -> Result<RunReport> {
    bail!("the channel is not compiled into this build (build with --features duplex)")
}

/// What the model is allowed to do with its own text stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Floor {
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
pub fn run(
    session: &Path,
    args: &RunOptions,
    stop: &AtomicBool,
    out: &mut Out<'_>,
) -> Result<RunReport> {
    use mary::models::personaplex::config as model_cfg;
    use mary::models::personaplex::pipeline::{agent_codes, RealtimePipeline, SILENCE};
    use mary::models::personaplex::prompt::Prompt;
    use mary::models::personaplex::sampling::SamplingConfig;
    use mary::models::personaplex::temporal_metal::WeightFmt;

    args.validate()?;
    let fmt = match args.fmt {
        WeightFormat::Q4 => WeightFmt::Q4,
        WeightFormat::Q8 => WeightFmt::Q8,
        WeightFormat::F16 => WeightFmt::F16,
    };
    let cadence = args.cadence;
    let floor_policy = args.floor;
    ensure_session(session)?;
    // A fresh run starts a fresh transcript; the durable copy is the pile.
    let _ = std::fs::remove_file(session.join(TRANSCRIPT_FILE));
    let _ = std::fs::remove_file(session.join(HOLD_FILE));
    write_cursor(session, 0)?;

    set_interactive_qos();

    // The mouth loads its own codec while the model loads, so the two long
    // loads overlap instead of queueing.
    out.line(format!("duplex: bringing up '{}' …", args.output))?;
    let mouth = Mouth::spawn(
        args.weights.clone(),
        args.output.clone(),
        args.wav.clone(),
        args.decode_context,
        args.decode_hop,
    )?;

    out.line(format!(
        "duplex: loading the model from {} …",
        args.weights.display()
    ))?;
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
    out.line(format!(
        "duplex: model ready in {:.1}s ({} prompt steps)",
        load_start.elapsed().as_secs_f64(),
        prompt.total_steps()
    ))?;

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
        out.line(format!(
            "duplex: generation only — no ear, the speaker is the clock \
             (lead {lead_target} frames = {} ms)",
            lead_target * 80
        ))?;
        None
    } else {
        out.line(format!(
            "duplex: subscribing to the body's microphone at {} …",
            args.soma
        ))?;
        let ear = Ear::open(&args.soma)?;
        out.line(format!(
            "duplex: ear open — {} Hz, {} sample frames; this process owns no device, so \
             `hear` can read the same frames",
            SAMPLE_RATE, FRAME_SAMPLES
        ))?;
        Some(ear)
    };

    let ledger = Ledger::spawn(args.pile.clone(), args.key.clone())?;
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
        if crate::turntaking::clear_stale(path) {
            out.line(format!(
                "duplex: cleared a stale pause file at {}",
                path.display()
            ))?;
        }
        out.line(format!(
            "duplex: holding {} while audible, so a `hear` on the same body stays deaf to us",
            path.display()
        ))?;
    }
    let mut audible: Option<crate::turntaking::PauseGuard> = None;
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
    let mut last_inject_cleanup_failure = None;

    out.line(format!(
        "duplex: live. `duplex read` to catch up, `duplex say` to speak, Ctrl-C to stop."
    ))?;
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
            ledger.report(out)?;
            let now_held = floor_held(session)?;
            if now_held != held {
                out.line(format!(
                    "duplex: floor {}",
                    if now_held {
                        "TAKEN — silent"
                    } else {
                        "released"
                    }
                ))?;
                held = now_held;
            }
            accept_inject_drain(
                drain_inject(session)?,
                &mut last_inject_cleanup_failure,
                |line| {
                    queued.extend(cadence_schedule(&spm, line, args.pace, cadence));
                    injected_text.push_back(line.to_owned());
                },
                out,
            )?;
        }

        // THE MICROPHONE IS THE CLOCK — one layer removed, and still no timer:
        // the ear blocks until the body hands over the frame the device just
        // produced.
        let samples = match ear.as_ref() {
            Some(ear) => match ear.next_frame() {
                Some(frame) => Some(frame),
                None => {
                    match ear.ended() {
                        Some(reason) => {
                            out.line(format!("duplex: the body's stream ended — {reason}"))?
                        }
                        None => out.line("duplex: the body stopped producing frames")?,
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
                audible = Some(crate::turntaking::PauseGuard::hold(path));
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
            spoken_line(
                session,
                &Line {
                    seq,
                    at_ms: now_millis()?,
                    speaker: speaker.tag().into(),
                    text: line.clone(),
                },
                &ledger,
                out,
            )?;
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
            out.line(format!(
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
            ))?;
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
        let speaker = if spoken_was_injected {
            Speaker::Agent
        } else {
            Speaker::Model
        };
        spoken_line(
            session,
            &Line {
                seq,
                at_ms: now_millis()?,
                speaker: speaker.tag().into(),
                text: line.clone(),
            },
            &ledger,
            out,
        )?;
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
    out.line(format!(
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
    ))?;
    // Was the model dragged? Report the schedule alongside its cost, so a
    // cadence claim is checkable against the model rather than against ears.
    let quantiles = |v: &mut Vec<usize>| -> (usize, usize, usize) {
        v.sort_unstable();
        let at = |p: f64| v[((v.len() - 1) as f64 * p).round() as usize];
        (at(0.50), at(0.90), at(0.99))
    };
    if rank_onset.is_empty() && rank_cont.is_empty() {
        out.line(format!("  forced-token rank: nothing was forced"))?;
    } else {
        let total = rank_onset.len() + rank_cont.len() + rank_pad.len();
        out.line(format!(
            "  forced-token rank in the model's own logits ({} cadence, gap {}, {} forced frames, {:.0}% PAD):",
            args.cadence.name(),
            args.pace,
            total,
            100.0 * rank_pad.len() as f64 / total.max(1) as f64,
        ))?;
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
            out.line(format!(
                "   {what}  p50 {a:>6}  p90 {b:>6}  p99 {c:>6}  (n={n})"
            ))?;
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
        out.line(format!(
            "  rhythm — frames from one word to the next: p50 {g50}  p90 {g90}  p99 {g99}  mean {mean:.2}  ({spread} distinct values over {n} words)"
        ))?;
    }
    if model_chose + nudged > 0 {
        out.line(format!(
            "  timing: the model chose the moment {model_chose} times, we started it {nudged} times ({:.0}% ours)",
            100.0 * nudged as f64 / (model_chose + nudged) as f64
        ))?;
        if held_back > 0 {
            out.line(format!(
                "          and held it back {held_back} frames for --min-word-gap {min_word_gap}"
            ))?;
        }
    }
    let report = RunReport {
        frames: frame_index,
        wall_seconds: wall,
        step_times_ms: step_times,
        over_budget,
        playback_underruns: mouth.underruns(),
        speaker_stalls: stalled,
        output_dropped: mouth.dropped(),
        input_skipped: ear.as_ref().map(Ear::skipped).unwrap_or(0),
        forced_onset_ranks: rank_onset,
        forced_continuation_ranks: rank_cont,
        forced_padding_ranks: rank_pad,
        word_gaps,
        model_chose,
        nudged,
        held_back,
    };
    // Give the other consumers their ears back before anything slow.
    drop(audible);
    drop(ear);
    mouth.finish()?;
    ledger.finish(out)?;
    Ok(report)
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
#[cfg(any(feature = "duplex", test))]
struct WavWriter {
    file: std::fs::File,
    data_bytes: u32,
}

#[cfg(any(feature = "duplex", test))]
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

#[cfg(any(feature = "duplex", test))]
impl Drop for WavWriter {
    fn drop(&mut self) {
        use std::io::{Seek, SeekFrom};
        if self.file.seek(SeekFrom::Start(0)).is_ok() {
            let _ = self.file.write_all(&wav_header(self.data_bytes));
            let _ = self.file.flush();
        }
    }
}

#[cfg(any(feature = "duplex", test))]
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
#[path = "tests.rs"]
mod tests;
