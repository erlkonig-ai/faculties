//! Full host CLI. Session/default paths, devices, model files, signal handling
//! and long-lived runtime options belong here, never to the MCP schemas.
use super::runtime::{
    self, Cadence, Floor, RunOptions, WeightFormat, DEFAULT_DECODE_CONTEXT, DEFAULT_DECODE_HOP,
    DEFAULT_SOMA, DEFAULT_SYSTEM, DEFAULT_UTTERANCE_GAP,
};
use super::{presentation, ReadOptions, Session};
use crate::out::Out;
use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "duplex",
    about = "A continuously running spoken channel with a transcript to read from and inject into."
)]
pub struct Cli {
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

impl TryFrom<RunArgs> for RunOptions {
    type Error = anyhow::Error;
    fn try_from(args: RunArgs) -> Result<Self> {
        let options = Self {
            weights: args.weights,
            voice_prompt: args.voice_prompt,
            spm: args.spm,
            soma: args.soma,
            output: args.output,
            fmt: WeightFormat::parse(&args.fmt)?,
            floor: Floor::parse(&args.floor)?,
            system: args.system,
            temp: args.temp,
            seed: args.seed,
            pace: args.pace,
            trace: args.trace,
            min_word_gap: args.min_word_gap,
            nudge_after: args.nudge_after,
            cadence: Cadence::parse(&args.cadence)?,
            gate: args.gate,
            utterance_gap: args.utterance_gap,
            pile: args.pile,
            key: args.key,
            frames: args.frames,
            wav: args.wav,
            decode_context: args.decode_context,
            decode_hop: args.decode_hop,
            no_input: args.no_input,
            lead: args.lead,
            pause_file: args.pause_file,
        };
        options.validate()?;
        Ok(options)
    }
}
fn default_session() -> PathBuf {
    std::env::temp_dir().join("duplex")
}

pub fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.command.is_none() {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }
    crate::cli::with_output("duplex", |out| execute(cli, out))
}
pub fn execute(cli: Cli, out: &mut Out<'_>) -> Result<()> {
    let path = cli.session.unwrap_or_else(default_session);
    let session = Session::new(path.clone());
    match cli.command {
        None => out.text(Cli::command().render_help().to_string()),
        Some(Command::Devices) => presentation::devices(&runtime::devices()?, out),
        Some(Command::Read {
            peek,
            all,
            hold_secs,
        }) => presentation::read(
            &session.read(ReadOptions {
                peek,
                all,
                hold_secs,
            })?,
            out,
        ),
        Some(Command::Say { text, keep_floor }) => {
            presentation::say(&session.say(&text.join(" "), keep_floor)?, true, out)
        }
        Some(Command::Release { keep_cursor }) => {
            presentation::release(&session.release(keep_cursor)?, out)
        }
        Some(Command::Status) => {
            presentation::status(&session.status()?, Some(session.path()), out)
        }
        Some(Command::Ear { soma, frames }) => {
            let stop = stop_on_signal()?;
            runtime::ear(&soma, frames, &stop, out)?;
            Ok(())
        }
        Some(Command::Run(args)) => {
            let options = RunOptions::try_from(*args)?;
            let stop = stop_on_signal()?;
            runtime::run(&path, &options, &stop, out)?;
            Ok(())
        }
    }
}
fn stop_on_signal() -> Result<Arc<AtomicBool>> {
    let stop = Arc::new(AtomicBool::new(false));
    let requested = Arc::clone(&stop);
    ctrlc::set_handler(move || requested.store(true, Ordering::Relaxed))
        .context("install Ctrl-C handler")?;
    Ok(stop)
}
