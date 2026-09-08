//! Explicit CLI UX: named-device speech remains a host operation; synthesis
//! can instead return audio to Drive without playing anything on the host.
use super::device::{Device, DEFAULT_DAEMON};
use super::synthesis::{ModelSources, Synthesizer};
use super::{Channel, Voice};
use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "voice",
    about = "Speech synthesis + privacy-aware output routing, on two channels."
)]
pub struct Cli {
    /// Path to the pile file
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it;
    /// initialize explicitly with `trible pile signing-key init <pile>`.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Reachy daemon base URL (the `shout` Reachy-speaker target).
    #[arg(long, env = "REACHY_DAEMON", default_value = DEFAULT_DAEMON)]
    daemon: String,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Speak on the PRIVATE channel — in-ear / headphone only. Routes to the
    /// highest-priority connected private device; if none can be safely
    /// targeted, prints the text instead of playing aloud. Recorded on the
    /// fixed Voice collection.
    Say {
        /// What to say.
        text: String,
        /// Resolve routing and report the target (or text-fallback) WITHOUT
        /// synthesizing or playing — for checking the policy on a busy GPU.
        #[arg(long)]
        dry_run: bool,
        /// Half-duplex pause file: created before any sound and removed when
        /// the utterance ends, so a listener started with the SAME path drops
        /// audio while we speak. See `crate::turntaking`. The listener
        /// never closes its microphone — the hold stops the model, never the
        /// person.
        #[arg(long, env = "VOICE_PAUSE_FILE")]
        pause_file: Option<PathBuf>,
    },
    /// Speak ALOUD on the PUBLIC channel — Reachy speaker → room → laptop.
    /// Broadcasting is the point; falls back to any audible device. Recorded on
    /// the fixed Voice collection.
    Shout {
        /// What to shout.
        text: String,
        /// Resolve routing and report the target WITHOUT synthesizing/playing.
        #[arg(long)]
        dry_run: bool,
        /// Half-duplex pause file — see `voice say --pause-file`. A shout is
        /// exactly the case that needs it: the room speaker is in the room
        /// with the microphone.
        #[arg(long, env = "VOICE_PAUSE_FILE")]
        pause_file: Option<PathBuf>,
    },
    /// Show the routing policy for both channels, the connected audio devices,
    /// and what each channel WOULD select right now (a pure dry-run). Read-only.
    Route,
    /// Set the ordered device-preference list for a channel, replacing it.
    /// Devices are matched case-insensitively as substrings of the connected
    /// device names. For `say`, non-private entries are warned about and will be
    /// ignored at speak-time (the privacy invariant can't be configured away).
    RouteSet {
        /// "say" or "shout".
        channel: String,
        /// Device-name patterns in priority order (highest preference first).
        #[arg(required = true)]
        devices: Vec<String>,
    },
    /// Synthesize a resident WAV without playing any local device.
    Synthesize {
        /// Literal prose, @file, @- stdin, or @@escaped leading at-sign.
        text: String,
        /// Also save the original WAV here (recommended without Drive).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// List the connected audio output devices and their privacy class. The
    /// raw input to routing — a quick way to see what `say`/`shout` can target.
    Devices,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    if cli.command.is_none() {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }
    crate::cli::with_output("voice", |out| execute(cli, out))
}
pub fn execute(cli: Cli, out: &mut crate::out::Out<'_>) -> Result<()> {
    let voice = Voice::new(cli.pile, cli.key);
    let synthesizer = Synthesizer::new(ModelSources::from_environment());
    let device = Device::new(voice.clone(), cli.daemon, synthesizer.clone());
    match cli.command {
        None => anyhow::bail!("Voice requires an explicit command"),
        Some(Command::Say {
            text,
            dry_run,
            pause_file,
        }) => {
            let text = crate::text_arg(&text, "voice text")?;
            device
                .speak(Channel::Say, &text, dry_run, pause_file.as_deref(), out)?
                .emit(Channel::Say, out)
        }
        Some(Command::Shout {
            text,
            dry_run,
            pause_file,
        }) => {
            let text = crate::text_arg(&text, "voice text")?;
            device
                .speak(Channel::Shout, &text, dry_run, pause_file.as_deref(), out)?
                .emit(Channel::Shout, out)
        }
        Some(Command::Route) => device.routes()?.emit(out),
        Some(Command::RouteSet { channel, devices }) => voice
            .set_route(Channel::parse(&channel)?, &devices)?
            .emit(out),
        Some(Command::Devices) => {
            let devices = super::device::detect_output_devices()?;
            if devices.is_empty() {
                out.line("no audio output devices found.")?;
            }
            for device in devices {
                out.line(super::device::describe_device(&device))?;
            }
            Ok(())
        }
        Some(Command::Synthesize { text, out: path }) => {
            anyhow::ensure!(
                cfg!(feature = "voice"),
                "speech synthesis requires a build with the `voice` feature"
            );
            let text = crate::text_arg(&text, "voice text")?;
            let clip = synthesizer.synthesize(&text)?;
            if let Some(path) = path {
                clip.save(&path)?;
                out.line(path.display().to_string())?;
            }
            out.audio(clip.wav, super::AUDIO_WAV_MIME)
        }
    }
}
