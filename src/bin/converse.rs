//! converse — the TALK-LOOP BRIDGE: ears → brain → mouth, half-duplex v0.
//!
//! Closes the spoken-conversation loop around three seams that all already
//! exist:
//!
//!   EARS   `gemma_listen` (mary) captures a NAMED mic, segments utterances
//!          (energy VAD), transcribes them (Gemma 4 audio tower, pile-only
//!          weights) and appends one JSON line per final utterance to a jsonl
//!          log: `{utc_ms, source, start_s, end_s, dur_s, prompt, text,
//!          latency_s[, wav]}`.
//!   BRAIN  `playground once <text> --system <text>` — a one-shot
//!          playground-backed turn (config/headspace from the pile: model,
//!          base_url, api key, or the `mary://` in-process engine). Nothing
//!          is recorded in the pile. Fallback: `--brain echo` replies with a
//!          canned acknowledgment including the heard text, so the plumbing
//!          is provable end-to-end without any model endpoint.
//!   MOUTH  `voice say|shout <reply>` (this crate) — privacy-routed audio
//!          out; `shout` reaches the room speaker. `--speak log` prints a
//!          `WOULD-SPEAK` line instead of making sound (silent night mode).
//!
//! DEVICES ARE ADDRESSED BY NAME, NEVER BY INDEX AND NEVER VIA THE SYSTEM
//! DEFAULT. Connecting a Bluetooth endpoint silently RENUMBERS the CoreAudio
//! device list, so an index-addressed or default-addressed stream can end up
//! on a dead virtual channel at -91 dB with nothing in the logs to say so.
//! Both ends already enforce this and must keep doing so: `voice` opens the
//! routed output device by name through cpal and never touches the system
//! default, and `gemma_listen` refuses to run live without an explicit
//! `--device <name>`. Nothing in this bin selects a device; it only passes
//! names through.
//!
//! TURN-TAKING (half-duplex v0): while speaking, converse holds a PAUSE FILE
//! open; `gemma_listen --pause-file <same path>` drops mic audio while the
//! file exists, so the ears never hear the mouth. The mic stream is NEVER
//! closed and reopened — that is load-bearing, not incidental: closing a
//! Bluetooth mic flips the endpoint between its handsfree and high-quality
//! profiles and chops speech mid-sentence. Belt-and-braces, converse also
//! classifies any utterance whose timestamp overlaps its own speech window as
//! a barge-in and drops it (v0 stub — real barge-in would kill the voice
//! child and yield the floor; on-chip AEC in the mic array is the
//! full-duplex upgrade path and needs no seam change).
//!
//! NO-SPEECH FILTER (observed on empty segments): the hear path PARROTS ITS
//! PROMPT on empty or AEC-suppressed audio (text == "Transcribe exactly what
//! is being said."), and sub-second blips trigger the VAD. Utterances are
//! dropped when the transcript equals/contains the utterance's own prompt, is
//! shorter than `--min-chars`, or the segment is shorter than `--min-dur-s`.
//!
//! # Live ceremony (two terminals)
//!
//! Terminal 1 — the ears (a mary checkout):
//! ```text
//! cargo build --release --features listen --bin gemma_listen
//! ./target/release/gemma_listen \
//!   --pile <gemma_e4b.pile> \
//!   --device '<exact input device name>' \
//!   --log /tmp/ears.jsonl --save-segments /tmp/ears_segments \
//!   --pause-file /tmp/ears.pause
//! ```
//!
//! Terminal 2 — the bridge (this bin; PILE set for voice + playground):
//! ```text
//! export PILE=<path to the pile>
//! converse run --log /tmp/ears.jsonl --pause-file /tmp/ears.pause \
//!   --brain playground --speak shout
//! ```
//!
//! Then speak. Notes:
//! - `--brain playground` needs a live model in the pile's headspace
//!   (`headspace list` / `headspace use <profile>`). `--brain echo` always
//!   works and still proves capture→reply→speech.
//! - Any OpenAI-compatible local server works as a plumbing-grade brain via
//!   `--brain-model <id>` — real replies at ~0.2 s warm with a small model.
//! - `--speak say` = private channel (headphones), `shout` = the room.
//!   Routing to a remote speaker daemon is upload-then-play, so time to first
//!   audio is seconds; for snappy replies prefer a locally connected speaker,
//!   which `voice` drives as a streaming native sink.
//! - `voice` records what was spoken on the pile's voice collection (that is
//!   the ledger; `--speak log` writes nothing anywhere but `--out`).
//!
//! # File-based gate (no audio; how this bin is tested)
//! ```text
//! converse run --log <utterances.jsonl> \
//!   --from-start --drain --brain echo --speak log --out /tmp/converse_gate.jsonl
//! ```

use std::io::{Read as _, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command as Proc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};

/// Default system context for the brain turn. Deliberately short: the pile's
/// configured system_prompt is the SHELL-LOOP prompt (one command per turn)
/// and would be wrong for a spoken reply, so `once` gets this override.
const DEFAULT_VOICE_SYSTEM: &str = "You are speaking ALOUD through a loudspeaker. What you \
output is spoken via text-to-speech: reply in one or two short, natural spoken sentences — \
warm, direct, no markdown, no emoji, no stage directions, no lists. Answer in the language \
you were addressed in.";

#[derive(Parser, Debug)]
#[command(
    version = faculties::GIT_VERSION,
    name = "converse",
    about = "Talk-loop bridge: tail ears jsonl → one-shot brain turn → spoken reply (half-duplex)."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the bridge loop (the only mode; see bin docs for the ceremony).
    Run(RunArgs),
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Brain {
    /// Canned acknowledgment including the heard text (plumbing-provable).
    Echo,
    /// `playground once` — a real playground-backed model turn.
    Playground,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Speak {
    /// Print `WOULD-SPEAK[...]` instead of making sound (silent night mode).
    Log,
    /// `voice say` — the PRIVATE channel (in-ear / headphones only).
    Say,
    /// `voice shout` — the PUBLIC channel (Reachy speaker → room).
    Shout,
}

#[derive(Args, Debug)]
struct RunArgs {
    /// Utterance jsonl to tail (the `gemma_listen --log` format).
    #[arg(long)]
    log: PathBuf,
    /// Process lines already in the log too (default: tail from EOF).
    #[arg(long, default_value_t = false)]
    from_start: bool,
    /// Process everything currently in the log, then exit (the file gate).
    #[arg(long, default_value_t = false)]
    drain: bool,
    /// Reply source.
    #[arg(long, value_enum, default_value_t = Brain::Echo)]
    brain: Brain,
    /// The playground binary (brain=playground).
    #[arg(long, default_value = "playground")]
    playground_bin: String,
    /// Pile holding playground config/headspace (brain=playground).
    /// Defaults to $PILE — the same pile `voice` uses.
    #[arg(long, env = "PILE")]
    brain_pile: Option<PathBuf>,
    /// Override the model id for the brain turn (`playground once --model`);
    /// default: the pile headspace's configured model.
    #[arg(long)]
    brain_model: Option<String>,
    /// System context for the brain turn (default: a built-in
    /// brief-spoken-reply brief; the pile's system_prompt is the shell-loop
    /// prompt and is NOT used).
    #[arg(long, conflicts_with = "system_file")]
    system: Option<String>,
    /// Read the system context from a file.
    #[arg(long)]
    system_file: Option<PathBuf>,
    /// Output channel.
    #[arg(long, value_enum, default_value_t = Speak::Log)]
    speak: Speak,
    /// The voice binary (speak=say|shout).
    #[arg(long, default_value = "voice")]
    voice_bin: String,
    /// Half-duplex pause file, held open while speaking; run gemma_listen
    /// with `--pause-file <same path>`. Default: `<log>.pause`.
    #[arg(long)]
    pause_file: Option<PathBuf>,
    /// Conversation jsonl (every turn, incl. drops, with reasons).
    #[arg(long, default_value = "/tmp/converse.jsonl")]
    out: PathBuf,
    /// Tail poll interval, ms.
    #[arg(long, default_value_t = 200)]
    poll_ms: u64,
    /// Drop utterances with fewer transcript characters than this.
    #[arg(long, default_value_t = 2)]
    min_chars: usize,
    /// Drop segments shorter than this (VAD blips; 0.46 s ones observed).
    #[arg(long, default_value_t = 0.6)]
    min_dur_s: f64,
    /// Truncate replies longer than this before speaking (latency guard).
    #[arg(long, default_value_t = 600)]
    max_reply_chars: usize,
    /// In `--speak log` mode, hold the pause file this long per reply so the
    /// half-duplex window is exercisable without audio (gate use).
    #[arg(long, default_value_t = 0)]
    simulate_speak_ms: u64,
    /// Grace after speech ends during which overlapping utterances are still
    /// treated as self-echo/barge-in, ms.
    #[arg(long, default_value_t = 500)]
    barge_grace_ms: u64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Run(args)) => run(args),
        None => {
            use clap::CommandFactory;
            Cli::command().print_help().ok();
            println!();
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------

fn run(args: RunArgs) -> Result<()> {
    if args.speak != Speak::Log && std::env::var("PILE").is_err() {
        eprintln!("warning: PILE is not set — `voice` needs it; set PILE or pass --speak log");
    }
    let pause_path = args
        .pause_file
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("{}.pause", args.log.display())));
    // A stale pause file permanently deafens the ears — clear it up front.
    if pause_path.exists() {
        std::fs::remove_file(&pause_path).ok();
        eprintln!("cleared stale pause file {}", pause_path.display());
    }

    let system = match (&args.system, &args.system_file) {
        (Some(s), _) => s.clone(),
        (None, Some(p)) => std::fs::read_to_string(p)
            .with_context(|| format!("read --system-file {}", p.display()))?,
        (None, None) => DEFAULT_VOICE_SYSTEM.to_string(),
    };

    if args.drain && !args.log.exists() {
        bail!("--drain: log {} does not exist", args.log.display());
    }
    eprintln!(
        "converse: log={} brain={:?} speak={:?} pause-file={} out={}",
        args.log.display(),
        args.brain,
        args.speak,
        pause_path.display(),
        args.out.display()
    );

    // Tail position: EOF unless --from-start (or the file doesn't exist yet).
    let mut pos: u64 = if args.from_start {
        0
    } else {
        std::fs::metadata(&args.log).map(|m| m.len()).unwrap_or(0)
    };
    let mut partial = String::new();
    // Last speech window (wall clock, ms) for the barge-in/self-echo guard.
    let mut speak_window: Option<(u64, u64)> = None;
    let (mut n_heard, mut n_replied, mut n_dropped) = (0usize, 0usize, 0usize);

    loop {
        let mut new = String::new();
        if let Ok(mut f) = std::fs::File::open(&args.log) {
            let len = f.metadata().map(|m| m.len()).unwrap_or(0);
            if len < pos {
                eprintln!("log truncated/rotated ({} -> {} bytes); restarting from 0", pos, len);
                pos = 0;
                partial.clear();
            }
            if len > pos {
                f.seek(SeekFrom::Start(pos)).context("seek log")?;
                let mut buf = Vec::with_capacity((len - pos) as usize);
                f.read_to_end(&mut buf).context("read log")?;
                pos = len;
                new = String::from_utf8_lossy(&buf).into_owned();
            }
        }

        if !new.is_empty() {
            partial.push_str(&new);
            // Consume only '\n'-terminated lines; keep the torn tail.
            while let Some(nl) = partial.find('\n') {
                let line: String = partial.drain(..=nl).collect();
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                n_heard += 1;
                match handle_line(line, &args, &system, &pause_path, &mut speak_window) {
                    Ok(true) => n_replied += 1,
                    Ok(false) => n_dropped += 1,
                    Err(e) => {
                        n_dropped += 1;
                        eprintln!("turn error (loop continues): {e:#}");
                    }
                }
            }
        } else if args.drain {
            break;
        } else {
            std::thread::sleep(Duration::from_millis(args.poll_ms));
        }
    }

    eprintln!("drained: {n_heard} line(s) → {n_replied} replied, {n_dropped} dropped/filtered");
    Ok(())
}

/// One utterance line → maybe one spoken reply. Ok(true) = replied.
fn handle_line(
    line: &str,
    args: &RunArgs,
    system: &str,
    pause_path: &Path,
    speak_window: &mut Option<(u64, u64)>,
) -> Result<bool> {
    let v: serde_json::Value =
        serde_json::from_str(line).with_context(|| format!("parse utterance line: {line}"))?;
    let text = v["text"].as_str().unwrap_or("").trim().to_string();
    let utt_prompt = v["prompt"].as_str().unwrap_or("").trim();
    let utc_ms = v["utc_ms"].as_u64().unwrap_or(0);
    let dur_s = v["dur_s"].as_f64().unwrap_or(0.0);

    // --- No-speech / junk filters (see bin docs) ---
    let drop_reason = if text.len() < args.min_chars {
        Some("too-short-text")
    } else if dur_s > 0.0 && dur_s < args.min_dur_s {
        Some("too-short-segment")
    } else if !utt_prompt.is_empty()
        && (text == utt_prompt || (utt_prompt.len() >= 12 && text.contains(utt_prompt)))
    {
        // Empty/AEC-suppressed audio makes the hear path parrot its prompt.
        // The substring form only fires for real (long) prompts — a short
        // prompt would false-positive on ordinary speech.
        Some("prompt-parrot (no speech)")
    } else if let Some((start, end)) = *speak_window {
        // Belt-and-braces vs the pause file: anything stamped inside our own
        // speech window is presumed self-echo. Real barge-in (v0 stub) would
        // kill the voice child here and yield the floor instead.
        if utc_ms >= start.saturating_sub(250) && utc_ms <= end + args.barge_grace_ms {
            Some("barge-in stub: overlapped our speech, presumed self-echo")
        } else {
            None
        }
    } else {
        None
    };

    if let Some(reason) = drop_reason {
        println!("[heard ] {text:?} ({dur_s:.2}s) → DROPPED: {reason}");
        log_turn(&args.out, &serde_json::json!({
            "utc_ms": now_ms(), "utc_ms_heard": utc_ms, "heard": text,
            "dur_s": dur_s, "dropped": reason,
        }));
        return Ok(false);
    }

    println!("[heard ] {text:?} ({dur_s:.2}s)");

    // --- Brain ---
    let t = Instant::now();
    let (reply, brain_used) = match args.brain {
        Brain::Echo => (echo_reply(&text), "echo"),
        Brain::Playground => match playground_reply(args, system, &text) {
            Ok(r) => (r, "playground"),
            Err(e) => {
                eprintln!("brain error, falling back to echo: {e:#}");
                (
                    format!("{} My brain is not reachable right now.", echo_reply(&text)),
                    "echo-fallback",
                )
            }
        },
    };
    let brain_s = t.elapsed().as_secs_f64();
    let mut reply = reply.trim().to_string();
    if reply.is_empty() {
        reply = "I heard you, but I have nothing to say to that yet.".to_string();
    }
    if reply.len() > args.max_reply_chars {
        let mut cut = args.max_reply_chars;
        while !reply.is_char_boundary(cut) {
            cut -= 1;
        }
        reply.truncate(cut);
        reply.push('…');
    }
    println!("[reply ] ({brain_used}, {brain_s:.2}s) {reply}");

    // --- Mouth (half-duplex: hold the pause file across the whole window) ---
    let speak_start = now_ms();
    let t = Instant::now();
    let _guard = PauseGuard::hold(pause_path);
    let spoke = match args.speak {
        Speak::Log => {
            println!("WOULD-SPEAK[shout]: {reply}");
            if args.simulate_speak_ms > 0 {
                std::thread::sleep(Duration::from_millis(args.simulate_speak_ms));
            }
            false
        }
        Speak::Say | Speak::Shout => {
            let channel = if args.speak == Speak::Say { "say" } else { "shout" };
            let status = Proc::new(&args.voice_bin)
                .args([channel, reply.as_str()])
                .status()
                .with_context(|| format!("spawn {} {channel}", args.voice_bin))?;
            if !status.success() {
                eprintln!("voice {channel} exited with {status} (text above is the fallback)");
            }
            status.success()
        }
    };
    drop(_guard);
    let speak_end = now_ms();
    *speak_window = Some((speak_start, speak_end));
    let speak_s = t.elapsed().as_secs_f64();

    log_turn(&args.out, &serde_json::json!({
        "utc_ms": speak_start, "utc_ms_heard": utc_ms,
        "heard": text, "dur_s": dur_s,
        "reply": reply, "brain": brain_used, "brain_s": brain_s,
        "speak": format!("{:?}", args.speak).to_lowercase(), "spoke": spoke,
        "speak_s": speak_s,
    }));
    Ok(true)
}

fn echo_reply(text: &str) -> String {
    format!("I heard you. You said: \u{201c}{text}\u{201d}.")
}

fn playground_reply(args: &RunArgs, system: &str, text: &str) -> Result<String> {
    let pile = args
        .brain_pile
        .as_ref()
        .ok_or_else(|| anyhow!("--brain playground needs --brain-pile or $PILE"))?;
    let mut cmd = Proc::new(&args.playground_bin);
    cmd.args([
        "--pile",
        &pile.display().to_string(),
        "once",
        text,
        "--system",
        system,
    ]);
    if let Some(m) = &args.brain_model {
        cmd.args(["--model", m]);
    }
    let out = cmd
        .output()
        .with_context(|| format!("spawn {} once", args.playground_bin))?;
    if !out.status.success() {
        bail!(
            "playground once failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn log_turn(path: &Path, record: &serde_json::Value) {
    use std::io::Write as _;
    let line = format!("{record}\n");
    if let Err(e) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut f| f.write_all(line.as_bytes()))
    {
        eprintln!("(conversation log append failed: {e})");
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Holds the half-duplex pause file for a scope; removal is the Drop so the
/// ears always resume, even on an error path.
struct PauseGuard {
    path: PathBuf,
    created: bool,
}

impl PauseGuard {
    fn hold(path: &Path) -> Self {
        let created = std::fs::write(path, format!("converse pid {}\n", std::process::id())).is_ok();
        if !created {
            eprintln!("warning: could not create pause file {}", path.display());
        }
        Self { path: path.to_path_buf(), created }
    }
}

impl Drop for PauseGuard {
    fn drop(&mut self) {
        if self.created {
            std::fs::remove_file(&self.path).ok();
        }
    }
}
