//! Host CLI: device configuration, @ action chunks and filesystem exports.
use super::device::{Action, Device, Gesture, DEFAULT_DAEMON, DEFAULT_PYTHON};
use super::{presentation, Body};
use crate::out::Out;
use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "body",
    about = "The Reachy Mini body: perception in, action out, deliberate captures to the pile"
)]
pub struct Cli {
    /// Path to the pile file. Required only by commands that keep or read data.
    #[arg(long, env = "PILE")]
    pile: Option<PathBuf>,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Daemon base URL
    #[arg(long, env = "REACHY_DAEMON", default_value = DEFAULT_DAEMON)]
    daemon: String,
    /// Python interpreter for the frame-grab shim (the reachy venv)
    #[arg(long, env = "REACHY_PYTHON", default_value = DEFAULT_PYTHON)]
    python: String,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Read the body's current proprioceptive state (head pose, body yaw,
    /// antennas, audio direction) and daemon status. Read-only.
    Pose,
    /// Feel for a touch: a hand sweeping the head registers as the audio
    /// direction-of-arrival sweeping across the mic array. Reports what was
    /// felt; `--keep` remembers it as a touch capture in the pile.
    Feel {
        /// Seconds to feel for — one window, or the whole session under --loop
        /// (default 12; loop default 300).
        #[arg(long)]
        secs: Option<f64>,
        /// Keep feeling in short windows and answer each touch — a petting
        /// session. Ctrl-C to stop.
        #[arg(long = "loop")]
        loop_: bool,
        /// Remember a felt touch as a capture in the pile.
        #[arg(long)]
        keep: bool,
        /// Answer a felt touch with a gentle antenna-wiggle.
        #[arg(long)]
        respond: bool,
        /// A note for the kept touch ("a gentle pet from JP").
        #[arg(long)]
        note: Option<String>,
    },
    /// Make a gentle gesture: nod, shake, wiggle, perk, look-left,
    /// look-right, center.
    Gesture {
        /// Gesture name.
        name: String,
    },
    /// Set or read the current INTENT — gemma's reasoned instruction that
    /// conditions the VLA (the perceive→reason→act seam). With text: writes a
    /// timestamped intent in the Body collection. Without: prints the LATEST
    /// intent text to stdout (what the control loop reads each cycle), time to
    /// stderr.
    Intent {
        /// The instruction to set ("lean into the touch, perk the antennas").
        /// Omit to read the latest intent instead.
        text: Option<String>,
    },
    /// Capture one camera frame into the pile and return a handle. Stores the
    /// proprioceptive pose alongside the frame so it can be grounded later.
    Look {
        /// Why you chose to remember this moment (the deliberate note).
        #[arg(long)]
        note: Option<String>,
    },
    /// List deliberate captures kept in the pile.
    List,
    /// Extract a capture's payload. Use @- for stdout, or omit for a default name.
    Get {
        /// Capture entity id (or prefix).
        id: String,
        /// Output path. Omit for a default name, @- for stdout.
        output: Option<String>,
    },
    /// Gentle wake-up motion (daemon-defined, bounded).
    Wake,
    /// Gentle go-to-sleep motion (daemon-defined, bounded).
    Sleep,
    /// Emit a RAW observation for a VLA loop as JSON: a native-resolution
    /// frame + the 9-real state vector + the touch channel. No resize, no
    /// normalize — the body stays dumb, the VLA owns preprocessing.
    Observe {
        /// Where to write the frame PNG (default a temp path).
        #[arg(long)]
        frame: Option<PathBuf>,
        /// Skip the camera frame (state + touch only — fast).
        #[arg(long)]
        no_frame: bool,
    },
    /// Execute an ABSOLUTE pose target in raw SDK units — 9 reals
    /// `x,y,z,roll,pitch,yaw,body_yaw,ant_l,ant_r` — as a single pose, or a
    /// chunk (JSON array of 9-real arrays via @file / @-) streamed as waypoints.
    Act {
        /// "x,y,z,roll,pitch,yaw,body_yaw,ant_l,ant_r", or @file / @- for a chunk.
        /// `allow_hyphen_values` so a negative-leading pose (e.g. "-0.01,...")
        /// isn't mis-parsed as a flag — the VLA emits negative values constantly.
        #[arg(allow_hyphen_values = true)]
        pose: String,
        /// Seconds for a single smooth move (goto). Ignored when streaming a chunk.
        #[arg(long, default_value_t = 0.5)]
        duration: f64,
        /// Seconds between chunk waypoints (set_target streaming).
        #[arg(long, default_value_t = 0.04)]
        dt: f64,
        /// Single pose: snap immediately (set_target) instead of a smooth goto.
        #[arg(long)]
        now: bool,
    },
}

pub fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.command.is_none() {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }
    crate::cli::with_output("body", |out| execute(cli, out))
}
fn storage(pile: Option<PathBuf>, key: Option<PathBuf>) -> Result<Body> {
    Ok(Body::new(
        pile.context("this command requires --pile (or PILE); hardware-only commands do not")?,
        key,
    ))
}
fn seconds(value: f64) -> Result<Duration> {
    Duration::try_from_secs_f64(value).context("seconds must be finite and nonnegative")
}

pub fn execute(cli: Cli, out: &mut Out<'_>) -> Result<()> {
    let device = Device::new(cli.daemon, cli.python);
    match cli.command {
        None => out.text(Cli::command().render_help().to_string()),
        Some(Command::Pose) => presentation::pose(&device.pose()?, out),
        Some(Command::Wake) => {
            device.wake()?;
            out.line("waking up")
        }
        Some(Command::Sleep) => {
            device.sleep()?;
            out.line("going to sleep")
        }
        Some(Command::Gesture { name }) => {
            device.gesture(Gesture::parse(&name)?)?;
            out.line(name.to_lowercase())
        }
        Some(Command::Intent { text }) => {
            let body = storage(cli.pile, cli.key)?;
            if let Some(text) = text {
                presentation::intent_set(&body.set_intent(&text)?, out)
            } else {
                let intent = body.intent()?;
                // Intent stdout is the VLA's plain instruction, not a report.
                if let Some(value) = &intent {
                    eprintln!("  ({})", presentation::format_time(value.tai_ns));
                }
                presentation::intent(intent.as_ref(), out)
            }
        }
        Some(Command::Look { note }) => presentation::captured(
            &device.look(&storage(cli.pile, cli.key)?, note.as_deref())?,
            out,
        ),
        Some(Command::List) => presentation::list(&storage(cli.pile, cli.key)?.list()?, out),
        Some(Command::Get { id, output }) => {
            let export = storage(cli.pile, cli.key)?.get(&id)?;
            if output.as_deref() == Some("@-") {
                let uri = export.uri();
                out.blob(export.bytes, "application/octet-stream", uri)
            } else {
                let path = output.map(PathBuf::from).unwrap_or_else(|| {
                    PathBuf::from(format!("{}.png", &format!("{:x}", export.id)[..12]))
                });
                std::fs::write(&path, export.bytes.as_ref())
                    .with_context(|| format!("write {}", path.display()))?;
                out.line(format!(
                    "Wrote {} ({} KiB)",
                    path.display(),
                    export.bytes.len() / 1024
                ))
            }
        }
        Some(Command::Act {
            pose,
            duration,
            dt,
            now,
        }) => {
            let action = if let Some(spec) = pose.strip_prefix('@') {
                let text = if spec == "-" {
                    use std::io::Read;
                    let mut text = String::new();
                    std::io::stdin().read_to_string(&mut text)?;
                    text
                } else {
                    std::fs::read_to_string(spec).with_context(|| format!("read chunk {spec}"))?
                };
                let rows: Vec<Vec<f64>> = serde_json::from_str(&text)
                    .context("parse chunk JSON (array of 9-real arrays)")?;
                let poses = rows
                    .into_iter()
                    .enumerate()
                    .map(|(i, row)| {
                        let len = row.len();
                        row.try_into().map_err(|_| {
                            anyhow::anyhow!("chunk waypoint {i} needs 9 reals, got {len}")
                        })
                    })
                    .collect::<Result<Vec<[f64; 9]>>>()?;
                Action::Chunk {
                    poses,
                    interval: seconds(dt)?,
                }
            } else {
                Action::Pose {
                    pose: parse_pose(&pose)?,
                    duration: seconds(duration)?,
                    immediate: now,
                }
            };
            presentation::action(&device.act(&action)?, out)
        }
        Some(Command::Observe { frame, no_frame }) => {
            let observation = device.observe(!no_frame)?;
            let (frame_path, dimensions) = if let Some(captured) = observation.frame {
                let path = frame.unwrap_or_else(|| std::env::temp_dir().join("body_observe.png"));
                std::fs::write(&path, captured.bytes.as_ref())
                    .with_context(|| format!("write {}", path.display()))?;
                (Some(path), [captured.width, captured.height])
            } else {
                (None, [0, 0])
            };
            let value = serde_json::json!({
                "t": presentation::format_time(observation.tai_ns), "frame": frame_path.map(|p|p.display().to_string()),
                "frame_size": dimensions, "state": observation.state,
                "state_layout": ["head_x_m","head_y_m","head_z_m","head_roll_rad","head_pitch_rad","head_yaw_rad","body_yaw_rad","antenna_l_rad","antenna_r_rad"],
                "touch": observation.touch.map(|d|serde_json::json!({"doa_angle_rad":d["angle"].as_f64(),"doa_speech":d["speech_detected"].as_bool()})),
                "raw":true,"note":"no resize/normalize — VLA owns preprocessing"
            });
            out.line(serde_json::to_string_pretty(&value)?)
        }
        Some(Command::Feel {
            secs,
            loop_,
            keep,
            respond,
            note,
        }) => {
            let body = if keep {
                Some(storage(cli.pile, cli.key)?)
            } else {
                None
            };
            feel(
                &device,
                body.as_ref(),
                secs,
                loop_,
                respond,
                note.as_deref(),
                out,
            )
        }
    }
}

fn parse_pose(text: &str) -> Result<[f64; 9]> {
    let values = text
        .split(',')
        .map(|v| v.trim().parse::<f64>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("bad pose number")?;
    let len = values.len();
    values.try_into().map_err(|_| {
        anyhow::anyhow!("pose needs 9 reals (x,y,z,roll,pitch,yaw,body_yaw,ant_l,ant_r), got {len}")
    })
}
fn feel(
    device: &Device,
    body: Option<&Body>,
    secs: Option<f64>,
    loop_: bool,
    respond: bool,
    note: Option<&str>,
    out: &mut Out<'_>,
) -> Result<()> {
    let duration = seconds(secs.unwrap_or(if loop_ { 300.0 } else { 12.0 }))?;
    let stop = Arc::new(AtomicBool::new(false));
    if loop_ {
        let requested = Arc::clone(&stop);
        ctrlc::set_handler(move || requested.store(true, Ordering::SeqCst))
            .context("install Ctrl-C handler")?;
        out.line(format!(
            "feeling continuously for {:.0}s — pet the top of my head whenever; Ctrl-C to stop.",
            duration.as_secs_f64()
        ))?;
    } else {
        out.line(format!(
            "feeling for {:.0}s — touch the top of my head…",
            duration.as_secs_f64()
        ))?;
    }
    let start = Instant::now();
    let mut count = 0;
    loop {
        if loop_ && (start.elapsed() >= duration || stop.load(Ordering::SeqCst)) {
            break;
        }
        let felt = device.feel(if loop_ {
            Duration::from_secs(3)
        } else {
            duration
        })?;
        if felt.touched() {
            count += 1;
            presentation::felt(&felt, out)?;
            if respond {
                if let Err(error) = device.gesture(Gesture::Wiggle) {
                    out.line(format!("  (couldn't wiggle back: {error})"))?;
                }
            }
            if let Some(body) = body {
                let receipt = body.capture(&felt.capture_input(note))?;
                out.line(format!(
                    "  kept it — {}",
                    &format!("{:x}", receipt.id)[..12]
                ))?;
            }
        } else if !loop_ {
            out.line(format!(
                "quiet — I didn't feel a touch. (head still to {:.0} mrad over {} samples.)",
                felt.head_deflect * 1000.0,
                felt.samples
            ))?;
        }
        if !loop_ {
            break;
        }
    }
    if loop_ {
        out.line(format!(
            "(stopped{} — felt {count} touch{} this session)",
            if stop.load(Ordering::SeqCst) {
                " by request"
            } else {
                ""
            },
            if count == 1 { "" } else { "es" }
        ))?;
    }
    Ok(())
}
