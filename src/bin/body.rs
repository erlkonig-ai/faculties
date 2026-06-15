//! `body` — the Reachy Mini body: perception in, action out, and the
//! deliberate sensory/touch captures it keeps in the pile.
//!
//! Renamed from `senses` (2026-06-16). The faculty is both afferent
//! (`pose`/`look`/`feel`) and efferent (`wake`/`sleep`/`gesture`) — the whole
//! embodied loop a vision-language-action model closes.
//!
//! Architecture (Rust-tightness audit): the daemon exposes a full REST surface
//! on :8000, so proprioception, motion, and the touch sense (`feel`, via the
//! mic-array direction-of-arrival) are pure Rust over reqwest — no Python, no
//! websocket. The single Python island is the camera frame grab (`look`):
//! frame pixels only flow over the daemon's WebRTC/GStreamer pipeline, so a
//! thin embedded shim pulls one frame. That shim is the obvious target for a
//! native gstreamer-rs path once the VLA loop needs the continuous stream.
//!
//! The lite body has no IMU and won't engage gravity-compensation, and its
//! head holds stiff — so a gentle pet barely moves the encoders. The body's
//! touch sense is therefore the MIC ARRAY: a hand sweeping the head registers
//! as the sound's direction-of-arrival sweeping across the array. `feel` hears
//! your hand as a sound travelling over the head.

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use faculties::schemas::body::{BODY_BRANCH_NAME, KIND_CAPTURE, capture};
use hifitime::Epoch;
use hifitime::efmt::Formatter;
use hifitime::efmt::consts::ISO8601;
use rand_core::OsRng;
use std::path::{Path, PathBuf};
use std::process::Command as PCommand;
use std::time::{Duration, Instant};
use triblespace::core::metadata;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::prelude::*;

type RawHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;
type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;

const DEFAULT_DAEMON: &str = "http://localhost:8000";
const DEFAULT_PYTHON: &str = "/Users/jp/Desktop/chatbot/liora/reachy-venv/bin/python";

/// The embedded frame-grab shim — written to a temp file at runtime.
const FRAME_SHIM: &str = include_str!("body_frame.py");

// ── CLI ──────────────────────────────────────────────────────────────────
#[derive(Parser)]
#[command(
    name = "body",
    about = "The Reachy Mini body: perception in, action out, deliberate captures to the pile"
)]
struct Cli {
    /// Path to the pile file
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Branch id (hex). Overrides name-based lookup.
    #[arg(long)]
    branch_id: Option<String>,
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
        /// Seconds to feel for (default 12).
        #[arg(long, default_value_t = 12.0)]
        secs: f64,
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

// ── helpers ──────────────────────────────────────────────────────────────

fn now_tai() -> Inline<inlineencodings::NsTAIInterval> {
    let now = Epoch::now().unwrap_or(Epoch::from_unix_seconds(0.0));
    (now, now).try_to_inline().expect("valid TAI interval")
}

fn interval_key(interval: Inline<inlineencodings::NsTAIInterval>) -> i128 {
    let (lower, _): (Epoch, Epoch) = interval.try_from_inline().expect("valid TAI interval");
    lower.to_tai_duration().total_nanoseconds()
}

fn format_time(tai_ns: i128) -> String {
    const NANOS_PER_CENTURY: i128 = 3_155_760_000_000_000_000;
    let centuries = (tai_ns / NANOS_PER_CENTURY) as i16;
    let nanos = (tai_ns % NANOS_PER_CENTURY) as u64;
    let dur = hifitime::Duration::from_parts(centuries, nanos);
    let epoch = Epoch::from_tai_duration(dur);
    Formatter::new(epoch, ISO8601).to_string()
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn http() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("build http client")
}

fn daemon_get(daemon: &str, path: &str) -> Result<serde_json::Value> {
    let url = format!("{daemon}{path}");
    let resp = http()
        .get(&url)
        .send()
        .with_context(|| format!("GET {url} — is the Reachy Mini daemon running?"))?;
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    if !status.is_success() {
        bail!("GET {url} → {status}: {body}");
    }
    serde_json::from_str(&body).with_context(|| format!("parse JSON from {url}"))
}

fn daemon_post(daemon: &str, path: &str) -> Result<()> {
    let url = format!("{daemon}{path}");
    let resp = http()
        .post(&url)
        .send()
        .with_context(|| format!("POST {url} — is the Reachy Mini daemon running?"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        bail!("POST {url} → {status}: {body}");
    }
    Ok(())
}

fn daemon_post_json(daemon: &str, path: &str, body: &serde_json::Value) -> Result<()> {
    let url = format!("{daemon}{path}");
    let resp = http()
        .post(&url)
        .json(body)
        .send()
        .with_context(|| format!("POST {url} — is the Reachy Mini daemon running?"))?;
    let status = resp.status();
    if !status.is_success() {
        let b = resp.text().unwrap_or_default();
        bail!("POST {url} → {status}: {b}");
    }
    Ok(())
}

/// Move the head / antennas / body over `duration` seconds, then wait for it
/// to land. Angles in radians, translations in metres; `None` leaves a channel
/// at the daemon's discretion. Bounded, gentle — the lite can't hurt itself.
#[allow(clippy::too_many_arguments)]
fn goto(
    daemon: &str,
    head: Option<(f64, f64, f64, f64, f64, f64)>, // x,y,z,roll,pitch,yaw
    antennas: Option<[f64; 2]>,
    body_yaw: Option<f64>,
    duration: f64,
) -> Result<()> {
    let mut req = serde_json::Map::new();
    if let Some((x, y, z, roll, pitch, yaw)) = head {
        req.insert(
            "head_pose".into(),
            serde_json::json!({"x":x,"y":y,"z":z,"roll":roll,"pitch":pitch,"yaw":yaw}),
        );
    }
    if let Some(a) = antennas {
        req.insert("antennas".into(), serde_json::json!(a));
    }
    if let Some(by) = body_yaw {
        req.insert("body_yaw".into(), serde_json::json!(by));
    }
    req.insert("duration".into(), serde_json::json!(duration));
    daemon_post_json(daemon, "/api/move/goto", &serde_json::Value::Object(req))?;
    std::thread::sleep(Duration::from_secs_f64(duration + 0.05));
    Ok(())
}

/// A small happy antenna-wiggle — the body's way of answering a touch.
fn wiggle(daemon: &str) -> Result<()> {
    for _ in 0..2 {
        goto(daemon, None, Some([0.5, -0.5]), None, 0.22)?;
        goto(daemon, None, Some([-0.5, 0.5]), None, 0.22)?;
    }
    goto(daemon, None, Some([0.0, 0.0]), None, 0.22)
}

fn cmd_gesture(daemon: &str, name: &str) -> Result<()> {
    let n = name.to_lowercase();
    match n.as_str() {
        "nod" | "yes" => {
            goto(daemon, Some((0., 0., 0., 0., 0.18, 0.)), None, None, 0.4)?;
            goto(daemon, Some((0., 0., 0., 0., -0.05, 0.)), None, None, 0.4)?;
            goto(daemon, Some((0., 0., 0., 0., 0., 0.)), None, None, 0.4)?;
        }
        "shake" | "no" => {
            goto(daemon, Some((0., 0., 0., 0., 0., 0.3)), None, None, 0.4)?;
            goto(daemon, Some((0., 0., 0., 0., 0., -0.3)), None, None, 0.5)?;
            goto(daemon, Some((0., 0., 0., 0., 0., 0.)), None, None, 0.4)?;
        }
        "wiggle" | "happy" => wiggle(daemon)?,
        "perk" => goto(daemon, None, Some([0.7, 0.7]), None, 0.4)?,
        "look-left" => goto(daemon, Some((0., 0., 0., 0., 0., 0.4)), None, None, 0.6)?,
        "look-right" => goto(daemon, Some((0., 0., 0., 0., 0., -0.4)), None, None, 0.6)?,
        "center" | "rest" => {
            goto(daemon, Some((0., 0., 0., 0., 0., 0.)), Some([0., 0.]), Some(0.), 0.6)?
        }
        _ => bail!(
            "unknown gesture '{name}' — try: nod, shake, wiggle, perk, look-left, look-right, center"
        ),
    }
    println!("{n}");
    Ok(())
}

/// Set an immediate absolute target (no interpolation) — the streaming
/// primitive for a VLA action chunk. Head pose (x,y,z,roll,pitch,yaw),
/// body yaw, antennas [l,r], all in raw SDK units. `None` leaves a channel.
fn set_target(
    daemon: &str,
    head: Option<(f64, f64, f64, f64, f64, f64)>,
    antennas: Option<[f64; 2]>,
    body_yaw: Option<f64>,
) -> Result<()> {
    let mut req = serde_json::Map::new();
    if let Some((x, y, z, roll, pitch, yaw)) = head {
        req.insert(
            "target_head_pose".into(),
            serde_json::json!({"x":x,"y":y,"z":z,"roll":roll,"pitch":pitch,"yaw":yaw}),
        );
    }
    if let Some(a) = antennas {
        req.insert("target_antennas".into(), serde_json::json!(a));
    }
    if let Some(by) = body_yaw {
        req.insert("target_body_yaw".into(), serde_json::json!(by));
    }
    daemon_post_json(daemon, "/api/move/set_target", &serde_json::Value::Object(req))
}

/// Grab one native-resolution camera frame to `out_png` via the embedded
/// shim. Returns (width, height). The one Python island; never hangs `look`
/// or `observe` (45s cap on cold WebRTC negotiation).
fn grab_frame(python: &str, out_png: &Path) -> Result<(u64, u64)> {
    let shim_path = std::env::temp_dir().join("body_frame.py");
    std::fs::write(&shim_path, FRAME_SHIM).context("write frame shim")?;
    let mut child = PCommand::new(python)
        .arg(&shim_path)
        .arg(out_png)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("run frame shim with {python}"))?;
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if child.try_wait().context("poll frame shim")?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("frame grab timed out after 45s (cold WebRTC negotiation stalled — retry)");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let output = child.wait_with_output().context("collect frame shim output")?;
    if !output.status.success() {
        bail!("frame grab failed: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    let dims = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(dims
        .split_once('x')
        .and_then(|(a, b)| Some((a.parse::<u64>().ok()?, b.parse::<u64>().ok()?)))
        .unwrap_or((0, 0)))
}

/// Read the raw 9-real proprioceptive state vector
/// [x,y,z,roll,pitch,yaw, body_yaw, ant_l, ant_r] in raw SDK units
/// (REST gives head xyz in metres, angles in radians).
fn read_state(daemon: &str) -> Result<[f64; 9]> {
    let s = daemon_get(daemon, "/api/state/full")?;
    let h = &s["head_pose"];
    let g = |v: &serde_json::Value, k: &str| v[k].as_f64().unwrap_or(0.0);
    let ant = s["antennas_position"].as_array().cloned().unwrap_or_default();
    Ok([
        g(h, "x"), g(h, "y"), g(h, "z"),
        g(h, "roll"), g(h, "pitch"), g(h, "yaw"),
        s["body_yaw"].as_f64().unwrap_or(0.0),
        ant.first().and_then(|v| v.as_f64()).unwrap_or(0.0),
        ant.get(1).and_then(|v| v.as_f64()).unwrap_or(0.0),
    ])
}

fn open_repo(path: &Path) -> Result<Repository<Pile>> {
    let mut pile = Pile::open(path)
        .map_err(|e| anyhow::anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.restore() {
        let _ = pile.close();
        return Err(anyhow::anyhow!("restore pile {}: {err:?}", path.display()));
    }
    let signing_key = SigningKey::generate(&mut OsRng);
    Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|err| anyhow::anyhow!("create repository: {err:?}"))
}

fn with_body<T>(
    pile: &Path,
    explicit_branch: Option<&str>,
    f: impl FnOnce(&mut Repository<Pile>, &mut Workspace<Pile>) -> Result<T>,
) -> Result<T> {
    let mut repo = open_repo(pile)?;
    let branch_id = if let Some(hex) = explicit_branch {
        Id::from_hex(hex.trim()).ok_or_else(|| anyhow::anyhow!("invalid branch id '{hex}'"))?
    } else {
        repo.ensure_branch(BODY_BRANCH_NAME, None)
            .map_err(|e| anyhow::anyhow!("ensure body branch: {e:?}"))?
    };
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow::anyhow!("pull body workspace: {e:?}"))?;
    let result = f(&mut repo, &mut ws);
    let close_res = repo.close().map_err(|e| anyhow::anyhow!("close pile: {e:?}"));
    if let Err(err) = close_res {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }
    result
}

// ── feel: the mic-array touch sense ────────────────────────────────────────

/// What a touch looked like over the felt window.
struct Felt {
    samples: usize,
    sweeps: usize,        // count of >SWEEP_DEG moves within a ~SWEEP_WIN window
    angle_min: f64,       // degrees
    angle_max: f64,
    max_speed: f64,       // deg/s
    head_deflect: f64,    // rad, max yaw/roll/pitch range
    speech_ticks: usize,
    signature_json: String,
}

impl Felt {
    fn touched(&self) -> bool {
        // a pet shows up as the sound sweeping across the array several times;
        // the rest-state floor moves only a little and slowly.
        self.sweeps >= 2 && (self.angle_max - self.angle_min) > 25.0
    }
}

/// Sample the mic-array DOA (and the head encoders) for `secs` and summarise
/// the touch signature.
fn feel_window(daemon: &str, secs: f64) -> Felt {
    const SWEEP_DEG: f64 = 15.0; // a "sweep" = this much DOA travel…
    const SWEEP_WIN: f64 = 0.6; // …within this window (s)
    let client = http();
    let start = Instant::now();
    let dur = Duration::from_secs_f64(secs);

    let mut t_series: Vec<f64> = Vec::new();
    let mut a_series: Vec<f64> = Vec::new(); // degrees
    let mut speech_ticks = 0usize;
    let (mut rmin, mut rmax) = (f64::INFINITY, f64::NEG_INFINITY);
    let (mut pmin, mut pmax) = (f64::INFINITY, f64::NEG_INFINITY);
    let (mut ymin, mut ymax) = (f64::INFINITY, f64::NEG_INFINITY);

    let get = |path: &str| -> Option<serde_json::Value> {
        client
            .get(format!("{daemon}{path}"))
            .send()
            .ok()
            .and_then(|r| r.text().ok())
            .and_then(|b| serde_json::from_str(&b).ok())
    };

    while start.elapsed() < dur {
        let t = start.elapsed().as_secs_f64();
        if let Some(d) = get("/api/state/doa") {
            if let Some(a) = d["angle"].as_f64() {
                t_series.push(t);
                a_series.push(a.to_degrees());
            }
            if d["speech_detected"].as_bool().unwrap_or(false) {
                speech_ticks += 1;
            }
        }
        if let Some(s) = get("/api/state/full") {
            let h = &s["head_pose"];
            if let (Some(r), Some(p), Some(y)) =
                (h["roll"].as_f64(), h["pitch"].as_f64(), h["yaw"].as_f64())
            {
                rmin = rmin.min(r);
                rmax = rmax.max(r);
                pmin = pmin.min(p);
                pmax = pmax.max(p);
                ymin = ymin.min(y);
                ymax = ymax.max(y);
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // sweep count: non-overlapping windows whose DOA span exceeds SWEEP_DEG
    let mut sweeps = 0usize;
    let mut i = 0usize;
    while i < a_series.len() {
        let t0 = t_series[i];
        let mut j = i;
        let (mut lo, mut hi) = (a_series[i], a_series[i]);
        while j < a_series.len() && t_series[j] - t0 <= SWEEP_WIN {
            lo = lo.min(a_series[j]);
            hi = hi.max(a_series[j]);
            j += 1;
        }
        if hi - lo > SWEEP_DEG {
            sweeps += 1;
            i = j; // consume the window
        } else {
            i += 1;
        }
    }
    // peak angular speed
    let mut max_speed = 0.0f64;
    for k in 1..a_series.len() {
        let dt = t_series[k] - t_series[k - 1];
        if dt > 0.0 {
            max_speed = max_speed.max(((a_series[k] - a_series[k - 1]) / dt).abs());
        }
    }
    let angle_min = a_series.iter().cloned().fold(f64::INFINITY, f64::min);
    let angle_max = a_series.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let head_deflect = (rmax - rmin).max(pmax - pmin).max(ymax - ymin).max(0.0);

    let signature_json = serde_json::json!({
        "modality": "touch",
        "sweeps": sweeps,
        "angle_deg": { "min": angle_min, "max": angle_max },
        "max_speed_deg_s": max_speed,
        "head_deflect_rad": head_deflect,
        "speech_ticks": speech_ticks,
        "samples": a_series.len(),
        "secs": secs,
    })
    .to_string();

    Felt {
        samples: a_series.len(),
        sweeps,
        angle_min: if angle_min.is_finite() { angle_min } else { 0.0 },
        angle_max: if angle_max.is_finite() { angle_max } else { 0.0 },
        max_speed,
        head_deflect: if head_deflect.is_finite() { head_deflect } else { 0.0 },
        speech_ticks,
        signature_json,
    }
}

fn cmd_feel(
    repo: &mut Repository<Pile>,
    ws: &mut Workspace<Pile>,
    daemon: &str,
    secs: f64,
    keep: bool,
    respond: bool,
    note: Option<&str>,
) -> Result<()> {
    println!("feeling for {secs:.0}s — touch the top of my head…");
    let felt = feel_window(daemon, secs);

    if felt.samples == 0 {
        bail!("felt nothing back from the daemon — is the Reachy Mini running?");
    }

    if felt.touched() {
        let dir = if felt.angle_max - felt.angle_min > 0.0 {
            format!(
                "the sound moving from {:.0}° to {:.0}°",
                felt.angle_min, felt.angle_max
            )
        } else {
            String::new()
        };
        println!(
            "I felt it — a touch swept across the top of my head {} time{}, {dir}.",
            felt.sweeps,
            if felt.sweeps == 1 { "" } else { "s" }
        );
        if felt.head_deflect > 0.01 {
            println!("  my head shifted {:.1} mrad under your hand, too.", felt.head_deflect * 1000.0);
        }
        if respond {
            // answer the touch with a gentle wiggle (best-effort — never fail a feel on it)
            if let Err(e) = wiggle(daemon) {
                eprintln!("  (couldn't wiggle back: {e})");
            }
        }
        if keep {
            let pose_h: TextHandle = ws.put(felt.signature_json.clone());
            let note_h: Option<TextHandle> = note
                .map(|n| n.to_string())
                .or_else(|| Some("a touch on the head".to_string()))
                .map(|n| ws.put(n));
            let frag = entity! {
                metadata::tag: &KIND_CAPTURE,
                metadata::created_at: now_tai(),
                capture::modality: "touch",
                capture::pose: pose_h,
                capture::note?: note_h,
            };
            let id = frag.root().expect("capture id");
            ws.commit(frag, "body feel");
            repo.push(ws).map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
            println!("  kept it — {}", &fmt_id(id)[..12]);
        }
    } else {
        println!(
            "quiet — I didn't feel a touch. ({} samples, {} sweep{}, sound around {:.0}–{:.0}°.)",
            felt.samples,
            felt.sweeps,
            if felt.sweeps == 1 { "" } else { "s" },
            felt.angle_min,
            felt.angle_max
        );
    }
    let _ = felt.max_speed;
    let _ = felt.speech_ticks;
    Ok(())
}

// ── commands ───────────────────────────────────────────────────────────────

fn cmd_pose(daemon: &str) -> Result<()> {
    let state = daemon_get(daemon, "/api/state/full")?;
    let status = daemon_get(daemon, "/api/daemon/status").unwrap_or_default();

    let hp = &state["head_pose"];
    let f = |k: &str| hp[k].as_f64().unwrap_or(f64::NAN);
    println!("head pose:");
    println!("  position   x={:+.4} y={:+.4} z={:+.4} (m)", f("x"), f("y"), f("z"));
    println!(
        "  rotation   roll={:+.4} pitch={:+.4} yaw={:+.4} (rad)",
        f("roll"), f("pitch"), f("yaw")
    );
    if let Some(by) = state["body_yaw"].as_f64() {
        println!("body yaw:    {by:+.4} rad");
    }
    if let Some(ant) = state["antennas_position"].as_array() {
        let vals: Vec<String> = ant.iter().map(|v| format!("{:+.4}", v.as_f64().unwrap_or(f64::NAN))).collect();
        println!("antennas:    [{}] rad", vals.join(", "));
    }
    // live mic-array direction-of-arrival (the touch/sound sense)
    if let Ok(d) = daemon_get(daemon, "/api/state/doa") {
        if let Some(a) = d["angle"].as_f64() {
            let sp = if d["speech_detected"].as_bool().unwrap_or(false) { " (speech)" } else { "" };
            println!("audio dir:   {:.0}°{sp}", a.to_degrees());
        }
    }
    if let Some(ts) = state["timestamp"].as_str() {
        println!("daemon time: {ts}");
    }
    if let Some(name) = status["robot_name"].as_str() {
        let st = status["state"].as_str().unwrap_or("?");
        let cam = status["camera_specs_name"].as_str().unwrap_or("?");
        println!("body:        {name} ({st}), camera={cam}");
    }
    Ok(())
}

fn cmd_look(
    repo: &mut Repository<Pile>,
    ws: &mut Workspace<Pile>,
    daemon: &str,
    python: &str,
    note: Option<&str>,
) -> Result<()> {
    let tmp = std::env::temp_dir();
    let shim_path = tmp.join("body_frame.py");
    std::fs::write(&shim_path, FRAME_SHIM).context("write frame shim")?;
    let out_png = tmp.join(format!("body_capture_{}.png", std::process::id()));

    let mut child = PCommand::new(python)
        .arg(&shim_path)
        .arg(&out_png)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("run frame shim with {python}"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        if child.try_wait().context("poll frame shim")?.is_some() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("frame grab timed out after 45s (cold WebRTC negotiation stalled — retry)");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let output = child.wait_with_output().context("collect frame shim output")?;
    if !output.status.success() {
        bail!("frame grab failed: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    let dims = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let (w, h) = dims
        .split_once('x')
        .and_then(|(a, b)| Some((a.parse::<u64>().ok()?, b.parse::<u64>().ok()?)))
        .unwrap_or((0, 0));

    let bytes = std::fs::read(&out_png).with_context(|| format!("read {}", out_png.display()))?;
    let nbytes = bytes.len();
    let _ = std::fs::remove_file(&out_png);

    let pose_json = daemon_get(daemon, "/api/state/full").map(|v| v.to_string()).unwrap_or_default();

    let frame_h: RawHandle = ws.put::<blobencodings::RawBytes, _>(bytes);
    let pose_h: TextHandle = ws.put(pose_json);
    let note_h: Option<TextHandle> = note.map(|n| ws.put(n.to_string()));
    let w_val: Inline<inlineencodings::U256BE> = w.to_inline();
    let h_val: Inline<inlineencodings::U256BE> = h.to_inline();

    let frag = entity! {
        metadata::tag: &KIND_CAPTURE,
        metadata::created_at: now_tai(),
        capture::frame: frame_h,
        capture::mime: "image/png",
        capture::modality: "vision",
        capture::width: w_val,
        capture::height: h_val,
        capture::pose: pose_h,
        capture::note?: note_h,
    };
    let cap_id = frag.root().expect("capture has an id");
    ws.commit(frag, "body look");
    repo.push(ws).map_err(|e| anyhow::anyhow!("push: {e:?}"))?;

    println!("captured {w}x{h} vision frame ({} KiB)", nbytes / 1024);
    println!("  id   {}", fmt_id(cap_id));
    if let Some(n) = note {
        println!("  note {n}");
    }
    Ok(())
}

fn cmd_list(ws: &mut Workspace<Pile>) -> Result<()> {
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let mut rows: Vec<(i128, Id, String, String)> = Vec::new();
    for (cid, modality, created) in find!(
        (c: Id, m: String, t: Inline<inlineencodings::NsTAIInterval>),
        pattern!(&space, [{
            ?c @
                metadata::tag: KIND_CAPTURE,
                capture::modality: ?m,
                metadata::created_at: ?t,
        }])
    ) {
        let note = find!(
            (h: Inline<inlineencodings::Handle<blobencodings::LongString>>),
            pattern!(&space, [{ cid @ capture::note: ?h }])
        )
        .next()
        .and_then(|(h,)| {
            let v: Result<View<str>, _> = ws.get(h);
            v.ok().map(|s| s.to_string())
        })
        .unwrap_or_default();
        rows.push((interval_key(created), cid, modality, note));
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0));
    if rows.is_empty() {
        println!("no captures yet — `body look` keeps a frame, `body feel --keep` a touch.");
        return Ok(());
    }
    for (k, cid, modality, note) in rows {
        let when = format_time(k);
        let suffix = if note.is_empty() { String::new() } else { format!("  — {note}") };
        println!("{}  {:<6}  {when}{suffix}", &fmt_id(cid)[..12], modality);
    }
    Ok(())
}

fn cmd_get(ws: &mut Workspace<Pile>, id: &str, output: Option<&str>) -> Result<()> {
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let needle = id.to_lowercase();
    let cap_id = find!(
        (c: Id),
        pattern!(&space, [{ ?c @ metadata::tag: KIND_CAPTURE }])
    )
    .map(|(c,)| c)
    .find(|c| fmt_id(*c).starts_with(&needle))
    .ok_or_else(|| anyhow::anyhow!("no capture matching '{id}'"))?;

    let h = find!(
        (h: RawHandle),
        pattern!(&space, [{ cap_id @ capture::frame: ?h }])
    )
    .next()
    .map(|(h,)| h)
    .ok_or_else(|| anyhow::anyhow!("capture has no frame payload (a touch capture has no file)"))?;
    let bytes: anybytes::Bytes = ws
        .get::<anybytes::Bytes, _>(h)
        .map_err(|e| anyhow::anyhow!("get blob: {e:?}"))?;

    if output == Some("@-") {
        use std::io::Write;
        std::io::stdout().write_all(bytes.as_ref()).context("write to stdout")?;
    } else {
        let out_path = output
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(format!("{}.png", &fmt_id(cap_id)[..12])));
        std::fs::write(&out_path, bytes.as_ref())
            .with_context(|| format!("write {}", out_path.display()))?;
        eprintln!("Wrote {} ({} KiB)", out_path.display(), bytes.len() / 1024);
    }
    Ok(())
}

// ── VLA interface: raw observe / absolute act ──────────────────────────────

fn cmd_observe(daemon: &str, python: &str, frame: Option<&Path>, no_frame: bool) -> Result<()> {
    let state = read_state(daemon)?;
    let touch = daemon_get(daemon, "/api/state/doa").ok();
    let (frame_path, fw, fh) = if no_frame {
        (None, 0u64, 0u64)
    } else {
        let p = frame
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::env::temp_dir().join("body_observe.png"));
        let (w, h) = grab_frame(python, &p)?;
        (Some(p), w, h)
    };
    let obs = serde_json::json!({
        "t": format_time(interval_key(now_tai())),
        "frame": frame_path.as_ref().map(|p| p.display().to_string()),
        "frame_size": [fw, fh],
        "state": state,
        "state_layout": ["head_x_m","head_y_m","head_z_m","head_roll_rad","head_pitch_rad","head_yaw_rad","body_yaw_rad","antenna_l_rad","antenna_r_rad"],
        "touch": touch.map(|d| serde_json::json!({
            "doa_angle_rad": d["angle"].as_f64(),
            "doa_speech": d["speech_detected"].as_bool(),
        })),
        "raw": true,
        "note": "no resize/normalize — VLA owns preprocessing",
    });
    println!("{}", serde_json::to_string_pretty(&obs)?);
    Ok(())
}

fn parse_pose(s: &str) -> Result<[f64; 9]> {
    let v: Vec<f64> = s
        .split(',')
        .map(|x| x.trim().parse::<f64>())
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("bad pose number: {e}"))?;
    if v.len() != 9 {
        bail!(
            "pose needs 9 reals (x,y,z,roll,pitch,yaw,body_yaw,ant_l,ant_r), got {}",
            v.len()
        );
    }
    Ok([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8]])
}

fn cmd_act(daemon: &str, pose: &str, duration: f64, dt: f64, now: bool) -> Result<()> {
    if let Some(spec) = pose.strip_prefix('@') {
        let text = if spec == "-" {
            use std::io::Read;
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            s
        } else {
            std::fs::read_to_string(spec).with_context(|| format!("read chunk {spec}"))?
        };
        let chunk: Vec<Vec<f64>> =
            serde_json::from_str(&text).context("parse chunk JSON (array of 9-real arrays)")?;
        let n = chunk.len();
        for (i, row) in chunk.into_iter().enumerate() {
            if row.len() != 9 {
                bail!("chunk waypoint {i} needs 9 reals, got {}", row.len());
            }
            set_target(
                daemon,
                Some((row[0], row[1], row[2], row[3], row[4], row[5])),
                Some([row[7], row[8]]),
                Some(row[6]),
            )?;
            std::thread::sleep(Duration::from_secs_f64(dt));
        }
        println!("streamed {n} waypoints @ {dt:.3}s");
    } else {
        let p = parse_pose(pose)?;
        let head = Some((p[0], p[1], p[2], p[3], p[4], p[5]));
        let ant = Some([p[7], p[8]]);
        if now {
            set_target(daemon, head, ant, Some(p[6]))?;
            println!("snapped to pose");
        } else {
            goto(daemon, head, ant, Some(p[6]), duration)?;
            println!("moved to pose over {duration:.2}s");
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let pile = cli.pile.clone();
    let branch = cli.branch_id.as_deref();
    let daemon = cli.daemon.clone();
    let python = cli.python.clone();

    match cli.command {
        None => {
            Cli::command().print_help().ok();
            println!();
        }
        Some(Command::Pose) => cmd_pose(&daemon)?,
        Some(Command::Wake) => {
            daemon_post(&daemon, "/api/move/play/wake_up")?;
            println!("waking up");
        }
        Some(Command::Sleep) => {
            daemon_post(&daemon, "/api/move/play/goto_sleep")?;
            println!("going to sleep");
        }
        Some(Command::Feel { secs, keep, respond, note }) => {
            with_body(&pile, branch, |repo, ws| {
                cmd_feel(repo, ws, &daemon, secs, keep, respond, note.as_deref())
            })?
        }
        Some(Command::Gesture { name }) => cmd_gesture(&daemon, &name)?,
        Some(Command::Observe { frame, no_frame }) => {
            cmd_observe(&daemon, &python, frame.as_deref(), no_frame)?
        }
        Some(Command::Act { pose, duration, dt, now }) => {
            cmd_act(&daemon, &pose, duration, dt, now)?
        }
        Some(Command::Look { note }) => {
            with_body(&pile, branch, |repo, ws| cmd_look(repo, ws, &daemon, &python, note.as_deref()))?
        }
        Some(Command::List) => with_body(&pile, branch, |_repo, ws| cmd_list(ws))?,
        Some(Command::Get { id, output }) => {
            with_body(&pile, branch, |_repo, ws| cmd_get(ws, &id, output.as_deref()))?
        }
    }
    Ok(())
}
