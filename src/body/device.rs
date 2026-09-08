//! Explicit host/device operations. Construction never contacts hardware.
//! The camera remains the original embedded Python/WebRTC island; REST motion
//! and state access are native. These operations are not registered with MCP.

use super::{Body, CaptureInput, CaptureReceipt, Signal};
use anybytes::Bytes;
use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

pub const DEFAULT_DAEMON: &str = "http://localhost:8000";
pub const DEFAULT_PYTHON: &str = "python3";
const FRAME_SHIM: &str = include_str!("../bin/body_frame.py");

#[derive(Clone, Debug)]
pub struct Device {
    daemon: String,
    python: String,
}
#[derive(Clone, Debug)]
pub struct PoseObservation {
    pub state: serde_json::Value,
    pub status: Option<serde_json::Value>,
    pub touch: Option<serde_json::Value>,
}
#[derive(Clone, Debug)]
pub struct Frame {
    pub bytes: Bytes,
    pub width: u64,
    pub height: u64,
}
#[derive(Clone, Debug)]
pub struct Observation {
    pub tai_ns: i128,
    pub state: [f64; 9],
    pub touch: Option<serde_json::Value>,
    pub frame: Option<Frame>,
}
#[derive(Clone, Copy, Debug)]
pub enum Gesture {
    Nod,
    Shake,
    Wiggle,
    Perk,
    LookLeft,
    LookRight,
    Center,
}
impl Gesture {
    pub fn parse(name: &str) -> Result<Self> {
        Ok(match name.to_ascii_lowercase().as_str() {
            "nod" | "yes" => Self::Nod, "shake" | "no" => Self::Shake,
            "wiggle" | "happy" => Self::Wiggle, "perk" => Self::Perk,
            "look-left" => Self::LookLeft, "look-right" => Self::LookRight,
            "center" | "rest" => Self::Center,
            _ => bail!("unknown gesture '{name}' — try: nod, shake, wiggle, perk, look-left, look-right, center"),
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Nod => "nod",
            Self::Shake => "shake",
            Self::Wiggle => "wiggle",
            Self::Perk => "perk",
            Self::LookLeft => "look-left",
            Self::LookRight => "look-right",
            Self::Center => "center",
        }
    }
}
#[derive(Clone, Debug)]
pub enum Action {
    Pose {
        pose: [f64; 9],
        duration: Duration,
        immediate: bool,
    },
    Chunk {
        poses: Vec<[f64; 9]>,
        interval: Duration,
    },
}
impl Action {
    /// Validate the complete chunk before the first physical movement.
    pub fn validate(&self) -> Result<()> {
        let finite = |pose: &[f64; 9]| -> Result<()> {
            if !pose.iter().all(|value| value.is_finite()) {
                bail!("pose values must be finite");
            }
            Ok(())
        };
        match self {
            Self::Pose { pose, .. } => finite(pose),
            Self::Chunk { poses, .. } => {
                for (index, pose) in poses.iter().enumerate() {
                    finite(pose).with_context(|| format!("chunk waypoint {index}"))?;
                }
                Ok(())
            }
        }
    }
}
#[derive(Clone, Debug)]
pub enum ActionReceipt {
    Snapped,
    Moved {
        duration: Duration,
    },
    Streamed {
        waypoints: usize,
        interval: Duration,
    },
}

impl Device {
    pub fn new(daemon: String, python: String) -> Self {
        Self { daemon, python }
    }
    pub fn pose(&self) -> Result<PoseObservation> {
        Ok(PoseObservation {
            state: daemon_get(&self.daemon, "/api/state/full")?,
            status: daemon_get(&self.daemon, "/api/daemon/status").ok(),
            touch: daemon_get(&self.daemon, "/api/state/doa").ok(),
        })
    }
    pub fn wake(&self) -> Result<()> {
        daemon_post(&self.daemon, "/api/move/play/wake_up")
    }
    pub fn sleep(&self) -> Result<()> {
        daemon_post(&self.daemon, "/api/move/play/goto_sleep")
    }
    pub fn gesture(&self, gesture: Gesture) -> Result<()> {
        perform_gesture(&self.daemon, gesture.name())
    }
    pub fn feel(&self, duration: Duration) -> Result<Felt> {
        let felt = feel_window(&self.daemon, duration);
        if felt.samples == 0 {
            bail!("felt nothing back from the daemon — is the Reachy Mini running?");
        }
        Ok(felt)
    }
    pub fn frame(&self) -> Result<Frame> {
        grab_frame(&self.python)
    }
    pub fn look(&self, body: &Body, note: Option<&str>) -> Result<CaptureReceipt> {
        let frame = self.frame()?;
        let pose = daemon_get(&self.daemon, "/api/state/full")
            .map(|value| value.to_string())
            .unwrap_or_default();
        body.capture(&CaptureInput {
            signal: Signal::Vision {
                bytes: frame.bytes,
                mime: "image/png".into(),
                width: frame.width,
                height: frame.height,
            },
            pose,
            note: note.map(str::to_owned),
        })
    }
    pub fn observe(&self, include_frame: bool) -> Result<Observation> {
        let state = read_state(&self.daemon)?;
        let touch = daemon_get(&self.daemon, "/api/state/doa").ok();
        let frame = include_frame.then(|| self.frame()).transpose()?;
        Ok(Observation {
            tai_ns: super::operations::interval_key(crate::clock::point_now()?),
            state,
            touch,
            frame,
        })
    }
    pub fn act(&self, action: &Action) -> Result<ActionReceipt> {
        action.validate()?;
        let target = |p: &[f64; 9]| {
            set_target(
                &self.daemon,
                Some((p[0], p[1], p[2], p[3], p[4], p[5])),
                Some([p[7], p[8]]),
                Some(p[6]),
            )
        };
        match action {
            Action::Pose {
                pose: p,
                duration,
                immediate,
            } => {
                if *immediate {
                    target(p)?;
                    Ok(ActionReceipt::Snapped)
                } else {
                    goto(
                        &self.daemon,
                        Some((p[0], p[1], p[2], p[3], p[4], p[5])),
                        Some([p[7], p[8]]),
                        Some(p[6]),
                        duration.as_secs_f64(),
                    )?;
                    Ok(ActionReceipt::Moved {
                        duration: *duration,
                    })
                }
            }
            Action::Chunk { poses, interval } => {
                for pose in poses {
                    target(pose)?;
                    std::thread::sleep(*interval);
                }
                Ok(ActionReceipt::Streamed {
                    waypoints: poses.len(),
                    interval: *interval,
                })
            }
        }
    }
}
impl Felt {
    pub fn capture_input(&self, note: Option<&str>) -> CaptureInput {
        CaptureInput {
            signal: Signal::Touch,
            pose: self.signature_json.clone(),
            note: Some(note.unwrap_or("a touch on the head").to_owned()),
        }
    }
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
    daemon_post_json(
        daemon,
        "/api/move/set_target",
        &serde_json::Value::Object(req),
    )
}

/// Read the raw 9-real proprioceptive state vector
/// [x,y,z,roll,pitch,yaw, body_yaw, ant_l, ant_r] in raw SDK units
/// (REST gives head xyz in metres, angles in radians).
fn read_state(daemon: &str) -> Result<[f64; 9]> {
    let s = daemon_get(daemon, "/api/state/full")?;
    let h = &s["head_pose"];
    let g = |v: &serde_json::Value, k: &str| v[k].as_f64().unwrap_or(0.0);
    let ant = s["antennas_position"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    Ok([
        g(h, "x"),
        g(h, "y"),
        g(h, "z"),
        g(h, "roll"),
        g(h, "pitch"),
        g(h, "yaw"),
        s["body_yaw"].as_f64().unwrap_or(0.0),
        ant.first().and_then(|v| v.as_f64()).unwrap_or(0.0),
        ant.get(1).and_then(|v| v.as_f64()).unwrap_or(0.0),
    ])
}

fn perform_gesture(daemon: &str, name: &str) -> Result<()> {
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
    Ok(())
}

/// What a touch looked like over the felt window.
#[derive(Clone, Debug)]
pub struct Felt {
    pub samples: usize,
    pub sweeps: usize,  // count of >SWEEP_DEG moves within a ~SWEEP_WIN window
    pub angle_min: f64, // degrees
    pub angle_max: f64,
    pub max_speed: f64,    // deg/s
    pub head_deflect: f64, // rad, max yaw/roll/pitch range
    pub speech_ticks: usize,
    pub signature_json: String,
}

impl Felt {
    pub fn touched(&self) -> bool {
        // A real touch physically DISPLACES the head — the encoders move far
        // past the rest floor (calibrated: ambient ≤6 mrad, JP's real pet
        // swung roll ~177 mrad). Ambient sound only wanders the mic DOA and
        // can't move the head, so head displacement is the pet-specific gate.
        // (The mic sweep is reported as corroboration, never as the trigger —
        // it false-positives on room noise.)
        self.head_deflect > 0.02
    }
}

/// Sample the mic-array DOA (and the head encoders) for `secs` and summarise
/// the touch signature.
fn feel_window(daemon: &str, duration: Duration) -> Felt {
    const SWEEP_DEG: f64 = 15.0; // a "sweep" = this much DOA travel…
    const SWEEP_WIN: f64 = 0.6; // …within this window (s)
    let client = http();
    let start = Instant::now();
    let dur = duration;
    let secs = duration.as_secs_f64();

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
        angle_min: if angle_min.is_finite() {
            angle_min
        } else {
            0.0
        },
        angle_max: if angle_max.is_finite() {
            angle_max
        } else {
            0.0
        },
        max_speed,
        head_deflect: if head_deflect.is_finite() {
            head_deflect
        } else {
            0.0
        },
        speech_ticks,
        signature_json,
    }
}

/// Reserve an owned output file. No common shim path is overwritten: Python
/// receives the embedded source directly, and this one reserved frame is removed
/// on success or failure after its bytes have become resident.
struct TemporaryFrame(PathBuf);
impl Drop for TemporaryFrame {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn grab_frame(python: &str) -> Result<Frame> {
    let stamp = crate::clock::tai_nanoseconds_now()?;
    let path = std::env::temp_dir().join(format!("body-frame-{}-{stamp}.png", std::process::id()));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .context("reserve camera output")?;
    drop(file);
    let output_path = TemporaryFrame(path);
    let mut child = Command::new(python)
        .arg("-c")
        .arg(FRAME_SHIM)
        .arg(&output_path.0)
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
            bail!("frame grab timed out after 45s (cold WebRTC negotiation stalled)");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let output = child
        .wait_with_output()
        .context("collect frame shim output")?;
    if !output.status.success() {
        bail!(
            "frame grab failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let dims = String::from_utf8_lossy(&output.stdout);
    let (width, height) = dims
        .trim()
        .split_once('x')
        .and_then(|(a, b)| Some((a.parse::<u64>().ok()?, b.parse::<u64>().ok()?)))
        .filter(|(w, h)| *w > 0 && *h > 0)
        .context("frame shim returned invalid dimensions")?;
    let bytes = std::fs::read(&output_path.0)
        .context("read camera frame")?
        .into();
    Ok(Frame {
        bytes,
        width,
        height,
    })
}
