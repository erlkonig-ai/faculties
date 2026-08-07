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

use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use faculties::collection_access::{self, CollectionView, CollectionWriter};
use faculties::schemas::body::{capture, intent, DEFAULT_SCOPE_ID, KIND_CAPTURE, KIND_INTENT};
use hifitime::efmt::consts::ISO8601;
use hifitime::efmt::Formatter;
use hifitime::Epoch;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command as PCommand;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use triblespace::core::collection::simplearchive_union;
use triblespace::core::collection::{CollectionCommit, CollectionData};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{self, reachable};
use triblespace::prelude::*;

type RawHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;
type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;

const DEFAULT_DAEMON: &str = "http://localhost:8000";
const LEGACY_BODY_BRANCH_NAME: &str = "body";
// The reachy venv's interpreter. `python3` resolves via PATH by default (set
// `REACHY_PYTHON` to point at a specific venv); no machine-absolute path.
const DEFAULT_PYTHON: &str = "python3";

/// The embedded frame-grab shim — written to a temp file at runtime.
const FRAME_SHIM: &str = include_str!("body_frame.py");

// ── CLI ──────────────────────────────────────────────────────────────────
#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "body",
    about = "The Reachy Mini body: perception in, action out, deliberate captures to the pile"
)]
struct Cli {
    /// Path to the pile file. Required only by commands that keep or read data.
    #[arg(long, env = "PILE")]
    pile: Option<PathBuf>,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Extrinsic collection scope for deliberate body data. Defaults to the
    /// stable body scope declared by this faculty.
    #[arg(long, value_parser = parse_id_arg)]
    scope: Option<Id>,
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
    /// timestamped intent in the body scope. Without: prints the LATEST intent
    /// text to stdout (what the control loop reads each cycle), time to stderr.
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
    /// Publish the signed legacy `body` branch as collection commits, then
    /// verify the exact materialized view. Stop every legacy body writer before
    /// running this command. It never removes the legacy pin; collection
    /// retention is not yet a durable recurring policy.
    MigrateLegacy {
        /// Exact legacy body branch id. Needed only when duplicate `body`
        /// branch names make name lookup ambiguous.
        #[arg(long, value_parser = parse_id_arg)]
        legacy_branch_id: Option<Id>,
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

// ── helpers ──────────────────────────────────────────────────────────────

fn parse_id_arg(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim()).ok_or_else(|| format!("invalid id '{raw}'"))
}

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
    daemon_post_json(
        daemon,
        "/api/move/set_target",
        &serde_json::Value::Object(req),
    )
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
    let output = child
        .wait_with_output()
        .context("collect frame shim output")?;
    if !output.status.success() {
        bail!(
            "frame grab failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
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

#[derive(Clone, Copy)]
struct BodyStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
    scope: Id,
}

impl BodyStorage<'_> {
    fn publish(&self, fragment: Fragment) -> Result<()> {
        collection_access::publish_fragment(
            self.pile,
            self.key,
            self.scope,
            fragment,
            Fragment::empty(),
        )?;
        Ok(())
    }

    fn view(&self) -> Result<CollectionView> {
        let signer = collection_access::load_signer(self.pile, self.key)?;
        let allowed = HashSet::from([signer.verifying_key()]);
        collection_access::materialize_scope(self.pile, self.scope, &allowed)
    }

    fn writer(&self) -> Result<CollectionWriter> {
        CollectionWriter::open(self.pile, self.key, self.scope)
    }
}

fn require_storage<'a>(
    pile: Option<&'a Path>,
    key: Option<&'a Path>,
    scope: Id,
) -> Result<BodyStorage<'a>> {
    let pile = pile.ok_or_else(|| {
        anyhow::anyhow!("this command requires --pile (or PILE); hardware-only commands do not")
    })?;
    Ok(BodyStorage { pile, key, scope })
}

// ── one-way legacy branch migration ──────────────────────────────────────

#[derive(Debug)]
struct LegacyCommitMigration {
    source: CommitHandle,
    target: CollectionCommit,
    content: Fragment,
    metadata: Fragment,
}

#[derive(Debug)]
struct LegacyMigrationPlan {
    branch_id: Id,
    pin_metadata: Inline<inlineencodings::Handle<blobencodings::SimpleArchive>>,
    head: CommitHandle,
    commits: Vec<LegacyCommitMigration>,
    skipped_merges: usize,
    facts: TribleSet,
}

#[derive(Debug)]
struct LegacyMigrationReport {
    branch_id: Id,
    head: CommitHandle,
    commits: Vec<(CommitHandle, Id)>,
    skipped_merges: usize,
    facts: usize,
    retention_direct: usize,
    retention_recursive: usize,
}

fn one_commit_value<V: InlineEncoding>(
    facts: &TribleSet,
    subject: Id,
    attribute: &Attribute<V>,
    field: &str,
) -> Result<Option<Inline<V>>> {
    let mut values = facts
        .iter()
        .filter(|fact| fact.e() == &subject && fact.a() == &attribute.id())
        .map(|fact| *fact.v::<V>());
    let first = values.next();
    if values.next().is_some() {
        bail!("legacy commit has repeated {field}");
    }
    Ok(first)
}

fn legacy_commit_subject(facts: &TribleSet, handle: CommitHandle) -> Result<Id> {
    let entities: BTreeSet<Id> = facts.iter().map(|fact| *fact.e()).collect();
    if entities.len() != 1 {
        bail!(
            "legacy commit {} must contain exactly one metadata entity, found {}",
            hex::encode_upper(handle.raw),
            entities.len()
        );
    }
    Ok(*entities.iter().next().expect("one entity"))
}

fn legacy_parents(
    facts: &TribleSet,
    subject: Id,
) -> Vec<Inline<inlineencodings::Handle<blobencodings::SimpleArchive>>> {
    let mut parents: Vec<_> = find!(
        (parent: Inline<inlineencodings::Handle<blobencodings::SimpleArchive>>),
        pattern!(facts, [{ subject @ repo::parent: ?parent }])
    )
    .map(|(parent,)| parent)
    .collect();
    parents.sort_unstable_by_key(|parent| parent.raw);
    parents.dedup();
    parents
}

fn load_legacy_commit_metadata(reader: &PileReader, handle: CommitHandle) -> Result<TribleSet> {
    reader
        .get(handle)
        .with_context(|| format!("read legacy commit {}", hex::encode_upper(handle.raw)))
}

fn legacy_commits_topological(
    reader: &PileReader,
    head: CommitHandle,
) -> Result<Vec<CommitHandle>> {
    let mut ordered = Vec::new();
    let mut emitted = HashSet::new();
    let mut active = HashSet::new();
    let mut stack = vec![(head, false)];

    while let Some((commit, expanded)) = stack.pop() {
        if emitted.contains(&commit) {
            continue;
        }
        if expanded {
            active.remove(&commit);
            emitted.insert(commit);
            ordered.push(commit);
            continue;
        }
        if !active.insert(commit) {
            bail!(
                "cycle in legacy commit ancestry at {}",
                hex::encode_upper(commit.raw)
            );
        }

        let facts = load_legacy_commit_metadata(reader, commit)?;
        let subject = legacy_commit_subject(&facts, commit)?;
        let parents = legacy_parents(&facts, subject);
        stack.push((commit, true));
        for parent in parents.into_iter().rev() {
            if active.contains(&parent) {
                bail!(
                    "cycle in legacy commit ancestry at {}",
                    hex::encode_upper(parent.raw)
                );
            }
            if !emitted.contains(&parent) {
                stack.push((parent, false));
            }
        }
    }
    Ok(ordered)
}

/// Hydrate the transitive part of a closure which is already resident.
///
/// `reachable` can follow references present in resident typed blobs, but an
/// untyped fact set cannot prove that a directly named child is absent. Body's
/// known direct payload attributes are therefore read strictly in
/// `preflight_legacy_body_payloads` before this helper is used.
fn hydrate_resident_closure(
    reader: &PileReader,
    roots: impl IntoIterator<Item = Inline<inlineencodings::Handle<blobencodings::UnknownBlob>>>,
) -> Result<MemoryBlobStore> {
    let mut blobs = MemoryBlobStore::new();
    for handle in reachable(reader, roots) {
        let blob: Blob<blobencodings::UnknownBlob> = reader.get(handle).with_context(|| {
            format!(
                "load reachable legacy attachment {}",
                hex::encode_upper(handle.raw)
            )
        })?;
        blobs.insert(blob);
    }
    Ok(blobs)
}

fn preflight_legacy_body_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts.iter() {
        if fact.a() == &capture::frame.id() {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::RawBytes>>();
            let _: anybytes::Bytes = reader.get(handle).with_context(|| {
                format!(
                    "strictly read legacy capture::frame payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
            continue;
        }

        let field = if fact.a() == &intent::text.id() {
            Some("intent::text")
        } else if fact.a() == &capture::note.id() {
            Some("capture::note")
        } else if fact.a() == &capture::pose.id() {
            Some("capture::pose")
        } else {
            None
        };
        if let Some(field) = field {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::LongString>>();
            let _: View<str> = reader.get(handle).with_context(|| {
                format!(
                    "strictly read legacy {field} payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

fn legacy_content_fragment(
    reader: &PileReader,
    content: Inline<inlineencodings::Handle<blobencodings::SimpleArchive>>,
) -> Result<(Blob<blobencodings::SimpleArchive>, Fragment)> {
    let archive: Blob<blobencodings::SimpleArchive> = reader
        .get(content)
        .with_context(|| format!("read legacy content {}", hex::encode_upper(content.raw)))?;
    let facts: TribleSet = reader
        .get(content)
        .with_context(|| format!("decode legacy content {}", hex::encode_upper(content.raw)))?;
    preflight_legacy_body_payloads(reader, &facts)?;
    let blobs = hydrate_resident_closure(reader, [content.transmute()])?;
    Ok((archive, Fragment::from_facts_and_blobs(facts, blobs)))
}

fn legacy_metadata_fragment(
    reader: &PileReader,
    facts: &TribleSet,
    subject: Id,
) -> Result<Fragment> {
    let attached = one_commit_value(facts, subject, &repo::metadata, "metadata")?;
    let message = one_commit_value(facts, subject, &repo::message, "message")?;
    let created = one_commit_value(facts, subject, &metadata::created_at, "created_at")?;

    let (mut projected_facts, mut projected_blobs) = if let Some(handle) = attached {
        let facts: TribleSet = reader.get(handle).with_context(|| {
            format!(
                "read attached legacy metadata {}",
                hex::encode_upper(handle.raw)
            )
        })?;
        let blobs = hydrate_resident_closure(reader, [handle.transmute()])?;
        (facts, blobs)
    } else {
        (TribleSet::new(), MemoryBlobStore::new())
    };

    if let Some(handle) = message {
        projected_blobs.union(hydrate_resident_closure(reader, [handle.transmute()])?);
    }

    let projection = match (created, message) {
        (Some(created), Some(message)) => entity! {
            metadata::created_at: created,
            metadata::description: message,
        },
        (Some(created), None) => entity! { metadata::created_at: created },
        (None, Some(message)) => entity! { metadata::description: message },
        (None, None) => Fragment::empty(),
    };
    let (projection_facts, projection_blobs) = projection.into_facts_and_blobs();
    projected_facts += projection_facts;
    projected_blobs.union(projection_blobs);
    Ok(Fragment::from_facts_and_blobs(
        projected_facts,
        projected_blobs,
    ))
}

fn validate_contentless_legacy_merge(
    facts: &TribleSet,
    subject: Id,
    source: CommitHandle,
) -> Result<()> {
    let parents = legacy_parents(facts, subject);
    let contains_only_parent_edges = facts
        .iter()
        .all(|fact| fact.e() == &subject && fact.a() == &repo::parent.id());
    if parents.len() < 2 || !contains_only_parent_edges {
        bail!(
            "legacy contentless commit {} is not a canonical merge",
            hex::encode_upper(source.raw)
        );
    }
    Ok(())
}

fn named_legacy_branch_snapshot(
    pile: &mut Pile,
    explicit: Option<Id>,
) -> Result<(
    Id,
    Inline<inlineencodings::Handle<blobencodings::SimpleArchive>>,
    PileReader,
)> {
    let ids: Vec<Id> = if let Some(branch) = explicit {
        vec![branch]
    } else {
        pile.pins()
            .context("list legacy pins")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("read legacy pin id")?
    };
    let mut heads = Vec::new();
    for id in ids {
        if let Some(head) = pile.head(id).context("read legacy pin head")? {
            heads.push((id, head));
        } else if explicit == Some(id) {
            bail!("legacy branch {id:X} does not exist");
        }
    }
    let reader = pile.reader().context("snapshot legacy body branch")?;
    let wanted: Inline<inlineencodings::Handle<blobencodings::LongString>> =
        LEGACY_BODY_BRANCH_NAME.to_owned().to_blob().get_handle();
    let mut matches = Vec::new();
    for (branch_id, pin_metadata) in heads {
        let branch_facts: TribleSet = reader
            .get(pin_metadata)
            .with_context(|| format!("read legacy branch metadata for {branch_id:X}"))?;
        let Ok(entity) = repo::branch::branch_entity(&branch_facts, branch_id) else {
            continue;
        };
        let name = one_commit_value(&branch_facts, entity, &metadata::name, "branch name")?;
        if name == Some(wanted) {
            matches.push((branch_id, pin_metadata));
        }
    }
    match matches.len() {
        0 if explicit.is_some() => bail!("the selected legacy pin is not the named body branch"),
        0 => bail!("no legacy body branch exists"),
        1 => Ok((matches[0].0, matches[0].1, reader)),
        _ => bail!("multiple legacy branches are named body; rerun with --legacy-branch-id"),
    }
}

fn build_legacy_migration_plan(
    pile_path: &Path,
    signer: &SigningKey,
    scope: Id,
    explicit_branch: Option<Id>,
) -> Result<LegacyMigrationPlan> {
    let mut pile = collection_access::open_pile_strict(pile_path)?;
    let snapshot = named_legacy_branch_snapshot(&mut pile, explicit_branch);
    let (branch_id, pin_metadata, reader) = finish_migration_pile(pile, snapshot)?;

    let branch_facts: TribleSet = reader
        .get(pin_metadata)
        .context("read snapshotted legacy branch metadata")?;
    let branch_entity = repo::branch::branch_entity(&branch_facts, branch_id)
        .map_err(|error| anyhow::anyhow!("resolve legacy branch entity: {error:?}"))?;
    let head = one_commit_value(&branch_facts, branch_entity, &repo::head, "branch head")?
        .ok_or_else(|| anyhow::anyhow!("legacy body branch is empty"))?;
    let head_blob: Blob<blobencodings::SimpleArchive> =
        reader.get(head).context("read legacy branch head commit")?;
    repo::branch::verify(branch_id, head_blob, branch_facts)
        .map_err(|_| anyhow::anyhow!("legacy body branch-head signature is invalid"))?;

    let definition = simplearchive_union::definition(scope);
    let mut commits = Vec::new();
    let mut targets = BTreeMap::new();
    let mut skipped_merges = 0;
    let mut union = TribleSet::new();

    for source in legacy_commits_topological(&reader, head)? {
        let commit_facts = load_legacy_commit_metadata(&reader, source)?;
        let subject = legacy_commit_subject(&commit_facts, source)?;
        let Some(content_handle) =
            one_commit_value(&commit_facts, subject, &repo::content, "content")?
        else {
            validate_contentless_legacy_merge(&commit_facts, subject, source)?;
            skipped_merges += 1;
            continue;
        };
        let (content_blob, content) = legacy_content_fragment(&reader, content_handle)?;
        repo::commit::verify(content_blob, commit_facts.clone()).map_err(|_| {
            anyhow::anyhow!(
                "legacy authored commit {} has an invalid content signature",
                hex::encode_upper(source.raw)
            )
        })?;
        let metadata = legacy_metadata_fragment(&reader, &commit_facts, subject)?;
        let data_blob: Blob<blobencodings::SimpleArchive> = content.facts().clone().to_blob();
        let metadata_blob: Blob<blobencodings::SimpleArchive> = metadata.facts().clone().to_blob();
        let data: CollectionData = data_blob.get_handle().into();
        let metadata_handle = metadata_blob.get_handle();
        let target = CollectionCommit::sign(signer, definition.id(), data, metadata_handle);
        if let Some(previous) = targets.insert(target.id(), source) {
            bail!(
                "legacy commits {} and {} collapse to collection commit {}; refusing to invent identity",
                hex::encode_upper(previous.raw),
                hex::encode_upper(source.raw),
                target.id()
            );
        }
        union += content.facts().clone();
        commits.push(LegacyCommitMigration {
            source,
            target,
            content,
            metadata,
        });
    }

    Ok(LegacyMigrationPlan {
        branch_id,
        pin_metadata,
        head,
        commits,
        skipped_merges,
        facts: union,
    })
}

fn finish_migration_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    let close = pile.close();
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(anyhow::anyhow!("close migration pile: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing migration pile failed too: {close_error}")))
        }
    }
}

fn confirm_legacy_pin(
    pile_path: &Path,
    branch_id: Id,
    expected: Inline<inlineencodings::Handle<blobencodings::SimpleArchive>>,
) -> Result<bool> {
    let mut pile = collection_access::open_pile_strict(pile_path)?;
    let current = pile.head(branch_id).context("recheck legacy body pin")?;
    finish_migration_pile(pile, Ok(current == Some(expected)))
}

/// Re-read the resident transitive closure of the newly published roots.
/// Direct body payload presence and decoding were established independently
/// during the strict legacy preflight.
fn verify_resident_collection_closure(
    view: &CollectionView,
    commits: impl IntoIterator<Item = CollectionCommit>,
) -> Result<()> {
    let roots = commits.into_iter().flat_map(|commit| {
        [
            inlineencodings::Handle::<blobencodings::UnknownBlob>::from_hash(commit.data()),
            commit.metadata().transmute(),
        ]
    });
    for handle in reachable(&view.reader, roots) {
        let _: Blob<blobencodings::UnknownBlob> = view.reader.get(handle).with_context(|| {
            format!(
                "verify migrated collection attachment {}",
                hex::encode_upper(handle.raw)
            )
        })?;
    }
    Ok(())
}

fn migrate_legacy(
    storage: BodyStorage<'_>,
    explicit_branch: Option<Id>,
) -> Result<LegacyMigrationReport> {
    // The durable signer is required before the legacy pile is even opened.
    let signer = collection_access::load_signer(storage.pile, storage.key)?;
    let allowed = HashSet::from([signer.verifying_key()]);
    let plan = build_legacy_migration_plan(storage.pile, &signer, storage.scope, explicit_branch)?;
    let CollectionView {
        facts: mut expected,
        reader: _,
    } = collection_access::materialize_scope(storage.pile, storage.scope, &allowed)?;
    expected += plan.facts.clone();

    // Validate every already-authorized collection before this command adds a
    // byte. In particular, an unsupported collection kind owned by the same
    // signer must fail here rather than after migrated COMMITs were appended.
    collection_access::plan_authorized_union_retention(storage.pile, &allowed)
        .context("preflight existing authorized collection retention")?;

    let mut pile = collection_access::open_pile_strict(storage.pile)?;
    let result = (|| {
        let current = pile
            .head(plan.branch_id)
            .context("recheck legacy body pin")?;
        if current != Some(plan.pin_metadata) {
            bail!("legacy body pin changed after snapshot; no collection commit was published");
        }

        let definition = simplearchive_union::definition(storage.scope);
        let mut published = Vec::with_capacity(plan.commits.len());
        for migration in &plan.commits {
            let commit = simplearchive_union::publish_fragment_commit(
                &mut pile,
                &definition,
                migration.content.clone(),
                migration.metadata.clone(),
                &signer,
            )
            .context("publish migrated body collection commit")?;
            if commit != migration.target {
                bail!("published migration commit differs from its preflight identity");
            }
            commit
                .verify_strict()
                .context("verify migrated body collection signature")?;
            published.push((migration.source, commit));
        }
        Ok(published)
    })();
    let published = finish_migration_pile(pile, result)?;

    let view = collection_access::materialize_scope(storage.pile, storage.scope, &allowed)?;
    if view.facts != expected {
        bail!("migrated body collection does not equal the prior collection union legacy facts");
    }
    verify_resident_collection_closure(&view, published.iter().map(|(_, commit)| commit.clone()))?;
    let retention = collection_access::plan_authorized_union_retention(storage.pile, &allowed)?;
    let retention_direct = retention.direct().len();
    let retention_recursive = retention.recursive().len();
    if !confirm_legacy_pin(storage.pile, plan.branch_id, plan.pin_metadata)? {
        bail!(
            "legacy body pin advanced during migration; collection commits may already have been appended. Stop every legacy writer, then rerun to migrate the new prefix; deterministic replay will reuse matching records"
        );
    }

    Ok(LegacyMigrationReport {
        branch_id: plan.branch_id,
        head: plan.head,
        commits: published
            .into_iter()
            .map(|(source, target)| (source, target.id()))
            .collect(),
        skipped_merges: plan.skipped_merges,
        facts: plan.facts.len() as usize,
        retention_direct,
        retention_recursive,
    })
}

fn cmd_migrate_legacy(storage: BodyStorage<'_>, explicit_branch: Option<Id>) -> Result<()> {
    let report = migrate_legacy(storage, explicit_branch)?;
    println!(
        "migrated {} authored commit{} ({} facts); skipped {} contentless merge{}",
        report.commits.len(),
        if report.commits.len() == 1 { "" } else { "s" },
        report.facts,
        report.skipped_merges,
        if report.skipped_merges == 1 { "" } else { "s" },
    );
    println!("  legacy branch {}", report.branch_id);
    println!("  legacy head   {}", hex::encode_upper(report.head.raw));
    println!(
        "  retention     {} direct + {} recursive roots (verified, not persisted)",
        report.retention_direct, report.retention_recursive
    );
    println!("  legacy pin remains in place until recurring retention policy exists");
    Ok(())
}

// ── feel: the mic-array touch sense ────────────────────────────────────────

/// What a touch looked like over the felt window.
#[allow(dead_code)]
struct Felt {
    samples: usize,
    sweeps: usize,  // count of >SWEEP_DEG moves within a ~SWEEP_WIN window
    angle_min: f64, // degrees
    angle_max: f64,
    max_speed: f64,    // deg/s
    head_deflect: f64, // rad, max yaw/roll/pitch range
    speech_ticks: usize,
    signature_json: String,
}

impl Felt {
    fn touched(&self) -> bool {
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

fn report_felt(felt: &Felt) {
    println!(
        "I felt it — your hand tipped my head {:.0} mrad ({:.1}°).",
        felt.head_deflect * 1000.0,
        felt.head_deflect.to_degrees()
    );
    if felt.angle_max - felt.angle_min > 20.0 {
        println!(
            "  and I heard it move across the mics, {:.0}–{:.0}°.",
            felt.angle_min, felt.angle_max
        );
    }
}

fn felt_fragment(
    felt: &Felt,
    note: Option<&str>,
    created: Inline<inlineencodings::NsTAIInterval>,
) -> Fragment {
    let mut fragment = Fragment::empty();
    let pose_h: TextHandle = fragment.put(felt.signature_json.clone());
    let note_h: TextHandle = fragment.put(note.unwrap_or("a touch on the head").to_owned());
    fragment += entity! {
        metadata::tag: &KIND_CAPTURE,
        metadata::created_at: created,
        capture::modality: "touch",
        capture::pose: pose_h,
        capture::note: note_h,
    };
    fragment
}

fn keep_felt(writer: &mut CollectionWriter, felt: &Felt, note: Option<&str>) -> Result<()> {
    let fragment = felt_fragment(felt, note, now_tai());
    let id = fragment.root().expect("capture id");
    writer.publish_fragment(fragment, Fragment::empty())?;
    println!("  kept it — {}", &fmt_id(id)[..12]);
    Ok(())
}

/// Set a new intent, or (with no text) print the latest one. The intent
/// channel is the pile-native seam between perception/reason (gemma) and action
/// (the VLA): writes append a timestamped KIND_INTENT in the body scope; the
/// reader is coordinate-and-cursor — the most recent `metadata::created_at`
/// wins, with the intrinsic entity id breaking equal-time ties. Latest text
/// goes to stdout so a control loop can read it directly.
fn intent_fragment(text: &str, created: Inline<inlineencodings::NsTAIInterval>) -> Fragment {
    let mut fragment = Fragment::empty();
    let text_h: TextHandle = fragment.put(text.to_owned());
    fragment += entity! {
        metadata::tag: &KIND_INTENT,
        metadata::created_at: created,
        intent::text: text_h,
    };
    fragment
}

fn latest_intent(view: &CollectionView) -> Result<Option<(i128, Id, String)>> {
    let mut best: Option<(i128, Id, TextHandle)> = None;
    for (intent_id, handle, created) in find!(
        (i: Id, h: TextHandle, t: Inline<inlineencodings::NsTAIInterval>),
        pattern!(&view.facts, [{
            ?i @
                metadata::tag: KIND_INTENT,
                intent::text: ?h,
                metadata::created_at: ?t,
        }])
    ) {
        let candidate = (interval_key(created), intent_id);
        if best
            .as_ref()
            .is_none_or(|(time, id, _)| candidate > (*time, *id))
        {
            best = Some((candidate.0, candidate.1, handle));
        }
    }

    let Some((time, id, handle)) = best else {
        return Ok(None);
    };
    let text: View<str> = view
        .reader
        .get(handle)
        .map_err(|error| anyhow::anyhow!("read latest intent {id:X}: {error}"))?;
    Ok(Some((time, id, text.to_string())))
}

fn cmd_intent(storage: BodyStorage<'_>, text: Option<&str>) -> Result<()> {
    match text {
        Some(t) => {
            let fragment = intent_fragment(t, now_tai());
            let id = fragment.root().expect("intent id");
            storage.publish(fragment)?;
            println!("  intent {} set: {t}", &fmt_id(id)[..12]);
        }
        None => {
            let view = storage.view()?;
            match latest_intent(&view)? {
                Some((time, _, text)) => {
                    eprintln!("  ({})", format_time(time));
                    println!("{text}");
                }
                None => println!("(no intent yet — gemma hasn't reasoned anything)"),
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_feel(
    mut writer: Option<&mut CollectionWriter>,
    daemon: &str,
    secs: Option<f64>,
    loop_: bool,
    respond: bool,
    note: Option<&str>,
) -> Result<()> {
    if loop_ {
        let session = secs.unwrap_or(300.0);
        let stop = Arc::new(AtomicBool::new(false));
        let requested = Arc::clone(&stop);
        ctrlc::set_handler(move || requested.store(true, Ordering::SeqCst))
            .context("install Ctrl-C handler")?;
        println!("feeling continuously for {session:.0}s — pet the top of my head whenever; Ctrl-C to stop.");
        let start = Instant::now();
        let mut felt_count = 0usize;
        while start.elapsed().as_secs_f64() < session && !stop.load(Ordering::SeqCst) {
            let felt = feel_window(daemon, 3.0);
            if felt.samples > 0 && felt.touched() {
                felt_count += 1;
                report_felt(&felt);
                if respond {
                    if let Err(e) = wiggle(daemon) {
                        eprintln!("  (couldn't wiggle back: {e})");
                    }
                }
                if let Some(writer) = writer.as_deref_mut() {
                    keep_felt(writer, &felt, note)?;
                }
            }
        }
        println!(
            "(stopped{} — felt {felt_count} touch{} this session)",
            if stop.load(Ordering::SeqCst) {
                " by request"
            } else {
                ""
            },
            if felt_count == 1 { "" } else { "es" }
        );
        return Ok(());
    }

    let secs = secs.unwrap_or(12.0);
    println!("feeling for {secs:.0}s — touch the top of my head…");
    let felt = feel_window(daemon, secs);
    if felt.samples == 0 {
        bail!("felt nothing back from the daemon — is the Reachy Mini running?");
    }
    if felt.touched() {
        report_felt(&felt);
        if respond {
            if let Err(e) = wiggle(daemon) {
                eprintln!("  (couldn't wiggle back: {e})");
            }
        }
        if let Some(writer) = writer.as_deref_mut() {
            keep_felt(writer, &felt, note)?;
        }
    } else {
        println!(
            "quiet — I didn't feel a touch. (head still to {:.0} mrad over {} samples.)",
            felt.head_deflect * 1000.0,
            felt.samples
        );
    }
    Ok(())
}

// ── commands ───────────────────────────────────────────────────────────────

fn cmd_pose(daemon: &str) -> Result<()> {
    let state = daemon_get(daemon, "/api/state/full")?;
    let status = daemon_get(daemon, "/api/daemon/status").unwrap_or_default();

    let hp = &state["head_pose"];
    let f = |k: &str| hp[k].as_f64().unwrap_or(f64::NAN);
    println!("head pose:");
    println!(
        "  position   x={:+.4} y={:+.4} z={:+.4} (m)",
        f("x"),
        f("y"),
        f("z")
    );
    println!(
        "  rotation   roll={:+.4} pitch={:+.4} yaw={:+.4} (rad)",
        f("roll"),
        f("pitch"),
        f("yaw")
    );
    if let Some(by) = state["body_yaw"].as_f64() {
        println!("body yaw:    {by:+.4} rad");
    }
    if let Some(ant) = state["antennas_position"].as_array() {
        let vals: Vec<String> = ant
            .iter()
            .map(|v| format!("{:+.4}", v.as_f64().unwrap_or(f64::NAN)))
            .collect();
        println!("antennas:    [{}] rad", vals.join(", "));
    }
    // live mic-array direction-of-arrival (the touch/sound sense)
    if let Ok(d) = daemon_get(daemon, "/api/state/doa") {
        if let Some(a) = d["angle"].as_f64() {
            let sp = if d["speech_detected"].as_bool().unwrap_or(false) {
                " (speech)"
            } else {
                ""
            };
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

fn vision_capture_fragment(
    bytes: Vec<u8>,
    pose_json: String,
    note: Option<&str>,
    width: u64,
    height: u64,
    created: Inline<inlineencodings::NsTAIInterval>,
) -> Fragment {
    let mut fragment = Fragment::empty();
    let frame_h: RawHandle = fragment.put::<blobencodings::RawBytes, _>(bytes);
    let pose_h: TextHandle = fragment.put(pose_json);
    let note_h: Option<TextHandle> = note.map(|text| fragment.put(text.to_owned()));
    let width: Inline<inlineencodings::U256BE> = width.to_inline();
    let height: Inline<inlineencodings::U256BE> = height.to_inline();

    fragment += entity! {
        metadata::tag: &KIND_CAPTURE,
        metadata::created_at: created,
        capture::frame: frame_h,
        capture::mime: "image/png",
        capture::modality: "vision",
        capture::width: width,
        capture::height: height,
        capture::pose: pose_h,
        capture::note?: note_h,
    };
    fragment
}

fn cmd_look(
    storage: BodyStorage<'_>,
    daemon: &str,
    python: &str,
    note: Option<&str>,
) -> Result<()> {
    let tmp = std::env::temp_dir();
    let out_png = tmp.join(format!("body_capture_{}.png", std::process::id()));
    let (w, h) = grab_frame(python, &out_png)?;

    let bytes = std::fs::read(&out_png).with_context(|| format!("read {}", out_png.display()))?;
    let nbytes = bytes.len();
    let _ = std::fs::remove_file(&out_png);

    let pose_json = daemon_get(daemon, "/api/state/full")
        .map(|v| v.to_string())
        .unwrap_or_default();

    let fragment = vision_capture_fragment(bytes, pose_json, note, w, h, now_tai());
    let cap_id = fragment.root().expect("capture has an id");
    storage.publish(fragment)?;

    println!("captured {w}x{h} vision frame ({} KiB)", nbytes / 1024);
    println!("  id   {}", fmt_id(cap_id));
    if let Some(n) = note {
        println!("  note {n}");
    }
    Ok(())
}

fn cmd_list(storage: BodyStorage<'_>) -> Result<()> {
    let view = storage.view()?;
    let mut rows: Vec<(i128, Id, String, String)> = Vec::new();
    for (cid, modality, created) in find!(
        (c: Id, m: String, t: Inline<inlineencodings::NsTAIInterval>),
        pattern!(&view.facts, [{
            ?c @
                metadata::tag: KIND_CAPTURE,
                capture::modality: ?m,
                metadata::created_at: ?t,
        }])
    ) {
        let note = find!(
            (h: Inline<inlineencodings::Handle<blobencodings::LongString>>),
            pattern!(&view.facts, [{ cid @ capture::note: ?h }])
        )
        .next()
        .map(|(handle,)| {
            view.reader
                .get::<View<str>, _>(handle)
                .map(|text| text.to_string())
                .map_err(|error| anyhow::anyhow!("read note for capture {cid:X}: {error}"))
        })
        .transpose()?
        .unwrap_or_default();
        rows.push((interval_key(created), cid, modality, note));
    }
    rows.sort_by(|a, b| (b.0, b.1).cmp(&(a.0, a.1)));
    if rows.is_empty() {
        println!("no captures yet — `body look` keeps a frame, `body feel --keep` a touch.");
        return Ok(());
    }
    for (k, cid, modality, note) in rows {
        let when = format_time(k);
        let suffix = if note.is_empty() {
            String::new()
        } else {
            format!("  — {note}")
        };
        println!("{}  {:<6}  {when}{suffix}", &fmt_id(cid)[..12], modality);
    }
    Ok(())
}

fn cmd_get(storage: BodyStorage<'_>, id: &str, output: Option<&str>) -> Result<()> {
    let view = storage.view()?;
    let needle = id.to_lowercase();
    let cap_id = find!(
        (c: Id),
        pattern!(&view.facts, [{ ?c @ metadata::tag: KIND_CAPTURE }])
    )
    .map(|(c,)| c)
    .find(|c| fmt_id(*c).starts_with(&needle))
    .ok_or_else(|| anyhow::anyhow!("no capture matching '{id}'"))?;

    let h = find!(
        (h: RawHandle),
        pattern!(&view.facts, [{ cap_id @ capture::frame: ?h }])
    )
    .next()
    .map(|(h,)| h)
    .ok_or_else(|| anyhow::anyhow!("capture has no frame payload (a touch capture has no file)"))?;
    let bytes: anybytes::Bytes = view
        .reader
        .get::<anybytes::Bytes, _>(h)
        .map_err(|error| anyhow::anyhow!("read frame for capture {cap_id:X}: {error}"))?;

    if output == Some("@-") {
        use std::io::Write;
        std::io::stdout()
            .write_all(bytes.as_ref())
            .context("write to stdout")?;
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
    let pile = cli.pile;
    let key = cli.key;
    let scope = cli.scope.unwrap_or(DEFAULT_SCOPE_ID);
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
        Some(Command::Feel {
            secs,
            loop_,
            keep,
            respond,
            note,
        }) => {
            if keep {
                let storage = require_storage(pile.as_deref(), key.as_deref(), scope)?;
                let mut writer = storage.writer()?;
                let result = cmd_feel(
                    Some(&mut writer),
                    &daemon,
                    secs,
                    loop_,
                    respond,
                    note.as_deref(),
                );
                writer.finish(result)?;
            } else {
                cmd_feel(None, &daemon, secs, loop_, respond, note.as_deref())?;
            }
        }
        Some(Command::Gesture { name }) => cmd_gesture(&daemon, &name)?,
        Some(Command::Intent { text }) => cmd_intent(
            require_storage(pile.as_deref(), key.as_deref(), scope)?,
            text.as_deref(),
        )?,
        Some(Command::Observe { frame, no_frame }) => {
            cmd_observe(&daemon, &python, frame.as_deref(), no_frame)?
        }
        Some(Command::Act {
            pose,
            duration,
            dt,
            now,
        }) => cmd_act(&daemon, &pose, duration, dt, now)?,
        Some(Command::Look { note }) => cmd_look(
            require_storage(pile.as_deref(), key.as_deref(), scope)?,
            &daemon,
            &python,
            note.as_deref(),
        )?,
        Some(Command::List) => cmd_list(require_storage(pile.as_deref(), key.as_deref(), scope)?)?,
        Some(Command::Get { id, output }) => cmd_get(
            require_storage(pile.as_deref(), key.as_deref(), scope)?,
            &id,
            output.as_deref(),
        )?,
        Some(Command::MigrateLegacy { legacy_branch_id }) => cmd_migrate_legacy(
            require_storage(pile.as_deref(), key.as_deref(), scope)?,
            legacy_branch_id,
        )?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use triblespace::core::collection::discover_collection_records;

    fn at_unix(seconds: f64) -> Inline<inlineencodings::NsTAIInterval> {
        let instant = Epoch::from_unix_seconds(seconds);
        (instant, instant).try_to_inline().unwrap()
    }

    fn fresh_storage(directory: &tempfile::TempDir) -> (PathBuf, PathBuf) {
        let pile = directory.path().join("body.pile");
        let key = directory.path().join("body.key");
        File::create(&pile).unwrap();
        collection_access::initialize_signer(&pile, Some(&key)).unwrap();
        (pile, key)
    }

    struct LegacyFixture {
        pile: PathBuf,
        key: PathBuf,
        scope: Id,
        branch: Id,
        legacy_facts: TribleSet,
    }

    fn test_id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn legacy_fixture(directory: &tempfile::TempDir) -> LegacyFixture {
        let pile_path = directory.path().join("legacy-body.pile");
        let key_path = directory.path().join("collection.key");
        File::create(&pile_path).unwrap();

        let legacy_signer = SigningKey::from_bytes(&[0x35; 32]);
        let pile = collection_access::open_pile_strict(&pile_path).unwrap();
        let mut repository = Repository::new(pile, legacy_signer, Fragment::empty()).unwrap();
        let branch = *repository
            .create_branch(LEGACY_BODY_BRANCH_NAME, None)
            .unwrap();

        let first = intent_fragment("legacy first intent", at_unix(10.0));
        let mut semantic_metadata = Fragment::empty();
        let semantic_text: TextHandle =
            semantic_metadata.put("fixture semantic metadata".to_owned());
        semantic_metadata += entity! { metadata::description: semantic_text };
        let mut first_workspace = repository.pull(branch).unwrap();
        first_workspace.commit_with_metadata(
            first.clone(),
            semantic_metadata,
            "first legacy body commit",
        );
        repository.push(&mut first_workspace).unwrap();

        // Fork from one exact head. Pushing both sides makes Repository append
        // one deterministic contentless merge commit after the three authored
        // leaves; migration must omit only that merge node.
        let mut left = repository.pull(branch).unwrap();
        let mut right = repository.pull(branch).unwrap();
        let left_content = vision_capture_fragment(
            b"legacy png bytes".to_vec(),
            r#"{"head_yaw":0.5}"#.to_owned(),
            Some("legacy glance"),
            320,
            240,
            at_unix(20.0),
        );
        let right_content = intent_fragment("legacy fork intent", at_unix(30.0));
        left.commit(left_content.clone(), "left legacy body commit");
        right.commit(right_content.clone(), "right legacy body commit");
        repository.push(&mut left).unwrap();
        repository.push(&mut right).unwrap();

        let mut legacy_facts = first.into_facts();
        legacy_facts += left_content.into_facts();
        legacy_facts += right_content.into_facts();
        repository.close().unwrap();

        collection_access::initialize_signer(&pile_path, Some(&key_path)).unwrap();
        LegacyFixture {
            pile: pile_path,
            key: key_path,
            scope: test_id(0x71),
            branch,
            legacy_facts,
        }
    }

    fn fixture_storage(fixture: &LegacyFixture) -> BodyStorage<'_> {
        BodyStorage {
            pile: &fixture.pile,
            key: Some(&fixture.key),
            scope: fixture.scope,
        }
    }

    fn pin_head(
        pile_path: &Path,
        branch: Id,
    ) -> Inline<inlineencodings::Handle<blobencodings::SimpleArchive>> {
        let mut pile = collection_access::open_pile_strict(pile_path).unwrap();
        let head = pile.head(branch).unwrap().unwrap();
        pile.close().unwrap();
        head
    }

    fn migrated_commits(fixture: &LegacyFixture) -> (PileReader, Vec<CollectionCommit>) {
        let signer = collection_access::load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let definition = simplearchive_union::definition(fixture.scope);
        let mut pile = collection_access::open_pile_strict(&fixture.pile).unwrap();
        let reader = pile.reader().unwrap();
        pile.close().unwrap();
        let records = discover_collection_records(&reader).unwrap();
        let commits = records
            .commits()
            .iter()
            .filter(|commit| commit.collection() == definition.id())
            .filter(|commit| commit.public_key().raw == signer.verifying_key().to_bytes())
            .cloned()
            .collect();
        (reader, commits)
    }

    #[test]
    fn legacy_migration_omits_merge_and_preserves_facts_attachments_and_signer() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = legacy_fixture(&directory);
        let legacy_pin = pin_head(&fixture.pile, fixture.branch);

        let report = migrate_legacy(fixture_storage(&fixture), None).unwrap();

        assert_eq!(report.branch_id, fixture.branch);
        assert_eq!(report.commits.len(), 3);
        assert_eq!(report.skipped_merges, 1);
        assert_eq!(pin_head(&fixture.pile, fixture.branch), legacy_pin);
        let signer = collection_access::load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let view = collection_access::materialize_scope(
            &fixture.pile,
            fixture.scope,
            &HashSet::from([signer.verifying_key()]),
        )
        .unwrap();
        assert_eq!(view.facts, fixture.legacy_facts);

        let (_, text_handle) = find!(
            (entity: Id, text: TextHandle),
            pattern!(&view.facts, [{ ?entity @ intent::text: ?text }])
        )
        .find(|(_, handle)| {
            view.reader
                .get::<View<str>, _>(*handle)
                .is_ok_and(|text| &*text == "legacy fork intent")
        })
        .unwrap();
        let text: View<str> = view.reader.get(text_handle).unwrap();
        assert_eq!(&*text, "legacy fork intent");

        let frame = find!(
            (frame: RawHandle),
            pattern!(&view.facts, [{ capture::frame: ?frame }])
        )
        .next()
        .unwrap()
        .0;
        let bytes: anybytes::Bytes = view.reader.get(frame).unwrap();
        assert_eq!(bytes.as_ref(), b"legacy png bytes");

        let (_, commits) = migrated_commits(&fixture);
        assert_eq!(commits.len(), 3);
        for commit in commits {
            commit.verify_strict().unwrap();
            assert_eq!(commit.public_key().raw, signer.verifying_key().to_bytes());
        }
    }

    #[test]
    fn legacy_migration_projects_commit_time_message_and_semantic_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = legacy_fixture(&directory);
        migrate_legacy(fixture_storage(&fixture), None).unwrap();

        let (reader, commits) = migrated_commits(&fixture);
        let mut projected = TribleSet::new();
        for commit in commits {
            let facts: TribleSet = reader.get(commit.metadata()).unwrap();
            projected += facts;
        }
        let created: Vec<_> = find!(
            (created: Inline<inlineencodings::NsTAIInterval>),
            pattern!(&projected, [{ metadata::created_at: ?created }])
        )
        .collect();
        assert_eq!(created.len(), 3);

        let descriptions: BTreeSet<String> = find!(
            (description: TextHandle),
            pattern!(&projected, [{ metadata::description: ?description }])
        )
        .map(|(handle,)| reader.get::<View<str>, _>(handle).unwrap().to_string())
        .collect();
        assert!(descriptions.contains("first legacy body commit"));
        assert!(descriptions.contains("left legacy body commit"));
        assert!(descriptions.contains("right legacy body commit"));
        assert!(descriptions.contains("fixture semantic metadata"));
    }

    #[test]
    fn legacy_migration_replay_is_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = legacy_fixture(&directory);
        let first = migrate_legacy(fixture_storage(&fixture), None).unwrap();
        let length = std::fs::metadata(&fixture.pile).unwrap().len();

        let second = migrate_legacy(fixture_storage(&fixture), None).unwrap();

        assert_eq!(first.commits, second.commits);
        assert_eq!(std::fs::metadata(&fixture.pile).unwrap().len(), length);
        assert_eq!(migrated_commits(&fixture).1.len(), 3);
    }

    #[test]
    fn migration_failure_never_changes_the_legacy_pin() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = legacy_fixture(&directory);
        let legacy_pin = pin_head(&fixture.pile, fixture.branch);
        let length = std::fs::metadata(&fixture.pile).unwrap().len();
        let missing_key = directory.path().join("missing.key");
        let storage = BodyStorage {
            pile: &fixture.pile,
            key: Some(&missing_key),
            scope: fixture.scope,
        };

        let error = migrate_legacy(storage, None).unwrap_err();

        assert!(format!("{error:#}").contains("load durable signing key"));
        assert_eq!(pin_head(&fixture.pile, fixture.branch), legacy_pin);
        assert_eq!(std::fs::metadata(&fixture.pile).unwrap().len(), length);
        assert!(migrated_commits(&fixture).1.is_empty());
    }

    #[test]
    fn full_preflight_rejects_a_late_bad_node_before_publication() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = legacy_fixture(&directory);
        let signer = SigningKey::from_bytes(&[0x35; 32]);
        let mut pile = collection_access::open_pile_strict(&fixture.pile).unwrap();
        let old_pin = pile.head(fixture.branch).unwrap().unwrap();
        let reader = pile.reader().unwrap();
        let branch_facts: TribleSet = reader.get(old_pin).unwrap();
        let branch_entity = repo::branch::branch_entity(&branch_facts, fixture.branch).unwrap();
        let name = one_commit_value(&branch_facts, branch_entity, &metadata::name, "branch name")
            .unwrap()
            .unwrap();
        let old_head = one_commit_value(&branch_facts, branch_entity, &repo::head, "branch head")
            .unwrap()
            .unwrap();
        let bad_commit = entity! { repo::parent: old_head }.into_facts().to_blob();
        pile.put::<blobencodings::SimpleArchive, _>(bad_commit.clone())
            .unwrap();
        let bad_branch =
            repo::branch::branch_metadata(&signer, fixture.branch, name, Some(bad_commit))
                .to_blob();
        let bad_pin = pile
            .put::<blobencodings::SimpleArchive, _>(bad_branch)
            .unwrap();
        pile.update(fixture.branch, Some(old_pin), Some(bad_pin))
            .unwrap();
        pile.flush().unwrap();
        pile.close().unwrap();
        let length = std::fs::metadata(&fixture.pile).unwrap().len();

        let error = migrate_legacy(fixture_storage(&fixture), None).unwrap_err();

        assert!(format!("{error:#}").contains("not a canonical merge"));
        assert_eq!(pin_head(&fixture.pile, fixture.branch), bad_pin);
        assert_eq!(std::fs::metadata(&fixture.pile).unwrap().len(), length);
        assert!(migrated_commits(&fixture).1.is_empty());
    }

    #[test]
    fn missing_known_legacy_payload_fails_before_publication() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = legacy_fixture(&directory);
        let missing: TextHandle = Inline::new([0x91; 32]);
        let bad_content = entity! {
            metadata::tag: &KIND_INTENT,
            metadata::created_at: at_unix(40.0),
            intent::text: missing,
        };
        let pile = collection_access::open_pile_strict(&fixture.pile).unwrap();
        let mut repository =
            Repository::new(pile, SigningKey::from_bytes(&[0x35; 32]), Fragment::empty()).unwrap();
        let mut workspace = repository.pull(fixture.branch).unwrap();
        workspace.commit(bad_content, "legacy commit with missing intent payload");
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();
        let legacy_pin = pin_head(&fixture.pile, fixture.branch);
        let length = std::fs::metadata(&fixture.pile).unwrap().len();

        let error = migrate_legacy(fixture_storage(&fixture), None).unwrap_err();

        assert!(format!("{error:#}").contains("strictly read legacy intent::text payload"));
        assert_eq!(pin_head(&fixture.pile, fixture.branch), legacy_pin);
        assert_eq!(std::fs::metadata(&fixture.pile).unwrap().len(), length);
        assert!(migrated_commits(&fixture).1.is_empty());
    }

    #[test]
    fn contentless_legacy_node_must_be_a_parent_only_merge() {
        let subject = ExclusiveId::force(test_id(0x72));
        let first: CommitHandle = Inline::new([0x41; 32]);
        let second: CommitHandle = Inline::new([0x42; 32]);
        let source: CommitHandle = Inline::new([0x43; 32]);
        let mut facts = entity! { &subject @ repo::parent: first }.into_facts();
        facts += entity! { &subject @ repo::parent: second }.into_facts();
        validate_contentless_legacy_merge(&facts, subject.id, source).unwrap();

        facts += entity! { &subject @ metadata::tag: &test_id(0x73) }.into_facts();
        let error = validate_contentless_legacy_merge(&facts, subject.id, source).unwrap_err();
        assert!(format!("{error:#}").contains("not a canonical merge"));
    }

    #[test]
    fn hardware_commands_parse_without_a_pile() {
        let command = Cli::command();
        let pile_argument = command
            .get_arguments()
            .find(|argument| argument.get_id() == "pile")
            .unwrap();
        assert!(!pile_argument.is_required_set());

        let commands = [
            vec!["body", "pose"],
            vec!["body", "feel"],
            vec!["body", "gesture", "center"],
            vec!["body", "wake"],
            vec!["body", "sleep"],
            vec!["body", "observe", "--no-frame"],
            vec!["body", "act", "0,0,0,0,0,0,0,0,0"],
        ];

        for args in commands {
            Cli::try_parse_from(args).unwrap();
        }
    }

    #[test]
    fn equal_time_intents_use_entity_id_as_the_tie_break() {
        let directory = tempfile::tempdir().unwrap();
        let (pile, key) = fresh_storage(&directory);
        let storage = BodyStorage {
            pile: &pile,
            key: Some(&key),
            scope: DEFAULT_SCOPE_ID,
        };
        let created = at_unix(42.0);
        let alpha = intent_fragment("alpha", created);
        let beta = intent_fragment("beta", created);
        let alpha_id = alpha.root().unwrap();
        let beta_id = beta.root().unwrap();

        // Publish the larger id first: this distinguishes the canonical tie
        // break from accidental last-publication-wins behavior.
        let (expected_id, expected_text, first, second) = if alpha_id > beta_id {
            (alpha_id, "alpha", alpha, beta)
        } else {
            (beta_id, "beta", beta, alpha)
        };
        storage.publish(first).unwrap();
        storage.publish(second).unwrap();

        let latest = latest_intent(&storage.view().unwrap()).unwrap().unwrap();
        assert_eq!(latest.0, interval_key(created));
        assert_eq!(latest.1, expected_id);
        assert_eq!(latest.2, expected_text);
    }

    #[test]
    fn vision_capture_owns_and_roundtrips_its_attachments() {
        let directory = tempfile::tempdir().unwrap();
        let (pile, key) = fresh_storage(&directory);
        let storage = BodyStorage {
            pile: &pile,
            key: Some(&key),
            scope: DEFAULT_SCOPE_ID,
        };
        let png = b"not really a png, deliberately storage-only".to_vec();
        let pose = r#"{"head_yaw":0.125}"#;
        let note = "a deliberate glance";
        let fragment = vision_capture_fragment(
            png.clone(),
            pose.to_owned(),
            Some(note),
            640,
            480,
            at_unix(73.0),
        );
        let capture_id = fragment.root().unwrap();
        storage.publish(fragment).unwrap();

        let view = storage.view().unwrap();
        let (frame, pose_handle, note_handle) = find!(
            (f: RawHandle, p: TextHandle, n: TextHandle),
            pattern!(&view.facts, [{ capture_id @
                capture::frame: ?f,
                capture::pose: ?p,
                capture::note: ?n,
            }])
        )
        .next()
        .unwrap();
        let stored_png: anybytes::Bytes = view.reader.get(frame).unwrap();
        let stored_pose: View<str> = view.reader.get(pose_handle).unwrap();
        let stored_note: View<str> = view.reader.get(note_handle).unwrap();

        assert_eq!(stored_png.as_ref(), png.as_slice());
        assert_eq!(&*stored_pose, pose);
        assert_eq!(&*stored_note, note);
    }

    #[test]
    fn felt_capture_owns_and_roundtrips_its_text_attachments() {
        let directory = tempfile::tempdir().unwrap();
        let (pile, key) = fresh_storage(&directory);
        let storage = BodyStorage {
            pile: &pile,
            key: Some(&key),
            scope: DEFAULT_SCOPE_ID,
        };
        let felt = Felt {
            samples: 4,
            sweeps: 1,
            angle_min: -12.0,
            angle_max: 19.0,
            max_speed: 80.0,
            head_deflect: 0.03,
            speech_ticks: 0,
            signature_json: r#"{"modality":"touch","samples":4}"#.to_owned(),
        };
        let fragment = felt_fragment(&felt, None, at_unix(81.0));
        let capture_id = fragment.root().unwrap();
        storage.publish(fragment).unwrap();

        let view = storage.view().unwrap();
        let (pose_handle, note_handle) = find!(
            (p: TextHandle, n: TextHandle),
            pattern!(&view.facts, [{ capture_id @
                capture::pose: ?p,
                capture::note: ?n,
            }])
        )
        .next()
        .unwrap();
        let stored_pose: View<str> = view.reader.get(pose_handle).unwrap();
        let stored_note: View<str> = view.reader.get(note_handle).unwrap();

        assert_eq!(&*stored_pose, felt.signature_json);
        assert_eq!(&*stored_note, "a touch on the head");
    }

    #[test]
    fn missing_referenced_intent_blob_is_a_hard_error() {
        let directory = tempfile::tempdir().unwrap();
        let (pile, key) = fresh_storage(&directory);
        let storage = BodyStorage {
            pile: &pile,
            key: Some(&key),
            scope: DEFAULT_SCOPE_ID,
        };
        let missing = TextHandle::new([0xA5; 32]);
        let fragment = entity! {
            metadata::tag: &KIND_INTENT,
            metadata::created_at: at_unix(99.0),
            intent::text: missing,
        };
        storage.publish(fragment).unwrap();

        let error = latest_intent(&storage.view().unwrap()).unwrap_err();
        assert!(
            error.to_string().contains("read latest intent"),
            "unexpected error: {error:#}"
        );
    }
}
