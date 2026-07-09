//! `voice` — Liora's voice organ: speech out, on two channels, with a
//! pile-backed routing policy that picks which audio device each channel plays
//! through.
//!
//! Extracted from `body` (2026-06-30). The body is the physical Reachy loop
//! (pose/look/feel/act); the voice is its own organ — synthesis (Qwen3-TTS via
//! mary, cloning the voice grown from "No No, No Yes") plus output routing.
//! Utterances and the routing config live on the pile's `voice` branch.
//!
//! Two channels, each a hard contract, not a soft preference:
//!   - `voice say <text>`   — the PRIVATE channel: in-ear / headphone only. If no
//!     private device is connected (or can't be safely targeted) it does NOT play
//!     aloud — it prints the text instead. There is NO code path that lets a
//!     `say` utterance reach a room speaker (see `route_say`).
//!   - `voice shout <text>` — the PUBLIC channel: broadcast freely (Reachy
//!     speaker → room → laptop), audible by design.
//!
//! Routing is an ORDERED device-preference list per channel, stored in the pile
//! (`KIND_ROUTE` entities), edited with `voice route set`. At speak-time the
//! faculty reads the preferences, intersects with the actually-connected
//! devices, and — for `say` — re-checks each candidate is a PRIVATE device
//! before it ever plays. The pile list is advisory ordering; the privacy
//! guarantee is in this code, so no misconfiguration can leak a private
//! utterance into a room.
//!
//! Synthesis (Qwen3-TTS via mary's Burn/Metal pipeline, weights zero-copy
//! mmap-aliased from a durable standalone pile) is gated behind the heavy
//! `voice` feature, mirroring `imagine`; the default build compiles a bail
//! stub so the rest of the faculty suite stays light. There is ONE generation
//! path — `mary::speak::synthesize_stream`, a live PCM-chunk iterator — and
//! the channels differ only by SINK: local devices stream the chunks into
//! `ffplay` as they are synthesized (first audio in seconds; afplay batch when
//! ffplay is absent), while the Reachy speaker drains the same stream to a
//! whole file (its daemon media API is upload+play; daemon-side streaming is a
//! noted follow-up).
//!
//! macOS device targeting: `afplay`/`ffplay` play to the *current default
//! output device* and have no device flag. True per-device targeting needs
//! `SwitchAudioSource` (brew: switchaudio-osx) to switch the default output
//! around playback. When it's present we use it; when it's absent we degrade
//! SAFELY: `say` plays only if the current default output is *itself* a private
//! device (otherwise text); `shout` plays through the default output. The
//! say-privacy invariant holds in both modes.

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use faculties::schemas::voice::{
    CHANNEL_SAY, CHANNEL_SHOUT, KIND_ROUTE, KIND_UTTERANCE, VOICE_BRANCH_NAME, route, utterance,
};
use hifitime::Epoch;
use hifitime::efmt::Formatter;
use hifitime::efmt::consts::ISO8601;
use rand_core::OsRng;
use std::path::{Path, PathBuf};
use std::process::Command as PCommand;
use triblespace::core::metadata;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::prelude::*;

type RawHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;
type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
type U256 = Inline<inlineencodings::U256BE>;

const DEFAULT_DAEMON: &str = "http://localhost:8000";

// Qwen3-TTS voice assets — used by the in-process `mary::speak` call (the
// `voice` feature). The voice was grown from "No No, No Yes" (F5 remains in
// mary as the voice-origin lineage); every utterance clones the v2 reference
// kit: an 11.46 s clean-boundary clip (24 kHz render of `ref_liora_v2.wav`),
// its EXACT transcript, and the clip's codec frames. Weights load from a
// durable standalone pile; `QWEN3TTS_PILE` overrides the path.
#[cfg(feature = "voice")]
const QWEN3TTS_PILE: &str = "/Users/jp/Desktop/chatbot/liora/models/qwen3tts.pile";
#[cfg(feature = "voice")]
const REF_WAV: &str = "/Users/jp/Desktop/chatbot/liora/ref_liora_v2_24k.wav";
#[cfg(feature = "voice")]
const REF_TXT_PATH: &str = "/Users/jp/Desktop/chatbot/liora/ref_liora_v2.txt";
#[cfg(feature = "voice")]
const REF_CODE: &str = "/Users/jp/Desktop/chatbot/liora/ref_liora_v2_code.npy";

// Default routing policy, used when the pile holds no `route set` for a channel.
// `say` lists ONLY private devices (the classifier rejects anything else anyway);
// `shout` is the public broadcast ladder.
const DEFAULT_SAY_DEVICES: &[&str] = &["AirPods Max", "AirPods Pro", "AirPods", "Headphones"];
const DEFAULT_SHOUT_DEVICES: &[&str] =
    &["Reachy Mini Audio", "Studio Display Speakers", "MacBook Pro Speakers"];

// ── CLI ──────────────────────────────────────────────────────────────────
#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "voice",
    about = "Liora's voice: synthesis + privacy-aware output routing, on two channels."
)]
struct Cli {
    /// Path to the pile file
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Branch id (hex). Overrides name-based lookup.
    #[arg(long)]
    branch_id: Option<String>,
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
    /// voice branch.
    Say {
        /// What to say.
        text: String,
        /// Resolve routing and report the target (or text-fallback) WITHOUT
        /// synthesizing or playing — for checking the policy on a busy GPU.
        #[arg(long)]
        dry_run: bool,
    },
    /// Speak ALOUD on the PUBLIC channel — Reachy speaker → room → laptop.
    /// Broadcasting is the point; falls back to any audible device. Recorded on
    /// the voice branch.
    Shout {
        /// What to shout.
        text: String,
        /// Resolve routing and report the target WITHOUT synthesizing/playing.
        #[arg(long)]
        dry_run: bool,
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
    /// List the connected audio output devices and their privacy class. The
    /// raw input to routing — a quick way to see what `say`/`shout` can target.
    Devices,
}

// ── time / id helpers (mirrors body/headspace) ─────────────────────────────

fn now_tai() -> Inline<inlineencodings::NsTAIInterval> {
    let now = Epoch::now().unwrap_or(Epoch::from_unix_seconds(0.0));
    (now, now).try_to_inline().expect("valid TAI interval")
}

fn interval_key(interval: Inline<inlineencodings::NsTAIInterval>) -> i128 {
    let (lower, _): (Epoch, Epoch) = interval.try_from_inline().expect("valid TAI interval");
    lower.to_tai_duration().total_nanoseconds()
}

#[allow(dead_code)]
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

fn u256be_to_u64(value: U256) -> u64 {
    let raw = value.raw;
    if raw[..24].iter().any(|b| *b != 0) {
        return u64::MAX;
    }
    let bytes: [u8; 8] = raw[24..32].try_into().unwrap_or([0xFF; 8]);
    u64::from_be_bytes(bytes)
}

fn http() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("build http client")
}

// ── audio device detection + classification ────────────────────────────────

/// What a device means for the privacy contract.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DeviceClass {
    /// In-ear / headphone — a PRIVATE listening device. The only class `say` may
    /// ever play through.
    Private,
    /// The Reachy Mini's own speaker — a public, in-the-room device (NOT
    /// private), reachable through the daemon.
    Reachy,
    /// Any other output: laptop / display / room speakers. Public, audible.
    Speaker,
}

impl DeviceClass {
    fn label(self) -> &'static str {
        match self {
            DeviceClass::Private => "private",
            DeviceClass::Reachy => "reachy",
            DeviceClass::Speaker => "speaker",
        }
    }
}

/// Classify a device by its name. This is the load-bearing privacy gate: only
/// names that read as personal listening hardware return `Private`. Anything not
/// recognised as private is treated as public — fail-closed, never fail-open.
fn classify(name: &str) -> DeviceClass {
    let n = name.to_lowercase();
    // Room-speaker markers beat brand hints: a "Beats Pill" is a speaker even
    // though "beats" reads as headphone-brand. Checked FIRST so a brand
    // substring can never launder a speaker into Private (fail-closed).
    const SPEAKER_MARKERS: &[&str] = &["pill", "speaker", "soundlink", "sonos", "homepod"];
    if SPEAKER_MARKERS.iter().any(|h| n.contains(h)) {
        return DeviceClass::Speaker;
    }
    const PRIVATE_HINTS: &[&str] = &[
        "airpods", "headphone", "headset", "earbud", "earphone", "earpod", "ear pod",
        "in-ear", "beats", "buds", " wf-", " wh-", "powerbeats",
    ];
    if PRIVATE_HINTS.iter().any(|h| n.contains(h)) {
        return DeviceClass::Private;
    }
    if n.contains("reachy") {
        return DeviceClass::Reachy;
    }
    DeviceClass::Speaker
}

#[derive(Clone, Debug)]
struct AudioDevice {
    name: String,
    is_default_output: bool,
}

impl AudioDevice {
    fn class(&self) -> DeviceClass {
        classify(&self.name)
    }
}

/// Enumerate connected audio OUTPUT devices via `system_profiler`. Output
/// devices carry a `coreaudio_device_output` channel count; the current default
/// output is flagged `coreaudio_default_audio_output_device == "spaudio_yes"`.
fn detect_output_devices() -> Result<Vec<AudioDevice>> {
    let out = PCommand::new("system_profiler")
        .args(["SPAudioDataType", "-json"])
        .output()
        .context("run system_profiler SPAudioDataType -json")?;
    if !out.status.success() {
        bail!(
            "system_profiler failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).context("parse system_profiler JSON")?;
    let items = v["SPAudioDataType"][0]["_items"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut devices = Vec::new();
    for item in items {
        // Only output-capable devices matter for routing.
        if item.get("coreaudio_device_output").is_none() {
            continue;
        }
        let name = item["_name"].as_str().unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }
        let is_default_output =
            item.get("coreaudio_default_audio_output_device").and_then(|x| x.as_str())
                == Some("spaudio_yes");
        devices.push(AudioDevice {
            name,
            is_default_output,
        });
    }
    Ok(devices)
}

/// `SwitchAudioSource` (brew: switchaudio-osx), if installed — the only reliable
/// way to target a SPECIFIC output device on macOS. `None` ⇒ degrade safely.
fn switch_audio_bin() -> Option<PathBuf> {
    for p in [
        "/opt/homebrew/bin/SwitchAudioSource",
        "/usr/local/bin/SwitchAudioSource",
    ] {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    // Fall back to PATH lookup.
    let ok = PCommand::new("SwitchAudioSource")
        .arg("-c")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    ok.then(|| PathBuf::from("SwitchAudioSource"))
}

/// First connected device whose name contains `pat` (case-insensitive).
fn connected_match<'a>(pat: &str, devices: &'a [AudioDevice]) -> Option<&'a AudioDevice> {
    let needle = pat.to_lowercase();
    devices.iter().find(|d| d.name.to_lowercase().contains(&needle))
}

// ── playback primitives ────────────────────────────────────────────────────

#[cfg(feature = "voice")]
fn afplay(wav: &Path) -> Result<()> {
    let st = PCommand::new("afplay").arg(wav).status().context("afplay")?;
    if !st.success() {
        bail!("afplay exited with failure");
    }
    Ok(())
}

/// Get the current default output device name (for save/restore around a switch).
#[cfg(feature = "voice")]
fn current_default_output(sw: &Path) -> Option<String> {
    let out = PCommand::new(sw).args(["-c", "-t", "output"]).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(feature = "voice")]
fn set_default_output(sw: &Path, name: &str) -> Result<()> {
    let st = PCommand::new(sw)
        .args(["-t", "output", "-s", name])
        .status()
        .with_context(|| format!("SwitchAudioSource -s {name}"))?;
    if !st.success() {
        bail!("SwitchAudioSource failed to select '{name}'");
    }
    Ok(())
}

/// Upload `wav` to the Reachy daemon and play it through the robot's speaker.
#[cfg(feature = "voice")]
fn play_on_reachy(daemon: &str, wav: &Path) -> Result<()> {
    let bytes = std::fs::read(wav)?;
    let fname = wav.file_name().unwrap().to_string_lossy().to_string();
    let part = reqwest::blocking::multipart::Part::bytes(bytes)
        .file_name(fname.clone())
        .mime_str("audio/wav")?;
    let form = reqwest::blocking::multipart::Form::new().part("file", part);
    let resp = http()
        .post(format!("{daemon}/api/media/sounds/upload"))
        .multipart(form)
        .send()
        .context("upload to Reachy daemon")?;
    if !resp.status().is_success() {
        bail!("Reachy upload failed: {}", resp.text().unwrap_or_default());
    }
    let resp = http()
        .post(format!("{daemon}/api/media/play_sound"))
        .json(&serde_json::json!({ "file": fname }))
        .send()
        .context("Reachy play_sound")?;
    if !resp.status().is_success() {
        bail!("Reachy play_sound failed: {}", resp.text().unwrap_or_default());
    }
    Ok(())
}

fn reachy_reachable(daemon: &str) -> bool {
    http()
        .get(format!("{daemon}/api/daemon/status"))
        .send()
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

// ── routing: the heart ──────────────────────────────────────────────────────

/// The outcome of resolving a channel's routing against the live devices.
enum Routed {
    /// Play through the Reachy robot speaker (daemon).
    Reachy,
    /// Play on a specific device via SwitchAudioSource targeting.
    Targeted(String),
    /// Play through the current default output device (plain afplay).
    Default(String),
    /// Do NOT play — print the text instead (the `say` private fallback).
    Text(String),
}

impl Routed {
    fn describe(&self) -> String {
        match self {
            Routed::Reachy => "Reachy speaker (daemon)".to_string(),
            Routed::Targeted(d) => format!("{d} (SwitchAudioSource-targeted)"),
            Routed::Default(d) => format!("{d} (default output)"),
            Routed::Text(why) => format!("TEXT fallback — {why}"),
        }
    }
}

/// Resolve the PRIVATE `say` channel. This function bakes in the invariant:
/// every branch that returns a playing `Routed` has proven the target is a
/// PRIVATE device. The only non-private outcome is `Routed::Text` (silent,
/// on-screen). There is deliberately NO branch that plays through a speaker.
fn route_say(prefs: &[String], devices: &[AudioDevice], sw: Option<&Path>) -> Routed {
    match sw {
        // True targeting available: pick the highest-priority CONNECTED PRIVATE
        // device from the policy and target it.
        Some(_) => {
            for pat in prefs {
                if let Some(dev) = connected_match(pat, devices) {
                    if dev.class() == DeviceClass::Private {
                        return Routed::Targeted(dev.name.clone());
                    }
                    // matched a non-private device: skip it — never play here.
                }
            }
            Routed::Text("no connected private (in-ear/headphone) device".into())
        }
        // No targeting tool: afplay can only reach the CURRENT DEFAULT OUTPUT.
        // So we may play ONLY if that default is itself a private device that the
        // policy allows. If the default is a speaker/Reachy, we must NOT play.
        None => {
            let Some(default) = devices.iter().find(|d| d.is_default_output) else {
                return Routed::Text("no default output device".into());
            };
            if default.class() != DeviceClass::Private {
                return Routed::Text(format!(
                    "default output '{}' is {} (no SwitchAudioSource to redirect to a private device)",
                    default.name,
                    default.class().label()
                ));
            }
            // Default IS private; honor the policy — only if it matches a say pref.
            let allowed = prefs
                .iter()
                .any(|p| default.name.to_lowercase().contains(&p.to_lowercase()));
            if !allowed {
                return Routed::Text(format!(
                    "default output '{}' is private but not in the say policy",
                    default.name
                ));
            }
            Routed::Default(default.name.clone())
        }
    }
}

/// Resolve the PUBLIC `shout` channel — broadcasting is the point, so it falls
/// back freely to any audible device.
fn route_shout(
    prefs: &[String],
    devices: &[AudioDevice],
    sw: Option<&Path>,
    daemon_up: bool,
) -> Routed {
    // Walk the policy; take the first connected match.
    for pat in prefs {
        if let Some(dev) = connected_match(pat, devices) {
            return match dev.class() {
                DeviceClass::Reachy if daemon_up => Routed::Reachy,
                // Reachy listed but daemon down → keep looking down the ladder.
                DeviceClass::Reachy => continue,
                _ if sw.is_some() => Routed::Targeted(dev.name.clone()),
                _ => Routed::Default(dev.name.clone()),
            };
        }
    }
    // Nothing in the policy is connected: just use the default output (audible).
    if let Some(default) = devices.iter().find(|d| d.is_default_output) {
        return Routed::Default(default.name.clone());
    }
    Routed::Text("no audible output device connected".into())
}

// ── pile plumbing ───────────────────────────────────────────────────────────

fn open_repo(path: &Path) -> Result<Repository<Pile>> {
    let mut pile = Pile::open(path)
        .map_err(|e| anyhow::anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.refresh() {
        let _ = pile.close();
        return Err(match err {
            triblespace::core::repo::pile::ReadError::CorruptPile { valid_length } => anyhow::anyhow!(
                "pile corrupt at byte {valid_length}: refusing to auto-repair (a stale binary \
                 could truncate newer data). If, and only if, the tail is a genuinely torn write, truncate it explicitly (DESTRUCTIVE) with: trible pile amputate {}",
                path.display()
            ),
            other => anyhow::anyhow!("refresh pile {}: {other:?}", path.display()),
        });
    }
    let signing_key = SigningKey::generate(&mut OsRng);
    Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|err| anyhow::anyhow!("create repository: {err:?}"))
}

fn with_voice<T>(
    pile: &Path,
    explicit_branch: Option<&str>,
    f: impl FnOnce(&mut Repository<Pile>, &mut Workspace<Pile>) -> Result<T>,
) -> Result<T> {
    let mut repo = open_repo(pile)?;
    let branch_id = if let Some(hex) = explicit_branch {
        Id::from_hex(hex.trim()).ok_or_else(|| anyhow::anyhow!("invalid branch id '{hex}'"))?
    } else {
        repo.ensure_branch(VOICE_BRANCH_NAME, None)
            .map_err(|e| anyhow::anyhow!("ensure voice branch: {e:?}"))?
    };
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow::anyhow!("pull voice workspace: {e:?}"))?;
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

/// Read a channel's routing policy from the pile. Each `voice route set` writes
/// a whole GENERATION of entries sharing one `metadata::updated_at`; the policy
/// is the LATEST generation only (a set replaces, it doesn't accumulate —
/// coordinate-and-cursor on the set timestamp keeps the pile append-only while
/// the read sees one current policy). Falls back to the baked-in defaults when
/// the pile holds no policy for the channel.
fn load_route(ws: &mut Workspace<Pile>, channel: &str) -> Result<Vec<String>> {
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    // (set-generation key, priority, device) for this channel.
    let mut rows: Vec<(i128, u64, String)> = Vec::new();
    for (dev, prio, updated) in find!(
        (d: String, p: U256, u: Inline<inlineencodings::NsTAIInterval>),
        pattern!(&space, [{
            _?e @
                metadata::tag: KIND_ROUTE,
                route::channel: channel.to_string(),
                route::device: ?d,
                route::priority: ?p,
                metadata::updated_at: ?u,
        }])
    ) {
        rows.push((interval_key(updated), u256be_to_u64(prio), dev));
    }
    let Some(latest_gen) = rows.iter().map(|(k, _, _)| *k).max() else {
        let defaults = match channel {
            CHANNEL_SAY => DEFAULT_SAY_DEVICES,
            _ => DEFAULT_SHOUT_DEVICES,
        };
        return Ok(defaults.iter().map(|s| s.to_string()).collect());
    };
    let mut entries: Vec<(u64, String)> = rows
        .into_iter()
        .filter(|(k, _, _)| *k == latest_gen)
        .map(|(_, p, d)| (p, d))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    Ok(entries.into_iter().map(|(_, d)| d).collect())
}

fn store_route(
    repo: &mut Repository<Pile>,
    ws: &mut Workspace<Pile>,
    channel: &str,
    devices: &[String],
) -> Result<()> {
    // One timestamp for the whole set — the generation marker `load_route` keys
    // on, so this set wholly replaces the previous policy for the channel.
    let set_time = now_tai();
    for (i, dev) in devices.iter().enumerate() {
        let prio: U256 = (i as u64).to_inline();
        let frag = entity! {
            metadata::tag: &KIND_ROUTE,
            metadata::updated_at: set_time,
            route::channel: channel,
            route::device: dev.as_str(),
            route::priority: prio,
        };
        ws.commit(frag, "voice route set");
    }
    repo.push(ws).map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
    Ok(())
}

/// Record an utterance on the voice branch. The fact falls out of speaking —
/// logging is a side effect of the act, not a separate obligation.
/// `commit_msg` is the ledger line: "voice spoke" on the happy path, an
/// explicit failure marker when there was no trustworthy audio to attach
/// (synthesis died mid-stream) — the words never vanish from the pile.
fn log_utterance(
    repo: &mut Repository<Pile>,
    ws: &mut Workspace<Pile>,
    channel: &str,
    text: &str,
    wav: Option<&Path>,
    commit_msg: &str,
) -> Result<()> {
    let text_h: TextHandle = ws.put(text.to_string());
    let audio_h: Option<RawHandle> = match wav {
        Some(p) => {
            let bytes = std::fs::read(p).with_context(|| format!("read {}", p.display()))?;
            Some(ws.put::<blobencodings::RawBytes, _>(bytes))
        }
        None => None,
    };
    let frag = entity! {
        metadata::tag: &KIND_UTTERANCE,
        metadata::created_at: now_tai(),
        utterance::channel: channel,
        utterance::text: text_h,
        utterance::audio?: audio_h,
        utterance::mime?: wav.map(|_| "audio/wav"),
    };
    let id = frag.root().expect("utterance id");
    ws.commit(frag, commit_msg);
    repo.push(ws).map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
    println!("  logged utterance {} [{channel}]", &fmt_id(id)[..12]);
    Ok(())
}

// ── synthesis + sinks (feature-gated, mirrors imagine) ─────────────────────
//
// ONE generation path, TWO kinds of sink. Every playing channel synthesizes
// through `mary::speak::synthesize_stream` — a live iterator of 24 kHz PCM
// chunks (frames hit the codec the moment they are sampled). The sinks differ
// only in how they drain it:
//   - STREAMING sink (say/shout to a local device): chunks are piped into
//     `ffplay` (raw s16le on stdin, playing to the DEFAULT output — the
//     streaming sibling of afplay, same device semantics, so the routing and
//     privacy model are untouched; SwitchAudioSource still does the
//     targeting). First audio lands seconds after the call, not after the
//     whole utterance. No ffplay ⇒ degrade to collect + afplay (batch).
//   - BATCH sink (shout via the Reachy robot): the daemon's media API accepts
//     whole files only (upload + play_sound), so the SAME stream is drained
//     to a WAV first. Streaming into the daemon is a noted follow-up on the
//     daemon side; this lane does not touch it.
// Every sink also accumulates the full utterance, which `cmd_speak` logs on
// the voice branch after completion — logging is unchanged.

/// What `speak_and_play` accomplished. An `Err` from it means SYNTHESIS
/// failed — `out` was NOT written and there is no trustworthy audio (the
/// caller logs the words text-only, with a failure marker). `Ok` means the
/// complete utterance was synthesized and written to `out`.
// Without the `voice` feature the stub `speak_and_play` only ever bails, so
// neither variant is constructed — the type still shapes `cmd_speak`'s match.
#[cfg_attr(not(feature = "voice"), allow(dead_code))]
enum Spoken {
    /// Synthesized, written to `out`, and played (or drained for the Reachy
    /// upload) successfully.
    Played,
    /// The full utterance was synthesized and written to `out`, but playback
    /// failed — the caller logs the audio, then surfaces this error.
    PlaybackFailed(anyhow::Error),
}

/// Synthesize `text` (streaming) and play it through the resolved route,
/// writing the COMPLETE utterance to `out` for the log. Never called for the
/// `Routed::Text` fallback (the caller short-circuits it — no GPU work for a
/// silent utterance). Returns after playback settles; see [`Spoken`] for the
/// synthesis-failure / playback-failure split.
#[cfg(feature = "voice")]
fn speak_and_play(
    routed: &Routed,
    daemon: &str,
    sw: Option<&Path>,
    channel: &str,
    text: &str,
    out: &Path,
) -> Result<Spoken> {
    let sr = mary::speak::SpeakStream::SAMPLE_RATE;
    let pile = std::env::var("QWEN3TTS_PILE").unwrap_or_else(|_| QWEN3TTS_PILE.to_string());
    let ref_text = std::fs::read_to_string(REF_TXT_PATH)
        .with_context(|| format!("read reference transcript {REF_TXT_PATH}"))?;
    let t_call = std::time::Instant::now();
    let mut stream = mary::speak::synthesize_stream(
        Path::new(&pile),
        Path::new(REF_WAV),
        ref_text.trim(),
        Path::new(REF_CODE),
        text,
    )?;

    let mut samples: Vec<f32> = Vec::new();
    let played: Result<()> = match routed {
        // Whole-file sink: drain the same stream, upload after.
        Routed::Reachy => {
            for chunk in stream.by_ref() {
                samples.extend_from_slice(&chunk);
            }
            Ok(())
        }
        Routed::Targeted(device) | Routed::Default(device) => {
            // Defense in depth: on the private channel the router only emits
            // private devices; re-assert before any sound (the streaming
            // sibling of `play_private_targeted`'s guard).
            if channel == CHANNEL_SAY && classify(device) != DeviceClass::Private {
                bail!(
                    "refusing to play a private utterance on non-private device '{device}' \
                     (privacy invariant)"
                );
            }
            // Targeted ⇒ switch the default output to the device around
            // playback (ffplay and afplay both play to the default output).
            let prior = match routed {
                Routed::Targeted(_) => {
                    let sw = sw.context("SwitchAudioSource required for targeted playback")?;
                    let prior = current_default_output(sw);
                    set_default_output(sw, device)?;
                    prior
                }
                _ => None,
            };
            let result = stream_to_default_output(&mut stream, &mut samples, t_call, device, sr);
            if let (Routed::Targeted(_), Some(sw), Some(prev)) = (routed, sw, prior.as_deref()) {
                let _ = set_default_output(sw, prev); // best-effort restore
            }
            result
        }
        Routed::Text(_) => Ok(()), // handled by the caller; nothing to play
    };

    // Settle generation and persist the FULL utterance for the log — every
    // sink, even after a playback hiccup (drain first: error paths may have
    // stopped consuming early).
    for chunk in stream.by_ref() {
        samples.extend_from_slice(&chunk);
    }
    // Synthesis failure = nothing trustworthy to attach as audio: `out` stays
    // unwritten and the error propagates — the CALLER still logs the words
    // (text + failure marker), so the utterance never vanishes from the pile.
    stream.finish()?;
    mary::models::f5::wav::write_pcm16_mono(out, &samples, sr);
    if let Err(e) = played {
        return Ok(Spoken::PlaybackFailed(e));
    }
    if matches!(routed, Routed::Reachy) {
        if let Err(e) = play_on_reachy(daemon, out) {
            return Ok(Spoken::PlaybackFailed(e));
        }
    }
    Ok(Spoken::Played)
}

/// Drain `stream` into the current DEFAULT output via `ffplay` (raw s16le PCM
/// on stdin) — chunks play as they are synthesized; prints the measured TTFA
/// (call → first chunk handed to the audio pipe). Without ffplay, degrades to
/// collect + `afplay` (batch, same generation path).
#[cfg(feature = "voice")]
fn stream_to_default_output(
    stream: &mut mary::speak::SpeakStream,
    samples: &mut Vec<f32>,
    t_call: std::time::Instant,
    device: &str,
    sr: u32,
) -> Result<()> {
    use std::io::Write;
    use std::process::Stdio;

    let spawned = PCommand::new("ffplay")
        .args(["-loglevel", "error", "-nodisp", "-autoexit", "-f", "s16le", "-ar"])
        .arg(sr.to_string())
        .args(["-ch_layout", "mono", "-i", "pipe:0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    match spawned {
        Ok(mut child) => {
            let mut stdin = child.stdin.take().context("ffplay stdin")?;
            let mut first = true;
            let mut broken = false;
            for chunk in stream.by_ref() {
                samples.extend_from_slice(&chunk);
                if broken {
                    continue; // keep draining for the log
                }
                let bytes: Vec<u8> = chunk
                    .iter()
                    .flat_map(|&s| (((s.clamp(-1.0, 1.0)) * 32767.0) as i16).to_le_bytes())
                    .collect();
                if stdin.write_all(&bytes).is_err() {
                    broken = true;
                    continue;
                }
                if first {
                    println!(
                        "  [stream] TTFA {:.2}s → {device}",
                        t_call.elapsed().as_secs_f32()
                    );
                    first = false;
                }
            }
            drop(stdin); // EOF ⇒ ffplay drains its buffer and -autoexit's
            let status = child.wait().context("wait for ffplay")?;
            if broken || !status.success() {
                bail!("streaming playback (ffplay) failed");
            }
            Ok(())
        }
        Err(_) => {
            // No ffplay: batch over the same stream. (brew install ffmpeg
            // enables streaming playback.)
            for chunk in stream.by_ref() {
                samples.extend_from_slice(&chunk);
            }
            let tmp =
                std::env::temp_dir().join(format!("liora_voice_batch_{}.wav", std::process::id()));
            mary::models::f5::wav::write_pcm16_mono(&tmp, samples, sr);
            println!("  [stream] ffplay not found — played whole utterance via afplay");
            let r = afplay(&tmp);
            let _ = std::fs::remove_file(&tmp);
            r
        }
    }
}

#[cfg(not(feature = "voice"))]
fn speak_and_play(
    _routed: &Routed,
    _daemon: &str,
    _sw: Option<&Path>,
    _channel: &str,
    _text: &str,
    _out: &Path,
) -> Result<Spoken> {
    bail!(
        "voice was built without the `voice` feature — rebuild with \
         `cargo build --release --features voice --bin voice` (pulls mary's \
         Qwen3-TTS Burn voice pipeline). Routing (`voice route`/`voice devices`) \
         and the text-fallback path work without it."
    );
}

// ── commands ────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn cmd_speak(
    repo: &mut Repository<Pile>,
    ws: &mut Workspace<Pile>,
    daemon: &str,
    channel: &str,
    text: &str,
    dry_run: bool,
) -> Result<()> {
    let devices = detect_output_devices()?;
    let sw = switch_audio_bin();
    let prefs = load_route(ws, channel)?;

    let routed = if channel == CHANNEL_SAY {
        route_say(&prefs, &devices, sw.as_deref())
    } else {
        route_shout(&prefs, &devices, sw.as_deref(), reachy_reachable(daemon))
    };

    println!("[{channel}] → {}", routed.describe());

    if dry_run {
        return Ok(());
    }

    // For the private text-fallback we do NOT synthesize at all — nothing to
    // play, and no GPU work for a silent on-screen utterance.
    if let Routed::Text(_) = routed {
        // Print the words (private, silent), log without audio.
        println!("{text}");
        return log_utterance(repo, ws, channel, text, None, "voice spoke");
    }

    // ONE generation path (streaming synthesis), sink chosen by the route —
    // see the synthesis section. `out` receives the complete utterance; the
    // path is minted FRESH (unique name + O_EXCL) so a stale WAV left by a
    // dead run can never be logged under this utterance's text.
    let out = unique_voice_tmp()?;
    match speak_and_play(&routed, daemon, sw.as_deref(), channel, text, &out) {
        // Synthesis failed mid-stream: no trustworthy audio, but the words
        // still happened — log them text-only with a failure marker so the
        // utterance survives on the pile, then surface the error.
        Err(synth_err) => {
            let _ = std::fs::remove_file(&out);
            eprintln!("synthesis failed — logging the utterance text-only: {synth_err:#}");
            if let Err(log_err) = log_utterance(
                repo,
                ws,
                channel,
                text,
                None,
                "voice spoke (synthesis FAILED mid-stream; text-only, no audio)",
            ) {
                eprintln!("warning: could not log the failed utterance: {log_err:#}");
            }
            Err(synth_err)
        }
        Ok(outcome) => {
            // Log the utterance with its audio regardless of a playback
            // hiccup, so the fact survives; surface a playback error after.
            let log = log_utterance(repo, ws, channel, text, Some(&out), "voice spoke");
            let _ = std::fs::remove_file(&out);
            if let Spoken::PlaybackFailed(play_err) = outcome {
                if let Err(log_err) = &log {
                    eprintln!("warning: could not log the utterance: {log_err:#}");
                }
                return Err(play_err);
            }
            log
        }
    }
}

/// Mint a FRESH, uniquely named temp WAV path (mkstemp-style: `create_new`
/// O_EXCL + a random component). The pid-named scheme this replaces could
/// collide with a STALE file from a dead run (pids recycle) and, combined
/// with an existence check, log a previous run's audio under new text. A
/// name nothing else can hold makes "the WAV exists" mean "written by THIS
/// run" structurally.
fn unique_voice_tmp() -> Result<PathBuf> {
    use rand_core::RngCore;
    for _ in 0..16 {
        let mut r = [0u8; 8];
        OsRng.fill_bytes(&mut r);
        let path = std::env::temp_dir().join(format!(
            "liora_voice_{}_{:016x}.wav",
            std::process::id(),
            u64::from_le_bytes(r)
        ));
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(_) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).with_context(|| format!("create temp wav {}", path.display()));
            }
        }
    }
    bail!(
        "could not mint a unique temp wav in {}",
        std::env::temp_dir().display()
    );
}

fn cmd_route(ws: &mut Workspace<Pile>, daemon: &str) -> Result<()> {
    let devices = detect_output_devices()?;
    let sw = switch_audio_bin();
    let daemon_up = reachy_reachable(daemon);

    println!("SwitchAudioSource: {}", if sw.is_some() { "present (per-device targeting)" } else { "ABSENT — degraded routing (see notes)" });
    println!("Reachy daemon:     {}", if daemon_up { "reachable" } else { "down" });
    println!();

    println!("connected output devices:");
    for d in &devices {
        let def = if d.is_default_output { "  [default output]" } else { "" };
        println!("  {:<28} {}{def}", d.name, d.class().label());
    }
    println!();

    for channel in [CHANNEL_SAY, CHANNEL_SHOUT] {
        let prefs = load_route(ws, channel)?;
        println!("{channel} policy (priority order): {}", prefs.join(" → "));
        let routed = if channel == CHANNEL_SAY {
            route_say(&prefs, &devices, sw.as_deref())
        } else {
            route_shout(&prefs, &devices, sw.as_deref(), daemon_up)
        };
        println!("  would route to: {}", routed.describe());
    }
    if sw.is_none() {
        println!();
        println!("note: without SwitchAudioSource, `say` plays only when the DEFAULT");
        println!("      output is itself a private device; otherwise it prints text.");
        println!("      Install with: brew install switchaudio-osx");
    }
    Ok(())
}

fn cmd_route_set(
    repo: &mut Repository<Pile>,
    ws: &mut Workspace<Pile>,
    channel: &str,
    devices: &[String],
) -> Result<()> {
    let channel = match channel.to_lowercase().as_str() {
        "say" => CHANNEL_SAY,
        "shout" => CHANNEL_SHOUT,
        other => bail!("unknown channel '{other}' — use 'say' or 'shout'"),
    };
    if channel == CHANNEL_SAY {
        for d in devices {
            if classify(d) != DeviceClass::Private {
                eprintln!(
                    "warning: '{d}' is {} — it will be IGNORED at speak-time on the \
                     private `say` channel (the privacy invariant can't be configured away).",
                    classify(d).label()
                );
            }
        }
    }
    store_route(repo, ws, channel, devices)?;
    println!("{channel} policy set: {}", devices.join(" → "));
    Ok(())
}

fn cmd_devices() -> Result<()> {
    let devices = detect_output_devices()?;
    if devices.is_empty() {
        println!("no audio output devices found.");
        return Ok(());
    }
    for d in &devices {
        let def = if d.is_default_output { "  [default output]" } else { "" };
        println!("{:<28} {}{def}", d.name, d.class().label());
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let pile = cli.pile.clone();
    let branch = cli.branch_id.as_deref();
    let daemon = cli.daemon.clone();

    match cli.command {
        None => {
            Cli::command().print_help().ok();
            println!();
        }
        Some(Command::Say { text, dry_run }) => with_voice(&pile, branch, |repo, ws| {
            cmd_speak(repo, ws, &daemon, CHANNEL_SAY, &text, dry_run)
        })?,
        Some(Command::Shout { text, dry_run }) => with_voice(&pile, branch, |repo, ws| {
            cmd_speak(repo, ws, &daemon, CHANNEL_SHOUT, &text, dry_run)
        })?,
        Some(Command::Route) => with_voice(&pile, branch, |_repo, ws| cmd_route(ws, &daemon))?,
        Some(Command::RouteSet { channel, devices }) => {
            with_voice(&pile, branch, |repo, ws| {
                cmd_route_set(repo, ws, &channel, &devices)
            })?
        }
        Some(Command::Devices) => cmd_devices()?,
    }
    Ok(())
}
