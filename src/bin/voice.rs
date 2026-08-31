//! `voice` — a text-to-speech faculty: speech out, on two channels, with a
//! pile-backed routing policy that picks which audio device each channel plays
//! through.
//!
//! Extracted from `body` (2026-06-30). The body is the physical Reachy loop
//! (pose/look/feel/act); the voice is its own organ — synthesis (Qwen3-TTS via
//! mary) plus output routing.
//! New utterances and routing config live in one fixed native collection.
//! Stopped-world migration validates historical records and reconstructs them
//! under the current live ontology and intrinsic identities.
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
//! Synthesis (Qwen3-TTS via mary's Burn/Metal pipeline) selects the exact base,
//! shared codec, filtered f16 talker, and folded f16 talker from one frozen
//! native model-collection snapshot. Its mmap pages are aliased zero-copy on
//! the production path. The heavy lane is gated behind the `voice` feature,
//! mirroring `imagine`; the default build compiles a bail stub so the rest of
//! the faculty suite stays light. There is ONE generation path —
//! `mary::speak::synthesize_stream`, a live PCM-chunk iterator — and
//! the channels differ only by SINK: local devices play the chunks as they
//! are synthesized through a NATIVE in-process audio sink (rodio/cpal — no
//! ffplay/afplay/SwitchAudioSource subprocesses, no pipe-probing latency),
//! while the Reachy speaker drains the same stream to a whole file (its
//! daemon media API is upload+play; daemon-side streaming is a noted
//! follow-up).
//!
//! HALF-DUPLEX (`--pause-file`, on both channels): the mouth creates the pause
//! file before any sound and removes it when the utterance ends, so a listener
//! started with the SAME path (`hear listen --pause-file`) discards audio for
//! exactly the window in which we might be audible. The listener NEVER CLOSES
//! ITS MICROPHONE to do this -- closing a Bluetooth mic flips the endpoint
//! between its handsfree and high-quality profiles and chops speech
//! mid-sentence, so turn-taking is gated in SOFTWARE only: the hold stops the
//! model, never the person. The hold is a guard whose `Drop` is the release,
//! because a crash mid-utterance must not deafen the ears forever. Protocol and
//! filters live in `faculties::turntaking` (extracted from the `converse`
//! bridge, which this pair replaces).
//!
//! Device targeting: the native sink opens the routed output device BY NAME
//! via cpal (CoreAudio), never touching the system default output — the
//! SwitchAudioSource machinery and its whole fragility class (default-switch
//! races, stale restores, a brew dependency) are gone, and so is the degraded
//! no-targeting mode. Enumeration and playback share ONE namespace, so a name
//! that routes is a name that plays. Opening the device is the verification:
//! an absent/asleep/rejecting device errors LOUDLY and playback falls to the
//! next device in the routing ladder (for `say`, only ever to another PRIVATE
//! device — else the text fallback). The say-privacy invariant is enforced at
//! resolution AND re-asserted per device name before any sound.

use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::clock;
use faculties::legacy_hint::open_scope;
use faculties::schemas::voice::{
    route, CHANNEL_SAY, CHANNEL_SHOUT, COLLECTION_SCOPE_ID, KIND_LIVE_RECORD, KIND_ROUTE,
};
use faculties::storage::{load_signer, open_pile_strict};
use faculties::voice as voice_model;
use hifitime::efmt::consts::ISO8601;
use hifitime::efmt::Formatter;
use hifitime::Epoch;
use rand_core::OsRng;
use std::path::{Path, PathBuf};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::collection::{Collection, CollectionCommit, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::prelude::*;

type U256 = Inline<inlineencodings::U256BE>;

const DEFAULT_DAEMON: &str = "http://localhost:8000";

// Qwen3-TTS voice assets — used by the in-process `mary::speak` call (the
// `voice` feature). The reference voice asset (F5 lineage remains in
// mary as the voice-origin lineage); every utterance clones the v2 reference
// kit: an 11.46 s clean-boundary clip (24 kHz render of `ref_voice_v2.wav`),
// its EXACT transcript, and the clip's codec frames. Weights load from a
// native model-collection pile (under the faculties model dir);
// `QWEN3TTS_PILE` overrides the path. The reference-kit assets live beside it
// in the model dir.
#[cfg(feature = "voice")]
const QWEN3TTS_PILE_FILE: &str = "qwen3tts.pile";
#[cfg(feature = "voice")]
const REF_WAV_FILE: &str = "ref_voice_v2_24k.wav";
#[cfg(feature = "voice")]
const REF_TXT_FILE: &str = "ref_voice_v2.txt";
#[cfg(feature = "voice")]
const REF_CODE_FILE: &str = "ref_voice_v2_code.npy";

// Default routing policy, used when the pile holds no `route set` for a channel.
// `say` lists ONLY private devices (the classifier rejects anything else anyway);
// `shout` is the public broadcast ladder.
const DEFAULT_SAY_DEVICES: &[&str] = &["AirPods Max", "AirPods Pro", "AirPods", "Headphones"];
const DEFAULT_SHOUT_DEVICES: &[&str] = &[
    "Reachy Mini Audio",
    "Studio Display Speakers",
    "MacBook Pro Speakers",
];

// ── CLI ──────────────────────────────────────────────────────────────────
#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "voice",
    about = "Speech synthesis + privacy-aware output routing, on two channels."
)]
struct Cli {
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
        /// audio while we speak. See `faculties::turntaking`. The listener
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
    /// List the connected audio output devices and their privacy class. The
    /// raw input to routing — a quick way to see what `say`/`shout` can target.
    Devices,
}

// ── time / id helpers (mirrors body/headspace) ─────────────────────────────

fn now_tai() -> Result<Inline<inlineencodings::NsTAIInterval>> {
    clock::point_now()
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
        "airpods",
        "headphone",
        "headset",
        "earbud",
        "earphone",
        "earpod",
        "ear pod",
        "in-ear",
        "beats",
        "buds",
        " wf-",
        " wh-",
        "powerbeats",
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

/// Enumerate connected audio OUTPUT devices natively via cpal (CoreAudio on
/// macOS) — the SAME namespace the playback sink opens devices from, so a
/// name that routes here is a name `open_named_sink` can actually play on
/// (the system_profiler/playback name-mismatch class can't exist).
#[cfg(feature = "audio")]
fn detect_output_devices() -> Result<Vec<AudioDevice>> {
    use rodio::cpal::traits::{DeviceTrait, HostTrait};
    let host = rodio::cpal::default_host();
    let default_name = host
        .default_output_device()
        .and_then(|d| d.description().ok().map(|desc| desc.name().to_string()));
    let mut devices = Vec::new();
    for dev in host
        .output_devices()
        .context("enumerate audio output devices (cpal)")?
    {
        let Ok(desc) = dev.description() else {
            continue;
        };
        let name = desc.name().to_string();
        if name.is_empty() {
            continue;
        }
        devices.push(AudioDevice {
            is_default_output: Some(&name) == default_name.as_ref(),
            name,
        });
    }
    Ok(devices)
}

/// Audio-less builds (`--no-default-features`, the FreeBSD server class):
/// same signature, fails loud. Every caller compiles unchanged; any
/// device-touching subcommand reports the missing capability honestly.
#[cfg(not(feature = "audio"))]
fn detect_output_devices() -> Result<Vec<AudioDevice>> {
    anyhow::bail!("audio device support not compiled into this build (enable the `audio` feature)")
}

/// Connected devices whose name contains `pat` (case-insensitive), in
/// enumeration order — a pattern can ladder several devices ("AirPods"
/// matches the Max and the Pro; the router keeps them all as fallbacks).
fn connected_matches<'a>(
    pat: &str,
    devices: &'a [AudioDevice],
) -> impl Iterator<Item = &'a AudioDevice> {
    let needle = pat.to_lowercase();
    devices
        .iter()
        .filter(move |d| d.name.to_lowercase().contains(&needle))
}

// ── playback primitives ────────────────────────────────────────────────────

/// Open a native audio sink on the output device with EXACTLY this name (the
/// namespace `detect_output_devices` enumerates). Opening is the
/// verification: a device that is absent, asleep, or rejects a stream errors
/// HERE, loudly — never a silent success against a dead route. The returned
/// `MixerDeviceSink` owns the live cpal stream (keep it alive for the whole
/// playback; dropping it stops the audio); cpal stream errors mid-play go to
/// rodio's default callback, which prints to stderr — no diagnostic channel
/// is ever nulled.
#[cfg(feature = "voice")]
fn open_named_sink(name: &str) -> Result<(rodio::MixerDeviceSink, rodio::Player)> {
    use rodio::cpal::traits::{DeviceTrait, HostTrait};
    let host = rodio::cpal::default_host();
    let device = host
        .output_devices()
        .context("enumerate audio output devices (cpal)")?
        .find(|d| {
            d.description()
                .map(|desc| desc.name() == name)
                .unwrap_or(false)
        })
        .with_context(|| format!("output device '{name}' not found (disconnected?)"))?;
    let mut sink = rodio::DeviceSinkBuilder::from_device(device)
        .and_then(|b| b.open_stream())
        .map_err(|e| anyhow::anyhow!("open audio stream on '{name}': {e}"))?;
    sink.log_on_drop(false); // we print our own completion line
    let player = rodio::Player::connect_new(sink.mixer());
    Ok((sink, player))
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
        bail!(
            "Reachy play_sound failed: {}",
            resp.text().unwrap_or_default()
        );
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
    /// Play through the Reachy robot speaker (daemon upload + play).
    Reachy,
    /// Play through the native sink on the first OPENABLE device of this
    /// non-empty ladder (candidates in priority order; a device that fails to
    /// open falls loudly to the next). For `say` every entry is PRIVATE.
    Devices(Vec<String>),
    /// Do NOT play — print the text instead (the `say` private fallback).
    Text(String),
}

impl Routed {
    fn describe(&self) -> String {
        match self {
            Routed::Reachy => "Reachy speaker (daemon)".to_string(),
            Routed::Devices(ladder) => {
                let (first, rest) = ladder.split_first().expect("ladder is never empty");
                if rest.is_empty() {
                    format!("{first} (native sink)")
                } else {
                    format!("{first} (native sink; fallbacks: {})", rest.join(" → "))
                }
            }
            Routed::Text(why) => format!("TEXT fallback — {why}"),
        }
    }
}

/// Resolve the PRIVATE `say` channel. This function bakes in the invariant:
/// the ladder it returns contains ONLY devices proven PRIVATE (the playback
/// sink re-asserts each name before sound as defense in depth). The only
/// non-private outcome is `Routed::Text` (silent, on-screen). There is
/// deliberately NO branch that ladders a speaker — not even as a fallback.
fn route_say(prefs: &[String], devices: &[AudioDevice]) -> Routed {
    let mut ladder: Vec<String> = Vec::new();
    for pat in prefs {
        for dev in connected_matches(pat, devices) {
            if dev.class() == DeviceClass::Private && !ladder.contains(&dev.name) {
                ladder.push(dev.name.clone());
            }
            // matched a non-private device: skip it — never play here.
        }
    }
    if ladder.is_empty() {
        Routed::Text("no connected private (in-ear/headphone) device".into())
    } else {
        Routed::Devices(ladder)
    }
}

/// Resolve the PUBLIC `shout` channel — broadcasting is the point, so it
/// builds the whole audible ladder: every connected policy match in priority
/// order, with the default output appended as the last resort. Reachy
/// short-circuits when it is the FIRST connected match and the daemon is up
/// (its sink is the whole-file daemon upload, not the streaming device sink);
/// when the daemon is down it is skipped and the ladder keeps going.
fn route_shout(prefs: &[String], devices: &[AudioDevice], daemon_up: bool) -> Routed {
    let mut ladder: Vec<String> = Vec::new();
    for pat in prefs {
        for dev in connected_matches(pat, devices) {
            match dev.class() {
                DeviceClass::Reachy if daemon_up && ladder.is_empty() => return Routed::Reachy,
                // Reachy below a local device (or daemon down): not a
                // streaming-sink candidate — keep walking the ladder.
                DeviceClass::Reachy => continue,
                _ => {
                    if !ladder.contains(&dev.name) {
                        ladder.push(dev.name.clone());
                    }
                }
            }
        }
    }
    // Last resort: the default output (audible), even if no policy entry matched.
    if let Some(default) = devices.iter().find(|d| d.is_default_output) {
        if !ladder.contains(&default.name) {
            ladder.push(default.name.clone());
        }
    }
    if ladder.is_empty() {
        Routed::Text("no audible output device connected".into())
    } else {
        Routed::Devices(ladder)
    }
}

// ── native collection persistence ─────────────────────────────────────────

#[derive(Clone, Copy)]
struct VoiceStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

struct VoiceSession<'a> {
    pile: &'a mut Pile,
    collection: Collection<SimpleArchive>,
    signer: &'a ed25519_dalek::SigningKey,
    facts: TribleSet,
    reader: PileSnapshot,
}

impl VoiceSession<'_> {
    fn commit(
        &mut self,
        mut fragment: Fragment,
        description: &'static str,
    ) -> Result<CollectionCommit> {
        voice_model::validate_candidate(&self.reader, &self.facts, &fragment)?;
        let added = fragment.facts().clone();
        fragment.describe_with(entity! { metadata::description: description });
        let commit = self
            .pile
            .commit(self.collection, self.signer, fragment)
            .context("commit Voice fragment")?;
        self.facts += added;
        self.reader = self
            .pile
            .snapshot()
            .context("refresh Voice attachment snapshot")?;
        Ok(commit)
    }
}

impl VoiceStorage<'_> {
    fn with_session<T>(
        &self,
        operation: impl FnOnce(&mut VoiceSession<'_>) -> Result<T>,
    ) -> Result<T> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = (|| {
            let collection = open_scope(&mut pile, COLLECTION_SCOPE_ID, &signer)?;
            let store_snapshot = pile.snapshot().context("freeze Voice store snapshot")?;
            let (facts, _) = faculties::storage::read_fact_collection(collection, &store_snapshot)
                .context("materialize Voice collection")?;
            voice_model::validate_catalog(&store_snapshot, &facts)
                .context("validate native Voice collection")?;
            operation(&mut VoiceSession {
                pile: &mut pile,
                collection,
                signer: &signer,
                facts,
                reader: store_snapshot,
            })
        })();
        finish_pile(pile, result)
    }
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context("close Voice pile")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing Voice pile also failed: {close_error}")))
        }
    }
}

/// Read a channel's routing policy from the pile. Each `voice route set` writes
/// a whole GENERATION of entries sharing one `metadata::updated_at`; the policy
/// is the LATEST generation only (a set replaces, it doesn't accumulate).
/// Exact timestamp ties are unioned. Falls back to the baked-in defaults when
/// the live projection holds no policy for the channel.
fn load_route(space: &TribleSet, channel: &str) -> Result<Vec<String>> {
    // (set-generation key, priority, device) for this channel.
    let mut rows: Vec<(i128, u64, String)> = Vec::new();
    for (dev, prio, updated) in find!(
        (d: String, p: U256, u: Inline<inlineencodings::NsTAIInterval>),
        pattern!(space, [{
            _?e @
                metadata::tag: KIND_LIVE_RECORD,
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

fn route_set_fragment(
    channel: &str,
    devices: &[String],
    set_time: Inline<inlineencodings::NsTAIInterval>,
) -> Fragment {
    let mut generation = Fragment::empty();
    for (i, dev) in devices.iter().enumerate() {
        let prio: U256 = (i as u64).to_inline();
        generation += voice_model::route_record(channel, dev, prio, set_time);
    }
    generation
}

fn store_route(session: &mut VoiceSession<'_>, channel: &str, devices: &[String]) -> Result<()> {
    let generation = route_set_fragment(channel, devices, now_tai()?);
    session.commit(generation, "voice route set")?;
    Ok(())
}

/// Record an utterance in the fixed Voice collection. The fact falls out of speaking —
/// logging is a side effect of the act, not a separate obligation.
/// `commit_msg` is the ledger line: "voice spoke" on the happy path, an
/// explicit failure marker when there was no trustworthy audio to attach
/// (synthesis died mid-stream) — the words never vanish from the pile.
fn log_utterance(
    session: &mut VoiceSession<'_>,
    channel: &str,
    text: &str,
    wav: Option<&Path>,
    commit_msg: &'static str,
) -> Result<()> {
    let audio = match wav {
        Some(path) => {
            Some(std::fs::read(path).with_context(|| format!("read {}", path.display()))?)
        }
        None => None,
    };
    let fragment = voice_model::utterance_fragment(channel, text, audio, now_tai()?)?;
    let id = fragment.root().expect("utterance id");
    session.commit(fragment, commit_msg)?;
    println!("  logged utterance {} [{channel}]", &fmt_id(id)[..12]);
    Ok(())
}

// ── adaptive prebuffer math (pure — unit-tested, no audio) ─────────────────

/// Estimate an utterance's total audio duration from its character count,
/// calibrated by the reference kit: assume the generated speech runs at the
/// reference clip's chars-per-second. This is the same linear chars→duration
/// model mary's batch F5 path uses to size its mel window
/// (`say::synth_chunk`: `duration = ref_len / ref_chars * gen_chars`). It is
/// an ESTIMATE — the underrun guard in `stream_to_device` catches the cases
/// where reality runs longer.
#[cfg_attr(not(feature = "voice"), allow(dead_code))]
fn estimate_audio_secs(gen_chars: usize, ref_secs: f32, ref_chars: usize) -> f32 {
    if ref_chars == 0 {
        return 0.0;
    }
    ref_secs * gen_chars as f32 / ref_chars as f32
}

/// How much audio (seconds) must be buffered before starting playback so
/// synthesis at `production_rate` (audio-seconds produced per wall-second;
/// < 1 is slower than realtime) stays ahead of the playhead for the REST of
/// an utterance totalling `total_est_secs`.
///
/// Derivation: playback starting with `B` seconds buffered has consumed `t`
/// seconds of audio by wall-time `t`, while production has `B + rate·t`
/// ready. Their gap `B − t·(1 − rate)` shrinks linearly (for rate < 1) until
/// production finishes at `t = (T − B)/rate`, so the binding constraint is
/// at the END: `B ≥ T·(1 − rate)` keeps the buffer nonnegative throughout —
/// the EXACT no-underrun bound, not a heuristic. The margin absorbs rate
/// jitter and estimate error (it holds a `margin/rate` cushion at the worst
/// point); the floor keeps the queue from starting starved even when there
/// is no deficit at all.
#[cfg_attr(not(feature = "voice"), allow(dead_code))]
fn prebuffer_target_secs(total_est_secs: f32, production_rate: f32) -> f32 {
    const MARGIN_SECS: f32 = 0.5;
    const FLOOR_SECS: f32 = 0.15;
    let deficit = total_est_secs * (1.0 - production_rate).max(0.0);
    (deficit + MARGIN_SECS).max(FLOOR_SECS)
}

// ── synthesis + sinks (feature-gated, mirrors imagine) ─────────────────────
//
// ONE generation path, TWO kinds of sink. Every playing channel synthesizes
// through `mary::speak::synthesize_stream` — a live iterator of 24 kHz PCM
// chunks (frames hit the codec the moment they are sampled). The sinks differ
// only in how they drain it:
//   - STREAMING sink (say/shout to a local device): chunks are appended to a
//     NATIVE in-process rodio sink opened by device NAME (cpal/CoreAudio).
//     Playback starts behind an ADAPTIVE prebuffer: estimate the utterance
//     duration from the text (reference-kit chars-per-second, the same
//     linear model mary's batch path sizes its mel window with), measure the
//     REAL production rate from the inter-chunk spacing, and hold playback
//     until the buffer covers the predicted deficit (`prebuffer_target_secs`
//     — the exact bound past which production stays ahead of the playhead).
//     Synthesis at/above realtime starts on the second chunk; 2.1x-slower
//     synthesis buffers ~half the utterance ONCE instead of stuttering
//     through all of it (JP's live test, 2026-07-08). No subprocess, no pipe
//     probing (the ffplay era needed low-latency flags to get under ~15 s to
//     first sample, and could fail SILENTLY with stderr nulled; both classes
//     are dead — open errors surface, playback is verified, completion is
//     reported).
//   - BATCH sink (shout via the Reachy robot): the daemon's media API accepts
//     whole files only (upload + play_sound), so the SAME stream is drained
//     to a WAV first. Streaming into the daemon is a noted follow-up on the
//     daemon side; this lane does not touch it.
// Every sink also accumulates the full utterance, which `cmd_speak` logs on
// the Voice collection after completion — logging is unchanged.

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
    channel: &str,
    text: &str,
    out: &Path,
) -> Result<Spoken> {
    let sr = mary::speak::SpeakStream::SAMPLE_RATE;
    let model_dir = faculties::model_dir();
    let pile = match std::env::var_os("QWEN3TTS_PILE") {
        Some(p) => PathBuf::from(p),
        None => model_dir.join(QWEN3TTS_PILE_FILE),
    };
    let ref_wav = model_dir.join(REF_WAV_FILE);
    let ref_txt_path = model_dir.join(REF_TXT_FILE);
    let ref_code = model_dir.join(REF_CODE_FILE);
    let ref_text = std::fs::read_to_string(&ref_txt_path)
        .with_context(|| format!("read reference transcript {}", ref_txt_path.display()))?;
    // Duration estimate for the adaptive prebuffer: the reference clip's
    // chars-per-second applied to the generated text (see
    // `estimate_audio_secs`). Read before t_call so TTFA stays a pure
    // synthesis measurement.
    let (ref_samples, ref_sr) = mary::models::f5::wav::read_pcm16_mono(&ref_wav);
    let est_secs = estimate_audio_secs(
        text.chars().count(),
        ref_samples.len() as f32 / ref_sr.max(1) as f32,
        ref_text.trim().chars().count(),
    );
    let variant = mary::speak::Qwen3TtsVariant::from_env();
    let snapshot =
        mary::model_collection::load_model_collection_local_latest(&pile).with_context(|| {
            format!(
                "discover and freeze the sole native Qwen3-TTS snapshot {}",
                pile.display()
            )
        })?;
    let weights =
        mary::speak::Qwen3TtsWeights::from_snapshot(snapshot, variant).with_context(|| {
            format!(
                "select {variant:?} Qwen3-TTS cohort from {}",
                pile.display()
            )
        })?;
    let t_call = std::time::Instant::now();
    let mut stream =
        mary::speak::synthesize_stream(weights, &ref_wav, ref_text.trim(), &ref_code, text)?;

    let mut samples: Vec<f32> = Vec::new();
    let played: Result<()> = match routed {
        // Whole-file sink: drain the same stream, upload after.
        Routed::Reachy => {
            for chunk in stream.by_ref() {
                samples.extend_from_slice(&chunk);
            }
            Ok(())
        }
        Routed::Devices(ladder) => stream_to_device(
            &mut stream,
            &mut samples,
            t_call,
            channel,
            ladder,
            sr,
            est_secs,
        ),
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

/// Drain `stream` into the first device of `ladder` that OPENS, through the
/// native in-process sink — chunks play as they are synthesized, behind an
/// ADAPTIVE prebuffer sized to the measured synthesis speed (see the loop
/// below and `prebuffer_target_secs`); the rodio mixer resamples 24 kHz mono
/// to whatever the device runs natively. `est_secs` is the chars-calibrated
/// duration estimate for the whole utterance. Every failure is LOUD: an
/// unopenable device prints why and falls to the next candidate (on the
/// `say` channel each name is re-asserted PRIVATE first — a ladder can only
/// fall to another private device); a queue that stops draining mid-play
/// errors instead of hanging forever. Prints the buffering decision when it
/// holds playback back, the measured TTFA (call → playback start), and a
/// completion line naming the device that ACTUALLY played and how much
/// audio was written to it.
#[cfg(feature = "voice")]
#[allow(clippy::too_many_arguments)]
fn stream_to_device(
    stream: &mut mary::speak::SpeakStream,
    samples: &mut Vec<f32>,
    t_call: std::time::Instant,
    channel: &str,
    ladder: &[String],
    sr: u32,
    est_secs: f32,
) -> Result<()> {
    use rodio::buffer::SamplesBuffer;
    use std::num::NonZero;

    // Walk the ladder: the first device that OPENS plays. Opening is the
    // verification — absent/asleep/stream-rejecting devices error here and we
    // say so before falling to the next (never a silent success).
    let mut opened = None;
    for name in ladder {
        // Defense in depth: the say router only ladders private devices;
        // re-assert the resolved NAME before any sound.
        if channel == CHANNEL_SAY && classify(name) != DeviceClass::Private {
            eprintln!(
                "  [stream] refusing non-private device '{name}' on the say channel \
                 (privacy invariant)"
            );
            continue;
        }
        match open_named_sink(name) {
            Ok(sink) => {
                opened = Some((sink, name.as_str()));
                break;
            }
            Err(e) => eprintln!("  [stream] could not open '{name}': {e:#} — trying next device"),
        }
    }
    let Some(((_device_sink, player), device)) = opened else {
        bail!(
            "no device in the routing ladder could be opened: {}",
            ladder.join(" → ")
        );
    };

    let mono = NonZero::new(1).expect("1 is nonzero");
    let sr_nz = NonZero::new(sr).context("PCM sample rate must be nonzero")?;
    let secs = |n: usize| n as f32 / sr as f32;

    // ── adaptive prebuffer ──
    // Synthesis may be SLOWER than realtime (JP's live test: 2.1x-slower and
    // a stutter every couple of seconds as rodio starved between chunks). No
    // fixed prebuffer fixes that — any constant is wrong for some rate. So:
    // measure the actual production rate from the inter-chunk spacing (chunk
    // 1 is excluded from the measurement — it pays model load + prefill, not
    // steady state) and hold playback until the buffer covers the predicted
    // deficit for the WHOLE utterance (`prebuffer_target_secs`, the exact
    // bound). At/above realtime the margin is met by the second chunk and
    // playback starts almost immediately; well below it, the buffer fills
    // ONCE up front instead of stuttering chunk-by-chunk to the end. The
    // rate keeps being re-measured on every chunk; if reality still dips
    // under the estimate mid-play, the underrun guard pauses ONCE and
    // rebuffers the remaining deficit rather than stutter.
    player.pause();
    let mut appended = 0usize;
    let mut started = false;
    let mut chunks = 0usize;
    let mut measure_from = 0usize; // samples appended when chunk 1 landed
    let mut t_first: Option<std::time::Instant> = None;
    let mut prod_rate = 1.0f32; // audio-secs produced per wall-sec (measured)
    let mut announced = false;
    let mut rebuffer_from: Option<usize> = None; // underrun-guard pause point
    for chunk in stream.by_ref() {
        // Underrun guard, checked BEFORE appending: playback started, the
        // queue drained dry, and here comes another chunk — the buffer was
        // sized short (rate dip, or the chars-estimate undershot). Pause and
        // rebuffer the remaining deficit at the freshly measured rate.
        if started && rebuffer_from.is_none() && player.empty() {
            player.pause();
            let target = prebuffer_target_secs((est_secs - secs(appended)).max(0.0), prod_rate);
            println!(
                "  [stream] underrun at {:.1}s — rebuffering {:.1}s (synthesis at {:.2}x realtime)",
                secs(appended),
                target,
                prod_rate
            );
            rebuffer_from = Some(appended);
        }
        samples.extend_from_slice(&chunk);
        appended += chunk.len();
        player.append(SamplesBuffer::new(mono, sr_nz, chunk));
        chunks += 1;
        match t_first {
            None => {
                t_first = Some(std::time::Instant::now());
                measure_from = appended;
            }
            // Steady-state production rate over everything since chunk 1.
            Some(t0) => {
                prod_rate = secs(appended - measure_from) / t0.elapsed().as_secs_f32().max(1e-3);
            }
        }
        if !started && chunks >= 2 {
            let target = prebuffer_target_secs(est_secs, prod_rate);
            if secs(appended) >= target {
                player.play();
                started = true;
                println!(
                    "  [stream] TTFA {:.2}s → {device}",
                    t_call.elapsed().as_secs_f32()
                );
            } else if !announced {
                println!(
                    "  [stream] buffering {:.1}s of ~{:.0}s (synthesis at {:.2}x realtime)",
                    target, est_secs, prod_rate
                );
                announced = true;
            }
        }
        if let Some(from) = rebuffer_from {
            let target = prebuffer_target_secs((est_secs - secs(from)).max(0.0), prod_rate);
            if secs(appended - from) >= target {
                player.play();
                rebuffer_from = None;
                println!(
                    "  [stream] resumed with {:.1}s rebuffered",
                    secs(appended - from)
                );
            }
        }
    }
    if appended == 0 {
        // Zero chunks: nothing was ever audible. Say so (the stream's own
        // error, if any, surfaces from `finish()` in the caller).
        bail!("no audio chunks arrived to play on '{device}'");
    }
    if !started {
        // Stream ended before the target was met (short utterance, or a
        // deficit larger than what remained): it is ALL buffered — play it.
        player.play();
        println!(
            "  [stream] TTFA {:.2}s → {device}",
            t_call.elapsed().as_secs_f32()
        );
    } else if rebuffer_from.is_some() {
        player.play(); // stream ended mid-rebuffer: the rest is all here now
    }

    // Bounded drain: wait for the queue to empty, but never hang on a dead
    // stream (a device dying mid-play stops consuming; sleeping forever would
    // resurrect the silent-failure class).
    let audio_secs = appended as f32 / sr as f32;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs_f32(audio_secs + 5.0);
    while !player.empty() {
        if std::time::Instant::now() > deadline {
            bail!("playback stalled on '{device}' ({audio_secs:.1}s of audio never drained)");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // Let the device's own buffer (~50 ms) flush before the stream drops.
    std::thread::sleep(std::time::Duration::from_millis(100));
    println!("  [stream] played {audio_secs:.1}s on {device} ({appended} samples)");
    Ok(())
}

#[cfg(not(feature = "voice"))]
fn speak_and_play(
    _routed: &Routed,
    _daemon: &str,
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

fn cmd_speak(
    session: &mut VoiceSession<'_>,
    daemon: &str,
    channel: &str,
    text: &str,
    dry_run: bool,
    pause_file: Option<&Path>,
) -> Result<()> {
    let devices = detect_output_devices()?;
    let prefs = load_route(&session.facts, channel)?;

    let routed = if channel == CHANNEL_SAY {
        route_say(&prefs, &devices)
    } else {
        route_shout(&prefs, &devices, reachy_reachable(daemon))
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
        return log_utterance(session, channel, text, None, "voice spoke");
    }

    // HALF-DUPLEX: hold the pause file across synthesis AND playback, so the
    // ears are deaf for the whole window in which we might be audible. The
    // guard's `Drop` is the release, which is why it is a guard: an error or a
    // panic mid-utterance must never leave a listener permanently deafened.
    // The listener does not stop capturing while this is held — it discards
    // frames. Closing a Bluetooth mic flips the endpoint between its handsfree
    // and high-quality profiles and chops speech mid-sentence, so turn-taking
    // is software-only: the hold stops the model, never the person.
    let _pause = pause_file.map(|path| {
        println!("  [half-duplex] holding {}", path.display());
        faculties::turntaking::PauseGuard::hold(path)
    });

    // ONE generation path (streaming synthesis), sink chosen by the route —
    // see the synthesis section. `out` receives the complete utterance; the
    // path is minted FRESH (unique name + O_EXCL) so a stale WAV left by a
    // dead run can never be logged under this utterance's text.
    let out = unique_voice_tmp()?;
    match speak_and_play(&routed, daemon, channel, text, &out) {
        // Synthesis failed mid-stream: no trustworthy audio, but the words
        // still happened — log them text-only with a failure marker so the
        // utterance survives on the pile, then surface the error.
        Err(synth_err) => {
            let _ = std::fs::remove_file(&out);
            eprintln!("synthesis failed — logging the utterance text-only: {synth_err:#}");
            if let Err(log_err) = log_utterance(
                session,
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
            let log = log_utterance(session, channel, text, Some(&out), "voice spoke");
            let _ = std::fs::remove_file(&out);
            if let Spoken::PlaybackFailed(play_err) = outcome {
                if channel == CHANNEL_SAY {
                    // The whole private ladder failed to play: the words still
                    // reach JP — on screen, never through a speaker.
                    println!("{text}");
                }
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
            "voice_out_{}_{:016x}.wav",
            std::process::id(),
            u64::from_le_bytes(r)
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
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

fn cmd_route(session: &VoiceSession<'_>, daemon: &str) -> Result<()> {
    let devices = detect_output_devices()?;
    let daemon_up = reachy_reachable(daemon);

    println!(
        "Reachy daemon: {}",
        if daemon_up { "reachable" } else { "down" }
    );
    println!();

    println!("connected output devices:");
    for d in &devices {
        let def = if d.is_default_output {
            "  [default output]"
        } else {
            ""
        };
        println!("  {:<28} {}{def}", d.name, d.class().label());
    }
    println!();

    for channel in [CHANNEL_SAY, CHANNEL_SHOUT] {
        let prefs = load_route(&session.facts, channel)?;
        println!("{channel} policy (priority order): {}", prefs.join(" → "));
        let routed = if channel == CHANNEL_SAY {
            route_say(&prefs, &devices)
        } else {
            route_shout(&prefs, &devices, daemon_up)
        };
        println!("  would route to: {}", routed.describe());
    }
    Ok(())
}

fn cmd_route_set(session: &mut VoiceSession<'_>, channel: &str, devices: &[String]) -> Result<()> {
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
    store_route(session, channel, devices)?;
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
        let def = if d.is_default_output {
            "  [default output]"
        } else {
            ""
        };
        println!("{:<28} {}{def}", d.name, d.class().label());
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let pile = cli.pile.clone();
    let key = cli.key.clone();
    let storage = VoiceStorage {
        pile: &pile,
        key: key.as_deref(),
    };
    let daemon = cli.daemon.clone();

    match cli.command {
        None => {
            Cli::command().print_help().ok();
            println!();
        }
        Some(Command::Say {
            text,
            dry_run,
            pause_file,
        }) => storage.with_session(|session| {
            cmd_speak(
                session,
                &daemon,
                CHANNEL_SAY,
                &text,
                dry_run,
                pause_file.as_deref(),
            )
        })?,
        Some(Command::Shout {
            text,
            dry_run,
            pause_file,
        }) => storage.with_session(|session| {
            cmd_speak(
                session,
                &daemon,
                CHANNEL_SHOUT,
                &text,
                dry_run,
                pause_file.as_deref(),
            )
        })?,
        Some(Command::Route) => storage.with_session(|session| cmd_route(session, &daemon))?,
        Some(Command::RouteSet { channel, devices }) => {
            storage.with_session(|session| cmd_route_set(session, &channel, &devices))?
        }
        Some(Command::Devices) => cmd_devices()?,
    }
    Ok(())
}

// ── tests: device resolution + the privacy invariant (no audio is played) ──
#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use triblespace::core::repo::BlobStoreGet;

    use faculties::schemas::voice::{utterance, KIND_UTTERANCE};
    use faculties::storage::{discover_target, initialize_signer};

    fn dev(name: &str, default: bool) -> AudioDevice {
        AudioDevice {
            name: name.to_string(),
            is_default_output: default,
        }
    }

    fn prefs(p: &[&str]) -> Vec<String> {
        p.iter().map(|s| s.to_string()).collect()
    }

    fn ladder(routed: Routed) -> Vec<String> {
        match routed {
            Routed::Devices(l) => l,
            other => panic!("expected a device ladder, got: {}", other.describe()),
        }
    }

    #[test]
    fn native_storage_uses_fixed_descriptor_and_atomic_voice_commits() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("voice.pile");
        let key = directory.path().join("voice.key");
        File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        let storage = VoiceStorage {
            pile: &pile,
            key: Some(&key),
        };

        let route = vec!["AirPods Max".to_owned(), "AirPods Pro".to_owned()];
        storage
            .with_session(|session| store_route(session, CHANNEL_SAY, &route))
            .unwrap();
        let wav = directory.path().join("utterance.wav");
        std::fs::write(&wav, b"synthetic wav bytes").unwrap();
        storage
            .with_session(|session| {
                log_utterance(
                    session,
                    CHANNEL_SAY,
                    "hello collection",
                    Some(&wav),
                    "voice spoke",
                )
            })
            .unwrap();

        storage
            .with_session(|session| {
                assert_eq!(load_route(&session.facts, CHANNEL_SAY)?, route);
                let (text, audio) = find!(
                    (text: voice_model::TextHandle, audio: voice_model::AudioHandle),
                    pattern!(&session.facts, [{
                        metadata::tag: KIND_LIVE_RECORD,
                        metadata::tag: KIND_UTTERANCE,
                        utterance::text: ?text,
                        utterance::audio: ?audio,
                    }])
                )
                .next()
                .expect("one live utterance");
                let text: anybytes::View<str> = session.reader.get(text)?;
                let audio: anybytes::Bytes = session.reader.get(audio)?;
                assert_eq!(text.as_ref(), "hello collection");
                assert_eq!(audio.as_ref(), b"synthetic wav bytes");
                Ok(())
            })
            .unwrap();

        let mut pile_storage = open_pile_strict(&pile).unwrap();
        let signer = faculties::storage::load_signer(&pile, Some(&key)).unwrap();
        let collection = open_scope(&mut pile_storage, COLLECTION_SCOPE_ID, &signer).unwrap();
        let discovery = discover_target(
            &mut pile_storage,
            COLLECTION_SCOPE_ID,
            signer.verifying_key(),
        )
        .unwrap();
        assert_eq!(discovery.commits().len(), 2);
        assert!(discovery
            .commits()
            .iter()
            .all(|commit| commit.collection() == collection.handle()));
        pile_storage.close().unwrap();
    }

    #[test]
    fn classify_is_fail_closed() {
        assert_eq!(classify("AirPods Max"), DeviceClass::Private);
        assert_eq!(classify("Sony WH-1000XM5"), DeviceClass::Private);
        assert_eq!(classify("Reachy Mini Audio"), DeviceClass::Reachy);
        // Speaker markers beat brand hints: a Beats Pill is a room speaker.
        assert_eq!(classify("Beats Pill"), DeviceClass::Speaker);
        // Anything unrecognised is PUBLIC — never fail-open into Private.
        assert_eq!(classify("Some Unknown Device"), DeviceClass::Speaker);
        assert_eq!(classify("MacBook Pro Speakers"), DeviceClass::Speaker);
    }

    #[test]
    fn say_ladders_all_private_matches_in_priority_order() {
        let devices = [
            dev("MacBook Pro Speakers", true),
            dev("AirPods Max", false),
            dev("AirPods Pro", false),
        ];
        // One pattern can ladder several devices (Max first: enumeration order).
        let l = ladder(route_say(&prefs(&["AirPods"]), &devices));
        assert_eq!(l, vec!["AirPods Max", "AirPods Pro"]);
    }

    #[test]
    fn say_never_ladders_a_speaker_even_when_the_policy_lists_one() {
        let devices = [dev("MacBook Pro Speakers", true), dev("AirPods Max", false)];
        // A (mis)configured policy that puts a speaker FIRST cannot make it play:
        // the ladder holds only the private device.
        let l = ladder(route_say(
            &prefs(&["MacBook Pro Speakers", "AirPods"]),
            &devices,
        ));
        assert_eq!(l, vec!["AirPods Max"]);
    }

    #[test]
    fn say_falls_to_text_when_no_private_device_connected() {
        let devices = [
            dev("MacBook Pro Speakers", true),
            dev("Studio Display Speakers", false),
            dev("Reachy Mini Audio", false),
        ];
        // Even a policy listing ONLY public devices yields TEXT, never sound.
        assert!(matches!(
            route_say(&prefs(&["MacBook", "Studio", "Reachy"]), &devices),
            Routed::Text(_)
        ));
        assert!(matches!(
            route_say(&prefs(&["AirPods"]), &devices),
            Routed::Text(_)
        ));
    }

    #[test]
    fn shout_short_circuits_to_reachy_when_daemon_up() {
        let devices = [
            dev("MacBook Pro Speakers", true),
            dev("Reachy Mini Audio", false),
        ];
        assert!(matches!(
            route_shout(&prefs(&["Reachy", "MacBook"]), &devices, true),
            Routed::Reachy
        ));
    }

    #[test]
    fn shout_skips_reachy_when_daemon_down_and_ladders_the_rest() {
        let devices = [
            dev("MacBook Pro Speakers", true),
            dev("Reachy Mini Audio", false),
            dev("Studio Display Speakers", false),
        ];
        let l = ladder(route_shout(
            &prefs(&["Reachy", "Studio", "MacBook"]),
            &devices,
            false,
        ));
        assert_eq!(l, vec!["Studio Display Speakers", "MacBook Pro Speakers"]);
    }

    #[test]
    fn shout_appends_default_output_as_last_resort() {
        let devices = [
            dev("MacBook Pro Speakers", true),
            dev("Studio Display Speakers", false),
        ];
        // Policy matches nothing: fall to the default output alone.
        let l = ladder(route_shout(&prefs(&["Reachy"]), &devices, false));
        assert_eq!(l, vec!["MacBook Pro Speakers"]);
        // Policy matches something: default output still appended as fallback.
        let l = ladder(route_shout(&prefs(&["Studio"]), &devices, false));
        assert_eq!(l, vec!["Studio Display Speakers", "MacBook Pro Speakers"]);
    }

    #[test]
    fn shout_local_device_above_reachy_wins() {
        let devices = [
            dev("MacBook Pro Speakers", true),
            dev("Reachy Mini Audio", false),
        ];
        // Reachy below a local match is not a streaming-sink candidate.
        let l = ladder(route_shout(&prefs(&["MacBook", "Reachy"]), &devices, true));
        assert_eq!(l, vec!["MacBook Pro Speakers"]);
    }

    // ── adaptive prebuffer math ──

    #[test]
    fn estimate_scales_by_reference_chars_per_second() {
        // Same char count as the reference → the reference's duration;
        // double the chars → double the estimate.
        assert!((estimate_audio_secs(240, 11.46, 240) - 11.46).abs() < 1e-4);
        assert!((estimate_audio_secs(480, 11.46, 240) - 22.92).abs() < 1e-3);
        // Degenerate reference: estimate 0 (the target floor still guards).
        assert_eq!(estimate_audio_secs(100, 11.46, 0), 0.0);
    }

    #[test]
    fn prebuffer_is_margin_only_when_synthesis_keeps_up() {
        // At or above realtime there is no deficit — just the 0.5 s margin,
        // met by the first ~0.64 s chunk: playback starts almost immediately
        // regardless of how long the utterance is.
        assert_eq!(prebuffer_target_secs(10.0, 1.0), 0.5);
        assert_eq!(prebuffer_target_secs(10.0, 1.05), 0.5);
        assert_eq!(prebuffer_target_secs(60.0, 2.0), 0.5);
    }

    #[test]
    fn prebuffer_covers_the_deficit_when_synthesis_is_slow() {
        // 1.4x-slower synthesis (rate ≈ 0.714): buffer ~29% of the utterance.
        let t = prebuffer_target_secs(10.0, 1.0 / 1.4);
        assert!((t - (10.0 * (1.0 - 1.0 / 1.4) + 0.5)).abs() < 1e-4);
        // 2.1x-slower (the live stutter case, rate ≈ 0.476): ~half + margin.
        let t = prebuffer_target_secs(10.0, 1.0 / 2.1);
        assert!(t > 5.7 && t < 5.8, "got {t}");
    }

    #[test]
    fn prebuffer_never_underruns_at_constant_rate() {
        // Simulate: start playback once `prebuffer_target_secs` is met and
        // check production stays ahead of the playhead to the end, over a
        // grid of rates and utterance lengths (buffered capped at the whole
        // utterance — a deficit larger than the text means play-after-drain,
        // which trivially can't underrun).
        for rate in [0.3f32, 1.0 / 2.1, 1.0 / 1.4, 0.9, 1.0, 1.5] {
            for total in [1.0f32, 5.0, 12.0, 60.0] {
                let b = prebuffer_target_secs(total, rate).min(total);
                let mut t = 0.0f32;
                while t <= total {
                    let produced = (b + rate * t).min(total);
                    let played = t.min(total);
                    assert!(
                        produced + 1e-3 >= played,
                        "underrun: rate {rate}, total {total}, t {t}: \
                         produced {produced} < played {played}"
                    );
                    t += 0.05;
                }
            }
        }
    }

    #[test]
    fn describe_names_the_ladder() {
        let routed = Routed::Devices(vec!["AirPods Max".into(), "AirPods Pro".into()]);
        assert_eq!(
            routed.describe(),
            "AirPods Max (native sink; fallbacks: AirPods Pro)"
        );
    }
}
