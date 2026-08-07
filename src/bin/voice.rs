//! `voice` — a text-to-speech faculty: speech out, on two channels, with a
//! pile-backed routing policy that picks which audio device each channel plays
//! through.
//!
//! Extracted from `body` (2026-06-30). The body is the physical Reachy loop
//! (pose/look/feel/act); the voice is its own organ — synthesis (Qwen3-TTS via
//! mary) plus output routing.
//! Utterances and routing config live in one stable extrinsic collection
//! scope. Each operation is an independently signed COMMIT under a durable
//! local identity; route replacement is one atomic fragment rather than a
//! sequence of branch commits.
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
//! the channels differ only by SINK: local devices play the chunks as they
//! are synthesized through a NATIVE in-process audio sink (rodio/cpal — no
//! ffplay/afplay/SwitchAudioSource subprocesses, no pipe-probing latency),
//! while the Reachy speaker drains the same stream to a whole file (its
//! daemon media API is upload+play; daemon-side streaming is a noted
//! follow-up).
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
use ed25519_dalek::SigningKey;
use faculties::collection_access::{self, CollectionView};
use faculties::schemas::voice::{
    route, utterance, CHANNEL_SAY, CHANNEL_SHOUT, DEFAULT_SCOPE_ID, KIND_ROUTE, KIND_UTTERANCE,
};
use hifitime::efmt::consts::ISO8601;
use hifitime::efmt::Formatter;
use hifitime::Epoch;
use rand_core::OsRng;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use triblespace::core::blob::Blob;
use triblespace::core::collection::simplearchive_union;
use triblespace::core::collection::{CollectionCommit, CollectionData};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{self, reachable};
use triblespace::prelude::*;

type RawHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;
type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
type U256 = Inline<inlineencodings::U256BE>;

const DEFAULT_DAEMON: &str = "http://localhost:8000";
const LEGACY_VOICE_BRANCH_NAME: &str = "voice";

// Qwen3-TTS voice assets — used by the in-process `mary::speak` call (the
// `voice` feature). The reference voice asset (F5 lineage remains in
// mary as the voice-origin lineage); every utterance clones the v2 reference
// kit: an 11.46 s clean-boundary clip (24 kHz render of `ref_voice_v2.wav`),
// its EXACT transcript, and the clip's codec frames. Weights load from a
// durable standalone pile (under the faculties model dir); `QWEN3TTS_PILE`
// overrides the path. The reference-kit assets live beside it in the model dir.
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
    /// Extrinsic collection scope for utterances and routing. Defaults to the
    /// stable voice scope declared by this faculty.
    #[arg(long, value_parser = parse_id_arg)]
    scope: Option<Id>,
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
    /// voice collection.
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
    /// the voice collection.
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
    /// Publish the signed legacy `voice` branch as collection commits, then
    /// verify the exact materialized view. Stop every legacy voice writer
    /// before running this command. It never removes the legacy pin.
    MigrateLegacy {
        /// Exact legacy voice branch id. Needed only when duplicate `voice`
        /// branch names make name lookup ambiguous.
        #[arg(long, value_parser = parse_id_arg)]
        legacy_branch_id: Option<Id>,
    },
    /// List the connected audio output devices and their privacy class. The
    /// raw input to routing — a quick way to see what `say`/`shout` can target.
    Devices,
}

// ── time / id helpers (mirrors body/headspace) ─────────────────────────────

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

// ── collection persistence ───────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct VoiceStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
    scope: Id,
}

impl VoiceStorage<'_> {
    fn view(&self) -> Result<CollectionView> {
        let signer = collection_access::load_signer(self.pile, self.key)?;
        let allowed = HashSet::from([signer.verifying_key()]);
        collection_access::materialize_scope(self.pile, self.scope, &allowed)
    }

    fn publish(&self, fragment: Fragment, message: &str) -> Result<CollectionCommit> {
        let mut commit_metadata = Fragment::empty();
        let description: TextHandle = commit_metadata.put(message.to_owned());
        commit_metadata += entity! { metadata::description: description };
        collection_access::publish_fragment(
            self.pile,
            self.key,
            self.scope,
            fragment,
            commit_metadata,
        )
    }
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
    head: Option<CommitHandle>,
    commits: Vec<LegacyCommitMigration>,
    skipped_merges: usize,
    facts: TribleSet,
}

#[derive(Debug)]
struct LegacyMigrationReport {
    branch_id: Id,
    head: Option<CommitHandle>,
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
/// untyped fact set cannot prove that a directly named child is absent. Voice's
/// known direct payload attributes are therefore read strictly in
/// `preflight_legacy_voice_payloads` before this helper is used.
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

fn preflight_legacy_voice_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts.iter() {
        if fact.a() == &utterance::audio.id() {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::RawBytes>>();
            let _: anybytes::Bytes = reader.get(handle).with_context(|| {
                format!(
                    "strictly read legacy utterance::audio payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
            continue;
        }

        if fact.a() == &utterance::text.id() {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::LongString>>();
            let _: View<str> = reader.get(handle).with_context(|| {
                format!(
                    "strictly read legacy utterance::text payload {}",
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
    preflight_legacy_voice_payloads(reader, &facts)?;
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
    let reader = pile.reader().context("snapshot legacy voice branch")?;
    let wanted: Inline<inlineencodings::Handle<blobencodings::LongString>> =
        LEGACY_VOICE_BRANCH_NAME.to_owned().to_blob().get_handle();
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
        0 if explicit.is_some() => bail!("the selected legacy pin is not the named voice branch"),
        0 => bail!("no legacy voice branch exists"),
        1 => Ok((matches[0].0, matches[0].1, reader)),
        _ => bail!("multiple legacy branches are named voice; rerun with --legacy-branch-id"),
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
    let head = one_commit_value(&branch_facts, branch_entity, &repo::head, "branch head")?;
    if let Some(head) = head {
        let head_blob: Blob<blobencodings::SimpleArchive> =
            reader.get(head).context("read legacy branch head commit")?;
        repo::branch::verify(branch_id, head_blob, branch_facts.clone())
            .map_err(|_| anyhow::anyhow!("legacy voice branch-head signature is invalid"))?;
    }

    let definition = simplearchive_union::definition(scope);
    let mut commits = Vec::new();
    let mut targets = BTreeMap::new();
    let mut skipped_merges = 0;
    let mut union = TribleSet::new();

    let sources = match head {
        Some(head) => legacy_commits_topological(&reader, head)?,
        None => Vec::new(),
    };
    for source in sources {
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
    let current = pile.head(branch_id).context("recheck legacy voice pin")?;
    finish_migration_pile(pile, Ok(current == Some(expected)))
}

/// Re-read the resident transitive closure of the newly published roots.
/// Direct voice payload presence and decoding were established independently
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
    storage: VoiceStorage<'_>,
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
            .context("recheck legacy voice pin")?;
        if current != Some(plan.pin_metadata) {
            bail!("legacy voice pin changed after snapshot; no collection commit was published");
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
            .context("publish migrated voice collection commit")?;
            if commit != migration.target {
                bail!("published migration commit differs from its preflight identity");
            }
            commit
                .verify_strict()
                .context("verify migrated voice collection signature")?;
            published.push((migration.source, commit));
        }
        Ok(published)
    })();
    let published = finish_migration_pile(pile, result)?;

    let view = collection_access::materialize_scope(storage.pile, storage.scope, &allowed)?;
    if view.facts != expected {
        bail!("migrated voice collection does not equal the prior collection union legacy facts");
    }
    verify_resident_collection_closure(&view, published.iter().map(|(_, commit)| commit.clone()))?;
    let retention = collection_access::plan_authorized_union_retention(storage.pile, &allowed)?;
    let retention_direct = retention.direct().len();
    let retention_recursive = retention.recursive().len();
    if !confirm_legacy_pin(storage.pile, plan.branch_id, plan.pin_metadata)? {
        bail!(
            "legacy voice pin advanced during migration; collection commits may already have been appended. Stop every legacy writer, then rerun to migrate the new prefix; deterministic replay will reuse matching records"
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

fn cmd_migrate_legacy(storage: VoiceStorage<'_>, explicit_branch: Option<Id>) -> Result<()> {
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
    println!(
        "  legacy head   {}",
        report
            .head
            .map(|head| hex::encode_upper(head.raw))
            .unwrap_or_else(|| "<empty>".to_owned())
    );
    println!(
        "  retention     {} direct + {} recursive roots (verified, not persisted)",
        report.retention_direct, report.retention_recursive
    );
    println!("  legacy pin remains in place until recurring retention policy exists");
    Ok(())
}

/// Read a channel's routing policy from the pile. Each `voice route set` writes
/// a whole GENERATION of entries sharing one `metadata::updated_at`; the policy
/// is the LATEST generation only (a set replaces, it doesn't accumulate —
/// selecting the maximum set timestamp keeps the pile append-only while the
/// read sees one current policy). Exact timestamp ties retain the union of both
/// generations, matching the legacy behavior. Falls back to the baked-in
/// defaults when the pile holds no policy for the channel.
fn load_route(space: &TribleSet, channel: &str) -> Result<Vec<String>> {
    // (set-generation key, priority, device) for this channel.
    let mut rows: Vec<(i128, u64, String)> = Vec::new();
    for (dev, prio, updated) in find!(
        (d: String, p: U256, u: Inline<inlineencodings::NsTAIInterval>),
        pattern!(space, [{
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

fn route_set_fragment(
    channel: &str,
    devices: &[String],
    set_time: Inline<inlineencodings::NsTAIInterval>,
) -> Fragment {
    let mut route_set = Fragment::empty();
    for (i, dev) in devices.iter().enumerate() {
        let prio: U256 = (i as u64).to_inline();
        route_set += entity! {
            metadata::tag: &KIND_ROUTE,
            metadata::updated_at: set_time,
            route::channel: channel,
            route::device: dev.as_str(),
            route::priority: prio,
        };
    }
    route_set
}

fn store_route(storage: VoiceStorage<'_>, channel: &str, devices: &[String]) -> Result<()> {
    // One timestamp for the whole set — the generation marker `load_route` keys
    // on, so this set wholly replaces the previous policy for the channel.
    let route_set = route_set_fragment(channel, devices, now_tai());
    storage.publish(route_set, "voice route set")?;
    Ok(())
}

/// Record an utterance in the voice collection. The fact falls out of speaking —
/// logging is a side effect of the act, not a separate obligation.
/// `commit_msg` is the ledger line: "voice spoke" on the happy path, an
/// explicit failure marker when there was no trustworthy audio to attach
/// (synthesis died mid-stream) — the words never vanish from the pile.
fn utterance_fragment(
    channel: &str,
    text: &str,
    audio: Option<Vec<u8>>,
    created: Inline<inlineencodings::NsTAIInterval>,
) -> Fragment {
    let mut fragment = Fragment::empty();
    let text_h: TextHandle = fragment.put(text.to_string());
    let audio_h: Option<RawHandle> =
        audio.map(|bytes| fragment.put::<blobencodings::RawBytes, _>(bytes));
    fragment += entity! {
        metadata::tag: &KIND_UTTERANCE,
        metadata::created_at: created,
        utterance::channel: channel,
        utterance::text: text_h,
        utterance::audio?: audio_h,
        utterance::mime?: audio_h.map(|_| "audio/wav"),
    };
    fragment
}

fn log_utterance(
    storage: VoiceStorage<'_>,
    channel: &str,
    text: &str,
    wav: Option<&Path>,
    commit_msg: &str,
) -> Result<()> {
    let audio = match wav {
        Some(path) => {
            Some(std::fs::read(path).with_context(|| format!("read {}", path.display()))?)
        }
        None => None,
    };
    let fragment = utterance_fragment(channel, text, audio, now_tai());
    let id = fragment.root().expect("utterance id");
    storage.publish(fragment, commit_msg)?;
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
// the voice collection after completion — logging is unchanged.

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
    let t_call = std::time::Instant::now();
    let mut stream =
        mary::speak::synthesize_stream(&pile, &ref_wav, ref_text.trim(), &ref_code, text)?;

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

#[allow(clippy::too_many_arguments)]
fn cmd_speak(
    storage: VoiceStorage<'_>,
    daemon: &str,
    channel: &str,
    text: &str,
    dry_run: bool,
) -> Result<()> {
    let devices = detect_output_devices()?;
    let view = storage.view()?;
    let prefs = load_route(&view.facts, channel)?;

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
        return log_utterance(storage, channel, text, None, "voice spoke");
    }

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
                storage,
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
            let log = log_utterance(storage, channel, text, Some(&out), "voice spoke");
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

fn cmd_route(storage: VoiceStorage<'_>, daemon: &str) -> Result<()> {
    let devices = detect_output_devices()?;
    let daemon_up = reachy_reachable(daemon);
    let view = storage.view()?;

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
        let prefs = load_route(&view.facts, channel)?;
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

fn cmd_route_set(storage: VoiceStorage<'_>, channel: &str, devices: &[String]) -> Result<()> {
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
    store_route(storage, channel, devices)?;
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
    let storage = VoiceStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
        scope: cli.scope.unwrap_or(DEFAULT_SCOPE_ID),
    };
    let daemon = cli.daemon.clone();

    match cli.command {
        None => {
            Cli::command().print_help().ok();
            println!();
        }
        Some(Command::Say { text, dry_run }) => {
            cmd_speak(storage, &daemon, CHANNEL_SAY, &text, dry_run)?
        }
        Some(Command::Shout { text, dry_run }) => {
            cmd_speak(storage, &daemon, CHANNEL_SHOUT, &text, dry_run)?
        }
        Some(Command::Route) => cmd_route(storage, &daemon)?,
        Some(Command::RouteSet { channel, devices }) => cmd_route_set(storage, &channel, &devices)?,
        Some(Command::MigrateLegacy { legacy_branch_id }) => {
            cmd_migrate_legacy(storage, legacy_branch_id)?
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
    use triblespace::core::collection::discover_collection_records;
    use triblespace::core::repo::Repository;

    fn at_unix(seconds: f64) -> Inline<inlineencodings::NsTAIInterval> {
        let instant = Epoch::from_unix_seconds(seconds);
        (instant, instant).try_to_inline().unwrap()
    }

    fn test_id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn fresh_storage(directory: &tempfile::TempDir) -> (PathBuf, PathBuf, Id) {
        let pile = directory.path().join("voice.pile");
        let key = directory.path().join("voice.key");
        File::create(&pile).unwrap();
        collection_access::initialize_signer(&pile, Some(&key)).unwrap();
        (pile, key, test_id(0x61))
    }

    fn collection_commits(
        pile_path: &Path,
        key_path: &Path,
        scope: Id,
    ) -> (PileReader, Vec<CollectionCommit>) {
        let signer = collection_access::load_signer(pile_path, Some(key_path)).unwrap();
        let definition = simplearchive_union::definition(scope);
        let mut pile = collection_access::open_pile_strict(pile_path).unwrap();
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

    fn pin_head(
        pile_path: &Path,
        branch: Id,
    ) -> Inline<inlineencodings::Handle<blobencodings::SimpleArchive>> {
        let mut pile = collection_access::open_pile_strict(pile_path).unwrap();
        let head = pile.head(branch).unwrap().unwrap();
        pile.close().unwrap();
        head
    }

    struct LegacyFixture {
        pile: PathBuf,
        key: PathBuf,
        scope: Id,
        branch: Id,
        legacy_facts: TribleSet,
    }

    fn legacy_fixture(directory: &tempfile::TempDir) -> LegacyFixture {
        let pile_path = directory.path().join("legacy-voice.pile");
        let key_path = directory.path().join("collection.key");
        File::create(&pile_path).unwrap();

        let first_signer = SigningKey::from_bytes(&[0x31; 32]);
        let pile = collection_access::open_pile_strict(&pile_path).unwrap();
        let mut repository = Repository::new(pile, first_signer, Fragment::empty()).unwrap();
        let branch = *repository
            .create_branch(LEGACY_VOICE_BRANCH_NAME, None)
            .unwrap();
        let devices = vec!["AirPods".to_owned(), "Headphones".to_owned()];
        let route_content = route_set_fragment(CHANNEL_SAY, &devices, at_unix(10.0));
        let mut workspace = repository.pull(branch).unwrap();
        workspace.commit(route_content.clone(), "legacy route generation");
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();

        // Legacy voice created a fresh signing identity on each invocation.
        // A valid branch may therefore contain heterogeneous authored commit
        // signatures; migration validates each commit rather than assuming one
        // legacy author.
        let second_signer = SigningKey::from_bytes(&[0x32; 32]);
        let pile = collection_access::open_pile_strict(&pile_path).unwrap();
        let mut repository = Repository::new(pile, second_signer, Fragment::empty()).unwrap();
        let utterance_content = utterance_fragment(
            CHANNEL_SAY,
            "legacy hello",
            Some(b"legacy wav bytes".to_vec()),
            at_unix(20.0),
        );
        let mut workspace = repository.pull(branch).unwrap();
        workspace.commit(utterance_content.clone(), "legacy voice spoke");
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();

        collection_access::initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let mut legacy_facts = route_content.into_facts();
        legacy_facts += utterance_content.into_facts();
        LegacyFixture {
            pile: pile_path,
            key: key_path,
            scope: test_id(0x62),
            branch,
            legacy_facts,
        }
    }

    fn fixture_storage(fixture: &LegacyFixture) -> VoiceStorage<'_> {
        VoiceStorage {
            pile: &fixture.pile,
            key: Some(&fixture.key),
            scope: fixture.scope,
        }
    }

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
    fn route_generation_is_one_atomic_collection_commit() {
        let directory = tempfile::tempdir().unwrap();
        let (pile, key, scope) = fresh_storage(&directory);
        let storage = VoiceStorage {
            pile: &pile,
            key: Some(&key),
            scope,
        };
        let devices = vec![
            "AirPods Max".to_owned(),
            "AirPods Pro".to_owned(),
            "Headphones".to_owned(),
        ];

        store_route(storage, CHANNEL_SAY, &devices).unwrap();

        assert_eq!(collection_commits(&pile, &key, scope).1.len(), 1);
        let view = storage.view().unwrap();
        assert_eq!(load_route(&view.facts, CHANNEL_SAY).unwrap(), devices);
        let route_entities: BTreeSet<Id> = find!(
            (entity: Id),
            pattern!(&view.facts, [{
                ?entity @
                    metadata::tag: KIND_ROUTE,
                    route::channel: CHANNEL_SAY.to_owned(),
            }])
        )
        .map(|(entity,)| entity)
        .collect();
        assert_eq!(route_entities.len(), 3);
    }

    #[test]
    fn route_reader_keeps_whole_generation_and_unions_exact_time_ties() {
        let old = vec!["Old device".to_owned()];
        let latest_a = vec!["Zulu".to_owned()];
        let latest_b = vec!["Alpha".to_owned()];
        let mut facts = route_set_fragment(CHANNEL_SAY, &old, at_unix(10.0)).into_facts();
        facts += route_set_fragment(CHANNEL_SAY, &latest_a, at_unix(20.0)).into_facts();
        facts += route_set_fragment(CHANNEL_SAY, &latest_b, at_unix(20.0)).into_facts();

        assert_eq!(
            load_route(&facts, CHANNEL_SAY).unwrap(),
            vec!["Alpha".to_owned(), "Zulu".to_owned()]
        );
    }

    #[test]
    fn utterance_commit_carries_text_audio_and_description() {
        let directory = tempfile::tempdir().unwrap();
        let (pile, key, scope) = fresh_storage(&directory);
        let storage = VoiceStorage {
            pile: &pile,
            key: Some(&key),
            scope,
        };
        let wav = directory.path().join("utterance.wav");
        std::fs::write(&wav, b"synthetic wav bytes").unwrap();
        let marker = "voice spoke";

        log_utterance(
            storage,
            CHANNEL_SHOUT,
            "hello collection",
            Some(&wav),
            marker,
        )
        .unwrap();

        let (reader, commits) = collection_commits(&pile, &key, scope);
        assert_eq!(commits.len(), 1);
        let view = storage.view().unwrap();
        let (text, audio) = find!(
            (text: TextHandle, audio: RawHandle),
            pattern!(&view.facts, [{
                metadata::tag: KIND_UTTERANCE,
                utterance::text: ?text,
                utterance::audio: ?audio,
            }])
        )
        .next()
        .unwrap();
        let text: View<str> = view.reader.get(text).unwrap();
        let audio: anybytes::Bytes = view.reader.get(audio).unwrap();
        assert_eq!(&*text, "hello collection");
        assert_eq!(audio.as_ref(), b"synthetic wav bytes");

        let metadata_facts: TribleSet = reader.get(commits[0].metadata()).unwrap();
        let description = find!(
            (description: TextHandle),
            pattern!(&metadata_facts, [{ metadata::description: ?description }])
        )
        .next()
        .unwrap()
        .0;
        let description: View<str> = reader.get(description).unwrap();
        assert_eq!(&*description, marker);
    }

    #[test]
    fn text_only_failure_marker_is_preserved_in_commit_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let (pile, key, scope) = fresh_storage(&directory);
        let storage = VoiceStorage {
            pile: &pile,
            key: Some(&key),
            scope,
        };
        let marker = "voice spoke (synthesis FAILED mid-stream; text-only, no audio)";

        log_utterance(storage, CHANNEL_SAY, "words survived", None, marker).unwrap();

        let (reader, commits) = collection_commits(&pile, &key, scope);
        assert_eq!(commits.len(), 1);
        let view = storage.view().unwrap();
        assert_eq!(
            find!(
                (audio: RawHandle),
                pattern!(&view.facts, [{ utterance::audio: ?audio }])
            )
            .count(),
            0
        );
        let metadata_facts: TribleSet = reader.get(commits[0].metadata()).unwrap();
        let description = find!(
            (description: TextHandle),
            pattern!(&metadata_facts, [{ metadata::description: ?description }])
        )
        .next()
        .unwrap()
        .0;
        assert_eq!(&*reader.get::<View<str>, _>(description).unwrap(), marker);
    }

    #[test]
    fn legacy_migration_is_exact_idempotent_and_preserves_pin() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = legacy_fixture(&directory);
        let old_pin = pin_head(&fixture.pile, fixture.branch);

        let first = migrate_legacy(fixture_storage(&fixture), None).unwrap();
        let length = std::fs::metadata(&fixture.pile).unwrap().len();
        let second = migrate_legacy(fixture_storage(&fixture), None).unwrap();

        assert_eq!(first.commits, second.commits);
        assert_eq!(first.commits.len(), 2);
        assert_eq!(std::fs::metadata(&fixture.pile).unwrap().len(), length);
        assert_eq!(pin_head(&fixture.pile, fixture.branch), old_pin);
        let view = fixture_storage(&fixture).view().unwrap();
        assert_eq!(view.facts, fixture.legacy_facts);
        let (text, audio) = find!(
            (text: TextHandle, audio: RawHandle),
            pattern!(&view.facts, [{
                metadata::tag: KIND_UTTERANCE,
                utterance::text: ?text,
                utterance::audio: ?audio,
            }])
        )
        .next()
        .unwrap();
        assert_eq!(
            &*view.reader.get::<View<str>, _>(text).unwrap(),
            "legacy hello"
        );
        assert_eq!(
            view.reader
                .get::<anybytes::Bytes, _>(audio)
                .unwrap()
                .as_ref(),
            b"legacy wav bytes"
        );
    }

    #[test]
    fn late_missing_legacy_text_fails_before_any_publication() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("dangling-voice.pile");
        let key_path = directory.path().join("collection.key");
        File::create(&pile_path).unwrap();
        let legacy_signer = SigningKey::from_bytes(&[0x41; 32]);
        let pile = collection_access::open_pile_strict(&pile_path).unwrap();
        let mut repository = Repository::new(pile, legacy_signer, Fragment::empty()).unwrap();
        let branch = *repository
            .create_branch(LEGACY_VOICE_BRANCH_NAME, None)
            .unwrap();
        let good = route_set_fragment(CHANNEL_SAY, &["AirPods".to_owned()], at_unix(29.0));
        let mut workspace = repository.pull(branch).unwrap();
        workspace.commit(good, "legacy good route before dangling utterance");
        repository.push(&mut workspace).unwrap();
        let missing: TextHandle = Inline::new([0x91; 32]);
        let bad_content = entity! {
            metadata::tag: &KIND_UTTERANCE,
            metadata::created_at: at_unix(30.0),
            utterance::channel: CHANNEL_SAY,
            utterance::text: missing,
        };
        let mut workspace = repository.pull(branch).unwrap();
        workspace.commit(bad_content, "legacy dangling utterance");
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();
        collection_access::initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let old_pin = pin_head(&pile_path, branch);
        let length = std::fs::metadata(&pile_path).unwrap().len();
        let storage = VoiceStorage {
            pile: &pile_path,
            key: Some(&key_path),
            scope: test_id(0x63),
        };

        let error = migrate_legacy(storage, None).unwrap_err();

        assert!(format!("{error:#}").contains("strictly read legacy utterance::text payload"));
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), length);
        assert_eq!(pin_head(&pile_path, branch), old_pin);
        assert!(collection_commits(&pile_path, &key_path, storage.scope)
            .1
            .is_empty());
    }

    #[test]
    fn missing_legacy_audio_fails_before_publication() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("dangling-audio.pile");
        let key_path = directory.path().join("collection.key");
        File::create(&pile_path).unwrap();
        let pile = collection_access::open_pile_strict(&pile_path).unwrap();
        let mut repository =
            Repository::new(pile, SigningKey::from_bytes(&[0x42; 32]), Fragment::empty()).unwrap();
        let branch = *repository
            .create_branch(LEGACY_VOICE_BRANCH_NAME, None)
            .unwrap();
        let missing: RawHandle = Inline::new([0x92; 32]);
        let mut bad_content = Fragment::empty();
        let text: TextHandle = bad_content.put("legacy words".to_owned());
        bad_content += entity! {
            metadata::tag: &KIND_UTTERANCE,
            metadata::created_at: at_unix(31.0),
            utterance::channel: CHANNEL_SHOUT,
            utterance::text: text,
            utterance::audio: missing,
            utterance::mime: "audio/wav",
        };
        let mut workspace = repository.pull(branch).unwrap();
        workspace.commit(bad_content, "legacy dangling audio");
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();
        collection_access::initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let old_pin = pin_head(&pile_path, branch);
        let length = std::fs::metadata(&pile_path).unwrap().len();
        let storage = VoiceStorage {
            pile: &pile_path,
            key: Some(&key_path),
            scope: test_id(0x65),
        };

        let error = migrate_legacy(storage, None).unwrap_err();

        assert!(format!("{error:#}").contains("strictly read legacy utterance::audio payload"));
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), length);
        assert_eq!(pin_head(&pile_path, branch), old_pin);
        assert!(collection_commits(&pile_path, &key_path, storage.scope)
            .1
            .is_empty());
    }

    #[test]
    fn empty_legacy_voice_branch_is_a_clean_noop() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("empty-voice.pile");
        let key_path = directory.path().join("collection.key");
        File::create(&pile_path).unwrap();
        let pile = collection_access::open_pile_strict(&pile_path).unwrap();
        let mut repository =
            Repository::new(pile, SigningKey::from_bytes(&[0x51; 32]), Fragment::empty()).unwrap();
        let branch = *repository
            .create_branch(LEGACY_VOICE_BRANCH_NAME, None)
            .unwrap();
        repository.close().unwrap();
        collection_access::initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let old_pin = pin_head(&pile_path, branch);
        let length = std::fs::metadata(&pile_path).unwrap().len();
        let storage = VoiceStorage {
            pile: &pile_path,
            key: Some(&key_path),
            scope: test_id(0x64),
        };

        let report = migrate_legacy(storage, None).unwrap();

        assert!(report.head.is_none());
        assert!(report.commits.is_empty());
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), length);
        assert_eq!(pin_head(&pile_path, branch), old_pin);
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
