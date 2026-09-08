//! Explicit host speech and device operations. The finite MCP synthesis path
//! never calls this module. Private routing is rechecked before every device.
use super::routing::*;
#[cfg(feature = "voice")]
use super::synthesis::prebuffer_target_secs;
use super::synthesis::Synthesizer;
use super::{Channel, Voice};
use crate::out::Out;
#[cfg(feature = "voice")]
use crate::schemas::voice::CHANNEL_SAY;
use anyhow::{bail, Context, Result};
use rand_core::OsRng;
use std::path::{Path, PathBuf};

mod reporting;
mod retention;
pub use reporting::SpeechReportingError;
#[cfg(feature = "voice")]
use reporting::{report, retain_before_report};
use retention::retain_after_playback;
pub use retention::SpeechRetentionError;

pub const DEFAULT_DAEMON: &str = "http://localhost:8000";
fn http() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("build voice HTTP client")
}

/// Enumerate connected audio OUTPUT devices natively via cpal (CoreAudio on
/// macOS) — the SAME namespace the playback sink opens devices from, so a
/// name that routes here is a name `open_named_sink` can actually play on
/// (the system_profiler/playback name-mismatch class can't exist).
#[cfg(feature = "audio")]
pub fn detect_output_devices() -> Result<Vec<AudioDevice>> {
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
pub fn detect_output_devices() -> Result<Vec<AudioDevice>> {
    anyhow::bail!("audio device support not compiled into this build (enable the `audio` feature)")
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

/// What `speak_and_play` accomplished. An `Err` means synthesis or retaining
/// its complete WAV failed (the caller logs the words text-only with a
/// failure marker). `Ok` means the
/// complete utterance was synthesized and written to `out`.
// Without the `voice` feature the stub `speak_and_play` only ever bails, so
// neither variant is constructed — the type still shapes `cmd_speak`'s match.
#[cfg_attr(not(feature = "voice"), allow(dead_code))]
enum Spoken {
    /// Synthesized and written to `out`; the disposition distinguishes a
    /// drained local queue from the Reachy daemon accepting a request.
    Played(SpeechDisposition),
    /// The full utterance was synthesized and written to `out`, but playback
    /// failed — the caller logs the audio, then surfaces this error.
    PlaybackFailed(anyhow::Error),
    /// Audio remains complete, but a progress/completion report was rejected.
    ReportingFailed(anyhow::Error),
}

/// Synthesize `text` (streaming) and play it through the resolved route,
/// writing the COMPLETE utterance to `out` for the log. Never called for the
/// `Routed::Text` fallback (the caller short-circuits it — no GPU work for a
/// silent utterance). Local playback settles; Reachy only acknowledges the
/// playback request. See [`Spoken`] for the failure-stage split.
#[cfg(feature = "voice")]
fn speak_and_play(
    routed: &Routed,
    daemon: &str,
    channel: &str,
    text: &str,
    out: &Path,
    synthesizer: &Synthesizer,
    output: &mut Out<'_>,
) -> Result<Spoken> {
    let super::synthesis::PreparedSpeech {
        mut stream,
        sample_rate: sr,
        estimated_seconds: est_secs,
        started: t_call,
    } = synthesizer.start(text)?;

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
            output,
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
    super::synthesis::AudioClip::from_samples(&samples, sr)?.save(out)?;
    if let Err(e) = played {
        return Ok(if e.is::<SpeechReportingError>() {
            Spoken::ReportingFailed(e)
        } else {
            Spoken::PlaybackFailed(e)
        });
    }
    if matches!(routed, Routed::Reachy) {
        if let Err(e) = play_on_reachy(daemon, out) {
            return Ok(Spoken::PlaybackFailed(e));
        }
    }
    Ok(Spoken::Played(if matches!(routed, Routed::Reachy) {
        SpeechDisposition::ReachyRequestAccepted
    } else {
        SpeechDisposition::LocalPlaybackDrained
    }))
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
    output: &mut Out<'_>,
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
        retain_before_report(samples, &chunk, || {
            if started && rebuffer_from.is_none() && player.empty() {
                player.pause();
                let target = prebuffer_target_secs((est_secs - secs(appended)).max(0.0), prod_rate);
                report(output, format!(
                    "  [stream] underrun at {:.1}s — rebuffering {:.1}s (synthesis at {:.2}x realtime)",
                    secs(appended), target, prod_rate
                ), None)?;
                rebuffer_from = Some(appended);
            }
            Ok(())
        })?;
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
                report(
                    output,
                    format!(
                        "  [stream] TTFA {:.2}s → {device}",
                        t_call.elapsed().as_secs_f32()
                    ),
                    None,
                )?;
            } else if !announced {
                report(
                    output,
                    format!(
                        "  [stream] buffering {:.1}s of ~{:.0}s (synthesis at {:.2}x realtime)",
                        target, est_secs, prod_rate
                    ),
                    None,
                )?;
                announced = true;
            }
        }
        if let Some(from) = rebuffer_from {
            let target = prebuffer_target_secs((est_secs - secs(from)).max(0.0), prod_rate);
            if secs(appended - from) >= target {
                player.play();
                rebuffer_from = None;
                report(
                    output,
                    format!(
                        "  [stream] resumed with {:.1}s rebuffered",
                        secs(appended - from)
                    ),
                    None,
                )?;
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
        report(
            output,
            format!(
                "  [stream] TTFA {:.2}s → {device}",
                t_call.elapsed().as_secs_f32()
            ),
            None,
        )?;
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
    report(
        output,
        format!("  [stream] played {audio_secs:.1}s on {device} ({appended} samples)"),
        Some(SpeechDisposition::LocalPlaybackDrained),
    )?;
    Ok(())
}

#[cfg(not(feature = "voice"))]
fn speak_and_play(
    _routed: &Routed,
    _daemon: &str,
    _channel: &str,
    _text: &str,
    _out: &Path,
    _synthesizer: &Synthesizer,
    _output: &mut Out<'_>,
) -> Result<Spoken> {
    bail!(
        "voice was built without the `voice` feature — rebuild with \
         `cargo build --release --features voice --bin voice` (pulls mary's \
         Qwen3-TTS Burn voice pipeline). Routing (`voice route`/`voice devices`) \
         and the text-fallback path work without it."
    );
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

#[derive(Clone, Debug)]
pub struct RouteReport {
    pub devices: Vec<AudioDevice>,
    pub daemon_up: bool,
    pub routes: Vec<(super::RoutePolicy, Routed)>,
}
impl RouteReport {
    pub fn emit(&self, out: &mut Out<'_>) -> Result<()> {
        out.line(format!(
            "Reachy daemon: {}",
            if self.daemon_up { "reachable" } else { "down" }
        ))?;
        out.line("")?;
        out.line("connected output devices:")?;
        for device in &self.devices {
            out.line(format!("  {}", describe_device(device)))?;
        }
        out.line("")?;
        for (policy, routed) in &self.routes {
            out.line(format!(
                "{} policy (priority order): {}",
                policy.channel.name(),
                policy.devices.join(" → ")
            ))?;
            out.line(format!("  would route to: {}", routed.describe()))?;
        }
        Ok(())
    }
}
pub fn describe_device(device: &AudioDevice) -> String {
    format!(
        "{:<28} {}{}",
        device.name,
        device.class().label(),
        if device.is_default_output {
            "  [default output]"
        } else {
            ""
        }
    )
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpeechDisposition {
    DryRun,
    TextFallback,
    /// The native queue drained and its device-buffer flush delay elapsed.
    /// This is not evidence that a listener heard it.
    LocalPlaybackDrained,
    /// Reachy accepted upload/play_sound; physical completion is not observed.
    ReachyRequestAccepted,
}
#[derive(Clone, Debug)]
pub struct SpeechReceipt {
    pub route: Routed,
    pub disposition: SpeechDisposition,
    pub utterance: Option<triblespace::prelude::Id>,
}
impl SpeechReceipt {
    pub fn emit(&self, channel: Channel, out: &mut Out<'_>) -> Result<()> {
        if self.disposition == SpeechDisposition::ReachyRequestAccepted {
            out.line("  Reachy accepted the playback request; completion was not observed")?;
        }
        if let Some(id) = self.utterance {
            out.line(format!("  logged utterance {:x} [{}]", id, channel.name()))?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct Device {
    pub voice: Voice,
    pub daemon: String,
    pub synthesizer: Synthesizer,
}
impl Device {
    pub fn new(voice: Voice, daemon: String, synthesizer: Synthesizer) -> Self {
        Self {
            voice,
            daemon,
            synthesizer,
        }
    }
    pub fn routes(&self) -> Result<RouteReport> {
        let policies = self.voice.routes()?;
        let devices = detect_output_devices()?;
        let daemon_up = reachy_reachable(&self.daemon);
        let routes = policies
            .into_iter()
            .map(|policy| {
                let routed = match policy.channel {
                    Channel::Say => route_say(&policy.devices, &devices),
                    Channel::Shout => route_shout(&policy.devices, &devices, daemon_up),
                };
                (policy, routed)
            })
            .collect();
        Ok(RouteReport {
            devices,
            daemon_up,
            routes,
        })
    }
    /// Explicit host speech. Output acceptance never means audio was played;
    /// the returned disposition names the actual outcome, and errors are never
    /// retried. Routing/storage snapshots close before model/device acquisition.
    pub fn speak(
        &self,
        channel: Channel,
        text: &str,
        dry_run: bool,
        pause_file: Option<&Path>,
        out: &mut Out<'_>,
    ) -> Result<SpeechReceipt> {
        super::operations::validate_text(text)?;
        let prefs = self.voice.route(channel)?;
        let devices = detect_output_devices()?;
        let routed = match channel {
            Channel::Say => route_say(&prefs, &devices),
            Channel::Shout => route_shout(&prefs, &devices, reachy_reachable(&self.daemon)),
        };
        out.line(format!("[{}] → {}", channel.name(), routed.describe()))?;
        if dry_run {
            return Ok(SpeechReceipt {
                route: routed,
                disposition: SpeechDisposition::DryRun,
                utterance: None,
            });
        }
        if matches!(routed, Routed::Text(_)) {
            out.line(text)?;
            let utterance = self.voice.record(channel, text, None, "voice spoke")?;
            return Ok(SpeechReceipt {
                route: routed,
                disposition: SpeechDisposition::TextFallback,
                utterance: Some(utterance),
            });
        }
        if let Some(path) = pause_file {
            out.line(format!("  [half-duplex] holding {}", path.display()))?;
        }
        let _pause = pause_file.map(crate::turntaking::PauseGuard::hold);
        let path = unique_voice_tmp()?;
        let outcome = speak_and_play(
            &routed,
            &self.daemon,
            channel.name(),
            text,
            &path,
            &self.synthesizer,
            out,
        );
        match outcome {
            Err(error) => {
                let _ = std::fs::remove_file(&path);
                // Generation may already have produced audible chunks. Preserve
                // the words as failure evidence, but never claim complete audio.
                if let Err(log_error) = self.voice.record(
                    channel,
                    text,
                    None,
                    "voice spoke (synthesis or WAV retention FAILED; text-only, no complete audio)",
                ) {
                    return Err(error.context(format!(
                        "recording failed utterance also failed: {log_error:#}"
                    )));
                }
                Err(error)
            }
            Ok(outcome) => {
                let bytes = std::fs::read(&path)
                    .with_context(|| format!("read generated WAV {}", path.display()));
                let _ = std::fs::remove_file(&path);
                let logged = bytes
                    .and_then(|bytes| self.voice.record(channel, text, Some(bytes), "voice spoke"));
                match outcome {
                    Spoken::PlaybackFailed(error) => {
                        if channel == Channel::Say {
                            // Never redirect the private fallback into a speaker.
                            if let Err(emission) = out.line(text) {
                                return Err(error.context(format!("private text fallback failed: {emission:#}; recording: {logged:?}")));
                            }
                        }
                        match logged {
                            Ok(id) => {
                                Err(error.context(format!("audio retained as utterance {id:x}")))
                            }
                            Err(log_error) => Err(error.context(format!(
                                "recording synthesized audio also failed: {log_error:#}"
                            ))),
                        }
                    }
                    Spoken::ReportingFailed(error) => Err(match logged {
                        Ok(id) => error.context(format!("audio retained as utterance {id:x}")),
                        Err(log_error) => error.context(format!(
                            "recording synthesized audio also failed: {log_error:#}"
                        )),
                    }),
                    Spoken::Played(disposition) => Ok(SpeechReceipt {
                        route: routed,
                        disposition,
                        // Playback happened before this already-completed
                        // retention attempt. Never lose that fact or replay it.
                        utterance: Some(retain_after_playback(disposition, logged)?),
                    }),
                }
            }
        }
    }
}
