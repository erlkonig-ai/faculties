//! Half-duplex turn-taking: the three things that stop a spoken loop hearing
//! itself.
//!
//! Extracted from the `converse` bridge (deleted 2026-08-27) so the knowledge
//! outlives the binary that carried it. `converse` chained an ear process, a
//! brain process and a mouth process by tailing a jsonl file; that chain is
//! gone, but the three guards it grew are not optional and are not obvious,
//! and every one of them was learned by listening to a robot talk to itself.
//!
//! The pieces are deliberately separate from any device, model or transport:
//! the MOUTH holds a [`PauseGuard`] for the whole time it makes sound, the
//! EARS check [`paused`] before keeping audio and run every finished utterance
//! past [`drop_reason`]. Two processes, one file, no shared memory.
//!
//! # THE RULE THIS MODULE EXISTS TO KEEP
//!
//! **NEVER CLOSE THE MICROPHONE STREAM.** Closing a Bluetooth mic flips the
//! endpoint between its handsfree and high-quality profiles and chops speech
//! mid-sentence. Turn-taking is gated in SOFTWARE ONLY: while the pause file
//! exists the ears keep reading frames and DISCARD them. The hold stops the
//! model, never the person — a human can talk over a hold and the stream is
//! still there when the hold lifts. Anything here that looks like it wants to
//! stop capture wants to drop samples instead.
//!
//! Two neighbouring rules, quoted because the code that keeps them is one step
//! away in either direction:
//!
//! **DEVICES BY NAME, NEVER BY INDEX, NEVER THE SYSTEM DEFAULT.** A Bluetooth
//! connect silently renumbers CoreAudio and an index-addressed stream lands on
//! a dead virtual channel at -91 dB with nothing in the logs. Opening the
//! named device IS the verification. (`voice` opens its sink by name;
//! `soma-client` inherits Soma's single named capture.)
//!
//! **THE SAY-PRIVACY INVARIANT LIVES IN CODE, NOT CONFIG.** There is no path
//! from `voice say` to a room speaker — see `route_say` in the `voice`
//! faculty. Nothing in this module routes audio, and if a sink is ever
//! repointed the invariant must be enforced at the NEW owner BEFORE the
//! repoint, or a private utterance lands in the room.

use std::path::{Path, PathBuf};

/// Grace after speech ends during which an overlapping utterance is still
/// treated as self-echo, in milliseconds. Measured default from `converse`.
pub const DEFAULT_BARGE_GRACE_MS: u64 = 500;
/// Slack BEFORE the speech window starts, in milliseconds — the mouth's own
/// first samples reach the mic slightly before the process notes the time.
pub const PRE_SPEECH_SLACK_MS: u64 = 250;

// ---------------------------------------------------------------------------
// 1. The pause-file protocol (the mouth's side, and the ears' check)
// ---------------------------------------------------------------------------

/// Holds the half-duplex pause file for a scope. The MOUTH creates it before
/// it makes any sound and removal is the `Drop`, so the ears always resume —
/// even on a panic or an error path, which is the whole reason this is a guard
/// and not two calls.
///
/// A stale pause file permanently deafens the ears, so the listening side
/// clears one at startup ([`clear_stale`]) rather than trusting the last run
/// to have exited cleanly.
pub struct PauseGuard {
    path: PathBuf,
    created: bool,
}

impl PauseGuard {
    /// Create the pause file, naming the holding process inside it. A failure
    /// to create is reported and NOT fatal: half-duplex degrades to "the ears
    /// may hear us", never to "we refuse to speak".
    pub fn hold(path: &Path) -> Self {
        let created = std::fs::write(path, format!("speaking, pid {}\n", std::process::id())).is_ok();
        if !created {
            eprintln!(
                "warning: could not create pause file {} — the ears may hear this utterance",
                path.display()
            );
        }
        Self {
            path: path.to_path_buf(),
            created,
        }
    }

    /// Whether the file is actually being held (creation succeeded).
    pub fn held(&self) -> bool {
        self.created
    }
}

impl Drop for PauseGuard {
    fn drop(&mut self) {
        if self.created {
            std::fs::remove_file(&self.path).ok();
        }
    }
}

/// The EARS' side of the protocol: is the mouth speaking right now?
///
/// While this is true the listener DROPS incoming audio and abandons any open
/// utterance as presumed self-echo. It does not stop capturing. See the module
/// rule.
pub fn paused(path: &Path) -> bool {
    path.exists()
}

/// Clear a pause file left behind by a crashed speaker. Returns whether one
/// was removed, so the caller can say so — a silently deaf loop is the worst
/// failure this whole module has.
pub fn clear_stale(path: &Path) -> bool {
    if path.exists() {
        std::fs::remove_file(path).ok();
        true
    } else {
        false
    }
}

/// The conventional pause-file path beside a log: `<log>.pause`.
pub fn default_pause_path(log: &Path) -> PathBuf {
    PathBuf::from(format!("{}.pause", log.display()))
}

// ---------------------------------------------------------------------------
// 2. The barge-in / self-echo overlap heuristic
// ---------------------------------------------------------------------------

/// The wall-clock window (unix ms) during which the mouth was making sound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpeechWindow {
    pub start_ms: u64,
    pub end_ms: u64,
}

impl SpeechWindow {
    /// Belt-and-braces against the pause file: an utterance STAMPED inside our
    /// own speech window is presumed self-echo, whatever the pause file did.
    /// The two guards fail differently — the pause file misses audio already
    /// buffered when the mouth opened, and a timestamp misses a clock skew —
    /// so keeping both is not redundancy, it is coverage.
    ///
    /// This is a v0 stub in one specific sense: real barge-in would kill the
    /// speaking child and YIELD THE FLOOR here rather than discard the human.
    /// On-chip AEC in the mic array is the full-duplex upgrade path and needs
    /// no change to this seam.
    pub fn overlaps(&self, utc_ms: u64, grace_ms: u64) -> bool {
        utc_ms >= self.start_ms.saturating_sub(PRE_SPEECH_SLACK_MS)
            && utc_ms <= self.end_ms + grace_ms
    }
}

// ---------------------------------------------------------------------------
// 3. The no-speech / prompt-parrot filter
// ---------------------------------------------------------------------------

/// Thresholds for [`drop_reason`]. Defaults are the values `converse` shipped
/// with, chosen from observed failures rather than taste.
#[derive(Debug, Clone, Copy)]
pub struct SpeechFilter {
    /// Drop transcripts with fewer characters than this.
    pub min_chars: usize,
    /// Drop segments shorter than this many seconds (VAD blips; 0.46 s ones
    /// were observed in the wild).
    pub min_dur_s: f64,
    /// Grace after speech ends during which an overlap is still self-echo.
    pub barge_grace_ms: u64,
}

impl Default for SpeechFilter {
    fn default() -> Self {
        Self {
            min_chars: 2,
            min_dur_s: 0.6,
            barge_grace_ms: DEFAULT_BARGE_GRACE_MS,
        }
    }
}

/// One utterance as the filter sees it.
#[derive(Debug, Clone, Copy)]
pub struct Utterance<'a> {
    /// The transcript.
    pub text: &'a str,
    /// The prompt the hear path was given for THIS utterance.
    pub prompt: &'a str,
    /// Wall-clock stamp of the utterance, unix ms (0 = unknown).
    pub utc_ms: u64,
    /// Segment duration in seconds (0.0 = unknown).
    pub dur_s: f64,
}

/// Why this utterance must not reach the brain, or `None` to let it through.
///
/// THE PROMPT-PARROT CASE IS THE IMPORTANT ONE, and it is the reason this
/// function exists at all. On empty or AEC-suppressed audio the hear path
/// PARROTS ITS OWN PROMPT back as the transcript (`text == "Transcribe exactly
/// what is being said."`). Without this check a silent room makes the bot say
/// its own instructions aloud, over and over, and it sounds exactly like a
/// model that has lost its mind. The substring form only fires for prompts of
/// at least 12 characters: a short prompt would false-positive on ordinary
/// speech.
pub fn drop_reason(
    u: &Utterance<'_>,
    f: &SpeechFilter,
    spoke: Option<SpeechWindow>,
) -> Option<&'static str> {
    let text = u.text.trim();
    let prompt = u.prompt.trim();
    if text.chars().count() < f.min_chars {
        return Some("too-short-text");
    }
    if !prompt.is_empty()
        && (text == prompt || (prompt.chars().count() >= 12 && text.contains(prompt)))
    {
        return Some("prompt-parrot (no speech)");
    }
    audio_drop_reason(u.dur_s, u.utc_ms, f, spoke)
}

/// The half of [`drop_reason`] that can be decided BEFORE a transcript exists:
/// VAD blips and self-echo overlap.
///
/// A consumer that hands over EMBEDDINGS never produces a transcript, so it
/// never sees a parroted prompt -- but it still has to drop blips and its own
/// voice, and it wants to drop them before paying for the audio tower. Callers
/// that transcribe reach this through [`drop_reason`], which adds the two
/// text-only checks in front.
pub fn audio_drop_reason(
    dur_s: f64,
    utc_ms: u64,
    f: &SpeechFilter,
    spoke: Option<SpeechWindow>,
) -> Option<&'static str> {
    if dur_s > 0.0 && dur_s < f.min_dur_s {
        return Some("too-short-segment");
    }
    if let Some(window) = spoke {
        if window.overlaps(utc_ms, f.barge_grace_ms) {
            return Some("barge-in stub: overlapped our speech, presumed self-echo");
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROMPT: &str = "Transcribe exactly what is being said.";

    fn utt<'a>(text: &'a str, dur_s: f64, utc_ms: u64) -> Utterance<'a> {
        Utterance {
            text,
            prompt: PROMPT,
            utc_ms,
            dur_s,
        }
    }

    #[test]
    fn parroted_prompt_is_not_speech() {
        let f = SpeechFilter::default();
        // The exact observed failure: empty/AEC-suppressed audio comes back as
        // the prompt itself, and without this the bot speaks its own
        // instructions into the room.
        assert_eq!(
            drop_reason(&utt(PROMPT, 2.0, 0), &f, None),
            Some("prompt-parrot (no speech)")
        );
        // ...and the padded/embedded form.
        assert_eq!(
            drop_reason(
                &utt(&format!("  {PROMPT}  "), 2.0, 0),
                &f,
                None
            ),
            Some("prompt-parrot (no speech)")
        );
        assert_eq!(
            drop_reason(&utt(&format!("uh {PROMPT}"), 2.0, 0), &f, None),
            Some("prompt-parrot (no speech)")
        );
        // Real speech survives.
        assert_eq!(drop_reason(&utt("what is the weather", 2.0, 0), &f, None), None);
    }

    #[test]
    fn a_short_prompt_never_swallows_ordinary_speech() {
        let f = SpeechFilter::default();
        let short = Utterance {
            text: "yes, tell me more about it",
            prompt: "yes",
            utc_ms: 0,
            dur_s: 2.0,
        };
        // Substring matching is gated at 12 chars precisely so this passes.
        assert_eq!(drop_reason(&short, &f, None), None);
        let echoed = Utterance {
            text: "yes",
            prompt: "yes",
            utc_ms: 0,
            dur_s: 2.0,
        };
        // The equality form still fires.
        assert_eq!(drop_reason(&echoed, &f, None), Some("prompt-parrot (no speech)"));
    }

    #[test]
    fn vad_blips_and_empty_transcripts_are_dropped() {
        let f = SpeechFilter::default();
        assert_eq!(drop_reason(&utt("", 2.0, 0), &f, None), Some("too-short-text"));
        assert_eq!(drop_reason(&utt("a", 2.0, 0), &f, None), Some("too-short-text"));
        // The 0.46 s blip that was actually observed.
        assert_eq!(
            drop_reason(&utt("hm", 0.46, 0), &f, None),
            Some("too-short-segment")
        );
        // Unknown duration must not be treated as zero.
        assert_eq!(drop_reason(&utt("hello there", 0.0, 0), &f, None), None);
    }

    #[test]
    fn overlap_with_our_own_speech_is_self_echo() {
        let f = SpeechFilter::default();
        let window = SpeechWindow {
            start_ms: 10_000,
            end_ms: 12_000,
        };
        let echo = drop_reason(&utt("hello there", 2.0, 11_000), &f, Some(window));
        assert_eq!(
            echo,
            Some("barge-in stub: overlapped our speech, presumed self-echo")
        );
        // The pre-speech slack: our first samples reach the mic before we
        // stamped the window open.
        assert!(window.overlaps(10_000 - PRE_SPEECH_SLACK_MS, f.barge_grace_ms));
        assert!(!window.overlaps(10_000 - PRE_SPEECH_SLACK_MS - 1, f.barge_grace_ms));
        // The trailing grace, and just past it.
        assert!(window.overlaps(12_000 + f.barge_grace_ms, f.barge_grace_ms));
        assert!(!window.overlaps(12_000 + f.barge_grace_ms + 1, f.barge_grace_ms));
        // After the grace the human gets the floor back.
        assert_eq!(
            drop_reason(&utt("hello there", 2.0, 13_000), &f, Some(window)),
            None
        );
    }

    #[test]
    fn the_audio_only_stage_stands_alone_for_an_embedding_consumer() {
        let f = SpeechFilter::default();
        let window = SpeechWindow {
            start_ms: 10_000,
            end_ms: 12_000,
        };
        // No transcript exists yet: blips and self-echo are still catchable,
        // and are caught BEFORE the audio tower is paid for.
        assert_eq!(
            audio_drop_reason(0.46, 0, &f, None),
            Some("too-short-segment")
        );
        assert_eq!(
            audio_drop_reason(2.0, 11_000, &f, Some(window)),
            Some("barge-in stub: overlapped our speech, presumed self-echo")
        );
        assert_eq!(audio_drop_reason(2.0, 13_000, &f, Some(window)), None);
        // An empty transcript must not be mistaken for "too short" when the
        // consumer never asked for one.
        assert_eq!(audio_drop_reason(2.0, 0, &f, None), None);
    }

    #[test]
    fn the_pause_file_is_held_for_a_scope_and_always_released() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ears.pause");
        assert!(!paused(&path));
        {
            let guard = PauseGuard::hold(&path);
            assert!(guard.held());
            assert!(paused(&path), "the ears must see the hold while we speak");
        }
        assert!(!paused(&path), "the ears must always resume");

        // Even when the speaking scope unwinds.
        let unwound = std::panic::catch_unwind(|| {
            let _guard = PauseGuard::hold(&path);
            panic!("synthesis exploded mid-utterance");
        });
        assert!(unwound.is_err());
        assert!(
            !paused(&path),
            "a crash mid-utterance must not deafen the ears forever"
        );
    }

    #[test]
    fn a_stale_pause_file_is_cleared_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ears.pause");
        std::fs::write(&path, "speaking, pid 1\n").unwrap();
        assert!(clear_stale(&path));
        assert!(!paused(&path));
        assert!(!clear_stale(&path));
    }

    #[test]
    fn default_pause_path_sits_beside_the_log() {
        assert_eq!(
            default_pause_path(Path::new("/tmp/ears.jsonl")),
            PathBuf::from("/tmp/ears.jsonl.pause")
        );
    }
}
