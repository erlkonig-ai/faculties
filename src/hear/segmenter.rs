//! The existing rate-local VAD; no transport, device, model, or file input.

#[derive(Clone, Debug)]
pub(super) struct VadConfig {
    frame_ms: usize,
    start_frames: usize,
    hangover_ms: usize,
    min_utt_ms: usize,
    max_utt_s: f32,
    ratio: f32,
    abs_floor: f32,
    preroll_ms: usize,
}

impl Default for VadConfig {
    fn default() -> Self {
        VadConfig {
            frame_ms: 20,
            start_frames: 3,
            hangover_ms: 700,
            min_utt_ms: 300,
            // Stay inside the feature extractor's 30 s window.
            max_utt_s: 28.0,
            ratio: 3.5,
            abs_floor: 0.008,
            preroll_ms: 240,
        }
    }
}

/// A finished utterance at the segmenter's native rate.
pub(super) struct Segment {
    pub(super) samples: Vec<f32>,
    /// Sample rate of `samples` — the rate the segmenter ran at, which is the
    /// capture rate live and 16 kHz for recorded clips.
    pub(super) rate: usize,
    pub(super) start_s: f64,
    pub(super) end_s: f64,
}

impl Segment {
    pub(super) fn dur_s(&self) -> f64 {
        self.end_s - self.start_s
    }
}

/// Streaming energy-VAD segmenter. Feed arbitrary-size mono chunks at a fixed
/// rate; complete utterances go to `emit`. The SAME code path serves the live
/// capture and recorded files, which is what makes `hear once` a real gate.
pub(super) struct Segmenter {
    cfg: VadConfig,
    rate: usize,
    frame: usize,
    pending: Vec<f32>,
    preroll: std::collections::VecDeque<f32>,
    preroll_cap: usize,
    noise_floor: f32,
    floor_warm: usize,
    in_speech: bool,
    speech_run: usize,
    silence_run: usize,
    current: Vec<f32>,
    utt_start_sample: u64,
    samples_seen: u64,
}

impl Segmenter {
    pub(super) fn new(rate: usize, cfg: VadConfig) -> Self {
        let frame = rate * cfg.frame_ms / 1000;
        let preroll_cap = rate * cfg.preroll_ms / 1000;
        Segmenter {
            cfg,
            rate,
            frame,
            pending: Vec::new(),
            preroll: std::collections::VecDeque::with_capacity(preroll_cap),
            preroll_cap,
            noise_floor: 0.0,
            floor_warm: 0,
            in_speech: false,
            speech_run: 0,
            silence_run: 0,
            current: Vec::new(),
            utt_start_sample: 0,
            samples_seen: 0,
        }
    }

    pub(super) fn push(&mut self, chunk: &[f32], emit: &mut impl FnMut(Segment)) {
        self.pending.extend_from_slice(chunk);
        while self.pending.len() >= self.frame {
            let frame: Vec<f32> = self.pending.drain(..self.frame).collect();
            self.frame_in(&frame, emit);
        }
    }

    /// End of stream/file: close any open utterance.
    pub(super) fn flush(&mut self, emit: &mut impl FnMut(Segment)) {
        if !self.pending.is_empty() {
            let rest = std::mem::take(&mut self.pending);
            if self.in_speech {
                self.current.extend_from_slice(&rest);
                self.samples_seen += rest.len() as u64;
            }
        }
        if self.in_speech {
            self.close(emit);
        }
    }

    /// Half-duplex pause: the mouth is speaking, so `n` incoming samples are
    /// DROPPED — not un-captured. Any open utterance is abandoned (it would be
    /// self-echo), the speech state clears, the adaptive noise floor is KEPT
    /// (no re-warm-up on every reply), and the stream clock still advances so
    /// later timestamps stay stream-relative.
    pub(super) fn pause_skip(&mut self, n: u64) {
        self.pending.clear();
        self.preroll.clear();
        self.current.clear();
        self.in_speech = false;
        self.speech_run = 0;
        self.silence_run = 0;
        self.samples_seen += n;
    }

    fn frame_in(&mut self, frame: &[f32], emit: &mut impl FnMut(Segment)) {
        let rms = (frame.iter().map(|&x| x * x).sum::<f32>() / frame.len() as f32).sqrt();

        let warm_frames = 500 / self.cfg.frame_ms;
        if self.floor_warm < warm_frames {
            self.noise_floor = if self.floor_warm == 0 {
                rms
            } else {
                0.7 * self.noise_floor + 0.3 * rms
            };
            self.floor_warm += 1;
        } else if !self.in_speech && rms < self.noise_floor * 2.0 {
            self.noise_floor = 0.98 * self.noise_floor + 0.02 * rms;
        }

        let threshold = (self.noise_floor * self.cfg.ratio).max(self.cfg.abs_floor);
        let speech = rms > threshold;

        if !self.in_speech {
            for &s in frame {
                if self.preroll.len() == self.preroll_cap {
                    self.preroll.pop_front();
                }
                self.preroll.push_back(s);
            }
            if speech {
                self.speech_run += 1;
                if self.speech_run >= self.cfg.start_frames {
                    self.in_speech = true;
                    self.silence_run = 0;
                    self.current = self.preroll.iter().copied().collect();
                    self.utt_start_sample = (self.samples_seen + frame.len() as u64)
                        .saturating_sub(self.current.len() as u64);
                }
            } else {
                self.speech_run = 0;
            }
        } else {
            self.current.extend_from_slice(frame);
            if speech {
                self.silence_run = 0;
            } else {
                self.silence_run += 1;
                let hangover_frames = self.cfg.hangover_ms / self.cfg.frame_ms;
                if self.silence_run >= hangover_frames {
                    // Trim most of the hangover, keep a ~200 ms tail.
                    let keep_tail = self.rate * 200 / 1000;
                    let hang = self.silence_run * self.frame;
                    let cut = hang.saturating_sub(keep_tail).min(self.current.len());
                    let newlen = self.current.len() - cut;
                    self.current.truncate(newlen);
                    self.close(emit);
                }
            }
            if self.in_speech && self.current.len() as f32 >= self.cfg.max_utt_s * self.rate as f32
            {
                self.close(emit);
            }
        }
        self.samples_seen += frame.len() as u64;
    }

    fn close(&mut self, emit: &mut impl FnMut(Segment)) {
        let samples = std::mem::take(&mut self.current);
        self.in_speech = false;
        self.speech_run = 0;
        self.silence_run = 0;
        self.preroll.clear();
        let min_len = self.rate * self.cfg.min_utt_ms / 1000;
        if samples.len() >= min_len {
            let start_s = self.utt_start_sample as f64 / self.rate as f64;
            let end_s = start_s + samples.len() as f64 / self.rate as f64;
            emit(Segment {
                samples,
                rate: self.rate,
                start_s,
                end_s,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "hear")]
    use crate::hear::operations::to_hear_rate;
    use crate::hear::operations::{CAPTURE_RATE, HEAR_RATE};
    use crate::turntaking::{self, SpeechFilter};

    /// `secs` of a 220 Hz tone at `amp`, at the segmenter's rate.
    fn tone(secs: f32, amp: f32) -> Vec<f32> {
        let n = (HEAR_RATE as f32 * secs) as usize;
        (0..n)
            .map(|i| amp * (i as f32 * 2.0 * std::f32::consts::PI * 220.0 / HEAR_RATE as f32).sin())
            .collect()
    }

    fn silence(secs: f32) -> Vec<f32> {
        vec![0.0; (HEAR_RATE as f32 * secs) as usize]
    }

    fn segment_all(chunks: &[Vec<f32>]) -> Vec<Segment> {
        // Recorded clips are decoded straight to 16 kHz, so the segmenter runs
        // at the model's rate and no resample is needed at all.
        let mut segmenter = Segmenter::new(HEAR_RATE, VadConfig::default());
        let mut out = Vec::new();
        for chunk in chunks {
            segmenter.push(chunk, &mut |s| out.push(s));
        }
        segmenter.flush(&mut |s| out.push(s));
        out
    }

    #[test]
    fn two_bursts_separated_by_silence_are_two_utterances() {
        let segments = segment_all(&[
            silence(1.0),
            tone(1.2, 0.3),
            silence(1.2),
            tone(1.0, 0.3),
            silence(1.2),
        ]);
        assert_eq!(segments.len(), 2, "one utterance per burst");
        assert!(segments[0].dur_s() > 0.6, "{:?}", segments[0].dur_s());
        assert!(
            segments[1].start_s > segments[0].end_s,
            "utterance clocks must advance monotonically"
        );
        // Timestamps are stream-relative: the second burst starts around 3.4 s.
        assert!(
            (segments[1].start_s - 3.4).abs() < 0.5,
            "second utterance at {:.2}s",
            segments[1].start_s
        );
    }

    /// Why the filter's `min_dur_s` exists on TOP of the segmenter's
    /// `min_utt_ms`, and why its default is 0.6 s.
    ///
    /// The segmenter's own minimum measures the PADDED segment: 240 ms of
    /// pre-roll (so a soft onset is not clipped) plus the speech plus the
    /// ~200 ms hangover tail it keeps. A 50 ms click therefore comes out as
    /// roughly half a second of audio and sails past `min_utt_ms = 300`. That
    /// is the "sub-second blips trigger the VAD; 0.46 s ones observed" note
    /// `converse` shipped with -- 0.46 s is padding, not speech. The audio-only
    /// filter is what actually catches it, before the audio tower is paid for.
    #[test]
    fn a_click_survives_the_segmenter_and_is_caught_by_the_filter() {
        let segments = segment_all(&[silence(1.0), tone(0.05, 0.4), silence(1.2)]);
        assert_eq!(segments.len(), 1, "the segmenter does emit the padded blip");
        let dur = segments[0].dur_s();
        assert!(
            (0.3..0.6).contains(&dur),
            "a click comes out as padding-sized, got {dur:.2}s"
        );
        let filter = SpeechFilter::default();
        assert_eq!(
            turntaking::audio_drop_reason(dur, 0, &filter, None),
            Some("too-short-segment"),
            "{dur:.2}s must not reach the model"
        );
        // ...and real speech still gets through the same filter.
        let real = segment_all(&[silence(1.0), tone(1.2, 0.3), silence(1.2)]);
        assert_eq!(real.len(), 1);
        assert_eq!(
            turntaking::audio_drop_reason(real[0].dur_s(), 0, &filter, None),
            None
        );
    }

    /// The half-duplex hold, from the ears' side: audio that arrives while the
    /// mouth is speaking is DISCARDED, and the open utterance is abandoned as
    /// presumed self-echo. Nothing here closes a stream — the clock advances
    /// through the hold so later timestamps stay stream-relative.
    #[test]
    fn a_pause_discards_our_own_voice_without_stopping_the_clock() {
        // Recorded clips are decoded straight to 16 kHz, so the segmenter runs
        // at the model's rate and no resample is needed at all.
        let mut segmenter = Segmenter::new(HEAR_RATE, VadConfig::default());
        let mut heard = Vec::new();
        segmenter.push(&silence(1.0), &mut |s| heard.push(s));
        // Speech starts...
        segmenter.push(&tone(0.5, 0.3), &mut |s| heard.push(s));
        // ...and the mouth opens. Everything from here is our own voice.
        let held = tone(2.0, 0.3);
        segmenter.pause_skip(held.len() as u64);
        segmenter.push(&silence(1.2), &mut |s| heard.push(s));
        segmenter.flush(&mut |s| heard.push(s));
        assert!(
            heard.is_empty(),
            "self-echo must not reach the model: {} utterance(s)",
            heard.len()
        );

        // The stream clock still advanced across the hold, so the next real
        // utterance is stamped where it actually happened.
        segmenter.push(&tone(1.2, 0.3), &mut |s| heard.push(s));
        segmenter.push(&silence(1.2), &mut |s| heard.push(s));
        assert_eq!(heard.len(), 1);
        assert!(
            heard[0].start_s > 3.0,
            "clock must survive the hold, got {:.2}s",
            heard[0].start_s
        );
    }

    /// The live segmenter runs at the CAPTURE rate, so a Soma frame is a whole
    /// number of segmenter samples with nothing resampled on the hot path and
    /// nothing to drift. Only the finished utterance is resampled.
    #[test]
    fn the_capture_frame_and_the_segmenter_agree_on_the_clock() {
        assert_eq!(CAPTURE_RATE, soma_client::SAMPLE_RATE as usize);
        assert_eq!(
            soma_client::FRAME_SAMPLES as u32 * 1_000 / soma_client::SAMPLE_RATE,
            soma_client::FRAME_MS
        );
        // One capture frame advances the 20 ms VAD frame exactly four times.
        let cfg = VadConfig::default();
        let vad_frame = CAPTURE_RATE * cfg.frame_ms / 1000;
        assert_eq!(soma_client::FRAME_SAMPLES % vad_frame, 0);
        assert_eq!(soma_client::FRAME_SAMPLES / vad_frame, 4);
    }

    /// A capture-rate utterance is resampled ONCE, whole, and comes out the
    /// right length — the property a per-frame resample would break.
    #[test]
    #[cfg(feature = "hear")]
    fn a_finished_utterance_resamples_to_the_model_rate_in_one_piece() {
        let secs = 1.5f64;
        let at_capture: Vec<f32> = (0..(CAPTURE_RATE as f64 * secs) as usize)
            .map(|i| {
                (i as f32 * 2.0 * std::f32::consts::PI * 220.0 / CAPTURE_RATE as f32).sin() * 0.3
            })
            .collect();
        let at_model = to_hear_rate(&at_capture, CAPTURE_RATE).unwrap();
        let expected = (HEAR_RATE as f64 * secs) as usize;
        // MEASURED (2026-08-27, mary's `resample_to_16k`, 1.5 s at 24 kHz ->
        // 16 kHz): 23828 of an expected 24000, i.e. ~172 samples / ~11 ms
        // short. That is the resampler's own startup delay, which the helper
        // skips from the FRONT without extending the tail, so the loss lands
        // at the END of the utterance -- inside the VAD's ~200 ms hangover
        // tail, which is why it is harmless here. It is also constant per
        // CALL, which is the whole reason this runs once per utterance
        // instead of once per 80 ms frame: per frame it would be ~11 ms lost
        // out of every 80 ms.
        assert!(
            at_model.len() <= expected,
            "resampling must never invent audio: {} > {expected}",
            at_model.len()
        );
        assert!(
            expected - at_model.len() < 300,
            "{} samples, expected ~{expected} (startup-delay loss should stay \
             under ~20 ms)",
            at_model.len()
        );
        // Already at the model rate: an identity, not a round trip through the
        // resampler.
        let same = to_hear_rate(&at_model, HEAR_RATE).unwrap();
        assert_eq!(same, at_model);
    }
}
