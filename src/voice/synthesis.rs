//! One streaming Qwen3-TTS source, drained either into resident audio or a host sink.
use anybytes::Bytes;
use anyhow::{ensure, Context, Result};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct ModelSources {
    pub pile: PathBuf,
    pub reference_wav: PathBuf,
    pub reference_text: PathBuf,
    pub reference_codes: PathBuf,
    #[cfg(feature = "voice")]
    pub variant: mary::speak::Qwen3TtsVariant,
}
impl ModelSources {
    /// Capture launcher configuration without opening any file or device.
    pub fn from_environment() -> Self {
        let directory = crate::model_dir();
        Self {
            pile: std::env::var_os("QWEN3TTS_PILE")
                .map(PathBuf::from)
                .unwrap_or_else(|| directory.join("qwen3tts.pile")),
            reference_wav: directory.join("ref_voice_v2_24k.wav"),
            reference_text: directory.join("ref_voice_v2.txt"),
            reference_codes: directory.join("ref_voice_v2_code.npy"),
            #[cfg(feature = "voice")]
            variant: mary::speak::Qwen3TtsVariant::from_env(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct AudioClip {
    pub wav: Bytes,
    pub sample_rate: u32,
    pub sample_count: usize,
}
impl AudioClip {
    /// PCM16 conversion matches Mary's existing WAV writer, but carries bytes
    /// instead of writing an implicit temporary file. Invalid frames fail first.
    pub fn from_samples(samples: &[f32], sample_rate: u32) -> Result<Self> {
        ensure!(!samples.is_empty(), "synthesis returned no audio samples");
        ensure!(
            sample_rate > 0 && sample_rate <= u32::MAX / 2,
            "invalid PCM sample rate"
        );
        ensure!(
            samples.iter().all(|sample| sample.is_finite()),
            "synthesis returned a non-finite sample"
        );
        let data_len = samples
            .len()
            .checked_mul(2)
            .and_then(|size| u32::try_from(size).ok())
            .filter(|size| *size <= u32::MAX - 36)
            .context("PCM clip exceeds RIFF/WAV size limit")?;
        let mut wav = Vec::with_capacity(44 + data_len as usize);
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&(36 + data_len).to_le_bytes());
        wav.extend_from_slice(b"WAVEfmt ");
        wav.extend_from_slice(&16_u32.to_le_bytes());
        wav.extend_from_slice(&1_u16.to_le_bytes());
        wav.extend_from_slice(&1_u16.to_le_bytes());
        wav.extend_from_slice(&sample_rate.to_le_bytes());
        wav.extend_from_slice(&(sample_rate * 2).to_le_bytes());
        wav.extend_from_slice(&2_u16.to_le_bytes());
        wav.extend_from_slice(&16_u16.to_le_bytes());
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&data_len.to_le_bytes());
        for sample in samples {
            wav.extend_from_slice(&((sample.clamp(-1.0, 1.0) * 32767.0) as i16).to_le_bytes());
        }
        Ok(Self {
            wav: wav.into(),
            sample_rate,
            sample_count: samples.len(),
        })
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        std::fs::write(path, self.wav.as_ref())
            .with_context(|| format!("write WAV to {}", path.display()))
    }
    pub fn duration_seconds(&self) -> f64 {
        self.sample_count as f64 / f64::from(self.sample_rate)
    }
}

#[derive(Clone, Debug)]
pub struct Synthesizer {
    pub sources: ModelSources,
}
impl Synthesizer {
    pub fn new(sources: ModelSources) -> Self {
        Self { sources }
    }
    /// Finite audio synthesis only. Never enumerates, selects, or plays devices,
    /// creates a pause file, writes a journal, or saves audio on the host.
    pub fn synthesize(&self, text: &str) -> Result<AudioClip> {
        super::operations::validate_text(text)?;
        #[cfg(not(feature = "voice"))]
        anyhow::bail!("speech synthesis requires a build with the `voice` feature");
        #[cfg(feature = "voice")]
        {
            let PreparedSpeech {
                mut stream,
                sample_rate,
                ..
            } = self.start(text)?;
            let mut samples = Vec::new();
            for chunk in stream.by_ref() {
                samples.extend_from_slice(&chunk);
            }
            stream.finish()?;
            AudioClip::from_samples(&samples, sample_rate)
        }
    }
    #[cfg(feature = "voice")]
    pub(super) fn start(&self, text: &str) -> Result<PreparedSpeech> {
        super::operations::validate_text(text)?;
        let ref_text = std::fs::read_to_string(&self.sources.reference_text)
            .context("read configured reference transcript")?;
        ensure!(!ref_text.trim().is_empty(), "reference transcript is empty");
        // Preflight the reference before Mary's infallible reader sees it.
        let reference =
            std::fs::read(&self.sources.reference_wav).context("read configured reference WAV")?;
        let (sample_count, sample_rate) = reference_metadata(&reference)?;
        preflight_reference_codes(&self.sources.reference_codes)?;
        let estimate = estimate_audio_secs(
            text.chars().count(),
            sample_count as f32 / sample_rate as f32,
            ref_text.trim().chars().count(),
        );
        let snapshot =
            mary::model_collection::load_model_collection_local_latest(&self.sources.pile)
                .with_context(|| {
                    format!(
                        "freeze native Qwen3-TTS collection {}",
                        self.sources.pile.display()
                    )
                })?;
        let weights = mary::speak::Qwen3TtsWeights::from_snapshot(snapshot, self.sources.variant)
            .context("select configured native Qwen3-TTS cohort")?;
        let started = std::time::Instant::now();
        let stream = mary::speak::synthesize_stream(
            weights,
            &self.sources.reference_wav,
            ref_text.trim(),
            &self.sources.reference_codes,
            text,
        )?;
        Ok(PreparedSpeech {
            stream,
            sample_rate: mary::speak::SpeakStream::SAMPLE_RATE,
            estimated_seconds: estimate,
            started,
        })
    }
}
#[cfg(feature = "voice")]
pub(super) struct PreparedSpeech {
    pub stream: mary::speak::SpeakStream,
    pub sample_rate: u32,
    pub estimated_seconds: f32,
    pub started: std::time::Instant,
}

/// Inspect the 24 kHz mono PCM16 reference shape required by Mary's speech
/// pipeline. Complete chunk lengths are checked before offsets are dereferenced.
#[cfg_attr(not(feature = "voice"), allow(dead_code))]
fn reference_metadata(bytes: &[u8]) -> Result<(usize, u32)> {
    ensure!(
        bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WAVE",
        "reference must be a RIFF/WAVE file"
    );
    let declared = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    ensure!(
        declared
            .checked_add(8)
            .is_some_and(|end| end == bytes.len()),
        "reference RIFF length does not match its bytes"
    );
    let mut offset = 12_usize;
    let mut rate = None;
    let mut samples = None;
    while offset < bytes.len() {
        let header = bytes
            .get(offset..offset + 8)
            .context("truncated WAV chunk header")?;
        let length = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        let body_start = offset + 8;
        let end = body_start
            .checked_add(length)
            .context("WAV chunk length overflow")?;
        let body = bytes
            .get(body_start..end)
            .context("truncated WAV chunk body")?;
        match &header[..4] {
            b"fmt " => {
                ensure!(body.len() >= 16, "truncated WAV format");
                ensure!(
                    u16::from_le_bytes(body[..2].try_into().unwrap()) == 1
                        && u16::from_le_bytes(body[2..4].try_into().unwrap()) == 1
                        && u16::from_le_bytes(body[14..16].try_into().unwrap()) == 16,
                    "reference must be mono PCM16"
                );
                let value = u32::from_le_bytes(body[4..8].try_into().unwrap());
                ensure!(
                    value == 24_000,
                    "reference clip must be 24 kHz mono PCM16 (got {value} Hz)"
                );
                rate = Some(value);
            }
            b"data" => {
                ensure!(rate.is_some(), "WAV format must precede reference samples");
                ensure!(
                    length > 0 && length % 2 == 0,
                    "reference samples are empty or incomplete"
                );
                samples = Some(length / 2);
            }
            _ => {}
        }
        offset = end
            .checked_add(length & 1)
            .context("WAV padding overflow")?;
        ensure!(offset <= bytes.len(), "truncated WAV chunk padding");
    }
    Ok((
        samples.context("reference has no data chunk")?,
        rate.context("reference has no format chunk")?,
    ))
}

/// Reuse Mary's CPU decoder before model acquisition. Its ordinary assertions
/// become a fixed error here; normal I/O errors keep their original cause.
/// This does not recover abort/OOM or validate new numeric code semantics.
/// Mary later reopens this path, so the launcher must keep the reference kit
/// stable throughout synthesis; preflight does not freeze those host files.
#[cfg(feature = "voice")]
fn preflight_reference_codes(path: &Path) -> Result<()> {
    use mary::models::qwen3tts::config::NUM_CODE_GROUPS;
    let (data, shape) = std::panic::catch_unwind(|| mary::nn::npy::load_npy(path))
        .map_err(|_| {
            anyhow::anyhow!("configured reference codec cache decoder rejected its input")
        })?
        .with_context(|| format!("read configured reference codec cache {}", path.display()))?;
    ensure!(
        shape.len() == 2 && shape[0] > 0 && shape[1] == NUM_CODE_GROUPS,
        "reference codes must have nonempty shape (T, {NUM_CODE_GROUPS}), got {shape:?}"
    );
    let expected = shape[0]
        .checked_mul(NUM_CODE_GROUPS)
        .context("reference code dimensions overflow")?;
    ensure!(
        data.len() == expected,
        "reference code shape needs {expected} values, decoded {}",
        data.len()
    );
    Ok(())
}

/// Estimate an utterance's total audio duration from its character count,
/// calibrated by the reference kit: assume the generated speech runs at the
/// reference clip's chars-per-second. This is the same linear chars→duration
/// model mary's batch F5 path uses to size its mel window
/// (`say::synth_chunk`: `duration = ref_len / ref_chars * gen_chars`). It is
/// an ESTIMATE — the underrun guard in `stream_to_device` catches the cases
/// where reality runs longer.
#[cfg_attr(not(feature = "voice"), allow(dead_code))]
pub(super) fn estimate_audio_secs(gen_chars: usize, ref_secs: f32, ref_chars: usize) -> f32 {
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
pub(super) fn prebuffer_target_secs(total_est_secs: f32, production_rate: f32) -> f32 {
    const MARGIN_SECS: f32 = 0.5;
    const FLOOR_SECS: f32 = 0.15;
    let deficit = total_est_secs * (1.0 - production_rate).max(0.0);
    (deficit + MARGIN_SECS).max(FLOOR_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resident_pcm_matches_existing_header_and_clamps_finite_samples() {
        let audio = AudioClip::from_samples(&[-2.0, 0.0, 2.0], 24_000).unwrap();
        assert_eq!(reference_metadata(audio.wav.as_ref()).unwrap(), (3, 24_000));
        assert_eq!(&audio.wav.as_ref()[44..], &[1, 128, 0, 0, 255, 127]);
        assert!(AudioClip::from_samples(&[f32::NAN], 24_000).is_err());
        assert!(AudioClip::from_samples(&[], 24_000).is_err());
        assert!(AudioClip::from_samples(&[0.0], 0).is_err());
    }
    #[test]
    fn malformed_reference_is_rejected_without_panicking() {
        let audio = AudioClip::from_samples(&[0.0; 8], 24_000).unwrap();
        for length in 0..audio.wav.len() {
            assert!(reference_metadata(&audio.wav.as_ref()[..length]).is_err());
        }
        let mut stereo = audio.wav.as_ref().to_vec();
        stereo[22] = 2;
        assert!(reference_metadata(&stereo).is_err());
    }

    #[test]
    fn reference_requires_24_khz_before_model_acquisition() {
        for rate in [16_000, 22_050, 44_100, 48_000] {
            let audio = AudioClip::from_samples(&[0.0; 8], rate).unwrap();
            let error = reference_metadata(audio.wav.as_ref()).unwrap_err();
            assert!(error.to_string().contains("24 kHz"));
        }
        let audio = AudioClip::from_samples(&[0.0; 8], 24_000).unwrap();
        assert_eq!(reference_metadata(audio.wav.as_ref()).unwrap(), (8, 24_000));
    }

    #[test]
    #[cfg(feature = "voice")]
    fn reference_code_preflight_reuses_mary_decoder_without_loading_a_model() {
        use mary::models::qwen3tts::config::NUM_CODE_GROUPS;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("reference.npy");
        let missing = preflight_reference_codes(&path).unwrap_err();
        assert_eq!(
            missing.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound,
        );
        mary::nn::npy::save_npy(
            &path,
            &vec![0.0; 2 * NUM_CODE_GROUPS],
            &[2, NUM_CODE_GROUPS],
        )
        .unwrap();
        preflight_reference_codes(&path).unwrap();
        for (data, shape) in [
            (Vec::new(), vec![0, NUM_CODE_GROUPS]),
            (vec![0.0; NUM_CODE_GROUPS], vec![NUM_CODE_GROUPS]),
            (vec![0.0; NUM_CODE_GROUPS - 1], vec![1, NUM_CODE_GROUPS]),
            (vec![0.0; NUM_CODE_GROUPS], vec![1, NUM_CODE_GROUPS - 1]),
        ] {
            mary::nn::npy::save_npy(&path, &data, &shape).unwrap();
            assert!(preflight_reference_codes(&path).is_err());
        }
        // Exercise the existing decoder's magic assertion, not a copied parser.
        std::fs::write(&path, b"not-an-npy-file").unwrap();
        let error = preflight_reference_codes(&path).unwrap_err();
        assert!(error.to_string().contains("decoder rejected"));
    }
}
