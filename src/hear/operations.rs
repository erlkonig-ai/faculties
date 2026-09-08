//! Resident hearing operations. VAD, filters and model embeddings are shared
//! by finite recorded-clip calls and the CLI-only continuous Soma listener.
//! No host input paths, transcript files or output directories live here.

use super::segmenter::{Segment, Segmenter, VadConfig};
use crate::out::Out;
use crate::turntaking::{self, SpeechFilter, SpeechWindow};
use anybytes::Bytes;
use anyhow::{bail, Context, Result};
use std::path::PathBuf;

pub const HEAR_RATE: usize = 16_000;
pub(super) const CAPTURE_RATE: usize = soma_client::SAMPLE_RATE as usize;
pub const DEFAULT_PROMPT: &str = "Transcribe exactly what is being said.";
pub const DEFAULT_MODEL: &str = "google/gemma-4-E4B-it";

/// Trusted launcher configuration. Discovery never resolves or opens these
/// paths. Weights come from the pile; config/tokenizer are explicit local files.
#[derive(Clone, Debug)]
pub struct ModelConfig {
    pub pile: PathBuf,
    pub model: String,
    pub config_json: PathBuf,
    pub tokenizer_json: PathBuf,
}
#[derive(Clone, Debug)]
pub struct Options {
    pub transcribe: bool,
    pub prompt: String,
    pub tokens: usize,
    pub filter: SpeechFilter,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            transcribe: false,
            prompt: DEFAULT_PROMPT.to_owned(),
            tokens: 64,
            filter: SpeechFilter::default(),
        }
    }
}
impl Options {
    pub fn validate(&self) -> Result<()> {
        if !self.filter.min_dur_s.is_finite() || self.filter.min_dur_s < 0.0 {
            bail!("minimum segment duration must be finite and nonnegative");
        }
        if self.transcribe && self.tokens == 0 {
            bail!("transcription token limit must be positive");
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq)]
pub struct Heard {
    pub n_tokens: usize,
    pub hidden: usize,
    pub rows: Vec<f32>,
    pub text: Option<String>,
}
impl Heard {
    pub fn validate(&self) -> Result<()> {
        let expected = self
            .n_tokens
            .checked_mul(self.hidden)
            .context("embedding shape overflow")?;
        if self.n_tokens == 0 || self.hidden == 0 || expected != self.rows.len() {
            bail!("embedding shape does not match nonempty row data");
        }
        if !self.rows.iter().all(|x| x.is_finite()) {
            bail!("audio embedding contains nonfinite values");
        }
        Ok(())
    }
    pub fn embedding_bytes(&self) -> Result<Bytes> {
        self.validate()?;
        let len = self
            .rows
            .len()
            .checked_mul(4)
            .context("embedding byte length overflow")?;
        let mut bytes = Vec::with_capacity(len);
        for value in &self.rows {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        Ok(bytes.into())
    }
}
/// Injectable native model seam, also useful to test endpointing without a GPU.
pub trait Backend {
    fn hear(&mut self, wave_16k: &[f32], options: &Options) -> Result<Heard>;
}
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    Dropped {
        reason: String,
        text: Option<String>,
    },
    Embedded(Heard),
}
#[derive(Clone, Debug, PartialEq)]
pub struct Observation {
    pub utc_ms: u64,
    pub source: String,
    pub start_s: f64,
    pub end_s: f64,
    pub outcome: Outcome,
}
impl Observation {
    pub fn duration(&self) -> f64 {
        self.end_s - self.start_s
    }
    pub fn kept(&self) -> bool {
        matches!(self.outcome, Outcome::Embedded(_))
    }
    /// Ordered metadata and an exact raw f32le resource, never mislabeled
    /// audio. Text is an optional diagnostic, not the embedding handover.
    pub fn emit(&self, out: &mut Out<'_>) -> Result<()> {
        match &self.outcome {
            Outcome::Dropped {reason,text}=>out.line(serde_json::json!({"utc_ms":self.utc_ms,"source":self.source,"start_s":self.start_s,"end_s":self.end_s,"dur_s":self.duration(),"text":text,"dropped":reason}).to_string()),
            Outcome::Embedded(heard)=>{
                let bytes=heard.embedding_bytes()?;
                let uri=format!("hear:embedding/{}",blake3::hash(bytes.as_ref()).to_hex());
                out.line(serde_json::json!({"utc_ms":self.utc_ms,"source":self.source,"start_s":self.start_s,"end_s":self.end_s,"dur_s":self.duration(),"rate":HEAR_RATE,"n_tokens":heard.n_tokens,"hidden":heard.hidden,"dtype":"f32le","layout":"row-major","emb":uri,"text":heard.text}).to_string())?;
                out.blob(bytes,"application/octet-stream",uri)
            }
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClipSummary {
    pub segments: usize,
    pub embedded: usize,
    pub dropped: usize,
}
#[derive(Clone, Debug)]
pub struct Hear {
    config: ModelConfig,
}
impl Hear {
    pub fn new(config: ModelConfig) -> Self {
        Self { config }
    }
    pub fn once(
        &self,
        bytes: Bytes,
        mime_type: &str,
        source: &str,
        options: &Options,
        out: &mut Out<'_>,
    ) -> Result<ClipSummary> {
        options.validate()?;
        let hint = mime_hint(mime_type)?;
        let wave = decode_clip(bytes, hint)?;
        validate_wave(&wave)?;
        let mut ears = Ears::open(&self.config)?;
        process_pcm16k(&mut ears, &wave, source, options, &mut |observation| {
            observation.emit(out)
        })
    }
}
/// Process one resident mono 16kHz clip with a supplied native backend. Each
/// accepted/dropped observation is emitted exactly once; output failure stops
/// without re-embedding or retrying already delivered observations.
pub fn process_pcm16k(
    backend: &mut impl Backend,
    wave: &[f32],
    source: &str,
    options: &Options,
    emit: &mut impl FnMut(Observation) -> Result<()>,
) -> Result<ClipSummary> {
    options.validate()?;
    let segments = segment_clip(wave)?;
    let mut summary = ClipSummary {
        segments: segments.len(),
        ..Default::default()
    };
    for segment in segments {
        let observed = hear_segment(backend, options, &segment, source, None, now_ms()?)?;
        if observed.kept() {
            summary.embedded += 1;
        } else {
            summary.dropped += 1;
        }
        emit(observed)?;
    }
    Ok(summary)
}
fn validate_wave(wave: &[f32]) -> Result<()> {
    if wave.is_empty() {
        bail!("recorded audio contains no samples");
    }
    if !wave.iter().all(|sample| sample.is_finite()) {
        bail!("recorded audio contains nonfinite samples");
    }
    Ok(())
}
pub(super) fn segment_clip(wave: &[f32]) -> Result<Vec<Segment>> {
    validate_wave(wave)?;
    let mut segmenter = Segmenter::new(HEAR_RATE, VadConfig::default());
    let mut segments = Vec::new();
    segmenter.push(wave, &mut |segment| segments.push(segment));
    segmenter.flush(&mut |segment| segments.push(segment));
    Ok(segments)
}
pub(super) fn hear_segment(
    backend: &mut impl Backend,
    options: &Options,
    segment: &Segment,
    source: &str,
    spoke: Option<SpeechWindow>,
    utc_ms: u64,
) -> Result<Observation> {
    let mut observation = Observation {
        utc_ms,
        source: source.to_owned(),
        start_s: segment.start_s,
        end_s: segment.end_s,
        outcome: Outcome::Dropped {
            reason: String::new(),
            text: None,
        },
    };
    if let Some(reason) =
        turntaking::audio_drop_reason(segment.dur_s(), utc_ms, &options.filter, spoke)
    {
        observation.outcome = Outcome::Dropped {
            reason: reason.to_owned(),
            text: None,
        };
        return Ok(observation);
    }
    let wave = to_hear_rate(&segment.samples, segment.rate)?;
    let heard = backend.hear(&wave, options)?;
    if let Some(text) = &heard.text {
        let utterance = turntaking::Utterance {
            text,
            prompt: &options.prompt,
            utc_ms,
            dur_s: segment.dur_s(),
        };
        if let Some(reason) = turntaking::drop_reason(&utterance, &options.filter, spoke) {
            observation.outcome = Outcome::Dropped {
                reason: reason.to_owned(),
                text: Some(text.clone()),
            };
            return Ok(observation);
        }
    }
    // Validate before a frontend can append a record referring to unusable rows.
    heard.validate()?;
    observation.outcome = Outcome::Embedded(heard);
    Ok(observation)
}
pub(super) fn now_ms() -> Result<u64> {
    Ok(crate::clock::now()?.to_unix_milliseconds() as u64)
}
pub(super) fn mime_hint(mime: &str) -> Result<Option<&'static str>> {
    match mime
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "audio/wav" | "audio/x-wav" | "audio/wave" => Ok(Some("wav")),
        "audio/mpeg" | "audio/mp3" => Ok(Some("mp3")),
        "audio/mp4" | "audio/x-m4a" => Ok(Some("m4a")),
        "audio/flac" | "audio/x-flac" => Ok(Some("flac")),
        "audio/aac" => Ok(Some("aac")),
        "audio/ogg" | "application/ogg" => Ok(Some("ogg")),
        other => bail!("unsupported recorded-audio MIME type {other:?}"),
    }
}
#[cfg(feature = "hear")]
fn decode_clip(bytes: Bytes, hint: Option<&str>) -> Result<Vec<f32>> {
    mary::models::gemma::gemma4::audio_load::load_audio_16k_mono_bytes(
        bytes.as_ref().to_vec(),
        hint,
    )
    .map_err(anyhow::Error::msg)
}
#[cfg(not(feature = "hear"))]
fn decode_clip(_bytes: Bytes, _hint: Option<&str>) -> Result<Vec<f32>> {
    bail!("hear was built without the `hear` feature")
}
#[cfg(feature = "hear")]
pub(super) struct Ears {
    hearing: mary::models::gemma::gemma4::hear::Hearing<mary::nn::backend::B>,
}
#[cfg(feature = "hear")]
impl Ears {
    pub(super) fn open(config: &ModelConfig) -> Result<Self> {
        use mary::models::gemma::gemma4::config::Gemma4Config;
        use mary::models::gemma::gemma4::hear::Hearing;
        use mary::nn::backend::{WgpuDevice, B};
        let model_config = Gemma4Config::load(&config.config_json);
        let tokenizer = tokenizers::Tokenizer::from_file(&config.tokenizer_json)
            .map_err(|error| anyhow::anyhow!("load hearing tokenizer: {error}"))?;
        let device = WgpuDevice::default();
        let (model, _vision, tower, embedder) = mary::persist::load_gemma4_hearing_from_pile::<B>(
            &config.pile,
            mary::selection::ModelSelector::Source {
                source: &config.model,
                quantization: mary::persist::QUANTIZATION_NATIVE,
            },
            model_config,
            &device,
        )
        .with_context(|| format!("load Gemma-4 hearing stack from {}", config.pile.display()))?;
        Ok(Self {
            hearing: Hearing::new(model, tower, embedder, tokenizer, device),
        })
    }
}
#[cfg(feature = "hear")]
impl Backend for Ears {
    fn hear(&mut self, wave: &[f32], options: &Options) -> Result<Heard> {
        let audio = self.hearing.embed(wave);
        let text = options.transcribe.then(|| {
            self.hearing
                .understand(wave, &options.prompt, options.tokens, |_| {})
        });
        Ok(Heard {
            n_tokens: audio.n_tokens,
            hidden: audio.hidden,
            rows: audio.rows,
            text,
        })
    }
}
#[cfg(not(feature = "hear"))]
pub(super) struct Ears;
#[cfg(not(feature = "hear"))]
impl Ears {
    pub(super) fn open(_config: &ModelConfig) -> Result<Self> {
        bail!("hear was built without the `hear` feature")
    }
}
#[cfg(not(feature = "hear"))]
impl Backend for Ears {
    fn hear(&mut self, _wave: &[f32], _options: &Options) -> Result<Heard> {
        bail!("hear was built without the `hear` feature")
    }
}
/// Resample a finished utterance only, never individual capture frames.
pub(super) fn to_hear_rate(samples: &[f32], rate: usize) -> Result<Vec<f32>> {
    if rate == HEAR_RATE {
        return Ok(samples.to_vec());
    }
    #[cfg(feature = "hear")]
    {
        mary::models::gemma::gemma4::audio_load::resample_to_16k(samples.to_vec(), rate)
            .map_err(anyhow::Error::msg)
    }
    #[cfg(not(feature = "hear"))]
    {
        bail!("hear was built without the `hear` feature")
    }
}
