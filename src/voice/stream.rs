//! Drive's framed text-to-PCM data plane, backed by one resident voice.
//!
//! MCP remains the request/response control plane. This module owns the pipe
//! convention: incremental UTF-8 records enter, complete sentences are queued
//! on Mary's resident session, and 24 kHz mono PCM records leave immediately.

use super::synthesis::{AudioClip, Synthesizer};
use super::{Channel, Voice};
#[cfg(feature = "voice")]
use anyhow::Context;
use anyhow::Result;
use framed_stream::{EndStatus, Frame, FramedReader, FramedWriter, TEXT_PLAIN, UNIT_SAMPLES};
use std::io::{Read, Write};

/// The PCM contract Drive consumes from the Voice process.
pub const PCM_S16LE: &str = "audio/L16;rate=24000;channels=1";
/// A declared tenth-second output hole for one declared input hole.
pub const GAP_SAMPLES: u64 = 2_400;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamReceipt {
    pub sentences: usize,
    pub logged: usize,
    /// Samples acknowledged only after Soma's playback ring drained.
    pub soma_samples: Option<u64>,
}

trait SpeechChunks {
    fn next_chunk(&mut self) -> Option<Vec<f32>>;
    fn finish(self) -> Result<()>;
}

trait Speech {
    type Chunks: SpeechChunks;

    fn speak(&self, text: &str) -> Result<Self::Chunks>;
}

trait ChunkMirror {
    type Receipt;

    fn push(&mut self, chunk: &[f32]) -> Result<()>;
    fn finish(&mut self) -> Result<Self::Receipt>;
}

#[cfg(feature = "voice")]
struct MarySpeech<'a>(&'a Synthesizer);

#[cfg(feature = "voice")]
struct MaryChunks(mary::speak::SpeakStream);

#[cfg(feature = "voice")]
impl SpeechChunks for MaryChunks {
    fn next_chunk(&mut self) -> Option<Vec<f32>> {
        self.0.next()
    }

    fn finish(self) -> Result<()> {
        self.0.finish()
    }
}

#[cfg(feature = "voice")]
impl Speech for MarySpeech<'_> {
    type Chunks = MaryChunks;

    fn speak(&self, text: &str) -> Result<Self::Chunks> {
        Ok(MaryChunks(self.0.start(text)?.stream))
    }
}

#[cfg(feature = "voice")]
struct SomaMirror {
    playback: Option<soma_client::SomaPlayback>,
    has_audio: bool,
}

#[cfg(feature = "voice")]
impl SomaMirror {
    fn open(configured: Option<&str>) -> Self {
        let playback = match configured {
            Some(url) if super::device::soma_reachable(url) => {
                eprintln!("[stream] Soma body at {url}");
                match soma_client::SomaPlayback::open(
                    url,
                    soma_client::PlaybackSpec::mono(mary::speak::SpeakStream::SAMPLE_RATE),
                ) {
                    Ok(playback) => Some(playback),
                    Err(error) => {
                        eprintln!(
                            "[stream] could not open Soma at {url}: {error:#}; PCM goes to stdout only"
                        );
                        None
                    }
                }
            }
            Some(url) => {
                eprintln!("[stream] Soma at {url} is not answering; PCM goes to stdout only");
                None
            }
            None => None,
        };
        Self {
            playback,
            has_audio: false,
        }
    }
}

#[cfg(feature = "voice")]
impl ChunkMirror for SomaMirror {
    type Receipt = Option<u64>;

    fn push(&mut self, chunk: &[f32]) -> Result<()> {
        let failure = self
            .playback
            .as_mut()
            .and_then(|playback| playback.push_f32(chunk).err());
        if let Some(error) = failure {
            eprintln!("[stream] Soma stopped accepting PCM: {error:#}; continuing on stdout");
            self.playback.take();
            self.has_audio = false;
        } else if self.playback.is_some() && !chunk.is_empty() {
            self.has_audio = true;
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<Self::Receipt> {
        let Some(playback) = self.playback.take() else {
            return Ok(None);
        };
        if !self.has_audio {
            return Ok(None);
        }
        match playback.finish() {
            Ok(receipt) => {
                eprintln!(
                    "[stream] Soma drained {:.1}s ({} samples; {} underrun; {} callbacks, {} late, max {:.2}ms)",
                    receipt.samples as f64 / mary::speak::SpeakStream::SAMPLE_RATE as f64,
                    receipt.samples,
                    receipt.underrun_samples,
                    receipt.callbacks,
                    receipt.late_callbacks,
                    receipt.max_callback_ms,
                );
                Ok(Some(receipt.samples))
            }
            Err(error) => {
                eprintln!("[stream] Soma did not drain cleanly: {error:#}");
                Ok(None)
            }
        }
    }
}

/// Run one framed Voice stream. The model is primed before the input preamble
/// is read, so its asynchronous load overlaps the first sentence arriving.
/// Complete sentence records are committed off the synthesis path in order.
pub fn run<R: Read, W: Write>(
    voice: &Voice,
    synthesizer: &Synthesizer,
    channel: Channel,
    soma: Option<&str>,
    input: R,
    output: W,
) -> Result<StreamReceipt> {
    #[cfg(not(feature = "voice"))]
    {
        let _ = (voice, synthesizer, channel, soma, input, output);
        anyhow::bail!("voice stream requires a build with the `voice` feature");
    }
    #[cfg(feature = "voice")]
    {
        synthesizer.prime()?;
        if channel == Channel::Say && soma.is_some() {
            eprintln!("[stream] private say never mirrors to the Soma body");
        }
        let mut mirror = SomaMirror::open(soma_target(channel, soma));
        let (jobs, incoming) = std::sync::mpsc::channel::<(String, Vec<u8>)>();
        let ledger_voice = voice.clone();
        let ledger = std::thread::Builder::new()
            .name("voice-ledger".into())
            .spawn(move || -> Result<usize> {
                let mut logged = 0;
                while let Ok((text, audio)) = incoming.recv() {
                    ledger_voice.record(channel, &text, Some(audio), "voice spoke")?;
                    logged += 1;
                }
                Ok(logged)
            })
            .context("start Voice ledger thread")?;

        let framed = transduce(
            input,
            output,
            &MarySpeech(synthesizer),
            &mut mirror,
            |text, audio| {
                jobs.send((text.to_owned(), audio.wav.as_ref().to_vec()))
                    .map_err(|_| anyhow::anyhow!("Voice ledger thread exited before recording"))
            },
        );
        drop(jobs);
        let logged = ledger
            .join()
            .map_err(|_| anyhow::anyhow!("Voice ledger thread panicked"))?;

        match (framed, logged) {
            (Ok((_output, sentences, soma_samples)), Ok(logged)) => {
                eprintln!("[stream] {sentences} sentence(s) spoken, {logged} logged");
                Ok(StreamReceipt {
                    sentences,
                    logged,
                    soma_samples,
                })
            }
            (Err(stream), Ok(_)) => Err(stream),
            (Ok(_), Err(ledger)) => Err(ledger.context("record streamed Voice utterances")),
            (Err(stream), Err(ledger)) => Err(stream.context(format!(
                "Voice ledger also failed while settling the stream: {ledger:#}"
            ))),
        }
    }
}

fn soma_target(channel: Channel, configured: Option<&str>) -> Option<&str> {
    match channel {
        Channel::Say => None,
        Channel::Shout => configured,
    }
}

fn transduce<R, W, S, M, L>(
    input: R,
    output: W,
    speech: &S,
    mirror: &mut M,
    mut log: L,
) -> Result<(W, usize, M::Receipt)>
where
    R: Read,
    W: Write,
    S: Speech,
    M: ChunkMirror,
    L: FnMut(&str, AudioClip) -> Result<()>,
{
    let mut reader = FramedReader::open(input)?;
    reader.require_content_type(TEXT_PLAIN)?;
    let mut writer = FramedWriter::open(output, PCM_S16LE, UNIT_SAMPLES)?;
    let mut pending = String::new();
    let mut sentences = 0;

    let status = loop {
        match reader.next_frame()? {
            Frame::Record(record) => {
                anyhow::ensure!(
                    record.content_type() == TEXT_PLAIN,
                    "text stream record {} overrides its content type with {:?}",
                    record.index,
                    record.content_type()
                );
                anyhow::ensure!(
                    record.extent == record.payload.len() as u64,
                    "text stream record {} declares {} byte(s) but carries {}",
                    record.index,
                    record.extent,
                    record.payload.len()
                );
                pending.push_str(record.text()?);
                while let Some(cut) = sentence_end(&pending) {
                    let sentence: String = pending.drain(..cut).collect();
                    if speak_sentence(
                        &sentence,
                        sentences + 1,
                        &mut writer,
                        speech,
                        mirror,
                        &mut log,
                    )? {
                        sentences += 1;
                    }
                }
            }
            Frame::Gap(gap) => {
                let tail = std::mem::take(&mut pending);
                if speak_sentence(&tail, sentences + 1, &mut writer, speech, mirror, &mut log)? {
                    sentences += 1;
                }
                writer.gap(
                    GAP_SAMPLES,
                    &format!("input gap of {} byte(s): {}", gap.extent, gap.reason),
                )?;
            }
            Frame::End(status) => {
                let tail = std::mem::take(&mut pending);
                if speak_sentence(&tail, sentences + 1, &mut writer, speech, mirror, &mut log)? {
                    sentences += 1;
                }
                break status;
            }
        }
    };

    let mirror_receipt = mirror.finish()?;
    let status = match status {
        EndStatus::Complete => EndStatus::Complete,
        EndStatus::Aborted(reason) => EndStatus::Aborted(format!("upstream aborted: {reason}")),
    };
    let mut output = writer.finish(status)?;
    output.flush()?;
    Ok((output, sentences, mirror_receipt))
}

fn speak_sentence<W, S, M, L>(
    sentence: &str,
    ordinal: usize,
    writer: &mut FramedWriter<W>,
    speech: &S,
    mirror: &mut M,
    log: &mut L,
) -> Result<bool>
where
    W: Write,
    S: Speech,
    M: ChunkMirror,
    L: FnMut(&str, AudioClip) -> Result<()>,
{
    let sentence = sentence.trim();
    if sentence.is_empty() {
        return Ok(false);
    }
    let called = std::time::Instant::now();
    let mut chunks = speech.speak(sentence)?;
    let mut samples = Vec::new();
    while let Some(chunk) = chunks.next_chunk() {
        if chunk.is_empty() {
            continue;
        }
        anyhow::ensure!(
            chunk.iter().all(|sample| sample.is_finite()),
            "resident speech emitted a non-finite PCM sample"
        );
        if samples.is_empty() {
            eprintln!(
                "[stream] sentence {ordinal}: first chunk {:.2}s after the cut ({} chars)",
                called.elapsed().as_secs_f32(),
                sentence.chars().count()
            );
        }
        writer.record(&pcm_s16le(&chunk), chunk.len() as u64)?;
        mirror.push(&chunk)?;
        samples.extend_from_slice(&chunk);
    }
    chunks.finish()?;
    log(
        sentence,
        AudioClip::from_samples(&samples, mary_sample_rate())?,
    )?;
    Ok(true)
}

fn mary_sample_rate() -> u32 {
    #[cfg(feature = "voice")]
    {
        mary::speak::SpeakStream::SAMPLE_RATE
    }
    #[cfg(not(feature = "voice"))]
    {
        24_000
    }
}

/// The byte index just past the first sentence punctuation followed by
/// whitespace. A punctuation mark at the current tail waits for the next
/// record, distinguishing `3.14` from a sentence that has actually ended.
fn sentence_end(pending: &str) -> Option<usize> {
    let mut chars = pending.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        if matches!(character, '.' | '!' | '?') {
            match chars.peek() {
                Some((_, next)) if next.is_whitespace() => {
                    return Some(index + character.len_utf8());
                }
                Some(_) => continue,
                None => return None,
            }
        }
    }
    None
}

fn pcm_s16le(samples: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(samples.len() * 2);
    for sample in samples {
        let value = (sample.clamp(-1.0, 1.0) * 32_767.0) as i16;
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct FakeSpeech {
        spoken: RefCell<Vec<String>>,
    }

    struct FakeChunks(std::vec::IntoIter<Vec<f32>>);

    impl SpeechChunks for FakeChunks {
        fn next_chunk(&mut self) -> Option<Vec<f32>> {
            self.0.next()
        }

        fn finish(self) -> Result<()> {
            Ok(())
        }
    }

    impl Speech for FakeSpeech {
        type Chunks = FakeChunks;

        fn speak(&self, text: &str) -> Result<Self::Chunks> {
            self.spoken.borrow_mut().push(text.to_owned());
            Ok(FakeChunks(vec![vec![0.5]].into_iter()))
        }
    }

    struct NoMirror;

    impl ChunkMirror for NoMirror {
        type Receipt = ();

        fn push(&mut self, _chunk: &[f32]) -> Result<()> {
            Ok(())
        }

        fn finish(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn sentence_ends_only_after_punctuation_and_whitespace() {
        assert_eq!(sentence_end("Hello there. And"), Some("Hello there.".len()));
        assert_eq!(sentence_end("Pi is 3.14 today"), None);
        assert_eq!(sentence_end("Really?! Yes"), Some("Really?!".len()));
        assert_eq!(sentence_end("Wait."), None);
        assert_eq!(sentence_end("Wait. "), Some("Wait.".len()));
        assert_eq!(sentence_end("no end here"), None);
    }

    #[test]
    fn private_stream_never_targets_soma() {
        assert_eq!(soma_target(Channel::Say, Some("http://body")), None);
        assert_eq!(
            soma_target(Channel::Shout, Some("http://body")),
            Some("http://body")
        );
    }

    #[test]
    fn framed_stream_relays_sentences_gap_and_abort() {
        let mut input = FramedWriter::open_text(Vec::new()).unwrap();
        input.text("Hello").unwrap();
        input.text(". Next").unwrap();
        input.gap(3, "three missing bytes").unwrap();
        input.text(" tail").unwrap();
        let input = input
            .finish(EndStatus::Aborted("source failed".into()))
            .unwrap();

        let speech = FakeSpeech {
            spoken: RefCell::new(Vec::new()),
        };
        let mut mirror = NoMirror;
        let mut logged = Vec::new();
        let (output, sentences, ()) = transduce(
            input.as_slice(),
            Vec::new(),
            &speech,
            &mut mirror,
            |text, audio| {
                assert_eq!(audio.sample_count, 1);
                logged.push(text.to_owned());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(sentences, 3);
        assert_eq!(speech.spoken.into_inner(), ["Hello.", "Next", "tail"]);
        assert_eq!(logged, ["Hello.", "Next", "tail"]);

        let mut output = FramedReader::open(output.as_slice()).unwrap();
        output.require_content_type(PCM_S16LE).unwrap();
        for index in 0..2 {
            let Frame::Record(record) = output.next_frame().unwrap() else {
                panic!("output {index} must be PCM");
            };
            assert_eq!(record.extent, 1);
            assert_eq!(record.payload, (16_383_i16).to_le_bytes());
        }
        let Frame::Gap(gap) = output.next_frame().unwrap() else {
            panic!("input gap must remain a gap");
        };
        assert_eq!(gap.extent, GAP_SAMPLES);
        assert!(gap.reason.contains("three missing bytes"));
        let Frame::Record(record) = output.next_frame().unwrap() else {
            panic!("tail must be PCM");
        };
        assert_eq!(record.extent, 1);
        assert_eq!(
            output.next_frame().unwrap(),
            Frame::End(EndStatus::Aborted("upstream aborted: source failed".into()))
        );
    }
}
