//! Explicit adaptation for Drive's existing Inkling audio frontend.
//!
//! Its historical `audio/L16` wire spelling carries LITTLE-endian PCM16, not
//! RFC L16's big-endian samples. Preserve that existing receiver contract here.
//! MCP and raw file exports never pass through this derived-perception path.

use anybytes::Bytes;
use anyhow::{bail, ensure, Context, Result};

const MAX_AUDIO_BYTES: usize = 128 * 1024 * 1024;

pub(super) fn prepare(bytes: Bytes, media_type: &str) -> Result<(Bytes, String)> {
    ensure!(!bytes.is_empty(), "Drive audio is empty");
    ensure!(
        bytes.len() <= MAX_AUDIO_BYTES,
        "Drive audio exceeds the 128 MiB input limit"
    );
    let mime: mime::Mime = media_type.parse().context("invalid audio MIME type")?;
    match mime.essence_str().to_ascii_lowercase().as_str() {
        "audio/l16" => {
            let rate = mime.get_param("rate").context("Drive PCM16 needs a rate parameter")?
                .as_str().parse::<u32>().context("invalid PCM16 rate")?;
            let channels = mime.get_param("channels").map(|value| value.as_str().parse::<u16>())
                .transpose().context("invalid PCM16 channel count")?.unwrap_or(1);
            ensure!(rate > 0 && channels == 1, "Drive PCM16 requires a positive rate and mono samples");
            ensure!(bytes.len() % 2 == 0, "Drive PCM16 has an incomplete sample");
            Ok((bytes, format!("audio/L16;rate={rate};channels=1")))
        }
        "audio/wav" | "audio/x-wav" | "audio/vnd.wave" => wav_pcm16(bytes.as_ref()),
        other => bail!("Drive cannot perceive {other}; provide a PCM16 WAV or mono PCM16 with an explicit rate (raw exports and MCP preserve original audio)"),
    }
}

fn wav_pcm16(bytes: &[u8]) -> Result<(Bytes, String)> {
    ensure!(
        bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WAVE",
        "Drive WAV input is not RIFF/WAVE"
    );
    let declared = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    ensure!(
        declared.checked_add(8) == Some(bytes.len()),
        "WAV RIFF length does not match input"
    );
    let mut offset = 12_usize;
    let mut format = None;
    let mut data = None;
    while offset < bytes.len() {
        let header = bytes
            .get(offset..offset + 8)
            .context("truncated WAV chunk header")?;
        let length = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        let start = offset + 8;
        let end = start
            .checked_add(length)
            .context("WAV chunk size overflow")?;
        let body = bytes.get(start..end).context("truncated WAV chunk")?;
        match &header[..4] {
            b"fmt " => {
                ensure!(format.is_none(), "WAV has multiple format chunks");
                ensure!(body.len() >= 16, "truncated WAV format");
                let encoding = u16::from_le_bytes(body[..2].try_into().unwrap());
                let channels = u16::from_le_bytes(body[2..4].try_into().unwrap());
                let rate = u32::from_le_bytes(body[4..8].try_into().unwrap());
                let byte_rate = u32::from_le_bytes(body[8..12].try_into().unwrap());
                let block_align = u16::from_le_bytes(body[12..14].try_into().unwrap());
                let bits = u16::from_le_bytes(body[14..16].try_into().unwrap());
                ensure!(
                    encoding == 1 && bits == 16,
                    "Drive WAV conversion supports PCM16 only"
                );
                ensure!(
                    (1..=8).contains(&channels) && rate > 0,
                    "WAV needs 1–8 channels and a positive rate"
                );
                ensure!(
                    block_align == channels * 2
                        && rate.checked_mul(u32::from(block_align)) == Some(byte_rate),
                    "WAV format has inconsistent frame or byte rate"
                );
                format = Some((channels, rate));
            }
            b"data" => {
                ensure!(data.is_none(), "WAV has multiple data chunks");
                data = Some(body);
            }
            _ => {}
        }
        offset = end
            .checked_add(length & 1)
            .context("WAV padding overflow")?;
        ensure!(offset <= bytes.len(), "truncated WAV chunk padding");
    }
    let (channels, rate) = format.context("WAV has no format chunk")?;
    let data = data.context("WAV has no data chunk")?;
    let frame_bytes = usize::from(channels) * 2;
    ensure!(
        !data.is_empty() && data.len() % frame_bytes == 0,
        "WAV samples are empty or incomplete"
    );
    // The original file stays intact; this is a derived mono perception. Use
    // integer averaging without gain or resampling (the mind owns resampling).
    let mono = if channels == 1 {
        data.to_vec()
    } else {
        let mut mono = Vec::with_capacity(data.len() / usize::from(channels));
        for frame in data.chunks_exact(frame_bytes) {
            let sum: i32 = frame
                .chunks_exact(2)
                .map(|sample| i32::from(i16::from_le_bytes([sample[0], sample[1]])))
                .sum();
            mono.extend_from_slice(&((sum / i32::from(channels)) as i16).to_le_bytes());
        }
        mono
    };
    Ok((mono.into(), format!("audio/L16;rate={rate};channels=1")))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wav(channels: u16, samples: &[i16]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"RIFF");
        bytes.extend_from_slice(&(36 + samples.len() as u32 * 2).to_le_bytes());
        bytes.extend_from_slice(b"WAVEfmt ");
        bytes.extend_from_slice(&16_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&channels.to_le_bytes());
        bytes.extend_from_slice(&24_000_u32.to_le_bytes());
        bytes.extend_from_slice(&(24_000_u32 * u32::from(channels) * 2).to_le_bytes());
        bytes.extend_from_slice(&(channels * 2).to_le_bytes());
        bytes.extend_from_slice(&16_u16.to_le_bytes());
        bytes.extend_from_slice(b"data");
        bytes.extend_from_slice(&(samples.len() as u32 * 2).to_le_bytes());
        for sample in samples {
            bytes.extend_from_slice(&sample.to_le_bytes());
        }
        bytes
    }
    #[test]
    fn wav_is_derived_to_existing_mono_wire_without_changing_the_original() {
        let original = wav(1, &[-32768, 0, 12345]);
        let (pcm, mime) = prepare(original.clone().into(), "audio/wav").unwrap();
        assert_eq!(pcm.as_ref(), &original[44..]);
        assert_eq!(mime, "audio/L16;rate=24000;channels=1");
        let stereo = wav(2, &[-30000, 10000, 32767, 32767]);
        let (mono, _) = prepare(stereo.into(), "audio/x-wav").unwrap();
        let expected = [-10000_i16, 32767]
            .into_iter()
            .flat_map(i16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(mono.as_ref(), expected);
    }
    #[test]
    fn malformed_or_unsupported_audio_fails_before_a_record_is_written() {
        let good = wav(1, &[1, 2, 3]);
        for length in 0..good.len() {
            assert!(prepare(good[..length].to_vec().into(), "audio/wav").is_err());
        }
        for (bytes, mime) in [
            (vec![1, 2], "audio/mp3"),
            (vec![1, 2], "audio/L16"),
            (vec![1, 2], "audio/L16;rate=0"),
            (vec![1, 2], "audio/L16;rate=24000;channels=2"),
            (vec![1], "audio/L16;rate=24000"),
            (wav(2, &[1]), "audio/wav"),
        ] {
            assert!(prepare(bytes.into(), mime).is_err(), "{mime}");
        }
    }
    #[test]
    fn explicit_existing_pcm_rate_is_preserved_without_a_second_conversion() {
        let raw: Bytes = vec![1_u8, 128, 255, 127].into();
        let (same, mime) = prepare(raw.clone(), "audio/L16;rate=16000").unwrap();
        assert_eq!(same.as_ptr(), raw.as_ptr());
        assert_eq!(mime, "audio/L16;rate=16000;channels=1");
    }
}
