//! Exercise the actual resident decoder on the delivery dependency graph.
//! These fixtures never open a model pile or acquire a GPU/microphone.
#![cfg(feature = "hear")]

use mary::models::gemma::gemma4::audio_load::{load_audio_16k_mono, load_audio_16k_mono_bytes};

fn stereo_wav() -> Vec<u8> {
    let samples = [0_i16, 0, 8192, 24576, -8192, -24576, 16384, -16384];
    let length = (samples.len() * 2) as u32;
    let mut wav = Vec::new();
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&(36 + length).to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16_u32.to_le_bytes());
    wav.extend_from_slice(&1_u16.to_le_bytes());
    wav.extend_from_slice(&2_u16.to_le_bytes());
    wav.extend_from_slice(&16000_u32.to_le_bytes());
    wav.extend_from_slice(&64000_u32.to_le_bytes());
    wav.extend_from_slice(&4_u16.to_le_bytes());
    wav.extend_from_slice(&16_u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&length.to_le_bytes());
    for sample in samples {
        wav.extend_from_slice(&sample.to_le_bytes());
    }
    wav
}

#[test]
fn resident_and_file_audio_share_the_real_decoder_and_downmix() {
    let original = stereo_wav();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("stereo.wav");
    std::fs::write(&path, &original).unwrap();
    let resident = load_audio_16k_mono_bytes(original.clone(), Some("wav")).unwrap();
    assert_eq!(resident, [0.0, 0.5, -0.5, 0.0]);
    assert_eq!(load_audio_16k_mono(&path).unwrap(), resident);
    assert_eq!(
        load_audio_16k_mono_bytes(original.clone(), None).unwrap(),
        resident
    );
    assert_eq!(std::fs::read(path).unwrap(), original);
}

#[test]
fn malformed_and_empty_resident_audio_are_errors_not_panics() {
    assert!(load_audio_16k_mono_bytes(b"not audio".to_vec(), Some("wav")).is_err());
    let mut empty = stereo_wav();
    empty.truncate(44);
    empty[4..8].copy_from_slice(&36_u32.to_le_bytes());
    empty[40..44].copy_from_slice(&0_u32.to_le_bytes());
    assert!(load_audio_16k_mono_bytes(empty, Some("wav")).is_err());
}
