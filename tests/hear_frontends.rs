use anybytes::Bytes;
use anyhow::Result;
use faculties::hear::{
    mcp, process_pcm16k, Backend, Heard, Observation, Options, Outcome, HEAR_RATE,
};
use faculties::mcp::{Faculty, InvalidArguments, Server};
use faculties::out::{Out, Part};

struct Fake {
    calls: usize,
    text: Option<String>,
    wrong_shape: bool,
}
impl Fake {
    fn new() -> Self {
        Self {
            calls: 0,
            text: None,
            wrong_shape: false,
        }
    }
}
impl Backend for Fake {
    fn hear(&mut self, wave: &[f32], _: &Options) -> Result<Heard> {
        assert!(!wave.is_empty());
        self.calls += 1;
        Ok(Heard {
            n_tokens: 1,
            hidden: if self.wrong_shape { 3 } else { 2 },
            rows: vec![0.25, -0.5],
            text: self.text.clone(),
        })
    }
}
fn tone(secs: f32, amp: f32) -> Vec<f32> {
    (0..(HEAR_RATE as f32 * secs) as usize)
        .map(|i| amp * (i as f32 * 2.0 * std::f32::consts::PI * 220.0 / HEAR_RATE as f32).sin())
        .collect()
}
fn silence(secs: f32) -> Vec<f32> {
    vec![0.0; (HEAR_RATE as f32 * secs) as usize]
}
fn clip() -> Vec<f32> {
    [
        silence(1.0),
        tone(1.2, 0.3),
        silence(1.2),
        tone(1.0, 0.3),
        silence(1.2),
    ]
    .concat()
}
fn sample_observation() -> Observation {
    Observation {
        utc_ms: 123,
        source: "@literal/source".into(),
        start_s: 1.0,
        end_s: 2.0,
        outcome: Outcome::Embedded(Heard {
            n_tokens: 1,
            hidden: 2,
            rows: vec![0.25, -0.5],
            text: Some("literal transcript".into()),
        }),
    }
}

#[test]
fn native_observation_emits_exact_shape_metadata_then_raw_embedding_resource() {
    let observation = sample_observation();
    let mut parts = Vec::new();
    observation
        .emit(&mut Out::new(&mut |p| {
            parts.push(p);
            Ok(())
        }))
        .unwrap();
    assert_eq!(parts.len(), 2);
    let Part::Text { text } = &parts[0] else {
        panic!("metadata first")
    };
    let metadata: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(metadata["source"], "@literal/source");
    assert_eq!(metadata["dtype"], "f32le");
    assert_eq!(metadata["layout"], "row-major");
    assert_eq!(metadata["n_tokens"], 1);
    assert_eq!(metadata["hidden"], 2);
    assert_eq!(metadata["text"], "literal transcript");
    let Part::Blob {
        bytes,
        mime_type,
        uri,
    } = &parts[1]
    else {
        panic!("raw resource, not sensory audio")
    };
    assert_eq!(mime_type, "application/octet-stream");
    assert_eq!(metadata["emb"], uri.as_str());
    let expected = [0.25_f32.to_le_bytes(), (-0.5_f32).to_le_bytes()].concat();
    assert_eq!(bytes.as_ref(), expected);
}
#[test]
fn shared_recorded_path_preserves_two_utterances_and_order() {
    let mut backend = Fake::new();
    let mut observations = Vec::new();
    let summary = process_pcm16k(
        &mut backend,
        &clip(),
        "clip",
        &Options::default(),
        &mut |o| {
            observations.push(o);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(summary.segments, 2);
    assert_eq!(summary.embedded, 2);
    assert_eq!(summary.dropped, 0);
    assert_eq!(backend.calls, 2);
    assert!(observations[1].start_s > observations[0].end_s);
    assert!(observations.iter().all(Observation::kept));
}
#[test]
fn audio_blip_and_prompt_parrot_filters_keep_model_and_output_boundaries() {
    let mut backend = Fake::new();
    let click = [silence(1.0), tone(0.05, 0.4), silence(1.2)].concat();
    let mut observations = Vec::new();
    let summary = process_pcm16k(
        &mut backend,
        &click,
        "click",
        &Options::default(),
        &mut |o| {
            observations.push(o);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(summary.dropped, 1);
    assert_eq!(backend.calls, 0);
    assert!(
        matches!(&observations[0].outcome,Outcome::Dropped{reason,..}if reason=="too-short-segment")
    );
    let options = Options {
        transcribe: true,
        ..Default::default()
    };
    backend.text = Some(options.prompt.clone());
    let mut observations = Vec::new();
    let summary = process_pcm16k(&mut backend, &clip(), "parrot", &options, &mut |o| {
        observations.push(o);
        Ok(())
    })
    .unwrap();
    assert_eq!(summary.embedded, 0);
    assert_eq!(summary.dropped, 2);
    assert_eq!(backend.calls, 2);
    assert!(observations
        .iter()
        .all(|o| matches!(o.outcome, Outcome::Dropped { .. })));
}
#[test]
fn output_failure_stops_without_retry_or_second_embedding() {
    let mut backend = Fake::new();
    let mut attempts = 0;
    let error = process_pcm16k(
        &mut backend,
        &clip(),
        "clip",
        &Options::default(),
        &mut |_| {
            attempts += 1;
            anyhow::bail!("reject observation")
        },
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("reject observation"));
    assert_eq!(backend.calls, 1);
    assert_eq!(attempts, 1);
    let mut parts = 0;
    assert!(sample_observation()
        .emit(&mut Out::new(&mut |_| {
            parts += 1;
            if parts == 2 {
                anyhow::bail!("reject raw resource");
            }
            Ok(())
        }))
        .is_err());
    assert_eq!(parts, 2);
}
#[test]
fn malformed_samples_and_embedding_shapes_fail_before_emission() {
    for wave in [&[][..], &[f32::NAN][..], &[f32::INFINITY][..]] {
        let mut backend = Fake::new();
        assert!(process_pcm16k(
            &mut backend,
            wave,
            "invalid",
            &Options::default(),
            &mut |_| anyhow::bail!("unexpected")
        )
        .is_err());
        assert_eq!(backend.calls, 0);
    }
    let mut backend = Fake::new();
    backend.wrong_shape = true;
    let mut emitted = 0;
    assert!(process_pcm16k(
        &mut backend,
        &clip(),
        "bad shape",
        &Options::default(),
        &mut |_| {
            emitted += 1;
            Ok(())
        }
    )
    .is_err());
    assert_eq!(emitted, 0);
    assert_eq!(backend.calls, 1);
    let mut invalid = sample_observation();
    if let Outcome::Embedded(h) = &mut invalid.outcome {
        h.rows[0] = f32::NAN;
    }
    assert!(invalid
        .emit(&mut Out::new(&mut |_| {
            emitted += 1;
            Ok(())
        }))
        .is_err());
    assert_eq!(emitted, 0);
}
#[test]
fn mcp_discovery_never_loads_models_and_caller_cannot_choose_devices_or_paths() {
    let adapter = mcp::Hear::new(None);
    assert_eq!(adapter.tools().len(), 1);
    assert_eq!(adapter.tools()[0].name, "hear_once");
    Server::new(&[&adapter]).unwrap();
    for args in [
        r#"{"data":"AQ==","path":"/host/audio.wav"}"#,
        r#"{"data":"AQ==","pile":"/host/model.pile"}"#,
        r#"{"data":"AQ==","model":"other"}"#,
        r#"{"data":"AQ==","soma":"http://localhost:8000"}"#,
        r#"{"data":"AQ==","out":"/host/log"}"#,
        r#"{"data":"AQ==","emb_dir":"/host/embeddings"}"#,
        r#"{"data":"AQ==","data":"Ag=="}"#,
        r#"{"data":"AQ==","tokens":0}"#,
        r#"{"data":"AQ==","min_dur_s":-1}"#,
        r#"{"data":"AQ==","mime_type":"image/png"}"#,
        r#"{"data":""}"#,
        r#"{"data":"!invalid!"}"#,
        "[]",
    ] {
        let error = adapter
            .call(
                "hear_once",
                Bytes::from(args),
                &mut Out::new(&mut |_| anyhow::bail!("unexpected emission")),
            )
            .unwrap_err();
        assert!(
            error.downcast_ref::<InvalidArguments>().is_some(),
            "{args}: {error:#}"
        );
    }
    let error = adapter
        .call(
            "hear_once",
            Bytes::from(r#"{"data":"AQ==","prompt":"@literal","source":"@literal"}"#),
            &mut Out::new(&mut |_| anyhow::bail!("unexpected emission")),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("no launcher-configured"));
    assert!(error.downcast_ref::<InvalidArguments>().is_none());
}
