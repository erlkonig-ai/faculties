//! Resident contracts only: no robot, camera shim, microphone or HTTP call.
use anybytes::Bytes;
use anyhow::{anyhow, Result};
use base64::Engine;
use clap::Parser;
use faculties::body::{self, Body, CaptureInput, Signal};
use faculties::files::presentation::ViewOptions;
use faculties::mcp::{Faculty, InvalidArguments};
use faculties::out::{Out, Part};
use faculties::storage::{initialize_signer, load_signer, open_pile_strict, publish_fragment};
use std::fs;
use std::path::PathBuf;
use triblespace::core::repo::SnapshotSource;
use triblespace::prelude::*;

struct Fixture {
    directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("body.pile");
        let key = directory.path().join("body.key");
        fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        Self {
            directory,
            pile,
            key,
        }
    }
    fn body(&self) -> Body {
        Body::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn mcp(&self) -> body::mcp::Body {
        body::mcp::Body::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn commits(&self) -> usize {
        let signer = load_signer(&self.pile, Some(&self.key)).unwrap();
        let mut pile = open_pile_strict(&self.pile).unwrap();
        let source = faculties::collection_names::open_configured(
            &mut pile,
            faculties::schemas::body::DEFAULT_SCOPE_ID,
            signer.verifying_key(),
        )
        .unwrap();
        let count = source.admitted(&pile.snapshot().unwrap()).unwrap().len();
        pile.close().unwrap();
        count
    }
}
fn json(value: serde_json::Value) -> Bytes {
    serde_json::to_vec(&value).unwrap().into()
}
fn parts(f: impl FnOnce(&mut Out<'_>) -> Result<()>) -> Result<Vec<Part>> {
    let mut values = Vec::new();
    f(&mut Out::new(&mut |part| {
        values.push(part);
        Ok(())
    }))?;
    Ok(values)
}
fn vision(bytes: Bytes) -> CaptureInput {
    CaptureInput {
        signal: Signal::Vision {
            bytes,
            mime: "image/png".into(),
            width: 2,
            height: 1,
        },
        pose: "@/not-a-pose-file".into(),
        note: Some("@-".into()),
    }
}
fn png() -> Bytes {
    let image = image::RgbaImage::from_pixel(2, 1, image::Rgba([12, 34, 56, 255]));
    let mut output = std::io::Cursor::new(Vec::new());
    image
        .write_to(&mut output, image::ImageFormat::Png)
        .unwrap();
    output.into_inner().into()
}

#[test]
fn direct_capture_returns_identity_and_preserves_original_bytes() {
    let fixture = Fixture::new();
    let body = fixture.body();
    let original: Bytes = vec![0, 255, 4, 5].into();
    let receipt = body.capture(&vision(original.clone())).unwrap();
    let id = format!("{:x}", receipt.id);
    assert_eq!(fixture.commits(), 1);
    assert_eq!(body.get(&id).unwrap().bytes, original);
    assert_eq!(body.list().unwrap()[0].note, "@-");
    assert!(
        body.view(&id, &ViewOptions::default()).is_err(),
        "raw storage does not claim corrupt image bytes can be perceived"
    );
    assert_eq!(fixture.commits(), 1);
}

#[test]
fn resident_mcp_capture_export_and_bounded_view_are_distinct() {
    let fixture = Fixture::new();
    let adapter = fixture.mcp();
    let image = png();
    let output = parts(|out| adapter.call("body_capture",json(serde_json::json!({"modality":"vision","data_base64":base64::engine::general_purpose::STANDARD.encode(&image),"mime":"image/png","width":2,"height":1,"pose":"@/not-a-file","note":"@-"})),out)).unwrap();
    assert!(output.iter().all(|p| matches!(p, Part::Text { .. })));
    let id = format!("{:x}", fixture.body().list().unwrap()[0].id);
    let output =
        parts(|out| adapter.call("body_get", json(serde_json::json!({"id":id})), out)).unwrap();
    assert!(
        matches!(&output[1],Part::Blob{bytes,mime_type,..} if bytes==&image && mime_type=="application/octet-stream")
    );
    let output = parts(|out| {
        adapter.call(
            "body_view",
            json(serde_json::json!({"id":id,"max_dimension":1})),
            out,
        )
    })
    .unwrap();
    let Part::Image { bytes, mime_type } = &output[0] else {
        panic!("perception image")
    };
    assert_eq!(mime_type, "image/png");
    assert_eq!(image::load_from_memory(bytes.as_ref()).unwrap().width(), 1);
    assert_eq!(fixture.body().get(&id).unwrap().bytes, image);
}

#[test]
fn touch_and_intent_strings_are_literal_and_read_does_not_execute_them() {
    let fixture = Fixture::new();
    let adapter = fixture.mcp();
    let missing = fixture.directory.path().join("not-a-file");
    let literal = format!("@{}", missing.display());
    parts(|out| {
        adapter.call(
            "body_capture",
            json(serde_json::json!({"modality":"touch","pose":literal,"note":"@-"})),
            out,
        )
    })
    .unwrap();
    let touch = fixture.body().list().unwrap().remove(0);
    assert_eq!(touch.modality, "touch");
    assert_eq!(touch.note, "@-");
    assert!(fixture
        .body()
        .get(&format!("{:x}", touch.id))
        .unwrap_err()
        .to_string()
        .contains("no frame"));
    parts(|out| {
        adapter.call(
            "body_intent_set",
            json(serde_json::json!({"text":literal})),
            out,
        )
    })
    .unwrap();
    assert_eq!(fixture.body().intent().unwrap().unwrap().text, literal);
    assert!(!missing.exists());
    assert_eq!(
        parts(|out| adapter.call("body_intent_get", json(serde_json::json!({})), out)).unwrap(),
        vec![Part::Text {
            text: format!("{literal}\n")
        }]
    );
}

#[test]
fn list_does_not_dereference_unselected_frames_or_poses() {
    let fixture = Fixture::new();
    // A note-free record: list needs neither frame nor pose, while get does.
    let mut input = vision(vec![1, 2, 3].into());
    input.note = None;
    let fragment = body::capture_fragment(&input, faculties::clock::point_now().unwrap()).unwrap();
    let id = fragment.root().unwrap();
    publish_fragment(
        &fixture.pile,
        Some(&fixture.key),
        faculties::schemas::body::DEFAULT_SCOPE_ID,
        Fragment::from(fragment.facts().clone()),
    )
    .unwrap();
    assert_eq!(fixture.body().list().unwrap().len(), 1);
    assert!(fixture.body().get(&format!("{id:x}")).is_err());
}

#[test]
fn invalid_mcp_arguments_fail_before_storage_or_hardware() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("missing.pile");
    let adapter = body::mcp::Body::new(pile.clone(), None);
    assert_eq!(adapter.tools().len(), 6);
    for (name, args) in [
        (
            "body_capture",
            serde_json::json!({"modality":"touch","pose":"{}","data_base64":"AA=="}),
        ),
        (
            "body_capture",
            serde_json::json!({"modality":"vision","pose":"{}","data_base64":"AA==","mime":"image/png","width":0,"height":1}),
        ),
        (
            "body_capture",
            serde_json::json!({"modality":"audio","pose":"{}","data_base64":"!","mime":"audio/wav"}),
        ),
        ("body_get", serde_json::json!({"id":"@-"})),
        (
            "body_get",
            serde_json::json!({"id":"a","output":"/tmp/file"}),
        ),
        ("body_view", serde_json::json!({"id":"a","max_bytes":0})),
        (
            "body_intent_set",
            serde_json::json!({"text":"move","daemon":"http://robot"}),
        ),
    ] {
        let error = parts(|out| adapter.call(name, json(args), out)).unwrap_err();
        assert!(
            error.downcast_ref::<InvalidArguments>().is_some(),
            "{name}: {error:#}"
        );
    }
    assert!(!pile.exists());
}

#[test]
fn emitter_failure_does_not_republish_capture_and_cli_export_is_exact() {
    let fixture = Fixture::new();
    let error = fixture
        .mcp()
        .call(
            "body_capture",
            json(serde_json::json!({"modality":"touch","pose":"literal"})),
            &mut Out::new(&mut |_| Err(anyhow!("sink closed"))),
        )
        .unwrap_err();
    assert!(error.to_string().contains("sink closed"));
    assert_eq!(fixture.commits(), 1);
    let raw: Bytes = vec![0, 255, 2].into();
    let receipt = fixture.body().capture(&vision(raw.clone())).unwrap();
    let cli = body::cli::Cli::try_parse_from([
        "body",
        "--pile",
        fixture.pile.to_str().unwrap(),
        "--key",
        fixture.key.to_str().unwrap(),
        "get",
        &format!("{:x}", receipt.id),
        "@-",
    ])
    .unwrap();
    assert!(
        matches!(&parts(|out|body::cli::execute(cli,out)).unwrap()[0],Part::Blob{bytes,..} if bytes==&raw)
    );
}

#[test]
fn native_actions_validate_the_whole_resident_chunk_before_device_access() {
    use body::device::{Action, Device};
    let mut bad = [0.0; 9];
    bad[8] = f64::NAN;
    let action = Action::Chunk {
        poses: vec![[0.0; 9], bad],
        interval: std::time::Duration::ZERO,
    };
    let error = Device::new("not-a-daemon".into(), "not-python".into())
        .act(&action)
        .unwrap_err();
    assert!(format!("{error:#}").contains("waypoint 1"));
}
