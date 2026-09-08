use std::collections::BTreeSet;
use std::io::Cursor;
use std::time::Duration;

use faculties::mcp::{Faculty, InvalidArguments};
use faculties::out::{Out, Part};
use faculties::viewer::{self, CaptureOptions, CapturePage, Target, Viewer};

fn tiny_page() -> CapturePage {
    let mut encoded = Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
        2,
        1,
        image::Rgba([10, 20, 30, 255]),
    ))
    .write_to(&mut encoded, image::ImageFormat::Png)
    .unwrap();
    CapturePage {
        card_index: 1,
        page_index: 0,
        page_count: 1,
        width: 2,
        height: 1,
        png: encoded.into_inner().into(),
    }
}

#[test]
fn target_inventory_and_original_dashboard_order_are_explicit() {
    assert_eq!(Target::ALL.len(), 12);
    assert_eq!(
        Target::ALL
            .into_iter()
            .map(Target::name)
            .collect::<BTreeSet<_>>()
            .len(),
        12
    );
    assert_eq!(
        Target::Dashboard.card_names(),
        &[
            "storage",
            "status",
            "headspace",
            "timeline",
            "gauge",
            "wiki",
            "compass",
            "decide",
            "mail",
            "planner",
            "messages",
            "discord",
            "teams",
            "relations",
            "memory",
            "files",
            "triage",
            "atlas",
        ]
    );
    for target in Target::ALL
        .into_iter()
        .filter(|target| *target != Target::Dashboard)
    {
        assert_eq!(target.card_names(), &["storage", target.name()]);
    }
    let adapter = viewer::mcp::Viewer::new("/not-opened.pile", None);
    assert_eq!(adapter.tools().len(), 1);
    let schema: serde_json::Value = serde_json::from_str(adapter.tools()[0].input_schema).unwrap();
    let targets: BTreeSet<_> = schema["properties"]["target"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(targets, Target::ALL.into_iter().map(Target::name).collect());
    assert_eq!(schema["required"], serde_json::json!(["target"]));
}

#[test]
fn all_native_bounds_fail_before_gpu_or_storage_acquisition() {
    let directory = tempfile::tempdir().unwrap();
    let viewer = Viewer::new(
        directory.path().join("absent.pile"),
        Some(directory.path().join("absent.key")),
    );
    let invalid = [
        CaptureOptions {
            scale: 0.0,
            ..Default::default()
        },
        CaptureOptions {
            scale: f32::NAN,
            ..Default::default()
        },
        CaptureOptions {
            scale: f32::INFINITY,
            ..Default::default()
        },
        CaptureOptions {
            scale: 4.1,
            ..Default::default()
        },
        CaptureOptions {
            settle_timeout: Duration::from_millis(5001),
            ..Default::default()
        },
        CaptureOptions {
            max_images: 0,
            ..Default::default()
        },
        CaptureOptions {
            max_images: 257,
            ..Default::default()
        },
        CaptureOptions {
            max_bytes: 0,
            ..Default::default()
        },
        CaptureOptions {
            max_bytes: usize::MAX,
            ..Default::default()
        },
    ];
    for options in invalid {
        assert!(viewer
            .capture_with(Target::Files, &options, |_| panic!(
                "invalid capture emitted"
            ))
            .is_err());
    }
    CaptureOptions {
        settle_timeout: Duration::ZERO,
        ..Default::default()
    }
    .validate()
    .unwrap();
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn resident_pages_emit_metadata_then_exact_png_not_a_file_resource() {
    let page = tiny_page();
    let mut output = Vec::new();
    page.emit(
        Target::Status,
        &mut Out::new(&mut |part| {
            output.push(part);
            Ok(())
        }),
    )
    .unwrap();
    assert_eq!(output.len(), 2);
    let Part::Text { text } = &output[0] else {
        panic!("metadata precedes image")
    };
    let metadata: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(metadata["target"], "status");
    assert_eq!(metadata["card"], "status");
    assert_eq!(metadata["card_index"], 1);
    assert_eq!(metadata["page_index"], 0);
    assert_eq!(metadata["page_count"], 1);
    assert_eq!(metadata["width"], 2);
    let Part::Image { bytes, mime_type } = &output[1] else {
        panic!("resident image, not path/blob")
    };
    assert_eq!(mime_type, "image/png");
    assert_eq!(bytes, &page.png);
    let decoded = image::load_from_memory(bytes.as_ref())
        .unwrap()
        .into_rgba8();
    assert_eq!(decoded.dimensions(), (2, 1));
    assert_eq!(decoded.get_pixel(1, 0).0, [10, 20, 30, 255]);
}

#[test]
fn output_failure_retains_exact_prefix_and_never_repeats_it() {
    let page = tiny_page();
    for fail_at in [0, 1] {
        let mut calls = 0;
        let mut accepted = Vec::new();
        let error = page
            .emit(
                Target::Files,
                &mut Out::new(&mut |part| {
                    let index = calls;
                    calls += 1;
                    if index == fail_at {
                        anyhow::bail!("receiver closed");
                    }
                    accepted.push(part);
                    Ok(())
                }),
            )
            .unwrap_err();
        assert!(error.to_string().contains("receiver closed"));
        assert_eq!(calls, fail_at + 1);
        assert_eq!(accepted.len(), fail_at);
        assert!(accepted
            .iter()
            .all(|part| matches!(part, Part::Text { .. })));
    }
}

#[test]
fn mcp_is_strict_finite_and_cannot_supply_host_paths_or_harness_flags() {
    let directory = tempfile::tempdir().unwrap();
    let adapter = viewer::mcp::Viewer::new(directory.path().join("absent.pile"), None);
    for input in [
        "[]",
        "{}",
        r#"{"target":"status","target":"files"}"#,
        r#"{"target":"@/host/path"}"#,
        r#"{"target":"status","pile":"/host/path"}"#,
        r#"{"target":"status","key":"/host/key"}"#,
        r#"{"target":"status","out_dir":"/host/path"}"#,
        r#"{"target":"status","export":true}"#,
        r#"{"target":"status","persona":"ambient"}"#,
        r#"{"target":"status","scale":0}"#,
        r#"{"target":"status","scale":1e99}"#,
        r#"{"target":"status","settle_ms":5001}"#,
        r#"{"target":"status","max_images":0}"#,
        r#"{"target":"status","max_bytes":0}"#,
    ] {
        let error = adapter
            .call(
                "viewer_capture",
                input.to_owned().into(),
                &mut Out::new(&mut |_| panic!("invalid capture emitted")),
            )
            .unwrap_err();
        assert!(
            error.downcast_ref::<InvalidArguments>().is_some(),
            "{input}: {error:#}"
        );
    }
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
#[cfg(not(feature = "widgets"))]
fn unavailable_renderer_fails_honestly_without_touching_launcher_paths() {
    let directory = tempfile::tempdir().unwrap();
    let adapter = viewer::mcp::Viewer::new(directory.path().join("absent.pile"), None);
    for target in Target::ALL {
        let error = adapter
            .call(
                "viewer_capture",
                format!("{{\"target\":\"{}\"}}", target.name()).into(),
                &mut Out::new(&mut |_| panic!("renderer unavailable")),
            )
            .unwrap_err();
        assert!(error.to_string().contains("native `widgets` feature"));
        assert!(error.downcast_ref::<InvalidArguments>().is_none());
    }
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn cli_information_is_resolved_without_the_notebook() {
    for flag in ["--help", "-h"] {
        let text = viewer::cli::information("files-capture", &[flag.into()]).unwrap();
        assert!(text.contains("Usage: files-capture"));
        for name in [
            "--pile",
            "--headless",
            "--out-dir",
            "--scale",
            "--headless-wait-ms",
            "--export",
            "--export-dir",
        ] {
            assert!(text.contains(name));
        }
    }
    assert!(viewer::cli::information("viewer", &["--version".into()])
        .unwrap()
        .starts_with("viewer "));
    assert!(viewer::cli::information("viewer", &["--headless".into()]).is_none());
}

#[test]
#[cfg(feature = "widgets")]
fn thin_wrapper_help_and_version_do_not_open_a_window_or_gpu() {
    for binary in [
        env!("CARGO_BIN_EXE_viewer"),
        env!("CARGO_BIN_EXE_files-capture"),
    ] {
        for flag in ["--help", "--version"] {
            let output = std::process::Command::new(binary)
                .arg(flag)
                .env("PILE", "/deliberately-absent.pile")
                .env_remove("DISPLAY")
                .env_remove("WAYLAND_DISPLAY")
                .env_remove("DRIVE_ENDPOINT")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!output.stdout.is_empty());
        }
    }
}
