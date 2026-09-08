use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

use anybytes::Bytes;
use clap::Parser;
use faculties::mcp::{Faculty, InvalidArguments, Server};
use faculties::memory::operations::{parse_tai_timestamp, parse_time_range};
use faculties::memory::{cli, mcp, CoverOpts, Memory};
use faculties::out::{Out, Part};
use faculties::storage::initialize_signer;
use serde_json::{json, Value};

struct Fixture {
    directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("memory.pile");
        let key = directory.path().join("explicit.key");
        fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        Self {
            directory,
            pile,
            key,
        }
    }
    fn memory(&self) -> Memory {
        Memory::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn adapter(&self) -> mcp::Memory {
        mcp::Memory::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn cli(&self, args: &[&str]) -> Vec<Part> {
        let mut argv = vec![
            "memory".to_owned(),
            "--pile".into(),
            self.pile.to_str().unwrap().into(),
            "--key".into(),
            self.key.to_str().unwrap().into(),
        ];
        argv.extend(args.iter().map(|arg| (*arg).to_owned()));
        let cli = cli::Cli::try_parse_from(argv).unwrap();
        let mut parts = Vec::new();
        let code = cli::execute(
            cli,
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
        assert_eq!(code, 0);
        parts
    }
    fn call(&self, name: &str, args: Value) -> Vec<Part> {
        let mut parts = Vec::new();
        self.adapter()
            .call(
                name,
                serde_json::to_vec(&args).unwrap().into(),
                &mut Out::new(&mut |part| {
                    parts.push(part);
                    Ok(())
                }),
            )
            .unwrap();
        parts
    }
}
fn text(parts: &[Part]) -> String {
    parts
        .iter()
        .map(|part| match part {
            Part::Text { text } => text.as_str(),
            other => panic!("expected text, got {other:?}"),
        })
        .collect()
}
fn receipt_id(parts: &[Part]) -> String {
    text(parts)
        .lines()
        .find_map(|line| line.strip_prefix("id: "))
        .unwrap()
        .to_owned()
}
const RANGE: &str = "2026-09-01T00:00:00..2026-09-02T00:00:00";

#[test]
fn library_cli_and_mcp_agree_on_resident_reads_and_exact_cover_text() {
    let fixture = Fixture::new();
    let memory = fixture.memory();
    let created = memory
        .create(
            "Grüße, this memory has texture.  \n",
            Some(parse_time_range(RANGE).unwrap()),
            None,
        )
        .unwrap();
    let id = format!("{:x}", created.id);
    assert_eq!(
        fixture.cli(&[&id]),
        fixture.call("memory_show", json!({"selector":id}))
    );
    assert_eq!(
        text(&fixture.cli(&[RANGE])),
        "Grüße, this memory has texture.\n"
    );
    for (verb, tool, arguments) in [
        ("meta", "memory_meta", json!({"selector":id})),
        ("provenance", "memory_provenance", json!({"id":id})),
    ] {
        assert_eq!(fixture.cli(&[verb, &id]), fixture.call(tool, arguments));
    }
    assert_eq!(
        fixture.cli(&["search", "texture"]),
        fixture.call("memory_search", json!({"query":"texture"}))
    );
    assert_eq!(
        fixture.cli(&["list", "1d"]),
        fixture.call("memory_list", json!({"grain":"1d"}))
    );
    assert_eq!(
        fixture.cli(&["check", "1d"]),
        fixture.call("memory_check", json!({"grain":"1d"}))
    );
    assert_eq!(
        fixture.cli(&["density", "1d"]),
        fixture.call("memory_density", json!({"grain":"1d"}))
    );
    let mut options = CoverOpts::plain(1000);
    options.chunk_overhead = 17;
    let report = memory.context(&options).unwrap();
    assert_eq!(
        text(&fixture.cli(&["context", "--chars", "1000", "--chunk-overhead", "17"])),
        report.text
    );
    let mcp = fixture.call(
        "memory_context",
        json!({"budget_chars":1000,"chunk_overhead":17}),
    );
    assert_eq!(
        mcp[0],
        Part::Text {
            text: report.text.clone()
        }
    );
    assert!(!report.text.contains("memory context —"));
    assert!(report
        .diagnostics
        .iter()
        .any(|value| value.contains("greedy SPACE order")));
    assert!(text(&mcp[1..]).contains("outside the charged cover text"));
}

#[test]
fn mcp_text_is_literal_and_only_cli_expands_host_input() {
    let fixture = Fixture::new();
    let path = fixture.directory.path().join("summary.txt");
    fs::write(&path, "loaded from a CLI file").unwrap();
    let argument = format!("@{}", path.display());
    let literal =
        receipt_id(&fixture.call("memory_create", json!({"range":RANGE,"summary":argument})));
    assert_eq!(
        text(&fixture.call("memory_show", json!({"selector":literal}))),
        format!("{argument}\n")
    );
    let expanded = receipt_id(&fixture.cli(&["create", RANGE, &argument]));
    assert_eq!(text(&fixture.cli(&[&expanded])), "loaded from a CLI file\n");
    let escaped = receipt_id(&fixture.cli(&["create", RANGE, "@@literal"]));
    assert_eq!(text(&fixture.cli(&[&escaped])), "@literal\n");
    let help = fixture.cli(&["create", "--help"]);
    assert!(text(&help).starts_with("usage: memory create"));
    let help_memory =
        receipt_id(&fixture.call("memory_create", json!({"range":RANGE,"summary":"--help"})));
    assert_eq!(text(&fixture.cli(&[&help_memory])), "--help\n");
}

#[test]
fn respan_moves_coordinates_without_changing_the_episode_or_its_hard_references() {
    let fixture = Fixture::new();
    let original = fixture
        .memory()
        .create(
            "immutable recollection",
            Some(parse_time_range(RANGE).unwrap()),
            None,
        )
        .unwrap();
    let original_id = format!("{:x}", original.id);
    let moved_range = "2026-09-03T00:00:00..2026-09-04T00:00:00";
    let moved = receipt_id(&fixture.call(
        "memory_respan",
        json!({"id":original_id,"range":moved_range}),
    ));
    assert_eq!(
        text(&fixture.cli(&[&original_id])),
        "immutable recollection\n"
    );
    assert_eq!(fixture.cli(&[&original_id]), fixture.cli(&[&moved]));
    let cover = fixture.memory().context(&CoverOpts::plain(2000)).unwrap();
    assert!(cover.text.contains(moved_range));
    assert!(!cover.text.contains(RANGE));
    let linked = receipt_id(&fixture.call(
        "memory_create",
        json!({"range":RANGE,"summary":format!("[why](memory:{original_id})")}),
    ));
    assert!(text(&fixture.call("memory_meta", json!({"selector":linked}))).contains(&original_id));
}

#[test]
fn image_memory_returns_native_validated_bytes_but_cover_placeholder_is_unchanged() {
    let fixture = Fixture::new();
    let mut encoded = Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
        2,
        3,
        image::Rgba([12, 90, 34, 255]),
    ))
    .write_to(&mut encoded, image::ImageFormat::Png)
    .unwrap();
    let bytes = encoded.into_inner();
    let created = fixture
        .memory()
        .image(&bytes, parse_time_range(RANGE).unwrap())
        .unwrap();
    let id = format!("{:x}", created.id);
    let displayed = fixture.call("memory_show", json!({"selector":id}));
    assert_eq!(displayed, fixture.cli(&[&id]));
    assert!(
        matches!(&displayed[1], Part::Image { bytes: actual, mime_type } if actual.as_ref() == bytes && mime_type == "image/png")
    );
    let expected = format!("\n{RANGE}\n[image memory @ {RANGE}]\n");
    assert_eq!(
        fixture
            .memory()
            .context(&CoverOpts::plain(2000))
            .unwrap()
            .text,
        expected
    );
    let corrupt = fixture
        .memory()
        .image(b"not an image", parse_time_range(RANGE).unwrap())
        .unwrap();
    let error = fixture
        .adapter()
        .call(
            "memory_show",
            Bytes::from(format!(r#"{{"selector":"{:x}"}}"#, corrupt.id)),
            &mut Out::new(&mut |_| Ok(())),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("recognized format"));
}

#[test]
fn replay_personas_are_explicit_and_a_failed_batch_output_does_not_advance() {
    let fixture = Fixture::new();
    let memory = fixture.memory();
    for summary in ["same-coordinate amber", "same-coordinate cobalt"] {
        memory
            .create(summary, Some(parse_time_range(RANGE).unwrap()), None)
            .unwrap();
    }
    fixture.call(
        "memory_replay_start",
        json!({"persona":"reader-a","grain":"1d","from":"2026-09-01T00:00:00"}),
    );
    fixture.call(
        "memory_replay_start",
        json!({"persona":"reader-b","grain":"1d","from":"2026-09-01T00:00:00"}),
    );
    let error = memory
        .replay(
            "reader-a",
            1,
            &mut Out::new(&mut |_| anyhow::bail!("receiver rejected output")),
        )
        .unwrap_err();
    assert!(error.to_string().contains("receiver rejected"));
    let first = fixture.call("memory_replay", json!({"persona":"reader-a","count":1}));
    assert!(text(&first).contains("same-coordinate amber"));
    assert!(text(&first).contains("same-coordinate cobalt"));
    assert!(text(&first).contains("batch: 2 chunk(s)"));
    assert_eq!(
        first,
        fixture.call("memory_replay", json!({"persona":"reader-b","count":1}))
    );
    assert!(
        text(&fixture.call("memory_replay", json!({"persona":"reader-a"})))
            .contains("nothing after the cursor")
    );
    fixture.call("memory_replay_stop", json!({"persona":"reader-a"}));
    assert!(memory
        .replay("reader-a", 1, &mut Out::new(&mut |_| Ok(())))
        .is_err());
}

#[test]
fn explicit_consolidation_publishes_a_memory_and_advances_only_that_persona() {
    let fixture = Fixture::new();
    fixture.call(
        "memory_consolidate_start",
        json!({"persona":"writer-a","timestamp":"2026-09-01T00:00:00"}),
    );
    let id = receipt_id(&fixture.call(
        "memory_consolidate",
        json!({"persona":"writer-a","until":"2026-09-02T00:00:00","summary":"@- stays literal"}),
    ));
    assert_eq!(text(&fixture.cli(&[&id])), "@- stays literal\n");
    assert!(fixture
        .memory()
        .consolidate(
            "writer-b",
            parse_tai_timestamp("2026-09-03T00:00:00").unwrap(),
            "no edge"
        )
        .is_err());
    fixture.call("memory_consolidate_stop", json!({"persona":"writer-a"}));
}

#[test]
fn mcp_has_only_explicit_resident_tools_and_rejects_argv_paths_and_duplicates() {
    let directory = tempfile::tempdir().unwrap();
    let adapter = mcp::Memory::new(directory.path().join("absent.pile"), None);
    let names: Vec<_> = adapter.tools().iter().map(|tool| tool.name).collect();
    assert_eq!(names.len(), 24);
    assert!(!names.iter().any(|name| name.contains("cover_")));
    Server::new(&[&adapter]).unwrap();
    for (tool, arguments) in [
        ("memory_create", r#"{"summary":"one","summary":"two"}"#),
        (
            "memory_create",
            r#"{"summary":"literal","pile":"/host/pile"}"#,
        ),
        (
            "memory_image",
            r#"{"when":"2026-09-01T00:00:00","path":"/host/image"}"#,
        ),
        ("memory_context", r#"{"argv":["--remove","secret"]}"#),
        ("memory_context", r#"{"budget_chars":-1}"#),
        ("memory_replay", r#"{"count":1}"#),
        ("memory_replay", r#"{"persona":"reader","key":"/host/key"}"#),
    ] {
        let mut emitted = 0;
        let error = adapter
            .call(
                tool,
                Bytes::from(arguments),
                &mut Out::new(&mut |_| {
                    emitted += 1;
                    Ok(())
                }),
            )
            .unwrap_err();
        assert!(
            error.downcast_ref::<InvalidArguments>().is_some(),
            "{tool}: {error:#}"
        );
        assert_eq!(emitted, 0);
    }
}

#[test]
fn malformed_calendar_grain_and_threshold_inputs_are_fallible_not_panics() {
    for timestamp in [
        "2026-99-01T00:00:00",
        "2026-02-30T00:00:00",
        "2026-09-01T99:00:00",
    ] {
        assert!(parse_tai_timestamp(timestamp).is_err());
    }
    let directory = tempfile::tempdir().unwrap();
    let memory = Memory::new(directory.path().join("absent.pile"), None);
    for grain in [
        "",
        "é",
        "1é",
        "0h",
        "-1h",
        "170141183460469231731687303715884105727w",
    ] {
        let error = memory.replay_start("reader", grain, None).unwrap_err();
        assert!(format!("{error:#}").contains("grain"), "{error:#}");
    }
    let mut options = CoverOpts::plain(1000);
    options.sim_threshold = f32::NAN;
    assert!(memory
        .context(&options)
        .unwrap_err()
        .to_string()
        .contains("sim_threshold"));
}
