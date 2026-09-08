use anybytes::Bytes;
use clap::Parser;
use faculties::mcp::{Faculty, InvalidArguments, Server};
use faculties::out::{Out, Part};
use faculties::schemas::triage::{cog, exec, KIND_EXEC_REQUEST_ID, KIND_EXEC_RESULT_ID};
use faculties::triage::{cli, mcp, InspectOptions, Triage};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use triblespace::core::metadata;
use triblespace::prelude::*;

struct Fixture {
    _directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("triage.pile");
        let key = directory.path().join("explicit.key");
        fs::File::create(&pile).unwrap();
        faculties::storage::initialize_signer(&pile, Some(&key)).unwrap();
        Self {
            _directory: directory,
            pile,
            key,
        }
    }
    fn triage(&self) -> Triage {
        Triage::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn adapter(&self) -> mcp::Triage {
        mcp::Triage::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn call(&self, tool: &str, args: Value) -> Vec<Part> {
        let mut parts = Vec::new();
        self.adapter()
            .call(
                tool,
                serde_json::to_vec(&args).unwrap().into(),
                &mut Out::new(&mut |part| {
                    parts.push(part);
                    Ok(())
                }),
            )
            .unwrap();
        parts
    }
    fn cli(&self, args: &[&str]) -> Vec<Part> {
        let mut argv = vec![
            "triage".to_owned(),
            "--pile".into(),
            self.pile.to_str().unwrap().into(),
            "--key".into(),
            self.key.to_str().unwrap().into(),
        ];
        argv.extend(args.iter().map(|value| (*value).to_owned()));
        let cli = cli::Cli::try_parse_from(argv).unwrap();
        let mut parts = Vec::new();
        cli::execute(
            cli,
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
        parts
    }
    fn profile(&self) {
        faculties::headspace::Headspace::new(self.pile.clone(), Some(self.key.clone()))
            .add(
                &faculties::headspace::AddProfileOptions {
                    name: "diagnostic".to_owned(),
                    ..Default::default()
                },
                &mut Out::new(&mut |_| Ok(())),
            )
            .unwrap();
    }
    fn seed_turn(&self) {
        let request = entity! { metadata::tag: KIND_EXEC_REQUEST_ID, exec::command_text: "a recorded command, never execute me".to_owned(), metadata::created_at: point(10.0) };
        let request_id = request.root().unwrap();
        let mut events = vec![request];
        for (index, content) in ["literal @/no-host-file", "another preserved candidate"]
            .iter()
            .enumerate()
        {
            let context =
                serde_json::to_string(&json!([{"role":"user","content":content}])).unwrap();
            let thought = entity! { cog::context: context };
            let thought_id = thought.root().unwrap();
            events.push(thought);
            events.push(entity! { metadata::tag: KIND_EXEC_RESULT_ID, exec::about_request: request_id, exec::about_thought: thought_id, exec::stdout_text: "recorded output λ".to_owned(), exec::exit_code: 0_u64.to_inline(), metadata::finished_at: point(20.0 + index as f64) });
        }
        faculties::cognition::publish_events(&self.pile, Some(&self.key), events).unwrap();
    }
}
fn point(seconds: f64) -> Inline<inlineencodings::NsTAIInterval> {
    faculties::clock::point(hifitime::Epoch::from_tai_seconds(seconds)).unwrap()
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

#[test]
fn empty_and_zero_limit_reports_match_across_library_cli_and_mcp() {
    let fixture = Fixture::new();
    let mut direct = Vec::new();
    fixture
        .triage()
        .scan(
            &InspectOptions::default(),
            &mut Out::new(&mut |part| {
                direct.push(part);
                Ok(())
            }),
        )
        .unwrap();
    assert_eq!(direct, fixture.cli(&["scan"]));
    assert_eq!(direct, fixture.call("triage_scan", json!({})));
    assert!(
        text(&direct).contains("no persona is configured")
            || text(&direct).contains("Headspace is unsettled")
    );
    assert_eq!(
        fixture.cli(&["loops", "--recent", "0"]),
        fixture.call("triage_loops", json!({"recent":0}))
    );
    let empty = fixture.call("triage_timeline", json!({"recent":0}));
    assert_eq!(fixture.cli(&["timeline", "--recent", "0"]), empty);
    assert!(text(&empty).contains("rows: 0"));
}

#[test]
fn context_keeps_all_candidates_and_raw_is_literal_reconstructed_json_text() {
    let fixture = Fixture::new();
    fixture.profile();
    fixture.seed_turn();
    let raw = fixture.call("triage_context", json!({"turn":1,"raw":true}));
    assert_eq!(raw, fixture.cli(&["context", "--turn", "1", "--raw"]));
    assert!(matches!(raw.as_slice(), [Part::Text { .. }]));
    let rows: Vec<Value> = serde_json::from_str(&text(&raw)).unwrap();
    assert_eq!(rows.len(), 2);
    let contents: std::collections::BTreeSet<_> = rows
        .iter()
        .map(|row| row["messages"][0]["content"].as_str().unwrap())
        .collect();
    assert!(contents.contains("literal @/no-host-file"));
    assert!(contents.contains("another preserved candidate"));
    assert_ne!(rows[0]["result"], rows[1]["result"]);
    let full = fixture.call("triage_context", json!({"turn":1,"full":true}));
    assert_eq!(full, fixture.cli(&["context", "--turn", "1", "--full"]));
    assert!(text(&full).contains("candidates: 2"));
    let turn = fixture.call("triage_turn", json!({"turn":1,"full":true}));
    assert!(text(&turn).contains("Context candidates (2)"));
    assert!(text(&turn).contains("recorded output λ"));
}

#[test]
fn memory_inspection_remains_read_only_and_uses_exact_episode_identity() {
    let fixture = Fixture::new();
    fixture.profile();
    let memory = faculties::memory::Memory::new(fixture.pile.clone(), Some(fixture.key.clone()));
    let range = (
        hifitime::Epoch::from_tai_seconds(30.0),
        hifitime::Epoch::from_tai_seconds(31.0),
    );
    let episode = memory
        .create("literal episodic memory", Some(range), None)
        .unwrap();
    let id = format!("{:x}", episode.id);
    assert_eq!(
        fixture.cli(&["chunk", &id]),
        fixture.call("triage_chunk", json!({"id":id}))
    );
    assert_eq!(
        fixture.cli(&["cover", "--full"]),
        fixture.call("triage_cover", json!({"full":true}))
    );
    let maintained = fs::metadata(&fixture.pile).unwrap().len();
    fixture.call("triage_chunk", json!({"id":id}));
    fixture.call("triage_cover", json!({"full":true}));
    assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), maintained);
}

#[test]
fn rejected_output_stops_inspection_without_authoring_or_replaying_work() {
    let fixture = Fixture::new();
    fixture.seed_turn();
    fixture.call("triage_timeline", json!({}));
    let maintained = fs::metadata(&fixture.pile).unwrap().len();
    let mut outputs = 0;
    let error = fixture
        .triage()
        .timeline(
            80,
            &mut Out::new(&mut |_| {
                outputs += 1;
                anyhow::bail!("receiver closed")
            }),
        )
        .unwrap_err();
    assert!(error.to_string().contains("receiver closed"));
    assert_eq!(outputs, 1);
    assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), maintained);
}

#[test]
fn triage_mcp_decodes_strict_resident_arguments_before_opening_storage() {
    let directory = tempfile::tempdir().unwrap();
    let adapter = mcp::Triage::new(directory.path().join("absent.pile"), None);
    assert_eq!(adapter.tools().len(), 7);
    Server::new(&[&adapter]).unwrap();
    for (tool, arguments) in [
        ("triage_scan", r#"{"pile":"/host/pile"}"#),
        ("triage_scan", r#"{"stale_min":-1}"#),
        ("triage_loops", r#"{"recent":1,"recent":2}"#),
        ("triage_turn", r#"{"turn":0}"#),
        ("triage_context", r#"{"turn":0}"#),
        ("triage_chunk", r#"{"id":"@-","argv":["repair"]}"#),
        ("triage_cover", r#"{"full":true,"key":"/host/key"}"#),
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
