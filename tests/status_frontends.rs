//! Status operations and explicit CLI/MCP boundaries over temporary native piles.

use anybytes::Bytes;
use anyhow::{bail, Result};
use faculties::mcp::{Faculty, InvalidArguments, Server};
use faculties::out::{Out, Part};
use faculties::relations::{ProfileInput, Relations};
use faculties::status::{self, Status};
use faculties::storage::{initialize_signer, publish_fragment};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use triblespace::prelude::*;

struct Fixture {
    directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("status.pile");
        let key = directory.path().join("status.key");
        fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        Self {
            directory,
            pile,
            key,
        }
    }
    fn status(&self) -> Status {
        Status::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn mcp(&self) -> status::mcp::Status {
        status::mcp::Status::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn cli(&self, persona: Option<&str>, arguments: &[&str], input: Option<&str>) -> String {
        let mut command = Command::new(env!("CARGO_BIN_EXE_status"));
        clean_child(&mut command);
        command
            .arg("--pile")
            .arg(&self.pile)
            .arg("--key")
            .arg(&self.key);
        if let Some(persona) = persona {
            command.arg("--persona").arg(persona);
        }
        command
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        if let Some(input) = input {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        } else {
            drop(child.stdin.take());
        }
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap()
    }
}
fn clean_child(command: &mut Command) {
    for (name, _) in std::env::vars_os() {
        let text = name.to_string_lossy();
        if text.starts_with("TRIBLESPACE_")
            || text.starts_with("DRIVE_")
            || matches!(text.as_ref(), "PILE" | "PERSONA")
        {
            command.env_remove(name);
        }
    }
}
fn collect(execute: impl FnOnce(&mut Out<'_>) -> Result<()>) -> Result<String> {
    let mut result = String::new();
    execute(&mut Out::new(&mut |part| {
        match part {
            Part::Text { text } => result.push_str(&text),
            other => panic!("unexpected output {other:?}"),
        }
        Ok(())
    }))?;
    Ok(result)
}
fn call(faculty: &status::mcp::Status, tool: &str, args: Value) -> Result<String> {
    collect(|out| faculty.call(tool, Bytes::from(serde_json::to_vec(&args).unwrap()), out))
}
fn at(seconds: f64) -> status::IntervalValue {
    let epoch = hifitime::Epoch::from_unix_seconds(seconds);
    (epoch, epoch).try_to_inline().unwrap()
}
fn without_age(text: &str) -> String {
    text.lines()
        .map(|line| line.split("  (").next().unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn native_receipts_replay_exactly_and_owned_history_remains_stable() {
    let fixture = Fixture::new();
    let operations = fixture.status();
    let window = format!("{:x}", genid().id);
    let first = operations.set_at(&window, "  first  ", at(10.0)).unwrap();
    let replay = operations.set_at(&window, "first", at(10.0)).unwrap();
    assert_eq!(first.event, replay.event);
    assert_eq!(first.commit, replay.commit);
    assert_eq!(first.text, "first");
    assert_eq!(format!("{:x}", first.window), window);
    let before = operations.show(&window, 10).unwrap();
    let second = operations.set_at(&window, "second", at(11.0)).unwrap();
    assert_eq!(before.total, 1);
    assert_eq!(before.entries[0].event, first.event);
    let after = operations.show(&window, 1).unwrap();
    assert_eq!(after.total, 2);
    assert_eq!(after.entries.len(), 1);
    assert_eq!(after.entries[0].event, second.event);
    let zero = operations.show(&window, 0).unwrap();
    assert_eq!(zero.total, 2);
    assert!(zero.entries.is_empty());
    assert!(operations.set(&window, " \n ").is_err());
}

#[test]
fn cli_mcp_and_native_status_reads_agree() {
    let fixture = Fixture::new();
    let relations = Relations::new(fixture.pile.clone(), Some(fixture.key.clone()));
    let person = relations
        .add(
            ProfileInput {
                label: "Example".into(),
                aliases: vec!["alias".into()],
                ..Default::default()
            },
            None,
            &[],
        )
        .unwrap();
    let id = format!("{:x}", person.person);
    let operations = fixture.status();
    let event = operations.set_at("alias", "working", at(10.0)).unwrap();
    assert_eq!(event.window, person.person);
    // Retired labels deliberately remain selectable for Status history/writes.
    relations.retire(&id).unwrap();
    operations
        .set_at("Example", "still visible", at(11.0))
        .unwrap();
    let faculty = fixture.mcp();
    assert_eq!(
        without_age(&fixture.cli(None, &["list"], None)),
        without_age(&call(&faculty, "status_list", json!({})).unwrap())
    );
    assert_eq!(
        without_age(&fixture.cli(None, &["show", "alias", "--limit", "1"], None)),
        without_age(&call(&faculty, "status_show", json!({"window":"alias","limit":1})).unwrap())
    );
    assert_eq!(
        without_age(&collect(|out| status::render::show(&operations.show(&id, 1)?, out)).unwrap()),
        without_age(&call(&faculty, "status_show", json!({"window":id,"limit":1})).unwrap())
    );
    assert!(
        call(&faculty, "status_show", json!({"window":id,"limit":0}))
            .unwrap()
            .starts_with("status for Example")
    );
}

#[test]
fn cli_keeps_file_stdin_and_escape_input_but_mcp_text_is_literal() {
    let fixture = Fixture::new();
    let id = format!("{:x}", genid().id);
    let path = fixture.directory.path().join("text.txt");
    fs::write(&path, "file text").unwrap();
    let literal = format!("@{}", path.display());
    fixture.cli(Some(&id), &["set", &literal], None);
    assert_eq!(
        fixture.status().show(&id, 1).unwrap().entries[0].text,
        "file text"
    );
    fixture.cli(Some(&id), &["set", "@-"], Some("stdin text"));
    assert_eq!(
        fixture.status().show(&id, 1).unwrap().entries[0].text,
        "stdin text"
    );
    fixture.cli(Some(&id), &["set", "@@-"], None);
    assert_eq!(fixture.status().show(&id, 1).unwrap().entries[0].text, "@-");
    call(
        &fixture.mcp(),
        "status_set",
        json!({"persona":id,"text":literal}),
    )
    .unwrap();
    assert_eq!(
        fixture.status().show(&id, 1).unwrap().entries[0].text,
        literal
    );
    call(
        &fixture.mcp(),
        "status_set",
        json!({"persona":id,"text":"@-"}),
    )
    .unwrap();
    assert_eq!(fixture.status().show(&id, 1).unwrap().entries[0].text, "@-");
}

#[test]
fn discovery_and_bad_arguments_do_not_open_storage() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("absent.pile");
    let faculty = status::mcp::Status::new(pile.clone(), None);
    Server::new(&[&faculty]).unwrap();
    assert_eq!(
        faculty
            .tools()
            .iter()
            .map(|tool| tool.name)
            .collect::<Vec<_>>(),
        ["status_set", "status_list", "status_show"]
    );
    for (tool, raw) in [
        ("status_set", r#"{"text":"missing persona"}"#),
        (
            "status_set",
            r#"{"persona":"x","text":"first","text":"second"}"#,
        ),
        ("status_set", r#"{"persona":true,"text":"x"}"#),
        (
            "status_set",
            r#"{"persona":"x","text":"x","pile":"/elsewhere"}"#,
        ),
        ("status_list", r#"{"key":"secret"}"#),
        ("status_show", r#"{"window":"x","limit":-1}"#),
        ("status_show", r#"{"window":"x","limit":"2"}"#),
        ("status_show", r#"{"window":"x","limit":1.5}"#),
    ] {
        let error = collect(|out| faculty.call(tool, Bytes::from(raw.as_bytes().to_vec()), out))
            .unwrap_err();
        assert!(error.is::<InvalidArguments>(), "{tool}: {error:#}");
    }
    assert!(!pile.exists());
}

#[test]
fn current_and_limited_history_do_not_read_cold_unselected_text() {
    let fixture = Fixture::new();
    let window = genid().id;
    let id = format!("{window:x}");
    let old = status::status_fragment(window, "cold history", at(1.0)).unwrap();
    publish_fragment(
        &fixture.pile,
        Some(&fixture.key),
        faculties::schemas::status::DEFAULT_SCOPE_ID,
        old.into_facts().into(),
    )
    .unwrap();
    fixture
        .status()
        .set_at(&id, "resident current", at(2.0))
        .unwrap();
    assert_eq!(
        fixture.status().list().unwrap()[0].status.text,
        "resident current"
    );
    assert_eq!(
        fixture.status().show(&id, 1).unwrap().entries[0].text,
        "resident current"
    );
    assert!(fixture.status().show(&id, 0).unwrap().entries.is_empty());
    let mut parts = Vec::new();
    let error = fixture
        .mcp()
        .call(
            "status_show",
            Bytes::from(serde_json::to_vec(&json!({"window":id,"limit":2})).unwrap()),
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("Status text payload"));
    assert!(
        parts.is_empty(),
        "read failure must not leak a partial header/history"
    );
}

#[test]
fn explicit_persona_does_not_fall_back_to_the_process_environment() {
    if std::env::var_os("FACULTIES_STATUS_PERSONA_CHILD").is_none() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        clean_child(&mut command);
        let output = command
            .args([
                "--exact",
                "explicit_persona_does_not_fall_back_to_the_process_environment",
                "--nocapture",
            ])
            .env("FACULTIES_STATUS_PERSONA_CHILD", "1")
            .env("PERSONA", "an-unrelated-window")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    let fixture = Fixture::new();
    assert!(call(
        &fixture.mcp(),
        "status_set",
        json!({"text":"no implicit author"})
    )
    .unwrap_err()
    .is::<InvalidArguments>());
    let id = format!("{:x}", genid().id);
    call(
        &fixture.mcp(),
        "status_set",
        json!({"persona":id,"text":"explicit"}),
    )
    .unwrap();
    let rows = fixture.status().list().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(format!("{:x}", rows[0].window), id);
}

#[test]
fn output_failure_happens_after_one_publication() {
    let fixture = Fixture::new();
    let id = format!("{:x}", genid().id);
    let error = fixture
        .mcp()
        .call(
            "status_set",
            Bytes::from(serde_json::to_vec(&json!({"persona":id,"text":"published"})).unwrap()),
            &mut Out::new(&mut |_| bail!("recipient closed")),
        )
        .unwrap_err();
    assert!(error.to_string().contains("recipient closed"));
    assert_eq!(fixture.status().show(&id, 10).unwrap().total, 1);
}
