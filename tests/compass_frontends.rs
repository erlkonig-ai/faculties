//! Library-first Compass actions, CLI/MCP parity, and transport-specific input.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anybytes::Bytes;
use anyhow::{bail, Result};
use faculties::compass::{self, AddOptions, Compass, ListOptions, NoteOptions};
use faculties::mcp::{Faculty, InvalidArguments, Server};
use faculties::out::{Out, Part};
use faculties::schemas::compass::{board, KIND_NOTE_ID, KIND_STATUS_ID};
use faculties::storage::{initialize_signer, load_signer, publish_fragment};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::prelude::*;

struct Fixture {
    directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("compass.pile");
        let key = directory.path().join("compass.key");
        File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        Self {
            directory,
            pile,
            key,
        }
    }

    fn operations(&self) -> Compass {
        Compass::new(self.pile.clone(), Some(self.key.clone()))
    }

    fn mcp(&self) -> compass::mcp::Compass {
        compass::mcp::Compass::new(self.pile.clone(), Some(self.key.clone()))
    }

    fn snapshot(&self) -> (TribleSet, PileSnapshot) {
        let signer = load_signer(&self.pile, Some(&self.key)).unwrap();
        let mut pile = Pile::open(&self.pile).unwrap();
        let result = compass::materialize_collection(&mut pile, &signer).unwrap();
        pile.close().unwrap();
        result
    }

    fn cli(&self, arguments: &[&str], stdin: Option<&str>) -> String {
        let mut command = Command::new(env!("CARGO_BIN_EXE_compass"));
        clean_child(&mut command);
        command
            .arg("--pile")
            .arg(&self.pile)
            .arg("--key")
            .arg(&self.key)
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        if let Some(input) = stdin {
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
        let name_text = name.to_string_lossy();
        if name_text.starts_with("TRIBLESPACE_")
            || name_text.starts_with("DRIVE_")
            || matches!(name_text.as_ref(), "PILE" | "PERSONA")
        {
            command.env_remove(name);
        }
    }
}

fn collect(operation: impl FnOnce(&mut Out<'_>) -> Result<()>) -> Result<String> {
    let mut text = String::new();
    operation(&mut Out::new(&mut |part| {
        match part {
            Part::Text { text: part } => text.push_str(&part),
            other => panic!("Compass emitted non-text output: {other:?}"),
        }
        Ok(())
    }))?;
    Ok(text)
}

fn call(faculty: &compass::mcp::Compass, name: &str, arguments: serde_json::Value) -> String {
    collect(|output| {
        faculty.call(
            name,
            Bytes::from(serde_json::to_vec(&arguments).unwrap()),
            output,
        )
    })
    .unwrap()
}

#[test]
fn direct_operations_return_action_ids_and_preserve_additive_semantics() {
    let fixture = Fixture::new();
    let operations = fixture.operations();
    let tags = vec!["test".into()];
    let parent = operations
        .add(
            "Parent",
            AddOptions {
                tags: &tags,
                note: Some("initial note"),
                ..AddOptions::default()
            },
        )
        .unwrap();
    let parent_id = format!("{:x}", parent.goal);
    let child = operations
        .add(
            "Child",
            AddOptions {
                parent: Some(&parent_id),
                ..AddOptions::default()
            },
        )
        .unwrap();
    let child_id = format!("{:x}", child.goal);
    assert_eq!(operations.resolve(&parent_id[..12]).unwrap(), parent.goal);
    let moved = operations.move_goal(&child_id, " DOING ", None).unwrap();
    assert_eq!(moved.goal, child.goal);
    assert_eq!(moved.status, "doing");
    assert_ne!(moved.event, child.status_event);

    let supersedes = vec![format!("{:x}", parent.note.unwrap())];
    let references = vec!["git:DEADBEEF".into()];
    let noted = operations
        .note(
            &parent_id,
            "replacement [wiki](wiki:ABCD)",
            NoteOptions {
                supersedes: &supersedes,
                references: &references,
                tags: &tags,
                ..NoteOptions::default()
            },
        )
        .unwrap();
    assert_eq!(noted.goal, parent.goal);
    assert_ne!(Some(noted.note), parent.note);
    assert!(operations.prioritize(&parent_id, &child_id).is_err());

    let other = operations.add("Other", AddOptions::default()).unwrap();
    let other_id = format!("{:x}", other.goal);
    let priority = operations.prioritize(&child_id, &other_id).unwrap();
    assert_eq!(
        (priority.higher, priority.lower, priority.active),
        (child.goal, other.goal, true)
    );
    let removed = operations.deprioritize(&child_id, &other_id).unwrap();
    assert!(!removed.active);
    assert_ne!(priority.event, removed.event);
    assert!(operations.deprioritize(&child_id, &other_id).is_err());

    let show = operations.show(&parent_id).unwrap();
    assert!(show.contains("initial note"));
    assert!(show.contains("replacement"));
    assert!(show.contains(&format!("supersedes: {}", supersedes[0])));
    let listed = operations
        .list(ListOptions {
            tags: &tags,
            all: true,
            ..ListOptions::default()
        })
        .unwrap();
    assert!(listed.contains("Parent"));
    assert!(!listed.contains("Other"));

    let (facts, _) = fixture.snapshot();
    assert_eq!(compass::goal_ids(&facts).len(), 3);
    assert_eq!(compass::note_ids(&facts).len(), 2);
    assert!(exists!(
        pattern!(&facts, [{ moved.event @ metadata::tag: &KIND_STATUS_ID, board::status_of: &child.goal }])
    ));
    assert!(exists!(
        pattern!(&facts, [{ noted.note @ metadata::tag: &KIND_NOTE_ID, board::task: &parent.goal }])
    ));
    assert!(!compass::active_priority_edges(&facts).contains(&(child.goal, other.goal)));
}

#[test]
fn cli_mcp_and_direct_reads_agree() {
    let fixture = Fixture::new();
    let operations = fixture.operations();
    let goal = operations
        .add(
            "Same projection",
            AddOptions {
                note: Some("one note"),
                ..AddOptions::default()
            },
        )
        .unwrap();
    let id = format!("{:x}", goal.goal);
    let faculty = fixture.mcp();
    assert_eq!(
        fixture.cli(&["show", &id], None),
        operations.show(&id).unwrap()
    );
    assert_eq!(
        call(&faculty, "compass_show", serde_json::json!({"id":id})),
        operations.show(&id).unwrap()
    );
    assert_eq!(
        fixture.cli(&["list"], None),
        operations.list(ListOptions::default()).unwrap()
    );
    assert_eq!(
        call(&faculty, "compass_list", serde_json::json!({})),
        operations.list(ListOptions::default()).unwrap()
    );
    assert_eq!(
        fixture.cli(&["resolve", &id[..12]], None),
        format!("{id}\n")
    );
    assert_eq!(
        call(
            &faculty,
            "compass_resolve",
            serde_json::json!({"prefix":&id[..12]})
        ),
        format!("{id}\n")
    );
}

#[test]
fn mcp_and_cli_priority_actions_share_native_state_and_presentation() {
    let fixture = Fixture::new();
    let operations = fixture.operations();
    let higher = operations.add("Higher", AddOptions::default()).unwrap();
    let lower = operations.add("Lower", AddOptions::default()).unwrap();
    let higher_id = format!("{:x}", higher.goal);
    let lower_id = format!("{:x}", lower.goal);
    let faculty = fixture.mcp();
    assert_eq!(
        call(
            &faculty,
            "compass_prioritize",
            serde_json::json!({"higher":higher_id,"over":lower_id}),
        ),
        "Higher > Lower\n"
    );
    let (facts, _) = fixture.snapshot();
    assert!(compass::active_priority_edges(&facts).contains(&(higher.goal, lower.goal)));
    assert_eq!(
        fixture.cli(&["deprioritize", &higher_id, "--over", &lower_id], None),
        "Removed: Higher > Lower\n"
    );
    assert_eq!(
        fixture.cli(&["prioritize", &higher_id, "--over", &lower_id], None),
        "Higher > Lower\n"
    );
    assert_eq!(
        call(
            &faculty,
            "compass_deprioritize",
            serde_json::json!({"higher":higher_id,"over":lower_id}),
        ),
        "Removed: Higher > Lower\n"
    );
    let (facts, _) = fixture.snapshot();
    assert!(!compass::active_priority_edges(&facts).contains(&(higher.goal, lower.goal)));
}

#[test]
fn mcp_title_and_notes_are_literal_even_when_a_matching_host_file_exists() {
    let fixture = Fixture::new();
    let source = fixture.directory.path().join("must-not-read.txt");
    std::fs::write(&source, "HOST CONTENT MUST NOT BE INGESTED").unwrap();
    let literal = format!("@{}", source.display());
    let faculty = fixture.mcp();
    call(
        &faculty,
        "compass_add",
        serde_json::json!({"title":literal,"note":"@-"}),
    );
    let (facts, _) = fixture.snapshot();
    let goal = *compass::goal_ids(&facts).iter().next().unwrap();
    let id = format!("{goal:x}");
    call(
        &faculty,
        "compass_note",
        serde_json::json!({"id":id,"note":literal}),
    );
    let shown = fixture.operations().show(&id).unwrap();
    assert!(shown.contains(&format!("Title: {literal}")));
    assert!(shown.contains("  @-"));
    assert!(!shown.contains("HOST CONTENT"));
    assert_eq!(shown.matches(&literal).count(), 2);
}

#[test]
fn cli_keeps_file_stdin_and_literal_escape_input_conventions() {
    let fixture = Fixture::new();
    let title_path = fixture.directory.path().join("title.txt");
    let note_path = fixture.directory.path().join("note.txt");
    std::fs::write(&title_path, "title from file").unwrap();
    std::fs::write(&note_path, "note from file").unwrap();
    fixture.cli(
        &[
            "add",
            &format!("@{}", title_path.display()),
            "--note",
            &format!("@{}", note_path.display()),
        ],
        None,
    );
    let (facts, _) = fixture.snapshot();
    let goal = *compass::goal_ids(&facts).iter().next().unwrap();
    let id = format!("{goal:x}");
    assert!(fixture
        .operations()
        .show(&id)
        .unwrap()
        .contains("note from file"));
    fixture.cli(&["note", &id, "@@-"], None);
    assert!(fixture.operations().show(&id).unwrap().contains("  @-"));
    fixture.cli(&["add", "@-"], Some("title from stdin"));
    fixture.cli(&["add", "@@literal title"], None);
    let listed = fixture
        .operations()
        .list(ListOptions {
            all: true,
            ..ListOptions::default()
        })
        .unwrap();
    assert!(listed.contains("title from file"));
    assert!(listed.contains("title from stdin"));
    assert!(listed.contains("@literal title"));
}

#[test]
fn discovery_and_invalid_arguments_do_not_open_the_pile() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("must-not-exist.pile");
    let faculty = compass::mcp::Compass::new(pile.clone(), None);
    let _server = Server::new(&[&faculty]).unwrap();
    let names: Vec<_> = faculty.tools().iter().map(|tool| tool.name).collect();
    assert_eq!(
        names,
        [
            "compass_add",
            "compass_list",
            "compass_move",
            "compass_note",
            "compass_show",
            "compass_prioritize",
            "compass_deprioritize",
            "compass_resolve",
        ]
    );
    for (tool, raw) in [
        ("compass_add", r#"{"title":"first","title":"second"}"#),
        ("compass_add", r#"{"title":"ok","pile":"/elsewhere"}"#),
        ("compass_add", r#"{"title":"ok","persona":true}"#),
        ("compass_list", r#"{"all":"true"}"#),
        ("compass_list", r#"{"tags":[1]}"#),
        ("compass_move", r#"{"id":"x","status":1}"#),
        (
            "compass_note",
            r#"{"id":"x","note":"first","note":"second"}"#,
        ),
        (
            "compass_note",
            r#"{"id":"x","note":"ok","supersedes":true}"#,
        ),
        ("compass_show", r#"{"id":"x","key":"wrong"}"#),
        ("compass_prioritize", r#"{"higher":"x","over":[]}"#),
        ("compass_deprioritize", r#"{"higher":"x"}"#),
        (
            "compass_resolve",
            r#"{"prefix":"x","output":"/tmp/target"}"#,
        ),
    ] {
        let error = collect(|out| faculty.call(tool, Bytes::from(raw.as_bytes().to_vec()), out))
            .unwrap_err();
        assert!(error.is::<InvalidArguments>(), "{tool}: {error:#}");
    }
    assert!(!pile.exists());
}

#[test]
fn explicit_mcp_persona_attributes_add_move_and_note_events() {
    let fixture = Fixture::new();
    let person = genid().id;
    let (fragment, _, _) = faculties::relations::person_fragment(
        person,
        faculties::relations::ProfileInput {
            label: "explicit-tester".into(),
            ..Default::default()
        },
    )
    .unwrap();
    publish_fragment(
        &fixture.pile,
        Some(&fixture.key),
        faculties::schemas::relations::DEFAULT_SCOPE_ID,
        fragment,
    )
    .unwrap();
    let faculty = fixture.mcp();
    call(
        &faculty,
        "compass_add",
        serde_json::json!({
            "title":"attributed", "note":"initial", "persona":"explicit-tester"
        }),
    );
    let (facts, _) = fixture.snapshot();
    let goal = *compass::goal_ids(&facts).iter().next().unwrap();
    let id = format!("{goal:x}");
    call(
        &faculty,
        "compass_move",
        serde_json::json!({"id":id,"status":"doing","persona":format!("{person:x}")}),
    );
    call(
        &faculty,
        "compass_note",
        serde_json::json!({"id":id,"note":"attributed too","persona":"explicit-tester"}),
    );
    let (facts, _) = fixture.snapshot();
    let by: Vec<Id> =
        find!(actor: Id, pattern!(&facts, [{ _?event @ board::by: ?actor }])).collect();
    assert_eq!(by.len(), 4);
    assert_eq!(
        by.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([person])
    );
}

#[test]
fn mcp_never_uses_ambient_persona_for_attribution() {
    if std::env::var_os("FACULTIES_COMPASS_PERSONA_CHILD").is_none() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        clean_child(&mut command);
        let output = command
            .args([
                "--exact",
                "mcp_never_uses_ambient_persona_for_attribution",
                "--nocapture",
            ])
            .env("FACULTIES_COMPASS_PERSONA_CHILD", "1")
            .env("PERSONA", "this-persona-does-not-exist")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    let fixture = Fixture::new();
    let faculty = fixture.mcp();
    call(
        &faculty,
        "compass_add",
        serde_json::json!({"title":"unattributed","note":"literal"}),
    );
    let (facts, _) = fixture.snapshot();
    assert_eq!(compass::goal_ids(&facts).len(), 1);
    assert!(!exists!(
        pattern!(&facts, [{ _?event @ board::by: _?actor }])
    ));
}

#[test]
fn output_failure_does_not_retry_or_erase_an_already_published_action() {
    let fixture = Fixture::new();
    let faculty = fixture.mcp();
    let error = faculty
        .call(
            "compass_add",
            Bytes::from(br#"{"title":"exactly one action"}"#.to_vec()),
            &mut Out::new(&mut |_| bail!("recipient closed")),
        )
        .unwrap_err();
    assert!(error.to_string().contains("recipient closed"));
    let (facts, _) = fixture.snapshot();
    assert_eq!(compass::goal_ids(&facts).len(), 1);
}
