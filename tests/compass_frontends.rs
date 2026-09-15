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

#[test]
fn source_writer_appends_actions_with_lagging_read_only_rollups() {
    use triblespace::core::blob::encodings::succinctarchive::{
        Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
    };
    use triblespace::core::collection::{
        grant_collection_read, grant_collection_write, CollectionRecord,
    };

    let fixture = Fixture::new();
    let first = fixture
        .operations()
        .add("resident goal", AddOptions::default())
        .unwrap();
    let first_id = format!("{:x}", first.goal);
    let person = genid().id;
    let (fragment, _, _) = faculties::relations::person_fragment(
        person,
        faculties::relations::ProfileInput {
            label: "source-writer".into(),
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
    fixture
        .operations()
        .note(
            &first_id,
            "warm both input chains",
            NoteOptions {
                persona: Some("source-writer"),
                ..Default::default()
            },
        )
        .unwrap();
    fixture.operations().list(ListOptions::default()).unwrap();
    let pending = fixture
        .operations()
        .add("not projected yet", AddOptions::default())
        .unwrap();

    let owner = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
    let writer_key = fixture.directory.path().join("source-writer.key");
    initialize_signer(&fixture.pile, Some(&writer_key)).unwrap();
    let writer = load_signer(&fixture.pile, Some(&writer_key)).unwrap();
    let denied_key = fixture.directory.path().join("ungranted.key");
    initialize_signer(&fixture.pile, Some(&denied_key)).unwrap();
    let mut pile = Pile::open(&fixture.pile).unwrap();
    let source = faculties::collection_names::open_configured(
        &mut pile,
        faculties::schemas::compass::DEFAULT_SCOPE_ID,
        owner.verifying_key(),
    )
    .unwrap();
    let relations = faculties::collection_names::open_configured(
        &mut pile,
        faculties::schemas::relations::DEFAULT_SCOPE_ID,
        owner.verifying_key(),
    )
    .unwrap();
    grant_collection_write(&mut pile, source.handle(), &owner, writer.verifying_key()).unwrap();
    for input in [source, relations] {
        let policy = input.policy(&pile.snapshot().unwrap()).unwrap();
        let succinct = pile
            .derive::<SuccinctArchiveBlob>(input, (), policy.clone())
            .unwrap();
        let rank9 = pile
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
            .unwrap();
        for target in [succinct.handle(), rank9.handle()] {
            grant_collection_read(&mut pile, target, &owner, writer.verifying_key()).unwrap();
        }
        let snapshot = pile.snapshot().unwrap();
        assert!(!succinct
            .writer_is_admitted(&snapshot, writer.verifying_key())
            .unwrap());
        assert!(!rank9
            .writer_is_admitted(&snapshot, writer.verifying_key())
            .unwrap());
        if input == source {
            let facts = snapshot
                .collection(rank9)
                .unwrap()
                .view::<faculties::storage::FactArchive>()
                .unwrap();
            assert!(compass::goal_ids(&facts).contains(&first.goal));
            assert!(!compass::goal_ids(&facts).contains(&pending.goal));
        }
    }
    let status = compass::status_register_collection(&mut pile, owner.verifying_key()).unwrap();
    grant_collection_read(&mut pile, status.handle(), &owner, writer.verifying_key()).unwrap();
    assert!(!status
        .writer_is_admitted(&pile.snapshot().unwrap(), writer.verifying_key())
        .unwrap());
    pile.close().unwrap();

    let records = || {
        let mut pile = Pile::open(&fixture.pile).unwrap();
        let records = pile
            .snapshot()
            .unwrap()
            .records()
            .unwrap()
            .map(std::result::Result::unwrap)
            .collect::<BTreeSet<_>>();
        pile.close().unwrap();
        records
    };
    let command = |key: &std::path::Path| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_compass"));
        clean_child(&mut command);
        command
            .arg("--pile")
            .arg(&fixture.pile)
            .arg("--key")
            .arg(key)
            .args(["--persona", "source-writer"])
            .env(
                "TRIBLESPACE_COLLECTION_COMPASS",
                hex::encode(source.handle().raw),
            )
            .env(
                "TRIBLESPACE_COLLECTION_RELATIONS",
                hex::encode(relations.handle().raw),
            );
        command
    };
    let before = records();
    let added = command(&writer_key)
        .args([
            "add",
            "appended child",
            "--parent",
            &first_id,
            "--note",
            "initial child note",
        ])
        .output()
        .unwrap();
    assert!(added.status.success(), "{added:?}");
    let added_text = String::from_utf8(added.stdout).unwrap();
    let child = added_text
        .lines()
        .find_map(|line| line.strip_prefix("Added goal "))
        .unwrap();
    let moved = command(&writer_key)
        .args(["move", &first_id, "doing"])
        .output()
        .unwrap();
    assert!(moved.status.success(), "{moved:?}");
    let noted = command(&writer_key)
        .args(["note", &first_id, "source-only research note"])
        .output()
        .unwrap();
    assert!(noted.status.success(), "{noted:?}");
    let after = records();
    let added_records: Vec<_> = after.difference(&before).copied().collect();
    assert_eq!(
        added_records.len(),
        3,
        "append preparation must publish no rollup equations"
    );
    assert!(added_records.iter().all(|record| matches!(record,
        CollectionRecord::Commit(commit)
            if commit.collection() == source.handle()
                && commit.public_key().raw == writer.verifying_key().to_bytes()
    )));

    let unknown = format!("{:x}", genid().id);
    let missing_goal = command(&writer_key)
        .args(["move", &unknown[..16], "doing"])
        .output()
        .unwrap();
    assert!(!missing_goal.status.success());
    let missing_note = command(&writer_key)
        .args([
            "note",
            &first_id,
            "invalid supersession",
            "--supersedes",
            &unknown,
        ])
        .output()
        .unwrap();
    assert!(!missing_note.status.success());
    let denied = command(&denied_key)
        .args(["add", "no source grant"])
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("requires source collection WRITE"));
    // Prefixes resolve against resident rows, unlike complete IDs, which
    // deliberately support forward references without proving membership.
    let child_prefix = &child[..16];
    let not_yet_visible = command(&writer_key)
        .args(["note", child_prefix, "wait for the projection"])
        .output()
        .unwrap();
    assert!(!not_yet_visible.status.success());
    assert_eq!(records(), after);

    let forward_reference = command(&writer_key)
        .args(["note", child, "explicit full-ID forward reference"])
        .output()
        .unwrap();
    assert!(forward_reference.status.success(), "{forward_reference:?}");
    let after_forward_reference = records();
    let forwarded: Vec<_> = after_forward_reference
        .difference(&after)
        .copied()
        .collect();
    assert_eq!(forwarded.len(), 1);
    assert!(matches!(forwarded[0],
        CollectionRecord::Commit(commit)
            if commit.collection() == source.handle()
                && commit.public_key().raw == writer.verifying_key().to_bytes()
    ));
    let after = after_forward_reference;

    let priority = command(&writer_key)
        .args([
            "prioritize",
            &first_id,
            "--over",
            &format!("{:x}", pending.goal),
        ])
        .output()
        .unwrap();
    assert!(
        !priority.status.success(),
        "priority changes retain complete-source preparation"
    );
    assert!(
        String::from_utf8_lossy(&priority.stderr).contains("maintain Compass Succinct collection")
    );
    assert_eq!(records(), after);

    let listing = fixture
        .operations()
        .list(ListOptions {
            all: true,
            ..Default::default()
        })
        .unwrap();
    assert!(listing.contains("appended child"));
    assert!(fixture
        .operations()
        .show(&first_id)
        .unwrap()
        .contains("source-only research note"));
    let now_visible = command(&writer_key)
        .args(["note", child_prefix, "after remote maintenance"])
        .output()
        .unwrap();
    assert!(now_visible.status.success(), "{now_visible:?}");
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
