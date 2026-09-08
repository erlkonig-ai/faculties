use std::path::PathBuf;
use std::process::Command;

use base64::Engine as _;
use faculties::habits::{self, DeclaredState, Habits};
use faculties::mcp::{Faculty, InvalidArguments};
use faculties::out::{Out, Part};
use faculties::storage::initialize_signer;
use serde_json::json;

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("habit.pile");
    let key = directory.path().join("habit.key");
    std::fs::File::create(&pile).unwrap();
    initialize_signer(&pile, Some(&key)).unwrap();
    (directory, pile, key)
}

fn call(faculty: &dyn Faculty, name: &str, args: serde_json::Value) -> String {
    let mut text = String::new();
    faculty
        .call(
            name,
            serde_json::to_vec(&args).unwrap().into(),
            &mut Out::new(&mut |part| {
                let Part::Text { text: emitted } = part else {
                    panic!("unexpected media");
                };
                text.push_str(&emitted);
                Ok(())
            }),
        )
        .unwrap();
    text
}

#[test]
fn mcp_listing_is_passive_and_evaluation_is_explicit() {
    let (directory, pile, key) = fixture();
    let marker = directory.path().join("predicate-runs");
    let operations = Habits::new(pile.clone(), Some(key.clone()));
    operations
        .add(
            "observe",
            &format!("when printf x >> '{}'", marker.display()),
            "inspect me",
            None,
            &[],
        )
        .unwrap();
    let mcp = habits::mcp::Habits::new(pile.clone(), Some(key.clone()));
    let passive = call(&mcp, "habit_list", json!({}));
    assert!(passive.contains("unevaluated"), "{passive}");
    assert!(!marker.exists());
    assert!(operations.list(false).unwrap().entries[0].state.is_none());
    assert!(!marker.exists());
    assert!(call(&mcp, "habit_show", json!({"habit":"observe"})).contains("inspect me"));
    assert!(!marker.exists());
    let due = call(&mcp, "habit_due", json!({}));
    assert!(due.contains("observe: inspect me"), "{due}");
    assert_eq!(std::fs::read(&marker).unwrap(), b"x");
    call(&mcp, "habit_list", json!({"evaluate_conditions":true}));
    assert_eq!(std::fs::read(&marker).unwrap(), b"xx");
    let cli = Command::new(env!("CARGO_BIN_EXE_habit"))
        .arg("--pile")
        .arg(&pile)
        .arg("--key")
        .arg(&key)
        .arg("list")
        .env_remove("DRIVE_ENDPOINT")
        .env_remove("DRIVE_KEY")
        .output()
        .unwrap();
    assert!(
        cli.status.success(),
        "{}",
        String::from_utf8_lossy(&cli.stderr)
    );
    assert_eq!(
        std::fs::read(&marker).unwrap(),
        b"xxx",
        "CLI list retains evaluation"
    );
}

#[test]
fn literal_prose_and_resident_script_bytes_are_preserved_without_execution() {
    let (_directory, pile, key) = fixture();
    let script = b"#!/bin/sh\nprintf 'should not run'\n";
    let mcp = habits::mcp::Habits::new(pile.clone(), Some(key.clone()));
    call(
        &mcp,
        "habit_add",
        json!({"label":"literal", "when":"when @script", "nudge":"@/not-a-file", "script_base64":base64::engine::general_purpose::STANDARD.encode(script)}),
    );
    let operations = Habits::new(pile, Some(key));
    let observed = operations.show("literal").unwrap();
    assert_eq!(observed.definition.nudge, "@/not-a-file");
    assert_eq!(observed.definition.condition, "when @script");
    assert_eq!(observed.definition.script.unwrap().bytes, script);
    assert!(call(&mcp, "habit_check", json!({})).contains("1 definitions"));
}

#[test]
fn definition_history_label_ambiguity_and_state_noops_survive_both_frontends() {
    let (_directory, pile, key) = fixture();
    let operations = Habits::new(pile.clone(), Some(key.clone()));
    let first = operations
        .add("repeat", "every 1h", "first", None, &[])
        .unwrap();
    let duplicate = operations
        .add("repeat", "every 1h", "first", None, &[])
        .unwrap();
    assert_eq!(first.id, duplicate.id);
    assert!(duplicate.already_present);
    let second = operations
        .add("repeat", "every 1h", "second", None, &[])
        .unwrap();
    assert!(operations.show("repeat").is_err());
    let joined = operations
        .add(
            "repeat",
            "every 1h",
            "joined",
            None,
            &[format!("{:x}", first.id), format!("{:x}", second.id)],
        )
        .unwrap();
    assert_eq!(operations.list(false).unwrap().entries.len(), 1);
    assert!(
        operations
            .show(&format!("{:x}", first.id))
            .unwrap()
            .superseded
    );
    let mcp = habits::mcp::Habits::new(pile, Some(key));
    assert!(call(&mcp, "habit_pause", json!({"habit":"repeat"})).contains("paused"));
    assert!(operations
        .set_state("repeat", DeclaredState::Paused)
        .unwrap()
        .event
        .is_none());
    assert!(call(&mcp, "habit_resume", json!({"habit":"repeat"})).contains("active"));
    assert!(operations
        .set_state("repeat", DeclaredState::Active)
        .unwrap()
        .event
        .is_none());
    assert!(call(&mcp, "habit_done", json!({"habit":"repeat"})).contains("done repeat"));
    // Historical lookup keeps every definition: a unique active label is not
    // a unique historical label. State-changing calls above target active heads.
    assert!(operations.show("repeat").is_err());
    assert_eq!(
        operations
            .show(&format!("{:x}", joined.id))
            .unwrap()
            .definition
            .id,
        joined.id
    );
    assert!(!operations.list(true).unwrap().entries[0]
        .state
        .as_ref()
        .unwrap()
        .is_due());
}

#[test]
fn invalid_transport_arguments_do_not_touch_absent_storage() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("absent.pile");
    let mcp = habits::mcp::Habits::new(pile.clone(), None);
    assert_eq!(mcp.tools().len(), 8);
    for (name, input) in [
        ("habit_list", r#"{"evaluate_conditions":"true"}"#),
        (
            "habit_list",
            r#"{"evaluate_conditions":true,"evaluate_conditions":false}"#,
        ),
        (
            "habit_add",
            r#"{"label":"x","when":"every 1h","nudge":"n","script_base64":"???"}"#,
        ),
        (
            "habit_add",
            r#"{"label":"x","when":"every 1h","nudge":"n","script_path":"/host/path"}"#,
        ),
        ("habit_due", r#"{"persona":"server"}"#),
        ("habit_show", r#"{}"#),
    ] {
        let error = mcp
            .call(
                name,
                input.to_owned().into(),
                &mut Out::new(&mut |_| panic!("invalid input emitted")),
            )
            .unwrap_err();
        assert!(
            error.downcast_ref::<InvalidArguments>().is_some(),
            "{error:#}"
        );
        assert!(!pile.exists());
    }
}

#[test]
fn delivery_failure_does_not_repeat_an_authored_definition() {
    let (_directory, pile, key) = fixture();
    let mcp = habits::mcp::Habits::new(pile.clone(), Some(key.clone()));
    let error = mcp
        .call(
            "habit_add",
            serde_json::to_vec(&json!({"label":"one", "when":"every 1h", "nudge":"once"}))
                .unwrap()
                .into(),
            &mut Out::new(&mut |_| anyhow::bail!("broken transport")),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("broken transport"));
    let operations = Habits::new(pile, Some(key));
    let report = operations.list(false).unwrap();
    assert_eq!(report.entries.len(), 1);
    let repeated = operations
        .add("one", "every 1h", "once", None, &[])
        .unwrap();
    assert_eq!(repeated.id, report.entries[0].row.id);
    assert!(repeated.already_present);
}
