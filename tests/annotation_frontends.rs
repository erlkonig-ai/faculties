//! Reason and Patience annotate execution; only their explicit CLI wrapper
//! may launch a child. All fixtures are isolated, with no ambient mutation.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;

use anybytes::Bytes;
use faculties::mcp::{Faculty, InvalidArguments};
use faculties::out::{Out, Part};
use faculties::storage::{initialize_signer, load_signer, open_pile_strict, read_fact_collection};
use faculties::{patience, reason};
use serde_json::json;
use triblespace::prelude::*;

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("annotations.pile");
    let key = directory.path().join("annotations.key");
    File::create(&pile).unwrap();
    initialize_signer(&pile, Some(&key)).unwrap();
    (directory, pile, key)
}

fn text_call(faculty: &dyn Faculty, name: &str, args: serde_json::Value) -> String {
    let mut text = String::new();
    faculty
        .call(
            name,
            serde_json::to_vec(&args).unwrap().into(),
            &mut Out::new(&mut |part| {
                let Part::Text { text: emitted } = part else {
                    panic!("non-text annotation");
                };
                text.push_str(&emitted);
                Ok(())
            }),
        )
        .unwrap();
    text
}

fn facts(pile: &Path, key: &Path) -> TribleSet {
    let signer = load_signer(pile, Some(key)).unwrap();
    let mut store = open_pile_strict(pile).unwrap();
    let collection = faculties::collection_names::open_configured(
        &mut store,
        faculties::schemas::cognition::DEFAULT_SCOPE_ID,
        signer.verifying_key(),
    )
    .unwrap();
    let reader = store.snapshot().unwrap();
    let (facts, _) = read_fact_collection(collection, &reader).unwrap();
    drop(reader);
    store.close().unwrap();
    facts
}

#[test]
fn direct_operations_return_receipts_and_reject_invalid_requests_without_storage() {
    let (_directory, pile, key) = fixture();
    let reason = reason::Reason::new(pile.clone(), Some(key.clone()));
    let patience = patience::Patience::new(pile.clone(), Some(key.clone()));
    let turn = fucid().id;
    let worker = fucid().id;
    let note = reason.record("@-", Some(turn), Some(worker)).unwrap();
    let action = reason
        .record_action("why", "false", Some(turn), Some(worker))
        .unwrap();
    let extension = patience.extend(turn, worker, 5000).unwrap();
    let observed = facts(&pile, &key);
    for id in [note, action.reason, action.action, extension] {
        assert!(observed.iter().any(|fact| *fact.e() == id));
    }
    let before = std::fs::metadata(&pile).unwrap().len();
    assert!(reason.record("  ", None, None).is_err());
    assert!(reason.record_action("why", "  ", None, None).is_err());
    assert!(patience.extend(turn, worker, 0).is_err());
    assert_eq!(std::fs::metadata(&pile).unwrap().len(), before);
}

#[test]
fn mcp_literals_are_not_files_and_recorded_commands_are_not_executed() {
    let (directory, pile, key) = fixture();
    let marker = directory.path().join("must-not-be-created");
    let reason = reason::mcp::Reason::new(pile.clone(), Some(key.clone()));
    let output = text_call(
        &reason,
        "reason_record",
        json!({
            "text": "@/definitely-not-an-input-file",
            "command_text": format!("touch {}", marker.display())
        }),
    );
    assert!(output.contains("reason_id:"));
    assert!(output.contains("reason_action_id:"));
    assert!(!marker.exists());

    let patience = patience::mcp::Patience::new(pile.clone(), Some(key.clone()));
    let output = text_call(
        &patience,
        "patience_extend",
        json!({
            "turn_id": format!("{:x}", fucid().id), "worker_id": format!("{:x}", fucid().id), "duration_ms": 1000
        }),
    );
    assert!(output.contains("timeout extended by 1000 ms"));
}

#[test]
fn invalid_mcp_shapes_never_open_the_configured_pile() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("absent.pile");
    let reason = reason::mcp::Reason::new(pile.clone(), None);
    let patience = patience::mcp::Patience::new(pile.clone(), None);
    for (faculty, name, arguments) in [
        (
            &reason as &dyn Faculty,
            "reason_record",
            r#"{"text":"x","path":"/forbidden"}"#,
        ),
        (&reason, "reason_record", r#"{"text":"x","text":"y"}"#),
        (&reason, "reason_record", r#"{"text":"x","turn_id":"bad"}"#),
        (
            &reason,
            "reason_record",
            r#"{"text":"x","command":["false"]}"#,
        ),
        (
            &patience as &dyn Faculty,
            "patience_extend",
            r#"{"duration_ms":1000}"#,
        ),
        (
            &patience,
            "patience_extend",
            r#"{"turn_id":"bad","worker_id":"bad","duration_ms":0}"#,
        ),
        (
            &patience,
            "patience_extend",
            r#"{"turn_id":"bad","worker_id":"bad","duration_ms":"1s"}"#,
        ),
    ] {
        let error = faculty
            .call(
                name,
                Bytes::from(arguments.to_owned()),
                &mut Out::new(&mut |_| panic!("invalid request emitted")),
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
fn cli_annotations_preserve_child_stdout_and_exit_status() {
    let (_directory, pile, key) = fixture();
    for (binary, arguments) in [
        (
            env!("CARGO_BIN_EXE_reason"),
            vec!["because", "--", "sh", "-c", "printf child; exit 7"],
        ),
        (
            env!("CARGO_BIN_EXE_patience"),
            vec!["1s", "--", "sh", "-c", "printf child; exit 7"],
        ),
    ] {
        let output = Command::new(binary)
            .arg("--pile")
            .arg(&pile)
            .arg("--key")
            .arg(&key)
            .args(arguments)
            .env_remove("DRIVE_ENDPOINT")
            .env_remove("DRIVE_KEY")
            .env("TURN_ID", format!("{:x}", fucid().id))
            .env("WORKER_ID", format!("{:x}", fucid().id))
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(7),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"child");
        assert!(!output.stderr.is_empty(), "annotation belongs to stderr");
    }
}

#[test]
fn cli_annotation_delivery_failure_does_not_launch_child_or_retry_publication() {
    let (directory, pile, key) = fixture();
    let marker = directory.path().join("child-ran");
    let output = Command::new(env!("CARGO_BIN_EXE_reason"))
        .arg("--pile")
        .arg(&pile)
        .arg("--key")
        .arg(&key)
        .args(["why", "--", "touch"])
        .arg(&marker)
        .env("DRIVE_ENDPOINT", "not-an-endpoint")
        .env_remove("TURN_ID")
        .env_remove("WORKER_ID")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!marker.exists());
    let observed = facts(&pile, &key);
    let ids: std::collections::BTreeSet<_> = find!(
        id: Id, pattern!(&observed, [{ ?id @ triblespace::core::metadata::tag: faculties::schemas::reason::KIND_REASON_ID }])
    ).collect();
    assert_eq!(
        ids.len(),
        2,
        "one note/action pair, no retry on uncertain delivery"
    );
}
