//! End-to-end proof that a legacy-only pile tells the operator so.
//!
//! The unit tests in `faculties::legacy_hint` prove the predicate. This proves
//! the delivery: someone who upgrades and runs a real faculty against a
//! pre-collection pile sees the hint, on stderr, without it breaking the
//! command — and stops seeing it once native history exists.

use std::fs::File;
use std::path::Path;
use std::process::Command;

use faculties::schemas::compass::{board, KIND_GOAL_ID};
use faculties::storage::{initialize_signer, open_pile_strict};
use triblespace::core::collection::simplearchive_union;
use triblespace::core::metadata;
use triblespace::macros::entity;
use triblespace::prelude::*;

fn goal_fragment(title: &str) -> Fragment {
    let mut fragment = Fragment::empty();
    let handle = fragment.put::<blobencodings::UTF8String, _>(title.to_owned());
    let goal = genid();
    fragment += entity! { &goal @
        metadata::tag: &KIND_GOAL_ID,
        board::title: handle,
    };
    fragment
}

/// Restore a byte-for-byte v0.46 `compass` branch and give the pile a durable
/// native signer. The historical bytes keep this compatibility test honest
/// without retaining a mutable legacy writer API.
fn legacy_only_pile(directory: &Path) -> std::path::PathBuf {
    let pile_path = directory.join("legacy.pile");
    std::fs::write(
        &pile_path,
        include_bytes!("fixtures/legacy_compass_v046.pile"),
    )
    .unwrap();

    initialize_signer(&pile_path, None).unwrap();
    pile_path
}

fn compass_list(pile: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_compass"))
        .args(["--pile", pile.to_str().unwrap(), "list"])
        .env_remove("PILE")
        .env_remove("PERSONA")
        .output()
        .expect("run compass")
}

#[test]
fn a_legacy_only_pile_tells_the_operator_how_to_migrate() {
    let directory = tempfile::TempDir::new().unwrap();
    let pile_path = legacy_only_pile(directory.path());

    let output = compass_list(&pile_path);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Warn, never break.
    assert!(
        output.status.success(),
        "the hint must not fail the command: {stderr}"
    );
    // The hint is a diagnostic, so it must not pollute the data stream.
    assert!(
        !stdout.contains("legacy"),
        "the hint belongs on stderr, not stdout: {stdout}"
    );

    assert!(
        stderr.contains("legacy `compass` branch still holds 1 authored commit"),
        "the hint must state the count it found: {stderr}"
    );
    assert!(
        stderr.contains("stop every writer"),
        "the hint must state the precondition: {stderr}"
    );
    assert!(
        stderr.contains("migrations --pile"),
        "the hint must name the binary that owns the migration: {stderr}"
    );
    assert!(
        stderr.contains("legacy-branches plan") && stderr.contains("legacy-branches activate"),
        "the hint must name both verbs: {stderr}"
    );
}

#[test]
fn open_admission_native_history_is_immediately_visible() {
    let directory = tempfile::TempDir::new().unwrap();
    let pile_path = legacy_only_pile(directory.path());

    // Same pile, same intact legacy branch. Only the native side changes.
    assert!(String::from_utf8_lossy(&compass_list(&pile_path).stderr).contains("legacy `compass`"));

    let signer = faculties::storage::load_signer(&pile_path, None).unwrap();
    let mut pile = open_pile_strict(&pile_path).unwrap();
    simplearchive_union::publish_fragment_commit(
        &mut pile,
        &faculties::collection_names::root_descriptor(
            faculties::schemas::compass::DEFAULT_SCOPE_ID,
            signer.verifying_key(),
        ),
        goal_fragment("a native goal"),
        &signer,
    )
    .unwrap();
    pile.close().unwrap();

    let output = compass_list(&pile_path);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stderr}");
    assert!(!stderr.contains("legacy `compass`"), "{stderr}");
    assert!(
        stdout.contains("a native goal"),
        "a strictly verified commit is visible immediately: {stdout}"
    );
}

#[test]
fn a_pile_with_no_legacy_history_says_nothing() {
    let directory = tempfile::TempDir::new().unwrap();
    let pile_path = directory.path().join("fresh.pile");
    File::create(&pile_path).unwrap();
    initialize_signer(&pile_path, None).unwrap();

    let output = compass_list(&pile_path);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        !stderr.contains("legacy"),
        "a fresh pile must be silent: {stderr}"
    );
}
