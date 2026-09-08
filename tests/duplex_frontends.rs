//! Session-directory fixtures only. Never starts a loop, touches Soma, loads a
//! model, opens an audio device, or mutates the process environment.
use anybytes::Bytes;
use anyhow::{anyhow, Result};
use clap::Parser;
use faculties::duplex::{self, ReadOptions, Session};
use faculties::mcp::{Faculty, InvalidArguments};
use faculties::out::{Out, Part};
use std::fs;
use std::io::Write;
use std::path::Path;

fn append(path: &Path, seq: u64, speaker: &str, text: &str) {
    fs::create_dir_all(path).unwrap();
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path.join("transcript.jsonl"))
        .unwrap();
    writeln!(
        file,
        "{}",
        serde_json::json!({"seq":seq,"at_ms":seq*1000,"speaker":speaker,"text":text})
    )
    .unwrap();
}
fn queue(path: &Path) -> Vec<(String, String)> {
    let mut values: Vec<_> = fs::read_dir(path.join("inject"))
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().to_string_lossy().into_owned(),
                fs::read_to_string(entry.path()).unwrap(),
            )
        })
        .collect();
    values.sort();
    values
}
fn collect(f: impl FnOnce(&mut Out<'_>) -> Result<()>) -> Result<String> {
    let mut text = String::new();
    f(&mut Out::new(&mut |part| {
        let Part::Text { text: part } = part else {
            panic!("Duplex finite control is text")
        };
        text.push_str(&part);
        Ok(())
    }))?;
    Ok(text)
}
fn json(value: serde_json::Value) -> Bytes {
    serde_json::to_vec(&value).unwrap().into()
}
fn args(path: &Path, args: &[&str]) -> duplex::cli::Cli {
    duplex::cli::Cli::try_parse_from(
        [
            "duplex".into(),
            "--session".into(),
            path.as_os_str().to_owned(),
        ]
        .into_iter()
        .chain(args.iter().map(std::ffi::OsString::from)),
    )
    .unwrap()
}

#[test]
fn direct_read_is_nonconsuming_and_say_advances_the_current_tail() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    append(path, 1, "agent", "first");
    append(
        path,
        2,
        "far",
        "[spoke for 1.5s — no transcription available]",
    );
    let session = Session::new(path.to_owned());
    let before = session.read(ReadOptions::default()).unwrap();
    assert_eq!(before.cursor, 0);
    assert_eq!(before.transcript_at, 2);
    assert_eq!(before.lines.len(), 2);
    assert!(session.status().unwrap().floor_held);
    assert_eq!(
        session.read(ReadOptions::default()).unwrap().lines,
        before.lines
    );
    // A floor request does not pause the far end or retain a hidden read token.
    append(
        path,
        3,
        "far",
        "[still speaking — no transcription available]",
    );
    let receipt = session.say("  @-  ", false).unwrap();
    assert_eq!(receipt.cursor, 3);
    assert_eq!(queue(path)[0].1, "@-");
    let status = session.status().unwrap();
    assert!(!status.floor_held);
    assert_eq!(status.cursor, 3);
    assert_eq!(status.unread, 0);
    assert!(session
        .read(ReadOptions {
            peek: true,
            ..ReadOptions::default()
        })
        .unwrap()
        .lines
        .is_empty());
    assert_eq!(
        before.lines.len(),
        2,
        "returned observation stays independent of later transcript appends"
    );
}

#[test]
fn peek_all_keep_floor_and_release_preserve_the_explicit_cursor_rules() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    append(path, 1, "model", "one");
    let session = Session::new(path.to_owned());
    let peek = session
        .read(ReadOptions {
            peek: true,
            ..ReadOptions::default()
        })
        .unwrap();
    assert_eq!(peek.requested_hold_secs, None);
    assert!(!session.status().unwrap().floor_held);
    session.read(ReadOptions::default()).unwrap();
    session.say("reply", true).unwrap();
    assert!(session.status().unwrap().floor_held);
    append(path, 2, "agent", "reply");
    let release = session.release(true).unwrap();
    assert!(release.kept_cursor);
    assert_eq!(release.cursor, 1);
    assert!(!session.status().unwrap().floor_held);
    let all = session
        .read(ReadOptions {
            peek: true,
            all: true,
            ..ReadOptions::default()
        })
        .unwrap();
    assert_eq!(all.lines.len(), 2);
    assert_eq!(all.cursor, 1);
    assert_eq!(session.release(false).unwrap().cursor, 2);
}

#[test]
fn mcp_is_literal_and_keeps_host_session_paths_out_of_its_success_ux() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("session");
    let sentinel = directory.path().join("private.txt");
    fs::write(&sentinel, "not speech").unwrap();
    append(&path, 1, "agent", "hello");
    let adapter = duplex::mcp::Duplex::new(Some(path.clone()));
    let literal = format!("@{}", sentinel.display());
    let output =
        collect(|out| adapter.call("duplex_say", json(serde_json::json!({"text":literal})), out))
            .unwrap();
    assert!(!output.contains(&path.display().to_string()));
    assert!(output.contains("queued"));
    assert!(!output.contains("spoken"));
    assert_eq!(queue(&path)[0].1, literal);
    assert_eq!(fs::read_to_string(sentinel).unwrap(), "not speech");
    let output =
        collect(|out| adapter.call("duplex_status", json(serde_json::json!({})), out)).unwrap();
    assert!(!output.contains(&path.display().to_string()));
    assert!(output.contains("liveness and audio delivery are not observed"));
}

#[test]
fn shared_cli_and_mcp_read_release_outputs_agree_without_argv_in_operations() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    append(path, 1, "far", "[spoke — no transcription]");
    let adapter = duplex::mcp::Duplex::new(Some(path.to_owned()));
    let mcp = collect(|out| {
        adapter.call(
            "duplex_read",
            json(serde_json::json!({"peek":true,"all":true})),
            out,
        )
    })
    .unwrap();
    let cli =
        collect(|out| duplex::cli::execute(args(path, &["read", "--peek", "--all"]), out)).unwrap();
    assert_eq!(mcp, cli);
    let mcp = collect(|out| {
        adapter.call(
            "duplex_release",
            json(serde_json::json!({"keep_cursor":true})),
            out,
        )
    })
    .unwrap();
    let cli = collect(|out| duplex::cli::execute(args(path, &["release", "--keep-cursor"]), out))
        .unwrap();
    assert_eq!(mcp, cli);
    let missing = directory.path().join("unused");
    let help = collect(|out| duplex::cli::execute(args(&missing, &[]), out)).unwrap();
    assert!(help.contains("Usage:"));
    assert!(!missing.exists());
}

#[test]
fn unconfigured_discovery_and_argument_errors_have_no_fallback_session() {
    let adapter = duplex::mcp::Duplex::new(None);
    assert_eq!(adapter.tools().len(), 4);
    for name in ["duplex_read", "duplex_release", "duplex_status"] {
        let error =
            collect(|out| adapter.call(name, json(serde_json::json!({})), out)).unwrap_err();
        assert!(error.to_string().contains("not configured"));
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("must-not-exist");
    let adapter = duplex::mcp::Duplex::new(Some(path.clone()));
    for (name, value) in [
        ("duplex_read", serde_json::json!({"hold_secs":-1})),
        ("duplex_read", serde_json::json!({"peek":"true"})),
        (
            "duplex_status",
            serde_json::json!({"session":"/tmp/arbitrary"}),
        ),
        ("duplex_say", serde_json::json!({"text":"  "})),
        (
            "duplex_say",
            serde_json::json!({"text":"hello","file":"/tmp/private"}),
        ),
        ("duplex_release", serde_json::json!({"keep_cursor":1})),
    ] {
        let error = collect(|out| adapter.call(name, json(value), out)).unwrap_err();
        assert!(
            error.downcast_ref::<InvalidArguments>().is_some(),
            "{name}: {error:#}"
        );
    }
    let duplicate = Bytes::from(br#"{"text":"first","text":"second"}"#.to_vec());
    assert!(collect(|out| adapter.call("duplex_say", duplicate, out))
        .unwrap_err()
        .downcast_ref::<InvalidArguments>()
        .is_some());
    assert!(!path.exists());
}

#[test]
fn emitter_failure_keeps_one_published_handoff_without_retrying() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    append(path, 1, "agent", "existing");
    let adapter = duplex::mcp::Duplex::new(Some(path.to_owned()));
    // Use independent emitters because Out borrows a local closure.
    let mut closed = |_| Err(anyhow!("closed"));
    let error = adapter
        .call(
            "duplex_read",
            json(serde_json::json!({})),
            &mut Out::new(&mut closed),
        )
        .unwrap_err();
    assert!(error.to_string().contains("closed"));
    let session = Session::new(path.to_owned());
    assert!(session.status().unwrap().floor_held);
    assert_eq!(session.status().unwrap().cursor, 0);
    let error = adapter
        .call(
            "duplex_say",
            json(serde_json::json!({"text":"one reply"})),
            &mut Out::new(&mut closed),
        )
        .unwrap_err();
    assert!(error.to_string().contains("closed"));
    assert_eq!(queue(path).len(), 1);
    assert_eq!(queue(path)[0].1, "one reply");
    assert_eq!(session.status().unwrap().cursor, 1);
    assert!(!session.status().unwrap().floor_held);
}

#[test]
fn typed_runtime_configuration_is_pure_and_keeps_input_protocol_explicit() {
    use duplex::runtime::{Cadence, Floor, RunOptions, WeightFormat};
    let directory = tempfile::tempdir().unwrap();
    let mut config = RunOptions::new(
        directory.path().join("absent.pile"),
        directory.path().join("absent.pt"),
        "named output".into(),
    );
    config.validate().unwrap();
    assert_eq!(config.fmt, WeightFormat::Q8);
    assert_eq!(config.floor, Floor::Listen);
    assert_eq!(config.cadence, Cadence::Model);
    assert!(!config.no_input);
    config.no_input = true;
    config.validate().unwrap();
    config.decode_hop = 0;
    assert!(config.validate().is_err());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn missing_session_is_empty_but_unreadable_control_state_is_not_success() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("missing");
    let session = Session::new(path.clone());
    assert_eq!(session.status().unwrap().transcript_lines, 0);
    assert!(
        !path.exists(),
        "status does not initialize a missing session"
    );
    fs::create_dir_all(path.join("transcript.jsonl")).unwrap();
    assert!(
        session.status().is_err(),
        "a directory/read failure is not an empty transcript"
    );
    let other = directory.path().join("other");
    fs::create_dir_all(&other).unwrap();
    fs::write(other.join("hold"), "not a deadline").unwrap();
    assert!(
        Session::new(other.clone()).status().is_err(),
        "invalid floor state is not free"
    );
    fs::remove_file(other.join("hold")).unwrap();
    fs::write(other.join("cursor"), "not a cursor").unwrap();
    assert!(
        Session::new(other).status().is_err(),
        "invalid cursor is not zero"
    );
}

#[test]
fn status_counts_only_ready_injection_files_and_reports_postqueue_failure() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    fs::create_dir_all(path.join("inject/a-directory.txt")).unwrap();
    fs::write(path.join("inject/.pending.tmp"), "unfinished").unwrap();
    fs::write(path.join("inject/ready.txt"), "ready").unwrap();
    let session = Session::new(path.to_owned());
    assert_eq!(session.status().unwrap().queued, 1);
    // The queue publication happens before the cursor rename. Make only that
    // second stage fail, proving the receipt error does not imply no handoff.
    fs::create_dir(path.join("cursor")).unwrap();
    let error = session.say("already queued", false).unwrap_err();
    assert!(format!("{error:#}").contains("already queued"));
    assert!(format!("{error:#}").contains("do not blindly retry"));
    let texts: Vec<_> = fs::read_dir(path.join("inject"))
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            fs::read_to_string(path).ok()
        })
        .collect();
    assert!(texts.iter().any(|text| text == "already queued"));
}
