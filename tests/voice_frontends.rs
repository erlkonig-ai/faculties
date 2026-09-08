use faculties::mcp::{Faculty, InvalidArguments};
use faculties::out::{Out, Part};
use faculties::storage::{discover_target, initialize_signer, load_signer, open_pile_strict};
use faculties::voice::{self, Channel, Voice};
use serde_json::json;
use std::path::PathBuf;

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("voice.pile");
    let key = directory.path().join("voice.key");
    std::fs::File::create(&pile).unwrap();
    initialize_signer(&pile, Some(&key)).unwrap();
    (directory, pile, key)
}
fn call(adapter: &dyn Faculty, name: &str, arguments: serde_json::Value) -> String {
    let mut text = String::new();
    adapter
        .call(
            name,
            serde_json::to_vec(&arguments).unwrap().into(),
            &mut Out::new(&mut |part| {
                let Part::Text { text: value } = part else {
                    panic!("expected policy text")
                };
                text.push_str(&value);
                Ok(())
            }),
        )
        .unwrap();
    text
}

#[test]
fn native_and_mcp_routing_are_device_free_and_literal() {
    let (_directory, pile, key) = fixture();
    let operations = Voice::new(pile.clone(), Some(key.clone()));
    let adapter = voice::mcp::Voice::new(pile, Some(key));
    assert!(call(&adapter, "voice_route", json!({})).contains("AirPods Max"));
    let text = call(
        &adapter,
        "voice_route_set",
        json!({"channel":"say", "devices":["@/literal-headphones", "Room Speaker"]}),
    );
    assert!(text.contains("Room Speaker"));
    assert!(text.contains("cannot route say to a speaker"));
    assert_eq!(
        operations.route(Channel::Say).unwrap(),
        ["@/literal-headphones", "Room Speaker"]
    );
    let devices = [voice::routing::AudioDevice {
        name: "Room Speaker".into(),
        is_default_output: true,
    }];
    assert!(matches!(
        voice::routing::route_say(&operations.route(Channel::Say).unwrap(), &devices),
        voice::routing::Routed::Text(_)
    ));
}

#[test]
fn cli_policy_edit_uses_the_same_native_storage_without_enumerating_devices() {
    let (_directory, pile, key) = fixture();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_voice"))
        .arg("--pile")
        .arg(&pile)
        .arg("--key")
        .arg(&key)
        .args(["route-set", "say", "AirPods Test"])
        .env_remove("DRIVE_ENDPOINT")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let operations = Voice::new(pile, Some(key));
    assert_eq!(operations.route(Channel::Say).unwrap(), ["AirPods Test"]);
    assert!(String::from_utf8(result.stdout)
        .unwrap()
        .contains("say policy set: AirPods Test"));
}

#[test]
fn malformed_requests_and_discovery_do_not_acquire_models_or_storage() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("absent.pile");
    let adapter = voice::mcp::Voice::new(pile.clone(), None);
    assert_eq!(adapter.tools().len(), 3);
    for (name, arguments) in [
        ("voice_synthesize", r#"{"text":"   "}"#),
        ("voice_synthesize", r#"{"text":"a","text":"b"}"#),
        (
            "voice_synthesize",
            r#"{"text":"a","device":"host speaker"}"#,
        ),
        ("voice_synthesize", r#"{"text":"a","model_path":"/host"}"#),
        ("voice_route", "[]"),
        ("voice_route", r#"{"daemon":"http://host"}"#),
        ("voice_route_set", r#"{"channel":"room","devices":["x"]}"#),
        ("voice_route_set", r#"{"channel":"say","devices":[]}"#),
        ("voice_route_set", r#"{"channel":"say","devices":[" "]}"#),
    ] {
        let error = adapter
            .call(
                name,
                arguments.to_owned().into(),
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
fn failed_route_receipt_does_not_publish_a_second_generation() {
    let (_directory, pile, key) = fixture();
    let adapter = voice::mcp::Voice::new(pile.clone(), Some(key.clone()));
    let error = adapter
        .call(
            "voice_route_set",
            r#"{"channel":"say","devices":["AirPods"]}"#.to_owned().into(),
            &mut Out::new(&mut |_| anyhow::bail!("delivery failed")),
        )
        .unwrap_err();
    assert!(error.to_string().contains("delivery failed"));
    assert_eq!(
        Voice::new(pile.clone(), Some(key.clone()))
            .route(Channel::Say)
            .unwrap(),
        ["AirPods"]
    );
    let signer = load_signer(&pile, Some(&key)).unwrap();
    let mut storage = open_pile_strict(&pile).unwrap();
    let discovery = discover_target(
        &mut storage,
        faculties::schemas::voice::COLLECTION_SCOPE_ID,
        signer.verifying_key(),
    )
    .unwrap();
    assert_eq!(discovery.commits().len(), 1);
    storage.close().unwrap();
}

#[test]
#[cfg(not(feature = "voice"))]
fn disabled_synthesis_does_not_fallback_to_a_device_or_journal_an_utterance() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("absent.pile");
    let adapter = voice::mcp::Voice::new(pile.clone(), None);
    let error = adapter
        .call(
            "voice_synthesize",
            r#"{"text":"@/not-a-file"}"#.to_owned().into(),
            &mut Out::new(&mut |_| panic!("no generation")),
        )
        .unwrap_err();
    assert!(error.to_string().contains("`voice` feature"));
    assert!(!pile.exists());
}

#[test]
#[cfg(not(feature = "voice"))]
fn disabled_synthesis_cli_does_not_read_files_or_wait_for_stdin() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("absent.pile");
    for text in [
        format!("@{}", directory.path().join("absent.txt").display()),
        "@-".into(),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_voice"))
            .arg("--pile")
            .arg(&pile)
            .arg("synthesize")
            .arg(text)
            .env_remove("DRIVE_ENDPOINT")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("disabled Voice synthesis waited for input");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("`voice` feature"));
        assert!(!pile.exists());
    }
    let help = Command::new(env!("CARGO_BIN_EXE_voice"))
        .args(["synthesize", "--help"])
        .env_remove("PILE")
        .env_remove("DRIVE_ENDPOINT")
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("Usage:"));
}

#[test]
fn reachy_receipt_claims_only_request_acceptance() {
    use voice::device::{SpeechDisposition, SpeechReceipt};
    let receipt = SpeechReceipt {
        route: voice::routing::Routed::Reachy,
        disposition: SpeechDisposition::ReachyRequestAccepted,
        utterance: None,
    };
    assert_ne!(receipt.disposition, SpeechDisposition::LocalPlaybackDrained);
    let mut text = String::new();
    receipt
        .emit(
            Channel::Shout,
            &mut Out::new(&mut |part| {
                let Part::Text { text: line } = part else {
                    panic!("expected receipt text")
                };
                text.push_str(&line);
                Ok(())
            }),
        )
        .unwrap();
    assert!(text.contains("accepted the playback request"));
    assert!(text.contains("completion was not observed"));
}
