use base64::Engine as _;
use faculties::mcp::{Faculty, InvalidArguments};
use faculties::out::{Out, Part};
use faculties::secrets::{self, Secrets};
use faculties::storage::initialize_signer;
use serde_json::json;
use std::path::PathBuf;
use std::process::Command;

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("secrets.pile");
    let key = directory.path().join("secrets.key");
    std::fs::File::create(&pile).unwrap();
    initialize_signer(&pile, Some(&key)).unwrap();
    (directory, pile, key)
}
fn call(adapter: &dyn Faculty, name: &str, args: serde_json::Value) -> Vec<Part> {
    let mut parts = Vec::new();
    adapter
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

#[test]
fn native_and_mcp_store_literal_values_and_list_metadata_only() {
    let (_directory, pile, key) = fixture();
    let operations = Secrets::new(pile.clone(), Some(key.clone()));
    let adapter = secrets::mcp::Secrets::new(pile, Some(key));
    let literal = "@/a-file-that-must-not-be-read";
    call(
        &adapter,
        "secrets_add",
        json!({"name":"literal", "value":literal}),
    );
    let rows = operations.list().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(&*operations.get(rows[0].id).unwrap(), literal.as_bytes());
    let metadata = call(&adapter, "secrets_list", json!({}));
    assert!(metadata
        .iter()
        .all(|part| matches!(part, Part::Text {text} if !text.contains(literal))));
    assert_eq!(operations.maintain().unwrap(), 0);
    call(&adapter, "secrets_maintain", json!({}));
    assert_eq!(operations.list().unwrap().len(), 1);
}

#[test]
fn explicit_exports_preserve_binary_plaintext_and_ignore_drive_on_cli() {
    let (_directory, pile, key) = fixture();
    let plaintext = b"raw\0\xff\r\n";
    let operations = Secrets::new(pile.clone(), Some(key.clone()));
    let adapter = secrets::mcp::Secrets::new(pile.clone(), Some(key.clone()));
    call(
        &adapter,
        "secrets_add",
        json!({"name":"binary", "data_base64":base64::engine::general_purpose::STANDARD.encode(plaintext)}),
    );
    let id = operations.list().unwrap()[0].id;
    let parts = call(&adapter, "secrets_get", json!({"secret":format!("{id:x}")}));
    assert_eq!(parts.len(), 1);
    let Part::Blob {
        bytes,
        mime_type,
        uri,
    } = &parts[0]
    else {
        panic!("plaintext is an explicit resource, not perception");
    };
    assert_eq!(bytes.as_ref(), plaintext);
    assert_eq!(mime_type, "application/octet-stream");
    assert_eq!(uri, &format!("secrets://{id:x}"));
    let output = Command::new(env!("CARGO_BIN_EXE_secrets"))
        .arg("--pile")
        .arg(&pile)
        .arg("--key")
        .arg(&key)
        .args(["get", "--secret", &format!("{id:x}")])
        .env("DRIVE_ENDPOINT", "invalid-and-must-not-be-used")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, plaintext);
}

#[test]
fn malformed_requests_do_not_open_or_initialize_storage() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("absent.pile");
    let adapter = secrets::mcp::Secrets::new(pile.clone(), None);
    assert_eq!(adapter.tools().len(), 4);
    for (name, input) in [
        ("secrets_add", r#"{"name":"x"}"#),
        (
            "secrets_add",
            r#"{"name":"x","value":"a","data_base64":"Yg=="}"#,
        ),
        ("secrets_add", r#"{"name":"x","data_base64":"???"}"#),
        ("secrets_add", r#"{"name":"x","value":"a","value":"b"}"#),
        ("secrets_get", r#"{"secret":"not-a-version"}"#),
        (
            "secrets_get",
            r#"{"secret":"00000000000000000000000000000000"}"#,
        ),
        ("secrets_list", r#"{"show_secrets":true}"#),
    ] {
        let error = adapter
            .call(
                name,
                input.to_owned().into(),
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
fn failed_receipt_does_not_encrypt_and_publish_a_second_version() {
    let (_directory, pile, key) = fixture();
    let adapter = secrets::mcp::Secrets::new(pile.clone(), Some(key.clone()));
    let error = adapter
        .call(
            "secrets_add",
            serde_json::to_vec(&json!({"name":"one", "value":"a"}))
                .unwrap()
                .into(),
            &mut Out::new(&mut |_| anyhow::bail!("receipt failed")),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("receipt failed"));
    let operations = Secrets::new(pile, Some(key));
    let rows = operations.list().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(&*operations.get(rows[0].id).unwrap(), b"a");
}
