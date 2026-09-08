use anybytes::Bytes;
use clap::Parser;
use faculties::headspace::{
    cli, mcp, AddProfileOptions, Credential, CredentialUpdateError, Headspace, ProfileEdit,
    SecretRole,
};
use faculties::mcp::{Faculty, InvalidArguments, Server};
use faculties::out::{Out, Part};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

struct Fixture {
    directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("headspace.pile");
        let key = directory.path().join("explicit.key");
        fs::File::create(&pile).unwrap();
        faculties::storage::initialize_signer(&pile, Some(&key)).unwrap();
        Self {
            directory,
            pile,
            key,
        }
    }
    fn headspace(&self) -> Headspace {
        Headspace::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn adapter(&self) -> mcp::Headspace {
        mcp::Headspace::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn add(&self, name: &str) -> String {
        let id = self
            .headspace()
            .add(
                &AddProfileOptions {
                    name: name.to_owned(),
                    ..Default::default()
                },
                &mut Out::new(&mut |_| Ok(())),
            )
            .unwrap();
        format!("{id:x}")
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
            "headspace".to_owned(),
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
fn direct_operations_cli_and_mcp_share_settled_profile_and_idempotent_updates() {
    let fixture = Fixture::new();
    let first = fixture.add("first");
    fixture.add("second");
    fixture.call("headspace_use", json!({"profile":first}));
    assert_eq!(
        fixture.cli(&["show"]),
        fixture.call("headspace_show", json!({}))
    );
    assert_eq!(
        fixture.cli(&["list"]),
        fixture.call("headspace_list", json!({}))
    );
    fixture
        .headspace()
        .set(&ProfileEdit::Stream(true), &mut Out::new(&mut |_| Ok(())))
        .unwrap();
    let current = fixture.call("headspace_show", json!({}));
    assert!(text(&current).contains("stream = true"));
    fixture.call("headspace_set", json!({"field":"stream","value":true}));
    assert_eq!(current, fixture.cli(&["show"]));
    fixture.call(
        "headspace_set",
        json!({"field":"reasoning-effort","value":"high"}),
    );
    fixture.call("headspace_unset", json!({"field":"reasoning-effort"}));
    assert!(text(&fixture.cli(&["show"])).contains("reasoning_effort = null"));
}

#[test]
fn mcp_profile_strings_are_literal_but_cli_alone_expands_file_inputs() {
    let fixture = Fixture::new();
    fixture.add("resident");
    let path = fixture.directory.path().join("model.txt");
    fs::write(&path, "model-from-cli-file").unwrap();
    let argument = format!("@{}", path.display());
    fixture.call("headspace_set", json!({"field":"model","value":argument}));
    assert!(text(&fixture.call("headspace_show", json!({}))).contains(&argument));
    fixture.cli(&["set", "model", &argument]);
    assert!(text(&fixture.call("headspace_show", json!({}))).contains("model-from-cli-file"));
    fixture.cli(&["set", "model", "@@literal-model"]);
    assert!(text(&fixture.cli(&["show"])).contains("@literal-model"));
    fixture.cli(&["set", "stream", "yes"]);
    assert!(text(&fixture.call("headspace_show", json!({}))).contains("stream = true"));
}

#[test]
fn secret_plaintext_is_literal_redacted_by_default_and_only_exact_active_references_open() {
    let fixture = Fixture::new();
    let first = fixture.add("first");
    let path = fixture.directory.path().join("credential.txt");
    fs::write(&path, "must-not-be-read-by-mcp").unwrap();
    let literal = format!("@{}", path.display());
    let receipt = fixture.call(
        "headspace_secret_set",
        json!({"role":"model","value":literal}),
    );
    assert!(!text(&receipt).contains(&literal));
    assert!(!text(&receipt).contains("must-not-be-read"));
    let redacted = text(&fixture.call("headspace_show", json!({})));
    assert!(redacted.contains("<redacted>"));
    assert!(!redacted.contains(&literal));
    assert!(text(&fixture.call("headspace_show", json!({"show_secrets":true}))).contains(&literal));
    fixture.add("second");
    fixture.call(
        "headspace_secret_set",
        json!({"role":"model","value":"only-second-profile"}),
    );
    let opened = text(&fixture.call("headspace_show", json!({"show_secrets":true})));
    assert!(opened.contains("only-second-profile"));
    assert!(!opened.contains(&literal));
    fixture.call("headspace_use", json!({"profile":first}));
    let opened = text(&fixture.call("headspace_show", json!({"show_secrets":true})));
    assert!(opened.contains(&literal));
    assert!(!opened.contains("only-second-profile"));
    fixture.call("headspace_secret_unset", json!({"role":"model"}));
    assert!(
        text(&fixture.call("headspace_show", json!({"show_secrets":true})))
            .contains("model_api_key = null")
    );
}

#[test]
fn secrets_first_output_failure_retains_exact_version_and_repair_does_not_republish_plaintext() {
    for fail_at in [1, 2] {
        let fixture = Fixture::new();
        fixture.add("recoverable");
        let mut emitted = 0;
        let error = fixture
            .headspace()
            .secret_set(
                SecretRole::Model,
                Credential::Plaintext(Zeroizing::new("sealed exactly once".to_owned())),
                &mut Out::new(&mut |_| {
                    emitted += 1;
                    if emitted == fail_at {
                        anyhow::bail!("receiver closed");
                    }
                    Ok(())
                }),
            )
            .unwrap_err();
        let evidence = error
            .downcast_ref::<CredentialUpdateError>()
            .expect("typed partial publication evidence");
        assert_eq!(evidence.reference_published, fail_at == 2);
        let version = evidence.version;
        assert!(format!("{error:#}").contains(&format!("{version:x}")));
        let repaired = fixture
            .headspace()
            .secret_set(
                SecretRole::Model,
                Credential::Version(format!("{version:x}")),
                &mut Out::new(&mut |_| Ok(())),
            )
            .unwrap();
        assert_eq!(repaired, version);
        let repaired_view = fixture.call("headspace_show", json!({"show_secrets":true}));
        assert!(text(&repaired_view).contains("sealed exactly once"));
        fixture.call(
            "headspace_secret_set",
            json!({"role":"model","version":format!("{version:x}")}),
        );
        assert_eq!(
            repaired_view,
            fixture.call("headspace_show", json!({"show_secrets":true}))
        );
    }
}

#[test]
fn headspace_schemas_reject_unknown_config_duplicates_and_untyped_edits_before_storage() {
    let directory = tempfile::tempdir().unwrap();
    let adapter = mcp::Headspace::new(directory.path().join("absent.pile"), None);
    assert_eq!(adapter.tools().len(), 9);
    Server::new(&[&adapter]).unwrap();
    for (tool, arguments) in [
        (
            "headspace_show",
            r#"{"show_secrets":false,"show_secrets":true}"#,
        ),
        ("headspace_show", r#"{"pile":"/host/pile"}"#),
        ("headspace_set", r#"{"field":"stream","value":"yes"}"#),
        (
            "headspace_set",
            r#"{"field":"model","value":"a","value":"b"}"#,
        ),
        (
            "headspace_set",
            r#"{"field":"model","value":"a","persona":"ambient"}"#,
        ),
        (
            "headspace_secret_set",
            r#"{"role":"model","value":"v","version":"id"}"#,
        ),
        ("headspace_secret_set", r#"{"role":"model"}"#),
        (
            "headspace_secret_set",
            r#"{"role":"model","path":"/host/secret"}"#,
        ),
        ("headspace_add", r#"{"name":"resident","key":"/host/key"}"#),
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
