//! Mail native/CLI/MCP contracts on temporary resident piles; no POP or SMTP network calls.
use anybytes::Bytes;
use anyhow::{bail, Result};
use base64::Engine as _;
use faculties::mail::{self, AccountOptions, DraftAttachment, DraftRequest, Mail};
use faculties::mcp::{Faculty, InvalidArguments, Server};
use faculties::out::{Out, Part};
use faculties::relations::{ProfileInput, Relations};
use faculties::storage::{
    initialize_signer, load_signer, open_pile_strict, publish_fragment, FactArchive,
};
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::{CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::repo::SnapshotSource;
use triblespace::prelude::*;

struct Fixture {
    directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
    account: Id,
    config: Id,
    credential: Id,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("mail.pile");
        let key = directory.path().join("mail.key");
        fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        let receipt = Mail::new(pile.clone(), Some(key.clone()))
            .account_set_with_password(
                AccountOptions {
                    account: None,
                    address: "me@example.test".into(),
                    display_name: "Me".into(),
                    pop_endpoint: "pop.example.test:995".into(),
                    smtp_endpoint: "smtp.example.test:465".into(),
                    username: None,
                    credential_version: None,
                    disabled: false,
                },
                "synthetic-mail-password".into(),
            )
            .unwrap();
        Self {
            directory,
            pile,
            key,
            account: receipt.account,
            config: receipt.config,
            credential: receipt.credential,
        }
    }
    fn operations(&self) -> Mail {
        Mail::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn mcp(&self) -> mail::mcp::Mail {
        mail::mcp::Mail::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn account_options(&self, disabled: bool) -> AccountOptions {
        AccountOptions {
            account: Some(format!("{:x}", self.account)),
            address: "me@example.test".into(),
            display_name: "Me".into(),
            pop_endpoint: "pop.example.test:995".into(),
            smtp_endpoint: "smtp.example.test:465".into(),
            username: None,
            credential_version: Some(self.credential),
            disabled,
        }
    }
    fn reader(&self, label: &str) -> Id {
        Relations::new(self.pile.clone(), Some(self.key.clone()))
            .add(
                ProfileInput {
                    label: label.into(),
                    ..Default::default()
                },
                None,
                &[],
            )
            .unwrap()
            .person
    }
    fn incoming(&self, uid: &str, body: &str) -> Id {
        let raw=format!("From: Sender <sender@example.test>\r\nTo: me@example.test\r\nMessage-ID: <inbound@example.test>\r\nSubject: Hello\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}");
        let value = mail::pop_publication(self.account, self.config, uid, raw.as_bytes()).unwrap();
        if !value.files.facts().is_empty() {
            publish_fragment(
                &self.pile,
                Some(&self.key),
                faculties::schemas::files::DEFAULT_SCOPE_ID,
                value.files,
            )
            .unwrap();
        }
        publish_fragment(
            &self.pile,
            Some(&self.key),
            faculties::schemas::mail::DEFAULT_SCOPE_ID,
            value.mail,
        )
        .unwrap();
        value.wire
    }
    fn draft(&self, subject: &str, body: &str) -> DraftRequest {
        DraftRequest {
            account: format!("{:x}", self.account),
            to: vec!["recipient@example.test".into()],
            cc: vec![],
            bcc: vec![],
            subject: subject.into(),
            body: body.into(),
            attachments: vec![],
        }
    }
    fn materialize(&self, id: Id) -> mail::MaterializedDraft {
        let signer = load_signer(&self.pile, Some(&self.key)).unwrap();
        let mut pile = open_pile_strict(&self.pile).unwrap();
        let mut indexes = Vec::new();
        for scope in [
            faculties::schemas::mail::DEFAULT_SCOPE_ID,
            faculties::schemas::files::DEFAULT_SCOPE_ID,
        ] {
            let source = faculties::collection_names::open_configured(
                &mut pile,
                scope,
                signer.verifying_key(),
            )
            .unwrap();
            let snapshot = pile.snapshot().unwrap();
            let policy = source.policy(&snapshot).unwrap();
            drop(snapshot);
            let succinct = pile
                .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
                .unwrap();
            let rank9 = pile
                .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
                .unwrap();
            pollster::block_on(async {
                drop(pile.ensure(source).await.unwrap());
                drop(pile.maintain(succinct).await.unwrap());
                drop(pile.maintain(rank9).await.unwrap());
            });
            indexes.push(rank9);
        }
        let reader = pile.snapshot().unwrap();
        let mail = reader
            .collection(indexes[0])
            .unwrap()
            .view::<FactArchive>()
            .unwrap();
        let files = reader
            .collection(indexes[1])
            .unwrap()
            .view::<FactArchive>()
            .unwrap();
        let value = mail::materialize_draft(&reader, &mail, &files, id).unwrap();
        pile.close().unwrap();
        value
    }
    fn cli(&self, persona: Option<&str>, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mail"));
        clean_child(&mut command);
        if let Some(persona) = persona {
            command.env("PERSONA", persona);
        }
        command
            .arg("--pile")
            .arg(&self.pile)
            .arg("--key")
            .arg(&self.key)
            .args(args)
            .output()
            .unwrap()
    }
}
fn clean_child(command: &mut Command) {
    for (name, _) in std::env::vars_os() {
        let text = name.to_string_lossy();
        if text.starts_with("TRIBLESPACE_")
            || text.starts_with("DRIVE_")
            || matches!(text.as_ref(), "PILE" | "PERSONA" | "MAIL_PASS")
        {
            command.env_remove(name);
        }
    }
}
fn collect(execute: impl FnOnce(&mut Out<'_>) -> Result<()>) -> Result<String> {
    let mut text = String::new();
    execute(&mut Out::new(&mut |part| {
        match part {
            Part::Text { text: part } => text.push_str(&part),
            _ => panic!("unexpected modality"),
        };
        Ok(())
    }))?;
    Ok(text)
}
fn call(faculty: &mail::mcp::Mail, tool: &str, args: Value) -> Result<String> {
    collect(|out| faculty.call(tool, Bytes::from(serde_json::to_vec(&args).unwrap()), out))
}
fn success(output: Output) -> String {
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn explicit_persona_seen_receipts_do_not_change_show_or_other_readers() {
    let fixture = Fixture::new();
    let first = fixture.reader("First");
    let second = fixture.reader("Second");
    let wire = fixture.incoming("uid-one", "@- resident message");
    let message = format!("{wire:x}");
    let shown = fixture.operations().show(&message).unwrap();
    assert_eq!(shown[0].body, "@- resident message");
    assert_eq!(
        success(fixture.cli(None, &["show", &message])),
        call(&fixture.mcp(), "mail_show", json!({"message":message})).unwrap()
    );
    assert!(fixture.operations().list("First", true, false).unwrap()[0].unread);
    let receipt = fixture.operations().read("First", &message).unwrap();
    assert_eq!(receipt.reader, first);
    assert_eq!(receipt.wire, wire);
    assert_eq!(
        receipt.observation,
        fixture
            .operations()
            .read("First", &message)
            .unwrap()
            .observation
    );
    assert!(fixture
        .operations()
        .list("First", true, false)
        .unwrap()
        .is_empty());
    assert_eq!(
        fixture
            .operations()
            .list(&format!("{second:x}"), true, false)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(fixture.operations().show(&message).unwrap(), shown);
    let listed = call(
        &fixture.mcp(),
        "mail_list",
        json!({"persona":"Second","unread":true}),
    )
    .unwrap();
    assert_eq!(
        listed,
        success(fixture.cli(Some("Second"), &["list", "--unread"]))
    );
    call(
        &fixture.mcp(),
        "mail_read",
        json!({"persona":"Second","message":message}),
    )
    .unwrap();
    assert!(fixture
        .operations()
        .list("Second", true, false)
        .unwrap()
        .is_empty());
}

#[test]
fn draft_supports_exact_files_and_resident_attachments_without_cli_paths() {
    let fixture = Fixture::new();
    let file =
        faculties::files::stage(b"existing file".to_vec(), "existing.txt", "text/plain").unwrap();
    let file_id = file.root().unwrap();
    publish_fragment(
        &fixture.pile,
        Some(&fixture.key),
        faculties::schemas::files::DEFAULT_SCOPE_ID,
        file,
    )
    .unwrap();
    let output=call(&fixture.mcp(),"mail_draft",json!({
        "account":format!("{:x}",fixture.account),"to":["recipient@example.test"],"subject":"@- literal subject","body":"@/not-a-host-file",
        "file_ids":[format!("{file_id:x}")],"attachments":[{"name":"resident.bin","mime":"application/octet-stream","data":base64::engine::general_purpose::STANDARD.encode([0,1,255])}],
    })).unwrap();
    let outbox = fixture.operations().outbox().unwrap();
    assert_eq!(outbox.len(), 1);
    let draft = fixture.materialize(outbox[0].draft);
    assert!(output.contains(&format!("Draft {:x}", draft.id)));
    assert!(output.contains(&format!("Decision {:x}", mail::draft_decision_id(draft.id))));
    assert_eq!(draft.subject, "@- literal subject");
    assert_eq!(draft.body, "@/not-a-host-file");
    assert_eq!(draft.attachments.len(), 2);
    assert!(draft
        .attachments
        .iter()
        .any(|file| file.filename == "existing.txt" && file.bytes == b"existing file"));
    assert!(draft
        .attachments
        .iter()
        .any(|file| file.filename == "resident.bin" && file.bytes == [0, 1, 255]));
    let invalid = fixture
        .operations()
        .draft(DraftRequest {
            attachments: vec![DraftAttachment::File(genid().id)],
            ..fixture.draft("should not publish", "body")
        })
        .unwrap_err();
    assert!(invalid.to_string().contains("unknown Files attachment"));
    assert_eq!(fixture.operations().outbox().unwrap().len(), 1);
}

#[test]
fn cli_expands_body_and_attachment_files_but_native_body_stays_literal() {
    let fixture = Fixture::new();
    let body = fixture.directory.path().join("body.txt");
    let file = fixture.directory.path().join("data.bin");
    fs::write(&body, "body from disk").unwrap();
    fs::write(&file, [3, 2, 1]).unwrap();
    let account = format!("{:x}", fixture.account);
    success(fixture.cli(
        None,
        &[
            "draft",
            "--account",
            &account,
            "--to",
            "recipient@example.test",
            "--subject",
            "CLI",
            "--attach",
            &file.display().to_string(),
            &format!("@{}", body.display()),
        ],
    ));
    let outbox = fixture.operations().outbox().unwrap();
    let draft = fixture.materialize(outbox[0].draft);
    assert_eq!(draft.body, "body from disk");
    assert_eq!(draft.attachments[0].bytes, [3, 2, 1]);
    let direct = fixture
        .operations()
        .draft(fixture.draft("native", "@-"))
        .unwrap();
    assert_eq!(fixture.materialize(direct.draft).body, "@-");
    assert_eq!(direct.decision, mail::draft_decision_id(direct.draft));
}

#[test]
fn reply_uses_literal_body_and_refuses_conflicting_wire_projections() {
    let fixture = Fixture::new();
    let wire = fixture.incoming("uid-first", "first source body");
    let before = fixture.operations().show(&format!("{wire:x}")).unwrap();
    call(&fixture.mcp(),"mail_reply",json!({"account":format!("{:x}",fixture.account),"message":format!("{wire:x}"),"body":"@-"})).unwrap();
    let outbox = fixture.operations().outbox().unwrap();
    let reply = fixture.materialize(outbox[0].draft);
    assert_eq!(reply.body, "@-");
    assert_eq!(reply.subject, "Re: Hello");
    assert_eq!(reply.to, ["Sender <sender@example.test>"]);
    assert_eq!(reply.in_reply_to, ["inbound@example.test"]);
    fixture.incoming("uid-other", "different body with same claimed Message-ID");
    assert_eq!(before[0].body, "first source body");
    let error=call(&fixture.mcp(),"mail_reply",json!({"account":format!("{:x}",fixture.account),"message":format!("{wire:x}"),"body":"must not choose"})).unwrap_err();
    assert!(error.to_string().contains("conflicting parser projections"));
    assert_eq!(fixture.operations().outbox().unwrap().len(), 1);
}

#[test]
fn account_exact_version_replay_and_disabled_fetch_are_credential_safe() {
    let fixture = Fixture::new();
    let replay = fixture
        .operations()
        .account_set(fixture.account_options(false))
        .unwrap();
    assert!(!replay.changed);
    assert_eq!(replay.credential, fixture.credential);
    let text = call(&fixture.mcp(), "mail_account_list", json!({})).unwrap();
    assert_eq!(text, success(fixture.cli(None, &["account", "list"])));
    assert!(!text.contains("synthetic-mail-password"));
    call(&fixture.mcp(),"mail_account_set",json!({
        "account":format!("{:x}",fixture.account),"address":"me@example.test","display_name":"Me",
        "pop_endpoint":"pop.example.test:995","smtp_endpoint":"smtp.example.test:465","credential_version":format!("{:x}",fixture.credential),"disabled":true,
    })).unwrap();
    assert!(fixture.operations().fetch().unwrap().is_empty());
    assert!(call(&fixture.mcp(), "mail_fetch", json!({}))
        .unwrap()
        .is_empty());
}

#[test]
fn send_requires_existing_decide_authorization_before_smtp() {
    let fixture = Fixture::new();
    let draft = fixture
        .operations()
        .draft(fixture.draft("not authorized", "body"))
        .unwrap();
    let error = call(
        &fixture.mcp(),
        "mail_send",
        json!({"draft":format!("{:x}",draft.draft)}),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("has no resolution"));
    assert!(!format!("{error:#}").contains("SMTP submission"));
    assert!(matches!(
        fixture.operations().outbox().unwrap()[0].delivery,
        mail::DraftDelivery::Pending
    ));
}

#[test]
fn independent_decoders_reject_nested_input_errors_and_credentials_without_storage() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("absent.pile");
    let faculty = mail::mcp::Mail::new(pile.clone(), None);
    Server::new(&[&faculty]).unwrap();
    assert_eq!(
        faculty
            .tools()
            .iter()
            .map(|tool| tool.name)
            .collect::<Vec<_>>(),
        [
            "mail_account_set",
            "mail_account_list",
            "mail_fetch",
            "mail_draft",
            "mail_reply",
            "mail_send",
            "mail_outbox",
            "mail_list",
            "mail_read",
            "mail_show",
            "mail_search",
        ]
    );
    for (tool, raw) in [
        (
            "mail_account_set",
            r#"{"address":"a","display_name":"n","pop_endpoint":"p","smtp_endpoint":"s","password":"do-not-output-this"}"#,
        ),
        (
            "mail_account_set",
            r#"{"address":"a","display_name":"n","pop_endpoint":"p","smtp_endpoint":"s","credential_version":"@-"}"#,
        ),
        (
            "mail_account_set",
            r#"{"address":"a","display_name":"n","pop_endpoint":"p","smtp_endpoint":"s"}"#,
        ),
        ("mail_account_list", r#"{"key":"credential"}"#),
        ("mail_fetch", r#"{"account":"not-supported"}"#),
        (
            "mail_draft",
            r#"{"account":"a","to":[],"subject":"s","body":"b"}"#,
        ),
        (
            "mail_draft",
            r#"{"account":"a","to":[1],"subject":"s","body":"b"}"#,
        ),
        (
            "mail_draft",
            r#"{"account":"a","to":["r"],"subject":"s","body":"a","body":"b"}"#,
        ),
        (
            "mail_draft",
            r#"{"account":"a","to":["r"],"subject":"s","body":"b","attachments":[{"name":"x","mime":"text/plain","data":"not-base64!"}]}"#,
        ),
        (
            "mail_draft",
            r#"{"account":"a","to":["r"],"subject":"s","body":"b","attachments":[{"name":"x","mime":"text/plain","data":"YQ==","path":"/host"}]}"#,
        ),
        (
            "mail_draft",
            r#"{"account":"a","to":["r"],"subject":"s","body":"b","attachments":[{"name":"x","name":"y","mime":"text/plain","data":"YQ=="}]}"#,
        ),
        (
            "mail_reply",
            r#"{"account":"a","message":"m","body":false}"#,
        ),
        ("mail_send", r#"{"draft":"a","draft":"b"}"#),
        ("mail_outbox", r#"{"pile":"/host"}"#),
        ("mail_list", r#"{"unread":true}"#),
        ("mail_list", r#"{"persona":"p","unread":"true"}"#),
        ("mail_read", r#"{"message":"m"}"#),
        ("mail_show", r#"{"message":0}"#),
        ("mail_search", r#"{"query":[]}"#),
    ] {
        let error = collect(|out| faculty.call(tool, Bytes::from(raw.as_bytes().to_vec()), out))
            .unwrap_err();
        assert!(error.is::<InvalidArguments>(), "{tool}: {error:#}");
        assert!(!format!("{error:#}").contains("do-not-output-this"));
    }
    assert!(!pile.exists());
}

#[test]
fn postcommit_delivery_failure_does_not_erase_draft_or_decision() {
    let fixture = Fixture::new();
    let error=fixture.mcp().call("mail_draft",Bytes::from(serde_json::to_vec(&json!({
        "account":format!("{:x}",fixture.account),"to":["recipient@example.test"],"subject":"durable draft","body":"literal",
    })).unwrap()),&mut Out::new(&mut |_|bail!("fixture emitter failure"))).unwrap_err();
    assert!(error.to_string().contains("fixture emitter failure"));
    let outbox = fixture.operations().outbox().unwrap();
    assert_eq!(outbox.len(), 1);
    assert_eq!(fixture.materialize(outbox[0].draft).body, "literal");
}

#[test]
fn mcp_persona_is_explicit_even_in_a_persona_configured_process() {
    if std::env::var_os("FACULTIES_MAIL_AMBIENT_CHILD").is_none() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        clean_child(&mut command);
        let output = command
            .args([
                "--exact",
                "mcp_persona_is_explicit_even_in_a_persona_configured_process",
                "--nocapture",
            ])
            .env("FACULTIES_MAIL_AMBIENT_CHILD", "1")
            .env("PERSONA", "Ambient")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    let fixture = Fixture::new();
    fixture.reader("Ambient");
    assert!(call(&fixture.mcp(), "mail_list", json!({}))
        .unwrap_err()
        .is::<InvalidArguments>());
    assert!(
        call(&fixture.mcp(), "mail_list", json!({"persona":"Ambient"}))
            .unwrap()
            .is_empty()
    );
}
