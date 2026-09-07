//! Real local collections exercising typed operations and their two frontends.
//! No process-global environment mutation, model execution, or network fixture.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anybytes::Bytes;
use anyhow::Result;
use clap::Parser;
use faculties::collection_names::open_configured;
use faculties::mcp::{Faculty, InvalidArguments};
use faculties::message::{
    cli, mcp, AckAllOptions, ListOptions, Message, MessageStatus, Recipient, SendOptions,
};
use faculties::out::{Out, Part};
use faculties::relations::{self, ProfileInput};
use faculties::schemas::message::DEFAULT_SCOPE_ID;
use faculties::schemas::relations::DEFAULT_SCOPE_ID as RELATIONS_SCOPE;
use faculties::storage::{initialize_signer, load_signer, open_pile_strict, publish_fragment};
use triblespace::prelude::*;

struct Fixture {
    directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
    alice: Id,
    bob: Id,
    cara: Id,
    group: Id,
    group_snapshot: Id,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("messages.pile");
        let key = directory.path().join("messages.key");
        fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        let [alice, bob, cara, group] = std::array::from_fn(|_| fucid().id);
        let mut fragment = Fragment::empty();
        for (person, label) in [(alice, "Alice"), (bob, "Bob"), (cara, "Cara")] {
            fragment += relations::person_fragment(
                person,
                ProfileInput {
                    label: label.into(),
                    ..Default::default()
                },
            )
            .unwrap()
            .0;
        }
        let (created, predecessor) =
            relations::group_create_fragment(group, "Original group").unwrap();
        fragment += created;
        let members = relations::group_snapshot_fragment(
            group,
            "Original group",
            &[alice, bob],
            &[predecessor],
        )
        .unwrap();
        let group_snapshot = members.root().unwrap();
        fragment += members;
        publish_fragment(&pile, Some(&key), RELATIONS_SCOPE, fragment).unwrap();
        Self {
            directory,
            pile,
            key,
            alice,
            bob,
            cara,
            group,
            group_snapshot,
        }
    }

    fn messages(&self) -> Message {
        Message::new(self.pile.clone(), Some(self.key.clone()))
    }

    fn mcp(&self) -> mcp::Message {
        mcp::Message::new(self.pile.clone(), Some(self.key.clone()))
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_message"));
        command
            .arg("--pile")
            .arg(&self.pile)
            .arg("--key")
            .arg(&self.key);
        for variable in [
            "DRIVE_ENDPOINT",
            "DRIVE_KEY",
            "PERSONA",
            "TRIBLESPACE_PEERS",
            "TRIBLESPACE_COLLECTION_MESSAGE",
            "TRIBLESPACE_COLLECTION_RELATIONS",
        ] {
            command.env_remove(variable);
        }
        command
    }

    fn cli(&self, arguments: &[&str]) -> cli::Cli {
        cli::Cli::try_parse_from(
            [
                "message".into(),
                "--pile".into(),
                self.pile.as_os_str().to_owned(),
                "--key".into(),
                self.key.as_os_str().to_owned(),
            ]
            .into_iter()
            .chain(
                arguments
                    .iter()
                    .map(|argument| std::ffi::OsString::from(*argument)),
            ),
        )
        .unwrap()
    }

    fn message_commits(&self) -> usize {
        let signer = load_signer(&self.pile, Some(&self.key)).unwrap();
        let mut pile = open_pile_strict(&self.pile).unwrap();
        let collection =
            open_configured(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key()).unwrap();
        let count = collection
            .admitted(&pile.snapshot().unwrap())
            .unwrap()
            .len();
        pile.close().unwrap();
        count
    }
}

fn text(operation: impl FnOnce(&mut Out<'_>) -> Result<()>) -> Result<String> {
    let mut result = String::new();
    operation(&mut Out::new(&mut |part| {
        let Part::Text { text } = part else {
            panic!("Message must emit text")
        };
        result.push_str(&text);
        Ok(())
    }))?;
    Ok(result)
}

fn call(fixture: &Fixture, name: &str, arguments: serde_json::Value) -> String {
    text(|out| {
        fixture
            .mcp()
            .call(name, serde_json::to_vec(&arguments).unwrap().into(), out)
    })
    .unwrap()
}

#[test]
fn direct_operations_keep_frozen_group_delivery_and_idempotent_receipts() {
    let fixture = Fixture::new();
    let messages = fixture.messages();
    let sent = messages
        .send(&SendOptions {
            from: "Alice",
            to: "Original group",
            text: "The original recipients.\nStill literal.",
        })
        .unwrap();
    assert_eq!(sent.from, fixture.alice);
    assert_eq!(
        sent.recipient,
        Recipient::Group {
            anchor: fixture.group,
            snapshot: fixture.group_snapshot,
            basis: faculties::schemas::message::GROUP_SNAPSHOT_BASIS_WITNESSED,
        }
    );
    let original = messages.list(&ListOptions::new("Bob")).unwrap();
    assert_eq!(original.reader, fixture.bob);
    assert_eq!(original.entries.len(), 1);
    assert_eq!(original.entries[0].row.id, sent.id);
    assert_eq!(original.entries[0].row.from, fixture.alice);
    assert_eq!(original.entries[0].status, MessageStatus::Unread);
    assert!(original.entries[0].incoming);
    assert!(!original.entries[0].outgoing);
    assert_eq!(original.entries[0].to_label, "Original group");

    let successor = relations::group_snapshot_fragment(
        fixture.group,
        "Changed group",
        &[fixture.cara],
        &[fixture.group_snapshot],
    )
    .unwrap();
    publish_fragment(
        &fixture.pile,
        Some(&fixture.key),
        RELATIONS_SCOPE,
        successor,
    )
    .unwrap();
    assert!(messages
        .list(&ListOptions::new("Cara"))
        .unwrap()
        .entries
        .is_empty());
    let still_bob = messages.list(&ListOptions::new("Bob")).unwrap();
    assert_eq!(still_bob.entries, original.entries);
    assert_eq!(
        messages
            .list(&ListOptions {
                reader: "Bob",
                unread: true,
                limit: 20
            })
            .unwrap()
            .entries
            .len(),
        1
    );
    assert!(messages.ack(&format!("{:x}", sent.id), "Alice").is_err());

    let ack = messages.ack(&format!("{:x}", sent.id), "Bob").unwrap();
    assert_eq!(
        (ack.message, ack.reader, ack.already_read),
        (sent.id, fixture.bob, false)
    );
    let committed = fixture.message_commits();
    assert!(
        messages
            .ack(&format!("{:x}", sent.id), "Bob")
            .unwrap()
            .already_read
    );
    assert_eq!(
        fixture.message_commits(),
        committed,
        "repeat ack must not publish"
    );
    assert!(messages
        .ack_all(&AckAllOptions {
            by: "Bob",
            from: None
        })
        .unwrap()
        .message_ids
        .is_empty());
    assert_eq!(fixture.message_commits(), committed);
    assert!(messages
        .list(&ListOptions {
            reader: "Bob",
            unread: true,
            limit: 20
        })
        .unwrap()
        .entries
        .is_empty());
    assert_eq!(
        original.entries[0].status,
        MessageStatus::Unread,
        "an earlier observation stays unchanged"
    );
}

#[test]
fn bulk_ack_filters_sender_and_outbox_reports_direct_receipts() {
    let fixture = Fixture::new();
    let messages = fixture.messages();
    let alice = messages
        .send(&SendOptions {
            from: "Alice",
            to: "Bob",
            text: "A",
        })
        .unwrap();
    let cara = messages
        .send(&SendOptions {
            from: "Cara",
            to: "Bob",
            text: "C",
        })
        .unwrap();
    assert_eq!(
        messages
            .list(&ListOptions {
                reader: "Bob",
                unread: false,
                limit: 1
            })
            .unwrap()
            .entries
            .len(),
        1
    );
    assert!(messages
        .list(&ListOptions {
            reader: "Bob",
            unread: false,
            limit: 0
        })
        .unwrap()
        .entries
        .is_empty());
    let before = fixture.message_commits();
    let acknowledged = messages
        .ack_all(&AckAllOptions {
            by: "Bob",
            from: Some("Alice"),
        })
        .unwrap();
    assert_eq!(acknowledged.reader, fixture.bob);
    assert_eq!(acknowledged.message_ids, [alice.id]);
    assert_eq!(fixture.message_commits(), before + 1);
    let remaining = messages
        .list(&ListOptions {
            reader: "Bob",
            unread: true,
            limit: 20,
        })
        .unwrap();
    assert_eq!(
        remaining
            .entries
            .iter()
            .map(|entry| entry.row.id)
            .collect::<Vec<_>>(),
        [cara.id]
    );
    let outbox = messages.list(&ListOptions::new("Alice")).unwrap();
    assert_eq!(outbox.entries[0].status, MessageStatus::ReadByRecipient);
    assert!(outbox.entries[0].outgoing);
    assert!(!outbox.entries[0].incoming);
    assert_eq!(
        messages
            .ack_all(&AckAllOptions {
                by: "Bob",
                from: None
            })
            .unwrap()
            .message_ids,
        [cara.id]
    );
}

#[test]
fn settled_identity_shares_receipts_without_rewriting_attribution() {
    let fixture = Fixture::new();
    let messages = fixture.messages();
    let sent = messages
        .send(&SendOptions {
            from: "Alice",
            to: "Bob",
            text: "@- is literal in the library too",
        })
        .unwrap();
    let id = format!("{:x}", sent.id);
    assert!(!messages.ack(&id, "Bob").unwrap().already_read);
    let committed = fixture.message_commits();
    let identity =
        relations::identity_verdict_fragment(fixture.bob, fixture.cara, true, &[]).unwrap();
    publish_fragment(&fixture.pile, Some(&fixture.key), RELATIONS_SCOPE, identity).unwrap();
    let receipt = messages.ack(&id, "Cara").unwrap();
    assert_eq!(receipt.reader, fixture.cara);
    assert!(receipt.already_read);
    assert_eq!(fixture.message_commits(), committed);
    let observed = messages.list(&ListOptions::new("Cara")).unwrap();
    assert_eq!(observed.entries.len(), 1);
    assert_eq!(
        (observed.entries[0].row.from, observed.entries[0].row.to),
        (fixture.alice, fixture.bob)
    );
    assert_eq!(observed.entries[0].status, MessageStatus::Read);
    assert_eq!(observed.entries[0].body, "@- is literal in the library too");
}

#[test]
fn mcp_text_is_literal_and_sender_and_host_configuration_are_never_implicit() {
    let fixture = Fixture::new();
    let source = fixture.directory.path().join("not-message-content.txt");
    fs::write(&source, "must not be read by MCP").unwrap();
    let literal_path = format!("@{}", source.display());
    for literal in ["@-", literal_path.as_str()] {
        call(
            &fixture,
            "message_send",
            serde_json::json!({"from":"Alice","to":"Bob","text":literal}),
        );
    }
    let received = fixture.messages().list(&ListOptions::new("Bob")).unwrap();
    assert_eq!(received.entries.len(), 2);
    for literal in ["@-", literal_path.as_str()] {
        assert!(received.entries.iter().any(|entry| entry.body == literal));
    }
    assert!(received
        .entries
        .iter()
        .all(|entry| entry.row.from == fixture.alice));

    let missing = fixture.directory.path().join("never-open.pile");
    let adapter = mcp::Message::new(missing.clone(), None);
    assert_eq!(
        adapter
            .tools()
            .iter()
            .map(|tool| tool.name)
            .collect::<Vec<_>>(),
        [
            "message_send",
            "message_list",
            "message_ack",
            "message_ack_all"
        ]
    );
    let send_schema: serde_json::Value =
        serde_json::from_str(adapter.tools()[0].input_schema).unwrap();
    assert!(send_schema["required"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("from")));
    for (tool, arguments) in [
        (
            "message_send",
            r#"{"to":"Bob","text":"no implicit sender"}"#,
        ),
        (
            "message_send",
            r#"{"from":"Alice","from":"Cara","to":"Bob","text":"x"}"#,
        ),
        ("message_send", r#"{"from":"Alice","to":"Bob","text":7}"#),
        ("message_send", r#"{"from":"Alice","to":"Bob","text":" "}"#),
        (
            "message_send",
            r#"{"from":"Alice","to":"Bob","path":"/etc/passwd"}"#,
        ),
        ("message_list", r#"{"reader":"Bob","unread":"true"}"#),
        ("message_list", r#"{"reader":"Bob","limit":-1}"#),
        ("message_list", r#"{"reader":"Bob","pile":"other.pile"}"#),
        ("message_ack", r#"{"id":"x","by":"Bob","key":"other.key"}"#),
        ("message_ack_all", r#"{"by":"Bob","from":9}"#),
    ] {
        let error = text(|out| adapter.call(tool, Bytes::from(arguments.as_bytes().to_vec()), out))
            .unwrap_err();
        assert!(
            error.chain().any(|cause| cause.is::<InvalidArguments>()),
            "{tool}: {error:#}"
        );
        assert!(!missing.exists());
    }
}

// Ages are observational, so parity must not depend on crossing a clock tick.
fn without_ages(rendered: &str) -> String {
    rendered
        .lines()
        .map(|line| {
            if line.starts_with('[') {
                let mut fields = line.splitn(3, ' ');
                let id = fields.next().unwrap();
                let _age = fields.next().unwrap();
                format!("{id} {}", fields.next().unwrap())
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn explicit_cli_and_mcp_share_list_and_receipt_rendering() {
    let fixture = Fixture::new();
    let sent = fixture
        .messages()
        .send(&SendOptions {
            from: "Alice",
            to: "Bob",
            text: "first\nsecond\r\nGrüße",
        })
        .unwrap();
    let cli_list = text(|out| cli::execute(fixture.cli(&["list", "Bob"]), out)).unwrap();
    let mcp_list = call(
        &fixture,
        "message_list",
        serde_json::json!({"reader":"Bob"}),
    );
    assert_eq!(without_ages(&cli_list), without_ages(&mcp_list));
    assert!(mcp_list.contains("(unread) first\\nsecond\\nGrüße"));
    let id = format!("{:x}", sent.id);
    let ack = call(
        &fixture,
        "message_ack",
        serde_json::json!({"id":id,"by":"Bob"}),
    );
    assert_eq!(ack, format!("Marked {id} as read by {:x}.\n", fixture.bob));
    let cli_ack = text(|out| cli::execute(fixture.cli(&["ack", &id, "Bob"]), out)).unwrap();
    let mcp_ack = call(
        &fixture,
        "message_ack",
        serde_json::json!({"id":id,"by":"Bob"}),
    );
    assert_eq!(cli_ack, mcp_ack);
    assert!(mcp_ack.contains("was already read"));
    let cli_all = text(|out| cli::execute(fixture.cli(&["ack-all", "Bob"]), out)).unwrap();
    assert_eq!(
        cli_all,
        call(&fixture, "message_ack_all", serde_json::json!({"by":"Bob"}))
    );
}

#[test]
fn cli_keeps_persona_file_and_stdin_text_conventions() {
    let fixture = Fixture::new();
    let source = fixture.directory.path().join("cli input.txt");
    fs::write(&source, "from a CLI file\n").unwrap();
    let output = fixture
        .command()
        .env("PERSONA", "Alice")
        .args(["send", "Bob", &format!("@{}", source.display())])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut child = fixture
        .command()
        .env("PERSONA", "Alice")
        .args(["send", "Bob", "@-", "--from", "Cara"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"from CLI stdin\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let received = fixture.messages().list(&ListOptions::new("Bob")).unwrap();
    assert!(received
        .entries
        .iter()
        .any(|entry| entry.row.from == fixture.alice && entry.body == "from a CLI file\n"));
    assert!(received
        .entries
        .iter()
        .any(|entry| entry.row.from == fixture.cara && entry.body == "from CLI stdin\n"));
    let output = fixture
        .command()
        .args(["send", "Bob", "no sender"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no sender"));
}

#[test]
fn emission_failure_does_not_retry_a_completed_send() {
    let fixture = Fixture::new();
    let before = fixture.message_commits();
    let mut emissions = 0;
    let error = fixture
        .mcp()
        .call(
            "message_send",
            Bytes::from(br#"{"from":"Alice","to":"Bob","text":"one publication"}"#.to_vec()),
            &mut Out::new(&mut |_| {
                emissions += 1;
                anyhow::bail!("closed output")
            }),
        )
        .unwrap_err();
    assert_eq!(emissions, 1);
    assert!(error.to_string().contains("closed output"));
    assert_eq!(fixture.message_commits(), before + 1);
    let received = fixture.messages().list(&ListOptions::new("Bob")).unwrap();
    assert_eq!(received.entries.len(), 1);
    assert_eq!(received.entries[0].body, "one publication");
}
