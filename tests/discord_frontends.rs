//! Discord frontends over temporary resident observations; no real bot or network requests.
use anybytes::Bytes;
use anyhow::{bail, Result};
use faculties::discord::{self, Discord, PullOptions, ReadOptions};
use faculties::mcp::{Faculty, InvalidArguments, Server};
use faculties::out::{Out, Part};
use faculties::schemas::{archive::archive, discord::discord as schema};
use faculties::storage::{initialize_signer, publish_fragment};
use hifitime::Epoch;
use serde_json::{json, Value};
use std::{fs, path::PathBuf, process::Command};
use triblespace::core::metadata;
use triblespace::prelude::inlineencodings::NsTAIInterval;
use triblespace::prelude::*;

const CHANNEL: &str = "100000000000000002";
const MESSAGE: &str = "100000000000000003";

struct Fixture {
    _directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("discord.pile");
        let key = directory.path().join("discord.key");
        fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        Self {
            _directory: directory,
            pile,
            key,
        }
    }
    fn operations(&self) -> Discord {
        Discord::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn mcp(&self) -> discord::mcp::Discord {
        discord::mcp::Discord::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn publish(&self, fragment: Fragment) {
        publish_fragment(
            &self.pile,
            Some(&self.key),
            faculties::schemas::discord::DEFAULT_SCOPE_ID,
            fragment,
        )
        .unwrap();
    }
}
fn at(seconds: f64) -> Inline<NsTAIInterval> {
    let epoch = Epoch::from_unix_seconds(seconds);
    (epoch, epoch).try_to_inline().unwrap()
}
fn observation(message: &str, content: &str, created: f64, edited: Option<f64>) -> Fragment {
    let mut fragment = discord::message_anchor_fragment(message).unwrap();
    let anchor = fragment.root().unwrap();
    let channel = discord::channel_fragment(CHANNEL).unwrap();
    let channel_id = channel.root().unwrap();
    fragment += channel;
    let author = discord::user_fragment("100000000000000004").unwrap();
    let author_id = author.root().unwrap();
    fragment += author;
    fragment += entity! { _ @ metadata::tag: schema::kind_user_profile, schema::user: author_id, archive::author_name: "Ada".to_owned() };
    fragment += entity! { _ @
        metadata::tag: archive::kind_message, schema::message: anchor, schema::channel: channel_id,
        archive::author: author_id, archive::content: content.to_owned(), metadata::created_at: at(created),
        archive::edited_at?: edited.map(at),
    };
    fragment
}
fn collect(execute: impl FnOnce(&mut Out<'_>) -> Result<()>) -> Result<String> {
    let mut text = String::new();
    execute(&mut Out::new(&mut |part| {
        match part {
            Part::Text { text: part } => text.push_str(&part),
            _ => panic!("unexpected modality"),
        }
        Ok(())
    }))?;
    Ok(text)
}
fn call(faculty: &discord::mcp::Discord, tool: &str, args: Value) -> Result<String> {
    collect(|out| faculty.call(tool, Bytes::from(serde_json::to_vec(&args).unwrap()), out))
}
fn clean_child(command: &mut Command) {
    for (name, _) in std::env::vars_os() {
        let text = name.to_string_lossy();
        if text.starts_with("TRIBLESPACE_")
            || text.starts_with("DRIVE_")
            || matches!(text.as_ref(), "PILE" | "PERSONA" | "DISCORD_TOKEN")
        {
            command.env_remove(name);
        }
    }
}

#[test]
fn native_and_mcp_resident_reads_need_no_bot_token() {
    let fixture = Fixture::new();
    fixture.publish(observation(MESSAGE, "@- literal message", 10.0, None));
    let history = fixture.operations().read(ReadOptions::default()).unwrap();
    assert_eq!(history.messages.len(), 1);
    assert_eq!(history.messages[0].content, "@- literal message");
    assert_eq!(
        history.messages[0].anchor,
        discord::message_anchor_fragment(MESSAGE)
            .unwrap()
            .root()
            .unwrap()
    );
    assert_eq!(
        collect(|out| discord::render::history(&history, out)).unwrap(),
        call(&fixture.mcp(), "discord_read", json!({})).unwrap()
    );

    let mut command = Command::new(env!("CARGO_BIN_EXE_discord"));
    clean_child(&mut command);
    let output = command
        .arg("--pile")
        .arg(&fixture.pile)
        .arg("--key")
        .arg(&fixture.key)
        .args(["read", CHANNEL])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing Discord token"));
}

#[test]
fn owned_history_keeps_old_snapshot_and_exposes_divergent_edits() {
    let fixture = Fixture::new();
    fixture.publish(observation(MESSAGE, "original", 10.0, None));
    let old = fixture.operations().read(ReadOptions::default()).unwrap();
    fixture.publish(observation(MESSAGE, "edited", 10.0, Some(20.0)));
    fixture.publish(observation(MESSAGE, "divergent", 10.0, Some(20.0)));
    assert_eq!(old.messages[0].content, "original");
    let current = fixture.operations().read(ReadOptions::default()).unwrap();
    assert_eq!(current.messages.len(), 2);
    assert!(current
        .messages
        .iter()
        .all(|value| value.variant_count == 2));
    let shown = call(
        &fixture.mcp(),
        "discord_read",
        json!({"channel_id":CHANNEL,"limit":0}),
    )
    .unwrap();
    assert!(shown.contains("[DIVERGENT 1/2]"));
    assert!(shown.contains("[DIVERGENT 2/2]"));
    assert!(shown.contains("edited"));
    assert!(shown.contains("divergent"));
    assert!(!shown.contains("original"));
}

#[test]
fn selected_history_does_not_acquire_unselected_cold_message_body() {
    let fixture = Fixture::new();
    fixture.publish(
        observation(MESSAGE, "cold text", 10.0, None)
            .into_facts()
            .into(),
    );
    fixture.publish(observation("100000000000000005", "warm text", 20.0, None));
    assert!(call(&fixture.mcp(), "discord_read", json!({"limit":1}))
        .unwrap()
        .contains("warm text"));
    let mut emitted = 0;
    let error = fixture
        .mcp()
        .call(
            "discord_read",
            Bytes::from(br#"{"limit":0}"#.to_vec()),
            &mut Out::new(&mut |_| {
                emitted += 1;
                Ok(())
            }),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("Discord message content"));
    assert_eq!(emitted, 0);
}

#[test]
fn decoder_rejects_bad_ids_numeric_types_duplicates_and_host_fields_without_storage() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("absent.pile");
    let faculty = discord::mcp::Discord::new(pile.clone(), None);
    Server::new(&[&faculty]).unwrap();
    assert_eq!(
        faculty
            .tools()
            .iter()
            .map(|tool| tool.name)
            .collect::<Vec<_>>(),
        [
            "discord_read",
            "discord_pull",
            "discord_send",
            "discord_channels_list"
        ]
    );
    for (tool, args) in [
        ("discord_read", r#"{"limit":-1}"#),
        ("discord_read", r#"{"limit":"2"}"#),
        ("discord_read", r#"{"limit":1.5}"#),
        ("discord_read", r#"{"channel_id":"01"}"#),
        ("discord_read", r#"{"since":"not a timestamp"}"#),
        ("discord_pull", r#"{"fetch_limit":0}"#),
        ("discord_pull", r#"{"reconcile_limit":101}"#),
        ("discord_pull", r#"{"token":"do-not-output"}"#),
        (
            "discord_send",
            r#"{"channel_id":"1","text":"a","text":"b"}"#,
        ),
        ("discord_send", r#"{"channel_id":1,"text":"a"}"#),
        ("discord_send", r#"{"channel_id":"1","text":" "}"#),
        (
            "discord_send",
            r#"{"channel_id":"1","text":"a","pile":"/elsewhere"}"#,
        ),
        (
            "discord_channels_list",
            r#"{"guild":"18446744073709551616"}"#,
        ),
        ("discord_channels_list", r#"{"guild":"1","guild":"2"}"#),
    ] {
        let error = collect(|out| faculty.call(tool, Bytes::from(args.as_bytes().to_vec()), out))
            .unwrap_err();
        assert!(error.is::<InvalidArguments>(), "{tool}: {error:#}");
    }
    assert!(!pile.exists());
}

#[test]
fn missing_bot_config_fails_before_storage_and_debug_never_discloses_it() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("absent.pile");
    let faculty = discord::mcp::Discord::new(pile.clone(), None);
    for (tool, args) in [
        (
            "discord_send",
            json!({"channel_id":"1","text":"@/not-a-host-file"}),
        ),
        ("discord_pull", json!({"channel_id":"1"})),
        ("discord_channels_list", json!({})),
    ] {
        let error = call(&faculty, tool, args).unwrap_err();
        assert!(
            format!("{error:#}").contains("missing Discord bot token"),
            "{tool}: {error:#}"
        );
    }
    assert!(!pile.exists());
    let token = "test-configured-bot-token";
    let configured = faculty.with_token(token.to_owned());
    assert!(format!("{configured:?}").contains("token_configured: true"));
    assert!(!format!("{configured:?}").contains(token));
    let native = Discord::new(pile.clone(), None).with_token(token.to_owned());
    assert!(!format!("{native:?}").contains(token));
    assert!(native
        .pull(PullOptions {
            fetch_limit: 0,
            ..Default::default()
        })
        .is_err());
    assert!(!pile.exists());
}

#[test]
fn mcp_does_not_inherit_an_ambient_bot_token_and_cli_help_redacts_it() {
    if std::env::var_os("FACULTIES_DISCORD_AMBIENT_CHILD").is_none() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        clean_child(&mut command);
        let output = command
            .args([
                "--exact",
                "mcp_does_not_inherit_an_ambient_bot_token_and_cli_help_redacts_it",
                "--nocapture",
            ])
            .env("FACULTIES_DISCORD_AMBIENT_CHILD", "1")
            .env("DISCORD_TOKEN", "test-only-secret-environment-token")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let faculty = discord::mcp::Discord::new(directory.path().join("absent.pile"), None);
    assert!(call(&faculty, "discord_channels_list", json!({}))
        .unwrap_err()
        .to_string()
        .contains("missing Discord bot token"));
    let output = Command::new(env!("CARGO_BIN_EXE_discord"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("test-only-secret-environment-token"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("test-only-secret-environment-token"));
}

#[test]
fn output_failure_stops_history_delivery_without_mutating_resident_evidence() {
    let fixture = Fixture::new();
    fixture.publish(observation(MESSAGE, "unchanged", 10.0, None));
    fixture.operations().read(ReadOptions::default()).unwrap();
    let before = fs::read(&fixture.pile).unwrap();
    let error = fixture
        .mcp()
        .call(
            "discord_read",
            Bytes::from(br#"{}"#.to_vec()),
            &mut Out::new(&mut |_| bail!("fixture delivery failure")),
        )
        .unwrap_err();
    assert!(error.to_string().contains("fixture delivery failure"));
    assert_eq!(fs::read(&fixture.pile).unwrap(), before);
}
