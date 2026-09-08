//! Teams native operations and tailored frontends, using only temporary resident fixtures.
use anybytes::Bytes;
use anyhow::{bail, Result};
use faculties::mcp::{Faculty, InvalidArguments, Server};
use faculties::out::{Out, Part};
use faculties::storage::{
    initialize_signer, load_signer, open_pile_strict, open_secrets_collection, publish_fragment,
};
use faculties::teams::{
    self, ArchiveAccess, AttachmentGetOptions, AttachmentInput, AttachmentListOptions,
    AttachmentLookup, AttachmentMaterialization, AuthProfileInput, MessageObservationInput,
    PresenceAvailability, ReadOptions, Teams,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs,
    path::PathBuf,
    process::{Command, Output},
};
use triblespace::prelude::inlineencodings::NsTAIInterval;
use triblespace::prelude::*;

const TENANT: &str = "tenant.example";

struct Fixture {
    directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("teams.pile");
        let key = directory.path().join("teams.key");
        fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        Self {
            directory,
            pile,
            key,
        }
    }
    fn operations(&self) -> Teams {
        Teams::new(self.pile.clone(), Some(self.key.clone())).with_tenant(Some(TENANT.to_owned()))
    }
    fn mcp(&self) -> teams::mcp::Teams {
        teams::mcp::Teams::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn publish(&self, fragment: Fragment) {
        teams::validate_commit_fragment(fragment.facts()).unwrap();
        publish_fragment(
            &self.pile,
            Some(&self.key),
            faculties::schemas::teams::DEFAULT_SCOPE_ID,
            fragment,
        )
        .unwrap();
    }
    fn secret(&self) -> Id {
        let signer = load_signer(&self.pile, Some(&self.key)).unwrap();
        let mut pile = open_pile_strict(&self.pile).unwrap();
        let collection = open_secrets_collection(&mut pile, signer.verifying_key()).unwrap();
        let id = faculties::secrets::storage::add_secret(
            &mut pile,
            &signer,
            collection,
            "teams/frontend-fixture",
            b"test-only-credential-never-output",
            at(1.0),
        )
        .unwrap();
        pile.close().unwrap();
        id
    }
    fn cli(&self, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_teams"));
        clean_child(&mut command);
        command
            .arg("--pile")
            .arg(&self.pile)
            .arg("--key")
            .arg(&self.key)
            .arg("--tenant")
            .arg(TENANT)
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
            || text.starts_with("TEAMS_")
            || matches!(text.as_ref(), "PILE" | "PERSONA")
        {
            command.env_remove(name);
        }
    }
}
fn at(seconds: f64) -> Inline<NsTAIInterval> {
    let epoch = hifitime::Epoch::from_unix_seconds(seconds);
    (epoch, epoch).try_to_inline().unwrap()
}
fn message(chat: &str, message: &str, seconds: f64, content: &str) -> MessageObservationInput {
    MessageObservationInput {
        chat_id: chat.to_owned(),
        message_id: message.to_owned(),
        raw: BTreeSet::from([format!("fixture:{chat}/{message}/{content}")]),
        author_user_id: Some("user-a".into()),
        author_name: Some("Alice".into()),
        content: Some(content.to_owned()),
        created_at: Some(at(seconds)),
        modified_at: at(seconds),
        deleted_at: None,
        etag: format!("{message}:{seconds}:{content}"),
        attachments: vec![],
    }
}
fn page(
    tenant: &str,
    inputs: Vec<MessageObservationInput>,
    generation: u128,
    predecessors: Vec<Id>,
) -> (Fragment, Id) {
    let mut fragment = teams::source_fragment(tenant);
    let source = fragment.root().unwrap();
    let mut observations = Vec::new();
    for input in inputs {
        let (observed, id) = teams::observation_fragment(tenant, source, input).unwrap();
        fragment += observed;
        observations.push(id);
    }
    let receipt = teams::coverage_fragment(
        source,
        generation,
        predecessors,
        "https://graph.example/request",
        &format!("https://graph.example/delta/{generation}"),
        "delta",
        observations,
    )
    .unwrap();
    let id = receipt.root().unwrap();
    fragment += receipt;
    (fragment, id)
}
fn attachment(kind: &str, source: &str, name: &str, bytes: Option<&[u8]>) -> AttachmentInput {
    AttachmentInput {
        kind: kind.to_owned(),
        source_id: source.to_owned(),
        name: Some(name.to_owned()),
        source_pointers: BTreeSet::from(["https://graph.example/not-fetched".to_owned()]),
        materialization: bytes.map(|bytes| AttachmentMaterialization {
            bytes: bytes.to_vec(),
            file_name: name.to_owned(),
            media_type: "image/png".to_owned(),
        }),
    }
}
fn parts(faculty: &teams::mcp::Teams, name: &str, args: Value) -> Result<Vec<Part>> {
    let mut parts = Vec::new();
    faculty.call(
        name,
        Bytes::from(serde_json::to_vec(&args).unwrap()),
        &mut Out::new(&mut |part| {
            parts.push(part);
            Ok(())
        }),
    )?;
    Ok(parts)
}
fn text(parts: &[Part]) -> String {
    parts
        .iter()
        .filter_map(|part| match part {
            Part::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}
fn call(faculty: &teams::mcp::Teams, name: &str, args: Value) -> Result<String> {
    Ok(text(&parts(faculty, name, args)?))
}
fn success(output: Output) -> String {
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn resident_reads_need_no_auth_and_keep_owned_observations_stable() {
    let fixture = Fixture::new();
    let (first, head) = page(
        TENANT,
        vec![message("chat", "m1", 10.0, "first")],
        1,
        vec![],
    );
    fixture.publish(first);
    let before = fixture
        .operations()
        .read(ReadOptions::default(), ArchiveAccess::Resident)
        .unwrap();
    assert_eq!(before.value[0].content, "first");
    let (second, _) = page(
        TENANT,
        vec![
            message("chat", "m1", 20.0, "edited"),
            message("chat", "m2", 30.0, "@- literal body"),
        ],
        2,
        vec![head],
    );
    fixture.publish(second);
    assert_eq!(before.value[0].content, "first");
    let current = fixture
        .operations()
        .read(ReadOptions::default(), ArchiveAccess::Resident)
        .unwrap();
    assert_eq!(current.value.len(), 2);
    assert_eq!(current.value[0].content, "edited");
    assert_eq!(current.value[1].content, "@- literal body");
    let latest = call(
        &fixture.mcp(),
        "teams_read",
        json!({"tenant":TENANT,"limit":1,"descending":true}),
    )
    .unwrap();
    assert!(latest.contains("@- literal body"));
    assert!(!latest.contains("edited"));

    // The CLI retains sync-then-read, and therefore fails on this auth-free archive.
    let synced = fixture.cli(&["read", "--limit", "1"]);
    assert!(!synced.status.success());
    assert!(String::from_utf8_lossy(&synced.stderr).contains("has no auth profile"));
    assert!(!String::from_utf8_lossy(&synced.stdout).contains("@- literal body"));
}

#[test]
fn limited_resident_reads_do_not_acquire_unselected_cold_payloads() {
    let fixture = Fixture::new();
    let (cold, head) = page(
        TENANT,
        vec![message("chat", "old", 10.0, "unavailable old body")],
        1,
        vec![],
    );
    fixture.publish(cold.into_facts().into());
    let (warm, _) = page(
        TENANT,
        vec![message("chat", "new", 20.0, "resident recent body")],
        2,
        vec![head],
    );
    fixture.publish(warm);
    assert!(call(
        &fixture.mcp(),
        "teams_read",
        json!({"tenant":TENANT,"limit":1})
    )
    .unwrap()
    .contains("resident recent body"));
    let mut output = Vec::new();
    let error = fixture
        .mcp()
        .call(
            "teams_read",
            Bytes::from(serde_json::to_vec(&json!({"tenant":TENANT,"limit":0})).unwrap()),
            &mut Out::new(&mut |part| {
                output.push(part);
                Ok(())
            }),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("Teams message content"));
    assert!(
        output.is_empty(),
        "do not emit a header before the complete selected read succeeds"
    );
}

#[test]
fn attachment_export_is_raw_and_preserves_reference_ambiguity() {
    let fixture = Fixture::new();
    let mut left = message("left", "m1", 10.0, "left attachment");
    left.attachments = vec![
        attachment(
            "attachment",
            "same",
            "image",
            Some(b"not-decoded-as-a-picture"),
        ),
        attachment("hosted-content", "same", "hosted", Some(b"hosted bytes")),
        attachment("attachment", "pointer", "remote", None),
    ];
    let mut right = message("right", "m2", 20.0, "right attachment");
    right.attachments = vec![attachment(
        "attachment",
        "same",
        "right",
        Some(b"other bytes"),
    )];
    let (fragment, _) = page(TENANT, vec![left, right], 1, vec![]);
    fixture.publish(fragment);
    let native = fixture.operations();
    assert_eq!(
        native
            .attachments_list(
                AttachmentListOptions {
                    limit: 0,
                    ..Default::default()
                },
                ArchiveAccess::Resident
            )
            .unwrap()
            .value
            .len(),
        4
    );
    let ambiguous = native
        .attachment_get(
            AttachmentGetOptions {
                source_id: "same".into(),
                chat_id: None,
                message_id: None,
            },
            ArchiveAccess::Resident,
        )
        .unwrap();
    assert!(
        matches!(ambiguous.value, AttachmentLookup::Ambiguous(ref values) if values.len() == 3)
    );
    let narrowed = parts(
        &fixture.mcp(),
        "teams_attachment_get",
        json!({"tenant":TENANT,"source_id":"attachment:same","chat_id":"left"}),
    )
    .unwrap();
    assert!(text(&narrowed).contains("mime=image/png"));
    let exports = narrowed
        .iter()
        .filter_map(|part| match part {
            Part::Blob {
                bytes,
                mime_type,
                uri,
            } => Some((bytes, mime_type, uri)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(exports.len(), 1);
    assert_eq!(exports[0].0.as_ref(), b"not-decoded-as-a-picture");
    assert_eq!(exports[0].1, "application/octet-stream");
    assert!(exports[0].2.starts_with("teams:///attachments/"));
    assert!(!narrowed
        .iter()
        .any(|part| matches!(part, Part::Image { .. } | Part::Audio { .. })));
    assert!(call(
        &fixture.mcp(),
        "teams_attachment_get",
        json!({"tenant":TENANT,"source_id":"attachment:pointer"})
    )
    .unwrap()
    .contains("No stored attachment bytes"));
    assert!(!fixture.directory.path().join("attachments").exists());
}

#[test]
fn cli_export_owns_filename_and_overwrite_policy_without_network() {
    let fixture = Fixture::new();
    let export_dir = fixture.directory.path().join("exports");
    let data = teams::AttachmentData {
        id: genid().id,
        bytes: Bytes::from(b"raw bytes".to_vec()),
        name: "../image".into(),
        media_type: Some("image/png".into()),
        reference: "attachment:a".into(),
    };
    let mut printed = Vec::new();
    teams::cli::export_attachment(
        AttachmentLookup::Found(data.clone()),
        &export_dir,
        None,
        false,
        &mut Out::new(&mut |part| {
            printed.push(part);
            Ok(())
        }),
    )
    .unwrap();
    let path = export_dir.join("_image.png");
    assert_eq!(fs::read(&path).unwrap(), b"raw bytes");
    assert!(text(&printed).contains("_image.png"));
    let mut discard = |_| Ok(());
    let mut output = Out::new(&mut discard);
    assert!(teams::cli::export_attachment(
        AttachmentLookup::Found(data.clone()),
        &export_dir,
        None,
        false,
        &mut output
    )
    .is_err());
    teams::cli::export_attachment(
        AttachmentLookup::Found(data),
        &export_dir,
        Some("renamed.bin"),
        true,
        &mut output,
    )
    .unwrap();
    assert_eq!(
        fs::read(export_dir.join("renamed.bin")).unwrap(),
        b"raw bytes"
    );
}

#[test]
fn context_and_auth_frontends_share_receipts_but_keep_literal_mcp_strings() {
    let fixture = Fixture::new();
    let native = fixture.operations();
    let context = native.context_set(TENANT, "Bulti", "Work only").unwrap();
    assert_eq!(
        context.source,
        teams::source_fragment(TENANT).root().unwrap()
    );
    assert_eq!(native.context_show().unwrap(), context.value);
    let mcp = fixture.mcp();
    call(
        &mcp,
        "teams_context_set",
        json!({"tenant":TENANT,"present_as":"@-","boundary":"@/not-a-host-file"}),
    )
    .unwrap();
    let shown = call(&mcp, "teams_context_show", json!({"tenant":TENANT})).unwrap();
    assert_eq!(shown, success(fixture.cli(&["context", "show"])));
    assert!(shown.contains("present_as: @-"));
    assert!(shown.contains("boundary: @/not-a-host-file"));

    let secret = fixture.secret();
    let args = json!({"tenant":TENANT,"client_id":"client","user_id":"user","scopes":"@-","client_secret_version":format!("{secret:x}")});
    let first = call(&mcp, "teams_auth_set", args.clone()).unwrap();
    assert_eq!(call(&mcp, "teams_auth_set", args).unwrap(), first);
    let status = call(&mcp, "teams_auth_status", json!({"tenant":TENANT})).unwrap();
    assert!(status.contains("scopes: @-"));
    assert!(status.contains(&format!("client_secret_version: {secret:x}")));
    assert!(!status.contains("test-only-credential"));
    let scopes = fixture.directory.path().join("scopes");
    fs::write(&scopes, "User.Read offline_access").unwrap();
    success(fixture.cli(&[
        "auth",
        "set",
        "--tenant",
        TENANT,
        "--client-id",
        "client",
        "--user-id",
        "user",
        "--scopes",
        &format!("@{}", scopes.display()),
        "--client-secret-version",
        &format!("{secret:x}"),
    ]));
    let after = native.auth_status().unwrap().value;
    assert!(after.contains("scopes: User.Read offline_access"));
    let same = native
        .auth_set(AuthProfileInput {
            tenant: TENANT.into(),
            client_id: "client".into(),
            user_id: "user".into(),
            scopes: "offline_access User.Read".into(),
            client_secret_version: Some(secret),
            delegated_token_version: None,
        })
        .unwrap();
    assert!(!same.changed);
    assert!(after.contains(&format!("auth_profile: {:x}", same.profile)));
}

#[test]
fn every_outward_action_checks_presentation_before_authentication() {
    let fixture = Fixture::new();
    fixture
        .operations()
        .context_set(TENANT, "Bulti", "Work only")
        .unwrap();
    for (tool, args) in [
        (
            "teams_send",
            json!({"tenant":TENANT,"present_as":"Other","chat_id":"chat","text":"@-"}),
        ),
        (
            "teams_presence_set",
            json!({"tenant":TENANT,"present_as":"Other","availability":"Busy"}),
        ),
        (
            "teams_chat_invite",
            json!({"tenant":TENANT,"present_as":"Other","chat_id":"chat","user_id":"user"}),
        ),
        (
            "teams_chat_create",
            json!({"tenant":TENANT,"present_as":"Other","user_ids":["user"],"topic":"@-"}),
        ),
    ] {
        let error = call(&fixture.mcp(), tool, args).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("presentation mismatch"),
            "{tool}: {message}"
        );
        assert!(
            !message.contains("has no auth profile"),
            "{tool}: {message}"
        );
        assert!(
            !message.contains("graph.microsoft.com"),
            "{tool}: {message}"
        );
    }
    let error = fixture
        .operations()
        .send("", "chat", "literal")
        .unwrap_err();
    assert!(format!("{error:#}").contains("--as Bulti"));
    // Supplying the right presentation reaches auth resolution, but this fixture has no credentials.
    let error = call(
        &fixture.mcp(),
        "teams_send",
        json!({"tenant":TENANT,"present_as":"Bulti","chat_id":"chat","text":"@-"}),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("has no auth profile"));
}

#[test]
fn independent_tool_schemas_reject_host_surface_and_bad_arguments_before_storage() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("absent.pile");
    let faculty = teams::mcp::Teams::new(pile.clone(), None);
    Server::new(&[&faculty]).unwrap();
    assert_eq!(
        faculty
            .tools()
            .iter()
            .map(|tool| tool.name)
            .collect::<Vec<_>>(),
        [
            "teams_read",
            "teams_pull",
            "teams_send",
            "teams_users_list",
            "teams_presence_set",
            "teams_presence_get",
            "teams_chat_invite",
            "teams_chat_create",
            "teams_attachments_list",
            "teams_attachment_get",
            "teams_context_set",
            "teams_context_show",
            "teams_auth_status",
            "teams_auth_set",
        ]
    );
    for (tool, raw) in [
        ("teams_read", r#"{"limit":1.5}"#),
        ("teams_read", r#"{"limit":"2"}"#),
        ("teams_read", r#"{"limit":-1}"#),
        ("teams_read", r#"{"since":"not a timestamp"}"#),
        ("teams_read", r#"{"tenant":"a","tenant":"b"}"#),
        ("teams_pull", r#"{"delta_url":"https://caller.example"}"#),
        ("teams_pull", r#"{"tenant":"common"}"#),
        (
            "teams_send",
            r#"{"chat_id":"chat","text":"missing present_as"}"#,
        ),
        (
            "teams_send",
            r#"{"present_as":"Bulti","chat_id":"chat","text":"first","text":"second"}"#,
        ),
        ("teams_users_list", r#"{"prefix":[]}"#),
        (
            "teams_presence_set",
            r#"{"present_as":"Bulti","availability":"Busy","activity":"Presenting"}"#,
        ),
        (
            "teams_presence_set",
            r#"{"present_as":"Bulti","availability":"Available","duration_mins":4}"#,
        ),
        (
            "teams_presence_set",
            r#"{"present_as":"Bulti","availability":"Available","duration_mins":241}"#,
        ),
        ("teams_presence_get", r#"{"user_ids":[]}"#),
        ("teams_presence_get", r#"{"user_ids":[1]}"#),
        (
            "teams_chat_invite",
            r#"{"present_as":"Bulti","chat_id":"chat","user_id":"user","owner":"true"}"#,
        ),
        (
            "teams_chat_create",
            r#"{"present_as":"Bulti","user_ids":[]}"#,
        ),
        ("teams_attachments_list", r#"{"descending":1}"#),
        (
            "teams_attachment_get",
            r#"{"source_id":"a","out_dir":"/host"}"#,
        ),
        ("teams_attachment_get", r#"{"source_id":"attachment:"}"#),
        (
            "teams_context_set",
            r#"{"tenant":"a","present_as":"Bulti","boundary":false}"#,
        ),
        ("teams_context_show", r#"{"pile":"/host"}"#),
        ("teams_auth_status", r#"{"key":"secret"}"#),
        (
            "teams_auth_set",
            r#"{"tenant":"a","client_id":"c","user_id":"u","scopes":"s","client_secret":"plaintext"}"#,
        ),
        (
            "teams_auth_set",
            r#"{"tenant":"a","client_id":"c","user_id":"u","scopes":"s","client_secret_version":"@-"}"#,
        ),
        (
            "teams_auth_set",
            r#"{"tenant":"a","client_id":"c","user_id":"u","scopes":"s"}"#,
        ),
    ] {
        let mut output = Vec::new();
        let error = faculty
            .call(
                tool,
                Bytes::from(raw.as_bytes().to_vec()),
                &mut Out::new(&mut |part| {
                    output.push(part);
                    Ok(())
                }),
            )
            .unwrap_err();
        assert!(error.is::<InvalidArguments>(), "{tool}: {error:#}");
        assert!(output.is_empty());
    }
    assert!(!pile.exists());
    let operations = Teams::new(pile.clone(), None);
    assert!(operations
        .presence_set("Bulti", PresenceAvailability::Available, None, 1, None)
        .is_err());
    assert!(!pile.exists());
}

#[test]
fn output_failure_after_context_commit_does_not_erase_the_receipt() {
    let fixture = Fixture::new();
    let error = fixture
        .mcp()
        .call(
            "teams_context_set",
            Bytes::from(
                serde_json::to_vec(&json!({
                    "tenant":TENANT,"present_as":"Bulti","boundary":"Durable before delivery",
                }))
                .unwrap(),
            ),
            &mut Out::new(&mut |_| bail!("synthetic emitter failure")),
        )
        .unwrap_err();
    assert!(error.to_string().contains("synthetic emitter"));
    assert_eq!(
        fixture
            .operations()
            .context_show()
            .unwrap()
            .boundary
            .as_deref(),
        Some("Durable before delivery")
    );
}

#[test]
fn mcp_does_not_use_ambient_tenant_or_persona() {
    if std::env::var_os("FACULTIES_TEAMS_AMBIENT_CHILD").is_none() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        clean_child(&mut command);
        let output = command
            .args([
                "--exact",
                "mcp_does_not_use_ambient_tenant_or_persona",
                "--nocapture",
            ])
            .env("FACULTIES_TEAMS_AMBIENT_CHILD", "1")
            .env("TEAMS_TENANT", TENANT)
            .env("PERSONA", "Bulti")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    let fixture = Fixture::new();
    for tenant in [TENANT, "another.example"] {
        let (fragment, _) = page(tenant, vec![message("chat", "m", 10.0, tenant)], 1, vec![]);
        fixture.publish(fragment);
    }
    assert!(call(&fixture.mcp(), "teams_read", json!({})).is_err());
    assert!(call(
        &fixture.mcp(),
        "teams_send",
        json!({"tenant":TENANT,"chat_id":"chat","text":"literal"})
    )
    .unwrap_err()
    .is::<InvalidArguments>());
    assert!(call(&fixture.mcp(), "teams_read", json!({"tenant":TENANT}))
        .unwrap()
        .contains(TENANT));
}
