use anybytes::Bytes;
use base64::Engine as _;
use clap::Parser;
use faculties::archive::{cli, mcp, Archive, ImportSource};
use faculties::mcp::{Faculty, InvalidArguments, Server};
use faculties::out::{Out, Part};
use faculties::schemas::blockdag as schema;
use faculties::storage::FactArchive;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use triblespace::core::metadata;
use triblespace::prelude::*;

struct Fixture {
    directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("archive.pile");
        let key = directory.path().join("explicit.key");
        fs::File::create(&pile).unwrap();
        faculties::storage::initialize_signer(&pile, Some(&key)).unwrap();
        Self {
            directory,
            pile,
            key,
        }
    }
    fn archive(&self) -> Archive {
        Archive::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn adapter(&self) -> mcp::Archive {
        mcp::Archive::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn call(&self, tool: &str, args: Value) -> Vec<Part> {
        let mut parts = Vec::new();
        self.adapter()
            .call(
                tool,
                serde_json::to_vec(&args).unwrap().into(),
                &mut Out::new(&mut |p| {
                    parts.push(p);
                    Ok(())
                }),
            )
            .unwrap();
        parts
    }
    fn cli(&self, args: &[&str]) -> Vec<Part> {
        let mut argv = vec![
            "archive",
            "--pile",
            self.pile.to_str().unwrap(),
            "--key",
            self.key.to_str().unwrap(),
        ];
        argv.extend_from_slice(args);
        let cli = cli::Cli::try_parse_from(argv).unwrap();
        let mut parts = Vec::new();
        cli::execute(
            cli,
            &mut Out::new(&mut |p| {
                parts.push(p);
                Ok(())
            }),
        )
        .unwrap();
        parts
    }
    fn projections(&self) -> Vec<Id> {
        let observed = pollster::block_on(faculties::archive_collection::ensure_local(
            &self.pile,
            Some(&self.key),
        ))
        .unwrap();
        let facts = observed.view::<FactArchive>().unwrap();
        find!(projection:Id,pattern!(&facts,[{?projection @ metadata::tag:&schema::source_projection::KIND}])).collect()
    }
    fn roots(&self) -> usize {
        let observed = pollster::block_on(faculties::archive_collection::ensure_local(
            &self.pile,
            Some(&self.key),
        ))
        .unwrap();
        observed
            .support()
            .commits(observed.snapshot())
            .unwrap()
            .len()
    }
}
fn text(parts: &[Part]) -> String {
    parts
        .iter()
        .map(|p| match p {
            Part::Text { text } => text.as_str(),
            _ => panic!("diagnostic text expected"),
        })
        .collect()
}
const CODE: &str = r#"{"type":"user","sessionId":"resident","uuid":"first","timestamp":"2026-03-01T15:34:01Z","message":{"role":"user","content":"quasar needle @literal"}}"#;
const CODEX: &str = concat!(
    r#"{"timestamp":"2026-08-16T08:00:00Z","type":"session_meta","payload":{"id":"resident-session","session_id":"resident-session"}}"#,
    "\n",
    r#"{"timestamp":"2026-08-16T08:01:00Z","type":"event_msg","payload":{"type":"user_message","message":"quasar needle"}}"#,
    "\n"
);
const CHATGPT: &str = r#"[{"id":"resident-chatgpt","mapping":{"node":{"id":"node","parent":null,"message":{"id":"message","author":{"role":"user"},"content":{"content_type":"text","parts":["quasar needle"]}}}}}]"#;
const WEB: &str = r#"[{"uuid":"resident-web","chat_messages":[{"uuid":"message","sender":"human","text":"quasar needle"}]}]"#;
const COPILOT: &str = r#"{"sessionId":"resident-copilot","requests":[{"requestId":"request","message":{"text":"quasar needle"},"response":[{"value":"answer"}]}]}"#;
const AGY: &str = concat!(
    r#"{"source":"USER_INPUT","content":"quasar needle","step_index":1}"#,
    "\n"
);
fn gemini(inner: &str) -> String {
    format!("<html><body><div class=\"outer-cell mdl-cell mdl-cell--12-col mdl-shadow--2dp\"><div><div class=\"header-cell\"><p>Gemini Apps<br></p></div><div class=\"content-cell mdl-cell mdl-cell--6-col mdl-typography--body-1\">{inner}</div><div class=\"content-cell mdl-cell mdl-cell--6-col mdl-typography--text-right\"></div></div></div></body></html>")
}

#[test]
fn all_seven_resident_scanners_preserve_file_projection_identity_and_bytes() {
    let html = gemini("Prompted&nbsp;quasar needle<br>18 Sept 2025, 12:02:52 CET<br><p>answer</p>");
    for (source, spelling, name, content) in [
        (ImportSource::Agy, "agy", "transcript_full.jsonl", AGY),
        (
            ImportSource::ChatGpt,
            "chatgpt",
            "conversations.json",
            CHATGPT,
        ),
        (
            ImportSource::ClaudeCode,
            "claude-code",
            "claude.jsonl",
            CODE,
        ),
        (ImportSource::ClaudeWeb, "claude-web", "web.json", WEB),
        (ImportSource::Codex, "codex", "rollout.jsonl", CODEX),
        (ImportSource::Copilot, "copilot", "copilot.json", COPILOT),
        (
            ImportSource::Gemini,
            "gemini",
            "My Activity.html",
            html.as_str(),
        ),
    ] {
        let fixture = Fixture::new();
        let path = fixture.directory.path().join(name);
        fs::write(&path, content).unwrap();
        let first = fixture.cli(&["import", path.to_str().unwrap(), "--source", spelling]);
        assert!(
            text(&first).contains("one signed COMMIT published"),
            "{spelling}"
        );
        let ids = fixture.projections();
        assert!(!ids.is_empty(), "{spelling}");
        let receipt = fixture
            .archive()
            .import(
                source,
                path.to_str().unwrap(),
                Bytes::from(content.to_owned()),
                &BTreeMap::new(),
            )
            .unwrap();
        assert!(
            receipt.commit.is_none(),
            "resident {spelling} must add no facts to its identical file projection"
        );
        assert_eq!(fixture.roots(), 1);
        assert_eq!(fixture.projections(), ids);
    }
}

#[test]
fn direct_cli_and_mcp_share_frozen_queries_and_literal_content() {
    let fixture = Fixture::new();
    fixture.call(
        "archive_import",
        json!({"source":"claude-code","source_name":"@not-a-host-path","content":CODE}),
    );
    let projection = format!("{:X}", fixture.projections()[0]);
    for (args, tool, values) in [
        (vec!["list"], "archive_list", json!({})),
        (
            vec!["show", projection.as_str()],
            "archive_show",
            json!({"id":projection}),
        ),
        (
            vec!["thread", projection.as_str()],
            "archive_thread",
            json!({"id":projection}),
        ),
        (
            vec!["search", "quasar"],
            "archive_search",
            json!({"text":"quasar"}),
        ),
        (vec!["index"], "archive_index", json!({})),
    ] {
        assert_eq!(fixture.cli(&args), fixture.call(tool, values));
    }
    assert!(text(&fixture.call("archive_show", json!({"id":projection}))).contains("@literal"));
    let query = fixture.directory.path().join("query.txt");
    fs::write(&query, "quasar").unwrap();
    let at = format!("@{}", query.display());
    assert!(!fixture.cli(&["search", &at]).is_empty());
    assert!(fixture
        .call("archive_search", json!({"text":at}))
        .is_empty());
    assert!(fixture.call("archive_list", json!({"limit":0})).is_empty());
    assert!(fixture
        .call("archive_search", json!({"text":"quasar","limit":0}))
        .is_empty());
}

#[test]
fn resident_attachments_never_fall_back_to_host_files() {
    let fixture = Fixture::new();
    let source = fixture.directory.path().join("conversations.json");
    let secret = fixture.directory.path().join("file-abc-hidden.png");
    fs::write(&secret, b"host bytes must stay unread").unwrap();
    let content = r#"[{"id":"resident-media","mapping":{"n":{"id":"n","message":{"id":"m","author":{"role":"user"},"content":{"content_type":"multimodal_text","parts":[{"content_type":"image_asset_pointer","asset_pointer":"file-service://file-abc"}]}}}}}]"#;
    let mut collected = Fragment::empty();
    let summary = faculties::archive_chatgpt::project_bytes(
        source.to_str().unwrap(),
        Bytes::from(content),
        &BTreeMap::new(),
        |p| {
            collected += p.fragment;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(summary.attachments_resolved, 0);
    let payload = Bytes::from(vec![1, 2, 3, 4]);
    let attachments = BTreeMap::from([("file-abc-resident.png".to_owned(), payload.clone())]);
    let mut resident = Fragment::empty();
    let summary = faculties::archive_chatgpt::project_bytes(
        source.to_str().unwrap(),
        Bytes::from(content),
        &attachments,
        |p| {
            resident += p.fragment;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(summary.attachments_resolved, 1);
    let handle:Inline<inlineencodings::Handle<blobencodings::RawBytes>>=find!(h:Inline<inlineencodings::Handle<blobencodings::RawBytes>>,pattern!(&resident,[{_?fact @ schema::content_fact::resolved_to:?h}])).next().unwrap();
    let reader = resident.blobs_mut().snapshot().unwrap();
    let recovered: Bytes = reader.get(handle).unwrap();
    assert_eq!(recovered, payload);
    let html = gemini(&format!(
        "Prompted&nbsp;hello<br>18 Sept 2025, 12:02:52 CET<br><p>answer</p><img src=\"{}\">",
        secret.display()
    ));
    let summary = faculties::archive_gemini::project_bytes(
        "uploaded.html",
        Bytes::from(html.clone()),
        &BTreeMap::new(),
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(summary.assets_resolved, 0);
    let supplied = BTreeMap::from([(secret.to_str().unwrap().to_owned(), payload)]);
    let summary = faculties::archive_gemini::project_bytes(
        "uploaded.html",
        Bytes::from(html),
        &supplied,
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(summary.assets_resolved, 1);
}

#[test]
fn replay_result_failure_does_not_advance_and_equal_time_peer_is_not_skipped() {
    let fixture = Fixture::new();
    let second = CODE
        .replace("\"first\"", "\"second\"")
        .replace("quasar needle", "another event");
    let content = format!("{CODE}\n{second}\n");
    fixture
        .archive()
        .import(
            ImportSource::ClaudeCode,
            "resident.jsonl",
            Bytes::from(content),
            &BTreeMap::new(),
        )
        .unwrap();
    fixture.call(
        "archive_replay_start",
        json!({"persona":"one","from":"2026-03-01T00:00:00"}),
    );
    fixture.call(
        "archive_replay_start",
        json!({"persona":"two","from":"2026-03-01T00:00:00"}),
    );
    let mut emitted = String::new();
    let error = fixture
        .archive()
        .replay(
            "one",
            1,
            false,
            &mut Out::new(&mut |part| {
                if let Part::Text { text } = part {
                    emitted.push_str(&text);
                }
                anyhow::bail!("rejected batch")
            }),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("rejected batch"));
    let first = fixture.call("archive_replay", json!({"persona":"one","limit":1}));
    let other = fixture.call("archive_replay", json!({"persona":"two","limit":1}));
    assert_eq!(first, other);
    assert!(text(&first).starts_with(&emitted));
    let second = fixture.call("archive_replay", json!({"persona":"one","limit":1}));
    assert_ne!(first, second);
    assert!(
        text(&fixture.call("archive_replay", json!({"persona":"one","limit":1})))
            .contains("nothing after the cursor")
    );
}

#[test]
fn malformed_import_is_not_published_and_output_failure_is_not_retried() {
    let fixture = Fixture::new();
    let malformed = format!("{CODE}\n{{invalid\n");
    assert!(fixture
        .archive()
        .import(
            ImportSource::ClaudeCode,
            "resident",
            Bytes::from(malformed),
            &BTreeMap::new()
        )
        .is_err());
    assert_eq!(fixture.roots(), 0);
    let adapter = fixture.adapter();
    let args = serde_json::to_vec(&json!({"source_name":"resident","content":CODE})).unwrap();
    let mut count = 0;
    assert!(adapter
        .call(
            "archive_import",
            args.into(),
            &mut Out::new(&mut |_| {
                count += 1;
                anyhow::bail!("reject receipt")
            })
        )
        .is_err());
    assert_eq!(count, 1);
    assert_eq!(fixture.roots(), 1);
    let again = fixture
        .archive()
        .import(
            ImportSource::ClaudeCode,
            "resident",
            Bytes::from(CODE),
            &BTreeMap::new(),
        )
        .unwrap();
    assert!(again.commit.is_none());
    assert_eq!(fixture.roots(), 1);
}

#[test]
fn codex_resident_import_retains_trailing_bytes_and_mcp_binary_content() {
    let fixture = Fixture::new();
    let content = format!("{CODEX}{{\"incomplete\":");
    let data = base64::engine::general_purpose::STANDARD.encode(content.as_bytes());
    let result = fixture.call(
        "archive_import",
        json!({"source":"codex","source_name":"rollout.jsonl","data":data}),
    );
    assert!(
        text(&result).contains("trailing_bytes_ignored=14"),
        "{}",
        text(&result)
    );
    assert_eq!(fixture.projections().len(), 1);
}

#[test]
fn finite_schemas_reject_config_duplicates_invalid_shapes_and_dates_before_storage() {
    let directory = tempfile::tempdir().unwrap();
    let adapter = mcp::Archive::new(directory.path().join("absent.pile"), None);
    assert_eq!(adapter.tools().len(), 9);
    Server::new(&[&adapter]).unwrap();
    for (tool, args) in [
        (
            "archive_import",
            r#"{"source_name":"x","content":"x","data":"eA=="}"#,
        ),
        (
            "archive_import",
            r#"{"source_name":"x","data":"!invalid!"}"#,
        ),
        (
            "archive_import",
            r#"{"source_name":"x","content":"x","path":"/host/file"}"#,
        ),
        (
            "archive_import",
            r#"{"source_name":"x","source_name":"y","content":"x"}"#,
        ),
        (
            "archive_import",
            r#"{"source":"gemini","source_name":"x","content":"x","attachments":[{"name":"x","data":""},{"name":"x","data":""}]}"#,
        ),
        ("archive_list", r#"{"pile":"/host/pile"}"#),
        ("archive_index", "[]"),
        ("archive_replay", r#"{"persona":"x","limit":0}"#),
        (
            "archive_replay_start",
            r#"{"persona":"x","from":"2026-02-30T00:00:00"}"#,
        ),
        ("archive_replay_stop", r#"{"persona":""}"#),
        ("archive_thread", r#"{"id":"abc","limit":0}"#),
    ] {
        let mut emitted = 0;
        let error = adapter
            .call(
                tool,
                Bytes::from(args),
                &mut Out::new(&mut |_| {
                    emitted += 1;
                    Ok(())
                }),
            )
            .unwrap_err();
        assert!(
            error.downcast_ref::<InvalidArguments>().is_some(),
            "{tool} {args}: {error:#}"
        );
        assert_eq!(emitted, 0);
    }
}
