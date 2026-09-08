//! Resident inputs and CLI/MCP parity; no model/network execution is needed.
use std::fs;
use std::io::{Cursor, Write};
use std::path::PathBuf;

use anybytes::Bytes;
use anyhow::{anyhow, Result};
use base64::Engine as _;
use clap::Parser;
use faculties::collection_names::open_configured;
use faculties::mcp::{Faculty, InvalidArguments};
use faculties::out::{Out, Part};
use faculties::posture::{
    self, cli, mcp, DocumentInput, FileOutcome, ListOptions, Posture, VocabularyState,
};
use faculties::schemas::posture::{
    modality, DEFAULT_POLICY_SCOPE_ID, DEFAULT_SCAN_SCOPE_ID, DOC_UNSUPPORTED, OUTCOME_EXAMINED,
    OUTCOME_PARSE_FAILED,
};
use faculties::storage::{initialize_signer, load_signer, open_pile_strict};
use triblespace::prelude::*;

struct Fixture {
    _directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("posture.pile");
        let key = directory.path().join("posture.key");
        fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        Self {
            _directory: directory,
            pile,
            key,
        }
    }
    fn operations(&self) -> Posture {
        Posture::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn adapter(&self) -> mcp::Posture {
        mcp::Posture::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn commits(&self, scope: Id) -> usize {
        let signer = load_signer(&self.pile, Some(&self.key)).unwrap();
        let mut pile = open_pile_strict(&self.pile).unwrap();
        let collection = open_configured(&mut pile, scope, signer.verifying_key()).unwrap();
        let count = collection
            .admitted(&pile.snapshot().unwrap())
            .unwrap()
            .len();
        pile.close().unwrap();
        count
    }
    fn cli(&self, args: &[&str]) -> cli::Cli {
        cli::Cli::try_parse_from(
            [
                "posture".into(),
                "--pile".into(),
                self.pile.as_os_str().to_owned(),
                "--key".into(),
                self.key.as_os_str().to_owned(),
            ]
            .into_iter()
            .chain(args.iter().map(std::ffi::OsString::from)),
        )
        .unwrap()
    }
}

fn office() -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file(
        "docProps/core.xml",
        zip::write::SimpleFileOptions::default(),
    )
    .unwrap();
    zip.write_all(b"<cp:coreProperties xmlns:cp='cp' xmlns:dc='dc'><dc:creator>Fixture Author</dc:creator></cp:coreProperties>").unwrap();
    zip.finish().unwrap().into_inner()
}
fn collect(operation: impl FnOnce(&mut Out<'_>) -> Result<()>) -> Result<String> {
    let mut text = String::new();
    operation(&mut Out::new(&mut |part| {
        let Part::Text { text: part } = part else {
            panic!("Posture emits text");
        };
        text.push_str(&part);
        Ok(())
    }))?;
    Ok(text)
}
fn json(value: serde_json::Value) -> Bytes {
    Bytes::from(serde_json::to_vec(&value).unwrap())
}

#[test]
fn resident_scan_is_model_free_and_dry_run_needs_no_store() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("never-opened.pile");
    let posture = Posture::new(missing.clone(), None);
    let bytes = office();
    let report = posture
        .scan(
            "@-/literal-label",
            &[
                DocumentInput {
                    name: "/not/an/input/path.bin",
                    bytes: &bytes,
                },
                DocumentInput {
                    name: "notes.txt",
                    bytes: b"unsupported fixture",
                },
                DocumentInput {
                    name: "broken.pdf",
                    bytes: b"%PDF malformed fixture",
                },
            ],
            true,
        )
        .unwrap();
    assert!(report.scan_id.is_none());
    assert!(!missing.exists());
    assert!(matches!(report.files[0].outcome, FileOutcome::Examined));
    assert_eq!(report.files[0].findings[0].value, "Fixture Author");
    assert!(matches!(report.files[1].outcome, FileOutcome::Unsupported));
    assert!(matches!(
        report.files[2].outcome,
        FileOutcome::ParseFailed(_)
    ));
    assert!(report.checked.contains(&modality::PDF_REDACTION_RECT));
    assert!(!report.unchecked.is_empty());
    let text = collect(|out| posture::presentation::scan(&report, out)).unwrap();
    assert!(text.contains("1 unsupported, 1 failed to parse"));
    assert!(text.contains("NOT CHECKED"));
}

#[test]
fn resident_and_path_scans_share_content_located_findings_and_coverage() {
    let fixture = Fixture::new();
    let posture = fixture.operations();
    let bytes = office();
    let input = fixture._directory.path().join("opaque.dat");
    fs::write(&input, &bytes).unwrap();
    let resident = posture
        .scan(
            "resident batch",
            &[
                DocumentInput {
                    name: "@-/different-name.bin",
                    bytes: &bytes,
                },
                DocumentInput {
                    name: "unsupported.bin",
                    bytes: b"plain text",
                },
                DocumentInput {
                    name: "broken.pdf",
                    bytes: b"%PDF malformed fixture",
                },
            ],
            false,
        )
        .unwrap();
    let local = posture.scan_path(&input, false).unwrap();
    assert_eq!(fixture.commits(DEFAULT_SCAN_SCOPE_ID), 2);
    assert_eq!(
        resident.files[0].findings[0].location,
        local.files[0].findings[0].location
    );
    let resident_list = posture
        .list(ListOptions {
            scan: resident.scan_id,
            ..Default::default()
        })
        .unwrap();
    let local_list = posture
        .list(ListOptions {
            scan: local.scan_id,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        resident_list.groups[0].examples[0].id,
        local_list.groups[0].examples[0].id
    );
    assert_ne!(resident.scan_id, local.scan_id);
    assert_ne!(resident.files[0].path, local.files[0].path);
    let coverage = posture.coverage(resident.scan_id).unwrap().unwrap();
    assert_eq!(coverage.outcomes.get(&OUTCOME_EXAMINED), Some(&1));
    assert_eq!(coverage.outcomes.get(&DOC_UNSUPPORTED), Some(&1));
    assert_eq!(coverage.outcomes.get(&OUTCOME_PARSE_FAILED), Some(&1));
    assert_eq!(posture.scans().unwrap().len(), 2);
}

#[test]
fn native_mcp_names_are_literal_and_read_frontends_agree() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter();
    let sentinel = fixture._directory.path().join("untouched.bin");
    fs::write(&sentinel, b"sentinel is not a document input").unwrap();
    let output = collect(|out| {
        adapter.call(
            "posture_scan",
            json(serde_json::json!({
                "label": "@-",
                "documents": [{
                    "name": sentinel.to_str().unwrap(),
                    "data_base64": base64::engine::general_purpose::STANDARD.encode(office()),
                }],
            })),
            out,
        )
    })
    .unwrap();
    assert!(output.contains("Fixture Author"));
    assert_eq!(
        fs::read(&sentinel).unwrap(),
        b"sentinel is not a document input"
    );
    assert_eq!(fixture.commits(DEFAULT_SCAN_SCOPE_ID), 1);
    let scan = fixture.operations().scans().unwrap().remove(0).id;
    let scan = format!("{scan:x}");
    for (tool, args, cli_args) in [
        (
            "posture_list",
            serde_json::json!({"scan": scan, "examples": 2}),
            vec!["list", "--scan", &scan, "--examples", "2", "--ids"],
        ),
        (
            "posture_coverage",
            serde_json::json!({"scan": scan}),
            vec!["coverage", &scan],
        ),
        ("posture_scans", serde_json::json!({}), vec!["scans"]),
    ] {
        let mcp = collect(|out| adapter.call(tool, json(args), out)).unwrap();
        let cli = collect(|out| cli::execute(fixture.cli(&cli_args), out)).unwrap();
        assert_eq!(mcp, cli, "{tool}");
    }
}

#[test]
fn vocabulary_receipts_are_typed_idempotent_and_mcp_prose_is_literal() {
    let fixture = Fixture::new();
    let posture = fixture.operations();
    let first = posture
        .vocab_add("@-", " Public-Release ", Some("@/literal-rationale"))
        .unwrap();
    assert!(first.published);
    assert!(first.revision.is_some());
    let again = posture
        .vocab_add("@-", "public-release", Some("@/literal-rationale"))
        .unwrap();
    assert!(!again.published);
    assert_eq!(first.member, again.member);
    assert_eq!(fixture.commits(DEFAULT_POLICY_SCOPE_ID), 1);
    let response = collect(|out| {
        fixture.adapter().call(
            "posture_vocab_add",
            json(serde_json::json!({
                "term": "@/literal-protected-term", "channel": "public-release", "why": "@-",
            })),
            out,
        )
    })
    .unwrap();
    assert!(response.contains("@/literal-protected-term"));
    let channels = posture.vocab_list(Some("public-release")).unwrap();
    let VocabularyState::Ready { terms, .. } = &channels[0].state else {
        panic!("one policy");
    };
    assert!(terms.contains(&("@-".into(), "@/literal-rationale".into())));
    assert!(terms.contains(&("@/literal-protected-term".into(), "@-".into())));
    let mcp = collect(|out| {
        fixture.adapter().call(
            "posture_vocab_list",
            json(serde_json::json!({"channel":"public-release"})),
            out,
        )
    })
    .unwrap();
    let cli = collect(|out| {
        cli::execute(
            fixture.cli(&["vocab", "list", "--channel", "public-release"]),
            out,
        )
    })
    .unwrap();
    assert_eq!(mcp, cli);
}

#[test]
fn mcp_rejects_bad_arguments_before_any_store_access_or_partial_batch() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.pile");
    let adapter = mcp::Posture::new(missing.clone(), None);
    let requests = [
        (
            "posture_scan",
            r#"{"label":"x","documents":[{"name":"x","data_base64":"","path":"/host"}]}"#,
        ),
        (
            "posture_scan",
            r#"{"label":"x","documents":[{"name":"ok","data_base64":""},{"name":"bad","data_base64":"%%%"}]}"#,
        ),
        (
            "posture_scan",
            r#"{"label":"x","label":"duplicate","documents":[]}"#,
        ),
        (
            "posture_scan",
            r#"{"label":"x","documents":[{"name":"same","data_base64":""},{"name":"same","data_base64":""}]}"#,
        ),
        (
            "posture_semantic",
            r#"{"documents":[{"name":"x","text":"literal","path":"/host"}],"channel":"x"}"#,
        ),
        ("posture_exemplar", r#"{"text":"too short","channel":"x"}"#),
        ("posture_vocab_add", r#"{"term":"x","channel":"  "}"#),
        ("posture_vocab_list", r#"{"channel":"x","pile":"/host"}"#),
        ("posture_list", r#"{"examples":-1}"#),
        ("posture_coverage", r#"{"scan":"not-an-id"}"#),
        ("posture_scans", r#"{"repo":"/host"}"#),
    ];
    for (tool, arguments) in requests {
        let mut emitted = 0;
        let error = adapter
            .call(
                tool,
                Bytes::from(arguments.as_bytes().to_vec()),
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
        assert!(!missing.exists());
    }
}

#[test]
fn output_failure_does_not_retry_a_scan_publication() {
    let fixture = Fixture::new();
    let mut emissions = 0;
    let error = fixture.adapter().call("posture_scan", json(serde_json::json!({
        "label":"one publication",
        "documents":[{"name":"opaque.bin","data_base64":base64::engine::general_purpose::STANDARD.encode(office())}],
    })), &mut Out::new(&mut |_| {
        emissions += 1;
        Err(anyhow!("emitter closed"))
    })).unwrap_err();
    assert!(error.to_string().contains("emitter closed"));
    assert_eq!(emissions, 1);
    assert_eq!(fixture.commits(DEFAULT_SCAN_SCOPE_ID), 1);
    assert_eq!(fixture.operations().scans().unwrap().len(), 1);
}

#[test]
fn discovery_exposes_resident_tools_not_host_git_hooks_or_model_side_effects() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("no-store.pile");
    let adapter = mcp::Posture::new(missing.clone(), None);
    let names = adapter
        .tools()
        .iter()
        .map(|tool| tool.name)
        .collect::<Vec<_>>();
    assert_eq!(names.len(), 8);
    for expected in [
        "posture_scan",
        "posture_list",
        "posture_coverage",
        "posture_scans",
        "posture_vocab_add",
        "posture_vocab_list",
        "posture_exemplar",
        "posture_semantic",
    ] {
        assert!(names.contains(&expected));
    }
    for tool in adapter.tools() {
        let schema: serde_json::Value = serde_json::from_str(tool.input_schema).unwrap();
        for forbidden in ["pile", "key", "path", "repo", "command"] {
            assert!(
                schema["properties"].get(forbidden).is_none(),
                "{} exposes {forbidden}",
                tool.name
            );
        }
    }
    assert!(!missing.exists());
}

#[cfg(not(feature = "local-embed"))]
#[test]
fn semantic_unavailability_is_explicit_without_opening_a_model_or_store() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("no-store.pile");
    let posture = Posture::new(missing.clone(), None);
    let error = posture.semantic(&[], "public-release", 0.55).unwrap_err();
    assert!(error.to_string().contains("semantic tier is unavailable"));
    assert!(!missing.exists());
}
