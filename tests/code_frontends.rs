//! One fixture, three surfaces: the Rust operations, the CLI grammar, and the
//! MCP adapter must answer the same question the same way.
//!
//! Env hygiene is mandatory and not decoration. On 2026-09-13 inherited live
//! descriptors caused 226 unrelated fixture failures, so every ambient
//! collection override, key, pile and endpoint is removed before a fixture runs.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anybytes::Bytes;
use clap::Parser;
use faculties::code::operations::{Code, Filter, IngestOptions};
use faculties::code::{cli, mcp};
use faculties::mcp::Faculty;
use faculties::out::{Out, Part};
use faculties::storage::initialize_signer;

const SOURCE: &str = r#"//! A fixture module.
use cubecl::wgpu::WgpuRuntime;

/// One integration step of the force-directed layout, on GPU.
pub fn force_step_kernel(n: u8) -> u8 {
    n
}
"#;

struct Fixture {
    _directory: tempfile::TempDir,
    repo: PathBuf,
    pile: PathBuf,
    key: PathBuf,
}

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?} failed");
}

impl Fixture {
    fn new() -> Self {
        // Ambient deployment state must never reach a fixture.
        for variable in [
            "DRIVE_ENDPOINT",
            "DRIVE_KEY",
            "TRIBLESPACE_COLLECTION_CODE",
            "TRIBLESPACE_KEY",
            "PILE",
        ] {
            std::env::remove_var(variable);
        }
        std::env::set_var("PERSONA", "ambient-not-a-target");

        let directory = tempfile::tempdir().unwrap();
        let repo = directory.path().join("fixture-repo");
        fs::create_dir_all(repo.join("src")).unwrap();
        fs::write(repo.join("src/lattice.rs"), SOURCE).unwrap();
        git(&repo, &["init", "--quiet"]);
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "--quiet", "-m", "fixture"]);

        let pile = directory.path().join("code.pile");
        let key = directory.path().join("code.key");
        fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();

        let fixture = Self {
            _directory: directory,
            repo,
            pile,
            key,
        };
        fixture
            .operations()
            .ingest(&[fixture.repo.clone()], &IngestOptions::default())
            .unwrap();
        fixture
    }

    fn operations(&self) -> Code {
        Code::new(self.pile.clone(), Some(self.key.clone()))
    }

    fn adapter(&self) -> mcp::Code {
        mcp::Code::new(self.pile.clone(), Some(self.key.clone()))
    }

    fn cli(&self, args: &[&str]) -> cli::Cli {
        cli::Cli::try_parse_from(
            [
                "code".into(),
                "--pile".into(),
                self.pile.as_os_str().to_owned(),
                "--key".into(),
                self.key.as_os_str().to_owned(),
            ]
            .into_iter()
            .chain(args.iter().map(std::ffi::OsString::from)),
        )
        .expect("parse CLI arguments")
    }
}

fn render_to_string(render: impl FnOnce(&mut Out<'_>) -> anyhow::Result<()>) -> String {
    let mut text = String::new();
    {
        let mut emit = |part: Part| {
            if let Part::Text { text: part } = part {
                text.push_str(&part);
            }
            Ok(())
        };
        let mut out = Out::new(&mut emit);
        render(&mut out).unwrap();
    }
    text
}

#[test]
fn the_cli_and_the_rust_api_answer_the_same_question() {
    let fixture = Fixture::new();
    let native = fixture
        .operations()
        .find("force_step_kernel", &Filter::default())
        .unwrap();
    assert_eq!(native.hits.len(), 1);

    let rendered =
        render_to_string(|out| cli::execute(fixture.cli(&["find", "force_step_kernel"]), out));
    assert!(rendered.contains("force_step_kernel"), "{rendered}");
    assert!(rendered.contains("src/lattice.rs"), "{rendered}");
    // Every read carries the revisions it was true at.
    assert!(rendered.contains("searched"), "{rendered}");
    assert!(rendered.contains("extractor rust-syn-v1"), "{rendered}");
}

#[test]
fn the_mcp_adapter_answers_through_the_same_operations() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter();
    let rendered = render_to_string(|out| {
        adapter.call(
            "code_find",
            Bytes::from_source(br#"{"name":"force_step_kernel"}"#.to_vec()),
            out,
        )
    });
    assert!(rendered.contains("src/lattice.rs"), "{rendered}");
    assert!(rendered.contains("searched"), "{rendered}");
}

#[test]
fn an_absence_is_the_same_verdict_on_every_surface() {
    let fixture = Fixture::new();
    let cli_text =
        render_to_string(|out| cli::execute(fixture.cli(&["find", "LearnerBuilder"]), out));
    let adapter = fixture.adapter();
    let mcp_text = render_to_string(|out| {
        adapter.call(
            "code_find",
            Bytes::from_source(br#"{"name":"LearnerBuilder"}"#.to_vec()),
            out,
        )
    });
    assert!(cli_text.contains("ABSENT"), "{cli_text}");
    assert_eq!(cli_text, mcp_text);
}

#[test]
fn an_mcp_tool_refuses_an_argument_it_does_not_model() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter();
    let mut sink = |_: Part| Ok(());
    let mut out = Out::new(&mut sink);
    let error = adapter
        .call(
            "code_find",
            Bytes::from_source(br#"{"name":"f","nonsense":true}"#.to_vec()),
            &mut out,
        )
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("nonsense"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn the_adapter_declares_one_tool_per_verb() {
    let fixture = Fixture::new();
    assert_eq!(fixture.adapter().tools().len(), 9);
}
