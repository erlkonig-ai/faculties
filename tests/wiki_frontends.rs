use std::fs;
use std::path::PathBuf;
use std::process::Command;

use anybytes::Bytes;
use faculties::mcp::{Faculty, InvalidArguments, Server};
use faculties::out::{Out, Part};
use faculties::storage::initialize_signer;
use faculties::wiki::{cli, mcp, ListOptions, Wiki};
use serde_json::{json, Value};
use triblespace::core::repo::SnapshotSource;

struct Fixture {
    directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("wiki.pile");
        let key = directory.path().join("explicit.key");
        fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        Self {
            directory,
            pile,
            key,
        }
    }

    fn wiki(&self) -> Wiki {
        Wiki::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn mcp(&self) -> mcp::Wiki {
        mcp::Wiki::new(self.pile.clone(), Some(self.key.clone()))
    }

    fn published_revisions(&self) -> usize {
        let signer = faculties::storage::load_signer(&self.pile, Some(&self.key)).unwrap();
        let mut pile = faculties::storage::open_pile_strict(&self.pile).unwrap();
        let collection = faculties::collection_names::open_configured(
            &mut pile,
            faculties::schemas::wiki::DEFAULT_SCOPE_ID,
            signer.verifying_key(),
        )
        .unwrap();
        let count = collection
            .admitted(&pile.snapshot().unwrap())
            .unwrap()
            .len();
        pile.close().unwrap();
        count
    }

    fn cli(&self, arguments: &[&str]) -> Vec<Part> {
        let mut argv = vec![
            "wiki".to_owned(),
            "--pile".into(),
            self.pile.to_str().unwrap().into(),
            "--key".into(),
            self.key.to_str().unwrap().into(),
        ];
        argv.extend(arguments.iter().map(|value| (*value).to_owned()));
        let mut parts = Vec::new();
        cli::execute_from(
            argv,
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
        parts
    }

    fn call(&self, name: &str, arguments: Value) -> Vec<Part> {
        let mut parts = Vec::new();
        self.mcp()
            .call(
                name,
                serde_json::to_vec(&arguments).unwrap().into(),
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

fn revision(parts: &[Part]) -> String {
    text(parts)
        .trim()
        .strip_prefix("revision ")
        .unwrap()
        .to_owned()
}

#[test]
fn library_cli_and_mcp_agree_on_frontier_exact_and_raw_exports() {
    let fixture = Fixture::new();
    let wiki = fixture.wiki();
    let first = wiki.create("page", "first draft\n", &[], true).unwrap();
    let first = format!("{first:x}");
    let head = wiki
        .edit(
            &first,
            Some("Grüße, second draft. No final newline."),
            None,
            &[],
            true,
        )
        .unwrap();
    let head = format!("{head:x}");
    for (exact, expected) in [
        (false, "Grüße, second draft. No final newline."),
        (true, "first draft\n"),
    ] {
        let mut arguments = vec!["show", first.as_str()];
        if exact {
            arguments.push("--exact");
        }
        let cli = fixture.cli(&arguments);
        let mcp = fixture.call("wiki_show", json!({"id":first,"exact":exact}));
        assert_eq!(cli, mcp);
        assert_eq!(text(&cli), wiki.show(&first, exact).unwrap());
        assert!(text(&cli).ends_with(expected));

        arguments[0] = "export";
        let cli = fixture.cli(&arguments);
        let mcp = fixture.call("wiki_export", json!({"id":first,"exact":exact}));
        assert_eq!(cli, mcp);
        let [Part::Blob {
            bytes,
            mime_type,
            uri,
        }] = cli.as_slice()
        else {
            panic!("raw export must be a blob")
        };
        assert_eq!(bytes.as_ref(), expected.as_bytes());
        assert_eq!(mime_type, "text/plain; charset=utf-8");
        assert_eq!(uri, &format!("wiki:{}", if exact { &first } else { &head }));
    }
    assert_eq!(
        fixture.cli(&["history", &first]),
        fixture.call("wiki_history", json!({"id":first}))
    );
    assert_eq!(
        fixture.cli(&["diff", &first]),
        fixture.call("wiki_diff", json!({"id":first}))
    );
}

#[test]
fn write_receipts_are_returned_after_publication_and_tag_noops_are_visible() {
    let fixture = Fixture::new();
    let first = revision(&fixture.call(
        "wiki_create",
        json!({"title":"resident","content":"ordinary text","tags":["blue"]}),
    ));
    assert!(fixture
        .wiki()
        .show(&first, true)
        .unwrap()
        .contains("ordinary text"));
    let next = revision(&fixture.call("wiki_edit", json!({"id":first,"content":"updated text"})));
    assert!(fixture.wiki().show(&first, false).unwrap().contains(&next));
    let no_op = fixture.call("wiki_tag_add", json!({"id":first,"name":"blue"}));
    assert_eq!(text(&no_op), "already tagged #blue\n");
    let archived = revision(&fixture.call("wiki_archive", json!({"id":first})));
    assert!(fixture
        .wiki()
        .list(&ListOptions::default())
        .unwrap()
        .is_empty());
    fixture.call("wiki_restore", json!({"id":archived}));
    assert!(fixture
        .wiki()
        .list(&ListOptions::default())
        .unwrap()
        .contains("resident"));
    fixture.call("wiki_revert", json!({"id":first,"to":1}));
    assert_eq!(
        fixture.wiki().export(&first, false).unwrap().bytes.as_ref(),
        b"ordinary text"
    );
}

#[test]
fn mcp_strings_are_literal_while_cli_owns_file_expansion() {
    let fixture = Fixture::new();
    let title_path = fixture.directory.path().join("title.txt");
    let content_path = fixture.directory.path().join("content.typ");
    fs::write(&title_path, "expanded title").unwrap();
    fs::write(&content_path, "expanded content").unwrap();
    let title_argument = format!("@{}", title_path.display());
    let content_argument = format!("@{}", content_path.display());
    let cli_id = revision(&fixture.cli(&["create", &title_argument, &content_argument]));
    assert!(fixture
        .wiki()
        .show(&cli_id, true)
        .unwrap()
        .starts_with("# expanded title\n"));
    let mcp_id = revision(&fixture.call(
        "wiki_create",
        json!({"title":title_argument,"content":"resident content"}),
    ));
    assert!(fixture
        .wiki()
        .show(&mcp_id, true)
        .unwrap()
        .starts_with(&format!("# {title_argument}\n")));
    assert_eq!(
        fixture.wiki().export(&mcp_id, true).unwrap().bytes.as_ref(),
        b"resident content"
    );

    // The same @path content that the CLI expanded remains the literal stored
    // body in MCP. Syntax acceptance is separate from host-file interpretation.
    let literal_id = revision(&fixture.call(
        "wiki_create",
        json!({"title":"literal path text","content":content_argument}),
    ));
    assert_eq!(
        fixture
            .wiki()
            .export(&literal_id, true)
            .unwrap()
            .bytes
            .as_ref(),
        content_argument.as_bytes(),
    );

    // The reference resolver treats @path as literal malformed input, without
    // expanding the file (which contains a valid reference it would resolve).
    let refs = fixture.directory.path().join("refs.txt");
    fs::write(&refs, format!("wiki:{}", &mcp_id[..12])).unwrap();
    let input = format!("@{}", refs.display());
    let result = fixture.call("wiki_fix_truncated", json!({"input":input}));
    assert!(text(&result).contains(&format!("FAILED: {input}")));
    assert!(!text(&result).contains(&format!("wiki:{mcp_id}")));
}

#[test]
fn mcp_rejects_host_configuration_unknown_fields_duplicates_and_wrong_types() {
    let fixture = Fixture::new();
    let faculty = fixture.mcp();
    for (tool, args) in [
        (
            "wiki_create",
            r#"{"title":"x","content":"x","pile":"elsewhere"}"#,
        ),
        (
            "wiki_create",
            r#"{"title":"x","content":"x","persona":"other"}"#,
        ),
        (
            "wiki_create",
            r#"{"title":"x","content":"x","title":"duplicate"}"#,
        ),
        ("wiki_edit", r#"{"id":"1","content":3}"#),
        ("wiki_check", r#"{"compile":true}"#),
        ("wiki_export", r#"{"id":"1","path":"host.typ"}"#),
        ("wiki_revert", r#"{"id":"1","to":0}"#),
        ("wiki_diff", r#"{"id":"1","from":0}"#),
        (
            "wiki_import",
            r#"{"documents":[{"title":"x","content":"x","path":"host.typ"}]}"#,
        ),
    ] {
        let mut parts = Vec::new();
        let error = faculty
            .call(
                tool,
                Bytes::from(args.as_bytes().to_vec()),
                &mut Out::new(&mut |part| {
                    parts.push(part);
                    Ok(())
                }),
            )
            .unwrap_err();
        assert!(
            error.downcast_ref::<InvalidArguments>().is_some(),
            "{tool}: {error:#}"
        );
        assert!(parts.is_empty());
    }
    assert!(fixture
        .wiki()
        .list(&ListOptions::default())
        .unwrap()
        .is_empty());
}

#[test]
fn resident_import_is_one_publication_and_keeps_titles_out_of_host_paths() {
    let fixture = Fixture::new();
    let before = fixture.published_revisions();
    let ids = text(&fixture.call(
        "wiki_import",
        json!({"documents":[
        {"title":"fallback","content":"= Heading\nfirst imported text"},
        {"title":"@/no/local/file","content":"second imported text"}
    ],"tags":["imported"]}),
    ));
    assert_eq!(ids.lines().count(), 2);
    assert_eq!(
        fixture.published_revisions(),
        before + 1,
        "multiple documents are published in one source COMMIT"
    );
    let listing = fixture.wiki().list(&ListOptions::default()).unwrap();
    assert!(listing.contains("Heading"));
    assert!(listing.contains("@/no/local/file"));
    assert!(listing.contains("imported"));

    let committed = fixture.published_revisions();
    let mut output = Vec::new();
    let result = fixture.mcp().call(
        "wiki_import",
        serde_json::to_vec(&json!({"documents": [
            {"title": "must not be published", "content": "valid first document"},
            {"title": "invalid second document", "content": "#let broken ="}
        ]}))
        .unwrap()
        .into(),
        &mut Out::new(&mut |part| {
            output.push(part);
            Ok(())
        }),
    );
    assert!(
        result.is_err(),
        "invalid later document must abort the import"
    );
    assert!(output.is_empty(), "no premature success receipts");
    assert_eq!(fixture.published_revisions(), committed);
    assert_eq!(
        fixture.wiki().list(&ListOptions::default()).unwrap(),
        listing
    );
}

#[test]
fn executable_export_stays_raw_while_show_uses_the_configured_sensory_route() {
    let fixture = Fixture::new();
    let content = "Exact original bytes.\nNo added newline";
    let id = format!(
        "{:x}",
        fixture
            .wiki()
            .create("export", content, &[], false)
            .unwrap()
    );
    for verb in ["export", "show"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_wiki"));
        command
            .arg("--pile")
            .arg(&fixture.pile)
            .arg("--key")
            .arg(&fixture.key)
            .args([verb, &id, "--exact"])
            .env(
                "DRIVE_ENDPOINT",
                "invalid-endpoint-must-only-affect-perception",
            );
        for name in [
            "DRIVE_KEY",
            "TRIBLESPACE_PEERS",
            "TRIBLESPACE_COLLECTION_WIKI",
            "TRIBLESPACE_COLLECTION_FILES",
        ] {
            command.env_remove(name);
        }
        let output = command.output().unwrap();
        if verb == "export" {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, content.as_bytes());
        } else {
            assert!(!output.status.success());
            assert!(
                output.stdout.is_empty(),
                "failed perception must not fall back to stdout"
            );
            assert!(String::from_utf8_lossy(&output.stderr).contains("Drive"));
        }
    }
}

#[test]
fn mcp_tools_are_explicit_finite_and_have_valid_independent_schemas() {
    let fixture = Fixture::new();
    let faculty = fixture.mcp();
    assert_eq!(faculty.tools().len(), 22);
    for tool in faculty.tools() {
        let schema: Value = serde_json::from_str(tool.input_schema).unwrap();
        assert_eq!(schema["additionalProperties"], false);
        assert!(schema["properties"].get("pile").is_none());
        assert!(schema["properties"].get("key").is_none());
        assert!(schema["properties"].get("persona").is_none());
    }
    let registered: [&dyn Faculty; 1] = [&faculty];
    Server::new(&registered).unwrap();
}
