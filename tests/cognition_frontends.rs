use anybytes::Bytes;
use clap::Parser;
use faculties::cognition::{self, cli, mcp, Cognition};
use faculties::mcp::{Faculty, InvalidArguments, Server};
use faculties::out::{Out, Part};
use std::fs;
use std::path::PathBuf;
use triblespace::core::collection::CollectionStoreExt;
use triblespace::prelude::*;

struct Fixture {
    _directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("cognition.pile");
        let key = directory.path().join("explicit.key");
        fs::File::create(&pile).unwrap();
        faculties::storage::initialize_signer(&pile, Some(&key)).unwrap();
        Self {
            _directory: directory,
            pile,
            key,
        }
    }
    fn cognition(&self) -> Cognition {
        Cognition::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn adapter(&self) -> mcp::Cognition {
        mcp::Cognition::new(self.pile.clone(), Some(self.key.clone()))
    }
}

#[test]
fn direct_cli_and_mcp_checks_agree_for_empty_and_authored_collections() {
    let fixture = Fixture::new();
    for populated in [false, true] {
        if populated {
            let event = cognition::reason_fragment(
                None,
                None,
                "a resident typed reason",
                None,
                faculties::clock::point(hifitime::Epoch::from_tai_seconds(42.0)).unwrap(),
            );
            cognition::publish_event(&fixture.pile, Some(&fixture.key), event).unwrap();
        }
        let report = fixture.cognition().check().unwrap();
        assert_eq!(report.facts == 0, !populated);
        let cli = cli::Cli::try_parse_from([
            "cognition",
            "--pile",
            fixture.pile.to_str().unwrap(),
            "--key",
            fixture.key.to_str().unwrap(),
            "check",
        ])
        .unwrap();
        let mut cli_parts = Vec::new();
        cli::execute(
            cli,
            &mut Out::new(&mut |part| {
                cli_parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
        let mut mcp_parts = Vec::new();
        fixture
            .adapter()
            .call(
                "cognition_check",
                Bytes::from("{}"),
                &mut Out::new(&mut |part| {
                    mcp_parts.push(part);
                    Ok(())
                }),
            )
            .unwrap();
        assert_eq!(cli_parts, mcp_parts);
        assert_eq!(
            cli_parts,
            vec![Part::Text {
                text: report.summary() + "\n"
            }]
        );
    }
}

#[test]
fn mcp_check_accepts_no_caller_config_or_synthetic_arguments() {
    let directory = tempfile::tempdir().unwrap();
    let adapter = mcp::Cognition::new(directory.path().join("absent.pile"), None);
    assert_eq!(adapter.tools().len(), 1);
    assert_eq!(adapter.tools()[0].name, "cognition_check");
    Server::new(&[&adapter]).unwrap();
    for arguments in [
        r#"{"pile":"/host/pile"}"#,
        r#"{"key":"@/host/key"}"#,
        r#"{"persona":"other"}"#,
        r#"{"argv":["check"]}"#,
        r#"{"repair":true,"repair":false}"#,
        "[]",
    ] {
        let mut emitted = 0;
        let error = adapter
            .call(
                "cognition_check",
                Bytes::from(arguments),
                &mut Out::new(&mut |_| {
                    emitted += 1;
                    Ok(())
                }),
            )
            .unwrap_err();
        assert!(
            error.downcast_ref::<InvalidArguments>().is_some(),
            "{error:#}"
        );
        assert_eq!(emitted, 0);
    }
}

#[test]
fn check_validates_known_selected_attachments_and_emits_no_false_success() {
    let fixture = Fixture::new();
    let mut omitted = Fragment::empty();
    let missing = omitted.put("not included in the published fragment".to_owned());
    let fragment = entity! { faculties::schemas::reason::reason_schema::text: missing };
    let signer = faculties::storage::load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
    let mut pile = faculties::storage::open_pile_strict(&fixture.pile).unwrap();
    let collection = faculties::collection_names::open_configured(
        &mut pile,
        faculties::schemas::cognition::DEFAULT_SCOPE_ID,
        signer.verifying_key(),
    )
    .unwrap();
    // An externally received collection may reference a locally absent payload.
    pile.commit(collection, &signer, fragment).unwrap();
    pile.close().unwrap();
    assert!(fixture.cognition().check().is_err());
    let mut emitted = 0;
    assert!(fixture
        .adapter()
        .call(
            "cognition_check",
            Bytes::from("{}"),
            &mut Out::new(&mut |_| {
                emitted += 1;
                Ok(())
            })
        )
        .is_err());
    assert_eq!(emitted, 0);
}
