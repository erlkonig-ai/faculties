//! Typed Decide operations and native frontend behavior over temporary local collections.
use anybytes::Bytes;
use anyhow::{anyhow, Result};
use clap::Parser;
use faculties::collection_names::open_configured;
use faculties::decide::{
    self, cli, mcp, Decide, FactorSide, ListOptions, Resolution, RESULT_BENIGN,
};
use faculties::mcp::{Faculty, InvalidArguments};
use faculties::out::{Out, Part};
use faculties::schemas::decide::DEFAULT_SCOPE_ID;
use faculties::storage::{initialize_signer, load_signer, open_pile_strict, publish_fragment};
use hifitime::Epoch;
use std::fs;
use std::path::PathBuf;
use triblespace::prelude::*;

struct Fixture {
    directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("decide.pile");
        let key = directory.path().join("decide.key");
        fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        Self {
            directory,
            pile,
            key,
        }
    }
    fn operations(&self) -> Decide {
        Decide::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn adapter(&self) -> mcp::Decide {
        mcp::Decide::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn commits(&self) -> usize {
        let signer = load_signer(&self.pile, Some(&self.key)).unwrap();
        let mut pile = open_pile_strict(&self.pile).unwrap();
        let source = open_configured(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key()).unwrap();
        let count = source.admitted(&pile.snapshot().unwrap()).unwrap().len();
        pile.close().unwrap();
        count
    }
    fn cli(&self, args: &[&str]) -> cli::Cli {
        cli::Cli::try_parse_from(
            [
                "decide".into(),
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
fn collect(operation: impl FnOnce(&mut Out<'_>) -> Result<()>) -> Result<String> {
    let mut text = String::new();
    operation(&mut Out::new(&mut |part| {
        let Part::Text { text: part } = part else {
            panic!("Decide emits text");
        };
        text.push_str(&part);
        Ok(())
    }))?;
    Ok(text)
}
fn json(value: serde_json::Value) -> Bytes {
    Bytes::from(serde_json::to_vec(&value).unwrap())
}
fn point(seconds: f64) -> decide::IntervalValue {
    let epoch = Epoch::from_unix_seconds(seconds);
    (epoch, epoch).try_to_inline().unwrap()
}

#[test]
fn direct_receipts_preserve_evidence_gates_result_and_closed_state() {
    let fixture = Fixture::new();
    let decide = fixture.operations();
    let proposed = decide
        .propose("@-", Some("@/literal-context"), None)
        .unwrap();
    let id = format!("{:x}", proposed.decision);
    assert!(decide
        .resolve(&id, "no evidence", Some(RESULT_BENIGN), false)
        .is_err());
    assert_eq!(fixture.commits(), 1);
    let pro = decide
        .factor(&id, "@/literal-pro", FactorSide::Pro)
        .unwrap();
    let con = decide.factor(&id, "@-", FactorSide::Con).unwrap();
    let receipt = decide
        .resolve(
            &id,
            "A free explanation, not a protocol token",
            Some(RESULT_BENIGN),
            false,
        )
        .unwrap();
    assert_eq!(
        receipt
            .evidence
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        [pro.factor, con.factor].into_iter().collect()
    );
    assert_eq!(receipt.result, Some(RESULT_BENIGN));
    assert!(!receipt.forced);
    assert!(receipt.predecessors.is_empty());
    let detail = decide.show(&id).unwrap();
    assert_eq!(detail.genesis.id, proposed.genesis);
    assert_eq!(detail.title, "@-");
    assert_eq!(detail.context.as_deref(), Some("@/literal-context"));
    assert!(matches!(detail.resolution, Resolution::Unique(_)));
    assert!(decide.list(ListOptions::default()).unwrap().is_empty());
    assert!(decide.factor(&id, "too late", FactorSide::Pro).is_err());
    assert!(decide.resolve(&id, "again", None, true).is_err());
    assert_eq!(fixture.commits(), 4);
}

#[test]
fn reconcile_cites_every_divergent_head_and_does_not_resolve_agreement_again() {
    for agree in [false, true] {
        let fixture = Fixture::new();
        let decide = fixture.operations();
        let proposed = decide.propose("Concurrent decision", None, None).unwrap();
        let id = format!("{:x}", proposed.decision);
        let pro = decide.factor(&id, "benefit", FactorSide::Pro).unwrap();
        let con = decide.factor(&id, "cost", FactorSide::Con).unwrap();
        let evidence = [pro.factor, con.factor];
        let (mut fragment, left) = decide::resolution_fragment(
            proposed.decision,
            "left",
            Some(RESULT_BENIGN),
            false,
            &evidence,
            &[],
            point(1.0),
        )
        .unwrap();
        let (right_fragment, right) = decide::resolution_fragment(
            proposed.decision,
            if agree { "left" } else { "right" },
            Some(RESULT_BENIGN),
            false,
            &evidence,
            &[],
            point(2.0),
        )
        .unwrap();
        fragment += right_fragment;
        publish_fragment(
            &fixture.pile,
            Some(&fixture.key),
            DEFAULT_SCOPE_ID,
            fragment,
        )
        .unwrap();
        let detail = decide.show(&id).unwrap();
        assert_eq!(detail.outcomes.len(), 2);
        assert!(decide
            .resolve(&id, "ordinary closure", None, false)
            .is_err());
        if agree {
            assert!(matches!(detail.resolution, Resolution::Agreed(_)));
            assert!(decide.reconcile(&id, "unnecessary", None, false).is_err());
            assert_eq!(fixture.commits(), 4);
        } else {
            assert!(matches!(detail.resolution, Resolution::Forked(_)));
            let rows = decide.list(ListOptions::default()).unwrap();
            assert_eq!(rows.len(), 1);
            assert!(rows[0].outcome.is_none());
            let receipt = decide
                .reconcile(&id, "explicit synthesis", None, false)
                .unwrap();
            assert_eq!(
                receipt
                    .predecessors
                    .into_iter()
                    .collect::<std::collections::BTreeSet<_>>(),
                [left, right].into_iter().collect()
            );
            assert!(matches!(
                decide.show(&id).unwrap().resolution,
                Resolution::Unique(_)
            ));
            assert_eq!(fixture.commits(), 5);
        }
    }
}

#[test]
fn mcp_literal_prose_and_cli_file_input_share_the_same_operations() {
    let fixture = Fixture::new();
    let sentinel = fixture.directory.path().join("context.txt");
    fs::write(&sentinel, "CLI reads these bytes").unwrap();
    let marker = format!("@{}", sentinel.display());
    collect(|out| {
        fixture.adapter().call(
            "decide_propose",
            json(serde_json::json!({
                "title":"@-", "context":marker
            })),
            out,
        )
    })
    .unwrap();
    let decide = fixture.operations();
    let first = decide.list(ListOptions::default()).unwrap().remove(0).id;
    assert_eq!(
        decide
            .show(&format!("{first:x}"))
            .unwrap()
            .context
            .as_deref(),
        Some(marker.as_str())
    );
    collect(|out| cli::execute(fixture.cli(&["propose", &marker]), out)).unwrap();
    assert!(decide
        .list(ListOptions::default())
        .unwrap()
        .iter()
        .any(|row| row.title == "CLI reads these bytes"));
    let id = format!("{first:x}");
    collect(|out| {
        fixture.adapter().call(
            "decide_factor",
            json(serde_json::json!({
                "decision":id, "side":"pro", "text":"@-"
            })),
            out,
        )
    })
    .unwrap();
    let forced = collect(|out| {
        fixture.adapter().call(
            "decide_resolve",
            json(serde_json::json!({
                "decision":id,"outcome":"@-/literal-outcome","result":"benign","force":true
            })),
            out,
        )
    })
    .unwrap();
    assert!(forced.contains("explicitly forced"));
    for (tool, args, cli_args) in [
        (
            "decide_show",
            serde_json::json!({"decision":id}),
            vec!["show", &id],
        ),
        (
            "decide_list",
            serde_json::json!({"all":true}),
            vec!["list", "--all"],
        ),
        (
            "decide_list",
            serde_json::json!({"forced":true}),
            vec!["list", "--forced"],
        ),
        (
            "decide_resolve_id",
            serde_json::json!({"prefix":id}),
            vec!["resolve-id", &id],
        ),
    ] {
        let mcp = collect(|out| fixture.adapter().call(tool, json(args), out)).unwrap();
        let cli = collect(|out| cli::execute(fixture.cli(&cli_args), out)).unwrap();
        assert_eq!(mcp, cli, "{tool}");
    }
    assert_eq!(
        decide.show(&id).unwrap().outcomes[0].outcome,
        "@-/literal-outcome"
    );
}

#[test]
fn malformed_mcp_arguments_fail_before_storage_or_emission() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.pile");
    let adapter = mcp::Decide::new(missing.clone(), None);
    for (tool, args) in [
        ("decide_propose", r#"{"title":"x","title":"y"}"#),
        ("decide_propose", r#"{"title":" ","context":"literal"}"#),
        ("decide_propose", r#"{"title":"x","path":"/host"}"#),
        (
            "decide_factor",
            r#"{"decision":"ab","text":"x","side":"neither"}"#,
        ),
        (
            "decide_resolve",
            r#"{"decision":"ab","outcome":"x","force":"true"}"#,
        ),
        (
            "decide_reconcile",
            r#"{"decision":"ab","outcome":"x","result":"unknown"}"#,
        ),
        ("decide_show", r#"{"decision":"@-"}"#),
        ("decide_resolve_id", r#"{"prefix":""}"#),
        ("decide_list", r#"{"all":true,"pile":"/host"}"#),
    ] {
        let error = adapter
            .call(
                tool,
                Bytes::from(args.as_bytes().to_vec()),
                &mut Out::new(&mut |_| panic!("invalid arguments must not emit")),
            )
            .unwrap_err();
        assert!(
            error.downcast_ref::<InvalidArguments>().is_some(),
            "{tool}: {error:#}"
        );
    }
    assert_eq!(adapter.tools().len(), 7);
    assert!(!missing.exists());
}

#[test]
fn output_failure_never_retries_a_proposal() {
    let fixture = Fixture::new();
    let mut emissions = 0;
    let error = fixture
        .adapter()
        .call(
            "decide_propose",
            json(serde_json::json!({"title":"one proposal"})),
            &mut Out::new(&mut |_| {
                emissions += 1;
                Err(anyhow!("sink failed"))
            }),
        )
        .unwrap_err();
    assert!(error.to_string().contains("sink failed"));
    assert_eq!(emissions, 1);
    assert_eq!(fixture.commits(), 1);
    assert_eq!(
        fixture
            .operations()
            .list(ListOptions::default())
            .unwrap()
            .len(),
        1
    );
}
