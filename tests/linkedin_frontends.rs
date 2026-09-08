//! LinkedIn frontends over resident fixtures and no real OAuth/API operations.
use anybytes::Bytes;
use anyhow::{bail, Result};
use faculties::collection_names::open_configured;
use faculties::linkedin::{self, Connection, LinkedIn, PullOptions};
use faculties::mcp::{Faculty, InvalidArguments, Server};
use faculties::out::{Out, Part};
use faculties::relations::{self, Head, ProfileInput};
use faculties::schemas::relations::DEFAULT_SCOPE_ID;
use faculties::storage::{
    initialize_signer, load_signer, open_pile_strict, publish_fragment, read_fact_collection,
};
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::prelude::*;

struct Fixture {
    directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("linkedin.pile");
        let key = directory.path().join("linkedin.key");
        fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        Self {
            directory,
            pile,
            key,
        }
    }
    fn operations(&self) -> LinkedIn {
        LinkedIn::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn mcp(&self) -> linkedin::mcp::LinkedIn {
        linkedin::mcp::LinkedIn::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn snapshot(&self) -> (TribleSet, PileSnapshot) {
        let signer = load_signer(&self.pile, Some(&self.key)).unwrap();
        let mut pile = open_pile_strict(&self.pile).unwrap();
        let collection =
            open_configured(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key()).unwrap();
        let snapshot = pile.snapshot().unwrap();
        let facts = read_fact_collection(collection, &snapshot).unwrap().0;
        pile.close().unwrap();
        (facts, snapshot)
    }
    fn publish(&self, fragment: Fragment) {
        publish_fragment(&self.pile, Some(&self.key), DEFAULT_SCOPE_ID, fragment).unwrap();
    }
    fn person(&self, input: ProfileInput) -> Id {
        let person = genid().id;
        self.publish(relations::person_fragment(person, input).unwrap().0);
        person
    }
    fn cli(&self, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_linkedin"));
        clean_child(&mut command);
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
            || matches!(text.as_ref(), "PILE" | "PERSONA" | "LINKEDIN_TOKEN")
        {
            command.env_remove(name);
        }
    }
}
fn profile(label: &str) -> ProfileInput {
    ProfileInput {
        label: label.into(),
        ..Default::default()
    }
}
fn connection(first_name: &str, profile_url: &str) -> Connection {
    Connection {
        first_name: first_name.into(),
        profile_url: profile_url.into(),
        ..Default::default()
    }
}
fn collect(execute: impl FnOnce(&mut Out<'_>) -> Result<()>) -> Result<String> {
    let mut text = String::new();
    execute(&mut Out::new(&mut |part| {
        match part {
            Part::Text { text: value } => text.push_str(&value),
            _ => panic!("unexpected modality"),
        }
        Ok(())
    }))?;
    Ok(text)
}
fn call(faculty: &linkedin::mcp::LinkedIn, tool: &str, args: Value) -> Result<String> {
    collect(|out| faculty.call(tool, Bytes::from(serde_json::to_vec(&args).unwrap()), out))
}
fn success(output: Output) -> String {
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn native_import_receipts_preserve_dry_runs_identity_components_and_noops() {
    let fixture = Fixture::new();
    let first = fixture.person(ProfileInput {
        profile_urls: vec!["linkedin.com/in/ada".into()],
        ..profile("URL Ada")
    });
    let second = fixture.person(ProfileInput {
        emails: vec!["ada@example.test".into()],
        ..profile("Email Ada")
    });
    fixture.publish(relations::identity_verdict_fragment(first, second, true, &[]).unwrap());
    let row = Connection {
        first_name: "Ada".into(),
        last_name: "Lovelace".into(),
        profile_url: "https://www.LinkedIn.com/in/Ada/".into(),
        email: "ADA@example.test".into(),
        company: "Analytical Engines".into(),
        ..Default::default()
    };
    let before = fixture.snapshot().0;
    let planned = fixture
        .operations()
        .import(std::slice::from_ref(&row), true)
        .unwrap();
    assert!(!planned.committed);
    assert!(planned.dry_run);
    assert_eq!(planned.created, 0);
    assert_eq!(planned.profiles.len(), 2);
    assert_eq!(planned.matched_by_email, 1);
    assert_eq!(planned.matched_by_url, 1);
    assert_eq!(fixture.snapshot().0, before);
    let imported = fixture
        .operations()
        .import(std::slice::from_ref(&row), false)
        .unwrap();
    assert!(imported.committed);
    assert_eq!(imported.profiles, planned.profiles);
    let (facts, reader) = fixture.snapshot();
    for value in &imported.profiles {
        assert!(!value.created);
        assert_eq!(
            relations::profile_head(&facts, value.person).unwrap(),
            Head::Unique(value.profile)
        );
        let snapshot = relations::current_profile(&facts, value.person).unwrap();
        let profile = relations::profile_input(&reader, &snapshot).unwrap();
        assert_eq!(profile.company.as_deref(), Some("Analytical Engines"));
        assert_eq!(profile.emails, ["ada@example.test"]);
        assert_eq!(profile.profile_urls, ["linkedin.com/in/ada"]);
    }
    let unchanged = fixture.operations().import(&[row], false).unwrap();
    assert!(!unchanged.committed);
    assert!(unchanged.profiles.is_empty());
}

#[test]
fn cli_export_file_and_mcp_resident_rows_produce_identical_literal_profiles() {
    let cli = Fixture::new();
    let mcp = Fixture::new();
    let snapshot = cli.directory.path().join("connections.json");
    fs::write(
        &snapshot,
        serde_json::to_vec(&json!([{
            "First Name":"@-", "Last Name":"Literal", "Company":"@/host/path",
            "Position":"@@unchanged", "URL":"https://linkedin.com/in/literal/",
            "Email Address":"literal@example.test", "upstream metadata":7
        }]))
        .unwrap(),
    )
    .unwrap();
    let shown_cli = success(cli.cli(&["import", snapshot.to_str().unwrap()]));
    assert!(shown_cli.contains("Read 1 connection records from"));
    assert!(shown_cli.contains("Committed to relations."));
    let shown_mcp = call(
        &mcp.mcp(),
        "linkedin_import",
        json!({"connections":[{
            "first_name":"@-", "last_name":"Literal", "company":"@/host/path",
            "position":"@@unchanged", "profile_url":"https://linkedin.com/in/literal/",
            "email":"literal@example.test"
        }]}),
    )
    .unwrap();
    let (cli_facts, cli_reader) = cli.snapshot();
    let (mcp_facts, mcp_reader) = mcp.snapshot();
    let people = relations::person_anchors(&cli_facts);
    assert_eq!(people, relations::person_anchors(&mcp_facts));
    assert_eq!(people.len(), 1);
    let person = *people.iter().next().unwrap();
    let cli_head = relations::current_profile(&cli_facts, person).unwrap();
    let mcp_head = relations::current_profile(&mcp_facts, person).unwrap();
    assert_eq!(cli_head.id, mcp_head.id);
    let profile = relations::profile_input(&cli_reader, &cli_head).unwrap();
    assert_eq!(
        profile,
        relations::profile_input(&mcp_reader, &mcp_head).unwrap()
    );
    assert_eq!(profile.first_name.as_deref(), Some("@-"));
    assert_eq!(profile.company.as_deref(), Some("@/host/path"));
    assert_eq!(profile.position.as_deref(), Some("@@unchanged"));
    assert!(shown_mcp.contains(&format!(
        "Authored person {person:x} profile {:x}",
        mcp_head.id
    )));
}

#[test]
fn name_only_dry_run_anchors_are_provisional_and_unpublished() {
    let fixture = Fixture::new();
    let row = connection("Name Only", "");
    let first = fixture
        .operations()
        .import(std::slice::from_ref(&row), true)
        .unwrap();
    let second = fixture
        .operations()
        .import(std::slice::from_ref(&row), true)
        .unwrap();
    assert_eq!(first.name_only, 1);
    assert!(first.profiles[0].created);
    assert_ne!(first.profiles[0].person, second.profiles[0].person);
    assert!(relations::person_anchors(&fixture.snapshot().0).is_empty());
    let text = call(
        &fixture.mcp(),
        "linkedin_import",
        json!({
            "connections":[{"first_name":"Name Only"}],"dry_run":true
        }),
    )
    .unwrap();
    assert!(text.contains("provisional dry-run anchors"));
    assert!(text.contains("Planned person"));
    assert!(relations::person_anchors(&fixture.snapshot().0).is_empty());
}

#[test]
fn owned_review_retains_total_and_frontends_offer_their_own_resolution_syntax() {
    let fixture = Fixture::new();
    for _ in 0..3 {
        fixture.person(profile("Shared Name"));
    }
    let operations = fixture.operations();
    let old = operations.review(1).unwrap();
    assert_eq!(old.total, 3);
    assert_eq!(old.pairs.len(), 1);
    let zero = operations.review(0).unwrap();
    assert_eq!(zero.total, 3);
    assert!(zero.pairs.is_empty());
    let cli = success(fixture.cli(&["review", "--limit", "1"]));
    let mcp = call(&fixture.mcp(), "linkedin_review", json!({"limit":1})).unwrap();
    assert!(cli.contains("linkedin resolve"));
    assert!(cli.contains("--same | --distinct"));
    assert!(cli.contains("(+2 more; raise --limit)"));
    assert!(mcp.contains("linkedin_resolve"));
    assert!(mcp.contains("same=true or false"));
    assert!(!mcp.contains("--same"));
    let pair = &old.pairs[0];
    operations
        .resolve(
            &format!("{:x}", pair.first.person),
            &format!("{:x}", pair.second.person),
            false,
        )
        .unwrap();
    assert_eq!(operations.review(50).unwrap().total, 2);
    assert_eq!(old.total, 3);
    assert_eq!(pair.first.profile.label, "Shared Name");
}

#[test]
fn resolution_receipts_settle_all_direct_fork_heads_without_rewriting_profiles() {
    let fixture = Fixture::new();
    let first = fixture.person(profile("Ada"));
    let second = fixture.person(profile("Ada"));
    let first_id = format!("{first:x}");
    let second_id = format!("{second:x}");
    let operations = fixture.operations();
    let before = fixture.snapshot().0;
    let initial = operations.resolve(&first_id, &second_id, false).unwrap();
    assert!(initial.changed);
    let noop = operations.resolve(&first_id, &second_id, false).unwrap();
    assert!(!noop.changed);
    assert_eq!(noop.verdict, initial.verdict);
    let left =
        relations::identity_verdict_fragment(first, second, true, &[initial.verdict]).unwrap();
    let left_id = left.root().unwrap();
    let right =
        relations::identity_verdict_fragment(first, second, false, &[initial.verdict]).unwrap();
    let right_id = right.root().unwrap();
    fixture.publish(left + right);
    assert_eq!(operations.review(50).unwrap().total, 1);
    let receipt = operations.resolve(&first_id, &second_id, true).unwrap();
    assert!(receipt.changed);
    assert_eq!(receipt.first, first);
    assert_eq!(receipt.second, second);
    assert!(receipt.same);
    let after = fixture.snapshot().0;
    assert_eq!(
        relations::identity_head(&after, first, second).unwrap(),
        Head::Unique(receipt.verdict)
    );
    let verdict = relations::identity_verdict(&after, receipt.verdict).unwrap();
    let predecessors = verdict
        .predecessors
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(predecessors, [left_id, right_id].into());
    for person in [first, second] {
        assert_eq!(
            relations::profile_head(&before, person).unwrap(),
            relations::profile_head(&after, person).unwrap()
        );
    }
    let text = call(
        &fixture.mcp(),
        "linkedin_resolve",
        json!({
            "first":first_id, "second":second_id, "same":true
        }),
    )
    .unwrap();
    assert!(text.contains(&format!("already settled at {:x}", receipt.verdict)));
}

#[test]
fn all_mcp_decoders_reject_host_inputs_duplicates_types_and_positional_rows_before_storage() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("absent.pile");
    let faculty = linkedin::mcp::LinkedIn::new(pile.clone(), None);
    Server::new(&[&faculty]).unwrap();
    assert_eq!(
        faculty
            .tools()
            .iter()
            .map(|tool| tool.name)
            .collect::<Vec<_>>(),
        [
            "linkedin_import",
            "linkedin_pull",
            "linkedin_review",
            "linkedin_resolve"
        ]
    );
    for (tool, args) in [
        ("linkedin_import", r#"{}"#),
        (
            "linkedin_import",
            r#"{"connections":[],"snapshot":"/host/file"}"#,
        ),
        (
            "linkedin_import",
            r#"{"connections":[],"persona":"ambient"}"#,
        ),
        (
            "linkedin_import",
            r#"{"connections":[{"First Name":"Ada"}]}"#,
        ),
        ("linkedin_import", r#"{"connections":[{"first_name":5}]}"#),
        (
            "linkedin_import",
            r#"{"connections":[{"first_name":"Ada","first_name":"Grace"}]}"#,
        ),
        ("linkedin_import", r#"{"connections":[],"connections":[]}"#),
        ("linkedin_import", r#"{"connections":[[]]}"#),
        ("linkedin_import", r#"{"connections":[["Ada"]]}"#),
        ("linkedin_import", r#"{"connections":[],"dry_run":"true"}"#),
        ("linkedin_import", r#"{"connections":"@-"}"#),
        ("linkedin_pull", r#"{"token":"secret"}"#),
        ("linkedin_pull", r#"{"url":"https://untrusted.invalid"}"#),
        ("linkedin_pull", r#"{"api_version":202312}"#),
        ("linkedin_pull", r#"{"api_version":"x\r\ny"}"#),
        ("linkedin_pull", r#"{"domain":""}"#),
        (
            "linkedin_pull",
            r#"{"domain":"CONNECTIONS","domain":"PROFILE"}"#,
        ),
        ("linkedin_review", r#"{"limit":-1}"#),
        ("linkedin_review", r#"{"limit":"2"}"#),
        ("linkedin_review", r#"{"limit":1.5}"#),
        ("linkedin_review", r#"{"limit":1,"limit":2}"#),
        ("linkedin_review", r#"{"key":"/host/key"}"#),
        ("linkedin_resolve", r#"{"first":"ab","second":"cd"}"#),
        (
            "linkedin_resolve",
            r#"{"first":"ab","second":"cd","same":"true"}"#,
        ),
        (
            "linkedin_resolve",
            r#"{"first":"ab","second":"cd","same":true,"distinct":false}"#,
        ),
        (
            "linkedin_resolve",
            r#"{"first":"@-","second":"cd","same":true}"#,
        ),
        (
            "linkedin_resolve",
            r#"{"first":"ab","first":"cd","second":"ef","same":true}"#,
        ),
        ("linkedin_review", r#"[]"#),
    ] {
        let mut emitted = 0;
        let error = faculty
            .call(
                tool,
                Bytes::from(args.as_bytes().to_vec()),
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
        assert!(!pile.exists());
    }
}

#[test]
fn missing_token_is_local_and_ambient_tokens_do_not_leak_into_native_or_mcp_calls() {
    if std::env::var_os("FACULTIES_LINKEDIN_AMBIENT_CHILD").is_none() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        clean_child(&mut command);
        let output = command
            .args([
                "--exact",
                "missing_token_is_local_and_ambient_tokens_do_not_leak_into_native_or_mcp_calls",
                "--nocapture",
            ])
            .env("FACULTIES_LINKEDIN_AMBIENT_CHILD", "1")
            .env("LINKEDIN_TOKEN", "test-only-linkedin-environment-token")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("absent.pile");
    let operations = LinkedIn::new(pile.clone(), None);
    let error = operations.pull(PullOptions::default()).unwrap_err();
    assert!(error.to_string().contains("token is not configured"));
    let faculty = linkedin::mcp::LinkedIn::new(pile.clone(), None);
    assert!(call(&faculty, "linkedin_pull", json!({}))
        .unwrap_err()
        .to_string()
        .contains("token is not configured"));
    assert!(!pile.exists());
    assert!(
        !format!("{:?}", operations.with_token("private-token".into())).contains("private-token")
    );
    assert!(!format!("{:?}", faculty.with_token("private-token".into())).contains("private-token"));
    let output = Command::new(env!("CARGO_BIN_EXE_linkedin"))
        .args(["pull", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("test-only-linkedin-environment-token")
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("test-only-linkedin-environment-token")
    );
}

#[test]
fn output_failure_cannot_undo_an_authored_import_or_verdict() {
    let fixture = Fixture::new();
    let faculty = fixture.mcp();
    let error = faculty
        .call(
            "linkedin_import",
            Bytes::from(
                br#"{
        "connections":[{"first_name":"Ada","profile_url":"linkedin.com/in/ada"}]
    }"#
                .to_vec(),
            ),
            &mut Out::new(&mut |_| bail!("fixture delivery failure")),
        )
        .unwrap_err();
    assert!(error.to_string().contains("fixture delivery failure"));
    let repeated = fixture
        .operations()
        .import(&[connection("Ada", "linkedin.com/in/ada")], false)
        .unwrap();
    assert!(!repeated.committed);
    let first = *relations::person_anchors(&fixture.snapshot().0)
        .iter()
        .next()
        .unwrap();
    let second = fixture.person(profile("Ada"));
    let first_id = format!("{first:x}");
    let second_id = format!("{second:x}");
    let args =
        serde_json::to_vec(&json!({"first":first_id,"second":second_id,"same":false})).unwrap();
    let error = faculty
        .call(
            "linkedin_resolve",
            Bytes::from(args),
            &mut Out::new(&mut |_| bail!("fixture delivery failure")),
        )
        .unwrap_err();
    assert!(error.to_string().contains("fixture delivery failure"));
    assert!(
        !fixture
            .operations()
            .resolve(&first_id, &second_id, false)
            .unwrap()
            .changed
    );
}

#[test]
fn semantic_import_conflict_is_an_operation_error_and_publishes_no_partial_people() {
    let fixture = Fixture::new();
    let error = call(
        &fixture.mcp(),
        "linkedin_import",
        json!({"connections":[
            {"first_name":"Unaffected","profile_url":"linkedin.com/in/first"},
            {"first_name":"Conflict","profile_url":"linkedin.com/in/second","company":"First"},
            {"first_name":"Conflict","profile_url":"linkedin.com/in/second","company":"Second"}
        ]}),
    )
    .unwrap_err();
    assert!(error.downcast_ref::<InvalidArguments>().is_none());
    assert!(error
        .to_string()
        .contains("conflicting company observations"));
    assert!(relations::person_anchors(&fixture.snapshot().0).is_empty());
}
