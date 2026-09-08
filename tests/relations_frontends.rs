//! Native Relations receipts, explicit frontends, and fork-visible updates.
use anybytes::Bytes;
use anyhow::{bail, Result};
use faculties::collection_names::open_configured;
use faculties::mcp::{Faculty, InvalidArguments, Server};
use faculties::out::{Out, Part};
use faculties::relations::{
    self, GroupAddition, Head, PeopleFilter, ProfileInput, ProfilePatch, Relations,
};
use faculties::schemas::relations::DEFAULT_SCOPE_ID;
use faculties::storage::{
    initialize_signer, load_signer, open_pile_strict, publish_fragment, read_fact_collection,
};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
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
        let pile = directory.path().join("relations.pile");
        let key = directory.path().join("relations.key");
        fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        Self {
            directory,
            pile,
            key,
        }
    }
    fn relations(&self) -> Relations {
        Relations::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn mcp(&self) -> relations::mcp::Relations {
        relations::mcp::Relations::new(self.pile.clone(), Some(self.key.clone()))
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
    fn cli(&self, arguments: &[&str]) -> String {
        let mut command = Command::new(env!("CARGO_BIN_EXE_relations"));
        for (name, _) in std::env::vars_os() {
            let text = name.to_string_lossy();
            if text.starts_with("TRIBLESPACE_")
                || text.starts_with("DRIVE_")
                || matches!(text.as_ref(), "PILE" | "PERSONA")
            {
                command.env_remove(name);
            }
        }
        let result = command
            .arg("--pile")
            .arg(&self.pile)
            .arg("--key")
            .arg(&self.key)
            .args(arguments)
            .output()
            .unwrap();
        assert!(result.status.success(), "{result:?}");
        String::from_utf8(result.stdout).unwrap()
    }
}
fn profile(label: &str) -> ProfileInput {
    ProfileInput {
        label: label.to_owned(),
        ..Default::default()
    }
}
fn collect(execute: impl FnOnce(&mut Out<'_>) -> Result<()>) -> Result<String> {
    let mut result = String::new();
    execute(&mut Out::new(&mut |part| {
        match part {
            Part::Text { text } => result.push_str(&text),
            other => panic!("unexpected output {other:?}"),
        }
        Ok(())
    }))?;
    Ok(result)
}
fn call(faculty: &relations::mcp::Relations, tool: &str, args: Value) -> Result<String> {
    collect(|out| faculty.call(tool, Bytes::from(serde_json::to_vec(&args).unwrap()), out))
}

#[test]
fn native_write_receipts_and_true_noops_do_not_require_text_parsing() {
    let fixture = Fixture::new();
    let operations = fixture.relations();
    let added = operations
        .add(profile("Ada"), None, &["native".into()])
        .unwrap();
    let id = format!("{:x}", added.person);
    let (facts, _) = fixture.snapshot();
    assert_eq!(
        relations::profile_head(&facts, added.person).unwrap(),
        Head::Unique(added.profile)
    );
    assert_eq!(
        relations::lifecycle_head(&facts, added.person).unwrap(),
        Head::Unique(added.lifecycle)
    );
    operations.show(&id).unwrap(); // warm derived views before checking a no-op
    let length = fs::metadata(&fixture.pile).unwrap().len();
    let unchanged = operations.set(&id, ProfilePatch::default(), &[]).unwrap();
    assert_eq!(unchanged.person, added.person);
    assert_eq!(unchanged.previous, added.profile);
    assert_eq!(unchanged.current, None);
    assert!(!unchanged.provenance_added);
    assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), length);
    let updated = operations
        .set(
            &id,
            ProfilePatch {
                note: Some("native note".into()),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
    assert_ne!(updated.current.unwrap(), added.profile);
    let provenance = operations
        .set(&id, ProfilePatch::default(), &["another-source".into()])
        .unwrap();
    assert_eq!(provenance.current, None);
    assert!(provenance.provenance_added);
    let (facts, _) = fixture.snapshot();
    assert_eq!(
        relations::person_sources(&facts, added.person).unwrap(),
        ["another-source", "native"]
    );
}

#[test]
fn cli_mcp_and_native_reads_preserve_all_profile_fields_and_clear_semantics() {
    let fixture = Fixture::new();
    let person = genid().id;
    let id = format!("{person:x}");
    let faculty = fixture.mcp();
    call(&faculty, "relations_add", json!({
        "label":"Ada","id":id,"sources":["mcp"],"profile":{
            "aliases":["Countess"],"affinities":["math"],"first_name":"Ada","last_name":"Lovelace",
            "display_name":"Ada L.","note":"literal note","teams_user_ids":["teams-id"],
            "emails":["ada@example.test"],"phones":["123"],"company":"Engines","position":"Programmer",
            "profile_urls":["https://example.test/ada"]
        }
    })).unwrap();
    let operations = fixture.relations();
    assert_eq!(fixture.cli(&["show", &id]), operations.show(&id).unwrap());
    assert_eq!(
        call(&faculty, "relations_show", json!({"person":id})).unwrap(),
        operations.show(&id).unwrap()
    );
    assert_eq!(
        fixture.cli(&["list", "--all", "--limit", "10"]),
        call(
            &faculty,
            "relations_list",
            json!({"filter":"all","limit":10})
        )
        .unwrap()
    );
    assert_eq!(
        operations.list(10, PeopleFilter::All).unwrap(),
        fixture.cli(&["list", "--all", "--limit", "10"])
    );
    call(
        &faculty,
        "relations_set",
        json!({"person":id,"patch":{"aliases":[],"clear":["note"],"company":"New Engines"}}),
    )
    .unwrap();
    let (facts, reader) = fixture.snapshot();
    let current = relations::profile_input(
        &reader,
        &relations::current_profile(&facts, person).unwrap(),
    )
    .unwrap();
    assert!(current.aliases.is_empty());
    assert_eq!(current.note, None);
    assert_eq!(current.company.as_deref(), Some("New Engines"));
    assert_eq!(current.first_name.as_deref(), Some("Ada"));
    assert_eq!(current.emails, ["ada@example.test"]);
    fixture.cli(&["set", &id, "--alias", "Restored", "--clear", "emails"]);
    let (facts, reader) = fixture.snapshot();
    let current = relations::profile_input(
        &reader,
        &relations::current_profile(&facts, person).unwrap(),
    )
    .unwrap();
    assert_eq!(current.aliases, ["Restored"]);
    assert!(current.emails.is_empty());
    assert!(call(
        &faculty,
        "relations_set",
        json!({"person":id,"patch":{"aliases":[],"clear":["aliases"]}})
    )
    .is_err());
    assert!(call(&faculty, "relations_reconcile", json!({"person":id}))
        .unwrap()
        .contains("already settled"));
}

#[test]
fn lifecycle_commands_keep_retirement_filters_and_restore_alias() {
    let fixture = Fixture::new();
    let person = fixture
        .relations()
        .add(profile("Example"), None, &[])
        .unwrap()
        .person;
    let id = format!("{person:x}");
    call(&fixture.mcp(), "relations_retire", json!({"person":id})).unwrap();
    assert_eq!(
        fixture.relations().list(50, PeopleFilter::Active).unwrap(),
        "No people.\n"
    );
    assert!(call(
        &fixture.mcp(),
        "relations_list",
        json!({"filter":"retired"})
    )
    .unwrap()
    .contains("[retired]"));
    assert!(fixture.cli(&["list", "--retired"]).contains("[retired]"));
    assert!(fixture.cli(&["restore", &id]).starts_with("active:"));
    fixture.cli(&["retire", &id]);
    assert!(
        call(&fixture.mcp(), "relations_unretire", json!({"person":id}))
            .unwrap()
            .starts_with("active:")
    );
    assert!(!fixture
        .relations()
        .show(&id)
        .unwrap()
        .contains("retired: true"));
}

#[test]
fn group_and_identity_frontends_share_exact_members_and_noop_outcomes() {
    let fixture = Fixture::new();
    let operations = fixture.relations();
    let first = operations.add(profile("First"), None, &[]).unwrap().person;
    let second = operations.add(profile("Second"), None, &[]).unwrap().person;
    let first_id = format!("{first:x}");
    let second_id = format!("{second:x}");
    let faculty = fixture.mcp();
    call(&faculty, "relations_group_create", json!({"name":"crew"})).unwrap();
    call(
        &faculty,
        "relations_group_add",
        json!({"group":"crew","person":first_id}),
    )
    .unwrap();
    call(
        &faculty,
        "relations_identity_resolve",
        json!({"first":first_id,"second":second_id,"same":true}),
    )
    .unwrap();
    assert_eq!(
        operations.group_add("crew", &second_id).unwrap(),
        GroupAddition::Already(second)
    );
    assert!(call(
        &faculty,
        "relations_group_add",
        json!({"group":"crew","person":second_id})
    )
    .unwrap()
    .contains("already represented"));
    assert_eq!(
        fixture.cli(&["group", "show", "crew"]),
        call(&faculty, "relations_group_show", json!({"group":"crew"})).unwrap()
    );
    assert_eq!(
        fixture.cli(&["group", "list"]),
        call(&faculty, "relations_group_list", json!({})).unwrap()
    );
    assert_eq!(
        fixture.cli(&["identity", "list"]),
        call(&faculty, "relations_identity_list", json!({})).unwrap()
    );
    assert!(fixture
        .cli(&["identity", "resolve", &first_id, &second_id, "--distinct"])
        .contains("distinct-from"));
    call(
        &faculty,
        "relations_group_remove",
        json!({"group":"crew","person":first_id}),
    )
    .unwrap();
    call(
        &faculty,
        "relations_group_rename",
        json!({"group":"crew","name":"new crew"}),
    )
    .unwrap();
    assert!(call(
        &faculty,
        "relations_group_reconcile",
        json!({"group":"new crew"})
    )
    .unwrap()
    .contains("already settled"));
    fixture.cli(&["group", "add", "new crew", &second_id]);
    fixture.cli(&["group", "remove", "new crew", &second_id]);
    fixture.cli(&["group", "rename", "new crew", "final crew"]);
    assert_eq!(
        operations.group_show("final crew").unwrap(),
        fixture.cli(&["group", "show", "final crew"])
    );
    assert!(call(
        &faculty,
        "relations_identity_resolve",
        json!({"first":first_id,"second":second_id,"same":false})
    )
    .unwrap()
    .contains("already settled"));
    let (facts, _) = fixture.snapshot();
    let group = *relations::group_anchors(&facts).iter().next().unwrap();
    assert!(relations::current_group(&facts, group)
        .unwrap()
        .members
        .is_empty());
}

#[test]
fn profile_forks_require_an_explicit_base_and_preserve_every_predecessor() {
    let fixture = Fixture::new();
    let operations = fixture.relations();
    let added = operations.add(profile("Ada"), None, &[]).unwrap();
    let id = format!("{:x}", added.person);
    let left =
        relations::profile_fragment(added.person, profile("Left"), &[added.profile]).unwrap();
    let left_id = left.root().unwrap();
    fixture.publish(left);
    fixture.publish(
        relations::profile_fragment(added.person, profile("Right"), &[added.profile]).unwrap(),
    );
    let faculty = fixture.mcp();
    assert!(operations
        .show(&id)
        .unwrap()
        .contains("profile_fork: 2 heads"));
    assert!(call(
        &faculty,
        "relations_set",
        json!({"person":id,"patch":{"aliases":[]}})
    )
    .is_err());
    assert!(call(&faculty, "relations_reconcile", json!({"person":id})).is_err());
    call(
        &faculty,
        "relations_reconcile",
        json!({"person":id,"base":format!("{left_id:x}"),"patch":{"label":"Joined"}}),
    )
    .unwrap();
    let (facts, reader) = fixture.snapshot();
    let current = relations::current_profile(&facts, added.person).unwrap();
    assert_eq!(current.predecessors.len(), 2);
    assert_eq!(
        relations::profile_input(&reader, &current).unwrap().label,
        "Joined"
    );
}

#[test]
fn group_and_identity_reconciliation_keep_concurrent_evidence() {
    let fixture = Fixture::new();
    let operations = fixture.relations();
    let first = operations.add(profile("First"), None, &[]).unwrap().person;
    let second = operations.add(profile("Second"), None, &[]).unwrap().person;
    let group = operations.group_create("crew").unwrap();
    let group_id = format!("{:x}", group.group);
    fixture.publish(
        relations::group_snapshot_fragment(group.group, "left", &[first], &[group.snapshot])
            .unwrap(),
    );
    fixture.publish(
        relations::group_snapshot_fragment(group.group, "right", &[second], &[group.snapshot])
            .unwrap(),
    );
    assert!(call(
        &fixture.mcp(),
        "relations_group_reconcile",
        json!({"group":group_id})
    )
    .is_err());
    assert!(call(
        &fixture.mcp(),
        "relations_group_show",
        json!({"group":group_id})
    )
    .unwrap()
    .contains("group_fork: 2 heads"));
    call(
        &fixture.mcp(),
        "relations_group_reconcile",
        json!({"group":group_id,"name":"joined"}),
    )
    .unwrap();
    let (facts, _) = fixture.snapshot();
    let current = relations::current_group(&facts, group.group).unwrap();
    assert_eq!(current.members, vec![first.min(second), first.max(second)]);
    assert_eq!(current.predecessors.len(), 2);
    fixture.publish(relations::identity_verdict_fragment(first, second, true, &[]).unwrap());
    fixture.publish(relations::identity_verdict_fragment(first, second, false, &[]).unwrap());
    assert!(operations
        .identity_list()
        .unwrap()
        .contains("fork: 2 heads"));
    call(
        &fixture.mcp(),
        "relations_identity_resolve",
        json!({"first":format!("{first:x}"),"second":format!("{second:x}"),"same":false}),
    )
    .unwrap();
    let (facts, _) = fixture.snapshot();
    let Head::Unique(verdict) = relations::identity_head(&facts, first, second).unwrap() else {
        panic!("verdict remains forked")
    };
    let verdict = relations::identity_verdict(&facts, verdict).unwrap();
    assert!(!verdict.same);
    assert_eq!(verdict.predecessors.len(), 2);
}

#[test]
fn mcp_profile_prose_and_group_names_are_literal_host_independent_values() {
    let fixture = Fixture::new();
    let path = fixture.directory.path().join("do-not-read.txt");
    fs::write(&path, "HOST FILE CONTENT").unwrap();
    let literal = format!("@{}", path.display());
    let person = genid().id;
    let id = format!("{person:x}");
    call(
        &fixture.mcp(),
        "relations_add",
        json!({"label":literal,"id":id,"profile":{"note":"@-"}}),
    )
    .unwrap();
    call(
        &fixture.mcp(),
        "relations_set",
        json!({"person":id,"patch":{"note":literal}}),
    )
    .unwrap();
    call(
        &fixture.mcp(),
        "relations_group_create",
        json!({"name":"@-"}),
    )
    .unwrap();
    let shown = fixture.relations().show(&id).unwrap();
    assert_eq!(shown.matches(&literal).count(), 2);
    assert!(!shown.contains("HOST FILE CONTENT"));
    assert!(fixture
        .relations()
        .group_show("@-")
        .unwrap()
        .contains("name: @-"));
}

#[test]
fn discovery_and_typed_nested_argument_errors_do_not_touch_storage() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("absent.pile");
    let faculty = relations::mcp::Relations::new(pile.clone(), None);
    Server::new(&[&faculty]).unwrap();
    assert_eq!(
        faculty
            .tools()
            .iter()
            .map(|tool| tool.name)
            .collect::<Vec<_>>(),
        [
            "relations_add",
            "relations_set",
            "relations_reconcile",
            "relations_list",
            "relations_show",
            "relations_retire",
            "relations_unretire",
            "relations_group_create",
            "relations_group_add",
            "relations_group_remove",
            "relations_group_rename",
            "relations_group_reconcile",
            "relations_group_list",
            "relations_group_show",
            "relations_identity_resolve",
            "relations_identity_list"
        ]
    );
    for (tool, raw) in [
        ("relations_add", r#"{"label":"first","label":"second"}"#),
        ("relations_add", r#"{"label":"Ada","id":"not-an-id"}"#),
        ("relations_add", r#"{"label":"Ada","persona":"ambient"}"#),
        (
            "relations_add",
            r#"{"label":"Ada","profile":{"note":"a","note":"b"}}"#,
        ),
        (
            "relations_set",
            r#"{"person":"Ada","patch":{"emails":[1]}}"#,
        ),
        (
            "relations_set",
            r#"{"person":"Ada","patch":{"clear":["missing"]}}"#,
        ),
        (
            "relations_set",
            r#"{"person":"Ada","patch":{"note":"a","note":"b"}}"#,
        ),
        (
            "relations_reconcile",
            r#"{"person":"Ada","patch":{"path":"/host"}}"#,
        ),
        ("relations_list", r#"{"limit":-1}"#),
        ("relations_list", r#"{"limit":"10"}"#),
        ("relations_list", r#"{"filter":"unknown"}"#),
        ("relations_show", r#"{"person":"Ada","key":"secret"}"#),
        ("relations_group_add", r#"{"group":"crew","person":false}"#),
        ("relations_group_list", r#"{"pile":"/elsewhere"}"#),
        (
            "relations_identity_resolve",
            r#"{"first":"a","second":"b","same":"true"}"#,
        ),
        (
            "relations_identity_resolve",
            r#"{"first":"a","second":"b","same":true,"distinct":true}"#,
        ),
    ] {
        let error = collect(|out| faculty.call(tool, Bytes::from(raw.as_bytes().to_vec()), out))
            .unwrap_err();
        assert!(error.is::<InvalidArguments>(), "{tool}: {error:#}");
    }
    assert!(!pile.exists());
}

#[test]
fn ambiguous_selectors_stay_visible_and_output_failure_does_not_repeat_writes() {
    let fixture = Fixture::new();
    fixture
        .relations()
        .add(profile("Shared"), None, &[])
        .unwrap();
    fixture
        .relations()
        .add(profile("Shared"), None, &[])
        .unwrap();
    assert!(fixture.relations().show("Shared").is_err());
    assert!(call(
        &fixture.mcp(),
        "relations_retire",
        json!({"person":"Shared"})
    )
    .is_err());
    let person = genid().id;
    let error = fixture
        .mcp()
        .call(
            "relations_add",
            Bytes::from(
                serde_json::to_vec(&json!({"label":"one publication","id":format!("{person:x}")}))
                    .unwrap(),
            ),
            &mut Out::new(&mut |_| bail!("recipient closed")),
        )
        .unwrap_err();
    assert!(error.to_string().contains("recipient closed"));
    let (facts, _) = fixture.snapshot();
    assert_eq!(relations::person_anchors(&facts).len(), 3);
    assert!(matches!(
        relations::profile_head(&facts, person).unwrap(),
        Head::Unique(_)
    ));
}
