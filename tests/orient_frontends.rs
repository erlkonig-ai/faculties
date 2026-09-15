use anybytes::Bytes;
use clap::Parser;
use faculties::mcp::{Faculty, InvalidArguments, Server};
use faculties::orient::{mcp, Orient, ShowOptions, WaitOptions, WakeOptions};
use faculties::out::{Out, Part};
use faculties::schemas::swarm_health::{self as health, Component, Condition, Recorder, State};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::lww_register::LwwRegisterBlob;
use triblespace::core::collection::{CollectionRead, CollectionRecord, CollectionStoreExt};
use triblespace::prelude::*;

struct Fixture {
    directory: tempfile::TempDir,
    pile: PathBuf,
    key: PathBuf,
    persona: Id,
    sender: Id,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("orient.pile");
        let key = directory.path().join("explicit.key");
        fs::File::create(&pile).unwrap();
        faculties::storage::initialize_signer(&pile, Some(&key)).unwrap();
        let fixture = Self {
            directory,
            pile,
            key,
            persona: *fucid(),
            sender: *fucid(),
        };
        // Orient deliberately ignores inbox rows addressed to non-person
        // anchors. Real Message calls resolve registered Relations identities.
        fixture.person(fixture.persona);
        fixture.person(fixture.sender);
        fixture
    }
    fn orient(&self) -> Orient {
        Orient::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn adapter(&self) -> mcp::Orient {
        mcp::Orient::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn who(&self) -> String {
        format!("{:x}", self.persona)
    }
    fn cli(&self, args: &[&str]) -> Vec<Part> {
        let mut argv = vec![
            "orient",
            "--pile",
            self.pile.to_str().unwrap(),
            "--key",
            self.key.to_str().unwrap(),
        ];
        argv.extend_from_slice(args);
        let cli = faculties::orient::cli::Cli::try_parse_from(argv).unwrap();
        let mut parts = Vec::new();
        faculties::orient::cli::execute(
            cli,
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
        parts
    }
    fn publish(&self, scope: Id, fragment: Fragment) {
        let signer = faculties::storage::load_signer(&self.pile, Some(&self.key)).unwrap();
        let mut pile = faculties::storage::open_pile_strict(&self.pile).unwrap();
        let collection =
            faculties::collection_names::open_configured(&mut pile, scope, signer.verifying_key())
                .unwrap();
        pile.commit(collection, &signer, fragment).unwrap();
        pile.close().unwrap();
    }

    /// Model the independent maintenance worker, never an Orient call.
    fn maintain(&self) {
        let signer = faculties::storage::load_signer(&self.pile, Some(&self.key)).unwrap();
        let mut pile = faculties::storage::open_pile_strict(&self.pile).unwrap();
        pollster::block_on(async {
            for scope in [
                faculties::schemas::message::DEFAULT_SCOPE_ID,
                faculties::schemas::mail::DEFAULT_SCOPE_ID,
                faculties::schemas::teams::DEFAULT_SCOPE_ID,
                faculties::schemas::compass::DEFAULT_SCOPE_ID,
                faculties::schemas::relations::DEFAULT_SCOPE_ID,
                faculties::schemas::status::DEFAULT_SCOPE_ID,
                faculties::schemas::habit::DEFAULT_SCOPE_ID,
                faculties::schemas::orient::DEFAULT_SCOPE_ID,
                faculties::schemas::memory::DEFAULT_SCOPE_ID,
                faculties::schemas::wiki::DEFAULT_SCOPE_ID,
                health::DEFAULT_SCOPE_ID,
            ] {
                let source = faculties::collection_names::open_configured(
                    &mut pile,
                    scope,
                    signer.verifying_key(),
                )
                .unwrap();
                let policy = source.policy(&pile.snapshot().unwrap()).unwrap();
                let succinct = pile
                    .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
                    .unwrap();
                let rank9 = pile
                    .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy.clone())
                    .unwrap();
                drop(pile.maintain(succinct, &signer).await.unwrap());
                drop(pile.maintain(rank9, &signer).await.unwrap());
                if scope == health::DEFAULT_SCOPE_ID {
                    let latest = pile
                        .derive::<LwwRegisterBlob>(
                            source,
                            (
                                health::attrs::node.id(),
                                triblespace::core::metadata::created_at.id(),
                            ),
                            policy,
                        )
                        .unwrap();
                    drop(pile.maintain(latest, &signer).await.unwrap());
                }
            }
            let status =
                faculties::compass::status_register_collection(&mut pile, signer.verifying_key())
                    .unwrap();
            drop(pile.maintain(status, &signer).await.unwrap());
            let latest =
                faculties::wiki::latest_collection(&mut pile, signer.verifying_key()).unwrap();
            drop(pile.maintain(latest, &signer).await.unwrap());
        });
        pile.close().unwrap();
    }

    fn records(&self) -> Vec<CollectionRecord> {
        let mut pile = faculties::storage::open_pile_strict(&self.pile).unwrap();
        let records = pile
            .snapshot()
            .unwrap()
            .records()
            .unwrap()
            .map(Result::unwrap)
            .collect();
        pile.close().unwrap();
        records
    }
    fn message(&self, text: &str, to: Id) -> Id {
        let mut fragment = Fragment::empty();
        let body = fragment.put(text.to_owned());
        let envelope = faculties::message::envelope_fragment(
            self.sender,
            to,
            body,
            faculties::clock::point_now().unwrap(),
            None,
            None,
        );
        let id = envelope.root().unwrap();
        fragment += envelope;
        self.publish(faculties::schemas::message::DEFAULT_SCOPE_ID, fragment);
        id
    }
    fn person(&self, person: Id) {
        let (fragment, _, _) = faculties::relations::person_fragment(
            person,
            faculties::relations::ProfileInput {
                label: format!("observer-{person:x}"),
                ..Default::default()
            },
        )
        .unwrap();
        self.publish(faculties::schemas::relations::DEFAULT_SCOPE_ID, fragment);
    }
    fn call(&self, tool: &str, args: Value) -> Vec<Part> {
        let mut parts = Vec::new();
        self.adapter()
            .call(
                tool,
                serde_json::to_vec(&args).unwrap().into(),
                &mut Out::new(&mut |part| {
                    parts.push(part);
                    Ok(())
                }),
            )
            .unwrap();
        parts
    }

    fn health_recorder(&self) -> Recorder {
        let signer = faculties::storage::load_signer(&self.pile, Some(&self.key)).unwrap();
        Recorder::new(signer.verifying_key())
    }

    fn health(
        &self,
        recorder: &mut Recorder,
        at: hifitime::Epoch,
        state: State,
        alert: bool,
    ) -> Fragment {
        let facts = recorder
            .record(
                at,
                [Condition {
                    component: Component::Dht,
                    collection: None,
                    peer: None,
                    state,
                    alert,
                }],
            )
            .unwrap();
        self.publish(health::DEFAULT_SCOPE_ID, facts.clone());
        facts
    }

    fn presented(&self) -> std::collections::BTreeSet<Id> {
        let signer = faculties::storage::load_signer(&self.pile, Some(&self.key)).unwrap();
        let mut store = faculties::storage::open_pile_strict(&self.pile).unwrap();
        let collection = faculties::collection_names::open_configured(
            &mut store,
            faculties::schemas::orient::DEFAULT_SCOPE_ID,
            signer.verifying_key(),
        )
        .unwrap();
        let snapshot = store.snapshot().unwrap();
        let (facts, _) = faculties::storage::read_fact_collection(collection, &snapshot).unwrap();
        faculties::orient::presented_events(&facts, self.persona)
    }
}
fn text(parts: &[Part]) -> String {
    parts
        .iter()
        .map(|p| match p {
            Part::Text { text } => text.as_str(),
            _ => panic!("text expected"),
        })
        .collect()
}

#[test]
fn authorized_readers_leave_lagging_targets_to_external_maintenance() {
    let f = Fixture::new();
    // Register and maintain the private projections under this same signer:
    // these reads have WRITE, but that is not a request to produce equations.
    f.maintain();
    let event = f.message("visible only after external upkeep", f.persona);
    let (goal, _) = faculties::compass::goal_fragment(
        "a goal still outside the resident projection",
        Vec::new(),
        None,
        faculties::clock::point_now().unwrap(),
    )
    .unwrap();
    f.publish(faculties::schemas::compass::DEFAULT_SCOPE_ID, goal);
    let before = f.records();
    assert!(f
        .call("orient_poll", json!({"persona": f.who()}))
        .is_empty());
    assert!(f
        .call("orient_poll", json!({"persona": f.who(), "peek": false}))
        .is_empty());
    let show = text(&f.call("orient_show", json!({})));
    let wake = text(&f.call("orient_wake", json!({"chars": 0})));
    for report in [&show, &wake] {
        assert!(!report.contains("visible only after external upkeep"));
        assert!(!report.contains("a goal still outside the resident projection"));
    }
    let options = WaitOptions {
        timeout: Some(Duration::from_millis(10)),
        poll_interval: Duration::from_millis(2),
    };
    let mut parts = Vec::new();
    f.orient()
        .wait(
            &f.who(),
            &options,
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
    assert!(text(&parts).contains("No change detected"));
    assert_eq!(
        f.records(),
        before,
        "ordinary reads must append no COMMIT, MERGE or DERIVE"
    );

    // A separate producer catches up the targets. The next one-shot wait can
    // deliver the message; its only signed output is the explicit receipt.
    f.maintain();
    let before_delivery = f.records();
    let peek = f.call("orient_poll", json!({"persona": f.who()}));
    assert!(text(&peek).contains("visible only after external upkeep"));
    assert_eq!(f.records(), before_delivery);
    parts.clear();
    f.orient()
        .wait(
            &f.who(),
            &options,
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
    assert!(text(&parts).contains("visible only after external upkeep"));
    assert!(f.presented().contains(&event));
    let after_delivery = f.records();
    let appended: Vec<_> = after_delivery
        .iter()
        .filter(|record| !before_delivery.contains(record))
        .collect();
    assert_eq!(appended.len(), 1);
    assert!(matches!(appended[0], CollectionRecord::Commit(_)));

    // The next operation freezes the receipt COMMIT even while its target is
    // behind. It must wait, not replay the message or derive its own receipt.
    assert!(f
        .call("orient_poll", json!({"persona": f.who(), "peek": false}))
        .is_empty());
    parts.clear();
    f.orient()
        .wait(
            &f.who(),
            &options,
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
    assert!(text(&parts).contains("No fully readable attention view"));
    assert!(!text(&parts).contains("visible only after external upkeep"));
    assert_eq!(f.records(), after_delivery);

    f.maintain();
    let after_upkeep = f.records();
    assert!(f
        .call("orient_poll", json!({"persona": f.who()}))
        .is_empty());
    parts.clear();
    f.orient()
        .wait(
            &f.who(),
            &options,
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
    assert!(text(&parts).contains("No change detected"));
    assert_eq!(f.records(), after_upkeep);
}

#[test]
fn poll_defaults_to_peek_and_consumption_is_exact_persona_scoped() {
    let f = Fixture::new();
    let body = "@literal pending news";
    f.message(body, f.persona);
    f.maintain();
    let first = f.call("orient_poll", json!({"persona":f.who()}));
    assert!(text(&first).contains(body));
    assert_eq!(first, f.call("orient_poll", json!({"persona":f.who()})));
    let mut direct = Vec::new();
    f.orient()
        .poll(
            &f.who(),
            true,
            &mut Out::new(&mut |p| {
                direct.push(p);
                Ok(())
            }),
        )
        .unwrap();
    assert_eq!(first, direct);
    assert_eq!(first, f.cli(&["--persona", &f.who(), "poll", "--peek"]));
    assert_eq!(
        first,
        f.call("orient_poll", json!({"persona":f.who(),"peek":false}))
    );
    f.maintain();
    assert!(f.call("orient_poll", json!({"persona":f.who()})).is_empty());
    let other = *fucid();
    f.person(other);
    f.message("another observer", other);
    f.maintain();
    assert!(f.call("orient_poll", json!({"persona":f.who()})).is_empty());
    assert!(
        text(&f.call("orient_poll", json!({"persona":format!("{other:x}")})))
            .contains("another observer")
    );
}

#[test]
fn rejected_complete_report_is_retryable_and_does_not_present() {
    let f = Fixture::new();
    f.message("delivery must succeed", f.persona);
    f.maintain();
    let expected = f.call("orient_poll", json!({"persona":f.who()}));
    let mut attempted = Vec::new();
    let error = f
        .orient()
        .poll(
            &f.who(),
            false,
            &mut Out::new(&mut |p| {
                attempted.push(p);
                anyhow::bail!("rejected delivery")
            }),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("rejected delivery"));
    assert_eq!(attempted, expected);
    assert_eq!(expected, f.call("orient_poll", json!({"persona":f.who()})));
    assert_eq!(
        expected,
        f.call("orient_poll", json!({"persona":f.who(),"peek":false}))
    );
    f.maintain();
    assert!(f.call("orient_poll", json!({"persona":f.who()})).is_empty());
}

#[test]
fn passive_show_never_executes_habit_conditions_and_opt_in_evaluates_once() {
    let f = Fixture::new();
    let marker = f.directory.path().join("habit-invocations");
    let (habit, _) = faculties::habits::habit_fragment(
        "probe",
        "when printf x >> habit-invocations",
        "probe due",
        None,
        &[],
        &[],
    )
    .unwrap();
    f.publish(faculties::schemas::habit::DEFAULT_SCOPE_ID, habit);
    f.maintain();
    let passive = f.call("orient_show", json!({}));
    assert!(text(&passive).contains("probe (not evaluated)"));
    assert!(!marker.exists());
    let mut direct = Vec::new();
    f.orient()
        .show(
            None,
            &ShowOptions {
                evaluate_habits: false,
                ..Default::default()
            },
            &mut Out::new(&mut |p| {
                direct.push(p);
                Ok(())
            }),
        )
        .unwrap();
    assert_eq!(direct, passive);
    assert!(!marker.exists());
    let active = f.call("orient_show", json!({"evaluate_habits":true}));
    assert!(text(&active).contains("probe due"));
    assert_eq!(fs::read(&marker).unwrap(), b"x");
    let cli = f.cli(&["show"]);
    assert_eq!(cli, active);
    assert_eq!(fs::read(&marker).unwrap(), b"xx");
    let wake = f.call("orient_wake", json!({"chars":0}));
    assert!(text(&wake).contains("Beliefs (cover):"));
    assert_eq!(fs::read(&marker).unwrap(), b"xx");
}

#[test]
fn show_only_loads_and_evaluates_global_or_matching_persona_habits() {
    let f = Fixture::new();
    for (label, targets) in [
        ("global-clock", vec![]),
        ("my-clock", vec![f.persona]),
        ("their-clock", vec![f.sender]),
    ] {
        let (habit, _) = faculties::habits::habit_fragment(
            label,
            format!("when printf x >> {label}"),
            format!("{label} due"),
            None,
            &[],
            &targets,
        )
        .unwrap();
        f.publish(faculties::schemas::habit::DEFAULT_SCOPE_ID, habit);
    }
    f.maintain();
    let passive = text(&f.call("orient_show", json!({"persona": f.who()})));
    assert!(passive.contains("global-clock (not evaluated)"));
    assert!(passive.contains("my-clock (not evaluated)"));
    assert!(!passive.contains("their-clock"));
    for label in ["global-clock", "my-clock", "their-clock"] {
        assert!(!f.directory.path().join(label).exists());
    }
    let global_only = text(&f.call("orient_show", json!({})));
    assert!(global_only.contains("global-clock"));
    assert!(!global_only.contains("my-clock"));
    assert!(!global_only.contains("their-clock"));
    let active = f.call(
        "orient_show",
        json!({"persona": f.who(), "evaluate_habits": true}),
    );
    f.maintain();
    let cli = f.cli(&["--persona", &f.who(), "show"]);
    assert_eq!(active, cli);
    assert!(text(&active).contains("my-clock due"));
    assert!(!text(&active).contains("their-clock"));
    assert_eq!(
        fs::read(f.directory.path().join("my-clock")).unwrap(),
        b"xx"
    );
    assert_eq!(
        fs::read(f.directory.path().join("global-clock")).unwrap(),
        b"xx"
    );
    assert!(!f.directory.path().join("their-clock").exists());
}

#[test]
fn show_limits_present_only_selected_events_and_baseline_discards_backlog_explicitly() {
    let f = Fixture::new();
    f.message("first item", f.persona);
    f.message("second item", f.persona);
    f.maintain();
    let report = f.call(
        "orient_show",
        json!({"persona":f.who(),"message_limit":1,"doing_limit":0,"todo_limit":0}),
    );
    let shown = text(&report);
    assert_eq!(
        usize::from(shown.contains("first item")) + usize::from(shown.contains("second item")),
        1
    );
    f.maintain();
    let pending = text(&f.call("orient_poll", json!({"persona":f.who()})));
    assert_eq!(
        usize::from(pending.contains("first item")) + usize::from(pending.contains("second item")),
        1
    );
    let receipt = f.orient().baseline(&f.who()).unwrap();
    assert_eq!(receipt.persona, f.persona);
    assert_eq!(
        receipt.events, 2,
        "baseline records the complete current attention set, including already presented entries"
    );
    f.maintain();
    assert!(f.call("orient_poll", json!({"persona":f.who()})).is_empty());
}

#[test]
fn a_one_shot_wait_reports_once_and_missing_persona_poll_remains_quiet() {
    let f = Fixture::new();
    assert!(f
        .call("orient_poll", json!({"persona":"not-yet-resident"}))
        .is_empty());
    f.message("ready before wait", f.persona);
    f.maintain();
    let mut parts = Vec::new();
    f.orient()
        .wait(
            &f.who(),
            &WaitOptions {
                timeout: Some(Duration::ZERO),
                poll_interval: Duration::from_millis(1),
            },
            &mut Out::new(&mut |p| {
                parts.push(p);
                Ok(())
            }),
        )
        .unwrap();
    assert_eq!(parts.len(), 1);
    assert!(text(&parts).contains("ready before wait"));
    f.maintain();
    assert!(f.call("orient_poll", json!({"persona":f.who()})).is_empty());
    let mut wake = Vec::new();
    f.orient()
        .wake(
            None,
            &WakeOptions {
                chars: 0,
                ..Default::default()
            },
            &mut Out::new(&mut |p| {
                wake.push(p);
                Ok(())
            }),
        )
        .unwrap();
    assert_eq!(wake, f.call("orient_wake", json!({"chars":0})));
}

#[test]
fn mcp_is_finite_and_rejects_host_config_waits_and_duplicate_fields() {
    let directory = tempfile::tempdir().unwrap();
    let adapter = mcp::Orient::new(directory.path().join("absent.pile"), None);
    assert_eq!(adapter.tools().len(), 4);
    Server::new(&[&adapter]).unwrap();
    assert!(!adapter.tools().iter().any(|t| t.name.contains("wait")));
    for (tool, args) in [
        ("orient_show", r#"{"pile":"/host/pile"}"#),
        (
            "orient_show",
            r#"{"evaluate_habits":false,"evaluate_habits":true}"#,
        ),
        ("orient_show", "[]"),
        ("orient_poll", r#"{"peek":true}"#),
        ("orient_poll", r#"{"persona":"p","poll_ms":10}"#),
        ("orient_wake", r#"{"key":"@/host/key"}"#),
        ("orient_baseline", r#"{"persona":"p","persona":"q"}"#),
    ] {
        let error = adapter
            .call(
                tool,
                Bytes::from(args),
                &mut Out::new(&mut |_| anyhow::bail!("unexpected output")),
            )
            .unwrap_err();
        assert!(
            error.downcast_ref::<InvalidArguments>().is_some(),
            "{tool}: {error:#}"
        );
    }
}

#[test]
fn local_health_episodes_are_peekable_and_cli_mcp_share_the_presentation_ledger() {
    let f = Fixture::new();
    let at = faculties::clock::now().unwrap();
    let mut recorder = f.health_recorder();
    let failure = f.health(&mut recorder, at + -30.0, State::Stalled, true);
    let issues: std::collections::BTreeSet<Id> = find!(event: Id, pattern!(failure.facts(), [{
        ?event @ triblespace::core::metadata::tag: &health::KIND_ALERT,
    }]))
    .collect();
    assert_eq!(issues.len(), 1);
    f.maintain();
    let cli = f.cli(&["--persona", &f.who(), "poll", "--peek"]);
    assert!(text(&cli).contains("DHT publication: stalled"));
    assert!(!text(&cli).contains("Swarm health (local observations)"));
    assert!(!text(&cli).contains("do not prove blob availability"));
    assert!(f.presented().is_empty());
    assert!(text(&f.call("orient_poll", json!({"persona":f.who()})))
        .contains("DHT publication: stalled"));
    assert!(f.presented().is_empty());
    f.call("orient_poll", json!({"persona":f.who(),"peek":false}));
    assert_eq!(f.presented(), issues);

    f.health(&mut recorder, at + -20.0, State::Stalled, true);
    f.maintain();
    assert!(f.call("orient_poll", json!({"persona":f.who()})).is_empty());
    f.health(&mut recorder, at + -10.0, State::Current, false);
    f.maintain();
    assert!(f
        .call("orient_poll", json!({"persona":f.who(),"peek":false}))
        .is_empty());
    f.health(&mut recorder, at, State::Current, false);
    f.maintain();
    assert!(f.call("orient_poll", json!({"persona":f.who()})).is_empty());
}

#[test]
fn health_is_visible_before_unavailable_message_bodies_and_wait_records_only_what_it_shows() {
    let f = Fixture::new();
    let mut recorder = f.health_recorder();
    let facts = f.health(
        &mut recorder,
        faculties::clock::now().unwrap() + -600.0,
        State::Current,
        false,
    );
    let report = facts.root().unwrap();
    // This attachment exists only in an uncommitted fixture fragment. Its
    // envelope is resident, so the ordinary attention path would need a fetch.
    let mut unattached = Fragment::empty();
    let body = unattached.put("test-only unavailable body".to_owned());
    let envelope = faculties::message::envelope_fragment(
        f.sender,
        f.persona,
        body,
        faculties::clock::point_now().unwrap(),
        None,
        None,
    );
    let message = envelope.root().unwrap();
    f.publish(faculties::schemas::message::DEFAULT_SCOPE_ID, envelope);
    f.maintain();
    let news = f.call("orient_poll", json!({"persona":f.who()}));
    assert!(text(&news).contains("report exceeds reader maximum age; current health unknown"));
    assert!(!text(&news).contains("unavailable body"));
    assert!(f.presented().is_empty());
    let mut parts = Vec::new();
    f.orient()
        .wait(
            &f.who(),
            &WaitOptions {
                timeout: Some(Duration::ZERO),
                poll_interval: Duration::from_millis(1),
            },
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
    assert!(text(&parts).contains("report exceeds reader maximum age; current health unknown"));
    assert_eq!(f.presented(), std::collections::BTreeSet::from([report]));
    assert!(!f.presented().contains(&message));
}

#[test]
fn health_max_age_is_reader_owned_across_native_cli_mcp_and_baseline() {
    let f = Fixture::new();
    let mut recorder = f.health_recorder();
    let facts = f.health(
        &mut recorder,
        faculties::clock::now().unwrap() + -600.0,
        State::Current,
        false,
    );
    let report = facts.root().unwrap();

    f.maintain();
    assert!(f
        .cli(&[
            "--persona",
            &f.who(),
            "poll",
            "--peek",
            "--health-max-age",
            "3600",
        ])
        .is_empty());
    assert!(text(&f.cli(&[
        "--persona",
        &f.who(),
        "--health-max-age",
        "60",
        "poll",
        "--peek",
    ]))
    .contains("report exceeds reader maximum age"));
    assert!(f
        .call(
            "orient_poll",
            json!({
                "persona": f.who(), "health_max_age_secs": 3600,
            })
        )
        .is_empty());
    assert!(text(&f.call(
        "orient_poll",
        json!({
            "persona": f.who(), "health_max_age_secs": 60,
        })
    ))
    .contains("report exceeds reader maximum age"));
    assert!(
        text(&f.call("orient_show", json!({"health_max_age_secs": 60})))
            .contains("unknown (report too old)")
    );
    assert!(
        !text(&f.call("orient_show", json!({"health_max_age_secs": 3600})))
            .contains("report too old")
    );

    let mut parts = Vec::new();
    f.orient()
        .with_health_max_age(Duration::from_secs(3600))
        .poll(
            &f.who(),
            true,
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
    assert!(parts.is_empty());
    assert!(f.presented().is_empty());
    f.call(
        "orient_baseline",
        json!({"persona": f.who(), "health_max_age_secs": 3600}),
    );
    assert!(!f.presented().contains(&report));
    f.call(
        "orient_baseline",
        json!({"persona": f.who(), "health_max_age_secs": 60}),
    );
    assert!(f.presented().contains(&report));
}

#[test]
fn wait_uses_the_same_reader_max_age_as_poll_and_show() {
    let f = Fixture::new();
    let mut recorder = f.health_recorder();
    let report = f
        .health(
            &mut recorder,
            faculties::clock::now().unwrap() + -600.0,
            State::Current,
            false,
        )
        .root()
        .unwrap();
    f.maintain();
    let options = WaitOptions {
        timeout: Some(Duration::ZERO),
        poll_interval: Duration::from_millis(1),
    };
    let mut parts = Vec::new();
    f.orient()
        .with_health_max_age(Duration::from_secs(3600))
        .wait(
            &f.who(),
            &options,
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
    assert!(!text(&parts).contains("News:"));
    assert!(f.presented().is_empty());
    parts.clear();
    f.orient()
        .with_health_max_age(Duration::from_secs(60))
        .wait(
            &f.who(),
            &options,
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
    assert!(text(&parts).contains("report exceeds reader maximum age"));
    assert_eq!(f.presented(), std::collections::BTreeSet::from([report]));
}

#[test]
fn quiet_health_does_not_wake_wait_and_show_acceptance_owns_its_alert_receipt() {
    let f = Fixture::new();
    assert!(text(&f.call("orient_show", json!({}))).contains("not observed / not configured"));
    let at = faculties::clock::now().unwrap();
    let mut recorder = f.health_recorder();
    f.health(&mut recorder, at + -10.0, State::Current, false);
    f.maintain();
    let mut parts = Vec::new();
    f.orient()
        .wait(
            &f.who(),
            &WaitOptions {
                timeout: Some(Duration::ZERO),
                poll_interval: Duration::from_millis(1),
            },
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
    assert!(text(&parts).contains("No change detected"));
    assert!(!text(&parts).contains("News:"));

    f.health(&mut recorder, at, State::Stalled, true);
    f.maintain();
    let error = f
        .orient()
        .show(
            Some(&f.who()),
            &ShowOptions {
                evaluate_habits: false,
                ..Default::default()
            },
            &mut Out::new(&mut |_| anyhow::bail!("health output rejected")),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("health output rejected"));
    assert!(f.presented().is_empty());
    let show = f.call("orient_show", json!({"persona":f.who()}));
    assert!(text(&show).starts_with("\nSwarm health (local observations):"));
    assert!(text(&show).contains("DHT publication: stalled"));
    assert_eq!(f.presented().len(), 1);
    f.maintain();
    assert!(f.call("orient_poll", json!({"persona":f.who()})).is_empty());
}
