use anybytes::Bytes;
use clap::Parser;
use faculties::mcp::{Faculty, InvalidArguments, Server};
use faculties::orient::{mcp, Orient, ShowOptions, WaitOptions, WakeOptions};
use faculties::out::{Out, Part};
use faculties::schemas::swarm_health::{self as health, Component, Condition, Recorder, State};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use triblespace::core::blob::encodings::entity_id_set::EntityIdSetBlob;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::lww_register::LwwRegisterBlob;
use triblespace::core::collection::{
    CollectionRead, CollectionRecord, CollectionStore, CollectionStoreExt,
};
use triblespace::core::metadata;
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
    fn process(&self, trace: Option<&str>) -> std::process::Command {
        self.process_with_key(&self.key, trace)
    }
    fn process_with_key(&self, key: &Path, trace: Option<&str>) -> std::process::Command {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_orient"));
        command
            .args([
                "--pile",
                self.pile.to_str().unwrap(),
                "--key",
                key.to_str().unwrap(),
            ])
            .args(["--persona", &self.who()])
            .env_remove("ORIENT_TRACE_REFRESH");
        for (name, _) in std::env::vars_os() {
            if name
                .to_string_lossy()
                .starts_with(faculties::collection_names::COLLECTION_OVERRIDE_PREFIX)
            {
                command.env_remove(name);
            }
        }
        if let Some(trace) = trace {
            command.env("ORIENT_TRACE_REFRESH", trace);
        }
        command
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
        self.maintain_receipts(&self.key);
    }

    fn maintain_receipts(&self, key: &Path) {
        let signer = faculties::storage::load_signer(&self.pile, Some(key)).unwrap();
        let mut pile = faculties::storage::open_pile_strict(&self.pile).unwrap();
        let policy = faculties::collection_names::private_policy(signer.verifying_key());
        let source = pile
            .collection(
                faculties::schemas::orient::RECEIPT_COLLECTION_NAME,
                policy.clone(),
            )
            .unwrap();
        let ids = pile
            .derive::<EntityIdSetBlob>(
                source,
                faculties::schemas::orient::presentation::event.id(),
                policy,
            )
            .unwrap();
        drop(pollster::block_on(pile.maintain(ids, &signer)).unwrap());
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
        self.presented_by(&self.key)
    }

    fn presented_by(&self, key: &Path) -> std::collections::BTreeSet<Id> {
        let signer = faculties::storage::load_signer(&self.pile, Some(key)).unwrap();
        let mut store = faculties::storage::open_pile_strict(&self.pile).unwrap();
        let collection = store
            .collection(
                faculties::schemas::orient::RECEIPT_COLLECTION_NAME,
                faculties::collection_names::private_policy(signer.verifying_key()),
            )
            .unwrap();
        let snapshot = store.snapshot().unwrap();
        let (facts, _) = faculties::storage::read_fact_collection(collection, &snapshot).unwrap();
        find!(event: Id, pattern!(&facts, [{
            _?receipt @ faculties::schemas::orient::presentation::event: ?event,
        }]))
        .collect()
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
fn daemon_keeps_observing_after_delivery_and_records_only_accepted_reports() {
    let f = Fixture::new();
    let first = f.message("daemon first delivery", f.persona);
    let mut second = None;
    let mut parts = Vec::new();
    f.orient()
        .daemon(
            &f.who(),
            &WaitOptions {
                timeout: Some(Duration::from_secs(2)),
                poll_interval: Duration::from_millis(10),
            },
            &mut Out::new(&mut |part| {
                let Part::Text { text } = &part else {
                    panic!("text expected")
                };
                assert!(text.starts_with("News: "), "not a delivery: {text}");
                if second.is_none() {
                    assert!(text.contains("daemon first delivery"));
                    assert!(
                        !f.presented().contains(&first),
                        "receipt precedes acceptance"
                    );
                    // A real second Pile owner appends while the daemon remains
                    // inside the same operation. No external maintenance call.
                    second = Some(f.message("daemon subsequent arrival", f.persona));
                }
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
    assert_eq!(
        parts.len(),
        2,
        "neither receipt writes nor timeout are news: {parts:?}"
    );
    assert!(text(&parts[1..]).contains("daemon subsequent arrival"));
    let receipts = f.presented();
    assert!(receipts.contains(&first));
    assert!(receipts.contains(&second.unwrap()));
    let restarted = f.call("orient_poll", json!({"persona": f.who()}));
    assert!(
        restarted.is_empty(),
        "accepted reports must remain seen after close"
    );
}

#[test]
fn daemon_failed_delivery_is_not_seen_and_is_not_retried_in_process() {
    let f = Fixture::new();
    let event = f.message("daemon rejected report", f.persona);
    let mut calls = 0;
    let result = f.orient().daemon(
        &f.who(),
        &WaitOptions::default(),
        &mut Out::new(&mut |_| {
            calls += 1;
            anyhow::bail!("injected delivery failure")
        }),
    );
    assert!(format!("{:#}", result.unwrap_err()).contains("injected delivery failure"));
    assert_eq!(calls, 1);
    assert!(!f.presented().contains(&event));
    assert!(text(&f.call("orient_poll", json!({"persona": f.who()})))
        .contains("daemon rejected report"));
}

#[test]
fn daemon_retains_due_habit_baseline_across_other_news_and_own_receipts() {
    let f = Fixture::new();
    let (habit, _) = faculties::habits::habit_fragment(
        "daemon clock",
        "every 1h",
        "do the thing",
        None,
        &[],
        &[f.persona],
    )
    .unwrap();
    f.publish(faculties::schemas::habit::DEFAULT_SCOPE_ID, habit);
    let mut parts = Vec::new();
    f.orient()
        .daemon(
            &f.who(),
            &WaitOptions {
                timeout: Some(Duration::from_secs(2)),
                poll_interval: Duration::from_millis(10),
            },
            &mut Out::new(&mut |part| {
                if parts.is_empty() {
                    assert!(text(std::slice::from_ref(&part)).contains("daemon clock"));
                    f.message("unrelated to unchanged due clock", f.persona);
                }
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
    let report = text(&parts);
    assert_eq!(report.matches("News: habit [").count(), 1, "{report}");
    assert!(report.contains("unrelated to unchanged due clock"));
    assert_eq!(
        parts.len(),
        2,
        "timeout must be silent and due state must not spin"
    );
}

#[test]
#[cfg(unix)]
fn daemon_cli_has_one_callback_channel_and_failure_does_not_acknowledge() {
    for success in [true, false] {
        let f = Fixture::new();
        let event = f.message("one callback, no stdout copy", f.persona);
        let report = f.directory.path().join("delivered");
        let code = if success { "0" } else { "7" };
        let result = f
            .process(None)
            .args([
                "daemon",
                "--poll-ms",
                "10",
                "--run-for",
                "1s",
                "--callback",
                "/bin/sh",
                "--callback-arg=-c",
                "--callback-arg",
                "cat >> \"$1\"; printf 'not another report'; exit \"$2\"",
                "--callback-arg",
                "delivery",
                "--callback-arg",
            ])
            .arg(&report)
            .args(["--callback-arg", code])
            .output()
            .unwrap();
        assert_eq!(result.status.success(), success, "{:?}", result);
        assert!(
            result.stdout.is_empty(),
            "callback output must not duplicate news"
        );
        let delivered = fs::read_to_string(report).unwrap();
        assert_eq!(delivered.matches("News: new message [").count(), 1);
        assert_eq!(f.presented().contains(&event), success);
    }
}

#[test]
#[cfg(unix)]
fn daemon_sigterm_closes_normally_after_delivery() {
    let f = Fixture::new();
    let event = f.message("stop the persistent observer", f.persona);
    let report = f.directory.path().join("delivered");
    let child = f
        .process(None)
        .args([
            "daemon",
            "--poll-ms",
            "10",
            "--run-for",
            "10s",
            "--callback",
            "/bin/sh",
            "--callback-arg=-c",
            "--callback-arg",
            "cat > \"$1\"",
            "--callback-arg",
            "delivery",
            "--callback-arg",
        ])
        .arg(&report)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let started = std::time::Instant::now();
    while !report.exists() && started.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
    }
    // The callback and receipt publication complete synchronously before the
    // observer yields to its signal boundary.
    let signalled = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let result = child.wait_with_output().unwrap();
    assert!(report.exists(), "daemon never delivered: {:?}", result);
    assert_eq!(signalled, 0);
    assert!(result.status.success(), "normal close: {:?}", result);
    assert!(result.stdout.is_empty());
    assert!(f.presented().contains(&event));
}

#[test]
fn refresh_probe_is_opt_in_stderr_only_and_preserves_peek() {
    let f = Fixture::new();
    f.message("diagnostic must not change the report", f.persona);
    f.maintain();
    let before = f.records();
    let plain = f.process(None).args(["poll", "--peek"]).output().unwrap();
    let disabled = f
        .process(Some("0"))
        .args(["poll", "--peek"])
        .output()
        .unwrap();
    let traced = f
        .process(Some("1"))
        .args(["poll", "--peek"])
        .output()
        .unwrap();
    for result in [&plain, &disabled, &traced] {
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    assert_eq!(plain.stdout, traced.stdout);
    assert_eq!(plain.stdout, disabled.stdout);
    assert!(!String::from_utf8_lossy(&plain.stderr).contains("ORIENT_TRACE_REFRESH"));
    assert!(!String::from_utf8_lossy(&disabled.stderr).contains("ORIENT_TRACE_REFRESH"));
    let stderr = String::from_utf8(traced.stderr).unwrap();
    for stage in ["stage=attach", "stage=view", "stage=query"] {
        assert!(stderr.contains(stage), "{stderr}");
    }
    assert!(!stderr.contains("diagnostic must not change the report"));
    assert_eq!(f.records(), before);
}

#[test]
fn refresh_probe_skips_unrelated_blobs_and_collection_records() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    use std::sync::mpsc;
    use triblespace::core::blob::encodings::UnknownBlob;

    let f = Fixture::new();
    f.maintain();
    let before = f.records();
    let mut child = f
        .process(Some("1"))
        .args(["wait", "--poll-ms", "20", "for", "2s"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (ready, received) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut output = String::new();
        let mut signalled = false;
        for line in BufReader::new(stderr).lines() {
            let line = line.unwrap();
            if !signalled
                && line.contains("event=end")
                && line.contains("scope=ordinary outcome=ready")
            {
                let _ = ready.send(());
                signalled = true;
            }
            output.push_str(&line);
            output.push('\n');
        }
        output
    });
    if received.recv_timeout(Duration::from_secs(10)).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("wait did not become ready: {}", reader.join().unwrap());
    }
    // Neither append changes any collection this observation consulted.
    let mut pile = faculties::storage::open_pile_strict(&f.pile).unwrap();
    pile.put::<UnknownBlob, _>(Bytes::from(b"unrelated hydration probe".to_vec()))
        .unwrap();
    let signer = faculties::storage::load_signer(&f.pile, Some(&f.key)).unwrap();
    let unrelated = pile
        .collection(
            "unrelated-refresh-probe",
            faculties::collection_names::private_policy(signer.verifying_key()),
        )
        .unwrap();
    let appended = pile
        .commit(unrelated, &signer, entity! { metadata::tag: f.persona })
        .unwrap();
    pile.close().unwrap();
    let result = child.wait_with_output().unwrap();
    let stderr = reader.join().unwrap();
    assert!(result.status.success(), "{stderr}");
    assert!(String::from_utf8_lossy(&result.stdout).contains("No change detected"));
    for target in ["Message", "Swarm health"] {
        assert_eq!(
            stderr
                .lines()
                .filter(|line| line.contains("event=stage")
                    && line.contains(&format!("target={target:?}"))
                    && line.contains("stage=attach"))
                .count(),
            1,
            "an unrelated append must not repeat {target} attachment: {stderr}"
        );
    }
    let after = f.records();
    assert_eq!(after.len(), before.len() + 1);
    assert!(after.contains(&CollectionRecord::Commit(appended)));
    assert!(before.iter().all(|record| after.contains(record)));
}

#[test]
fn wait_refreshes_an_arriving_message_target_without_rebuilding_health() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    use std::sync::mpsc;

    let f = Fixture::new();
    f.maintain();
    let mut child = f
        .process(Some("1"))
        .args(["wait", "--poll-ms", "20", "for", "10s"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (ready, received) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut output = String::new();
        let mut signalled = false;
        for line in BufReader::new(stderr).lines() {
            let line = line.unwrap();
            if !signalled
                && line.contains("event=end")
                && line.contains("scope=ordinary outcome=ready")
            {
                let _ = ready.send(());
                signalled = true;
            }
            output.push_str(&line);
            output.push('\n');
        }
        output
    });
    if received.recv_timeout(Duration::from_secs(10)).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("wait did not become ready: {}", reader.join().unwrap());
    }
    let event = f.message("this target arrived after the wait observation", f.persona);
    // Only the raw source arrives: the active waiter owns its eager catch-up.
    let result = child.wait_with_output().unwrap();
    let stderr = reader.join().unwrap();
    assert!(result.status.success(), "{stderr}");
    assert!(String::from_utf8_lossy(&result.stdout)
        .contains("this target arrived after the wait observation"));
    for (target, count) in [("Message", 2), ("Swarm health", 1)] {
        assert_eq!(
            stderr
                .lines()
                .filter(|line| line.contains("event=stage")
                    && line.contains(&format!("target={target:?}"))
                    && line.contains("stage=attach"))
                .count(),
            count,
            "only the changed target should be attached again: {stderr}"
        );
    }
    assert!(f.presented().contains(&event));
}

#[test]
fn authorized_reporting_frontends_maintain_lagging_targets_without_a_daemon() {
    for frontend in ["poll", "show", "wake", "wait"] {
        let f = Fixture::new();
        // Start with registered, exact targets, then append only raw source
        // commits. Each fresh fixture makes this frontend own the catch-up.
        f.maintain();
        let body = "visible through eager reader upkeep";
        let title = "a goal carried by the reporting frontend";
        let event = f.message(body, f.persona);
        let (goal, _) = faculties::compass::goal_fragment(
            title,
            Vec::new(),
            None,
            faculties::clock::point_now().unwrap(),
        )
        .unwrap();
        f.publish(faculties::schemas::compass::DEFAULT_SCOPE_ID, goal);
        let before = f.records();
        let report = match frontend {
            "poll" => text(&f.call("orient_poll", json!({"persona": f.who()}))),
            "show" => text(&f.call("orient_show", json!({"persona": f.who()}))),
            "wake" => text(&f.call("orient_wake", json!({"chars": 0}))),
            "wait" => {
                let mut parts = Vec::new();
                f.orient()
                    .wait(
                        &f.who(),
                        &WaitOptions {
                            timeout: Some(Duration::from_secs(5)),
                            poll_interval: Duration::from_millis(2),
                        },
                        &mut Out::new(&mut |part| {
                            parts.push(part);
                            Ok(())
                        }),
                    )
                    .unwrap();
                text(&parts)
            }
            _ => unreachable!(),
        };
        if frontend == "wake" {
            assert!(report.contains(title), "{frontend}: {report}");
        } else {
            assert!(report.contains(body), "{frontend}: {report}");
        }
        if frontend == "show" {
            assert!(report.contains(title), "{report}");
        }
        let after = f.records();
        let appended: Vec<_> = after
            .iter()
            .filter(|record| !before.contains(record))
            .collect();
        assert!(
            appended
                .iter()
                .any(|record| matches!(record, CollectionRecord::Derive(_))),
            "{frontend} must carry the raw input before reporting"
        );
        assert!(before.iter().all(|record| after.contains(record)));
        if matches!(frontend, "show" | "wait") {
            assert!(f.presented().contains(&event));
            // A fresh reporting call catches up its own receipt projection;
            // no external upkeep call is inserted to hide a duplicate.
            assert!(f
                .call("orient_poll", json!({"persona": f.who()}))
                .is_empty());
        } else {
            assert!(
                f.presented().is_empty(),
                "{frontend} must remain non-consuming"
            );
            assert!(appended.iter().all(|record| matches!(
                record,
                CollectionRecord::Merge(_) | CollectionRecord::Derive(_)
            )));
        }
    }
}

#[test]
fn poll_defaults_to_peek_and_contact_routing_remains_exact() {
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
    let before = f.records();
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
    assert_eq!(f.records(), before);
    assert!(f.presented().is_empty());
    assert_eq!(expected, f.call("orient_poll", json!({"persona":f.who()})));
    let mut accepted = Vec::new();
    f.orient()
        .poll(
            &f.who(),
            false,
            &mut Out::new(&mut |part| {
                assert_eq!(f.records(), before, "receipt COMMIT must follow acceptance");
                accepted.push(part);
                Ok(())
            }),
        )
        .unwrap();
    assert_eq!(expected, accepted);
    let after = f.records();
    let appended: Vec<_> = after
        .iter()
        .filter(|record| !before.contains(record))
        .collect();
    assert_eq!(appended.len(), 1);
    assert!(matches!(appended[0], CollectionRecord::Commit(_)));
    f.maintain();
    assert!(f.call("orient_poll", json!({"persona":f.who()})).is_empty());
}

#[test]
fn routing_aliases_under_one_signer_share_projected_health_receipts() {
    let f = Fixture::new();
    let other = *fucid();
    f.person(other);
    let mut recorder = f.health_recorder();
    f.health(
        &mut recorder,
        faculties::clock::now().unwrap(),
        State::Stalled,
        true,
    );
    f.maintain();
    let alias = format!("{other:x}");
    for persona in [f.who(), alias.clone()] {
        assert!(text(&f.call("orient_poll", json!({"persona": persona})))
            .contains("DHT publication: stalled"));
    }
    assert!(
        text(&f.call("orient_poll", json!({"persona": f.who(), "peek": false})))
            .contains("DHT publication: stalled")
    );
    // The other routing alias is the first reader after acceptance. Its eager
    // upkeep must observe the same signer-owned receipt without a daemon.
    assert!(f.call("orient_poll", json!({"persona": alias})).is_empty());
    assert!(f
        .call("orient_poll", json!({"persona": f.who()}))
        .is_empty());
    assert!(f.call("orient_poll", json!({"persona": alias})).is_empty());
}

#[test]
fn distinct_signers_keep_private_receipts_over_shared_domain_views() {
    use triblespace::core::collection::grant_collection_read;

    let f = Fixture::new();
    let event = f.message("one shared inbox, two zooids", f.persona);
    f.maintain();
    let other_key = f.directory.path().join("other-zooid.key");
    let other = faculties::storage::initialize_signer(&f.pile, Some(&other_key)).unwrap();
    let owner = faculties::storage::load_signer(&f.pile, Some(&f.key)).unwrap();
    assert_ne!(owner.verifying_key(), other.verifying_key());
    let mut pile = faculties::storage::open_pile_strict(&f.pile).unwrap();
    let mut overrides = Vec::new();
    for scope in [
        faculties::schemas::message::DEFAULT_SCOPE_ID,
        faculties::schemas::relations::DEFAULT_SCOPE_ID,
    ] {
        let source =
            faculties::collection_names::open(&mut pile, scope, owner.verifying_key()).unwrap();
        let policy = source.policy(&pile.snapshot().unwrap()).unwrap();
        let succinct = pile
            .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
            .unwrap();
        let rank9 = pile
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
            .unwrap();
        for handle in [source.handle(), succinct.handle(), rank9.handle()] {
            grant_collection_read(&mut pile, handle, &owner, other.verifying_key()).unwrap();
        }
        overrides.push((
            faculties::collection_names::override_env_name(scope),
            hex::encode(source.handle().raw),
        ));
    }
    let first_receipts = pile
        .collection(
            faculties::schemas::orient::RECEIPT_COLLECTION_NAME,
            faculties::collection_names::private_policy(owner.verifying_key()),
        )
        .unwrap();
    let second_receipts = pile
        .collection(
            faculties::schemas::orient::RECEIPT_COLLECTION_NAME,
            faculties::collection_names::private_policy(other.verifying_key()),
        )
        .unwrap();
    assert_ne!(first_receipts, second_receipts);
    let snapshot = pile.snapshot().unwrap();
    for (collection, stranger) in [
        (first_receipts, other.verifying_key()),
        (second_receipts, owner.verifying_key()),
    ] {
        assert!(!collection.reader_is_admitted(&snapshot, stranger).unwrap());
        assert!(!collection.writer_is_admitted(&snapshot, stranger).unwrap());
    }

    // A readable old mixed-persona ledger is not the new zooid's receipt
    // source, even if deployment still supplies the legacy override.
    let legacy = faculties::collection_names::open(
        &mut pile,
        faculties::schemas::orient::DEFAULT_SCOPE_ID,
        owner.verifying_key(),
    )
    .unwrap();
    pile.commit(
        legacy,
        &owner,
        faculties::orient::presented_fragment(f.persona, [event]),
    )
    .unwrap();
    let policy = legacy.policy(&pile.snapshot().unwrap()).unwrap();
    let succinct = pile
        .derive::<SuccinctArchiveBlob>(legacy, (), policy.clone())
        .unwrap();
    let rank9 = pile
        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
        .unwrap();
    pollster::block_on(async {
        drop(pile.maintain(succinct, &owner).await.unwrap());
        drop(pile.maintain(rank9, &owner).await.unwrap());
    });
    overrides.push((
        faculties::collection_names::override_env_name(
            faculties::schemas::orient::DEFAULT_SCOPE_ID,
        ),
        hex::encode(legacy.handle().raw),
    ));
    pile.close().unwrap();

    f.call("orient_poll", json!({"persona": f.who(), "peek": false}));
    f.maintain_receipts(&f.key);
    assert!(f
        .call("orient_poll", json!({"persona": f.who()}))
        .is_empty());
    let run_other = |consume: bool| {
        let mut command = f.process_with_key(&other_key, None);
        command.envs(overrides.iter().map(|(name, value)| (name, value)));
        command.arg("poll");
        if !consume {
            command.arg("--peek");
        }
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        String::from_utf8(result.stdout).unwrap()
    };
    assert!(run_other(false).contains("one shared inbox, two zooids"));
    assert!(f.presented_by(&other_key).is_empty());
    assert!(run_other(true).contains("one shared inbox, two zooids"));
    assert_eq!(f.presented(), std::collections::BTreeSet::from([event]));
    assert_eq!(
        f.presented_by(&other_key),
        std::collections::BTreeSet::from([event])
    );
    f.maintain_receipts(&other_key);
    assert!(run_other(false).is_empty());
}

#[test]
fn missing_historical_receipt_payload_does_not_block_accepted_news() {
    use triblespace::core::collection::{records::empty_metadata_handle, CollectionCommit};
    use triblespace::core::repo::WantRead;

    let f = Fixture::new();
    let event = f.message("history is not a receipt barrier", f.persona);
    let signer = faculties::storage::load_signer(&f.pile, Some(&f.key)).unwrap();
    let mut pile = faculties::storage::open_pile_strict(&f.pile).unwrap();
    let receipts = pile
        .collection(
            faculties::schemas::orient::RECEIPT_COLLECTION_NAME,
            faculties::collection_names::private_policy(signer.verifying_key()),
        )
        .unwrap();
    let earlier = *fucid();
    pile.commit(
        receipts,
        &signer,
        faculties::orient::receipt_fragment([earlier], faculties::clock::point_now().unwrap()),
    )
    .unwrap();
    pile.close().unwrap();
    f.maintain();

    let cold =
        faculties::orient::receipt_fragment([*fucid()], faculties::clock::point_now().unwrap());
    let cold = IntoBlob::<blobencodings::SimpleArchive>::to_blob(cold.facts().clone());
    let mut pile = faculties::storage::open_pile_strict(&f.pile).unwrap();
    pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
        &signer,
        receipts.handle(),
        inlineencodings::Handle::<blobencodings::SimpleArchive>::to_hash(cold.get_handle()),
        empty_metadata_handle(),
    )))
    .unwrap();
    pile.close().unwrap();
    let before = f.records();
    let report = f.call("orient_poll", json!({"persona": f.who(), "peek": false}));
    assert!(text(&report).contains("history is not a receipt barrier"));
    assert_eq!(
        f.presented(),
        std::collections::BTreeSet::from([earlier, event])
    );
    let after = f.records();
    let appended: Vec<_> = after
        .iter()
        .filter(|record| !before.contains(record))
        .collect();
    assert_eq!(appended.len(), 1);
    assert!(
        matches!(appended[0], CollectionRecord::Commit(commit) if commit.collection() == receipts.handle())
    );
    let mut pile = faculties::storage::open_pile_strict(&f.pile).unwrap();
    let snapshot = pile.snapshot().unwrap();
    assert!(!snapshot.contains_blob(cold.get_handle()).unwrap());
    assert!(snapshot.wants().unwrap().next().is_none());
    pile.close().unwrap();
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
