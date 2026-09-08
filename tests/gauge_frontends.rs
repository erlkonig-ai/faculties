use faculties::gauge::{self, Gauge};
use faculties::mcp::{Faculty, InvalidArguments};
use faculties::out::{Out, Part};
use faculties::storage::initialize_signer;
use faculties::wiki::Wiki;
use serde_json::json;
use std::process::Command;

#[test]
fn observations_measure_the_wiki_frontier_and_both_frontends_present_them() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("gauge.pile");
    let key = directory.path().join("gauge.key");
    std::fs::File::create(&pile).unwrap();
    initialize_signer(&pile, Some(&key)).unwrap();
    let wiki = Wiki::new(pile.clone(), Some(key.clone()));
    let target = wiki
        .create("refuted", "old claim", &["refuted".into()], true)
        .unwrap();
    let source = wiki
        .create(
            "source",
            &format!("#link(\"wiki:{target:x}\")[claim]"),
            &[],
            true,
        )
        .unwrap();
    wiki.create("alone", "孤独", &[], true).unwrap();
    let gauge = Gauge::new(pile.clone(), Some(key.clone()));
    let health = gauge.health().unwrap();
    assert_eq!((health.entries, health.states, health.forks), (3, 3, 0));
    assert_eq!(
        (
            health.links.total,
            health.links.unique,
            health.links.missing
        ),
        (1, 1, 0)
    );
    assert_eq!(health.unanimous_orphans, 2);
    let tags = gauge.tags().unwrap();
    assert_eq!(
        (tags[0].tag.as_str(), tags[0].states, tags[0].entries),
        ("refuted", 1, 1)
    );
    assert_eq!(gauge.quality().unwrap()[0].revision, target);
    assert_eq!(gauge.hubs(1).unwrap().rows[0].entry.id, target);
    assert_eq!(gauge.risk().unwrap().rows[0].entry.id, source);
    assert_eq!(gauge.orphans(1).unwrap().total, 2);
    assert_eq!(gauge.orphans(1).unwrap().rows.len(), 1);
    assert!(gauge.hubs(0).unwrap().rows.is_empty());

    let adapter = gauge::mcp::Gauge::new(pile.clone(), Some(key.clone()));
    for verb in ["health", "tags", "quality", "hubs", "risk", "orphans"] {
        let mut text = String::new();
        adapter
            .call(
                &format!("gauge_{verb}"),
                serde_json::to_vec(&json!({})).unwrap().into(),
                &mut Out::new(&mut |part| {
                    let Part::Text { text: value } = part else {
                        panic!("non-text Gauge report")
                    };
                    text.push_str(&value);
                    Ok(())
                }),
            )
            .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_gauge"))
            .arg("--pile")
            .arg(&pile)
            .arg("--key")
            .arg(&key)
            .arg(verb)
            .env_remove("DRIVE_ENDPOINT")
            .env_remove("DRIVE_KEY")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8(output.stdout).unwrap(), text, "{verb}");
        assert!(!text.is_empty());
    }
}

#[test]
fn discovery_and_malformed_limits_do_not_touch_storage() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("absent.pile");
    let gauge = gauge::mcp::Gauge::new(pile.clone(), None);
    assert_eq!(gauge.tools().len(), 6);
    for (tool, arguments) in [
        ("gauge_health", r#"{"pile":"/elsewhere"}"#),
        ("gauge_hubs", r#"{"top":-1}"#),
        ("gauge_orphans", r#"{"top":3,"top":4}"#),
        ("gauge_orphans", r#"{"ids":true}"#),
    ] {
        let error = gauge
            .call(
                tool,
                arguments.to_owned().into(),
                &mut Out::new(&mut |_| panic!("unexpected report")),
            )
            .unwrap_err();
        assert!(
            error.downcast_ref::<InvalidArguments>().is_some(),
            "{error:#}"
        );
        assert!(!pile.exists());
    }
}
