//! Typed Planner operations and resident frontend contracts. No network, model,
//! device, process-global timezone, or environment changes are used.
use anybytes::Bytes;
use anyhow::{anyhow, Result};
use clap::Parser;
use faculties::collection_names::open_configured;
use faculties::mcp::{Faculty, InvalidArguments};
use faculties::out::{Out, Part};
use faculties::planner::{
    self, cli, mcp, AddOptions, CalendarInput, Planner, STATUS_CANCELLED, STATUS_CONFIRMED,
};
use faculties::schemas::planner::DEFAULT_SCOPE_ID;
use faculties::storage::{initialize_signer, load_signer, open_pile_strict};
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
        let pile = directory.path().join("planner.pile");
        let key = directory.path().join("planner.key");
        fs::File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        Self {
            directory,
            pile,
            key,
        }
    }
    fn operations(&self) -> Planner {
        Planner::new(self.pile.clone(), Some(self.key.clone()))
    }
    fn adapter(&self) -> mcp::Planner {
        mcp::Planner::new(self.pile.clone(), Some(self.key.clone()))
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
                "planner".into(),
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
            panic!("Planner emits text");
        };
        text.push_str(&part);
        Ok(())
    }))?;
    Ok(text)
}
fn json(value: serde_json::Value) -> Bytes {
    Bytes::from(serde_json::to_vec(&value).unwrap())
}
fn calendar(uid: &str, title: &str) -> String {
    format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nSUMMARY:{title}\r\nDTSTART:20260809T120000Z\r\nDTEND:20260809T130000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
}
fn window() -> planner::Window {
    planner::event_window("2026-08-09", Some("2026-08-10")).unwrap()
}

#[test]
fn direct_add_and_initial_note_are_one_publication_and_cancel_is_monotone() {
    let fixture = Fixture::new();
    let planner = fixture.operations();
    let mut input = AddOptions::new(
        "meeting",
        planner::event_window("2026-08-09T12:00", None).unwrap(),
    );
    input.description = Some("@/literal-description".into());
    input.note = Some("@-".into());
    let receipt = planner.add(&input).unwrap();
    assert!(receipt.note.is_some());
    assert_eq!(fixture.commits(), 1);
    let id = format!("{:x}", receipt.event);
    let detail = planner.show(&id).unwrap();
    assert_eq!(detail.uid, receipt.uid);
    assert_eq!(detail.description.as_deref(), Some("@/literal-description"));
    assert_eq!(detail.notes[0].row.id, receipt.note.unwrap());
    assert_eq!(detail.notes[0].text, "@-");
    assert_eq!(planner.list(window(), false).unwrap().len(), 1);
    assert!(!planner.cancel(&id).unwrap().already_cancelled);
    assert!(planner.cancel(&id).unwrap().already_cancelled);
    assert_eq!(fixture.commits(), 2);
    let detail = planner.show(&id).unwrap();
    assert_eq!(detail.event.status, STATUS_CONFIRMED);
    assert!(detail.cancelled);
    assert!(planner.list(window(), false).unwrap().is_empty());
    assert_eq!(
        planner.list(window(), true).unwrap()[0].status,
        STATUS_CANCELLED
    );
}

#[test]
fn resident_ingest_stages_full_batch_and_preserves_uid_duplicate_conflicts() {
    let fixture = Fixture::new();
    let planner = fixture.operations();
    let a = calendar("a@example", "first");
    let b = calendar("b@example", "second");
    let receipt = planner
        .ingest(&[
            CalendarInput {
                name: "first.ics",
                text: &a,
            },
            CalendarInput {
                name: "same-again.ics",
                text: &a,
            },
            CalendarInput {
                name: "second.ics",
                text: &b,
            },
        ])
        .unwrap();
    assert_eq!(
        (receipt.imported.len(), receipt.total, receipt.duplicates),
        (2, 3, 1)
    );
    assert_eq!(fixture.commits(), 1);
    let with_sequence = a.replace("SUMMARY:first", "SUMMARY:first\r\nSEQUENCE:99");
    let again = planner
        .ingest(&[CalendarInput {
            name: "later-sequence.ics",
            text: &with_sequence,
        }])
        .unwrap();
    assert_eq!(
        (again.imported.len(), again.total, again.duplicates),
        (0, 1, 1)
    );
    assert_eq!(fixture.commits(), 1);
    let new = calendar("not-published@example", "staged only");
    let conflict = calendar("a@example", "changed");
    let error = planner
        .ingest(&[
            CalendarInput {
                name: "new-first.ics",
                text: &new,
            },
            CalendarInput {
                name: "conflict-later.ics",
                text: &conflict,
            },
        ])
        .unwrap_err();
    assert!(error.to_string().contains("immutable fields differ"));
    assert_eq!(fixture.commits(), 1);
    assert_eq!(planner.list(window(), false).unwrap().len(), 2);
    let malformed = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:missing uid\r\nDTSTART:20260809T120000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    assert!(planner
        .ingest(&[
            CalendarInput {
                name: "new-first.ics",
                text: &new
            },
            CalendarInput {
                name: "invalid-later.ics",
                text: malformed
            },
        ])
        .is_err());
    assert_eq!(fixture.commits(), 1);
}

#[test]
fn mcp_resident_names_and_notes_are_literal_and_reports_match_cli() {
    let fixture = Fixture::new();
    let sentinel = fixture.directory.path().join("untouched.ics");
    fs::write(&sentinel, "not the calendar supplied to MCP").unwrap();
    let ics = calendar("resident@example", "resident");
    collect(|out| {
        fixture.adapter().call(
            "planner_ingest",
            json(serde_json::json!({
                "documents":[{"name":sentinel.to_str().unwrap(),"text":ics}]
            })),
            out,
        )
    })
    .unwrap();
    assert_eq!(
        fs::read_to_string(&sentinel).unwrap(),
        "not the calendar supplied to MCP"
    );
    let planner = fixture.operations();
    let event = planner.list(window(), false).unwrap()[0].event_id;
    let id = format!("{event:x}");
    collect(|out| {
        fixture.adapter().call(
            "planner_note",
            json(serde_json::json!({"id":id,"text":"@-"})),
            out,
        )
    })
    .unwrap();
    assert_eq!(planner.show(&id).unwrap().notes[0].text, "@-");
    for (tool, args, cli_args) in [
        (
            "planner_show",
            serde_json::json!({"id":id}),
            vec!["show", &id],
        ),
        (
            "planner_list",
            serde_json::json!({"from":"2026-08-09","to":"2026-08-10"}),
            vec!["list", "--from", "2026-08-09", "--to", "2026-08-10"],
        ),
        (
            "planner_resolve",
            serde_json::json!({"prefix":id}),
            vec!["resolve", &id],
        ),
    ] {
        let mcp = collect(|out| fixture.adapter().call(tool, json(args), out)).unwrap();
        let cli = collect(|out| cli::execute(fixture.cli(&cli_args), out)).unwrap();
        assert_eq!(mcp, cli, "{tool}");
    }
    let after = planner::chrono_to_epoch(planner::parse_iso8601("2026-08-09T11:00:00Z").unwrap());
    let next = planner.next(Some(after)).unwrap();
    let direct = collect(|out| {
        planner::presentation::occurrences(next.as_ref().map_or(&[], std::slice::from_ref), out)
    })
    .unwrap();
    let mcp = collect(|out| {
        fixture.adapter().call(
            "planner_next",
            json(serde_json::json!({"after":"2026-08-09T11:00:00Z"})),
            out,
        )
    })
    .unwrap();
    assert_eq!(direct, mcp);
}

#[test]
fn cli_file_and_prose_inputs_remain_cli_only() {
    let fixture = Fixture::new();
    let path = fixture.directory.path().join("event.ics");
    fs::write(&path, calendar("cli@example", "CLI input")).unwrap();
    collect(|out| cli::execute(fixture.cli(&["ingest", path.to_str().unwrap()]), out)).unwrap();
    let planner = fixture.operations();
    let event = planner.list(window(), false).unwrap()[0].event_id;
    let text = fixture.directory.path().join("note.txt");
    fs::write(&text, "read by CLI, not interpreted in operations").unwrap();
    let marker = format!("@{}", text.display());
    collect(|out| cli::execute(fixture.cli(&["note", &format!("{event:x}"), &marker]), out))
        .unwrap();
    assert_eq!(
        planner.show(&format!("{event:x}")).unwrap().notes[0].text,
        "read by CLI, not interpreted in operations"
    );
    let before = fixture.commits();
    let help = collect(|out| cli::execute(fixture.cli(&[]), out)).unwrap();
    assert!(help.contains("Usage:"));
    assert_eq!(fixture.commits(), before);
}

#[test]
fn explicit_utc_and_typed_argument_constraints_hold_before_storage() {
    let date = planner::event_window("2026-08-09", None).unwrap();
    let explicit =
        planner::event_window("2026-08-09T00:00:00Z", Some("2026-08-10T00:00:00Z")).unwrap();
    assert_eq!(date, explicit);
    let naive = planner::event_window("2026-08-09T12:00", None).unwrap();
    let zoned = planner::event_window(
        "2026-08-09T14:00:00+02:00",
        Some("2026-08-09T15:00:00+02:00"),
    )
    .unwrap();
    assert_eq!(naive, zoned);
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.pile");
    let adapter = mcp::Planner::new(missing.clone(), None);
    for (tool, args) in [
        (
            "planner_add",
            r#"{"summary":"x","from":"2026-08-09","status":"maybe"}"#,
        ),
        (
            "planner_add",
            r#"{"summary":"x","from":"2026-08-10","to":"2026-08-09"}"#,
        ),
        (
            "planner_add",
            r#"{"summary":"x","summary":"duplicate","from":"2026-08-09"}"#,
        ),
        (
            "planner_list",
            r#"{"from":"2026-08-09","to":"2026-08-10","timezone":"host"}"#,
        ),
        (
            "planner_note",
            r#"{"id":"ab","text":"literal","file":"/host"}"#,
        ),
        ("planner_show", r#"{"id":"@-"}"#),
        ("planner_cancel", r#"{"id":""}"#),
        (
            "planner_ingest",
            r#"{"documents":[{"name":"x","text":"literal","path":"/host"}]}"#,
        ),
        ("planner_ingest", r#"{"documents":[]}"#),
        ("planner_resolve", r#"{"prefix":"ab","pile":"/host"}"#),
    ] {
        let error = adapter
            .call(
                tool,
                Bytes::from(args.as_bytes().to_vec()),
                &mut Out::new(&mut |_| panic!("invalid args must not emit")),
            )
            .unwrap_err();
        assert!(
            error.downcast_ref::<InvalidArguments>().is_some(),
            "{tool}: {error:#}"
        );
    }
    let error = adapter
        .call(
            "planner_add",
            json(serde_json::json!({"summary":"é".repeat(17),"from":"2026-08-09"})),
            &mut Out::new(&mut |_| panic!("invalid bytes must not emit")),
        )
        .unwrap_err();
    assert!(error.downcast_ref::<InvalidArguments>().is_some());
    assert_eq!(adapter.tools().len(), 8);
    assert!(!missing.exists());
}

#[test]
fn output_failure_does_not_repeat_calendar_publication() {
    let fixture = Fixture::new();
    let mut emissions = 0;
    let error = fixture
        .adapter()
        .call(
            "planner_ingest",
            json(serde_json::json!({
                "documents":[{"name":"one.ics","text":calendar("once@example","once")}]
            })),
            &mut Out::new(&mut |_| {
                emissions += 1;
                Err(anyhow!("closed emitter"))
            }),
        )
        .unwrap_err();
    assert!(error.to_string().contains("closed emitter"));
    assert_eq!(emissions, 1);
    assert_eq!(fixture.commits(), 1);
    assert_eq!(fixture.operations().list(window(), false).unwrap().len(), 1);
}
