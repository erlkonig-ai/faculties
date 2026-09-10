use super::*;

use std::fs::{self, File};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::schemas::planner::{cancellation, KIND_CANCELLATION_ID, KIND_NOTE_ID};

static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "faculties-planner-live-{}-{serial}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fresh_storage(directory: &TestDirectory) -> (PathBuf, PathBuf) {
    let pile = directory.0.join("planner.pile");
    let key = directory.0.join("planner.key");
    File::create(&pile).unwrap();
    crate::storage::initialize_signer(&pile, Some(&key)).unwrap();
    (pile, key)
}

fn fixture_draft(uid: &str, summary: &str) -> EventDraft {
    empty_event_draft(
        uid.to_owned(),
        summary.to_owned(),
        make_interval(
            Epoch::from_unix_seconds(10.0),
            Epoch::from_unix_seconds(20.0),
        ),
        STATUS_CONFIRMED.to_owned(),
        TRANSP_OPAQUE.to_owned(),
    )
}

fn fixture_id(byte: u8) -> Id {
    Id::new([byte; 16]).unwrap()
}

#[test]
fn event_and_initial_note_publish_as_one_signed_mutation() {
    let directory = TestDirectory::new();
    let (pile, key) = fresh_storage(&directory);
    let storage = PlannerStorage {
        storage: &crate::storage::Storage::new(pile.clone(), Some(key.clone())),
    };
    let mut fragment = event_fragment(&fixture_draft("one@example", "meeting")).unwrap();
    let event = fragment.root().unwrap();
    fragment += note_fragment(
        event,
        "agenda",
        point_interval(Epoch::from_unix_seconds(30.0)),
    )
    .unwrap();
    storage
        .update("add event", |_| Ok((Some(fragment), ())))
        .unwrap();

    assert_eq!(storage.commit_count().unwrap(), 1);
    storage
        .with_view(|loaded| {
            assert!(planner_model::event(&loaded.facts, event).is_some());
            assert_eq!(
                planner_model::notes_for_event(&loaded.facts, event).len(),
                1
            );
            let occurrences = collect_occurrences(
                &loaded.facts,
                (
                    Epoch::from_unix_seconds(0.0),
                    Epoch::from_unix_seconds(40.0),
                ),
                false,
            );
            assert_eq!(occurrences.len(), 1);
            assert_eq!(occurrences[0].event_id, event);
            Ok(())
        })
        .unwrap();
}

#[test]
fn same_batch_duplicate_uid_collapses_but_conflict_is_rejected() {
    let directory = TestDirectory::new();
    let (pile, key) = fresh_storage(&directory);
    let storage = PlannerStorage {
        storage: &crate::storage::Storage::new(pile.clone(), Some(key.clone())),
    };
    storage
        .with_view(|loaded| {
            let mut staged = BTreeMap::new();
            let first = event_fragment(&fixture_draft("duplicate@example", "same")).unwrap();
            let duplicate = event_fragment(&fixture_draft("duplicate@example", "same")).unwrap();
            let conflict =
                event_fragment(&fixture_draft("duplicate@example", "different")).unwrap();

            assert!(stage_import_event(loaded, &mut staged, "duplicate@example", first).unwrap());
            assert!(
                !stage_import_event(loaded, &mut staged, "duplicate@example", duplicate).unwrap()
            );
            let error =
                stage_import_event(loaded, &mut staged, "duplicate@example", conflict).unwrap_err();
            assert!(format!("{error:#}").contains("conflicting immutable fields"));
            Ok(())
        })
        .unwrap();
}

#[test]
fn duplicate_scalar_ical_property_is_rejected() {
    let bytes = b"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:a@example\r\nUID:b@example\r\nDTSTART:20260809T120000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    let calendars: Vec<_> = ical::IcalParser::new(&bytes[..]).collect();
    let calendar: Vec<_> = calendars
        .into_iter()
        .map(|calendar| calendar.unwrap())
        .collect();
    let error = parse_ical_event(&calendar[0].events[0]).unwrap_err();
    assert!(format!("{error:#}").contains("more than one UID"));
}

#[test]
fn exact_reingest_does_not_publish_another_authored_commit() {
    let directory = TestDirectory::new();
    let (pile, key) = fresh_storage(&directory);
    let ics = directory.0.join("event.ics");
    fs::write(
        &ics,
        "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:stable@example\r\nSUMMARY:Stable\r\nDTSTART:20260809T120000Z\r\nDTEND:20260809T130000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
    )
    .unwrap();
    let storage = PlannerStorage {
        storage: &crate::storage::Storage::new(pile.clone(), Some(key.clone())),
    };

    let text = fs::read_to_string(&ics).unwrap();
    let documents = [CalendarInput {
        name: "event.ics",
        text: &text,
    }];
    ingest(storage, &documents).unwrap();
    ingest(storage, &documents).unwrap();

    assert_eq!(storage.commit_count().unwrap(), 1);
}

#[test]
fn conflicting_same_batch_uid_fails_before_any_signed_commit() {
    let directory = TestDirectory::new();
    let (pile, key) = fresh_storage(&directory);
    let ics = directory.0.join("conflict.ics");
    fs::write(
        &ics,
        "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:fork@example\r\nSUMMARY:Left\r\nDTSTART:20260809T120000Z\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:fork@example\r\nSUMMARY:Right\r\nDTSTART:20260809T120000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
    )
    .unwrap();
    let storage = PlannerStorage {
        storage: &crate::storage::Storage::new(pile.clone(), Some(key.clone())),
    };

    let text = fs::read_to_string(&ics).unwrap();
    let error = ingest(
        storage,
        &[CalendarInput {
            name: "conflict.ics",
            text: &text,
        }],
    )
    .unwrap_err();

    assert!(format!("{error:#}").contains("conflicting immutable fields"));
    assert_eq!(storage.commit_count().unwrap(), 0);
    storage
        .with_view(|loaded| {
            assert!(planner_model::event_ids(&loaded.facts).is_empty());
            Ok(())
        })
        .unwrap();
}

#[test]
fn cancel_adds_one_assertion_without_mutating_baseline_status() {
    let directory = TestDirectory::new();
    let (pile, key) = fresh_storage(&directory);
    let storage = PlannerStorage {
        storage: &crate::storage::Storage::new(pile.clone(), Some(key.clone())),
    };
    let event = event_fragment(&fixture_draft("cancel@example", "meeting")).unwrap();
    let event_id = event.root().unwrap();
    storage
        .update("add event", |_| Ok((Some(event), ())))
        .unwrap();

    cancel(storage, &fmt_id(event_id)).unwrap();
    cancel(storage, &fmt_id(event_id)).unwrap();

    assert_eq!(storage.commit_count().unwrap(), 2);
    storage
        .with_view(|loaded| {
            assert_eq!(
                planner_model::event(&loaded.facts, event_id)
                    .expect("published event remains readable")
                    .status,
                STATUS_CONFIRMED
            );
            assert!(planner_model::event_is_cancelled(&loaded.facts, event_id));
            Ok(())
        })
        .unwrap();
}

#[test]
fn opaque_repeated_cancellation_edges_cancel_every_occurrence_target() {
    let first = event_fragment(&fixture_draft("first@example", "first")).unwrap();
    let first_id = first.root().unwrap();
    let second = event_fragment(&fixture_draft("second@example", "second")).unwrap();
    let second_id = second.root().unwrap();
    let assertion = fixture_id(7);
    let mut facts = first.into_facts();
    facts += second.into_facts();
    facts += entity! { ExclusiveId::force_ref(&assertion) @
        metadata::tag: &KIND_CANCELLATION_ID,
        cancellation::event: &first_id,
    };
    facts += entity! { ExclusiveId::force_ref(&assertion) @
        cancellation::event: &second_id,
    };

    let window = (
        Epoch::from_unix_seconds(0.0),
        Epoch::from_unix_seconds(30.0),
    );
    assert!(collect_occurrences(&facts, window, false).is_empty());

    let all = collect_occurrences(&facts, window, true);
    assert_eq!(all.len(), 2);
    assert!(all
        .iter()
        .all(|occurrence| occurrence.status == STATUS_CANCELLED));
    assert_eq!(
        all.iter()
            .map(|occurrence| occurrence.event_id)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([first_id, second_id])
    );
}

#[test]
fn occurrence_reads_ignore_notes_and_skip_unsupported_event_rows() {
    let event = event_fragment(&fixture_draft("readable@example", "readable")).unwrap();
    let event_id = event.root().unwrap();
    let mut unsupported = fixture_draft("unsupported@example", "unsupported");
    unsupported.rrule = Some("FREQ=NOTREAL".to_owned());
    let unsupported = event_fragment(&unsupported).unwrap();
    let note = note_fragment(
        event_id,
        "this belongs to show, not occurrence reads",
        point_interval(Epoch::from_unix_seconds(30.0)),
    )
    .unwrap();
    let mut facts = event.into_facts();
    facts += unsupported.into_facts();
    facts += note.into_facts();
    let incomplete_note = fixture_id(8);
    facts += entity! { ExclusiveId::force_ref(&incomplete_note) @
        metadata::tag: &KIND_NOTE_ID,
    };

    let window = (
        Epoch::from_unix_seconds(0.0),
        Epoch::from_unix_seconds(30.0),
    );
    let occurrences = collect_occurrences(&facts, window, false);
    assert_eq!(occurrences.len(), 1);
    assert_eq!(occurrences[0].event_id, event_id);
    assert_eq!(
        next_occurrence(&facts, window)
            .expect("readable event remains the next occurrence")
            .event_id,
        event_id
    );
}

#[test]
fn next_compares_rrule_and_every_rdate_after_applying_exdates() {
    let mut recurring = fixture_draft("recurring@example", "recurring");
    recurring.time = make_interval(
        Epoch::from_unix_seconds(0.0),
        Epoch::from_unix_seconds(10.0),
    );
    recurring.rrule = Some("FREQ=DAILY;COUNT=3".to_owned());
    recurring.rdates = BTreeSet::from([
        make_interval(
            Epoch::from_unix_seconds(50.0),
            Epoch::from_unix_seconds(60.0),
        ),
        make_interval(
            Epoch::from_unix_seconds(90_000.0),
            Epoch::from_unix_seconds(90_010.0),
        ),
    ]);
    recurring.exdates = BTreeSet::from([
        recurring.time,
        make_interval(
            Epoch::from_unix_seconds(50.0),
            Epoch::from_unix_seconds(60.0),
        ),
    ]);
    let recurring = event_fragment(&recurring).unwrap();
    let recurring_id = recurring.root().unwrap();

    let mut later = fixture_draft("later@example", "later");
    later.time = make_interval(
        Epoch::from_unix_seconds(100_000.0),
        Epoch::from_unix_seconds(100_010.0),
    );
    let later = event_fragment(&later).unwrap();
    let mut facts = recurring.into_facts();
    facts += later.into_facts();

    // EXDATE must be inside the recurrence set before `all(1)`: otherwise
    // it yields the excluded DTSTART and the later RDATE wins after the
    // exact filter. The next unexcluded RRULE occurrence is one day later.
    let next = next_occurrence(
        &facts,
        (
            Epoch::from_unix_seconds(-1.0),
            Epoch::from_unix_seconds(200_000.0),
        ),
    )
    .expect("an unexcluded occurrence exists");
    assert_eq!(next.event_id, recurring_id);
    assert_eq!(next.start, Epoch::from_unix_seconds(86_400.0));
    assert_eq!(next.end, Epoch::from_unix_seconds(86_410.0));

    // The RDATE fold must inspect every value rather than assume query
    // order. Put the winning value after a later one deliberately.
    let mut row = occurrence_event(&facts, recurring_id).unwrap();
    row.rdates = vec![
        (
            Epoch::from_unix_seconds(90_000.0),
            Epoch::from_unix_seconds(90_010.0),
        ),
        (
            Epoch::from_unix_seconds(100.0),
            Epoch::from_unix_seconds(110.0),
        ),
    ];
    assert_eq!(
        next_event_occurrence(
            &row,
            (
                Epoch::from_unix_seconds(1.0),
                Epoch::from_unix_seconds(200_000.0),
            ),
        ),
        Some((
            Epoch::from_unix_seconds(100.0),
            Epoch::from_unix_seconds(110.0),
        ))
    );
}
