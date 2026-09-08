use super::*;

/// The frame shape is not this binary's to choose: it is Soma's wire
/// format, and a divergence would be two agreeing constants drifting
/// apart. (Also enforced at compile time by the `const _` above.)
#[test]
fn the_frame_is_somas_frame() {
    assert_eq!(FRAME_SAMPLES, soma_client::FRAME_SAMPLES);
    assert_eq!(SAMPLE_RATE, soma_client::SAMPLE_RATE);
    assert_eq!(FRAME_SAMPLES as u32 * 1_000 / SAMPLE_RATE, 80);
}

/// User-audio presence and text arbitration are independent protocol
/// axes. In particular, generation-only mode must select Mary's explicit
/// output-only API under both scheduled and model-timed speech; a learned
/// silence frame is an ordinary duplex input, not an output-only stand-in.
#[cfg(feature = "duplex")]
#[test]
fn personaplex_step_api_keeps_output_only_separate_from_duplex() {
    use PersonaPlexStepApi::*;

    assert_eq!(PersonaPlexStepApi::select(false, false), Duplex);
    assert_eq!(PersonaPlexStepApi::select(false, true), DuplexArbitrated);
    assert_eq!(PersonaPlexStepApi::select(true, false), OutputOnly);
    assert_eq!(PersonaPlexStepApi::select(true, true), OutputOnlyArbitrated);
}

/// A loop slower than the world skips FORWARD rather than falling behind,
/// and says how much it skipped. The model's step count is its clock, so
/// it cannot catch up by stepping faster.
#[test]
fn a_slow_loop_skips_forward_and_counts_it() {
    let ear = Ear {
        ring: Arc::new((Mutex::new(EarRing::default()), Condvar::new())),
        stop: Arc::new(AtomicBool::new(false)),
        thread: None,
        soma: "test".into(),
    };
    {
        let mut ring = ear.ring.0.lock().unwrap();
        for value in 0..(MAX_BACKLOG_FRAMES + 5) {
            ring.frames.push_back([value as f32; FRAME_SAMPLES]);
        }
    }
    let frame = ear.next_frame().expect("a frame");
    // Everything but the last two frames is dropped, and the frame handed
    // over is the current one, not the stale head.
    assert_eq!(frame[0], (MAX_BACKLOG_FRAMES + 3) as f32);
    assert_eq!(ear.skipped(), MAX_BACKLOG_FRAMES + 3);
}

/// The shared-microphone guard's one rule: the window must not close while
/// our voice is still coming out of the speaker. It opens on the first
/// speaking frame, stays open for the whole generation window, and then
/// outlasts it by exactly what the mouth still had in flight — never less.
#[test]
fn the_audible_window_outlasts_generation_by_what_is_still_in_flight() {
    let mut window = AudibleWindow::default();
    assert!(!window.observe(false, 0), "silence is not audible");
    // Speaking, with 6 frames sitting in front of the speaker.
    for _ in 0..5 {
        assert!(window.observe(true, 6));
    }
    // Generation stops. The tail is what was queued plus the prebuffer,
    // counted down one frame per frame.
    let tail = 6 + PREBUFFER_FRAMES;
    for frame in 0..tail {
        assert!(
            window.observe(false, 0),
            "frame {frame} of the tail is still in the room"
        );
    }
    assert!(
        !window.observe(false, 0),
        "and then, and only then, silence"
    );
}

/// A stream that ended hands over what it already delivered before it
/// reports the ending: missing speech must never read as silence, and
/// delivered speech must never be swallowed by the ending.
#[test]
fn buffered_frames_survive_the_end_of_the_stream() {
    let ear = Ear {
        ring: Arc::new((Mutex::new(EarRing::default()), Condvar::new())),
        stop: Arc::new(AtomicBool::new(false)),
        thread: None,
        soma: "test".into(),
    };
    {
        let mut ring = ear.ring.0.lock().unwrap();
        ring.frames.push_back([0.5; FRAME_SAMPLES]);
        ring.ended = Some("the body stopped".into());
    }
    assert_eq!(ear.next_frame().expect("the buffered frame")[0], 0.5);
    assert!(ear.next_frame().is_none());
    assert_eq!(ear.ended().as_deref(), Some("the body stopped"));
}

#[test]
fn injected_lines_come_back_oldest_first_and_only_once() {
    let dir = tempfile::tempdir().unwrap();
    let session = dir.path();
    inject(session, "first").unwrap();
    std::thread::sleep(Duration::from_millis(5));
    inject(session, "second").unwrap();
    let drained = drain_inject(session).unwrap();
    assert_eq!(drained.lines, vec!["first", "second"]);
    assert!(drained.cleanup_failure.is_none());
    let drained = drain_inject(session).unwrap();
    assert!(drained.lines.is_empty());
    assert!(drained.cleanup_failure.is_none());
}

#[test]
fn the_floor_is_held_until_given_back_and_expires_on_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let session = dir.path();
    assert!(!floor_held(session).unwrap());
    take_floor(session, 60).unwrap();
    assert!(floor_held(session).unwrap());
    give_floor(session).unwrap();
    assert!(!floor_held(session).unwrap());
    // A reader that never comes back must not mute the channel forever.
    take_floor(session, 0).unwrap();
    std::thread::sleep(Duration::from_millis(5));
    assert!(!floor_held(session).unwrap());
}

#[test]
fn reading_does_not_move_the_cursor_but_saying_does() {
    let dir = tempfile::tempdir().unwrap();
    let session = dir.path();
    ensure_session(session).unwrap();
    for seq in 1..=3 {
        append_line(
            session,
            &Line {
                seq,
                at_ms: seq,
                speaker: "model".into(),
                text: format!("line {seq}"),
            },
        )
        .unwrap();
    }
    Session::new(session.to_owned())
        .read(ReadOptions {
            peek: false,
            all: false,
            hold_secs: 60,
        })
        .unwrap();
    assert_eq!(read_cursor(session).unwrap(), 0, "reading must not consume");
    assert!(floor_held(session).unwrap(), "reading takes the floor");
    Session::new(session.to_owned())
        .say("a reply", false)
        .unwrap();
    assert_eq!(
        read_cursor(session).unwrap(),
        3,
        "acting on a read consumes it"
    );
    assert!(!floor_held(session).unwrap(), "saying gives the floor back");
    let drained = drain_inject(session).unwrap();
    assert_eq!(drained.lines, vec!["a reply"]);
    assert!(drained.cleanup_failure.is_none());
}

#[test]
fn transcript_lines_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let session = dir.path();
    append_line(
        session,
        &Line {
            seq: 7,
            at_ms: 42,
            speaker: "far".into(),
            text: "[spoke for 1.5s — no transcription available]".into(),
        },
    )
    .unwrap();
    let lines = read_lines(session).unwrap();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].seq, 7);
    assert_eq!(lines[0].speaker, "far");
    assert!(lines[0].text.contains("1.5s"));
}

#[test]
fn wav_header_states_its_own_length() {
    let header = wav_header(1920 * 2);
    assert_eq!(&header[0..4], b"RIFF");
    assert_eq!(&header[36..40], b"data");
    assert_eq!(
        u32::from_le_bytes(header[40..44].try_into().unwrap()),
        1920 * 2
    );
}

#[test]
fn an_output_failure_keeps_the_spoken_line_and_joins_the_closed_ledger() {
    let directory = tempfile::tempdir().unwrap();
    let (tx, rx) = mpsc::sync_channel::<String>(2);
    let (_warnings_tx, warnings) = mpsc::sync_channel(1);
    let received = Arc::new(Mutex::new(Vec::new()));
    let closed = Arc::new(AtomicBool::new(false));
    let worker_received = Arc::clone(&received);
    let worker_closed = Arc::clone(&closed);
    let worker = std::thread::spawn(move || loop {
        // A regression that joins before closing the sender fails in two
        // seconds instead of leaving the CPU test hung forever.
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(text) => worker_received.lock().unwrap().push(text),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                worker_closed.store(true, Ordering::Relaxed);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => break,
        }
    });
    let ledger = Ledger {
        lines: Some(tx),
        worker: Some(worker),
        warnings,
        dropped_warnings: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        dropped_lines: std::cell::Cell::new(0),
    };
    let line = Line {
        seq: 1,
        at_ms: 42,
        speaker: "agent".into(),
        text: "already generated".into(),
    };
    let error = spoken_line(
        directory.path(),
        &line,
        &ledger,
        &mut Out::new(&mut |_| Err(anyhow::anyhow!("output closed"))),
    )
    .unwrap_err();
    assert!(error.to_string().contains("output closed"));
    assert_eq!(read_lines(directory.path()).unwrap(), vec![line]);
    drop(ledger);
    assert!(
        closed.load(Ordering::Relaxed),
        "worker joined after observing the closed input queue"
    );
    assert_eq!(*received.lock().unwrap(), vec!["already generated"]);
}

#[test]
fn queue_read_failure_preserves_earlier_selected_entries() {
    let directory = tempfile::tempdir().unwrap();
    let first = inject(directory.path(), "first").unwrap();
    let later = directory.path().join("inject/zzzz.txt");
    std::fs::write(&later, [0xff]).unwrap();
    let mut removal_attempted = false;
    assert!(drain_inject_with(directory.path(), |_| {
        removal_attempted = true;
        Ok(())
    })
    .is_err());
    assert!(!removal_attempted);
    assert!(first.exists());
    assert!(later.exists());
}

#[test]
fn queue_cleanup_failure_schedules_only_consumed_prefix_and_recovers_once() {
    let directory = tempfile::tempdir().unwrap();
    ensure_session(directory.path()).unwrap();
    let first = directory.path().join("inject/001.txt");
    let second = directory.path().join("inject/002.txt");
    let third = directory.path().join("inject/003.txt");
    for (path, text) in [(&first, "first"), (&second, "second"), (&third, "third")] {
        std::fs::write(path, text).unwrap();
    }

    let mut attempted = Vec::new();
    let mut remove = |path: &Path| {
        attempted.push(path.to_owned());
        if path == second {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected cleanup failure",
            ))
        } else {
            std::fs::remove_file(path)
        }
    };
    let mut scheduled = Vec::new();
    let mut reports = Vec::new();
    let mut last_failure = None;
    for expected in [vec!["first"], vec![]] {
        let drained = drain_inject_with(directory.path(), &mut remove).unwrap();
        assert_eq!(drained.lines, expected);
        assert!(format!("{:#}", drained.cleanup_failure.as_ref().unwrap())
            .contains("injected cleanup failure"));
        assert!(!first.exists());
        assert!(second.exists());
        assert!(third.exists());
        accept_inject_drain(
            drained,
            &mut last_failure,
            |line| scheduled.push(line.to_owned()),
            &mut Out::new(&mut |part| {
                reports.push(part);
                Ok(())
            }),
        )
        .unwrap();
    }
    assert_eq!(attempted, vec![first, second.clone(), second.clone()]);
    assert_eq!(scheduled, vec!["first"]);
    assert_eq!(
        reports.len(),
        2,
        "one speech notice and one cleanup warning"
    );
    match &reports[1] {
        crate::out::Part::Text { text } => {
            assert!(text.contains(&second.display().to_string()));
            assert!(text.contains("injected cleanup failure"));
            assert!(text.contains("later entries remain queued"));
        }
        other => panic!("expected cleanup warning, got {other:?}"),
    }

    let remaining = drain_inject(directory.path()).unwrap();
    assert_eq!(remaining.lines, vec!["second", "third"]);
    assert!(remaining.cleanup_failure.is_none());
    accept_inject_drain(
        remaining,
        &mut last_failure,
        |line| scheduled.push(line.to_owned()),
        &mut Out::new(&mut |part| {
            reports.push(part);
            Ok(())
        }),
    )
    .unwrap();
    assert_eq!(scheduled, vec!["first", "second", "third"]);
    assert!(last_failure.is_none());
    assert_eq!(reports.len(), 4);
    assert!(drain_inject(directory.path()).unwrap().lines.is_empty());
}

#[test]
fn a_queue_file_that_disappeared_after_read_is_not_injected() {
    let directory = tempfile::tempdir().unwrap();
    ensure_session(directory.path()).unwrap();
    let gone = directory.path().join("inject/001.txt");
    let remaining = directory.path().join("inject/002.txt");
    std::fs::write(&gone, "already consumed elsewhere").unwrap();
    std::fs::write(&remaining, "still queued").unwrap();
    let drained = drain_inject_with(directory.path(), |path| {
        std::fs::remove_file(path)?;
        if path == gone {
            Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        } else {
            Ok(())
        }
    })
    .unwrap();
    assert_eq!(drained.lines, vec!["still queued"]);
    assert!(drained.cleanup_failure.is_none());
    assert!(drain_inject(directory.path()).unwrap().lines.is_empty());
}

#[test]
fn cleanup_warning_changes_and_recurs_after_a_successful_poll() {
    let mut last_failure = None;
    let mut reports = 0;
    for failure in [
        Some("first"),
        Some("first"),
        Some("second"),
        None,
        Some("second"),
    ] {
        accept_inject_drain(
            InjectDrain {
                lines: Vec::new(),
                cleanup_failure: failure.map(|cause| anyhow::anyhow!("cleanup failure: {cause}")),
            },
            &mut last_failure,
            |_| panic!("no consumed speech"),
            &mut Out::new(&mut |_| {
                reports += 1;
                Ok(())
            }),
        )
        .unwrap();
    }
    assert_eq!(reports, 3);
}

#[test]
fn injection_reporting_failure_is_still_terminal_not_a_delivery_receipt() {
    let mut scheduled = Vec::new();
    let mut last_failure = None;
    let error = accept_inject_drain(
        InjectDrain {
            lines: vec!["first".into(), "second".into()],
            cleanup_failure: Some(anyhow::anyhow!("cleanup failed after the prefix")),
        },
        &mut last_failure,
        |line| scheduled.push(line.to_owned()),
        &mut Out::new(&mut |_| Err(anyhow::anyhow!("output closed"))),
    )
    .unwrap_err();
    assert_eq!(scheduled, vec!["first", "second"]);
    assert!(error.to_string().contains("output closed"));
    assert!(last_failure.is_none(), "the warning was not delivered");
    // run still propagates this error, dropping its in-memory scheduled lines.
    // Scheduling before reporting does not guarantee audio or durable delivery.
}

#[cfg(feature = "duplex")]
#[test]
fn dropping_playback_signals_cancel_and_closes_input_before_joining() {
    let (tx, rx) = mpsc::sync_channel::<Codes>(1);
    let cancel = Arc::new(AtomicBool::new(false));
    let observed_cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = Arc::clone(&cancel);
    let worker_observed = Arc::clone(&observed_cancel);
    let worker = std::thread::spawn(move || {
        if matches!(
            rx.recv_timeout(Duration::from_secs(2)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ) {
            worker_observed.store(worker_cancel.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        Ok(())
    });
    let mouth = Mouth {
        frames: Some(tx),
        worker: Some(worker),
        dropped: Arc::new(AtomicU64::new(0)),
        underruns: Arc::new(AtomicU64::new(0)),
        played: Arc::new(AtomicU64::new(0)),
        pushed: std::cell::Cell::new(0),
        playing: Arc::new(AtomicBool::new(false)),
        cancel,
    };
    drop(mouth);
    assert!(observed_cancel.load(Ordering::Relaxed));
}
