//! GATE for the framed-stream convention, over REAL OS pipes and a REAL child
//! process.
//!
//! The crate's own unit tests drive the format through in-memory buffers,
//! which proves the encoding. They cannot prove the thing the convention exists
//! for: that a faculty on the far end of a pipe can start producing output
//! before the producer has finished sending input. That needs two processes and
//! a kernel between them, which is what these tests are.
//!
//! The far end is `framed_relay`, this crate's reference streaming faculty. It
//! stands in for a speech faculty the way a protocol mock stands in for a
//! server: same format, same pipes, no model. A real speech faculty is that
//! program with a vocoder in the middle.

use std::io::Write;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

use framed_stream::{EndStatus, FacultyStream, Frame, FramedReader, TEXT_PLAIN, UNIT_BYTES};

/// How long a test waits for the far end before calling it a hang. Generous:
/// the assertion is "before the input finished", not "within N ms".
const PATIENCE: Duration = Duration::from_secs(20);

fn relay(mode: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_framed_relay"));
    command.arg(mode);
    command
}

/// Drain a faculty's output stream on its own thread, forwarding each frame.
///
/// Two pipes between two processes deadlock if both fill at once, so a caller
/// that streams in both directions puts the reader somewhere else. Doing that
/// here is not test scaffolding — it is the shape the convention requires, and
/// `FacultyStream::spawn` hands back separate halves precisely so it is
/// possible.
fn drain(output: std::process::ChildStdout) -> mpsc::Receiver<anyhow::Result<Frame>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = match FramedReader::open(output) {
            Ok(reader) => reader,
            Err(error) => {
                let _ = tx.send(Err(error));
                return;
            }
        };
        loop {
            match reader.next_frame() {
                Ok(frame) => {
                    let done = matches!(frame, Frame::End(_));
                    if tx.send(Ok(frame)).is_err() || done {
                        return;
                    }
                }
                Err(error) => {
                    let _ = tx.send(Err(error));
                    return;
                }
            }
        }
    });
    rx
}

fn next(rx: &mpsc::Receiver<anyhow::Result<Frame>>) -> Frame {
    rx.recv_timeout(PATIENCE)
        .expect("the faculty produced nothing before the deadline")
        .expect("the faculty's stream is well-formed")
}

/// THE LOAD-BEARING PROPERTY: output before the input has finished.
///
/// This is the whole reason drive streams into a faculty instead of handing it
/// one finished string. A speech faculty that only starts after the last token
/// is a speech faculty that starts a sentence late.
#[test]
fn a_faculty_produces_output_before_the_input_stream_has_finished() {
    let mut halves = FacultyStream::spawn(&mut relay("words"), TEXT_PLAIN, UNIT_BYTES)
        .expect("start the streaming faculty");
    let frames = drain(halves.output);

    // Feed the first token and NOTHING else. If the far end were batching until
    // EOF, this frame would never arrive and the deadline would fire.
    halves.input.text("hello ").expect("stream the first token");
    let Frame::Record(first) = next(&frames) else {
        panic!("expected a record before the input finished")
    };
    assert_eq!(first.text().unwrap(), "HELLO");
    assert_eq!(first.content_type(), TEXT_PLAIN);

    // Only now does the rest of the utterance go in.
    for token in ["world ", "and ", "everything"] {
        halves.input.text(token).expect("stream a token");
    }
    let sink = halves
        .input
        .finish(EndStatus::Complete)
        .expect("end the input stream");
    drop(sink);

    let mut words = vec![first.text().unwrap().to_string()];
    loop {
        match next(&frames) {
            Frame::Record(record) => words.push(record.text().unwrap().to_string()),
            Frame::Gap(gap) => panic!("unexpected gap: {gap:?}"),
            Frame::End(status) => {
                assert_eq!(status, EndStatus::Complete);
                break;
            }
        }
    }
    assert_eq!(words, ["HELLO", "WORLD", "AND", "EVERYTHING"]);
    let status = halves.stream.wait().expect("reap the faculty");
    assert!(status.success(), "the faculty exited cleanly");
}

/// A faculty that dies mid-utterance must not look like one that finished.
#[test]
fn a_faculty_that_dies_mid_stream_reads_as_truncated_not_complete() {
    let mut halves = FacultyStream::spawn(&mut relay("truncate"), TEXT_PLAIN, UNIT_BYTES)
        .expect("start the streaming faculty");
    let frames = drain(halves.output);

    // The relay exits, without a terminator, after its second input record.
    for token in ["one ", "two ", "three "] {
        // The far end may already be gone; a broken pipe here is the producer
        // learning what the consumer's truncation is about to say.
        if halves.input.text(token).is_err() {
            break;
        }
    }

    let mut saw_record = false;
    let error = loop {
        match frames
            .recv_timeout(PATIENCE)
            .expect("no frame before deadline")
        {
            Ok(Frame::Record(_)) => saw_record = true,
            Ok(Frame::Gap(_)) => {}
            Ok(Frame::End(status)) => {
                panic!("a killed faculty must NOT report a clean end, got {status:?}")
            }
            Err(error) => break error,
        }
    };
    assert!(saw_record, "the relay did produce output before dying");
    assert!(
        format!("{error:#}").contains("TRUNCATED"),
        "the consumer must name the truncation: {error:#}"
    );
}

/// A faculty that gives up says so, and that is a well-formed stream: the
/// content is incomplete and the consumer knows exactly that.
#[test]
fn a_faculty_that_gives_up_ends_the_stream_as_aborted() {
    let mut halves = FacultyStream::spawn(&mut relay("abort"), TEXT_PLAIN, UNIT_BYTES)
        .expect("start the streaming faculty");
    let frames = drain(halves.output);
    for token in ["one ", "two "] {
        if halves.input.text(token).is_err() {
            break;
        }
    }

    let mut statuses = Vec::new();
    loop {
        match next(&frames) {
            Frame::Record(_) | Frame::Gap(_) => {}
            Frame::End(status) => {
                statuses.push(status);
                break;
            }
        }
    }
    let Some(EndStatus::Aborted(reason)) = statuses.pop() else {
        panic!("expected an aborted terminator")
    };
    assert!(reason.contains("abort"), "the abort names itself: {reason}");
}

/// Loss travels rather than vanishing: a relay that cannot deliver a record
/// declares a gap, and the gap moves both clocks so the consumer's arithmetic
/// stays honest about what it lost.
#[test]
fn declared_loss_survives_a_process_boundary() {
    let mut halves = FacultyStream::spawn(&mut relay("gap"), TEXT_PLAIN, UNIT_BYTES)
        .expect("start the streaming faculty");
    let frames = drain(halves.output);
    for token in ["alpha", "beta", "gamma"] {
        halves.input.text(token).expect("stream a token");
    }
    let sink = halves
        .input
        .finish(EndStatus::Complete)
        .expect("end the input stream");
    drop(sink);

    let mut gaps = Vec::new();
    let mut records = Vec::new();
    loop {
        match next(&frames) {
            Frame::Record(record) => records.push(record),
            Frame::Gap(gap) => gaps.push(gap),
            Frame::End(status) => {
                assert_eq!(status, EndStatus::Complete);
                break;
            }
        }
    }
    assert_eq!(gaps.len(), 1, "the relay declared exactly one gap");
    assert_eq!(gaps[0].extent, "beta".len() as u64, "the gap says how much");
    assert!(gaps[0].reason.contains("deliberately skipped"));
    // The gap advanced the unit clock, so the record after it is offset by the
    // lost content rather than pretending it never was.
    let after = records
        .iter()
        .find(|r| r.index > gaps[0].index)
        .expect("a record follows the gap");
    assert_eq!(after.offset, gaps[0].offset + gaps[0].extent);
    assert_eq!(
        records
            .iter()
            .map(|r| r.text().unwrap())
            .collect::<Vec<_>>(),
        ["ALPHA", "GAMMA"]
    );
}

/// A consumer that does not understand the modality refuses it rather than
/// interpreting the bytes as whatever it was hoping for.
#[test]
fn a_faculty_refuses_a_modality_it_does_not_understand() {
    let mut halves = FacultyStream::spawn(
        &mut relay("echo"),
        "audio/L16;rate=24000;channels=1",
        "samples",
    )
    .expect("start the streaming faculty");
    // The relay reads the preamble, sees a modality it has no vocoder for, and
    // exits. Writing into the closed pipe may fail, which is the same news.
    let _ = halves.input.record(&[0u8; 32], 16);
    let status = halves.stream.wait().expect("reap the faculty");
    assert!(
        !status.success(),
        "a faculty handed the wrong modality must fail loudly"
    );
}

/// The convention composes with the rest of Unix, which is the reason it is on a
/// pipe: a stream captured to a file is the same bytes, replayable, and a
/// consumer of the replay reaches the same conclusions.
#[test]
fn a_captured_stream_replays_identically() {
    let mut buffer = Vec::new();
    {
        let mut writer =
            framed_stream::FramedWriter::open(&mut buffer, TEXT_PLAIN, UNIT_BYTES).unwrap();
        writer.text("captured ").unwrap();
        writer.text("and ").unwrap();
        writer.text("replayed").unwrap();
        writer.finish(EndStatus::Complete).unwrap();
    }
    let path = std::env::temp_dir().join(format!(
        "drive-framed-capture-{}.bin",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::File::create(&path)
        .unwrap()
        .write_all(&buffer)
        .unwrap();

    let file = std::fs::File::open(&path).unwrap();
    let mut reader = FramedReader::open(file).unwrap();
    let mut text = String::new();
    loop {
        match reader.next_frame().unwrap() {
            Frame::Record(record) => text.push_str(record.text().unwrap()),
            Frame::Gap(_) => panic!("no gaps here"),
            Frame::End(status) => {
                assert_eq!(status, EndStatus::Complete);
                break;
            }
        }
    }
    assert_eq!(text, "captured and replayed");
    let _ = std::fs::remove_file(&path);
}
