//! `framed_relay` — the reference streaming faculty, and the fixture the
//! convention is proved against.
//!
//! It does what a real streaming faculty does, minus the modality: reads a
//! framed stream on stdin, does something per record, and writes a framed
//! stream on stdout — incrementally, so a consumer sees output before the input
//! has finished arriving. That last property is the whole reason the convention
//! exists, and the only way to test it is with a real process on the far end of
//! a real pipe.
//!
//! A speech faculty is the same program with a vocoder in the middle: text
//! records in, PCM records out, first sound before the last token. A camera
//! faculty is the same program with no input stream at all. A robot is the same
//! program with two.
//!
//! ```text
//!   drive ──framed text──▶ framed_relay ──framed text──▶ drive
//! ```
//!
//! MODES (argv[1], default `echo`):
//!   - `echo`     — one output record per input record, uppercased.
//!   - `words`    — accumulate text and emit one record per whitespace-delimited
//!                  WORD, which is the realistic shape: a synthesizer does not
//!                  emit one unit of output per unit of input, it re-chunks.
//!   - `gap`      — like `echo`, but declares a gap instead of relaying the
//!                  second record, to exercise announced loss.
//!   - `truncate` — relay one record then exit WITHOUT a terminator, so a
//!                  consumer must report truncation rather than a clean end.
//!   - `abort`    — relay one record then end the stream as aborted.

use std::io::Write;

use framed_stream::{EndStatus, Frame, FramedReader, FramedWriter, TEXT_PLAIN, UNIT_BYTES};

fn main() {
    if let Err(error) = run() {
        eprintln!("framed_relay: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "echo".to_string());
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = FramedReader::open(stdin.lock())?;
    // A consumer that does not understand the modality must refuse it rather
    // than interpret the bytes as whatever it was hoping for.
    reader.require_content_type(TEXT_PLAIN)?;
    let mut writer = FramedWriter::open(stdout.lock(), TEXT_PLAIN, UNIT_BYTES)?;

    let mut pending = String::new();
    let mut relayed = 0usize;
    loop {
        match reader.next_frame()? {
            Frame::Record(record) => {
                let text = record.text()?;
                match mode.as_str() {
                    "words" => {
                        pending.push_str(text);
                        emit_complete_words(&mut writer, &mut pending)?;
                    }
                    "gap" if relayed == 1 => {
                        writer.gap(text.len() as u64, "relay mode `gap`: deliberately skipped")?;
                    }
                    "truncate" if relayed == 1 => {
                        // Exit without a terminator, and without running the
                        // writer's Drop (process::exit does not unwind), so the
                        // consumer sees a TRUNCATED stream rather than a short
                        // complete one — a faculty that died mid-utterance.
                        std::process::exit(0);
                    }
                    "abort" if relayed == 1 => {
                        let mut sink =
                            writer.finish(EndStatus::Aborted("relay mode `abort`".into()))?;
                        sink.flush()?;
                        return Ok(());
                    }
                    _ => writer.text(&text.to_uppercase())?,
                }
                relayed += 1;
            }
            Frame::Gap(gap) => {
                // Loss travels: a relay that hides an upstream gap would turn
                // missing content into apparent content one hop later.
                writer.gap(gap.extent, &format!("relayed upstream gap: {}", gap.reason))?;
            }
            Frame::End(status) => {
                if mode == "words" && !pending.is_empty() {
                    let tail = std::mem::take(&mut pending);
                    writer.text(&tail.to_uppercase())?;
                }
                // An upstream abort is relayed as an abort: a consumer must not
                // be told the content is complete when its source said otherwise.
                let out = match status {
                    EndStatus::Complete => EndStatus::Complete,
                    EndStatus::Aborted(reason) => {
                        EndStatus::Aborted(format!("upstream aborted: {reason}"))
                    }
                };
                let mut sink = writer.finish(out)?;
                sink.flush()?;
                return Ok(());
            }
        }
    }
}

/// Emit one record per complete word, keeping the unfinished tail buffered —
/// the re-chunking a real synthesizer does.
fn emit_complete_words<W: Write>(
    writer: &mut FramedWriter<W>,
    pending: &mut String,
) -> anyhow::Result<()> {
    while let Some(cut) = pending.find(char::is_whitespace) {
        let word: String = pending.drain(..cut).collect();
        // Drop the delimiter itself.
        let mut chars = pending.chars();
        let delim_len = chars.next().map(char::len_utf8).unwrap_or(0);
        pending.drain(..delim_len);
        if !word.is_empty() {
            writer.text(&word.to_uppercase())?;
        }
    }
    Ok(())
}
