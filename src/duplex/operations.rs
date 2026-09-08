//! Finite operations over one explicitly chosen live-session control directory.
//! These never load weights, open devices or infer that a running loop exists.
//! A queued line is a handoff, not a claim that any audio has been played.

use crate::clock;
use anyhow::{bail, Context, Result};
#[cfg(any(feature = "duplex", test))]
use std::io::Write as _;
use std::path::{Path, PathBuf};

pub(super) const TRANSCRIPT_FILE: &str = "transcript.jsonl";
const CURSOR_FILE: &str = "cursor";
pub(super) const HOLD_FILE: &str = "hold";
const INJECT_DIR: &str = "inject";
const RELEASE_FILE: &str = "release";

#[derive(Clone, Debug)]
pub struct Session {
    path: PathBuf,
}
#[derive(Clone, Copy, Debug)]
pub struct ReadOptions {
    pub peek: bool,
    pub all: bool,
    pub hold_secs: u64,
}
impl Default for ReadOptions {
    fn default() -> Self {
        Self {
            peek: false,
            all: false,
            hold_secs: 180,
        }
    }
}
#[derive(Clone, Debug)]
pub struct ReadObservation {
    pub lines: Vec<Line>,
    pub cursor: u64,
    pub transcript_at: u64,
    /// None for peek; otherwise a hold request was published before reading.
    /// The running loop polls that request; this is not an audio-drain barrier.
    pub requested_hold_secs: Option<u64>,
}
#[derive(Clone, Debug)]
pub struct SayReceipt {
    pub queued: PathBuf,
    pub cursor: u64,
    pub kept_floor: bool,
}
impl SayReceipt {
    pub fn queue_id(&self) -> String {
        self.queued
            .file_name()
            .expect("queue file has name")
            .to_string_lossy()
            .into_owned()
    }
}
#[derive(Clone, Copy, Debug)]
pub struct ReleaseReceipt {
    pub cursor: u64,
    pub kept_cursor: bool,
}
#[derive(Clone, Copy, Debug)]
pub struct Status {
    pub transcript_lines: usize,
    pub transcript_at: u64,
    pub cursor: u64,
    pub unread: u64,
    pub floor_held: bool,
    pub queued: usize,
}

impl Session {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Publish the one-sided floor request first, then read. The cursor is not
    /// consumed. Far-end input is never paused and may continue to arrive.
    pub fn read(&self, options: ReadOptions) -> Result<ReadObservation> {
        ensure_session(&self.path)?;
        if !options.peek {
            take_floor(&self.path, options.hold_secs)?;
        }
        let lines = read_lines(&self.path)?;
        let cursor = read_cursor(&self.path)?;
        let transcript_at = lines.last().map(|line| line.seq).unwrap_or(cursor);
        let shown = lines
            .into_iter()
            .filter(|line| options.all || line.seq > cursor)
            .collect();
        Ok(ReadObservation {
            lines: shown,
            cursor,
            transcript_at,
            requested_hold_secs: (!options.peek).then_some(options.hold_secs),
        })
    }

    /// Queue literal prose atomically, then advance past the transcript as it
    /// exists at this operation, and optionally give the floor back. These are
    /// separate existing file publications: an error after queueing must not be
    /// retried as if nothing happened.
    pub fn say(&self, text: &str, keep_floor: bool) -> Result<SayReceipt> {
        validate_text(text)?;
        ensure_session(&self.path)?;
        let queued = inject(&self.path, text.trim())?;
        let finish = || -> Result<u64> {
            let last = latest_sequence(&self.path)?;
            write_cursor(&self.path, last)?;
            if !keep_floor {
                give_floor(&self.path)?;
            }
            Ok(last)
        };
        let cursor = finish().with_context(|| format!("line already queued as {}; completing cursor/floor update failed (do not blindly retry)", queued.file_name().unwrap().to_string_lossy()))?;
        Ok(SayReceipt {
            queued,
            cursor,
            kept_floor: keep_floor,
        })
    }

    pub fn release(&self, keep_cursor: bool) -> Result<ReleaseReceipt> {
        ensure_session(&self.path)?;
        give_floor(&self.path)?;
        let cursor = if keep_cursor {
            read_cursor(&self.path)?
        } else {
            let last = latest_sequence(&self.path)?;
            write_cursor(&self.path, last)
                .context("floor released, but cursor publication failed")?;
            last
        };
        Ok(ReleaseReceipt {
            cursor,
            kept_cursor: keep_cursor,
        })
    }

    /// Control-file observation only, not a process heartbeat. Expired holds
    /// are cleared as in the runtime; no model/device is inspected.
    pub fn status(&self) -> Result<Status> {
        let lines = read_lines(&self.path)?;
        let cursor = read_cursor(&self.path)?;
        let transcript_at = lines.last().map(|line| line.seq).unwrap_or(0);
        let queued = queued_files(&self.path)?.len();
        Ok(Status {
            transcript_lines: lines.len(),
            transcript_at,
            cursor,
            unread: transcript_at.saturating_sub(cursor),
            floor_held: floor_held(&self.path)?,
            queued,
        })
    }
}

pub fn validate_text(text: &str) -> Result<()> {
    if text.trim().is_empty() {
        bail!("nothing to say");
    }
    Ok(())
}

pub(super) fn ensure_session(session: &Path) -> Result<()> {
    std::fs::create_dir_all(session)
        .with_context(|| format!("create session directory {}", session.display()))?;
    std::fs::create_dir_all(session.join(INJECT_DIR))?;
    Ok(())
}

pub(super) fn now_millis() -> Result<u64> {
    Ok(clock::now()?.to_unix_milliseconds() as u64)
}

// ── the transcript file ────────────────────────────────────────────────────

/// Who said it. `model` is the model's own words, `agent` is a line handed to
/// it, `far` is the other end of the channel — for whom this model can report
/// presence and duration but not words.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg(feature = "duplex")]
pub(super) enum Speaker {
    Model,
    Agent,
    Far,
}

#[cfg(feature = "duplex")]
impl Speaker {
    pub(super) fn tag(self) -> &'static str {
        match self {
            Speaker::Model => "model",
            Speaker::Agent => "agent",
            Speaker::Far => "far",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub seq: u64,
    pub at_ms: u64,
    pub speaker: String,
    pub text: String,
}

/// One line per entry, appended and flushed as it happens, so a reader in
/// another process always sees a whole line or nothing.
#[cfg(any(feature = "duplex", test))]
pub(super) fn append_line(session: &Path, line: &Line) -> Result<()> {
    let path = session.join(TRANSCRIPT_FILE);
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    let record = serde_json::json!({
        "seq": line.seq,
        "at_ms": line.at_ms,
        "speaker": line.speaker,
        "text": line.text,
    });
    writeln!(file, "{record}")?;
    file.flush()?;
    Ok(())
}

pub(super) fn read_lines(session: &Path) -> Result<Vec<Line>> {
    let path = session.join(TRANSCRIPT_FILE);
    let Some(text) = optional_text(&path)? else {
        return Ok(Vec::new());
    };
    let mut lines = Vec::new();
    for raw in text.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
            continue;
        };
        lines.push(Line {
            seq: value.get("seq").and_then(|v| v.as_u64()).unwrap_or(0),
            at_ms: value.get("at_ms").and_then(|v| v.as_u64()).unwrap_or(0),
            speaker: value
                .get("speaker")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_owned(),
            text: value
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned(),
        });
    }
    Ok(lines)
}

pub(super) fn read_cursor(session: &Path) -> Result<u64> {
    match optional_text(&session.join(CURSOR_FILE))? {
        Some(text) => text.trim().parse().context("invalid Duplex cursor"),
        None => Ok(0),
    }
}

fn latest_sequence(session: &Path) -> Result<u64> {
    match read_lines(session)?.last() {
        Some(line) => Ok(line.seq),
        None => read_cursor(session),
    }
}

fn optional_text(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn remove_optional_file(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
    }
}

pub(super) fn write_cursor(session: &Path, seq: u64) -> Result<()> {
    let path = session.join(CURSOR_FILE);
    let staged = session.join(".cursor.tmp");
    std::fs::write(&staged, seq.to_string())?;
    std::fs::rename(&staged, &path).with_context(|| format!("publish {}", path.display()))?;
    Ok(())
}

// ── the floor ──────────────────────────────────────────────────────────────

/// The hold is a file with a deadline in it — the same primitive the
/// half-duplex bridge used to keep its ears off its own mouth, here keeping
/// the model quiet while a reader catches up. A file survives the reader
/// dying; the deadline means the channel recovers when it does.
pub(super) fn take_floor(session: &Path, hold_secs: u64) -> Result<()> {
    let deadline = now_millis()?.saturating_add(hold_secs.saturating_mul(1_000));
    let staged = session.join(".hold.tmp");
    std::fs::write(&staged, deadline.to_string())?;
    std::fs::rename(&staged, session.join(HOLD_FILE)).context("publish the floor hold")?;
    remove_optional_file(&session.join(RELEASE_FILE))
        .context("floor hold was published, but stale release cleanup failed")?;
    Ok(())
}

pub(super) fn floor_held(session: &Path) -> Result<bool> {
    let Some(text) = optional_text(&session.join(HOLD_FILE))? else {
        return Ok(false);
    };
    let deadline: u64 = text
        .trim()
        .parse()
        .context("invalid Duplex floor deadline")?;
    if now_millis()? > deadline {
        // Expired holds are cleared by whoever notices, so a dead reader
        // cannot mute the channel indefinitely.
        give_floor(session).context("clear expired floor hold")?;
        return Ok(false);
    }
    Ok(true)
}

pub(super) fn give_floor(session: &Path) -> Result<()> {
    remove_optional_file(&session.join(HOLD_FILE))
}

// ── the inject queue ───────────────────────────────────────────────────────

/// Queue one line. Written under a temporary name and renamed into place, so
/// the loop never observes a half-written file.
pub(super) fn inject(session: &Path, text: &str) -> Result<PathBuf> {
    let dir = session.join(INJECT_DIR);
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let stamp = clock::tai_nanoseconds_now()?;
    let staged = dir.join(format!(".{stamp}.tmp"));
    let published = dir.join(format!("{stamp}.txt"));
    std::fs::write(&staged, text)?;
    std::fs::rename(&staged, &published)
        .with_context(|| format!("publish {}", published.display()))?;
    Ok(published)
}

fn queued_files(session: &Path) -> Result<Vec<PathBuf>> {
    let dir = session.join(INJECT_DIR);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).context("read Duplex inject queue"),
    };
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.context("read Duplex inject queue entry")?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "txt") && entry.file_type()?.is_file() {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// The consumed prefix and, if consumption stopped, its first cleanup failure.
/// Failed and later queue files are not consumed or returned as speech.
#[cfg(any(feature = "duplex", test))]
#[derive(Debug, Default)]
pub(super) struct InjectDrain {
    pub lines: Vec<String>,
    pub cleanup_failure: Option<anyhow::Error>,
}

/// Take complete queued lines oldest first. Acquisition/read errors consume
/// nothing; a cleanup error retains the successfully consumed prefix in the
/// outcome instead of losing it through an early return.
#[cfg(any(feature = "duplex", test))]
pub(super) fn drain_inject(session: &Path) -> Result<InjectDrain> {
    drain_inject_with(session, |path| std::fs::remove_file(path))
}

/// The removal seam permits deterministic CPU-only filesystem fault tests.
#[cfg(any(feature = "duplex", test))]
pub(super) fn drain_inject_with(
    session: &Path,
    mut remove: impl FnMut(&Path) -> std::io::Result<()>,
) -> Result<InjectDrain> {
    // Stage the selected reads before consuming any queue file. A later read
    // failure must not discard earlier lines without returning them.
    let mut staged = Vec::new();
    for path in queued_files(session)? {
        let text = optional_text(&path)?;
        staged.push((path, text));
    }
    let mut drained = InjectDrain::default();
    for (path, text) in staged {
        let Some(text) = text else {
            // Do not delete a newly arrived file whose earlier staged read
            // was already NotFound: those bytes have not been read.
            continue;
        };
        match remove(&path) {
            Ok(()) => {
                let text = text.trim();
                if !text.is_empty() {
                    drained.lines.push(text.to_owned());
                }
            }
            // A file that disappeared after the read was not consumed by us.
            // Do not inject its stale bytes.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                drained.cleanup_failure = Some(anyhow::Error::new(error).context(format!(
                    "consume queued line {}; this file and later entries remain queued",
                    path.display()
                )));
                break;
            }
        }
    }
    Ok(drained)
}
