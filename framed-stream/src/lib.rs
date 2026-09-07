//! **The framed-stream convention** — how a faculty carries a modality, in
//! either direction, over an ordinary pipe.
//!
//! # Why this is a crate
//!
//! It was a module in `drive` for one commit, because `soma/` and `faculties/`
//! were being edited concurrently and it touched neither. That was a scheduling
//! fact, not a design one: a convention only one program can link is not a
//! convention. A speech faculty, a camera faculty, `soma-client`'s capture
//! decoder — none of them wants a cognition loop, a sandbox client, or a pile,
//! and none of them should have to take one to agree with drive about what a
//! record is. So this crate is **std + anyhow**, has no dependency on drive, and
//! ships its own reference faculty (`framed_relay`) and its own
//! process-boundary gate, which is what lets its guarantees be tested by
//! whoever links it rather than by whoever happens to host it.
//!
//! # Why a pipe, and why framed
//!
//! Drive needs to hand a faculty a stream it is still producing: say "start
//! speaking" ONCE and then feed tokens in as it generates them, rather than
//! handing over one finished string. And it needs the other direction too — a
//! faculty that owns a device, a conversation, or a robot, reporting back
//! continuously.
//!
//! MCP cannot do this, and should not learn to. MCP is request/response: it
//! starts a tool call and the call returns. That makes it the perfect CONTROL
//! plane — the mind says "start speaking", and that is one request — but it can
//! never be the DATA plane, because there is no way to keep feeding a call that
//! has not returned. So the split is: **MCP (or a plain spawn) starts the
//! process and hands it a pipe; the streaming happens on the pipe.**
//!
//! A pipe, specifically, because that is what CLI tools already speak. A faculty
//! that reads content-typed framed records on stdin and writes them on stdout
//! composes with everything Unix has: `tee` it to a file, `nc` it to another
//! host, splice it into another faculty, capture it for a golden test. "Connect
//! to a robot" or "connect to a video call" stops being an integration and
//! becomes "something else that produces frames on a pipe".
//!
//! Most of what drive needs never crosses a sandbox at all: drive and the
//! faculties run side by side on the same host, so drive → a speech faculty is
//! ordinary local pipes with no playground in the path. That is the case this
//! module serves. (See *What the sandbox case would need*, below, for the one
//! that is not built here.)
//!
//! # The read half already existed
//!
//! `soma-client` is the prototype: Soma owns the microphone, emits one fixed
//! record per 80 ms frame with a `frame_index` and a `first_sample_index`, and a
//! consumer that misses a record gets a loud discontinuity error instead of
//! apparent silence. This module is that idea generalised off HTTP and onto
//! pipes, and made bidirectional and modality-agnostic — deliberately following
//! its two-clock scheme rather than inventing a second one.
//!
//! # The wire format
//!
//! ```text
//! STREAM   := PREAMBLE RECORD* TERMINATOR
//!
//! PREAMBLE := "FRMSTRM\0"          magic, 8 bytes
//!             version              u16le, currently 1
//!             flags                u16le, reserved, must be 0
//!             content_type         u16le length + UTF-8 bytes
//!             unit                 u16le length + UTF-8 bytes
//!
//! RECORD   := 0x01                 kind: DATA
//!             index                u64le  record ordinal, +1 per record
//!             offset               u64le  cumulative extent before this record
//!             extent               u64le  this record's extent, in `unit`
//!             content_type         u16le length + UTF-8 (EMPTY = the stream's)
//!             payload              u32le length + bytes
//!
//!           | 0x02                 kind: GAP — content the producer could not
//!             index                u64le  deliver, declared rather than hidden
//!             offset               u64le
//!             extent               u64le  how much of `unit` was skipped
//!             reason               u16le length + UTF-8
//!
//! TERMINATOR := 0x03               kind: END
//!             index                u64le
//!             offset               u64le
//!             status               u8: 0 = complete, 1 = aborted
//!             reason               u16le length + UTF-8 (empty when complete)
//! ```
//!
//! # The four guarantees
//!
//! **1. Every record carries its content type.** The preamble declares the
//! stream's type; a record may override it with a non-empty type of its own, and
//! an empty type means "the stream's". So a record's type is always determinate
//! (this is what [`Record::content_type`] returns), a homogeneous stream pays
//! two bytes per record for the property, and a heterogeneous one — telemetry
//! interleaved with keyframes — needs no separate channel.
//!
//! **2. Continuity is checkable, in two clocks.** `index` counts records;
//! `offset` counts the modality's own unit — samples for PCM, bytes for text,
//! frames for video, whatever the preamble declares. A reader requires
//! `index == expected` and `offset == expected`, exactly as `soma-client`
//! requires both of its clocks, and advances `expected_offset` by the record's
//! declared `extent`. Two clocks rather than one because they catch different
//! lies: a dropped record breaks `index`, and a record that under- or
//! over-reports its own content breaks `offset`.
//!
//! **3. A producer that cannot keep up must SAY SO.** On a pipe, backpressure is
//! the default: a producer whose consumer is slow simply blocks in `write`. A
//! producer that must NOT block — a live device with a fixed clock — has exactly
//! one legal alternative: emit a [`Gap`] record naming what it
//! skipped and why, which advances both clocks explicitly. Silently renumbering
//! is not available: the reader would reject the next record. There is no path
//! by which missing content becomes apparent content.
//!
//! **4. "The producer ended" is distinguishable from "the pipe broke".** A
//! stream ends with an explicit END record carrying a status. A reader that hits
//! clean EOF *without* having seen END reports a TRUNCATED stream — because a
//! truncated stream and a complete short one are otherwise byte-identical, and
//! that ambiguity is the same class of failure as a missing binary reading as a
//! clean exit. A writer dropped without [`FramedWriter::finish`] makes a
//! best-effort attempt to write `END{aborted}` on the way out, so even a
//! panicking producer usually manages to say that it failed.
//!
//! # Carrying a modality it was not designed for
//!
//! Nothing above mentions audio. To carry a modality, a producer answers three
//! questions in the preamble and one per record:
//!
//! | | audio (PCM) | text/token stream | video | robot telemetry |
//! |---|---|---|---|---|
//! | `content_type` | `audio/L16;rate=24000;channels=1` | `text/plain;charset=utf-8` | `image/jpeg` | `application/json` |
//! | `unit` | `samples` | `bytes` | `frames` | `samples` |
//! | `extent` | samples in this record | bytes in this record | `1` | `1` |
//!
//! A consumer that does not understand a content type must refuse it loudly
//! ([`FramedReader::require_content_type`]) rather than treat the bytes as
//! whatever it expected. The framing layer is deliberately ignorant of all of
//! them: it moves length-delimited, content-typed, continuity-checked byte
//! records, and the modality lives entirely in the type string and the unit.
//!
//! # What the sandbox case would need (NOT built here)
//!
//! A process INSIDE a playground sandbox cannot be piped to from outside today.
//! `exec` runs to completion, `job_exec` polls for output, and `write` is
//! implemented as an exec with `stdin: Some(bytes)` — real byte-into-stdin
//! machinery, but one shot: the pipe closes when the call returns, and there is
//! a 3 MiB ceiling. Streaming into the sandbox needs one new playground verb:
//! *start a process and hold a bidirectional pipe open across the boundary*,
//! with the MCP call returning a handle rather than an output. This module needs
//! nothing else from it — the format, the continuity checks, and the
//! end-vs-broken distinction all work unchanged over whatever byte transport
//! that verb provides. It is bounded, real, and deliberately not built here.
//!
//! # What is proven, and what is not
//!
//! The unit tests at the foot of this file drive the encoding through in-memory
//! buffers; `tests/framed_stream.rs` drives real records through real OS pipes
//! into a real child process (`framed_relay`, the reference faculty), in both
//! directions at once, and proves every guarantee above including truncation
//! detection and gap accounting. What is NOT proven is any modality: nothing in
//! this crate produces PCM or video, so the audio row of that table is a
//! contract, not a measurement.

use std::io::{ErrorKind, Read, Write};

/// Magic at the head of every framed stream. A reader attached to the wrong
/// producer fails here, immediately, instead of misparsing.
pub const MAGIC: &[u8; 8] = b"FRMSTRM\0";
/// Wire version this module writes and accepts.
pub const VERSION: u16 = 1;

/// Kind byte for a data record.
const KIND_DATA: u8 = 0x01;
/// Kind byte for a declared gap.
const KIND_GAP: u8 = 0x02;
/// Kind byte for the end-of-stream terminator.
const KIND_END: u8 = 0x03;

/// Largest payload a reader will allocate for one record (16 MiB). A corrupt or
/// hostile length field must not become an allocation.
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
/// Largest content-type / reason string a reader will accept.
pub const MAX_STRING_BYTES: usize = 4096;

/// Conventional content type for an incremental UTF-8 text stream — what drive
/// feeds a speech faculty as it generates.
pub const TEXT_PLAIN: &str = "text/plain;charset=utf-8";
/// Conventional unit for a text stream: bytes of UTF-8.
pub const UNIT_BYTES: &str = "bytes";
/// Inkling's dMel audio input: `frames * 80` quantised mel levels, one byte
/// each, in a stream counted in frames of 50 ms. The ear faculty writes
/// them; the mind renders each record as the model's own audio part.
pub const INKLING_DMEL: &str = "application/x-inkling-dmel";
/// Inkling's image input: whole patches as `mary::models::inkling::patches`
/// lays them out (little-endian f32, 9,600 values each: two time steps of a
/// 40 x 40 x 3 square), in a stream counted in patches. The eye faculty
/// writes them; the mind renders each record as the model's own image part.
pub const INKLING_PATCHES: &str = "application/x-inkling-patches";
/// Conventional unit for a patch stream: patches.
pub const UNIT_PATCHES: &str = "patches";
/// Conventional unit for an audio stream: PCM sample frames.
pub const UNIT_SAMPLES: &str = "samples";
/// Conventional unit for a video stream: frames.
pub const UNIT_FRAMES: &str = "frames";

/// How a stream ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndStatus {
    /// The producer said everything it had to say.
    Complete,
    /// The producer gave up, for the stated reason. The stream is well-formed;
    /// its CONTENT is incomplete and the consumer knows exactly that.
    Aborted(String),
}

impl EndStatus {
    fn code(&self) -> u8 {
        match self {
            EndStatus::Complete => 0,
            EndStatus::Aborted(_) => 1,
        }
    }

    fn reason(&self) -> &str {
        match self {
            EndStatus::Complete => "",
            EndStatus::Aborted(reason) => reason,
        }
    }
}

/// What a reader got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// One content-typed record of the modality.
    Record(Record),
    /// The producer declared content it could not deliver — never silence.
    Gap(Gap),
    /// The stream ended, in the stated way. No further frames follow.
    End(EndStatus),
}

/// One data record: where it sits in both clocks, what it is, and its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Record ordinal, +1 per record (including gaps).
    pub index: u64,
    /// Cumulative extent, in the stream's `unit`, of everything before this.
    pub offset: u64,
    /// This record's extent in the stream's `unit`.
    pub extent: u64,
    /// This record's own content type, or empty meaning "the stream's".
    /// Read it through [`Record::content_type`], which resolves the default.
    pub content_type_override: String,
    /// The modality bytes.
    pub payload: Vec<u8>,
    /// The stream's declared content type, copied in by the reader so a record
    /// is self-describing once it has been handed to a consumer.
    stream_content_type: String,
}

impl Record {
    /// This record's content type: its own override, or the stream's.
    pub fn content_type(&self) -> &str {
        if self.content_type_override.is_empty() {
            &self.stream_content_type
        } else {
            &self.content_type_override
        }
    }

    /// The payload as UTF-8 text, for text-typed streams.
    pub fn text(&self) -> anyhow::Result<&str> {
        std::str::from_utf8(&self.payload)
            .map_err(|error| anyhow::anyhow!("record {} is not valid UTF-8: {error}", self.index))
    }
}

/// A producer's declaration that it dropped content, rather than hiding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub index: u64,
    pub offset: u64,
    /// How much of the stream's `unit` was skipped.
    pub extent: u64,
    /// Why — recorded so a consumer can say what it lost, not merely that it
    /// lost something.
    pub reason: String,
}

// ── writing ─────────────────────────────────────────────────────────────────

/// The producing half: writes a preamble, then records, then a terminator.
///
/// Every record is FLUSHED as it is written. That is what makes this a stream
/// rather than a batch: the point of feeding a speech faculty token by token is
/// that it can start speaking before generation finishes, which it cannot do if
/// the bytes are sitting in a buffer.
pub struct FramedWriter<W: Write> {
    sink: Option<W>,
    index: u64,
    offset: u64,
    content_type: String,
    finished: bool,
}

impl<W: Write> FramedWriter<W> {
    /// Open a stream of `content_type`, measured in `unit`, and write its
    /// preamble immediately so a consumer can validate before any content
    /// exists.
    pub fn open(mut sink: W, content_type: &str, unit: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            content_type.len() <= MAX_STRING_BYTES && unit.len() <= MAX_STRING_BYTES,
            "content type / unit exceed {MAX_STRING_BYTES} bytes"
        );
        let mut preamble = Vec::with_capacity(32 + content_type.len() + unit.len());
        preamble.extend_from_slice(MAGIC);
        preamble.extend_from_slice(&VERSION.to_le_bytes());
        preamble.extend_from_slice(&0u16.to_le_bytes()); // flags, reserved
        put_string(&mut preamble, content_type);
        put_string(&mut preamble, unit);
        sink.write_all(&preamble)?;
        sink.flush()?;
        Ok(Self {
            sink: Some(sink),
            index: 0,
            offset: 0,
            content_type: content_type.to_string(),
            finished: false,
        })
    }

    /// A text stream: `text/plain;charset=utf-8`, measured in bytes.
    pub fn open_text(sink: W) -> anyhow::Result<Self> {
        Self::open(sink, TEXT_PLAIN, UNIT_BYTES)
    }

    /// The stream's declared content type.
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    /// The next record ordinal this writer will emit.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// The cumulative extent emitted so far, in the stream's unit.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Write one record of `extent` units, in the stream's own content type.
    pub fn record(&mut self, payload: &[u8], extent: u64) -> anyhow::Result<()> {
        self.record_as("", payload, extent)
    }

    /// Write one record whose content type OVERRIDES the stream's — the
    /// heterogeneous case (a keyframe among telemetry). Pass `""` for "the
    /// stream's type".
    pub fn record_as(
        &mut self,
        content_type: &str,
        payload: &[u8],
        extent: u64,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(!self.finished, "the stream has already been ended");
        anyhow::ensure!(
            payload.len() <= MAX_PAYLOAD_BYTES,
            "record payload {} exceeds {MAX_PAYLOAD_BYTES} bytes",
            payload.len()
        );
        anyhow::ensure!(
            content_type.len() <= MAX_STRING_BYTES,
            "content type exceeds {MAX_STRING_BYTES} bytes"
        );
        let mut buf = Vec::with_capacity(32 + content_type.len() + payload.len());
        buf.push(KIND_DATA);
        buf.extend_from_slice(&self.index.to_le_bytes());
        buf.extend_from_slice(&self.offset.to_le_bytes());
        buf.extend_from_slice(&extent.to_le_bytes());
        put_string(&mut buf, content_type);
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(payload);
        self.emit(&buf)?;
        self.index += 1;
        self.offset += extent;
        Ok(())
    }

    /// Write one text record, whose extent is its byte length. The natural call
    /// for feeding a token stream: one token, one record.
    pub fn text(&mut self, text: &str) -> anyhow::Result<()> {
        self.record(text.as_bytes(), text.len() as u64)
    }

    /// Declare a gap of `extent` units that this producer could not deliver.
    ///
    /// This is the ONLY legal way to skip content. It advances both clocks
    /// explicitly, so the loss is visible to the consumer as loss.
    pub fn gap(&mut self, extent: u64, reason: &str) -> anyhow::Result<()> {
        anyhow::ensure!(!self.finished, "the stream has already been ended");
        anyhow::ensure!(
            reason.len() <= MAX_STRING_BYTES,
            "gap reason exceeds {MAX_STRING_BYTES} bytes"
        );
        let mut buf = Vec::with_capacity(32 + reason.len());
        buf.push(KIND_GAP);
        buf.extend_from_slice(&self.index.to_le_bytes());
        buf.extend_from_slice(&self.offset.to_le_bytes());
        buf.extend_from_slice(&extent.to_le_bytes());
        put_string(&mut buf, reason);
        self.emit(&buf)?;
        self.index += 1;
        self.offset += extent;
        Ok(())
    }

    /// End the stream and return the sink. After this the writer is spent; its
    /// `Drop` will not write a second terminator.
    pub fn finish(mut self, status: EndStatus) -> anyhow::Result<W> {
        self.write_end(&status)?;
        let mut sink = self.sink.take().expect("sink is present until finish");
        sink.flush()?;
        Ok(sink)
    }

    fn write_end(&mut self, status: &EndStatus) -> anyhow::Result<()> {
        anyhow::ensure!(!self.finished, "the stream has already been ended");
        let reason = status.reason();
        let mut buf = Vec::with_capacity(24 + reason.len());
        buf.push(KIND_END);
        buf.extend_from_slice(&self.index.to_le_bytes());
        buf.extend_from_slice(&self.offset.to_le_bytes());
        buf.push(status.code());
        put_string(&mut buf, reason);
        self.emit(&buf)?;
        self.finished = true;
        Ok(())
    }

    fn emit(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        let sink = self
            .sink
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("the stream's sink is gone"))?;
        sink.write_all(bytes)?;
        // Flush per record: a buffered stream is not a stream.
        sink.flush()?;
        Ok(())
    }
}

impl<W: Write> Drop for FramedWriter<W> {
    /// A writer that goes out of scope without [`finish`](Self::finish) makes a
    /// best-effort attempt to say so, so a consumer sees `END{aborted}` rather
    /// than an ambiguous truncation. If the process is dying hard the write will
    /// fail and the consumer sees truncation instead — which is the honest
    /// report of what happened.
    fn drop(&mut self) {
        if self.finished || self.sink.is_none() {
            return;
        }
        let status = EndStatus::Aborted("writer dropped without finish()".to_string());
        let _ = self.write_end(&status);
    }
}

// ── reading ─────────────────────────────────────────────────────────────────

/// The consuming half: validates the preamble, then yields frames with both
/// clocks enforced.
pub struct FramedReader<R: Read> {
    source: R,
    content_type: String,
    unit: String,
    expect_index: u64,
    expect_offset: u64,
    ended: bool,
}

impl<R: Read> FramedReader<R> {
    /// Read and validate the preamble. Fails immediately on a stream that is not
    /// one of ours, or is a version this reader does not speak.
    pub fn open(mut source: R) -> anyhow::Result<Self> {
        let mut magic = [0u8; 8];
        read_exact_or_eof(&mut source, &mut magic, "stream preamble")?;
        anyhow::ensure!(
            &magic == MAGIC,
            "not a framed stream: magic {magic:?} (expected {MAGIC:?})"
        );
        let version = read_u16(&mut source, "version")?;
        anyhow::ensure!(
            version == VERSION,
            "framed stream version {version} is not supported (this reader speaks {VERSION})"
        );
        let flags = read_u16(&mut source, "flags")?;
        anyhow::ensure!(flags == 0, "framed stream sets reserved flags {flags:#x}");
        let content_type = read_string(&mut source, "content type")?;
        let unit = read_string(&mut source, "unit")?;
        Ok(Self {
            source,
            content_type,
            unit,
            expect_index: 0,
            expect_offset: 0,
            ended: false,
        })
    }

    /// The stream's declared content type.
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    /// The unit both `offset` and `extent` are measured in.
    pub fn unit(&self) -> &str {
        &self.unit
    }

    /// Refuse a stream whose declared content type is not `expected`. A consumer
    /// that does not understand a modality must say so rather than interpret the
    /// bytes as whatever it was hoping for.
    pub fn require_content_type(&self, expected: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.content_type == expected,
            "stream carries {} but this consumer requires {expected}",
            self.content_type
        );
        Ok(())
    }

    /// Block for the next frame.
    ///
    /// A clean EOF *before* an END record is an error naming the stream as
    /// TRUNCATED — never a quiet `None`, because "the producer finished" and
    /// "the producer died" must not look the same.
    pub fn next_frame(&mut self) -> anyhow::Result<Frame> {
        anyhow::ensure!(
            !self.ended,
            "the stream already ended; there is nothing after END"
        );
        let mut kind = [0u8; 1];
        match self.source.read(&mut kind) {
            Ok(0) => anyhow::bail!(
                "framed stream TRUNCATED: clean EOF after {} record(s) with no END record — \
                 the producer died rather than finished",
                self.expect_index
            ),
            Ok(_) => {}
            Err(error) => {
                return Err(anyhow::Error::new(error).context("read framed record kind"));
            }
        }
        match kind[0] {
            KIND_DATA => {
                let (index, offset, extent) = self.read_clocks("data record")?;
                let content_type_override = read_string(&mut self.source, "record content type")?;
                let len = read_u32(&mut self.source, "payload length")? as usize;
                anyhow::ensure!(
                    len <= MAX_PAYLOAD_BYTES,
                    "record {index} declares a {len}-byte payload, over the {MAX_PAYLOAD_BYTES} cap"
                );
                let mut payload = vec![0u8; len];
                read_exact_or_eof(&mut self.source, &mut payload, "record payload")?;
                self.advance(extent);
                Ok(Frame::Record(Record {
                    index,
                    offset,
                    extent,
                    content_type_override,
                    payload,
                    stream_content_type: self.content_type.clone(),
                }))
            }
            KIND_GAP => {
                let (index, offset, extent) = self.read_clocks("gap record")?;
                let reason = read_string(&mut self.source, "gap reason")?;
                self.advance(extent);
                Ok(Frame::Gap(Gap {
                    index,
                    offset,
                    extent,
                    reason,
                }))
            }
            KIND_END => {
                let index = read_u64(&mut self.source, "end index")?;
                let offset = read_u64(&mut self.source, "end offset")?;
                self.check_clocks("end record", index, offset)?;
                let mut code = [0u8; 1];
                read_exact_or_eof(&mut self.source, &mut code, "end status")?;
                let reason = read_string(&mut self.source, "end reason")?;
                self.ended = true;
                match code[0] {
                    0 => Ok(Frame::End(EndStatus::Complete)),
                    1 => Ok(Frame::End(EndStatus::Aborted(reason))),
                    other => anyhow::bail!("unknown end status {other}"),
                }
            }
            other => anyhow::bail!("unknown framed record kind {other:#x}"),
        }
    }

    /// Whether the END record has been seen.
    pub fn ended(&self) -> bool {
        self.ended
    }

    fn read_clocks(&mut self, what: &str) -> anyhow::Result<(u64, u64, u64)> {
        let index = read_u64(&mut self.source, "index")?;
        let offset = read_u64(&mut self.source, "offset")?;
        let extent = read_u64(&mut self.source, "extent")?;
        self.check_clocks(what, index, offset)?;
        Ok((index, offset, extent))
    }

    /// Both clocks, exactly as `soma-client` checks its two: a dropped record
    /// breaks `index`, a misdeclared extent breaks `offset`.
    fn check_clocks(&self, what: &str, index: u64, offset: u64) -> anyhow::Result<()> {
        anyhow::ensure!(
            index == self.expect_index,
            "framed stream discontinuity at {what}: index {index}, expected {} — \
             content was dropped without a gap record",
            self.expect_index
        );
        anyhow::ensure!(
            offset == self.expect_offset,
            "framed stream discontinuity at {what}: offset {offset} {}, expected {} — \
             a record misdeclared its extent",
            self.unit,
            self.expect_offset
        );
        Ok(())
    }

    fn advance(&mut self, extent: u64) {
        self.expect_index += 1;
        self.expect_offset += extent;
    }
}

// ── the process seam ────────────────────────────────────────────────────────

/// A faculty started as a child process with a framed stream in each direction.
///
/// This is the local case, which is most of what drive needs: drive and the
/// faculties run side by side, so "start speaking and feed it my tokens" is a
/// spawn and two pipes, with no sandbox in the path.
///
/// # Deadlock, and why the halves are separate
///
/// Two pipes between two processes deadlock if both fill at once: drive blocks
/// writing stdin while the child blocks writing stdout. [`spawn`](Self::spawn)
/// therefore hands back the two halves as independently owned values, so a
/// caller that streams in both directions can put the reader on its own thread.
/// A caller that only writes, or only reads, can ignore the other half. The type
/// does not hide the hazard behind a convenience method that would sometimes
/// hang.
pub struct FacultyStream {
    child: std::process::Child,
}

/// The two halves of a [`FacultyStream`], plus the child to wait on.
pub struct FacultyHalves {
    /// Framed records INTO the faculty's stdin.
    pub input: FramedWriter<std::process::ChildStdin>,
    /// The faculty's stdout, ready to be opened as a [`FramedReader`]. It is
    /// handed over unopened because opening reads the preamble, which BLOCKS
    /// until the child has written it — a caller that only writes must not be
    /// made to wait for that.
    pub output: std::process::ChildStdout,
    /// The running faculty.
    pub stream: FacultyStream,
}

impl FacultyStream {
    /// Start `command` with both pipes connected and write the input stream's
    /// preamble, declaring what drive is about to send.
    ///
    /// stderr is inherited: a faculty's diagnostics belong on drive's stderr,
    /// not swallowed into a pipe nobody reads.
    pub fn spawn(
        command: &mut std::process::Command,
        content_type: &str,
        unit: &str,
    ) -> anyhow::Result<FacultyHalves> {
        use anyhow::Context as _;
        use std::process::Stdio;

        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::inherit());
        let mut child = command.spawn().context("spawn the streaming faculty")?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("faculty stdin was not piped"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("faculty stdout was not piped"))?;
        let input = FramedWriter::open(stdin, content_type, unit)
            .context("write the input stream preamble")?;
        Ok(FacultyHalves {
            input,
            output: stdout,
            stream: FacultyStream { child },
        })
    }

    /// Wait for the faculty to exit and return its status.
    pub fn wait(&mut self) -> anyhow::Result<std::process::ExitStatus> {
        Ok(self.child.wait()?)
    }

    /// Kill the faculty. The consumer of its output stream will see a truncated
    /// stream, which is the correct report: it was killed, it did not finish.
    pub fn kill(&mut self) -> anyhow::Result<()> {
        Ok(self.child.kill()?)
    }
}

// ── primitives ──────────────────────────────────────────────────────────────

fn put_string(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u16).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

/// Read exactly `buf.len()` bytes. An EOF partway through is a TORN record, not
/// a clean end — the same distinction the END record draws at stream scope.
fn read_exact_or_eof<R: Read>(source: &mut R, buf: &mut [u8], what: &str) -> anyhow::Result<()> {
    source.read_exact(buf).map_err(|error| {
        if error.kind() == ErrorKind::UnexpectedEof {
            anyhow::anyhow!(
                "framed stream TRUNCATED inside {what}: {} byte(s) expected",
                buf.len()
            )
        } else {
            anyhow::Error::new(error).context(format!("read {what}"))
        }
    })
}

fn read_u16<R: Read>(source: &mut R, what: &str) -> anyhow::Result<u16> {
    let mut b = [0u8; 2];
    read_exact_or_eof(source, &mut b, what)?;
    Ok(u16::from_le_bytes(b))
}

fn read_u32<R: Read>(source: &mut R, what: &str) -> anyhow::Result<u32> {
    let mut b = [0u8; 4];
    read_exact_or_eof(source, &mut b, what)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64<R: Read>(source: &mut R, what: &str) -> anyhow::Result<u64> {
    let mut b = [0u8; 8];
    read_exact_or_eof(source, &mut b, what)?;
    Ok(u64::from_le_bytes(b))
}

fn read_string<R: Read>(source: &mut R, what: &str) -> anyhow::Result<String> {
    let len = read_u16(source, what)? as usize;
    anyhow::ensure!(
        len <= MAX_STRING_BYTES,
        "{what} declares {len} bytes, over the {MAX_STRING_BYTES} cap"
    );
    let mut bytes = vec![0u8; len];
    read_exact_or_eof(source, &mut bytes, what)?;
    String::from_utf8(bytes).map_err(|error| anyhow::anyhow!("{what} is not valid UTF-8: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A reader that yields at most `max_read` bytes per call, so record
    /// reassembly across arbitrary transport boundaries is exercised — a pipe
    /// splits wherever it likes.
    struct Fragmented<R> {
        inner: R,
        max_read: usize,
    }

    impl<R: Read> Read for Fragmented<R> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let take = out.len().min(self.max_read);
            self.inner.read(&mut out[..take])
        }
    }

    fn text_stream(pieces: &[&str]) -> Vec<u8> {
        let mut writer = FramedWriter::open_text(Vec::new()).unwrap();
        for piece in pieces {
            writer.text(piece).unwrap();
        }
        writer.finish(EndStatus::Complete).unwrap()
    }

    #[test]
    fn a_token_stream_round_trips_with_both_clocks() {
        let wire = text_stream(&["Hel", "lo, ", "world"]);
        let mut reader = FramedReader::open(Cursor::new(wire)).unwrap();
        assert_eq!(reader.content_type(), TEXT_PLAIN);
        assert_eq!(reader.unit(), UNIT_BYTES);

        let mut text = String::new();
        let mut offsets = Vec::new();
        loop {
            match reader.next_frame().unwrap() {
                Frame::Record(r) => {
                    offsets.push((r.index, r.offset, r.extent));
                    // Every record resolves a content type, even without an
                    // override on the record itself.
                    assert_eq!(r.content_type(), TEXT_PLAIN);
                    text.push_str(r.text().unwrap());
                }
                Frame::Gap(g) => panic!("unexpected gap {g:?}"),
                Frame::End(status) => {
                    assert_eq!(status, EndStatus::Complete);
                    break;
                }
            }
        }
        assert_eq!(text, "Hello, world");
        // The unit clock is cumulative bytes; the record clock is ordinal.
        assert_eq!(offsets, vec![(0, 0, 3), (1, 3, 4), (2, 7, 5)]);
    }

    #[test]
    fn records_reassemble_across_arbitrary_transport_boundaries() {
        let wire = text_stream(&["alpha", "beta"]);
        let mut reader = FramedReader::open(Fragmented {
            inner: Cursor::new(wire),
            max_read: 3,
        })
        .unwrap();
        let mut got = String::new();
        while let Frame::Record(r) = reader.next_frame().unwrap() {
            got.push_str(r.text().unwrap());
        }
        assert_eq!(got, "alphabeta");
    }

    #[test]
    fn a_per_record_content_type_overrides_the_stream_default() {
        // The heterogeneous case: telemetry with a keyframe spliced in.
        let mut writer = FramedWriter::open(Vec::new(), "application/json", "samples").unwrap();
        writer.record(br#"{"joint":1}"#, 1).unwrap();
        writer
            .record_as("image/jpeg", &[0xff, 0xd8, 0xff], 1)
            .unwrap();
        let wire = writer.finish(EndStatus::Complete).unwrap();

        let mut reader = FramedReader::open(Cursor::new(wire)).unwrap();
        let Frame::Record(first) = reader.next_frame().unwrap() else {
            panic!("expected a record")
        };
        let Frame::Record(second) = reader.next_frame().unwrap() else {
            panic!("expected a record")
        };
        assert_eq!(first.content_type(), "application/json");
        assert_eq!(second.content_type(), "image/jpeg");
    }

    #[test]
    fn truncation_is_never_a_clean_end() {
        // THE distinction: a complete short stream and a truncated one are
        // byte-identical up to the terminator, so the terminator is what tells
        // them apart.
        let wire = text_stream(&["one", "two"]);
        let cut = wire.len() - 4;
        let mut reader = FramedReader::open(Cursor::new(wire[..cut].to_vec())).unwrap();
        let mut error = None;
        for _ in 0..8 {
            match reader.next_frame() {
                Ok(Frame::End(_)) => panic!("a truncated stream must not report END"),
                Ok(_) => {}
                Err(e) => {
                    error = Some(e);
                    break;
                }
            }
        }
        let error = error.expect("truncation must surface as an error");
        assert!(
            format!("{error:#}").contains("TRUNCATED"),
            "expected a truncation error, got: {error:#}"
        );
    }

    #[test]
    fn an_abort_is_a_well_formed_end_that_says_it_failed() {
        let mut writer = FramedWriter::open_text(Vec::new()).unwrap();
        writer.text("partial").unwrap();
        let wire = writer
            .finish(EndStatus::Aborted("model died".into()))
            .unwrap();
        let mut reader = FramedReader::open(Cursor::new(wire)).unwrap();
        assert!(matches!(reader.next_frame().unwrap(), Frame::Record(_)));
        assert_eq!(
            reader.next_frame().unwrap(),
            Frame::End(EndStatus::Aborted("model died".into()))
        );
    }

    #[test]
    fn a_dropped_writer_still_says_it_aborted() {
        let mut sink = Vec::new();
        {
            let mut writer = FramedWriter::open_text(&mut sink).unwrap();
            writer.text("half a thought").unwrap();
            // No finish(): the writer goes out of scope here.
        }
        let mut reader = FramedReader::open(Cursor::new(sink)).unwrap();
        assert!(matches!(reader.next_frame().unwrap(), Frame::Record(_)));
        let Frame::End(EndStatus::Aborted(reason)) = reader.next_frame().unwrap() else {
            panic!("a dropped writer must terminate the stream as aborted")
        };
        assert!(reason.contains("without finish"), "{reason}");
    }

    #[test]
    fn a_declared_gap_advances_both_clocks_and_names_what_was_lost() {
        let mut writer =
            FramedWriter::open(Vec::new(), "audio/L16;rate=24000;channels=1", UNIT_SAMPLES)
                .unwrap();
        writer.record(&[0u8; 8], 4).unwrap();
        writer
            .gap(1_920, "capture ring overran; consumer too slow")
            .unwrap();
        writer.record(&[0u8; 8], 4).unwrap();
        let wire = writer.finish(EndStatus::Complete).unwrap();

        let mut reader = FramedReader::open(Cursor::new(wire)).unwrap();
        assert!(matches!(reader.next_frame().unwrap(), Frame::Record(_)));
        let Frame::Gap(gap) = reader.next_frame().unwrap() else {
            panic!("expected the declared gap")
        };
        assert_eq!((gap.index, gap.offset, gap.extent), (1, 4, 1_920));
        assert!(gap.reason.contains("too slow"));
        let Frame::Record(after) = reader.next_frame().unwrap() else {
            panic!("expected a record after the gap")
        };
        // The gap moved the unit clock, so the following record's offset
        // accounts for the lost samples rather than pretending they never were.
        assert_eq!(after.offset, 4 + 1_920);
    }

    #[test]
    fn silent_renumbering_is_rejected() {
        // Hand-build a stream whose second record skips an index — what a
        // producer that dropped content without saying so would emit.
        let mut wire = text_stream(&["a", "b"]);
        // Rewrite the SECOND record's index (preamble, then record 0, then the
        // kind byte of record 1) from 1 to 2.
        let preamble = MAGIC.len() + 2 + 2 + 2 + TEXT_PLAIN.len() + 2 + UNIT_BYTES.len();
        let record_len = 1 + 8 + 8 + 8 + 2 + 4 + 1;
        let second_index_at = preamble + record_len + 1;
        wire[second_index_at..second_index_at + 8].copy_from_slice(&2u64.to_le_bytes());

        let mut reader = FramedReader::open(Cursor::new(wire)).unwrap();
        assert!(matches!(reader.next_frame().unwrap(), Frame::Record(_)));
        let Err(error) = reader.next_frame() else {
            panic!("a renumbered record must be rejected")
        };
        assert!(
            format!("{error:#}").contains("without a gap record"),
            "{error:#}"
        );
    }

    #[test]
    fn a_foreign_stream_is_refused_at_the_preamble() {
        let Err(error) = FramedReader::open(Cursor::new(b"not a framed stream at all".to_vec()))
        else {
            panic!("a foreign stream must be refused at the preamble")
        };
        assert!(
            format!("{error:#}").contains("not a framed stream"),
            "{error:#}"
        );
    }

    #[test]
    fn a_consumer_refuses_a_modality_it_does_not_understand() {
        let wire = text_stream(&["hi"]);
        let reader = FramedReader::open(Cursor::new(wire)).unwrap();
        let Err(error) = reader.require_content_type("audio/L16") else {
            panic!("a consumer must refuse a modality it does not understand")
        };
        assert!(
            format!("{error:#}").contains("requires audio/L16"),
            "{error:#}"
        );
    }
}
