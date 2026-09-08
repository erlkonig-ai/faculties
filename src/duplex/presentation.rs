//! Shared textual rendering; the operation reports remain useful without Out.
use super::runtime::PlaybackDevice;
use super::{ReadObservation, ReleaseReceipt, SayReceipt, Status};
use crate::out::Out;
use anyhow::Result;
use std::path::Path;

pub fn read(value: &ReadObservation, out: &mut Out<'_>) -> Result<()> {
    if value.lines.is_empty() {
        out.line(format!("(nothing new since cursor {})", value.cursor))?;
    } else {
        for line in &value.lines {
            out.line(format!("[{}] {}", line.speaker, line.text))?;
        }
    }
    match value.requested_hold_secs {
        None => out.line(format!("\ncursor {}, transcript at {} — floor not taken",value.cursor,value.transcript_at)),
        Some(seconds) => out.line(format!("\ncursor {}, transcript at {} — FLOOR HOLD REQUESTED for {seconds}s; say or release gives it back",value.cursor,value.transcript_at)),
    }
}

/// A local path is useful CLI diagnostics; MCP uses only the queue receipt ID.
pub fn say(value: &SayReceipt, show_path: bool, out: &mut Out<'_>) -> Result<()> {
    let queued = if show_path {
        value.queued.display().to_string()
    } else {
        value.queue_id()
    };
    out.line(format!(
        "queued ({queued}), cursor at {}, floor {}",
        value.cursor,
        if value.kept_floor {
            "still held"
        } else {
            "released"
        }
    ))
}
pub fn release(value: &ReleaseReceipt, out: &mut Out<'_>) -> Result<()> {
    out.line(format!(
        "floor released, cursor {}at {}",
        if value.kept_cursor { "unchanged " } else { "" },
        value.cursor
    ))
}
pub fn status(value: &Status, local_session: Option<&Path>, out: &mut Out<'_>) -> Result<()> {
    if let Some(path) = local_session {
        out.line(format!("session   : {}", path.display()))?;
    }
    out.line(format!(
        "transcript: {} lines, latest seq {}",
        value.transcript_lines, value.transcript_at
    ))?;
    out.line(format!(
        "cursor    : {} ({} unread)",
        value.cursor, value.unread
    ))?;
    out.line(format!(
        "floor     : {}",
        if value.floor_held {
            "HELD — silence requested"
        } else {
            "free — speaking permitted"
        }
    ))?;
    out.line(format!(
        "queued    : {} line(s) waiting to be spoken",
        value.queued
    ))?;
    out.line("(control files only; loop liveness and audio delivery are not observed)")
}
pub fn devices(values: &[PlaybackDevice], out: &mut Out<'_>) -> Result<()> {
    out.line("capture: Soma's, named once there and inherited (`duplex ear` to check it)")?;
    out.line("playback devices (--output):")?;
    for device in values {
        match &device.configuration {
            Ok(config) => out.line(format!(
                "  {}\n      {} ch, {} Hz, {}",
                device.name, config.channels, config.sample_rate, config.sample_format
            ))?,
            Err(error) => out.line(format!(
                "  {}\n      no usable output configuration: {error}",
                device.name
            ))?,
        }
    }
    Ok(())
}
