//! Textual UX only; callers can use all observations without an emitter.
use super::device::{ActionReceipt, Felt, PoseObservation};
use super::{CaptureReceipt, CaptureSummary, IntentObservation};
use crate::out::Out;
use anyhow::Result;
use hifitime::efmt::{consts::ISO8601, Formatter};
use hifitime::Epoch;

pub fn format_time(tai_ns: i128) -> String {
    const NANOS_PER_CENTURY: i128 = 3_155_760_000_000_000_000;
    let centuries = (tai_ns / NANOS_PER_CENTURY) as i16;
    let nanos = (tai_ns % NANOS_PER_CENTURY) as u64;
    let dur = hifitime::Duration::from_parts(centuries, nanos);
    let epoch = Epoch::from_tai_duration(dur);
    Formatter::new(epoch, ISO8601).to_string()
}

pub fn pose(value: &PoseObservation, out: &mut Out<'_>) -> Result<()> {
    let state = &value.state;
    let status = value.status.as_ref().unwrap_or(&serde_json::Value::Null);

    let hp = &state["head_pose"];
    let f = |k: &str| hp[k].as_f64().unwrap_or(f64::NAN);
    out.line(format!("head pose:"))?;
    out.line(format!(
        "  position   x={:+.4} y={:+.4} z={:+.4} (m)",
        f("x"),
        f("y"),
        f("z")
    ))?;
    out.line(format!(
        "  rotation   roll={:+.4} pitch={:+.4} yaw={:+.4} (rad)",
        f("roll"),
        f("pitch"),
        f("yaw")
    ))?;
    if let Some(by) = state["body_yaw"].as_f64() {
        out.line(format!("body yaw:    {by:+.4} rad"))?;
    }
    if let Some(ant) = state["antennas_position"].as_array() {
        let vals: Vec<String> = ant
            .iter()
            .map(|v| format!("{:+.4}", v.as_f64().unwrap_or(f64::NAN)))
            .collect();
        out.line(format!("antennas:    [{}] rad", vals.join(", ")))?;
    }
    // live mic-array direction-of-arrival (the touch/sound sense)
    if let Some(d) = value.touch.as_ref() {
        if let Some(a) = d["angle"].as_f64() {
            let sp = if d["speech_detected"].as_bool().unwrap_or(false) {
                " (speech)"
            } else {
                ""
            };
            out.line(format!("audio dir:   {:.0}°{sp}", a.to_degrees()))?;
        }
    }
    if let Some(ts) = state["timestamp"].as_str() {
        out.line(format!("daemon time: {ts}"))?;
    }
    if let Some(name) = status["robot_name"].as_str() {
        let st = status["state"].as_str().unwrap_or("?");
        let cam = status["camera_specs_name"].as_str().unwrap_or("?");
        out.line(format!("body:        {name} ({st}), camera={cam}"))?;
    }
    Ok(())
}

pub fn felt(felt: &Felt, out: &mut Out<'_>) -> Result<()> {
    out.line(format!(
        "I felt it — your hand tipped my head {:.0} mrad ({:.1}°).",
        felt.head_deflect * 1000.0,
        felt.head_deflect.to_degrees()
    ))?;
    if felt.angle_max - felt.angle_min > 20.0 {
        out.line(format!(
            "  and I heard it move across the mics, {:.0}–{:.0}°.",
            felt.angle_min, felt.angle_max
        ))?;
    }
    Ok(())
}

pub fn captured(value: &CaptureReceipt, out: &mut Out<'_>) -> Result<()> {
    if let Some((w, h)) = value.dimensions {
        out.line(format!(
            "captured {w}x{h} vision frame ({} KiB)",
            value.bytes / 1024
        ))?;
    } else {
        out.line(format!(
            "captured {} ({} bytes)",
            value.modality, value.bytes
        ))?;
    }
    out.line(format!("  id   {:x}", value.id))?;
    if let Some(note) = &value.note {
        out.line(format!("  note {note}"))?;
    }
    Ok(())
}
pub fn intent_set(value: &IntentObservation, out: &mut Out<'_>) -> Result<()> {
    out.line(format!(
        "  intent {} set: {}",
        &format!("{:x}", value.id)[..12],
        value.text
    ))
}
pub fn intent(value: Option<&IntentObservation>, out: &mut Out<'_>) -> Result<()> {
    match value {
        Some(value) => out.line(&value.text),
        None => out.line("(no intent yet — gemma hasn't reasoned anything)"),
    }
}
pub fn list(rows: &[CaptureSummary], out: &mut Out<'_>) -> Result<()> {
    if rows.is_empty() {
        return out
            .line("no captures yet — `body look` keeps a frame, `body feel --keep` a touch.");
    }
    for row in rows {
        let suffix = if row.note.is_empty() {
            String::new()
        } else {
            format!("  — {}", row.note)
        };
        out.line(format!(
            "{}  {:<6}  {}{suffix}",
            &format!("{:x}", row.id)[..12],
            row.modality,
            format_time(row.tai_ns)
        ))?;
    }
    Ok(())
}
pub fn action(receipt: &ActionReceipt, out: &mut Out<'_>) -> Result<()> {
    match receipt {
        ActionReceipt::Snapped => out.line("snapped to pose"),
        ActionReceipt::Moved { duration } => {
            out.line(format!("moved to pose over {:.2}s", duration.as_secs_f64()))
        }
        ActionReceipt::Streamed {
            waypoints,
            interval,
        } => out.line(format!(
            "streamed {waypoints} waypoints @ {:.3}s",
            interval.as_secs_f64()
        )),
    }
}
