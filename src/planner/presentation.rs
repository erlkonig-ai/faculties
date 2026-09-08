//! Native, fallible Planner report presentation.
use super::operations::{epoch_to_chrono_utc, fmt_interval, unpack_interval};
use super::{
    AddedEvent, AddedNote, CancellationReceipt, EventDetail, IngestReceipt, Occurrence,
    STATUS_CANCELLED, STATUS_CONFIRMED,
};
use crate::out::Out;
use anyhow::Result;
use triblespace::prelude::Id;
fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

pub fn occurrences(occurrences: &[Occurrence], out: &mut Out<'_>) -> Result<()> {
    if occurrences.is_empty() {
        out.line("(no events)")?;
        return Ok(());
    }
    for occurrence in occurrences {
        let start = epoch_to_chrono_utc(occurrence.start)?;
        let end = epoch_to_chrono_utc(occurrence.end)?;
        let time = if (end - start).num_seconds() == 86_400
            && start.format("%H:%M:%S").to_string() == "00:00:00"
        {
            start.format("%Y-%m-%d (all day)     ").to_string()
        } else if start.date_naive() == end.date_naive() {
            format!(
                "{} {}-{}",
                start.format("%Y-%m-%d"),
                start.format("%H:%M"),
                end.format("%H:%M UTC")
            )
        } else {
            format!(
                "{} → {}",
                start.format("%Y-%m-%d %H:%M"),
                end.format("%Y-%m-%d %H:%M UTC")
            )
        };
        let mut line = format!(
            "  {} {} {}",
            &fmt_id(occurrence.event_id)[..8],
            time,
            occurrence.summary
        );
        if let Some(location) = &occurrence.location {
            line.push_str(&format!("  @ {location}"));
        }
        if occurrence.status != STATUS_CONFIRMED {
            line.push_str(&format!("  [{}]", occurrence.status));
        }
        out.line(line)?;
    }
    Ok(())
}

pub fn added(receipt: &AddedEvent, out: &mut Out<'_>) -> Result<()> {
    out.line(format!("Added event {}", fmt_id(receipt.event)))
}
pub fn noted(receipt: &AddedNote, out: &mut Out<'_>) -> Result<()> {
    out.line(format!("Added note to event {}", fmt_id(receipt.event)))
}
pub fn cancelled(receipt: &CancellationReceipt, out: &mut Out<'_>) -> Result<()> {
    if receipt.already_cancelled {
        out.line(format!(
            "Event {} is already cancelled",
            fmt_id(receipt.event)
        ))
    } else {
        out.line(format!("Cancelled event {}", fmt_id(receipt.event)))
    }
}
pub fn ingested(receipt: &IngestReceipt, out: &mut Out<'_>) -> Result<()> {
    out.line(format!(
        "ingested {} of {} events ({} exact duplicates skipped)",
        receipt.imported.len(),
        receipt.total,
        receipt.duplicates
    ))
}
pub fn show(detail: &EventDetail, out: &mut Out<'_>) -> Result<()> {
    let row = &detail.event;
    out.line(format!("event {}  {}", fmt_id(row.id), row.summary))?;
    out.line(format!("  time:     {}", fmt_interval(row.time)?))?;
    if let Some(location) = &row.location {
        out.line(format!("  location: {location}"))?;
    }
    let status = if detail.cancelled {
        STATUS_CANCELLED
    } else {
        &row.status
    };
    if status != STATUS_CONFIRMED {
        out.line(format!("  status:   {status}"))?;
    }
    if let Some(rrule) = &row.rrule {
        out.line(format!("  rrule:    {rrule}"))?;
    }
    out.line(format!("  uid:      {}", detail.uid))?;
    if let Some(description) = &detail.description {
        out.line("  ----")?;
        for line in description.lines() {
            out.line(format!("  {line}"))?;
        }
    }
    if !detail.notes.is_empty() {
        out.line("  notes:")?;
        for note in &detail.notes {
            let when = epoch_to_chrono_utc(unpack_interval(note.row.created_at).0)?;
            out.line(format!(
                "  - [{}] {}",
                when.format("%Y-%m-%d %H:%M UTC"),
                note.text
            ))?;
        }
    }
    Ok(())
}
