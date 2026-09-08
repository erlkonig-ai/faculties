//! Presentation of already-owned Status observations. No storage reads occur here.

use super::{SetStatus, StatusHistory, WindowStatus};
use crate::out::Out;
use anyhow::Result;

/// Compact age like "3m" / "2h" / "5d" from two nanosecond coordinates.
fn format_age(now: i128, past: i128) -> String {
    let secs = ((now - past) / 1_000_000_000).max(0);
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3_600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3_600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

pub fn set(receipt: &SetStatus, output: &mut Out<'_>) -> Result<()> {
    output.line(format!("{:x} → {}", receipt.window, receipt.text))
}

pub fn list(rows: &[WindowStatus], output: &mut Out<'_>) -> Result<()> {
    if rows.is_empty() {
        return output.line("No statuses set yet.");
    }
    let now = super::point_timestamp(crate::clock::point_now()?)?;
    for row in rows {
        let age = format_age(now, super::point_timestamp(row.status.at)?);
        output.line(format!("{}: {}  ({age} ago)", row.label, row.status.text))?;
    }
    Ok(())
}

pub fn show(history: &StatusHistory, output: &mut Out<'_>) -> Result<()> {
    output.line(format!(
        "status for {} ({:x})",
        history.label, history.window
    ))?;
    if history.total == 0 {
        return output.line("- (no status set)");
    }
    let now = super::point_timestamp(crate::clock::point_now()?)?;
    for (index, entry) in history.entries.iter().enumerate() {
        let age = format_age(now, super::point_timestamp(entry.at)?);
        let marker = if index == 0 { "*" } else { " " };
        output.line(format!("{marker} {}  ({age} ago)", entry.text))?;
    }
    Ok(())
}
