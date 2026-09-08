//! Discord presentation over completed native observations.
use super::operations::*;
use crate::out::Out;
use anyhow::Result;

pub fn sent(receipt: &SendReceipt, out: &mut Out<'_>) -> Result<()> {
    out.line(format!(
        "Sent and stored message {} in channel {}",
        receipt.message_id, receipt.channel_id
    ))
}
pub fn history(value: &History, out: &mut Out<'_>) -> Result<()> {
    if value.messages.is_empty() {
        return out.line(match value.channel_id.as_deref() {
            Some(channel) => format!("(no messages in collection for channel {channel})"),
            None => "(no messages in collection)".to_owned(),
        });
    }
    for message in &value.messages {
        let edited = message
            .edited_at
            .map(|at| format!(" (edited {})", format_interval(at)))
            .unwrap_or_default();
        let channel = if value.channel_id.is_some() {
            String::new()
        } else {
            message
                .channel_name
                .as_ref()
                .map(|name| format!(" #{name}"))
                .unwrap_or_default()
        };
        let conflict = if message.variant_count > 1 {
            format!(
                " [DIVERGENT {}/{}]",
                message.variant_index + 1,
                message.variant_count
            )
        } else {
            String::new()
        };
        out.line(format!(
            "[{}]{channel}{edited}{conflict} {}: {}",
            format_interval(message.created_at),
            message.author,
            message.content
        ))?;
    }
    Ok(())
}
pub fn channel_receipt(value: &ChannelReceipt, out: &mut Out<'_>) -> Result<()> {
    if value.observations == 0 {
        return out.line(format!("  {}: no observations", value.channel_id));
    }
    match value.coverage {
        Some(interval) => out.line(format!(
            "  {}: {} observations; covered ({}, {}]{}",
            value.channel_id,
            value.observations,
            interval.after_exclusive,
            interval.through_inclusive,
            if interval.baseline {
                " (bounded baseline)"
            } else {
                ""
            }
        )),
        None => out.line(format!(
            "  {}: {} reconciled observations",
            value.channel_id, value.observations
        )),
    }
}
pub fn pull_header(report: &PullReport, out: &mut Out<'_>) -> Result<()> {
    if report.all_visible {
        if report.channels.is_empty() {
            out.line("Bot is not in any guilds or has no text-capable channels.")?;
        } else {
            out.line(format!(
                "Polling {} channels across {} guilds…",
                report.channels.len(),
                report.guilds
            ))?;
        }
    }
    Ok(())
}
pub fn pull(report: &PullReport, out: &mut Out<'_>) -> Result<()> {
    pull_header(report, out)?;
    for channel in &report.channels {
        match &channel.result {
            Ok(receipt) => channel_receipt(receipt, out)?,
            Err(error) => out.line(format!(
                "  ! {} ({}): {error}",
                channel.channel_id, channel.name
            ))?,
        }
    }
    Ok(())
}
pub fn channels(value: &ChannelListing, out: &mut Out<'_>) -> Result<()> {
    if !value.bot_in_any_guild {
        return out.line("Bot is not a member of any guilds. Invite it to a server first.");
    }
    for guild in &value.guilds {
        out.line(format!("{}  ({})", guild.name, guild.id))?;
        for channel in &guild.channels {
            out.line(format!(
                "  {:<12} #{:<30} {}",
                channel_type_label(channel.kind),
                channel.name,
                channel.id
            ))?;
        }
        out.line("")?;
    }
    Ok(())
}

fn channel_type_label(kind: i64) -> &'static str {
    match kind {
        0 => "text",
        1 => "dm",
        2 => "voice",
        3 => "group-dm",
        4 => "category",
        5 => "announcement",
        10 => "announce-thread",
        11 => "public-thread",
        12 => "private-thread",
        13 => "stage",
        14 => "directory",
        15 => "forum",
        16 => "media",
        _ => "other",
    }
}
