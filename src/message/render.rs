//! Shared text presentation of owned Message operation results.
use super::operations::interval_key;
use super::{AcknowledgedMessages, Acknowledgement, MessageList, MessageStatus, SentMessage};
use crate::out::Out;
use anyhow::Result;

fn format_age(now_key: i128, past_key: i128) -> String {
    let seconds = (now_key.saturating_sub(past_key) / 1_000_000_000).max(0);
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3_600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h", seconds / 3_600)
    } else {
        format!("{}d", seconds / 86_400)
    }
}

fn truncate_single_line(text: &str, max: usize) -> String {
    let mut output = String::with_capacity(max);
    for character in text.chars() {
        if output.len() >= max {
            output.push_str("...");
            break;
        }
        if matches!(character, '\n' | '\r') {
            output.push(' ');
        } else {
            output.push(character);
        }
    }
    output
}

fn render_list_body(text: &str) -> String {
    text.replace('\r', "").replace('\n', "\\n")
}

pub(super) fn sent(sent: &SentMessage, text: &str, out: &mut Out<'_>) -> Result<()> {
    out.line(format!(
        "[{:x}] {:x} -> {:x}: {}",
        sent.id,
        sent.from,
        sent.recipient.anchor(),
        truncate_single_line(text, 120),
    ))
}

pub(super) fn acknowledged(ack: &Acknowledgement, out: &mut Out<'_>) -> Result<()> {
    if ack.already_read {
        out.line(format!(
            "Message {:x} was already read by {:x}.",
            ack.message, ack.reader
        ))
    } else {
        out.line(format!(
            "Marked {:x} as read by {:x}.",
            ack.message, ack.reader
        ))
    }
}

pub(super) fn acknowledged_all(ack: &AcknowledgedMessages, out: &mut Out<'_>) -> Result<()> {
    if ack.message_ids.is_empty() {
        out.line(format!("No unread messages for {:x}.", ack.reader))
    } else {
        out.line(format!(
            "Marked {} message(s) as read by {:x}.",
            ack.message_ids.len(),
            ack.reader
        ))
    }
}

pub(super) fn list(list: &MessageList, out: &mut Out<'_>) -> Result<()> {
    if list.entries.is_empty() {
        return out.line("No messages.");
    }
    let now = interval_key(list.observed_at);
    for entry in &list.entries {
        let status = match entry.status {
            MessageStatus::Unread => "unread".to_owned(),
            MessageStatus::Read => "read".to_owned(),
            MessageStatus::Sent => "sent".to_owned(),
            MessageStatus::ReadByRecipient => format!("read-by:{}", entry.to_label),
        };
        out.line(format!(
            "[{:x}] {} {} -> {} ({}) {}",
            entry.row.id,
            format_age(now, interval_key(entry.row.created_at)),
            entry.from_label,
            entry.to_label,
            status,
            render_list_body(&entry.body),
        ))?;
    }
    Ok(())
}
