//! Mail presentation over owned observations and explicit durable receipts.
use super::operations::*;
use crate::out::Out;
use anyhow::Result;

pub fn account_set(value: &AccountSetReceipt, out: &mut Out<'_>) -> Result<()> {
    if value.changed {
        out.line(format!(
            "Account {:x} config {:x}",
            value.account, value.config
        ))
    } else {
        out.line(format!(
            "Account {:x} already has config {:x}",
            value.account, value.config
        ))
    }
}
pub fn accounts(values: &[AccountSummary], out: &mut Out<'_>) -> Result<()> {
    for value in values {
        match &value.state {
            AccountState::Missing => out.line(format!("{:x}  MISSING", value.account))?,
            AccountState::Forked(ids) => {
                out.line(format!("{:x}  FORKED {ids:?}", value.account))?
            }
            AccountState::Configured {
                config,
                address,
                enabled,
            } => out.line(format!(
                "{:x}  {}  {}  config={:x}",
                value.account,
                address,
                if *enabled { "enabled" } else { "disabled" },
                config
            ))?,
        }
    }
    Ok(())
}
pub fn fetched(values: &[AccountFetched], out: &mut Out<'_>) -> Result<()> {
    for value in values {
        out.line(format!(
            "{}: fetched {} message(s)",
            value.address, value.fetched
        ))?;
    }
    Ok(())
}
pub fn draft(value: &DraftReceipt, out: &mut Out<'_>) -> Result<()> {
    out.line(format!("Draft {:x}", value.draft))?;
    out.line(format!("Decision {:x}", value.decision))
}
pub fn sent(value: &SendReceipt, out: &mut Out<'_>) -> Result<()> {
    match &value.status {
        SendStatus::AlreadyAccepted => out.line(format!(
            "Draft {:x} was already accepted (attempt {:x}).",
            value.draft, value.attempt
        )),
        SendStatus::Accepted(response) => out.line(format!(
            "Accepted draft {:x} as attempt {:x}: {} {}",
            value.draft, value.attempt, response.code, response.message
        )),
    }
}
pub fn outbox(values: &[DraftStatus], out: &mut Out<'_>) -> Result<()> {
    for value in values {
        let state = match value.delivery {
            DraftDelivery::Pending => "pending".to_owned(),
            DraftDelivery::Uncertain(id) => format!("UNCERTAIN attempt={id:x}"),
            DraftDelivery::Accepted(id) => format!("accepted attempt={id:x}"),
            DraftDelivery::MultipleAttempts => "INVALID multiple attempts".to_owned(),
        };
        out.line(format!("{:x}  {}  {}", value.draft, state, value.subject))?;
    }
    Ok(())
}
pub fn inbox(values: &[InboxMessage], out: &mut Out<'_>) -> Result<()> {
    for value in values {
        let view = &value.projection;
        out.line(format!(
            "{:x}  {}{}  {}  {}",
            view.wire,
            if value.unread { "UNREAD" } else { "read" },
            if view.spam { "/spam" } else { "" },
            view.from.as_deref().unwrap_or("(no From)"),
            view.subject
        ))?;
    }
    Ok(())
}
pub fn read(value: &ReadReceipt, out: &mut Out<'_>) -> Result<()> {
    out.line(format!("Read {:x} ({:x})", value.wire, value.observation))
}
pub fn show(values: &[super::ProjectionView], out: &mut Out<'_>) -> Result<()> {
    for view in values {
        out.line(format!("Wire: {:x}", view.wire))?;
        out.line(format!(
            "Message-ID: {}",
            view.message_id.as_deref().unwrap_or("(not claimed)")
        ))?;
        out.line(format!("Source: {:x}", view.source))?;
        out.line(format!(
            "From: {}",
            view.from.as_deref().unwrap_or_default()
        ))?;
        out.line(format!("To: {}", view.to.join(", ")))?;
        if !view.cc.is_empty() {
            out.line(format!("Cc: {}", view.cc.join(", ")))?;
        }
        out.line(format!("Subject: {}", view.subject))?;
        out.line("")?;
        out.line(&view.body)?;
        if !view.attachments.is_empty() {
            out.line(format!(
                "\nAttachment occurrences: {}",
                view.attachments
                    .iter()
                    .map(|id| format!("{id:x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))?;
        }
    }
    Ok(())
}
pub fn search(values: &[super::ProjectionView], out: &mut Out<'_>) -> Result<()> {
    for view in values {
        out.line(format!(
            "{:x}  {}  {}",
            view.wire,
            view.from.as_deref().unwrap_or_default(),
            view.subject
        ))?;
    }
    Ok(())
}
