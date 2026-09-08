//! Teams presentation shared where the frontend semantics really agree.
use super::operations::*;
use crate::out::Out;
use anyhow::Result;

pub fn context_banner(context: &PresentationContext) -> String {
    let name = context
        .name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let boundary = context
        .boundary
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let title = match name {
        Some(name) => format!("TEAMS · PRESENT AS {name} · PROFESSIONAL WORK CONTEXT"),
        None => "TEAMS · CONTEXT UNSET".to_owned(),
    };
    format!("{title}\nBOUNDARY · {}\n", boundary.unwrap_or("UNSET"))
}

pub fn activity<T>(value: &Activity<T>, out: &mut Out<'_>) -> Result<()> {
    out.text(context_banner(&value.context))?;
    for notice in &value.notices {
        out.line(notice)?;
    }
    Ok(())
}

pub fn context(value: &PresentationContext, out: &mut Out<'_>) -> Result<()> {
    out.line(format!(
        "present_as: {}",
        value.name.as_deref().unwrap_or("(unset)")
    ))?;
    out.line("context: professional/work-only")?;
    out.line(format!(
        "boundary: {}",
        value.boundary.as_deref().unwrap_or("(unset)")
    ))
}

pub fn messages(values: &[ArchivedMessage], out: &mut Out<'_>) -> Result<()> {
    for message in values {
        out.line(format!(
            "[{}] ({}) {}: {}",
            format_interval(message.created_at),
            message.chat,
            message.author,
            message.content
        ))?;
    }
    Ok(())
}

pub fn users(values: &[DirectoryUser], out: &mut Out<'_>) -> Result<()> {
    for user in values {
        out.line(format!("{}  {}  {}", user.id, user.name, user.contact))?;
    }
    Ok(())
}

pub fn presence(values: &[Presence], out: &mut Out<'_>) -> Result<()> {
    for value in values {
        out.line(format!(
            "{}  {}  {}",
            value.id, value.availability, value.activity
        ))?;
    }
    Ok(())
}

pub fn attachments(values: &[AttachmentInfo], out: &mut Out<'_>) -> Result<()> {
    for row in values {
        out.line(format!(
            "[{}] ({}) msg={} attachment={} name={} mime={} size={} source={}",
            format_interval(row.created_at),
            row.chat,
            row.message,
            row.reference,
            row.name.as_deref().unwrap_or("-"),
            row.media_type.as_deref().unwrap_or("-"),
            row.size
                .map(|size| size.to_string())
                .as_deref()
                .unwrap_or("-"),
            if row.source_pointers.is_empty() {
                "-".to_owned()
            } else {
                row.source_pointers.join(" | ")
            }
        ))?;
    }
    Ok(())
}

pub fn attachment_missing(reference: &str, out: &mut Out<'_>) -> Result<()> {
    out.line(format!("No stored attachment bytes found for {reference}."))
}

pub fn attachment_matches(matches: &[AttachmentMatch], out: &mut Out<'_>) -> Result<()> {
    for value in matches {
        out.line(format!(
            "- chat={} message={} attachment={}",
            value.chat, value.message, value.reference
        ))?;
    }
    Ok(())
}

pub fn auth_set(receipt: &AuthSet, out: &mut Out<'_>) -> Result<()> {
    out.line(format!("auth_profile: {:x}", receipt.profile))
}

pub fn login(receipt: &LoginReceipt, out: &mut Out<'_>) -> Result<()> {
    out.line(format!("auth_profile: {:x}", receipt.profile))?;
    out.line(format!(
        "delegated_token_version: {:x}",
        receipt.delegated_token_version
    ))?;
    if let Some(version) = receipt.client_secret_version {
        out.line(format!("client_secret_version: {version:x}"))?;
    }
    Ok(())
}
