//! Text presentation over owned LinkedIn observations and exact write receipts.
use super::operations::*;
use crate::out::Out;
use anyhow::Result;
use triblespace::prelude::Id;

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

/// Historical import summary shared by both frontends.
pub fn import(report: &ImportReport, out: &mut Out<'_>) -> Result<()> {
    out.line("")?;
    out.line(format!("  new people:        {}", report.created))?;
    out.line(format!(
        "  matched by email:  {}   (components with existing email evidence)",
        report.matched_by_email
    ))?;
    out.line(format!(
        "  matched by url:    {}   (components with existing profile-URL evidence)",
        report.matched_by_url
    ))?;
    out.line(format!(
        "  prospective review:{}   (same current label, kept distinct)",
        report.prospective_collisions.len()
    ))?;
    if report.skipped > 0 {
        out.line(format!(
            "  skipped:           {}   (identity-less junk rows)",
            report.skipped
        ))?;
    }
    if report.name_only > 0 {
        let qualification = if report.dry_run {
            "fresh provisional dry-run anchors; no stable upstream key"
        } else {
            "fresh anchors; no stable upstream key"
        };
        out.line(format!(
            "  name-only rows:     {}   ({qualification})",
            report.name_only
        ))?;
    }
    if !report.prospective_collisions.is_empty() {
        out.line("\nProspective name collisions (derived, not persisted):")?;
        for (new_id, existing, name) in &report.prospective_collisions {
            out.line(format!(
                "  {} ~ {}   {name}",
                fmt_id(*new_id),
                fmt_id(*existing)
            ))?;
        }
    }
    if report.dry_run {
        out.line("\n(dry run — nothing committed)")?;
    } else if report.committed {
        out.line("\nCommitted to relations.")?;
    } else {
        out.line("\nNothing to commit.")?;
    }
    Ok(())
}

pub fn profiles(report: &ImportReport, out: &mut Out<'_>) -> Result<()> {
    for value in &report.profiles {
        out.line(format!(
            "{} person {:x} profile {:x}",
            if report.dry_run {
                "Planned"
            } else {
                "Authored"
            },
            value.person,
            value.profile
        ))?;
    }
    Ok(())
}

pub fn person(value: &ReviewPerson, out: &mut Out<'_>) -> Result<()> {
    out.line(format!("{:x}  {}", value.person, value.profile.label))?;
    if let Some(position) = &value.profile.position {
        out.line(format!("    position: {position}"))?;
    }
    if let Some(company) = &value.profile.company {
        out.line(format!("    company:  {company}"))?;
    }
    for email in &value.profile.emails {
        out.line(format!("    email:    {email}"))?;
    }
    for url in &value.profile.profile_urls {
        out.line(format!("    url:      {url}"))?;
    }
    Ok(())
}

pub fn review(value: &ReviewReport, out: &mut Out<'_>) -> Result<()> {
    if value.total == 0 {
        return out.line("No open review candidates. 🎉");
    }
    out.line(format!("{} open review candidate(s):\n", value.total))?;
    for (index, pair) in value.pairs.iter().enumerate() {
        out.line(format!(
            "[{}] ─────────────────────────────────────",
            index + 1
        ))?;
        person(&pair.first, out)?;
        out.line("    ~ same person? ~")?;
        person(&pair.second, out)?;
        out.line(format!(
            "  → linkedin_resolve: first={:x}, second={:x}, same=true or false\n",
            pair.first.person, pair.second.person
        ))?;
    }
    if value.total > value.pairs.len() {
        out.line(format!(
            "(+{} more; raise limit)",
            value.total - value.pairs.len()
        ))?;
    }
    Ok(())
}

pub fn resolved(value: &ResolutionReceipt, out: &mut Out<'_>) -> Result<()> {
    if value.changed {
        let verdict = if value.same {
            "same_as"
        } else {
            "distinct_from"
        };
        out.line(format!(
            "Recorded {verdict}: {:x} ↔ {:x} ({:x})",
            value.first, value.second, value.verdict
        ))
    } else {
        out.line(format!(
            "Identity verdict is already settled at {:x}.",
            value.verdict
        ))
    }
}
