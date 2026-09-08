//! Render already computed observations; no storage or network work here.
use super::*;
use crate::out::Out;

fn short(value: &str, chars: usize) -> String {
    value.chars().take(chars).collect()
}
fn fraction(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        100.0 * numerator as f64 / denominator as f64
    }
}
pub fn health(report: &Health, out: &mut Out<'_>) -> Result<()> {
    out.line("=== GAUGE: Research Health ===\n")?;
    out.line(format!("Logical entries:       {}", report.entries))?;
    out.line(format!("Current states:        {}", report.states))?;
    out.line(format!("Forked entries:        {}", report.forks))?;
    out.line(format!("Outgoing references:   {}", report.links.total))?;
    out.line(format!("  resolved uniquely:   {}", report.links.unique))?;
    out.line(format!("  ambiguous selector:  {}", report.links.ambiguous))?;
    out.line(format!("  unresolved selector: {}", report.links.missing))?;
    out.line(format!(
        "Unanimous orphans:     {} ({:.0}% of entries)",
        report.unanimous_orphans,
        fraction(report.unanimous_orphans, report.entries)
    ))?;
    out.line(format!("Mixed orphan forks:    {}", report.mixed_orphans))
}
pub fn tags(rows: &[TagCount], out: &mut Out<'_>) -> Result<()> {
    out.line("=== GAUGE: Current Tag Evidence ===\n")?;
    out.line(format!("{:<27} {:>8} {:>8}", "tag", "states", "entries"))?;
    for row in rows {
        out.line(format!(
            "{:<27} {:>8} {:>8}",
            row.tag, row.states, row.entries
        ))?;
    }
    Ok(())
}
pub fn quality(rows: &[QualityState], out: &mut Out<'_>) -> Result<()> {
    out.line("=== GAUGE: Published / Refuted Frontier States ===\n")?;
    for row in rows {
        out.line(format!(
            "[{}] {} — revision {:x}{}",
            row.statuses.join(", "),
            short(&row.title, 65),
            row.revision,
            if row.fork { " [fork]" } else { "" }
        ))?;
    }
    if rows.is_empty() {
        out.line("No current frontier state is tagged published or refuted.")?;
    }
    Ok(())
}
pub fn hubs(report: &Hubs, out: &mut Out<'_>) -> Result<()> {
    out.line("=== GAUGE: Knowledge Hubs ===\n")?;
    for row in &report.rows {
        out.line(format!(
            "{:>4} <- {} [wiki:{:x}]",
            row.incoming,
            short(&row.entry.title, 65),
            row.entry.id
        ))?;
    }
    out.line(format!(
        "\nExcluded ambiguous references: {}",
        report.ambiguous
    ))?;
    out.line(format!(
        "Excluded unresolved references: {}",
        report.missing
    ))
}
pub fn risk(report: &RiskReport, out: &mut Out<'_>) -> Result<()> {
    out.line("=== GAUGE: Risk Scan ===\n")?;
    if report.flagged == 0 {
        return out.line("No current entry frontier contains refuted or audit-warning evidence.");
    }
    for row in &report.rows {
        out.line(format!(
            "{} [wiki:{:x}]",
            short(&row.entry.title, 65),
            row.entry.id
        ))?;
        let references: BTreeSet<_> = row
            .references
            .iter()
            .map(|reference| match reference {
                RiskReference::Unique(entry) => {
                    format!("wiki:{:x} {}", entry.id, short(&entry.title, 45))
                }
                RiskReference::Ambiguous {
                    selector,
                    candidates,
                } => format!(
                    "ambiguous selector wiki:{selector:x}; candidates: {}",
                    candidates
                        .iter()
                        .map(|id| format!("wiki:{id:x}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            })
            .collect();
        for reference in references {
            out.line(format!("  cites -> {reference}"))?;
        }
    }
    Ok(())
}
pub fn orphans(report: &Orphans, ids: bool, out: &mut Out<'_>) -> Result<()> {
    if ids {
        for row in &report.rows {
            out.line(format!("{:x}", row.id))?;
        }
        return Ok(());
    }
    out.line("=== GAUGE: Unanimous Orphan Entries ===\n")?;
    out.line(format!(
        "{} / {} entries have no outgoing link in any current state\n",
        report.total, report.entries
    ))?;
    for row in &report.rows {
        out.line(format!(
            "{} [wiki:{:x}]{}",
            short(&row.title, 65),
            row.id,
            if row.fork { " [fork]" } else { "" }
        ))?;
    }
    Ok(())
}
