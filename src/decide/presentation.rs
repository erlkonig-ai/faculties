//! Native, fallible presentation of completed Decide observations.
use super::operations::common_snapshot;
use super::{
    AddedFactor, DecisionDetail, DecisionSummary, FactorDetail, FactorSide, IntervalValue,
    ProposedDecision, Resolution, ResolutionReceipt, ResolutionSnapshot,
};
use crate::out::Out;
use anyhow::{anyhow, Result};
use hifitime::Epoch;
use triblespace::prelude::*;

fn fmt_result(id: Id) -> String {
    match super::result_name(id) {
        Some(name) => format!("{name} ({id:x})"),
        None => format!("{id:x}"),
    }
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn format_interval(interval: IntervalValue) -> String {
    let (lower, _): (Epoch, Epoch) = interval
        .try_from_inline()
        .expect("validated point interval");
    format!("{lower}")
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_owned()
    } else {
        format!(
            "{}…",
            value
                .chars()
                .take(max.saturating_sub(1))
                .collect::<String>()
        )
    }
}

fn list_status(resolution: &Resolution) -> String {
    match resolution {
        Resolution::Missing => "open".to_owned(),
        Resolution::Unique(snapshot) if snapshot.forced => "resolved [forced]".to_owned(),
        Resolution::Unique(_) => "resolved".to_owned(),
        Resolution::Agreed(snapshots) if snapshots[0].forced => {
            format!("resolved [forced agreement: {} heads]", snapshots.len())
        }
        Resolution::Agreed(snapshots) => {
            format!("resolved [agreement: {} heads]", snapshots.len())
        }
        Resolution::Forked(snapshots) => format!("FORKED: {} divergent heads", snapshots.len()),
        Resolution::Invalid(reason) => format!("INVALID: {reason}"),
    }
}

pub fn proposed(receipt: &ProposedDecision, out: &mut Out<'_>) -> Result<()> {
    out.line(format!("Proposed decision {:x}", receipt.decision))
}
pub fn factor(receipt: &AddedFactor, out: &mut Out<'_>) -> Result<()> {
    out.line(format!(
        "Added {} factor {:x} to {:x}",
        receipt.side.label(),
        receipt.factor,
        receipt.decision
    ))
}
pub fn resolved(receipt: &ResolutionReceipt, reconciled: bool, out: &mut Out<'_>) -> Result<()> {
    if reconciled {
        out.line(format!(
            "Reconciled {} resolution heads for {:x} at {:x}",
            receipt.predecessors.len(),
            receipt.decision,
            receipt.head
        ))?;
    } else {
        out.line(format!(
            "Resolved decision {:x} at {:x}",
            receipt.decision, receipt.head
        ))?;
    }
    match receipt.result {
        Some(result) => out.line(format!("Result: {}", fmt_result(result)))?,
        None => out.line("Result: none — no gate will read this outcome")?,
    }
    if receipt.forced {
        out.line(if reconciled {
            "Reconciliation is explicitly forced"
        } else {
            "Resolution is explicitly forced"
        })?;
    }
    Ok(())
}
pub fn list(rows: &[DecisionSummary], out: &mut Out<'_>) -> Result<()> {
    if rows.is_empty() {
        return out.line("(no decisions)");
    }
    for row in rows {
        let mut line = format!(
            "  {} [{}] +{}/-{} {}",
            &fmt_id(row.id)[..8],
            list_status(&row.resolution),
            row.pros,
            row.cons,
            row.title
        );
        if let Some(snapshot) = common_snapshot(&row.resolution) {
            if let Some(result) = snapshot.result {
                line.push_str(&format!(
                    "  → [{}]",
                    super::result_name(result)
                        .map(str::to_owned)
                        .unwrap_or_else(|| format!("{result:x}"))
                ));
            } else {
                line.push_str("  →");
            }
            if let Some(outcome) = &row.outcome {
                line.push_str(&format!(
                    " {}",
                    truncate(outcome.lines().next().unwrap_or(""), 60)
                ));
            }
        }
        out.line(line)?;
    }
    Ok(())
}
fn show_factor(factor: &FactorDetail, out: &mut Out<'_>) -> Result<()> {
    let sign = match factor.record.side {
        FactorSide::Pro => '+',
        FactorSide::Con => '-',
    };
    out.line(format!(
        "    {sign} [{}] {} ({})",
        fmt_id(factor.record.id),
        factor.text,
        format_interval(factor.record.created_at)
    ))
}
fn snapshot(
    report: &DecisionDetail,
    snapshot: &ResolutionSnapshot,
    out: &mut Out<'_>,
) -> Result<()> {
    let outcome = report
        .outcomes
        .iter()
        .find(|outcome| outcome.head == snapshot.id)
        .ok_or_else(|| anyhow!("resolution head {:x} has no prepared outcome", snapshot.id))?;
    out.line(format!("    head {}", fmt_id(snapshot.id)))?;
    out.line(format!(
        "      result: {}",
        snapshot
            .result
            .map(fmt_result)
            .unwrap_or_else(|| "(none - prose only, no gate reads it)".to_owned())
    ))?;
    out.line(format!("      forced: {}", snapshot.forced))?;
    out.line(format!(
        "      finished: {}",
        format_interval(snapshot.finished_at)
    ))?;
    out.line(format!(
        "      evidence: {}",
        if snapshot.evidence.is_empty() {
            "(none)".to_owned()
        } else {
            snapshot
                .evidence
                .iter()
                .map(|id| fmt_id(*id))
                .collect::<Vec<_>>()
                .join(", ")
        }
    ))?;
    if !snapshot.predecessors.is_empty() {
        out.line(format!(
            "      supersedes: {}",
            snapshot
                .predecessors
                .iter()
                .map(|id| fmt_id(*id))
                .collect::<Vec<_>>()
                .join(", ")
        ))?;
    }
    out.line("      outcome:")?;
    for line in outcome.outcome.lines() {
        out.line(format!("        {line}"))?;
    }
    Ok(())
}
pub fn show(report: &DecisionDetail, out: &mut Out<'_>) -> Result<()> {
    out.line(format!("decision {:x}", report.id))?;
    out.line(format!("  title: {}", report.title))?;
    out.line(format!(
        "  created: {}",
        format_interval(report.genesis.created_at)
    ))?;
    if let Some(context) = &report.context {
        out.line("  context:")?;
        for line in context.lines() {
            out.line(format!("    {line}"))?;
        }
    }
    if let Some(about) = report.genesis.about {
        out.line(format!("  about: {about:x}"))?;
    }
    for (side, name) in [(FactorSide::Pro, "pros"), (FactorSide::Con, "cons")] {
        let factors = report
            .factors
            .iter()
            .filter(|factor| factor.record.side == side)
            .collect::<Vec<_>>();
        out.line(format!("  {name} ({}):", factors.len()))?;
        for factor in factors {
            show_factor(factor, out)?;
        }
    }
    match &report.resolution {
        Resolution::Missing => out.line("  resolution: MISSING (open)")?,
        Resolution::Unique(head) => {
            out.line("  resolution: UNIQUE")?;
            snapshot(report, head, out)?;
        }
        Resolution::Agreed(heads) => {
            out.line(format!(
                "  resolution: AGREED ({} concurrent heads; all remain join obligations)",
                heads.len()
            ))?;
            for head in heads {
                snapshot(report, head, out)?;
            }
        }
        Resolution::Forked(heads) => {
            out.line(format!(
                "  resolution: FORKED ({} divergent heads; no outcome selected)",
                heads.len()
            ))?;
            for head in heads {
                snapshot(report, head, out)?;
            }
        }
        Resolution::Invalid(reason) => out.line(format!("  resolution: INVALID ({reason})"))?,
    }
    Ok(())
}
