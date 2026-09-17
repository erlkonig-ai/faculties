//! Output contracts. These are part of the specification, not decoration.
//!
//! Two rules govern everything here:
//!
//! 1. **Every read ends with the revisions it read at.** Absence is only
//!    meaningful with its denominator. Three wrong absence claims were made from
//!    stale checkouts on the night this faculty was commissioned; a tool that
//!    says "absent" without saying absent *from what* will make the fourth.
//! 2. **A high-frequency identifier is never phrased as a settled answer.** A
//!    tool that says "0 hits" beautifully and "4,912 hits" identically has
//!    learned nothing.

use anyhow::Result;

use crate::code::index::{IndexReport, SearchReport};
use crate::code::operations::{
    Answer, BlameReport, DuplicateReport, Hit, IngestReport, ItemDetail, Provenance, StatsReport,
};
use crate::out::Out;

/// `34795` as `34,795`. An absence verdict's denominator has to be readable.
fn grouped(value: usize) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(character);
    }
    out
}

fn first_line(text: &str, limit: usize) -> String {
    let line = text.lines().next().unwrap_or("").trim();
    if line.chars().count() <= limit {
        return line.to_owned();
    }
    let cut = line
        .char_indices()
        .nth(limit)
        .map(|(at, _)| at)
        .unwrap_or(line.len());
    format!("{}…", &line[..cut])
}

pub fn provenance(provenance: &Provenance, out: &mut Out<'_>) -> Result<()> {
    if provenance.scans.is_empty() {
        return out.line(
            "searched NOTHING: this pile holds no Code scan. Run `code ingest <dir>...` first.",
        );
    }
    out.line(format!(
        "searched {} placement(s) over {} unit(s)",
        grouped(provenance.placements),
        grouped(provenance.units),
    ))?;
    let labels: Vec<String> = provenance.scans.iter().map(|scan| scan.label()).collect();
    out.line(format!("  {}", labels.join(" · ")))?;
    out.line(format!("  extractor {}", provenance.extractor))
}

fn hit_line(hit: &Hit, indent: &str, out: &mut Out<'_>) -> Result<()> {
    let kind = hit.kind.clone().unwrap_or_else(|| "?".to_owned());
    let name = hit.name.clone().unwrap_or_else(|| "—".to_owned());
    out.line(format!(
        "{indent}{:<7} {:<32} {}",
        kind,
        name,
        hit.location()
    ))?;
    if let Some(signature) = &hit.signature {
        out.line(format!("{indent}        {}", first_line(signature, 140)))?;
    }
    if let Some(doc) = &hit.doc {
        out.line(format!("{indent}        \"{}\"", first_line(doc, 120)))?;
    }
    Ok(())
}

/// A definition answer, or an affirmative ABSENT verdict.
///
/// Absence exits 0. It is a finding, not a failure: answering "absent"
/// confidently, with a denominator and a pointer at history, is worth more than
/// a list of near-misses that a reader will mistake for results.
pub fn definition(answer: &Answer, out: &mut Out<'_>) -> Result<()> {
    if answer.hits.is_empty() {
        out.line(format!("{} — ABSENT", answer.subject))?;
        out.line(format!(
            "  no declaration named `{}` in {} unit(s) at {} scanned revision(s)",
            answer.subject,
            grouped(answer.provenance.units),
            answer.provenance.scans.len(),
        ))?;
        if !answer.near.is_empty() {
            out.line("  nearby (NOT answers; name-similar declarations):")?;
            for hit in &answer.near {
                hit_line(hit, "    ", out)?;
            }
        }
        if let Some(followup) = &answer.followup {
            out.line(format!("  {followup}"))?;
        }
    } else {
        out.line(format!(
            "{} — {} declaration(s)",
            answer.subject,
            grouped(answer.hits.len())
        ))?;
        for hit in &answer.hits {
            hit_line(hit, "  ", out)?;
        }
    }
    out.line("")?;
    provenance(&answer.provenance, out)
}

/// A usage answer. Zero rows IS the answer, and is said so.
pub fn usage(answer: &Answer, out: &mut Out<'_>) -> Result<()> {
    if answer.hits.is_empty() {
        out.line(format!("{} — NOT NAMED ANYWHERE", answer.subject))?;
        out.line(format!(
            "  no catalogued declaration syntactically names `{}` in {} unit(s)",
            answer.subject,
            grouped(answer.provenance.units),
        ))?;
    } else {
        out.line(format!(
            "{} — named by {} declaration(s)",
            answer.subject,
            grouped(answer.hits.len())
        ))?;
        if let Some(caveat) = &answer.caveat {
            out.line(format!("  {caveat}"))?;
            out.line("")?;
        }
        for hit in answer.hits.iter().take(200) {
            hit_line(hit, "  ", out)?;
        }
        if answer.hits.len() > 200 {
            out.line(format!("  … and {} more", grouped(answer.hits.len() - 200)))?;
        }
    }
    out.line("")?;
    provenance(&answer.provenance, out)
}

pub fn search(report: &SearchReport, out: &mut Out<'_>) -> Result<()> {
    if let Some(stale) = &report.stale {
        out.line(stale)?;
        return Ok(());
    }
    if report.groups.is_empty() {
        out.line(format!("{} — no lexical hits", report.query))?;
    }
    for (rank, group) in report.groups.iter().enumerate() {
        out.line(format!(
            "{}. {}/{:<50} {:.4}",
            rank + 1,
            group.repo,
            group.path,
            group.score
        ))?;
        if !group.distinguishing.is_empty() {
            out.line(format!(
                "   distinguishing imports: {}",
                group.distinguishing.join(" · ")
            ))?;
        }
        if let Some((shared, total)) = group.shared_with_top {
            if rank > 0 {
                out.line(format!(
                    "   shares {shared}/{total} distinguishing imports with #1"
                ))?;
            }
        }
        for member in &group.members {
            let kind = member.kind.clone().unwrap_or_else(|| "?".to_owned());
            let name = member.name.clone().unwrap_or_else(|| "—".to_owned());
            let prose = member
                .doc
                .as_deref()
                .map(|doc| format!("  \"{}\"", first_line(doc, 90)))
                .unwrap_or_default();
            out.line(format!(
                "   {:<7} {:<30} :{:<6}{}",
                kind, name, member.line, prose
            ))?;
        }
    }
    out.line("")?;
    out.line(
        "ranking is lexical. It answers \"what do we have that is about this\"; it CANNOT \
answer \"is this absent\" — use `code find` for that.",
    )?;
    provenance(&report.provenance, out)
}

pub fn detail(detail: &ItemDetail, out: &mut Out<'_>) -> Result<()> {
    out.line(format!("item {:x}", detail.hit.item))?;
    hit_line(&detail.hit, "  ", out)?;
    if detail.places.len() > 1 {
        out.line(format!(
            "  placed in {} location(s) — byte-identical code is ONE item:",
            detail.places.len()
        ))?;
        for place in &detail.places {
            out.line(format!("    {}", place.location()))?;
        }
    }
    if let Some(source) = &detail.source {
        out.line("")?;
        for line in source.lines() {
            out.line(format!("  {line}"))?;
        }
    }
    out.line("")?;
    provenance(&detail.provenance, out)
}

pub fn duplicates(report: &DuplicateReport, out: &mut Out<'_>) -> Result<()> {
    if report.groups.is_empty() {
        out.line("no item is placed in more than one location at these revisions")?;
    }
    for group in &report.groups {
        out.line(format!(
            "{} {} — {} placement(s), {} line(s)",
            group.kind.clone().unwrap_or_else(|| "?".to_owned()),
            group.name.clone().unwrap_or_else(|| "—".to_owned()),
            group.places.len(),
            group.lines,
        ))?;
        for place in &group.places {
            out.line(format!("    {}", place.location()))?;
        }
    }
    out.line("")?;
    out.line(
        "these are EXACT duplicates: one item, several placements. Near-duplicates are out of \
scope — an exact match is what content addressing can see, and nothing here approximates.",
    )?;
    provenance(&report.provenance, out)
}

pub fn stats(report: &StatsReport, out: &mut Out<'_>) -> Result<()> {
    for row in &report.rows {
        out.line(format!(
            "{}: {} unit(s), {} placement(s), {} parse failure(s)",
            row.scan,
            grouped(row.units),
            grouped(row.placements),
            grouped(row.parse_failures),
        ))?;
        let kinds: Vec<String> = row
            .kinds
            .iter()
            .map(|(kind, count)| format!("{kind} {}", grouped(*count)))
            .collect();
        if !kinds.is_empty() {
            out.line(format!("  {}", kinds.join(" · ")))?;
        }
    }
    out.line("")?;
    provenance(&report.provenance, out)
}

pub fn blame(report: &BlameReport, out: &mut Out<'_>) -> Result<()> {
    if report.rows.is_empty() {
        out.line(format!(
            "{} — git found no commit adding or removing an occurrence in {}",
            report.identifier,
            report.searched.join(", ")
        ))?;
        return Ok(());
    }
    out.line(format!(
        "{} — {} commit(s) changed an occurrence",
        report.identifier,
        report.rows.len()
    ))?;
    for row in &report.rows {
        out.line(format!(
            "  {} {} {} \"{}\"",
            row.date,
            row.repo,
            &row.commit[..8.min(row.commit.len())],
            row.subject
        ))?;
        for path in &row.paths {
            out.line(format!("      {path}"))?;
        }
    }
    out.line("")?;
    out.line(format!(
        "searched history in: {}",
        report.searched.join(" · ")
    ))
}

pub fn ingest(report: &IngestReport, out: &mut Out<'_>) -> Result<()> {
    if report.dry_run {
        out.line("dry run — nothing was written")?;
    }
    for row in &report.repos {
        let commit = if row.commit.starts_with("worktree:") {
            format!("worktree ({})", &row.commit[9..17.min(row.commit.len())])
        } else {
            row.commit.chars().take(12).collect()
        };
        out.line(format!(
            "{}@{}: {} file(s) seen, {} parsed, {} skipped, {} declaration(s), {} parse failure(s)",
            row.repo,
            commit,
            grouped(row.files_seen),
            grouped(row.files_parsed),
            grouped(row.files_skipped),
            grouped(row.items),
            grouped(row.parse_failures),
        ))?;
    }
    if !report.dry_run {
        out.line("")?;
        out.line(
            "ingest does not build a search index. Run `code index` when you want `code search`.",
        )?;
    }
    Ok(())
}

pub fn index(report: &IndexReport, out: &mut Out<'_>) -> Result<()> {
    out.line(format!(
        "Code: {} collection element(s) — the signed COMMITs the covers derive from",
        grouped(report.source_elements)
    ))?;
    out.line(format!(
        "Code prose BM25: {} document(s)",
        grouped(report.doc_documents)
    ))?;
    out.line(format!(
        "Code token BM25: {} document(s)",
        grouped(report.text_documents)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_denominator_is_grouped_so_a_reader_can_see_its_size() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1_000), "1,000");
        assert_eq!(grouped(34_795), "34,795");
        assert_eq!(grouped(1_262_000), "1,262,000");
    }

    #[test]
    fn a_first_line_is_truncated_with_an_ellipsis() {
        assert_eq!(first_line("one\ntwo", 80), "one");
        assert_eq!(first_line("abcdef", 3), "abc…");
    }
}
