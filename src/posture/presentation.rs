//! Fallible textual presentation of completed operation reports.
//! Publication and model work never run inside an emission/retry closure.
use super::*;
use crate::out::Out;
use crate::schemas::posture::{modality, DOC_UNSUPPORTED, OUTCOME_EXAMINED, OUTCOME_PARSE_FAILED};
use anyhow::{bail, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use triblespace::prelude::Id;

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

pub fn scan(report: &ScanReport, out: &mut Out<'_>) -> Result<()> {
    let files = &report.files;
    let omissions = &report.omissions;
    let target = &report.target;
    let examined = files
        .iter()
        .filter(|file| matches!(file.outcome, FileOutcome::Examined))
        .count();
    let unsupported = files
        .iter()
        .filter(|file| matches!(file.outcome, FileOutcome::Unsupported))
        .count();
    let failed = files
        .iter()
        .filter(|file| matches!(file.outcome, FileOutcome::ParseFailed(_)))
        .count();
    let finding_count: usize = files.iter().map(|file| file.findings.len()).sum();

    out.line(format!("scanned  : {} files under {}", files.len(), target))?;
    out.line(format!(
        "examined : {examined} ({unsupported} unsupported, {failed} failed to parse)"
    ))?;
    out.line(format!("findings : {finding_count}\n"))?;

    let mut by_modality: BTreeMap<&str, Vec<(&Path, &Finding)>> = BTreeMap::new();
    for file in files {
        for found in &file.findings {
            by_modality
                .entry(modality::name(found.modality))
                .or_default()
                .push((&file.path, found));
        }
    }
    for (name, items) in &by_modality {
        let documents = items.iter().map(|(path, _)| *path).collect::<BTreeSet<_>>();
        out.line(format!(
            "  {name}  ({} findings across {} document(s))",
            items.len(),
            documents.len()
        ))?;
        for (path, found) in items.iter().take(3) {
            let value = found.value.replace('\n', " ");
            let value: String = value.chars().take(90).collect();
            out.line(format!(
                "    {}  {}  {value}",
                path.display(),
                found.location.display()
            ))?;
        }
        if items.len() > 3 {
            out.line(format!("    … {} more", items.len() - 3))?;
        }
    }
    if failed > 0 {
        out.line(format!("\n  parse failures (NOT clean — unexamined):"))?;
        for file in files
            .iter()
            .filter(|file| matches!(file.outcome, FileOutcome::ParseFailed(_)))
            .take(5)
        {
            let FileOutcome::ParseFailed(error) = &file.outcome else {
                unreachable!()
            };
            out.line(format!("    {}  {error}", file.path.display()))?;
        }
    }

    out.line(format!(
        "\nNOT CHECKED by this scan — do not read silence here as safety:"
    ))?;
    for id in &report.unchecked {
        out.line(format!("  - {}", modality::name(*id)))?;
    }
    if unsupported > 0 {
        out.line(format!(
            "  - {unsupported} file(s) no extractor understands"
        ))?;
    }
    for omitted in omissions.iter().take(8) {
        out.line(format!(
            "  - {} ({})",
            omitted.path.display(),
            omitted.detail
        ))?;
    }
    if omissions.len() > 8 {
        out.line(format!(
            "  - … {} more persisted omission(s)",
            omissions.len() - 8
        ))?;
    }

    match report.scan_id {
        Some(id) => out.line(format!("\nscan {}", fmt_id(id)))?,
        None => out.line("\n(dry run — nothing written)")?,
    }
    Ok(())
}

pub fn list(report: &FindingList, ids: bool, out: &mut Out<'_>) -> Result<()> {
    if report.hidden > 0 && !report.include_resolved {
        out.line(format!("{} finding(s) hidden by a resolved Decide decision with result \"benign\" — pass --all to include them", report.hidden))?;
    }
    if report.groups.is_empty() {
        out.line(format!(
            "no findings{}",
            if report.scan.is_some() {
                " for that scan"
            } else {
                ""
            }
        ))?;
        out.line("(this is NOT a clean bill of health — see posture coverage)")?;
    }
    for group in &report.groups {
        out.line(format!("{}  ({})", group.name, group.count))?;
        for example in &group.examples {
            let value: String = example.value.replace('\n', " ").chars().take(90).collect();
            let evidence = &example.evidence;
            if ids {
                out.line(format!("  {}  {evidence}  {value}", fmt_id(example.id)))?;
            } else {
                out.line(format!("  {evidence}  {value}"))?;
            }
        }
        if group.count > group.examples.len() {
            out.line(format!("  … {} more", group.count - group.examples.len()))?;
        }
    }
    Ok(())
}

pub fn coverage(report: Option<&Coverage>, out: &mut Out<'_>) -> Result<()> {
    let Some(report) = report else {
        return out.line("no scans recorded");
    };
    out.line(format!(
        "scan {} over {}\n",
        fmt_id(report.scan),
        report.target
    ))?;
    out.line("checked:")?;
    for id in &report.checked {
        out.line(format!("  + {}", modality::name(*id)))?;
    }
    out.line("\nNOT checked — silence here is not evidence of absence:")?;
    for id in &report.unchecked {
        out.line(format!("  - {}", modality::name(*id)))?;
    }
    out.line(format!(
        "\nfiles: {} examined, {} unsupported, {} parse-failed",
        report.outcomes.get(&OUTCOME_EXAMINED).copied().unwrap_or(0),
        report.outcomes.get(&DOC_UNSUPPORTED).copied().unwrap_or(0),
        report
            .outcomes
            .get(&OUTCOME_PARSE_FAILED)
            .copied()
            .unwrap_or(0)
    ))?;
    if !report.omissions.is_empty() {
        out.line("\npersisted traversal omissions:")?;
        for omission in &report.omissions {
            out.line(format!(
                "  - {} ({})",
                omission.path.display(),
                omission.detail
            ))?;
        }
    }
    Ok(())
}

pub fn scans(scans: &[ScanRecord], out: &mut Out<'_>) -> Result<()> {
    if scans.is_empty() {
        out.line("no scans recorded")?;
    }
    for scan in scans {
        out.line(format!(
            "{}  {:>5} findings  {}",
            fmt_id(scan.id),
            scan.findings,
            scan.target
        ))?;
    }
    Ok(())
}

pub fn vocabulary(channels: &[VocabularyChannel], out: &mut Out<'_>) -> Result<()> {
    if channels.is_empty() {
        out.line("no channels defined (add one with posture vocab add <term> --channel <name>)")?;
    }
    let mut forks = 0;
    for channel in channels {
        let name = &channel.name;
        match &channel.state {
            VocabularyState::Missing => out.line(format!("{name}  (!! no policy revision)"))?,
            VocabularyState::Forked(heads) => {
                forks += 1;
                out.line(format!(
                    "{name}  (!! FORKED across {} policy heads)",
                    heads.len()
                ))?;
                for head in heads {
                    out.line(format!("  {}", fmt_id(*head)))?;
                }
            }
            VocabularyState::Ready { terms, .. } => {
                out.line(format!("{name}  ({} term(s))", terms.len()))?;
                for (term, why) in terms {
                    if why.is_empty() {
                        out.line(format!("  {term}"))?;
                    } else {
                        out.line(format!("  {term}  — {why}"))?;
                    }
                }
            }
        }
    }
    if forks > 0 {
        bail!("{forks} channel policy fork(s) require explicit reconciliation");
    }
    Ok(())
}

pub fn policy(receipt: &PolicyReceipt, out: &mut Out<'_>) -> Result<()> {
    let channel = &receipt.channel;
    match receipt.kind {
        PolicyMemberKind::Term => {
            let state = if receipt.published {
                "protecting"
            } else {
                "already protecting"
            };
            out.line(format!(
                "{state} {:?} from channel {channel:?}",
                receipt.text
            ))
        }
        PolicyMemberKind::Exemplar { benign, words } => {
            let role = if benign { "BENIGN" } else { "protected" };
            if receipt.published {
                out.line(format!(
                    "stored {role} exemplar ({words} words) for channel {channel:?}"
                ))
            } else {
                out.line(format!(
                    "already stored {role} exemplar for channel {channel:?}"
                ))
            }
        }
    }
}

pub fn git(report: &GitReport, out: &mut Out<'_>) -> Result<()> {
    let channel = &report.channel;
    let lexical_checked = report.lexical_checked;
    let range = &report.range;
    let n_commits = report.commits;
    let n_added = report.added_lines;
    let n_removed = report.removed_lines;
    let hidden = report.hidden;
    let hits = &report.hits;
    let unsafe_attribute_hits = &report.unsafe_attribute_hits;
    let protected_finding_ids = &report.protected_finding_ids;
    let unsafe_finding_ids = &report.unsafe_finding_ids;
    out.line(format!(
        "channel  : {channel} ({} protected term(s))",
        report.protected_terms
    ))?;
    if !lexical_checked {
        out.line(format!(
            "lexical  : NOT CHECKED — channel has no protected-term vocabulary"
        ))?;
    }
    out.line(format!("range    : {range}"))?;
    out.line(format!("examined : {n_commits} commit message(s), {n_added} added and {n_removed} removed line(s) across {n_commits} commit patch(es)\n"))?;

    if hidden > 0 {
        out.line(format!(
            "{hidden} finding(s) hidden by a resolved Decide decision with result \"benign\"."
        ))?;
    }
    if !hits.is_empty() {
        let total: usize = hits.values().map(|v| v.len()).sum();
        out.line(format!("{total} hit(s) across {} term(s):\n", hits.len()))?;
        for (term, term_hits) in hits {
            out.line(format!("  {term}  ({} hit(s))", term_hits.len()))?;
            for hit in term_hits.iter().take(4) {
                let id = protected_finding_ids
                    .get(&hit.location)
                    .copied()
                    .ok_or_else(|| anyhow::anyhow!("published Posture finding has no entity id"))?;
                out.line(format!("    {}  {}", fmt_id(id), hit.display))?;
            }
            if term_hits.len() > 4 {
                out.line(format!("    … {} more", term_hits.len() - 4))?;
            }
        }
    }
    if !unsafe_attribute_hits.is_empty() {
        out.line(format!(
            "{} literal-pinned Rust attribute declaration change(s) require justification:\n",
            unsafe_attribute_hits.len()
        ))?;
        for hit in unsafe_attribute_hits {
            let id = unsafe_finding_ids
                .get(&hit.location)
                .copied()
                .ok_or_else(|| {
                    anyhow::anyhow!("published unsafe-attribute finding has no entity id")
                })?;
            out.line(format!("    {}  {}", fmt_id(id), hit.display))?;
        }
    }
    if hits.is_empty() && unsafe_attribute_hits.is_empty() {
        out.line(format!(
            "no unresolved Posture finding remains in this range."
        ))?;
    } else {
        out.line(format!(
            "\nA finding stops blocking only after a Decide decision about its exact id \
             resolves with `--result benign`; the outcome text is free prose and stays yours \
             to write. An unsafe-attribute change additionally requires a nonempty \
             `decide propose --context` justification."
        ))?;
    }

    // Never a clean bill of health.
    out.line(format!(
        "\nNOT CHECKED — this audit is narrow by construction:"
    ))?;
    out.line(format!(
        "  - file contents outside this range's added lines"
    ))?;
    out.line(format!(
        "  - removed-line protected terms (literal-pinned attribute declarations ARE checked)"
    ))?;
    out.line(format!("  - author names, emails and commit dates"))?;
    out.line(format!(
        "  - binary files, and anything a term does not literally spell"
    ))?;
    out.line(format!(
        "  - thematic material carrying no protected term (the 2026-07-22 leak was exactly this)"
    ))?;

    if !lexical_checked {
        out.line(format!(
            "posture: refusing a clean result because channel {channel:?} has no \
             protected-term vocabulary; the unsafe-attribute invariant was still checked."
        ))?;
    }
    Ok(())
}

pub fn hooks(report: &HookReport, out: &mut Out<'_>) -> Result<()> {
    let channel = &report.channel;
    let remote_match = report.remote_match.as_deref();
    let want_pre_push = report.pre_push;
    let want_post_commit = report.post_commit;
    for installed in &report.installed {
        out.line(format!("installed {}", installed.display()))?;
    }
    out.line(format!("  channel : {channel}"))?;
    match remote_match {
        Some(m) => out.line(format!(
            "  remotes : only those matching {m:?} (pre-push only)"
        ))?,
        None => out.line(format!(
            "  remotes : ALL (pass --remote-match to scope by destination)"
        ))?,
    }
    out.line(format!("  pile    : {}", report.pile.display()))?;
    if want_pre_push {
        out.line(format!(
            "\npre-push is the GATE. It runs on every push and exits non-zero on a hit,"
        ))?;
        out.line(format!(
            "and also when the channel has no vocabulary — a hook that passes because"
        ))?;
        out.line(format!(
            "it checked nothing is worse than no hook. It audits what the push ADDS,"
        ))?;
        out.line(format!(
            "never what the remote already holds; for existing history run"
        ))?;
        out.line(format!("`posture sweep --history`."))?;
    }
    if want_post_commit {
        out.line(format!(
            "\npost-commit is the SMOKE ALARM. It audits the commit that just happened"
        ))?;
        out.line(format!(
            "and never refuses anything — by push time a leak is history and the remedy"
        ))?;
        out.line(format!(
            "is a rewrite; one commit earlier it is `git commit --amend`. It runs"
        ))?;
        out.line(format!(
            "DETACHED, so the commit returns at once and the report follows a little"
        ))?;
        out.line(format!(
            "later, in the terminal and in .git/posture-post-commit.log."
        ))?;
    }
    Ok(())
}

pub fn semantic(report: &SemanticReport, out: &mut Out<'_>) -> Result<()> {
    let channel = &report.channel;
    let n_protected = report.protected;
    let n_benign = report.benign;
    let n_chunks = report.chunks;
    let threshold = report.threshold;
    let skipped = report.skipped;
    let too_big = report.too_big;
    let omissions = &report.omissions;
    let hits = &report.hits;
    out.line(format!(
        "channel  : {channel} ({n_protected} protected, {n_benign} benign exemplar(s))"
    ))?;
    if n_benign == 0 {
        out.line(format!(
            "  !! no benign exemplars: scores are ABSOLUTE and will track prose register"
        ))?;
        out.line(format!(
            "     rather than content. Add contrast with `posture exemplar ... --benign`."
        ))?;
    }
    out.line(format!(
        "examined : {} of {} file(s), {n_chunks} chunk(s), threshold {threshold}",
        report.examined,
        report.examined + skipped + too_big
    ))?;
    out.line("")?;
    if hits.is_empty() {
        out.line(format!("no chunk resembles an exemplar above {threshold}."))?;
    } else {
        out.line(format!(
            "{} document(s) with a resembling chunk:\n",
            hits.len()
        ))?;
        for hit in hits.iter().take(40) {
            let s: String = hit.snippet.chars().take(80).collect();
            let score = hit.score;
            let line = hit.line;
            out.line(format!("  {score:.3}  {}:{line}  {s}", hit.name))?;
        }
        if hits.len() > 40 {
            out.line(format!("  … {} more", hits.len() - 40))?;
        }
    }
    out.line(format!("\nNOT CHECKED:"))?;
    // Counted, not asserted. A coverage line that states a policy instead of a
    // measurement is how "0 files examined" once read as a clean bill of health.
    out.line(format!("  - {skipped} file(s) that are not valid UTF-8 (binaries, PDFs, office documents — use `posture scan`)"))?;
    out.line(format!(
        "  - {too_big} file(s) over {} MiB",
        SEMANTIC_MAX_BYTES / 1024 / 1024
    ))?;
    for omission in omissions {
        out.line(format!(
            "  - {} ({})",
            omission.path.display(),
            omission.detail
        ))?;
    }
    out.line(format!(
        "  - anything an exemplar does not resemble — this tier is only as"
    ))?;
    out.line(format!(
        "    broad as the exemplars given to it, and cosine similarity is a"
    ))?;
    out.line(format!(
        "    proxy for 'about the same thing', not a proof of it"
    ))?;
    out.line("")?;
    out.line(format!(
        "  READ THIS BEFORE TRUSTING THE RANKING. Measured 2026-08-05 on this"
    ))?;
    out.line(format!(
        "  project: the tier DETECTS but does not RANK. Inserting a narrative"
    ))?;
    out.line(format!(
        "  paragraph moved its own file 0.017 -> 0.039, yet two innocent files"
    ))?;
    out.line(format!(
        "  scored higher (0.081, 0.076) — ordinary doc comments about memory and"
    ))?;
    out.line(format!(
        "  identity. This codebase IMPLEMENTS the concepts the protected material"
    ))?;
    out.line(format!(
        "  DESCRIBES, so both occupy the same semantic region and no absolute"
    ))?;
    out.line(format!(
        "  threshold separates them. That is structural, not a tuning problem."
    ))?;
    out.line(format!(
        "  Use it on a DIFF, where a file is its own baseline, not as a filter"
    ))?;
    out.line(format!(
        "  over a tree. Corpora whose subject matter differs from the protected"
    ))?;
    out.line(format!("  material should behave far better."))?;
    Ok(())
}

pub fn sweep(report: &SweepReport, out: &mut Out<'_>) -> Result<()> {
    out.line(format!(
        "channel  : {} ({} protected term(s))",
        report.channel, report.protected_terms
    ))?;
    if !report.lexical_checked {
        out.line("lexical  : NOT CHECKED — channel has no protected-term vocabulary")?;
    }
    out.line(format!("root     : {}", report.root.display()))?;
    out.line(format!("repos    : {}\n", report.repos))?;
    if !report.gh_available && !report.include_private {
        out.line("  !! gh is unavailable: visibility is unknown, so EVERY repo with a")?;
        out.line("     remote is audited rather than silently skipped.\n")?;
    }
    for repo in &report.examined {
        let scope = if report.history { "reach" } else { "ahead" };
        let count = repo.terms.values().sum::<usize>() + repo.unsafe_attributes;
        let name = repo
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("?");
        let state = if count == 0 {
            "no unresolved findings".to_owned()
        } else {
            format!(
                "{count} finding(s) across {} class(es)",
                repo.terms.len() + usize::from(repo.unsafe_attributes > 0)
            )
        };
        out.line(format!(
            "  {name:<24} {:<28} {:<8} {scope}={:<5} {state}",
            repo.slug, repo.visibility, repo.commits
        ))?;
        if count > 0 {
            out.line(format!("      (range {})", repo.range))?;
            for (term, count) in &repo.terms {
                out.line(format!("      {term}  ({count} hit(s))"))?;
            }
            if repo.unsafe_attributes > 0 {
                out.line(format!(
                    "      unsafe-attribute-id  ({} finding(s))",
                    repo.unsafe_attributes
                ))?;
            }
        }
    }
    out.line(format!(
        "\n{} repositor(y/ies) carry unresolved Posture findings {}.",
        report.flagged(),
        if report.history {
            "anywhere in their reachable history"
        } else {
            "ahead of their remote"
        }
    ))?;
    out.line("\nNOT CHECKED:")?;
    out.line(format!(
        "  - {} repo(s) whose remote gh reports PRIVATE (re-run with --all)",
        report.skipped_private
    ))?;
    out.line(format!(
        "  - {} repo(s) with no origin remote",
        report.no_remote
    ))?;
    out.line("  - repos nested deeper than one level under the root")?;
    out.line("  - OTHER BRANCHES of a scanned repo: only the checked-out HEAD is audited")?;
    if !report.history {
        out.line(
            "  - HISTORY already on the remote: only work ahead of it was read (pass --history)",
        )?;
    }
    out.line("  - uncommitted work, which cannot be pushed but can be committed later")?;
    out.line("  - everything posture git does not check (see its own coverage note)")?;
    if !report.lexical_checked {
        out.line(format!("posture: sweep cannot issue a clean result because channel {:?} has no protected-term vocabulary; unsafe-attribute invariants were still checked.", report.channel))?;
    }
    Ok(())
}
