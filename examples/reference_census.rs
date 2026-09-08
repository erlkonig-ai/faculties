//! What the wiki's `wiki:<hex>` references actually point at.
//!
//! A reference names a REVISION — immutable, pinned to the text its author
//! read — or it names nothing. It used to be able to name a legacy ANCHOR
//! instead, a live indirection that returned whatever was head today; `wiki
//! lint` rewrote every anchor reference in the corpus to the anchor's
//! then-current head, and anchor lookup was then removed outright.
//!
//! What is left over is history: SUPERSEDED revisions are content-addressed
//! and cannot be rewritten, so the anchor references in their text are
//! permanent and now resolve to nothing. This census counts them. It is the
//! standing measure of what retiring the anchors cost, and — read over the
//! FRONTIER — the check that the live wiki itself is clean.
//!
//! Reads only; never writes. `PILE=… cargo run --release --example reference_census`.

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{Context, Result};
use faculties::storage::{load_signer, open_pile_strict};
use faculties::wiki as wiki_model;
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::prelude::*;

#[derive(Default)]
struct Bucket {
    revisions_scanned: usize,
    revision_refs: usize,
    /// Of the resolvable references, the ones naming a revision that is still
    /// its entry's current head — following the link lands on live text.
    head_refs: usize,
    /// Of the resolvable references, the ones naming a SUPERSEDED revision.
    /// The target is real, so nothing reports breakage; the text it carries is
    /// simply out of date. This is the silent class, and the reason `wiki
    /// show` resolves to the frontier by default.
    stale_refs: usize,
    stale_targets: BTreeSet<Id>,
    stale_sources: BTreeSet<Id>,
    /// Of the stale ones, how many a reader would actually click.
    stale_in_links: usize,
    /// References naming no revision in the store: retired anchors, and ids
    /// that never resolved.
    unresolvable_refs: usize,
    unresolvable_revisions: BTreeSet<Id>,
    unresolvable_targets: BTreeSet<Id>,
    /// Of the unresolvable ones, how many sit in link syntax (a reader would
    /// click them) versus bare prose versus quoted inside a fenced block.
    unresolvable_in_links: usize,
    unresolvable_bare: usize,
    unresolvable_fenced: usize,
    truncated_refs: usize,
}

impl Bucket {
    fn report(&self, label: &str) {
        println!("{label}:");
        println!(
            "  revisions scanned:              {}",
            self.revisions_scanned
        );
        println!("  references naming a revision:   {}", self.revision_refs);
        println!("    naming a CURRENT head:        {}", self.head_refs);
        println!(
            "    naming a SUPERSEDED revision: {} across {} revision(s), naming {} distinct id(s)",
            self.stale_refs,
            self.stale_sources.len(),
            self.stale_targets.len()
        );
        println!("      in link syntax:             {}", self.stale_in_links);
        if self.revision_refs > 0 {
            println!(
                "      share of resolvable refs:   {:.1}%",
                100.0 * self.stale_refs as f64 / self.revision_refs as f64
            );
        }
        println!(
            "  references naming nothing:      {} across {} revision(s), naming {} distinct id(s)",
            self.unresolvable_refs,
            self.unresolvable_revisions.len(),
            self.unresolvable_targets.len()
        );
        println!(
            "    in link syntax:               {}",
            self.unresolvable_in_links
        );
        println!(
            "    bare prose mentions:          {}",
            self.unresolvable_bare
        );
        println!(
            "    inside fenced code blocks:    {}",
            self.unresolvable_fenced
        );
        println!("  truncated (non-32-hex) refs:    {}", self.truncated_refs);
    }
}

fn read_content(reader: &PileSnapshot, revision: &wiki_model::RevisionRecord) -> Result<String> {
    wiki_model::read_text(reader, revision.content)
}

fn main() -> Result<()> {
    let pile: PathBuf = std::env::var("PILE").expect("PILE").into();
    let signer = load_signer(&pile, None)?;
    let mut store = open_pile_strict(&pile)?;
    let collection = faculties::collection_names::open(
        &mut store,
        faculties::schemas::wiki::DEFAULT_SCOPE_ID,
        signer.verifying_key(),
    )
    .context("register Wiki collection descriptor")?;
    let reader = store.snapshot().context("freeze Wiki store snapshot")?;
    let (facts, _) = faculties::storage::read_fact_collection(collection, &reader)
        .context("snapshot Wiki collection")?;
    let catalog = wiki_model::load_catalog(&facts)?;
    let model = &catalog.revisions;

    let records: Vec<wiki_model::RevisionRecord> = model.revision_records().cloned().collect();
    assert!(!records.is_empty(), "census scanned zero revisions");
    let known_revisions: BTreeSet<Id> = records.iter().map(|record| record.id).collect();

    let entries = model.all_entries();
    let frontier: BTreeSet<Id> = entries
        .iter()
        .flat_map(|entry| entry.frontier.iter().map(|head| head.id))
        .collect();

    // The same three shapes the lint pass sees: any reference token, and the
    // two link syntaxes. `lint_fix` skips fenced code blocks, so fenced hits
    // are counted apart rather than promising fixes nothing will deliver.
    let re = regex::Regex::new(r"wiki:(?:[A-Za-z_][A-Za-z0-9_]*:)?([0-9A-Fa-f]+)").unwrap();
    let typst_link =
        regex::Regex::new(r#"#link\("wiki:(?:[A-Za-z_][A-Za-z0-9_]*:)?[0-9A-Fa-f]+"\)"#).unwrap();
    let markdown_link =
        regex::Regex::new(r"\[[^\]]+\]\(wiki:(?:[A-Za-z_][A-Za-z0-9_]*:)?[0-9A-Fa-f]+\)").unwrap();
    let mut frontier_bucket = Bucket::default();
    let mut superseded_bucket = Bucket::default();
    // (source head, superseded target) for the LIVE wiki only: the citations a
    // reader following today's text would land on.
    let mut stale_pairs: Vec<(Id, Id)> = Vec::new();

    for record in &records {
        let is_frontier = frontier.contains(&record.id);
        let bucket = if is_frontier {
            &mut frontier_bucket
        } else {
            &mut superseded_bucket
        };
        bucket.revisions_scanned += 1;
        let content = read_content(&reader, record)?;
        let mut fenced = false;
        for line in content.lines() {
            if line.trim_start().starts_with("```") {
                fenced = !fenced;
                continue;
            }
            let link_spans: Vec<(usize, usize)> = typst_link
                .find_iter(line)
                .chain(markdown_link.find_iter(line))
                .map(|found| (found.start(), found.end()))
                .collect();
            for captures in re.captures_iter(line) {
                let whole = captures.get(0).unwrap();
                let token = &captures[1];
                if token.len() != 32 {
                    bucket.truncated_refs += 1;
                    continue;
                }
                let Some(id) = Id::from_hex(&token.to_ascii_lowercase()) else {
                    bucket.truncated_refs += 1;
                    continue;
                };
                let in_link = link_spans
                    .iter()
                    .any(|(start, end)| whole.start() >= *start && whole.end() <= *end);
                if known_revisions.contains(&id) {
                    bucket.revision_refs += 1;
                    if frontier.contains(&id) {
                        bucket.head_refs += 1;
                    } else {
                        bucket.stale_refs += 1;
                        bucket.stale_targets.insert(id);
                        bucket.stale_sources.insert(record.id);
                        if in_link {
                            bucket.stale_in_links += 1;
                        }
                        if is_frontier {
                            stale_pairs.push((record.id, id));
                        }
                    }
                    continue;
                }
                bucket.unresolvable_refs += 1;
                bucket.unresolvable_revisions.insert(record.id);
                bucket.unresolvable_targets.insert(id);
                if fenced {
                    bucket.unresolvable_fenced += 1;
                } else if in_link {
                    bucket.unresolvable_in_links += 1;
                } else {
                    bucket.unresolvable_bare += 1;
                }
            }
        }
    }
    // A stale citation only MISLEADS if the frontier says something different.
    // Resolving each live-wiki stale target forward and diffing the text is
    // what separates "names an older id" from "shows the reader older text".
    let mut differing_refs = 0usize;
    let mut identical_refs = 0usize;
    let mut fork_refs = 0usize;
    let mut affected_entries: BTreeSet<Id> = BTreeSet::new();
    let mut misleading_sources: BTreeSet<Id> = BTreeSet::new();
    let mut resolved: std::collections::BTreeMap<Id, bool> = std::collections::BTreeMap::new();
    for (source, target) in &stale_pairs {
        let entry = model
            .entry_containing(*target)
            .expect("every revision belongs to one entry");
        affected_entries.insert(*entry.roots.first().expect("entry has a root"));
        if entry.frontier.len() > 1 {
            fork_refs += 1;
            continue;
        }
        let differs = match resolved.get(target) {
            Some(known) => *known,
            None => {
                let old = wiki_model::read_text(&reader, model.revision(*target).unwrap().content)?;
                let new = wiki_model::read_text(&reader, entry.frontier[0].content)?;
                let differs = old != new;
                resolved.insert(*target, differs);
                differs
            }
        };
        if differs {
            differing_refs += 1;
            misleading_sources.insert(*source);
        } else {
            identical_refs += 1;
        }
    }
    let _ = store.close();

    let legacy = records.iter().filter(|r| !r.is_native()).count();
    println!(
        "revisions: {} total ({} legacy, {} native); entries: {}; frontier revisions: {}; superseded: {}",
        records.len(),
        legacy,
        records.len() - legacy,
        entries.len(),
        frontier.len(),
        records.len() - frontier.len()
    );
    frontier_bucket.report("FRONTIER revisions (the live wiki)");
    superseded_bucket.report("SUPERSEDED revisions (immutable history)");
    println!("FOLLOWING the live wiki's stale citations forward:");
    println!(
        "  target text differs from the frontier: {differing_refs} ref(s), in {} source revision(s), touching {} entry(-ies)",
        misleading_sources.len(),
        affected_entries.len()
    );
    println!("  target text identical to the frontier: {identical_refs} ref(s)");
    println!("  target's entry is forked:              {fork_refs} ref(s)");
    if frontier_bucket.unresolvable_refs == 0 {
        println!("FRONTIER CLEAN: every reference in the live wiki names a revision");
    } else {
        println!(
            "FRONTIER DIRTY: {} reference(s) in the live wiki name nothing; run `wiki lint --fix`",
            frontier_bucket.unresolvable_refs
        );
    }
    Ok(())
}
