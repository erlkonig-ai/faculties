//! What the wiki's `wiki:<32-hex>` references actually point at.
//!
//! An anchor reference is a LIVE indirection: `wiki show <anchor>` returns
//! whatever is head today, so a citation written in March silently follows the
//! text to August. A revision reference is a citation: immutable, pinned to
//! what the author read. `wiki lint --fix` can rewrite the first kind into the
//! second, but only in FRONTIER revisions — superseded revisions are
//! content-addressed and immutable, so their anchor references are permanent,
//! and their count is the standing cost of removing anchor lookup entirely.
//!
//! Reads only; never writes. `PILE=… cargo run --release --example anchor_reference_census`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{Context, Result};
use faculties::storage::{load_signer, open_pile_strict};
use faculties::wiki as wiki_model;
use triblespace::core::collection::Collection;
use triblespace::core::repo::pile::PileReader;
use triblespace::prelude::*;

#[derive(Default)]
struct Bucket {
    revisions_scanned: usize,
    anchor_refs: usize,
    anchor_ref_revisions: BTreeSet<Id>,
    anchor_targets: BTreeSet<Id>,
    /// Anchor references the lint pass can actually rewrite: a `#link("wiki:…")`
    /// or `[x](wiki:…)` form, outside a fenced code block.
    anchor_refs_in_links: usize,
    anchor_link_revisions: BTreeSet<Id>,
    /// Anchor references written as bare prose text (`wiki:<hex>` with no link
    /// syntax around it) or sitting inside a fenced block. `lint` leaves both.
    anchor_refs_bare: usize,
    anchor_refs_fenced: usize,
    revision_refs: usize,
    dangling_refs: usize,
    dangling_targets: BTreeSet<Id>,
    truncated_refs: usize,
}

impl Bucket {
    fn report(&self, label: &str) {
        println!("{label}:");
        println!(
            "  revisions scanned:              {}",
            self.revisions_scanned
        );
        println!(
            "  wiki:<anchor> references:       {} across {} revision(s), naming {} distinct anchor(s)",
            self.anchor_refs,
            self.anchor_ref_revisions.len(),
            self.anchor_targets.len()
        );
        println!(
            "    of those, in link syntax:     {} across {} revision(s)  <- lint rewrites these",
            self.anchor_refs_in_links,
            self.anchor_link_revisions.len()
        );
        println!(
            "    bare prose mentions:          {}",
            self.anchor_refs_bare
        );
        println!(
            "    inside fenced code blocks:    {}",
            self.anchor_refs_fenced
        );
        println!("  wiki:<revision> references:     {}", self.revision_refs);
        println!(
            "  references resolving to nothing:{} ({} distinct id(s))",
            self.dangling_refs,
            self.dangling_targets.len()
        );
        println!("  truncated (non-32-hex) refs:    {}", self.truncated_refs);
    }
}

fn read_content(reader: &PileReader, revision: &wiki_model::RevisionRecord) -> Result<String> {
    wiki_model::read_text(reader, revision.content)
}

fn main() -> Result<()> {
    let pile: PathBuf = std::env::var("PILE").expect("PILE").into();
    let signer = load_signer(&pile, None)?;
    let mut handle = open_pile_strict(&pile)?;
    let facts = Collection::new(&mut handle, faculties::schemas::wiki::DEFAULT_SCOPE_ID, signer)
        .materialize()
        .context("materialize Wiki collection")?;
    let reader = handle.reader().context("open Wiki attachment reader")?;
    let catalog = wiki_model::load_catalog(&facts)?;
    let model = &catalog.revisions;

    let records: Vec<wiki_model::RevisionRecord> = model.revision_records().cloned().collect();
    assert!(!records.is_empty(), "census scanned zero revisions");
    let known_revisions: BTreeSet<Id> = records.iter().map(|record| record.id).collect();
    let anchors: BTreeSet<Id> = records.iter().filter_map(|r| r.legacy_fragment).collect();
    assert!(!anchors.is_empty(), "census saw zero anchors: vacuous");

    let entries = model.all_entries();
    let frontier: BTreeSet<Id> = entries
        .iter()
        .flat_map(|entry| entry.frontier.iter().map(|head| head.id))
        .collect();

    // How many anchors a lint pass could resolve unambiguously (single head)?
    let mut resolvable = 0usize;
    let mut forked: Vec<Id> = Vec::new();
    let mut unresolvable: Vec<Id> = Vec::new();
    for anchor in &anchors {
        match model.legacy_fragment_frontier(*anchor) {
            Some([_only]) => resolvable += 1,
            Some(many) if !many.is_empty() => forked.push(*anchor),
            _ => unresolvable.push(*anchor),
        }
    }

    // The same three shapes the lint pass sees: any reference token, and the
    // two link syntaxes it rewrites. `lint_fix` skips fenced code blocks, so
    // this counts fenced hits separately rather than promising fixes it cannot
    // deliver.
    let re = regex::Regex::new(r"wiki:(?:[A-Za-z_][A-Za-z0-9_]*:)?([0-9A-Fa-f]+)").unwrap();
    let typst_link =
        regex::Regex::new(r#"#link\("wiki:(?:[A-Za-z_][A-Za-z0-9_]*:)?[0-9A-Fa-f]+"\)"#).unwrap();
    let markdown_link =
        regex::Regex::new(r"\[[^\]]+\]\(wiki:(?:[A-Za-z_][A-Za-z0-9_]*:)?[0-9A-Fa-f]+\)").unwrap();
    let mut frontier_bucket = Bucket::default();
    let mut superseded_bucket = Bucket::default();
    let mut fixable_refs = 0usize;
    let mut fixable_revisions: BTreeSet<Id> = BTreeSet::new();
    let mut self_refs = 0usize;

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
                } else if anchors.contains(&id) {
                    bucket.anchor_refs += 1;
                    bucket.anchor_ref_revisions.insert(record.id);
                    bucket.anchor_targets.insert(id);
                    if fenced {
                        bucket.anchor_refs_fenced += 1;
                    } else if in_link {
                        bucket.anchor_refs_in_links += 1;
                        bucket.anchor_link_revisions.insert(record.id);
                        if is_frontier {
                            if let Some([head]) = model.legacy_fragment_frontier(id) {
                                fixable_refs += 1;
                                fixable_revisions.insert(record.id);
                                if *head == record.id {
                                    self_refs += 1;
                                }
                            }
                        }
                    } else {
                        bucket.anchor_refs_bare += 1;
                    }
                } else {
                    bucket.dangling_refs += 1;
                    bucket.dangling_targets.insert(id);
                }
            }
        }
    }
    let _ = handle.close();

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
    println!(
        "anchors: {} total; {} resolve to exactly one head; {} resolve to several (forked); {} resolve to nothing",
        anchors.len(),
        resolvable,
        forked.len(),
        unresolvable.len()
    );
    if !forked.is_empty() {
        println!(
            "  forked anchors: {}",
            forked
                .iter()
                .map(|id| format!("{id:x}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    frontier_bucket.report("FRONTIER revisions (lint can rewrite these)");
    superseded_bucket.report("SUPERSEDED revisions (immutable — lint cannot rewrite)");
    println!(
        "lint-fixable anchor references: {fixable_refs} in {} frontier revision(s) ({self_refs} of them self-references)",
        fixable_revisions.len()
    );

    let mut per_anchor: BTreeMap<Id, usize> = BTreeMap::new();
    for anchor in superseded_bucket.anchor_targets.iter() {
        per_anchor.insert(*anchor, 0);
    }
    println!(
        "distinct anchors cited from superseded revisions: {}",
        per_anchor.len()
    );
    Ok(())
}
