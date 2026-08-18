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
use triblespace::core::collection::Collection;
use triblespace::core::repo::pile::PileReader;
use triblespace::prelude::*;

#[derive(Default)]
struct Bucket {
    revisions_scanned: usize,
    revision_refs: usize,
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
        println!(
            "  references naming a revision:   {}",
            self.revision_refs
        );
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
        println!(
            "  truncated (non-32-hex) refs:    {}",
            self.truncated_refs
        );
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
                if known_revisions.contains(&id) {
                    bucket.revision_refs += 1;
                    continue;
                }
                bucket.unresolvable_refs += 1;
                bucket.unresolvable_revisions.insert(record.id);
                bucket.unresolvable_targets.insert(id);
                let in_link = link_spans
                    .iter()
                    .any(|(start, end)| whole.start() >= *start && whole.end() <= *end);
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
    frontier_bucket.report("FRONTIER revisions (the live wiki)");
    superseded_bucket.report("SUPERSEDED revisions (immutable history)");
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
