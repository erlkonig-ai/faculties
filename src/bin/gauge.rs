//! A read-only research-quality lens over Wiki's canonical revision DAG.
//!
//! Every metric is explicit about its unit: logical entries or current
//! frontier states. Forks are evidence, never rows to settle by clock or
//! iteration order. Links are reproduced from admitted content and legacy
//! selectors resolve through the same revision/legacy-selector model as the
//! Wiki CLI.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::storage::{load_signer, open_pile_strict};
use faculties::wiki::{self as wiki_model, FrontierEntry, FrontierModel, LinkResolution};

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "gauge",
    about = "Research-quality metrics over Wiki entries and complete DAG frontiers"
)]
struct Cli {
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads never create one.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Show entry, frontier, tag, link, and orphan metrics.
    Health,
    /// Count tags both by current state occurrence and by logical entry.
    Tags,
    /// Show current published/refuted states without settling forks.
    Quality,
    /// Show entries with the most unambiguously resolved incoming links.
    Hubs {
        #[arg(short, long, default_value = "15")]
        top: usize,
    },
    /// Find entries whose current states cite refuted or audit-warned entries.
    Risk,
    /// List entries for which every current state has zero outgoing links.
    Orphans {
        #[arg(short, long, default_value = "20")]
        top: usize,
        /// Print one stable entry selector per line.
        #[arg(long)]
        ids: bool,
    },
}

type GaugeModel = FrontierModel;

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

fn link_census(model: &GaugeModel) -> (usize, usize, usize, usize) {
    let mut total = 0;
    let mut resolved = 0;
    let mut ambiguous = 0;
    let mut missing = 0;
    for state in model.active_entries().flat_map(|entry| &entry.states) {
        for &target in &state.links {
            total += 1;
            match model.resolve(target) {
                LinkResolution::Unique(_) => resolved += 1,
                LinkResolution::Ambiguous(_) => ambiguous += 1,
                LinkResolution::Missing => missing += 1,
            }
        }
    }
    (total, resolved, ambiguous, missing)
}

fn cmd_health(model: &GaugeModel) {
    let states = model.state_count();
    let forks = model
        .active_entries()
        .filter(|entry| entry.states.len() > 1)
        .count();
    let unanimous_orphans = model
        .active_entries()
        .filter(|entry| entry.states.iter().all(|state| state.links.is_empty()))
        .count();
    let mixed_orphans = model
        .active_entries()
        .filter(|entry| {
            entry.states.iter().any(|state| state.links.is_empty())
                && entry.states.iter().any(|state| !state.links.is_empty())
        })
        .count();
    let (links, resolved, ambiguous, missing) = link_census(model);

    println!("=== GAUGE: Research Health ===\n");
    println!("Logical entries:       {}", model.active_count());
    println!("Current states:        {states}");
    println!("Forked entries:        {forks}");
    println!("Outgoing references:   {links}");
    println!("  resolved uniquely:   {resolved}");
    println!("  ambiguous selector:  {ambiguous}");
    println!("  unresolved selector: {missing}");
    println!(
        "Unanimous orphans:     {unanimous_orphans} ({:.0}% of entries)",
        fraction(unanimous_orphans, model.active_count())
    );
    println!("Mixed orphan forks:    {mixed_orphans}");
}

fn tag_counts(model: &GaugeModel) -> BTreeMap<String, (usize, usize)> {
    let mut counts = BTreeMap::new();
    for entry in model.active_entries() {
        let mut entry_tags = BTreeSet::new();
        for state in &entry.states {
            for tag in &state.tags {
                counts.entry(tag.clone()).or_insert((0, 0)).0 += 1;
                entry_tags.insert(tag.clone());
            }
        }
        for tag in entry_tags {
            counts.entry(tag).or_insert((0, 0)).1 += 1;
        }
    }
    counts
}

fn cmd_tags(model: &GaugeModel) {
    let mut rows: Vec<_> = tag_counts(model).into_iter().collect();
    rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    println!("=== GAUGE: Current Tag Evidence ===\n");
    println!("{:<27} {:>8} {:>8}", "tag", "states", "entries");
    for (tag, (states, entries)) in rows {
        println!("{tag:<27} {states:>8} {entries:>8}");
    }
}

fn cmd_quality(model: &GaugeModel) {
    println!("=== GAUGE: Published / Refuted Frontier States ===\n");
    let mut count = 0;
    for entry in model.active_entries() {
        for state in &entry.states {
            let statuses: Vec<&str> = ["published", "refuted"]
                .into_iter()
                .filter(|tag| state.tags.contains(*tag))
                .collect();
            if statuses.is_empty() {
                continue;
            }
            count += 1;
            let fork = if entry.states.len() > 1 {
                " [fork]"
            } else {
                ""
            };
            println!(
                "[{}] {} — revision {:x}{fork}",
                statuses.join(", "),
                short(&state.title, 65),
                state.revision
            );
        }
    }
    if count == 0 {
        println!("No current frontier state is tagged published or refuted.");
    }
}

fn cmd_hubs(model: &GaugeModel, top: usize) {
    let mut incoming = vec![0usize; model.entries.len()];
    let mut ambiguous = 0;
    let mut missing = 0;
    for state in model.active_entries().flat_map(|entry| &entry.states) {
        for &target in &state.links {
            match model.resolve(target) {
                LinkResolution::Unique(entry) => incoming[entry] += 1,
                LinkResolution::Ambiguous(_) => ambiguous += 1,
                LinkResolution::Missing => missing += 1,
            }
        }
    }
    let mut rows: Vec<_> = incoming.into_iter().enumerate().collect();
    rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    println!("=== GAUGE: Knowledge Hubs ===\n");
    for (index, count) in rows
        .into_iter()
        .filter(|(index, count)| model.entries[*index].active && *count > 0)
        .take(top)
    {
        println!(
            "{count:>4} <- {} [wiki:{:x}]",
            short(&model.entries[index].title(), 65),
            model.entries[index].label
        );
    }
    println!("\nExcluded ambiguous references: {ambiguous}");
    println!("Excluded unresolved references: {missing}");
}

fn cmd_risk(model: &GaugeModel) {
    let flagged: BTreeSet<usize> = model
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            entry.active
                && entry.states.iter().any(|state| {
                    state.tags.contains("refuted") || state.tags.contains("audit-warning")
                })
        })
        .map(|(index, _)| index)
        .collect();
    println!("=== GAUGE: Risk Scan ===\n");
    if flagged.is_empty() {
        println!("No current entry frontier contains refuted or audit-warning evidence.");
        return;
    }

    for (index, entry) in model
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.active)
    {
        if flagged.contains(&index) {
            continue;
        }
        let mut risks = BTreeSet::new();
        for state in &entry.states {
            for &target in &state.links {
                match model.resolve(target) {
                    LinkResolution::Unique(target) if flagged.contains(&target) => {
                        risks.insert(format!(
                            "wiki:{:x} {}",
                            model.entries[target].label,
                            short(&model.entries[target].title(), 45)
                        ));
                    }
                    LinkResolution::Ambiguous(candidates)
                        if candidates
                            .iter()
                            .any(|candidate| flagged.contains(candidate)) =>
                    {
                        let choices = candidates
                            .into_iter()
                            .map(|candidate| format!("wiki:{:x}", model.entries[candidate].label))
                            .collect::<Vec<_>>()
                            .join(", ");
                        risks.insert(format!(
                            "ambiguous selector wiki:{target:x}; candidates: {choices}"
                        ));
                    }
                    _ => {}
                }
            }
        }
        if !risks.is_empty() {
            println!("{} [wiki:{:x}]", short(&entry.title(), 65), entry.label);
            for risk in risks {
                println!("  cites -> {risk}");
            }
        }
    }
}

fn cmd_orphans(model: &GaugeModel, top: usize, ids: bool) {
    let mut rows: Vec<&FrontierEntry> = model
        .active_entries()
        .filter(|entry| entry.states.iter().all(|state| state.links.is_empty()))
        .collect();
    rows.sort_by_key(|entry| (entry.title().to_lowercase(), entry.label));
    if ids {
        for entry in rows.into_iter().take(top) {
            println!("{:x}", entry.label);
        }
        return;
    }
    println!("=== GAUGE: Unanimous Orphan Entries ===\n");
    println!(
        "{} / {} entries have no outgoing link in any current state\n",
        rows.len(),
        model.active_count()
    );
    for entry in rows.into_iter().take(top) {
        let fork = if entry.states.len() > 1 {
            " [fork]"
        } else {
            ""
        };
        println!(
            "{} [wiki:{:x}]{fork}",
            short(&entry.title(), 65),
            entry.label
        );
    }
}

fn with_model<T>(
    pile_path: &Path,
    key_path: Option<&Path>,
    operation: impl FnOnce(&GaugeModel) -> Result<T>,
) -> Result<T> {
    let signer = load_signer(pile_path, key_path)?;
    let mut pile = open_pile_strict(pile_path)?;
    let result = (|| {
        let snapshot = wiki_model::materialize_indexed_collection(&mut pile, &signer)
            .context("materialize indexed Wiki collection")?;
        let model = GaugeModel::load(snapshot.catalog(), snapshot.reader(), snapshot.facts())?;
        operation(&model)
    })();
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context("close Gauge pile")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing Gauge pile also failed: {close_error}")))
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    };

    with_model(&cli.pile, cli.key.as_deref(), |model| {
        match command {
            Command::Health => cmd_health(model),
            Command::Tags => cmd_tags(model),
            Command::Quality => cmd_quality(model),
            Command::Hubs { top } => cmd_hubs(model, top),
            Command::Risk => cmd_risk(model),
            Command::Orphans { top, ids } => cmd_orphans(model, top, ids),
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    use faculties::schemas::wiki::TAG_ARCHIVED_ID;
    use faculties::storage::initialize_signer;
    use faculties::wiki::{author_record, revision_record, tag_record, RevisionDraft};
    use hifitime::Epoch;
    use triblespace::core::collection::CollectionStoreExt;
    use triblespace::prelude::*;

    struct Fixture {
        _directory: tempfile::TempDir,
        pile: PathBuf,
        key: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let pile = directory.path().join("gauge.pile");
            let key = directory.path().join("gauge.key");
            File::create(&pile).unwrap();
            initialize_signer(&pile, Some(&key)).unwrap();
            Self {
                _directory: directory,
                pile,
                key,
            }
        }

        fn publish(&self, fragment: Fragment) {
            let signer = load_signer(&self.pile, Some(&self.key)).unwrap();
            let mut pile = open_pile_strict(&self.pile).unwrap();
            let collection = faculties::collection_names::open(
                &mut pile,
                faculties::schemas::wiki::DEFAULT_SCOPE_ID,
                signer.verifying_key(),
            )
            .unwrap();
            pile.commit(collection, &signer, fragment).unwrap();
            pile.close().unwrap();
        }

        fn with_model(&self, operation: impl FnOnce(&GaugeModel)) {
            super::with_model(&self.pile, Some(&self.key), |model| {
                operation(model);
                Ok(())
            })
            .unwrap();
        }
    }

    fn authored_at(seconds: f64) -> Inline<inlineencodings::NsTAIInterval> {
        let epoch = Epoch::from_tai_seconds(seconds);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn revision(
        author: Id,
        title: &str,
        content: &str,
        tags: BTreeSet<Id>,
        predecessors: BTreeSet<Id>,
    ) -> (Fragment, Id) {
        revision_record(RevisionDraft {
            title: title.to_owned(),
            content: content.to_owned(),
            tags,
            predecessors,
            author,
            authored_at: authored_at(1.0),
        })
        .unwrap()
    }

    #[test]
    fn model_keeps_forks_and_resolves_every_revision_to_the_entry() {
        let fixture = Fixture::new();
        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let (author_fragment, author) = author_record(&signer.verifying_key());
        let (tag, published, _) = tag_record("published").unwrap();
        let (root_fragment, root) =
            revision(author, "root", "root", BTreeSet::new(), BTreeSet::new());
        let (left_fragment, left) = revision(
            author,
            "fork",
            "#link(\"wiki:11111111111111111111111111111111\")[x]",
            BTreeSet::from([published]),
            BTreeSet::from([root]),
        );
        let (right_fragment, right) = revision(
            author,
            "fork",
            "#link(\"wiki:11111111111111111111111111111111\")[x]",
            BTreeSet::new(),
            BTreeSet::from([root]),
        );
        fixture.publish(author_fragment + tag + root_fragment + left_fragment + right_fragment);

        fixture.with_model(|model| {
            assert_eq!(model.entries.len(), 1);
            assert_eq!(model.entries[0].states.len(), 2);
            assert_eq!(model.resolve(root), LinkResolution::Unique(0));
            assert_eq!(model.resolve(left), LinkResolution::Unique(0));
            assert_eq!(model.resolve(right), LinkResolution::Unique(0));
            assert!(model.entries[0]
                .states
                .iter()
                .any(|state| state.tags.contains("published")));
        });
    }

    #[test]
    fn archived_only_entries_are_not_gauged() {
        let fixture = Fixture::new();
        let signer = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let (author_fragment, author) = author_record(&signer.verifying_key());
        let (tag, _, _) = tag_record("archived").unwrap();
        let (revision, _) = revision(
            author,
            "retired",
            "body",
            BTreeSet::from([TAG_ARCHIVED_ID]),
            BTreeSet::new(),
        );
        fixture.publish(author_fragment + tag + revision);
        fixture.with_model(|model| {
            assert_eq!(
                model.entries.len(),
                1,
                "selector resolution retains history"
            );
            assert_eq!(
                model.active_count(),
                0,
                "metrics hide archived-only entries"
            );
        });
    }
}
