//! Research-quality observations over Wiki's canonical, fork-visible frontier.
pub mod cli;
pub mod mcp;
pub mod presentation;

use crate::storage::{load_signer, open_pile_strict};
use crate::wiki::{self as wiki_model, FrontierModel, LinkResolution};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use triblespace::prelude::Id;

type GaugeModel = FrontierModel;

#[derive(Clone, Debug)]
pub struct Gauge {
    pile: PathBuf,
    key: Option<PathBuf>,
}
impl Gauge {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self { pile, key }
    }
    pub fn health(&self) -> Result<Health> {
        with_model(&self.pile, self.key.as_deref(), |model| Ok(health(model)))
    }
    pub fn tags(&self) -> Result<Vec<TagCount>> {
        with_model(&self.pile, self.key.as_deref(), |model| Ok(tags(model)))
    }
    pub fn quality(&self) -> Result<Vec<QualityState>> {
        with_model(&self.pile, self.key.as_deref(), |model| Ok(quality(model)))
    }
    pub fn hubs(&self, top: usize) -> Result<Hubs> {
        with_model(&self.pile, self.key.as_deref(), |model| {
            Ok(hubs(model, top))
        })
    }
    pub fn risk(&self) -> Result<RiskReport> {
        with_model(&self.pile, self.key.as_deref(), |model| Ok(risk(model)))
    }
    pub fn orphans(&self, top: usize) -> Result<Orphans> {
        with_model(&self.pile, self.key.as_deref(), |model| {
            Ok(orphans(model, top))
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkCensus {
    pub total: usize,
    pub unique: usize,
    pub ambiguous: usize,
    pub missing: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Health {
    pub entries: usize,
    pub states: usize,
    pub forks: usize,
    pub links: LinkCensus,
    pub unanimous_orphans: usize,
    pub mixed_orphans: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagCount {
    pub tag: String,
    pub states: usize,
    pub entries: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QualityState {
    pub statuses: Vec<String>,
    pub title: String,
    pub revision: Id,
    pub fork: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub id: Id,
    pub title: String,
    pub fork: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hub {
    pub entry: Entry,
    pub incoming: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hubs {
    pub rows: Vec<Hub>,
    pub ambiguous: usize,
    pub missing: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RiskReference {
    Unique(Entry),
    Ambiguous { selector: Id, candidates: Vec<Id> },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Risk {
    pub entry: Entry,
    pub references: Vec<RiskReference>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RiskReport {
    pub flagged: usize,
    pub rows: Vec<Risk>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Orphans {
    pub total: usize,
    pub entries: usize,
    pub rows: Vec<Entry>,
}

fn entry(row: &crate::wiki::FrontierEntry) -> Entry {
    Entry {
        id: row.label,
        title: row.title(),
        fork: row.states.len() > 1,
    }
}

pub fn health(model: &FrontierModel) -> Health {
    let mut links = LinkCensus::default();
    for state in model.active_entries().flat_map(|entry| &entry.states) {
        for &target in &state.links {
            links.total += 1;
            match model.resolve(target) {
                LinkResolution::Unique(_) => links.unique += 1,
                LinkResolution::Ambiguous(_) => links.ambiguous += 1,
                LinkResolution::Missing => links.missing += 1,
            }
        }
    }
    Health {
        entries: model.active_count(),
        states: model.state_count(),
        forks: model
            .active_entries()
            .filter(|entry| entry.states.len() > 1)
            .count(),
        links,
        unanimous_orphans: model
            .active_entries()
            .filter(|entry| entry.states.iter().all(|state| state.links.is_empty()))
            .count(),
        mixed_orphans: model
            .active_entries()
            .filter(|entry| {
                entry.states.iter().any(|state| state.links.is_empty())
                    && entry.states.iter().any(|state| !state.links.is_empty())
            })
            .count(),
    }
}
pub fn tags(model: &FrontierModel) -> Vec<TagCount> {
    let mut counts: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for entry in model.active_entries() {
        let mut entry_tags = BTreeSet::new();
        for state in &entry.states {
            for tag in &state.tags {
                counts.entry(tag.clone()).or_default().0 += 1;
                entry_tags.insert(tag.clone());
            }
        }
        for tag in entry_tags {
            counts.entry(tag).or_default().1 += 1;
        }
    }
    let mut rows: Vec<_> = counts.into_iter().collect();
    rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    rows.into_iter()
        .map(|(tag, (states, entries))| TagCount {
            tag,
            states,
            entries,
        })
        .collect()
}
pub fn quality(model: &FrontierModel) -> Vec<QualityState> {
    let mut rows = Vec::new();
    for entry in model.active_entries() {
        for state in &entry.states {
            let statuses: Vec<_> = ["published", "refuted"]
                .into_iter()
                .filter(|tag| state.tags.contains(*tag))
                .map(str::to_owned)
                .collect();
            if !statuses.is_empty() {
                rows.push(QualityState {
                    statuses,
                    title: state.title.clone(),
                    revision: state.revision,
                    fork: entry.states.len() > 1,
                });
            }
        }
    }
    rows
}
pub fn hubs(model: &FrontierModel, top: usize) -> Hubs {
    let mut incoming = vec![0usize; model.entries.len()];
    let mut report = Hubs {
        rows: Vec::new(),
        ambiguous: 0,
        missing: 0,
    };
    for state in model.active_entries().flat_map(|entry| &entry.states) {
        for &target in &state.links {
            match model.resolve(target) {
                LinkResolution::Unique(entry) => incoming[entry] += 1,
                LinkResolution::Ambiguous(_) => report.ambiguous += 1,
                LinkResolution::Missing => report.missing += 1,
            }
        }
    }
    let mut rows: Vec<_> = incoming.into_iter().enumerate().collect();
    rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    report.rows = rows
        .into_iter()
        .filter(|(index, count)| model.entries[*index].active && *count > 0)
        .take(top)
        .map(|(index, incoming)| Hub {
            entry: entry(&model.entries[index]),
            incoming,
        })
        .collect();
    report
}
pub fn risk(model: &FrontierModel) -> RiskReport {
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
    let mut rows = Vec::new();
    for (index, row) in model
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.active)
    {
        if flagged.contains(&index) {
            continue;
        }
        let mut unique = BTreeSet::new();
        let mut ambiguous = BTreeMap::new();
        for state in &row.states {
            for &target in &state.links {
                match model.resolve(target) {
                    LinkResolution::Unique(target) if flagged.contains(&target) => {
                        unique.insert(target);
                    }
                    LinkResolution::Ambiguous(candidates)
                        if candidates
                            .iter()
                            .any(|candidate| flagged.contains(candidate)) =>
                    {
                        ambiguous.insert(
                            target,
                            candidates
                                .into_iter()
                                .map(|candidate| model.entries[candidate].label)
                                .collect(),
                        );
                    }
                    _ => {}
                }
            }
        }
        let references: Vec<_> =
            unique
                .into_iter()
                .map(|index| RiskReference::Unique(entry(&model.entries[index])))
                .chain(ambiguous.into_iter().map(|(selector, candidates)| {
                    RiskReference::Ambiguous {
                        selector,
                        candidates,
                    }
                }))
                .collect();
        if !references.is_empty() {
            rows.push(Risk {
                entry: entry(row),
                references,
            });
        }
    }
    RiskReport {
        flagged: flagged.len(),
        rows,
    }
}
pub fn orphans(model: &FrontierModel, top: usize) -> Orphans {
    let mut rows: Vec<_> = model
        .active_entries()
        .filter(|entry| entry.states.iter().all(|state| state.links.is_empty()))
        .map(entry)
        .collect();
    rows.sort_by_key(|entry| (entry.title.to_lowercase(), entry.id));
    let total = rows.len();
    rows.truncate(top);
    Orphans {
        total,
        entries: model.active_count(),
        rows,
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
        let snapshot = pollster::block_on(wiki_model::query_snapshot(&mut pile, &signer))
            .context("query maintained Wiki collection")?;
        let model = GaugeModel::load(
            snapshot.store_snapshot(),
            snapshot.facts(),
            snapshot.latest(),
        )?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    use crate::schemas::wiki::TAG_ARCHIVED_ID;
    use crate::storage::initialize_signer;
    use crate::wiki::{author_record, revision_record, tag_record, RevisionDraft};
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
            let collection = crate::collection_names::open(
                &mut pile,
                crate::schemas::wiki::DEFAULT_SCOPE_ID,
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
