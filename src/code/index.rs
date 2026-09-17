//! The lexical tier: two stock BM25 derivations, and the capability question.
//!
//! There is deliberately no new `CollectionMapping` here. `triblespace-search`
//! already publishes `TextAttributeToBm25`, whose descriptor carries the
//! selected attribute and the tokenizer as facts, so `trible pile collection
//! search` can query either of these indexes from the command line with no code
//! at all. Writing a bespoke mapping would mint an algorithm id for a law that
//! already exists — `archive_bm25.rs` is a reference for house style here, not
//! something to copy.
//!
//! Two indexes, `or!`-joined at query time:
//!
//! - over `attrs::doc` — the prose a person wrote about the code. This is the
//!   tier that answers "do we already have X", because a capability is
//!   described in prose and not spelled in the identifiers.
//! - over `attrs::source_tokens` — the code itself, for when the prose is
//!   absent, which for a function in this corpus is the median case.
//!
//! **`find`, `uses` and `show` never touch BM25.** A lexical index cannot
//! represent absence: `code_tokens` shatters `LearnerBuilder` into common words
//! and returns confident hits from a corpus containing none. Absence is an empty
//! `find!`, and an empty `find!` IS the answer.
//!
//! Maintenance is a separate verb. `code ingest` never maintains an index and
//! neither does a read; `code index` does, once, explicitly. Correctness does
//! not depend on it — a union archive answers `pattern!` without the
//! acceleration — only speed does. A collection this size that re-indexed itself
//! on every read would make `code find` cost what an `orient wake` costs.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, Context, Result};
use triblespace::core::collection::{Collection, CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::inline::TryFromInline;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::blobencodings::SimpleArchive;
use triblespace::prelude::*;
use triblespace_search::portable_bm25::{PortableBM25Blob, PortableBM25View};
use triblespace_search::text_bm25::{Bm25Tokenizer, TextAttributeToBm25};
use triblespace_search::tokens::{code_tokens, WordHash};

use crate::code::operations::{
    hit, keeps, placements_of_item, provenance, select_scans, Code, Filter, Hit, Provenance, Texts,
};
use crate::collection_names::{open_configured, private_policy};
use crate::schemas::code::{attrs, DEFAULT_SCOPE_ID};
use crate::storage::FactArchive;

type CodeBM25View = PortableBM25View<inlineencodings::GenId, WordHash>;

/// Which text an index covers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tier {
    /// Prose: doc comments, banner comments, module docs, and whole prose files.
    Docs,
    /// The normalized token stream of every declaration.
    Text,
    Both,
}

impl Tier {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "docs" => Some(Self::Docs),
            "text" => Some(Self::Text),
            "both" => Some(Self::Both),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IndexReport {
    pub doc_documents: usize,
    pub text_documents: usize,
    pub source_elements: usize,
}

/// One file's worth of hits, ranked as a group.
#[derive(Clone, Debug)]
pub struct SearchGroup {
    pub repo: String,
    pub path: String,
    pub score: f32,
    /// The rarest `use` roots in this file, by corpus frequency.
    ///
    /// Derived, never a hardcoded vocabulary of "GPU things": the evidence line
    /// is whatever this file imports that almost nothing else does, which is
    /// what distinguishes a `cubecl` kernel file from a simulated-annealing one
    /// in a single glance.
    pub distinguishing: Vec<String>,
    /// `shares N/M distinguishing imports with #1`, for every group below the
    /// first.
    pub shared_with_top: Option<(usize, usize)>,
    pub members: Vec<Hit>,
}

#[derive(Clone, Debug, Default)]
pub struct SearchReport {
    pub query: String,
    pub groups: Vec<SearchGroup>,
    pub provenance: Provenance,
    /// Set when the BM25 cover is behind the facts, naming the verb that fixes
    /// it — the way `trible pile collection search` already does.
    pub stale: Option<String>,
}

/// How many members of one group are printed before the rest are counted.
const MAX_GROUP_MEMBERS: usize = 4;
/// How many distinguishing imports form the evidence line.
const DISTINGUISHING: usize = 3;
/// Import roots every file has; they distinguish nothing.
const UBIQUITOUS: &[&str] = &["std", "crate", "super", "self", "core", "alloc"];

fn register(
    pile: &mut triblespace::core::repo::pile::Pile,
    source: Collection<SimpleArchive>,
    attribute: Id,
    authority: ed25519_dalek::VerifyingKey,
) -> Result<Collection<PortableBM25Blob>> {
    pile.derive::<PortableBM25Blob>(
        source,
        TextAttributeToBm25 {
            attribute,
            tokenizer: Bm25Tokenizer::Code,
        },
        private_policy(authority),
    )
    .context("register Code BM25 derivation")
}

impl Code {
    /// Build or refresh both lexical covers. The only verb that maintains.
    pub fn index(&self) -> Result<IndexReport> {
        self.storage().with_pile(|pile, signer| {
            pollster::block_on(async {
                let source = open_configured(pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
                drop(
                    pile.ensure(source, signer)
                        .await
                        .context("ensure Code source dependencies")?,
                );
                let doc_target = register(pile, source, attrs::doc.id(), signer.verifying_key())?;
                let text_target = register(
                    pile,
                    source,
                    attrs::source_tokens.id(),
                    signer.verifying_key(),
                )?;

                let after = pile
                    .maintain(doc_target, signer)
                    .await
                    .context("maintain Code prose BM25 cover")?;
                let doc_documents = match after.collection(doc_target) {
                    Ok(attached) => attached
                        .view::<CodeBM25View>()
                        .map(|view| view.segments().iter().map(|index| index.doc_count()).sum())
                        .unwrap_or(0),
                    // A cover that has never been maintained is not an error.
                    Err(_) => 0,
                };

                let after = pile
                    .maintain(text_target, signer)
                    .await
                    .context("maintain Code token BM25 cover")?;
                let text_documents = match after.collection(text_target) {
                    Ok(attached) => attached
                        .view::<CodeBM25View>()
                        .map(|view| view.segments().iter().map(|index| index.doc_count()).sum())
                        .unwrap_or(0),
                    // A cover that has never been maintained is not an error.
                    Err(_) => 0,
                };

                let source_elements = match after.collection(source) {
                    Ok(attached) => attached.support().map(|support| support.len()).unwrap_or(0),
                    Err(_) => 0,
                };

                Ok(IndexReport {
                    doc_documents,
                    text_documents,
                    source_elements,
                })
            })
        })
    }

    /// The capability question: what do we already have that does X?
    ///
    /// Ranked by file rather than by declaration, because the answer to "do we
    /// have a GPU graph layout" is a FILE, and BM25's length normalization
    /// otherwise lets a tiny file outrank the one that actually holds the
    /// kernels. Group score is the sum of its members'; the evidence line is
    /// derived rarity, not a vocabulary.
    pub fn search(
        &self,
        query: &str,
        tier: Tier,
        top: usize,
        filter: &Filter,
    ) -> Result<SearchReport> {
        let scores = self.bm25_scores(query, tier)?;
        let observed = crate::code::ingest::ensure_local_with_storage(self.storage())?;
        let facts = observed.view::<FactArchive>().context("read Code facts")?;
        let reader = observed.snapshot();
        let mut texts = Texts::new(reader);
        let scans = select_scans(&facts, &mut texts, filter)?;

        let mut report = SearchReport {
            query: query.to_owned(),
            provenance: provenance(&facts, &scans),
            ..SearchReport::default()
        };
        if scores.is_empty() {
            report.stale = Some(
                "no lexical cover answered this query. If the catalogue holds facts, its BM25 \
cover is behind them: run `code index`."
                    .to_owned(),
            );
            return Ok(report);
        }

        let mut ranked: Vec<(Id, f32)> = scores.into_iter().collect();
        ranked.sort_by(|left, right| {
            right
                .1
                .partial_cmp(&left.1)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        ranked.truncate(top.saturating_mul(12).max(60));

        // Turn scored entities into located declarations, then group by file.
        // A scored entity that is a unit rather than an item contributes its
        // score to that file's group without a member line: the prose it
        // matched is the module's, not any one declaration's.
        let mut groups: BTreeMap<(String, String), (f32, Vec<Hit>)> = BTreeMap::new();
        for (entity, score) in ranked {
            let mut placed = false;
            for scan in &scans {
                for located in placements_of_item(&facts, scan.id, entity) {
                    let hit = hit(&facts, &mut texts, scan, located)?;
                    if !keeps(&hit, filter) {
                        continue;
                    }
                    placed = true;
                    let entry = groups
                        .entry((hit.repo.clone(), hit.path.clone()))
                        .or_insert_with(|| (0.0, Vec::new()));
                    entry.0 += score;
                    entry.1.push(hit);
                }
            }
            if placed {
                continue;
            }
            for (repo, path) in crate::code::unit_location(&facts, entity) {
                let repo = texts.get(repo)?;
                let path = texts.get(path)?;
                if filter.repo.as_deref().is_some_and(|wanted| wanted != repo) {
                    continue;
                }
                let entry = groups
                    .entry((repo, path))
                    .or_insert_with(|| (0.0, Vec::new()));
                entry.0 += score;
            }
        }

        let mut ordered: Vec<SearchGroup> = groups
            .into_iter()
            .map(|((repo, path), (score, mut members))| {
                members.sort_by(|left, right| {
                    right
                        .doc
                        .is_some()
                        .cmp(&left.doc.is_some())
                        .then(left.line.cmp(&right.line))
                });
                members.dedup_by(|left, right| left.line == right.line && left.name == right.name);
                SearchGroup {
                    repo,
                    path,
                    score,
                    distinguishing: Vec::new(),
                    shared_with_top: None,
                    members,
                }
            })
            .collect();
        ordered.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        ordered.truncate(top);

        attach_evidence(&facts, reader, &mut ordered);
        for group in &mut ordered {
            group.members.truncate(MAX_GROUP_MEMBERS);
        }
        report.groups = ordered;
        Ok(report)
    }
}

impl Code {
    fn bm25_scores(&self, query: &str, tier: Tier) -> Result<BTreeMap<Id, f32>> {
        let terms = code_tokens(query);
        self.storage().with_pile(|pile, signer| {
            let source = open_configured(pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
            let doc_target = register(pile, source, attrs::doc.id(), signer.verifying_key())?;
            let text_target = register(
                pile,
                source,
                attrs::source_tokens.id(),
                signer.verifying_key(),
            )?;
            let snapshot = pile.snapshot().context("freeze Code search snapshot")?;

            let mut scores: BTreeMap<Id, f32> = BTreeMap::new();
            let accumulate = |target: Collection<PortableBM25Blob>,
                              weight: f32,
                              scores: &mut BTreeMap<Id, f32>|
             -> Result<()> {
                let Ok(attached) = snapshot.collection(target) else {
                    // A cover that has never been maintained is not an error; it
                    // is a cover that is behind, and the caller is told so.
                    return Ok(());
                };
                let Ok(view) = attached.view::<CodeBM25View>() else {
                    return Ok(());
                };
                let query = view.query().context("prepare Code BM25 query")?;
                for (document, score) in query.query_multi(&terms) {
                    let id = Id::try_from_inline(&document).map_err(|error| {
                        anyhow!("Code BM25 document is not an entity id: {error:?}")
                    })?;
                    *scores.entry(id).or_insert(0.0) += score * weight;
                }
                Ok(())
            };

            if matches!(tier, Tier::Docs | Tier::Both) {
                accumulate(doc_target, 1.0, &mut scores)?;
            }
            if matches!(tier, Tier::Text | Tier::Both) {
                // Prose is what answers a capability question; the token stream
                // is the fallback for the median function, which has no prose at
                // all. Weighting them equally would let a long body outvote the
                // sentence that says what the file is for.
                accumulate(text_target, 0.5, &mut scores)?;
            }
            Ok(scores)
        })
    }
}

/// The rarest import roots of each group's file, and the overlap with the
/// top-ranked group's.
///
/// One counting query per candidate root — a few dozen per invocation, each a
/// constant-folded index range — and nothing is retained between them. Building
/// a corpus-wide frequency table once, at startup, would be the very shadow
/// model this faculty exists to avoid.
///
/// There is no vocabulary of "GPU things" anywhere in this code. The evidence
/// line is whatever a file imports that almost nothing else does, which is
/// exactly what separates a `cubecl` kernel file from a simulated-annealing one
/// at a glance.
fn attach_evidence(
    facts: &FactArchive,
    reader: &triblespace::core::repo::pile::PileSnapshot,
    groups: &mut [SearchGroup],
) {
    let mut top: Option<BTreeSet<String>> = None;
    for (rank, group) in groups.iter_mut().enumerate() {
        let units: Vec<Id> = find!(
            unit: Id,
            pattern!(facts, [{ ?unit @
                attrs::repo: crate::code::text_handle(&group.repo),
                attrs::path: crate::code::text_handle(&group.path) }])
        )
        .collect();
        let mut roots: Vec<(usize, String)> = Vec::new();
        for unit in units {
            for handle in crate::code::unit_import_roots(facts, unit) {
                let text: anybytes::View<str> = match reader.get(handle) {
                    Ok(text) => text,
                    Err(_) => continue,
                };
                let text = text.to_string();
                if UBIQUITOUS.contains(&text.as_str()) {
                    continue;
                }
                roots.push((crate::code::import_root_frequency(facts, handle), text));
            }
        }
        roots.sort();
        roots.dedup_by(|left, right| left.1 == right.1);
        group.distinguishing = roots
            .into_iter()
            .take(DISTINGUISHING)
            .map(|(_, root)| root)
            .collect();
        if rank == 0 {
            top = Some(group.distinguishing.iter().cloned().collect());
            continue;
        }
        // A top group with NO distinguishing imports is a real answer — a file
        // that pulls in nothing unusual — but "shares 0/0" compares against
        // nothing, and printing "0/1" to avoid the zero would be inventing a
        // denominator. Say nothing instead.
        if let Some(top) = top.as_ref().filter(|top| !top.is_empty()) {
            let shared = group
                .distinguishing
                .iter()
                .filter(|root| top.contains(*root))
                .count();
            group.shared_with_top = Some((shared, top.len()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tier_name_round_trips() {
        assert_eq!(Tier::from_name("docs"), Some(Tier::Docs));
        assert_eq!(Tier::from_name("text"), Some(Tier::Text));
        assert_eq!(Tier::from_name("both"), Some(Tier::Both));
        assert_eq!(Tier::from_name("semantic"), None);
    }

    #[test]
    fn ubiquitous_roots_cannot_distinguish_anything() {
        for root in ["std", "crate", "super", "self"] {
            assert!(UBIQUITOUS.contains(&root));
        }
        assert!(!UBIQUITOUS.contains(&"cubecl"));
    }
}
