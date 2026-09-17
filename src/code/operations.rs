//! The Code faculty's Rust API: no argv, no transport.
//!
//! Every read here ends by reporting the revisions it read at. Absence is only
//! meaningful with its denominator, and a tool that says "absent" without
//! saying absent *from what* is how the fourth wrong absence claim gets made.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use hifitime::Epoch;
use triblespace::core::blob::encodings::succinctarchive::Rank9AcceleratedSuccinctArchiveBlob;
use triblespace::core::collection::CollectionSnapshot;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::core::repo::BlobStoreGet;
#[allow(unused_imports)]
use triblespace::prelude::blobencodings::RawBytes;
#[allow(unused_imports)]
use triblespace::prelude::blobencodings::UTF8String;
use triblespace::prelude::*;

use crate::code::{self, extract, git, ingest, TextHandle};
use crate::schemas::code::{ItemKind, Language, EXTRACTOR_RUST_SYN_V1_NAME};
use crate::storage::{FactArchive, Storage};

/// Largest file this build will hold in a unit's content blob.
///
/// A generated or vendored monster in a tracked path would otherwise put tens
/// of megabytes into the pile for a file nobody will ever read here. Skipping it
/// is reported, not silent.
const MAX_UNIT_BYTES: usize = 4 * 1024 * 1024;

/// Flush a repository's staged delta if it grows past this, so one enormous
/// repository does not hold a million facts resident before its single commit.
const MAX_STAGED_FACTS: usize = 400_000;

pub struct Code {
    storage: Storage,
}

// ── shared result shapes ────────────────────────────────────────────────

/// One scan, resolved to text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanSummary {
    pub id: Id,
    pub repo: String,
    pub commit: String,
    pub observed_at: Epoch,
}

impl ScanSummary {
    /// `faculties@336a8765`, the way a footer names a revision.
    pub fn label(&self) -> String {
        let commit = if self.commit.starts_with("worktree:") {
            "worktree".to_owned()
        } else {
            self.commit.chars().take(8).collect()
        };
        format!("{}@{}", self.repo, commit)
    }
}

/// What every answer carries so it can be believed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Provenance {
    pub scans: Vec<ScanSummary>,
    pub units: usize,
    pub placements: usize,
    pub extractor: String,
}

/// One located declaration, as a reader sees it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hit {
    pub item: Id,
    pub unit: Id,
    pub repo: String,
    pub path: String,
    pub line: u64,
    pub end_line: u64,
    pub kind: Option<String>,
    pub visibility: Option<String>,
    pub name: Option<String>,
    pub signature: Option<String>,
    pub doc: Option<String>,
    pub scan: String,
}

impl Hit {
    pub fn location(&self) -> String {
        format!("{}/{}:{}", self.repo, self.path, self.line)
    }
}

/// An answer to a question about one identifier.
#[derive(Clone, Debug, Default)]
pub struct Answer {
    pub subject: String,
    pub hits: Vec<Hit>,
    /// Name-similar declarations. Explicitly NOT answers; printed below the
    /// verdict and labelled, because a list of near-misses presented as results
    /// is exactly how an absence gets misread as a presence.
    pub near: Vec<Hit>,
    pub caveat: Option<String>,
    pub followup: Option<String>,
    pub provenance: Provenance,
}

/// What one ingest run did to one repository.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RepoIngest {
    pub repo: String,
    pub commit: String,
    pub files_seen: usize,
    pub files_parsed: usize,
    pub files_skipped: usize,
    pub parse_failures: usize,
    pub items: usize,
    pub commits: usize,
}

#[derive(Clone, Debug, Default)]
pub struct IngestReport {
    pub repos: Vec<RepoIngest>,
    pub dry_run: bool,
}

/// Per-repository counts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StatsRow {
    pub scan: String,
    pub units: usize,
    pub placements: usize,
    pub parse_failures: usize,
    pub kinds: Vec<(String, usize)>,
}

#[derive(Clone, Debug, Default)]
pub struct StatsReport {
    pub rows: Vec<StatsRow>,
    pub provenance: Provenance,
}

/// One item placed in more than one location.
#[derive(Clone, Debug)]
pub struct DuplicateGroup {
    pub item: Id,
    pub name: Option<String>,
    pub kind: Option<String>,
    pub lines: u64,
    pub places: Vec<Hit>,
}

#[derive(Clone, Debug, Default)]
pub struct DuplicateReport {
    pub groups: Vec<DuplicateGroup>,
    pub provenance: Provenance,
}

/// What `code show` found.
#[derive(Clone, Debug)]
pub struct ItemDetail {
    pub hit: Hit,
    pub places: Vec<Hit>,
    pub source: Option<String>,
    pub provenance: Provenance,
}

/// One commit a pickaxe search attributes a change to.
#[derive(Clone, Debug)]
pub struct BlameRow {
    pub repo: String,
    pub commit: String,
    pub date: String,
    pub subject: String,
    pub paths: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct BlameReport {
    pub identifier: String,
    pub rows: Vec<BlameRow>,
    pub searched: Vec<String>,
}

/// How a caller selected the revisions to answer at.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Revision {
    /// The newest scan of each repository.
    #[default]
    Latest,
    /// Every scan of an uncommitted working tree.
    Worktree,
    /// `<repo>@<commit prefix>`, `<repo>@worktree`, or a bare commit prefix.
    Selector(String),
}

impl Revision {
    pub fn parse(raw: Option<&str>) -> Self {
        match raw.map(str::trim) {
            None | Some("") => Self::Latest,
            Some("worktree") => Self::Worktree,
            Some(selector) => Self::Selector(selector.to_owned()),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Filter {
    pub kind: Option<String>,
    pub repo: Option<String>,
    pub revision: Revision,
}

#[derive(Clone, Debug, Default)]
pub struct IngestOptions {
    /// Ingest one named revision from git objects instead of the working tree.
    pub commit: Option<String>,
    pub dry_run: bool,
}

// ── reading ─────────────────────────────────────────────────────────────

type Observed = CollectionSnapshot<PileSnapshot, Rank9AcceleratedSuccinctArchiveBlob>;

/// A per-invocation memo of blob text.
///
/// This is the blob reader's cache, not a model of the pile's relations: it
/// holds strings keyed by content handle for the length of one command and is
/// dropped with it. Nothing queries it, nothing joins against it, and it never
/// answers a question the pile was not asked.
pub(crate) struct Texts<'a> {
    reader: &'a PileSnapshot,
    seen: HashMap<[u8; 32], String>,
}

impl<'a> Texts<'a> {
    pub(crate) fn new(reader: &'a PileSnapshot) -> Self {
        Self {
            reader,
            seen: HashMap::new(),
        }
    }

    pub(crate) fn get(&mut self, handle: TextHandle) -> Result<String> {
        if let Some(text) = self.seen.get(&handle.raw) {
            return Ok(text.clone());
        }
        let value: View<str> = self
            .reader
            .get(handle)
            .context("read catalogued text from the pile")?;
        let text = value.to_string();
        self.seen.insert(handle.raw, text.clone());
        Ok(text)
    }

    /// The first value, when a relation this reader models happens to hold one.
    /// Absence is ordinary; several values are ordinary too, and neither is an
    /// error, because the schema language cannot express cardinality and
    /// re-imposing it in Rust would be inventing a constraint the substrate
    /// deliberately refuses.
    fn first(&mut self, handles: Vec<TextHandle>) -> Result<Option<String>> {
        let mut texts: Vec<String> = Vec::new();
        for handle in handles {
            texts.push(self.get(handle)?);
        }
        texts.sort();
        Ok(texts.into_iter().next())
    }
}

impl Code {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(Storage::new(pile, key))
    }

    pub fn with_storage(storage: Storage) -> Self {
        Self { storage }
    }

    fn observe(&self) -> Result<Observed> {
        ingest::ensure_local_with_storage(&self.storage)
    }

    // ── ingest ──────────────────────────────────────────────────────────

    /// Catalogue one or more git working copies.
    ///
    /// Git is the walker: ignore rules, submodules, `target*` and the
    /// tracked/untracked split all come from it rather than from a hand-rolled
    /// filesystem walk with an ignore list that would drift.
    pub fn ingest(&self, dirs: &[PathBuf], options: &IngestOptions) -> Result<IngestReport> {
        let mut plans = Vec::new();
        for dir in dirs {
            let dir = dir
                .canonicalize()
                .with_context(|| format!("resolve {}", dir.display()))?;
            if !git::is_repository(&dir) {
                bail!("{} is not a git working copy", dir.display());
            }
            plans.push(plan_repository(&dir, options)?);
        }

        let mut report = IngestReport {
            dry_run: options.dry_run,
            ..IngestReport::default()
        };
        if options.dry_run {
            for plan in &plans {
                report.repos.push(RepoIngest {
                    repo: plan.repo.clone(),
                    commit: plan.commit.clone(),
                    files_seen: plan.sources.len(),
                    files_skipped: plan.skipped,
                    ..RepoIngest::default()
                });
            }
            return Ok(report);
        }

        report.repos = self.storage.with_pile(|pile, signer| {
            let mut writer = pollster::block_on(ingest::CodeImportWriter::from_pile(pile, signer))?;
            let mut rows = Vec::new();
            for plan in plans {
                rows.push(ingest_repository(&mut writer, plan)?);
            }
            // Publish whatever the last repository left staged.
            writer.commit_unit()?;
            Ok(rows)
        })?;
        Ok(report)
    }

    // ── questions ───────────────────────────────────────────────────────

    /// Where is `name` defined — and if nowhere, say so with a denominator.
    pub fn find(&self, name: &str, filter: &Filter) -> Result<Answer> {
        let observed = self.observe()?;
        let facts = observed.view::<FactArchive>().context("read Code facts")?;
        let reader = observed.snapshot();
        let mut texts = Texts::new(reader);
        let scans = select_scans(&facts, &mut texts, filter)?;
        let provenance = provenance(&facts, &scans);

        let handle = code::text_handle(name);
        let mut hits = Vec::new();
        for scan in &scans {
            for located in code::definitions_in_scan(&facts, scan.id, handle) {
                hits.push(hit(&facts, &mut texts, scan, located)?);
            }
        }
        hits.retain(|hit| keeps(hit, filter));
        sort_hits(&mut hits);
        hits.dedup_by(|left, right| left.item == right.item && left.location() == right.location());

        let mut near = Vec::new();
        if hits.is_empty() {
            for candidate in near_miss_candidates(name) {
                let candidate_handle = code::text_handle(&candidate);
                for scan in &scans {
                    for located in code::definitions_in_scan(&facts, scan.id, candidate_handle) {
                        near.push(hit(&facts, &mut texts, scan, located)?);
                    }
                }
            }
            near.retain(|hit| keeps(hit, filter));
            sort_hits(&mut near);
            near.dedup_by(|left, right| left.location() == right.location());
            near.truncate(8);
        }

        Ok(Answer {
            subject: name.to_owned(),
            hits,
            near,
            caveat: None,
            followup: Some(format!(
                "`code blame {name}` searches history for a removal."
            )),
            provenance,
        })
    }

    /// What names `identifier` — definitions included, since a definition names
    /// itself.
    pub fn uses(&self, identifier: &str, filter: &Filter) -> Result<Answer> {
        let observed = self.observe()?;
        let facts = observed.view::<FactArchive>().context("read Code facts")?;
        let reader = observed.snapshot();
        let mut texts = Texts::new(reader);
        let scans = select_scans(&facts, &mut texts, filter)?;
        let provenance = provenance(&facts, &scans);

        let handle = code::text_handle(identifier);
        let mut hits = Vec::new();
        for scan in &scans {
            let located = match filter.kind.as_deref() {
                Some(kind) => code::items_of_kind_mentioning_in_scan(&facts, scan.id, kind, handle),
                None => code::usages_in_scan(&facts, scan.id, handle),
            };
            for located in located {
                hits.push(hit(&facts, &mut texts, scan, located)?);
            }
        }
        hits.retain(|hit| keeps(hit, filter));
        sort_hits(&mut hits);
        hits.dedup_by(|left, right| left.location() == right.location());

        Ok(Answer {
            subject: identifier.to_owned(),
            caveat: spread_caveat(&hits),
            hits,
            near: Vec::new(),
            followup: None,
            provenance,
        })
    }

    /// Which `use` roots appear in the catalogued corpus, and how often.
    pub fn imports(&self, root: &str, filter: &Filter) -> Result<(usize, Provenance)> {
        let observed = self.observe()?;
        let facts = observed.view::<FactArchive>().context("read Code facts")?;
        let reader = observed.snapshot();
        let mut texts = Texts::new(reader);
        let scans = select_scans(&facts, &mut texts, filter)?;
        let provenance = provenance(&facts, &scans);
        let count = code::import_root_frequency(&facts, code::text_handle(root));
        Ok((count, provenance))
    }

    /// Everything the catalogue holds about one item.
    pub fn show(&self, selector: &str, with_source: bool) -> Result<ItemDetail> {
        let observed = self.observe()?;
        let facts = observed.view::<FactArchive>().context("read Code facts")?;
        let reader = observed.snapshot();
        let mut texts = Texts::new(reader);
        let filter = Filter::default();
        let scans = select_scans(&facts, &mut texts, &filter)?;
        let provenance = provenance(&facts, &scans);

        let item = resolve_item(&facts, &mut texts, &scans, selector)?;
        // Placements of exactly this item, in every selected scan.
        let mut places = Vec::new();
        for scan in &scans {
            for located in placements_of_item(&facts, scan.id, item) {
                places.push(hit(&facts, &mut texts, scan, located)?);
            }
        }
        sort_hits(&mut places);
        places.dedup_by(|left, right| left.location() == right.location());

        let head = places
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("item {item:x} has no placement in the selected revisions"))?;

        let source = if with_source {
            item_source(&facts, reader, &head)?
        } else {
            None
        };

        Ok(ItemDetail {
            hit: head,
            places,
            source,
            provenance,
        })
    }

    /// Code that exists in more than one place.
    ///
    /// Byte-identical code is already ONE item, so this is a self-join on the
    /// placement relation, not a comparison pass: the pile's content addressing
    /// IS the clone detector. Near-duplicates are out of scope, and the
    /// renderer says so — `arc_points` being exact is luck, not a guarantee.
    pub fn duplicates(
        &self,
        min_lines: u64,
        cross_repo: bool,
        filter: &Filter,
    ) -> Result<DuplicateReport> {
        let observed = self.observe()?;
        let facts = observed.view::<FactArchive>().context("read Code facts")?;
        let reader = observed.snapshot();
        let mut texts = Texts::new(reader);
        let scans = select_scans(&facts, &mut texts, filter)?;
        let provenance = provenance(&facts, &scans);

        let mut pairs: BTreeSet<(Id, Id, Id)> = BTreeSet::new();
        for scan in &scans {
            for (item, left, right, _, _) in code::duplicate_placements_in_scan(&facts, scan.id) {
                // Bag-to-set presentation: the self-join necessarily yields the
                // reflexive pair and both orderings.
                if left == right {
                    continue;
                }
                let (low, high) = if left < right {
                    (left, right)
                } else {
                    (right, left)
                };
                pairs.insert((item, low, high));
            }
        }

        let mut by_item: BTreeMap<Id, BTreeSet<Id>> = BTreeMap::new();
        for (item, left, right) in pairs {
            let entry = by_item.entry(item).or_default();
            entry.insert(left);
            entry.insert(right);
        }

        let mut groups = Vec::new();
        for (item, placements) in by_item {
            let mut places = Vec::new();
            for scan in &scans {
                for located in placements_of_item(&facts, scan.id, item) {
                    if placements.contains(&located.placement) {
                        places.push(hit(&facts, &mut texts, scan, located)?);
                    }
                }
            }
            sort_hits(&mut places);
            places.dedup_by(|left, right| left.location() == right.location());
            if places.len() < 2 {
                continue;
            }
            let lines = places
                .iter()
                .map(|place| place.end_line.saturating_sub(place.line) + 1)
                .max()
                .unwrap_or(1);
            if lines < min_lines {
                continue;
            }
            if cross_repo {
                let repos: BTreeSet<&str> =
                    places.iter().map(|place| place.repo.as_str()).collect();
                if repos.len() < 2 {
                    continue;
                }
            }
            groups.push(DuplicateGroup {
                item,
                name: places.first().and_then(|place| place.name.clone()),
                kind: places.first().and_then(|place| place.kind.clone()),
                lines,
                places,
            });
        }
        groups.sort_by(|left, right| {
            right
                .places
                .len()
                .cmp(&left.places.len())
                .then(right.lines.cmp(&left.lines))
                .then(left.name.cmp(&right.name))
        });

        Ok(DuplicateReport { groups, provenance })
    }

    /// What the catalogue holds, per revision.
    pub fn stats(&self, filter: &Filter) -> Result<StatsReport> {
        let observed = self.observe()?;
        let facts = observed.view::<FactArchive>().context("read Code facts")?;
        let reader = observed.snapshot();
        let mut texts = Texts::new(reader);
        let scans = select_scans(&facts, &mut texts, filter)?;

        // `stats` and the footer want the same two counts, so they are asked
        // for once and the footer is built from them rather than re-running the
        // join over every placement a second time.
        let mut rows = Vec::new();
        let mut total_units = 0;
        let mut total_placements = 0;
        for scan in &scans {
            let units = code::units_in_scan(&facts, scan.id).len();
            let placements = code::placement_count_in_scan(&facts, scan.id);
            total_units += units;
            total_placements += placements;
            let parse_failures = code::parse_failures_in_scan(&facts, scan.id).len();
            let mut kinds = Vec::new();
            for kind in [
                ItemKind::Fn,
                ItemKind::Struct,
                ItemKind::Enum,
                ItemKind::Trait,
                ItemKind::Impl,
                ItemKind::Mod,
                ItemKind::Use,
                ItemKind::Const,
                ItemKind::Static,
                ItemKind::Type,
                ItemKind::Macro,
            ] {
                let count = code::items_of_kind_in_scan(&facts, scan.id, kind.name()).len();
                if count > 0 {
                    kinds.push((kind.name().to_owned(), count));
                }
            }
            kinds.sort_by(|left, right| right.1.cmp(&left.1));
            rows.push(StatsRow {
                scan: scan.label(),
                units,
                placements,
                parse_failures,
                kinds,
            });
        }
        Ok(StatsReport {
            rows,
            provenance: Provenance {
                scans,
                units: total_units,
                placements: total_placements,
                extractor: EXTRACTOR_RUST_SYN_V1_NAME.to_owned(),
            },
        })
    }

    /// Ask git which commits added or removed an occurrence of `identifier`.
    ///
    /// The deliberate seam: the catalogue answers from facts when it holds them
    /// and asks git when it does not. Git shows the DIFF, so unlike a name-set
    /// difference between two scans this cannot misread a rename-with-edit as a
    /// removal.
    pub fn blame(&self, identifier: &str, dirs: &[PathBuf], limit: usize) -> Result<BlameReport> {
        let mut report = BlameReport {
            identifier: identifier.to_owned(),
            ..BlameReport::default()
        };
        for dir in dirs {
            let dir = dir
                .canonicalize()
                .with_context(|| format!("resolve {}", dir.display()))?;
            if !git::is_repository(&dir) {
                continue;
            }
            let repo = repo_name(&dir);
            report.searched.push(repo.clone());
            for change in git::pickaxe(&dir, identifier, limit)? {
                let paths = git::commit_paths(&dir, &change.commit, 6).unwrap_or_default();
                report.rows.push(BlameRow {
                    repo: repo.clone(),
                    commit: change.commit,
                    date: change.date,
                    subject: change.subject,
                    paths,
                });
            }
        }
        report
            .rows
            .sort_by(|left, right| right.date.cmp(&left.date));
        Ok(report)
    }

    pub fn storage(&self) -> &Storage {
        &self.storage
    }
}

// ── ingest internals ────────────────────────────────────────────────────

struct RepoPlan {
    repo: String,
    commit: String,
    mode: String,
    sources: Vec<(String, Vec<u8>)>,
    skipped: usize,
}

fn repo_name(dir: &Path) -> String {
    dir.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| dir.display().to_string())
}

/// Read one repository's catalogued files, and decide what commit value names
/// what was read.
///
/// A dirty tree gets `worktree:<blake3 of the sorted (path, content-handle)
/// list>`, so two agents ingesting the same uncommitted tree converge on one
/// scan and a differing tree is visibly a different one.
fn plan_repository(dir: &Path, options: &IngestOptions) -> Result<RepoPlan> {
    let repo = repo_name(dir);
    let mut sources: Vec<(String, Vec<u8>)> = Vec::new();
    let mut skipped = 0usize;

    let (commit, mode) = match &options.commit {
        Some(revision) => {
            let resolved = git::resolve(dir, revision)?;
            let entries = git::ls_tree(dir, &resolved)?;
            let mut by_object: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for entry in &entries {
                if Language::of_path(&entry.path).is_none() {
                    continue;
                }
                by_object
                    .entry(entry.object.clone())
                    .or_default()
                    .push(entry.path.clone());
            }
            let objects: Vec<String> = by_object.keys().cloned().collect();
            let mut payloads: BTreeMap<String, Vec<u8>> = BTreeMap::new();
            git::cat_objects(dir, &objects, |object, payload| {
                payloads.insert(object.to_owned(), payload);
                Ok(())
            })?;
            for (object, paths) in by_object {
                let Some(payload) = payloads.get(&object) else {
                    continue;
                };
                for path in paths {
                    if payload.len() > MAX_UNIT_BYTES {
                        skipped += 1;
                        continue;
                    }
                    sources.push((path, payload.clone()));
                }
            }
            (resolved, "commit".to_owned())
        }
        None => {
            for path in git::ls_files(dir)? {
                if Language::of_path(&path).is_none() {
                    // An extension this build cannot model is skipped, never
                    // rejected, and never even read.
                    continue;
                }
                let full = dir.join(&path);
                let Ok(bytes) = std::fs::read(&full) else {
                    // A tracked path missing from the working tree is something
                    // this reader cannot establish, not an error to refuse over.
                    skipped += 1;
                    continue;
                };
                if bytes.len() > MAX_UNIT_BYTES {
                    skipped += 1;
                    continue;
                }
                sources.push((path, bytes));
            }
            if git::is_dirty(dir)? {
                (worktree_commit(&sources), "worktree".to_owned())
            } else {
                (git::head(dir)?, "head".to_owned())
            }
        }
    };

    sources.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(RepoPlan {
        repo,
        commit,
        mode,
        sources,
        skipped,
    })
}

/// A commit value for an uncommitted tree: the tree's own content, digested.
pub fn worktree_commit(sources: &[(String, Vec<u8>)]) -> String {
    let mut entries: Vec<(String, String)> = sources
        .iter()
        .map(|(path, bytes)| (path.clone(), hex::encode(code::bytes_handle(bytes).raw)))
        .collect();
    entries.sort();
    let mut hasher = blake3::Hasher::new();
    for (path, handle) in entries {
        hasher.update(path.as_bytes());
        hasher.update(b"\0");
        hasher.update(handle.as_bytes());
        hasher.update(b"\n");
    }
    format!("worktree:{}", hasher.finalize().to_hex())
}

fn ingest_repository<P: std::borrow::BorrowMut<triblespace::core::repo::pile::Pile>>(
    writer: &mut ingest::CodeImportWriter<P>,
    plan: RepoPlan,
) -> Result<RepoIngest> {
    let repo_handle = code::text_handle(&plan.repo);
    let commit_handle = code::text_handle(&plan.commit);
    let scan_core = code::scan_core(repo_handle, commit_handle);
    let scan = scan_core.root().expect("scan core has one intrinsic root");

    // A re-observation of an IDENTICAL revision must write nothing at all, so
    // the observation time is recorded once, when this `(repo, commit)` first
    // becomes known. The clock deliberately never enters the core — two
    // machines scanning one commit produce the same scan entity — and stamping
    // a fresh `created_at` on every run would be the one fact that made an
    // otherwise no-op re-ingest grow the pile forever.
    let known = writer.holds_entity(scan);
    let mut scan_fragment = Fragment::empty();
    // The blobs behind both identity values still have to reach the pile.
    let mut carrier = Fragment::empty();
    let _ = carrier.put::<blobencodings::UTF8String, _>(plan.repo.clone());
    let _ = carrier.put::<blobencodings::UTF8String, _>(plan.commit.clone());
    scan_fragment += carrier;
    scan_fragment += scan_core;
    if !known {
        scan_fragment += code::scan_annotation(scan, crate::clock::point_now()?, &plan.mode);
    }
    writer.stage_fragment(scan_fragment)?;

    let mut row = RepoIngest {
        repo: plan.repo.clone(),
        commit: plan.commit.clone(),
        files_seen: plan.sources.len(),
        files_skipped: plan.skipped,
        ..RepoIngest::default()
    };

    for (path, bytes) in &plan.sources {
        let Some(language) = Language::of_path(path) else {
            // Unreachable: the plan only collects paths with a language. Kept
            // as a skip rather than an unwrap, because a reader that cannot
            // model something ignores it.
            row.files_skipped += 1;
            continue;
        };
        let path_handle = code::text_handle(path);
        let content_handle = code::bytes_handle(bytes);
        let unit_core = code::unit_core(repo_handle, path_handle, content_handle);
        let unit = unit_core.root().expect("unit core has one intrinsic root");

        // Always assert membership: it is cheap, it converges, and it is what
        // makes a re-scan of an unchanged tree zero-growth rather than absent.
        writer.stage_fragment(code::scan_holds(scan, unit))?;

        if writer.holds_entity(unit) {
            // These exact bytes at this exact path are already catalogued. No
            // parse at all — one Blake3 and one existence probe per unchanged
            // file is what makes a steady-state ingest cost ten parses.
            continue;
        }

        let extracted = extract::extract(&String::from_utf8_lossy(bytes), language);
        if extracted.parse_error.is_some() {
            row.parse_failures += 1;
        }
        row.files_parsed += 1;
        row.items += extracted.items.len();
        let (fragment, _) = code::unit_fragment(&plan.repo, path, language, bytes, &extracted);
        writer.stage_fragment(fragment)?;

        if writer.delta_len() > MAX_STAGED_FACTS {
            if writer.commit_unit()?.is_some() {
                row.commits += 1;
            }
        }
    }

    if writer.commit_unit()?.is_some() {
        row.commits += 1;
    }
    Ok(row)
}

// ── read internals ──────────────────────────────────────────────────────

pub(crate) fn placements_of_item<P>(facts: &P, scan: Id, item: Id) -> Vec<code::Located>
where
    P: TriblePattern + ?Sized,
{
    find!(
        (placement: Id, unit: Id, range: code::SpanValue),
        pattern!(facts, [
            { scan @ crate::schemas::code::attrs::holds: ?unit },
            { ?placement @
                crate::schemas::code::attrs::unit: ?unit,
                crate::schemas::code::attrs::item: item,
                crate::schemas::code::attrs::source_range: ?range },
        ])
    )
    .map(|(placement, unit, range)| code::Located {
        item,
        placement,
        unit,
        range,
    })
    .collect()
}

/// Which scans answer this question.
///
/// With no selector this is the newest scan per repository, which is the only
/// default that does not silently mix two revisions of the same file.
pub(crate) fn select_scans(
    facts: &FactArchive,
    texts: &mut Texts<'_>,
    filter: &Filter,
) -> Result<Vec<ScanSummary>> {
    let mut all = Vec::new();
    for row in code::projected_scans(facts) {
        let repo = texts.get(row.repo)?;
        let commit = texts.get(row.commit)?;
        let observed_at = interval_start(row.observed_at);
        all.push(ScanSummary {
            id: row.id,
            repo,
            commit,
            observed_at,
        });
    }
    if let Some(repo) = &filter.repo {
        all.retain(|scan| &scan.repo == repo);
    }

    let mut selected = match &filter.revision {
        Revision::Latest => {
            let mut newest: BTreeMap<String, ScanSummary> = BTreeMap::new();
            for scan in all {
                newest
                    .entry(scan.repo.clone())
                    .and_modify(|current| {
                        if scan.observed_at > current.observed_at {
                            *current = scan.clone();
                        }
                    })
                    .or_insert(scan);
            }
            newest.into_values().collect::<Vec<_>>()
        }
        Revision::Worktree => all
            .into_iter()
            .filter(|scan| scan.commit.starts_with("worktree:"))
            .collect(),
        Revision::Selector(selector) => {
            let (repo, revision) = match selector.split_once('@') {
                Some((repo, revision)) => (Some(repo), revision),
                None => (None, selector.as_str()),
            };
            all.into_iter()
                .filter(|scan| repo.is_none_or(|repo| scan.repo == repo))
                .filter(|scan| {
                    if revision == "worktree" {
                        scan.commit.starts_with("worktree:")
                    } else {
                        scan.commit.starts_with(revision)
                    }
                })
                .collect()
        }
    };
    selected.sort_by(|left, right| left.repo.cmp(&right.repo));
    Ok(selected)
}

/// The lower bound of an observation interval.
///
/// A value this reader cannot decode sorts to the epoch rather than failing the
/// command: an undecodable timestamp on someone else's scan is not a reason to
/// refuse to answer a question about ours.
fn interval_start(interval: code::IntervalValue) -> Epoch {
    let bounds: std::result::Result<(i128, i128), _> = interval.try_from_inline();
    let lower = bounds.map(|(lower, _)| lower).unwrap_or(0);
    Epoch::from_tai_duration(hifitime::Duration::from_total_nanoseconds(lower))
}

pub(crate) fn provenance(facts: &FactArchive, scans: &[ScanSummary]) -> Provenance {
    let mut units = 0;
    let mut placements = 0;
    for scan in scans {
        units += code::units_in_scan(facts, scan.id).len();
        placements += code::placement_count_in_scan(facts, scan.id);
    }
    Provenance {
        scans: scans.to_vec(),
        units,
        placements,
        extractor: EXTRACTOR_RUST_SYN_V1_NAME.to_owned(),
    }
}

/// Assemble one display row for one surviving result.
///
/// This is render-time projection: it is built per result that already passed
/// the relation query, it is never cached, and it never outlives the call.
pub(crate) fn hit(
    facts: &FactArchive,
    texts: &mut Texts<'_>,
    scan: &ScanSummary,
    located: code::Located,
) -> Result<Hit> {
    let (repo, path) = match code::unit_location(facts, located.unit).into_iter().next() {
        Some((repo, path)) => (texts.get(repo)?, texts.get(path)?),
        None => (scan.repo.clone(), "?".to_owned()),
    };
    let row = code::item_row(facts, located.item).into_iter().next();
    let (line, _, end_line, _) = code::span_parts(located.range);
    Ok(Hit {
        item: located.item,
        unit: located.unit,
        repo,
        path,
        line,
        end_line,
        kind: row.map(|row| row.kind.name().to_owned()),
        visibility: row.map(|row| row.visibility.name().to_owned()),
        name: texts.first(code::item_names(facts, located.item))?,
        signature: texts.first(code::item_signature(facts, located.item))?,
        doc: texts.first(code::item_doc(facts, located.item))?,
        scan: scan.label(),
    })
}

pub(crate) fn keeps(hit: &Hit, filter: &Filter) -> bool {
    if let Some(kind) = &filter.kind {
        if hit.kind.as_deref() != Some(kind.as_str()) {
            return false;
        }
    }
    if let Some(repo) = &filter.repo {
        if &hit.repo != repo {
            return false;
        }
    }
    true
}

fn sort_hits(hits: &mut [Hit]) {
    hits.sort_by(|left, right| {
        left.repo
            .cmp(&right.repo)
            .then(left.path.cmp(&right.path))
            .then(left.line.cmp(&right.line))
    });
}

/// A spread line for an identifier common enough that a list means little.
///
/// A tool that says "0 hits" beautifully and "4,912 hits" identically has
/// learned nothing. `mentions` is unresolved, so above a threshold the honest
/// output is the shape of the answer plus what it cannot tell you.
fn spread_caveat(hits: &[Hit]) -> Option<String> {
    if hits.len() < 60 {
        return None;
    }
    let units: BTreeSet<(&str, &str)> = hits
        .iter()
        .map(|hit| (hit.repo.as_str(), hit.path.as_str()))
        .collect();
    let repos: BTreeSet<&str> = hits.iter().map(|hit| hit.repo.as_str()).collect();
    Some(format!(
        "{} item(s) across {} file(s) across {} repo(s). `mentions` is UNRESOLVED: \
these are declarations that spell this identifier, not resolved references to one \
definition, so a common name returns a list this catalogue cannot narrow.",
        hits.len(),
        units.len(),
        repos.len(),
    ))
}

/// Exact queries for name-similar declarations, rather than a fuzzy scan.
///
/// `LearnerBuilder` yields `Learner` and `Builder`; `snapshot_at` yields
/// `snapshot` and `at`. Each candidate is looked up exactly, so the near-miss
/// list costs a handful of constant-folded index probes rather than reading
/// thirty thousand names.
pub fn near_miss_candidates(name: &str) -> Vec<String> {
    let mut candidates: BTreeSet<String> = BTreeSet::new();

    let camel = split_camel(name);
    for window in 1..camel.len() {
        candidates.insert(camel[..window].concat());
        candidates.insert(camel[window..].concat());
    }
    for word in &camel {
        candidates.insert((*word).to_owned());
    }

    let snake: Vec<&str> = name.split('_').filter(|part| !part.is_empty()).collect();
    for window in 1..snake.len() {
        candidates.insert(snake[..window].join("_"));
        candidates.insert(snake[window..].join("_"));
    }
    for word in &snake {
        candidates.insert((*word).to_owned());
    }

    candidates.remove(name);
    candidates.retain(|candidate| candidate.len() >= 3);
    candidates.into_iter().collect()
}

fn split_camel(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    for character in name.chars() {
        if character.is_uppercase() && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        current.push(character);
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn resolve_item(
    facts: &FactArchive,
    texts: &mut Texts<'_>,
    scans: &[ScanSummary],
    selector: &str,
) -> Result<Id> {
    let trimmed = selector.trim();
    if trimmed
        .chars()
        .all(|character| character.is_ascii_hexdigit())
        && trimmed.len() >= 4
    {
        if let Ok(id) = crate::resolve_id_prefix(trimmed, code::all_item_ids(facts)) {
            return Ok(id);
        }
    }
    let handle = code::text_handle(trimmed);
    for scan in scans {
        if let Some(located) = code::definitions_in_scan(facts, scan.id, handle)
            .into_iter()
            .next()
        {
            return Ok(located.item);
        }
    }
    let _ = texts;
    bail!("no catalogued item matches {selector:?}")
}

/// The declaration's own lines, sliced out of the exact unit it was placed in.
///
/// Addressing the unit rather than the path matters: two revisions of one file
/// are two units with the same path, and slicing the wrong one would print
/// lines that do not say what the reported line number says they do.
fn item_source(facts: &FactArchive, reader: &PileSnapshot, hit: &Hit) -> Result<Option<String>> {
    for handle in code::unit_content(facts, hit.unit) {
        let bytes: anybytes::Bytes = match reader.get(handle) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let start = hit.line.saturating_sub(1) as usize;
        let end = (hit.end_line as usize).min(text.lines().count());
        if start >= end {
            continue;
        }
        return Ok(Some(
            text.lines()
                .skip(start)
                .take(end - start)
                .collect::<Vec<_>>()
                .join("\n"),
        ));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_camel_name_yields_its_head_and_tail_as_near_misses() {
        let candidates = near_miss_candidates("LearnerBuilder");
        assert!(candidates.contains(&"Learner".to_owned()), "{candidates:?}");
        assert!(candidates.contains(&"Builder".to_owned()));
        assert!(!candidates.contains(&"LearnerBuilder".to_owned()));
    }

    #[test]
    fn a_snake_name_yields_its_segments_as_near_misses() {
        let candidates = near_miss_candidates("snapshot_at");
        assert!(
            candidates.contains(&"snapshot".to_owned()),
            "{candidates:?}"
        );
    }

    #[test]
    fn a_worktree_commit_is_stable_for_the_same_tree() {
        let tree = vec![
            ("b.rs".to_owned(), b"two".to_vec()),
            ("a.rs".to_owned(), b"one".to_vec()),
        ];
        let reversed = vec![
            ("a.rs".to_owned(), b"one".to_vec()),
            ("b.rs".to_owned(), b"two".to_vec()),
        ];
        assert_eq!(worktree_commit(&tree), worktree_commit(&reversed));
        assert!(worktree_commit(&tree).starts_with("worktree:"));

        let changed = vec![
            ("a.rs".to_owned(), b"one".to_vec()),
            ("b.rs".to_owned(), b"three".to_vec()),
        ];
        assert_ne!(worktree_commit(&tree), worktree_commit(&changed));
    }

    #[test]
    fn a_revision_selector_defaults_to_the_newest_scan_per_repo() {
        assert_eq!(Revision::parse(None), Revision::Latest);
        assert_eq!(Revision::parse(Some("  ")), Revision::Latest);
        assert_eq!(Revision::parse(Some("worktree")), Revision::Worktree);
        assert_eq!(
            Revision::parse(Some("faculties@336a8765")),
            Revision::Selector("faculties@336a8765".to_owned())
        );
    }
}
