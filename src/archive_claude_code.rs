//! Deterministic Claude Code JSONL projection onto Archive's canonical block DAG.
//!
//! This module deliberately stops at the source-adapter boundary. It scans a
//! file or directory, projects each source file into bounded,
//! attachment-complete [`Fragment`]s, and hands those fragments to a
//! caller-provided sink. A child
//! fragment may name a predecessor catalog entity carried by another emitted
//! fragment, so callers must stage the complete emitted union through
//! `ArchiveImportWriter` and publish it with one validated COMMIT. The adapter
//! knows nothing about Archive's CLI, legacy repositories, branches,
//! workspaces, or signing policy.
//!
//! Directory projection first scans the complete semantic source graph. Exact
//! `forkedFrom` aliases are quotiented first. Only non-fork parent assertions
//! enter the semantic graph; known transparent records are contracted, and
//! narrowly classified reciprocal `system/turn_duration` telemetry backlinks
//! are removed before any intrinsic block identity is constructed. Blocks and
//! source-receipt identities are then planned over the complete record DAG, so
//! cross-file references and Rayon completion order cannot affect identity.
//! Each receipt additively cites every known receipt supporting its canonical
//! predecessor classes; this is semantic support, not a transcription of that
//! receipt's raw `parentUuid`, which remains preserved in `raw_record`.
//! Missing corpus-external references are accounted but do not block otherwise
//! useful definitions. Projection first freezes each live JSONL file into one
//! immutable, disk-backed snapshot and verifies it against the pre-scan. It
//! then emits semantic receipts one record at a time plus one exact source
//! snapshot over reusable fixed-size byte chunks. Snapshots are disjoint from
//! dialogue projections: they retain everything contracted out of the
//! semantic graph without creating a fake bottom-block message. Both passes
//! are line-streaming and materialize only canonical fields.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use hifitime::Epoch;
use rayon::prelude::*;
use triblespace::core::blob::Bytes;
use triblespace::core::import::scanner as sc;
use triblespace::prelude::blobencodings::{RawBytes, UTF8String};
use triblespace::prelude::inlineencodings::{Blake3, Handle, NsTAIInterval};
use triblespace::prelude::*;

use crate::schemas::blockdag as schema;
use crate::{archive_source, blockdag, files};

const TOOL_RESULT_STATUS_OK: &str = "urn:triblespace:archive:tool-result-status:v1:ok";
const TOOL_RESULT_STATUS_ERROR: &str = "urn:triblespace:archive:tool-result-status:v1:error";
/// Observable projection accounting. Missing or unresolved source evidence is
/// counted rather than silently replaced with invented values.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProjectionStats {
    /// Non-empty JSONL records scanned.
    pub records_seen: usize,
    /// Canonical source projections emitted for semantic occurrences.
    pub source_projections: usize,
    /// Reusable content-addressed byte ranges in exact source snapshots.
    pub raw_chunks: usize,
    /// Exact frozen source versions retained independently of semantic rows.
    pub source_snapshots: usize,
    /// Ordered content parts emitted before set-level deduplication.
    pub content_parts: usize,
    /// Non-dialogue, contentless, or identity-less records retained only in
    /// the exact source snapshot rather than semantic dialogue blocks.
    pub skipped_records: usize,
    /// Dialogue records lacking either `sessionId` or `uuid`.
    pub missing_source_identity: usize,
    /// `parentUuid` references whose target source record has neither a block
    /// nor a forwarded projected ancestor.
    pub skipped_parents: usize,
    /// `parentUuid` references whose source key is absent from the imported
    /// corpus. Semantic cycles are rejected before any fragment is emitted.
    pub unresolved_parents: usize,
    /// `tool_result` correlators with no matching explicit source class or raw
    /// `(sessionId, tool_use_id)` binding.
    pub unresolved_tool_results: usize,
    /// Image sources omitted because neither bytes nor a usable pointer existed.
    pub undecodable_images: usize,
}

impl ProjectionStats {
    fn absorb(&mut self, other: Self) {
        self.records_seen += other.records_seen;
        self.source_projections += other.source_projections;
        self.raw_chunks += other.raw_chunks;
        self.source_snapshots += other.source_snapshots;
        self.content_parts += other.content_parts;
        self.skipped_records += other.skipped_records;
        self.missing_source_identity += other.missing_source_identity;
        self.skipped_parents += other.skipped_parents;
        self.unresolved_parents += other.unresolved_parents;
        self.unresolved_tool_results += other.unresolved_tool_results;
        self.undecodable_images += other.undecodable_images;
    }
}

/// One bounded projection fragment plus every blob its facts reference.
///
/// `source_path` is presentation metadata only. It is also attached to each
/// source-projection receipt as a nonidentity occurrence annotation, so moving
/// a transcript never changes any source-projection or block id.
#[derive(Debug)]
pub struct ProjectedFile {
    pub source_path: PathBuf,
    pub fragment: Fragment,
    pub stats: ProjectionStats,
}

/// Corpus-level result returned after every projected fragment has reached
/// `emit`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProjectionSummary {
    /// JSONL files scanned, including files containing no projectable records.
    pub files_scanned: usize,
    /// Non-empty bounded fragments handed to the sink.
    pub fragments_emitted: usize,
    pub stats: ProjectionStats,
}

/// Project one Claude Code JSONL file or a recursively scanned directory.
///
/// Files are discovered and emitted deterministically. Each semantic source
/// occurrence is emitted immediately as a bounded fragment, followed by one
/// exact source snapshot over offset-addressed chunks. The caller must stage every supplied
/// fragment into one `ArchiveImportWriter` and call its `finish` only after
/// projection succeeds; publishing fragments independently can expose an
/// invalid partial catalog. The projector itself performs no pile writes.
pub fn project_path<F>(path: &Path, mut emit: F) -> Result<ProjectionSummary>
where
    F: FnMut(ProjectedFile) -> Result<()>,
{
    if path.is_dir() {
        return project_directory(path, &mut emit);
    }

    let prescan = prescan_file(path)?;
    let plan = SourcePlan::from_scans(std::slice::from_ref(&prescan))
        .context("plan canonical Claude Code lineage")?;
    let snapshot = archive_source::freeze_file(path)?;
    project_snapshot(
        path,
        snapshot,
        prescan.digest,
        prescan.file_anchor.as_ref(),
        &plan,
        &mut emit,
    )
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct SourceKey {
    session: String,
    uuid: String,
}

impl SourceKey {
    fn new(session: impl Into<String>, uuid: impl Into<String>) -> Self {
        Self {
            session: session.into(),
            uuid: uuid.into(),
        }
    }

    fn locator(&self) -> String {
        format!("{}/{}", self.session, self.uuid)
    }
}

#[derive(Debug, Default)]
struct PreScan {
    sources: HashMap<SourceKey, SourceObservation>,
    aliases: BTreeSet<(SourceKey, SourceKey)>,
    /// First native `(sessionId, uuid)` observed in this physical file.
    file_anchor: Option<SourceKey>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct SourceObservation {
    semantic: bool,
    turn_duration: bool,
    non_turn_duration: bool,
    parents: BTreeSet<SourceKey>,
    shapes: Vec<RecordShape>,
    raw_records: BTreeSet<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecordShape {
    timestamp: Option<Inline<NsTAIInterval>>,
    parts: Vec<PartShape>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PartShape {
    ordinal: u64,
    fact: Id,
    tool_call_id: Option<String>,
    responds_to: Option<ToolReference>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ToolReference {
    source: Option<SourceKey>,
    session: String,
    correlator: String,
}

/// Canonical semantic source graph built from every exact receipt before any
/// intrinsic block identity is constructed.
///
/// Explicit `forkedFrom` edges form an identity quotient. Parent observations
/// from non-fork receipts union between quotient classes. Contentless source
/// records are contracted; only reciprocal backlinks on Claude's proven
/// message-less `system/turn_duration` telemetry are removed. The result is a
/// construction-history-independent predecessor set for every projected key.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct SourcePlan {
    semantic: HashSet<SourceKey>,
    parents: HashMap<SourceKey, BTreeSet<SourceKey>>,
    canonical: HashMap<SourceKey, SourceKey>,
    blocks: HashMap<SourceKey, Id>,
    tool_parts: HashMap<(SourceKey, String), Id>,
    session_tool_parts: HashMap<(String, String), Id>,
    projection_ids: HashMap<SourceKey, BTreeSet<Id>>,
}

impl SourcePlan {
    fn from_scans(scans: &[PreScan]) -> Result<Self> {
        Self::build(scans)
    }

    fn build(scans: &[PreScan]) -> Result<Self> {
        let mut raw: HashMap<SourceKey, SourceObservation> = HashMap::new();
        let mut keys = BTreeSet::new();
        let mut aliases = BTreeSet::new();
        for scan in scans {
            aliases.extend(scan.aliases.iter().cloned());
            for (key, incoming) in &scan.sources {
                keys.insert(key.clone());
                keys.extend(incoming.parents.iter().cloned());
                let observation = raw.entry(key.clone()).or_default();
                observation.semantic |= incoming.semantic;
                observation.turn_duration |= incoming.turn_duration;
                observation.non_turn_duration |= incoming.non_turn_duration;
                observation.parents.extend(incoming.parents.iter().cloned());
                observation
                    .raw_records
                    .extend(incoming.raw_records.iter().copied());
                for shape in &incoming.shapes {
                    if !observation.shapes.contains(shape) {
                        observation.shapes.push(shape.clone());
                    }
                }
            }
        }
        for (destination, origin) in &aliases {
            keys.insert(destination.clone());
            keys.insert(origin.clone());
        }

        let canonical = alias_quotient(&keys, &aliases);
        let canonical_key =
            |key: &SourceKey| canonical.get(key).cloned().unwrap_or_else(|| key.clone());
        let mut observed: HashMap<SourceKey, SourceObservation> = HashMap::new();
        for (key, incoming) in &raw {
            let observation = observed.entry(canonical_key(key)).or_default();
            observation.semantic |= incoming.semantic;
            observation.turn_duration |= incoming.turn_duration;
            observation.non_turn_duration |= incoming.non_turn_duration;
            observation
                .parents
                .extend(incoming.parents.iter().map(&canonical_key));
        }

        for (key, observation) in &observed {
            if observation.semantic && observation.turn_duration {
                bail!(
                    "Claude Code source key {} is both semantic dialogue and turn-duration telemetry",
                    key.locator()
                );
            }
        }

        let semantic: HashSet<_> = observed
            .iter()
            .filter_map(|(key, observation)| observation.semantic.then_some(key.clone()))
            .collect();
        let mut normalized: HashMap<_, _> = observed
            .iter()
            .map(|(key, observation)| (key.clone(), observation.parents.clone()))
            .collect();

        // Claude Code emits a message-less `system/turn_duration` record T
        // after an assistant A in a small number of transcripts while also
        // recording A as T's parent and T as one observation of A's parent.
        // That is telemetry adjacency, not a semantic A <-> T cycle. A census
        // of 3,391 files / 1.3M records found exactly 19 reciprocal cases and
        // no counterexample to removing only T's direct reciprocal backlink.
        // Requiring every
        // occurrence of T to carry the exact telemetry subtype keeps this
        // normalization deliberately narrower than generic cycle breaking.
        for (telemetry, observation) in &observed {
            if !observation.turn_duration || observation.non_turn_duration {
                continue;
            }
            let reciprocal = observation
                .parents
                .iter()
                .filter(|parent| {
                    observed
                        .get(*parent)
                        .is_some_and(|candidate| candidate.parents.contains(telemetry))
                })
                .cloned()
                .collect::<Vec<_>>();
            let parents = normalized
                .get_mut(telemetry)
                .expect("every observed source has normalized parents");
            for parent in reciprocal {
                parents.remove(&parent);
            }
        }

        let mut parents = HashMap::with_capacity(semantic.len());
        let mut memo = HashMap::new();
        for key in sorted_source_keys(&semantic) {
            let mut frontier = BTreeSet::new();
            for parent in normalized.get(&key).into_iter().flatten() {
                frontier.extend(semantic_frontier(
                    parent,
                    &semantic,
                    &normalized,
                    &mut memo,
                )?);
            }
            parents.insert(key, frontier);
        }

        // Full-corpus evidence for this quotient (2026-08-09): 126,058
        // explicit aliases collapse into 796,984 classes; unioning every
        // non-fork parent assertion leaves 793,454 class edges, 199 genuine
        // multi-parent classes, and no semantic SCC. Fourteen native records
        // refer to keys defined only by fork receipts, so alias resolution is
        // not merely cosmetic.
        validate_semantic_dag(&semantic, &parents)?;

        let mut tool_parts = HashMap::new();
        let mut session_tool_parts = HashMap::new();
        for (key, observation) in &raw {
            let class = canonical_key(key);
            for shape in &observation.shapes {
                for part in &shape.parts {
                    let Some(correlator) = &part.tool_call_id else {
                        continue;
                    };
                    let id = content_part_id(part.ordinal, part.fact, None)?;
                    if tool_parts
                        .insert((class.clone(), correlator.clone()), id)
                        .is_some_and(|previous| previous != id)
                    {
                        bail!(
                            "Claude Code tool correlator {:?} has conflicting calls in alias class {}",
                            correlator,
                            class.locator()
                        );
                    }
                    if session_tool_parts
                        .insert((key.session.clone(), correlator.clone()), id)
                        .is_some_and(|previous| previous != id)
                    {
                        bail!(
                            "Claude Code tool correlator {:?} has conflicting calls in raw session {:?}",
                            correlator,
                            key.session
                        );
                    }
                }
            }
        }

        let mut plan = Self {
            semantic,
            parents,
            canonical,
            blocks: HashMap::new(),
            tool_parts,
            session_tool_parts,
            projection_ids: HashMap::new(),
        };

        let mut shapes = HashMap::new();
        for (key, observation) in &raw {
            let class = plan.canonical_key(key);
            for shape in &observation.shapes {
                let resolved = plan.resolve_shape(shape)?;
                if shapes
                    .insert(class.clone(), resolved.clone())
                    .is_some_and(|previous| previous != resolved)
                {
                    bail!(
                        "Claude Code alias class {} carries conflicting semantic payloads",
                        class.locator()
                    );
                }
            }
        }
        plan.blocks = build_block_ids(&plan.semantic, &plan.parents, &shapes)?;

        for (key, observation) in &raw {
            if !observation.semantic {
                continue;
            }
            let class = plan.canonical_key(key);
            let block = *plan.blocks.get(&class).ok_or_else(|| {
                anyhow!(
                    "semantic Claude Code alias class {} has no block",
                    class.locator()
                )
            })?;
            for raw_digest in &observation.raw_records {
                plan.projection_ids
                    .entry(class.clone())
                    .or_default()
                    .insert(source_projection_id(key, *raw_digest, block));
            }
        }
        Ok(plan)
    }

    fn canonical_key(&self, key: &SourceKey) -> SourceKey {
        self.canonical
            .get(key)
            .cloned()
            .unwrap_or_else(|| key.clone())
    }

    fn resolve_tool_part(&self, reference: &ToolReference) -> Option<Id> {
        match &reference.source {
            Some(source) => self
                .tool_parts
                .get(&(self.canonical_key(source), reference.correlator.clone()))
                .copied(),
            None => self
                .session_tool_parts
                .get(&(reference.session.clone(), reference.correlator.clone()))
                .copied(),
        }
    }

    fn resolve_shape(&self, shape: &RecordShape) -> Result<ResolvedRecordShape> {
        let mut parts = Vec::with_capacity(shape.parts.len());
        for part in &shape.parts {
            let responds_to = part
                .responds_to
                .as_ref()
                .and_then(|reference| self.resolve_tool_part(reference));
            parts.push(content_part_id(part.ordinal, part.fact, responds_to)?);
        }
        Ok(ResolvedRecordShape {
            timestamp: shape.timestamp,
            parts,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedRecordShape {
    timestamp: Option<Inline<NsTAIInterval>>,
    parts: Vec<Id>,
}

fn alias_quotient(
    keys: &BTreeSet<SourceKey>,
    aliases: &BTreeSet<(SourceKey, SourceKey)>,
) -> HashMap<SourceKey, SourceKey> {
    let ordered = keys.iter().cloned().collect::<Vec<_>>();
    let indices = ordered
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, key)| (key, index))
        .collect::<HashMap<_, _>>();
    let mut disjoint = DisjointSet::new(ordered.len());
    for (destination, origin) in aliases {
        disjoint.union(indices[destination], indices[origin]);
    }
    let mut representatives = HashMap::<usize, SourceKey>::new();
    for (index, key) in ordered.iter().enumerate() {
        let root = disjoint.find(index);
        representatives
            .entry(root)
            .and_modify(|current| {
                if key < current {
                    *current = key.clone();
                }
            })
            .or_insert_with(|| key.clone());
    }
    ordered
        .into_iter()
        .enumerate()
        .map(|(index, key)| {
            let representative = representatives[&disjoint.find(index)].clone();
            (key, representative)
        })
        .collect()
}

struct DisjointSet {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl DisjointSet {
    fn new(len: usize) -> Self {
        Self {
            parent: (0..len).collect(),
            rank: vec![0; len],
        }
    }

    fn find(&mut self, index: usize) -> usize {
        if self.parent[index] != index {
            self.parent[index] = self.find(self.parent[index]);
        }
        self.parent[index]
    }

    fn union(&mut self, left: usize, right: usize) {
        let left = self.find(left);
        let right = self.find(right);
        if left == right {
            return;
        }
        match self.rank[left].cmp(&self.rank[right]) {
            std::cmp::Ordering::Less => self.parent[left] = right,
            std::cmp::Ordering::Greater => self.parent[right] = left,
            std::cmp::Ordering::Equal => {
                self.parent[right] = left;
                self.rank[left] += 1;
            }
        }
    }
}

fn content_part_id(ordinal: u64, fact: Id, responds_to: Option<Id>) -> Result<Id> {
    blockdag::content_part(
        ordinal,
        Fragment::rooted(fact, TribleSet::new()),
        responds_to,
    )?
    .root()
    .ok_or_else(|| anyhow!("canonical content-part constructor returned no root"))
}

fn build_block_ids(
    semantic: &HashSet<SourceKey>,
    parents: &HashMap<SourceKey, BTreeSet<SourceKey>>,
    shapes: &HashMap<SourceKey, ResolvedRecordShape>,
) -> Result<HashMap<SourceKey, Id>> {
    let mut dependencies = HashMap::new();
    let mut children: HashMap<SourceKey, BTreeSet<SourceKey>> = HashMap::new();
    let mut ready = BTreeSet::new();
    for key in semantic {
        let count = parents
            .get(key)
            .into_iter()
            .flatten()
            .filter(|parent| semantic.contains(*parent))
            .count();
        dependencies.insert(key.clone(), count);
        if count == 0 {
            ready.insert(key.clone());
        }
        for parent in parents
            .get(key)
            .into_iter()
            .flatten()
            .filter(|parent| semantic.contains(*parent))
        {
            children
                .entry(parent.clone())
                .or_default()
                .insert(key.clone());
        }
    }

    let mut blocks = HashMap::with_capacity(semantic.len());
    while let Some(key) = ready.pop_first() {
        let shape = shapes.get(&key).ok_or_else(|| {
            anyhow!(
                "semantic Claude Code alias class {} has no payload",
                key.locator()
            )
        })?;
        let predecessors = parents
            .get(&key)
            .into_iter()
            .flatten()
            .filter_map(|parent| blocks.get(parent).copied())
            .collect::<BTreeSet<_>>();
        let parts = Fragment::new(shape.parts.iter().copied(), TribleSet::new());
        let block = blockdag::block(predecessors, shape.timestamp, parts)?
            .root()
            .ok_or_else(|| anyhow!("canonical block constructor returned no root"))?;
        blocks.insert(key.clone(), block);

        for child in children.get(&key).into_iter().flatten() {
            let remaining = dependencies
                .get_mut(child)
                .expect("every semantic child has a dependency count");
            *remaining -= 1;
            if *remaining == 0 {
                ready.insert(child.clone());
            }
        }
    }
    if blocks.len() != semantic.len() {
        bail!("semantic Claude Code source cycle remains after normalization");
    }
    Ok(blocks)
}

fn source_projection_id(source: &SourceKey, raw_digest: [u8; 32], block: Id) -> Id {
    let locator: Inline<Handle<UTF8String>> =
        Handle::from_hash(Inline::new(Blake3::digest(source.locator().as_bytes())));
    let raw_record: Inline<Handle<RawBytes>> = Handle::from_hash(Inline::new(raw_digest));
    entity! { _ @
        schema::source_projection::source_namespace:
            &schema::source_projection::SOURCE_CLAUDE_CODE,
        schema::source_projection::source_locator: locator,
        schema::source_projection::raw_record: raw_record,
        schema::source_projection::projects_to: &block,
    }
    .root()
    .expect("intrinsic source projection exports one root")
}

fn sorted_source_keys(keys: &HashSet<SourceKey>) -> Vec<SourceKey> {
    let mut keys = keys.iter().cloned().collect::<Vec<_>>();
    keys.sort();
    keys
}

fn semantic_frontier(
    key: &SourceKey,
    semantic: &HashSet<SourceKey>,
    normalized: &HashMap<SourceKey, BTreeSet<SourceKey>>,
    memo: &mut HashMap<SourceKey, BTreeSet<SourceKey>>,
) -> Result<BTreeSet<SourceKey>> {
    if semantic.contains(key) {
        return Ok(BTreeSet::from([key.clone()]));
    }
    if let Some(frontier) = memo.get(key) {
        return Ok(frontier.clone());
    }
    if !normalized.contains_key(key) {
        // A referenced source absent from this corpus remains explicit so the
        // projection pass can account it as unresolved rather than silently
        // turning a non-root into a root.
        return Ok(BTreeSet::from([key.clone()]));
    }

    // Source histories can be hundreds of thousands of records deep. Keep
    // that depth on the heap rather than coupling it to the process stack.
    let mut active = HashSet::new();
    let mut stack = vec![(key.clone(), false)];
    while let Some((current, exiting)) = stack.pop() {
        if semantic.contains(&current) || !normalized.contains_key(&current) {
            continue;
        }
        if memo.contains_key(&current) {
            continue;
        }
        if exiting {
            let mut frontier = BTreeSet::new();
            for parent in normalized
                .get(&current)
                .expect("known transparent source retains its parent set")
            {
                if semantic.contains(parent) || !normalized.contains_key(parent) {
                    frontier.insert(parent.clone());
                } else {
                    frontier.extend(
                        memo.get(parent)
                            .expect("transparent predecessor exits before its child")
                            .iter()
                            .cloned(),
                    );
                }
            }
            active.remove(&current);
            memo.insert(current, frontier);
            continue;
        }
        if !active.insert(current.clone()) {
            bail!(
                "transparent Claude Code source cycle remains after telemetry normalization at {}",
                current.locator()
            );
        }
        stack.push((current.clone(), true));
        for parent in normalized
            .get(&current)
            .expect("known transparent source retains its parent set")
            .iter()
            .rev()
        {
            if active.contains(parent) {
                bail!(
                    "transparent Claude Code source cycle remains after telemetry normalization at {} -> {}",
                    current.locator(),
                    parent.locator()
                );
            }
            if !semantic.contains(parent)
                && normalized.contains_key(parent)
                && !memo.contains_key(parent)
            {
                stack.push((parent.clone(), false));
            }
        }
    }
    Ok(memo
        .get(key)
        .expect("requested transparent source receives a memoized frontier")
        .clone())
}

fn validate_semantic_dag(
    semantic: &HashSet<SourceKey>,
    parents: &HashMap<SourceKey, BTreeSet<SourceKey>>,
) -> Result<()> {
    let mut visited = HashSet::new();
    for key in sorted_source_keys(semantic) {
        if visited.contains(&key) {
            continue;
        }
        let mut active = HashSet::new();
        let mut stack = vec![(key, false)];
        while let Some((current, exiting)) = stack.pop() {
            if visited.contains(&current) {
                continue;
            }
            if exiting {
                active.remove(&current);
                visited.insert(current);
                continue;
            }
            if !active.insert(current.clone()) {
                bail!(
                    "semantic Claude Code source cycle remains after normalization at {}",
                    current.locator()
                );
            }
            stack.push((current.clone(), true));
            for parent in parents.get(&current).into_iter().flatten().rev() {
                if !semantic.contains(parent) || visited.contains(parent) {
                    continue;
                }
                if active.contains(parent) {
                    bail!(
                        "semantic Claude Code source cycle remains after normalization at {} -> {}",
                        current.locator(),
                        parent.locator()
                    );
                }
                stack.push((parent.clone(), false));
            }
        }
    }
    Ok(())
}

fn project_directory<F>(root: &Path, emit: &mut F) -> Result<ProjectionSummary>
where
    F: FnMut(ProjectedFile) -> Result<()>,
{
    let mut paths = Vec::new();
    collect_jsonl_files(root, &mut paths)
        .with_context(|| format!("scan Claude Code source {}", root.display()))?;
    paths.sort();

    let scanned: Vec<Result<PreScan>> = paths.par_iter().map(|path| prescan_file(path)).collect();
    let mut prescans = Vec::with_capacity(scanned.len());
    for (path, scan) in paths.iter().zip(scanned) {
        prescans.push(scan.with_context(|| format!("pre-scan {}", path.display()))?);
    }
    let plan = SourcePlan::from_scans(&prescans).context("plan canonical Claude Code lineage")?;
    let mut summary = ProjectionSummary {
        files_scanned: paths.len(),
        ..ProjectionSummary::default()
    };

    // The complete record DAG has already fixed every intrinsic id. Freeze and
    // project one physical file at a time: pre-scan may exploit parallelism,
    // but projection never retains several multi-gigabyte snapshots or
    // per-file fragment unions concurrently.
    for (path, prescan) in paths.iter().zip(&prescans) {
        let snapshot = archive_source::freeze_file(path)?;
        let projected = project_snapshot(
            path,
            snapshot,
            prescan.digest,
            prescan.file_anchor.as_ref(),
            &plan,
            emit,
        )
        .with_context(|| format!("project Claude Code file {}", path.display()))?;
        summary.fragments_emitted += projected.fragments_emitted;
        summary.stats.absorb(projected.stats);
    }

    Ok(summary)
}

fn collect_jsonl_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("read directory {}", path.display()))? {
        let entry = entry.context("read directory entry")?;
        let entry_path = entry.path();
        let file_type = entry.file_type().context("read directory-entry type")?;
        if file_type.is_dir() {
            collect_jsonl_files(&entry_path, out)?;
        } else if file_type.is_file()
            && entry_path
                .extension()
                .and_then(|extension| extension.to_str())
                == Some("jsonl")
        {
            out.push(entry_path);
        }
    }
    Ok(())
}

fn prescan_file(path: &Path) -> Result<PreScan> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    prescan_reader(&mut reader, path)
}

fn prescan_reader<R: BufRead>(reader: &mut R, source_path: &Path) -> Result<PreScan> {
    let mut scan = PreScan::default();
    let mut digest = blake3::Hasher::new();
    for_each_jsonl_line(reader, Some(&mut digest), |line_number, raw| {
        let mut bytes = scanner_bytes(raw)?;
        let record = scan_record(&mut bytes).map_err(|error| {
            anyhow!(
                "pre-scan Claude Code record at {}:{}: {error}",
                source_path.display(),
                line_number
            )
        })?;
        let Some(key) = record.source_key() else {
            return Ok(());
        };
        scan.file_anchor.get_or_insert_with(|| key.clone());
        let shape = record_shape(&record, &key)?;
        let semantic = shape.is_some();
        let turn_duration =
            record.record_type == "system" && record.subtype.as_deref() == Some("turn_duration");
        let raw_parent = record
            .parent_uuid
            .as_ref()
            .map(|parent| SourceKey::new(key.session.clone(), parent.clone()));
        let fork_origin = record.fork_origin_key()?;
        if let Some(origin) = &fork_origin {
            scan.aliases.insert((key.clone(), origin.clone()));
        }
        // `forkedFrom` is an explicit identity alias to the named origin. Its
        // destination `parentUuid` describes replay serialization (and can
        // reverse tool chronology), so it remains in the exact raw receipt but
        // is not a canonical semantic ancestry assertion.
        let parent = fork_origin
            .is_none()
            .then_some(raw_parent.clone())
            .flatten();
        let observation = scan.sources.entry(key.clone()).or_default();
        observation.semantic |= semantic;
        observation.turn_duration |= turn_duration;
        observation.non_turn_duration |= !turn_duration;
        if observation.semantic && observation.turn_duration {
            bail!(
                "Claude Code source key {}/{} is both semantic dialogue and turn-duration telemetry",
                key.session,
                key.uuid
            );
        }
        if let Some(parent) = parent {
            observation.parents.insert(parent);
        }
        if let Some(shape) = shape {
            if !observation.shapes.contains(&shape) {
                observation.shapes.push(shape);
            }
            observation
                .raw_records
                .insert(*blake3::hash(raw).as_bytes());
        }
        Ok(())
    })?;
    scan.digest = *digest.finalize().as_bytes();
    Ok(scan)
}

fn project_snapshot<F>(
    source_path: &Path,
    snapshot: archive_source::FrozenSource,
    expected_digest: [u8; 32],
    native_anchor: Option<&SourceKey>,
    plan: &SourcePlan,
    emit: &mut F,
) -> Result<ProjectionSummary>
where
    F: FnMut(ProjectedFile) -> Result<()>,
{
    if snapshot.digest != expected_digest {
        bail!(
            "Claude Code source {} changed between dependency pre-scan and immutable snapshot",
            source_path.display()
        );
    }

    let mut summary = ProjectionSummary {
        files_scanned: 1,
        ..ProjectionSummary::default()
    };
    let mut reader = std::io::Cursor::new(snapshot.bytes.as_ref());

    for_each_jsonl_line(&mut reader, None, |line_number, raw| {
        let mut row_stats = ProjectionStats {
            records_seen: 1,
            ..ProjectionStats::default()
        };
        let mut bytes = scanner_bytes(raw)?;
        let record = scan_record(&mut bytes).map_err(|error| {
            anyhow!(
                "scan Claude Code record at {}:{}: {error}",
                source_path.display(),
                line_number
            )
        })?;
        let mut fragment = Fragment::empty();
        project_record(
            record,
            raw,
            source_path,
            plan,
            &mut fragment,
            &mut row_stats,
        )
        .with_context(|| {
            format!(
                "project Claude Code record at {}:{}",
                source_path.display(),
                line_number
            )
        })?;
        summary.stats.absorb(row_stats);
        if !fragment.facts().is_empty() {
            emit(ProjectedFile {
                source_path: source_path.to_path_buf(),
                fragment,
                stats: row_stats,
            })?;
            summary.fragments_emitted += 1;
        }
        Ok(())
    })?;

    let anchor = native_anchor.map_or_else(
        || {
            let first = snapshot.bytes.slice(
                0..snapshot
                    .bytes
                    .len()
                    .min(schema::source_chunk::CANONICAL_BYTES),
            );
            format!("digest/{}", blake3::hash(first.as_ref()).to_hex())
        },
        |key| format!("native/{}", key.locator()),
    );
    // Chunks are reusable content-addressed values, while the snapshot root
    // records which exact ordered sequence and length coexisted. They are not
    // dialogue projections and therefore never pollute projection queries.
    let (fragment, raw_chunks) = archive_source::source_snapshot_fragment(
        schema::source_projection::SOURCE_CLAUDE_CODE,
        &anchor,
        source_path,
        &snapshot.bytes,
    )?;
    let snapshot_stats = ProjectionStats {
        raw_chunks,
        source_snapshots: 1,
        ..ProjectionStats::default()
    };
    emit(ProjectedFile {
        source_path: source_path.to_path_buf(),
        fragment,
        stats: snapshot_stats,
    })?;
    summary.fragments_emitted += 1;
    summary.stats.absorb(snapshot_stats);

    Ok(summary)
}

#[cfg(test)]
struct Projected {
    fragment: Fragment,
    stats: ProjectionStats,
}

fn for_each_jsonl_line<R, F>(
    reader: &mut R,
    mut digest: Option<&mut blake3::Hasher>,
    mut visit: F,
) -> Result<()>
where
    R: BufRead,
    F: FnMut(usize, &[u8]) -> Result<()>,
{
    let mut buffer = Vec::new();
    let mut line_number = 0usize;
    loop {
        buffer.clear();
        let read = reader.read_until(b'\n', &mut buffer)?;
        if read == 0 {
            break;
        }
        if let Some(digest) = digest.as_deref_mut() {
            digest.update(&buffer);
        }
        line_number += 1;
        if buffer.last() == Some(&b'\n') {
            buffer.pop();
        }
        if buffer.last() == Some(&b'\r') {
            buffer.pop();
        }
        if buffer.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        visit(line_number, &buffer)?;
    }
    Ok(())
}

fn scanner_bytes(raw: &[u8]) -> Result<Bytes> {
    let first = raw
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .ok_or_else(|| anyhow!("empty JSONL record"))?;
    let last = raw
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .expect("a first non-whitespace byte implies a last byte");
    Ok(Bytes::from_source(raw[first..=last].to_vec()))
}

fn project_record(
    record: RawRecord,
    raw_record: &[u8],
    source_path: &Path,
    plan: &SourcePlan,
    corpus: &mut Fragment,
    stats: &mut ProjectionStats,
) -> Result<()> {
    let direction = match record.record_type.as_str() {
        "user" => schema::content_fact::direction::IN,
        "assistant" => schema::content_fact::direction::OUT,
        _ => {
            stats.skipped_records += 1;
            return Ok(());
        }
    };

    let Some(key) = record.source_key() else {
        stats.missing_source_identity += 1;
        stats.skipped_records += 1;
        return Ok(());
    };
    let class = plan.canonical_key(&key);
    let mut parts = Fragment::empty();
    let mut ordinal = 0u64;
    for content in &record.blocks {
        let responds_to = if content.kind == BlockKind::ToolResult {
            content.correlator.as_ref().and_then(|correlator| {
                let reference = ToolReference {
                    source: record
                        .source_tool_assistant_uuid
                        .as_ref()
                        .map(|uuid| SourceKey::new(key.session.clone(), uuid.clone())),
                    session: key.session.clone(),
                    correlator: correlator.clone(),
                };
                let target = plan.resolve_tool_part(&reference);
                if target.is_none() {
                    stats.unresolved_tool_results += 1;
                }
                target
            })
        } else {
            None
        };
        for item in &content.items {
            let Some(fact) = project_item(item, content.kind, direction, stats)? else {
                continue;
            };
            let part = blockdag::content_part(ordinal, fact, responds_to)?;
            parts += part;
            ordinal = ordinal.checked_add(1).ok_or_else(|| {
                anyhow!("Claude Code record has more than u64::MAX content parts")
            })?;
            stats.content_parts += 1;
        }
    }

    if parts.exports().next().is_none() {
        stats.skipped_records += 1;
        return Ok(());
    }

    let planned_parents = plan.parents.get(&class).ok_or_else(|| {
        anyhow!(
            "projectable Claude Code source {} was absent from its source plan",
            key.locator()
        )
    })?;
    if record.forked_from.is_none() && record.parent_uuid.is_some() && planned_parents.is_empty() {
        // The observed edge ended at a known transparent root after canonical
        // contraction. This is distinct from a corpus-external predecessor,
        // which remains in `planned_parents` and is counted as unresolved.
        stats.skipped_parents += 1;
    }
    let mut predecessors = BTreeSet::new();
    let mut semantic_predecessor_support = BTreeSet::new();
    for parent_key in planned_parents {
        if let Some(block) = plan.blocks.get(parent_key) {
            predecessors.insert(*block);
            semantic_predecessor_support.extend(
                plan.projection_ids
                    .get(parent_key)
                    .into_iter()
                    .flatten()
                    .copied(),
            );
        } else {
            stats.unresolved_parents += 1;
        }
    }

    let timestamp = record.timestamp.and_then(epoch_interval);
    let block = blockdag::block(predecessors, timestamp, parts)?;
    let block_id = block
        .root()
        .expect("canonical block constructor returns one root");
    let planned_block = plan.blocks.get(&class).ok_or_else(|| {
        anyhow!(
            "projectable Claude Code alias class {} has no planned block",
            class.locator()
        )
    })?;
    if block_id != *planned_block {
        bail!(
            "Claude Code source {} materialized block {block_id:x}, expected {planned_block:x}",
            key.locator()
        );
    }

    let projection = blockdag::source_projection(
        schema::source_projection::SOURCE_CLAUDE_CODE,
        key.locator(),
        raw_record.to_vec(),
        block,
    )?;
    let annotations = blockdag::ProjectionAnnotations {
        semantic_predecessor_support: semantic_predecessor_support.into_iter().collect(),
        source_timestamp: timestamp,
        raw_role: record.role,
        raw_model: record.model,
        source_path: Some(source_path.to_string_lossy().into_owned()),
        ..blockdag::ProjectionAnnotations::default()
    };
    let projection = blockdag::annotate_source_projection(projection, annotations)?;
    let projection_id = projection
        .root()
        .expect("canonical source-projection constructor returns one root");
    if !plan
        .projection_ids
        .get(&class)
        .is_some_and(|ids| ids.contains(&projection_id))
    {
        bail!(
            "Claude Code source {} materialized an unplanned projection identity",
            key.locator()
        );
    }
    *corpus += projection;
    stats.source_projections += 1;
    Ok(())
}

fn project_item(
    item: &RawItem,
    block_kind: BlockKind,
    record_direction: Id,
    stats: &mut ProjectionStats,
) -> Result<Option<Fragment>> {
    match item {
        RawItem::Text(text) => {
            if text.trim().is_empty() {
                return Ok(None);
            }
            let (modality, direction) = match block_kind {
                BlockKind::Text => (schema::content_fact::modality::TEXT, record_direction),
                BlockKind::Thinking => (
                    schema::content_fact::modality::THINKING,
                    schema::content_fact::direction::OUT,
                ),
                BlockKind::ToolUse => (
                    schema::content_fact::modality::TOOL_CALL,
                    schema::content_fact::direction::OUT,
                ),
                BlockKind::ToolResult => (
                    schema::content_fact::modality::TOOL_RESULT,
                    schema::content_fact::direction::IN,
                ),
                BlockKind::Image | BlockKind::Other => return Ok(None),
            };
            Ok(Some(blockdag::text_fact(
                modality,
                direction,
                text.clone(),
            )?))
        }
        RawItem::Image(image) => {
            let direction = if block_kind == BlockKind::ToolResult {
                schema::content_fact::direction::IN
            } else {
                record_direction
            };
            project_image(image, direction, stats)
        }
        RawItem::ToolResultStatus(is_error) => {
            let status = if *is_error {
                TOOL_RESULT_STATUS_ERROR
            } else {
                TOOL_RESULT_STATUS_OK
            };
            Ok(Some(blockdag::text_fact(
                schema::content_fact::modality::EVENT,
                schema::content_fact::direction::IN,
                status,
            )?))
        }
    }
}

fn project_image(
    image: &RawImageSource,
    direction: Id,
    stats: &mut ProjectionStats,
) -> Result<Option<Fragment>> {
    if image.source_type == "base64" {
        let Some(data) = image.data.as_deref() else {
            stats.undecodable_images += 1;
            return Ok(None);
        };
        let bytes = match BASE64_STANDARD.decode(data.as_bytes()) {
            Ok(bytes) => bytes,
            Err(_) => {
                stats.undecodable_images += 1;
                return Ok(None);
            }
        };
        let media_type = image
            .media_type
            .as_deref()
            .map(files::normalize_media_type_or_default)
            .unwrap_or_else(|| files::DEFAULT_MEDIA_TYPE.to_owned());
        return Ok(Some(blockdag::blob_fact(
            schema::content_fact::modality::IMAGE,
            direction,
            bytes,
            &media_type,
        )?));
    }

    let Some(pointer) = usable_pointer(image) else {
        stats.undecodable_images += 1;
        return Ok(None);
    };
    let media_type = image
        .media_type
        .as_deref()
        .map(files::normalize_media_type_or_default);
    Ok(Some(blockdag::asset_pointer_fact(
        schema::content_fact::modality::IMAGE,
        direction,
        schema::source_projection::SOURCE_CLAUDE_CODE,
        pointer.clone(),
        media_type.as_deref(),
        image.size,
    )?))
}

fn epoch_interval(epoch: Epoch) -> Option<Inline<NsTAIInterval>> {
    (epoch, epoch).try_to_inline().ok()
}

// ---------------------------------------------------------------------------
// Streaming field scanner
// ---------------------------------------------------------------------------

#[derive(Default)]
struct RawRecord {
    record_type: String,
    subtype: Option<String>,
    session_id: Option<String>,
    uuid: Option<String>,
    parent_uuid: Option<String>,
    forked_from: Option<ForkedFrom>,
    source_tool_assistant_uuid: Option<String>,
    timestamp: Option<Epoch>,
    role: Option<String>,
    model: Option<String>,
    blocks: Vec<RawBlock>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ForkedFrom {
    session_id: Option<String>,
    message_uuid: Option<String>,
}

impl RawRecord {
    fn source_key(&self) -> Option<SourceKey> {
        Some(SourceKey::new(self.session_id.clone()?, self.uuid.clone()?))
    }

    fn fork_origin_key(&self) -> Result<Option<SourceKey>> {
        let Some(forked_from) = &self.forked_from else {
            return Ok(None);
        };
        match (&forked_from.session_id, &forked_from.message_uuid) {
            (Some(session), Some(uuid)) => Ok(Some(SourceKey::new(session.clone(), uuid.clone()))),
            _ => bail!("Claude Code forkedFrom must name both sessionId and messageUuid"),
        }
    }
}

struct RawBlock {
    kind: BlockKind,
    correlator: Option<String>,
    items: Vec<RawItem>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlockKind {
    Text,
    Thinking,
    ToolUse,
    ToolResult,
    Image,
    Other,
}

enum RawItem {
    Text(String),
    Image(RawImageSource),
    ToolResultStatus(bool),
}

fn record_shape(record: &RawRecord, source: &SourceKey) -> Result<Option<RecordShape>> {
    let direction = match record.record_type.as_str() {
        "user" => schema::content_fact::direction::IN,
        "assistant" => schema::content_fact::direction::OUT,
        _ => return Ok(None),
    };
    let explicit_tool_source = record
        .source_tool_assistant_uuid
        .as_ref()
        .map(|uuid| SourceKey::new(source.session.clone(), uuid.clone()));
    let mut parts = Vec::new();
    let mut ordinal = 0u64;
    let mut stats = ProjectionStats::default();
    for block in &record.blocks {
        let responds_to = (block.kind == BlockKind::ToolResult)
            .then(|| {
                block.correlator.as_ref().map(|correlator| ToolReference {
                    source: explicit_tool_source.clone(),
                    session: source.session.clone(),
                    correlator: correlator.clone(),
                })
            })
            .flatten();
        for item in &block.items {
            let Some(fact) = project_item(item, block.kind, direction, &mut stats)? else {
                continue;
            };
            let fact = fact
                .root()
                .expect("canonical content-fact constructor returns one root");
            parts.push(PartShape {
                ordinal,
                fact,
                tool_call_id: (block.kind == BlockKind::ToolUse)
                    .then(|| block.correlator.clone())
                    .flatten(),
                responds_to: responds_to.clone(),
            });
            ordinal = ordinal.checked_add(1).ok_or_else(|| {
                anyhow!("Claude Code record has more than u64::MAX content parts")
            })?;
        }
    }
    if parts.is_empty() {
        Ok(None)
    } else {
        Ok(Some(RecordShape {
            timestamp: record.timestamp.and_then(epoch_interval),
            parts,
        }))
    }
}

fn usable_pointer(image: &RawImageSource) -> Option<&String> {
    let preferred = if image.source_type == "url" {
        [&image.url, &image.file_id]
    } else {
        [&image.file_id, &image.url]
    };
    preferred
        .into_iter()
        .flatten()
        .find(|pointer| !pointer.trim().is_empty())
}

#[derive(Default)]
struct RawImageSource {
    source_type: String,
    media_type: Option<String>,
    data: Option<String>,
    url: Option<String>,
    file_id: Option<String>,
    size: Option<u128>,
}

#[derive(Default)]
struct BlockAccum {
    block_type: String,
    text: Option<String>,
    thinking: Option<String>,
    tool_id: Option<String>,
    tool_name: Option<String>,
    tool_use_id: Option<String>,
    input_raw: Option<Bytes>,
    is_error: Option<bool>,
    tool_result_items: Vec<RawItem>,
    image_source: Option<RawImageSource>,
}

#[derive(Default)]
struct MessagePart {
    role: Option<String>,
    model: Option<String>,
    blocks: Vec<RawBlock>,
}

fn scan_syntax(message: &str) -> sc::ScanError {
    sc::ScanError::Syntax(message.to_owned())
}

fn bytes_to_string(bytes: Bytes) -> std::result::Result<String, sc::ScanError> {
    Ok(bytes
        .view::<str>()
        .map_err(|_| scan_syntax("invalid UTF-8 string"))?
        .as_ref()
        .to_owned())
}

fn parse_optional_string(bytes: &mut Bytes) -> std::result::Result<Option<String>, sc::ScanError> {
    if bytes.first().copied() == Some(b'"') {
        Ok(Some(bytes_to_string(sc::parse_string(bytes)?)?))
    } else {
        sc::skip_value(bytes)?;
        Ok(None)
    }
}

fn capture_raw_json(bytes: &mut Bytes) -> std::result::Result<String, sc::ScanError> {
    let before = bytes.clone();
    sc::skip_value(bytes)?;
    let consumed = before.len() - bytes.len();
    Ok(String::from_utf8_lossy(before.slice(0..consumed).as_ref()).into_owned())
}

fn scan_record(bytes: &mut Bytes) -> std::result::Result<RawRecord, sc::ScanError> {
    let mut record = RawRecord::default();
    sc::object(bytes, &mut record, |record, key, value| {
        let key = key
            .view::<str>()
            .map_err(|_| scan_syntax("invalid UTF-8 object key"))?;
        match key.as_ref() {
            "type" => record.record_type = parse_optional_string(value)?.unwrap_or_default(),
            "subtype" => record.subtype = parse_optional_string(value)?,
            "sessionId" => record.session_id = parse_optional_string(value)?,
            "uuid" => record.uuid = parse_optional_string(value)?,
            "parentUuid" => record.parent_uuid = parse_optional_string(value)?,
            "forkedFrom" => record.forked_from = scan_optional_forked_from(value)?,
            "sourceToolAssistantUUID" => {
                record.source_tool_assistant_uuid = parse_optional_string(value)?
            }
            "timestamp" => {
                record.timestamp = parse_optional_string(value)?
                    .as_deref()
                    .and_then(parse_iso_timestamp)
            }
            "message" => {
                let message = scan_message(value)?;
                record.role = message.role;
                record.model = message.model;
                record.blocks = message.blocks;
            }
            _ => sc::skip_value(value)?,
        }
        Ok(record)
    })?;
    Ok(record)
}

fn scan_optional_forked_from(
    bytes: &mut Bytes,
) -> std::result::Result<Option<ForkedFrom>, sc::ScanError> {
    if bytes.first().copied() != Some(b'{') {
        sc::skip_value(bytes)?;
        return Ok(None);
    }
    let mut forked_from = ForkedFrom::default();
    sc::object(bytes, &mut forked_from, |forked_from, key, value| {
        let key = key
            .view::<str>()
            .map_err(|_| scan_syntax("invalid UTF-8 object key"))?;
        match key.as_ref() {
            "sessionId" => forked_from.session_id = parse_optional_string(value)?,
            "messageUuid" => forked_from.message_uuid = parse_optional_string(value)?,
            _ => sc::skip_value(value)?,
        }
        Ok(forked_from)
    })?;
    Ok(Some(forked_from))
}

fn scan_message(bytes: &mut Bytes) -> std::result::Result<MessagePart, sc::ScanError> {
    let mut message = MessagePart::default();
    sc::object(bytes, &mut message, |message, key, value| {
        let key = key
            .view::<str>()
            .map_err(|_| scan_syntax("invalid UTF-8 object key"))?;
        match key.as_ref() {
            "role" => message.role = parse_optional_string(value)?,
            "model" => message.model = parse_optional_string(value)?,
            "content" => message.blocks = scan_content(value)?,
            _ => sc::skip_value(value)?,
        }
        Ok(message)
    })?;
    Ok(message)
}

fn scan_content(bytes: &mut Bytes) -> std::result::Result<Vec<RawBlock>, sc::ScanError> {
    match bytes.first().copied() {
        Some(b'"') => Ok(vec![RawBlock {
            kind: BlockKind::Text,
            correlator: None,
            items: vec![RawItem::Text(bytes_to_string(sc::parse_string(bytes)?)?)],
        }]),
        Some(b'[') => {
            let mut blocks = Vec::new();
            sc::array(bytes, &mut blocks, |blocks, element| {
                blocks.push(scan_content_block(element)?);
                Ok(blocks)
            })?;
            Ok(blocks)
        }
        _ => {
            sc::skip_value(bytes)?;
            Ok(Vec::new())
        }
    }
}

fn scan_content_block(bytes: &mut Bytes) -> std::result::Result<RawBlock, sc::ScanError> {
    let mut block = BlockAccum::default();
    sc::object(bytes, &mut block, |block, key, value| {
        let key = key
            .view::<str>()
            .map_err(|_| scan_syntax("invalid UTF-8 object key"))?;
        match key.as_ref() {
            "type" => block.block_type = parse_optional_string(value)?.unwrap_or_default(),
            "text" => block.text = parse_optional_string(value)?,
            "thinking" => block.thinking = parse_optional_string(value)?,
            "signature" => sc::skip_value(value)?,
            "id" => block.tool_id = parse_optional_string(value)?,
            "name" => block.tool_name = parse_optional_string(value)?,
            "tool_use_id" => block.tool_use_id = parse_optional_string(value)?,
            "input" => block.input_raw = Some(sc::take_value(value)?),
            "is_error" => block.is_error = parse_optional_bool(value)?,
            "content" => block.tool_result_items = scan_tool_result_content(value)?,
            "source" => block.image_source = scan_optional_image_source(value)?,
            _ => sc::skip_value(value)?,
        }
        Ok(block)
    })?;
    build_block(block)
}

fn build_block(block: BlockAccum) -> std::result::Result<RawBlock, sc::ScanError> {
    Ok(match block.block_type.as_str() {
        "text" => RawBlock {
            kind: BlockKind::Text,
            correlator: None,
            items: block.text.into_iter().map(RawItem::Text).collect(),
        },
        "thinking" => RawBlock {
            kind: BlockKind::Thinking,
            correlator: None,
            items: block.thinking.into_iter().map(RawItem::Text).collect(),
        },
        "tool_use" => RawBlock {
            kind: BlockKind::ToolUse,
            correlator: block.tool_id,
            items: vec![RawItem::Text(canonical_tool_call(
                block.tool_name,
                block.input_raw,
            )?)],
        },
        "tool_result" => {
            let mut items = Vec::with_capacity(
                block.tool_result_items.len() + usize::from(block.is_error.is_some()),
            );
            items.extend(block.is_error.map(RawItem::ToolResultStatus));
            items.extend(block.tool_result_items);
            RawBlock {
                kind: BlockKind::ToolResult,
                correlator: block.tool_use_id,
                items,
            }
        }
        "image" => RawBlock {
            kind: BlockKind::Image,
            correlator: None,
            items: block.image_source.into_iter().map(RawItem::Image).collect(),
        },
        _ => RawBlock {
            kind: BlockKind::Other,
            correlator: None,
            items: Vec::new(),
        },
    })
}

fn parse_optional_bool(bytes: &mut Bytes) -> std::result::Result<Option<bool>, sc::ScanError> {
    let raw = capture_raw_json(bytes)?;
    Ok(match raw.trim() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    })
}

fn canonical_tool_call(
    name: Option<String>,
    input: Option<Bytes>,
) -> std::result::Result<String, sc::ScanError> {
    let name = match name {
        Some(name) => archive_source::canonical_json_string(&name),
        None => "null".to_owned(),
    };
    let input = match input {
        Some(raw) => archive_source::canonical_json(raw)?,
        None => "null".to_owned(),
    };
    Ok(format!(r#"{{"name":{name},"input":{input}}}"#))
}

fn scan_tool_result_content(bytes: &mut Bytes) -> std::result::Result<Vec<RawItem>, sc::ScanError> {
    match bytes.first().copied() {
        Some(b'"') => Ok(vec![RawItem::Text(bytes_to_string(sc::parse_string(
            bytes,
        )?)?)]),
        Some(b'[') => {
            let mut items = Vec::new();
            sc::array(bytes, &mut items, |items, element| {
                if let Some(item) = scan_tool_result_item(element)? {
                    items.push(item);
                }
                Ok(items)
            })?;
            Ok(items)
        }
        _ => Ok(vec![RawItem::Text(capture_raw_json(bytes)?)]),
    }
}

#[derive(Default)]
struct ToolResultItem {
    item_type: String,
    text: Option<String>,
    source: Option<RawImageSource>,
}

fn scan_tool_result_item(bytes: &mut Bytes) -> std::result::Result<Option<RawItem>, sc::ScanError> {
    if bytes.first().copied() == Some(b'"') {
        return Ok(Some(RawItem::Text(bytes_to_string(sc::parse_string(
            bytes,
        )?)?)));
    }
    if bytes.first().copied() != Some(b'{') {
        sc::skip_value(bytes)?;
        return Ok(None);
    }

    let mut item = ToolResultItem::default();
    sc::object(bytes, &mut item, |item, key, value| {
        let key = key
            .view::<str>()
            .map_err(|_| scan_syntax("invalid UTF-8 object key"))?;
        match key.as_ref() {
            "type" => item.item_type = parse_optional_string(value)?.unwrap_or_default(),
            "text" => item.text = parse_optional_string(value)?,
            "source" => item.source = scan_optional_image_source(value)?,
            _ => sc::skip_value(value)?,
        }
        Ok(item)
    })?;
    if item.item_type == "image" {
        Ok(item.source.map(RawItem::Image))
    } else {
        Ok(item.text.map(RawItem::Text))
    }
}

fn scan_optional_image_source(
    bytes: &mut Bytes,
) -> std::result::Result<Option<RawImageSource>, sc::ScanError> {
    if bytes.first().copied() != Some(b'{') {
        sc::skip_value(bytes)?;
        return Ok(None);
    }
    let mut source = RawImageSource::default();
    let mut file_size = None;
    let mut legacy_size = None;
    sc::object(bytes, &mut source, |source, key, value| {
        let key = key
            .view::<str>()
            .map_err(|_| scan_syntax("invalid UTF-8 object key"))?;
        match key.as_ref() {
            "type" => source.source_type = parse_optional_string(value)?.unwrap_or_default(),
            "media_type" => source.media_type = parse_optional_string(value)?,
            "data" => source.data = parse_optional_string(value)?,
            "url" => source.url = parse_optional_string(value)?,
            "file_id" => source.file_id = parse_optional_string(value)?,
            "file_size" => file_size = Some(capture_raw_json(value)?.trim().parse::<u128>().ok()),
            "size" => legacy_size = Some(capture_raw_json(value)?.trim().parse::<u128>().ok()),
            _ => sc::skip_value(value)?,
        }
        Ok(source)
    })?;
    source.size = file_size.unwrap_or_else(|| legacy_size.flatten());
    Ok(Some(source))
}

fn parse_iso_timestamp(value: &str) -> Option<Epoch> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        value.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::io::Cursor;

    use tempfile::TempDir;
    use triblespace::core::metadata;
    use triblespace::core::repo::pile::{Pile, PileSnapshot};
    use triblespace::core::repo::BlobStoreGet;
    use triblespace::prelude::blobencodings::{RawBytes, UTF8String};
    use triblespace::prelude::inlineencodings::Handle;

    use super::*;
    const SINGLE_FILE: &str = r#"{"type":"user","sessionId":"session-1","uuid":"u1","parentUuid":null,"timestamp":"2026-03-01T15:34:01.542Z","message":{"role":"user","content":"hello there"}}
{"type":"assistant","sessionId":"session-1","uuid":"a1","parentUuid":"u1","timestamp":"2026-03-01T15:34:02.000Z","message":{"role":"assistant","model":"claude-opus-4","content":[{"type":"thinking","thinking":"consider it","signature":"opaque"},{"type":"text","text":"hi!"},{"type":"tool_use","id":"toolu_1","name":"Screenshot","input":{"display":1}}]}}
{"type":"user","sessionId":"session-1","uuid":"u2","parentUuid":"a1","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"text","text":"screenshot below"},{"type":"image","source":{"type":"base64","media_type":"IMAGE/PNG; charset=binary","data":"iVBORw=="}}]}]}}"#;

    fn prescan_text(text: &str, path: &Path) -> PreScan {
        let mut cursor = Cursor::new(text.as_bytes());
        prescan_reader(&mut cursor, path).unwrap()
    }

    fn project_text(text: &str, path: &Path) -> Projected {
        let prescan = prescan_text(text, path);
        let plan = SourcePlan::from_scans(std::slice::from_ref(&prescan)).unwrap();
        let bytes = Bytes::from_source(text.as_bytes().to_vec());
        let snapshot = archive_source::FrozenSource {
            digest: *blake3::hash(bytes.as_ref()).as_bytes(),
            bytes,
        };
        let mut fragment = Fragment::empty();
        let summary = project_snapshot(
            path,
            snapshot,
            prescan.digest,
            prescan.file_anchor.as_ref(),
            &plan,
            &mut |projected| {
                fragment += projected.fragment;
                Ok(())
            },
        )
        .unwrap();
        Projected {
            fragment,
            stats: summary.stats,
        }
    }

    fn empty_reader() -> (TempDir, PileSnapshot) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("empty.pile");
        File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        let reader = pile.snapshot().unwrap();
        pile.close().unwrap();
        (directory, reader)
    }

    fn ids_with_tag(fragment: &Fragment, tag: Id) -> BTreeSet<Id> {
        find!(
            entity: Id,
            pattern!(fragment.facts(), [{ ?entity @ metadata::tag: &tag }])
        )
        .collect()
    }

    fn block_with_payload(fragment: &Fragment, needle: &str) -> Id {
        let mut fragment = fragment.clone();
        let reader = fragment.blobs_mut().snapshot().unwrap();
        for (block, payload) in find!(
            (block: Id, payload: Inline<Handle<UTF8String>>),
            pattern!(fragment.facts(), [
                { ?block @ schema::block::contains: _?part },
                { _?part @ schema::content_part::fact: _?fact },
                { _?fact @ schema::content_fact::payload: ?payload },
            ])
        ) {
            let text: anybytes::View<str> = reader.get(payload).unwrap();
            if text.as_ref() == needle {
                return block;
            }
        }
        panic!("no block contains payload {needle:?}");
    }

    fn projection_for_block(fragment: &Fragment, block: Id) -> Id {
        find!(
            projection: Id,
            pattern!(fragment.facts(), [{
                ?projection @ schema::source_projection::projects_to: &block
            }])
        )
        .next()
        .expect("block has a source projection")
    }

    fn projections_for_block(fragment: &Fragment, block: Id) -> BTreeSet<Id> {
        find!(
            projection: Id,
            pattern!(fragment.facts(), [{
                ?projection @ schema::source_projection::projects_to: &block
            }])
        )
        .collect()
    }

    fn raw_projection_record(fragment: &Fragment, projection: Id) -> Vec<u8> {
        let handle = find!(
            raw: Inline<Handle<RawBytes>>,
            pattern!(fragment.facts(), [{
                projection @ schema::source_projection::raw_record: ?raw
            }])
        )
        .next()
        .expect("projection has one exact raw record");
        let mut fragment = fragment.clone();
        let reader = fragment.blobs_mut().snapshot().unwrap();
        let raw: anybytes::Bytes = reader.get(handle).unwrap();
        raw.as_ref().to_vec()
    }

    fn source_chunk_raws(fragment: &Fragment) -> Vec<(Id, u128, Bytes)> {
        let mut blobs = fragment.blobs().clone();
        let reader = blobs.snapshot().unwrap();
        find!(
            (
                chunk: Id,
                offset: Inline<triblespace::prelude::inlineencodings::U256BE>,
                raw: Inline<Handle<RawBytes>>
            ),
            pattern!(fragment.facts(), [
                { ?chunk @ metadata::tag: &schema::source_chunk::KIND },
                { ?chunk @ schema::source_chunk::offset: ?offset },
                { ?chunk @ schema::source_chunk::bytes: ?raw },
            ])
        )
        .map(|(chunk, offset, raw)| {
            let offset = u128::try_from_inline(&offset).unwrap();
            let raw = reader.get::<Bytes, RawBytes>(raw).unwrap();
            (chunk, offset, raw)
        })
        .collect()
    }

    fn exact_source_snapshot(fragment: &Fragment) -> Vec<u8> {
        let snapshots = ids_with_tag(fragment, schema::source_snapshot::KIND);
        assert_eq!(snapshots.len(), 1, "expected exactly one source snapshot");
        let snapshot = *snapshots.first().unwrap();
        let selected: BTreeSet<_> = find!(
            chunk: Id,
            pattern!(fragment.facts(), [{
                snapshot @ schema::source_snapshot::contains: ?chunk
            }])
        )
        .collect();
        let mut chunks = source_chunk_raws(fragment)
            .into_iter()
            .filter(|(chunk, _, _)| selected.contains(chunk))
            .collect::<Vec<_>>();
        chunks.sort_by_key(|(_, offset, _)| *offset);
        chunks
            .into_iter()
            .flat_map(|(_, _, bytes)| bytes.as_ref().to_vec())
            .collect()
    }

    #[test]
    fn precomputed_projection_identity_matches_the_canonical_constructor() {
        let source = SourceKey::new("identity-session", "identity-record");
        let raw = br#"{"exact":true}"#;
        let block = Id::from_hex("11111111111111111111111111111111").unwrap();
        let expected = blockdag::source_projection(
            schema::source_projection::SOURCE_CLAUDE_CODE,
            source.locator(),
            raw.to_vec(),
            Fragment::rooted(block, TribleSet::new()),
        )
        .unwrap()
        .root()
        .unwrap();
        assert_eq!(
            source_projection_id(&source, *blake3::hash(raw).as_bytes(), block),
            expected
        );
    }

    #[test]
    fn projection_is_canonical_and_does_not_fabricate_missing_time_or_actors() {
        let projected = project_text(SINGLE_FILE, Path::new("/imports/session.jsonl"));
        assert_eq!(projected.stats.source_projections, 3);
        assert_eq!(projected.stats.source_snapshots, 1);
        assert_eq!(projected.stats.raw_chunks, 1);
        assert_eq!(projected.stats.content_parts, 6);
        assert_eq!(projected.stats.unresolved_tool_results, 0);
        assert_eq!(projected.stats.undecodable_images, 0);

        let (_directory, reader) = empty_reader();
        let (_, validation) =
            blockdag::validate_catalog_union(&reader, &TribleSet::new(), &projected.fragment)
                .unwrap();
        assert_eq!(validation, blockdag::CatalogValidation::Accepted);

        let without_time = block_with_payload(&projected.fragment, "screenshot below");
        assert!(!exists!(pattern!(&projected.fragment, [{
            without_time @ schema::block::timestamp: _?timestamp
        }])));

        for projection in ids_with_tag(&projected.fragment, schema::source_projection::KIND) {
            assert!(!exists!(pattern!(&projected.fragment, [{
                projection @ schema::source_projection::author: _?author
            }])));
            assert!(!exists!(pattern!(&projected.fragment, [{
                projection @ schema::source_projection::experiencer: _?experiencer
            }])));
        }
    }

    #[test]
    fn replay_and_source_move_preserve_intrinsic_identities() {
        let first = project_text(SINGLE_FILE, Path::new("/first/session.jsonl"));
        let replay = project_text(SINGLE_FILE, Path::new("/first/session.jsonl"));
        assert_eq!(first.fragment.facts(), replay.fragment.facts());

        let moved = project_text(SINGLE_FILE, Path::new("/moved/session.jsonl"));
        assert_eq!(
            ids_with_tag(&first.fragment, schema::block::KIND),
            ids_with_tag(&moved.fragment, schema::block::KIND),
        );
        assert_eq!(
            ids_with_tag(&first.fragment, schema::source_projection::KIND),
            ids_with_tag(&moved.fragment, schema::source_projection::KIND),
        );
        assert_ne!(
            first.fragment.facts(),
            moved.fragment.facts(),
            "the path remains additive occurrence evidence"
        );
    }

    #[test]
    fn skipped_source_nodes_transparently_contract_to_the_nearest_projected_ancestor() {
        let child_raw = r#"{"type":"assistant","sessionId":"contract","uuid":"child","parentUuid":"empty","message":{"role":"assistant","model":"claude","content":"after metadata"}}"#;
        let source = format!(
            "{}\n{}\n{}\n{}\n{child_raw}",
            r#"{"type":"user","sessionId":"contract","uuid":"root","parentUuid":null,"message":{"role":"user","content":"before metadata"}}"#,
            r#"{"type":"attachment","sessionId":"contract","uuid":"attachment","parentUuid":"root","attachment":{"type":"skill_listing"}}"#,
            r#"{"type":"system","sessionId":"contract","uuid":"system","parentUuid":"attachment","content":"metadata"}"#,
            r#"{"type":"user","sessionId":"contract","uuid":"empty","parentUuid":"system","message":{"role":"user","content":[]}}"#,
        );
        let projected = project_text(&source, Path::new("contract.jsonl"));
        assert_eq!(projected.stats.skipped_records, 3);
        assert_eq!(projected.stats.skipped_parents, 0);
        assert_eq!(projected.stats.unresolved_parents, 0);

        let parent = block_with_payload(&projected.fragment, "before metadata");
        let child = block_with_payload(&projected.fragment, "after metadata");
        assert!(exists!(pattern!(&projected.fragment, [{
            child @ schema::block::previous: &parent
        }])));
        let parent_projection = projection_for_block(&projected.fragment, parent);
        let child_projection = projection_for_block(&projected.fragment, child);
        assert!(exists!(pattern!(&projected.fragment, [{
            child_projection @ schema::source_projection::semantic_predecessor_support: &parent_projection
        }])));
        assert_eq!(
            raw_projection_record(&projected.fragment, child_projection),
            child_raw.as_bytes(),
            "the exact receipt retains direct vendor adjacency while the semantic graph contracts it"
        );
    }

    #[test]
    fn nonsemantic_rows_live_only_in_the_exact_source_snapshot() {
        let semantic = r#"{"type":"user","sessionId":"raw-cover","uuid":"root","message":{"role":"user","content":"hello"}}"#;
        let telemetry = r#"{"type":"progress","sessionId":"raw-cover","uuid":"progress","parentUuid":"root","data":{"type":"agent_progress"}}"#;
        let empty = r#"{"type":"user","sessionId":"raw-cover","uuid":"empty","parentUuid":"progress","message":{"role":"user","content":[]}}"#;
        let source = format!("{semantic}\n{telemetry}\n{empty}\n");
        let projected = project_text(&source, Path::new("raw-cover.jsonl"));

        assert_eq!(projected.stats.records_seen, 3);
        assert_eq!(projected.stats.skipped_records, 2);
        assert_eq!(projected.stats.raw_chunks, 1);
        assert_eq!(projected.stats.source_projections, 1);
        assert_eq!(projected.stats.source_snapshots, 1);
        assert_eq!(
            exact_source_snapshot(&projected.fragment),
            source.as_bytes()
        );

        let raw_records = ids_with_tag(&projected.fragment, schema::source_projection::KIND)
            .into_iter()
            .map(|projection| raw_projection_record(&projected.fragment, projection))
            .collect::<Vec<_>>();
        assert!(raw_records.iter().any(|raw| raw == semantic.as_bytes()));
        assert!(!raw_records.iter().any(|raw| raw == telemetry.as_bytes()));
        assert!(!raw_records.iter().any(|raw| raw == empty.as_bytes()));
    }

    #[test]
    fn append_reuses_complete_raw_chunks_and_replaces_only_the_bounded_tail() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("growing.jsonl");
        let root = r#"{"type":"user","sessionId":"growing","uuid":"root","message":{"role":"user","content":"hello"}}"#;
        let large_progress = format!(
            r#"{{"type":"progress","sessionId":"growing","uuid":"progress","parentUuid":"root","data":"{}"}}"#,
            "x".repeat(schema::source_chunk::CANONICAL_BYTES)
        );
        let first_source = format!("{root}\n{large_progress}\n");
        fs::write(&path, &first_source).unwrap();

        let mut first = Fragment::empty();
        let first_summary = project_path(&path, |projected| {
            first += projected.fragment;
            Ok(())
        })
        .unwrap();
        assert_eq!(first_summary.stats.raw_chunks, 2);
        let first_chunks = ids_with_tag(&first, schema::source_chunk::KIND);
        assert_eq!(first_chunks.len(), 2);

        let appended = format!(
            "{first_source}{}\n",
            r#"{"type":"progress","sessionId":"growing","uuid":"later","parentUuid":"progress","data":"more"}"#
        );
        fs::write(&path, appended).unwrap();
        let mut second = Fragment::empty();
        let second_summary = project_path(&path, |projected| {
            second += projected.fragment;
            Ok(())
        })
        .unwrap();
        assert_eq!(second_summary.stats.raw_chunks, 2);
        let second_chunks = ids_with_tag(&second, schema::source_chunk::KIND);
        assert_eq!(second_chunks.len(), 2);
        assert_eq!(
            first_chunks.intersection(&second_chunks).count(),
            1,
            "the complete prefix chunk is stable while only the bounded tail changes"
        );
    }

    #[test]
    fn digest_mismatch_emits_no_fragment() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mutable.jsonl");
        fs::write(
            &path,
            r#"{"type":"user","sessionId":"mutable","uuid":"before","message":{"role":"user","content":"before"}}"#,
        )
        .unwrap();
        let prescan = prescan_file(&path).unwrap();
        let plan = SourcePlan::from_scans(std::slice::from_ref(&prescan)).unwrap();
        fs::write(
            &path,
            r#"{"type":"user","sessionId":"mutable","uuid":"after","message":{"role":"user","content":"after"}}"#,
        )
        .unwrap();
        let snapshot = archive_source::freeze_file(&path).unwrap();
        let mut emitted = 0usize;
        let error = project_snapshot(
            &path,
            snapshot,
            prescan.digest,
            prescan.file_anchor.as_ref(),
            &plan,
            &mut |_| {
                emitted += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(emitted, 0);
        assert!(format!("{error:#}").contains("changed between dependency pre-scan"));
    }

    #[test]
    fn source_plan_unions_duplicate_parent_evidence_and_normalizes_exact_turn_telemetry() {
        // Reduced, field-faithful form of the only record-level cycle found in
        // the complete 2026-08-08 corpus census. S is transparent turn-duration
        // telemetry. One A receipt reports S while a second reports the real
        // semantic predecessor P; S reciprocally reports A. The canonical
        // future is U -> P -> A -> N, independent of receipt order/history.
        let source = concat!(
            r#"{"type":"user","sessionId":"turn","uuid":"U","parentUuid":null,"message":{"role":"user","content":"before"}}"#,
            "\n",
            r#"{"type":"assistant","sessionId":"turn","uuid":"P","parentUuid":"U","message":{"role":"assistant","content":[{"type":"thinking","thinking":"thought"}]}}"#,
            "\n",
            r#"{"type":"system","subtype":"turn_duration","sessionId":"turn","uuid":"S","parentUuid":"A","durationMs":36}"#,
            "\n",
            r#"{"type":"assistant","sessionId":"turn","uuid":"A","parentUuid":"S","message":{"role":"assistant","content":"answer"}}"#,
            "\n",
            r#"{"type":"assistant","sessionId":"turn","uuid":"A","parentUuid":"P","message":{"role":"assistant","content":"answer"}}"#,
            "\n",
            r#"{"type":"user","sessionId":"turn","uuid":"N","parentUuid":"A","message":{"role":"user","content":"next"}}"#,
        );
        let prescan = prescan_text(source, Path::new("turn-duration.jsonl"));
        let plan = SourcePlan::from_scans(&[prescan]).unwrap();
        let u = SourceKey::new("turn", "U");
        let p = SourceKey::new("turn", "P");
        let s = SourceKey::new("turn", "S");
        let a = SourceKey::new("turn", "A");
        let n = SourceKey::new("turn", "N");
        assert_eq!(plan.parents[&u], BTreeSet::new());
        assert_eq!(plan.parents[&p], BTreeSet::from([u]));
        assert_eq!(plan.parents[&a], BTreeSet::from([p]));
        assert_eq!(plan.parents[&n], BTreeSet::from([a]));
        assert!(!plan.semantic.contains(&s));

        let projected = project_text(source, Path::new("turn-duration.jsonl"));
        assert_eq!(projected.stats.source_projections, 5);
        assert_eq!(projected.stats.skipped_records, 1);
        assert_eq!(projected.stats.unresolved_parents, 0);
        let thought = block_with_payload(&projected.fragment, "thought");
        let answer = block_with_payload(&projected.fragment, "answer");
        let next = block_with_payload(&projected.fragment, "next");
        assert!(exists!(pattern!(&projected.fragment, [{
            answer @ schema::block::previous: &thought
        }])));
        assert!(exists!(pattern!(&projected.fragment, [{
            next @ schema::block::previous: &answer
        }])));
        let answer_receipts: BTreeSet<_> = find!(
            projection: Id,
            pattern!(&projected.fragment, [{
                ?projection @ schema::source_projection::projects_to: &answer
            }])
        )
        .collect();
        assert_eq!(answer_receipts.len(), 2);
        let next_projection = projection_for_block(&projected.fragment, next);
        let previous_receipts: BTreeSet<_> = find!(
            previous: Id,
            pattern!(&projected.fragment, [{
                next_projection @ schema::source_projection::semantic_predecessor_support: ?previous
            }])
        )
        .collect();
        assert_eq!(previous_receipts, answer_receipts);
    }

    #[test]
    fn fork_alias_quotient_preserves_tool_chronology_not_replay_serialization() {
        // Reduced, field-faithful form of the d00f... origin / 77fe...
        // destination replay that exposed the fork cycle. Fork receipts are
        // exact evidence for their origin class, but their destination parent
        // links are serialization artifacts. The later native replay restores
        // the semantic B -> A -> U chronology even though U appears first.
        let source = concat!(
            r#"{"type":"user","sessionId":"d00f65db-0741-41e1-aa27-420e1423e24b","uuid":"2b46fe81-12d5-4291-a494-40b7130cf37e","parentUuid":null,"message":{"role":"user","content":"request"}}"#,
            "\n",
            r#"{"type":"assistant","sessionId":"d00f65db-0741-41e1-aa27-420e1423e24b","uuid":"1fdd8a4d-15f2-4915-a4ab-0630bfbbaf76","parentUuid":"2b46fe81-12d5-4291-a494-40b7130cf37e","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_exemplar","name":"Read","input":{"file":"x"}}]}}"#,
            "\n",
            r#"{"type":"user","sessionId":"d00f65db-0741-41e1-aa27-420e1423e24b","uuid":"353e151f-7443-40f6-9dc1-7736b5f02db8","parentUuid":"1fdd8a4d-15f2-4915-a4ab-0630bfbbaf76","sourceToolAssistantUUID":"1fdd8a4d-15f2-4915-a4ab-0630bfbbaf76","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_exemplar","content":"result"}]}}"#,
            "\n",
            r#"{"type":"user","sessionId":"77fe8720-6f5b-42d9-8462-a3edd3445af9","uuid":"2b46fe81-12d5-4291-a494-40b7130cf37e","parentUuid":null,"forkedFrom":{"sessionId":"d00f65db-0741-41e1-aa27-420e1423e24b","messageUuid":"2b46fe81-12d5-4291-a494-40b7130cf37e"},"message":{"role":"user","content":"request"}}"#,
            "\n",
            // Replay serialization reverses U/A here; neither edge is a
            // semantic parent assertion because both receipts are forked.
            r#"{"type":"user","sessionId":"77fe8720-6f5b-42d9-8462-a3edd3445af9","uuid":"353e151f-7443-40f6-9dc1-7736b5f02db8","parentUuid":"2b46fe81-12d5-4291-a494-40b7130cf37e","sourceToolAssistantUUID":"1fdd8a4d-15f2-4915-a4ab-0630bfbbaf76","forkedFrom":{"sessionId":"d00f65db-0741-41e1-aa27-420e1423e24b","messageUuid":"353e151f-7443-40f6-9dc1-7736b5f02db8"},"message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_exemplar","content":"result"}]}}"#,
            "\n",
            r#"{"type":"assistant","sessionId":"77fe8720-6f5b-42d9-8462-a3edd3445af9","uuid":"1fdd8a4d-15f2-4915-a4ab-0630bfbbaf76","parentUuid":"353e151f-7443-40f6-9dc1-7736b5f02db8","forkedFrom":{"sessionId":"d00f65db-0741-41e1-aa27-420e1423e24b","messageUuid":"1fdd8a4d-15f2-4915-a4ab-0630bfbbaf76"},"message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_exemplar","name":"Read","input":{"file":"x"}}]}}"#,
            "\n",
            // Native replay order in the file is U then A, but its assertions
            // are A -> U and B -> A and therefore form the true DAG.
            r#"{"type":"user","sessionId":"77fe8720-6f5b-42d9-8462-a3edd3445af9","uuid":"353e151f-7443-40f6-9dc1-7736b5f02db8","parentUuid":"1fdd8a4d-15f2-4915-a4ab-0630bfbbaf76","sourceToolAssistantUUID":"1fdd8a4d-15f2-4915-a4ab-0630bfbbaf76","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_exemplar","content":"result"}]}}"#,
            "\n",
            r#"{"type":"assistant","sessionId":"77fe8720-6f5b-42d9-8462-a3edd3445af9","uuid":"1fdd8a4d-15f2-4915-a4ab-0630bfbbaf76","parentUuid":"2b46fe81-12d5-4291-a494-40b7130cf37e","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_exemplar","name":"Read","input":{"file":"x"}}]}}"#,
        );

        let projected = project_text(source, Path::new("fork-exemplar.jsonl"));
        assert_eq!(projected.stats.unresolved_tool_results, 0);
        let request = block_with_payload(&projected.fragment, "request");
        let call = block_with_payload(
            &projected.fragment,
            r#"{"name":"Read","input":{"file":"x"}}"#,
        );
        let result = block_with_payload(&projected.fragment, "result");
        assert!(exists!(pattern!(&projected.fragment, [{
            call @ schema::block::previous: &request
        }])));
        assert!(exists!(pattern!(&projected.fragment, [{
            result @ schema::block::previous: &call
        }])));
        assert!(!exists!(pattern!(&projected.fragment, [{
            call @ schema::block::previous: &result
        }])));

        let call_receipts = projections_for_block(&projected.fragment, call);
        let result_receipts = projections_for_block(&projected.fragment, result);
        assert_eq!(call_receipts.len(), 3);
        assert_eq!(result_receipts.len(), 3);
        for receipt in result_receipts {
            let previous: BTreeSet<_> = find!(
                previous: Id,
                pattern!(&projected.fragment, [{
                    receipt @ schema::source_projection::semantic_predecessor_support: ?previous
                }])
            )
            .collect();
            assert_eq!(previous, call_receipts);
        }
    }

    #[test]
    fn fork_origin_message_uuid_need_not_equal_the_destination_uuid() {
        let source = concat!(
            r#"{"type":"user","sessionId":"origin","uuid":"origin-message","message":{"role":"user","content":"same payload"}}"#,
            "\n",
            r#"{"type":"user","sessionId":"destination","uuid":"copy-message","forkedFrom":{"sessionId":"origin","messageUuid":"origin-message"},"message":{"role":"user","content":"same payload"}}"#,
        );
        let scan = prescan_text(source, Path::new("different-uuid.jsonl"));
        let plan = SourcePlan::from_scans(&[scan]).unwrap();
        let origin = SourceKey::new("origin", "origin-message");
        let copy = SourceKey::new("destination", "copy-message");
        assert_eq!(plan.canonical_key(&origin), plan.canonical_key(&copy));

        let projected = project_text(source, Path::new("different-uuid.jsonl"));
        let block = block_with_payload(&projected.fragment, "same payload");
        assert_eq!(projections_for_block(&projected.fragment, block).len(), 2);
    }

    #[test]
    fn alias_class_payload_conflict_fails_before_emission() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("origin.jsonl"),
            r#"{"type":"user","sessionId":"origin","uuid":"message","message":{"role":"user","content":"origin payload"}}"#,
        )
        .unwrap();
        fs::write(
            directory.path().join("fork.jsonl"),
            r#"{"type":"user","sessionId":"fork","uuid":"message","forkedFrom":{"sessionId":"origin","messageUuid":"message"},"message":{"role":"user","content":"conflicting payload"}}"#,
        )
        .unwrap();
        let mut emitted = 0;
        let error = project_path(directory.path(), |_| {
            emitted += 1;
            Ok(())
        })
        .unwrap_err();
        assert_eq!(emitted, 0);
        assert!(format!("{error:#}").contains("alias class"));
        assert!(format!("{error:#}").contains("conflicting semantic payloads"));
    }

    #[test]
    fn alias_representative_and_blocks_are_independent_of_scan_order() {
        let origin = prescan_text(
            r#"{"type":"user","sessionId":"z-origin","uuid":"message","message":{"role":"user","content":"stable"}}"#,
            Path::new("origin.jsonl"),
        );
        let fork = prescan_text(
            r#"{"type":"user","sessionId":"a-fork","uuid":"copy","forkedFrom":{"sessionId":"z-origin","messageUuid":"message"},"message":{"role":"user","content":"stable"}}"#,
            Path::new("fork.jsonl"),
        );
        let forward = SourcePlan::from_scans(&[origin, fork]).unwrap();

        let fork = prescan_text(
            r#"{"type":"user","sessionId":"a-fork","uuid":"copy","forkedFrom":{"sessionId":"z-origin","messageUuid":"message"},"message":{"role":"user","content":"stable"}}"#,
            Path::new("fork.jsonl"),
        );
        let origin = prescan_text(
            r#"{"type":"user","sessionId":"z-origin","uuid":"message","message":{"role":"user","content":"stable"}}"#,
            Path::new("origin.jsonl"),
        );
        let reverse = SourcePlan::from_scans(&[fork, origin]).unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(
            forward.canonical_key(&SourceKey::new("z-origin", "message")),
            SourceKey::new("a-fork", "copy")
        );
    }

    #[test]
    fn fourteen_native_bridge_references_resolve_through_fork_only_keys() {
        // The full corpus has exactly fourteen native parent assertions whose
        // destination-session key is defined only by a fork receipt. Freeze
        // that cardinality here so a future "forks never provide identities"
        // shortcut cannot silently reintroduce the missing bridges.
        let mut source = String::new();
        for index in 0..14 {
            let origin_session = format!("origin-{index:02}");
            let destination_session = format!("destination-{index:02}");
            let provider = format!("provider-{index:02}");
            let child = format!("child-{index:02}");
            let payload = format!("provider payload {index:02}");
            let child_payload = format!("child payload {index:02}");
            for line in [
                format!(
                    r#"{{"type":"user","sessionId":"{origin_session}","uuid":"{provider}","message":{{"role":"user","content":"{payload}"}}}}"#
                ),
                format!(
                    r#"{{"type":"user","sessionId":"{destination_session}","uuid":"{provider}","forkedFrom":{{"sessionId":"{origin_session}","messageUuid":"{provider}"}},"message":{{"role":"user","content":"{payload}"}}}}"#
                ),
                format!(
                    r#"{{"type":"assistant","sessionId":"{destination_session}","uuid":"{child}","parentUuid":"{provider}","message":{{"role":"assistant","content":"{child_payload}"}}}}"#
                ),
            ] {
                if !source.is_empty() {
                    source.push('\n');
                }
                source.push_str(&line);
            }
        }

        let projected = project_text(&source, Path::new("fourteen-bridges.jsonl"));
        assert_eq!(projected.stats.unresolved_parents, 0);
        for index in 0..14 {
            let provider =
                block_with_payload(&projected.fragment, &format!("provider payload {index:02}"));
            let child =
                block_with_payload(&projected.fragment, &format!("child payload {index:02}"));
            assert!(exists!(pattern!(&projected.fragment, [{
                child @ schema::block::previous: &provider
            }])));
        }
    }

    #[test]
    fn true_semantic_cycle_is_rejected_before_emission() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("cycle.jsonl"),
            concat!(
                r#"{"type":"user","sessionId":"cycle","uuid":"a","parentUuid":"b","message":{"role":"user","content":"a"}}"#,
                "\n",
                r#"{"type":"assistant","sessionId":"cycle","uuid":"b","parentUuid":"a","message":{"role":"assistant","content":"b"}}"#,
            ),
        )
        .unwrap();
        let mut emitted = 0;
        let error = project_path(directory.path(), |_| {
            emitted += 1;
            Ok(())
        })
        .unwrap_err();
        assert_eq!(emitted, 0);
        assert!(format!("{error:#}").contains("semantic Claude Code source cycle"));
    }

    #[test]
    fn tool_semantics_include_canonical_name_input_and_tristate_result_status() {
        let bash_a = project_text(
            r#"{"type":"assistant","sessionId":"tools","uuid":"a","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_a","name":"Bash","input":{"z":1,"a":2}}]}}"#,
            Path::new("bash-a.jsonl"),
        );
        let bash_b = project_text(
            r#"{"type":"assistant","sessionId":"tools","uuid":"b","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_b","name":"Bash","input":{"a":2,"z":1}}]}}"#,
            Path::new("bash-b.jsonl"),
        );
        let read = project_text(
            r#"{"type":"assistant","sessionId":"tools","uuid":"c","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_c","name":"Read","input":{"a":2,"z":1}}]}}"#,
            Path::new("read.jsonl"),
        );
        let bash_a_block =
            block_with_payload(&bash_a.fragment, r#"{"name":"Bash","input":{"a":2,"z":1}}"#);
        let bash_b_block =
            block_with_payload(&bash_b.fragment, r#"{"name":"Bash","input":{"a":2,"z":1}}"#);
        let read_block =
            block_with_payload(&read.fragment, r#"{"name":"Read","input":{"a":2,"z":1}}"#);
        assert_eq!(bash_a_block, bash_b_block);
        assert_ne!(bash_a_block, read_block);
        assert_ne!(
            projection_for_block(&bash_a.fragment, bash_a_block),
            projection_for_block(&bash_b.fragment, bash_b_block),
            "vendor correlators remain exact receipt evidence, not semantic identity"
        );

        let missing = project_text(
            r#"{"type":"user","sessionId":"tools","uuid":"missing","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"unknown","content":"same output"}]}}"#,
            Path::new("missing.jsonl"),
        );
        let ok = project_text(
            r#"{"type":"user","sessionId":"tools","uuid":"ok","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"unknown","content":"same output","is_error":false}]}}"#,
            Path::new("ok.jsonl"),
        );
        let error = project_text(
            r#"{"type":"user","sessionId":"tools","uuid":"error","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"unknown","content":"same output","is_error":true}]}}"#,
            Path::new("error.jsonl"),
        );
        let missing_block = block_with_payload(&missing.fragment, "same output");
        let ok_block = block_with_payload(&ok.fragment, "same output");
        let error_block = block_with_payload(&error.fragment, "same output");
        assert_ne!(missing_block, ok_block);
        assert_ne!(ok_block, error_block);
        assert_ne!(missing_block, error_block);
        assert_eq!(
            block_with_payload(&ok.fragment, TOOL_RESULT_STATUS_OK),
            ok_block
        );
        assert_eq!(
            block_with_payload(&error.fragment, TOOL_RESULT_STATUS_ERROR),
            error_block
        );
        let (_empty, reader) = empty_reader();
        let (_, validation) =
            blockdag::validate_catalog_union(&reader, &TribleSet::new(), &ok.fragment).unwrap();
        assert_eq!(validation, blockdag::CatalogValidation::Accepted);

        let linked = project_text(
            concat!(
                r#"{"type":"assistant","sessionId":"linked","uuid":"call","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_linked","name":"Bash","input":{"command":"true"}}]}}"#,
                "\n",
                r#"{"type":"user","sessionId":"linked","uuid":"result","parentUuid":"call","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_linked","content":"done","is_error":false}]}}"#,
            ),
            Path::new("linked.jsonl"),
        );
        let call_part = find!(
            part: Id,
            pattern!(linked.fragment.facts(), [
                { ?part @ schema::content_part::fact: _?fact },
                { _?fact @ schema::content_fact::modality: &schema::content_fact::modality::TOOL_CALL },
            ])
        )
        .next()
        .unwrap();
        let response_modalities: BTreeSet<Id> = find!(
            modality: Id,
            pattern!(linked.fragment.facts(), [
                { _?part @ schema::content_part::responds_to: &call_part },
                { _?part @ schema::content_part::fact: _?fact },
                { _?fact @ schema::content_fact::modality: ?modality },
            ])
        )
        .collect();
        assert_eq!(
            response_modalities,
            BTreeSet::from([
                schema::content_fact::modality::EVENT,
                schema::content_fact::modality::TOOL_RESULT,
            ])
        );
    }

    #[test]
    fn canonical_tool_json_sorts_nested_objects_and_escapes_decoded_strings() {
        let input = Bytes::from_source(
            br#"{ "z":{"quote":"a\"b","line":"x\ny"},"a":[{"two":2,"one":1}],"dup":0,"dup":3}"#
                .to_vec(),
        );
        let canonical = canonical_tool_call(Some("say \"hi\"\n".to_owned()), Some(input)).unwrap();
        assert_eq!(
            canonical,
            "{\"name\":\"say \\\"hi\\\"\\n\",\"input\":{\"a\":[{\"one\":1,\"two\":2}],\"dup\":3,\"z\":{\"line\":\"x\\ny\",\"quote\":\"a\\\"b\"}}}"
        );
    }

    #[test]
    fn canonical_json_preserves_historical_number_spelling_at_boundaries() {
        for (raw, expected) in [
            ("-0", "-0.0"),
            ("-0.0", "-0.0"),
            ("0.0", "0.0"),
            ("1e2", "100.0"),
            ("1e-2", "0.01"),
            ("9223372036854775807", "9223372036854775807"),
            ("9223372036854775808", "9223372036854775808"),
            ("18446744073709551615", "18446744073709551615"),
            ("18446744073709551616", "1.8446744073709552e+19"),
            ("-9223372036854775808", "-9223372036854775808"),
            ("-9223372036854775809", "-9.223372036854776e+18"),
        ] {
            let actual =
                archive_source::canonical_json(Bytes::from_source(raw.as_bytes().to_vec()))
                    .unwrap();
            assert_eq!(actual, expected, "canonical spelling for {raw}");
        }
        assert!(archive_source::canonical_json(Bytes::from_source(b"1e400".to_vec())).is_err());
    }

    #[test]
    fn image_size_alias_priority_is_order_independent_and_null_authoritative() {
        fn size(source: &str) -> Option<u128> {
            let mut source = Bytes::from_source(source.as_bytes().to_vec());
            scan_optional_image_source(&mut source)
                .unwrap()
                .unwrap()
                .size
        }

        assert_eq!(size(r#"{"file_size":7,"size":99}"#), Some(7));
        assert_eq!(size(r#"{"size":99,"file_size":7}"#), Some(7));
        assert_eq!(size(r#"{"file_size":null,"size":99}"#), None);
        assert_eq!(size(r#"{"size":99,"file_size":null}"#), None);
        assert_eq!(size(r#"{"size":99}"#), Some(99));
    }

    #[test]
    fn explicit_tool_source_resolves_a_call_that_appears_later_in_the_file() {
        let projected = project_text(
            concat!(
                r#"{"type":"user","sessionId":"forward-tool","uuid":"result","parentUuid":"call","sourceToolAssistantUUID":"call","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_forward","content":"forward result"}]}}"#,
                "\n",
                r#"{"type":"assistant","sessionId":"forward-tool","uuid":"call","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_forward","name":"Read","input":{"file":"later"}}]}}"#,
            ),
            Path::new("forward-tool.jsonl"),
        );
        assert_eq!(projected.stats.unresolved_tool_results, 0);
        let call_part = find!(
            part: Id,
            pattern!(projected.fragment.facts(), [
                { ?part @ schema::content_part::fact: _?fact },
                { _?fact @ schema::content_fact::modality: &schema::content_fact::modality::TOOL_CALL },
            ])
        )
        .next()
        .unwrap();
        assert!(exists!(pattern!(projected.fragment.facts(), [
            { _?part @ schema::content_part::responds_to: &call_part },
            { _?part @ schema::content_part::fact: _?fact },
            { _?fact @ schema::content_fact::modality: &schema::content_fact::modality::TOOL_RESULT },
        ])));
    }

    #[test]
    fn alias_equivalent_tool_sources_do_not_conflict_before_resolution() {
        let source = concat!(
            r#"{"type":"assistant","sessionId":"alias-tools","uuid":"call-origin","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_alias","name":"Read","input":{"file":"x"}}]}}"#,
            "\n",
            r#"{"type":"assistant","sessionId":"alias-tools","uuid":"call-copy","forkedFrom":{"sessionId":"alias-tools","messageUuid":"call-origin"},"message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_alias","name":"Read","input":{"file":"x"}}]}}"#,
            "\n",
            r#"{"type":"user","sessionId":"alias-tools","uuid":"result","sourceToolAssistantUUID":"call-origin","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_alias","content":"same result"}]}}"#,
            "\n",
            r#"{"type":"user","sessionId":"alias-tools","uuid":"result","sourceToolAssistantUUID":"call-copy","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_alias","content":"same result"}]}}"#,
        );
        let projected = project_text(source, Path::new("alias-tool-sources.jsonl"));
        assert_eq!(projected.stats.unresolved_tool_results, 0);
        let result = block_with_payload(&projected.fragment, "same result");
        assert_eq!(projections_for_block(&projected.fragment, result).len(), 2);
    }

    #[test]
    fn implicit_tool_resolution_is_stable_under_unrelated_sessions() {
        let base = concat!(
            r#"{"type":"assistant","sessionId":"local","uuid":"call","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_reused","name":"Read","input":{"file":"local"}}]}}"#,
            "\n",
            r#"{"type":"user","sessionId":"local","uuid":"result","parentUuid":"call","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_reused","content":"local result"}]}}"#,
        );
        let extended = format!(
            "{base}\n{}",
            r#"{"type":"assistant","sessionId":"unrelated","uuid":"call","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_reused","name":"Read","input":{"file":"unrelated"}}]}}"#,
        );
        let base = project_text(base, Path::new("base.jsonl"));
        let extended = project_text(&extended, Path::new("extended.jsonl"));
        assert_eq!(base.stats.unresolved_tool_results, 0);
        assert_eq!(extended.stats.unresolved_tool_results, 0);
        assert_eq!(
            block_with_payload(&base.fragment, "local result"),
            block_with_payload(&extended.fragment, "local result"),
            "an unrelated session cannot retract an intrinsic tool edge"
        );
    }

    #[test]
    fn conflicting_implicit_tool_definition_rejects_the_enlarged_import() {
        let source = concat!(
            r#"{"type":"assistant","sessionId":"conflicting-tools","uuid":"one","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_same","name":"Read","input":{"file":"one"}}]}}"#,
            "\n",
            r#"{"type":"assistant","sessionId":"conflicting-tools","uuid":"two","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_same","name":"Read","input":{"file":"two"}}]}}"#,
        );
        let scan = prescan_text(source, Path::new("conflicting-tools.jsonl"));
        let error = SourcePlan::from_scans(&[scan]).unwrap_err();
        assert!(format!("{error:#}").contains("conflicting calls in raw session"));
    }

    #[test]
    fn corpus_plan_resolves_cross_file_support_independent_of_path_order() {
        let directory = tempfile::tempdir().unwrap();
        let child = directory.path().join("00-child.jsonl");
        let parent = directory.path().join("99-parent.jsonl");
        fs::write(
            &parent,
            r#"{"type":"user","sessionId":"cross","uuid":"root","parentUuid":null,"timestamp":"2026-03-01T15:34:01Z","message":{"role":"user","content":"parent payload"}}"#,
        )
        .unwrap();
        fs::write(
            &child,
            r#"{"type":"assistant","sessionId":"cross","uuid":"child","parentUuid":"root","timestamp":"2026-03-01T15:34:02Z","message":{"role":"assistant","model":"claude","content":[{"type":"text","text":"child payload"}]}}"#,
        )
        .unwrap();

        let mut union = Fragment::empty();
        project_path(directory.path(), |projected| {
            union += projected.fragment;
            Ok(())
        })
        .unwrap();

        let parent_id = block_with_payload(&union, "parent payload");
        let child_id = block_with_payload(&union, "child payload");
        assert!(exists!(pattern!(&union, [{
            child_id @ schema::block::previous: &parent_id
        }])));
        let (_empty, reader) = empty_reader();
        let (_, validation) =
            blockdag::validate_catalog_union(&reader, &TribleSet::new(), &union).unwrap();
        assert_eq!(validation, blockdag::CatalogValidation::Accepted);
    }

    #[test]
    fn absent_reference_does_not_strand_a_files_resolvable_descendants() {
        let directory = tempfile::tempdir().unwrap();
        let child = directory.path().join("00-child.jsonl");
        let provider = directory.path().join("99-provider.jsonl");
        fs::write(
            &provider,
            r#"{"type":"user","sessionId":"mixed","uuid":"provider","parentUuid":"absent","message":{"role":"user","content":"partially rooted provider"}}"#,
        )
        .unwrap();
        fs::write(
            &child,
            r#"{"type":"assistant","sessionId":"mixed","uuid":"child","parentUuid":"provider","message":{"role":"assistant","content":"dependent child"}}"#,
        )
        .unwrap();

        let mut union = Fragment::empty();
        let summary = project_path(directory.path(), |projected| {
            union += projected.fragment;
            Ok(())
        })
        .unwrap();
        assert_eq!(summary.stats.unresolved_parents, 1);
        let provider = block_with_payload(&union, "partially rooted provider");
        let child = block_with_payload(&union, "dependent child");
        assert!(exists!(pattern!(&union, [{
            child @ schema::block::previous: &provider
        }])));
    }

    #[test]
    fn transparent_source_chain_resolves_across_reversed_file_order() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("00-child.jsonl"),
            r#"{"type":"assistant","sessionId":"transparent-files","uuid":"child","parentUuid":"system","message":{"role":"assistant","content":"file child"}}"#,
        )
        .unwrap();
        fs::write(
            directory.path().join("33-system.jsonl"),
            r#"{"type":"system","sessionId":"transparent-files","uuid":"system","parentUuid":"attachment","content":"metadata"}"#,
        )
        .unwrap();
        fs::write(
            directory.path().join("66-attachment.jsonl"),
            r#"{"type":"attachment","sessionId":"transparent-files","uuid":"attachment","parentUuid":"root","attachment":{"type":"skill_listing"}}"#,
        )
        .unwrap();
        fs::write(
            directory.path().join("99-root.jsonl"),
            r#"{"type":"user","sessionId":"transparent-files","uuid":"root","parentUuid":null,"message":{"role":"user","content":"file root"}}"#,
        )
        .unwrap();

        let mut union = Fragment::empty();
        let summary = project_path(directory.path(), |projected| {
            union += projected.fragment;
            Ok(())
        })
        .unwrap();
        assert_eq!(summary.stats.unresolved_parents, 0);
        let root = block_with_payload(&union, "file root");
        let child = block_with_payload(&union, "file child");
        assert!(exists!(pattern!(&union, [{
            child @ schema::block::previous: &root
        }])));
        let root_projection = projection_for_block(&union, root);
        let child_projection = projection_for_block(&union, child);
        assert!(exists!(pattern!(&union, [{
            child_projection @ schema::source_projection::semantic_predecessor_support: &root_projection
        }])));
    }

    #[test]
    fn dead_progress_backlink_does_not_create_a_file_dependency_cycle() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("00-agent.jsonl"),
            r#"{"type":"assistant","sessionId":"live-dag","uuid":"agent","parentUuid":"root","message":{"role":"assistant","content":"agent reply"}}"#,
        )
        .unwrap();
        fs::write(
            directory.path().join("99-main.jsonl"),
            concat!(
                r#"{"type":"user","sessionId":"live-dag","uuid":"root","parentUuid":null,"message":{"role":"user","content":"main root"}}"#,
                "\n",
                // Claude's progress telemetry may point from the main file to
                // an agent message even though it has no semantic descendant.
                // File adjacency is cyclic; the live semantic source DAG is
                // simply root -> agent.
                r#"{"type":"progress","sessionId":"live-dag","uuid":"progress","parentUuid":"agent","data":{"type":"agent_progress"}}"#,
            ),
        )
        .unwrap();

        let mut union = Fragment::empty();
        let summary = project_path(directory.path(), |projected| {
            union += projected.fragment;
            Ok(())
        })
        .unwrap();
        assert_eq!(summary.stats.skipped_records, 1);
        let root = block_with_payload(&union, "main root");
        let agent = block_with_payload(&union, "agent reply");
        assert!(exists!(pattern!(&union, [{
            agent @ schema::block::previous: &root
        }])));
    }

    #[test]
    fn file_level_cycle_does_not_obscure_a_valid_record_dag() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("00-a.jsonl"),
            concat!(
                r#"{"type":"user","sessionId":"cycle","uuid":"p","parentUuid":null,"message":{"role":"user","content":"root p"}}"#,
                "\n",
                r#"{"type":"assistant","sessionId":"cycle","uuid":"a1","parentUuid":"b1","message":{"role":"assistant","content":"after b1"}}"#,
            ),
        )
        .unwrap();
        fs::write(
            directory.path().join("99-b.jsonl"),
            r#"{"type":"user","sessionId":"cycle","uuid":"b1","parentUuid":"p","message":{"role":"user","content":"after p"}}"#,
        )
        .unwrap();

        let mut union = Fragment::empty();
        project_path(directory.path(), |projected| {
            union += projected.fragment;
            Ok(())
        })
        .unwrap();
        let p = block_with_payload(&union, "root p");
        let b = block_with_payload(&union, "after p");
        let a = block_with_payload(&union, "after b1");
        assert!(exists!(
            pattern!(&union, [{ b @ schema::block::previous: &p }])
        ));
        assert!(exists!(
            pattern!(&union, [{ a @ schema::block::previous: &b }])
        ));
    }

    #[test]
    fn duplicate_source_receipts_union_when_their_canonical_block_agrees() {
        let directory = tempfile::tempdir().unwrap();
        let parent_a = directory.path().join("parent-a.jsonl");
        let parent_b = directory.path().join("parent-b.jsonl");
        let child = directory.path().join("child.jsonl");
        fs::write(
            &parent_a,
            r#"{"type":"user","sessionId":"duplicate","uuid":"root","parentUuid":null,"message":{"role":"user","content":"same parent"}}"#,
        )
        .unwrap();
        // Exact source bytes differ, while their canonical block is identical.
        fs::write(
            &parent_b,
            r#"{ "uuid":"root", "sessionId":"duplicate", "parentUuid":null, "type":"user", "message":{"content":"same parent","role":"user"} }"#,
        )
        .unwrap();
        fs::write(
            &child,
            r#"{"type":"assistant","sessionId":"duplicate","uuid":"child","parentUuid":"root","message":{"role":"assistant","model":"claude","content":"after both receipts"}}"#,
        )
        .unwrap();

        let mut union = Fragment::empty();
        project_path(directory.path(), |projected| {
            union += projected.fragment;
            Ok(())
        })
        .unwrap();
        let parent = block_with_payload(&union, "same parent");
        let child_block = block_with_payload(&union, "after both receipts");
        assert!(exists!(pattern!(&union, [{
            child_block @ schema::block::previous: &parent
        }])));

        let child_projection = find!(
            projection: Id,
            pattern!(&union, [{
                ?projection @ schema::source_projection::projects_to: &child_block
            }])
        )
        .next()
        .unwrap();
        let previous_receipts: BTreeSet<Id> = find!(
            previous: Id,
            pattern!(&union, [{
                child_projection @ schema::source_projection::semantic_predecessor_support: ?previous
            }])
        )
        .collect();
        assert_eq!(previous_receipts.len(), 2);

        let (_empty, reader) = empty_reader();
        let (_, validation) =
            blockdag::validate_catalog_union(&reader, &TribleSet::new(), &union).unwrap();
        assert_eq!(validation, blockdag::CatalogValidation::Accepted);
    }

    #[test]
    fn conflicting_duplicate_source_is_rejected_before_its_fragment_is_emitted() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("a.jsonl"),
            r#"{"type":"user","sessionId":"conflict","uuid":"same","message":{"role":"user","content":"first"}}"#,
        )
        .unwrap();
        fs::write(
            directory.path().join("b.jsonl"),
            r#"{"type":"user","sessionId":"conflict","uuid":"same","message":{"role":"user","content":"second"}}"#,
        )
        .unwrap();
        let mut emitted = 0usize;
        let error = project_path(directory.path(), |_| {
            emitted += 1;
            Ok(())
        })
        .unwrap_err();
        assert_eq!(emitted, 0);
        assert!(format!("{error:#}").contains("conflicting semantic payloads"));
    }

    #[test]
    fn dialogue_without_vendor_identity_is_retained_only_in_the_exact_snapshot() {
        let source = r#"{"type":"user","message":{"role":"user","content":"anonymous"}}"#;
        let projected = project_text(source, Path::new("anonymous.jsonl"));
        let receipts = ids_with_tag(&projected.fragment, schema::source_projection::KIND);
        assert!(receipts.is_empty());
        assert_eq!(projected.stats.source_projections, 0);
        assert_eq!(projected.stats.source_snapshots, 1);
        assert_eq!(
            exact_source_snapshot(&projected.fragment),
            source.as_bytes()
        );
        assert_eq!(projected.stats.missing_source_identity, 1);
        assert_eq!(projected.stats.skipped_records, 1);
    }
}
